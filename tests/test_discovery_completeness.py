"""Offline evidence for bounded discovery, retry classification and last-good preservation."""

import json
import time
from datetime import UTC, datetime
from email.utils import format_datetime

import httpx
import pytest
import yaml

from sigharvest import discover, discovery_http, sync_remote
from sigharvest.config import SourceConfig, Workspace, load_sources, save_sources
from sigharvest.discovery_coverage import DiscoveryCoverage
from sigharvest.retry import RetryBudget, git_category, http_category, retry_after
from sigharvest.sync import SyncError
from tests.test_discover_offline import _client, _json, _mock, _noop, _repo_item


@pytest.mark.parametrize("value", ["NaN", "Infinity", "-1", "nonsense", "1e999", ""])
def test_corrupt_retry_after_and_reset_use_bounded_jitter(value):
    assert retry_after({"retry-after": value, "x-ratelimit-reset": value}, 1000) is None
    budget = RetryBudget(jitter=lambda: 0.25, now=lambda: 1000, attempts=1)
    assert budget.delay("rate_limit", {"retry-after": value, "x-ratelimit-reset": value}) == 1.25


def test_retry_after_http_date_and_server_minimum_exceeding_budget():
    now = 1700000000
    date = format_datetime(datetime.fromtimestamp(now + 15, UTC), usegmt=True)
    assert retry_after({"retry-after": date}, now) == 15
    assert retry_after({"retry-after": "bad", "x-ratelimit-reset": str(now + 20)}, now) == 20
    budget = RetryBudget(attempts=1, jitter=lambda: 0.5, now=lambda: now)
    assert budget.delay("rate_limit", {"retry-after": "3700"}) is None
    assert budget.waited == 0
    assert budget.delay("auth") is None
    assert budget.delay("transient") == 1.5


@pytest.mark.parametrize("status,expected", [(401, "auth"), (403, "auth"), (404, "not_found"), (410, "gone"), (429, "rate_limit"), (503, "transient")])
def test_error_categories(status, expected):
    assert http_category(status) == expected
    assert http_category(404, ref=True) == "missing_ref"
    assert git_category(SyncError("remote ref is missing or ambiguous")) == "missing_ref"
    assert git_category(SyncError("Authentication failed for secret URL")) == "auth"


@pytest.mark.parametrize(
    "stderr",
    [
        "error: RPC failed; curl 28 Operation too slow. Less than 1000 bytes/sec transferred the last 60 seconds",
        "error: RPC failed; curl 56 GnuTLS recv error (-9): A TLS packet with unexpected length was received.",
        "fetch-pack: unexpected disconnect while reading sideband packet\nfatal: early EOF",
    ],
)
def test_stalled_git_transfer_is_transient(stderr):
    """The full-corpus run of 2026-11-15 lost 37 live repositories to stalled clones classified "unknown"."""
    assert git_category(RuntimeError(stderr)) == "transient"


def test_stalled_clone_is_retried_then_succeeds(tmp_path, monkeypatch):
    import subprocess

    from sigharvest import sync

    calls = []

    def run(cmd, **_k):
        calls.append(cmd)
        target = tmp_path / "repo.git"
        if len(calls) == 1:
            target.mkdir()  # a half-written target must not make the retry refuse it
            return subprocess.CompletedProcess(cmd, 128, "", "error: RPC failed; curl 28 Operation too slow.\n")
        assert not target.exists()
        return subprocess.CompletedProcess(cmd, 0, "done", "")

    sleeps = []
    monkeypatch.setattr(sync.subprocess, "run", run)
    monkeypatch.setattr(sync.time, "sleep", sleeps.append)
    assert sync._git(["clone", "--bare", "--", "https://example.invalid/r.git", str(tmp_path / "repo.git")]) == "done"
    assert len(calls) == 2 and len(sleeps) == 1


def test_clone_retries_are_bounded_and_unknown_or_auth_fail_at_once(tmp_path, monkeypatch):
    import subprocess

    from sigharvest import sync

    def runner(stderr):
        calls = []

        def run(cmd, **_k):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 128, "", stderr)

        return calls, run

    monkeypatch.setattr(sync.time, "sleep", lambda _s: None)
    for stderr, attempts, category in [
        ("error: RPC failed; curl 28 Operation too slow.", sync.NETWORK_RETRIES + 1, "transient"),
        ("fatal: could not read Username for 'https://github.com': terminal prompts disabled", 1, "auth"),
        ("fatal: something new", 1, "unknown"),
    ]:
        calls, run = runner(stderr)
        monkeypatch.setattr(sync.subprocess, "run", run)
        with pytest.raises(SyncError, match=rf"git clone failed \({category}\)"):
            sync._git(["clone", "--", "https://example.invalid/r.git", str(tmp_path / "x.git")])
        assert len(calls) == attempts
    calls, run = runner("error: RPC failed; curl 28 Operation too slow.")
    monkeypatch.setattr(sync.subprocess, "run", run)
    with pytest.raises(SyncError):
        sync._git(["ls-remote", "--", "https://example.invalid/r.git"])
    assert len(calls) == 1  # ls-remote has its own 60 s budget and no retry


def test_429_without_headers_retries_and_auth_never_retries(tmp_path, monkeypatch):
    answers = [_json({}, 429), _json({"ok": True})]
    seen = _mock(monkeypatch, lambda r: answers.pop(0))
    client, sleeps = _client(tmp_path)
    assert client.get("https://api.github.com/x") == {"ok": True}
    assert len(seen) == 2 and sleeps == [1] and client.retries == 1
    answers.append(_json({}, 403))
    with pytest.raises(discover.ApiError) as error:
        client.get("https://api.github.com/auth?token=private-value")
    assert error.value.category == "auth" and "private-value" not in str(error.value)
    assert sleeps == [1]


def test_global_budget_counts_transport_failures(tmp_path, monkeypatch):
    def down(r):
        raise httpx.ConnectError("private-value")

    seen = _mock(monkeypatch, down)
    client = discover.CachedClient(tmp_path, sleep=lambda _: None, jitter=lambda: 0, max_requests=2)
    with pytest.raises(discover.ApiError) as error:
        client.get("https://api.github.com/x")
    assert error.value.category == "budget_exhausted"
    assert len(seen) == client.http_attempts == 2
    assert client.requests == 0 and client.retries == 1
    assert "private-value" not in str(error.value)


def test_stale_negative_cache_recovers_within_hour(tmp_path, monkeypatch):
    answers = [_json({}, 404), _json({"ok": 1})]
    seen = _mock(monkeypatch, lambda r: answers.pop(0))
    client, _ = _client(tmp_path, max_age=7 * 86400)
    url = "https://api.github.com/repos/old/name"
    with pytest.raises(discover.ApiError):
        client.get(url)
    path = client._path(url)
    cached = json.loads(path.read_text())
    cached["fetched_at"] = time.time() - 3601
    cached["etag"] = "negative-etag"
    path.write_text(json.dumps(cached))
    assert client.get(url) == {"ok": 1}
    assert len(seen) == 2 and "if-none-match" not in seen[1].headers


def test_http_and_cache_size_caps(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery_http, "MAX_HTTP_BYTES", 20)
    _mock(monkeypatch, lambda r: httpx.Response(200, content=b"x" * 21))
    client, _ = _client(tmp_path)
    with pytest.raises(discover.ApiError) as error:
        client.get("https://api.github.com/x")
    assert error.value.category == "resource_limit"
    assert not list((tmp_path / "cache").glob("*.json"))


@pytest.mark.parametrize("incomplete,complete", [(False, True), (True, False)])
def test_paginated_repositories_record_provider_incompleteness(tmp_path, monkeypatch, incomplete, complete):
    monkeypatch.setattr(discover, "TOPICS", ["sigma"])
    monkeypatch.setattr(discover, "REPO_KEYWORDS", [])

    def page(r):
        n = int(r.url.params["page"])
        return _json(
            {
                "items": [_repo_item(f"o/r{n}-{i}", id=n * 1000 + i) for i in range(100 if n == 1 else 1)],
                "total_count": 101,
                "incomplete_results": incomplete,
            }
        )

    _mock(monkeypatch, page)
    client, _ = _client(tmp_path)
    pool = {}
    discover.search_repos(client, pool, _noop)
    report = client.coverage.summary()
    row = report["strategies"]["repos"]
    assert row["pages"] == 2 and row["items"] == 101 and row["complete"] is complete
    assert report["provider_complete"] is False
    assert all(c.provider_id for c in pool.values())


def test_code_failure_consumes_budget_and_unstarted_queries_are_visible(tmp_path, monkeypatch):
    monkeypatch.setattr(discover, "CODE_PATHS", [""])
    monkeypatch.setattr(discover, "CODE_KEYWORDS", [""])
    monkeypatch.setattr(discover, "CODE_EXTENSIONS", ["yml", "yaml"])
    seen = _mock(monkeypatch, lambda r: _json({}, 401))
    client, _ = _client(tmp_path)
    assert discover.search_code(client, {}, 1, _noop) == 1
    summary = client.coverage.summary()["strategies"]["code"]
    assert len(seen) == 1 and summary["queries_planned"] == 2
    assert not summary["complete"] and summary["errors"] == {"auth": 1}
    assert summary["budget_exhausted_queries"] == 1


def test_repo_and_gitlab_page_caps(tmp_path, monkeypatch):
    monkeypatch.setattr(discover, "TOPICS", ["sigma"])
    monkeypatch.setattr(discover, "REPO_KEYWORDS", [])
    monkeypatch.setattr(discover, "GITLAB_QUERIES", ["sigma"])

    def page(r):
        if r.url.host == "gitlab.com":
            return _json([{"id": n, "path_with_namespace": f"g/p{n}", "archived": True} for n in range(100)])
        return _json({"items": [_repo_item(f"o/r{i}") for i in range(100)], "total_count": 1500})

    _mock(monkeypatch, page)
    client, _ = _client(tmp_path)
    pool = {}
    discover.search_repos(client, pool, _noop)
    discover.search_gitlab(client, pool, _noop)
    evidence = client.coverage.summary()
    assert evidence["strategies"]["repos"]["truncated_queries"] == 1
    assert evidence["strategies"]["gitlab"]["truncated_queries"] == 4
    assert all(c.archived and c.provider_id for c in pool.values() if c.host == "gitlab")


def test_short_or_changing_pages_do_not_claim_complete():
    coverage = DiscoveryCoverage()
    q = coverage.start("repos", "query")
    q.page(100, total=150)
    q.page(2, total=102)
    q.finish()
    assert not q.complete and q.stop_reason == "changing_results"
    q = coverage.start("repos", "short")
    q.page(1, total=20)
    q.finish()
    assert not q.complete and q.truncated and q.stop_reason == "short_page"


def test_provider_id_rename_and_disabled_sources(tmp_path):
    pool = {}
    old = discover.github_candidate("old/rules", "topic")
    old.provider_id = "42"
    discover.merge_candidate(pool, old)
    new = discover.github_candidate("new/rules", "code")
    new.provider_id = "42"
    merged = discover.merge_candidate(pool, new)
    assert len(pool) == 1 and merged is old and old.full_name == "new/rules"
    assert old.aliases == ["github.com/old/rules"]
    old.verified, old.valid_rule_count = True, 10
    ws = Workspace(tmp_path)
    save_sources(ws, [SourceConfig(name="old", type="git", url="https://github.com/old/rules.git", enabled=False)])
    before = ws.sources_file.read_bytes()
    assert discover.register_sources(ws, [old], {old.key}, True, "2026-10-27") == []
    assert ws.sources_file.read_bytes() == before and old.source == "old"
    assert not load_sources(ws)[0].enabled
    archived = discover.github_candidate("archive/rules", "topic")
    archived.archived, archived.verified, archived.valid_rule_count = True, True, 20
    discover.classify(archived, 5)
    assert archived.status == discover.STATUS_REVIEW
    discover.register_sources(ws, [archived], {archived.key}, True, "2026-10-27")
    assert not load_sources(ws)[1].enabled


def _cached_verification(count, **extra):
    return {
        "pushed_at": "2026-10-01T00:00:00Z",
        "refs": discover.REFERENCE_VERSION,
        "head": "old",
        "provider_id": "42",
        "valid_rule_count": count,
        "rule_files": count,
        "yaml_files": count,
        "unique_logic": count,
        "sigma_paths": ["rules/*"],
        "verified_at": 0,
        **extra,
    }


def test_expired_negative_verification_is_retried_and_last_good_is_preserved(tmp_path, monkeypatch):
    monkeypatch.setattr(discover, "SEEDS", [("org/rules", "")])
    monkeypatch.setattr(discover, "REFERENCE_REPOS", {})
    monkeypatch.setattr(discover, "github_token", lambda: None)
    _mock(monkeypatch, lambda r: _json(_repo_item("org/rules", id=42, pushed_at="2026-10-01T00:00:00Z")))
    ws = Workspace(tmp_path)
    save_sources(ws, [])
    cache = ws.cache / "discovery" / "_verify.json"
    cache.parent.mkdir(parents=True)
    cache.write_text(json.dumps({"github.com/org/rules": _cached_verification(0)}))
    calls = []

    def verify(c, *args):
        calls.append(c.key)
        c.verified, c.valid_rule_count, c.rule_files, c.yaml_files, c.unique_logic = True, 5, 5, 5, 5
        return c, set()

    monkeypatch.setattr(discover, "verify", verify)
    result = discover.run_discovery(ws, discover.DiscoveryOptions(strategies=(), auto_add=False))
    assert calls == ["github.com/org/rules"] and result.verified == 1

    def failed(c, *args):
        c.verified, c.reason, c.error_category = False, "clone/verify failed: transient", "transient"
        return c, set()

    monkeypatch.setattr(discover, "verify", failed)
    result = discover.run_discovery(ws, discover.DiscoveryOptions(strategies=(), reverify=True))
    c = result.candidates[0]
    assert c.stale and not c.verified and c.valid_rule_count == 5 and c.error_category == "transient"
    assert not load_sources(ws)
    assert json.loads(cache.read_text())["github.com/org/rules"]["valid_rule_count"] == 5
    report = yaml.safe_load((ws.root / "discovery/candidates.yaml").read_text())
    assert report["completeness"]["verification"]["stale"] == 1
    assert report["completeness"]["provider_complete"] is False


def test_discovery_rename_across_runs_uses_cached_provider_id(tmp_path, monkeypatch):
    monkeypatch.setattr(discover, "SEEDS", [("new/rules", "")])
    monkeypatch.setattr(discover, "REFERENCE_REPOS", {})
    monkeypatch.setattr(discover, "github_token", lambda: None)
    _mock(monkeypatch, lambda r: _json(_repo_item("new/rules", id=42, pushed_at="2026-10-01T00:00:00Z")))
    ws = Workspace(tmp_path)
    save_sources(ws, [SourceConfig(name="old", type="git", url="https://github.com/old/rules.git", enabled=False)])
    cache = ws.cache / "discovery" / "_verify.json"
    cache.parent.mkdir(parents=True)
    cache.write_text(json.dumps({"github.com/old/rules": _cached_verification(5)}))
    monkeypatch.setattr(discover, "verify", lambda *a: pytest.fail("positive cache should be reusable by provider id"))
    result = discover.run_discovery(ws, discover.DiscoveryOptions(strategies=()))
    assert len(load_sources(ws)) == 1 and not load_sources(ws)[0].enabled
    assert result.candidates[0].source == "old" and result.candidates[0].provider_id == "42"


def test_remote_download_shares_retry_policy_and_keeps_stale_content(tmp_path, monkeypatch):
    from sqlalchemy import select

    from sigharvest.models import Occurrence, Source
    from sigharvest.service import open_db, sync_all

    answers = [
        httpx.Response(429, headers={"retry-after": "bad"}),
        httpx.Response(200, content=b"logsource: {}\ndetection: {s: {a: b}, condition: s}\n"),
    ]

    def handler(r):
        return answers.pop(0) if answers else httpx.Response(503)

    seen = _mock(monkeypatch, handler)
    sleeps = []
    monkeypatch.setattr(sync_remote.time, "sleep", sleeps.append)
    ws = Workspace(tmp_path)
    save_sources(ws, [SourceConfig(name="remote", type="http-files", url="https://example.test/rule.yml")])
    open_db(ws, migrate=True)
    assert sync_all(ws)[0].status == "ok"
    assert len(seen) == 2 and len(sleeps) == 1
    with open_db(ws, migrate=True)() as s:
        previous = s.scalars(select(Source)).one().last_commit
    assert sync_all(ws)[0].status == "error"
    with open_db(ws, migrate=True)() as s:
        assert s.scalars(select(Source)).one().last_commit == previous
        assert s.scalars(select(Occurrence).where(Occurrence.present.is_(True))).one()
    assert len(seen) == 5 and len(sleeps) == 3


def test_redirects_consume_budget_and_strip_cross_origin_auth(tmp_path, monkeypatch):
    def handler(request):
        if request.url.host == "api.github.com":
            return httpx.Response(302, headers={"location": "https://gitlab.com/redirected"})
        return _json({"ok": True})

    seen = _mock(monkeypatch, handler)
    client = discover.CachedClient(tmp_path, token="dummy-token", max_requests=2)
    assert client.get("https://api.github.com/repos/old/name") == {"ok": True}
    assert client.http_attempts == 2 and len(seen) == 2
    assert "authorization" in seen[0].headers and "authorization" not in seen[1].headers
    client = discover.CachedClient(tmp_path / "limited", max_requests=1)
    with pytest.raises(discover.ApiError) as error:
        client.get("https://api.github.com/repos/old/name")
    assert error.value.category == "budget_exhausted" and client.http_attempts == 1


def test_duplicate_pages_cannot_claim_query_complete():
    q = DiscoveryCoverage().start("repos", "same results")
    q.page(1, total=2, ids=["42"])
    q.page(1, total=2, ids=["42"])
    q.finish()
    assert not q.complete and q.stop_reason == "duplicate_results"
