"""Discovery without the network: the cached HTTP client, every collection strategy, enrichment, the token lookup
and one full `run_discovery` whose API answers come from an httpx.MockTransport and whose clones come from local
git repositories (git `url.<file-uri>.insteadOf` rewrites the https URLs; conftest makes git refuse anything else).
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

import sigharvest.discover as discover_mod
from sigharvest.config import Workspace, load_sources, save_sources
from sigharvest.discover import (
    GITHUB_API,
    GITLAB_API,
    ApiError,
    CachedClient,
    Candidate,
    DiscoveryOptions,
    enrich,
    github_candidate,
    github_token,
    merge_candidate,
    mine_awesome,
    run_discovery,
    search_code,
    search_gitlab,
    search_repos,
)
from tests.test_pipeline import commit, git

Handler = Callable[[httpx.Request], httpx.Response]
RECENT = "2026-09-01T10:00:00Z"
_REAL_CLIENT = httpx.Client  # before any test patches it


def _mock(monkeypatch: pytest.MonkeyPatch, handler: Handler) -> list[httpx.Request]:
    """Route every httpx.Client created by discover.py through `handler`; returns the requests seen."""
    seen: list[httpx.Request] = []
    real = _REAL_CLIENT

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    def factory(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs["transport"] = httpx.MockTransport(record)
        return real(*args, **kwargs)

    monkeypatch.setattr(discover_mod.httpx, "Client", factory)
    return seen


def _client(tmp_path: Path, token: str | None = None, max_age: float = 3600) -> tuple[CachedClient, list[float]]:
    sleeps: list[float] = []
    return CachedClient(tmp_path / "cache", token=token, max_age=max_age, sleep=sleeps.append, jitter=lambda: 0.0), sleeps


def _json(body: Any, status: int = 200, **headers: str) -> httpx.Response:
    return httpx.Response(status, json=body, headers=headers)


def _noop(_msg: str) -> None:
    return None


# ------------------------------------------------------------------ CachedClient


def test_fresh_cache_entry_is_used_without_a_request(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _mock(monkeypatch, lambda r: _json({"n": 1}, etag='"v1"'))
    c, _ = _client(tmp_path)
    assert c.get(f"{GITHUB_API}/repos/a/b") == {"n": 1}
    assert c.get(f"{GITHUB_API}/repos/a/b") == {"n": 1}
    assert len(seen) == 1 and c.requests == 1 and c.cache_hits == 1


def test_stale_entry_is_revalidated_with_its_etag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        if r.headers.get("if-none-match") == '"v1"':
            return httpx.Response(304)
        return _json({"n": 1}, etag='"v1"')

    seen = _mock(monkeypatch, handler)
    c, _ = _client(tmp_path, max_age=0)
    assert c.get(f"{GITHUB_API}/repos/a/b") == {"n": 1}
    assert c.get(f"{GITHUB_API}/repos/a/b") == {"n": 1}  # 304: the cached body
    assert [r.headers.get("if-none-match") for r in seen] == [None, '"v1"']


def test_not_found_is_cached_and_raised_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _mock(monkeypatch, lambda r: _json({"message": "Not Found"}, 404))
    c, _ = _client(tmp_path)
    for _ in range(2):
        with pytest.raises(ApiError) as exc:
            c.get(f"{GITHUB_API}/repos/gone/repo")
        assert exc.value.status == 404
    assert len(seen) == 1 and c.cache_hits == 1
    # a stale cached 404 revalidated with 304 is still a 404
    entry = next((tmp_path / "cache").glob("*.json"))
    data = json.loads(entry.read_text())
    entry.write_text(json.dumps({**data, "etag": '"e"', "fetched_at": 0}))
    _mock(monkeypatch, lambda r: httpx.Response(304))
    with pytest.raises(ApiError):
        _client(tmp_path)[0].get(f"{GITHUB_API}/repos/gone/repo")


def test_server_errors_and_transport_errors_are_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    answers: list[Any] = [httpx.ConnectError("down"), _json({}, 502), _json({"ok": True})]

    def handler(r: httpx.Request) -> httpx.Response:
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a

    _mock(monkeypatch, handler)
    c, sleeps = _client(tmp_path)
    assert c.get(f"{GITHUB_API}/x") == {"ok": True}
    assert sleeps == [1, 2]  # exponential back-off, injected sleep
    assert c.requests == 2  # transport errors are not counted as requests


def test_a_gzip_answer_is_decoded_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import gzip

    body = gzip.compress(json.dumps({"total_count": 1, "items": []}).encode())
    headers = {"content-encoding": "gzip", "content-type": "application/json; charset=utf-8"}
    _mock(monkeypatch, lambda r: httpx.Response(200, headers=headers, stream=httpx.ByteStream(body)))
    c, sleeps = _client(tmp_path)
    assert c.get(f"{GITHUB_API}/search/repositories?q=x") == {"total_count": 1, "items": []} and sleeps == []


def test_a_body_that_does_not_match_its_encoding_is_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    broken = httpx.Response(200, headers={"content-encoding": "gzip", "content-type": "application/json"}, stream=httpx.ByteStream(b"not gzip"))
    answers = [broken, _json({"ok": True})]
    _mock(monkeypatch, lambda r: answers.pop(0))
    c, sleeps = _client(tmp_path)
    assert c.get(f"{GITHUB_API}/x") == {"ok": True} and sleeps == [1]


def test_persistent_failure_gives_up_with_599(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _mock(monkeypatch, lambda r: _json({}, 500))
    c, sleeps = _client(tmp_path)
    with pytest.raises(ApiError) as exc:
        c.get(f"{GITHUB_API}/x")
    assert exc.value.status == 599 and len(sleeps) == 7
    _mock(monkeypatch, lambda r: _json({}, 401))
    with pytest.raises(ApiError) as exc:
        _client(tmp_path)[0].get(f"{GITHUB_API}/y")
    assert exc.value.status == 401  # other client errors are not retried (and not cached)


def test_rate_limits_are_honoured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    reset = str(int(time.time()) + 30)
    answers = [
        _json({}, 403, **{"retry-after": "7"}),
        _json({}, 429, **{"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset}),
        _json({"ok": 1}, 200, **{"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset}),
    ]
    _mock(monkeypatch, lambda r: answers.pop(0))
    c, sleeps = _client(tmp_path)
    assert c.get(f"{GITHUB_API}/rate") == {"ok": 1}
    assert sleeps[0] == 7.0
    assert 1.0 <= sleeps[1] <= 32 and len(sleeps) == 2  # no sleep after a successful final response
    assert c.requests == 3


def test_raw_text_and_authorization_only_for_the_github_api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        if r.url.host == "gitlab.com":
            return httpx.Response(200, text="plain", headers={"content-type": "text/plain"})
        return httpx.Response(200, text="# README", headers={"content-type": "application/json"})

    seen = _mock(monkeypatch, handler)
    c, _ = _client(tmp_path, token="secret-token")
    assert c.get(f"{GITHUB_API}/repos/a/b/readme", accept="application/vnd.github.raw") == "# README"
    assert c.get(f"{GITLAB_API}/projects/x") == "plain"  # not JSON: kept as text
    assert seen[0].headers["authorization"] == "Bearer secret-token"
    assert seen[0].headers["accept"] == "application/vnd.github.raw"
    assert "authorization" not in seen[1].headers
    c.close()


def test_code_search_calls_are_spaced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _mock(monkeypatch, lambda r: _json({"items": [], "total_count": 0}))
    c, sleeps = _client(tmp_path)
    c.get(f"{GITHUB_API}/search/code?q=a")
    c.get(f"{GITHUB_API}/search/code?q=b")
    assert len(sleeps) == 1 and 0 < sleeps[0] <= 6.2


# ------------------------------------------------------------------ strategies


def _repo_item(full_name: str, **extra: Any) -> dict[str, Any]:
    return {
        "full_name": full_name,
        "stargazers_count": 3,
        "size": 120,
        "default_branch": "main",
        "pushed_at": RECENT,
        "license": {"spdx_id": "MIT"},
        "fork": False,
        "description": "rules",
        **extra,
    }


def test_search_code_slices_large_results_and_respects_the_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discover_mod, "CODE_PATHS", [""])
    monkeypatch.setattr(discover_mod, "CODE_KEYWORDS", [""])
    monkeypatch.setattr(discover_mod, "CODE_EXTENSIONS", ["yml"])

    def handler(r: httpx.Request) -> httpx.Response:
        q = r.url.params["q"]
        if "size:>5000" in q:
            return _json({"message": "Validation Failed"}, 422)
        items = [{"repository": {"full_name": f"o{len(q)}/r{i}", "fork": i == 0, "description": "d"}} for i in range(3)]
        items.append({"repository": {}})  # no full name: skipped
        return _json({"items": items, "total_count": 1500 if "size:" not in q else 10})

    seen = _mock(monkeypatch, handler)
    c, _ = _client(tmp_path)
    pool: dict[str, Candidate] = {}
    msgs: list[str] = []
    used = search_code(c, pool, max_requests=100, progress=msgs.append)
    queries = [r.url.params["q"] for r in seen]
    assert queries[0] == "logsource detection condition extension:yml"
    assert len(queries) == 9 and all("size:" in q for q in queries[1:])  # 8 size slices of the large query
    assert used == 9  # failed queries consume the budget too
    assert all("code_search" in x.strategies and x.code_hits >= 1 for x in pool.values())
    assert any(x.fork for x in pool.values()) and "1500 files" in msgs[0]

    pool2: dict[str, Candidate] = {}
    assert search_code(_client(tmp_path / "b")[0], pool2, max_requests=2, progress=_noop) == 2


def test_search_repos_topics_and_keywords(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discover_mod, "TOPICS", ["sigma", "broken"])
    monkeypatch.setattr(discover_mod, "REPO_KEYWORDS", ["sigma-rules"])

    def handler(r: httpx.Request) -> httpx.Response:
        q = r.url.params["q"]
        if q == "topic:broken":
            return _json({}, 422)
        if q.startswith("topic:"):
            page = int(r.url.params["page"])
            items = [_repo_item(f"topic/r{page}-{i}") for i in range(100 if page == 1 else 2)]
            return _json({"items": items, "total_count": 102})
        return _json({"items": [_repo_item("topic/r1-0"), _repo_item("kw/one", fork=True, parent={"full_name": "up/one"})], "total_count": 2})

    _mock(monkeypatch, handler)
    pool: dict[str, Candidate] = {}
    search_repos(_client(tmp_path)[0], pool, _noop)
    assert len(pool) == 103
    both = pool["github.com/topic/r1-0"]
    assert both.strategies == ["topic", "keyword"] and both.licence == "MIT" and both.pushed_at == RECENT
    fork = pool["github.com/kw/one"]
    assert fork.fork and fork.parent == "up/one"


def test_mine_awesome_lists_github_and_gitlab_links(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discover_mod, "AWESOME_LISTS", ["good/list", "gone/list"])
    monkeypatch.setattr(discover_mod, "SIGMAHQ_SITE_FILES", ["README.md", "missing.md"])
    readme = "- [a](https://github.com/acme/rules)\n- [b](https://gitlab.com/grp/sub/proj/-/tree/main)\n- https://github.com/features/x\n"

    def handler(r: httpx.Request) -> httpx.Response:
        path = r.url.path
        if "gone" in path or "missing" in path:
            return _json({}, 404)
        if "sigmahq.github.io" in path:
            return httpx.Response(200, text="see https://github.com/siteowner/rules", headers={"content-type": "text/plain"})
        return httpx.Response(200, text=readme, headers={"content-type": "text/plain"})

    _mock(monkeypatch, handler)
    pool: dict[str, Candidate] = {}
    search_msgs: list[str] = []
    mine_awesome(_client(tmp_path)[0], pool, search_msgs.append)
    assert set(pool) == {"github.com/acme/rules", "gitlab.com/grp/sub/proj", "github.com/siteowner/rules"}
    assert pool["gitlab.com/grp/sub/proj"].host == "gitlab" and pool["gitlab.com/grp/sub/proj"].url == "https://gitlab.com/grp/sub/proj.git"
    assert pool["github.com/siteowner/rules"].strategies == ["sigmahq_site"]
    assert pool["github.com/acme/rules"].strategies == ["awesome_list"]


def test_search_gitlab_projects_and_forks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discover_mod, "GITLAB_QUERIES", ["sigma rules"])

    def handler(r: httpx.Request) -> httpx.Response:
        if r.url.params.get("topic") == "sigma":
            return _json({"message": "odd"})  # not a list: ignored
        if r.url.params.get("topic"):
            return _json({}, 404)
        if r.url.params.get("page") != "1":
            return _json([])
        return _json(
            [
                {"path_with_namespace": "grp/rules", "star_count": 4, "default_branch": "main", "last_activity_at": RECENT, "description": "x" * 400},
                {"path_with_namespace": "me/fork", "forked_from_project": {"path_with_namespace": "grp/rules"}},
                {"name": "no path"},
            ]
        )

    _mock(monkeypatch, handler)
    pool: dict[str, Candidate] = {}
    search_gitlab(_client(tmp_path)[0], pool, _noop)
    assert set(pool) == {"gitlab.com/grp/rules", "gitlab.com/me/fork"}
    rules = pool["gitlab.com/grp/rules"]
    assert rules.stars == 4 and rules.pushed_at == RECENT and rules.description is not None and len(rules.description) == 300
    fork = pool["gitlab.com/me/fork"]
    assert fork.fork and fork.parent == "grp/rules" and fork.description is None


def test_enrich_follows_renames_and_records_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        path = r.url.path
        if path.endswith("/repos/old/name"):
            return _json(_repo_item("new/name"))
        if path.endswith("/repos/alias/dup"):
            return _json(_repo_item("Real/Repo"))
        if path.endswith("/repos/gone/repo"):
            return _json({}, 404)
        if path.endswith("/repos/odd/repo"):
            return _json({}, 422)
        if "/projects/" in path:
            return _json({"license": {"key": "mit"}, "star_count": 9})
        raise AssertionError(f"unexpected request {r.url}")

    seen = _mock(monkeypatch, handler)
    pool: dict[str, Candidate] = {}
    real = merge_candidate(pool, github_candidate("Real/Repo", "topic"))
    real.pushed_at, real.size_kb = RECENT, 10  # complete metadata: not fetched again
    cands = [merge_candidate(pool, github_candidate(n, "code_search")) for n in ("old/name", "alias/dup", "gone/repo", "odd/repo")]
    gl = merge_candidate(pool, Candidate(url="https://gitlab.com/grp/rules.git", full_name="grp/rules", host="gitlab"))
    enrich(_client(tmp_path)[0], pool, [real, *cands, gl])
    renamed, dup, gone, odd = cands
    assert "github.com/new/name" in pool and "github.com/old/name" not in pool and renamed.full_name == "new/name"
    assert dup.reason == "duplicate of Real/Repo" and pool["github.com/real/repo"] is real
    assert gone.reason is not None and gone.reason.startswith("not found")
    assert odd.reason == "metadata error 422"
    assert gl.licence == "MIT" and gl.stars == 9
    assert not any(r.url.path.endswith("/repos/Real/Repo") for r in seen)


def test_github_token_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", " tok-env \n")
    assert github_token() == "tok-env"
    monkeypatch.delenv("GITHUB_TOKEN")

    def missing(*a: Any, **k: Any) -> Any:
        raise FileNotFoundError("gh")

    monkeypatch.setattr(discover_mod.subprocess, "run", missing)
    assert github_token() is None
    monkeypatch.setattr(discover_mod.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "not logged in"))
    assert github_token() is None
    monkeypatch.setattr(discover_mod.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, "tok-gh\n", ""))
    assert github_token() == "tok-gh"


# ------------------------------------------------------------------ run_discovery end to end


def _rule(tag: str) -> str:
    return (
        f"title: Rule {tag}\nlogsource:\n  product: windows\n  category: process_creation\n"
        f"detection:\n  selection:\n    Image|endswith: '\\\\{tag}.exe'\n  condition: selection\nlevel: high\n"
    )


def _local_repo(root: Path, name: str, files: dict[str, str]) -> Path:
    repo = root / name.replace("/", "__")
    repo.mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    commit(repo, "init")
    return repo


def _offline_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Workspace:
    """Local git repositories behind github.com URLs and a mocked GitHub API (requests must carry the token)."""
    sigma_rules = {f"rules/windows/s{i}.yml": _rule(f"s{i}") for i in range(5)}
    repos = {
        "acme/rules": {**{f"detections/sigma/a{i}.yml": _rule(f"a{i}") for i in range(6)}, "README.md": "# acme\n"},
        "SigmaHQ/sigma": sigma_rules,
        "mirror/copy": dict(list(sigma_rules.items())[:4]),
        "small/one": {"one.yml": _rule("only")},
    }
    remote = tmp_path / "remote"
    paths = {name: _local_repo(remote, name, files) for name, files in repos.items()}
    monkeypatch.setenv("GIT_CONFIG_COUNT", str(len(paths)))
    for i, (name, path) in enumerate(paths.items()):
        monkeypatch.setenv(f"GIT_CONFIG_KEY_{i}", f"url.{path.resolve().as_uri()}.insteadOf")
        monkeypatch.setenv(f"GIT_CONFIG_VALUE_{i}", f"https://github.com/{name}.git")
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(discover_mod, "SEEDS", [("acme/rules", "seed")])
    monkeypatch.setattr(discover_mod, "AWESOME_LISTS", ["x/awesome"])
    monkeypatch.setattr(discover_mod, "SIGMAHQ_SITE_FILES", [])
    monkeypatch.setattr(discover_mod, "TOPICS", ["sigma"])
    monkeypatch.setattr(discover_mod, "REPO_KEYWORDS", [])
    monkeypatch.setattr(discover_mod, "CODE_PATHS", [""])
    monkeypatch.setattr(discover_mod, "CODE_KEYWORDS", [""])
    monkeypatch.setattr(discover_mod, "CODE_EXTENSIONS", ["yml"])
    monkeypatch.setattr(discover_mod, "MIN_FREE_BYTES", 0)

    def handler(r: httpx.Request) -> httpx.Response:
        path = r.url.path
        assert r.headers.get("authorization") == "Bearer test-token"
        if path.endswith("/repos/x/awesome/readme"):
            return httpx.Response(200, text="* https://github.com/SigmaHQ/sigma\n", headers={"content-type": "text/plain"})
        if path.endswith("/search/repositories"):
            return _json({"items": [_repo_item("mirror/copy"), _repo_item("small/one", license=None)], "total_count": 2})
        if path.endswith("/search/code"):
            return _json({"items": [{"repository": {"full_name": "gone/repo"}}], "total_count": 1})
        if path.endswith("/repos/gone/repo"):
            return _json({}, 404)
        for name in ("acme/rules", "SigmaHQ/sigma"):
            if path.endswith(f"/repos/{name}"):
                return _json(_repo_item(name, license={"spdx_id": "DRL-1.1" if "sigma" in name else "MIT"}))
        raise AssertionError(f"unexpected request {r.url}")

    _mock(monkeypatch, handler)
    ws = Workspace(tmp_path / "ws")
    ws.root.mkdir()
    save_sources(ws, [])
    return ws


def test_run_discovery_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = _offline_world(tmp_path, monkeypatch)
    opts = DiscoveryOptions(min_rules=3, top=2, workers=2, max_code_requests=1, strategies=("awesome", "repos", "code"))
    rep = run_discovery(ws, opts, progress=_noop)

    by_name = {c.full_name: c for c in rep.candidates}
    assert {n: c.valid_rule_count for n, c in by_name.items()} == {
        "acme/rules": 6,
        "SigmaHQ/sigma": 5,
        "mirror/copy": 4,
        "small/one": 1,
        "gone/repo": 0,
    }
    assert by_name["mirror/copy"].mirror_of == "SigmaHQ/sigma" and by_name["mirror/copy"].reference_overlap == 1.0
    assert by_name["acme/rules"].sigma_paths == ["detections/sigma/*"] and by_name["acme/rules"].sigmahq_overlap == 0.0
    assert by_name["small/one"].status == "manual_review" and by_name["gone/repo"].status == "rejected"
    assert [c.full_name for c in rep.top] == ["acme/rules", "SigmaHQ/sigma"]
    assert rep.per_strategy == {"seed": 1, "awesome_list": 1, "topic": 2, "code_search": 1}

    sources = {s.name: s for s in load_sources(ws)}
    assert set(sources) == {"acme__rules", "sigmahq__sigma", "mirror__copy"}  # small/one is below --min-rules
    assert sources["acme__rules"].enabled and sources["acme__rules"].priority == discover_mod.PRIORITY_SEED
    assert sources["sigmahq__sigma"].enabled and sources["sigmahq__sigma"].licence == "DRL-1.1"
    assert not sources["mirror__copy"].enabled and "mirror of SigmaHQ/sigma" in (sources["mirror__copy"].notes or "")
    assert sources["acme__rules"].paths == ["detections/sigma/*"]
    doc = yaml.safe_load((ws.root / "discovery" / "candidates.yaml").read_text())
    assert doc["summary"]["candidates"] == 5 and doc["summary"]["auto_added"] == 3
    top = (ws.root / "discovery" / "top100.md").read_text()
    assert "[acme/rules](https://github.com/acme/rules)" in top and "seed" in top

    # second run: HTTP answers and verifications come from the caches; nothing is cloned again
    clones: list[str] = []
    real_clone = discover_mod.clone

    def counting_clone(url: str, dest: Path, timeout: int = 900) -> str:
        clones.append(url)
        return real_clone(url, dest, timeout)

    monkeypatch.setattr(discover_mod, "clone", counting_clone)
    rep2 = run_discovery(ws, opts, progress=_noop)
    assert clones == [] and rep2.requests == 0 and rep2.cache_hits > 0
    assert {c.full_name: c.valid_rule_count for c in rep2.candidates} == {n: c.valid_rule_count for n, c in by_name.items()}
    assert rep2.added == [] and set(s.name for s in load_sources(ws)) == set(sources)

    # --output writes a separate, all-disabled sources file and never edits sources.yaml; --known and
    # --denylist leave out repositories that are already curated or refused.
    before = ws.sources_file.read_bytes()
    known = tmp_path / "known.yaml"
    known.write_text(yaml.safe_dump({"sources": [{"name": "curated-acme", "url": "https://github.com/acme/rules.git"}]}))
    deny = tmp_path / "deny.yaml"
    deny.write_text(yaml.safe_dump(["nobody__else"]))
    out = tmp_path / "discovered.yaml"
    report_file = tmp_path / "report.md"
    from dataclasses import replace

    rep3 = run_discovery(ws, replace(opts, output=out, known=known, denylist=deny, report_file=report_file), progress=_noop)
    assert ws.sources_file.read_bytes() == before
    written = yaml.safe_load(out.read_text())["sources"]
    assert [s["name"] for s in written] == rep3.added == ["sigmahq__sigma"]  # acme is known, the mirror and small/one are left out
    assert all(s["enabled"] is False and s["tier"] == "discovered" for s in written)
    assert "Top" in report_file.read_text()
    deny.write_text(yaml.safe_dump(["https://github.com/SigmaHQ/sigma"]))
    run_discovery(ws, replace(opts, output=out, known=known, denylist=deny), progress=_noop)
    assert yaml.safe_load(out.read_text())["sources"] == []


def test_two_step_discovery_keeps_the_token_out_of_the_cloning_step(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """--collect-only uses the API token and clones nothing; --candidates clones and verifies with no
    token in the environment and no API request at all."""
    ws = _offline_world(tmp_path, monkeypatch)
    clones: list[str] = []
    real_clone = discover_mod.clone

    def counting_clone(url: str, dest: Path, timeout: int = 900) -> str:
        clones.append(url)
        assert "GITHUB_TOKEN" not in os.environ
        return real_clone(url, dest, timeout)

    monkeypatch.setattr(discover_mod, "clone", counting_clone)
    base = DiscoveryOptions(min_rules=3, top=2, workers=2, max_code_requests=1, strategies=("awesome", "repos", "code"))
    from dataclasses import replace

    first = run_discovery(ws, replace(base, collect_only=True), progress=_noop)
    assert clones == [] and first.verified == 0 and first.added == []
    candidates = ws.root / "discovery" / "candidates.yaml"
    assert {c["full_name"] for c in yaml.safe_load(candidates.read_text())["candidates"]} >= {"acme/rules", "SigmaHQ/sigma"}

    monkeypatch.delenv("GITHUB_TOKEN")
    monkeypatch.setattr(discover_mod, "github_token", lambda: pytest.fail("the verify step must not look for a token"))
    second = run_discovery(ws, replace(base, candidates=candidates), progress=_noop)
    assert second.requests == 0 and clones
    counts = {c.full_name: c.valid_rule_count for c in second.candidates}
    assert counts["acme/rules"] == 6 and counts["SigmaHQ/sigma"] == 5 and counts["mirror/copy"] == 4
    assert {s.name for s in load_sources(ws)} == {"acme__rules", "sigmahq__sigma", "mirror__copy"}


def test_discovery_caches_survive_a_backward_clock_step(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A second run right after the wall clock stepped back still answers from the HTTP and verification caches."""
    import time

    ws = _offline_world(tmp_path, monkeypatch)
    opts = DiscoveryOptions(min_rules=3, top=2, workers=2, max_code_requests=1, strategies=("awesome", "repos", "code"))
    run_discovery(ws, opts, progress=_noop)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() - 90.0)
    clones: list[str] = []
    real_clone = discover_mod.clone
    monkeypatch.setattr(discover_mod, "clone", lambda url, dest, timeout=900: clones.append(url) or real_clone(url, dest, timeout))
    rep = run_discovery(ws, opts, progress=_noop)
    assert clones == [] and rep.requests == 0 and rep.cache_hits > 0


def test_an_offline_run_stops_after_the_first_query(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Offline, every query retried with backoff (about 90 s each): `discover` stayed silent for over an hour. When
    the first query never connects, the run stops with one clear error; a later blip stays a retried query."""
    from sigharvest.discovery_http import Unreachable

    def down(r: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("[Errno -3] Temporary failure in name resolution")

    _mock(monkeypatch, down)
    c, sleeps = _client(tmp_path)
    with pytest.raises(Unreachable, match=r"cannot reach api\.github\.com: discovery needs the network"):
        c.get(f"{GITHUB_API}/x")
    assert len(sleeps) == 7  # the first query is still retried (a blip at start is not an outage)


def test_a_connect_error_after_an_answer_is_a_failed_query_not_an_outage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest.discovery_http import ApiError

    answers: list[Any] = [_json({"ok": True})]

    def handler(r: httpx.Request) -> httpx.Response:
        if answers:
            return answers.pop(0)
        raise httpx.ConnectError("down")

    _mock(monkeypatch, handler)
    c, _ = _client(tmp_path)
    assert c.get(f"{GITHUB_API}/a") == {"ok": True}
    with pytest.raises(ApiError):
        c.get(f"{GITHUB_API}/b")
