"""Offline failure injection at source acquisition, ingest and acknowledgement boundaries."""

import json
import shutil

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from typer.testing import CliRunner

from sigharvest import publication, source_snapshots, sync
from sigharvest.cli import app
from sigharvest.config import SourceConfig, load_sources, save_sources
from sigharvest.db import get_meta
from sigharvest.ingest import Ingestor
from sigharvest.models import Occurrence, Quarantine, RuleVersion, Source
from sigharvest.service import fetch_source, open_db, sync_all
from sigharvest.source_snapshots import ACTIVE_PREFIX, CONFIG_PREFIX, config_fingerprint, load_snapshot
from tests.test_pipeline import RULE, UIDS, commit, make_repo, workspace
from tests.test_sync_http import serve, zip_bytes


def state(ws):
    with open_db(ws, migrate=True)() as s:
        src = s.scalars(select(Source)).one()
        return {
            "active": get_meta(s, ACTIVE_PREFIX + src.name),
            "config": get_meta(s, CONFIG_PREFIX + src.name),
            "source": (src.last_commit, src.last_sync_at, src.url, src.priority),
            "versions": s.scalar(select(func.count()).select_from(RuleVersion)),
            "occurrences": list(s.execute(select(Occurrence.path, Occurrence.version_id, Occurrence.present).order_by(Occurrence.id))),
            "quarantine": list(s.execute(select(Quarantine.path, Quarantine.present).order_by(Quarantine.id))),
        }


@pytest.mark.parametrize("kind", ["git", "local", "http", "http-files"])
def test_globs_narrow_and_widen_offline(tmp_path, monkeypatch, kind):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    cfg = load_sources(ws)[0]
    cfg.type = kind
    if kind == "http":
        cfg.url = "https://example.org/rules.zip"
        serve(monkeypatch, lambda r: httpx.Response(200, content=zip_bytes({p.name: p.read_bytes() for p in (repo / "rules").iterdir()})))
    elif kind == "http-files":
        cfg.url = "https://example.org/rules.yml"
        serve(monkeypatch, lambda r: httpx.Response(200, content=(repo / "rules/a.yml").read_bytes()))
    cfg.paths = ["**/*"]
    save_sources(ws, [cfg])
    assert sync_all(ws)[0].status == "ok"
    original = state(ws)
    original_files = load_snapshot(ws, cfg).hashes
    # Every cached acquisition remains independently readable after promotion.
    first = original["active"]
    cfg.paths = ["nothing/*"]
    save_sources(ws, [cfg])
    shutil.rmtree(repo)
    monkeypatch.setattr(sync, "_git", lambda *a, **k: pytest.fail("rescan invoked Git"))
    monkeypatch.setattr(httpx, "Client", lambda *a, **k: pytest.fail("rescan invoked HTTP"))
    assert sync_all(ws, rescan=True)[0].status == "ok"
    assert not any(o[2] for o in state(ws)["occurrences"])
    cfg.paths = ["**/*"]
    save_sources(ws, [cfg])
    assert sync_all(ws, rescan=True)[0].status == "ok"
    assert state(ws)["occurrences"] == original["occurrences"]
    assert load_snapshot(ws, cfg, first).hashes == original_files


def test_parser_change_forces_full_scan_without_head_change(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    before = state(ws)
    monkeypatch.setattr(source_snapshots, "ingest_policy", lambda: "new-parser-policy")
    result = sync_all(ws, remote_check=True)[0]
    assert result.status == "ok" and result.log.files_added == 5
    assert state(ws)["config"] != before["config"]
    assert state(ws)["source"][0] == before["source"][0]
    assert state(ws)["versions"] == before["versions"]


def test_fingerprint_ignores_credentials_and_metadata(tmp_path, monkeypatch):
    cfg = SourceConfig(name="test", type="local", url=str(tmp_path), auth="TEST_SOURCE_TOKEN")
    first = config_fingerprint(cfg)
    monkeypatch.setenv("TEST_SOURCE_TOKEN", "dummy-secret")
    cfg.priority, cfg.licence = 3, "MIT"
    assert config_fingerprint(cfg) == first
    cfg.exclude = ["test/*"]
    assert config_fingerprint(cfg) != first


def test_cached_origin_changes_and_incomplete_clone_restarts(tmp_path):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    cache = ws.git_repo("local")
    cache.mkdir(parents=True)
    (cache / "partial-download").write_text("interrupted clone")
    assert sync_all(ws)[0].status == "ok"
    other = tmp_path / "renamed-upstream"
    repo.rename(other)
    cfg = load_sources(ws)[0]
    cfg.url = str(other)
    save_sources(ws, [cfg])
    assert sync_all(ws, remote_check=True)[0].status == "ok"
    assert sync._git(["remote", "get-url", "origin"], cwd=cache).strip() == str(other)
    assert state(ws)["source"][2] == str(other)


def test_missing_eligible_git_blob_preserves_active_source(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    before = state(ws)
    (repo / "rules/a.yml").write_text(RULE.format(n="changed", uid=UIDS[1]))
    commit(repo, "change")
    monkeypatch.setattr(sync, "_read_blobs", lambda *a: {})
    result = sync_all(ws)[0]
    assert result.status == "error" and "eligible Git blob is missing" in result.message
    assert state(ws) == before


@pytest.mark.parametrize("kind", ["git", "http"])
def test_fetch_before_ingest_crash_recovers_without_network(tmp_path, monkeypatch, kind):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    cfg = load_sources(ws)[0]
    cfg.type = kind
    payload = {"body": zip_bytes({"rules/a.yml": (repo / "rules/a.yml").read_bytes()})}
    if kind == "http":
        cfg.url = "https://example.org/rules.zip"
        serve(monkeypatch, lambda r: httpx.Response(200, content=payload["body"]))
    save_sources(ws, [cfg])
    assert sync_all(ws)[0].status == "ok"
    before = state(ws)
    (repo / "rules/a.yml").unlink()
    (repo / "rules/new.yml").write_text(RULE.format(n="new", uid=UIDS[0]))
    commit(repo, "new generation")
    payload["body"] = zip_bytes({"rules/new.yml": (repo / "rules/new.yml").read_bytes()})
    fetched = fetch_source(ws, cfg, before["source"][0], {})
    assert fetched.snapshot_id != before["active"]
    assert state(ws) == before
    shutil.rmtree(repo)
    monkeypatch.setattr(httpx, "Client", lambda *a, **k: pytest.fail("network"))
    result = sync_all(ws, rescan=True)[0]
    assert result.status == "ok", result.message
    current = state(ws)
    assert current["active"] == fetched.snapshot_id
    assert not next(o[2] for o in current["occurrences"] if o[0] == "rules/a.yml")
    assert any(o[2] for o in current["occurrences"] if o[0] == "rules/new.yml")


def test_http_retry_diffs_database_not_unaccepted_fetch(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    cfg = SourceConfig(name="local", type="http", url="https://example.org/rules.zip")
    save_sources(ws, [cfg])
    payload = {"body": zip_bytes({"a.yml": (repo / "rules/a.yml").read_bytes()})}
    serve(monkeypatch, lambda r: httpx.Response(200, content=payload["body"]))
    assert sync_all(ws)[0].status == "ok"
    before = state(ws)
    payload["body"] = zip_bytes({"b.yml": (repo / "rules/b.yml").read_bytes()})
    fetch_source(ws, cfg, before["source"][0], {})
    result = sync_all(ws)[0]
    assert result.status == "ok" and result.log.files_removed == 1 and result.log.files_added == 1
    assert [o[0] for o in state(ws)["occurrences"] if o[2]] == ["b.yml"]


@pytest.mark.parametrize("failure", ["disk", "sql"])
@pytest.mark.slow
def test_failure_after_file_501_keeps_previous_source_and_reader_view(tmp_path, monkeypatch, failure):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    before = state(ws)
    (repo / "rules/a.yml").unlink()
    cfg = load_sources(ws)[0]
    cfg.priority = 1
    save_sources(ws, [cfg])
    for i in range(503):
        (repo / f"rules/new-{i:04d}.yml").write_text(RULE.format(n="new", uid=UIDS[0]))
    commit(repo, "large update")
    original = Ingestor.ingest_file
    calls = 0

    def fail(self, root, rel):
        nonlocal calls
        calls += 1
        original(self, root, rel)
        if calls == 501:
            assert state(ws) == before  # Independent reader still sees accepted data.
            if failure == "sql":
                raise OperationalError("fixture", {}, RuntimeError("database full"))
            raise OSError("disk failure after file 501")

    monkeypatch.setattr(Ingestor, "ingest_file", fail)
    result = sync_all(ws)[0]
    assert result.status == "error" and calls == 501
    assert state(ws) == before
    assert load_snapshot(ws, cfg).generation != before["active"]
    monkeypatch.setattr(Ingestor, "ingest_file", original)
    assert sync_all(ws, rescan=True)[0].status == "ok"
    assert state(ws)["source"][3] == 1
    assert not next(o[2] for o in state(ws)["occurrences"] if o[0] == "rules/a.yml")


def test_sql_error_is_not_a_bad_document(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    before = state(ws)

    def fail(*args):
        raise OperationalError("fixture", {}, RuntimeError("storage failure"))

    monkeypatch.setattr(Ingestor, "_version_id", fail)
    assert sync_all(ws, rescan=True)[0].status == "error"
    assert state(ws) == before


def test_failed_http_directory_publication_keeps_cache_and_active(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    cfg = SourceConfig(name="local", type="http", url="https://example.org/rules.zip")
    save_sources(ws, [cfg])
    payload = {"body": zip_bytes({"a.yml": (repo / "rules/a.yml").read_bytes()})}
    serve(monkeypatch, lambda r: httpx.Response(200, content=payload["body"]))
    assert sync_all(ws)[0].status == "ok"
    before = state(ws)
    old_bytes = (ws.source_dir("local") / "a.yml").read_bytes()
    payload["body"] = zip_bytes({"b.yml": (repo / "rules/b.yml").read_bytes()})

    def fail(*args):
        raise OSError("injected rename failure")

    monkeypatch.setattr(publication, "_promote", fail)
    assert sync_all(ws)[0].status == "error"
    assert state(ws) == before
    assert (ws.source_dir("local") / "a.yml").read_bytes() == old_bytes
    assert load_snapshot(ws, cfg).generation == before["active"]


@pytest.mark.parametrize("damage", ["blob", "manifest", "missing", "symlink"])
def test_rescan_rejects_damaged_snapshot_without_retiring_data(tmp_path, damage):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    before = state(ws)
    cfg = load_sources(ws)[0]
    snapshot = load_snapshot(ws, cfg)
    path = snapshot.root / "rules/a.yml"
    if damage == "blob":
        path.write_bytes(b"corrupt")
    elif damage == "manifest":
        (snapshot.root.parent / "manifest.json").write_text(json.dumps({"files": {"../escape": {}}}))
    else:
        path.unlink()
        if damage == "symlink":
            path.symlink_to(repo / "rules/a.yml")
    result = sync_all(ws, rescan=True)[0]
    assert result.status == "error"
    assert state(ws) == before


def test_rescan_refuses_changed_origin_and_missing_cache(tmp_path):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws, rescan=True)[0].status == "error"
    assert sync_all(ws)[0].status == "ok"
    cfg = load_sources(ws)[0]
    cfg.url = str(tmp_path / "another")
    save_sources(ws, [cfg])
    before = state(ws)
    assert sync_all(ws, rescan=True)[0].status == "error"
    assert state(ws) == before


def test_rescan_cli_and_incompatible_remote_check(tmp_path):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    shutil.rmtree(repo)
    runner = CliRunner()
    env = {"SIGHARVEST_HOME": str(ws.root)}
    result = runner.invoke(app, ["sync", "--rescan", "--source", "local"], env=env)
    assert result.exit_code == 0, result.output
    result = runner.invoke(app, ["sync", "--rescan", "--remote-check"], env=env)
    assert result.exit_code == 2, result.output


@pytest.mark.parametrize("kind", ["local", "http", "http-files"])
def test_normal_sync_reconciles_changed_selection_at_same_revision(tmp_path, monkeypatch, kind):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    cfg = load_sources(ws)[0]
    cfg.type = kind
    if kind == "http":
        cfg.url = "https://example.org/rules.zip"
        # Reuse identical archive bytes: ZIP timestamps otherwise change the revision between requests.
        archive = zip_bytes({"rules/a.yml": (repo / "rules/a.yml").read_bytes()})
        serve(monkeypatch, lambda r: httpx.Response(200, content=archive))
    elif kind == "http-files":
        cfg.url = "https://example.org/rules.yml"
        serve(monkeypatch, lambda r: httpx.Response(200, content=(repo / "rules/a.yml").read_bytes()))
    cfg.paths = ["**/*"]
    save_sources(ws, [cfg])
    assert sync_all(ws)[0].status == "ok"
    before = state(ws)
    cfg.exclude = ["*"]
    save_sources(ws, [cfg])
    assert sync_all(ws)[0].status == "ok"
    assert state(ws)["source"][0] == before["source"][0]
    assert not any(o[2] for o in state(ws)["occurrences"])
    cfg.exclude = []
    save_sources(ws, [cfg])
    assert sync_all(ws)[0].status == "ok"
    assert state(ws)["occurrences"] == before["occurrences"]


@pytest.mark.parametrize("damage", ["missing", "changed"])
def test_materialized_git_cache_damage_is_not_upstream_change(tmp_path, damage):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    before = state(ws)
    path = ws.source_dir("local") / "rules/a.yml"
    if damage == "missing":
        path.unlink()
    else:
        path.write_text("wrong cached content")
    assert sync_all(ws)[0].status == "ok"
    assert state(ws)["occurrences"] == before["occurrences"]
    assert state(ws)["active"] == before["active"]
    assert path.read_bytes() == (repo / "rules/a.yml").read_bytes()


@pytest.mark.parametrize("limit", ["MAX_SNAPSHOT_BYTES", "MAX_SNAPSHOT_FILES", "MAX_MANIFEST_BYTES"])
def test_snapshot_budget_failure_does_not_acknowledge(tmp_path, monkeypatch, limit):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    before = state(ws)
    (repo / "rules/new.yml").write_text(RULE.format(n="new", uid=UIDS[0]))
    commit(repo, "exceed test budget")
    monkeypatch.setattr(source_snapshots, limit, 1)
    assert sync_all(ws)[0].status == "error"
    assert state(ws) == before


def test_final_acknowledgement_failure_rolls_back_membership(tmp_path, monkeypatch):
    from sigharvest import service

    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    before = state(ws)
    (repo / "rules/a.yml").unlink()
    commit(repo, "delete a")
    original = service.set_meta

    def fail(session, key, value):
        if key.startswith(ACTIVE_PREFIX):
            raise OperationalError("fixture", {}, RuntimeError("acknowledgement failure"))
        original(session, key, value)

    monkeypatch.setattr(service, "set_meta", fail)
    assert sync_all(ws)[0].status == "error"
    assert state(ws) == before


def test_local_symlinks_are_not_copied_into_snapshots(tmp_path):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    cfg = load_sources(ws)[0]
    cfg.type = "local"
    save_sources(ws, [cfg])
    outside = tmp_path / "outside.yml"
    outside.write_text(RULE.format(n="outside", uid=UIDS[0]))
    (repo / "rules/link.yml").symlink_to(outside)
    assert sync_all(ws)[0].status == "ok"
    assert "rules/link.yml" not in load_snapshot(ws, cfg).hashes
    assert not any(o[0] == "rules/link.yml" for o in state(ws)["occurrences"])


@pytest.mark.parametrize("kind", ["git", "local"])
def test_non_portable_upstream_name_skips_only_that_file(tmp_path, kind):
    # A backslash is an ordinary POSIX name byte but never a safe snapshot path; one
    # such upstream file must not fail the whole source (auteqia__rules, 2026-11-02).
    repo = make_repo(tmp_path)
    odd = "rules/sub\\odd.yml"
    (repo / odd).write_text(RULE.format(n="odd", uid=UIDS[0]))
    commit(repo, "non-portable name")
    ws = workspace(tmp_path, repo)
    cfg = load_sources(ws)[0]
    cfg.type = kind
    save_sources(ws, [cfg])
    outcome = sync_all(ws)[0]
    assert outcome.status == "ok", outcome.message
    assert "1 unsafe paths" in outcome.message
    retained = load_snapshot(ws, cfg).hashes
    assert odd not in retained and "rules/a.yml" in retained
    paths = {o[0] for o in state(ws)["occurrences"] if o[2]}
    assert odd not in paths and "rules/a.yml" in paths


def test_snapshot_load_still_refuses_unsafe_manifest_paths(tmp_path):
    for rel in ("a\\b.yml", "/abs.yml", "../up.yml", "a/../b.yml", "a//b.yml", "./a.yml", "a\0b"):
        with pytest.raises(sync.SyncError, match="unsafe source snapshot path"):
            source_snapshots._safe_path(rel)


def test_local_snapshot_only_retains_sigma_content_and_retires_prose(tmp_path):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    cfg = load_sources(ws)[0]
    cfg.type = "local"
    save_sources(ws, [cfg])
    (repo / "settings.env").write_text("EXAMPLE=not-a-real-credential\n")
    assert sync_all(ws)[0].status == "ok"
    retained = load_snapshot(ws, cfg).hashes
    assert "settings.env" not in retained and "README.md" not in retained
    (repo / "rules/a.yml").write_text("This is no longer a rule.\n")
    assert sync_all(ws)[0].status == "ok"
    assert not next(o[2] for o in state(ws)["occurrences"] if o[0] == "rules/a.yml")


def test_missing_previously_eligible_blob_size_cannot_retire_path(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    before = state(ws)
    cfg = load_sources(ws)[0]
    cfg.exclude = ["rules/b.yml"]  # Forces a full scan at the unchanged HEAD.
    save_sources(ws, [cfg])
    original = sync._tree

    def damaged(*args):
        tree = original(*args)
        tree["rules/a.yml"] = (tree["rules/a.yml"][0], -1)
        return tree

    monkeypatch.setattr(sync, "_tree", damaged)
    result = sync_all(ws)[0]
    assert result.status == "error" and "previously eligible" in result.message
    assert state(ws) == before


@pytest.mark.parametrize("odd_name", [False, True])
def test_skipped_unsafe_name_does_not_force_a_full_rescan(tmp_path, monkeypatch, odd_name):
    """Capture skips a backslash name, but the materialized tree still holds it: an unchanged
    upstream must not read as a damaged cache (a full rescan and an index rebuild every update)."""
    repo = make_repo(tmp_path)
    if odd_name:
        (repo / "rules/sub\\odd.yml").write_text(RULE.format(n="odd", uid=UIDS[0]))
        commit(repo, "non-portable name")
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    seen = []
    original = sync.sync_git

    def spy(*args, **kwargs):
        result = original(*args, **kwargs)
        seen.append(result.full_scan)
        return result

    import sigharvest.service as service

    monkeypatch.setattr(service, "sync_git", spy)
    out = sync_all(ws)[0]
    assert out.status == "ok", out.message
    assert (out.log.files_added, out.log.files_changed, out.log.files_removed) == (0, 0, 0)
    assert seen == [False]


def test_a_blob_named_dot_git_is_never_materialised(tmp_path, monkeypatch):
    """A crafted tree with a `.git` entry must not reach corpus/<name>/.git: the next sync would take the corpus
    for an old work-tree layout and rebuild it on every run."""
    import subprocess

    repo = make_repo(tmp_path)

    def git(*args: str, data: bytes | None = None) -> str:
        ident = ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid"]
        return subprocess.run(["git", *ident, *args], cwd=repo, input=data, capture_output=True, check=True).stdout.decode().strip()

    blob = git("hash-object", "-w", "--stdin", data=RULE.format(n="dotgit", uid=UIDS[0]).encode())
    entries = git("ls-tree", "HEAD") + f"\n100644 blob {blob}\t.git\n"
    tree = git("mktree", data=entries.encode())
    new = git("commit-tree", tree, "-p", "HEAD", "-m", "crafted .git entry")
    git("update-ref", "refs/heads/" + git("symbolic-ref", "--short", "HEAD"), new)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    assert not any(p.name == ".git" for p in ws.corpus.rglob("*"))
    seen = []
    original = sync.sync_git

    def spy(*args, **kwargs):
        result = original(*args, **kwargs)
        seen.append(result.full_scan)
        return result

    import sigharvest.service as service

    monkeypatch.setattr(service, "sync_git", spy)
    assert sync_all(ws)[0].status == "ok"
    assert seen == [False]
