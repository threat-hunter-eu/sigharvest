"""Steady-state sync cost: no global work per statement or per unchanged source."""

from __future__ import annotations

import shutil

import pytest

from sigharvest import service, snapshot_reads, source_snapshots
from sigharvest.config import Workspace, load_sources
from sigharvest.service import sync_all
from tests.test_pipeline import RULE, UIDS, commit, make_repo, workspace
from tests.test_sync_rebaseline import corpus_rows


def test_unchanged_source_reuses_the_verified_fetch_instead_of_rereading_the_snapshot(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    reads = []
    original = source_snapshots.load_snapshot

    def counted(*args, **kwargs):
        reads.append(args[2] if len(args) > 2 else kwargs.get("generation"))
        return original(*args, **kwargs)

    monkeypatch.setattr(source_snapshots, "load_snapshot", counted)
    monkeypatch.setattr(service, "verified_snapshot", counted)
    manifests = []
    monkeypatch.setattr(service, "manifest_hashes", lambda *args: manifests.append(args) or {})
    outcome = sync_all(ws)[0]
    assert outcome.status == "ok", outcome.message
    assert (outcome.log.files_added, outcome.log.files_changed, outcome.log.files_removed) == (0, 0, 0)
    assert reads == [None]  # one verification of the fetched generation, in the fetch thread
    assert manifests == []


def test_upstream_change_diffs_the_old_manifest_without_reverifying_its_blobs(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    cfg = load_sources(ws)[0]
    old = source_snapshots.load_snapshot(ws, cfg)
    full = Workspace(tmp_path / "full")
    shutil.copytree(ws.root, full.root)
    (repo / "rules" / "b.yml").write_text(RULE.format(n="changed", uid=UIDS[2]))
    (repo / "rules" / "new.yml").write_text(RULE.format(n="new", uid=UIDS[6]))
    (repo / "rules" / "a.yml").unlink()
    commit(repo, "change")
    reads = []
    original = source_snapshots.load_snapshot

    def counted(*args, **kwargs):
        reads.append(args[2] if len(args) > 2 else kwargs.get("generation"))
        return original(*args, **kwargs)

    monkeypatch.setattr(source_snapshots, "load_snapshot", counted)
    monkeypatch.setattr(service, "verified_snapshot", counted)
    outcome = sync_all(ws)[0]
    assert outcome.status == "ok", outcome.message
    assert (outcome.log.files_added, outcome.log.files_changed, outcome.log.files_removed) == (1, 1, 1)
    # The accepted generation's blobs are verified once (fetch cache check), not again
    # on the single writer thread; the new generation is verified at capture.
    assert reads.count(old.generation) == 0 and reads.count(None) == 1
    # The manifest yields exactly the hashes the full verification returned before.
    assert snapshot_reads.manifest_hashes(ws, cfg, old.generation) == old.hashes
    # Same rows as the previous implementation, which re-verified the old generation.
    monkeypatch.setattr(service, "manifest_hashes", lambda w, c, g: original(w, c, g).hashes)
    assert sync_all(full)[0].log.files_changed == 1
    assert corpus_rows(ws) == corpus_rows(full)


def test_damaged_old_manifest_falls_back_to_a_full_scan(tmp_path):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    cfg = load_sources(ws)[0]
    old = source_snapshots.load_snapshot(ws, cfg)
    (old.root.parent / "manifest.json").write_text("{}")
    (repo / "rules" / "new.yml").write_text(RULE.format(n="new", uid=UIDS[6]))
    commit(repo, "change")
    outcome = sync_all(ws)[0]
    assert outcome.status == "ok", outcome.message
    assert outcome.log.files_added == 6  # every selected file, as on a first sync


def test_manual_sync_rebuilds_the_index_only_when_something_changed(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from sigharvest import index
    from sigharvest.cli import app

    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    env = {"SIGHARVEST_HOME": str(ws.root)}
    rebuilds = []
    original = index.rebuild
    monkeypatch.setattr(index, "rebuild", lambda *args, **kwargs: rebuilds.append(1) or original(*args, **kwargs))
    first = CliRunner().invoke(app, ["sync"], env=env)
    assert first.exit_code == 0, first.output
    assert rebuilds == [1]
    second = CliRunner().invoke(app, ["sync"], env=env)
    assert second.exit_code == 0, second.output
    assert "index up to date" in second.output and rebuilds == [1]
    (repo / "rules" / "new.yml").write_text(RULE.format(n="new", uid=UIDS[6]))
    commit(repo, "change")
    third = CliRunner().invoke(app, ["sync"], env=env)
    assert third.exit_code == 0, third.output
    assert rebuilds == [1, 1]
    # Disabling a source syncs nothing (no outcome, no file counts), but retiring its
    # occurrences changes the live corpus, so the index still rebuilds.
    from dataclasses import replace

    from sigharvest.config import save_sources

    save_sources(ws, [replace(load_sources(ws)[0], enabled=False)])
    fourth = CliRunner().invoke(app, ["sync"], env=env)
    assert fourth.exit_code == 0, fourth.output
    assert "index up to date" not in fourth.output and rebuilds == [1, 1, 1]
    fifth = CliRunner().invoke(app, ["sync"], env=env)
    assert fifth.exit_code == 0, fifth.output
    assert "index up to date" in fifth.output and rebuilds == [1, 1, 1]


def _outcome(fn, *args):
    try:
        snapshot = fn(*args)
    except Exception as exc:  # noqa: BLE001 - compare the exact failure
        return type(exc).__name__, str(exc)
    return snapshot.generation, snapshot.root, snapshot.manifest


@pytest.mark.parametrize("damage", ["none", "blob", "missing", "symlink-dir", "symlink-file", "outside-dir"])
def test_fast_snapshot_verification_matches_load_snapshot(tmp_path, damage):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    cfg = load_sources(ws)[0]
    root = source_snapshots.load_snapshot(ws, cfg).root
    target = root / "rules" / "b.yml"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "b.yml").write_bytes(target.read_bytes())
    if damage == "blob":
        target.unlink()
        target.write_text("damaged")
    elif damage == "missing":
        target.unlink()
    elif damage == "symlink-file":
        target.unlink()
        target.symlink_to(outside / "b.yml")
    elif damage in ("symlink-dir", "outside-dir"):
        moved = tmp_path / "moved-rules"
        (root / "rules").rename(moved)
        (root / "rules").symlink_to(moved if damage == "symlink-dir" else outside)
    expected = _outcome(source_snapshots.load_snapshot, ws, cfg)
    assert _outcome(snapshot_reads.verified_snapshot, ws, cfg) == expected
    assert (damage == "none") == (expected[0] not in ("SyncError", "FileNotFoundError", "OSError"))


def test_fetch_pool_shortens_the_switch_interval_and_restores_it(tmp_path, monkeypatch):
    import sys

    seen = []
    original = service.fetch_source

    def recording(*args, **kwargs):
        seen.append(sys.getswitchinterval())
        return original(*args, **kwargs)

    monkeypatch.setattr(service, "fetch_source", recording)
    before = sys.getswitchinterval()
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    assert seen == [service.FETCH_SWITCH_INTERVAL]
    assert sys.getswitchinterval() == before
    with pytest.raises(RuntimeError), service.fetch_pool(2):
        raise RuntimeError("interrupted")
    assert sys.getswitchinterval() == before
