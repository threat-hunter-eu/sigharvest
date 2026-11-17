"""Legacy snapshot recovery must match a full ingest without parsing accepted files."""

import shutil
from dataclasses import replace

import pytest
from sqlalchemy import delete, select

from sigharvest import service, source_snapshots
from sigharvest.config import Workspace, load_sources
from sigharvest.db import get_meta, set_meta
from sigharvest.ingest import Ingestor
from sigharvest.models import Meta, Occurrence, Quarantine, QuarantineAttempt, QuarantineBlob, RuleVersion
from sigharvest.service import open_db, sync_all
from sigharvest.source_snapshots import ACTIVE_PREFIX, CONFIG_PREFIX, attach, capture
from sigharvest.sync import SyncResult
from tests.test_pipeline import RULE, UIDS, make_repo, workspace


def legacy(ws, *, policy=None):
    with open_db(ws)() as session:
        session.execute(delete(Meta).where(Meta.key.in_([ACTIVE_PREFIX + "local", CONFIG_PREFIX + "local"])))
        if policy:
            set_meta(session, CONFIG_PREFIX + "local", policy)
        session.commit()


def corpus_rows(ws):
    # Compare every persisted semantic column, including IDs, provenance, byte
    # spans and history. Wall-clock observation times are intentionally excluded.
    result = {}
    with open_db(ws)() as session:
        for model in (RuleVersion, Occurrence, Quarantine, QuarantineBlob, QuarantineAttempt):
            columns = [c for c in model.__table__.columns if c.name not in {"first_seen", "last_seen", "seen_at", "resolved_at", "created_at"}]
            result[model.__tablename__] = [tuple(row) for row in session.execute(select(*columns).order_by(*model.__table__.primary_key))]
    return result


@pytest.mark.parametrize("keep_policy", [False, True])
def test_missing_snapshot_uses_verified_hashes_and_matches_full_scan(tmp_path, monkeypatch, keep_policy):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    cfg = load_sources(ws)[0]
    legacy(ws, policy=source_snapshots.config_fingerprint(cfg) if keep_policy else None)
    shutil.rmtree(ws.cache / "source-snapshots")
    # Damaged acquisition cache must be repaired from Git before hash reuse.
    (ws.source_dir(cfg.name) / "rules/a.yml").write_text("bad cache")
    full = Workspace(tmp_path / "full")
    shutil.copytree(ws.root, full.root)
    calls = []
    original = Ingestor.ingest_file

    def counted(self, root, rel):
        calls.append(rel)
        return original(self, root, rel)

    monkeypatch.setattr(Ingestor, "ingest_file", counted)
    outcome = sync_all(ws)[0]
    assert outcome.status == "ok", outcome.message
    assert calls == ["rules/broken.yml"]  # quarantine remains an ordinary ingest
    assert outcome.log.files_added == 0 and outcome.log.files_changed == 1
    assert get_active(ws)
    with monkeypatch.context() as patch:
        patch.setattr("sigharvest.source_rebaseline.rebaseline", lambda *args: False)
        assert sync_all(full)[0].status == "ok"
    assert corpus_rows(ws) == corpus_rows(full)


def get_active(ws):
    with open_db(ws)() as session:
        return get_meta(session, ACTIVE_PREFIX + "local")


def test_rebaseline_new_changed_removed_multidocument_and_selection_parity(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    cfg = load_sources(ws)[0]
    previous = source_snapshots.load_snapshot(ws, cfg)
    legacy(ws)
    materialized = tmp_path / "materialized"
    shutil.copytree(previous.root, materialized)
    (materialized / "rules/a.yml").unlink()
    (materialized / "rules/broken.yml").unlink()
    (materialized / "rules/b.yml").write_text(RULE.format(n="changed", uid=UIDS[2]))
    (materialized / "rules/new.yml").write_text(RULE.format(n="new", uid=UIDS[6]))
    # Shrink a multidocument file and narrow one old selection at the same commit.
    (materialized / "rules/multi.yaml").write_text(RULE.format(n="c", uid=UIDS[3]))
    cfg = replace(cfg, exclude=["rules/e.txt"])
    from sigharvest.config import save_sources

    save_sources(ws, [cfg])
    full = Workspace(tmp_path / "full")
    shutil.copytree(ws.root, full.root)

    def fetch(workspace, config, *args):
        result = SyncResult(previous.manifest["revision"], previous.manifest["revision"], materialized, full_scan=True)
        return attach(result, capture(workspace, config, result), config)

    monkeypatch.setattr(service, "fetch_source", fetch)
    outcome = sync_all(ws)[0]
    assert outcome.status == "ok", outcome.message
    assert (outcome.log.files_added, outcome.log.files_changed, outcome.log.files_removed) == (1, 2, 3)
    monkeypatch.setattr("sigharvest.source_rebaseline.rebaseline", lambda *args: False)
    assert sync_all(full)[0].status == "ok"
    assert corpus_rows(ws) == corpus_rows(full)


@pytest.mark.parametrize("change", ["policy", "revision", "origin", "rescan", "no-occurrences", "missing-spans", "conflicting-hashes", "inactive-occurrence"])
def test_unsafe_reuse_falls_back_to_ingest(tmp_path, monkeypatch, change):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    legacy(ws, policy="old-parser" if change == "policy" else None)
    with open_db(ws)() as session:
        from sigharvest.models import Source

        source = session.scalar(select(Source))
        if change == "revision":
            source.last_commit = "old-revision"
        elif change == "origin":
            source.url = "https://example.invalid/old"
        elif change == "no-occurrences":
            session.execute(delete(Occurrence))
        elif change == "missing-spans":
            session.scalar(select(Occurrence).where(Occurrence.path == "rules/a.yml")).span_start = None
        elif change == "inactive-occurrence":
            session.scalar(select(Occurrence).where(Occurrence.path == "rules/a.yml")).present = False
        elif change == "conflicting-hashes":
            session.scalar(select(Occurrence).where(Occurrence.path == "rules/multi.yaml")).file_hash = "0" * 64
        session.commit()
    calls = []
    original = Ingestor.ingest_file

    def counted(self, root, rel):
        calls.append(rel)
        return original(self, root, rel)

    monkeypatch.setattr(Ingestor, "ingest_file", counted)
    outcome = sync_all(ws, rescan=change == "rescan")[0]
    assert outcome.status == "ok", outcome.message
    if change in {"missing-spans", "inactive-occurrence"}:
        assert set(calls) == {"rules/a.yml", "rules/broken.yml"}
    elif change == "conflicting-hashes":
        assert set(calls) == {"rules/multi.yaml", "rules/broken.yml"}
    else:
        assert len(calls) == 5


def test_rebaseline_ack_failure_rolls_back_reused_rows(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    legacy(ws)
    with open_db(ws)() as session:
        before = list(session.execute(select(Occurrence.__table__).order_by(Occurrence.id)))
    original = service.set_meta

    def fail(session, key, value):
        if key.startswith(ACTIVE_PREFIX):
            raise OSError("fixture acknowledgement failure")
        return original(session, key, value)

    monkeypatch.setattr(service, "set_meta", fail)
    assert sync_all(ws)[0].status == "error"
    assert not get_active(ws)
    with open_db(ws)() as session:
        assert list(session.execute(select(Occurrence.__table__).order_by(Occurrence.id))) == before


def test_sync_logs_one_summary_per_source_and_publishes_structured_detail(tmp_path):
    from sigharvest.job_control import SYNC_PROGRESS
    from sigharvest.runs import close_log, open_log

    ws = workspace(tmp_path, make_repo(tmp_path))
    details, messages = [], []
    token = SYNC_PROGRESS.set(details.append)
    handler = open_log(ws)
    try:
        outcome = sync_all(ws, progress=messages.append)[0]
    finally:
        close_log(handler)
        SYNC_PROGRESS.reset(token)
    assert outcome.status == "ok"
    summary = details[-1]
    assert (summary.done, summary.total, summary.added, summary.changed, summary.removed) == (1, 1, 5, 0, 0)
    assert summary.seconds > 0
    assert summary.text.startswith("sync 1/1 local: +5 ~0 -0, ")
    lines = next((ws.root / "data/logs").glob("update-*.log")).read_text().splitlines()
    assert len(lines) == 1 and lines[0].endswith(summary.text)
    assert messages[-1] == summary.text
    assert details[0].status == "ingesting"


def test_quarantine_path_cache_tracks_new_failures(tmp_path):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    from sigharvest.models import Source

    with open_db(ws)() as session:
        source = Source(name="local", type="local", url=str(repo))
        session.add(source)
        session.flush()
        ingestor = Ingestor(session, source, "revision")
        ingestor.ingest_file(repo, "rules/a.yml")  # cache initially empty
        ingestor.ingest_file(repo, "rules/broken.yml")
        ingestor.ingest_file(repo, "rules/broken.yml")  # rejection remains deduplicated
        assert len(list(session.scalars(select(QuarantineAttempt)))) == 1
        (repo / "rules/broken.yml").write_text(RULE.format(n="repaired", uid=UIDS[8]))
        ingestor.ingest_file(repo, "rules/broken.yml")
        letter = session.scalar(select(Quarantine))
        assert not letter.present and letter.resolution == "superseded"
        assert session.scalar(select(Occurrence).where(Occurrence.path == "rules/broken.yml")).present
