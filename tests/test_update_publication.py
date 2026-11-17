"""Offline publication, interruption and operator diagnostics for scheduled updates."""

import os
import signal
import sqlite3

import pytest
from sqlalchemy import func, select
from typer.testing import CliRunner

from sigharvest import runs
from sigharvest.cli import app, pipeline
from sigharvest.config import SourceConfig, load_sources, save_sources
from sigharvest.db import get_meta, set_meta
from sigharvest.health import index_check
from sigharvest.job_control import Cancelled
from sigharvest.lock import mutation_lease
from sigharvest.models import LogicGroup, Occurrence, Source
from sigharvest.service import open_db, sync_all
from sigharvest.update_publication import candidate
from tests.test_update_runs import N_RULES, commit, latest, make_workspace, report, write_rule


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    repo, ws = make_workspace(tmp_path)
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    open_db(ws, migrate=True)
    # Real ingest, index and gates; expensive backend conversion has its own tests.
    monkeypatch.setattr(pipeline, "_test", lambda *args, **kwargs: 0)
    return repo, ws


def update(ws, *options):
    result = CliRunner().invoke(app, ["update", "-j", "1", "--no-report", *options], env={"SIGHARVEST_HOME": str(ws.root), "COLUMNS": "240"})
    if result.exception and not isinstance(result.exception, SystemExit):
        raise result.exception
    return result


def published(ws):
    """Mark the workspace as having a published corpus: only then is an update a gated candidate."""
    from sigharvest.index import INDEX_BUILT_AT

    with open_db(ws)() as s:
        set_meta(s, INDEX_BUILT_AT, "2026-01-01T00:00:00+00:00")
        s.commit()


def test_stage_commits_are_invisible_until_accepted(workspace):
    _, ws = workspace
    published(ws)
    with mutation_lease(ws), candidate(ws) as publication:
        with open_db(ws)() as s:
            set_meta(s, "candidate-probe", "new")
            s.commit()
        with sqlite3.connect(ws.db_path.as_uri() + "?mode=ro", uri=True) as reader:
            assert reader.execute("SELECT value FROM meta WHERE key='candidate-probe'").fetchone() is None
        with open_db(ws)() as s:
            assert get_meta(s, "candidate-probe") == "new"
        publication.accepted = True
    with open_db(ws)() as s:
        assert get_meta(s, "candidate-probe") == "new"
    with mutation_lease(ws), candidate(ws), open_db(ws)() as s:
        set_meta(s, "candidate-probe", "rejected")
        s.commit()
    with open_db(ws)() as s:
        assert get_meta(s, "candidate-probe") == "new"


def test_failed_gate_keeps_published_search(workspace, monkeypatch):
    repo, ws = workspace
    assert update(ws).exit_code == 0
    for i in range(10):
        (repo / "rules" / f"r{i}.yml").unlink()
    commit(repo, "remove")
    original = runs.corpus_counts

    def counts(*args):
        # Another reader still sees all published rules after candidate indexing.
        with sqlite3.connect(ws.db_path.as_uri() + "?mode=ro", uri=True) as reader:
            assert reader.execute("SELECT COUNT(*) FROM logic_groups").fetchone()[0] == N_RULES
            assert reader.execute("SELECT COUNT(*) FROM rules_fts WHERE rules_fts MATCH 'tool1'").fetchone()[0] > 0
        return original(*args)

    monkeypatch.setattr(runs, "corpus_counts", counts)
    result = update(ws)
    assert result.exit_code == 1, result.output
    run = latest(ws)
    assert run.status == "failed gate" and run.counts["unique_logic"] == N_RULES - 10
    assert len(report(ws, run)[1]["removed"]) == 10
    with open_db(ws)() as s:
        assert s.scalar(select(func.count()).select_from(LogicGroup)) == N_RULES
        assert s.scalar(select(func.count()).select_from(Occurrence).where(Occurrence.present.is_(True))) == N_RULES
    monkeypatch.setattr(runs, "corpus_counts", original)
    assert update(ws, "--max-logic-drop", "100").exit_code == 0
    with open_db(ws)() as s:
        assert s.scalar(select(func.count()).select_from(LogicGroup)) == N_RULES - 10


@pytest.mark.parametrize("remove", [True, False])
def test_source_retirement_and_reenable(workspace, remove):
    _, ws = workspace
    assert update(ws).exit_code == 0
    configs = load_sources(ws)
    save_sources(ws, [] if remove else [SourceConfig(**(configs[0].to_dict() | {"enabled": False}))])
    result = update(ws, "--max-logic-drop", "100")
    assert result.exit_code == 0, result.output
    assert latest(ws).counts["removed"] == N_RULES
    with open_db(ws)() as s:
        assert s.scalar(select(func.count()).select_from(Occurrence).where(Occurrence.present.is_(True))) == 0
    save_sources(ws, configs)
    assert update(ws).exit_code == 0
    assert latest(ws).counts["unique_logic"] == N_RULES


def test_disabled_copy_does_not_retire_other_source(workspace):
    _, ws = workspace
    config = load_sources(ws)[0]
    save_sources(ws, [config, SourceConfig(**(config.to_dict() | {"name": "mirror"}))])
    sync_all(ws, workers=1)
    config.enabled = False
    save_sources(ws, [config, SourceConfig(**(config.to_dict() | {"name": "mirror", "enabled": True}))])
    sync_all(ws, names=["mirror"], workers=1)
    with open_db(ws)() as s:
        rows = s.execute(select(Source.name, func.count()).join(Occurrence).where(Occurrence.present.is_(True)).group_by(Source.name)).all()
        assert rows == [("mirror", N_RULES)]


def test_sigterm_rolls_back_and_records_notifies(workspace, monkeypatch):
    repo, ws = workspace
    assert update(ws).exit_code == 0
    write_rule(repo, 100)
    commit(repo, "new")
    previous_handler = signal.getsignal(signal.SIGTERM)
    monkeypatch.setattr(pipeline, "_test", lambda *args, **kwargs: signal.raise_signal(signal.SIGTERM))
    notified = []
    monkeypatch.setattr(pipeline, "_notify", lambda command, path: notified.append(path))
    with pytest.raises(Cancelled):
        update(ws, "--notify-cmd", "fixture-notify")
    run = latest(ws)
    assert run.status == "cancelled" and run.finished_at is not None
    assert report(ws, run)[1]["status"] == "cancelled"
    assert notified and "cancelled" in next((ws.root / "data/logs").glob("update-*.log")).read_text()
    assert signal.getsignal(signal.SIGTERM) == previous_handler
    with open_db(ws)() as s:
        assert s.scalar(select(func.count()).select_from(LogicGroup)) == N_RULES


@pytest.mark.parametrize("fail_commit", [False, True])
def test_cancel_at_candidate_commit_obeys_durable_publication(workspace, fail_commit):
    from sqlalchemy import Connection, event

    from sigharvest.update_publication import sessions

    _, ws = workspace
    published(ws)
    raced = []

    def commit(connection):
        if sessions(ws.db_path) is not None and not raced:
            raced.append(True)
            signal.raise_signal(signal.SIGTERM)
            if fail_commit:
                raise RuntimeError("injected candidate commit failure")

    event.listen(Connection, "commit", commit)
    try:
        if fail_commit:
            with pytest.raises(Cancelled):
                update(ws)
        else:
            assert update(ws).exit_code == 0
    finally:
        event.remove(Connection, "commit", commit)
    assert raced
    with open_db(ws)() as session:
        assert session.scalar(select(func.count()).select_from(LogicGroup)) == (0 if fail_commit else N_RULES)
    assert latest(ws).status == ("cancelled" if fail_commit else "ok")


def test_doctor_defers_index_failure_during_lease(workspace):
    _, ws = workspace
    with mutation_lease(ws), open_db(ws)() as s:
        check = index_check(s, ws)
        assert check.status == "warn" and "running" in check.message


def test_failed_sources_absolute_floor():
    counts = {"unique_logic": 4, "sources_enabled": 5, "sources_failed": 1}

    def gate(th):
        return next(g for g in runs.evaluate(counts, None, th) if g.name == "failed sources")

    assert gate(runs.Thresholds()).status == "pass"
    assert gate(runs.Thresholds(failed_sources_floor=0)).status == "fail"
    counts["sources_failed"] = 2
    assert gate(runs.Thresholds()).status == "fail"


def test_sigterm_during_snapshot_records_outcome(workspace, monkeypatch):
    _, ws = workspace
    original = runs.snapshot
    calls = 0

    def snapshot(s):
        nonlocal calls
        calls += 1
        if calls == 1:
            signal.raise_signal(signal.SIGTERM)
        return original(s)

    monkeypatch.setattr(runs, "snapshot", snapshot)
    with pytest.raises(Cancelled):
        update(ws)
    run = latest(ws)
    assert run.status == "cancelled"
    assert report(ws, run)[1]["status"] == "cancelled"


def test_sigterm_records_before_waiting_for_fetch(workspace, monkeypatch):
    import threading

    from sigharvest import service
    from sigharvest.sync import SyncError

    _, ws = workspace
    release = threading.Event()
    notified = []

    def fetch(*args):
        os.kill(os.getpid(), signal.SIGTERM)
        released = release.wait(15)
        if not released:
            raise AssertionError("interrupted outcome was not written before waiting for fetch")
        raise SyncError("cancelled fixture")

    def notify(command, path):
        notified.append(path)
        release.set()

    monkeypatch.setattr(service, "fetch_source", fetch)
    monkeypatch.setattr(pipeline, "_notify", notify)
    with pytest.raises(Cancelled):
        update(ws, "--notify-cmd", "fixture")
    assert notified
    assert latest(ws).status == "cancelled"


@pytest.mark.parametrize("kind", ["git", "local"])
def test_sync_progress_and_skipped_files(workspace, kind, monkeypatch):
    from sigharvest.documents import MAX_FILE_BYTES

    repo, ws = workspace
    (repo / "rules/settings.yaml").write_text("name: not sigma\n")
    with (repo / "rules/large.yml").open("wb") as stream:
        stream.truncate(MAX_FILE_BYTES + 1)
    commit(repo, "ineligible")
    if kind == "local":
        cfg = load_sources(ws)[0]
        cfg.type = "local"
        save_sources(ws, [cfg])
    result = update(ws)
    assert result.exit_code == 0, result.output
    assert "sync 1/1 local: +31 ~0 -0," in result.output
    assert "skipped: 1 non-Sigma YAML, 1 large files" in result.output


def test_disk_refusal_is_readable(tmp_path, monkeypatch):
    from sigharvest import space

    monkeypatch.setattr(space, "capacity", lambda path: space.Capacity(1, 1024**3, None))
    with pytest.raises(space.SpaceError, match=r"1.0 GiB available, .* GiB required"):
        space.admit([space.Need("index", tmp_path, 2 * 1024**3)])


@pytest.mark.parametrize("where", ["test", "outcome"])
def test_exception_escaping_the_update_finalizes_its_run(workspace, monkeypatch, where):
    """Update 5 on live stayed "running" after a conversion failure; its outcome block never ran."""
    from sigharvest.conversion_memory import ResourceFailure

    repo, ws = workspace
    assert update(ws).exit_code == 0
    write_rule(repo, 100)
    commit(repo, "new")
    if where == "test":
        monkeypatch.setattr(pipeline, "_test", lambda *args, **kwargs: (_ for _ in ()).throw(ResourceFailure("worker lost")))
        # The stage error is caught; then the outcome block itself fails.
    # The gates fail closed (report-only work no longer can: see test_update_report_robust).
    original = runs.evaluate

    def broken(*args, **kwargs):
        raise RuntimeError("outcome block failed")

    monkeypatch.setattr(runs, "evaluate", broken)
    with pytest.raises(RuntimeError, match="outcome block failed"):
        update(ws)
    monkeypatch.setattr(runs, "evaluate", original)
    monkeypatch.setattr(pipeline, "_test", lambda *args, **kwargs: 0)
    run = latest(ws)
    assert run.status == "error" and run.finished_at is not None
    assert run.reasons[0] == "error: RuntimeError: outcome block failed"
    assert "nothing was published" in run.reasons[1] and run.counts["phase"] == "finished"
    log = next((ws.root / "data/logs").glob("update-*.log")).read_text()
    assert "update failed before its outcome was recorded" in log and "Traceback" in log
    with open_db(ws)() as s:
        # Nothing from the failed candidate was published.
        assert s.scalar(select(func.count()).select_from(LogicGroup)) == N_RULES
    # The next update starts normally.
    assert update(ws).exit_code == 0 and latest(ws).status == "ok"


def test_failure_to_record_a_failed_update_keeps_the_original_error(workspace, monkeypatch):
    from sigharvest import update_publication

    repo, ws = workspace
    write_rule(repo, 100)
    commit(repo, "new")
    monkeypatch.setattr(runs, "evaluate", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("outcome block failed")))
    monkeypatch.setattr(update_publication, "record_failure", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(RuntimeError, match="outcome block failed") as raised:
        update(ws)
    assert any("disk full" in note for note in getattr(raised.value, "__notes__", []))
    log = next((ws.root / "data/logs").glob("update-*.log")).read_text()
    assert "could not record the failed update's outcome" in log


def test_interrupted_first_update_keeps_its_work_and_resumes(workspace, monkeypatch):
    """Nothing is published yet, so the first update commits stage by stage: Ctrl+C keeps the ingested sources,
    and the re-run neither re-ingests the unchanged source nor rebuilds from zero."""
    from sigharvest.models import RuleVersion

    _, ws = workspace
    monkeypatch.setattr(pipeline, "_test", lambda *args, **kwargs: signal.raise_signal(signal.SIGINT))
    with pytest.raises((Cancelled, KeyboardInterrupt)):
        update(ws)
    assert latest(ws).status == "cancelled"
    with open_db(ws)() as s:
        assert s.scalar(select(func.count()).select_from(RuleVersion)) >= N_RULES
        assert s.scalar(select(Source.last_commit).where(Source.name == "local"))
    monkeypatch.setattr(pipeline, "_test", lambda *args, **kwargs: 0)
    result = update(ws)
    assert result.exit_code == 0, result.output
    assert "1 sources unchanged" in result.output
    with open_db(ws)() as s:
        assert s.scalar(select(func.count()).select_from(LogicGroup)) == N_RULES
