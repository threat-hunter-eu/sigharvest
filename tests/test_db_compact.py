"""Retention keeps current keys, real status transitions and active-run provenance."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

from sigharvest import db_compact, testing
from sigharvest.cli import app
from sigharvest.config import Workspace
from sigharvest.db import session_factory
from sigharvest.errors import SigharvestError
from sigharvest.models import RuleVersion, TestResult, TestResultHistory, TestRun, utcnow
from sigharvest.schema import migration_backup


@pytest.fixture
def database(tmp_path):
    ws = Workspace(tmp_path)
    factory = session_factory(ws.db_path, migrate=True)
    with factory() as s:
        version = RuleVersion(content_hash="a" * 64, logic_hash="b" * 64, rule_id="c" * 36, kind="rule", raw="test")
        s.add(version)
        s.flush()
        runs = [TestRun(stage="convert", status=status, finished_at=utcnow() if status != "running" else None) for status in ("ok", "interrupted", "running")]
        s.add_all(runs)
        s.flush()
        for i, (target, dataset) in enumerate((("splunk", ""), ("splunk", "lab"), ("sqlite", ""))):
            result = TestResult(
                version_id=version.id,
                stage="convert",
                target=target,
                dataset=dataset,
                status="ok",
                detail={"query": "current"},
                fingerprint="old",
                run_id=runs[i].id,
            )
            s.add(result)
            s.flush()
            # Five prior changes followed by repeated current status: only error,warning survive N=2.
            for status in ("warning", "error", "ok", "warning", "warning", "error", "error", "ok", "ok"):
                s.add(TestResultHistory(result_id=result.id, fingerprint="old", snapshot={"status": status, "run_id": runs[i].id, "detail": "x" * 4000}))
        s.commit()
    return ws, factory


def current(path: Path):
    with sqlite3.connect(path) as conn:
        return conn.execute("SELECT * FROM test_results ORDER BY id").fetchall()


def test_dry_run_is_byte_stable_and_compaction_is_idempotent(database):
    ws, factory = database
    before_bytes = ws.db_path.read_bytes()
    before = current(ws.db_path)
    dry = db_compact.compact(ws.db_path, dry_run=True, history=2, vacuum=True)
    assert dry["prune"] == {"history_rows": 14, "superseded_result_rows": 0}
    assert dry["before"] == dry["after"]
    assert ws.db_path.read_bytes() == before_bytes
    result = db_compact.compact(ws.db_path, history=2)
    assert result["prune"] == dry["prune"]
    assert result["after"]["result_rows"] == 3
    assert result["after"]["history_rows"] == 13  # running snapshots remain pinned
    assert current(ws.db_path) == before
    with factory() as s:
        for rid in (1, 2):
            assert [
                h.snapshot["status"] for h in s.scalars(select(TestResultHistory).where(TestResultHistory.result_id == rid).order_by(TestResultHistory.id))
            ] == ["warning", "error"]
    assert db_compact.compact(ws.db_path, history=2)["prune"]["history_rows"] == 0
    with factory() as s:
        run = s.get(TestRun, 3)
        run.status, run.finished_at = "interrupted", utcnow()
        s.commit()
    assert db_compact.compact(ws.db_path, history=0)["after"]["history_rows"] == 0
    assert current(ws.db_path) == before


def test_vacuum_checks_space_before_mutating_and_shrinks(database, monkeypatch):
    ws, _ = database
    original = ws.db_path.read_bytes()
    with monkeypatch.context() as patch:
        patch.setattr(db_compact.shutil, "disk_usage", lambda _: SimpleNamespace(free=0))
        with pytest.raises(SigharvestError, match="VACUUM needs"):
            db_compact.compact(ws.db_path, vacuum=True)
    assert ws.db_path.read_bytes() == original
    result = db_compact.compact(ws.db_path, history=0, vacuum=True)
    assert result["after"]["database_bytes"] < result["before"]["database_bytes"]
    with sqlite3.connect(ws.db_path) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_backup_retention_ignores_unowned_partial_and_symlink_files(database):
    ws, _ = database
    first = migration_backup(ws.db_path, "0026")
    second = migration_backup(ws.db_path, "0026", keep=2)
    assert first.exists() and second.exists()
    folder = first.parent
    unrelated = folder / "someone-elses.sqlite3"
    unrelated.write_text("keep")
    partial = folder / "work.partial"
    partial.write_text("unfinished")
    symlink = folder / f"sigharvest.db.{'f' * 32}.sqlite3"
    symlink.symlink_to(unrelated)
    third = migration_backup(ws.db_path, "0026")
    assert third.exists() and not first.exists() and not second.exists()
    assert unrelated.exists() and partial.exists() and symlink.is_symlink()
    extra = folder / f"sigharvest.db.{'e' * 32}.sqlite3"
    extra.write_bytes(third.read_bytes())
    os.utime(extra, (1, 1))
    plan = db_compact.compact(ws.db_path, dry_run=True)
    assert plan["backup_files"] == 1 and extra.exists()
    db_compact.compact(ws.db_path)
    assert not extra.exists() and third.exists()


def test_store_archives_status_changes_even_with_same_fingerprint(database):
    _, factory = database
    with factory() as s:
        s.query(TestResultHistory).delete()
        result = s.get(TestResult, 1)
        testing._store(s, 1, "convert", [(result.version_id, "splunk", "ok", {"fingerprint": "new"})])
        s.flush()
        prior = s.scalars(select(TestResultHistory)).one()
        assert prior.fingerprint == "old" and prior.snapshot["detail"] == {"query": "current"}
        testing._store(s, 1, "convert", [(result.version_id, "splunk", "error", {"fingerprint": "new"})])
        s.flush()
        retained = list(s.scalars(select(TestResultHistory).order_by(TestResultHistory.id)))
        assert [row.fingerprint for row in retained] == ["old", "new"]
        assert all(row.snapshot["status"] == "ok" for row in retained)
        assert s.get(TestResult, 2).dataset == "lab"
        s.rollback()
        assert s.get(TestResult, 1).status == "ok"


@pytest.mark.parametrize("stage", ["convert", "validate"])
def test_fingerprint_only_history_is_bounded_and_conversion_specific(database, stage):
    ws, factory = database
    with factory() as s:
        s.query(TestResultHistory).delete()
        current = s.get(TestResult, 1)
        current.stage, current.fingerprint = stage, "third"
        for fingerprint in (None, "first", "second"):
            s.add(TestResultHistory(result_id=current.id, fingerprint=fingerprint, snapshot={"status": "ok", "run_id": 1, "detail": {"original": fingerprint}}))
        s.commit()
    db_compact.compact(ws.db_path, history=1)
    with factory() as s:
        history = list(s.scalars(select(TestResultHistory)))
        assert len(history) == (1 if stage == "convert" else 0)
        if history:
            assert history[0].fingerprint == "second"
            assert history[0].snapshot == {"status": "ok", "run_id": 1, "detail": {"original": "second"}}
        assert s.get(TestResult, 1).fingerprint == "third"


def test_stage_prunes_even_when_no_work_and_configuration_is_validated(database, monkeypatch):
    ws, factory = database
    monkeypatch.setenv("SIGHARVEST_TEST_HISTORY", "1")
    monkeypatch.setattr(testing, "_run_stage", lambda *args, **_kwargs: testing.StageSummary("convert", 0, 0, {}))
    with factory() as s:
        testing.run_stage(ws, s, "convert")
        assert len(list(s.scalars(select(TestResultHistory)))) == 3
        assert s.get(TestRun, 3).status == "interrupted"
    monkeypatch.setenv("SIGHARVEST_TEST_HISTORY", "invalid")
    with pytest.raises(SigharvestError, match="nonnegative"):
        db_compact.compact(ws.db_path)
    with pytest.raises(SigharvestError, match="nonnegative"):
        db_compact.history_limit(-1)


def test_cli_dry_run_and_keep(database, monkeypatch):
    ws, _ = database
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    result = CliRunner().invoke(app, ["db", "compact", "--dry-run", "--history", "2", "--keep", "3", "--json"])
    assert result.exit_code == 0, result.output
    output = json.loads(result.output)
    assert output["dry_run"] and "test_result_history" in output["before"]["tables_bytes"]
    assert CliRunner().invoke(app, ["db", "compact", "--keep", "0"]).exit_code == 2


def test_interrupted_stage_prunes_committed_history(database, monkeypatch):
    ws, factory = database
    monkeypatch.setenv("SIGHARVEST_TEST_HISTORY", "1")

    def interrupted(*args, **_kwargs):
        raise RuntimeError("stage interrupted")

    monkeypatch.setattr(testing, "_run_stage", interrupted)
    with factory() as s:
        with pytest.raises(RuntimeError, match="stage interrupted"):
            testing.run_stage(ws, s, "convert")
        assert len(list(s.scalars(select(TestResultHistory)))) == 3
        assert s.get(TestRun, 3).status == "interrupted"


def test_symlinked_backup_directory_is_never_pruned(database, tmp_path):
    ws, _ = database
    outside = tmp_path / "other-backups"
    outside.mkdir()
    for i in range(2):
        (outside / f"sigharvest.db.{i:032x}.sqlite3").write_text("unowned")
    (ws.db_path.parent / "migration-backups").symlink_to(outside, target_is_directory=True)
    assert db_compact.backup_candidates(ws.db_path) == []
    assert db_compact.compact(ws.db_path)["backup_files"] == 0
    assert len(list(outside.iterdir())) == 2


def test_lost_lease_rolls_back_pruning(database, monkeypatch):
    from contextlib import contextmanager

    ws, _ = database
    before = ws.db_path.read_bytes()

    class Owner:
        checks = 0

        def assert_owned(self):
            self.checks += 1
            if self.checks > 1:
                raise SigharvestError("lease lost")

    @contextmanager
    def lease(*args):
        yield Owner()

    monkeypatch.setattr(db_compact, "database_lease", lease)
    with pytest.raises(SigharvestError, match="lease lost"):
        db_compact.compact(ws.db_path, history=0)
    assert ws.db_path.read_bytes() == before


@pytest.fixture
def compact_result():
    before = {
        "database_bytes": 100_000,
        "wal_bytes": 20_000,
        "allocated_bytes": 110_000,
        "reusable_bytes": 4_096,
        "tables_bytes": {f"table_{i}": i * 1_024 for i in range(1, 9)},
        "result_rows": 30,
        "history_rows": 40,
    }
    after = dict(before, database_bytes=110_000, wal_bytes=0, reusable_bytes=8_192, history_rows=20)
    after["tables_bytes"] = {name: size // 2 for name, size in before["tables_bytes"].items()}
    return {
        "dry_run": False,
        "history_limit": 2,
        "before": before,
        "after": after,
        "prune": {"history_rows": 20, "superseded_result_rows": 0},
        "backup_files": 3,
        "backup_bytes": 999_999,
        "vacuum": False,
        "checkpoint_busy": False,
    }


def render_compact(result, width=120):
    from io import StringIO

    from rich.console import Console

    from sigharvest.cli.database_summary import print_compact_summary

    stream = StringIO()
    print_compact_summary(result, Console(file=stream, width=width, color_system=None))
    return stream.getvalue()


@pytest.mark.parametrize("width", [80, 120])
@pytest.mark.parametrize("preview", [False, True])
def test_summary_reconciles_dto_and_top_five(compact_result, width, preview):
    result = compact_result
    if preview:
        result.update(dry_run=True, after=result["before"], vacuum_required_bytes=70_000_000)
    output = render_compact(result, width)
    flat = " ".join(output.split())
    assert output.startswith("Preview" if preview else "Completed")
    action = "eligible" if preview else "removed"
    assert f"History rows {action}: 20" in output
    assert "History limit: 2 previous changes per result" in flat
    assert f"Migration backups {action}: 3 files; 999,999 bytes" in flat
    for label, key in (
        ("DB file", "database_bytes"),
        ("WAL file", "wal_bytes"),
        ("SQLite allocation", "allocated_bytes"),
        ("Reusable pages (bytes, not disk freed)", "reusable_bytes"),
    ):
        assert f"{label}: {result['before'][key]:,} bytes -> {result['after'][key]:,} bytes" in flat
    assert "History rows: 40 -> " + ("40" if preview else "20") in flat
    assert "current results: 30 -> 30" in flat
    for i in range(4, 9):
        assert f"table_{i}: {i * 1024:,} bytes -> {i * 1024 // (1 if preview else 2):,} bytes" in flat
    assert output.index("table_8:") < output.index("table_7:") < output.index("table_4:")
    assert "Other tables (3): 6,144 bytes -> " + ("6,144" if preview else "3,072") + " bytes" in flat
    assert "table_3:" not in output
    assert max(map(len, output.splitlines())) <= width
    if width == 120:
        assert len(output.splitlines()) <= 35
    if preview:
        assert "nothing deleted" in output
        assert "no compaction was measured" in output
        assert "No space was freed" in output
        assert "not run; requires at least 70,000,000 bytes free" in flat
        assert "file-size reduction" not in output
    else:
        assert "DB file change (after - before): +10,000 bytes" in flat
        assert "WAL file change (after - before): -20,000 bytes" in flat
        assert "DB + WAL file-size reduction: +10,000 bytes" in flat
        assert "No vacuum" in output
        assert "does not shrink the file" in flat


def test_summary_reports_growth_and_busy_checkpoint(compact_result):
    compact_result["after"]["database_bytes"] = 150_000
    compact_result["checkpoint_busy"] = True
    output = render_compact(compact_result)
    assert "DB + WAL file-size reduction: -30,000 bytes (negative means growth)" in output
    assert "Checkpoint busy" in output


@pytest.mark.parametrize("width", [80, 120])
def test_summary_names_are_literal_and_complete(compact_result, width):
    from rich.cells import cell_len

    name = "[bold]long_" + "table_" * 40 + "é漢[/bold]\n\x1b[31m\t"
    compact_result["before"]["tables_bytes"] = {name: 123_456}
    compact_result["after"]["tables_bytes"] = {name: 65_432}
    output = render_compact(compact_result, width)
    joined = "".join(output.split())
    assert "[bold]long_" in output and "[/bold]\\n\\x1b[31m\\t" in joined
    assert "table_" * 40 in joined
    assert "\x1b" not in output
    assert "123,456 bytes" in output and "65,432 bytes" in output
    assert max(map(cell_len, output.splitlines())) <= width


def test_summary_only_reads_dto(compact_result, monkeypatch):
    from copy import deepcopy
    from io import StringIO

    from rich.console import Console

    from sigharvest.cli.database_summary import compact_summary, print_compact_summary

    original = deepcopy(compact_result)
    output = StringIO()
    terminal = Console(file=output, width=80, color_system=None)

    def forbidden(*args, **kwargs):
        pytest.fail("renderer must not access storage or repeat maintenance")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(db_compact, "compact", forbidden)
    monkeypatch.setattr(db_compact, "storage_stats", forbidden)
    for method in ("stat", "open", "unlink", "iterdir"):
        monkeypatch.setattr(Path, method, forbidden)
    assert compact_summary(compact_result).startswith("Completed")
    print_compact_summary(compact_result, terminal)
    assert output.getvalue().startswith("Completed")
    assert compact_result == original


@pytest.mark.parametrize(
    "tty,explicit_json,force_color",
    [(False, False, False), (False, False, True), (True, False, False), (True, False, True), (True, True, False), (True, True, True)],
)
@pytest.mark.parametrize("dry_run", [False, True])
def test_cli_dispatch_calls_compact_once_with_unchanged_arguments(compact_result, monkeypatch, tmp_path, tty, explicit_json, force_color, dry_run):
    from unittest.mock import Mock

    from sigharvest.cli import database as cli

    if dry_run:
        compact_result.update(dry_run=True, after=compact_result["before"], vacuum_required_bytes=70_000_000)
    operation = Mock(return_value=compact_result)
    monkeypatch.setattr(cli, "compact", operation)
    monkeypatch.setattr(cli, "find_workspace", lambda: SimpleNamespace(db_path=tmp_path / "sigharvest.db"))
    args = ["db", "compact", "--history", "2", "--keep", "3", "--vacuum"]
    if dry_run:
        args += ["--dry-run"]
    if explicit_json:
        args += ["--json"]
    env = {"FORCE_COLOR": "1"} if force_color else {}
    result = CliRunner(env=env).invoke(app, args)
    assert result.exit_code == 0, result.output
    operation.assert_called_once_with(tmp_path / "sigharvest.db", dry_run=dry_run, history=2, keep=3, vacuum=True)
    if explicit_json:  # JSON only when asked for, terminal or not (docs/conventions.md)
        assert result.output == json.dumps(compact_result) + "\n"
        assert json.loads(result.output) == compact_result
    else:
        assert result.output.startswith("Preview" if dry_run else "Completed")


@pytest.mark.parametrize("vacuum", [False, True])
def test_empty_history_and_local_vacuum_summary(database, vacuum):
    ws, factory = database
    with factory() as session:
        session.query(TestResultHistory).delete()
        session.commit()
    result = db_compact.compact(ws.db_path, vacuum=vacuum)
    output = render_compact(result)
    assert "History rows removed: 0" in output
    assert "History rows: 0 -> 0" in output
    assert ("Vacuum completed" if vacuum else "No vacuum") in output


def test_live_local_wal_and_multiple_simulated_backups(database):
    from contextlib import closing

    ws, _ = database
    folder = ws.db_path.parent / "migration-backups"
    folder.mkdir()
    backups = []
    for i in range(4):
        path = folder / f"{ws.db_path.name}.{i:032x}.sqlite3"
        path.write_bytes(b"local simulated backup" * (i + 1))
        os.utime(path, (i + 1, i + 1))
        backups.append(path)
    with closing(sqlite3.connect(ws.db_path)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("UPDATE test_results SET duration=1")
        conn.commit()
        before = {p: p.read_bytes() for p in [ws.db_path, ws.db_path.with_name(ws.db_path.name + "-wal"), *backups]}
        plan = db_compact.compact(ws.db_path, dry_run=True, history=0)
        assert plan["before"]["wal_bytes"] > 0
        assert plan["backup_files"] == 3
        assert plan["backup_bytes"] == sum(len(before[p]) for p in backups[:3])
        assert all(p.read_bytes() == data for p, data in before.items())
        result = db_compact.compact(ws.db_path, history=0)
        assert result["backup_files"] == plan["backup_files"]
        assert result["backup_bytes"] == plan["backup_bytes"]
        assert result["after"]["database_bytes"] >= result["before"]["database_bytes"]
        assert all(not p.exists() for p in backups[:3]) and backups[3].exists()
        assert f"WAL file: {result['before']['wal_bytes']:,} bytes -> {result['after']['wal_bytes']:,} bytes" in render_compact(result)


@pytest.mark.parametrize("json_output", [False, True])
def test_missing_database_never_reports_completed(tmp_path, monkeypatch, json_output):
    from sigharvest.cli import database as cli

    monkeypatch.setattr(cli, "find_workspace", lambda: SimpleNamespace(db_path=tmp_path / "missing.db"))
    result = CliRunner().invoke(app, ["db", "compact", *(["--json"] if json_output else [])])
    assert result.exit_code == 2
    assert "workspace database does not exist" in result.output
    assert "Completed" not in result.output and "Preview" not in result.output
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("message", ["SQLite dbstat support is required for per-table space reporting", "VACUUM needs at least 42 free bytes", "lease lost"])
def test_cli_backend_errors_do_not_render_success(monkeypatch, tmp_path, message):
    from sigharvest.cli import database as cli

    def refused(*args, **kwargs):
        raise SigharvestError(message)

    monkeypatch.setattr(cli, "compact", refused)
    monkeypatch.setattr(cli, "find_workspace", lambda: SimpleNamespace(db_path=tmp_path / "sigharvest.db"))
    result = CliRunner().invoke(app, ["db", "compact"])
    assert result.exit_code == 2
    assert message in result.output
    assert "Completed" not in result.output


def test_cli_lock_refusal_exits_two(monkeypatch, tmp_path):
    from sigharvest.cli import database as cli
    from sigharvest.lock import LockHeld

    def refused(*args, **kwargs):
        raise LockHeld("workspace busy")

    monkeypatch.setattr(cli, "compact", refused)
    monkeypatch.setattr(cli, "find_workspace", lambda: SimpleNamespace(db_path=tmp_path / "sigharvest.db"))
    result = CliRunner().invoke(app, ["db", "compact"])
    assert result.exit_code == 2 and "workspace busy" in result.output
    assert "Completed" not in result.output


def test_dbstat_and_schema_refusals_preserve_database(database, monkeypatch):
    from contextlib import contextmanager

    ws, _ = database
    original = ws.db_path.read_bytes()

    class NoDbstat:
        def execute(self, sql):
            if "dbstat" in sql:
                raise sqlite3.OperationalError("no such table: dbstat")
            return SimpleNamespace(fetchone=lambda: (4096,))

    with pytest.raises(SigharvestError, match="dbstat support"):
        db_compact.storage_stats(NoDbstat(), ws.db_path)

    @contextmanager
    def refused(*args, **kwargs):
        raise SigharvestError("workspace lock unavailable")
        yield  # pragma: no cover

    monkeypatch.setattr(db_compact, "database_lease", refused)
    with pytest.raises(SigharvestError, match="workspace lock unavailable"):
        db_compact.compact(ws.db_path)
    assert ws.db_path.read_bytes() == original
