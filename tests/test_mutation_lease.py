"""The workspace lock: process races, crash release, migrations under the lock, CLI/web mutation coverage."""

from __future__ import annotations

import multiprocessing as mp
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from sqlalchemy import text
from typer.testing import CliRunner

from sigharvest.cli import app
from sigharvest.config import Workspace, save_sources
from sigharvest.db import session_factory
from sigharvest.lock import LockHeld, UpdateLock, holder, lock_path, mutation_lease
from sigharvest.schema import head_revision, revision


def _contender(root, start, finish, results):
    start.wait(15)
    try:
        with UpdateLock(Workspace(Path(root))):
            results.put("owner")
            finish.wait(10)
    except LockHeld:
        results.put("busy")


def _abandon(root, ready):
    lock = UpdateLock(Workspace(Path(root)))
    lock.acquire()
    ready.set()
    os._exit(0)


def _migrate(path, start, results):
    start.wait(10)
    try:
        factory = session_factory(Path(path), migrate=True)
        with factory() as s:
            results.put(s.scalar(text("SELECT version_num FROM alembic_version")))
    except Exception as exc:  # noqa: BLE001 - return child failures to the parent assertion
        results.put(repr(exc))


@pytest.mark.slow
def test_competing_stale_contenders_and_crash(tmp_path):
    ws = Workspace(tmp_path)
    ctx = mp.get_context("spawn")
    ready = ctx.Event()
    crashed = ctx.Process(target=_abandon, args=(str(ws.root), ready))
    crashed.start()
    assert ready.wait(10)
    crashed.join(10)
    assert crashed.exitcode == 0
    assert holder(lock_path(ws)) is None  # the kernel released the dead owner's lock
    # Two independent processes race for the free lock. Both reach the barrier
    # before either may acquire; the winner stays alive until the loser reports.
    # pytest + spawn tracker + two actors = four total processes.
    start, finish, results = ctx.Barrier(3), ctx.Event(), ctx.Queue()
    contenders = [ctx.Process(target=_contender, args=(str(ws.root), start, finish, results)) for _ in range(2)]
    try:
        for process in contenders:
            process.start()
        start.wait(15)
        outcomes = [results.get(timeout=15) for _ in contenders]
        assert sorted(outcomes) == ["busy", "owner"]
    finally:
        finish.set()
        for process in contenders:
            process.join(10)
            if process.is_alive():
                process.kill()
                process.join()
    assert all(p.exitcode == 0 for p in contenders)
    assert holder(lock_path(ws)) is None


def test_nested_stages_reuse_lease_but_other_threads_cannot(tmp_path):
    ws = Workspace(tmp_path)
    with mutation_lease(ws) as outer:
        with mutation_lease(ws) as inner:
            assert outer is inner
        with ThreadPoolExecutor(1) as pool, pytest.raises(LockHeld):
            pool.submit(UpdateLock(ws).acquire).result()
        outer.assert_owned()


def test_simultaneous_migration_and_backup_of_wal(tmp_path):
    db = tmp_path / "data" / "sigharvest.db"
    db.parent.mkdir()
    # Legacy unversioned database, with committed user data still in WAL.
    original = sqlite3.connect(db)
    original.execute("PRAGMA journal_mode=WAL")
    original.execute("PRAGMA wal_autocheckpoint=0")
    original.execute("CREATE TABLE operator_notes (note TEXT)")
    original.execute("INSERT INTO operator_notes VALUES ('keep me')")
    original.commit()
    ctx = mp.get_context("spawn")
    # The controller is the third independent migration actor, after all actors
    # reach the same barrier. No migration is serialized by the test harness.
    start, results = ctx.Barrier(3), ctx.Queue()
    processes = [ctx.Process(target=_migrate, args=(str(db), start, results)) for _ in range(2)]
    try:
        for process in processes:
            process.start()
        _migrate(str(db), start, results)
        assert [results.get(timeout=20) for _ in range(3)] == [head_revision()] * 3
    finally:
        original.close()
        for process in processes:
            process.join(10)
            if process.is_alive():
                process.kill()
                process.join()
    backups = list((db.parent / "migration-backups").glob("*.sqlite3"))
    assert len(backups) == 1
    assert backups[0].stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(backups[0]) as backup:
        assert backup.execute("SELECT note FROM operator_notes").fetchone() == ("keep me",)
        assert not backup.execute("SELECT 1 FROM sqlite_master WHERE name='alembic_version'").fetchone()
    import shutil

    restored = tmp_path / "restore" / "sigharvest.db"
    restored.parent.mkdir()
    shutil.copyfile(backups[0], restored)
    with session_factory(restored, migrate=True)() as s:
        assert s.scalar(text("SELECT note FROM operator_notes")) == "keep me"
    assert revision(db) == head_revision()
    session_factory(db, migrate=True)
    assert len(list(backups[0].parent.glob("*.sqlite3"))) == 1


@pytest.mark.parametrize(
    "command",
    [
        ["quarantine", "retry", "1", "--parser", "current"],
        ["sync"],
        ["update"],
        ["test"],
        ["index"],
        ["sources", "add", "example", "https://example.com/rules.git"],
        ["sources", "remove", "example"],
        ["sources", "enable", "example"],
        ["sources", "disable", "example"],
        ["collection", "create", "new"],
        ["collection", "add", "new", "abcdef"],
        ["collection", "remove", "new", "abcdef"],
        ["collection", "rename", "new", "other"],
        ["collection", "delete", "new", "--yes"],
        ["collection", "update", "new"],
        ["runs", "accept"],
        ["discover"],
        ["report"],
        ["doctor", "--clean-cache", "--yes"],
    ],
)
def test_mutating_commands_refuse_before_side_effects(tmp_path, command):
    ws = Workspace(tmp_path)
    save_sources(ws, [])
    session_factory(ws.db_path, migrate=True)
    before = ws.sources_file.read_bytes()
    with UpdateLock(ws):
        result = CliRunner().invoke(app, command, env={"SIGHARVEST_HOME": str(ws.root)})
    assert result.exit_code == 2, (command, result.output, result.exception)
    assert "busy" in result.output
    assert ws.sources_file.read_bytes() == before


def test_init_locks_its_destination_not_current_workspace(tmp_path):
    ws = Workspace(tmp_path / "destination")
    with UpdateLock(ws):
        result = CliRunner().invoke(app, ["init", str(ws.root)])
        assert result.exit_code == 2
        assert not ws.sources_file.exists()


def test_read_commands_remain_available_during_writer(tmp_path):
    from tests.test_collections import _setup

    _repo, ws, _sessions = _setup(tmp_path)
    with UpdateLock(ws):
        for command in (["search", "Test"], ["stats"], ["sources", "list"], ["runs", "list"], ["collection", "list"]):
            result = CliRunner().invoke(app, command, env={"SIGHARVEST_HOME": str(ws.root)})
            assert result.exit_code == 0, result.output


def test_unknown_or_changed_schema_refuses_normal_sessions(tmp_path):
    from sigharvest.errors import SigharvestError

    db = tmp_path / "test.sqlite3"
    factory = session_factory(db, migrate=True)
    with sqlite3.connect(db) as connection:
        connection.execute("UPDATE alembic_version SET version_num='future' ")
    with pytest.raises(SigharvestError, match="schema changed"), factory() as s:
        s.execute(text("SELECT 1"))
    with pytest.raises(SigharvestError, match="newer or unknown"):
        session_factory(db, migrate=True)
    assert not (db.parent / "migration-backups").exists()


def test_failed_backup_never_runs_migration(tmp_path, monkeypatch):
    import sigharvest.schema as module

    db = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE notes (value TEXT)")
    before = db.read_bytes()

    def fail(*args):
        raise OSError("disk full")

    monkeypatch.setattr(module, "migration_backup", fail)
    with pytest.raises(OSError, match="disk full"):
        session_factory(db, migrate=True)
    assert db.read_bytes() == before


def test_failed_migration_retains_completed_backup(tmp_path, monkeypatch):
    import sigharvest.schema as module

    db = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE notes (value TEXT)")

    def fail(*args):
        raise RuntimeError("injected migration failure")

    monkeypatch.setattr(module.command, "upgrade", fail)
    with pytest.raises(RuntimeError, match="injected"):
        session_factory(db, migrate=True)
    (backup,) = (db.parent / "migration-backups").glob("*.sqlite3")
    with sqlite3.connect(backup) as conn:
        assert conn.execute("SELECT count(*) FROM notes").fetchone() == (0,)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork descriptor contract")
def test_forked_worker_does_not_keep_abandoned_parent_lease(tmp_path):
    # The child inherits descriptors but has no right to keep a parent's lease alive.
    ws = Workspace(tmp_path)
    ready_read, ready_write = os.pipe()
    finish_read, finish_write = os.pipe()
    child = None
    try:
        with UpdateLock(ws):
            child = os.fork()
            if child == 0:
                os.close(ready_read)
                os.close(finish_write)
                os.write(ready_write, b"1")
                os.read(finish_read, 1)
                os._exit(0)
            os.close(ready_write)
            os.close(finish_read)
            assert os.read(ready_read, 1) == b"1"
        with UpdateLock(ws):
            pass  # child is still alive, but did not keep the inherited guard
    finally:
        if child:
            os.write(finish_write, b"1")
            os.waitpid(child, 0)
        os.close(ready_read)
        os.close(finish_write)


@pytest.mark.parametrize("owner,contender", [("sync", "update"), ("update", "sync")])
def test_manual_sync_and_update_share_operation_lease(tmp_path, monkeypatch, owner, contender):
    from sigharvest.cli import pipeline

    ws = Workspace(tmp_path)
    save_sources(ws, [])
    session_factory(ws.db_path, migrate=True)

    def probe(*args, **kwargs):
        with ThreadPoolExecutor(1) as pool:
            result = pool.submit(CliRunner().invoke, app, [contender], env={"SIGHARVEST_HOME": str(ws.root)}).result()
        assert result.exit_code == 2, result.output
        return [] if owner == "sync" else 0

    monkeypatch.setattr(pipeline, "_sync" if owner == "sync" else "_update", probe)
    result = CliRunner().invoke(app, [owner], env={"SIGHARVEST_HOME": str(ws.root)})
    assert result.exit_code == 0, (result.output, result.exception)


HOLD = """
import sys, time
from pathlib import Path
from sigharvest.config import Workspace
from sigharvest.lock import mutation_lease
with mutation_lease(Workspace(Path(sys.argv[1]))) as lock:
    lock.set_operation("update")
    print("held", flush=True)
    time.sleep(60)
"""


def test_second_writer_names_the_holder_and_a_killed_holder_frees_the_lock(tmp_path):
    import signal
    import subprocess
    import sys

    ws = Workspace(tmp_path)
    child = subprocess.Popen([sys.executable, "-c", HOLD, str(ws.root)], stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout is not None and child.stdout.readline().strip() == "held"
        with pytest.raises(LockHeld, match=rf"busy \(pid {child.pid} on .*: update\)"), mutation_lease(ws):
            pass
        assert holder(lock_path(ws)).startswith(f"pid {child.pid} ")
        result = CliRunner().invoke(app, ["sync"], env={"SIGHARVEST_HOME": str(ws.root)})
        assert result.exit_code == 2 and f"pid {child.pid}" in result.output
    finally:
        child.send_signal(signal.SIGKILL)
        child.wait(10)
    assert holder(lock_path(ws)) is None
    with mutation_lease(ws) as lock:
        assert holder(lock_path(ws)).startswith(f"pid {os.getpid()} ")  # a second descriptor conflicts even in-process
        lock.assert_owned()


@pytest.mark.parametrize("raw", ["[" * 2048 + "]" * 2048, "x" * 5000, '{"pid": 0, "host": "old-format"}', ""])
def test_leftover_lock_file_content_never_blocks(tmp_path, raw):
    """Only the kernel lock counts: whatever a previous version or a crash left in the file is overwritten."""
    ws = Workspace(tmp_path)
    path = lock_path(ws)
    path.parent.mkdir()
    path.write_text(raw)
    (path.parent / ".update.lock.guard").write_text("")  # left behind by an older version
    assert holder(path) is None
    with mutation_lease(ws):
        assert path.read_text().startswith(f"pid {os.getpid()} ")
    assert path.read_text() == ""


def test_refused_command_keeps_the_lock_file_of_the_holder(tmp_path, monkeypatch):
    """A refused writer on a folder that was not there when it started must not unlink the holder's lock file."""
    import threading

    import typer

    import sigharvest.conversion_spills  # noqa: F401  (bind the real mutation_lease before patching)
    import sigharvest.lock as lock
    from sigharvest.cli.common import mutation_command

    root = tmp_path / "new"
    in_body, leave = threading.Event(), threading.Event()

    @mutation_command(workspace_arg="path")
    def init_like(path: str) -> None:
        in_body.set()
        leave.wait(10)

    holder_thread = threading.Thread(target=lambda: init_like(str(root)))
    real_lease = lock.mutation_lease

    def late_lease(ws, *, timeout=0):  # the refused command sampled "not there" before the holder created it
        if threading.current_thread() is threading.main_thread() and not holder_thread.is_alive():
            holder_thread.start()
            assert in_body.wait(10)
        return real_lease(ws, timeout=timeout)

    monkeypatch.setattr(lock, "mutation_lease", late_lease)
    try:
        with pytest.raises(typer.Exit) as refused:
            init_like(str(root))
        assert refused.value.exit_code == 2
        assert lock_path(Workspace(root)).exists()
        with pytest.raises(LockHeld):
            UpdateLock(Workspace(root)).acquire()
    finally:
        leave.set()
        holder_thread.join(10)


def test_waiter_on_a_cleaned_up_lock_file_reopens_it(tmp_path, monkeypatch):
    """A writer waiting on the lock of a folder whose failed command removes it locks the file that is there now."""
    import threading
    import time

    import sigharvest.lock as lock
    from sigharvest.cli.common import mutation_command

    root = tmp_path / "new"
    ws = Workspace(root)
    waiting, release = threading.Event(), threading.Event()
    real_try = lock._try_lock

    def observed_try(fd, shared=False):
        ok = real_try(fd, shared)
        if not ok and threading.current_thread() is not threading.main_thread():
            waiting.set()
        return ok

    monkeypatch.setattr(lock, "_try_lock", observed_try)

    @mutation_command(workspace_arg="path")
    def failing_init(path: str) -> None:
        threading.Thread(target=waiter, daemon=True).start()
        assert waiting.wait(10)
        raise RuntimeError("bad pack")

    got: list[UpdateLock] = []

    def waiter() -> None:
        w = UpdateLock(ws, timeout=10)
        w.acquire()
        got.append(w)
        release.wait(10)
        w.release()

    with pytest.raises(RuntimeError, match="bad pack"):
        failing_init(str(root))
    deadline = time.monotonic() + 10
    while not got and time.monotonic() < deadline:
        time.sleep(0.01)
    try:
        assert got, "the waiter never acquired"
        path = lock_path(ws)
        assert os.fstat(got[0].fd).st_ino == os.stat(path).st_ino  # locked on the file at the path, not an unlinked one
        with pytest.raises(LockHeld):
            UpdateLock(ws).acquire()
    finally:
        release.set()
