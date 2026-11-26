"""Workspace lock: one writer (sync, update, test, index, collection edits, migrations) at a time.

Readers (search, show, the web UI) do not lock: SQLite WAL gives them the last committed snapshot. The lock is an
flock on data/sigharvest.lock, so the kernel releases it when the process dies and a crash never leaves a stale lock.
The file records who holds it, for the "busy" message and `sigharvest doctor`.

One operation owns its nested stages (update -> sync -> test -> index): a second `mutation_lease` in the same
context reuses the held lock. Another thread or process gets LockHeld. POSIX only: Windows is supported through WSL.
"""

from __future__ import annotations

import os
import socket
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from pathlib import Path
from types import TracebackType

from sigharvest.config import Workspace
from sigharvest.errors import SigharvestError

WSL_DOCS = "https://github.com/threat-hunter-eu/sigharvest/blob/main/docs/getting-started.md#windows-use-wsl"
_ACTIVE_FDS: set[int] = set()
LOCK_NAME = "sigharvest.lock"  # data/sigharvest.lock (before 0.1.0: data/.update.lock)


def _after_fork() -> None:
    # A forked worker must not keep the parent's lock alive through an inherited descriptor.
    for fd in _ACTIVE_FDS:
        with suppress(OSError):
            os.close(fd)
    _ACTIVE_FDS.clear()
    _OWNERS.set(())


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)


class LockHeld(SigharvestError, RuntimeError):
    """Another writer owns the workspace."""


def lock_path(ws: Workspace) -> Path:
    return ws.db_path.parent / LOCK_NAME


def database_lock_path(db_path: Path) -> Path:
    """Workspace databases share the CLI lock; a standalone library database has its own."""
    db_path = db_path.resolve()
    if db_path.name == "sigharvest.db" and db_path.parent.name == "data":
        return db_path.parent / LOCK_NAME
    return db_path.with_name(db_path.name + ".mutation.lock")


# A writer that finds the lock taken retries this long before LockHeld even with timeout 0: `holder()` (doctor) probes
# the lock for a few microseconds, and a writer starting at that moment must not fail.
PROBE_GRACE = 0.5


def _try_lock(fd: int, shared: bool = False) -> bool:
    import fcntl

    try:
        fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _read_holder(path: Path) -> str:
    try:
        with path.open("rb") as f:
            text = f.read(4096).decode("utf-8", "replace")
    except OSError:
        text = ""
    return text.strip("\x00 \r\n\t") or "another sigharvest process"


def holder(path: Path) -> str | None:
    """Who holds the lock at `path` (its recorded text), or None when nobody does.

    Probes with a shared lock for a few microseconds: probes never conflict with each other, and a writer that starts
    meanwhile retries for PROBE_GRACE instead of failing."""
    if os.name != "posix" or not path.exists():
        return None
    try:
        fd = os.open(path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    try:
        if _try_lock(fd, shared=True):
            return None  # closing the descriptor below releases it
        return _read_holder(path)
    finally:
        os.close(fd)


class UpdateLock:
    """The exclusive lock itself; independent acquisitions (even in one process) conflict."""

    def __init__(self, ws: Workspace, *, timeout: float = 0, path: Path | None = None) -> None:
        self.path = path or lock_path(ws)
        self.timeout = timeout
        self.fd: int | None = None
        self.pid = os.getpid()
        self.operation = ""

    def acquire(self) -> None:
        if os.name != "posix":
            raise LockHeld(f"the workspace lock needs POSIX flock on a local filesystem. Windows is supported through WSL: {WSL_DOCS}")
        deadline = time.monotonic() + max(self.timeout, PROBE_GRACE)
        while True:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
            except FileNotFoundError:
                if time.monotonic() >= deadline:
                    raise LockHeld(f"workspace is busy (its folder keeps being removed); retry when it finishes. Lock file: {self.path}") from None
                continue  # a failed command removed the folder it created between mkdir and open
            try:
                while not _try_lock(fd):
                    if time.monotonic() >= deadline:
                        raise LockHeld(f"workspace is busy ({_read_holder(self.path)}); retry when it finishes. Lock file: {self.path}")
                    time.sleep(0.05)
                if self._is_current(fd):
                    break
            except BaseException:
                os.close(fd)
                raise
            os.close(fd)  # locked a file its holder unlinked while we waited: lock the one at the path now
        self.fd, self.pid = fd, os.getpid()
        _ACTIVE_FDS.add(fd)
        self._write()

    def _is_current(self, fd: int) -> bool:
        """The locked descriptor is still the file at the path (a failed `init` removes the lock file it created)."""
        try:
            at_path = os.lstat(self.path)
        except FileNotFoundError:
            return False
        locked = os.fstat(fd)
        return (locked.st_dev, locked.st_ino) == (at_path.st_dev, at_path.st_ino)

    def _write(self) -> None:
        assert self.fd is not None
        started = time.strftime("%Y-%m-%d %H:%M:%S")
        text = f"pid {os.getpid()} on {socket.gethostname()} since {started}" + (f": {self.operation}" if self.operation else "")
        os.ftruncate(self.fd, 0)
        os.pwrite(self.fd, text.encode() + b"\n", 0)

    def set_operation(self, operation: str) -> None:
        """Record a short operation name (never CLI arguments) for the busy message."""
        self.assert_owned()
        self.operation = operation[:80]
        self._write()

    def assert_owned(self) -> None:
        if self.fd is None:
            raise LockHeld("workspace lock has been released")
        if self.pid != os.getpid():
            raise LockHeld("workspace lock belongs to the parent process")

    def release(self) -> None:
        if self.fd is not None:
            if self.pid == os.getpid():
                _ACTIVE_FDS.discard(self.fd)
                with suppress(OSError):
                    os.ftruncate(self.fd, 0)
                os.close(self.fd)  # releases the flock
            self.fd = None

    def __enter__(self) -> UpdateLock:
        self.acquire()
        return self

    def __exit__(self, et: type[BaseException] | None, ev: BaseException | None, tb: TracebackType | None) -> None:
        self.release()


_OWNERS: ContextVar[tuple[UpdateLock, ...]] = ContextVar("sigharvest_mutation_owners", default=())


@contextmanager
def _lease_path(path: Path, timeout: float) -> Iterator[UpdateLock]:
    path = path.resolve()
    for owner in _OWNERS.get():
        if owner.path == path:
            owner.assert_owned()
            yield owner
            return
    with UpdateLock(Workspace(path.parent.parent), timeout=timeout, path=path) as owner:
        if path.name == LOCK_NAME:
            from sigharvest.conversion_spills import require_quiescent

            require_quiescent(Workspace(path.parent.parent))
        reset = _OWNERS.set((*_OWNERS.get(), owner))
        try:
            yield owner
        finally:
            _OWNERS.reset(reset)


@contextmanager
def mutation_lease(ws: Workspace, *, timeout: float = 0) -> Iterator[UpdateLock]:
    """Own the workspace for one operation; nested stages in the same context reuse it."""
    with _lease_path(lock_path(ws), timeout) as owner:
        yield owner


@contextmanager
def database_lease(db_path: Path, *, timeout: float = 0) -> Iterator[UpdateLock]:
    """The same lock for database-only callers (migrations), including standalone library databases."""
    with _lease_path(database_lock_path(db_path), timeout) as owner:
        yield owner
