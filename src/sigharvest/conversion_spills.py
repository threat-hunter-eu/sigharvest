"""Workspace-local spill ownership; kernel exclusion, never age, authorizes recovery.

The parent and every writing task hold independent shared flocks. Recovery takes
an exclusive flock and revalidates bounded metadata and inode bindings. Delayed
workers cannot recreate an attempt or write after recovery has taken ownership.
New attempts require local Linux directory flock and user extended attributes.
The atomic inode attribute is both the publication point and final deletion proof;
no separate marker/guard removal can strand a published protocol-2 directory.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import socket
import stat
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from sigharvest.config import Workspace
from sigharvest.conversion_output import MAX_PENDING_OUTPUT_BYTES, RULE_REPLY_BYTES, CleanupFailure
from sigharvest.lock import LockHeld, mutation_lease

ROOT = ".conversion-spills"
PROTOCOL = 2
OWNER_ATTRIBUTE = "user.sigharvest.conversion-owner"
MAX_ATTEMPTS = 32
# Every reservable spill slot (conversion_output.pending_output_bytes grows with -j), marker,
# guard and bounded headroom; a smaller limit made cleanup refuse after -j > 8.
MAX_FILES = MAX_PENDING_OUTPUT_BYTES // RULE_REPLY_BYTES + 4
# Recovery inspects at most what the largest spill reservation could leave behind.
MAX_WORK_BYTES = MAX_PENDING_OUTPUT_BYTES
MAX_MARKER_BYTES = 4096
DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _process_identity(pid: int) -> str:
    """Linux boot and process start ticks distinguish a reused PID without a clock."""
    try:
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return f"{boot}:{fields[19]}"
    except (OSError, IndexError):
        return ""


def refuse(reason: str) -> CleanupFailure:
    return CleanupFailure(f"conversion spill recovery refused ({reason}); preserve the directory, stop its writers and inspect ownership before retrying")


class SpillBusy(CleanupFailure, LockHeld):
    """Lease admission failed; retain the existing spill recovery error contract."""


def _check(info: os.stat_result, directory: bool = False) -> None:
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not valid_type or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
        raise refuse("unsafe type, permissions or ownership")
    if not directory and info.st_nlink != 1:
        raise refuse("linked file")


def _same(fd: int, parent: int, name: str) -> None:
    before, current = os.fstat(fd), os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
        raise refuse("inode replaced")
    _check(current, stat.S_ISDIR(before.st_mode))


def _names(fd: int, maximum: int) -> list[str]:
    names: list[str] = []
    with os.scandir(fd) as entries:
        for entry in entries:
            if len(names) == maximum:
                raise refuse("inventory limit")
            names.append(entry.name)
    return sorted(names)


@contextmanager
def _opened(name: str, flags: int, parent: int | None = None) -> Iterator[int]:
    if not all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")):
        raise refuse("local no-follow directory descriptors required")
    fd = os.open(name, flags, 0o600, dir_fd=parent)
    try:
        yield fd
    finally:
        os.close(fd)


def _flock(fd: int, *, exclusive: bool) -> None:
    import fcntl

    fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    data = dict(pairs)
    if len(data) != len(pairs):
        raise ValueError("duplicate marker field")
    return data


@dataclass(frozen=True)
class Ticket:
    root: str
    workspace: str
    name: str
    device: int
    inode: int


class Attempt:
    def __init__(self, ticket: Ticket, root: int, directory: int, guard: int | None = None) -> None:
        self.ticket, self.root, self.directory = ticket, root, directory
        self.legacy = guard is not None
        self.guard = directory if guard is None else guard

    def validate(self) -> dict[str, Any]:
        t = self.ticket
        if not re.fullmatch(r"[0-9a-f]{32}", t.name):
            raise refuse("unknown attempt name")
        _check(os.fstat(self.root), True)
        root_now = os.stat(t.root, follow_symlinks=False)
        _check(root_now, True)
        if (root_now.st_dev, root_now.st_ino) != (os.fstat(self.root).st_dev, os.fstat(self.root).st_ino):
            raise refuse("root replaced")
        _same(self.directory, self.root, t.name)
        if self.legacy:
            _same(self.guard, self.directory, "guard")
            if os.fstat(self.guard).st_size != 0:
                raise refuse("nonempty guard")
        if (os.fstat(self.directory).st_dev, os.fstat(self.directory).st_ino) != (t.device, t.inode):
            raise refuse("attempt replaced")
        if self.legacy:
            with _opened("marker", FILE_FLAGS, self.directory) as fd:
                _check(os.fstat(fd))
                raw = os.read(fd, MAX_MARKER_BYTES + 1)
                _same(fd, self.directory, "marker")
        else:
            raw = os.getxattr(self.directory, OWNER_ATTRIBUTE)
        try:
            if len(raw) > MAX_MARKER_BYTES:
                raise ValueError
            data = json.loads(raw, object_pairs_hook=_unique_pairs)
            expected = {"protocol", "workspace", "attempt", "device", "inode", "pid", "process", "host"}
            if self.legacy:
                expected.add("guard")
            if (
                not isinstance(data, dict)
                or set(data) != expected
                or type(data["protocol"]) is not int
                or data["protocol"] != (1 if self.legacy else PROTOCOL)
                or data["workspace"] != t.workspace
                or data["attempt"] != t.name
                or type(data["device"]) is not int
                or data["device"] != t.device
                or type(data["inode"]) is not int
                or data["inode"] != t.inode
                or (self.legacy and (type(data["guard"]) is not int or data["guard"] != os.fstat(self.guard).st_ino))
                or type(data["pid"]) is not int
                or not 0 < data["pid"] < 2**31
                or data["host"] != socket.gethostname()
                or not isinstance(data["process"], str)
                or not re.fullmatch(r"[0-9a-f-]{36}:[0-9]+", data["process"])
            ):
                raise ValueError
        except (ValueError, TypeError, KeyError, RecursionError):
            raise refuse("invalid marker or workspace binding") from None
        return data

    def inventory(self) -> tuple[list[str], int]:
        self.validate()
        names = _names(self.directory, MAX_FILES)
        total = 0 if self.legacy else len(os.getxattr(self.directory, OWNER_ATTRIBUTE))
        metadata = {"marker", "guard"} if self.legacy else set()
        for name in names:
            if name not in metadata and not re.fullmatch(r"[1-9][0-9]{0,18}", name):
                raise refuse("unknown file")
            info = os.stat(name, dir_fd=self.directory, follow_symlinks=False)
            _check(info)
            if info.st_size > (MAX_MARKER_BYTES if name in {"marker", "guard"} else RULE_REPLY_BYTES):
                raise refuse("file byte limit")
            total += info.st_size
        return names, total

    def slot(self, version_id: int) -> Path:
        self.validate()
        if type(version_id) is not int or not 0 < version_id < 10**19:
            raise refuse("invalid slot")
        # Anchor IO to the already checked directory, not a re-resolved pathname.
        return Path(f"/proc/self/fd/{self.directory}/{version_id}")

    def require_live_parent(self) -> None:
        """Reject delayed tasks before backend execution while holding the shared flock."""
        marker = self.validate()
        if not _alive(marker["pid"]) or _process_identity(marker["pid"]) != marker["process"]:
            raise refuse("worker parent exited or changed identity")

    def discard(self, version_id: int) -> None:
        """Delete one slot left by a lost worker, so the rule can be converted again."""
        self.slot(version_id)
        name = str(version_id)
        try:
            with _opened(name, FILE_FLAGS, self.directory) as fd:
                _same(fd, self.directory, name)
                os.unlink(name, dir_fd=self.directory)
        except FileNotFoundError:
            return

    def remove(self) -> int:
        _flock(self.guard, exclusive=True)
        names, size = self.inventory()
        for name in names:
            if name in {"marker", "guard"}:
                continue
            self.validate()
            # Reopen and compare at use; no recursive traversal or followed links.
            with _opened(name, FILE_FLAGS, self.directory) as fd:
                _same(fd, self.directory, name)
                os.unlink(name, dir_fd=self.directory)
        self.validate()
        if self.legacy:
            os.unlink("marker", dir_fd=self.directory)
            _same(self.guard, self.directory, "guard")
            os.unlink("guard", dir_fd=self.directory)
        # Protocol 2 never unlinks its proof or lock: both belong to the directory
        # inode and survive until this final rmdir, including interrupted recovery.
        _same(self.directory, self.root, self.ticket.name)
        os.rmdir(self.ticket.name, dir_fd=self.root)
        return size


@contextmanager
def attach(ticket: Ticket, *, exclusive: bool = False) -> Iterator[Attempt]:
    """No creation in workers/recovery; an old queued ticket cannot resurrect a slot."""
    try:
        if not re.fullmatch(r"[0-9a-f]{32}", ticket.name):
            raise refuse("unknown attempt name")
        with (
            _opened(ticket.root, DIR_FLAGS) as root,
            _opened(ticket.name, DIR_FLAGS, root) as directory,
            ExitStack() as stack,
        ):
            _check(os.fstat(directory), True)
            try:
                os.getxattr(directory, OWNER_ATTRIBUTE)
            except OSError as exc:
                if exc.errno not in {errno.ENODATA, errno.ENOTSUP}:
                    raise
                # Complete v1 attempts retain their original guard/marker contract.
                guard = stack.enter_context(_opened("guard", FILE_FLAGS, directory))
                _check(os.fstat(guard))
                attempt = Attempt(ticket, root, directory, guard)
            else:
                attempt = Attempt(ticket, root, directory)
            _flock(attempt.guard, exclusive=exclusive)
            attempt.validate()
            yield attempt
    except BlockingIOError:
        raise refuse("active parent or worker") from None
    except OSError:
        raise refuse("filesystem access or cleanup failed") from None


@contextmanager
def _root(ws: Workspace) -> Iterator[tuple[Path, int, str]]:
    path = ws.db_path.parent.resolve()
    with _opened(str(path), DIR_FLAGS) as parent:
        info = os.fstat(parent)
        workspace = hashlib.sha256(f"{path}:{info.st_dev}:{info.st_ino}".encode()).hexdigest()
        with suppress(FileExistsError):
            os.mkdir(ROOT, mode=0o700, dir_fd=parent)
        with _opened(ROOT, DIR_FLAGS, parent) as root:
            _same(root, parent, ROOT)
            yield path / ROOT, root, workspace


def require_quiescent(ws: Workspace) -> None:
    """Read-only admission under the mutation guard, before replacing its owner.

    Independent exclusive flocks prove no attached worker can still write. Dead
    parent proof plus require_live_parent prevents queued tasks from attaching
    after this check. Recovery/deletion remains the explicit conversion retry's
    job; unknown ownership fails closed without changing receipts or SQL.
    """
    try:
        path = ws.db_path.parent / ROOT
        try:
            path.lstat()
        except FileNotFoundError:
            return
        with _root(ws) as (path, root, workspace), ExitStack() as stack:
            for name in _names(root, MAX_ATTEMPTS):
                info = os.stat(name, dir_fd=root, follow_symlinks=False)
                _check(info, True)
                ticket = Ticket(str(path), workspace, name, info.st_dev, info.st_ino)
                attempt = stack.enter_context(attach(ticket, exclusive=True))
                marker = attempt.validate()
                if _alive(marker["pid"]):
                    identity = _process_identity(marker["pid"])
                    if not identity or identity == marker["process"]:
                        raise refuse("live or unknown parent identity")
    except (CleanupFailure, OSError) as exc:
        raise SpillBusy(str(exc) if isinstance(exc, CleanupFailure) else str(refuse("filesystem access failed"))) from None


def recover(ws: Workspace) -> dict[str, int | float]:
    """Preflight the whole bounded inventory under the workspace's existing lease."""
    from sigharvest import conversion_memory

    try:
        conversion_memory.require_support()
    except conversion_memory.ResourceFailure:
        # No conversion can run on this host, so no spill of it exists here; the stage then fails with the platform
        # message instead of a POSIX-only recovery check blaming directory ownership.
        return {}
    start = time.monotonic()
    count = size = 0
    try:
        with mutation_lease(ws) as lease, _root(ws) as (path, root, workspace), ExitStack() as stack:
            lease.assert_owned()
            attempts = []
            for name in _names(root, MAX_ATTEMPTS):
                info = os.stat(name, dir_fd=root, follow_symlinks=False)
                _check(info, True)
                ticket = Ticket(str(path), workspace, name, info.st_dev, info.st_ino)
                attempt = stack.enter_context(attach(ticket, exclusive=True))
                marker = attempt.validate()
                if _alive(marker["pid"]):
                    identity = _process_identity(marker["pid"])
                    if not identity or identity == marker["process"]:
                        raise refuse("live or unknown parent identity")
                _, amount = attempt.inventory()
                size += amount
                if size > MAX_WORK_BYTES:
                    raise refuse("workspace byte limit")
                attempts.append((attempt, marker))
            for attempt, marker in attempts:
                lease.assert_owned()
                if attempt.validate() != marker:
                    raise refuse("ownership changed after inventory")
                attempt.remove()
                count += 1
    except OSError:
        raise refuse("filesystem access or cleanup failed") from None
    return {"recovered_attempts": count, "recovered_bytes": size, "recovery_seconds": time.monotonic() - start}


class _CallerError(Exception):
    def __init__(self, error: OSError) -> None:
        super().__init__(str(error))
        self.error = error


@contextmanager
def create(ws: Workspace) -> Iterator[Attempt]:
    """Caller holds the mutation lease from recovery through worker shutdown."""
    try:
        with mutation_lease(ws) as lease, _root(ws) as (path, root, workspace):
            lease.assert_owned()
            if _names(root, MAX_ATTEMPTS):
                raise refuse("recovery required before starting an attempt")
            name = uuid4().hex
            os.mkdir(name, mode=0o700, dir_fd=root)
            with _opened(name, DIR_FLAGS, root) as directory:
                info = os.fstat(directory)
                ticket = Ticket(str(path), workspace, name, info.st_dev, info.st_ino)
                _check(info, True)
                _flock(directory, exclusive=False)
                marker = dict(
                    protocol=PROTOCOL,
                    workspace=workspace,
                    attempt=name,
                    device=info.st_dev,
                    inode=info.st_ino,
                    pid=os.getpid(),
                    process=_process_identity(os.getpid()),
                    host=socket.gethostname(),
                )
                raw = json.dumps(marker, separators=(",", ":")).encode()
                # Atomic publication on the bound inode, before exposing a ticket.
                # mkdir -> setxattr remains unverifiable if the creator is killed.
                # No random name, empty directory or PID grants deletion authority.
                os.setxattr(directory, OWNER_ATTRIBUTE, raw, flags=os.XATTR_CREATE)
                attempt = Attempt(ticket, root, directory)
                attempt.validate()
                try:
                    yield attempt
                except OSError as exc:
                    # An error of the caller's work (for example starting worker processes) is not a
                    # spill-directory problem: report it as it is, after cleaning up.
                    raise _CallerError(exc) from exc
                finally:
                    lease.assert_owned()
                    attempt.remove()
    except _CallerError as wrapped:
        raise wrapped.error from None
    except BlockingIOError:
        raise refuse("active worker during cleanup") from None
    except OSError:
        raise refuse("filesystem access or cleanup failed") from None
