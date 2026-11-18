"""Build complete sibling generations, then atomically replace a published directory."""

from __future__ import annotations

import ctypes
import errno
import os
import shutil
import stat
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from sigharvest.errors import SigharvestError


class PublicationError(SigharvestError, RuntimeError):
    pass


def rename_no_replace(stage: Path, out: Path) -> None:
    """Publish exclusively, including against a concurrently created empty folder.

    Unsupported systems fail closed; a check followed
    by ordinary POSIX rename would overwrite a raced-in empty directory.
    """
    if os.name == "nt":
        os.rename(stage, out)
        return
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    if rename is None:
        raise OSError(errno.ENOSYS, "Atomic directory publication requires renameat2 on Linux")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(stage), -100, os.fsencode(out), 1) != 0:
        raise OSError(ctypes.get_errno(), "Cannot publish directory without replacing output")


def private_directories(path: Path) -> None:
    """Create missing ancestors with mode 0700; reject existing symlink components."""
    for part in reversed((path.absolute(), *path.absolute().parents)):
        if part.is_symlink():
            raise PublicationError("publication path must not contain symlinks")
        part.mkdir(mode=0o700, exist_ok=True)


def sync_directory(path: Path) -> None:
    """Require directory fsync, without silently claiming unsupported durability."""
    if not hasattr(os, "O_DIRECTORY"):
        return  # Windows cannot open a directory for fsync; NTFS journals its metadata
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sync_tree(root: Path) -> None:
    """Sync closed files, then directories from children to parent."""
    directories = [root]
    for path in root.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            directories.append(path)
        elif stat.S_ISREG(mode):
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        else:
            raise PublicationError("publication requires regular files and directories")
    for path in sorted(directories, key=lambda p: len(p.parts), reverse=True):
        sync_directory(path)


def build_time(epoch: int | None = None) -> str:
    """Explicit epoch wins over SOURCE_DATE_EPOCH; otherwise use the current UTC time."""
    if epoch is None and "SOURCE_DATE_EPOCH" in os.environ:
        try:
            epoch = int(os.environ["SOURCE_DATE_EPOCH"])
        except ValueError as exc:
            raise PublicationError("SOURCE_DATE_EPOCH must be an integer") from exc
    try:
        if epoch is not None and (type(epoch) is not int or epoch < 0):
            raise ValueError
        now = datetime.now(UTC) if epoch is None else datetime.fromtimestamp(epoch, UTC)
        return now.isoformat(timespec="seconds")
    except (ValueError, OverflowError, OSError) as exc:
        raise PublicationError("build epoch must be a representable nonnegative Unix timestamp") from exc


def _promote(stage: Path, out: Path) -> None:
    if out.is_symlink():
        raise PublicationError("publication output must not be a symlink")
    if not out.exists():
        os.replace(stage, out)
        return
    if not out.is_dir():
        raise PublicationError("publication output must be a directory")
    # A two-rename backup dance has a crash window with no published directory.
    # Linux exchange swaps both names in one syscall, retaining the old tree in stage.
    if sys.platform != "linux":
        raise PublicationError("atomic replacement of an existing directory requires Linux renameat2; use a new output directory")
    libc = ctypes.CDLL(None, use_errno=True)
    exchange = getattr(libc, "renameat2", None)
    if exchange is None:
        raise PublicationError("atomic directory exchange unavailable; use a new output directory")
    exchange.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    exchange.restype = ctypes.c_int
    if exchange(-100, os.fsencode(stage), -100, os.fsencode(out), 2):
        code = ctypes.get_errno()
        raise PublicationError(f"atomic directory exchange failed: {os.strerror(code)}; previous output preserved")


@contextmanager
def staged_directory(out: Path) -> Iterator[Path]:
    """Only promote after the caller successfully writes and validates every artifact.

    Staging and output share a filesystem. Cleanup cannot turn a successful promotion
    into a reported failure. A killed process can leave a disposable staging directory.
    """
    out = out.absolute()
    if out.is_symlink():
        raise PublicationError("publication output must not be a symlink")
    out.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{out.name}.stage-", dir=out.parent))
    try:
        yield stage
        # Staging is private; publication keeps the existing directory permissions.
        # Fresh static outputs must be traversable by a separately run web server.
        stage.chmod(stat.S_IMODE(out.stat().st_mode) if out.exists() else 0o755)
        _promote(stage, out)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
