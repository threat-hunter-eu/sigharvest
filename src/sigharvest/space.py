"""Disk admission on destination filesystems, including WAL, temporary files and inodes.

Estimates are conservative planning inputs, never reservations or quotas. A successful
check cannot prevent another process from consuming the remaining space.
"""

from __future__ import annotations

import errno
import os
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from sigharvest.config import SourceConfig, Workspace
from sigharvest.errors import SigharvestError

MIB = 1024**2


class SpaceError(SigharvestError):
    """Insufficient storage, or invalid storage policy."""


def setting(name: str, default: int) -> int:
    """Read a nonnegative integer policy value without echoing arbitrary environment data."""
    try:
        value = int(os.environ.get(f"SIGHARVEST_DISK_{name}", str(default)))
        if value < 0:
            raise ValueError
    except ValueError:
        raise SpaceError(f"SIGHARVEST_DISK_{name} must be a nonnegative integer") from None
    return value


@dataclass(frozen=True)
class Need:
    """Additional peak bytes/inodes expected at one destination."""

    label: str
    path: Path
    bytes: int
    inodes: int = 0


@dataclass(frozen=True)
class Capacity:
    """Available capacity for the current user, not root-reserved blocks."""

    device: int
    bytes: int
    inodes: int | None


def capacity(path: Path) -> Capacity:
    """Probe the nearest existing ancestor, resolving symlinks to the actual volume."""
    path = path.resolve()
    while not path.exists():
        path = path.parent
    inodes = None
    if hasattr(os, "statvfs"):
        stat = os.statvfs(path)
        free = stat.f_bavail * stat.f_frsize
        if stat.f_files > 0:
            inodes = stat.f_favail
    else:
        free = shutil.disk_usage(path).free
    return Capacity(path.stat().st_dev, free, inodes)


def human_bytes(value: int) -> str:
    """Format disk budgets in binary units with enough precision for operators."""
    for unit, divisor in (("TiB", 1024**4), ("GiB", 1024**3), ("MiB", 1024**2), ("KiB", 1024)):
        if value >= divisor:
            return f"{value / divisor:.1f} {unit}"
    return f"{value} bytes"


def admit(needs: list[Need]) -> None:
    """Sum simultaneous growth per device; charge the reserve only once per device."""
    reserve = setting("RESERVE_BYTES", 256 * MIB)
    reserve_inodes = setting("RESERVE_INODES", 1024)
    groups: dict[int, list[tuple[Need, Capacity]]] = {}
    for need in needs:
        if need.bytes < 0 or need.inodes < 0:
            raise ValueError("growth estimates must be nonnegative")
        probe = capacity(need.path)
        groups.setdefault(probe.device, []).append((need, probe))
    for entries in groups.values():
        labels = ", ".join(n.label for n, _ in entries)
        required = reserve + sum(n.bytes for n, _ in entries)
        available = min(c.bytes for _, c in entries)
        if available < required:
            raise SpaceError(
                f"disk admission refused ({labels}): {human_bytes(available)} available, {human_bytes(required)} required including reserve; "
                "free space or adjust SIGHARVEST_DISK_* estimates"
            )
        known = [c.inodes for _, c in entries if c.inodes is not None]
        required_inodes = reserve_inodes + sum(n.inodes for n, _ in entries)
        if known and min(known) < required_inodes:
            raise SpaceError(
                f"disk admission refused ({labels}): {min(known)} inodes available, {required_inodes} required including reserve; free files/inodes"
            )


def database_path(s: Session, fallback: Path) -> Path:
    """Use the bound SQLite database, including library callers outside a workspace."""
    bind = s.get_bind()
    url = bind.engine.url
    return Path(url.database) if url.database and url.database != ":memory:" else fallback


def size(path: Path) -> int:
    """File size without scanning a potentially enormous cache."""
    return path.stat().st_size if path.exists() else 0


def temporary_needs() -> list[Need]:
    """Python and SQLite may use different temporary filesystems."""
    growth = setting("TEMP_BYTES", 64 * MIB)
    python = Path(tempfile.gettempdir())
    sqlite = Path(os.environ.get("SQLITE_TMPDIR") or os.environ.get("TMPDIR") or tempfile.gettempdir())
    return [Need("temporary files", python, growth, 64), Need("SQLite temporary files", sqlite, growth, 64)]


def database_needs(path: Path, growth: int) -> list[Need]:
    """Allow both persistent growth and an equally large WAL alongside the database."""
    path = path.resolve()
    return [Need("database", path, growth, 4), Need("database WAL", Path(str(path) + "-wal"), growth, 4)]


def before_sync(ws: Workspace, sources: list[SourceConfig]) -> None:
    """Budget every submitted source on its own cache/corpus mount, not just workers."""
    estimate = setting("SYNC_SOURCE_BYTES", 32 * MIB)
    needs = []
    for source in sources:
        # All adapters now retain immutable acquisitions, including local sources.
        snapshot = ws.cache / "source-snapshots" / source.name
        needs.append(Need("source snapshot/blobs", snapshot, estimate * 2, 4096))
        if source.type == "local":  # Input stays in place; its retained snapshot does not.
            continue
        corpus = ws.source_dir(source.name)
        needs.append(Need("corpus", corpus, estimate, 2048))
        if source.type == "git":
            cache = ws.git_repo(source.name)
        elif source.type == "http":
            cache = corpus.with_name(corpus.name + ".tmp")
        else:
            cache = ws.cache / "non-git" / source.name
        needs.append(Need("source cache/staging", cache, estimate * 2, 2048))
    needs += database_needs(ws.db_path, max(size(ws.db_path), len(sources) * estimate))
    admit([*needs, *temporary_needs()])


def before_test(ws: Workspace, s: Session, versions: int, schema_cache: Path | None = None) -> None:
    """Budget result detail, indexes and WAL before schema downloads or result writes."""
    db = database_path(s, ws.db_path)
    growth = max(64 * MIB, versions * setting("TEST_VERSION_BYTES", 128 * 1024))
    admit([Need("schema cache", schema_cache or ws.cache / "sigma-specification", 8 * MIB, 16), *database_needs(db, growth), *temporary_needs()])


def before_release(s: Session, out: Path) -> None:
    """Stage output beside its destination, never on an unrelated system temp volume."""
    db = database_path(s, out.parent / "sigharvest.db").resolve()
    growth = max(setting("RELEASE_MIN_BYTES", 64 * MIB), 2 * (size(db) + size(Path(str(db) + "-wal"))))
    admit([Need("release output", out, 0, 0), Need("release output/staging", out.parent, growth, 16), *database_needs(db, 0), *temporary_needs()])


def is_full(exc: BaseException) -> bool:
    """Recognize OS quota/space exhaustion and SQLite SQLITE_FULL without string guessing."""
    if isinstance(exc, DBAPIError):
        return exc.orig is not None and is_full(exc.orig)
    return (isinstance(exc, OSError) and exc.errno in (errno.ENOSPC, errno.EDQUOT)) or (
        isinstance(exc, sqlite3.Error) and getattr(exc, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL
    )
