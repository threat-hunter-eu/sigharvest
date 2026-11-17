"""Schema checks and upgrades. Upgrades run under the workspace lock (one writer).

Existing databases get an explicit SQLite backup before an actual revision change.
Readers only check the revision; connections check it again at checkout (db.py, db_reads.py).
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
from contextlib import closing
from functools import lru_cache
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.script import ScriptDirectory

from sigharvest.errors import SigharvestError
from sigharvest.lock import database_lease

# Alembic's EnvironmentContext proxy is process-global, including for different DBs.
_ALEMBIC = threading.RLock()
LOCK_TIMEOUT = 30.0
log = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def head_revision() -> str:
    from sigharvest.db import alembic_config

    head = ScriptDirectory.from_config(alembic_config(Path("unused"))).get_current_head()
    assert head is not None
    return head


@lru_cache(maxsize=1)
def known_revisions() -> frozenset[str]:
    """Revisions that the installed code can identify during degraded web reads."""
    from sigharvest.db import alembic_config

    return frozenset(step.revision for step in ScriptDirectory.from_config(alembic_config(Path("unused"))).walk_revisions())


def revision(db_path: Path) -> str | None:
    if not db_path.exists() or db_path.stat().st_size == 0:
        return None
    with closing(sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='alembic_version'").fetchone():
            return None
        rows = conn.execute("SELECT version_num FROM alembic_version").fetchall()
    return rows[0][0] if len(rows) == 1 else None


def require_current_schema(db_path: Path) -> None:
    """Validate an existing schema without creating a database, backup or migration."""
    if not db_path.is_file():
        raise SigharvestError("database is missing; run sigharvest doctor to initialize the schema")
    current = revision(db_path)
    if current == head_revision():
        return
    if current is None or current in known_revisions():
        raise SigharvestError("database schema is behind this code; run sigharvest doctor before retrying")
    raise SigharvestError("database schema is newer or unknown; restart with matching sigharvest code")


def migration_backup(db_path: Path, old_revision: str | None, *, keep: int = 1) -> Path:
    """Back up committed WAL state before DDL; retain completed backups even on failure."""
    if keep < 1:
        raise SigharvestError("keep must be at least one migration backup")
    folder = db_path.parent / "migration-backups"
    folder.mkdir(mode=0o700, exist_ok=True)
    # Revisions from an existing DB are untrusted and never used as path components.
    target = folder / f"{db_path.name}.{uuid4().hex}.sqlite3"
    staging = target.with_suffix(".partial")
    try:
        fd = os.open(staging, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
        os.close(fd)
        with closing(sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)) as source, closing(sqlite3.connect(staging)) as dest:
            source.backup(dest)
        os.replace(staging, target)
    finally:
        staging.unlink(missing_ok=True)
    log.warning("pre-migration SQLite backup: %s (revision %r)", target, old_revision)
    from sigharvest.db_compact import prune_backups

    prune_backups(db_path, keep)
    return target


def upgrade_schema(db_path: Path, *, timeout: float = LOCK_TIMEOUT) -> None:
    """Check without the lock; take the workspace lock (and re-check) only for an actual upgrade."""
    from sigharvest.db import alembic_config

    db_path = db_path.resolve()
    if revision(db_path) == head_revision():
        return
    with database_lease(db_path, timeout=timeout), _ALEMBIC:
        old = revision(db_path)
        if old == head_revision():
            return
        # Reject unknown/newer schemas before making a backup or running any DDL.
        scripts = ScriptDirectory.from_config(alembic_config(db_path))
        if old is not None:
            try:
                scripts.get_revision(old)
            except Exception as exc:
                raise SigharvestError("database schema is newer or unknown; use matching sigharvest code") from exc
        if db_path.exists() and db_path.stat().st_size:
            migration_backup(db_path, old)
        command.upgrade(alembic_config(db_path), "head")
