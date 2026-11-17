"""Database engine and Alembic-managed schema upgrades."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from alembic.config import Config
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

MIGRATIONS = Path(__file__).parent / "migrations"
# Values per `IN (...)` query when filtering on long key lists: well under SQLite's limit on bound parameters.
IN_CHUNK = 500
RESULTS_REVISION = "results_revision"
INDEXED_RESULTS_REVISION = "indexed_results_revision"
# Opaque revision of the synced corpus: every successful source sync sets a new one, the index records the one it
# was built from. Comparing revisions, not timestamps, keeps freshness right when the wall clock steps backwards.
SYNC_REVISION = "sync_revision"
INDEXED_SYNC_REVISION = "indexed_sync_revision"


def make_engine(db_path: Path, *, expected_revision: str | None = None) -> Engine:
    """Writable SQLite engine; close returned connections so WAL cleanup never waits for GC."""
    from sigharvest.db_settings import sqlite_synchronous

    synchronous = sqlite_synchronous()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    # Wait up to 30 s for another writer (a sync, an index rebuild) instead of failing after the default 5 s.
    # An idle pooled writer can survive Session.close(), then checkpoint WAL when
    # collected during an unrelated read-only request. Keep cleanup within the
    # connection owner's lifetime instead of deferring it to garbage collection.
    engine = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30}, poolclass=NullPool)

    @event.listens_for(engine, "connect")
    def _pragmas(conn, _record):  # type: ignore[no-untyped-def]
        cur = conn.cursor()
        try:
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute(f"PRAGMA synchronous={synchronous}")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA busy_timeout=30000")
        finally:
            cur.close()

    if expected_revision is not None:

        @event.listens_for(engine, "checkout")
        def _checkout(conn, record, proxy):  # type: ignore[no-untyped-def]
            from sigharvest.errors import SigharvestError

            rows = conn.execute("SELECT version_num FROM alembic_version").fetchall()
            if rows != [(expected_revision,)]:
                raise SigharvestError("database schema changed; restart with matching sigharvest code")

    return engine


def alembic_config(db_path: Path) -> Config:
    """Alembic configuration for this database file, using the bundled migrations."""
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return cfg


def upgrade(db_path: Path, *, timeout: float = 30.0) -> None:
    """Create the database or migrate it to the latest schema."""
    from sigharvest.schema import upgrade_schema

    upgrade_schema(db_path, timeout=timeout)


def session_factory(db_path: Path, *, migrate: bool = False, migration_timeout: float = 30.0, readonly: bool = False) -> sessionmaker[Session]:
    """Open a current schema; only explicit migrate=True may initialize or upgrade it.

    Migration takes the workspace lock. Read-only callers cannot opt in.
    """
    from sigharvest.schema import head_revision, require_current_schema
    from sigharvest.update_publication import sessions

    if readonly and migrate:
        raise ValueError("read-only sessions cannot migrate")
    staged = sessions(db_path)
    if staged is not None:
        return staged
    if migrate:
        upgrade(db_path, timeout=migration_timeout)
    require_current_schema(db_path)
    if readonly:
        from sigharvest.db_reads import make_read_engine

        engine = make_read_engine(db_path, expected_revision=head_revision())
    else:
        engine = make_engine(db_path, expected_revision=head_revision())
    return sessionmaker(engine, expire_on_commit=False)


def get_meta(s: Session, key: str) -> str | None:
    """A value of the `meta` table (models.Meta), or None."""
    from sigharvest.models import Meta

    row = s.get(Meta, key)
    return row.value if row is not None else None


def set_meta(s: Session, key: str, value: str) -> None:
    """Create or replace a value of the `meta` table (the caller commits)."""
    from sigharvest.models import Meta

    row = s.get(Meta, key)
    if row is None:
        s.add(Meta(key=key, value=value))
    else:
        row.value = value


def mark_results_changed(s: Session) -> None:
    """Invalidate the derived index in the same transaction as result publication.

    Opaque revisions avoid clock comparisons and survive interruption after all
    workers finish but before indexing starts. The caller owns the commit.
    """
    set_meta(s, RESULTS_REVISION, uuid4().hex)


def mark_sync_changed(s: Session) -> None:
    """Record a successful source sync in the same transaction; the index is stale until it records this revision."""
    set_meta(s, SYNC_REVISION, uuid4().hex)
