"""Read-only SQLite snapshots for pooled web requests and short-lived readers."""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.pool import NullPool, QueuePool

from sigharvest.errors import SchemaUnavailable, SigharvestError


def _integer(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except ValueError:
        raise SigharvestError(f"{name} must be an integer") from None
    if not minimum <= value <= maximum:
        raise SigharvestError(f"{name} must be between {minimum} and {maximum}")
    return value


WEB_STATEMENT_SECONDS = 15
PROGRESS_STEPS = 100_000  # SQLite virtual-machine steps between two deadline checks
DEFAULT_POOL = min(2, os.cpu_count() or 1)


@dataclass(frozen=True)
class ReadSettings:
    """Reader pool sizing. `timeout` is the SQLite busy timeout; `queue_timeout` is the
    wait for a free pooled reader; `statement_seconds` stops one statement (0 = no limit)."""

    # Few readers: readers stepping through large facet scans in parallel hand the GIL back and forth on every row.
    # Measured on a 22k-rule workspace, 10 clients, mixed search/facet load: 32 readers 5.9 req/s, 4 readers
    # 10.2, 2 readers 26.7, 1 reader 37.8 (one client alone: 46). Two keep most of the throughput while one slow
    # search (stopped after WEB_STATEMENT_SECONDS) cannot block every page; 32 also kept ~3 GB of RSS mapped.
    pool_size: int = DEFAULT_POOL
    cache_kib: int = 8192
    mmap_mib: int = 256
    timeout: int = 5
    queue_timeout: int = 15
    statement_seconds: int = 60

    @classmethod
    def from_env(cls, statement_default: int = 60) -> ReadSettings:
        """`statement_default`: WEB_STATEMENT_SECONDS for the web UI (a search that runs longer is stopped with a
        503 "too expensive"), 60 s for the CLI; SIGHARVEST_READ_STATEMENT_SECONDS overrides both."""
        return cls(
            _integer("SIGHARVEST_READ_POOL", DEFAULT_POOL, 1, 64),
            _integer("SIGHARVEST_READ_CACHE_KIB", 8192, 256, 65536),
            _integer("SIGHARVEST_READ_MMAP_MIB", 256, 0, 4096),
            _integer("SIGHARVEST_READ_TIMEOUT", 5, 1, 30),
            _integer("SIGHARVEST_READ_QUEUE_TIMEOUT", 15, 1, 120),
            _integer("SIGHARVEST_READ_STATEMENT_SECONDS", statement_default, 0, 3600),
        )


class DeadlineConnection(sqlite3.Connection):
    """A reader whose SQLite progress handler interrupts a statement after its deadline.

    The deadline is set when a statement starts, so a request that keeps running after
    its client disconnected cannot hold a pooled reader indefinitely.
    """

    deadline = float("inf")

    def expired(self) -> bool:
        return time.monotonic() > self.deadline


def interrupted(exc: BaseException) -> bool:
    """True for the OperationalError raised when the statement deadline stopped SQLite."""
    orig = getattr(exc, "orig", exc)
    return isinstance(orig, sqlite3.OperationalError) and str(orig) == "interrupted"


def make_read_engine(
    path: Path,
    *,
    expected_revision: str | None = None,
    settings: ReadSettings | None = None,
    allowed_revisions: frozenset[str] | None = None,
    pooled: bool = True,
) -> Engine:
    """Observe live WAL with mode=ro; no migrations, checkpointing or idle writers.

    BEGIN pins the generation key and data to one snapshot; an idle pooled reader has no transaction.
    Set pooled=False for locally owned engines that must close every returned reader.
    """
    if allowed_revisions is None:
        from sigharvest.schema import head_revision, require_current_schema

        require_current_schema(path)
        expected_revision = expected_revision or head_revision()
    settings = settings or ReadSettings.from_env()

    def connect() -> sqlite3.Connection:
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, check_same_thread=False, timeout=settings.timeout, factory=DeadlineConnection)
        conn.isolation_level = None
        conn.execute("PRAGMA query_only=ON")
        conn.execute(f"PRAGMA cache_size=-{settings.cache_kib}")
        conn.execute(f"PRAGMA mmap_size={settings.mmap_mib * 1024 * 1024}")
        # File-backed temporary work keeps adversarial sorts outside the RAM budget.
        conn.execute("PRAGMA temp_store=FILE")
        if settings.statement_seconds:
            # Checked every 100k virtual-machine steps: negligible overhead for normal reads.
            conn.set_progress_handler(conn.expired, PROGRESS_STEPS)
        return conn

    if pooled:
        engine = create_engine(
            "sqlite://", creator=connect, poolclass=QueuePool, pool_size=settings.pool_size, max_overflow=0, pool_timeout=settings.queue_timeout
        )
    else:
        engine = create_engine("sqlite://", creator=connect, poolclass=NullPool)

    if settings.statement_seconds:

        @event.listens_for(engine, "before_cursor_execute")
        def start_deadline(conn: Any, cursor: Any, statement: Any, parameters: Any, context: Any, executemany: Any) -> None:
            raw = conn.connection.dbapi_connection
            if isinstance(raw, DeadlineConnection):
                raw.deadline = time.monotonic() + settings.statement_seconds

    @event.listens_for(engine, "begin")
    def begin(conn: Any) -> None:
        conn.exec_driver_sql("BEGIN")

    @event.listens_for(engine, "checkout")
    def checkout(conn: Any, record: Any, proxy: Any) -> None:
        if expected_revision or allowed_revisions is not None:
            rows = conn.execute("SELECT version_num FROM alembic_version").fetchall()
            allowed = frozenset({expected_revision}) if expected_revision else allowed_revisions
            if len(rows) != 1 or rows[0][0] not in (allowed or ()):
                raise SchemaUnavailable("database schema changed; restart with matching sigharvest code")

    @event.listens_for(engine, "checkin")
    @event.listens_for(engine, "close")
    def release(conn: Any, record: Any) -> None:
        if isinstance(conn, DeadlineConnection):
            conn.deadline = float("inf")

    return engine
