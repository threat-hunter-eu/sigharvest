"""Keep the published corpus visible while an update builds a gated SQLite generation.

WAL readers retain the last committed snapshot. Stage commits release savepoints,
not the outer transaction. Only a successful gate decision commits that transaction.
No database copy or file replacement is needed, so existing reader connections work.
"""

from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import Executor
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import Connection
from sqlalchemy.orm import Session, sessionmaker

from sigharvest.config import Workspace

_ACTIVE: ContextVar[tuple[Path, Connection] | None] = ContextVar("update_publication", default=None)

_PENDING: ContextVar[list[Executor] | None] = ContextVar("update_pending_workers", default=None)


def defer_shutdown(pool: Executor) -> bool:
    """Cancel queued fetches; let the run finalizer record interruption before waiting."""
    pending = _PENDING.get()
    if pending is None:
        return False
    pool.shutdown(wait=False, cancel_futures=True)
    pending.append(pool)
    return True


@contextmanager
def pending_workers() -> Iterator[None]:
    """Retain the mutation lease until active fetches stop, after writing the outcome."""
    pending: list[Executor] = []
    token = _PENDING.set(pending)
    try:
        yield
    finally:
        _PENDING.reset(token)
        for pool in pending:
            pool.shutdown(wait=True, cancel_futures=True)


def gated() -> bool:
    """True inside an update's candidate: stage commits are published only if its gates pass."""
    return _ACTIVE.get() is not None


def sessions(path: Path) -> sessionmaker[Session] | None:
    """Join stage sessions to the current candidate, only in the owning context."""
    active = _ACTIVE.get()
    if active is None or path.resolve() != active[0]:
        return None
    return sessionmaker(active[1], expire_on_commit=False, join_transaction_mode="create_savepoint")


@dataclass
class Publication:
    accepted: bool = False
    bootstrap: bool = False  # nothing published yet: stages commit as they finish (see candidate)


def nothing_published(ws: Workspace) -> bool:
    """True before the first index build and the first passed update: there is no corpus a gate could protect."""
    from sqlalchemy import select

    from sigharvest.db import get_meta
    from sigharvest.index import INDEX_BUILT_AT
    from sigharvest.models import UpdateRun
    from sigharvest.runs import PASSED
    from sigharvest.service import open_db

    with open_db(ws)() as s:
        return get_meta(s, INDEX_BUILT_AT) is None and s.scalar(select(UpdateRun.id).where(UpdateRun.status.in_(PASSED)).limit(1)) is None


@contextmanager
def candidate(ws: Workspace) -> Iterator[Publication]:
    """Rollback by default, including exceptions, SIGTERM and process death.

    Exception: the first update of a workspace (nothing published yet) has no previous corpus to keep, so its stages
    commit as they finish. Ctrl+C or a crash then keeps every ingested source and stored validation result, and the
    next `update` resumes instead of starting from zero (the first curated update is the longest one)."""
    from sigharvest.db import make_engine
    from sigharvest.job_control import terminal_publication

    if nothing_published(ws):
        yield Publication(bootstrap=True)
        return
    engine = make_engine(ws.db_path)
    publication = Publication()
    with engine.connect() as connection:
        # Explicit BEGIN is essential with sqlite3's legacy transaction mode:
        # otherwise releasing the first SAVEPOINT could publish its changes.
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        token = _ACTIVE.set((ws.db_path.resolve(), connection))
        try:
            yield publication
            if publication.accepted:
                with terminal_publication():
                    connection.commit()
        finally:
            _ACTIVE.reset(token)
            connection.rollback()
    engine.dispose()


def record_failure(ws: Workspace, *, run_id: int | None, error: str) -> bool:
    """Finalize a run whose outcome was never recorded because an exception escaped the update.

    The gated candidate rolled back, so nothing was published. Only a row still marked
    running is changed; returns whether one was.
    """
    from sigharvest.models import UpdateRun, utcnow
    from sigharvest.runs import clean_text
    from sigharvest.service import open_db

    if run_id is None:
        return False
    with open_db(ws)() as s:
        run = s.get(UpdateRun, run_id)
        if run is None or run.status != "running":
            return False
        run.status, run.finished_at = "error", utcnow()
        run.reasons = [clean_text(f"error: {error}"[:2000]), "nothing was published; the previously published corpus is retained"]
        run.counts = run.counts | {"phase": "finished"}
        s.commit()
    return True


def record_interruption(ws: Workspace, *, run_id: int | None, cancelled: bool = False) -> Path | None:
    """Finalize SIGTERM outside the stage loop, including snapshot/report generation."""
    import logging

    from sigharvest import runs
    from sigharvest.models import UpdateRun, utcnow
    from sigharvest.service import open_db

    if run_id is None:
        return None
    with open_db(ws)() as s:
        run = s.get(UpdateRun, run_id)
        if run is None or run.finished_at is not None or run.status != "running":
            # A commit may have completed before its acknowledgement failed.
            # Cancellation cannot replace a terminal outcome observed on reopen.
            return None
        status = "cancelled" if cancelled else "interrupted"
        run.status, run.finished_at = status, utcnow()
        run.reasons = ["interrupted by termination request; published corpus retained"]
        run.counts = run.counts | {"phase": "finished"}
        s.commit()
        # Avoid repeating the interrupted stage or reading partially computed projections.
        data = {
            "run": run.id,
            "started": run.started_at.isoformat(),
            "finished": run.finished_at.isoformat(),
            "status": run.status,
            "reasons": run.reasons,
            "previous_run": None,
            "previous_counts": None,
            "gates": run.gates or [],
            "counts": run.counts,
            "durations": run.durations or {},
            "new": [],
            "changed": [],
            "removed": [],
            "sources": {},
            "collections": [],
        }
        path = None
        try:
            path = runs.write_report(ws, data, run.started_at)
            from sigharvest.config import workspace_relative

            run.report = workspace_relative(path, ws.root)
            s.commit()
        except OSError:
            logging.getLogger("sigharvest.update").error("interrupted report write failed; outcome retained")
        logging.getLogger("sigharvest.update").warning("update %d: %s", run.id, status)
        return path
