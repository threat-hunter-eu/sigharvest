"""Small transactional revision keys and bounded, per-slot web computation locks.

SQLite triggers invalidate even raw SQL edits. Keys are read inside the same
snapshot as their result, never from wall clocks or connection-local data_version.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from time import monotonic
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import TimeoutError
from sqlalchemy.orm import Session

FACET_TABLES = ("logic_groups", "rule_versions", "sources", "occurrences")


@contextmanager
def computation_lock(lock: Any, wait_seconds: float | None) -> Iterator[None]:
    """Bound an opted-in caller's lock wait without cancelling the producer.

    The caller still owns its snapshot and must close its session on timeout.
    Other cache users retain their existing blocking/reentrant lock semantics.
    """
    if wait_seconds is None:
        with lock:
            yield
        return
    deadline = monotonic() + wait_seconds
    if not lock.acquire(timeout=max(0.0, deadline - monotonic())):
        raise TimeoutError("Coverage calculation is busy; retry in a few seconds.")
    try:
        # A release at the deadline must not start another expensive calculation.
        if monotonic() >= deadline:
            raise TimeoutError("Coverage calculation is busy; retry in a few seconds.")
        yield
    finally:
        lock.release()


def revision(s: Session, tables: tuple[str, ...] | None = None) -> tuple[Any, ...]:
    rows = s.execute(text("SELECT name, revision FROM cache_revisions ORDER BY name"))
    return tuple((name, value) for name, value in rows if tables is None or name in tables)


def value_bytes(value: Any) -> int:
    """Size of cached data graphs, counting shared members once; no ORM graphs."""
    import sys
    from dataclasses import fields, is_dataclass

    seen: set[int] = set()
    pending = [value]
    total = 0
    while pending:
        item = pending.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        total += sys.getsizeof(item)
        if total > 16 * 1024 * 1024:
            return total
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, (tuple, list, set, frozenset)):
            pending.extend(item)
        elif is_dataclass(item) and not isinstance(item, type):
            pending.extend(getattr(item, f.name) for f in fields(item))
    return total
