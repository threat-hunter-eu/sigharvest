"""Exact, disposable current-corpus reference lookup and atomic incremental repair.

All retained effective documents are projected, so occurrence retirement/reactivation
needs no YAML work. Candidates always rejoin live occurrences and indexed logic.
The reader and its receipt use one SQLite snapshot, including legacy-driver sessions.
"""

from __future__ import annotations

from functools import cache

from sqlalchemy import delete, func, insert, select, text
from sqlalchemy.orm import Session

from sigharvest.correlation_reference_schema import OBJECTS, install
from sigharvest.fingerprints import implementation
from sigharvest.models import CorrelationReference, CorrelationReferenceDirty, RuleVersion

BATCH = 100
# A full projection parses every retained document (tens of thousands on a first update): above this many, the
# YAML work runs in a process pool. Results are identical; only the parsing moves out of the main process.
PARALLEL_MIN = 2000
WINDOW = 2000
CHUNK = 50


def aliases(raws: list[str]) -> list[list[str]]:
    """The id/name aliases of each document (empty when the YAML is rejected). Runs in worker processes."""
    from sigharvest.correlation_plan import document, names

    out: list[list[str]] = []
    for raw in raws:
        try:
            found = names(document(raw))
        except ValueError:
            found = set()
        out.append(sorted(name for name in found if 0 < len(name) <= 256))
    return out


@cache
def fingerprint() -> str:
    return implementation(
        "correlation-references-v1",
        modules=("correlation_references.py", "correlation_plan.py", "ruleview.py", "identity.py", "correlation_reference_schema.py"),
    )


def snapshot(s: Session) -> None:
    """Pin receipt and candidates until the caller ends its existing transaction."""
    s.flush()
    connection = s.connection()
    driver = connection.connection.driver_connection
    if connection.dialect.name == "sqlite" and driver is not None and not driver.in_transaction:
        connection.exec_driver_sql("BEGIN")


def status(s: Session) -> str:
    """Cheap receipt validation; unavailable projections never certify absence."""
    snapshot(s)
    objects = set(s.scalars(text("SELECT name FROM sqlite_master WHERE name LIKE 'correlation_ref%' OR name='ix_correlation_references_content'")))
    if not objects >= OBJECTS:
        return "missing"
    row = s.execute(text("SELECT * FROM correlation_reference_state WHERE id=1")).mappings().first()
    if row is None or row["fingerprint"] != fingerprint():
        return "incompatible"
    if row["built_projection"] != row["projection_token"]:
        return "damaged"
    if row["built_input"] != row["input_token"] or s.scalar(select(CorrelationReferenceDirty.content_hash).limit(1)) is not None:
        return "stale"
    return "ready"


def refresh(s: Session, *, full: bool = False, workers: int | None = None) -> int:
    """Rebuild/repair in a savepoint; the caller owns the writer lease and commit.

    No partial receipt survives even when a caller catches an interruption and commits.
    A write before reads serializes publication against concurrent corpus mutations.
    Returns parsed document count (including rejected YAML), not alias count.
    """
    snapshot(s)
    with s.begin_nested():
        # Existing meta is authoritative workspace schema, independent of lost projections.
        s.execute(text("UPDATE meta SET value=value WHERE key='index_built_at'"))
        state = status(s)
        if state == "ready" and not full:
            return 0
        if state in {"missing", "incompatible"}:
            install(s.connection())
        pending = s.scalar(select(CorrelationReferenceDirty.content_hash).limit(1)) is not None
        full = full or state in {"missing", "incompatible", "damaged"} or not pending
        if full:
            s.execute(delete(CorrelationReference))
        else:
            s.execute(delete(CorrelationReference).where(CorrelationReference.content_hash.in_(select(CorrelationReferenceDirty.content_hash))))
        parsed = 0
        after = 0
        pool = None
        try:
            while True:
                query = select(RuleVersion.id, RuleVersion.content_hash, RuleVersion.logic_hash, RuleVersion.raw).where(RuleVersion.id > after)
                if not full:
                    query = query.where(RuleVersion.content_hash.in_(select(CorrelationReferenceDirty.content_hash)))
                batch = s.execute(query.order_by(RuleVersion.id).limit(WINDOW if pool is not None or parsed == 0 else BATCH)).all()
                if not batch:
                    break
                if pool is None and parsed == 0 and len(batch) >= WINDOW and (workers or 1) > 1:
                    total = s.scalar(select(func.count()).select_from(query.subquery())) or 0
                    if total >= PARALLEL_MIN:
                        import multiprocessing
                        from concurrent.futures import ProcessPoolExecutor

                        pool = ProcessPoolExecutor(max(1, min(int(workers or 1), 22)), mp_context=multiprocessing.get_context("spawn"))
                raws = [raw for _, _, _, raw in batch]
                if pool is not None:
                    found = [x for part in pool.map(aliases, [raws[i : i + CHUNK] for i in range(0, len(raws), CHUNK)]) for x in part]
                else:
                    found = aliases(raws)
                rows: list[dict[str, str]] = []
                for (vid, content, logic, _), names in zip(batch, found, strict=True):
                    parsed += 1
                    after = vid
                    rows.extend({"name": name, "content_hash": content, "logic_hash": logic} for name in names)
                if rows:
                    s.execute(insert(CorrelationReference), rows)
        finally:
            if pool is not None:
                pool.shutdown(wait=True, cancel_futures=True)
        s.execute(delete(CorrelationReferenceDirty))
        s.execute(
            text("UPDATE correlation_reference_state SET fingerprint=:fingerprint, built_input=input_token,built_projection=projection_token WHERE id=1"),
            {"fingerprint": fingerprint()},
        )
        return parsed
