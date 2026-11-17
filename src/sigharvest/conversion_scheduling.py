"""Conversion admission and cost ordering; deliberately outside semantic fingerprints."""

from __future__ import annotations

import time
from collections.abc import Callable, Generator, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, wait
from dataclasses import dataclass
from typing import Any

from sqlalchemy import LargeBinary, cast, func, select
from sqlalchemy.orm import Session

from sigharvest.errors import SigharvestError
from sigharvest.models import Occurrence, RuleVersion

# Largest inputs first (longest-processing-time order): conversion time grows with rule size, so starting the giant
# keyword rules while the many small rules are still queued keeps every worker busy to the end instead of leaving a
# tail of giants for the last minutes. v1 ran smallest first.
SCHEDULING_VERSION = "input-bytes-desc-v2"
MAX_PENDING_BYTES = 16 * 1024 * 1024
RESULT_BATCH_SIZE = 64
# Retained for pinned historical scheduler benchmarks; production charges actual
# reply bytes through conversion_output.BUFFER_OUTPUT_BYTES.
RESULT_BUFFER_BYTES = 2 * 1024 * 1024
TAIL_INPUT_BYTES = 64 * 1024


class InputBudgetExceeded(SigharvestError):
    """The selected graph cannot fit; no result or skip is invented for it."""


@dataclass(frozen=True)
class Job:
    version_id: int
    kind: str
    input_bytes: int


@dataclass
class Admission:
    peak_bytes: int = 0
    peak_tasks: int = 0


def sibling_query(s: Session, version_id: int) -> Any:
    """Use exactly the first live occurrence and file order used by conversion."""
    occ = s.execute(
        select(Occurrence.source_id, Occurrence.path).where(Occurrence.version_id == version_id, Occurrence.present.is_(True)).order_by(Occurrence.id).limit(1)
    ).first()
    return (
        select(RuleVersion.raw)
        .join(Occurrence, Occurrence.version_id == RuleVersion.id)
        .where(
            Occurrence.source_id == (occ.source_id if occ else -1),
            Occurrence.path == (occ.path if occ else ""),
            Occurrence.present.is_(True),
            Occurrence.version_id != version_id,
        )
        .order_by(Occurrence.doc_index, Occurrence.id)
    )


def jobs(s: Session, selected: Sequence[int]) -> list[Job]:
    """Read scalar sizes, never batches of YAML; include correlation dependencies.

    Selection/limit belongs to the caller and precedes sorting. The frozen finite
    queue cannot starve: every selected job is submitted once, largest input first,
    with stable ID ties.
    """
    out = []
    for offset in range(0, len(selected), 200):
        rows = s.execute(
            select(RuleVersion.id, RuleVersion.kind, func.length(cast(RuleVersion.raw, LargeBinary))).where(RuleVersion.id.in_(selected[offset : offset + 200]))
        )
        for vid, kind, size in rows:
            if kind == "correlation":
                q = sibling_query(s, vid).with_only_columns(func.length(cast(RuleVersion.raw, LargeBinary)))
                size += sum(s.scalars(q))
            out.append(Job(vid, kind, size))
    if len(out) != len(selected):
        raise RuntimeError("selected conversion inputs disappeared")
    return sorted(out, key=lambda job: (-job.input_bytes, job.version_id))


# Fixed per-rule cost (process hand-off, parsing, pipelines, storing) in input-byte equivalents, for progress
# estimates. Measured on the curated preset (23k rules, 250 MB, 1,180 rules over 40 KB holding 206 MB): the large
# rules take about 85% of the stage, slightly more than their byte share, so the per-rule term stays small.
RULE_OVERHEAD_BYTES = 1024


def work(job: Job) -> int:
    """Estimated relative cost of one job, the unit of the stage's time-left estimate."""
    return job.input_bytes + RULE_OVERHEAD_BYTES


def load(s: Session, job: Job) -> tuple[int, str, str, list[str]]:
    raw = s.execute(select(RuleVersion.raw).where(RuleVersion.id == job.version_id)).scalar_one()
    context = list(s.scalars(sibling_query(s, job.version_id))) if job.kind == "correlation" else []
    return job.version_id, job.kind, raw, context


def admitted_results(
    queue: Sequence[Job],
    submit: Callable[[Job], Future[Any]],
    *,
    max_tasks: int,
    max_bytes: int = MAX_PENDING_BYTES,
    stats: Admission | None = None,
    before_tail_wait: Callable[[], None] | None = None,
    deadline: float | None = None,
) -> Generator[Any, None, None]:
    """Reserve bytes before loading input; release only after consuming its result.

    deadline (a time.monotonic() value): no job is submitted after it; jobs already submitted finish and are yielded,
    the rest are left unconverted (eligible for resume).

    Oversized jobs fail explicitly before any submissions, never silently disappear
    or bypass the bound. Cancellation leaves uncommitted work eligible for resume.
    The byte bound covers UTF-8 input including dependencies, not backend heap use.
    """
    if max_tasks < 1 or max_bytes < 1:
        raise ValueError("conversion admission limits must be positive")
    for job in queue:
        if job.input_bytes > max_bytes:
            raise InputBudgetExceeded(
                f"conversion version {job.version_id} including dependencies exceeds {max_bytes} byte admission limit; review the input graph before retrying"
            )
    stats = stats if stats is not None else Admission()
    pending: dict[Future[Any], int] = {}
    used = 0
    cursor = 0
    try:

        def admitting() -> bool:
            return cursor < len(queue) and (deadline is None or time.monotonic() < deadline)

        while admitting() or pending:
            while admitting() and len(pending) < max_tasks and used + queue[cursor].input_bytes <= max_bytes:
                job = queue[cursor]
                pending[submit(job)] = job.input_bytes
                used += job.input_bytes
                cursor += 1
                stats.peak_bytes = max(stats.peak_bytes, used)
                stats.peak_tasks = max(stats.peak_tasks, len(pending))
            if not pending:
                continue  # the deadline passed before anything was submitted: the loop ends
            if before_tail_wait and min(pending.values()) >= TAIL_INPUT_BYTES and not any(f.done() for f in pending):
                # Publish a short final ordinary batch before waiting for giants.
                before_tail_wait()
            completed, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in completed:
                yield future.result()
                used -= pending.pop(future)
            completed.clear()
            del future
    finally:
        for future in pending:
            future.cancel()
