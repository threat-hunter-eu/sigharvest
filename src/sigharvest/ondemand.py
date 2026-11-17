"""Bounded on-demand conversion for the web UI: every conversion runs in a worker process with a wall-clock deadline
and (on Linux) the same address-space cap as `update --convert` (conversion_memory), never inline in a server thread.

Why: pySigma backends are super-linear on some ordinary rules (thousands of `|contains` values), and a SIGALRM timeout
cannot interrupt a web worker thread. A slot is one single-worker process pool; a conversion that overruns its deadline
or its memory cap kills only that slot's worker (the next conversion starts a fresh one), and the caller gets a
`timeout` / `resource_failure` result instead of a thread that never returns.

Interactive conversion also refuses rules that are too big before any worker starts (`too_large`): more than
MAX_CHARS of YAML (rule plus correlation siblings) or more than MAX_VALUES detection values.
"""

from __future__ import annotations

import logging
import queue
import threading
from collections.abc import Iterator, Sequence
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout
from concurrent.futures.process import BrokenProcessPool
from contextlib import contextmanager
from typing import Any

from sigharvest import conversion
from sigharvest.conversion import Conversion

log = logging.getLogger("sigharvest.ondemand")

SLOTS = 2  # conversions running at once (one worker process each)
SOURCE_TIMEOUT = 20.0  # per data source, inside the worker (SIGALRM works there: it is the worker's main thread)
DEADLINE = 60.0  # wall clock for one whole conversion, enforced by the caller: the worker is killed after it
WAIT = 30.0  # how long a request waits for a free slot
MAX_CHARS = 128 * 1024
MAX_VALUES = 2000


class Busy(RuntimeError):
    """No conversion slot became free in time."""


def _init_worker() -> None:
    """Worker setup: the address-space cap of update's conversion workers where the platform supports it."""
    from sigharvest import conversion_memory

    try:
        conversion_memory.require_support()
    except conversion_memory.ResourceFailure:
        return  # not Linux/CPython 3.12+: the wall-clock deadline still applies
    conversion_memory.install()


def _run(raw: str, target: str, kind: str, siblings: Sequence[str], variant: str | None, sources: Sequence[str] | None) -> Conversion:
    return conversion.convert(raw, target, kind=kind, siblings=siblings, variant=variant, sources=sources, timeout=SOURCE_TIMEOUT)


class _Slot:
    def __init__(self) -> None:
        self.executor: Any = None

    def submit(self, *args: Any) -> Future[Conversion]:
        if self.executor is None:
            import multiprocessing
            from concurrent.futures import ProcessPoolExecutor

            from sigharvest.conversion_memory import start_method

            self.executor = ProcessPoolExecutor(max_workers=1, mp_context=multiprocessing.get_context(start_method()), initializer=_init_worker)
        future: Future[Conversion] = self.executor.submit(_run, *args)
        return future

    def kill(self) -> None:
        """Stop the worker now (it overran its deadline or died) and forget the pool; the next use starts a new one."""
        from sigharvest.conversion_memory import abort

        executor, self.executor = self.executor, None
        if executor is not None:
            abort(executor)
            executor.shutdown(wait=False, cancel_futures=True)


_slots: queue.Queue[_Slot] | None = None
_slots_lock = threading.Lock()


def _pool() -> queue.Queue[_Slot]:
    global _slots
    with _slots_lock:
        if _slots is None:
            _slots = queue.Queue()
            for _ in range(SLOTS):
                _slots.put(_Slot())
        return _slots


def shutdown() -> None:
    """Stop every worker (server shutdown, tests)."""
    global _slots
    with _slots_lock:
        slots, _slots = _slots, None
    while slots is not None and not slots.empty():
        slots.get_nowait().kill()


def value_count(raw: str) -> int:
    """Leaf values under `detection` (lists count each item): what makes backends slow, independent of YAML size."""
    import yaml

    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError:
        return 0
    detection = doc.get("detection") if isinstance(doc, dict) else None
    count, steps, stack = 0, 0, [detection]
    while stack and count <= MAX_VALUES and steps <= 50 * MAX_VALUES:  # aliases can make the graph exponential
        steps += 1
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        elif node is not None:
            count += 1
    return count


def too_large(raw: str, siblings: Sequence[str] = ()) -> str | None:
    """Why this rule is not converted interactively, or None."""
    if len(raw) + sum(len(x) for x in siblings) > MAX_CHARS:
        return f"the rule is larger than {MAX_CHARS // 1024} KiB"
    values = value_count(raw) + sum(value_count(x) for x in siblings)
    if values > MAX_VALUES:
        return f"the rule has {values:,} detection values (more than {MAX_VALUES:,})"
    return None


def convert(
    raw: str,
    target: str,
    kind: str = "rule",
    siblings: Sequence[str] = (),
    variant: str | None = None,
    sources: Sequence[str] | None = None,
    *,
    wait: float = WAIT,
) -> Conversion:
    """`conversion.convert_cached` with the conversion itself in a bounded worker. Raises Busy when no slot frees up
    within `wait` seconds and ValueError for an unknown backend/variant/source (checked before any worker starts)."""
    if target not in conversion.BACKENDS or variant not in conversion.VARIANTS:
        raise ValueError("unknown backend or variant")
    if sources is not None:
        from sigharvest.datasources import select_sources

        select_sources([], list(sources))  # raises ValueError for an unknown source name
    if reason := too_large(raw, siblings):
        return Conversion(target, "skipped", reason=f"not converted on demand: {reason}; use `sigharvest convert` in a terminal")

    def isolated(raw: str, target: str, *, kind: str, siblings: Sequence[str], variant: str | None, sources: Sequence[str] | None, timeout: Any) -> Conversion:
        slots = _pool()
        try:
            slot = slots.get(timeout=wait)
        except queue.Empty:
            raise Busy("busy converting other rules") from None
        try:
            future = slot.submit(raw, target, kind, list(siblings), variant, list(sources) if sources is not None else None)
            try:
                return future.result(timeout=DEADLINE)
            except FutureTimeout:
                slot.kill()
                return Conversion(target, "timeout", reason=f"conversion took longer than {DEADLINE:g} s")
            except BrokenProcessPool:
                slot.kill()
                return Conversion(target, "resource_failure", reason="the conversion worker ran out of memory or was lost")
        finally:
            slots.put(slot)

    return conversion.convert_cached(raw, target, kind=kind, siblings=siblings, variant=variant, sources=sources, runner=isolated)


# ----------------------------------------------------------------------------- downloads: a bounded job queue

EXPORTS_RUNNING = 1  # web downloads built at once
EXPORTS_QUEUED = 2  # downloads that may wait for a turn; more are refused (HTTP 429)
EXPORT_WAIT = 120.0


class QueueFull(RuntimeError):
    """Too many downloads are already running or waiting."""


_export_turns = threading.BoundedSemaphore(EXPORTS_RUNNING)
_export_lock = threading.Lock()
_export_jobs = 0
SENDS_MAX = 8  # built downloads being sent (from a temporary file) at once; more are refused (HTTP 429)
_sends = 0


@contextmanager
def download_send() -> Iterator[None]:
    """One download from its build until its body is sent (or its send times out); QueueFull beyond SENDS_MAX.
    Separate from the build turn, so a client that reads slowly never holds up the next build."""
    global _sends
    with _export_lock:
        if _sends >= SENDS_MAX:
            raise QueueFull("too many downloads being sent")
        _sends += 1
    try:
        yield
    finally:
        with _export_lock:
            _sends -= 1


@contextmanager
def export_job(wait: float = EXPORT_WAIT) -> Iterator[None]:
    """One web download: at most EXPORTS_RUNNING at once and EXPORTS_QUEUED waiting (QueueFull beyond that);
    Busy when the turn does not come within `wait` seconds."""
    global _export_jobs
    with _export_lock:
        if _export_jobs >= EXPORTS_RUNNING + EXPORTS_QUEUED:
            raise QueueFull("too many downloads in progress")
        _export_jobs += 1
    try:
        if not _export_turns.acquire(timeout=wait):
            raise Busy("busy building other downloads")
        try:
            yield
        finally:
            _export_turns.release()
    finally:
        with _export_lock:
            _export_jobs -= 1
