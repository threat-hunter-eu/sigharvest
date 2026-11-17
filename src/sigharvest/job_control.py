"""Cooperative SIGTERM unwinding and bounded job progress.

Only the main process installs a signal handler. Nested CLI calls reuse it and
forked pool workers keep their normal termination behavior.
"""

from __future__ import annotations

import os
import re
import signal
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from types import FrameType


class Cancelled(BaseException):
    """Operator cancellation must pass through ordinary per-source error handlers."""


@dataclass
class _Cancellation:
    requested: bool = False
    publishing: bool = False
    completed: bool = False


_ACTIVE: ContextVar[_Cancellation | None] = ContextVar("job_cancellation", default=None)
PROGRESS: ContextVar[Callable[[str, int | None, int | None], None] | None] = ContextVar("job_progress", default=None)
STAGES = {"snapshot", "sync", "test", "validate", "convert", "index", "report"}


@dataclass(frozen=True)
class SyncProgress:
    """Structured source counts; never carry URLs, paths or exception text."""

    done: int
    total: int
    name: str
    added: int = 0
    changed: int = 0
    removed: int = 0
    seconds: float = 0.0
    status: str = "ok"

    @property
    def text(self) -> str:
        name = re.sub(r"[^A-Za-z0-9_. -]", "_", self.name[:100])
        if self.status == "ingesting":
            return f"sync {self.done}/{self.total} {name}: ingesting"
        suffix = f", {self.status}" if self.status != "ok" else ""
        return f"sync {self.done}/{self.total} {name}: +{self.added} ~{self.changed} -{self.removed}, {self.seconds:.1f} s{suffix}"


SYNC_PROGRESS: ContextVar[Callable[[SyncProgress], None] | None] = ContextVar("source_sync_progress", default=None)


def source_progress(value: SyncProgress) -> None:
    callback = SYNC_PROGRESS.get()
    if callback is not None:
        callback(value)


def cancellation_requested() -> bool:
    """Retain operator intent even when an unwind cleanup raises another error."""
    state = _ACTIVE.get()
    return state is not None and state.requested and not state.completed


@contextmanager
def terminal_publication() -> Iterator[None]:
    """Let a terminal commit win a racing SIGTERM, only if publication succeeds.

    Enter only after active work and its cleanup. Once durable, a late cancel
    must not rewrite the outcome while reports or the outer Actions record finish.
    The owning cancellation scope restores the previous handler on exit.
    """
    state = _ACTIVE.get()
    if state is None or state.completed or state.publishing:
        yield
        return
    requested = state.requested
    state.publishing = True
    try:
        yield
    except BaseException:
        if state.requested and not requested:
            raise Cancelled() from None
        raise
    else:
        state.completed = True
    finally:
        state.publishing = False


def progress(stage: str, done: int | None = None, total: int | None = None) -> None:
    """Publish fixed stage labels and aggregate counters, never source/log text."""
    callback = PROGRESS.get()
    if callback is not None and stage in STAGES:
        callback(stage, done, total)


@contextmanager
def cancellation() -> Iterator[None]:
    if _ACTIVE.get() or threading.current_thread() is not threading.main_thread():
        yield
        return
    pid = os.getpid()
    state = _Cancellation()

    def terminate(signum: int, frame: FrameType | None) -> None:
        if os.getpid() != pid:
            os._exit(128 + signum)
        if not state.requested and not state.completed:
            state.requested = True
            if not state.publishing:
                raise Cancelled()

    previous = signal.signal(signal.SIGTERM, terminate)
    token = _ACTIVE.set(state)
    try:
        yield
    finally:
        _ACTIVE.reset(token)
        signal.signal(signal.SIGTERM, previous)
