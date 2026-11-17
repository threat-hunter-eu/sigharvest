"""Wall-clock limit for a call where SIGALRM is unavailable (Windows, or a thread other than the main one).

With SIGALRM the callers interrupt the work itself. Without it the call runs in a daemon thread and the caller stops
waiting after `timeout` seconds: the result is the timeout outcome, and the abandoned thread finishes (or dies with
the process) in the background. That bounds the caller (an `update` never hangs on one rule), not the CPU spent.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


class _Outcome:
    __slots__ = ("error", "value")

    def __init__(self) -> None:
        self.value: object = None
        self.error: BaseException | None = None


def call_with_timeout(fn: Callable[[], T], timeout: float, on_timeout: Callable[[], T]) -> T:
    outcome = _Outcome()

    def run() -> None:
        try:
            outcome.value = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller's thread
            outcome.error = exc

    worker = threading.Thread(target=run, name="sigharvest-deadline", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        return on_timeout()
    if outcome.error is not None:
        raise outcome.error
    return outcome.value  # type: ignore[return-value]
