"""Child-only address-space containment and fail-stop conversion pool cleanup.

This is a Linux RLIMIT_AS contract, not an RSS sampler or a host memory limit.
The envelope reserves parent capacity without imposing a limit on the caller.
"""

from __future__ import annotations

import multiprocessing
import os
import sys
import time
from collections.abc import Callable, Iterator
from concurrent.futures.process import BrokenProcessPool
from contextlib import contextmanager
from typing import Any

from sigharvest.errors import SigharvestError

WORKER_ADDRESS_SPACE_BYTES = 512 * 1024**2
# Fallback budget when host memory cannot be read.
CONVERSION_MEMORY_BYTES = 3 * 1024**3
PARENT_RESERVE_BYTES = 1024**3
# Share of MemAvailable the conversion stage may reserve (parent plus workers' address-space caps).
MEMORY_FRACTION = 0.5
MEMORY_ENV = "SIGHARVEST_CONVERSION_MEMORY_BYTES"
MEMORY_EXIT = 86
SETUP_EXIT = 87
# A broken pool's manager thread terminates and joins its workers; abort() kills any that outlive this.
MANAGER_JOIN_SECONDS = 5.0
CONTRACT = "linux-rlimit-as-v1"


class ResourceFailure(SigharvestError):
    """Incomplete conversion, never a Sigma diagnostic or a successful skip."""


def describe_exit(code: int | None) -> str:
    """Why one worker process ended, in words."""
    import signal

    if code == MEMORY_EXIT:
        return f"exceeded its {WORKER_ADDRESS_SPACE_BYTES} byte address-space cap"
    if code == SETUP_EXIT:
        return "could not install memory protection during setup"
    if code is None:
        return "was lost"
    if code < 0:
        try:
            return f"was killed by {signal.Signals(-code).name}"
        except ValueError:
            return f"was killed by signal {-code}"
    return f"exited with code {code}"


class WorkerLost(ResourceFailure):
    """A conversion worker process died; the pool is unusable and its unfinished work is unknown."""

    def __init__(self, exitcodes: list[int | None], *, during_setup: bool = False) -> None:
        self.exitcodes = exitcodes
        self.during_setup = during_setup
        # Workers terminated by the executor after the loss end with SIGTERM; report the cause.
        causes = [c for c in exitcodes if c not in (None, -15)] or exitcodes or [None]
        self.cause = causes[0]
        super().__init__(f"conversion worker lost: a worker {describe_exit(self.cause)}")

    @property
    def setup(self) -> bool:
        """Memory protection itself failed: a platform problem, not a property of any rule."""
        return self.during_setup or SETUP_EXIT in self.exitcodes

    @property
    def reason(self) -> str:
        return ("died before any rule ran: " if self.during_setup else "") + describe_exit(self.cause)


def _ready() -> bool:
    return True


def require_support() -> None:
    """Fail closed; neither CLI limits nor sampled RSS substitute for the primitive."""
    if sys.platform != "linux" or sys.implementation.name != "cpython" or not hasattr(sys, "monitoring"):
        raise ResourceFailure("conversion memory protection unavailable: requires Linux and CPython 3.12+; use a supported worker host")
    try:
        import resource

        resource.getrlimit(resource.RLIMIT_AS)
    except (ImportError, AttributeError, OSError, ValueError):
        raise ResourceFailure("conversion memory protection unavailable: RLIMIT_AS is unavailable; use a supported worker host") from None


def _parse_bytes(text: str) -> int:
    units = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    value = text.strip().upper().removesuffix("B").removesuffix("I")
    unit = value[-1:] if value[-1:] in units else ""
    number = int(value[: len(value) - len(unit)] or "x")
    if number < 1:
        raise ValueError
    return number * units[unit]


def available_memory(meminfo: str = "/proc/meminfo") -> int | None:
    """MemAvailable in bytes, or None when the kernel does not report it."""
    try:
        with open(meminfo) as stream:
            for line in stream:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def memory_budget() -> int:
    """Bytes the parent reserve and all workers' address-space caps may add up to.

    SIGHARVEST_CONVERSION_MEMORY_BYTES (bytes, or with a K/M/G suffix) overrides it;
    otherwise half of MemAvailable, or CONVERSION_MEMORY_BYTES when that is unknown.
    """
    override = os.environ.get(MEMORY_ENV, "").strip()
    if override:
        try:
            return _parse_bytes(override)
        except ValueError:
            raise ResourceFailure(f"{MEMORY_ENV} must be a positive byte count such as 8G, not {override!r}") from None
    available = available_memory()
    if available is None:
        return CONVERSION_MEMORY_BYTES
    # Low memory still admits one worker; the per-worker cap keeps each one bounded.
    return max(int(available * MEMORY_FRACTION), PARENT_RESERVE_BYTES + WORKER_ADDRESS_SPACE_BYTES)


def admit_workers(requested: int, budget: int | None = None) -> int:
    """Workers to start: the request, bounded by the memory budget. The 512 MiB per-worker cap is unchanged."""
    require_support()
    budget = memory_budget() if budget is None else budget
    slots = (budget - PARENT_RESERVE_BYTES) // WORKER_ADDRESS_SPACE_BYTES
    if requested < 1 or slots < 1:
        raise ResourceFailure("conversion memory reservation cannot admit one worker and the parent reserve")
    return min(requested, slots)


def _raised(code: Any, offset: int, exception: BaseException) -> None:
    # RAISE runs before backend exception handlers, even when they catch Exception
    # or BaseException. Exit without allocating a diagnostic under memory pressure.
    if isinstance(exception, MemoryError) or (isinstance(exception, OSError) and exception.errno == 12):
        os._exit(MEMORY_EXIT)


def install() -> None:
    """Install before worker initialization, pipeline restoration or input loading."""
    if multiprocessing.parent_process() is None:
        raise ResourceFailure("conversion memory protection must only be installed in a child process")
    require_support()
    import resource

    monitoring: Any = vars(sys)["monitoring"]
    for tool_id in range(6):
        if monitoring.get_tool(tool_id) is None:
            monitoring.use_tool_id(tool_id, "sigharvest-conversion-memory")
            monitoring.register_callback(tool_id, monitoring.events.RAISE, _raised)
            monitoring.set_events(tool_id, monitoring.events.RAISE)
            break
    else:
        raise ResourceFailure("conversion memory protection unavailable: no exception monitor slot")
    inherited = resource.getrlimit(resource.RLIMIT_AS)
    limit = min((WORKER_ADDRESS_SPACE_BYTES, *(bound for bound in inherited if bound != resource.RLIM_INFINITY)))
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # A fork may inherit a host with a large virtual mapping. Refuse it instead of
    # claiming that lowering RLIMIT_AS removed already existing mappings.
    mapped = int(open_statm().split()[0]) * os.sysconf("SC_PAGE_SIZE")
    if mapped >= limit:
        raise ResourceFailure("conversion memory protection unavailable: inherited address space already exceeds limit")


def open_statm() -> str:
    with open("/proc/self/statm") as stream:
        return stream.read()


def initialize(initializer: Callable[..., None]) -> None:
    if multiprocessing.parent_process() is None:
        raise ResourceFailure("conversion memory protection must only be installed in a child process")
    try:
        install()
        initializer({}, "convert")
    except BaseException:  # noqa: BLE001 - no backend text or traceback under memory pressure
        os._exit(SETUP_EXIT)


def abort(pool: Any) -> None:
    """Same terminate/join/kill lifecycle as replay, before deleting owned spills.

    Python 3.12 lacks public terminate_workers; keep compatibility access here.
    """
    processes = list((getattr(pool, "_processes", None) or {}).values())
    for process in processes:
        if process.is_alive():
            process.terminate()
    deadline = time.monotonic() + 0.5
    for process in processes:
        process.join(max(0, deadline - time.monotonic()))
    for process in processes:
        if process.is_alive():
            process.kill()
    for process in processes:
        process.join()


# The forkserver listens on a Unix socket under the temporary directory; socket paths are limited to about
# 100 bytes (104 on macOS). With a long TMPDIR, start workers with spawn instead (slower start, same isolation).
MAX_SOCKET_DIR = 60


def start_method() -> str:
    import multiprocessing
    import tempfile

    if "forkserver" not in multiprocessing.get_all_start_methods():  # Windows
        return "spawn"
    return "forkserver" if len(tempfile.gettempdir().encode()) <= MAX_SOCKET_DIR else "spawn"


@contextmanager
def pool(factory: Any, workers: int, initializer: Callable[..., None]) -> Iterator[Any]:
    # Start workers from a small forkserver, not by forking this (possibly large) process: a fork inherits the
    # parent's whole address space, which can already exceed the per-worker cap and makes every worker refuse.
    import multiprocessing
    from concurrent.futures import ProcessPoolExecutor

    # Only the stock executor gets the context; subclasses/test doubles choose their own start method.
    extra = {"mp_context": multiprocessing.get_context(start_method())} if factory is ProcessPoolExecutor else {}
    with factory(max_workers=workers, initializer=initialize, initargs=(initializer,), **extra) as executor:
        setup = True
        try:
            # A worker that dies before running any rule failed its setup, not on a rule.
            executor.submit(_ready).result()
            setup = False
            yield executor
        except BaseException as exc:
            processes = list((getattr(executor, "_processes", None) or {}).values())
            if isinstance(exc, BrokenProcessPool):
                # The executor's manager thread reaps a broken pool's workers itself. Reaping them
                # concurrently lets this thread's waitpid see ECHILD before the other thread stores
                # the exit code, so a capped worker read as "was lost" and its rule went uncached.
                manager = getattr(executor, "_executor_manager_thread", None)
                if manager is not None:
                    manager.join(MANAGER_JOIN_SECONDS)
            abort(executor)
            # Read after abort has joined them: a forkserver child's exit code arrives asynchronously.
            exitcodes = [getattr(p, "exitcode", None) for p in processes]
            if isinstance(exc, BrokenProcessPool):
                raise WorkerLost([code for code in exitcodes if code is not None] or [None], during_setup=setup) from None
            raise
