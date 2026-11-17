"""Suite-wide guards: no network, no git transport other than local files, deterministic hypothesis settings.

Tests must never reach the network (.github/CONTRIBUTING.md). Outbound sockets to anything but localhost are refused and
recorded; a test that tried one fails at teardown even when the code under test caught the error (ATT&CK and
schema downloads are wrapped in broad `except` blocks in places). git runs as a subprocess, so the socket guard
cannot see it: GIT_ALLOW_PROTOCOL=file makes git refuse every remote transport, whatever `-c protocol.*` says.
"""

from __future__ import annotations

import errno
import math
import os
import signal
import socket
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, settings

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "testserver", ""}
_attempts: list[str] = []

_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_real_getaddrinfo = socket.getaddrinfo


def _is_local(address: Any) -> bool:
    if isinstance(address, (str, bytes)):  # AF_UNIX path
        return True
    host = address[0] if isinstance(address, tuple) and address else address
    host = host.decode() if isinstance(host, bytes) else str(host)
    return host in _LOCAL_HOSTS or host.startswith("127.")


class NetworkBlocked(OSError):
    """Raised instead of opening an outbound connection during tests."""


def _blocked(what: str) -> NetworkBlocked:
    _attempts.append(what)
    return NetworkBlocked(f"network access blocked in tests: {what}")


def _guarded_connect(self: socket.socket, address: Any) -> None:
    if not _is_local(address):
        raise _blocked(f"connect {address!r}")
    _real_connect(self, address)


def _guarded_connect_ex(self: socket.socket, address: Any) -> int:
    if not _is_local(address):
        raise _blocked(f"connect_ex {address!r}")
    return _real_connect_ex(self, address)


def _guarded_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
    if host is not None and not _is_local((host,)):
        raise _blocked(f"getaddrinfo {host!r}")
    return _real_getaddrinfo(host, *args, **kwargs)


socket.socket.connect = _guarded_connect  # type: ignore[method-assign]
socket.socket.connect_ex = _guarded_connect_ex  # type: ignore[method-assign]
socket.getaddrinfo = _guarded_getaddrinfo
os.environ["GIT_ALLOW_PROTOCOL"] = "file"
os.environ.setdefault("GIT_CONFIG_NOSYSTEM", "1")
# xdist injects COLUMNS=80 before collection. Rich would freeze that width at import,
# ignoring each CLI test's explicit CliRunner COLUMNS and wrapping asserted paths.
os.environ.pop("COLUMNS", None)
# Forked conversion workers inherit the parent's address space and correctly refuse
# to start once it reaches their 512 MiB cap (decision 468). A long-lived xdist worker
# accumulates reservations a single CLI invocation never has before conversion: one
# ~64 MiB glibc malloc arena per thread earlier tests started, and OpenBLAS buffers
# sized by CPU count once a semantic test imports numpy (about 700 MiB on 22 CPUs).
# Both are read at process or library start, so set them before workers spawn.
os.environ.setdefault("MALLOC_ARENA_MAX", "2")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")

settings.register_profile("sigharvest", deadline=None, database=None, derandomize=True, suppress_health_check=[HealthCheck.too_slow])
settings.load_profile("sigharvest")


def pytest_configure(config: pytest.Config) -> None:
    """Restore Ctrl-C for the suite when the launcher ignored it (nohup, `cmd &` without job control).

    An ignored SIGINT survives exec, so the controller, xdist workers and every Python child
    the tests start would never raise KeyboardInterrupt, and the Ctrl-C/timeout ownership
    tests hang or fail only in background runs. A Python handler resets to the default on
    exec, so children get Python's normal Ctrl-C behaviour again.
    """
    if threading.current_thread() is threading.main_thread() and signal.getsignal(signal.SIGINT) is signal.SIG_IGN:
        signal.signal(signal.SIGINT, signal.default_int_handler)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item: pytest.Item) -> Iterator[None]:
    """Record wall-clock steps during each test so a failure that compares timestamps says so.

    Hosts whose clock is stepped (WSL2 with both Hyper-V time sync and an NTP client)
    move time.time() back by seconds; monotonic time is unaffected.
    """
    wall, mono = time.time(), time.monotonic()
    yield
    step = (time.time() - wall) - (time.monotonic() - mono)
    if abs(step) > 0.5:
        item.add_report_section("call", "clock", f"wall clock stepped by {step:+.3f} s during this test")


# Module attributes that legitimately hold objects from test modules: (module, attribute) -> reason.
LEAK_GUARD_ALLOWED: dict[tuple[str, str], str] = {}
_GUARDED_PREFIXES = ("sigharvest", "sigharvest_lab")


def _test_object(value: Any) -> bool:
    """A function, class or mock that only a test could have bound into product code."""
    from unittest import mock

    if isinstance(value, mock.NonCallableMock):
        return True
    origin = getattr(value, "__module__", None)
    if not isinstance(origin, str) or not callable(value):
        return False
    root = origin.split(".", 1)[0]
    return root in {"tests", "conftest"} or origin.startswith("lab.tests") or root.startswith("test_")


def _leaked_bindings(names: set[str]) -> list[str]:
    import sys

    found = []
    for name in sorted(names):
        module = sys.modules.get(name)
        if module is None or not name.startswith(_GUARDED_PREFIXES):
            continue
        for attribute, value in list(vars(module).items()):
            if (name, attribute) in LEAK_GUARD_ALLOWED:
                continue
            lambda_from_elsewhere = getattr(value, "__name__", None) == "<lambda>" and getattr(value, "__module__", name) != name
            if lambda_from_elsewhere or _test_object(value):
                origin = getattr(value, "__module__", type(value).__module__)
                found.append(f"{name}.{attribute} = {getattr(value, '__qualname__', type(value).__name__)} from {origin}")
    return found


@pytest.fixture(autouse=True)
def _leak_guard() -> Iterator[None]:
    """Fail a test whose patch was captured by a module it imported first.

    `from x import f` binds f by value. When that import first happens while a test has
    x.f patched, the importing module keeps the test's stub after monkeypatch restores x,
    and later tests in the same worker see it. Runs after monkeypatch teardown (this
    autouse fixture sorts first, so it is torn down last) and only scans modules imported
    during the test.
    """
    import sys

    before = set(sys.modules)
    yield
    leaked = _leaked_bindings(set(sys.modules) - before)
    if leaked:
        pytest.fail(
            "test patches leaked into modules first imported during this test (import the module "
            "before patching, and patch its own binding too): " + "; ".join(leaked),
            pytrace=False,
        )


@pytest.fixture(autouse=True)
def _no_attack_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    """An isolated interpreter cannot inherit the parent socket monkeypatches."""
    from sigharvest import attack_io

    def blocked(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Offline test attempted ATT&CK transport subprocess")

    monkeypatch.setattr(attack_io, "_launch", blocked)


@pytest.fixture(autouse=True)
def _no_network() -> Iterator[None]:
    """Fail the test that tried to open an outbound connection, even if the code swallowed the error."""
    start = len(_attempts)
    yield
    tried = _attempts[start:]
    if tried:
        pytest.fail(f"test tried to use the network: {tried[:3]}", pytrace=False)


@pytest.fixture(scope="session", autouse=True)
def offline_pysigma_tags() -> Iterator[None]:
    """pySigma 1.5 loads tag catalogues lazily from a writable user cache/network.

    Use the suite's fixed ATT&CK vocabulary, retaining real tag validation without
    depending on ~/.cache or changing files outside the test workspace.
    """
    from sigma.data import mitre_attack, mitre_d3fend

    from tests.helpers import ATTACK_FIXTURE

    data = {
        "mitre_attack_tactics": {row[2]: row[0] for row in ATTACK_FIXTURE["tactics"]},
        "mitre_attack_techniques": {row["id"]: row["name"] for row in ATTACK_FIXTURE["techniques"]},
        "mitre_attack_intrusion_sets": {},
        "mitre_attack_software": {},
        "mitre_attack_datasources": {},
        "mitre_attack_mitigations": {},
    }
    with pytest.MonkeyPatch.context() as patch:
        for key, value in data.items():
            patch.setitem(vars(mitre_attack), key, value)
        for key in ("mitre_d3fend_tactics", "mitre_d3fend_techniques", "mitre_d3fend_artifacts"):
            patch.setitem(vars(mitre_d3fend), key, {})
        yield


@pytest.fixture(autouse=True)
def _plain_cli_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    """xdist seeds COLUMNS before imports; do not freeze that width into the shared console."""
    from sigharvest.cli.common import console

    monkeypatch.setattr(console, "_width", None)


@pytest.fixture
def schedule(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Inject only scanner module clocks and pipe readiness; restore after each test."""
    from tests.process_schedule import scheduled_stream

    return lambda script, **kwargs: scheduled_stream(monkeypatch, script, **kwargs)


@pytest.fixture(scope="session")
def test_timeout() -> Callable[[float], float]:
    """Scale harness watchdogs, never the deadlines whose semantics are tested."""
    load = os.getloadavg()[0] / (os.cpu_count() or 1) if hasattr(os, "getloadavg") else 1
    factor = float(os.environ.get("SIGHARVEST_TEST_LOAD_FACTOR", str(max(1.0, load))))
    if not math.isfinite(factor) or not 1 <= factor <= 20:
        raise pytest.UsageError("SIGHARVEST_TEST_LOAD_FACTOR must be finite and between 1 and 20")
    return lambda seconds: seconds * factor


@pytest.fixture
def workbench_timeout(monkeypatch: pytest.MonkeyPatch, test_timeout: Callable[[float], float]) -> None:
    from sigharvest import workbench

    monkeypatch.setattr(workbench, "WORKER_SECONDS", test_timeout(30))


@pytest.fixture
def local_syslog(test_timeout: Callable[[float], float]) -> Iterator[tuple[socket.socket, str]]:
    """Own a short, unique Unix socket independent of pytest's long basetemp."""
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("local syslog transport requires AF_UNIX datagram sockets")
    # Unix sun_path is usually only 108 bytes, including the terminating NUL.
    with tempfile.TemporaryDirectory(prefix="sg-", dir="/tmp" if Path("/tmp").is_dir() else None) as root:
        address = str(Path(root) / "s")
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        except OSError as exc:
            if exc.errno in {errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EPERM, errno.EACCES, errno.ENOSYS}:
                pytest.skip(f"AF_UNIX datagram sockets unavailable in this OS or container: {exc}")
            raise
        with sock:
            try:
                sock.bind(address)
            except OSError as exc:
                if exc.errno in {errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EPERM, errno.EACCES, errno.ENOSYS}:
                    pytest.skip(f"AF_UNIX datagram bind unavailable in this OS or container: {exc}")
                raise
            sock.settimeout(test_timeout(5))
            yield sock, address
