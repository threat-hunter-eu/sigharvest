"""Shared ATT&CK source/JSON admission, bounded transport and atomic publication.

Keep byte admission independent of STIX reduction. In particular, ignored metadata
must not hide duplicate keys or non-JSON constants from either acquisition reader.
"""

from __future__ import annotations

import os
import signal
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from http.client import HTTPException
from typing import TYPE_CHECKING, Any, BinaryIO
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID

from sigharvest.errors import SigharvestError

if TYPE_CHECKING:
    import subprocess
    from pathlib import Path

from sigharvest.attack_json import ExpansionLimit, preflight

MAX_BUNDLE_BYTES = 128 * 1024 * 1024
BUNDLE_ID_LENGTH = 44
_READ_BYTES = 64 * 1024
ACQUISITION_SECONDS = 300.0


class AttackEnvelopeError(SigharvestError):
    """The original source is not an explicitly identified STIX bundle."""


def admit_bundle_envelope(bundle: dict[str, Any]) -> None:
    """Check only source identity, once before reduction; never apply to caches.

    UUID parsing alone accepts alternate spellings. Require the exact canonical
    spelling without repairing it, and bound the input before parsing. This is
    structural admission, not proof of authenticity or of an ATT&CK release.
    """
    if not isinstance(bundle.get("type"), str) or bundle["type"] != "bundle":
        raise AttackEnvelopeError(
            'Invalid ATT&CK root.type: expected exactly "bundle". Supply a complete Enterprise ATT&CK source bundle with the correct root.type.'
        )
    identity = bundle.get("id")
    if isinstance(identity, str) and len(identity) == BUNDLE_ID_LENGTH and identity.startswith("bundle--"):
        try:
            if str(UUID(identity[8:])) == identity[8:]:
                return
        except ValueError:
            pass
    raise AttackEnvelopeError(
        "Invalid ATT&CK root.id: expected bundle--UUID with a canonical lowercase, hyphenated UUID (44 characters, no padding). "
        "Supply a complete Enterprise ATT&CK source bundle with a valid root.id."
    )


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON object key")
        out[key] = value
    return out


def _invalid_constant(value: str) -> None:
    raise ValueError("non-JSON numeric constant")


def json_object(raw: bytes) -> dict[str, Any]:
    """Decode already bounded UTF-8 bytes without losing repeated object members."""
    import json

    try:
        preflight(raw)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=_invalid_constant)
    except ExpansionLimit:
        raise
    except (ValueError, RecursionError):
        raise ValueError("invalid UTF-8 JSON, duplicate object key, numeric constant or excessive nesting") from None
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class AcquisitionDeadline(ValueError):
    """The complete transport exhausted its one monotonic budget."""

    def __init__(self) -> None:
        super().__init__("ATT&CK acquisition timed out. Retry the coverage request. No cache was published.")


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AcquisitionDeadline()
    return remaining


@contextmanager
def _defer_cancel() -> Iterator[None]:
    """Register/reap the owned child before handling pending POSIX cancellation.

    Blocking the signals in this thread is not enough: with other threads running
    (web workers, pytest-xdist I/O), the kernel delivers SIGINT/SIGTERM to one of
    them and Python still runs the handler in the main thread, inside this block,
    which lost the just-launched child. The main thread therefore also records the
    signals while blocked and re-raises them to the restored handlers afterwards.
    """
    import threading

    if not hasattr(signal, "pthread_sigmask"):
        yield
        return
    signals: tuple[int, ...] = (signal.SIGINT, signal.SIGTERM)
    deferred: list[int] = []
    handlers: dict[int, Any] = {}
    if threading.current_thread() is threading.main_thread():
        for signum in signals:
            # None: a handler installed outside Python, which cannot be restored; leave it.
            if signal.getsignal(signum) is not None:
                handlers[signum] = signal.signal(signum, lambda received, frame: deferred.append(received))
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, set(signals))
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        for signum, handler in handlers.items():
            signal.signal(signum, handler)
        for signum in dict.fromkeys(deferred):
            signal.raise_signal(signum)


def _launch(url: str, deadline: float, output: BinaryIO) -> subprocess.Popen[bytes]:
    import subprocess
    from pathlib import Path

    # An isolated interpreter avoids forking a threaded web process. Pin imports
    # to this installation rather than inheriting an ambient PYTHONPATH.
    code = "import sys; sys.path.insert(0, sys.argv[1]); from sigharvest.attack_io import _worker; _worker()"
    return subprocess.Popen(
        [sys.executable, "-I", "-c", code, str(Path(__file__).resolve().parent.parent), url, repr(deadline)],
        stdin=subprocess.DEVNULL,
        stdout=output,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )


def _acquire(url: str, deadline: float) -> bytes:
    """Own one child and an anonymous spool until success, failure or cancellation.

    Socket timeouts cannot bound DNS or a read that keeps receiving bytes. The
    parent can kill the entire transport, including TLS and header processing.
    No pipe receive, downloader thread, child pool or background retry is used.
    """
    import subprocess
    import tempfile

    with tempfile.TemporaryFile() as output:
        child = None
        try:
            _remaining(deadline)
            with _defer_cancel():
                child = _launch(url, deadline, output)
            while child.poll() is None:
                with suppress(subprocess.TimeoutExpired):
                    child.wait(timeout=min(0.01, _remaining(deadline)))
            _remaining(deadline)
            if child.returncode == 2:
                raise AcquisitionDeadline()
            if child.returncode:
                raise ValueError("ATT&CK transport failed or response was interrupted")
            output.seek(0)
            raw = output.read(MAX_BUNDLE_BYTES + 1)
            _remaining(deadline)
            if len(raw) > MAX_BUNDLE_BYTES:
                raise ValueError("ATT&CK bundle exceeds byte limit")
            return raw
        finally:
            if child is not None:
                with _defer_cancel():
                    if child.poll() is None:
                        child.kill()
                    child.wait()


def fetch_bundle(url: str) -> bytes:
    """Acquire bytes within one 300-second budget, before JSON/STIX reduction."""
    deadline = time.monotonic() + ACQUISITION_SECONDS
    try:
        raw = _acquire(url, deadline)
        _remaining(deadline)
        return raw
    except OSError:
        raise ValueError("ATT&CK transport could not start or complete; retry") from None


def _worker() -> None:
    """Private subprocess entry point; only fixed exit codes and body bytes escape."""
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT, signal.SIGTERM})
    try:
        raw = _read_bundle(sys.argv[2], float(sys.argv[3]))
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
    except AcquisitionDeadline:
        sys.exit(2)
    except (ValueError, OSError):
        sys.exit(1)


def _read_bundle(url: str, deadline: float) -> bytes:
    """Read at most cap+1 body bytes, with no automatic content decompression.

    HTTPResponse.read(n) bounds the allocation at the transport read boundary;
    iterator chunk sizes in decoding HTTP clients do not provide that guarantee.
    Content-Length is only a framing consistency check, never the memory bound.
    """
    _remaining(deadline)
    opener = build_opener(_NoRedirect())
    try:
        for _ in range(6):
            if urlsplit(url).scheme != "https":
                raise ValueError("ATT&CK acquisition requires HTTPS redirects")
            try:
                response = opener.open(Request(url, headers={"Accept-Encoding": "identity"}), timeout=_remaining(deadline))  # noqa: S310
            except HTTPError as exc:
                # urllib represents redirect/error responses as file-like exceptions.
                with exc:
                    _remaining(deadline)
                    if exc.code in {301, 302, 303, 307, 308} and exc.headers.get("Location"):
                        url = urljoin(url, exc.headers["Location"])
                        continue
                    raise ValueError("ATT&CK HTTP request failed") from None
            with response:
                _remaining(deadline)
                if response.status != 200:
                    raise ValueError("ATT&CK HTTP request failed")
                if response.headers.get("Content-Encoding", "identity").lower().strip() != "identity":
                    raise ValueError("compressed ATT&CK responses are not supported; request identity encoding")
                declared = response.headers.get("Content-Length")
                if declared is not None and (not declared.isascii() or not declared.isdecimal() or len(declared) > 20):
                    raise ValueError("invalid ATT&CK Content-Length")
                length = int(declared) if declared is not None else None
                if length is not None and length > MAX_BUNDLE_BYTES:
                    raise ValueError("ATT&CK bundle exceeds byte limit")
                raw = bytearray()
                while True:
                    _remaining(deadline)
                    chunk = response.read(min(_READ_BYTES, MAX_BUNDLE_BYTES + 1 - len(raw)))
                    _remaining(deadline)
                    if not chunk:
                        break
                    raw.extend(chunk)
                    if len(raw) > MAX_BUNDLE_BYTES:
                        raise ValueError("ATT&CK bundle exceeds byte limit")
                if length is not None and len(raw) != length:
                    raise ValueError("incomplete ATT&CK response or inconsistent Content-Length")
            _remaining(deadline)
            return bytes(raw)
        raise ValueError("too many ATT&CK HTTP redirects")
    except (OSError, HTTPException):
        _remaining(deadline)
        raise ValueError("ATT&CK transport failed or response was interrupted") from None


def publish(target: Path, encoded: bytes) -> None:
    """Reuse threat refresh's same-directory, flushed temporary-file replacement."""
    import tempfile
    from pathlib import Path

    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as out:
        temporary = Path(out.name)
        try:
            out.write(encoded)
            out.flush()
            os.fsync(out.fileno())
            out.close()
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
