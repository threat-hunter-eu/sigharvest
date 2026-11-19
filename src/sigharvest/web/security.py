"""Request guards for the local UI: same-origin checks (CSRF), body size caps and security headers.

On loopback the UI has no login; bound to any other address it requires a token (TokenAuth, `serve --token-env`).
These guards also prevent cross-site requests, DNS rebinding and untrusted rule text running as script.
"""

from __future__ import annotations

import base64
import hmac
import math
import time
from collections import deque
from collections.abc import Callable
from typing import Any

from fastapi import HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse, Response


def refusal(scope: dict[str, Any], text: str, status: int, headers: dict[str, str] | None = None) -> Response:
    """A guard's refusal: JSON `{"detail": text}` under /api/ (like every API error, docs/conventions.md), else text."""
    if str(scope.get("path") or "").startswith("/api/"):
        return JSONResponse({"detail": text}, status_code=status, headers=headers)
    return PlainTextResponse(text, status_code=status, headers=headers)


# script-src 'self': no inline scripts or event handlers anywhere; style-src 'self': no inline style attributes.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
# FastAPI's Swagger page loads its own script and styles from a CDN; it gets no CSP (it shows no rule content).
CSP_EXEMPT = ("/api/docs", "/api/docs/oauth2-redirect")
HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"same-origin"),
    (b"x-frame-options", b"DENY"),
    (b"cross-origin-opener-policy", b"same-origin"),
]


def same_origin_headers(headers: dict[str, str]) -> bool:
    site = headers.get("sec-fetch-site")
    if site is not None and site not in ("same-origin", "none"):
        return False
    origin = headers.get("origin")
    if origin is None:
        return True  # non-browser clients (curl, tests) send no Origin
    host = headers.get("host", "")
    return origin in (f"http://{host}", f"https://{host}")


class UploadGuard:
    """ASGI middleware for every POST: refuse cross-site requests and oversized bodies before the form is parsed.

    `limit_for(path)` gives the byte limit of a path (forms and collection imports). The limit is
    enforced on Content-Length and again while the body streams (chunked uploads).
    """

    def __init__(self, app: Any, limit_for: Callable[[str], int]) -> None:
        self.app = app
        self.limit_for = limit_for

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("method") in ("GET", "HEAD", "OPTIONS"):
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        if not same_origin_headers(headers):
            await refusal(scope, "cross-site request refused", 403)(scope, receive, send)
            return
        limit = self.limit_for(str(scope.get("path")))
        length = headers.get("content-length")
        if length is not None and (not length.isdigit() or int(length) > limit):
            await refusal(scope, "upload too large", 413)(scope, receive, send)
            return
        seen = 0

        async def counted() -> dict[str, Any]:
            nonlocal seen
            message: dict[str, Any] = await receive()
            if message.get("type") == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    raise HTTPException(413, "upload too large")
            return message

        await self.app(scope, counted, send)


class SecurityHeaders:
    """ASGI middleware adding the Content-Security-Policy and a few hardening headers to every response."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        exempt = scope.get("path") in CSP_EXEMPT

        async def send_with_headers(message: dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers", []))
                present = {k.lower() for k, _ in headers}
                headers += [(k, v) for k, v in HEADERS if k not in present]
                if not exempt and b"content-security-policy" not in present:
                    headers.append((b"content-security-policy", CSP.encode()))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


MIN_TOKEN_LENGTH = 16


def authorised(header: str, token: str) -> bool:
    """HTTP Basic (any user name, the token as password) or Bearer; compared in constant time."""
    if header[:6].lower() == "basic ":
        try:
            _, _, password = base64.b64decode(header[6:], validate=True).decode().partition(":")
        except (ValueError, UnicodeDecodeError):
            return False
        return hmac.compare_digest(password.encode(), token.encode())
    if header[:7].lower() == "bearer ":
        return hmac.compare_digest(header[7:].encode("utf-8", "surrogateescape"), token.encode())
    return False


class TokenAuth:
    """ASGI middleware: every HTTP request needs the token (`sigharvest serve --token-env VAR`), static files included.

    A peer address that sends MAX_FAILURES wrong tokens within WINDOW_SECONDS is refused (429) until the oldest of
    them leaves the window, even with the right token, so the token cannot be guessed at line rate. A request with no
    Authorization header (a browser's first request) does not count; a successful login does not reset the count.
    The peer is the TCP client: behind a reverse proxy every client shares the proxy's address.
    """

    MAX_FAILURES = 20
    WINDOW_SECONDS = 60
    MAX_PEERS = 4096

    def __init__(self, app: Any, token: str, clock: Callable[[], float] = time.monotonic) -> None:
        self.app = app
        self.token = token
        self.clock = clock
        self.failures: dict[str, deque[float]] = {}

    def _recent(self, peer: str, now: float) -> deque[float]:
        times = self.failures.get(peer, deque())
        while times and times[0] <= now - self.WINDOW_SECONDS:
            times.popleft()
        if not times:
            self.failures.pop(peer, None)
        return times

    def _record(self, peer: str, now: float) -> None:
        if peer not in self.failures and len(self.failures) >= self.MAX_PEERS:
            for stale in [p for p, t in self.failures.items() if t[-1] <= now - self.WINDOW_SECONDS]:
                del self.failures[stale]
            if len(self.failures) >= self.MAX_PEERS:
                del self.failures[next(iter(self.failures))]
        times = self.failures.setdefault(peer, deque())
        times.append(now)
        while len(times) > self.MAX_FAILURES:
            times.popleft()

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        peer = str(client[0]) if client else ""
        now = self.clock()
        recent = self._recent(peer, now)
        if len(recent) >= self.MAX_FAILURES:
            wait = max(1, math.ceil(recent[0] + self.WINDOW_SECONDS - now))
            await refusal(scope, "too many failed logins", 429, {"Retry-After": str(wait)})(scope, receive, send)
            return
        header = next((v.decode("latin-1") for k, v in scope.get("headers", []) if k.lower() == b"authorization"), "")
        if not authorised(header, self.token):
            if header:
                self._record(peer, now)
            response = refusal(scope, "authentication required", 401, {"WWW-Authenticate": 'Basic realm="sigharvest"'})
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)
