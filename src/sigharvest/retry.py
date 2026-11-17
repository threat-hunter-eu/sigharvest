"""Classify remote failures and bound retries without trusting server delay headers.

Unknown failures are not transient by default. HTTP 404 is ambiguous (private,
renamed or absent); only a ref-specific request can classify it as missing_ref.
"""

from __future__ import annotations

import math
import random
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC
from email.utils import parsedate_to_datetime

import httpx

RETRYABLE = frozenset({"rate_limit", "transient"})


def http_category(status: int, headers: Mapping[str, str] | None = None, *, ref: bool = False) -> str:
    headers = headers or {}
    if status == 429 or (status == 403 and (headers.get("retry-after") or headers.get("x-ratelimit-remaining") == "0")):
        return "rate_limit"
    if status in (401, 403):
        return "auth"
    if ref and status in (404, 422):
        return "missing_ref"
    if status == 404:
        return "not_found"
    if status in (410, 451):
        return "gone"
    if status >= 500 or status == 408:
        return "transient"
    return "invalid_response" if status >= 400 else "ok"


def git_category(exc: Exception) -> str:
    """Conservative classification; never expose stderr, URLs or credentials."""
    if isinstance(exc, (httpx.TransportError, subprocess.TimeoutExpired, TimeoutError, ConnectionError)):
        return "transient"
    if getattr(exc, "category", None):
        return str(exc.category)  # type: ignore[attr-defined]
    message = str(exc).lower()
    if "refusing" in message:
        return "refusing_input"
    if any(s in message for s in ("authentication failed", "permission denied", "could not read username", "http 401", "error: 403")):
        return "auth"
    if any(s in message for s in ("remote ref is missing", "couldn't find remote ref", "remote branch", "not a valid object name")):
        return "missing_ref"
    if any(s in message for s in ("repository not found", "does not exist", "not found")):
        return "not_found"
    if "410" in message:
        return "gone"
    if any(
        s in message
        for s in (
            "timed out",
            "could not resolve host",
            "connection reset",
            "failed to connect",
            "error: 502",
            "error: 503",
            # git's own words for a stalled or cut HTTP transfer (GIT_HTTP_LOW_SPEED_*: curl 28; dropped stream: curl
            # 18/56). The full-corpus run of 2026-11-15 lost 37 live repositories to these as "unknown", not retried.
            "operation too slow",
            "rpc failed",
            "early eof",
            "unexpected disconnect",
            "remote end hung up",
            "curl 18",
            "curl 28",
            "curl 56",
        )
    ):
        return "transient"
    return "infrastructure" if isinstance(exc, OSError) else "unknown"


def _number(value: str | None) -> float | None:
    try:
        result = float(value or "")
    except (ValueError, OverflowError):
        return None
    return result if math.isfinite(result) and result >= 0 else None


def retry_after(headers: Mapping[str, str], now: float) -> float | None:
    """Seconds or HTTP-date, then reset epoch. Ignore negative/nonfinite/corrupt values."""
    value = headers.get("retry-after")
    delay = _number(value)
    if delay is None and value:
        try:
            date = parsedate_to_datetime(value)
            if date.tzinfo is None:
                date = date.replace(tzinfo=UTC)
            delay = max(0.0, date.timestamp() - now)
        except (TypeError, ValueError, OverflowError):
            pass
    if delay is not None:
        return delay
    reset = _number(headers.get("x-ratelimit-reset"))
    return max(0.0, reset - now) if reset is not None else None


@dataclass
class RetryBudget:
    """At most eight attempts and 120 seconds of wait, with each wait at most 60s.

    A server minimum exceeding the budget ends this request instead of retrying early.
    The caller counts attempts including transport failures and applies a global cap.
    """

    max_attempts: int = 8
    max_wait: float = 120.0
    max_delay: float = 60.0
    jitter: Callable[[], float] = field(default=random.random)
    now: Callable[[], float] = field(default=time.time)
    attempts: int = 0
    waited: float = 0.0

    def delay(self, category: str, headers: Mapping[str, str] | None = None) -> float | None:
        if category not in RETRYABLE or self.attempts >= self.max_attempts:
            return None
        minimum = retry_after(headers or {}, self.now())
        backoff = min(30.0, 2.0 ** max(0, self.attempts - 1))
        delay = (minimum if minimum is not None else backoff) + max(0.0, min(1.0, self.jitter()))
        if delay > self.max_delay or self.waited + delay > self.max_wait:
            return None
        self.waited += delay
        return delay
