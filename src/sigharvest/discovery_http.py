"""Bounded discovery HTTP, short-lived negative cache and classified retry budgets."""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import threading
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from sigharvest.discovery_coverage import DiscoveryCoverage
from sigharvest.errors import SigharvestError
from sigharvest.retry import RetryBudget, http_category

MAX_HTTP_BYTES = 8 * 1024**2
MAX_CACHE_BYTES = 64 * 1024**2
# Cache timestamps are wall-clock times persisted across runs. Hosts (WSL2, VMs, NTP) can step the clock backwards,
# so an entry written a moment ago may look slightly in the future; it is still fresh.
CLOCK_STEP_TOLERANCE = 300.0


class ApiError(RuntimeError):
    def __init__(self, status: int, url: str, category: str | None = None) -> None:
        # Never expose arbitrary URLs, query values, response bodies or credentials.
        self.category = category or http_category(status, ref="/contents/" in url)
        super().__init__(f"HTTP {status} ({self.category})")
        self.status = status


class Unreachable(SigharvestError):
    """No request of this run has reached a server and the next one cannot connect: the machine is offline."""


class CachedClient:
    """GET-only JSON/text client with an on-disk ETag cache and rate-limit handling.

    Cache entries are files named by the SHA-256 of the full URL. An entry younger than `max_age`
    seconds is used without any request; an older one is revalidated with If-None-Match (a 304 does
    not count against the GitHub core quota). On 403/429 the client honours Retry-After or waits for
    X-RateLimit-Reset. Code search (10 requests/min) is additionally spaced to one call per 6.2 s.
    """

    def __init__(
        self,
        cache_dir: Path,
        token: str | None = None,
        max_age: float = 7 * 86400,
        sleep: Callable[[float], None] = time.sleep,
        max_requests: int = 2000,
        jitter: Callable[[], float] | None = None,
    ) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age = max_age
        self._sleep = sleep
        self._lock = threading.Lock()
        self._last_code_search = -math.inf  # time.monotonic(): spacing within this process
        self.requests = 0
        self.cache_hits = 0
        self.http_attempts = 0
        self.retries = 0
        self.max_requests = max_requests
        self.jitter = jitter
        self.coverage = DiscoveryCoverage()
        self.errors: Counter[str] = Counter()
        headers = {"User-Agent": "sigharvest-discovery", "X-GitHub-Api-Version": "2022-11-28"}
        self._gh = httpx.Client(timeout=60, headers={**headers, "Accept": "application/vnd.github+json"}, follow_redirects=False)
        self._plain = httpx.Client(timeout=60, headers=headers, follow_redirects=False)
        self._token = token

    def close(self) -> None:
        self._gh.close()
        self._plain.close()

    def _path(self, url: str) -> Path:
        return self.cache_dir / (hashlib.sha256(url.encode()).hexdigest() + ".json")

    def get(self, url: str, accept: str | None = None) -> Any:
        """Return the decoded JSON body (or text when `accept` ends with 'raw'). Raises ApiError on 4xx/5xx."""
        key_url = url + (f"#accept={accept}" if accept else "")
        path = self._path(key_url)
        cached: dict[str, Any] | None = None
        if path.exists():
            with contextlib.suppress(OSError, ValueError):
                with path.open("rb") as handle:
                    payload = handle.read(MAX_CACHE_BYTES + 1)
                if len(payload) <= MAX_CACHE_BYTES:
                    cached = json.loads(payload)
        if not isinstance(cached, dict):
            cached = None
        try:
            age = time.time() - float(cached.get("fetched_at", 0)) if cached else float("inf")
            status = int(cached.get("status", 200)) if cached else 200
        except (ValueError, TypeError, OverflowError):
            cached, age, status = None, float("inf"), 200
        if cached and ("body" not in cached or not math.isfinite(age) or status < 200 or status > 599):
            cached = None
        ttl = min(self.max_age, 3600) if status >= 400 else self.max_age
        if cached and "body" in cached and -CLOCK_STEP_TOLERANCE <= age < ttl:
            self.cache_hits += 1
            if status >= 400:
                raise ApiError(int(cached["status"]), url)
            return cached["body"]
        parsed = httpx.URL(url)
        is_github = parsed.scheme == "https" and parsed.host == "api.github.com" and parsed.port in (None, 443)
        headers: dict[str, str] = {}
        if accept:
            headers["Accept"] = accept
        if is_github and self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        if cached and cached.get("etag") and status < 400:
            headers["If-None-Match"] = cached["etag"]
        client = self._gh if is_github else self._plain
        resp = self._request(client, url, headers)
        if resp.status_code == 304 and cached:
            cached.pop("url", None)
            cached["fetched_at"] = time.time()
            path.write_text(json.dumps(cached), encoding="utf-8")
            if status >= 400:
                raise ApiError(int(cached["status"]), url)
            return cached["body"]
        if resp.status_code in (404, 410, 451, 422):
            # Permanent-ish answers are cached too, so dead repos are not re-asked on every run.
            path.write_text(json.dumps({"status": resp.status_code, "fetched_at": time.time(), "body": None}), encoding="utf-8")
            raise ApiError(resp.status_code, url)
        if resp.status_code >= 400:
            raise ApiError(resp.status_code, url, http_category(resp.status_code, resp.headers))
        try:
            body: Any = resp.text if (accept or "").endswith("raw") or not resp.headers.get("content-type", "").startswith("application/json") else resp.json()
        except ValueError:
            raise ApiError(resp.status_code, url, "invalid_response") from None
        entry = {"status": 200, "etag": resp.headers.get("etag"), "fetched_at": time.time(), "body": body}
        path.write_text(json.dumps(entry), encoding="utf-8")
        return body

    def _request(self, client: httpx.Client, url: str, headers: dict[str, str]) -> httpx.Response:
        budget = RetryBudget()
        if self.jitter is not None:
            budget.jitter = self.jitter
        current = httpx.URL(url)
        origin = (current.scheme, current.host, current.port)
        redirects = 0
        connect_failed = True  # every attempt so far failed to connect
        while True:
            if self.http_attempts >= self.max_requests:
                self.errors["budget_exhausted"] += 1
                raise ApiError(599, url, "budget_exhausted")
            if "/search/code" in url:
                with self._lock:
                    wait = self._last_code_search + 6.2 - time.monotonic()
                    if wait > 0:
                        self._sleep(min(wait, 6.2))
                    self._last_code_search = time.monotonic()
            budget.attempts += 1
            self.http_attempts += 1
            response_headers: dict[str, str] = {}
            status = 599
            try:
                same_origin = (current.scheme, current.host, current.port) == origin
                scoped_headers = headers if same_origin else {k: v for k, v in headers.items() if k == "Accept"}
                with client.stream("GET", current, headers=scoped_headers) as response:
                    body = bytearray()
                    for chunk in response.iter_bytes(chunk_size=64 * 1024):
                        body.extend(chunk)
                        if len(body) > MAX_HTTP_BYTES:
                            raise ApiError(response.status_code, url, "resource_limit")
                    # iter_bytes already decoded the body: drop the encoding headers, or the new Response would
                    # decode it a second time (every gzip answer, e.g. GitHub search pages, failed with "incorrect
                    # header check").
                    plain = [(k, v) for k, v in response.headers.multi_items() if k.lower() not in ("content-encoding", "content-length", "transfer-encoding")]
                    resp = httpx.Response(response.status_code, headers=plain, content=bytes(body))
            except (httpx.TransportError, httpx.DecodingError) as exc:
                connect_failed = connect_failed and isinstance(exc, httpx.ConnectError)
                # DecodingError: a body that does not match its Content-Encoding (seen from a CDN mid-deploy); retried
                # like a dropped connection, then reported as a failed query instead of ending the whole run.
                category = "transient"
            else:
                connect_failed = False
                self.requests += 1
                status = resp.status_code
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location")
                    redirects += 1
                    if not location or len(location) > 8192 or redirects > 5 or budget.attempts >= budget.max_attempts:
                        raise ApiError(status, url, "invalid_response")
                    try:
                        destination = current.join(location)
                        if destination.scheme != "https" or not destination.host or destination.userinfo:
                            raise ValueError
                    except (httpx.InvalidURL, ValueError):
                        raise ApiError(status, url, "invalid_response") from None
                    current = destination
                    continue
                response_headers = dict(resp.headers)
                category = http_category(status, resp.headers, ref="/contents/" in url)
                if category == "ok":
                    return resp
                if category not in ("transient", "rate_limit"):
                    self.errors[category] += 1
                    return resp
            self.errors[category] += 1
            delay = budget.delay(category, response_headers)
            if self.http_attempts >= self.max_requests:
                self.errors["budget_exhausted"] += 1
                raise ApiError(599, url, "budget_exhausted")
            if delay is None:
                if connect_failed and self.requests == 0:
                    # Every attempt of the first query failed to connect (no network, DNS, proxy): each further query
                    # would retry with the same backoff, which kept an offline `discover` silent for over an hour.
                    raise Unreachable(f"cannot reach {current.host}: discovery needs the network (check the connection, DNS or HTTPS_PROXY and run it again)")
                raise ApiError(status if category == "rate_limit" else 599, url, category)
            self.retries += 1
            self._sleep(delay)
