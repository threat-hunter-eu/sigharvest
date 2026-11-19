"""Versioned local telemetry: sanitized logs, bounded metric labels and optional trace IDs.

No exporter, network transport or event bodies. Timings use monotonic clocks in callers.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
from collections import Counter
from contextlib import suppress
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

CONTEXT: ContextVar[dict[str, Any] | None] = ContextVar("sigharvest_telemetry", default=None)
EVENTS = {"log", "run.started", "run.finished", "run.abandoned", "stage.finished", "web.admitted", "web.busy", "web.finished", "outbox.delivered"}
STAGES = {"snapshot", "sync", "test", "index", "report"}
_metrics: Counter[tuple[str, str]] = Counter()
_mutex = threading.Lock()
_secret = re.compile(r"token|password|secret|authorization|credential|api.?key", re.I)


# One linear pass: each URL token is consumed once and tested in the callback. A pattern that requires @?# inside
# the token backtracks over the rest of it at every "http://", which is quadratic on untrusted titles.
_url = re.compile(r"https?://[^\s<>\"']*", re.I)
_url_any = re.compile(r"https?://[^\s<>\"']+", re.I)
_url_sensitive = re.compile(r"[@?#]")


def _redact_sensitive(match: re.Match[str]) -> str:
    return "[url redacted]" if _url_sensitive.search(match[0]) else match[0]


def scrub(text: str, *, redact_urls: bool = True) -> str:
    """Remove configured secrets, credential assignments, URLs and terminal controls."""
    values = sorted({v for k, v in os.environ.items() if _secret.search(k) and v}, key=len, reverse=True)
    for value in values:
        text = text.replace(value, "[redacted]")
    text = _url_any.sub("[url redacted]", text) if redact_urls else _url.sub(_redact_sensitive, text)
    text = re.sub(r"(?i)\b(?:bearer|basic)\s+\S+", "[authorization redacted]", text)
    text = re.sub(r"(?i)\b(token|password|secret|api[_-]?key|authorization)\s*[:=]\s*[^\s,;]+", r"\1=[redacted]", text)
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "\ufffd", text)


def count(event: str, stage: str = "") -> None:
    """Only fixed labels: rule/source/principal IDs never become metric dimensions."""
    with _mutex:
        _metrics[(event if event in EVENTS else "log", stage if stage in STAGES else "")] += 1


def metrics() -> dict[str, int]:
    with _mutex:
        return {event + (":" + stage if stage else ""): value for (event, stage), value in sorted(_metrics.items())}


class Formatter(logging.Formatter):
    def __init__(self, structured: bool = False) -> None:
        super().__init__("%(asctime)s %(levelname)s %(name)s: %(message)s")
        self.structured = structured

    def format(self, record: logging.LogRecord) -> str:
        if not self.structured:
            return scrub(super().format(record)).replace("\n", "\\n").replace("\r", "\\r")
        event = getattr(record, "event", "log")
        fields: dict[str, Any] = {
            "schema": "sigharvest.log.v1",
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "event": event if event in EVENTS else "log",
            "message": scrub(record.getMessage())[:4000],
        }
        for key in ("run_id", "job_id", "source_id", "trace_id", "stage", "status", "principal", "environment", "correlations"):
            value = getattr(record, key, (CONTEXT.get() or {}).get(key))
            if value is not None:
                fields[key] = scrub(str(value))[:128]
        if record.exc_info and record.exc_info[0]:
            fields["error_type"] = record.exc_info[0].__name__
        return json.dumps(fields, ensure_ascii=True)


class FileHandler(logging.FileHandler):
    """A full log filesystem cannot abort a committed run or print unsanitized records."""

    failed = False

    def handleError(self, record: logging.LogRecord) -> None:
        if not self.failed:
            self.failed = True
            with suppress(OSError):
                sys.stderr.write("sigharvest: log write failed; consult the committed run in the database\n")
