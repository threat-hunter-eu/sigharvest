"""Size limits for search text, shared by the web UI, the JSON API and the CLI.

FTS cost grows with every term, so an unbounded query (thousands of repeated words)
can keep a reader busy for minutes. Real hunts stay far below these limits.
"""

from __future__ import annotations

from sigharvest.errors import SigharvestError

MAX_QUERY_CHARS = 1000
MAX_QUERY_TERMS = 64


class QueryTooLong(SigharvestError, ValueError):
    """The search text exceeds MAX_QUERY_CHARS characters or MAX_QUERY_TERMS terms."""


class QueryFilterError(QueryTooLong):
    """An inline filter combination the search cannot express (for example `OR` between different filter keys).

    A subclass of QueryTooLong so every caller that reports a bad query (web 400, CLI message) handles it."""


class QueryTooExpensive(QueryTooLong):
    """A query whose cost is out of proportion: a very short prefix (`a*`), or a search stopped by the read time
    budget (SIGHARVEST_READ_STATEMENT_SECONDS). The web UI and the API answer 400 / 503 with the message."""


def check_query(text: str | None) -> None:
    """Raise QueryTooLong with a plain message when the search text is over a limit."""
    if not text:
        return
    if len(text) > MAX_QUERY_CHARS:
        raise QueryTooLong(f"Search text is too long ({len(text):,} characters); the limit is {MAX_QUERY_CHARS:,}. Shorten the query and retry.")
    terms = len(text.split())
    if terms > MAX_QUERY_TERMS:
        raise QueryTooLong(f"Search text has too many terms ({terms:,}); the limit is {MAX_QUERY_TERMS}. Shorten the query and retry.")
