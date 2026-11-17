"""Evidence for completeness of configured discovery queries, never a global census."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class QueryCoverage:
    strategy: str
    query: str
    pages: int = 0
    items: int = 0
    reported_total: int | None = None
    complete: bool = False
    truncated: bool = False
    budget_exhausted: bool = False
    stop_reason: str = "not_started"
    errors: dict[str, int] = field(default_factory=dict)
    _seen_ids: set[str] = field(default_factory=set, repr=False)

    def error(self, category: str) -> None:
        self.errors[category] = self.errors.get(category, 0) + 1
        self.stop_reason = category
        self.budget_exhausted = category == "budget_exhausted"

    def page(self, count: int, *, total: int | None = None, incomplete: bool = False, ids: list[str] | None = None) -> None:
        for key in ids or []:
            if key in self._seen_ids:
                self.truncated, self.stop_reason = True, "duplicate_results"
            self._seen_ids.add(key)
        self.pages += 1
        self.items += count
        if self.reported_total is not None and total is not None and total != self.reported_total:
            self.truncated = True
            self.stop_reason = "changing_results"
        if total is not None:
            self.reported_total = total
        if incomplete:
            self.truncated = True
            self.stop_reason = "provider_incomplete"

    def to_record(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("_seen_ids")
        return data

    def finish(self, reason: str = "exhausted") -> None:
        self.stop_reason = reason if not self.truncated else self.stop_reason
        self.complete = reason == "exhausted" and not self.truncated and not self.errors
        if self.complete and self.reported_total is not None and self.items < self.reported_total:
            self.complete, self.truncated, self.stop_reason = False, True, "short_page"
        if reason in ("result_cap", "page_cap", "low_yield"):
            self.truncated = True
        if reason == "budget_exhausted":
            self.budget_exhausted = True


@dataclass
class DiscoveryCoverage:
    queries: list[QueryCoverage] = field(default_factory=list)

    def start(self, strategy: str, query: str) -> QueryCoverage:
        row = QueryCoverage(strategy, query)
        self.queries.append(row)
        return row

    def summary(self) -> dict[str, Any]:
        strategies: dict[str, Any] = {}
        for name in sorted({q.strategy for q in self.queries}):
            rows = [q for q in self.queries if q.strategy == name]
            errors: Counter[str] = Counter()
            for q in rows:
                errors.update(q.errors)
            strategies[name] = {
                "queries_planned": len(rows),
                "queries_complete": sum(q.complete for q in rows),
                "pages": sum(q.pages for q in rows),
                "items": sum(q.items for q in rows),
                "truncated_queries": sum(q.truncated for q in rows),
                "budget_exhausted_queries": sum(q.budget_exhausted for q in rows),
                "complete": all(q.complete for q in rows),
                "errors": dict(errors),
            }
        return {
            "schema_version": 1,
            "scope": "configured_queries",
            "provider_complete": False,
            "strategies": strategies,
            "queries": [q.to_record() for q in self.queries],
        }
