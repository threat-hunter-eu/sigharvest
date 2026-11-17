"""Bounded metadata inspection using the execution planner's exact reference resolver.

This is a current read snapshot, never a historical graph or executed evidence.
No recording, event decoder, evaluator, maintenance or evidence writer is invoked.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import LargeBinary, cast, func, select
from sqlalchemy.orm import Session

from sigharvest.correlation_plan import Candidate, document, names, reference_queries
from sigharvest.errors import SigharvestError
from sigharvest.models import Occurrence, RuleVersion, Source

MAX_DOCUMENTS = 1000
MAX_BYTES = 32 * 1024 * 1024
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_CANDIDATES = 32
MAX_NODES = 32
MAX_DEPTH = 4
MAX_LOCATIONS = 8
FALLBACK_ROWS = 1000
SECONDS = 3.0


class DependencyError(SigharvestError):
    """Invalid exact selection or unavailable bounded input."""


class _Limit(Exception):
    pass


@dataclass
class Inspection:
    session: Session
    deadline: float = field(default_factory=lambda: time.monotonic() + SECONDS)
    documents: dict[str, dict[str, Any]] = field(default_factory=dict)
    raw: dict[str, str] = field(default_factory=dict)
    parsed: dict[str, dict[str, Any]] = field(default_factory=dict)
    bytes_read: int = 0
    queries: int = 0
    fallback_queries: int = 0
    fallback_seconds: float = 0.0
    fallback_ids: list[int] | None = None
    fallback_complete: bool = True
    index_state: str = ""

    def check(self) -> None:
        if time.monotonic() > self.deadline:
            raise _Limit("inspection time cap")

    def load(self, content: str) -> dict[str, Any]:
        if content in self.documents:
            return self.documents[content]
        self.check()
        if len(self.documents) >= MAX_DOCUMENTS:
            raise _Limit("document cap")
        row = self.session.execute(
            select(RuleVersion.id, RuleVersion.logic_hash, RuleVersion.kind, func.length(cast(RuleVersion.raw, LargeBinary))).where(
                RuleVersion.content_hash == content
            )
        ).first()
        if row is None:
            raise DependencyError("Exact content version is unavailable; no current version was substituted")
        vid, logic, kind, size = row
        if size > MAX_DOCUMENT_BYTES or self.bytes_read + size > MAX_BYTES:
            raise _Limit("rule byte cap")
        raw = self.session.scalar(select(RuleVersion.raw).where(RuleVersion.id == vid))
        assert raw is not None
        self.bytes_read += size
        self.raw[content] = raw
        try:
            self.parsed[content] = document(raw)
            error = None
        except ValueError as exc:
            self.parsed[content] = {}
            error = str(exc)
        locations = self.session.execute(
            select(Source.name, Occurrence.path, Occurrence.doc_index, Occurrence.present)
            .join(Occurrence, Occurrence.source_id == Source.id)
            .where(Occurrence.version_id == vid)
            .order_by(Occurrence.id)
            .limit(MAX_LOCATIONS + 1)
        ).all()
        result = {
            "content_hash": content,
            "logic_hash": logic,
            "kind": kind,
            "parse_error": error,
            "locations": [dict(zip(("source", "path", "document", "present"), row, strict=True)) for row in locations[:MAX_LOCATIONS]],
            "locations_complete": len(locations) <= MAX_LOCATIONS,
        }
        self.documents[content] = result
        return result

    def candidate(self, content: str, key: str | None = None) -> Candidate:
        doc = self.load(content)
        return key or doc["logic_hash"], self.raw[content], self.parsed[content]

    def stage(self, ref: str, key: str, same_file: bool) -> dict[str, Any]:
        started = time.monotonic()
        indexed = self.index_state == "ready"
        items: list[str] = []
        complete = True
        reason = None
        try:
            self.check()
            query = reference_queries(ref, key, indexed)[0 if same_file else 1]
            # Without an index every eligible document in the bounded prefix must
            # be parsed. A textual prefilter can hide escaped aliases.
            if not indexed:
                if self.fallback_ids is None:
                    ids = list(self.session.scalars(select(RuleVersion.id).order_by(RuleVersion.id).limit(FALLBACK_ROWS + 1)))
                    self.fallback_ids = ids[:FALLBACK_ROWS]
                    self.fallback_complete = len(ids) <= FALLBACK_ROWS
                query = query.where(RuleVersion.id <= (self.fallback_ids[-1] if self.fallback_ids else 0))
                complete = self.fallback_complete
                reason = None if complete else "fallback corpus prefix cap"
                self.fallback_queries += 1
            self.queries += 1
            limit = MAX_CANDIDATES if indexed else FALLBACK_ROWS
            contents = list(self.session.scalars(query.with_only_columns(RuleVersion.content_hash).limit(limit + 1)))
            if len(contents) > limit:
                complete, reason = False, "candidate cap"
            for content in contents[:limit]:
                self.load(content)
                if ref in names(self.parsed[content]):
                    if len(items) >= MAX_CANDIDATES:
                        complete, reason = False, "candidate cap"
                        break
                    items.append(content)
        except _Limit as exc:
            complete, reason = False, str(exc)
        finally:
            if not indexed:
                self.fallback_seconds += time.monotonic() - started
        return {"candidates": items, "complete": complete, "reason": reason}
