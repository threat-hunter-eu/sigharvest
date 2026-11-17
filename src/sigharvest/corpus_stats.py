"""Exact local CLI inventory, published through the existing summary transaction.

These counts include unindexed live copies, unlike source
projections or default search facets. A stale/missing summary falls back to live
queries; readers never refresh it or write to the workspace.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from sigharvest.models import LogicGroup, Occurrence, RuleVersion, SearchSummary, Source
from sigharvest.read_cache import revision

NAME = "cli_stats:v1"
TABLES = ("rule_versions", "occurrences", "sources", "logic_groups")


@dataclass
class CorpusStats:
    documents: int
    contents: int
    rule_ids: int
    logic: int
    semantic: int
    families: int
    sources: list[tuple[str, int, int]]
    only: dict[str, int]


def key(s: Session) -> str:
    return json.dumps(revision(s, TABLES))


def live(s: Session) -> CorpusStats:
    """Preserve the CLI's live-copy counts and indexed family/only-here counts."""
    present = select(Occurrence.version_id).where(Occurrence.present.is_(True)).distinct().subquery()
    contents, ids, logic, semantic = s.execute(
        select(
            func.count(),
            func.count(func.distinct(RuleVersion.rule_id)),
            func.count(func.distinct(RuleVersion.logic_hash)),
            func.count(func.distinct(func.nullif(RuleVersion.semantic_hash, ""))),
        )
        .select_from(RuleVersion)
        .join(present, present.c.version_id == RuleVersion.id)
    ).one()
    sources = s.execute(
        select(Source.name, func.count(Occurrence.id), func.count(func.distinct(RuleVersion.logic_hash)))
        .join(Occurrence, Occurrence.source_id == Source.id)
        .join(RuleVersion, RuleVersion.id == Occurrence.version_id)
        .where(Occurrence.present.is_(True))
        .group_by(Source.name)
        .order_by(func.count(Occurrence.id).desc())
    ).all()
    only = dict(s.execute(select(LogicGroup.canonical_source, func.count()).where(LogicGroup.n_sources == 1).group_by(LogicGroup.canonical_source)).all())
    return CorpusStats(
        sum(row[1] for row in sources),
        contents,
        ids,
        logic,
        semantic,
        s.scalar(select(func.count(func.distinct(LogicGroup.family_id)))) or 0,
        [(name, docs, count) for name, docs, count in sources],
        only,
    )


def read(s: Session) -> CorpusStats:
    stored = s.get(SearchSummary, NAME)
    if stored is not None and stored.revision == key(s):
        payload = stored.payload | {"sources": [tuple(row) for row in stored.payload["sources"]]}
        return CorpusStats(**payload)
    return live(s)


def refresh(s: Session) -> None:
    """Publish local inventory with the index; the caller owns commit/rollback."""
    s.flush()
    s.merge(SearchSummary(name=NAME, revision=key(s), payload=asdict(live(s))))
