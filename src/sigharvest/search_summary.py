"""Unfiltered facets computed during indexing and invalidated by transactional revisions."""

from __future__ import annotations

import json
from collections import defaultdict
from hashlib import sha256
from typing import Any

from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session

from sigharvest.index import FACET_COLUMNS, GroupFilters, scalar_facets, search_groups, shared_matches
from sigharvest.models import LogicGroup, Occurrence, SearchSummary
from sigharvest.read_cache import FACET_TABLES, revision

# Bumped when the facet derivation changes, so summaries stored by an older build are recomputed live.
FACETS_KEY = "facets:v3"

CARD_FIELDS = (
    "logic_hash",
    "title",
    "description",
    "level",
    "product",
    "category",
    "service",
    "copies",
    "n_sources",
    "family_size",
    "validation",
    "quality_flags",
    "junk",
    "score",
)


def card(group: Any) -> dict[str, Any]:
    from sigharvest.conversion import statuses_of

    return {name: getattr(group, name) for name in CARD_FIELDS} | {"conversion": statuses_of(group)}


def limits() -> dict[str, int]:
    long_lists = {"source", "service", "datasource", "product", "category", "technique", "tactic"}
    return {col: 10000 if col in long_lists else 40 for col in sorted(FACET_COLUMNS)}


def counts(s: Session, query: str | None, filters: GroupFilters, per_family: bool) -> dict[str, Any]:
    """Facet counts for a search; the default search reads the counts published with the index."""
    if not query and filters == GroupFilters():
        stored = read(s, per_family)
        if stored is not None:
            return stored
    with shared_matches():
        return scalar_facets(s, query, filters, per_family, limits())


def key(s: Session) -> str:
    return json.dumps(revision(s, FACET_TABLES))


def read(s: Session, per_family: bool) -> dict[str, Any] | None:
    row = s.get(SearchSummary, f"{FACETS_KEY}:{int(per_family)}")
    if row is None or row.revision != key(s):
        return None
    return row.payload


def refresh(s: Session, *, source_ready: bool = False) -> None:
    """Publish default facets and pages atomically with the index; callers own commit."""
    s.flush()
    s.execute(delete(SearchSummary))
    generation = key(s)
    if source_ready:
        s.add(SearchSummary(name="source_projection", revision=generation, payload={}))
    s.add(SearchSummary(name="search_stats", revision=generation, payload=live_stats(s)))
    from sigharvest.corpus_stats import refresh as refresh_corpus_stats

    refresh_corpus_stats(s)
    refresh_rank(s)
    refresh_memberships(s)
    refresh_first_pages(s)
    for families in (False, True):
        payload = scalar_facets(s, None, GroupFilters(), families, limits())
        s.add(SearchSummary(name=f"{FACETS_KEY}:{int(families)}", revision=generation, payload=payload))
    s.flush()


def refresh_first_pages(s: Session) -> None:
    """Persist the default page, with the same exact ranking and totals as live SQL."""
    generation = key(s)
    groups, total = search_groups(s, None, GroupFilters())
    for families in (False, True):
        selected, found = search_groups(s, None, GroupFilters(), per_family=True) if families else (groups, total)
        payload = {"ids": [g.id for g in selected], "rows": [card(g) for g in selected], "total": found, "logic_total": total}
        s.merge(SearchSummary(name=f"search_page:v1:{int(families)}", revision=generation, payload=payload))


def live_stats(s: Session) -> dict[str, int]:
    from sigharvest.source_status import counts as source_counts

    logic, families = s.execute(select(func.count(), func.count(func.distinct(LogicGroup.family_id))).select_from(LogicGroup)).one()
    return {
        "logic": logic,
        "families": families,
        "documents": s.scalar(select(func.count()).select_from(Occurrence).where(Occurrence.present.is_(True))) or 0,
        "sources": source_counts(s)[1],
    }


def stats(s: Session) -> dict[str, Any]:
    from sigharvest.source_status import counts as source_counts

    stored = s.get(SearchSummary, "search_stats")
    if stored is not None and stored.revision == key(s):
        return stored.payload | {"sources": source_counts(s)[1]}
    return live_stats(s)


def membership_name(source: str) -> str:
    return "members:" + sha256(source.encode()).hexdigest()[:48]


def refresh_memberships(s: Session) -> None:
    """Compact inverted source membership, avoiding a JSON scan of every group."""
    members: dict[str, list[int]] = defaultdict(list)
    for gid, sources in s.execute(select(LogicGroup.id, LogicGroup.sources).execution_options(yield_per=500)):
        for source in set(sources):
            members[source].append(gid)
    generation = key(s)
    for source, ids in members.items():
        s.add(SearchSummary(name=membership_name(source), revision=generation, payload={"ids": ids}))
    s.add(SearchSummary(name="members_ready", revision=generation, payload={}))
    s.flush()


def source_members(s: Session, sources: str) -> list[int] | None:
    ready = s.get(SearchSummary, "members_ready")
    generation = key(s)
    if ready is None or ready.revision != generation:
        return None
    ids: set[int] = set()
    for source in {value.strip() for value in sources.split(",") if value.strip()}:
        row = s.get(SearchSummary, membership_name(source))
        if row is not None:
            if row.revision != generation:
                return None
            ids.update(row.payload["ids"])
    return sorted(ids)


def refresh_rank(s: Session) -> None:
    s.execute(text("DELETE FROM search_rank"))
    s.execute(
        text("""INSERT INTO search_rank (id, family_id, score, status, junk)
        SELECT g.id, g.family_id, g.score, g.status, g.junk FROM logic_groups g""")
    )
    s.add(SearchSummary(name="rank_ready", revision=key(s), payload={}))
    s.flush()


def compact_base(s: Session, base: str, query: str | None, filters: GroupFilters) -> tuple[str, bool]:
    """Use compact keys only for equivalent local default/text/single-source queries.

    Other filters, sort columns and publication scopes retain the live SQL oracle.
    A direct mutation invalidates both ranking and membership before any read.
    """
    from dataclasses import replace

    from sigharvest.index import parse_query

    if replace(filters, source=None) != GroupFilters():
        return base, False
    _, inline = parse_query(query or "")
    if inline.keys() - {"source"} or "," in (filters.source or inline.get("source", "")):
        return base, False
    ready = s.get(SearchSummary, "rank_ready")
    if ready is None or ready.revision != key(s):
        return base, False
    # Every remaining predicate uses these six columns, unless source membership
    # is stale (in which case the JSON predicate still requires the original row).
    if "json_each(g.sources)" in base:
        return base, False
    return base.replace("logic_groups g", "search_rank g"), True
