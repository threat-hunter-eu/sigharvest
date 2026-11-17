"""Telemetry boundaries for families; retain cross-boundary identity as related.

Raw identity postings remain available for explanation. Only postings sharing
the normalized product/category/service route may union into a family. Missing
route components are explicit values, never wildcards.
"""

from __future__ import annotations

import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased

from sigharvest.models import IndexFamilyLink, LogicGroup, Occurrence, RuleVersion
from sigharvest.normalize import logsource

Route = tuple[str | None, str | None, str | None]


def routes(s: Session, live: set[str]) -> dict[str, Route]:
    """Logic hashes include raw logsource, so versions of a logic share a route."""
    if not live:
        return {}
    present = select(Occurrence.id).where(Occurrence.version_id == RuleVersion.id, Occurrence.present.is_(True)).exists()
    query = select(RuleVersion.logic_hash, RuleVersion.product, RuleVersion.category, RuleVersion.service).where(present).distinct()
    keys = func.json_each(json.dumps(sorted(live))).table_valued("value")
    query = query.where(RuleVersion.logic_hash.in_(select(keys.c.value)))
    return {lh: logsource(product, category, service) for lh, product, category, service in s.execute(query)}


def related(s: Session, group: LogicGroup, limit: int = 50) -> list[tuple[LogicGroup, str]]:
    """Direct retained identity bridges, bounded and subject to ORM visibility.

    A result is a related rule on another route, not an interchangeable variant.
    Different posting owners distinguish UUID reuse from a declared relation.
    """
    link = aliased(IndexFamilyLink)
    peer = aliased(IndexFamilyLink)
    prefix = "public:"
    query = (
        select(LogicGroup, link.key, link.owner, peer.owner)
        .select_from(link)
        .join(peer, peer.key == link.key)
        .join(LogicGroup, LogicGroup.logic_hash == peer.logic_hash)
        .where(
            link.logic_hash == group.logic_hash,
            link.owner.startswith(prefix),
            peer.owner.startswith(prefix),
            LogicGroup.family_id != group.family_id,
        )
        .distinct()
        .order_by(LogicGroup.logic_hash, link.key, link.owner, peer.owner)
        .limit(max(1, min(limit, 100)))
    )
    result = []
    seen: set[tuple[str, str]] = set()
    for other, key, owner, peer_owner in s.execute(query):
        reason = (
            "semantic_hash" if key.startswith("s:") else "rule_id" if owner.startswith(prefix + "u:") and peer_owner.startswith(prefix + "u:") else "related"
        )
        if (other.logic_hash, reason) not in seen:
            seen.add((other.logic_hash, reason))
            result.append((other, reason))
    return result
