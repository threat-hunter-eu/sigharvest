"""Precomputed, directional repository overlap using compact logic bitsets.

Exact counts use logic hashes. Near counts use existing MinHash candidates verified
by Jaccard and count each subject logic once, excluding exact matches in that peer.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from sqlalchemy import delete, insert, select
from sqlalchemy.orm import Session

from sigharvest.models import LogicGroup, SourceOverlap, SourceSummary


def overlap_counts(membership: Mapping[str, set[str]], near: Iterable[tuple[str, str]], *, affected: set[str] | None = None) -> list[dict[str, Any]]:
    """Return nonzero directed overlaps; percentages use the subject's unique logic."""
    bits: dict[str, int] = defaultdict(int)
    positions = {logic: i for i, logic in enumerate(membership)}
    for logic, repositories in membership.items():
        bit = 1 << positions[logic]
        for name in repositories:
            bits[name] |= bit
    neighbors: dict[str, int] = defaultdict(int)
    for a, b in near:
        if a not in positions or b not in positions:
            continue
        for name in membership[b]:
            neighbors[name] |= 1 << positions[a]
        for name in membership[a]:
            neighbors[name] |= 1 << positions[b]
    near_only = {name: neighbors[name] & ~value for name, value in bits.items()}
    names = sorted(bits)
    rows = []
    for i, a in enumerate(names):
        for b in names[i + 1 :]:
            if affected is not None and a not in affected and b not in affected:
                continue
            exact = (bits[a] & bits[b]).bit_count()
            for subject, peer in ((a, b), (b, a)):
                similar = (bits[subject] & near_only[peer]).bit_count()
                if exact or similar:
                    rows.append({"name": subject, "other": peer, "exact": exact, "near": similar})
    return rows


def rebuild_source_overlap(
    s: Session,
    membership: Mapping[str, set[str]],
    near: Iterable[tuple[str, str]],
    documents: Mapping[str, int],
    *,
    affected: set[str] | None = None,
    overlap_affected: set[str] | None = None,
) -> None:
    """Replace overlap and source quality projections in the caller's index transaction."""
    overlap_names = overlap_affected if overlap_affected is not None else affected
    rows = overlap_counts(membership, near, affected=overlap_names) if overlap_names != set() else []
    s.execute(
        delete(SourceOverlap)
        if overlap_names is None
        else delete(SourceOverlap).where(SourceOverlap.name.in_(overlap_names) | SourceOverlap.other.in_(overlap_names))
    )
    for i in range(0, len(rows), 5000):
        s.execute(insert(SourceOverlap), rows[i : i + 5000])
    acc: dict[str, dict[str, Any]] = {}
    for _lh, sources, family, validation, score in s.execute(
        select(LogicGroup.logic_hash, LogicGroup.sources, LogicGroup.family_id, LogicGroup.validation, LogicGroup.score)
    ):
        for name in sources:
            if affected is not None and name not in affected:
                continue
            a = acc.setdefault(name, {"logic": 0, "families": set(), "only": 0, "ok": 0, "tested": 0, "score": 0.0})
            a["logic"] += 1
            a["families"].add(family)
            a["only"] += len(sources) == 1
            a["tested"] += bool(validation)
            a["ok"] += validation == "ok"
            a["score"] += score
    s.execute(delete(SourceSummary) if affected is None else delete(SourceSummary).where(SourceSummary.name.in_(affected)))
    if acc:
        s.execute(
            insert(SourceSummary),
            [
                {
                    "name": name,
                    "documents": documents.get(name, 0),
                    "logic": a["logic"],
                    "families": len(a["families"]),
                    "only": a["only"],
                    "valid_pct": round(100 * a["ok"] / a["tested"]) if a["tested"] else None,
                    "avg_score": round(a["score"] / a["logic"]),
                }
                for name, a in acc.items()
            ],
        )
