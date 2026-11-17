"""Stream exact duplicate counts without retaining every occurrence for a preview.

Keep one aggregate per identity and only one canonical candidate per logic. Full
reports retain query.dedupe's complete inventory; CLI previews build details only
for the requested top groups, preserving the full report's ordering and counts.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from sigharvest.models import Occurrence, RuleVersion, Source
from sigharvest.query import DedupeReport


@dataclass(slots=True)
class _Logic:
    copies: int = 0
    sources: set[str] = field(default_factory=set)
    rule_ids: set[str] = field(default_factory=set)
    order: tuple[int, datetime, str, str] | None = None
    canonical: dict[str, str | None] = field(default_factory=dict)


@dataclass(slots=True)
class _Rule:
    title: str | None
    logics: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)


def compute(s: Session, top: int) -> DedupeReport:
    """Use the same input order and canonical tie breakers as the full report."""
    query = (
        select(
            RuleVersion.rule_id,
            RuleVersion.logic_hash,
            RuleVersion.content_hash,
            RuleVersion.title,
            RuleVersion.title_slug,
            Source.name,
            Source.priority,
            Occurrence.path,
            Occurrence.first_seen,
        )
        .join(Occurrence, Occurrence.version_id == RuleVersion.id)
        .join(Source, Source.id == Occurrence.source_id)
        .where(Occurrence.present.is_(True))
    )
    logics: dict[str, _Logic] = {}
    rules: dict[str, _Rule] = {}
    contents: Counter[str] = Counter()
    titles: dict[str, set[str]] = defaultdict(set)
    rep = DedupeReport()
    for rid, logic, content, title, slug, source, priority, path, first_seen in s.execute(query.execution_options(yield_per=2000)):
        rep.live_documents += 1
        contents[content] += 1
        group = logics.get(logic)
        if group is None:
            group = logics[logic] = _Logic()
        group.copies += 1
        group.sources.add(source)
        group.rule_ids.add(rid)
        order = (priority, first_seen, source, path)
        if group.order is None or order < group.order:
            group.order = order
            group.canonical = {"source": source, "path": path, "rule_id": rid, "title": title}
        rule = rules.get(rid)
        if rule is None:
            rule = rules[rid] = _Rule(title)
        rule.logics.add(logic)
        rule.sources.add(source)
        if slug:
            titles[slug].add(logic)
    rep.unique_contents, rep.unique_rule_ids, rep.unique_logic = len(contents), len(rules), len(logics)
    rep.exact_copies = rep.live_documents - rep.unique_contents
    rep.exact_copy_groups = sum(count > 1 for count in contents.values())
    groups = sorted(((logic, group) for logic, group in logics.items() if group.copies > 1), key=lambda pair: -pair[1].copies)
    rep.logic_groups = [
        {
            "logic_hash": logic,
            "copies": group.copies,
            "sources": sorted(group.sources),
            "rule_ids": sorted(group.rule_ids),
            "canonical": group.canonical,
        }
        for logic, group in groups[:top]
    ]
    rep.id_conflicts = [
        {"rule_id": rid, "logic_variants": len(rule.logics), "sources": sorted(rule.sources), "title": rule.title}
        for rid, rule in rules.items()
        if len(rule.logics) > 1
    ]
    rep.id_conflicts.sort(key=lambda group: -group["logic_variants"])
    rep.title_groups = [{"title_slug": slug, "logic_variants": len(values)} for slug, values in titles.items() if len(values) > 1]
    rep.title_groups.sort(key=lambda group: -group["logic_variants"])
    return rep
