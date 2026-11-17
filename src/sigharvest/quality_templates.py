"""Conservative source-local template cohorts; no rule or source name blacklist.

Twenty distinct logic hashes must share a title pattern, logsource, condition
and all but one scalar detection value. Copies and metadata revisions cannot
inflate the threshold. Oversized or recursive inputs are left unclassified.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from typing import Any

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from sigharvest import normalize
from sigharvest.db import IN_CHUNK
from sigharvest.models import Occurrence, RuleVersion, Source

MIN_TEMPLATE_LOGIC = 20
MAX_RAW = 1024 * 1024
MAX_LEAVES = 64
MAX_NODES = 4096
MAX_DEPTH = 32
_BASELINE = re.compile(r"\S.*\s+-\s+Analytic\s+\d{3,}\s+Baseline\s*$", re.I)
_NUMBERS = re.compile(r"\b\d+\b")


def baseline_query(title: str, level: str | None, status: str | None) -> bool:
    """Explicit numbered baseline series without an alert severity."""
    # Real series titles are short; the length check keeps the backtracking pattern linear on hostile titles.
    return len(title) <= 300 and bool(_BASELINE.fullmatch(title)) and not level and normalize.status(status) == "experimental"


def title_pattern(title: str) -> str:
    title = " ".join(title.casefold().split())
    prefix, colon, _ = title.partition(":")
    if colon and len(prefix.split()) >= 3:
        title = prefix + ":*"
    return _NUMBERS.sub("#", title)


def skeletons(raw: str) -> tuple[str, ...]:
    """Hash each single-value hole, retaining field names, modifiers and structure.

    Conditions and timeframe are never holes. Lists retain order and length;
    dictionaries are sorted. This intentionally misses multi-value generators.
    """
    if len(raw.encode("utf-8")) > MAX_RAW:
        return ()
    try:
        data = yaml.load(raw, Loader=getattr(yaml, "CBaseLoader", yaml.BaseLoader))  # noqa: S506 - strings only
        if not isinstance(data, dict) or not isinstance(data.get("detection"), dict):
            return ()
        tokens: list[Any] = []
        holes: list[int] = []
        nodes = 0

        def walk(value: Any, depth: int = 0, variable: bool = True) -> None:
            nonlocal nodes
            nodes += 1
            if nodes > MAX_NODES or depth > MAX_DEPTH or len(holes) > MAX_LEAVES:
                raise ValueError("template structure budget")
            if isinstance(value, dict):
                tokens.append(["map", len(value)])
                for key in sorted(value):
                    tokens.append(["key", key])
                    walk(value[key], depth + 1, variable and not (depth == 0 and key in {"condition", "timeframe"}))
            elif isinstance(value, list):
                tokens.append(["list", len(value)])
                for item in value:
                    walk(item, depth + 1, variable)
            else:
                if variable:
                    holes.append(len(tokens))
                tokens.append(["value", value])

        walk(data["detection"])
        if not holes or len(holes) > MAX_LEAVES:
            return ()
        ls = data.get("logsource")
        if not isinstance(ls, dict):
            return ()
        # Full raw logsource also preserves definition/extra routing constraints.
        prefix = json.dumps(ls, sort_keys=True, ensure_ascii=False).encode()
        result = []
        for pos in holes:
            original = tokens[pos]
            tokens[pos] = ["hole"]
            result.append(hashlib.sha256(prefix + json.dumps(tokens, ensure_ascii=False).encode()).hexdigest())
            tokens[pos] = original
        return tuple(result)
    except (yaml.YAMLError, ValueError, TypeError, RecursionError):
        return ()


def template_groups(s: Session, *, only_hashes: set[str] | None = None) -> set[str]:
    """Read narrow live metadata first; parse only sufficiently large title sets.

    Re-evaluate cohort membership each index, including unchanged neighbours
    when additions/removals cross the threshold. No disposable table or live DB write is needed.
    """
    cohorts: dict[tuple[str, str], dict[str, int]] = defaultdict(dict)
    flagged: set[str] = set()
    query = (
        select(Source.name, RuleVersion.id, RuleVersion.logic_hash, RuleVersion.title, RuleVersion.level, RuleVersion.status)
        .join(Occurrence, Occurrence.version_id == RuleVersion.id)
        .join(Source, Source.id == Occurrence.source_id)
        .where(Occurrence.present.is_(True), RuleVersion.kind == "rule")
        .distinct()
    )
    if only_hashes is not None:
        keys = func.json_each(json.dumps(sorted(only_hashes))).table_valued("value")
        query = query.where(RuleVersion.logic_hash.in_(select(keys.c.value)))
    for source, vid, lh, title, level, status in s.execute(query):
        if baseline_query(title or "", level, status):
            flagged.add(lh)
        pattern = title_pattern(title or "")
        if pattern:
            members = cohorts[source, pattern]
            members[lh] = min(vid, members.get(lh, vid))
    candidates = [members for members in cohorts.values() if len(members) >= MIN_TEMPLATE_LOGIC]
    del cohorts
    by_version: dict[int, list[int]] = defaultdict(list)
    for i, members in enumerate(candidates):
        for vid in members.values():
            by_version[vid].append(i)
    buckets: dict[tuple[int, str], set[str]] = defaultdict(set)
    ids = sorted(by_version)
    for start in range(0, len(ids), IN_CHUNK):
        for vid, lh, raw in s.execute(select(RuleVersion.id, RuleVersion.logic_hash, RuleVersion.raw).where(RuleVersion.id.in_(ids[start : start + IN_CHUNK]))):
            for signature in skeletons(raw):
                for cohort in by_version[vid]:
                    buckets[cohort, signature].add(lh)
    for bucket in buckets.values():
        if len(bucket) >= MIN_TEMPLATE_LOGIC:
            flagged.update(bucket)
    return flagged
