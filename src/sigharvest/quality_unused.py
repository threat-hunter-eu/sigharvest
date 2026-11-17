"""Unused named detections from pySigma's condition AST, never token guesses.

Names only suggest exclusion intent; they do not prove false positives. Invalid,
unresolved or oversized conditions produce no finding. Lists use the union of
references, including pySigma's exclusion of private names from rule wildcards.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

import yaml
from pyparsing import ParseBaseException
from sigma.conditions import ConditionAND, ConditionIdentifier, ConditionNOT, ConditionOR, ConditionSelector, condition
from sigma.exceptions import SigmaError

from sigharvest.quality_precision import glob_match

FLAGS = frozenset({"unused_selection", "unused_filter"})
FILTER_PREFIXES = ("filter", "exclude", "fp", "not_")
MAX_NAMES = 512
MAX_CONDITIONS = 128
MAX_CONDITION_CHARS = 8192
MAX_RAW_BYTES = 2 * 1024 * 1024


def is_filter(name: str) -> bool:
    return name.lower().startswith(FILTER_PREFIXES)


@lru_cache(maxsize=512)
def _references(names: tuple[str, ...], texts: tuple[str, ...]) -> tuple[tuple[str, ...], str | None]:
    used: set[str] = set()
    roots = []
    try:
        for text in texts:
            if len(text) > 4096 or text.count("(") > 32 or len(text.split()) > 128:
                return (), None
            root = condition.parse_string(text, parse_all=True)[0]
            roots.append(root)
            pending = [root]
            budget = 512
            while pending:
                budget -= 1
                if budget < 0:
                    return (), None
                node = pending.pop()
                if isinstance(node, ConditionIdentifier):
                    if node.identifier not in names:
                        return (), None
                    used.add(node.identifier)
                elif isinstance(node, ConditionSelector):
                    pattern = "*" if node.pattern == "them" else node.pattern
                    matched = {n for n in names if glob_match(pattern, n) and (pattern.startswith("_") or not n.startswith("_"))}
                    if not matched:
                        return (), None
                    used.update(matched)
                elif isinstance(node, (ConditionAND, ConditionOR, ConditionNOT)):
                    pending.extend(node.args)
                else:
                    return (), None
    except (ParseBaseException, SigmaError, ValueError, RecursionError):
        return (), None
    unused = tuple(n for n in names if n not in used)
    suggestion = None
    # Only the unambiguous two-name shape merits a display-only hypothesis.
    if len(names) == 2 and len(unused) == 1 and is_filter(unused[0]) and len(roots) == 1:
        root = roots[0]
        if isinstance(root, ConditionIdentifier) and not is_filter(root.identifier) and re.fullmatch(r"[A-Za-z0-9_]+", unused[0]):
            suggestion = f"{root.identifier} and not {unused[0]}"
    return unused, suggestion


def unused_selections(data: dict[str, Any]) -> dict[str, Any]:
    """Return names, filter-like subset and optional suggestion; empty means no finding."""
    detection = data.get("detection")
    if not isinstance(detection, dict) or len(detection) > MAX_NAMES + 2:
        return {}
    names = [n for n in detection if n not in {"condition", "timeframe"}]
    if not names or len(names) > MAX_NAMES or any(not isinstance(n, str) or len(n) > 256 for n in names):
        return {}
    texts = detection.get("condition")
    texts = texts if isinstance(texts, list) else [texts]
    if not texts or len(texts) > MAX_CONDITIONS or any(not isinstance(t, str) for t in texts):
        return {}
    if sum(map(len, texts)) > MAX_CONDITION_CHARS:
        return {}
    unused, suggestion = _references(tuple(sorted(names)), tuple(texts))
    if not unused:
        return {}
    return {"names": list(unused), "filters": [n for n in unused if is_filter(n)], "suggestion": suggestion}


def from_raw(raw: str) -> dict[str, Any]:
    """Preserve YAML scalar types so non-string conditions cannot become identifiers."""
    if len(raw) > MAX_RAW_BYTES or len(raw.encode()) > MAX_RAW_BYTES:
        return {}
    try:
        data = yaml.load(raw, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))  # noqa: S506 - safe constructors only
        return unused_selections(data) if isinstance(data, dict) else {}
    except (yaml.YAMLError, ValueError, RecursionError):
        return {}


def messages(details: dict[str, Any]) -> list[tuple[str, str]]:
    """One review message per sub-case, shared by lint and presentation."""
    out = []
    filters = details.get("filters", [])
    positive = [n for n in details.get("names", []) if n not in filters]
    if filters:
        out.append(("unused_filter", f"Unused filter-like selections: {', '.join(filters)}. Likely omitted exclusions; strong FP prior, not measured noise."))
    if positive:
        out.append(("unused_selection", f"Unused positive selections: {', '.join(positive)}. May broaden the rule or be dead code; weak structural prior."))
    return out
