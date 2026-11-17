"""Conservative detection-shape heuristics, independent of index freshness.

These are reviewable quality signals, not proof that a detection is useless.
Only unconstrained positive branches trigger wildcard heuristics.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from pyparsing import ParseBaseException
from sigma.conditions import ConditionAND, ConditionIdentifier, ConditionNOT, ConditionOR, ConditionSelector, condition

PRECISION_FLAGS = frozenset({"negation_only", "short_keyword_wildcard", "generic_field_wildcard", "test_like_low_level"})
_GENERIC = {"message", "msg", "raw", "rawmessage", "event.original", "full_log"}
_TEST = re.compile(r"\b(?:test|testing|fixture|dummy|example|sample|negated|wrong identifier|invalid (?:value|type|modifier|condition))\b", re.I)


@lru_cache(maxsize=512)
def glob_match(pattern: str, name: str) -> bool:
    """Match a Sigma condition wildcard (only `*`) in linear time; rule text is untrusted, so no regex."""
    parts = pattern.split("*")
    if len(parts) == 1:
        return pattern == name
    first, last = parts[0], parts[-1]
    if len(first) + len(last) > len(name) or not name.startswith(first) or not name.endswith(last):
        return False
    pos, end = len(first), len(name) - len(last)
    for part in parts[1:-1]:
        if not part:
            continue
        found = name.find(part, pos, end)
        if found < 0:
            return False
        pos = found + len(part)
    return True


def _tree(text: str) -> Any:
    if len(text) > 4096 or text.count("(") > 32 or len(text.split()) > 128:
        return None
    try:
        return condition.parse_string(text, parse_all=True)[0]
    except (ParseBaseException, ValueError, RecursionError):
        return None


def _short(value: Any) -> bool:
    return isinstance(value, str) and "*" in value and "\\" not in value and "?" not in value and 1 <= len(value.replace("*", "").strip()) <= 4


def _generic(value: Any) -> bool:
    if not isinstance(value, dict) or len(value) != 1:
        return False
    field, pattern = next(iter(value.items()))
    parts = str(field).lower().split("|")
    if parts[0] not in _GENERIC or parts[1:] not in ([], ["contains"]):
        return False
    if isinstance(pattern, list):
        if len(pattern) != 1:
            return False
        pattern = pattern[0]
    if not isinstance(pattern, str) or "\\" in pattern or "?" in pattern:
        return False
    if parts[1:] == ["contains"]:
        pattern = f"*{pattern}*"
    return bool(re.fullmatch(r"\*[^*]+\*", pattern))


def precision_flags(data: dict[str, Any]) -> list[str]:
    """Inspect boolean structure; mandatory strong selectors prevent wildcard exclusions."""
    flags: set[str] = set()
    if str(data.get("level") or "none").lower() == "none" and _TEST.search(str(data.get("title") or "")):
        flags.add("test_like_low_level")
    detection = data.get("detection")
    if not isinstance(detection, dict):
        return sorted(flags)
    selectors = {k: v for k, v in detection.items() if k not in {"condition", "timeframe"}}
    ls = data.get("logsource") or {}
    product_only = isinstance(ls, dict) and bool(ls.get("product")) and not (ls.get("category") or ls.get("service"))

    def visit(node: Any, kind: str, negated: bool = False) -> bool:
        if isinstance(node, ConditionNOT):
            return visit(node.args[0], kind, not negated)
        if isinstance(node, (ConditionAND, ConditionOR)):
            values = [visit(arg, kind, negated) for arg in node.args]
            if kind == "negation_only":
                return bool(values) and all(values)
            use_all = isinstance(node, ConditionAND) != negated
            return bool(values) and (all(values) if use_all else any(values))
        if isinstance(node, ConditionSelector):
            pattern = "*" if node.pattern == "them" else node.pattern
            names = [n for n in selectors if isinstance(n, str) and glob_match(pattern, n) and (node.pattern.startswith("_") or not n.startswith("_"))]
            values = [visit(ConditionIdentifier([name]), kind, negated) for name in names]
            use_all = kind == "negation_only" or ((node.cond_class is ConditionAND) != negated)
            return bool(values) and (all(values) if use_all else any(values))
        if not isinstance(node, ConditionIdentifier) or node.identifier not in selectors:
            return False
        if kind == "negation_only":
            return negated
        if negated:
            return False
        value = selectors[node.identifier]
        if kind == "short_keyword_wildcard":
            # A list of strings is OR; mappings and list-of-mappings are not keyword searches.
            return _short(value) or (isinstance(value, list) and any(_short(v) for v in value))
        return bool(product_only and _generic(value))

    conditions = detection.get("condition")
    for text in conditions if isinstance(conditions, list) else [conditions]:
        if not isinstance(text, str):
            continue
        tree = _tree(text)
        if tree is None:
            continue
        for kind in PRECISION_FLAGS - {"test_like_low_level"}:
            if visit(tree, kind):
                flags.add(kind)
    return sorted(flags)
