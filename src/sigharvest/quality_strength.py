"""Detection strength: can the condition be satisfied by weak values alone? (computed by `quality.classify`).

A value is weak when it says almost nothing about the event:
- a wildcard value (`*`/`?` or a contains/startswith/endswith modifier) with fewer than 3 literal ASCII characters,
  e.g. `Image|startswith: /`, `CommandLine|contains: '-e '`, `cs-uri|contains: '?c='` (`?` is a Sigma wildcard);
- a regular expression with fewer than 3 literal ASCII characters; a CIDR of /8 or wider;
- `exists` on a catch-all field (message, raw, full_log...): the presence of a specific field stays a signal.
Plain equality is never weak (`UserAgent: ''` is a real indicator), and neither are numbers, comparisons, field
references or a file name after a path separator (`Image|endswith: /w`).
A negated branch adds no strength: `selection and not filter` is as weak as `selection`.

Flags (reviewable heuristics, the rule text is never changed):
- weak_detection: every way to satisfy the condition uses only weak values (it matches almost any event of its log
  source); informational (broad hunting rules are legitimate), lowers the score;
- weak_high_severity: weak_detection on a high or critical rule: the level promises precision the detection cannot
  give, so it is hidden by default like the other junk flags;
- weak_branch: some OR branch is weak, but other branches are specific; informational, lowers the score.
"""

from __future__ import annotations

import re
from typing import Any

from sigma.conditions import ConditionAND, ConditionIdentifier, ConditionNOT, ConditionOR, ConditionSelector

from sigharvest.quality_precision import _GENERIC, _tree, glob_match

STRENGTH_FLAGS = ("weak_detection", "weak_high_severity", "weak_branch")
# score penalty per flag (index.score); weak_high_severity is junk and already costs the junk penalty
STRENGTH_PENALTY = {"weak_detection": 15.0, "weak_branch": 5.0}
_WILDCARD_MODS = {"contains", "startswith", "endswith"}
_REGEX_META = re.compile(r"\\.|[.*+?^$()\[\]{}|]")
_MAX_NODES = 4096  # untrusted rule text: bound the work per rule

# (can be satisfied by weak values only, every satisfying path is weak)
Strength = tuple[bool, bool]
_STRONG: Strength = (False, False)
_WEAK: Strength = (True, True)


def _literal(value: str) -> tuple[str, bool]:
    """Literal text of a Sigma string value without unescaped wildcards, and whether it had one."""
    out: list[str] = []
    wild = False
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(value[i + 1])
            i += 2
            continue
        if ch in "*?":
            wild = True
        else:
            out.append(ch)
        i += 1
    return "".join(out).strip(), wild


def value_is_weak(field: str, modifiers: list[str], value: Any) -> bool:
    """True when one field value (or keyword, with field '') says almost nothing about the event."""
    if isinstance(value, (dict, list)):
        return False
    mods = {m.lower() for m in modifiers}
    text = "" if value is None else str(value)
    if "exists" in mods:
        return field.lower() in _GENERIC and text.lower() in ("true", "yes")
    if mods & {"fieldref", "gt", "gte", "lt", "lte", "expand"}:
        return False  # a relation between two fields, a number or a placeholder: not a free-text value
    if "re" in mods:
        lit = _REGEX_META.sub("", text).strip()
        return not lit or (len(lit) < 3 and lit.isascii())
    if "cidr" in mods:
        m = re.search(r"/(\d+)\s*$", text)
        return m is not None and int(m.group(1)) <= 8
    if mods & {"base64", "base64offset"}:
        return False
    lit, wild = _literal(text)
    wild = wild or bool(mods & _WILDCARD_MODS) or not field  # keywords match anywhere in the event
    if not wild:
        return False
    if "endswith" in mods and len(lit) >= 2 and lit[0] in "/\\" and not set(lit[1:]) & set("/\\ "):
        return False  # `Image|endswith: /w`: a whole file name after a path separator
    if _anchored_symbols(text, mods, lit):
        return False  # `USER: '#-*'`: a value starting with two symbols is rare in real data (sudo CVE-2019-14287)
    return not lit or (len(lit) < 3 and lit.isascii())


def _anchored_symbols(text: str, mods: set[str], lit: str) -> bool:
    """Two punctuation characters (not spaces, dashes-plus-space or path separators) anchored at the value start."""
    anchored = "startswith" in mods or not (mods & _WILDCARD_MODS or text.startswith(("*", "?")))
    return anchored and len(lit) == 2 and text[:2] == lit and all(not c.isalnum() and not c.isspace() and c not in "/\\" for c in lit)


def _or(parts: list[Strength]) -> Strength:
    return (any(p[0] for p in parts), all(p[1] for p in parts)) if parts else _STRONG


def _and(parts: list[Strength]) -> Strength:
    return (all(p[0] for p in parts), all(p[1] for p in parts)) if parts else _STRONG


def _field_strength(key: str, values: Any) -> Strength:
    field, *mods = str(key).split("|")
    items = values if isinstance(values, list) else [values]
    if not items:
        return _STRONG
    parts = [_WEAK if value_is_weak(field, mods, v) else _STRONG for v in items]
    return _and(parts) if "all" in {m.lower() for m in mods} else _or(parts)


def _selection_strength(sel: Any) -> Strength:
    if isinstance(sel, dict):
        return _and([_field_strength(k, v) for k, v in sel.items()])
    if isinstance(sel, list):
        if all(isinstance(x, dict) for x in sel):
            return _or([_selection_strength(x) for x in sel])
        return _or([_WEAK if value_is_weak("", [], x) else _STRONG for x in sel if not isinstance(x, (dict, list))])
    if isinstance(sel, str):
        return _WEAK if value_is_weak("", [], sel) else _STRONG
    return _STRONG


def detection_strength(detection: Any) -> Strength | None:
    """(weak path exists, all paths weak) over every condition, or None when the condition cannot be read."""
    if not isinstance(detection, dict):
        return None
    selectors = {k: v for k, v in detection.items() if isinstance(k, str) and k not in {"condition", "timeframe"}}
    budget = [_MAX_NODES]

    def visit(node: Any) -> Strength:
        budget[0] -= 1
        if budget[0] < 0:
            raise RecursionError("condition too large")
        if isinstance(node, ConditionNOT):
            return _WEAK
        if isinstance(node, (ConditionAND, ConditionOR)):
            parts = [visit(a) for a in node.args]
            return _and(parts) if isinstance(node, ConditionAND) else _or(parts)
        if isinstance(node, ConditionSelector):
            pattern = "*" if node.pattern == "them" else node.pattern
            names = [n for n in selectors if glob_match(pattern, n) and (node.pattern.startswith("_") or not n.startswith("_"))]
            parts = [visit(ConditionIdentifier([n])) for n in names]
            return _and(parts) if node.cond_class is ConditionAND else _or(parts)
        if isinstance(node, ConditionIdentifier) and node.identifier in selectors:
            return _selection_strength(selectors[node.identifier])
        return _STRONG

    conditions = detection.get("condition")
    results: list[Strength] = []
    for text in conditions if isinstance(conditions, list) else [conditions]:
        tree = _tree(text) if isinstance(text, str) else None
        if tree is None:
            continue
        try:
            results.append(visit(tree))
        except RecursionError:
            return None
    return _or(results) if results else None


def strength_flags(data: dict[str, Any]) -> list[str]:
    """`weak_detection` (+ `weak_high_severity`), `weak_branch` or nothing for one parsed rule document."""
    result = detection_strength(data.get("detection"))
    if result is None or not result[0]:
        return []
    if not result[1]:
        return ["weak_branch"]
    high = str(data.get("level") or "").strip().lower() in ("high", "critical")
    return ["weak_detection", "weak_high_severity"] if high else ["weak_detection"]


def strength_penalty(flags: list[str] | None) -> float:
    """Score points removed for the strength flags (see STRENGTH_PENALTY)."""
    return sum(STRENGTH_PENALTY.get(f, 0.0) for f in flags or [])
