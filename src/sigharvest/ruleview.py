"""Rule page helpers: copies grouped by source, a one-line difference between family variants, the rule's own
context (false positives, references, regression data) and history ordered by the rule's own dates.

Everything here reads rule YAML from third-party repositories: it is parsed with a safe loader, size-capped, and
only ever displayed through autoescaped templates.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

DIFF_MAX_BYTES = 200_000  # larger rules (IOC lists) are not compared on the rule page
CONTEXT_MAX_ITEMS = 30

WALK_MAX_NODES = 50_000  # values visited per rule when comparing detections
WALK_MAX_DEPTH = 40
_FAST_SAFE_LOADER = getattr(yaml, "CSafeLoader", None)


class _NoAliasLoader(yaml.SafeLoader):
    """Rule YAML for display only: aliases are refused, because a small document with nested aliases expands
    hugely when it is walked (billion laughs). Real rules do not use them."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise yaml.YAMLError("aliases are not allowed")
        return super().compose_node(parent, index)


class _TooLarge(Exception):
    pass


def unsafe_yaml(raw: bytes) -> str | None:
    """Why untrusted YAML must not be parsed, or None. Fails closed: every chunk that load_documents will parse
    is composed (nodes only, nothing constructed) with a loader that refuses aliases; any YAML error refuses."""
    from sigharvest.documents import split_documents

    for chunk in split_documents(raw):
        try:
            for _ in yaml.compose_all(chunk, Loader=_NoAliasLoader):
                pass
        except yaml.YAMLError as exc:
            return "YAML aliases (*name) are not allowed" if "aliases are not allowed" in str(exc) else f"invalid YAML: {exc}"[:300]
        except (RecursionError, ValueError):
            return "YAML nesting too deep"
    return None


def _load(raw: str, *, loader: Any = None, max_nodes: int | None = None) -> dict[str, Any] | None:
    """Parse untrusted rule YAML (no aliases); None when it fails or is refused."""
    try:
        if _FAST_SAFE_LOADER is None and loader is None:
            data = yaml.load(raw, Loader=_NoAliasLoader)  # noqa: S506 - SafeLoader subclass without aliases
        else:
            # The C composer does not call the Python compose_node override.
            # Reject aliases in its event stream before constructing any object.
            # Bound nesting as well, before libyaml builds a deep object graph.
            selected_loader = loader or _FAST_SAFE_LOADER
            assert selected_loader is not None
            depth = nodes = 0
            for event in yaml.parse(raw, Loader=selected_loader):
                if isinstance(event, yaml.AliasEvent):
                    return None
                if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                    depth += 1
                    if depth > WALK_MAX_DEPTH + 8:
                        return None
                elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                    depth -= 1
                if max_nodes is not None and isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent, yaml.ScalarEvent)):
                    nodes += 1
                    if nodes > max_nodes:
                        return None
            data = yaml.load(raw, Loader=selected_loader)  # noqa: S506 - safe loader after alias check
    except (yaml.YAMLError, RecursionError, ValueError):
        return None
    return data if isinstance(data, dict) else None


@dataclass
class DetectionFacts:
    values: set[str] = field(default_factory=set)  # "field|modifiers=value" of positive selections, lower-cased
    filters: int = 0  # selections used under `not`
    filter_values: set[str] = field(default_factory=set)  # values of those selections
    logsource: tuple[str, str, str] = ("", "", "")
    condition: str = ""


def detection_facts(raw: str) -> DetectionFacts | None:
    """What a cheap comparison needs from a rule; None for unparseable or very large rules."""
    if len(raw) > DIFF_MAX_BYTES:
        return None
    data = _load(raw)
    if data is None or not isinstance(data.get("detection"), dict):
        return None
    det: dict[str, Any] = data["detection"]
    facts = DetectionFacts()

    visited = 0

    def walk(fld: str, x: Any, depth: int = 0) -> None:
        nonlocal visited
        visited += 1
        if visited > WALK_MAX_NODES or depth > WALK_MAX_DEPTH:
            raise _TooLarge
        if isinstance(x, dict):
            for k, v in x.items():
                walk(str(k).lower(), v, depth + 1)
        elif isinstance(x, list):
            for v in x:
                walk(fld, v, depth + 1)
        else:
            facts.values.add(f"{fld}={'null' if x is None else str(x).lower()}")

    names = [str(k) for k in det if k not in ("condition", "timeframe")]
    cond = det.get("condition")
    conds = [str(c) for c in cond] if isinstance(cond, list) else [str(cond or "")]
    facts.condition = " | ".join(" ".join(c.lower().split()) for c in conds)
    negated: set[str] = set()
    for c in conds:
        for pattern in re.findall(r"\bnot\s+(?:(?:1|all)\s+of\s+)?([\w*]+)", c, flags=re.I):
            negated |= set(names) if pattern.lower() == "them" else {n for n in names if fnmatch.fnmatchcase(n, pattern)}
    facts.filters = len(negated)
    try:
        for k in names:
            if k not in negated:
                walk("", det[k])
        positive, facts.values = facts.values, set()
        for k in negated:
            walk("", det[k])
    except _TooLarge:
        return None
    facts.filter_values, facts.values = facts.values, positive
    ls = data.get("logsource") if isinstance(data.get("logsource"), dict) else {}
    facts.logsource = tuple(str(ls.get(k) or "").lower() for k in ("product", "category", "service"))  # type: ignore[assignment,union-attr]
    return facts


def variant_diff(base: DetectionFacts | None, other: DetectionFacts | None) -> str:
    """'+3 values, -1 filter, other logsource' for a variant compared with this rule."""
    if base is None or other is None:
        return "not compared (large or unparseable rule)"
    parts = []
    added, removed = len(other.values - base.values), len(base.values - other.values)
    if added:
        parts.append(f"+{added} value{'s' if added > 1 else ''}")
    if removed:
        parts.append(f"-{removed} value{'s' if removed > 1 else ''}")
    df = other.filters - base.filters
    if df:
        parts.append(f"{'+' if df > 0 else '-'}{abs(df)} filter{'s' if abs(df) > 1 else ''}")
    elif other.filter_values != base.filter_values:
        parts.append("other filter values")
    if other.logsource != base.logsource:
        parts.append("other logsource (" + "/".join(x for x in other.logsource if x) + ")")
    if not parts:
        parts.append("same values, other condition" if other.condition != base.condition else "same values, other structure")
    return ", ".join(parts)


def _strings(x: Any) -> list[str]:
    if x is None:
        return []
    items = x if isinstance(x, list) else [x]
    return [str(i) for i in items if i is not None and str(i).strip()][:CONTEXT_MAX_ITEMS]


def rule_context(raw: str) -> dict[str, Any]:
    """falsepositives, references (with a flag saying whether each may be linked) and regression_tests_path."""
    data = _load(raw) if len(raw) <= 5 * DIFF_MAX_BYTES else None
    if data is None:
        return {"falsepositives": [], "references": [], "regression_tests_path": None}
    refs = [{"text": r, "link": bool(re.match(r"https?://[^\s\"'<>]+$", r))} for r in _strings(data.get("references"))]
    reg = data.get("regression_tests_path")
    return {
        "falsepositives": _strings(data.get("falsepositives")),
        "references": refs,
        "regression_tests_path": str(reg) if isinstance(reg, (str, int, float)) and str(reg).strip() else None,
    }


def current_text(group: Any, raw: str) -> tuple[str | None, str | None]:
    """Use published canonical metadata; parse only an unindexed show fallback."""
    from sigharvest.text_metadata import from_raw

    return (group.author, group.description) if group is not None else from_raw(raw)


def rule_date(v: Any) -> str:
    """The rule's own last date (modified, else date), normalised to YYYY-MM-DD where possible."""
    text = str(v.modified or v.date or "").strip().replace("/", "-")
    return text[:10]


def history_order(versions: list[Any]) -> list[Any]:
    """Versions of a rule id ordered by the rule's own modified/date fields (undated last), then first seen."""
    return sorted(versions, key=lambda h: (rule_date(h) == "", rule_date(h), h.first_seen))
