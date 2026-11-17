"""Resolve Sigma correlation dependencies without choosing an arbitrary corpus fork.

Selected documents take precedence over the corpus. Only live corpus documents are
considered; copies with identical logic are interchangeable. Dependencies run privately,
while explicitly selected base rules remain visible in check results.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import yaml
from sqlalchemy import LargeBinary, Select, cast, func, select, tuple_
from sqlalchemy.orm import Session, load_only

from sigharvest.documents import MAX_FILE_BYTES, FastSigmaSafeLoader
from sigharvest.identity import logic_hash
from sigharvest.models import CorrelationReference, LogicGroup, Occurrence, RuleVersion
from sigharvest.ruleview import WALK_MAX_DEPTH, unsafe_yaml

MAX_REFERENCES = 64
MAX_FIELDS = 16
CORRELATION_HINT = re.compile(r"^[ \t]*(?:correlation|'correlation'|\"correlation\")[ \t]*:", re.M)
TYPES = {"event_count", "value_count", "temporal", "temporal_ordered"}
OPERATORS = {"eq", "neq", "lt", "lte", "gt", "gte"}
# Seconds per unit, as in pySigma (a month and a year are mean Gregorian lengths).
TIMESPAN_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "M": 2629746, "y": 31556952}


class _Loader(FastSigmaSafeLoader):
    """Reject duplicate/nonstring keys instead of silently changing rule semantics."""

    def construct_mapping(self, node: Any, deep: bool = False) -> Any:
        keys = [self.construct_object(key, deep=deep) for key, _ in node.value]
        if any(not isinstance(key, str) for key in keys) or len(set(keys)) != len(keys):
            raise ValueError("rule mapping keys must be unique strings")
        return super().construct_mapping(node, deep=deep)


def document(raw: str) -> dict[str, Any]:
    """Bounded, alias-free YAML for dependency identity and correlation grammar."""
    if len(raw.encode()) > MAX_FILE_BYTES:
        raise ValueError("rule exceeds 2 MiB")
    try:
        depth = 0
        for event in yaml.parse(raw, Loader=FastSigmaSafeLoader):
            if isinstance(event, yaml.AliasEvent):
                raise ValueError("YAML aliases (*name) are not allowed")
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
                if depth > WALK_MAX_DEPTH + 8:
                    raise ValueError("YAML nesting too deep")
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
    except yaml.YAMLError:
        # Keep the existing diagnostics for invalid YAML, off the successful path.
        raise ValueError(unsafe_yaml(raw.encode()) or "invalid rule YAML") from None
    try:
        data = yaml.load(raw, Loader=_Loader)  # noqa: S506 - SafeLoader subclass
    except (yaml.YAMLError, RecursionError) as exc:
        raise ValueError("invalid rule YAML") from exc
    if not isinstance(data, dict):
        raise ValueError("expected a rule mapping")
    return data


def _identity(data: dict[str, Any], raw: str) -> str:
    try:
        return logic_hash(data)
    except (ValueError, TypeError, AttributeError):
        # An invalid named dependency must be reported, never replaced by a corpus rule.
        return hashlib.sha256(raw.encode()).hexdigest()


def names(data: dict[str, Any]) -> set[str]:
    return {data[k] for k in ("id", "name") if isinstance(data.get(k), str)}


def strings(value: Any, label: str, maximum: int = MAX_FIELDS, empty: bool = False) -> list[str]:
    if not isinstance(value, list) or not (0 if empty else 1) <= len(value) <= maximum:
        raise ValueError(f"{label} must be a list with at most {maximum} entries")
    if not all(isinstance(x, str) and 0 < len(x) <= 256 for x in value) or len(set(value)) != len(value):
        raise ValueError(f"{label} must contain distinct nonempty strings (at most 256 characters)")
    return value


@dataclass
class Correlation:
    key: str
    title: str
    level: str | None
    kind: str = ""
    references: list[str] = field(default_factory=list)
    keys: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    span: int = 0  # microseconds
    conditions: dict[str, int] = field(default_factory=dict)
    value_fields: list[str] = field(default_factory=list)
    aliases: dict[str, dict[str, str]] = field(default_factory=dict)
    error: str | None = None


def parse(key: str, data: dict[str, Any]) -> Correlation:
    spec = Correlation(key, str(data.get("title", key)), data.get("level") if isinstance(data.get("level"), str) else None)
    try:
        c = data["correlation"]
        if not isinstance(c, dict):
            raise ValueError("correlation must be a mapping")
        if set(c) - {"type", "rules", "group-by", "timespan", "condition", "aliases", "generate"}:
            raise ValueError("unsupported correlation attributes")
        # `generate` only controls whether conversion also emits the bases; it never
        # changes which events match (pySigma reads it inside the correlation block).
        if not isinstance(c.get("generate", False), bool):
            raise ValueError("generate must be a boolean")
        spec.kind = c.get("type", "")
        if not isinstance(spec.kind, str) or spec.kind not in TYPES:
            raise ValueError("unsupported correlation type")
        # pySigma accepts a single reference or group-by field as a plain string.
        rules, groups = c.get("rules"), c.get("group-by", [])
        spec.references = strings([rules] if isinstance(rules, str) else rules, "rules", MAX_REFERENCES)
        spec.groups = strings([groups] if isinstance(groups, str) else groups, "group-by", empty=True)
        span = c.get("timespan")
        # Same grammar as pySigma's SigmaCorrelationTimespan: ASCII digits (leading
        # zeros allowed, any length) with a count above zero, then one unit letter.
        match = re.fullmatch(r"([0-9]+)([smhdwMy])", span) if isinstance(span, str) else None
        digits = match[1].lstrip("0") if match is not None else ""
        if match is None or not digits:
            raise ValueError("timespan must be a positive integer followed by s, m, h, d, w, M or y")
        spec.span = int(digits) * TIMESPAN_UNITS[match[2]] * 1_000_000 if len(digits) <= 19 else 2**63
        if spec.span > 2**63 - 1:
            raise ValueError("timespan exceeds the supported range")
        cond = c.get("condition", {"gte": len(spec.references)} if spec.kind.startswith("temporal") else None)
        if not isinstance(cond, dict) or not cond or set(cond) - OPERATORS - {"field"}:
            raise ValueError("invalid correlation condition")
        if spec.kind == "value_count":
            fields = cond.get("field")
            spec.value_fields = strings([fields] if isinstance(fields, str) else fields, "condition.field")
        elif "field" in cond:
            raise ValueError("condition.field is only supported for value_count")
        spec.conditions = {k: v for k, v in cond.items() if k != "field"}
        if not spec.conditions or any(type(v) is not int or not 0 <= v <= 2**63 - 1 for v in spec.conditions.values()):
            raise ValueError("condition thresholds must be nonnegative integers")
        if spec.kind == "temporal_ordered" and spec.conditions != {"gte": len(spec.references)}:
            raise ValueError("temporal_ordered supports only the default all-rules condition")
        aliases = c.get("aliases", {})
        if not isinstance(aliases, dict) or len(aliases) > MAX_FIELDS:
            raise ValueError("invalid aliases")
        for alias, fields in aliases.items():
            if not isinstance(alias, str) or alias not in spec.groups + spec.value_fields or not isinstance(fields, dict):
                raise ValueError("aliases must map a grouping/value field to per-rule fields")
            if set(fields) != set(spec.references) or not all(isinstance(f, str) and 0 < len(f) <= 256 for f in fields.values()):
                raise ValueError("each alias must define a field for every referenced rule")
        spec.aliases = aliases
    except (ValueError, TypeError, KeyError) as exc:
        spec.error = str(exc)
        if not isinstance(spec.kind, str):
            spec.kind = "unsupported"
    return spec


@dataclass
class Plan:
    bases: list[tuple[str, str]]
    correlations: list[Correlation]
    visible: set[str]
    categories: dict[str, str]


Candidate = tuple[str, str, dict[str, Any]]


def reference_queries(ref: str, key: str, indexed: bool) -> tuple[Select[RuleVersion], Select[RuleVersion]]:
    """Live candidates by decoded alias, or complete semantic scan without an index.

    Raw substring predicates are unsound: YAML escapes need not contain the alias.
    Callers must bound the unindexed scan and never certify a partial result.
    """
    query = (
        select(RuleVersion)
        .where(
            select(Occurrence.id).where(Occurrence.version_id == RuleVersion.id, Occurrence.present.is_(True)).exists(),
            select(LogicGroup.id).where(LogicGroup.logic_hash == RuleVersion.logic_hash).exists(),
        )
        .order_by(RuleVersion.id)
        .execution_options(yield_per=100)
    )
    if indexed:
        query = query.join(
            CorrelationReference,
            (CorrelationReference.content_hash == RuleVersion.content_hash) & (CorrelationReference.logic_hash == RuleVersion.logic_hash),
        ).where(CorrelationReference.name == ref)
    locations = (
        select(Occurrence.source_id, Occurrence.path)
        .join(RuleVersion, RuleVersion.id == Occurrence.version_id)
        .where(RuleVersion.logic_hash == key, Occurrence.present.is_(True))
        .correlate(None)
    )
    in_file = (
        select(Occurrence.id)
        .where(
            Occurrence.version_id == RuleVersion.id,
            Occurrence.present.is_(True),
            tuple_(Occurrence.source_id, Occurrence.path).in_(locations),
        )
        .exists()
    )
    return query.where(in_file), query


def resolve_reference(ref: str, key: str, local: dict[str, list[Candidate]], fetch: Callable[[bool], list[Candidate]]) -> Candidate | str:
    """Authoritative precedence and identity collapse; fetch is lazy, same-file first."""
    candidates = local.get(ref, [])
    scope = key.rsplit("#", 1)[0]
    same_file = [row for row in candidates if row[0].rsplit("#", 1)[0] == scope]
    candidates = same_file or candidates or fetch(True) or fetch(False)
    by_logic = {_identity(data, raw): (key, raw, data) for key, raw, data in candidates}
    return next(iter(by_logic.values())) if len(by_logic) == 1 else f"{'ambiguous' if by_logic else 'missing'} reference: {ref}"


class ReferenceUnavailable(ValueError):
    """A bounded lookup cannot establish absence or uniqueness."""


@dataclass
class CatalogBudget:
    """Optional cumulative metadata budget for prospective, read-only callers."""

    bytes: int = 16 * 1024**2
    documents: int = 200

    def admit(self, sizes: list[int]) -> None:
        if len(sizes) > self.documents or any(n > 256 * 1024 for n in sizes) or sum(sizes) > self.bytes:
            raise ValueError("dependency metadata exceeds readiness budget")
        self.documents -= len(sizes)
        self.bytes -= sum(sizes)


def build(rules: list[tuple[str, str]], session: Session | None = None, *, catalog_budget: CatalogBudget | None = None) -> Plan:
    """Build one replay plan; missing, ambiguous and chained references fail per rule."""
    plan = Plan([], [], {key for key, _ in rules}, {})
    if not any(CORRELATION_HINT.search(raw) for _, raw in rules):
        plan.bases = rules
        return plan
    # Keep the name inventory without retaining every parsed YAML tree. Only
    # documents actually named by a correlation need their full detection data
    # for identity collapse and reference validation.
    local_raw: dict[str, list[tuple[str, str]]] = {}
    for key, raw in rules:
        try:
            data = document(raw)
        except ValueError as exc:
            if CORRELATION_HINT.search(raw):
                plan.correlations.append(Correlation(key, key, None, error=str(exc)))
            else:
                # Unsafe dependencies must never enter pySigma, even when selected explicitly.
                plan.bases.append((key, "invalid rule"))
            continue
        for name in names(data):
            local_raw.setdefault(name, []).append((key, raw))
        if "correlation" in data:
            plan.correlations.append(parse(key, data))
        else:
            plan.bases.append((key, raw))
            ls = data.get("logsource")
            if isinstance(ls, dict):
                plan.categories[key] = str(ls.get("category", "")).lower()
    base_keys = {key for key, _ in plan.bases}
    indexed: bool | None = None
    fallback_budget = catalog_budget if catalog_budget is not None else CatalogBudget()
    local: dict[str, list[Candidate]] = {}
    cache: dict[tuple[str, str], tuple[str, str, dict[str, Any]] | str] = {}
    for spec in plan.correlations:
        if spec.error:
            continue
        for ref in spec.references:
            scope = spec.key.rsplit("#", 1)[0]
            cache_key = (ref, scope)
            if cache_key not in cache:
                if ref not in local:
                    local[ref] = [(key, raw, document(raw)) for key, raw in local_raw.get(ref, [])]

                def fetch(same_file: bool, ref: str = ref, spec: Correlation = spec) -> list[Candidate]:
                    nonlocal indexed
                    if session is None:
                        return []
                    from sigharvest.correlation_references import status

                    if indexed is None:
                        indexed = status(session) == "ready"
                    query = reference_queries(ref, spec.key, indexed)[0 if same_file else 1]
                    budget = catalog_budget if indexed else fallback_budget
                    if budget is not None:
                        sizes = list(
                            session.execute(
                                query.with_only_columns(RuleVersion.id, func.length(cast(RuleVersion.raw, LargeBinary))).limit(budget.documents + 1)
                            )
                        )
                        try:
                            budget.admit([size for _, size in sizes])
                        except ValueError as exc:
                            raise ReferenceUnavailable(
                                "reference resolution unavailable: metadata scan budget exceeded"
                                + ("; run sigharvest index to rebuild the reference projection" if not indexed else "")
                            ) from exc
                        query = query.where(RuleVersion.id.in_([vid for vid, _ in sizes])).options(
                            load_only(RuleVersion.id, RuleVersion.logic_hash, RuleVersion.content_hash, RuleVersion.raw)
                        )
                    by_logic: dict[str, Candidate] = {}
                    for version in session.scalars(query):
                        if indexed and version.logic_hash in by_logic:
                            continue
                        try:
                            data = document(version.raw)
                        except ValueError:
                            continue
                        if ref in names(data):
                            by_logic.setdefault(version.logic_hash, (version.logic_hash, version.raw, data))
                            if len(by_logic) > 1:
                                break
                    return list(by_logic.values())

                try:
                    cache[cache_key] = resolve_reference(ref, spec.key, local, fetch)
                except ReferenceUnavailable as exc:
                    cache[cache_key] = str(exc)
            resolved = cache[cache_key]
            if isinstance(resolved, str):
                spec.error = resolved
                break
            key, raw, data = resolved
            if "correlation" in data or not isinstance(data.get("detection"), dict):
                spec.error = f"reference is not a base detection rule (chains/cycles unsupported): {ref}"
                break
            if key in spec.keys:
                spec.error = "multiple references resolve to the same base rule"
                break
            spec.keys.append(key)
            if key not in base_keys:
                plan.bases.append((key, raw))
                base_keys.add(key)
            ls = data.get("logsource")
            if isinstance(ls, dict):
                plan.categories[key] = str(ls.get("category", "")).lower()
    return plan
