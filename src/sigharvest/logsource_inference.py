"""Bounded inference from positive source selectors, never from event numbers alone."""

from __future__ import annotations

import json
import re
from typing import Any

import yaml

from sigharvest.logsource_catalog import WINDOWS_CHANNELS

MAX_DETECTION_BYTES = 2 * 1024 * 1024
IDENTITY_FIELDS = frozenset({"Channel", "channel", "winlog.channel", "appname", "syslog_appname", "eventSource"})
CHANNEL_NAMES = {
    name.lower(): service for service, channels in WINDOWS_CHANNELS.items() for name in [service, *(channels if isinstance(channels, list) else [channels])]
}
CHANNEL_NAMES["msexchange_management"] = "msexchange-management"


def _identity(value: object, product: str | None) -> tuple[str, str] | None:
    if not isinstance(value, str):
        return None
    value = value.lower().strip("*")
    if product == "windows" and value in CHANNEL_NAMES:
        return "windows", CHANNEL_NAMES[value]
    if product == "aws":
        if value == "guardduty":
            return "aws", "guardduty"
        if re.fullmatch(r"[a-z0-9.-]+\.amazonaws\.com", value) or value == "cloudtrail":
            return "aws", "cloudtrail"
    return None


def _selector_identity(selector: object, product: str | None) -> set[tuple[str, str]]:
    if isinstance(selector, list):
        # An OR selector only constrains the source if every branch agrees.
        if not selector or len(selector) > 64:
            return set()
        if not all(isinstance(branch, dict) for branch in selector):
            return set()
        return set.intersection(*(_selector_identity(branch, product) for branch in selector))
    if not isinstance(selector, dict):
        return set()
    found: set[tuple[str, str]] = set()
    for field, values in selector.items():
        if not isinstance(field, str):
            continue
        parts = field.split("|")
        if parts[0] not in IDENTITY_FIELDS or any(mod not in {"cased"} for mod in parts[1:]):
            continue
        values = values if isinstance(values, list) else [values]
        identities = {_identity(value, product) for value in values if isinstance(value, str)}
        if values and len(values) <= 64 and len(identities) == 1 and None not in identities and all(isinstance(v, str) for v in values):
            found.update(identity for identity in identities if identity is not None)
    # Conflicting identities are not a valid source constraint.
    return found if len(found) == 1 else set()


def infer_service(product: str | None, data: dict[str, Any]) -> str | None:
    """Recognize a required channel in a simple conjunction, ignoring negated filters.

    OR, wildcards/quantifiers in conditions, missing selectors and arbitrary nesting
    remain unknown. No rule content is executed and no source constraint is rewritten.
    """
    condition = data.get("condition")
    if not isinstance(condition, str) or len(condition) > 4096:
        return None
    names = condition.strip().split(" and ")
    if len(names) > 32:
        return None
    found: set[tuple[str, str]] = set()
    for name in names:
        if re.fullmatch(r"not (?:[A-Za-z_][A-Za-z0-9_]*|\([A-Za-z_][A-Za-z0-9_]*(?: or [A-Za-z_][A-Za-z0-9_]*)*\))", name):
            continue
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or name not in data:
            return None
        found.update(_selector_identity(data[name], product))
    return next(iter(found))[1] if len(found) == 1 else None


# Deliberately small, contextual allowlist. Numbers are never global channel IDs.
# 517 is the legacy Security log-clear event. System 104 and 7045 cover log clear
# and service installation.
SECURITY_EVENT_IDS = frozenset(
    {
        517,
        1102,
        4608,
        4609,
        4616,
        4624,
        4625,
        4634,
        4647,
        4648,
        4656,
        4657,
        4658,
        4660,
        4662,
        4663,
        4670,
        4672,
        4673,
        4674,
        4688,
        4689,
        4697,
        4698,
        4699,
        4700,
        4701,
        4702,
        4703,
        4719,
        4720,
        4722,
        4723,
        4724,
        4725,
        4726,
        4728,
        4729,
        4732,
        4733,
        4738,
        4740,
        4741,
        4742,
        4743,
        4756,
        4757,
        4767,
        4768,
        4769,
        4770,
        4771,
        4776,
        4778,
        4779,
        4798,
        4799,
        4907,
        5025,
        5038,
        5136,
        5137,
        5139,
        5140,
        5141,
        5142,
        5143,
        5144,
        5145,
        5156,
        5157,
        5379,
    }
)
AUTHENTICATION_EVENT_IDS = frozenset({4624, 4625, 4648, 4776})
SYSTEM_EVENT_IDS = frozenset({104, 7045})
INFERENCE_PREFIX = "non-standard logsource, routed by inference to "
MAX_INFERENCE_BRANCHES = 64
MAX_INFERENCE_NODES = 4096
MAX_INFERENCE_DEPTH = 64
# Each branch maps required fields to exact values, or None for a non-exact match.
Constraints = dict[str, frozenset[str] | None]


def _positive_branches(node: Any, budget: list[int], depth: int = 0) -> list[Constraints]:
    """Bounded DNF of positive predicates; negation cannot establish a source."""
    from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionOR
    from sigma.types import SigmaExists, SigmaNull, SigmaNumber, SigmaString

    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_INFERENCE_DEPTH:
        raise ValueError("source inference condition limit")
    if isinstance(node, ConditionFieldEqualsValueExpression):
        value = node.value
        if isinstance(value, SigmaNull) or (isinstance(value, SigmaExists) and not value.exists):
            return [{}]
        exact = None
        if isinstance(value, SigmaNumber) or (isinstance(value, SigmaString) and not value.contains_special()):
            exact = frozenset({str(value).lower()})
        return [{str(node.field).lower(): exact}]
    if isinstance(node, ConditionOR):
        result = []
        for arg in node.args:
            result.extend(_positive_branches(arg, budget, depth + 1))
            if len(result) > MAX_INFERENCE_BRANCHES:
                raise ValueError("source inference branch limit")
        return result
    if isinstance(node, ConditionAND):
        result = [{}]
        for arg in node.args:
            branches = _positive_branches(arg, budget, depth + 1)
            if len(result) * len(branches) > MAX_INFERENCE_BRANCHES:
                raise ValueError("source inference branch limit")
            merged = []
            for left in result:
                for right in branches:
                    both = dict(left)
                    for key, values in right.items():
                        previous = both.get(key)
                        both[key] = values if previous is None else previous if values is None else previous & values
                    merged.append(both)
            result = merged
        return result
    return [{}]


def _branch_targets(category: str, service: str, branch: Constraints) -> dict[str, frozenset[int]] | None:
    from sigharvest.detection import windows_logsources

    table = windows_logsources()
    channels = {channel for targets in table.values() for channel, _ in targets}
    explicit = [branch[key] for key in ("channel", "winlog.channel") if key in branch]
    if explicit:
        # Wildcards, contradictory fields and unrecognized channels cannot prove a route.
        if any(not values or not values <= channels for values in explicit):
            return None
        chosen = set.intersection(*(set(values) for values in explicit if values))
        return {channel: frozenset() for channel in chosen} or None
    values = branch.get("eventid")
    if "eventid" in branch and (not values or any(not v.isdecimal() or len(v) > 8 for v in values)):
        return None
    ids = frozenset(int(v) for v in values) if values else frozenset()
    # An explicit unknown service cannot be overridden by a category alias.
    word = service or category
    if word in {"security", "authentication", "system"}:
        allowed = AUTHENTICATION_EVENT_IDS if word == "authentication" else SYSTEM_EVENT_IDS if word == "system" else SECURITY_EVENT_IDS | SYSTEM_EVENT_IDS
        if not ids or not ids <= allowed:
            return None
        # Every ID needs exactly one owner, even if future table edits overlap.
        # Different IDs may still prove different channels in the same rule.
        if ids & SECURITY_EVENT_IDS & SYSTEM_EVENT_IDS:
            return None
        return {ch: subset for ch, subset in (("security", ids & SECURITY_EVENT_IDS), ("system", ids & SYSTEM_EVENT_IDS)) if subset}
    aliases = {
        "registry": ("registry_event", "targetobject"),
        "file": ("file_event", "targetfilename"),
        "powershell": ("ps_script", "scriptblocktext"),
    }
    if word not in aliases:
        return None
    canonical, field = aliases[word]
    targets = table.get(("category", canonical), [])
    # Registry's generic category is a Sysmon bundle; never borrow Security 4657.
    if word == "registry":
        targets = [(str(WINDOWS_CHANNELS["sysmon"]).lower(), frozenset({12, 13, 14}))]
    if not targets:
        return None
    if ids:
        return {channel: ids for channel, _ in targets} if all(ids <= allowed_ids for _, allowed_ids in targets) else None
    return dict(targets) if field in branch else None


def infer_windows_route(
    product: str, category: str, service: str, detection: object, *, trees: list[Any] | None = None, raw: str | None = None
) -> list[tuple[str, frozenset[int]]] | None:
    """Infer only unmapped Windows sources, proving a route for every positive branch.

    Reviewed ambiguous services need author review and cannot be inferred.
    Explicit exact Channel selectors are authoritative. Otherwise source words and
    individually unambiguous EventIDs or characteristic fields must establish
    each branch's route; different branches may identify different channels.
    Original YAML, rule identity and existing mapped routes remain unchanged.
    """
    from sigma.exceptions import SigmaError
    from sigma.rule import SigmaDetections

    from sigharvest.detection import NON_WINDOWS_CATEGORIES, WINDOWS_PRODUCTS, logsource_targets
    from sigharvest.logsource_catalog import WINDOWS_AMBIGUOUS_SERVICES

    product, category, service = product.lower(), category.lower(), service.lower()
    if product not in WINDOWS_PRODUCTS or not (category or service) or category in NON_WINDOWS_CATEGORIES:
        return None
    if service in WINDOWS_AMBIGUOUS_SERVICES:
        return None  # A misplaced or ambiguous service needs author review, not inference.
    if logsource_targets(product, category, service) is not None:
        return None
    try:
        if trees is None:
            if raw is not None:
                # The index uses BaseLoader for text metadata; source proof needs
                # the same null/boolean/numeric types as actual evaluation.
                from sigharvest.detection import _detection_data

                if len(raw) > MAX_DETECTION_BYTES:
                    return None
                document = _detection_data(raw)
                detection = document.get("detection") if document else None
            if not isinstance(detection, dict) or len(json.dumps(detection)) > MAX_DETECTION_BYTES:
                return None
            from sigharvest import pysigma_limits

            pysigma_limits.install()
            with pysigma_limits.budget():
                trees = [c.parse() for c in SigmaDetections.from_dict(detection).parsed_condition]
        budget = [MAX_INFERENCE_NODES]
        branches = []
        for tree in trees:
            branches.extend(_positive_branches(tree, budget))
            if len(branches) > MAX_INFERENCE_BRANCHES:
                return None
        result: dict[str, frozenset[int]] = {}
        for branch in branches:
            targets = _branch_targets(category, service, branch)
            if not targets:
                return None
            for channel, ids in targets.items():
                result[channel] = (result[channel] | ids if result[channel] and ids else frozenset()) if channel in result else ids
        # An inferred alias/selector can refine an unknown constraint, but cannot
        # override another explicit, mapped category or service on the same rule.
        from sigharvest.detection import windows_logsources

        table = windows_logsources()
        for kind, name in (("category", category), ("service", service)):
            known = table.get((kind, name))
            if known is None:
                continue
            allowed = dict(known)
            narrowed = {}
            for channel, ids in result.items():
                if channel not in allowed:
                    continue
                other = allowed[channel]
                if ids and other and not (ids & other):
                    continue
                narrowed[channel] = ids & other if ids and other else ids or other
            result = narrowed
        return sorted(result.items()) or None
    except (SigmaError, yaml.YAMLError, ValueError, TypeError, AttributeError, RecursionError):
        return None


def inference_note(targets: list[tuple[str, frozenset[int]]] | None) -> str | None:
    """Stable human-readable note shared by replay, index and rule pages."""
    if targets is None:
        return None
    return INFERENCE_PREFIX + "; ".join(channel + ("/" + ",".join(map(str, sorted(ids))) if ids else "/*") for channel, ids in targets)
