"""Review unmatched trailing quote literals without rewriting detection semantics."""

from __future__ import annotations

import re
from typing import Any

import yaml

from sigharvest.quality_unused import MAX_RAW_BYTES, is_filter


def quote_artifacts(data: dict[str, Any]) -> dict[str, Any]:
    """Find parsed literals with a closing quote and no corresponding opening quote.

    This is an advisory heuristic: quotes can be intentional log content. In a
    path filter, a damaged literal cannot exclude the intended unquoted path.
    Bound traversal also handles recursive YAML aliases without recursion.
    """
    detection = data.get("detection")
    if not isinstance(detection, dict) or len(detection) > 512:
        return {}
    findings = []
    pending = [(str(name), "", value) for name, value in detection.items() if name not in {"condition", "timeframe"}]
    budget = 10000
    while pending and budget:
        name, field, value = pending.pop()
        budget -= 1
        if isinstance(value, dict):
            if len(value) > budget - len(pending):
                return {}
            pending.extend((name, str(key), item) for key, item in value.items())
        elif isinstance(value, list):
            if len(value) > budget - len(pending):
                return {}
            pending.extend((name, field, item) for item in value)
        elif isinstance(value, str) and len(value) > 2 and value[-1] in {"'", '"'} and value[-1] not in value[:-1]:
            base, *modifiers = field.casefold().split("|")
            base = base.rsplit(".", 1)[-1]
            # Command/regex suffixes deliberately match a closing argument quote.
            # Effective YAML can re-quote source literals; scalar style alone
            # cannot establish whether quotes belong in the intended log value.
            path = bool(re.match(r"^(?:[a-z]:\\|\\)", value, re.I))
            filename = base in {"image", "parentimage", "sourceimage", "targetimage", "imageloaded", "newprocessname", "targetfilename"} and bool(
                re.match(r"^[\w-]+\.[\w]+['\"]$", value)
            )
            arguments = {"commandline", "parentcommandline", "scriptblocktext", "details", "newvalue", "imagepath", "cmd_line", "command_line"}
            if "re" not in modifiers and base not in arguments and (path or filename):
                findings.append({"selection": name, "field": field, "value": value, "filter": is_filter(name)})
    if pending or not findings:
        return {}
    findings.sort(key=lambda item: (item["selection"], item["field"], item["value"]))
    return {"findings": findings, "filters": sorted({item["selection"] for item in findings if item["filter"]})}


def from_raw(raw: str) -> dict[str, Any]:
    if len(raw) > MAX_RAW_BYTES or len(raw.encode()) > MAX_RAW_BYTES:
        return {}
    try:
        data = yaml.load(raw, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))  # noqa: S506 - safe constructors
        return quote_artifacts(data) if isinstance(data, dict) else {}
    except (yaml.YAMLError, ValueError, RecursionError):
        return {}


def message(details: dict[str, Any]) -> str:
    names = sorted({item["selection"] for item in details.get("findings", [])})
    return (
        f"Unopened trailing quote in detection selections: {', '.join(names)}. "
        "Review the literal: damaged path filters cannot exclude the intended unquoted path. "
        "This is a structural warning, not measured false-positive evidence."
    )
