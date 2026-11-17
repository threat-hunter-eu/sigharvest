"""Sigma detection helpers shared by validation, conversion, semantic hashing and quality checks.

`detection_only` keeps only what matching needs (title, logsource, detection), so broken metadata does not hide a
valid detection. `windows_logsources`/`logsource_targets` map Sigma Windows logsources to event log channels.
"""

from __future__ import annotations

import functools
from typing import Any

import yaml

LogsourceTargets = list[tuple[str, frozenset[int]]]  # (channel, event ids; empty = any event of the channel)

# Supplements to installed pySigma tables (Windows event channels and providers).
WINDOWS_SERVICE_CHANNELS = {
    "setup": "Setup",
    "msexchange": "MSExchange Management",
    "audit-cve": "Application",
    "smbclient-connectivity": "Microsoft-Windows-SMBClient/Connectivity",
    "iis-configuration": "Microsoft-IIS-Configuration/Operational",
    "terminalservices-remoteconnectionmanager": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
}


@functools.cache
def windows_logsources() -> dict[tuple[str, str], LogsourceTargets]:
    """(channel, event ids) per Sigma logsource (('category'|'service', name)), built from pySigma's own tables:
    sysmon (categories -> Sysmon event ids), windows-logsources (services -> channels, PowerShell categories) and
    windows-audit (process_creation -> Security 4688, registry_* -> Security 4657)."""
    from importlib import import_module

    from sigharvest.logsource_catalog import WINDOWS_SERVICE_ALIASES

    common = import_module("sigma.pipelines.common")
    sysmon = import_module("sigma.pipelines.sysmon.sysmon")
    windows = import_module("sigma.pipelines.windows.windows")
    services: dict[str, Any] = dict(common.windows_logsource_mapping)
    for name, channel in WINDOWS_SERVICE_CHANNELS.items():
        services.setdefault(name, channel)
    for alias, canonical in WINDOWS_SERVICE_ALIASES.items():
        services[alias] = services[canonical]
    sysmon_ids: dict[str, Any] = dict(sysmon.sysmon_generic_logsource_eventid_mapping)
    ps_categories: dict[str, Any] = dict(windows.windows_generic_category_channel_mapping)
    audit: dict[str, Any] = dict(windows.generic_logsource_to_windows_audit_event_mapping)

    def _channels(source: Any) -> list[str]:
        return [c.lower() for c in ([source] if isinstance(source, str) else source)]

    def _ids(x: Any) -> frozenset[int]:
        return frozenset(int(i) for i in (x if isinstance(x, list) else [x]))

    out: dict[tuple[str, str], LogsourceTargets] = {}
    sysmon_channel = _channels(services["sysmon"])[0]
    for cat, ids in sysmon_ids.items():
        out.setdefault(("category", cat), []).append((sysmon_channel, _ids(ids)))
    for cat, info in ps_categories.items():
        for ch in _channels(services[info["service"]]):
            out.setdefault(("category", cat), []).append((ch, _ids(info["EventID"])))
    security = _channels(services["security"])[0]
    for cat, cond in audit.items():
        # OperationType is checked by _logsource_filter for both raw message IDs and rendered text.
        out.setdefault(("category", cat), []).append((security, _ids(cond["EventID"])))
    for service, source in services.items():
        out[("service", service)] = [(ch, frozenset()) for ch in _channels(source)]
    return out


# Logsources that never come from a Windows event log channel, even with product windows.
NON_WINDOWS_CATEGORIES = frozenset({"proxy", "webserver", "firewall", "dns"})

# Products seen in the corpus that mean "no particular product", or Windows under another name.
GENERIC_PRODUCTS = frozenset({"any", "all", "generic", "*"})

WINDOWS_PRODUCTS = frozenset({"windows", "sysmon", "windows_defender"})


def logsource_targets(product: str, category: str, service: str) -> LogsourceTargets | None:
    """Windows channel/ID targets shared by event routing and sample exposure.

    None means no mapped target; an empty list means contradictory mapped sources.
    This describes telemetry presence, not fields or Security registry operations.
    """
    if product.lower() not in WINDOWS_PRODUCTS:
        return None
    table = windows_logsources()
    category, service = category.lower(), service.lower()
    # Every explicit constraint must be understood. A known category must not
    # erase an unknown service, nor may a known service erase an unknown category.
    if category in NON_WINDOWS_CATEGORIES:
        return []
    if (category and ("category", category) not in table) or (service and ("service", service) not in table):
        return None
    targets = table.get(("category", category)) or table.get(("service", service))
    if targets is not None and ("service", service.lower()) in table:
        channels = {ch for ch, _ in table[("service", service.lower())]}
        return [(ch, ids) for ch, ids in targets if ch in channels]
    return targets


BROAD_MIN = 20


def _stringify_modified(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return [_stringify_modified(v) for v in value]
    return value


_NON_STRING_MODIFIERS = {"lt", "lte", "gt", "gte", "exists", "cidr", "fieldref", "minute", "hour", "day", "week", "month", "year"}


def _clean_search(search: Any) -> Any:
    """Numbers under string modifiers become strings (pySigma crashes on e.g. `|windash` with an int)."""
    if isinstance(search, dict):
        out = {}
        for k, v in search.items():
            mods = {m.strip().lower() for m in str(k).split("|")[1:]}
            out[k] = _stringify_modified(v) if mods and not mods & _NON_STRING_MODIFIERS else v
        return out
    if isinstance(search, list):
        return [_clean_search(x) for x in search]
    return search


def _detection_data(raw: str | dict[str, Any]) -> dict[str, Any] | None:
    """Keep only what matching needs (title, logsource, detection), so broken metadata (invalid id, tags, dates,
    level, status) does not stop a rule from being evaluated. Condition keywords are lower-cased.

    Internal callers may supply an already admitted, locally owned document.
    The ordinary compilation entry point still accepts and parses original YAML.
    """
    from sigharvest.documents import FastSigmaSafeLoader, SigmaSafeLoader
    from sigharvest.identity import canonical_condition

    if isinstance(raw, dict):
        data = raw
    else:
        try:
            data = yaml.load(raw, Loader=FastSigmaSafeLoader)  # noqa: S506 - SafeLoader subclass
        except yaml.YAMLError:
            data = yaml.load(raw, Loader=SigmaSafeLoader)  # noqa: S506 - preserve Python parser diagnostics
    if not isinstance(data, dict) or not isinstance(data.get("detection"), dict):
        return None
    det = {k: (canonical_condition(v) if k == "condition" else _clean_search(v)) for k, v in data["detection"].items()}
    ls_raw = data.get("logsource")
    logsource: dict[str, Any] = ls_raw if isinstance(ls_raw, dict) else {}
    clean = {
        "title": str(data.get("title") or "untitled"),
        "logsource": {k: str(v) for k, v in logsource.items() if v is not None and k in ("product", "category", "service")},
        "detection": det,
    }
    if isinstance(data.get("level"), str) and data["level"].lower() in ("informational", "low", "medium", "high", "critical"):
        clean["level"] = data["level"].lower()
    return clean


def detection_only(raw: str) -> str:
    """Compatibility YAML representation of the metadata-independent detection."""
    clean = _detection_data(raw)
    return raw if clean is None else yaml.safe_dump(clean, sort_keys=False, allow_unicode=True)
