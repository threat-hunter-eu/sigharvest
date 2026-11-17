"""Normalised categories for search and facets: logsource, level, status and tags.

The index (`logic_groups`) stores normalised values so filters and facets are not split across spellings
("Palo Alto Networks" / "palo_alto", "attack.credential_access" / "attack.credential-access", "info" /
"informational"). The rule's own YAML is never changed; rule pages show it as published.

Tags follow the current Sigma tag specification: ATT&CK tactics with hyphens (attack.credential-access),
techniques as attack.tNNNN[.NNN], CVEs as cve.YYYY-NNNNN. ATT&CK v19 split Defense Evasion into Stealth
(TA0005) and Defense Impairment (TA0112): legacy defense_evasion tags become attack.defense-impairment when the
rule is tagged with an impairment technique (T1562, T1685), attack.stealth otherwise.
"""

from __future__ import annotations

import re

LEVELS = ("informational", "low", "medium", "high", "critical")
_LEVEL_ALIASES = {
    "info": "informational",
    "information": "informational",
    "inform": "informational",
    "meduim": "medium",
    "med": "medium",
    "moderate": "medium",
    "crit": "critical",
    "crítico": "critical",
    "critico": "critical",
    "hight": "high",
    "severe": "critical",
}
_STATUS_ALIASES = {
    "production": "stable",
    "active": "stable",
    "prod": "stable",
    "release": "stable",
    "draft": "test",
    "testing": "test",
    "tested": "test",
    "beta": "test",
    "experimental": "experimental",
    "expermintal": "experimental",
    "experiment": "experimental",
    "dev": "experimental",
    "development": "experimental",
    "stable": "stable",
    "test": "test",
    "deprecated": "deprecated",
    "unsupported": "unsupported",
    "obsolete": "deprecated",
}

_PRODUCT_ALIASES = {
    "windwos": "windows",
    "winodws": "windows",
    "window": "windows",
    "win32": "windows",
    "mac_os": "macos",
    "macosx": "macos",
    "mssql": "sqlserver",
    "postgres": "postgresql",
    "postgresql_server": "postgresql",
    "bro": "zeek",
    "google_cloud": "gcp",
    "google_cloud_platform": "gcp",
    "gcp.audit": "gcp",
    "crowdstrike_falcon": "crowdstrike",
    "carbon_black": "carbonblack",
    "palo alto networks": "paloalto",
    "palo_alto": "paloalto",
    "palo-alto": "paloalto",
    "paloalto_panos": "paloalto",
    "pan-os": "paloalto",
    "panos": "paloalto",
    "check point": "checkpoint",
    "check_point": "checkpoint",
    "azuread": "azure",
    "azure_ad": "azure",
    "entra": "azure",
    "microsoft entra": "azure",
    "entra_id": "azure",
    "microsoft365": "m365",
    "office365": "m365",
    "o365": "m365",
    "microsoft 365": "m365",
    "google workspace": "google_workspace",
    "gworkspace": "google_workspace",
    "amazon": "aws",
    "amazon web services": "aws",
    "gcp": "gcp",
    "google cloud": "gcp",
    "k8s": "kubernetes",
    "mac": "macos",
    "osx": "macos",
    "mac os": "macos",
    "win": "windows",
    "microsoft windows": "windows",
    "fortinet": "fortigate",
    "fortios": "fortigate",
    "sonic wall": "sonicwall",
}
_CATEGORY_ALIASES = {
    "process_create": "process_creation",
    "process_creatoin": "process_creation",
    "process_creationn": "process_creation",
    "network_conection": "network_connection",
    "raw_access_read": "raw_access_thread",
    "driver_loaded": "driver_load",
    "script_block_logging": "ps_script",
    "registry_value_change": "registry_set",
    "web_access": "webserver",
    "web_proxy": "proxy",
    "webproxy": "proxy",
    "file_creation": "file_event",
    "file_create": "file_event",
    "file_created": "file_event",
    "process": "process_creation",
    "process creation": "process_creation",
    "process-creation": "process_creation",
    "proc_creation": "process_creation",
    "network-connection": "network_connection",
    "network connection": "network_connection",
    "net_connection": "network_connection",
    "web_server": "webserver",
    "web server": "webserver",
    "web-server": "webserver",
    "anti_virus": "antivirus",
    "anti-virus": "antivirus",
    "dns-query": "dns_query",
    "dns query": "dns_query",
    "registry-event": "registry_event",
    "registry_change": "registry_set",
    "image-load": "image_load",
    "imageload": "image_load",
    "ps-script": "ps_script",
    "powershell_script": "ps_script",
}
_CATEGORY_NOISE = {"third_party_log", "attack_scale_variant", "generic", "any", "test", "unknown", "none", "n/a", "other", "misc"}
_SERVICE_ALIASES = {
    "cloud_trail": "cloudtrail",
    "aws_cloudtrail": "cloudtrail",
    "unified_log": "unifiedlog",
    "endpoint_security": "endpointsecurity",
    "windows_security": "security",
    "powershell/operational": "powershell",
    "microsoft-windows-powershell/operational": "powershell",
    "microsoft-windows-sysmon/operational": "sysmon",
    "azureactivity": "activitylogs",
    "activity_log": "activitylogs",
    "audit_log": "audit",
    "sign_in": "signinlogs",
    "audit_logs": "auditlogs",
    "activity_logs": "activitylogs",
    "signin_logs": "signinlogs",
    "sign_in_logs": "signinlogs",
    "task_scheduler": "taskscheduler",
    "azure.activitylogs": "activitylogs",
    "azure.signinlogs": "signinlogs",
    "azure.auditlogs": "auditlogs",
    "power_shell": "powershell",
    "power-shell": "powershell",
    "windows defender": "windefend",
    "defender": "windefend",
}
_TACTICS = {
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "stealth",
    "defense-impairment",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
}
_TACTIC_IDS = {
    "ta0043": "reconnaissance",
    "ta0042": "resource-development",
    "ta0001": "initial-access",
    "ta0002": "execution",
    "ta0003": "persistence",
    "ta0004": "privilege-escalation",
    "ta0005": "stealth",
    "ta0112": "defense-impairment",
    "ta0006": "credential-access",
    "ta0007": "discovery",
    "ta0008": "lateral-movement",
    "ta0009": "collection",
    "ta0011": "command-and-control",
    "ta0010": "exfiltration",
    "ta0040": "impact",
}
_SQUASHED = {t.replace("-", ""): t for t in _TACTICS} | {"defenseevasion": "defense-evasion"}
_TECH = re.compile(r"^(?:attack\.|mitre\.|mitre-attack\.|att&ck\.)?t(\d{4})(?:[._\-/](\d{3}))?$")
_CVE = re.compile(r"^cve[._-](\d{4})[._-](\d{4,7})$")
_IMPAIRMENT = ("attack.t1562", "attack.t1685")


def _clean(value: object) -> str | None:
    text = str(value).strip().lower() if value is not None else ""
    return text or None


def level(value: object) -> str | None:
    v = _clean(value)
    if v is None:
        return None
    v = _LEVEL_ALIASES.get(v, v)
    return v if v in LEVELS else None


def status(value: object) -> str | None:
    v = _clean(value)
    return _STATUS_ALIASES.get(v) if v else None


def product(value: object) -> str | None:
    v = _clean(value)
    if v is None:
        return None
    v = re.sub(r"\s+", " ", v)
    return _PRODUCT_ALIASES.get(v, v)


def category(value: object) -> str | None:
    v = _clean(value)
    if v is None:
        return None
    v = v.split(",")[0].strip().strip("[]'\" ")  # "endpoint, network" -> endpoint
    v = _CATEGORY_ALIASES.get(v, v)
    return None if not v or v in _CATEGORY_NOISE else v  # "," or "[]" leave nothing: no category


def service(value: object) -> str | None:
    v = _clean(value)
    return _SERVICE_ALIASES.get(v, v) if v else None


def logsource(p: object, c: object, s: object) -> tuple[str | None, str | None, str | None]:
    """Normalised (product, category, service). `product: sysmon` means Windows with the sysmon service."""
    np, nc, ns = product(p), category(c), service(s)
    if np == "gcp" and _clean(p) == "gcp.audit" and ns is None:
        ns = "gcp.audit"
    if np is None and ns == "cloudtrail":
        np = "aws"
    if np is None and _clean(s) in {"azure.activitylogs", "azure.signinlogs", "azure.auditlogs"}:
        np = "azure"
    if np == "windows" and ns is None and nc in {"security", "system", "application", "sysmon"}:
        nc, ns = None, nc
    if np == "windows" and nc is None and ns == "process_creation":
        nc, ns = ns, None
    if np == "macos" and nc is None and ns in {"process", "process_creation"}:
        nc, ns = "process_creation", None
    if np == "linux" and ns == "linux_syslog":
        ns = "syslog"
    if np == "linux" and ns == "linux_secure":
        ns = "auth"
    if np == "sysmon":
        np, ns = "windows", ns or "sysmon"
    if (
        nc
        and nc
        in {
            "process_creation",
            "network_connection",
            "file_event",
            "dns_query",
            "image_load",
            "registry_set",
            "registry_event",
            "registry_add",
            "registry_delete",
            "ps_script",
            "ps_module",
            "process_access",
            "pipe_created",
            "driver_load",
        }
        and np is None
    ):
        np = "windows" if nc.startswith(("ps_", "registry", "pipe", "driver", "image")) else None
    return np, nc, ns


def tag(value: object) -> str | None:
    v = _clean(value)
    if v is None:
        return None
    v = v.replace(" ", "")
    m = _TECH.match(v)
    if m:
        return f"attack.t{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")
    m = _CVE.match(v)
    if m:
        return f"cve.{m.group(1)}-{m.group(2)}"
    if v.startswith("attack."):
        from sigharvest.attack import normalise_technique

        identity = normalise_technique(v)
        if identity.domain == "internal":
            return identity.label
        name = v[7:].replace("_", "-")
        if name in _TACTIC_IDS:
            return "attack." + _TACTIC_IDS[name]
        name = _SQUASHED.get(name.replace("-", ""), name)
        return "attack." + name if name else None
    return v


def tags(values: list[object] | None) -> list[str]:
    out: list[str] = []
    for raw in values or []:
        t = tag(raw)
        if t and t not in out:
            out.append(t)
    if "attack.defense-evasion" in out:
        impairment = any(t.startswith(_IMPAIRMENT) for t in out)
        new = "attack.defense-impairment" if impairment else "attack.stealth"
        out = [new if t == "attack.defense-evasion" else t for t in out]
        out = list(dict.fromkeys(out))
    return out
