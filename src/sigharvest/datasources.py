"""Data-source capabilities, separate from repository sources and backend syntax.

Security capabilities are intentionally conservative: absent/unequal fields cannot be
made equivalent by renaming them. See docs/concepts.md for ingestion prerequisites.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class DataSource:
    name: str
    label: str
    description: str


SOURCES = {
    s.name: s
    for s in (
        DataSource("sysmon", "Sysmon", "28 Windows categories; native Sysmon fields or Winlogbeat ECS"),
        DataSource("security", "Windows Security", "4688 process creation; 4657 audited registry values; native or Winlogbeat ECS"),
        DataSource("mde", "Microsoft Defender", "DeviceProcessEvents, DeviceImageLoadEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceNetworkEvents"),
        DataSource("windows", "Windows event log", "Explicit Windows channels and PowerShell events"),
        DataSource("default", "Default", "Existing non-Windows mapping, or syntax-only conversion"),
    )
}
SECURITY_CATEGORIES = frozenset({"process_creation", "registry_event", "registry_set", "registry_add"})
SECURITY_BACKENDS = frozenset({"splunk", "lucene", "esql", "opensearch", "sqlite"})
BOOLEAN_BACKENDS = frozenset({"splunk", "lucene", "opensearch"})
# The <System> part of every Windows event, plus RuleName and UtcTime, which every Sysmon event carries.
SYSMON_COMMON = frozenset(
    {
        "EventID",
        "Channel",
        "Provider_Name",
        "Computer",
        "ComputerName",
        "Level",
        "Task",
        "Opcode",
        "Keywords",
        "EventRecordID",
        "Version",
        "RuleName",
        "UtcTime",
    }
)
SYSMON_PROCESS = SYSMON_COMMON | frozenset(
    {
        "ProcessGuid",
        "ProcessId",
        "Image",
        "FileVersion",
        "Description",
        "Product",
        "Company",
        "OriginalFileName",
        "CommandLine",
        "CurrentDirectory",
        "User",
        "LogonGuid",
        "LogonId",
        "TerminalSessionId",
        "IntegrityLevel",
        "Hashes",
        "ParentProcessGuid",
        "ParentProcessId",
        "ParentImage",
        "ParentCommandLine",
        "ParentUser",
    }
)
SYSMON_REGISTRY = SYSMON_COMMON | frozenset({"EventType", "ProcessGuid", "ProcessId", "Image", "User", "TargetObject"})
_PROCESS_REF = frozenset({"ProcessGuid", "ProcessId", "Image", "User"})
_FILE = _PROCESS_REF | frozenset({"TargetFilename", "Hashes"})
_PE_INFO = frozenset({"FileVersion", "Description", "Product", "Company", "OriginalFileName"})
_SIGNATURE = frozenset({"Hashes", "Signed", "Signature", "SignatureStatus"})
# <EventData> fields of each Sysmon event (Sysmon 15 schema, `sysmon -s`), per generic Sigma category, with the event
# ids pysigma-pipeline-sysmon maps the category to. A field outside this table is absent from the event: a query that
# tests it can never match, so the Sysmon result is `partial` without a query (as for Security 4688/4657).
SYSMON_FIELDS: dict[str, frozenset[str]] = {
    "process_creation": SYSMON_PROCESS,  # 1
    "file_change": SYSMON_COMMON | _PROCESS_REF | {"TargetFilename", "CreationUtcTime", "PreviousCreationUtcTime"},  # 2
    "network_connection": SYSMON_COMMON  # 3
    | _PROCESS_REF
    | {
        "Protocol",
        "Initiated",
        "SourceIsIpv6",
        "SourceIp",
        "SourceHostname",
        "SourcePort",
        "SourcePortName",
        "DestinationIsIpv6",
        "DestinationIp",
        "DestinationHostname",
        "DestinationPort",
        "DestinationPortName",
    },
    "sysmon_status": SYSMON_COMMON | {"State", "Version", "SchemaVersion", "Configuration", "ConfigurationFileHash"},  # 4, 16
    "process_termination": SYSMON_COMMON | _PROCESS_REF,  # 5
    "driver_load": SYSMON_COMMON | _SIGNATURE | {"ImageLoaded"},  # 6
    "image_load": SYSMON_COMMON | _PROCESS_REF | _PE_INFO | _SIGNATURE | {"ImageLoaded"},  # 7
    "create_remote_thread": SYSMON_COMMON  # 8 (event 8 spells Guid, event 10 GUID: accept both)
    | {
        "SourceProcessGuid",
        "SourceProcessGUID",
        "SourceProcessId",
        "SourceImage",
        "TargetProcessGuid",
        "TargetProcessGUID",
        "TargetProcessId",
        "TargetImage",
        "NewThreadId",
        "StartAddress",
        "StartModule",
        "StartFunction",
        "SourceUser",
        "TargetUser",
    },
    "raw_access_thread": SYSMON_COMMON | _PROCESS_REF | {"Device"},  # 9
    "process_access": SYSMON_COMMON  # 10
    | {
        "SourceProcessGUID",
        "SourceProcessGuid",
        "SourceProcessId",
        "SourceThreadId",
        "SourceImage",
        "TargetProcessGUID",
        "TargetProcessGuid",
        "TargetProcessId",
        "TargetImage",
        "GrantedAccess",
        "CallTrace",
        "SourceUser",
        "TargetUser",
    },
    "file_event": SYSMON_COMMON | _PROCESS_REF | {"TargetFilename", "CreationUtcTime"},  # 11
    "registry_add": SYSMON_REGISTRY,  # 12
    "registry_delete": SYSMON_REGISTRY,  # 12
    "registry_set": SYSMON_REGISTRY | {"Details"},  # 13
    "registry_rename": SYSMON_REGISTRY | {"NewName"},  # 14
    "registry_event": SYSMON_REGISTRY | {"Details", "NewName"},  # 12, 13, 14
    "create_stream_hash": SYSMON_COMMON | _PROCESS_REF | {"TargetFilename", "CreationUtcTime", "Hash", "Contents"},  # 15: Hash
    "pipe_created": SYSMON_COMMON | _PROCESS_REF | {"EventType", "PipeName"},  # 17, 18
    "wmi_event": SYSMON_COMMON  # 19, 20, 21
    | {"EventType", "Operation", "User", "EventNamespace", "Name", "Query", "Type", "Destination", "Consumer", "Filter"},
    "dns_query": SYSMON_COMMON | _PROCESS_REF | {"QueryName", "QueryStatus", "QueryResults"},  # 22
    "file_delete": SYSMON_COMMON | _FILE | {"IsExecutable", "Archived"},  # 23
    "clipboard_capture": SYSMON_COMMON | _PROCESS_REF | {"Session", "ClientInfo", "Hashes", "Archived"},  # 24
    "process_tampering": SYSMON_COMMON | _PROCESS_REF | {"Type"},  # 25
    "file_delete_detected": SYSMON_COMMON | _FILE | {"IsExecutable"},  # 26
    "file_block_executable": SYSMON_COMMON | _FILE,  # 27
    "file_block_shredding": SYSMON_COMMON | _FILE | {"IsExecutable"},  # 28
    "file_executable_detected": SYSMON_COMMON | _FILE,  # 29
    "sysmon_error": SYSMON_COMMON | {"ID", "Description"},  # 255
}
# Native fields may also be used in a generic category. Sigma equivalents are listed explicitly.
SECURITY_COMMON = frozenset(
    {
        "EventID",
        "Channel",
        "Provider_Name",
        "Computer",
        "ComputerName",
        "SubjectUserSid",
        "SubjectUserName",
        "SubjectDomainName",
        "SubjectLogonId",
        "LogonId",
    }
)
SECURITY_PROCESS = SECURITY_COMMON | frozenset(
    {
        "Image",
        "ParentImage",
        "CommandLine",
        "NewProcessName",
        "ParentProcessName",
        "NewProcessId",
        "ProcessId",
        "TokenElevationType",
        "TargetUserSid",
        "TargetUserName",
        "TargetDomainName",
        "TargetLogonId",
        "MandatoryLabel",
    }
)
SECURITY_REGISTRY = SECURITY_COMMON | frozenset(
    {
        "Image",
        "ProcessName",
        "ObjectName",
        "ObjectValueName",
        "OperationType",
        "OldValue",
        "NewValue",
        "OldValueType",
        "NewValueType",
        "HandleId",
        "ProcessId",
    }
)
OPERATIONS = {
    "registry_add": ["%%1904", "New registry value created"],
    "registry_set": ["%%1904", "New registry value created", "%%1905", "Existing registry value modified"],
    "registry_event": ["%%1904", "New registry value created", "%%1905", "Existing registry value modified", "%%1906", "Registry value deleted"],
}


def applicable(target: str, product: str | None, category: str | None, service: str | None) -> list[str]:
    from sigharvest.conversion import SYSMON_CATEGORIES

    if target == "microsoft365defender":
        return ["mde"]
    if product != "windows":
        return ["default"]
    # Explicit channels constrain a rule; do not silently convert it for a different channel.
    if service == "security":
        return ["security"] if target in SECURITY_BACKENDS else ["default"]
    if service == "sysmon":
        return ["sysmon"]
    if service:
        return ["windows"]
    result = ["sysmon"] if category in SYSMON_CATEGORIES else ["windows"]
    if category in SECURITY_CATEGORIES and target in SECURITY_BACKENDS:
        result.append("security")
    return result


def select_sources(available: Sequence[str], requested: Sequence[str] | None) -> list[str]:
    if requested is None or list(requested) in (["all"], ["combined"]):
        return list(available)
    if not requested or any(s not in SOURCES for s in requested):
        raise ValueError(f"source must be all, combined or one of {', '.join(SOURCES)}")
    return list(dict.fromkeys(requested))


def _sysmon_event(category: str) -> str:
    """'file_event (event 11)': the category and the Sysmon event ids the sysmon pipeline adds for it."""
    from sigma.pipelines.sysmon.sysmon import sysmon_generic_logsource_eventid_mapping

    mapped = sysmon_generic_logsource_eventid_mapping.get(category)
    if mapped is None:
        return category
    ids = mapped if isinstance(mapped, list) else [mapped]
    return f"{category} (event{'s' if len(ids) > 1 else ''} {', '.join(map(str, ids))})"


def limitations(source: str, category: str | None, fields: set[str], target: str | None = None) -> tuple[list[str], list[str]]:
    """Missing equivalents and prerequisites. Never remove these fields from a detection."""
    if source == "sysmon" and category in SYSMON_FIELDS:
        missing = sorted(fields - SYSMON_FIELDS[category])
        notes = [f"no documented native Sysmon field in {_sysmon_event(category)}: " + ", ".join(missing)] if missing else []
        if target in ("lucene", "esql", "opensearch") and category in SECURITY_CATEGORIES:
            # Winlogbeat removes these raw fields. ecs_windows does not implement equivalent compound mappings.
            unmapped = fields & {"Hashes", "Details", "User"}
            if unmapped:
                missing = sorted(set(missing) | unmapped)
                notes.append("ecs_windows lacks an equivalent Winlogbeat mapping for " + ", ".join(sorted(unmapped)))
        return missing, notes
    if source != "security" or category not in SECURITY_CATEGORIES:
        return [], []
    supported = SECURITY_PROCESS if category == "process_creation" else SECURITY_REGISTRY
    missing = sorted(fields - supported)
    notes = []
    if missing:
        notes.append("no equivalent Security field: " + ", ".join(missing))
    if "TargetObject" in missing:
        notes.append("TargetObject combines key and value; 4657 splits ObjectName/ObjectValueName and uses native registry roots")
    if "Details" in missing:
        notes.append("Details and NewValue have different type/rendering semantics")
    if "ProcessId" in fields:
        missing = sorted(set(missing) | {"ProcessId"})
        notes.append("ProcessId needs event-specific field mapping and hexadecimal/decimal normalization")
    if category == "process_creation":
        # ProcessId in Sigma is the new process, but native Security ProcessId is its parent.
        if "CommandLine" in fields:
            notes.append("CommandLine needs command-line auditing (4688 version 1 or later)")
        if "ParentImage" in fields or "ParentProcessName" in fields:
            notes.append("ParentImage needs 4688 version 2 (Windows 10 / Server 2016 or later)")
    else:
        notes.append("4657 needs Audit Registry and Set Value auditing in the key SACL")
        if category != "registry_set":
            notes.append("4657 covers registry values only; key creation/deletion and renames are not covered")
    return missing, notes


def datasource_key(value: str) -> str:
    """Stable, case-insensitive facet key; accept the display spelling 'Sysmon EventID 1'."""
    return " ".join(value.lower().replace("eventid", "").split())


def rule_datasources(product: str | None, category: str | None, service: str | None, detection: object = None) -> list[str]:
    """Candidate telemetry for a logsource, not a guarantee of field coverage or conversion.

    Explicit services constrain alternatives. Event IDs are reported only from positive
    selectors referenced by a simple condition; complex conditions retain a channel label.
    This shared mapping can also be used by telemetry inventory and prerequisites views.
    """
    import re

    from sigma.pipelines.sysmon.sysmon import sysmon_generic_logsource_eventid_mapping

    from sigharvest.logsource_catalog import WINDOWS_CHANNELS, collection_route
    from sigharvest.logsource_inference import infer_service
    from sigharvest.normalize import logsource

    product, category, service = logsource(product, category, service)
    if service is None and category is None and isinstance(detection, dict):
        service = infer_service(product, detection)
    event_ids: set[str] = set()
    if isinstance(detection, dict):
        condition = detection.get("condition")
        if isinstance(condition, str) and re.fullmatch(r"[\w]+", condition):
            selection = detection.get(condition)
            if isinstance(selection, dict):
                values = selection.get("EventID", [])
                for value in values if isinstance(values, list) else [values]:
                    if re.fullmatch(r"\d{1,5}", str(value)):
                        event_ids.add(str(int(value)))
    if product == "windows":
        if service:
            if service not in WINDOWS_CHANNELS:
                return []
            label = {"sysmon": "Sysmon", "security": "Security", "powershell": "PowerShell", "powershell-classic": "PowerShell Classic"}.get(service, service)
            if event_ids:
                return sorted(f"{label} {eid}" for eid in event_ids)
            if service == "sysmon" and category in sysmon_generic_logsource_eventid_mapping:
                ids = sysmon_generic_logsource_eventid_mapping[category]
                return sorted(f"Sysmon {eid}" for eid in (ids if isinstance(ids, list) else [ids]))
            if service == "security" and category in SECURITY_CATEGORIES:
                return ["Security 4688" if category == "process_creation" else "Security 4657"]
            if service == "powershell" and category in {"ps_script", "ps_module"}:
                return [f"PowerShell {4104 if category == 'ps_script' else 4103}"]
            return [label]
        if category in {"ps_script", "ps_module", "ps_classic_start", "ps_classic_provider_start", "ps_classic_script"}:
            return [
                {
                    "ps_script": "PowerShell 4104",
                    "ps_module": "PowerShell 4103",
                    "ps_classic_start": "PowerShell Classic 400",
                    "ps_classic_provider_start": "PowerShell Classic 600",
                    "ps_classic_script": "PowerShell Classic 800",
                }[category]
            ]
        ids = sysmon_generic_logsource_eventid_mapping.get(category or "", [])
        result = [f"Sysmon {eid}" for eid in (ids if isinstance(ids, list) else [ids])]
        if category in SECURITY_CATEGORIES:
            result.append("Security 4688" if category == "process_creation" else "Security 4657")
        return sorted(result)
    route = collection_route(product, category, service)
    if route:
        # Retain the established facet spelling for these common sources.
        return [{"aws:cloudtrail": "CloudTrail", "linux:auditd": "auditd"}.get(route.key, route.label)]
    return []
