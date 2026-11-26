"""Sysmon field capabilities for every Sysmon category: a field the event does not carry makes the Sysmon result
partial (no query), as for Security 4688/4657, instead of an `ok` query that can never match."""

import pytest

from sigharvest.conversion import SYSMON_CATEGORIES, convert
from sigharvest.datasources import SYSMON_FIELDS, limitations


def rule(category: str, *fields: str, logsource: str = "product: windows") -> str:
    lines = "\n".join(f"    {f}|contains: 'x'" for f in fields)
    return f"title: t\nlogsource: {{{logsource}, category: {category}}}\ndetection:\n  sel:\n{lines}\n  condition: sel\n"


def test_every_sysmon_category_has_a_field_table() -> None:
    assert set(SYSMON_FIELDS) == SYSMON_CATEGORIES


@pytest.mark.parametrize(
    ("category", "fields"),
    [
        ("file_event", ["TargetFilename", "Image", "User", "CreationUtcTime"]),
        ("file_change", ["TargetFilename", "PreviousCreationUtcTime"]),
        ("network_connection", ["Image", "DestinationHostname", "DestinationIp", "DestinationPort", "Initiated", "SourcePortName"]),
        (
            "image_load",
            [
                "Image",
                "ImageLoaded",
                "Hashes",
                "Signed",
                "Signature",
                "SignatureStatus",
                "Product",
                "Company",
                "Description",
                "OriginalFileName",
                "FileVersion",
                "User",
            ],
        ),
        ("driver_load", ["ImageLoaded", "Hashes", "Signed", "Signature", "SignatureStatus"]),
        ("process_access", ["SourceImage", "TargetImage", "GrantedAccess", "CallTrace", "SourceUser", "TargetUser", "SourceProcessGUID"]),
        ("create_remote_thread", ["SourceImage", "TargetImage", "StartAddress", "StartModule", "StartFunction", "SourceProcessGuid"]),
        ("dns_query", ["Image", "QueryName", "QueryStatus", "QueryResults"]),
        ("pipe_created", ["Image", "PipeName", "EventType"]),
        ("create_stream_hash", ["TargetFilename", "Hash", "Contents"]),
        ("file_delete", ["TargetFilename", "Hashes", "IsExecutable", "Archived"]),
        ("wmi_event", ["Destination", "Query", "Consumer", "Filter", "EventNamespace"]),
        ("registry_rename", ["TargetObject", "NewName"]),
        ("process_tampering", ["Image", "Type"]),
        ("sysmon_status", ["State", "SchemaVersion"]),
        ("file_event", ["EventID", "Computer", "Channel", "Provider_Name", "RuleName", "UtcTime", "EventRecordID"]),
    ],
)
def test_documented_fields_are_accepted(category: str, fields: list[str]) -> None:
    assert limitations("sysmon", category, set(fields), "splunk") == ([], [])


@pytest.mark.parametrize(
    ("category", "field"),
    [
        ("file_event", "file.path"),  # ECS
        ("file_event", "winlog.event_data.TargetFilename"),  # Winlogbeat raw
        ("file_event", "TargetFileName"),  # field names are case-sensitive in Splunk and Elastic
        ("file_event", "Hashes"),  # only file_delete and the file block events carry Hashes
        ("network_connection", "CommandLine"),  # process fields do not exist on other events
        ("network_connection", "ParentImage"),
        ("image_load", "md5"),
        ("driver_load", "Image"),
        ("process_access", "Image"),
        ("create_remote_thread", "SourceParentImage"),
        ("create_stream_hash", "Hashes"),  # event 15 has Hash
        ("dns_query", "QueryType"),
        ("registry_delete", "Details"),
    ],
)
def test_unknown_fields_make_sysmon_partial(category: str, field: str) -> None:
    valid = {"driver_load": "ImageLoaded", "process_access": "SourceImage", "create_remote_thread": "SourceImage"}.get(category, "Image")
    missing, notes = limitations("sysmon", category, {field, valid}, "splunk")
    assert missing == [field]
    assert len(notes) == 1 and field in notes[0] and category in notes[0] and "Sysmon" in notes[0]


def test_conversion_has_no_query_and_a_clear_reason() -> None:
    c = convert(rule("file_event", "Image", "file.path"), "splunk")
    assert c.status == "partial" and c.missing_fields == ["file.path"] and not c.queries and not c.combined_query
    assert c.reason == "no documented native Sysmon field in file_event (event 11): file.path"
    assert c.covered_sources == []


def test_valid_rule_still_converts() -> None:
    c = convert(rule("file_event", "Image", "TargetFilename"), "splunk")
    assert c.status == "ok" and c.covered_sources == ["sysmon"]
    assert "EventCode=11" in c.queries[0] and "TargetFilename=" in c.queries[0]


def test_event_ids_in_the_note() -> None:
    _missing, notes = limitations("sysmon", "pipe_created", {"Pipe"}, "splunk")
    assert notes == ["no documented native Sysmon field in pipe_created (events 17, 18): Pipe"]


def test_explicit_sysmon_service_is_checked_too() -> None:
    c = convert(rule("network_connection", "Image", "Application", logsource="product: windows, service: sysmon"), "splunk")
    assert c.status == "partial" and c.missing_fields == ["Application"]


def test_security_categories_keep_both_sources() -> None:
    # process_creation keeps its Security alternative: a field only Sysmon lacks still converts on 4688.
    c = convert(rule("process_creation", "Image", "NewProcessName"), "splunk")
    assert c.results[0].source == "sysmon" and c.results[0].status == "partial"
    assert c.results[0].reason == "no documented native Sysmon field in process_creation (event 1): NewProcessName"


@pytest.mark.parametrize(("source", "category"), [("sysmon", None), ("sysmon", "ps_script"), ("windows", "file_event"), ("default", "file_event")])
def test_other_sources_and_categories_are_not_checked(source: str, category: str | None) -> None:
    assert limitations(source, category, {"anything.at.all"}, "splunk") == ([], [])


def test_non_windows_rules_are_untouched() -> None:
    c = convert(rule("file_event", "file.path", logsource="product: linux"), "splunk")
    assert c.status != "partial" and not c.missing_fields
