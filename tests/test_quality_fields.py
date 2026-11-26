"""Field names from another schema on a Windows rule: foreign_field_names (quality_fields.py)."""

import pytest
import yaml

from sigharvest.quality import classify, is_junk
from sigharvest.quality_fields import detection_fields, field_flags, field_penalty

_LOADER = getattr(yaml, "CBaseLoader", yaml.BaseLoader)  # the index reads rules with BaseLoader


def _rule(detection: str, logsource: str = "{product: windows, category: process_creation}") -> dict:
    text = f"title: t\nlevel: high\nlogsource: {logsource}\ndetection:\n{detection}\n"
    return yaml.load(text, Loader=_LOADER)


FOREIGN = {
    "ECS names": "  sel: {process.name: 'vssadmin.exe', process.command_line|contains: 'delete shadows'}\n  condition: sel",
    "Wazuh names": "  sel: {data.TargetFilename|contains: '\\\\Temp\\\\x\\\\'}\n  condition: sel",
    "Winlogbeat names": "  sel: {winlog.event_data.CommandLine|contains: 'reg add'}\n  condition: sel",
    # no single event has both `data.CommandLine` and `Image`: the AND can never match
    "mixed styles": "  a: {Image|endswith: '\\\\rundll32.exe'}\n  b: {data.CommandLine|contains: 'DownloadString'}\n  condition: a and b",
    "list of maps": "  sel:\n    - {Image|endswith: '\\\\x.exe'}\n    - {file.path|contains: 'y'}\n  condition: sel",
}


@pytest.mark.parametrize("name", list(FOREIGN))
def test_dotted_windows_fields_are_flagged(name: str) -> None:
    assert field_flags(_rule(FOREIGN[name])) == ["foreign_field_names"]


def test_sysmon_as_product_counts_as_windows() -> None:
    assert field_flags(_rule(FOREIGN["Wazuh names"], "{product: sysmon, category: osquery}")) == ["foreign_field_names"]


@pytest.mark.parametrize(
    "detection,logsource",
    [
        (
            "  sel: {Image|endswith: '\\\\vssadmin.exe', CommandLine|contains: 'delete shadows'}\n  condition: sel",
            "{product: windows, category: process_creation}",
        ),
        ("  sel: {EventID: 4688, NewProcessName|endswith: '\\\\nc.exe'}\n  condition: sel", "{product: windows, service: security}"),
        ("  keywords: ['process.name', 'a.b']\n  condition: keywords", "{product: windows, service: system}"),
        # cloud audit logs use dotted names by design
        ("  sel: {eventName: CreateUser, requestParameters.userName|contains: adm}\n  condition: sel", "{product: aws, service: cloudtrail}"),
        ("  sel: {process.name: bash}\n  condition: sel", "{product: linux, category: process_creation}"),
    ],
)
def test_flat_names_and_other_products_are_not_flagged(detection: str, logsource: str) -> None:
    assert field_flags(_rule(detection, logsource)) == []


def test_classify_adds_an_informational_flag() -> None:
    flags = classify(_rule(FOREIGN["ECS names"]), ["rules/a.yml"])
    assert "foreign_field_names" in flags
    assert not is_junk(["foreign_field_names"])


def test_penalty_and_unreadable_input() -> None:
    assert field_penalty(["foreign_field_names", "ioc_list"]) == 10.0
    assert field_penalty(None) == 0.0
    assert field_flags({"detection": None, "logsource": {"product": "windows"}}) == []
    assert field_flags({"detection": {"sel": {"a.b": "x"}}, "logsource": "windows"}) == []
    assert detection_fields({"sel": [{"A|contains": "x"}, "kw"], "condition": "sel"}) == ["A"]
