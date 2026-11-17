"""Real backend conversions, source boundaries, public interfaces and independent timeout budgets."""

import time
from pathlib import Path

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

from sigharvest import conversion, testing_conversion
from sigharvest.cli import app
from sigharvest.conversion import convert, statuses_of
from sigharvest.datasources import applicable
from sigharvest.models import LogicGroup, TestResult
from tests.test_conversion import IMAGE_LOAD, SAFEBOOT, _title
from tests.test_conversion import corpus as corpus

PROCESS = r"""title: Suspicious process
logsource: {product: windows, category: process_creation}
detection:
  sel:
    Image|endswith: '\evil.exe'
    ParentImage|endswith: '\cmd.exe'
  condition: sel
"""
REGISTRY = PROCESS.replace("process_creation", "registry_set").replace("    ParentImage|endswith: '\\cmd.exe'\n", "")


@pytest.mark.parametrize("target", ["splunk", "lucene", "opensearch", "esql", "sqlite"])
def test_process_sources_and_correct_parent(target: str) -> None:
    conv = convert(PROCESS, target)
    assert conv.status == "ok" and conv.covered_sources == ["sysmon", "security"]
    sysmon, security = conv.results
    assert sysmon.source == "sysmon" and security.source == "security"
    assert security.fields == ["Image", "ParentImage"] and not security.missing_fields
    q = security.queries[0]
    assert "4688" in q and "Security" in q
    if target == "splunk":
        assert "NewProcessName=" in q and "ParentProcessName=" in q
    elif target in ("lucene", "opensearch", "esql"):
        assert "process.parent.executable.caseless" in q and "process.parent.name" not in q
    assert convert(PROCESS, target, sources=["security"]).queries == security.queries
    assert convert(PROCESS, target, variant="windows-audit").queries == security.queries


@pytest.mark.parametrize("field", ["Hashes", "OriginalFileName", "IntegrityLevel", "User", "ParentCommandLine", "CurrentDirectory", "ProcessGuid"])
def test_missing_security_fields_never_drop_conditions(field: str) -> None:
    raw = PROCESS.replace("    ParentImage|endswith:", f"    {field}|endswith:")
    c = convert(raw, "splunk")
    assert c.status == "ok" and c.covered_sources == ["sysmon"]
    r = c.results[1]
    assert r.status == "partial" and r.missing_fields == [field] and not r.queries
    assert field in (r.reason or "")
    assert c.combined_query == c.results[0].queries[0] and c.combined_sources == ["sysmon"]
    assert not convert(raw, "splunk", sources=["security"]).queries


def test_command_line_prerequisite_is_not_silent() -> None:
    c = convert(PROCESS.replace("ParentImage", "CommandLine"), "splunk")
    r = c.results[1]
    assert r.status == "partial" and "command-line auditing" in (r.reason or "")
    assert r.queries and "CommandLine=" in r.queries[0]  # diagnostic retains the condition
    assert c.combined_sources == ["sysmon"]


@pytest.mark.parametrize("target", ["splunk", "lucene", "opensearch", "esql", "sqlite"])
def test_registry_operation_and_actual_ingest_fields(target: str) -> None:
    c = convert(REGISTRY, target, sources=["security"])
    assert c.status == "ok"
    q = c.queries[0]
    assert "4657" in q and "1904" in q and "1905" in q
    assert "New registry value created" in q and "Existing registry value modified" in q
    assert "ProcessName" in q and "NewProcessName" not in q
    if target in ("lucene", "opensearch", "esql"):
        assert "winlog.event_data.ProcessName" in q and "process.executable" not in q
    partial = convert(SAFEBOOT, target, sources=["security"])
    assert partial.status == "partial" and partial.missing_fields == ["TargetObject"] and not partial.queries


@pytest.mark.parametrize("category", ["registry_add", "registry_event"])
def test_registry_value_only_coverage(category: str) -> None:
    c = convert(REGISTRY.replace("registry_set", category), "splunk", sources=["security"])
    assert c.status == "partial" and c.queries and "values only" in (c.reason or "")


def test_applicability_and_nonwindows_are_preserved() -> None:
    assert applicable("splunk", "windows", "image_load", None) == ["sysmon"]
    assert convert(IMAGE_LOAD, "splunk", sources=["security"]).status == "unsupported"
    assert convert(PROCESS.replace("category: process_creation", "category: process_creation, service: sysmon"), "splunk").covered_sources == ["sysmon"]
    linux = convert(PROCESS.replace("windows", "linux"), "splunk")
    assert linux.status == "raw" and len(linux.results) == 1 and linux.results[0].source == "default"
    for bad in ([], ["nope"], ["all", "security"]):
        with pytest.raises(ValueError):
            convert(PROCESS, "splunk", sources=bad)
    with pytest.raises(ValueError):
        convert(PROCESS, "splunk", sources=["sysmon"], variant="windows-audit")


@pytest.mark.parametrize("target", ["splunk", "lucene", "opensearch"])
@pytest.mark.parametrize("condition", ["sel and not filter", "1 of sel* and not filter"])
def test_combination_wraps_complete_branches(target: str, condition: str) -> None:
    raw = PROCESS.replace("  condition: sel", "  filter:\n    Image|endswith: '\\trusted.exe'\n  condition: " + condition)
    c = convert(raw, target)
    assert c.covered_sources == ["sysmon", "security"]
    assert c.combined_query == " OR ".join(f"({r.queries[0]})" for r in c.results)
    for r in c.results:
        assert "NOT" in r.queries[0] and "trusted.exe" in r.queries[0]
        assert r.queries == convert(raw, target, sources=[r.source]).queries


@pytest.mark.parametrize("target", ["esql", "microsoft365defender", "loki", "sqlite"])
def test_complete_programs_stay_separate(target: str) -> None:
    c = convert(PROCESS, target, sources=["combined"])
    assert c.results and c.combined_query is None and c.combined_sources == []
    assert all(r.source and r.label for r in c.results)


def test_timeout_is_per_source_and_success_survives(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    original = conversion._convert_single

    def slow(raw, target, kind, siblings, variant):  # type: ignore[no-untyped-def]
        if variant is None:
            time.sleep(1)
        return original(raw, target, kind, siblings, variant)

    # Warm imports before the very short test budget.
    convert(PROCESS, "splunk")
    monkeypatch.setattr(conversion, "_convert_single", slow)
    monkeypatch.setattr(testing_conversion, "CONVERT_TIMEOUT", 0.1)
    status, detail = testing_conversion._convert_with_timeout(PROCESS, "splunk", "rule", [])
    assert status == "ok" and detail["covered_sources"] == ["security"]
    assert [r["status"] for r in detail["results"]] == ["timeout", "ok"]
    assert detail["combined_sources"] == ["security"]


def test_storage_keeps_partial_source_and_score_credits_sysmon(corpus) -> None:  # type: ignore[no-untyped-def]
    _ws, session = corpus
    with session() as s:
        v = _title(s, "SafeBoot registry change")
        g = s.scalars(select(LogicGroup).where(LogicGroup.logic_hash == v.logic_hash)).one()
        assert g.conversion["splunk"] == {"status": "ok", "covered_sources": ["sysmon"], "sources": {"sysmon": "ok", "security": "partial"}}
        assert "splunk" in g.converts and statuses_of(g)["splunk"] == "ok"
        row = s.scalars(select(TestResult).where(TestResult.version_id == v.id, TestResult.target == "splunk")).one()
        assert row.detail["results"][1]["missing_fields"] == ["TargetObject"]


@pytest.mark.backend("esql")
def test_cli_source_alias_and_export(corpus, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    ws, _session = corpus
    rule = tmp_path / "process.yml"
    rule.write_text(PROCESS)
    runner = CliRunner()
    outputs = []
    for options in (["--telemetry", "security"], ["--telemetry", "security"], ["--variant", "windows-audit"]):
        r = runner.invoke(app, ["convert", str(rule), "-t", "splunk", *options])
        assert r.exit_code == 0, r.output
        assert "4688" in r.output and "NewProcessName" in r.output and "Sysmon" not in r.output
        outputs.append(r.output)
    assert outputs[0] == outputs[1] == outputs[2]
    combined = runner.invoke(app, ["convert", str(rule), "--telemetry", "combined"])
    assert combined.exit_code == 0 and ") OR (" in combined.output
    esql = runner.invoke(app, ["convert", str(rule), "-t", "esql", "--telemetry", "combined"])
    assert esql.exit_code == 0 and "separate queries" in esql.output and "Sysmon" in esql.output and "4688" in esql.output
    bad = runner.invoke(app, ["convert", str(rule), "--telemetry", "nope"])
    assert bad.exit_code == 2
    output = tmp_path / "export.spl"
    r = runner.invoke(app, ["export", "SafeBoot", "--format", "splunk", "--telemetry", "security", "--out", str(output)], env={"SIGHARVEST_HOME": str(ws.root)})
    assert r.exit_code == 1, r.output  # nothing exported is a failure for scripts
    assert "-> 0 written for splunk" in r.output and 'source="WinEventLog:' not in output.read_text()


@pytest.mark.backend("microsoft365defender")
@pytest.mark.parametrize("field", ["EventID", "EventCode", "ObjectType", "Channel"])
def test_mde_cannot_discard_or_invent_fields(field: str) -> None:
    raw = PROCESS.replace("    ParentImage|endswith:", f"    {field}|endswith:")
    result = convert(raw, "microsoft365defender")
    assert result.status == "partial" and not result.queries
    assert result.missing_fields == [field]


def test_boolean_query_can_contain_a_literal_pipe() -> None:
    raw = PROCESS.replace("evil.exe", "evil|exe")
    assert convert(raw, "splunk").combined_sources == ["sysmon", "security"]


def test_native_audit_fields_do_not_claim_sysmon_coverage() -> None:
    raw = PROCESS.replace("Image|endswith", "NewProcessName|endswith").replace("ParentNewProcessName", "ParentProcessName")
    result = convert(raw, "splunk")
    assert result.status == "ok" and result.covered_sources == ["security"]
    assert result.results[0].status == "partial" and "NewProcessName" in result.results[0].missing_fields
    assert result.combined_sources == ["security"]


def test_field_references_are_checked_for_capability() -> None:
    raw = PROCESS.replace("    ParentImage|endswith: '\\cmd.exe'", "    ParentImage|fieldref: OriginalFileName")
    result = convert(raw, "splunk", sources=["security"])
    assert result.status == "partial" and "OriginalFileName" in result.missing_fields


@pytest.mark.parametrize("field", ["Hashes", "User"])
@pytest.mark.parametrize("target", ["lucene", "esql", "opensearch"])
def test_ecs_does_not_query_raw_fields_removed_by_winlogbeat(field: str, target: str) -> None:
    raw = PROCESS.replace("    ParentImage|endswith:", f"    {field}|endswith:")
    result = convert(raw, target)
    assert result.status == "partial" and not result.combined_query
    assert all(field in r.missing_fields for r in result.results)
    assert "Winlogbeat" in (result.results[0].reason or "")


@pytest.mark.backend("microsoft365defender")
def test_mde_registry_set_restricts_operation_and_rejects_unequal_paths() -> None:
    c = convert(REGISTRY, "microsoft365defender")
    assert c.status == "ok" and "ActionType" in c.queries[0] and "RegistryValueSet" in c.queries[0]
    c = convert(SAFEBOOT, "microsoft365defender")
    assert c.status == "partial" and c.missing_fields == ["TargetObject"] and not c.queries
