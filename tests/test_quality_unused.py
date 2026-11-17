"""Parsed selection references, index publication and author review."""

import copy

import pytest
import yaml

from sigharvest.lint import Corpus, lint_paths
from sigharvest.quality import classify, is_junk
from sigharvest.quality_unused import FLAGS, from_raw, unused_selections
from tests.test_effective_documents import workspace as workspace_fixture

workspace = workspace_fixture


def rule(condition="selection", **selections):
    return {
        "title": "Suspicious FTP connection",
        "logsource": {"product": "windows", "category": "network_connection"},
        "level": "high",
        "detection": {"selection": {"EventID": 3}, **selections, "condition": condition},
    }


@pytest.mark.parametrize("name", ["filter", "filter_main", "excludeChrome", "fp", "fp_known", "not_browser", "FilterVendor"])
def test_filter_names_are_a_subcase(name):
    data = rule(**{name: {"Image|endswith": "chrome.exe"}})
    before = copy.deepcopy(data)
    assert unused_selections(data) == {"names": [name], "filters": [name], "suggestion": f"selection and not {name}"}
    flags = classify(data, [])
    assert set(flags) >= FLAGS and not is_junk(flags)
    assert data == before


@pytest.mark.parametrize("condition", ["1 of sel*", "all of sel*", "any of sel*", "all of them", "1 of them", ["selection", "sel_image"]])
def test_patterns_and_lists_use_union(condition):
    assert unused_selections(rule(condition, sel_image={"Image": "ftp.exe"})) == {}


def test_explicit_negation_and_nested_wildcards_count_references():
    assert unused_selections(rule("selection and not (1 of filter_*)", filter_browser={"Image": "chrome.exe"})) == {}
    assert unused_selections(rule("(selection or sel_other) and not filter", sel_other={"EventID": 1}, filter={"User": "SYSTEM"})) == {}
    assert unused_selections(rule("selection and not filter", filter={"Image": "chrome.exe"}, stale={"User": "SYSTEM"}))["names"] == ["stale"]


def test_underscore_names_follow_pysigma_wildcard_semantics():
    data = rule("all of them", _private={"Image": "ftp.exe"})
    assert unused_selections(data)["names"] == ["_private"]
    data["detection"]["condition"] = "all of them and 1 of _*"
    assert unused_selections(data) == {}


@pytest.mark.parametrize(
    "condition",
    [
        "selection | count() > 5",
        "selection AND filter",
        "selection and missing",
        "1 of missing_*",
        "selection trailing",
        "selection and",
        ["selection", "event.code == 3"],
        True,
        None,
        [],
        "(" * 33 + "selection" + ")" * 33,
    ],
)
def test_non_sigma_unresolved_or_bounded_conditions_have_no_flag(condition):
    data = rule(condition, filter={"Image": "chrome.exe"})
    assert unused_selections(data) == {}
    assert not set(classify(data, [])) & FLAGS


def test_timeframe_is_metadata_and_raw_worker_projection_agrees():
    data = rule(filter={"Enabled": True}, timeframe="5m")
    assert from_raw(yaml.safe_dump(data)) == unused_selections(data)
    assert unused_selections(rule(timeframe="5m")) == {}


def test_file_lint_names_and_display_only_suggestion(tmp_path):
    path = tmp_path / "rule.yml"
    raw = yaml.safe_dump(rule(filter={"Image": "chrome.exe"}))
    path.write_text(raw)
    findings = lint_paths([path], Corpus())
    assert any(f.rule == "quality-unused-filter" and "filter" in f.message for f in findings)
    assert any(f.rule == "condition-suggestion" and "selection and not filter" in f.message for f in findings)
    assert path.read_text() == raw


def test_analyzer_changes_invalidate_index(monkeypatch):
    from sigharvest import fingerprints, index_delta

    before = index_delta.fingerprint()
    original = fingerprints.source_digest
    monkeypatch.setattr(fingerprints, "source_digest", lambda name: "changed-unused-analysis" if name == "quality_unused.py" else original(name))
    assert index_delta.fingerprint() != before


@pytest.mark.parametrize("condition", [True, False, 123, None])
def test_index_text_loader_cannot_turn_invalid_condition_into_identifier(condition):
    from sigharvest.index_workers import prepare

    name = {True: "true", False: "false", 123: "123", None: "null"}[condition]
    data = rule(condition, **{name: {"EventID": 1}})
    raw = yaml.safe_dump(data)
    assert from_raw(raw) == {}
    assert not set(prepare([(1, raw, False, False, "rule")])[1][1]) & FLAGS


@pytest.mark.parametrize("condition", ["1 of sel_*", "all of sel_*"])
def test_exact_selection_prefix_pattern(condition):
    data = rule(condition, sel_image={"Image": "ftp.exe"})
    data["detection"]["sel_eid3"] = data["detection"].pop("selection")
    assert unused_selections(data) == {}
