"""Several values of one filter are a union, in every spelling; OR across different filters is refused, not dropped."""

import json

import pytest
import typer

from sigharvest.cli.level_option import levels
from sigharvest.index import GroupFilters, _base, parse_query
from sigharvest.query_limits import QueryFilterError


@pytest.mark.parametrize("query", ["level:high OR level:critical", "level:critical OR level:high", "level:high level:critical", "level:high,critical"])
def test_inline_level_union(query):
    text, filters = parse_query(query)
    assert text == ""
    assert sorted(filters["level"].split(",")) == ["critical", "high"]


def test_text_or_is_kept_and_cross_filter_or_is_refused():
    assert parse_query("mimikatz OR lsass level:high") == ("mimikatz OR lsass", {"level": "high"})
    with pytest.raises(QueryFilterError, match="OR between different filters"):
        parse_query("level:high OR product:linux")
    with pytest.raises(QueryFilterError, match="OR between words and a filter"):
        parse_query("level:high OR lsass")
    with pytest.raises(QueryFilterError, match=r"Run two searches: 'windash' and 'level:high'"):
        parse_query("windash OR level:high")


def test_comma_list_becomes_an_in_predicate():
    _, _, params = _base(None, GroupFilters(level="high,critical"))
    assert sorted(json.loads(params["level"])) == ["critical", "high"]
    _, _, params = _base(None, GroupFilters(level="high"))
    assert params["level"] == "high"


def test_cli_levels_repeatable_and_comma():
    assert levels(["high", "critical"]) == "high,critical"
    assert levels(["high,critical", "high"]) == "high,critical"
    assert levels(None) is None
    with pytest.raises(typer.BadParameter):
        levels(["severe"])


@pytest.mark.parametrize(
    ("query", "message"),
    [
        ("mimikatz prodct:windows", r"unknown filter prodct: \(did you mean product:\?\)"),
        ("lsass levle:high", r"unknown filter levle: \(did you mean level:\?\)"),
        ("severity:high", r"unknown filter severity: \(did you mean level:\?\)"),
        ("titel:mimikatz", r"unknown filter titel: \(did you mean title:\?\)"),
        ("level:hgh", r"'hgh' is not a level: .*\(did you mean level:high\?\)"),
        ("level:high,critcal", r"'critcal' is not a level: .*\(did you mean level:critical\?\)"),
        ("status:stabel", r"'stabel' is not a status: .*\(did you mean status:stable\?\)"),
    ],
)
def test_typo_in_an_inline_filter_is_refused_with_a_suggestion(query, message):
    """A typo must not look like an empty corpus ("no rules match"): every caller turns this into a 400 / exit 2."""
    with pytest.raises(QueryFilterError, match=message):
        parse_query(query)


@pytest.mark.parametrize(
    "query",
    ["sekurlsa::logonpasswords", r"C:\Windows\Temp", "http://example.com/x", "cmd.exe:x", "foo:bar", "title:mimikatz", "level:info", "status:deprecated,test"],
)
def test_text_with_colons_and_valid_filters_still_work(query):
    parse_query(query)


@pytest.mark.parametrize(
    ("field", "column", "stored", "value"),
    [
        ("tag", "tags", ["detection.emerging-threats"], "detection.emerging_threats"),
        ("tag", "tags", ["attack.t1059"], "attack.t1%"),
        ("flag", "quality_flags", ["autogenXtemplate"], "autogen_template"),
        ("flag", "quality_flags", ["no_level"], "%"),
        ("backend", "converts", ["splunk"], "spl_nk"),
        ("backend", "converts", ["splunk"], "%"),
    ],
)
def test_like_filters_treat_wildcards_as_literal_text(field, column, stored, value):
    """`%` and `_` in a tag, flag or backend filter match themselves, not any text or any character."""
    import sqlite3

    predicates: list[tuple[str, str]] = []
    _, _, params = _base(None, GroupFilters(**{field: value}), predicates=predicates)
    clause = dict(predicates)[field]
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE logic_groups (tags TEXT, converts TEXT, quality_flags TEXT)")
    db.execute(f"INSERT INTO logic_groups ({column}) VALUES (?)", (json.dumps(stored),))
    sql = "SELECT count(*) FROM logic_groups g WHERE " + clause.replace(f":{field}", "?")
    assert db.execute(sql, (params[field],)).fetchone()[0] == 0
    db.execute(f"UPDATE logic_groups SET {column} = ?", (json.dumps([value]),))
    assert db.execute(sql, (params[field],)).fetchone()[0] == 1
