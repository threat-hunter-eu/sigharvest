"""The plain-language rule summary and the "You need" telemetry table (sigharvest.summary)."""

from __future__ import annotations

import pytest

from sigharvest.summary import Summary, needs, summarise


def text_of(summary: Summary) -> str:
    return "".join(f"`{t}`" if k == "code" else t for k, t in summary.parts)


RULE = """title: t
description: Author text.
logsource: {product: windows, category: %s}
detection:
%s
"""


def summary(category: str, detection: str) -> str:
    return text_of(summarise(RULE % (category, detection)))


def test_one_selection() -> None:
    text = summary("process_creation", "  sel:\n    Image|endswith: '\\certutil.exe'\n    CommandLine|contains: urlcache\n  condition: sel")
    assert text == "Alerts on process creation events where Image ends with `\\certutil.exe` and CommandLine contains `urlcache`."


def test_any_of_and_all_values() -> None:
    det = (
        "  selection_1:\n    ScriptBlockText|contains|all: [DumpCreds, DumpCerts]\n"
        "  selection_2:\n    ScriptBlockText|contains: 'sekurlsa::logonpasswords'\n  condition: 1 of selection*"
    )
    text = summary("ps_script", det)
    assert text.startswith("Alerts on PowerShell script block events where ScriptBlockText contains `DumpCreds` and `DumpCerts`; or ")
    assert text.endswith("Any one of the two is enough.")


def test_filters_become_unless() -> None:
    det = "  sel:\n    Image|endswith: a.exe\n  filter:\n    User: SYSTEM\n  condition: sel and not filter"
    assert summary("process_creation", det).endswith("Image ends with `a.exe`, unless User is `SYSTEM`.")


def test_many_values_are_counted() -> None:
    det = "  sel:\n    CommandLine|contains: [a1, a2, a3, a4, a5, a6, a7, a8]\n  condition: sel"
    assert "(or 2 more)" in summary("process_creation", det)


@pytest.mark.parametrize(
    "detection",
    [
        "  s1: {a: 1}\n  s2: {b: 1}\n  s3: {c: 1}\n  s4: {d: 1}\n  s5: {e: 1}\n  condition: 1 of s*",
        "  s1: {a: 1}\n  s2: {b: 1}\n  s3: {c: 1}\n  condition: (s1 or s2) and s3",
        "  s1: {a: 1}\n  condition: s1 | count() > 5",
    ],
)
def test_complex_detections_use_the_author_description(detection: str) -> None:
    result = summarise(RULE % ("process_creation", detection))
    assert result.kind == "author" and text_of(result) == "Author text."


def test_crafted_condition_is_bounded_before_the_tree_is_built(monkeypatch: pytest.MonkeyPatch) -> None:
    """Many selections and many `1 of x*` atoms: the parser stops early instead of matching every name per atom."""
    import fnmatch

    from sigharvest import summary as module

    calls = 0
    real = fnmatch.fnmatchcase

    def counting(name: str, pattern: str) -> bool:
        nonlocal calls
        calls += 1
        return real(name, pattern)

    monkeypatch.setattr(module.fnmatch, "fnmatchcase", counting)
    selections = "".join(f"  a{i}: x\n" for i in range(2000))
    condition = " or ".join(["1 of a*"] * 100)
    result = summarise(RULE % ("process_creation", f"{selections}  condition: {condition}"))
    assert result.kind == "author" and result.reason == "condition too long"
    assert calls < 1000


def test_too_many_tokens_use_the_author_description() -> None:
    condition = " or ".join(["s1"] * 200)
    result = summarise(RULE % ("process_creation", f"  s1: {{a: 1}}\n  condition: {condition}"))
    assert result.kind == "author" and result.reason == "condition too long"


def test_many_exclusion_filters_are_still_counted() -> None:
    filters = "".join(f"  filter_{i}: {{User: u{i}}}\n" for i in range(40))
    det = f"  sel:\n    Image|endswith: a.exe\n{filters}  condition: sel and not 1 of filter_*"
    assert summary("process_creation", det).endswith("unless one of 40 exclusion filters matches.")


def test_summary_is_deterministic_and_parts_are_plain_text() -> None:
    raw = RULE % ("process_creation", "  sel:\n    CommandLine|contains: '<script>'\n  condition: sel")
    assert summarise(raw) == summarise(raw)
    assert ("code", "<script>") in summarise(raw).parts  # escaped by the template, never markup here


def test_needs_table() -> None:
    assert needs("windows", "ps_script", None) == ("PowerShell Script Block Logging (event 4104)", True)
    assert needs("aws", None, "cloudtrail")[0].startswith("AWS CloudTrail")
    assert needs(None, "proxy", None)[0] == "web proxy access logs"
    assert needs("acme", "widget", None) == ("Logs that match logsource: acme / widget", False)
