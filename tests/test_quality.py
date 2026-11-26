"""Quality flags: junk detection by content and paths."""

import copy
import random
import re
import time

import pytest

from sigharvest.quality import classify, is_junk

DET = {"selection": {"Image|endswith": "\\\\x.exe"}, "condition": "selection"}


def _rule(**kw: object) -> dict[str, object]:
    base: dict[str, object] = {"title": "Suspicious X", "logsource": {"product": "windows", "category": "process_creation"}, "detection": DET}
    base.update(kw)
    return base


def test_clean_rule_has_no_flags() -> None:
    assert classify(_rule(), ["rules/windows/x.yml"]) == []


def test_junk_kinds() -> None:
    assert "foreign_query" in classify(_rule(detection={"splunk_spl": "index=* | stats count", "condition": "x"}), [])
    assert "synthetic" in classify(_rule(title="WMI Process Creation Scale Variant 3480 Marker"), [])
    assert "test_fixture" in classify(_rule(), ["tests/fixtures/golden/a.yml", "examples/a.yml"])
    assert "test_fixture" not in classify(_rule(), ["tests/a.yml", "rules/a.yml"])
    assert "test_fixture" in classify(_rule(title="[TEST] my rule"), [])
    assert "autogen_stub" in classify(_rule(description="Auto-generated stub for T1059"), [])
    assert "template_title" in classify(_rule(title="AWS $(aws.eventSource) change"), [])
    assert "match_all" in classify(_rule(detection={"s": {"Image": "*"}, "condition": "s"}), [])
    assert "upstream_deprecated" in classify(_rule(), [], upstream_deprecated=True)
    assert is_junk(["synthetic"]) and not is_junk(["ioc_list", "broad_logsource"])


def test_informational_flags() -> None:
    hashes = [f"{i:064x}" for i in range(60)]
    assert "ioc_list" in classify(_rule(detection={"s": {"Hashes|contains": hashes}, "condition": "s"}), [])
    assert "broad_logsource" in classify(_rule(logsource={"product": "windows"}), [])
    # an empty value is not match-all (e.g. "HTTP request with empty user agent")
    assert "match_all" not in classify(_rule(detection={"s": {"UserAgent": ""}, "condition": "s"}), [])


@pytest.mark.parametrize(
    "source,flag",
    [({"service": service}, "ambiguous_logsource") for service in ("process", "registry_event", "firewall")]
    + [({"service": service}, "nonstandard_logsource") for service in ("bits", "vhd", "windows-defender")]
    + [({"category": category}, "incompatible_logsource") for category in ("webserver", "dns", "proxy", "firewall")],
)
def test_source_review_flags_preserve_rules(source, flag):
    data = _rule(logsource={"product": "WINDOWS", **{k: v.upper() for k, v in source.items()}})
    before = copy.deepcopy(data)
    flags = classify(data, [])
    assert flags == [flag] and not is_junk(flags)
    assert data == before
    data["logsource"]["product"] = "linux"
    assert flag not in classify(data, [])


@pytest.mark.parametrize("service", ["setup", "bits-client", "vhdmp", "windefend", "firewall-as"])
def test_canonical_services_are_not_quality_mistakes(service):
    assert classify(_rule(logsource={"product": "windows", "service": service}), []) == []


_OLD_TEMPLATE = re.compile(r"\$\([^)]*\)|\{\{[^}]*\}\}|<[a-z_ .|-]{3,40}>", re.I)


def test_template_title_matches_the_regex_it_replaces() -> None:
    rng = random.Random(1234)
    alphabet = ["$(", "$", "(", ")", "{{", "{", "}", "}}", "<", ">", "abc", " ", "x"]
    titles = ["".join(rng.choice(alphabet) for _ in range(rng.randrange(12))) for _ in range(20000)]
    titles += ["AWS $(aws.eventSource) change", "{{ var }}", "{{a}x}}", "{{a}}", "<user name>", "$()", "{{}}"]
    for title in titles:
        assert ("template_title" in classify(_rule(title=title), [])) == bool(_OLD_TEMPLATE.search(title)), title


@pytest.mark.parametrize("opener", ["$(", "{{"])
def test_template_title_is_linear_on_unclosed_openers(opener: str) -> None:
    # The regex form took about 11 s for 40,000 "$(" (quadratic); a 2 MiB rule allows ~1,000,000.
    title = opener * 200_000
    start = time.perf_counter()
    assert "template_title" not in classify(_rule(title=title), [])
    assert time.perf_counter() - start < 2.0
