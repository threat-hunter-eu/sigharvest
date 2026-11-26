"""Detection strength flags: weak_detection, weak_high_severity, weak_branch (quality_strength.py)."""

import pytest
import yaml

from sigharvest.quality import classify, is_junk
from sigharvest.quality_strength import strength_flags, strength_penalty, value_is_weak

_LOADER = getattr(yaml, "CBaseLoader", yaml.BaseLoader)  # the index reads rules with BaseLoader


def _rule(detection: str, level: str = "high") -> dict:
    text = f"title: t\nlevel: {level}\nlogsource: {{product: windows, category: process_creation}}\ndetection:\n{detection}\n"
    return yaml.load(text, Loader=_LOADER)


# name: (weak detection, its specific counterpart, flags of the weak one)
PATTERNS = {
    "any process": (
        "  sel: {Image|startswith: '/'}\n  condition: sel",
        "  sel: {Image|startswith: '/usr/libexec/', CommandLine|contains: 'xprotect'}\n  condition: sel",
        ["weak_detection", "weak_high_severity"],
    ),
    "catch-all field exists": (
        "  sel: {message|exists: true}\n  condition: sel",
        "  sel: {message|contains: 'Failed password for'}\n  condition: sel",
        ["weak_detection", "weak_high_severity"],
    ),
    "sigma ? wildcard": (
        "  a: {cs-uri-stem|contains: 'shell.php'}\n  b: {cs-uri-stem|contains: '?c='}\n  condition: a or b",
        "  a: {cs-uri-stem|contains: 'shell.php'}\n  b: {cs-uri-stem|contains: '\\?c='}\n  condition: a or b",
        ["weak_branch"],
    ),
    "lone -E": (
        "  sel: {CommandLine|contains: '-E '}\n  condition: sel",
        "  sel: {Image|endswith: '\\powershell.exe', CommandLine|contains: '-E '}\n  condition: sel",
        ["weak_detection", "weak_high_severity"],
    ),
    "short OR value": (
        "  sel: {useragent|contains: ['<script>', '</', 'alert(']}\n  condition: sel",
        "  sel: {useragent|contains: ['<script>', 'alert(']}\n  condition: sel",
        ["weak_branch"],
    ),
    "two weak values AND": (
        "  sel: {CommandLine|contains|all: ['nc ', '-e ']}\n  condition: sel",
        "  sel: {CommandLine|contains|all: ['nc ', '-e /bin/sh']}\n  condition: sel",
        ["weak_detection", "weak_high_severity"],
    ),
    "one metachar": (
        "  a: {cs-body|contains: 'pitboss'}\n  b: {cs-body|contains: [';', '|']}\n  condition: a or b",
        "  a: {cs-body|contains: 'pitboss'}\n  b: {cs-body|contains: [';id;', '|sh']}\n  condition: a or b",
        ["weak_branch"],
    ),
    "negation adds no strength": (
        "  sel: {CommandLine|contains: '*'}\n  f: {Image|endswith: '\\x.exe'}\n  condition: sel and not f",
        "  sel: {CommandLine|contains: 'vssadmin'}\n  f: {Image|endswith: '\\x.exe'}\n  condition: sel and not f",
        ["weak_detection", "weak_high_severity"],
    ),
    "keyword list": (
        "  keywords: ['ab', 'mimikatz']\n  condition: keywords",
        "  keywords: ['sekurlsa', 'mimikatz']\n  condition: keywords",
        ["weak_branch"],
    ),
}


@pytest.mark.parametrize("name", list(PATTERNS))
def test_weak_and_specific_pattern(name: str) -> None:
    weak, specific, flags = PATTERNS[name]
    assert strength_flags(_rule(weak)) == flags
    assert strength_flags(_rule(specific)) == []


def test_level_decides_only_the_junk_flag() -> None:
    weak = PATTERNS["any process"][0]
    assert strength_flags(_rule(weak, level="low")) == ["weak_detection"]
    assert not is_junk(classify(_rule(weak, level="medium"), ["rules/a.yml"]))
    assert is_junk(classify(_rule(weak, level="critical"), ["rules/a.yml"]))
    assert not is_junk(classify(_rule(PATTERNS["short OR value"][0]), ["rules/a.yml"]))


def test_penalty() -> None:
    assert strength_penalty(["weak_detection", "weak_high_severity"]) == 15.0
    assert strength_penalty(["weak_branch", "ioc_list"]) == 5.0
    assert strength_penalty(None) == 0.0


@pytest.mark.parametrize(
    "field,mods,value",
    [
        ("UserAgent", [], ""),  # an empty user agent is a real indicator
        ("CommandLine", ["re"], "^.*\u202e.*$"),  # one right-to-left override character is specific
        ("TargetFilename", ["fieldref"], "Image"),  # relation between two fields
        ("Image", ["endswith"], "/w"),  # the `w` binary
        ("x-middleware-subrequest", ["exists"], "true"),  # presence of a specific header
        ("EventID", [], "4688"),
        ("DestinationIp", ["cidr"], "10.0.0.0/16"),
        ("USER", [], "#-*"),  # sudo CVE-2019-14287: a user id starting with `#-` is the exploit itself
        ("USER", ["startswith"], "#-"),
    ],
)
def test_specific_values(field: str, mods: list[str], value: str) -> None:
    assert not value_is_weak(field, mods, value)


@pytest.mark.parametrize(
    "field,mods,value",
    [
        ("CommandLine", ["re"], ".*"),
        ("DestinationIp", ["cidr"], "0.0.0.0/0"),
        ("Image", ["startswith"], "/"),
        ("Image", ["endswith"], "/"),
        ("raw", ["exists"], "true"),
        ("CommandLine", [], "*a*"),
        ("USER", ["contains"], "#-"),  # not anchored: anywhere in the value
        ("CommandLine", [], "*#-*"),
        ("Image", ["startswith"], "C:"),  # letters, not symbols
        ("CommandLine", ["startswith"], "//"),  # path separators
    ],
)
def test_weak_values(field: str, mods: list[str], value: str) -> None:
    assert value_is_weak(field, mods, value)


def test_unreadable_or_missing_conditions_are_not_flagged() -> None:
    assert strength_flags({"detection": None}) == []
    assert strength_flags({"correlation": {"type": "event_count"}}) == []
    assert strength_flags(_rule("  sel: {Image|startswith: '/'}\n  condition: sel and (")) == []
    assert strength_flags(_rule("  sel: {Image|startswith: '/'}\n  condition: missing")) == []
