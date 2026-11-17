"""Normalised categories."""

from sigharvest import normalize as n


def test_tags() -> None:
    assert n.tags(["attack.T1059_001", "T1059.001", "mitre.t1003", "attack.credential_access", "attack.TA0005", "CVE.2021.44228"]) == [
        "attack.t1059.001",
        "attack.t1003",
        "attack.credential-access",
        "attack.stealth",
        "cve.2021-44228",
    ]
    assert n.tags(["attack.defense_evasion", "attack.t1562.001"]) == ["attack.defense-impairment", "attack.t1562.001"]
    assert n.tags(["attack.defenseevasion"]) == ["attack.stealth"]
    assert n.tags(["attack.commandandcontrol", "attack.g0016", "sysmon"]) == ["attack.command-and-control", "attack.g0016", "sysmon"]


def test_logsource_level_status() -> None:
    assert n.logsource("Palo Alto Networks", None, None) == ("paloalto", None, None)
    assert n.logsource("sysmon", "process_creation", None) == ("windows", "process_creation", "sysmon")
    assert n.logsource("windows", "endpoint, network", None) == ("windows", "endpoint", None)
    assert n.logsource("windows", "THIRD_PARTY_LOG", "Sysmon") == ("windows", None, "sysmon")
    assert n.logsource(None, "registry_set", None) == ("windows", "registry_set", None)
    assert n.level("info") == "informational" and n.level("<informational | low") is None
    assert n.status("production") == "stable" and n.status("draft") == "test" and n.status("测试阶段") is None


def test_attack_credit_preserves_only_supported_complete_aliases() -> None:
    from sigharvest.attack_score import Context, credit

    context = Context()
    for value in ("attack.T1059_001", "T1059.001", "mitre.t1059-001", "mitre-attack.T1059/001", "att&ck.t1059.001", " Attack.T1059 "):
        assert credit([value], context) == 4
        assert credit([n.tag(value)], context) == 4
    for value in (
        "attack.t1059junk",
        "attack.t1059.",
        "attack.t10590",
        "attack.t1059.01",
        "attack.t1059.0001",
        "attack.t1059.001junk",
        "attack.execution",
        "attack.TA0002",
        "internal.hunting",
        "attack.lolbas",
        "attack.ics.t0855",
        "attack.mobile.t1629",
        "attack.t0855",
        "attack.t1409",
        None,
        1059,
        {},
        ["attack.t1059"],
    ):
        assert credit([value], context) == 0
    assert credit(["attack.t1059.001", "attack.t1059", "attack.t1059junk"], context) == 4
    assert credit("attack.t1059", context) == 0

    class PretendsToBeTag:
        def __str__(self) -> str:
            return "attack.t1059"

    assert credit([PretendsToBeTag()], context) == 0
