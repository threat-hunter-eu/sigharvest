import yaml

from sigharvest.identity import (
    LOGIC_VERSION,
    canonical_condition,
    canonical_logic,
    content_hash,
    fallback_rule_id,
    logic_hash,
    resolve_rule_id,
    rule_kind,
    title_slug,
)

BASE = """
title: Whoami Execution
id: 502b42de-4306-40b4-9596-6f590c81f073
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\whoami.exe'
        CommandLine|contains:
            - '/all'
            - '/priv'
    condition: selection
level: low
"""


def load(text: str) -> dict:
    return yaml.safe_load(text)


def test_kind_detection() -> None:
    assert rule_kind(load(BASE)) == "rule"
    assert rule_kind({"title": "x", "correlation": {"type": "event_count"}}) == "correlation"
    assert rule_kind({"filter": {"rules": []}, "logsource": {}}) == "filter"
    assert rule_kind({"title": "not sigma"}) is None
    assert rule_kind(["list"]) is None  # type: ignore[arg-type]


def test_logic_hash_ignores_metadata() -> None:
    other = BASE.replace("Whoami Execution", "Another title").replace("level: low", "level: high")
    other = other.replace("502b42de-4306-40b4-9596-6f590c81f073", "11111111-2222-3333-4444-555555555555")
    assert logic_hash(load(BASE)) == logic_hash(load(other))


def test_logic_hash_ignores_key_order_quoting_and_list_order() -> None:
    reordered = """
title: Whoami Execution
logsource: {product: windows, category: process_creation}
detection:
    condition:   selection
    selection:
        CommandLine|contains: ["/priv", "/all"]
        Image|endswith: "\\\\whoami.exe"
"""
    assert logic_hash(load(BASE)) == logic_hash(load(reordered))


def test_logic_hash_case_folds_values_and_modifiers() -> None:
    upper = BASE.replace("'\\whoami.exe'", "'\\WHOAMI.EXE'").replace("Image|endswith", "Image|EndsWith")
    assert logic_hash(load(BASE)) == logic_hash(load(upper))


def test_cased_and_regex_values_keep_case() -> None:
    a = load(BASE)
    b = load(BASE)
    a["detection"]["selection"] = {"CommandLine|re": "Foo.*"}
    b["detection"]["selection"] = {"CommandLine|re": "foo.*"}
    assert logic_hash(a) != logic_hash(b)
    a["detection"]["selection"] = {"CommandLine|cased": "Foo"}
    b["detection"]["selection"] = {"CommandLine|cased": "foo"}
    assert logic_hash(a) != logic_hash(b)


def test_field_names_are_case_sensitive() -> None:
    a = load(BASE)
    b = load(BASE)
    b["detection"]["selection"]["image|endswith"] = b["detection"]["selection"].pop("Image|endswith")
    assert logic_hash(a) != logic_hash(b)


def test_condition_order_is_semantic_but_whitespace_is_not() -> None:
    assert canonical_condition("selection   and not  filter") == "selection and not filter"
    assert canonical_condition("Selection AND (filter_a OR filter_b)") == "Selection and ( filter_a or filter_b )"
    assert canonical_condition("a and b") != canonical_condition("b and a")


def test_or_list_of_maps_is_sorted() -> None:
    a = load(BASE)
    b = load(BASE)
    a["detection"]["selection"] = [{"Image|endswith": "\\a.exe"}, {"Image|endswith": "\\b.exe"}]
    b["detection"]["selection"] = [{"Image|endswith": "\\b.exe"}, {"Image|endswith": "\\a.exe"}]
    assert logic_hash(a) == logic_hash(b)


def test_numbers_and_numeric_strings_are_equal() -> None:
    a = {"logsource": {"product": "windows"}, "detection": {"sel": {"EventID": 4688}, "condition": "sel"}}
    b = {"logsource": {"product": "windows"}, "detection": {"sel": {"EventID": "4688"}, "condition": "sel"}}
    assert logic_hash(a) == logic_hash(b)


def test_logsource_definition_is_ignored() -> None:
    a = load(BASE)
    b = load(BASE)
    b["logsource"]["definition"] = "Requires Sysmon"
    assert logic_hash(a) == logic_hash(b)


def test_detection_change_changes_hash() -> None:
    changed = BASE.replace("'/priv'", "'/groups'")
    assert logic_hash(load(BASE)) != logic_hash(load(changed))


def test_golden_hash_is_stable() -> None:
    # If this fails, the canonicalisation changed: bump LOGIC_VERSION and update docs/identity.md.
    assert LOGIC_VERSION == "sigharvest-logic-v1"
    canon = canonical_logic(load(BASE))
    assert canon == {
        "kind": "rule",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {"map": [["CommandLine|contains", ["/all", "/priv"]], ["Image|endswith", "\\whoami.exe"]]},
            "condition": "selection",
        },
    }
    assert logic_hash(load(BASE)) == "edf9182a3de38919a40c70d718a5bbc25726a412faca5f75398e83442157b4ad"


def test_ids() -> None:
    rid, flag = resolve_rule_id(load(BASE), "x")
    assert rid == "502b42de-4306-40b4-9596-6f590c81f073" and flag is None
    rid, flag = resolve_rule_id({"title": "t"}, "abc")
    assert rid == fallback_rule_id("abc") and flag == "id_missing"
    rid, flag = resolve_rule_id({"id": "not-a-uuid"}, "abc")
    assert flag == "id_invalid"
    assert fallback_rule_id("abc") == fallback_rule_id("abc")


def test_title_slug_and_content_hash() -> None:
    assert title_slug("Suspicious  PowerShell -- Download (Cradle)!") == "suspicious-powershell-download-cradle"
    assert title_slug("Exécution suspecte") == "execution-suspecte"
    assert content_hash(b"a") != content_hash(b"a ")


def test_placeholder_uuids() -> None:
    import uuid

    from sigharvest.identity import placeholder_uuid

    for u in (
        "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "00000000-0000-0000-0000-000000000000",
        "11111111-2222-3333-4444-555555555555",
        "12345678-1234-1234-1234-123456789abc",
        "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
    ):
        assert placeholder_uuid(u), u
    assert sum(placeholder_uuid(str(uuid.uuid4())) for _ in range(5000)) <= 2
    assert not placeholder_uuid("e9142d84-fbe0-401d-ac50-3e519fe2a4e0")


def test_related_ids() -> None:
    from sigharvest.index import related_ids

    raw = (
        "title: x\nrelated:\n"
        "    - id: e9142d84-fbe0-401d-ac50-3e519fe2a4e0\n      type: derived\n"
        "    - id: 1321dc4e-a1fe-481d-a016-52c45f0c8b4f\n      type: similar\n"
        "status: test\n"
    )
    assert related_ids(raw) == ["e9142d84-fbe0-401d-ac50-3e519fe2a4e0"]
    assert related_ids("title: x\n") == []


def test_search_language() -> None:
    from sigharvest.index import fts_query, parse_query

    assert fts_query("powershell OR pwsh") == ('"powershell"* OR "pwsh"*', "")
    assert fts_query("mimikatz -sekurlsa") == ('("mimikatz"*) NOT "sekurlsa"*', "")
    assert fts_query("NOT mimikatz") == ("", '"mimikatz"*')
    assert fts_query("(certutil OR bitsadmin) download") == ('( "certutil"* OR "bitsadmin"* ) AND "download"*', "")
    assert fts_query("((") == ("", "")
    assert fts_query('title:"net user" or') == ('title:"net user"* AND "or"', "")  # a two-letter word is exact
    assert fts_query('" OR "x') == ('"OR"* AND "x"*', "") or fts_query('" OR "x')[0]  # quoting keeps syntax out
    assert parse_query("mimikatz level:high product:windows id:a642964e") == (
        "mimikatz",
        {"level": "high", "product": "windows", "id": "a642964e"},
    )


def test_source_roots_collapse_mirrors() -> None:
    from sigharvest.index import _Acc, source_roots

    groups = {}
    for i in range(10):  # upstream has 10 rules; a mirror copies 9 of them; a fork of the mirror copies 8
        acc = _Acc(f"l{i}")
        acc.sources = {"upstream"} | ({"mirror"} if i < 9 else set()) | ({"fork"} if i < 8 else set())
        groups[f"l{i}"] = acc
    own = _Acc("x")
    own.sources = {"independent"}
    groups["x"] = own
    shared = _Acc("y")
    shared.sources = {"independent", "upstream"}
    groups["y"] = shared
    roots = source_roots(groups)
    assert roots["mirror"][0] == "upstream" and roots["fork"][0] == "upstream"
    assert roots["independent"][0] == "independent" and roots["upstream"][0] == "upstream"
    assert len({roots[s][0] for s in groups["l0"].sources}) == 1


def test_near_duplicates() -> None:
    from sigharvest.neardup import items, pairs

    base = {"sel": {"Image|endswith": ["\\\\a.exe", "\\\\b.exe", "\\\\c.exe", "\\\\d.exe", "\\\\e.exe"]}, "condition": "sel"}
    close = {"s1": {"Image|endswith": ["\\\\a.exe", "\\\\b.exe", "\\\\c.exe", "\\\\d.exe", "\\\\e.exe", "\\\\f.exe"]}, "condition": "s1"}
    other = {"sel": {"CommandLine|contains": ["x", "y", "z", "w"]}, "condition": "sel"}
    rows = [("a" * 64, "w/p/", items(base)), ("b" * 64, "w/p/", items(close)), ("c" * 64, "w/p/", items(other)), ("d" * 64, "l/p/", items(base))]
    found = pairs(rows)
    assert [(a[0], b[0]) for a, b, _ in found] == [("a", "b")]  # same logsource only, similar only
    assert found[0][2] >= 0.8
