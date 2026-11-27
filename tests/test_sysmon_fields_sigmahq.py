"""The SigmaHQ rules that become `partial` on Sysmon with the field check (accepted by the maintainers).

Each case keeps the shape of the rule's detection (selections, condition, negations, null tests) with placeholder
values. The field each rule tests positively is not in its Sysmon event: SigmaHQ writes these rules for agents that
enrich file, network and image load events with process fields (several say so in `logsource.definition`). On plain
Sysmon the query could never match, so the Sysmon result is `partial` with the reason, not an `ok` query.
"""

import pytest

from sigharvest.conversion import convert

FILE_EVENT = "no documented native Sysmon field in file_event (event 11): "
NETWORK = "no documented native Sysmon field in network_connection (event 3): "
IMAGE_LOAD = "no documented native Sysmon field in image_load (event 7): "


def sigma(category: str, detection: str) -> str:
    return f"title: t\nlogsource:\n  product: windows\n  category: {category}\ndetection:\n{detection}"


CASES = [
    (
        "bd1212e5-78da-431e-95fa-c58e3237a8e6",  # Suspicious ASPX File Drop by Exchange (core)
        sigma(
            "file_event",
            "  selection:\n    Image|endswith: '\\a.exe'\n    CommandLine|contains: 'b'\n    TargetFilename|contains: ['\\c\\', '\\d\\']\n"
            "  selection_types:\n    TargetFilename|endswith: ['.e', '.f']\n  condition: all of selection*\n",
        ),
        FILE_EVENT + "CommandLine",
    ),
    (
        "6b269392-9eba-40b5-acb6-55c882b20ba6",  # Suspicious File Drop by Exchange (core)
        sigma(
            "file_event",
            "  selection:\n    Image|endswith: '\\a.exe'\n    CommandLine|contains: 'b'\n"
            "  selection_types:\n    TargetFilename|endswith: ['.e', '.f']\n  condition: all of selection*\n",
        ),
        FILE_EVENT + "CommandLine",
    ),
    (
        "b1c50487-1967-4315-a026-6491686d860e",  # Office Macro File Creation From Suspicious Process (core)
        sigma(
            "file_event",
            "  selection_cmd:\n    - Image|endswith: ['\\a.exe', '\\b.exe']\n    - ParentImage|endswith: ['\\a.exe', '\\b.exe']\n"
            "  selection_ext:\n    TargetFilename|endswith: ['.c', '.d']\n  condition: all of selection_*\n",
        ),
        FILE_EVENT + "ParentImage",
    ),
    (
        "4e7050dd-e548-483f-b7d6-527ab4fa784d",  # NTDS.DIT Creation By Uncommon Parent Process (core)
        sigma(
            "file_event",
            "  selection_file:\n    TargetFilename|endswith: '\\a.b'\n"
            "  selection_process_parent:\n    ParentImage|endswith: ['\\c.exe', '\\d.exe']\n"
            "  selection_process_parent_path:\n    ParentImage|contains: ['\\e\\', '\\f\\']\n"
            "  condition: selection_file and 1 of selection_process_*\n",
        ),
        FILE_EVENT + "ParentImage",
    ),
    (
        "121b25f7-b9d6-4b37-afa0-cba317ec52f3",  # WDAC Policy File Creation In CodeIntegrity Folder (threat-hunting)
        sigma(
            "file_event",
            "  selection:\n    TargetFilename|contains: ':\\a\\'\n    TargetFilename|endswith: ['.b', '.c']\n"
            "    IntegrityLevel: 'High'\n  condition: selection\n",
        ),
        FILE_EVENT + "IntegrityLevel",
    ),
    (
        "cae6cee6-0244-44d2-84ed-e65f548eb7dc",  # Potential Pikabot C2 Activity (emerging threats)
        sigma(
            "network_connection",
            "  selection:\n    ParentImage|endswith: '\\a.exe'\n    Image|endswith: ['\\b.exe', '\\c.exe']\n"
            "    Protocol: tcp\n    Initiated: 'true'\n  condition: selection\n",
        ),
        NETWORK + "ParentImage",
    ),
    (
        "20384606-a124-4fec-acbb-8bd373728613",  # Suspicious Network Connection Binary No CommandLine (core)
        sigma(
            "network_connection",
            "  selection:\n    Initiated: 'true'\n    Image|endswith: ['\\a.exe', '\\b.exe']\n    CommandLine|endswith: ['\\a.exe', '\\b.exe']\n"
            "  filter_no_cmdline:\n    CommandLine: ''\n  filter_null:\n    CommandLine: null\n"
            "  condition: selection and not 1 of filter*\n",
        ),
        NETWORK + "CommandLine",
    ),
    (
        "c649a6c7-cd8c-4a78-9c04-000fc76df954",  # Potentially Suspicious Wuauclt Network Connection (core)
        sigma(
            "network_connection",
            "  selection:\n    Image|contains: 'a'\n    CommandLine|contains: ' /b'\n"
            "  filter_main_uus:\n    CommandLine|contains: ['c', 'd']\n"
            "  filter_main_cli_null:\n    CommandLine: null\n  filter_main_cli_empty:\n    CommandLine: ''\n"
            "  condition: selection and not 1 of filter_main_*\n",
        ),
        NETWORK + "CommandLine",
    ),
    (
        "ad1f4bb9-8dfb-4765-adb6-2a7cfb6c0f94",  # Suspicious WSMAN Provider Image Loads (core)
        # CommandLine only in negated parts, but one of them tests it for null: an absent field is always null,
        # so on Sysmon `not (svchost and commandline_null)` would drop every svchost event.
        sigma(
            "image_load",
            "  request_client:\n    - ImageLoaded|endswith: ['\\a.dll', '\\b.dll']\n    - OriginalFileName: ['a.dll', 'b.dll']\n"
            "  respond_server:\n    Image|endswith: '\\c.exe'\n    OriginalFileName: 'd.dll'\n"
            "  filter_general:\n    Image: ['C:\\e.exe']\n"
            "  filter_svchost:\n    CommandLine|contains: ['f', 'g']\n"
            "  svchost:\n    Image|endswith: '\\c.exe'\n  commandline_null:\n    CommandLine: null\n"
            "  condition: ( request_client or respond_server ) and not 1 of filter* and not ( svchost and commandline_null )\n",
        ),
        IMAGE_LOAD + "CommandLine",
    ),
]


@pytest.mark.parametrize(("rule_id", "text", "reason"), CASES, ids=[c[0][:8] for c in CASES])
def test_sigmahq_rules_needing_enriched_fields_are_partial_on_sysmon(rule_id: str, text: str, reason: str) -> None:
    c = convert(text, "splunk")
    assert c.status == "partial", rule_id
    assert c.missing_fields == [reason.rsplit(": ", 1)[1]]
    assert c.reason == reason
    assert not c.queries and not c.combined_query and c.covered_sources == []


def test_the_accepted_list_has_nine_distinct_rules() -> None:
    assert len({c[0] for c in CASES}) == 9
