"""Offline canonical IDs, provenance, directionality and index publication parity."""

from __future__ import annotations

import json
from dataclasses import asdict

import pytest

from sigharvest.attack import ATTACK_VERSION, Matrix, Technique, cached_matrix, normalise_technique, tag_metadata, technique_ids
from sigharvest.config import Workspace


def matrix() -> Matrix:
    return Matrix(
        ATTACK_VERSION,
        [("defense-impairment", "Defense Impairment", "TA0112")],
        {
            "T1685": Technique("T1685", "Disable Defenses", ["defense-impairment"], None),
            "T1685.001": Technique("T1685.001", "Fixture child", ["defense-impairment"], "T1685"),
        },
        {"T1089": "T1562.001", "T1562.001": "T1685", "T1562": "T1685"},
        {"T1043"},
    )


def seed(ws: Workspace, data: Matrix | None = None) -> None:
    path = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    value = data or matrix()
    path.write_text(json.dumps(asdict(value) | {"techniques": [asdict(t) for t in value.techniques.values()], "deprecated": sorted(value.deprecated)}))


def test_chain_original_provenance_cycles_and_missing_successor():
    data = matrix()
    item = normalise_technique(" Attack.T1089 ", data)
    assert (item.original, item.original_id, item.current_id, item.status) == ("Attack.T1089", "T1089", "T1685", "replaced")
    assert item.label == "T1089 -> T1685 in ATT&CK v20.0"
    assert item.tactics == ("defense-impairment",)
    assert data.resolve("attack.t1089") == "T1685"
    assert technique_ids(["T1089", "attack.t1562.001", "T1685"], data) == {"T1685"}
    assert normalise_technique("T1043", data).status == "deprecated"
    data.replaced["T1086"] = "T1043"
    assert normalise_technique("T1086", data).status == "deprecated"
    data.replaced["T1685"] = "T1089"
    assert normalise_technique("T1089", data).status == "cycle"
    assert data.resolve("T1685") is None
    data.replaced["T1685"] = "T9999"
    assert normalise_technique("T1089", data).status == "unknown"


def test_external_identity_selection_preserves_normalisation_consumers():
    from sigharvest.attack import _reduce, matrix_from_data
    from tests.test_attack import bundle

    data = bundle()
    original = matrix_from_data(_reduce(data))
    for obj in data["objects"]:
        if refs := obj.get("external_references"):
            obj["external_references"] = [{"source_name": "other", "external_id": "G0001"}, *refs, dict(refs[0])]
    repeated = matrix_from_data(_reduce(data))
    assert repeated == original
    tags = ["attack.t1086", "attack.t1059.001", "attack.t1059", "attack.t9999", "attack.execution", "internal.lolbas"]
    assert tag_metadata(tags, repeated) == tag_metadata(tags, original)
    assert technique_ids(tags, repeated) == {"T1059", "T1059.001"}


@pytest.mark.parametrize("permutation", ["reverse", "rotate", "sorted"])
def test_phase_admission_preserves_order_names_and_normalisation(permutation):
    from copy import deepcopy

    from sigharvest.attack import _reduce, matrix_from_data
    from tests.test_attack import bundle

    data = bundle()
    data["objects"].append(
        {
            "type": "x-mitre-tactic",
            "id": "x2",
            "name": "Discovery",
            "x_mitre_shortname": "discovery",
            "external_references": [{"source_name": "mitre-attack", "external_id": "TA0007"}],
        }
    )
    data["objects"][1]["tactic_refs"].append("x2")
    data["objects"][2]["kill_chain_phases"].insert(0, {"kill_chain_name": "mitre-attack", "phase_name": "discovery"})
    expected = _reduce(data)
    original = matrix_from_data(expected)
    for obj in data["objects"]:
        if "kill_chain_phases" in obj:
            obj["kill_chain_phases"].insert(1, {"kill_chain_name": "mitre-mobile-attack", "phase_name": "foreign-phase"})
    objects = data["objects"]
    if permutation == "reverse":
        objects.reverse()
    elif permutation == "rotate":
        objects[:] = objects[3:] + objects[:3]
    else:
        objects.sort(key=lambda obj: (obj["type"], obj.get("id", "")))
    before = deepcopy(data)
    assert _reduce(data) == expected
    assert data == before
    admitted = matrix_from_data(_reduce(data))
    assert admitted == original
    assert admitted.techniques["T1059"].tactics == ["discovery", "execution"]
    tags = ["attack.t1086", "attack.t1059", "attack.t9999", "attack.mobile.t1400", "internal.lolbas"]
    assert tag_metadata(tags, admitted) == tag_metadata(tags, original)


@pytest.mark.parametrize(
    "tag,domain,status",
    [
        ("attack.ics.t0855", "ics", "unverified"),
        ("T0855", "ics", "unverified"),
        ("attack.mobile.t1629", "mobile", "unverified"),
        ("T1409", "mobile", "unverified"),
        ("attack.lolbas", "internal", "label"),
        ("attack.generated", "internal", "label"),
        ("attack.hunting", "internal", "label"),
        ("attack.supply-chain", "internal", "label"),
        ("attack.g0007", "other", "not_technique"),
        ("attack.s0001", "other", "not_technique"),
        ("attack.358", "other", "not_technique"),
        ("attack.execution", "other", "not_technique"),
    ],
)
def test_domains_and_labels_are_not_enterprise_techniques(tag, domain, status):
    result = normalise_technique(tag, matrix())
    assert (result.domain, result.status) == (domain, status)
    assert result.comparison_id is None
    assert technique_ids([tag], matrix()) == set()


def test_internal_labels_keep_source_independent_of_catalog():
    from sigharvest.normalize import tag

    assert tag("attack.lolbas") == "internal.lolbas"
    assert tag("attack.generated") == "internal.generated"
    assert tag("attack.supply_chain") == tag(tag("attack.supply_chain")) == "internal.supply-chain"
    assert tag("attack.t1562.001") == "attack.t1562.001"
    assert tag_metadata(["attack.lolbas"], matrix())[0]["original"] == "attack.lolbas"


@pytest.mark.parametrize("bad", [{"replaced": []}, {"replaced": {"T1089": []}}, {"deprecated": {}}, {"techniques": [None]}])
def test_corrupt_cache_is_offline_and_unverified(tmp_path, bad):
    ws = Workspace(tmp_path)
    seed(ws)
    path = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    value = json.loads(path.read_text()) | bad
    path.write_text(json.dumps(value))
    assert cached_matrix(ws) is None
    assert normalise_technique("T1089", cached_matrix(ws)).status == "unverified"


def test_metadata_memo_is_catalog_scoped_and_returns_independent_dicts():
    cache = {}
    before = tag_metadata(["T1089"], matrix(), cache)
    before[0]["label"] = "caller edit"
    assert tag_metadata(["T1089"], matrix(), cache)[0]["label"].startswith("T1089 -> T1685")
    changed = matrix()
    changed.replaced["T1089"] = "T1043"
    assert tag_metadata(["T1089"], changed, {})[0]["status"] == "deprecated"


@pytest.mark.parametrize("declarations", [False, True])
@pytest.mark.parametrize("duplicate", [False, True])
def test_source_subtechnique_declarations_preserve_canonical_selection(declarations: bool, duplicate: bool) -> None:
    from sigharvest.attack import _reduce, coverage_tag_sets, matrix_from_data
    from tests.test_attack import bundle, declare_subtechniques

    data = bundle()
    expected = matrix_from_data(_reduce(data))
    if declarations:
        declare_subtechniques(data)
        if duplicate:
            data["objects"].append(dict(data["objects"][-1]))
    for objects in (data["objects"], list(reversed(data["objects"])), data["objects"][2:] + data["objects"][:2]):
        actual = matrix_from_data(_reduce(data | {"objects": objects}))
        assert actual == expected
        tags = ["attack.t1086", "attack.t1059.001", "attack.t1059"]
        assert technique_ids(tags, actual) == {"T1059", "T1059.001"}
        assert tag_metadata(tags, actual) == tag_metadata(tags, expected)
        assert coverage_tag_sets(actual) == coverage_tag_sets(expected)
        assert set(coverage_tag_sets(actual)["T1059"]) == {"T1059", "T1059.001", "T1086"}
