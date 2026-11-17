import copy
import json
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.cells import cell_len
from rich.console import Console
from sqlalchemy import select
from typer.testing import CliRunner

from sigharvest.attack import (
    ATTACK_VERSION,
    MAX_EXTERNAL_REFERENCE_FIELDS,
    MAX_EXTERNAL_REFERENCES,
    MAX_REFERENCE_SOURCE_NAME,
    AttackIdentityError,
    _ext_id,
    _reduce,
    compute,
    navigator_layer,
)
from sigharvest.cli import app
from sigharvest.cli import reports as cli_reports
from sigharvest.config import Workspace, save_sources
from sigharvest.errors import SigharvestError
from sigharvest.index import GroupFilters, rebuild
from sigharvest.models import LogicGroup, RuleVersion
from sigharvest.service import open_db, sync_all
from tests.helpers import ATTACK_FIXTURE, seed_attack
from tests.test_pipeline import make_repo, workspace


def bundle() -> dict:
    def ap(ref: str, tid: str, name: str, tactic: str, **extra: object) -> dict:
        return {
            "type": "attack-pattern",
            "x_mitre_domains": ["enterprise-attack"],
            "id": ref,
            "name": name,
            "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": tactic}],
            **extra,
        }

    return {
        "type": "bundle",
        "id": "bundle--12345678-1234-4234-8234-123456789abc",
        "objects": [
            {
                "type": "x-mitre-tactic",
                "id": "x1",
                "name": "Execution",
                "x_mitre_shortname": "execution",
                "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002"}],
            },
            {"type": "x-mitre-matrix", "id": "m", "x_mitre_domains": ["enterprise-attack"], "tactic_refs": ["x1"]},
            ap("a1", "T1059", "Command and Scripting Interpreter", "execution"),
            ap("a2", "T1059.001", "PowerShell", "execution"),
            ap("a3", "T1086", "PowerShell (old)", "execution", revoked=True),
            {"type": "relationship", "relationship_type": "revoked-by", "source_ref": "a3", "target_ref": "a2"},
        ],
    }


def mock_bundle_http(monkeypatch, data):
    from sigharvest import attack_io

    monkeypatch.setattr(attack_io, "_acquire", attack_io._read_bundle)
    response = BytesIO(json.dumps(data).encode())
    response.status = 200
    response.headers = {}
    monkeypatch.setattr("sigharvest.attack_io.build_opener", lambda *a: SimpleNamespace(open=lambda *a, **kw: response))
    return response


def test_reduce_and_tags() -> None:
    data = _reduce(bundle())
    assert data["tactics"] == [["execution", "Execution", "TA0002"]]
    assert [t["id"] for t in data["techniques"]] == ["T1059", "T1059.001"]
    assert data["replaced"] == {"T1086": "T1059.001"}


@pytest.mark.parametrize("value", [None, False, 1, "execution", {}, [], [None], [True], [1], ["execution"], [[]]])
def test_phase_container_admission(value: object) -> None:
    from sigharvest.attack import AttackPhaseError

    data = bundle()
    data["objects"][2]["kill_chain_phases"] = value
    with pytest.raises(AttackPhaseError, match=r"attack-pattern.kill_chain_phases"):
        _reduce(data)
    data["objects"][2].pop("kill_chain_phases")
    with pytest.raises(AttackPhaseError, match="at least one Enterprise tactic"):
        _reduce(data)


@pytest.mark.parametrize("field", ["kill_chain_name", "phase_name"])
@pytest.mark.parametrize("value", [None, False, 1, [], {}, "", " ", " execution", "execution ", "bad\ntext", "bad\x00text", "bad\x7ftext", "x" * 1025])
@pytest.mark.parametrize("chain", ["mitre-attack", "other-chain"])
def test_phase_shape_checked_before_domain_filter(field: str, value: object, chain: str) -> None:
    from sigharvest.attack import AttackPhaseError

    data = bundle()
    phases = data["objects"][2]["kill_chain_phases"]
    phases.append({"kill_chain_name": chain, "phase_name": "execution", field: value})
    with pytest.raises(AttackPhaseError, match=rf"kill_chain_phases\[1\].{field}") as error:
        _reduce(data)
    assert len(str(error.value)) < 260
    phases[1].pop(field)
    with pytest.raises(AttackPhaseError, match=rf"kill_chain_phases\[1\].{field}"):
        _reduce(data)


@pytest.mark.parametrize("phase", ["Execution", "unknown", "EXECUTION", "execution.extra"])
def test_phase_requires_exact_declared_shortname(phase: str) -> None:
    from sigharvest.attack import AttackPhaseError

    data = bundle()
    data["objects"][2]["kill_chain_phases"][0]["phase_name"] = phase
    with pytest.raises(AttackPhaseError, match="unknown Enterprise tactic"):
        _reduce(data)


def test_phase_limits_mixed_chains_and_duplicates() -> None:
    from sigharvest.attack import MAX_CATALOG_NAME, MAX_KILL_CHAIN_PHASES, AttackPhaseError

    data = bundle()
    expected = _reduce(data)
    phases = data["objects"][2]["kill_chain_phases"]
    # Foreign phases need a valid envelope but do not enter Enterprise membership.
    foreign = {"kill_chain_name": "x" * MAX_CATALOG_NAME, "phase_name": "y" * MAX_CATALOG_NAME}
    phases.extend([foreign] * (MAX_KILL_CHAIN_PHASES - 1))
    assert _reduce(data) == expected
    phases.append(foreign)
    with pytest.raises(AttackPhaseError, match="phase count exceeds limit"):
        _reduce(data)
    phases[:] = [phases[0], {"kill_chain_name": "mitre-mobile-attack", "phase_name": "execution"}, dict(phases[0])]
    with pytest.raises(AttackPhaseError, match=r"\[2\].phase_name: duplicate"):
        _reduce(data)
    phases.pop()
    phases += [{"kill_chain_name": "mitre-ics-attack", "phase_name": "unknown"}, {"kill_chain_name": "mitre-atack", "phase_name": "execution"}]
    assert _reduce(data) == expected
    phases.pop(0)
    with pytest.raises(AttackPhaseError, match="at least one Enterprise tactic"):
        _reduce(data)


def test_phase_admission_keeps_existing_consumed_object_scope() -> None:
    data = bundle()
    expected = _reduce(data)
    data["objects"][4]["kill_chain_phases"] = False  # Retired identity, phases unused.
    data["objects"].append({"type": "attack-pattern", "id": "unidentified", "x_mitre_domains": ["enterprise-attack"], "kill_chain_phases": None})
    data["objects"].append({"type": "report", "kill_chain_phases": None})
    assert _reduce(data) == expected
    data["objects"][4].pop("revoked")
    data["objects"][4]["x_mitre_deprecated"] = True
    assert _reduce(data)["deprecated"] == ["T1086"]


def test_invalid_source_phases_are_not_written_by_matrix_acquisition(tmp_path, monkeypatch) -> None:
    from sigharvest.attack import AttackPhaseError, cached_matrix, load_matrix

    data = bundle()
    data["objects"][2]["kill_chain_phases"] = [None]

    mock_bundle_http(monkeypatch, data)
    ws = Workspace(tmp_path)
    with pytest.raises(AttackPhaseError):
        load_matrix(ws)
    assert not (ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json").exists()
    assert cached_matrix(ws) is None


INVALID_TECHNIQUE_DOMAINS = [
    None,
    "enterprise-attack",
    [],
    {},
    True,
    1,
    [None],
    [True],
    [1],
    [{}],
    [[]],
    [""],
    ["unknown-attack"],
    ["Enterprise-Attack"],
    [" enterprise-attack"],
    ["enterprise-attack "],
    ["enterprise-attack\n"],
    ["enterprise-attack\x00"],
    ["ｅnterprise-attack"],
    ["x" * 1024],
    ["enterprise-attack", "enterprise-attack"],
    ["mobile-attack", "mobile-attack"],
    ["enterprise-attack", "ics-attack", "mobile-attack", "enterprise-attack"],
    ["enterprise-attack", None],
    [None, "enterprise-attack"],
]


@pytest.mark.parametrize("domains", INVALID_TECHNIQUE_DOMAINS)
@pytest.mark.parametrize("lifecycle", [{}, {"revoked": True}, {"x_mitre_deprecated": True}])
def test_technique_domain_admission_rejects_invalid_declarations(domains, lifecycle):
    from sigharvest.attack import InvalidMatrix

    data = bundle()
    obj = next(o for o in data["objects"] if o.get("id") == "a1")
    obj.update(lifecycle, x_mitre_domains=domains)
    before = copy.deepcopy(data)
    with pytest.raises(InvalidMatrix, match="attack-pattern x_mitre_domains"):
        _reduce(data)
    assert data == before


@pytest.mark.parametrize("ref", ["a1", "a3"])
def test_technique_missing_domain_is_not_implicitly_enterprise(ref):
    from sigharvest.attack import InvalidMatrix

    data = bundle()
    del next(o for o in data["objects"] if o.get("id") == ref)["x_mitre_domains"]
    with pytest.raises(InvalidMatrix, match="x_mitre_domains must be a nonempty list"):
        _reduce(data)


@pytest.mark.parametrize("domains", [["mobile-attack"], ["ics-attack"], ["mobile-attack", "ics-attack"]])
def test_foreign_techniques_do_not_supply_active_retirement_or_reference_identities(domains):
    from sigharvest.attack import _reduce_with_refs

    data = bundle()
    base = next(o for o in data["objects"] if o.get("id") == "a1")
    for index, lifecycle in enumerate(({}, {"revoked": True}, {"x_mitre_deprecated": True})):
        data["objects"].append(base | lifecycle | {"id": f"foreign-{index}", "x_mitre_domains": domains})
        data["objects"].append({"type": "relationship", "relationship_type": "revoked-by", "source_ref": f"foreign-{index}", "target_ref": "a2"})
    expected = _reduce_with_refs(bundle())
    # Matching MITRE ID and mitre-attack phase cannot certify a foreign object.
    for objects in (data["objects"], list(reversed(data["objects"]))):
        assert _reduce_with_refs(data | {"objects": objects}) == expected


@pytest.mark.parametrize("domains", [["enterprise-attack", "mobile-attack"], ["ics-attack", "enterprise-attack", "mobile-attack"]])
def test_multidomain_techniques_are_admitted_once_and_order_independent(domains):
    import random

    from sigharvest.attack import _reduce_with_refs

    data = bundle()
    for obj in data["objects"]:
        if obj["type"] == "attack-pattern":
            obj["x_mitre_domains"] = domains
    expected = _reduce_with_refs(bundle())
    orders = [data["objects"], list(reversed(data["objects"]))]
    for seed in (7, 19):
        shuffled = list(data["objects"])
        random.Random(seed).shuffle(shuffled)
        orders.append(shuffled)
    for objects in orders:
        assert _reduce_with_refs(data | {"objects": objects}) == expected


@pytest.mark.parametrize("target_lifecycle", [{}, {"revoked": True}, {"x_mitre_deprecated": True}])
@pytest.mark.parametrize("rel_lifecycle", [{}, {"revoked": True}, {"x_mitre_deprecated": True}])
def test_enterprise_replacement_cannot_silently_lose_foreign_successor(target_lifecycle, rel_lifecycle):
    from sigharvest.attack import InvalidMatrix

    data = bundle()
    target = next(o for o in data["objects"] if o.get("id") == "a2")
    target.update(target_lifecycle, x_mitre_domains=["ics-attack"])
    data["objects"][-1].update(rel_lifecycle)
    for objects in (data["objects"], list(reversed(data["objects"]))):
        if rel_lifecycle:
            assert _reduce(data | {"objects": objects})["replaced"] == {}
        else:
            with pytest.raises(InvalidMatrix, match=r"revoked-by.*excluded by x_mitre_domains"):
                _reduce(data | {"objects": objects})


def test_domain_refusal_first_acquisition_does_not_publish(tmp_path, monkeypatch):
    from sigharvest.attack import AttackCacheError, load_matrix

    data = bundle()
    del data["objects"][2]["x_mitre_domains"]

    mock_bundle_http(monkeypatch, data)
    ws = Workspace(tmp_path)
    with pytest.raises(AttackCacheError, match=r"x_mitre_domains.*Supply a complete Enterprise"):
        load_matrix(ws)
    assert not (ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json").exists()


def test_domain_admission_rechecks_mutated_objects_without_identity_coercion():
    from sigharvest.attack import InvalidMatrix, _reduce_with_refs

    data = bundle()
    obj = next(o for o in data["objects"] if o.get("id") == "a1")
    assert "a1" in _reduce_with_refs(data)[1]
    obj["x_mitre_domains"][:] = ["mobile-attack"]
    # Excluded objects do not enter the external-identity boundary at all.
    obj["external_references"] = "unused foreign metadata"
    assert "a1" not in _reduce_with_refs(data)[1]
    obj["x_mitre_domains"].append(None)
    with pytest.raises(InvalidMatrix, match="x_mitre_domains"):
        _reduce(data)


@pytest.mark.parametrize(
    ("kind", "identity", "other"),
    [
        ("attack-pattern", "T1059", "T1105"),
        ("attack-pattern", "T1059.001", "T1059.002"),
        ("x-mitre-tactic", "TA0002", "TA0003"),
        ("intrusion-set", "G0001", "G0002"),
        ("malware", "S0001", "S0002"),
        ("tool", "S0001", "S0002"),
    ],
)
def test_external_identity_order_duplicates_and_conflicts(kind: str, identity: str, other: str) -> None:
    valid = {"source_name": "mitre-attack", "external_id": identity}
    citation = {"source_name": "another-provider", "external_id": other, "description": {"irrelevant": [None]}}
    for refs in ([valid, citation, dict(valid)], [dict(valid), citation, valid], [citation, valid]):
        assert _ext_id({"type": kind, "external_references": refs}) == identity
    for refs in ([valid, {**valid, "external_id": other}], [{**valid, "external_id": other}, valid]):
        with pytest.raises(AttackIdentityError, match=r"external_references\[\].external_id: conflicting MITRE IDs"):
            _ext_id({"type": kind, "external_references": refs})


@pytest.mark.parametrize("value", [None, True, False, 1059, 1059.001, [], {}, "", "t1059", " T1059", "T1059\n", "T١٠٥٩", "T1059.01", "G0001", "x" * 10_000])
@pytest.mark.parametrize("reverse", [False, True])
def test_malformed_mitre_reference_cannot_hide(value: object, reverse: bool) -> None:
    refs = [{"source_name": "mitre-attack", "external_id": "T1059"}, {"source_name": "mitre-attack", "external_id": value}]
    with pytest.raises(AttackIdentityError, match=r"external_references\[\].external_id"):
        _ext_id({"type": "attack-pattern", "external_references": refs[::-1] if reverse else refs})


@pytest.mark.parametrize("kind", ["attack-pattern", "x-mitre-tactic", "intrusion-set", "malware", "tool"])
def test_missing_mitre_identity_and_type_mismatch(kind: str) -> None:
    assert _ext_id({"type": kind}) is None
    assert _ext_id({"type": kind, "external_references": []}) is None
    assert _ext_id({"type": kind, "external_references": [{"source_name": "other", "external_id": "T1059"}]}) is None
    with pytest.raises(AttackIdentityError, match="external_id"):
        _ext_id({"type": kind, "external_references": [{"source_name": "mitre-attack"}]})
    wrong = "G0001" if kind != "intrusion-set" else "S0001"
    with pytest.raises(AttackIdentityError, match="invalid MITRE ID for object type"):
        _ext_id({"type": kind, "external_references": [{"source_name": "mitre-attack", "external_id": wrong}]})


@pytest.mark.parametrize(
    "refs",
    [
        None,
        True,
        1,
        "mitre-attack",
        {},
        [None],
        [True],
        [[]],
        [{}],
        [{"source_name": None}],
        [{"source_name": True}],
        [{"source_name": []}],
        [{"source_name": "x" * (MAX_REFERENCE_SOURCE_NAME + 1)}],
        [{"source_name": "other"}] * (MAX_EXTERNAL_REFERENCES + 1),
        [{"source_name": "mitre-attack", **{str(i): i for i in range(MAX_EXTERNAL_REFERENCE_FIELDS)}}],
    ],
)
def test_external_reference_shape_and_budgets(refs: object) -> None:
    with pytest.raises(AttackIdentityError, match="external_references"):
        _ext_id({"type": "attack-pattern", "external_references": refs})


def test_external_reference_exact_bounds_and_unconsumed_types() -> None:
    ref = {"source_name": "mitre-attack", "external_id": "T1059"}
    ref.update({str(i): None for i in range(MAX_EXTERNAL_REFERENCE_FIELDS - 2)})
    assert _ext_id({"type": "attack-pattern", "external_references": [ref] * MAX_EXTERNAL_REFERENCES}) == "T1059"
    assert _ext_id({"type": "attack-pattern", "external_references": [{"source_name": "x" * MAX_REFERENCE_SOURCE_NAME}]}) is None
    assert _ext_id({"type": "report", "external_references": None}) is None


@pytest.mark.parametrize("target", ["x1", "a1", "a2", "a3"])
def test_matrix_identity_checks_include_replacement_endpoints(target: str) -> None:
    data = bundle()
    obj = next(o for o in data["objects"] if o.get("id") == target)
    obj["external_references"].append({"source_name": "mitre-attack", "external_id": None})
    with pytest.raises(AttackIdentityError, match="external_id"):
        _reduce(data)


def test_matrix_missing_identity_and_unconsumed_metadata() -> None:
    from sigharvest.attack import InvalidMatrix

    data = bundle()
    next(o for o in data["objects"] if o.get("id") == "a3").pop("external_references")
    next(o for o in data["objects"] if o.get("id") == "a2").pop("external_references")
    data["objects"].append({"type": "report", "external_references": None})
    # Matrix/relationship references are not used as external identities.
    for obj in data["objects"]:
        if obj.get("type") in {"relationship", "x-mitre-matrix"}:
            obj["external_references"] = False
    reduced = _reduce(data)
    assert [row["id"] for row in reduced["techniques"]] == ["T1059"]
    assert reduced["replaced"] == {}
    next(o for o in data["objects"] if o.get("id") == "x1").pop("external_references")
    with pytest.raises(InvalidMatrix, match="canonical TA IDs"):
        _reduce(data)


@pytest.mark.parametrize("index", [0, 1, 2, 4, 5])
@pytest.mark.parametrize("field", ["revoked", "x_mitre_deprecated"])
@pytest.mark.parametrize("value", ["false", "true", 0, 1, None, [], {}, [False], {"private-canary": True}, 0.0])
def test_reduce_rejects_ambiguous_lifecycle(index, field, value):
    data = bundle()
    obj = data["objects"][index]
    obj[field] = value
    # An already retired object must not hide an invalid companion flag.
    obj["x_mitre_deprecated" if field == "revoked" else "revoked"] = True
    before = copy.deepcopy(data)
    with pytest.raises(SigharvestError, match=rf"{field}: expected boolean, got {type(value).__name__}") as error:
        _reduce(data)
    assert "private-canary" not in str(error.value)
    assert data == before


@pytest.mark.parametrize("field", ["revoked", "x_mitre_deprecated"])
@pytest.mark.parametrize("value", [None, False, True])
@pytest.mark.parametrize("index", [0, 1, 2, 5])
def test_reduce_boolean_lifecycle(index, field, value):
    from sigharvest.attack import InvalidMatrix

    data = bundle()
    expected = _reduce(data)
    if value is not None:  # None denotes omission only in this parameter table.
        data["objects"][index][field] = value
    before = copy.deepcopy(data)
    if value is True and index in (0, 1):
        reason = "target is revoked or deprecated" if index == 0 else "found 0"
        with pytest.raises(InvalidMatrix, match=reason):
            _reduce(data)
        assert data == before
        return
    actual = _reduce(data)
    if value is not True:
        assert actual == expected
    elif index == 2:
        assert [t["id"] for t in actual["techniques"]] == ["T1059.001"]
        assert actual["deprecated"] == (["T1059"] if field == "x_mitre_deprecated" else [])
    else:
        assert actual["replaced"] == {}
    assert data == before


def test_revoked_source_can_have_active_replacement():
    from sigharvest.attack import matrix_from_data

    data = bundle()
    assert data["objects"][4]["revoked"] is True
    matrix = matrix_from_data(_reduce(data))
    assert "T1086" not in matrix.techniques
    assert matrix.resolve("T1086") == "T1059.001"
    data["objects"][5]["revoked"] = True
    assert matrix_from_data(_reduce(data)).resolve("T1086") is None


def test_reducer_ignores_unused_extension_lifecycle():
    data = bundle()
    expected = _reduce(data)
    data["objects"] += [
        {"type": "x-unused-extension", "revoked": "false", "x_mitre_deprecated": None},
        {"type": "relationship", "relationship_type": "unconsumed", "revoked": []},
    ]
    assert _reduce(data) == expected


def test_invalid_lifecycle_cannot_publish_matrix(tmp_path, monkeypatch):
    from sigharvest.attack import cached_matrix, load_matrix

    data = bundle()
    data["objects"][5]["revoked"] = "false"

    mock_bundle_http(monkeypatch, data)
    ws = Workspace(tmp_path)
    with pytest.raises(SigharvestError, match="revoked: expected boolean, got str"):
        load_matrix(ws)
    assert not (ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json").exists()
    assert cached_matrix(ws) is None


MATRIX_FAILURES = {
    "no-matrix": "found 0",
    "two-matrices": "found 2",
    "retired-matrix": "found 0",
    "deprecated-matrix": "found 0",
    "foreign-matrix": "found 0",
    "unscoped-matrix": "found 0",
    "scalar-domain": "found 0",
    "missing-refs": "nonempty list",
    "null-refs": "nonempty list",
    "scalar-refs": "nonempty list",
    "mapping-refs": "nonempty list",
    "empty-refs": "nonempty list",
    "nontext-ref": "must be nonblank printable text",
    "mapping-ref": "must be nonblank printable text",
    "empty-ref": "must be nonblank printable text",
    "padded-ref": "must be nonblank printable text",
    "control-ref": "must be nonblank printable text",
    "missing-target": "target is missing",
    "wrong-type": "target is not an x-mitre-tactic",
    "revoked-target": "target is revoked or deprecated",
    "deprecated-target": "target is revoked or deprecated",
    "duplicate-ref": "repeats an earlier reference",
    "invalid-tactic-id": "invalid MITRE ID for object type",
    "invalid-tactic-name": "invalid tactic shortname or name",
}


def break_matrix(data: dict, case: str) -> None:
    """Perturb only matrix structure; also used by offline refresh tests."""
    objects = data["objects"]
    matrix = next(o for o in objects if o.get("type") == "x-mitre-matrix")
    tactic = next(o for o in objects if o.get("type") == "x-mitre-tactic")
    if case == "no-matrix":
        objects.remove(matrix)
    elif case == "two-matrices":
        objects.append(matrix | {"id": "m2"})
    elif case in {"retired-matrix", "deprecated-matrix"}:
        matrix["revoked" if case == "retired-matrix" else "x_mitre_deprecated"] = True
    elif case == "foreign-matrix":
        matrix["x_mitre_domains"] = ["mobile-attack", "ics-attack"]
    elif case == "unscoped-matrix":
        del matrix["x_mitre_domains"]
    elif case == "scalar-domain":
        matrix["x_mitre_domains"] = "enterprise-attack"
    elif case == "missing-refs":
        del matrix["tactic_refs"]
    elif case in {"null-refs", "scalar-refs", "mapping-refs", "empty-refs"}:
        matrix["tactic_refs"] = {"null-refs": None, "scalar-refs": "x1", "mapping-refs": {"x1": 1}, "empty-refs": []}[case]
    elif case in {"nontext-ref", "mapping-ref", "empty-ref", "padded-ref", "control-ref", "missing-target"}:
        value = {"nontext-ref": 17, "mapping-ref": {}, "empty-ref": "", "padded-ref": " x1", "control-ref": "x\n1", "missing-target": "absent"}[case]
        matrix["tactic_refs"].append(value)
    elif case == "wrong-type":
        tactic["type"] = "intrusion-set"
    elif case in {"revoked-target", "deprecated-target"}:
        tactic["revoked" if case == "revoked-target" else "x_mitre_deprecated"] = True
    elif case == "duplicate-ref":
        matrix["tactic_refs"] *= 2
    elif case == "invalid-tactic-id":
        tactic["external_references"][0]["external_id"] = "G0001"
    elif case == "invalid-tactic-name":
        tactic["name"] = None
    else:
        raise AssertionError(case)


@pytest.mark.parametrize("case,reason", MATRIX_FAILURES.items())
@pytest.mark.parametrize("reverse", [False, True])
def test_source_matrix_rejected_before_reduction(case, reason, reverse):
    from sigharvest.attack import InvalidMatrix

    data = bundle()
    break_matrix(data, case)
    if reverse:
        data["objects"].reverse()
    error_type = AttackIdentityError if case == "invalid-tactic-id" else InvalidMatrix
    with pytest.raises(error_type, match=reason):
        _reduce(data)


def test_matrix_order_and_complete_valid_parity():
    import copy
    import random

    from sigharvest.attack import matrix_from_data

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
    data["objects"][1]["tactic_refs"] = ["x1", "x2"]
    # Foreign and retired matrices cannot compete with the explicit Enterprise matrix.
    data["objects"] += [
        {"type": "x-mitre-matrix", "id": "mobile", "x_mitre_domains": ["mobile-attack"]},
        {"type": "x-mitre-matrix", "id": "ics", "x_mitre_domains": ["ics-attack"]},
        {"type": "x-mitre-matrix", "id": "old", "x_mitre_domains": ["enterprise-attack"], "revoked": True},
    ]
    expected = {
        "version": ATTACK_VERSION,
        "tactics": [["execution", "Execution", "TA0002"], ["discovery", "Discovery", "TA0007"]],
        "techniques": [
            {"id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["execution"], "parent": None},
            {"id": "T1059.001", "name": "PowerShell", "tactics": ["execution"], "parent": "T1059"},
        ],
        "replaced": {"T1086": "T1059.001"},
        "deprecated": [],
    }
    untouched = copy.deepcopy(data)
    for mode in range(4):
        permuted = copy.deepcopy(data)
        if mode == 1:
            permuted["objects"].reverse()
        elif mode > 1:
            random.Random(mode).shuffle(permuted["objects"])
        assert _reduce(permuted) == expected
        assert matrix_from_data(_reduce(permuted)) == matrix_from_data(expected)
    assert data == untouched
    data["objects"][1]["tactic_refs"].reverse()
    assert _reduce(data) == expected | {"tactics": list(reversed(expected["tactics"]))}


def test_matrix_reference_limits(monkeypatch):
    from sigharvest import attack

    data = bundle()
    monkeypatch.setattr(attack, "MAX_MATRIX_TACTIC_REFS", 1)
    monkeypatch.setattr(attack, "MAX_TACTIC_REF_LENGTH", 2)
    assert attack._reduce(data)["tactics"] == [["execution", "Execution", "TA0002"]]
    data["objects"][1]["tactic_refs"].append("x1")
    with pytest.raises(attack.InvalidMatrix, match="at most 1 references"):
        attack._reduce(data)
    data["objects"][1]["tactic_refs"] = ["xxx"]
    with pytest.raises(attack.InvalidMatrix, match="at most 2 characters"):
        attack._reduce(data)


@pytest.mark.parametrize("case,reason", MATRIX_FAILURES.items())
def test_invalid_source_matrix_never_publishes_cache(tmp_path, monkeypatch, case, reason):
    from sigharvest.attack import AttackCacheError, cached_matrix, load_matrix

    data = bundle()
    break_matrix(data, case)

    ws = Workspace(tmp_path)
    mock_bundle_http(monkeypatch, data)
    error_type = AttackIdentityError if case == "invalid-tactic-id" else AttackCacheError
    with pytest.raises(error_type, match=reason) as error:
        load_matrix(ws)
    if case == "invalid-tactic-id":
        assert "Supply a corrected Enterprise" in str(error.value)
    else:
        assert "Supply a complete Enterprise" in str(error.value)
        assert "no cache was published" in str(error.value)
    assert cached_matrix(ws) is None
    assert not list(ws.cache.rglob("*.json"))


def test_replacement_target_identity_and_repeated_revision():
    data = bundle()
    rel = data["objects"][-1]
    rel["id"] = "relationship--same"
    # Repeated observations of one revision are harmless too. Selecting between
    # differing revisions belongs to the not-yet-integrated revision selector.
    data["objects"].append(dict(rel))
    target = next(o for o in data["objects"] if o.get("id") == "a2")
    data["objects"].append(target | {"id": "a2-other", "revoked": True})
    data["objects"].append(rel | {"id": "relationship--other", "target_ref": "a2-other"})
    for objects in (data["objects"], list(reversed(data["objects"]))):
        assert _reduce(data | {"objects": objects})["replaced"] == {"T1086": "T1059.001"}


@pytest.mark.parametrize("terminal,status", [("a3", "cycle"), ("absent", "unknown"), ("deprecated", "deprecated"), ("a1", "replaced")])
def test_replacement_reduction_preserves_terminal_diagnostics(terminal, status):
    from sigharvest.attack import matrix_from_data, normalise_technique

    data = bundle()
    old = next(o for o in data["objects"] if o.get("id") == "a3")
    data["objects"].extend(
        [
            old | {"id": "absent", "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}]},
            old | {"id": "deprecated", "external_references": [{"source_name": "mitre-attack", "external_id": "T1064"}], "x_mitre_deprecated": True},
            {"type": "relationship", "relationship_type": "revoked-by", "source_ref": "a2", "target_ref": terminal},
            {"type": "relationship", "relationship_type": "revoked-by", "source_ref": "a3", "target_ref": "unresolvable-stix-ref"},
        ]
    )
    for objects in (data["objects"], list(reversed(data["objects"]))):
        matrix = matrix_from_data(_reduce(data | {"objects": objects}))
        identity = normalise_technique("T1086", matrix)
        assert identity.status == status
        assert identity.current_id == ("T1059" if status == "replaced" else None)


def test_conflicting_first_acquisition_does_not_publish(tmp_path, monkeypatch):
    from sigharvest.attack import AttackCacheError, cached_matrix, load_matrix

    data = bundle()
    data["objects"].append(data["objects"][-1] | {"id": "relationship--other", "target_ref": "a1"})

    mock_bundle_http(monkeypatch, data)
    ws = Workspace(tmp_path)
    with pytest.raises(AttackCacheError, match="candidate was not published"):
        load_matrix(ws)
    assert not (ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json").exists()
    monkeypatch.setattr("sigharvest.attack_io.build_opener", lambda *a, **kw: pytest.fail("passive read downloaded"))
    assert cached_matrix(ws) is None


@pytest.mark.parametrize(
    "kind,identity",
    [("attack-pattern", "T1059"), ("x-mitre-tactic", "TA0002"), ("intrusion-set", "G٠٠٠١"), ("malware", "S0001"), ("tool", "S０００１")],
)
def test_equal_external_id_reuses_only_typed_regex(monkeypatch: pytest.MonkeyPatch, kind: str, identity: str) -> None:
    from sigharvest import attack

    pattern = attack._EXTERNAL_ID_PATTERNS[kind]
    calls = []

    class Pattern:
        def fullmatch(self, value):
            calls.append(value)
            return pattern.fullmatch(value)

    monkeypatch.setitem(attack._EXTERNAL_ID_PATTERNS, kind, Pattern())
    refs = [{"source_name": "mitre-attack", "external_id": identity} for _ in range(MAX_EXTERNAL_REFERENCES)]
    obj = {"type": kind, "external_references": refs}
    assert _ext_id(obj) == identity
    assert calls == [identity]
    # A repeated value never exempts its reference envelope from validation.
    refs[-1].update({str(i): None for i in range(MAX_EXTERNAL_REFERENCE_FIELDS)})
    with pytest.raises(AttackIdentityError, match="field count exceeds limit"):
        _ext_id(obj)
    assert calls == [identity, identity]


@pytest.mark.parametrize("position", [0, MAX_EXTERNAL_REFERENCES // 2, MAX_EXTERNAL_REFERENCES - 1])
@pytest.mark.parametrize(
    "fault,problem",
    [
        ({"source_name": "mitre-attack", "external_id": "T1105"}, "conflicting MITRE IDs"),
        ({"source_name": "mitre-attack", "external_id": "G0001"}, "invalid MITRE ID for object type"),
        ({"source_name": "mitre-attack", "external_id": None}, "expected a string MITRE ID"),
        ({"source_name": ""}, "expected a nonempty bounded string"),
        ({"source_name": "citation", **{str(i): None for i in range(MAX_EXTERNAL_REFERENCE_FIELDS)}}, "field count exceeds limit"),
    ],
)
def test_dense_references_keep_error_at_every_position(position: int, fault: dict, problem: str) -> None:
    refs = [{"source_name": "mitre-attack", "external_id": "T1059"} for _ in range(MAX_EXTERNAL_REFERENCES)]
    refs[position] = fault
    with pytest.raises(AttackIdentityError, match=problem):
        _ext_id({"type": "attack-pattern", "external_references": refs})


def test_external_id_alias_is_revalidated_between_calls() -> None:
    ref = {"source_name": "mitre-attack", "external_id": "T1059"}
    obj = {"type": "attack-pattern", "external_references": [ref, ref]}
    assert _ext_id(obj) == "T1059"
    ref["external_id"] = "T1105"
    assert _ext_id(obj) == "T1105"
    ref["external_id"] = "G0001"
    with pytest.raises(AttackIdentityError, match="invalid MITRE ID for object type"):
        _ext_id(obj)


def test_coverage_counts_and_layer(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    (repo / "rules" / "ps.yml").write_text(
        "title: PS\nid: 0a5c2b1e-0000-4000-8000-0000000000aa\ntags: [attack.t1086]\nlogsource: {product: windows, category: ps_script}\n"
        "detection:\n  sel:\n    ScriptBlockText|contains: iex\n  condition: sel\n"
    )
    import subprocess

    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "ps"], cwd=repo, check=True)
    ws = workspace(tmp_path, repo)
    cache = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    cache.parent.mkdir(parents=True)
    cache.write_text(json.dumps(_reduce(bundle())))
    assert sync_all(ws)[0].status == "ok"
    S = open_db(ws, migrate=True)
    with S() as s:
        rebuild(s)
        cov = compute(ws, s)
    # the revoked T1086 tag counts for T1059.001 and its parent T1059
    assert cov.families == {"T1059.001": 1, "T1059": 1}
    layer = navigator_layer(cov)
    assert {t["techniqueID"] for t in layer["techniques"]} == {"T1059", "T1059.001"} and "MITRE" in layer["description"]


@pytest.fixture
def coverage_corpus(tmp_path: Path):
    ws = Workspace(tmp_path / "coverage")
    ws.root.mkdir()
    save_sources(ws, [])
    seed_attack(ws)
    path = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    data = json.loads(path.read_text())
    # One parent belongs to two tactics; one family contributes to two parents.
    data["techniques"][3]["tactics"].append("discovery")
    path.write_text(json.dumps(data))
    factory = open_db(ws, migrate=True)
    tags = [
        ["attack.t1086", "attack.t1059.001", "attack.t1033"],
        ["attack.t1059.001"],
        ["attack.t9999", "attack.t1064"],
        ["attack.ics.t0855", "attack.mobile.t1409", "internal.lolbas"],
        [],
        ["attack.t1105"],
        ["attack.t1105"],
        ["attack.t1105"],
        ["attack.t1105"],
    ]
    with factory() as s:
        for i, values in enumerate(tags, 1):
            key = f"{i:064x}"
            s.add(RuleVersion(id=i, content_hash=key, logic_hash=key, rule_id=key[:36], kind="rule", raw=""))
            s.flush()
            s.add(
                LogicGroup(
                    id=i,
                    logic_hash=key,
                    canonical_version_id=i,
                    canonical_source="canonical",
                    rule_id=key[:36],
                    kind="rule",
                    title=f"Rule {i}",
                    product="windows" if i == 1 else "linux",
                    category="process_creation",
                    sources=["selected-source"],
                    tags=values,
                    family_id=1 if i < 3 else i,
                    score=10,
                    validation="ok",
                    converts=["splunk"],
                    status={6: "deprecated", 7: "unsupported"}.get(i),
                    junk=i in (8, 9),
                )
            )
        s.commit()
    return ws, factory


@pytest.mark.parametrize("width", [80, 120])
def test_cli_coverage_units_filters_details_and_navigator(coverage_corpus, monkeypatch, tmp_path: Path, width: int):
    ws, factory = coverage_corpus
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    monkeypatch.setattr(cli_reports, "console", Console(width=width, highlight=False))
    runner = CliRunner()
    with factory() as s:
        cov = compute(ws, s)
    assert cov.rules_total == 5 and cov.rules_with_tags == 3
    assert cov.families == {"T1059": 1, "T1059.001": 1, "T1033": 1}
    expected_layer = navigator_layer(cov)
    output = tmp_path / "layer.json"
    res = runner.invoke(app, ["coverage", "--navigator", str(output)])
    assert res.exit_code == 0, res.exception
    assert "Tagged unique logics: 3/5 selected" in res.output
    assert "Parent techniques covered: 2/5" in res.output
    assert "Subtechniques covered: 1/2" in res.output
    assert "best covered parent" not in res.output
    discovery = next(line for line in res.output.splitlines() if "Discovery" in line)
    assert [cell.strip() for cell in discovery.split("│")[1:-1]] == ["Discovery", "2/2", "2"]
    assert "unique rules" not in res.output and "rule families (sum)" not in res.output
    assert "not demonstrated detection" in res.output
    assert "internal.lolbas" in res.output and "T1086 -> T1059.001" in res.output
    assert "ICS ATT&CK" in res.output and "mobile ATT&CK" in res.output
    assert "T9999 (unknown" in res.output and "T1064 (deprecated" in res.output
    assert max(cell_len(line) for line in res.output.splitlines()) <= width
    assert json.loads(output.read_text()) == expected_layer
    detail_layer = tmp_path / "details.json"
    detailed = runner.invoke(app, ["coverage", "--details", "--navigator", str(detail_layer)])
    assert detailed.exit_code == 0, detailed.exception
    assert "best covered parent" in detailed.output and "Command and Scripting" in detailed.output
    assert json.loads(detail_layer.read_text()) == expected_layer
    filtered = runner.invoke(app, ["coverage", "--product", "windows", "--source", "selected-source", "--backend", "splunk", "--validation", "ok"])
    assert filtered.exit_code == 0, filtered.exception
    assert "product=windows" in filtered.output and "source=selected-source" in filtered.output
    assert "Tagged unique logics: 1/1 selected" in filtered.output
    assert "Parent techniques covered: 2/5" in filtered.output
    assert "Subtechniques covered: 1/2" in filtered.output
    assert "canonical copy" in filtered.output
    empty = runner.invoke(app, ["coverage", "--product", "no-such-product", "--gaps"])
    assert empty.exit_code == 0, empty.exception
    assert "Tagged unique logics: 0/0 selected" in empty.output
    assert "Parent techniques covered: 0/5" in empty.output
    assert "Subtechniques covered: 0/2" in empty.output
    for tech in ATTACK_FIXTURE["techniques"]:
        assert tech["id"] in empty.output


@pytest.mark.parametrize("width", [80, 120])
@pytest.mark.parametrize("minimum", [0, 1, 2])
def test_cli_gaps_complete_and_literal(coverage_corpus, monkeypatch, width: int, minimum: int):
    ws, factory = coverage_corpus
    # Exercise the real local catalog reader, not a download or mocked matrix.
    path = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    data = json.loads(path.read_text())
    long_name = "[bold]" + "界" * 90 + "[/bold] END-OF-NAME"
    for i in range(1200, 1250):
        data["techniques"].append({"id": f"T{i}", "name": long_name, "tactics": ["discovery", "execution"], "parent": None})
    data["tactics"][0][1] = "[red]" + "界" * 50 + "[/red] END-OF-TACTIC"
    path.write_text(json.dumps(data))
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    monkeypatch.setattr(cli_reports, "console", Console(width=width, highlight=False))
    with factory() as s:
        expected = compute(ws, s)
    result = CliRunner().invoke(app, ["coverage", "--gaps", "--min", str(minimum), "--details"])
    assert result.exit_code == 0, result.exception
    assert max(cell_len(line) for line in result.output.splitlines()) <= width
    assert "…" not in result.output and "..." not in result.output
    assert "[red]" in result.output and "[/red]" in result.output and "END-OF-TACTIC" in result.output
    gap_text = result.output.split("Gaps:", 1)[1].split("Non-current tags", 1)[0]
    import re

    ids = re.findall(r"│ (T\d{4}(?:\.\d{3})?)\s+│", gap_text)
    assert ids == sorted(tid for tid in expected.matrix.techniques if expected.families.get(tid, 0) < minimum)
    assert "organization-wide detection gaps" in " ".join(result.output.split())
    if minimum:
        assert gap_text.count("END-OF-NAME") == 50
        assert gap_text.count("[bold]") == gap_text.count("[/bold]") == 50


def test_cli_empty_corpus_and_all_interpretations(coverage_corpus, monkeypatch):
    ws, factory = coverage_corpus
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    monkeypatch.setattr(cli_reports, "console", Console(width=80, highlight=False))
    with factory() as s:
        groups = list(s.scalars(select(LogicGroup)))
        for group in groups:
            s.delete(group)
        s.commit()
    result = CliRunner().invoke(app, ["coverage"])
    assert result.exit_code == 0 and "Tagged unique logics: 0/0 selected" in result.output
    with factory() as s:
        cov = compute(ws, s, GroupFilters())
    for i in range(30):
        cov.normalisation[str(i)] = {"status": "unknown", "rules": 1, "original": str(i), "label": f"unknown-{i:02}"}
    with cli_reports.console.capture() as capture:
        cli_reports._print_coverage(cov, selection=[], details=True)
    assert all(f"unknown-{i:02}" in capture.get() for i in range(30))


def test_coverage_tag_sets_match_cell_unions_and_resolve_once(monkeypatch):
    from sigharvest.attack import Matrix, Technique, coverage_tag_sets, matrix_from_data

    matrix = matrix_from_data(_reduce(bundle()))
    matrix.replaced.update({"T1000": "T1086", "T1001": "T9999", "T1002": "T1003", "T1003": "T1002"})
    matrix.techniques["T2000"] = Technique("T2000", "Unrelated", ["execution"], None)
    expected = {
        t.id: sorted(
            tid
            for tid in {*matrix.techniques, *matrix.replaced}
            if (resolved := matrix.resolve(tid)) == t.id or (resolved is not None and matrix.techniques[resolved].parent == t.id)
        )
        for t in matrix.techniques.values()
    }
    calls = []
    original = Matrix.resolve

    def resolve(self, tid):
        calls.append(tid)
        return original(self, tid)

    monkeypatch.setattr(Matrix, "resolve", resolve)
    assert coverage_tag_sets(matrix) == expected
    assert len(calls) == len(set(calls)) == len({*matrix.techniques, *matrix.replaced})
    assert expected["T2000"] == ["T2000"]


def _invalid_catalog(case):
    """Independent malformed reduced inputs, including valid JSON of wrong types."""
    from copy import deepcopy

    data = {"version": ATTACK_VERSION, **deepcopy(ATTACK_FIXTURE)}
    if case.startswith("root-"):
        return {"root-null": None, "root-list": [], "root-string": "catalog", "root-number": 1}[case]
    if case.startswith("missing-"):
        del data[case.removeprefix("missing-")]
    elif case.startswith("section-"):
        data[case.removeprefix("section-")] = None
    elif case.startswith("field-"):
        del data["techniques"][0][case.removeprefix("field-")]
    elif case == "version":
        data["version"] = "19.0"
    elif case == "version-type":
        data["version"] = 20
    elif case in {"null", "scalar", "array"}:
        data["techniques"].append({"null": None, "scalar": 12, "array": []}[case])
    elif case in {"duplicate", "duplicate-changed", "casing"}:
        item = dict(data["techniques"][0])
        if case == "duplicate-changed":
            item["name"] = "Other name"
        if case == "casing":
            item["id"] = item["id"].lower()
        data["techniques"].append(item)
    elif case in {"name-null", "name-blank", "name-control", "name-padding", "name-long"}:
        data["techniques"][0]["name"] = {
            "name-null": None,
            "name-blank": "",
            "name-control": "a\nb",
            "name-padding": " name",
            "name-long": "x" * 1025,
        }[case]
    elif case == "id-unicode":
        data["techniques"][0]["id"] = "T١٠٠٣"
    elif case == "unknown-field":
        data["techniques"][0]["extra"] = 1
    elif case == "unknown-section":
        data["extra"] = []
    elif case in {"parent-wrong", "parent-null", "parent-array", "parent-child"}:
        data["techniques"][1]["parent"] = {"parent-wrong": "T1059", "parent-null": None, "parent-array": [], "parent-child": "T1003.001"}[case]
    elif case == "parent-missing":
        del data["techniques"][0]
    elif case == "parent-top":
        data["techniques"][0]["parent"] = "T1003"
    elif case in {"phases-null", "phases-scalar", "phases-member", "phases-unknown", "phases-empty", "phases-duplicate"}:
        data["techniques"][0]["tactics"] = {
            "phases-null": None,
            "phases-scalar": "execution",
            "phases-member": [{}],
            "phases-unknown": ["missing"],
            "phases-empty": [],
            "phases-duplicate": ["execution", "execution"],
        }[case]
    elif case in {"tactic-null", "tactic-short-row", "tactic-string-row"}:
        data["tactics"][0] = {"tactic-null": None, "tactic-short-row": ["a", "b"], "tactic-string-row": "abc"}[case]
    elif case == "tactic-duplicate":
        data["tactics"].append(data["tactics"][0][:])
    elif case == "tactic-id-duplicate":
        data["tactics"][1][2] = data["tactics"][0][2]
    elif case == "tactic-short-duplicate":
        data["tactics"][1][0] = data["tactics"][0][0]
    elif case in {"tactic-casing", "tactic-name", "tactic-id"}:
        pos, value = {"tactic-casing": (0, "Discovery"), "tactic-name": (1, None), "tactic-id": (2, "ta0007")}[case]
        data["tactics"][0][pos] = value
    elif case == "replacement-value":
        data["replaced"]["T1086"] = []
    elif case == "replacement-casing":
        data["replaced"]["t1086"] = "T1059"
    elif case == "deprecated-duplicate":
        data["deprecated"] *= 2
    elif case == "deprecated-casing":
        data["deprecated"].append("t1064")
    elif case == "deprecated-member":
        data["deprecated"].append({})
    else:
        raise AssertionError(case)
    return data


INVALID_CATALOG_CASES = [
    "root-null",
    "root-list",
    "root-string",
    "root-number",
    "missing-version",
    "missing-tactics",
    "missing-techniques",
    "section-tactics",
    "section-techniques",
    "section-replaced",
    "section-deprecated",
    "version",
    "version-type",
    "field-id",
    "field-name",
    "field-tactics",
    "field-parent",
    "null",
    "scalar",
    "array",
    "duplicate",
    "duplicate-changed",
    "casing",
    "name-null",
    "name-blank",
    "name-control",
    "name-padding",
    "name-long",
    "id-unicode",
    "unknown-field",
    "unknown-section",
    "parent-wrong",
    "parent-null",
    "parent-array",
    "parent-child",
    "parent-missing",
    "parent-top",
    "phases-null",
    "phases-scalar",
    "phases-member",
    "phases-unknown",
    "phases-empty",
    "phases-duplicate",
    "tactic-null",
    "tactic-short-row",
    "tactic-string-row",
    "tactic-duplicate",
    "tactic-id-duplicate",
    "tactic-short-duplicate",
    "tactic-casing",
    "tactic-name",
    "tactic-id",
    "replacement-value",
    "replacement-casing",
    "deprecated-duplicate",
    "deprecated-casing",
    "deprecated-member",
]


@pytest.mark.parametrize("case", INVALID_CATALOG_CASES)
def test_common_catalog_admission(tmp_path, monkeypatch, case):
    from sigharvest.attack import AttackCacheError, InvalidCatalog, cached_matrix, load_matrix, matrix_from_data, normalise_technique
    from sigharvest.attack_score import Context, credit, explanation

    ws = Workspace(tmp_path)
    seed_attack(ws)
    path = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    data = _invalid_catalog(case)
    path.write_text(json.dumps(data))
    payload, before = path.read_bytes(), path.stat()
    with monkeypatch.context() as guarded:
        guarded.setattr("sigharvest.attack_io.build_opener", lambda *a, **kw: pytest.fail("catalog read attempted a download"))
        guarded.setattr(Path, "write_text", lambda *a, **kw: pytest.fail("catalog read attempted a write"))
        guarded.setattr(Path, "write_bytes", lambda *a, **kw: pytest.fail("catalog read attempted a write"))
        with pytest.raises(InvalidCatalog):
            matrix_from_data(data)
        assert cached_matrix(ws) is None
        assert normalise_technique("T1086", cached_matrix(ws)).status == "unverified"
        context = Context(cached_matrix(ws))
        assert credit(["attack.t9999"], context) == 4
        assert "Unverified" in explanation(["attack.t9999"], context, context.fingerprint)
        with pytest.raises(AttackCacheError, match="Replace it with a verified Enterprise"):
            load_matrix(ws)
    assert path.read_bytes() == payload
    assert path.stat().st_mtime_ns == before.st_mtime_ns
    seed_attack(ws)
    assert cached_matrix(ws) == load_matrix(ws)
    assert cached_matrix(ws).resolve("T1086") == "T1059.001"


@pytest.mark.parametrize(
    "payload",
    [
        '{"version":"19.0","version":"20.0","tactics":[],"techniques":[]}',
        '{"version":"20.0","replaced":{"T1086":"T1059","T1086":"T1059"}}',
        "[",
        "[" * 1100 + "0" + "]" * 1100,
    ],
)
def test_invalid_wire_json_is_controlled(tmp_path, payload):
    from sigharvest.attack import AttackCacheError, cached_matrix, load_matrix

    ws = Workspace(tmp_path)
    seed_attack(ws)
    path = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    path.write_text(payload)
    assert cached_matrix(ws) is None
    with pytest.raises(AttackCacheError):
        load_matrix(ws)


def test_catalog_limits_and_optional_retirement_sections(tmp_path, monkeypatch):
    from copy import deepcopy

    from sigharvest import attack

    ws = Workspace(tmp_path)
    seed_attack(ws)
    path = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    data = json.loads(path.read_bytes())
    matrix = attack.matrix_from_data(data)
    assert attack.cached_matrix(ws) == attack.load_matrix(ws) == matrix
    assert data == {"version": ATTACK_VERSION, **ATTACK_FIXTURE}
    legacy = deepcopy(data)
    del legacy["replaced"], legacy["deprecated"]
    assert attack.matrix_from_data(legacy).techniques == matrix.techniques
    assert attack.matrix_from_data(legacy).replaced == {}
    with pytest.raises(attack.InvalidCatalog, match="version"):
        attack.matrix_from_data(data, version="19.0")
    size = path.stat().st_size
    monkeypatch.setattr(attack, "MAX_CATALOG_BYTES", size)
    assert attack.cached_matrix(ws) is not None
    path.write_bytes(path.read_bytes() + b" ")
    assert attack.cached_matrix(ws) is None
    with pytest.raises(attack.AttackCacheError):
        attack.load_matrix(ws)
    with pytest.raises(attack.InvalidCatalog, match="byte limit"):
        attack.matrix_from_data(data | {"techniques": [data["techniques"][0] | {"name": "x" * 1024}, *data["techniques"][1:]]})
    monkeypatch.setattr(attack, "MAX_CATALOG_OBJECTS", 1)
    with pytest.raises(attack.InvalidCatalog, match="object limit"):
        attack.matrix_from_data(data)


@pytest.mark.parametrize("terminal,status", [("T1086", "cycle"), ("T9999", "unknown"), ("T1064", "deprecated")])
def test_retirement_diagnostics_survive_catalog_admission(tmp_path, terminal, status):
    from sigharvest.attack import cached_matrix, load_matrix, normalise_technique
    from sigharvest.attack_score import Context, credit

    ws = Workspace(tmp_path)
    seed_attack(ws)
    path = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    data = json.loads(path.read_bytes())
    # Exact IDs can be mentioned in live and retirement sections. Existing
    # replacement/deprecation precedence must survive structural admission.
    data["replaced"]["T1059.001"] = terminal
    path.write_text(json.dumps(data))
    matrix = cached_matrix(ws)
    assert matrix is not None and matrix == load_matrix(ws)
    assert normalise_technique("T1086", matrix).status == status
    assert normalise_technique("T1086", matrix).current_id is None
    assert credit(["attack.t1086"], Context(matrix)) == 0


def test_catalog_revision_includes_ctime_and_recovers(tmp_path):
    import os

    from sigharvest.attack import AttackCacheError, cached_matrix, coverage_key, load_matrix

    ws = Workspace(tmp_path)
    seed_attack(ws)
    path = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    good = path.read_bytes()
    before, key = path.stat(), coverage_key(ws)
    assert cached_matrix(ws) is not None
    path.write_bytes(good.replace(b'"20.0"', b'"19.0"'))
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert coverage_key(ws) != key
    assert cached_matrix(ws) is None
    with pytest.raises(AttackCacheError):
        load_matrix(ws)
    path.write_bytes(good)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert cached_matrix(ws) == load_matrix(ws)


def test_passive_absence_and_nonregular_catalogs(tmp_path, monkeypatch):
    import os

    from sigharvest.attack import AttackCacheError, cached_matrix, load_matrix

    ws = Workspace(tmp_path)
    monkeypatch.setattr("sigharvest.attack_io.build_opener", lambda *a, **kw: pytest.fail("unexpected acquisition"))
    assert cached_matrix(ws) is None
    assert not ws.cache.exists()
    path = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    path.parent.mkdir(parents=True)
    for kind in ("directory", "fifo", "symlink"):
        if kind == "directory":
            path.mkdir()
        elif kind == "fifo":
            os.mkfifo(path)
        else:
            path.symlink_to(path.parent / "absent")
        assert cached_matrix(ws) is None
        with pytest.raises(AttackCacheError):
            load_matrix(ws)
        path.rmdir() if kind == "directory" else path.unlink()


def test_explicit_absent_cache_acquisition_remains_separate(tmp_path, monkeypatch):
    from sigharvest.attack import cached_matrix, load_matrix, matrix_from_data

    ws = Workspace(tmp_path)
    calls = []
    response = mock_bundle_http(monkeypatch, bundle())

    def fetch(*args, **kwargs):
        calls.append(args)
        return response

    monkeypatch.setattr("sigharvest.attack_io.build_opener", lambda *a: SimpleNamespace(open=fetch))
    assert cached_matrix(ws) is None and not calls
    assert load_matrix(ws) == matrix_from_data(_reduce(bundle()))
    assert len(calls) == 1
    assert cached_matrix(ws) == load_matrix(ws)
    assert len(calls) == 1


@pytest.mark.parametrize("field", ["version", "id", "replacement"])
def test_duplicate_json_members_cannot_be_silently_overwritten(tmp_path, field):
    from sigharvest.attack import AttackCacheError, cached_matrix, load_matrix

    ws = Workspace(tmp_path)
    seed_attack(ws)
    path = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    original = path.read_text()
    member = {
        "version": f'"version": "{ATTACK_VERSION}"',
        "id": '"id": "T1003"',
        "replacement": '"T1086": "T1059.001"',
    }[field]
    payload = original.replace(member, member + ", " + member, 1)
    assert payload != original
    # Ordinary JSON decoding would hide the duplicated declaration entirely.
    assert json.loads(payload) == json.loads(original)
    path.write_text(payload)
    assert cached_matrix(ws) is None
    with pytest.raises(AttackCacheError):
        load_matrix(ws)


def matrix_reference_bundle() -> dict:
    """Three ordered tactics for independent first/middle/last fault probes."""
    data = bundle()
    tactic = data["objects"][0]
    for number in (2, 3):
        data["objects"].append(
            tactic
            | {
                "id": f"x{number}",
                "name": f"Tactic {number}",
                "x_mitre_shortname": f"tactic-{number}",
                "external_references": [{"source_name": "mitre-attack", "external_id": f"TA{number + 100:04d}"}],
            }
        )
    data["objects"][1]["tactic_refs"] = ["x3", "x1", "x2"]
    return data


def break_reference_at(data: dict, fault: str, position: int) -> int:
    matrix = next(o for o in data["objects"] if o.get("type") == "x-mitre-matrix")
    refs = matrix["tactic_refs"]
    target = next(o for o in data["objects"] if o.get("id") == refs[position])
    if fault == "missing":
        refs[position] = "absent"
    elif fault == "wrong-type":
        target["type"] = "extension"
    elif fault in {"revoked", "x_mitre_deprecated"}:
        target[fault] = True
    elif fault == "duplicate":
        refs[position] = refs[0 if position else 1]
        return max(1, position)
    elif fault == "nontext":
        refs[position] = 7
    elif fault == "identity":
        target["external_references"][0]["external_id"] = "G0001"
    else:
        raise AssertionError(fault)
    return position


@pytest.mark.parametrize("position", [0, 1, 2])
@pytest.mark.parametrize("fault", ["missing", "wrong-type", "revoked", "x_mitre_deprecated", "duplicate", "nontext", "identity"])
def test_matrix_reference_fault_positions_and_mutation(fault, position):
    from sigharvest.attack import InvalidMatrix

    data = matrix_reference_bundle()
    before = copy.deepcopy(data)
    expected = _reduce(data)
    rejected_position = break_reference_at(data, fault, position)
    error = AttackIdentityError if fault == "identity" else InvalidMatrix
    reason = "invalid MITRE ID" if fault == "identity" else rf"tactic_refs\[{rejected_position}\]"
    with pytest.raises(error, match=reason):
        _reduce(data)  # Same bundle dict as the successful call; no identity cache.
    data["objects"][:] = before["objects"]
    assert _reduce(data) == expected


def test_technique_lifecycle_still_precedes_matrix_admission():
    from sigharvest.attack import InvalidMatrix

    data = matrix_reference_bundle()
    data["objects"][1]["tactic_refs"] = ["absent"]
    data["objects"].append({"type": "attack-pattern", "id": "last", "revoked": "false"})
    with pytest.raises(SigharvestError, match="revoked: expected boolean"):
        _reduce(data)
    data["objects"][-1]["revoked"] = False
    with pytest.raises(InvalidMatrix, match="target is missing"):
        _reduce(data)


def test_matrix_tactic_revision_order_is_unchanged():
    data = matrix_reference_bundle()
    duplicate = dict(data["objects"][0], name="Last active revision")
    data["objects"].append(duplicate)
    assert _reduce(data)["tactics"][1][1] == "Last active revision"
    duplicate["revoked"] = True
    assert _reduce(data)["tactics"][1][1] == "Execution"


@pytest.mark.slow
def test_matrix_reference_actual_bounds():
    from sigharvest.attack import MAX_MATRIX_TACTIC_REFS, MAX_TACTIC_REF_LENGTH, InvalidMatrix, matrix_from_data

    data = bundle()
    # TA IDs have four digits: 10,000 is the largest distinct valid tactic set.
    tactics = [
        {
            "type": "x-mitre-tactic",
            "id": f"ref-{i}",
            "name": f"Tactic {i}",
            "x_mitre_shortname": f"tactic-{i}",
            "external_references": [{"source_name": "mitre-attack", "external_id": f"TA{i:04d}"}],
        }
        for i in range(10000)
    ]
    tactics[2]["x_mitre_shortname"] = "execution"
    data["objects"] = [o for o in data["objects"] if o["type"] != "x-mitre-tactic"] + tactics
    matrix = data["objects"][0]
    matrix["tactic_refs"] = [o["id"] for o in reversed(tactics)]
    assert len(matrix_from_data(_reduce(data)).tactics) == 10000
    assert _reduce(data)["tactics"][0][2] == "TA9999"
    # At the list cap, admission reaches reference validation; cap+1 fails early.
    matrix["tactic_refs"] *= 2
    assert len(matrix["tactic_refs"]) == MAX_MATRIX_TACTIC_REFS
    with pytest.raises(InvalidMatrix, match=r"tactic_refs\[10000\] repeats"):
        _reduce(data)
    matrix["tactic_refs"].append("absent")
    with pytest.raises(InvalidMatrix, match="at most 20000 references"):
        _reduce(data)
    # Keep the techniques' execution phase declared while isolating ref length.
    tactics[2]["id"] = "x" * MAX_TACTIC_REF_LENGTH
    matrix["tactic_refs"] = [tactics[2]["id"]]
    assert len(_reduce(data)["tactics"]) == 1
    matrix["tactic_refs"][0] += "x"
    with pytest.raises(InvalidMatrix, match="at most 1024 characters"):
        _reduce(data)


SUBTECHNIQUE_FAILURES = {
    "flag-string": "expected a JSON boolean",
    "flag-null": "expected a JSON boolean",
    "flag-mismatch": "flag disagrees",
    "wrong-parent": "parent conflicts",
    "conflicting-edge": "parent conflicts",
    "missing-source": "identified attack-pattern",
    "missing-target": "identified attack-pattern",
    "wrong-source-type": "identified attack-pattern",
    "wrong-target-type": "identified attack-pattern",
    "unidentified-source": "identified attack-pattern",
    "unidentified-target": "identified attack-pattern",
    "self-loop": "self-loop",
    "parent-subtechnique": "parent must have a top-level",
    "source-parent": "source must have a subtechnique",
    "source-container": "bounded nonblank printable STIX reference",
    "target-container": "bounded nonblank printable STIX reference",
    "source-oversized": "bounded nonblank printable STIX reference",
    "target-oversized": "bounded nonblank printable STIX reference",
}


def declare_subtechniques(data: dict) -> dict:
    """Add consistent declarations to the legacy catalog/graph fixture."""
    for obj in data["objects"]:
        if obj.get("type") == "attack-pattern":
            obj["x_mitre_is_subtechnique"] = "." in _ext_id(obj)
    data["objects"].append({"type": "relationship", "relationship_type": "subtechnique-of", "source_ref": "a2", "target_ref": "a1"})
    return data


def break_subtechniques(data: dict, fault: str) -> None:
    objects = data["objects"]
    parent = next(o for o in objects if o.get("id") == "a1")
    child = next(o for o in objects if o.get("id") == "a2")
    edge = next(o for o in objects if o.get("relationship_type") == "subtechnique-of")
    if fault.startswith("flag-"):
        child["x_mitre_is_subtechnique"] = {"flag-string": "false", "flag-null": None, "flag-mismatch": False}[fault]
    elif fault in {"wrong-parent", "conflicting-edge"}:
        objects.append(parent | {"id": "other", "external_references": [{"source_name": "mitre-attack", "external_id": "T1106"}]})
        if fault == "wrong-parent":
            edge["target_ref"] = "other"
        else:
            objects.append(edge | {"target_ref": "other"})
    elif fault.startswith("missing-"):
        edge[fault.removeprefix("missing-") + "_ref"] = "private-canary-absent"
    elif fault.startswith("wrong-"):
        edge["source_ref" if "source" in fault else "target_ref"] = "x1"
    elif fault.startswith("unidentified-"):
        (child if fault.endswith("source") else parent).pop("external_references")
    elif fault.startswith(("retired-", "deprecated-")):
        (child if fault.endswith("source") else parent)["revoked" if fault.startswith("retired-") else "x_mitre_deprecated"] = True
    elif fault == "self-loop":
        edge["target_ref"] = "a2"
    elif fault == "parent-subtechnique":
        objects.append(child | {"id": "other-child", "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.002"}]})
        edge["target_ref"] = "other-child"
    elif fault == "source-parent":
        objects.append(parent | {"id": "other", "external_references": [{"source_name": "mitre-attack", "external_id": "T1106"}]})
        edge["source_ref"] = "other"
    else:
        edge["source_ref" if fault.startswith("source-") else "target_ref"] = [] if fault.endswith("container") else "private-canary" * 1024


@pytest.mark.parametrize("fault", ["retired-source", "retired-target", "deprecated-source", "deprecated-target"])
def test_subtechnique_edges_of_retired_techniques_are_ignored(fault: str) -> None:
    """Real MITRE bundles keep subtechnique-of edges of revoked techniques; they must not reject the catalog."""
    data = declare_subtechniques(bundle())
    break_subtechniques(data, fault)
    _reduce(data)


@pytest.mark.parametrize("fault", SUBTECHNIQUE_FAILURES)
@pytest.mark.parametrize("order", ["original", "reverse", "rotate", "sorted"])
def test_subtechnique_declaration_rejections(fault: str, order: str) -> None:
    from sigharvest.attack_subtechniques import AttackSubtechniqueError

    data = declare_subtechniques(bundle())
    break_subtechniques(data, fault)
    objects = data["objects"]
    if order == "reverse":
        objects.reverse()
    elif order == "rotate":
        data["objects"] = objects[3:] + objects[:3]
    elif order == "sorted":
        objects.sort(key=lambda o: str(o.get("id", "")))
    before = copy.deepcopy(data)
    with pytest.raises(AttackSubtechniqueError, match=SUBTECHNIQUE_FAILURES[fault]) as error:
        _reduce(data)
    assert "objects[" in str(error.value)
    assert "private-canary" not in str(error.value)
    assert len(str(error.value)) < 300
    assert data == before


@pytest.mark.parametrize("index", [2, 3, 4])
@pytest.mark.parametrize("value", [None, "false", "true", 0, 1, 0.0, [], {}, [False]])
def test_subtechnique_flag_types_include_retirement_identities(index: int, value: object) -> None:
    from sigharvest.attack_subtechniques import AttackSubtechniqueError

    data = bundle()
    data["objects"][index]["x_mitre_is_subtechnique"] = value
    with pytest.raises(AttackSubtechniqueError, match=rf"objects\[{index}\].x_mitre_is_subtechnique: expected a JSON boolean"):
        _reduce(data)


@pytest.mark.parametrize("index,flag", [(2, True), (3, False), (4, True)])
def test_subtechnique_boolean_shape_conflict(index: int, flag: bool) -> None:
    from sigharvest.attack_subtechniques import AttackSubtechniqueError

    data = bundle()
    data["objects"][index]["x_mitre_is_subtechnique"] = flag
    with pytest.raises(AttackSubtechniqueError, match="flag disagrees"):
        _reduce(data)


@pytest.mark.parametrize("field", ["revoked", "x_mitre_deprecated"])
def test_subtechnique_withdrawn_edges_and_lifecycle_diagnostics(field: str) -> None:
    expected = _reduce(bundle())
    data = declare_subtechniques(bundle())
    edge = data["objects"][-1]
    edge.update({field: True, "source_ref": [], "target_ref": "missing"})
    assert _reduce(data) == expected
    other = "revoked" if field != "revoked" else "x_mitre_deprecated"
    edge[other] = "false"
    with pytest.raises(SigharvestError, match=rf"{other}: expected boolean"):
        _reduce(data)


def test_subtechnique_limits_and_legacy_absence(monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest import attack, attack_subtechniques

    data = declare_subtechniques(bundle())
    expected = _reduce(bundle())
    data["objects"][-1]["target_ref"] = "p" * attack_subtechniques.MAX_ENDPOINT_LENGTH
    data["objects"][2]["id"] = data["objects"][-1]["target_ref"]
    assert _reduce(data) == expected
    monkeypatch.setattr(attack, "MAX_SOURCE_OBJECTS", len(data["objects"]))
    assert _reduce(data) == expected
    with pytest.raises(attack_subtechniques.AttackSubtechniqueError, match="bounded list"):
        _reduce(data | {"objects": data["objects"] + [{}]})
    monkeypatch.setattr(attack_subtechniques, "MAX_SOURCE_OBJECTS", 3)
    with pytest.raises(attack_subtechniques.AttackSubtechniqueError, match="object count"):
        _reduce(data)
    monkeypatch.setattr(attack_subtechniques, "MAX_SOURCE_OBJECTS", 4)
    assert _reduce(data) == expected
    data["objects"][-1]["target_ref"] += "p"
    with pytest.raises(attack_subtechniques.AttackSubtechniqueError, match="target_ref"):
        _reduce(data)


@pytest.mark.parametrize("objects", [None, {}, [None], [1]])
def test_subtechnique_object_envelope(objects: object) -> None:
    from sigharvest.attack_subtechniques import AttackSubtechniqueError

    data = bundle()

    with pytest.raises(AttackSubtechniqueError, match="Invalid ATT&CK"):
        _reduce(data | {"objects": objects})


def test_subtechnique_invalid_first_acquisition_does_not_publish(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest.attack import cached_matrix, load_matrix
    from sigharvest.attack_subtechniques import AttackSubtechniqueError

    data = declare_subtechniques(bundle())
    break_subtechniques(data, "wrong-parent")

    mock_bundle_http(monkeypatch, data)
    ws = Workspace(tmp_path)
    with pytest.raises(AttackSubtechniqueError, match="parent conflicts"):
        load_matrix(ws)
    assert not (ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json").exists()
    assert cached_matrix(ws) is None


@pytest.mark.parametrize("ref", [None, [], {}, 0, True, "", " padded", "control\n", "x" * 1025])
def test_subtechnique_consumed_reference_is_bounded(ref: object) -> None:
    from sigharvest.attack_subtechniques import AttackSubtechniqueError

    data = bundle()
    data["objects"][3]["id"] = ref
    with pytest.raises(AttackSubtechniqueError, match=r"objects\[3\].id: expected a bounded"):
        _reduce(data)


def test_subtechnique_unidentified_and_unconsumed_flags() -> None:
    from sigharvest.attack_subtechniques import AttackSubtechniqueError

    data = bundle()
    child = data["objects"][3]
    child.pop("external_references")
    child["x_mitre_is_subtechnique"] = True
    expected = _reduce(data)
    assert [t["id"] for t in expected["techniques"]] == ["T1059"]
    child["x_mitre_is_subtechnique"] = False  # No admitted ID to compare against.
    assert _reduce(data) == expected
    data["objects"].append({"type": "report", "x_mitre_is_subtechnique": "private-canary"})
    assert _reduce(data) == expected
    child["x_mitre_is_subtechnique"] = None
    with pytest.raises(AttackSubtechniqueError, match="expected a JSON boolean"):
        _reduce(data)


def test_passive_matrix_load_does_not_acquire_absent_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest.attack import AttackCacheError, load_matrix

    def forbidden(*args, **kwargs):
        pytest.fail("passive load attempted acquisition")

    monkeypatch.setattr("httpx.get", forbidden)
    monkeypatch.setattr("sigharvest.attack_io.build_opener", forbidden)
    ws = Workspace(tmp_path)
    with pytest.raises(AttackCacheError, match="Run sigharvest coverage"):
        load_matrix(ws, acquire=False)
    assert not ws.cache.exists()


def test_combined_source_admission_preserves_error_order() -> None:
    from sigharvest.attack import AttackPhaseError, InvalidMatrix
    from sigharvest.attack_subtechniques import AttackSubtechniqueError

    data = declare_subtechniques(bundle())
    matrix, parent, child = data["objects"][1:4]
    matrix["tactic_refs"] = ["absent"]
    parent["external_references"][0]["external_id"] = "invalid"
    child["revoked"] = "false"
    child["x_mitre_is_subtechnique"] = False
    child["kill_chain_phases"] = [None]
    # Lifecycle admission still covers every consumed object before matrix and
    # identity checks; neither new source check masks those existing diagnostics.
    with pytest.raises(SigharvestError, match="revoked: expected boolean"):
        _reduce(data)
    child["revoked"] = False
    with pytest.raises(InvalidMatrix, match="target is missing"):
        _reduce(data)
    matrix["tactic_refs"] = ["x1"]
    with pytest.raises(AttackIdentityError, match="invalid MITRE ID"):
        _reduce(data)
    parent["external_references"][0]["external_id"] = "T1059"
    with pytest.raises(AttackSubtechniqueError, match="flag disagrees"):
        _reduce(data)
    child["x_mitre_is_subtechnique"] = True
    with pytest.raises(AttackPhaseError, match=r"kill_chain_phases\[0\]"):
        _reduce(data)
    child["kill_chain_phases"] = [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]
    assert _reduce(data) == _reduce(bundle())


# Synthetic JSON forms; labels keep pytest node IDs bounded and value-free.
INVALID_OBJECT_KINDS = {
    "missing": None,
    "null": None,
    "false": False,
    "true": True,
    "integer": 1,
    "zero": 0,
    "float": 1.5,
    "list": ["private-kind-canary"],
    "object": {"private-kind-canary": "relationship"},
    "empty": "",
    "blank": " ",
    "leading-space": " private-kind-canary",
    "trailing-space": "private-kind-canary ",
    "tab": "private-kind-canary\t",
    "newline": "private-kind-canary\ntext",
    "nul": "private-kind-canary\x00",
    "del": "private-kind-canary\x7f",
    "c1-control": "private-kind-canary\x85",
    "zero-width": "private-kind-canary\u200b",
    "bidi": "private-kind-canary\u202e",
    "surrogate": "private-kind-canary\ud800",
    "unicode-space": "private-kind-canary\u00a0text",
    "line-separator": "private-kind-canary\u2028text",
    "over-limit": "x" * 1025,
}
VALID_EXTENSION_KINDS = ["x-extension", "Relationship", "ATTACK-PATTERN", "Uses", "x-雪🙂", "x-e\u0301", 'x-"\\escaped', "x extension", "é" * 1024]


def object_kind_fault(field: str, fault: str, **extra: object) -> dict:
    obj = {
        "type": "relationship",
        # Plausible identity hints must never replace an invalid discriminator.
        "id": "attack-pattern--private-kind-canary",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
        **extra,
    }
    if fault == "missing":
        obj.pop(field, None)
    else:
        obj[field] = INVALID_OBJECT_KINDS[fault]
    return obj


@pytest.mark.parametrize("field", ["type", "relationship_type"])
@pytest.mark.parametrize("fault", INVALID_OBJECT_KINDS)
@pytest.mark.parametrize("lifecycle", [{}, {"revoked": True}, {"x_mitre_deprecated": True}], ids=["active", "revoked", "deprecated"])
def test_object_kind_refusal_before_dispatch(field: str, fault: str, lifecycle: dict) -> None:
    from sigharvest.attack import AttackObjectKindError

    data = bundle()
    position = len(data["objects"])
    data["objects"].append(object_kind_fault(field, fault, **lifecycle))
    before = copy.deepcopy(data)
    with pytest.raises(AttackObjectKindError) as error:
        _reduce(data)
    assert str(error.value) == (
        f"Invalid ATT&CK objects[{position}].{field}: expected 1-1024 printable characters without surrounding whitespace. "
        "Supply a corrected Enterprise ATT&CK bundle."
    )
    assert data == before


@pytest.mark.parametrize("kind", VALID_EXTENSION_KINDS, ids=range(len(VALID_EXTENSION_KINDS)))
def test_object_kind_valid_extensions_and_unused_metadata(kind: str) -> None:
    data = bundle()
    expected = _reduce(data)
    for value in INVALID_OBJECT_KINDS.values():
        data["objects"].append({"type": kind, "relationship_type": value, "revoked": "unused-metadata"})
    data["objects"].append({"type": "relationship", "relationship_type": kind, "revoked": "unused-metadata"})
    data["objects"][2]["relationship_type"] = ["unused-metadata"]
    assert _reduce(data) == expected


@pytest.mark.parametrize("field", ["type", "relationship_type"])
@pytest.mark.parametrize("fault", INVALID_OBJECT_KINDS)
def test_object_kind_first_acquisition_refuses_before_publication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, fault: str) -> None:
    from sigharvest.attack import AttackObjectKindError, cached_matrix, load_matrix

    data = bundle()
    data["objects"].append(object_kind_fault(field, fault))
    response = mock_bundle_http(monkeypatch, data)
    ws = Workspace(tmp_path)
    with pytest.raises(AttackObjectKindError, match=rf"objects\[6\].{field}"):
        load_matrix(ws)
    assert response.closed
    assert not ws.cache.exists()
    assert cached_matrix(ws) is None


def test_object_kind_passive_cache_reads_do_not_revalidate_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest.attack import cached_matrix, load_matrix

    ws = Workspace(tmp_path)
    seed_attack(ws)
    path = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    before = path.read_bytes(), path.stat().st_mtime_ns

    def forbidden(*args, **kwargs):
        pytest.fail("passive reader dispatched source admission, acquisition or indexing")

    monkeypatch.setattr("sigharvest.attack._object_kind", forbidden)
    monkeypatch.setattr("sigharvest.attack_io.build_opener", forbidden)
    monkeypatch.setattr("sigharvest.index.rebuild", forbidden)
    assert cached_matrix(ws) == load_matrix(ws, acquire=False)
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_object_kind_json_escapes_preserve_exact_dispatch() -> None:
    from sigharvest.attack_io import json_object

    data = bundle()
    raw = json.dumps(data).replace('"relationship"', '"\\u0072elationship"').replace('"revoked-by"', '"\\u0072evoked-by"').encode()
    assert _reduce(json_object(raw)) == _reduce(data)


@pytest.mark.parametrize("field", ["type", "relationship_type"])
def test_object_kind_coverage_cli_first_acquisition(coverage_corpus, monkeypatch: pytest.MonkeyPatch, field: str) -> None:
    ws, _ = coverage_corpus
    path = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    path.unlink()
    data = bundle()
    data["objects"].append(object_kind_fault(field, "list"))
    response = mock_bundle_http(monkeypatch, data)
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    result = CliRunner().invoke(app, ["coverage"])
    assert result.exit_code == 2, result.output
    assert f"objects[6].{field}" in result.output
    assert "corrected Enterprise" in " ".join(result.output.split())
    assert "Traceback" not in result.output
    assert "private-kind-canary" not in result.output
    assert response.closed
    assert not path.exists()


@pytest.mark.parametrize("count", [1, 31, 32, 1024])
def test_phase_membership_preserves_order_and_rechecks_mutated_input(count):
    from sigharvest.attack import AttackPhaseError, _technique_phases

    names = [f"tactic-{i}" for i in reversed(range(count))]
    phases = [{"kill_chain_name": "mitre-attack", "phase_name": name} for name in names]
    original = copy.deepcopy(phases)
    assert _technique_phases(phases, set(names)) == names
    assert phases == original
    # A second invocation on the same list must read changed entries and tactics.
    phases[-1]["phase_name"] = "unknown"
    with pytest.raises(AttackPhaseError, match=rf"\[{count - 1}\].phase_name: unknown"):
        _technique_phases(phases, set(names))
    phases[-1]["phase_name"] = names[-1]
    with pytest.raises(AttackPhaseError, match=r"\[0\].phase_name: unknown"):
        _technique_phases(phases, set())
    assert _technique_phases(phases, set(names)) == names
    if count > 1:
        phases[-1]["phase_name"] = names[0]
        with pytest.raises(AttackPhaseError, match=rf"\[{count - 1}\].phase_name: duplicate"):
            _technique_phases(phases, set(names))


@pytest.mark.parametrize("field", ["kill_chain_name", "phase_name"])
def test_phase_text_limit_and_error_order(field):
    from sigharvest.attack import AttackPhaseError, _technique_phases

    foreign = {"kill_chain_name": "foreign", "phase_name": "foreign", field: "x" * 1024}
    phases = [foreign, {"kill_chain_name": "mitre-attack", "phase_name": "execution"}]
    assert _technique_phases(phases, {"execution"}) == ["execution"]
    foreign[field] += "x"
    with pytest.raises(AttackPhaseError, match=rf"\[0\].{field}") as error:
        _technique_phases(phases, {"execution"})
    assert "x" * 20 not in str(error.value)
    phases[0] = {"kill_chain_name": False, "phase_name": None}
    with pytest.raises(AttackPhaseError, match=r"\[0\].kill_chain_name"):
        _technique_phases(phases, {"execution"})
    phases[0] = {"kill_chain_name": "mitre-attack", "phase_name": "unknown"}
    phases[1] = None
    with pytest.raises(AttackPhaseError, match=r"\[0\].phase_name: unknown"):
        _technique_phases(phases, {"execution"})


@pytest.mark.parametrize("padding", [0, 31])
def test_phase_duplicate_membership_preserves_string_subclass_equality(padding):
    from sigharvest.attack import AttackPhaseError, _technique_phases

    class AlternateHash(str):
        def __hash__(self):
            return super().__hash__() + 1

    first = AlternateHash("execution")
    names = {first, "execution", *(f"extra-{i}" for i in range(padding))}
    phases = [{"kill_chain_name": "mitre-attack", "phase_name": first}]
    assert _technique_phases(phases, names) == [first]
    phases.extend({"kill_chain_name": "mitre-attack", "phase_name": f"extra-{i}"} for i in range(padding))
    phases.append({"kill_chain_name": "mitre-attack", "phase_name": "execution"})
    with pytest.raises(AttackPhaseError, match=rf"\[{padding + 1}\].phase_name: duplicate"):
        _technique_phases(phases, names)
    phases.reverse()
    with pytest.raises(AttackPhaseError, match=rf"\[{padding + 1}\].phase_name: duplicate"):
        _technique_phases(phases, names)


def test_subtechnique_admission_error_precedence() -> None:
    from sigharvest.attack import AttackIdentityError, AttackPhaseError
    from sigharvest.attack_subtechniques import AttackSubtechniqueError

    data = declare_subtechniques(bundle())
    child = data["objects"][3]
    child["x_mitre_is_subtechnique"] = "false"
    child["kill_chain_phases"] = None
    data["objects"][4]["external_references"] = None
    with pytest.raises(AttackIdentityError):
        _reduce(data)
    data["objects"][4].pop("external_references")
    with pytest.raises(AttackSubtechniqueError, match="expected a JSON boolean"):
        _reduce(data)
    child["x_mitre_is_subtechnique"] = True
    with pytest.raises(AttackPhaseError):
        _reduce(data)


@pytest.mark.parametrize("field", ["source_ref", "target_ref"])
def test_subtechnique_endpoint_length_is_checked_before_hashing(field: str) -> None:
    from sigharvest.attack_subtechniques import MAX_ENDPOINT_LENGTH, AttackSubtechniqueError

    class Oversized(str):
        def __hash__(self):
            pytest.fail("oversized reference was hashed before its byte-independent length bound")

    data = declare_subtechniques(bundle())
    data["objects"][-1][field] = Oversized("x" * (MAX_ENDPOINT_LENGTH + 1))
    with pytest.raises(AttackSubtechniqueError, match=field + ": expected a bounded"):
        _reduce(data)


@pytest.mark.parametrize("field", ["source_ref", "target_ref"])
@pytest.mark.parametrize("printable", [False, True])
def test_subtechnique_endpoint_subclass_keeps_grammar_checks(field: str, printable: bool) -> None:
    from sigharvest.attack_subtechniques import AttackSubtechniqueError

    class Reference(str):
        def isprintable(self) -> bool:
            return printable

    data = declare_subtechniques(bundle())
    expected = _reduce(data)
    edge = data["objects"][-1]
    edge[field] = Reference(edge[field])
    if printable:
        assert _reduce(data) == expected
    else:
        with pytest.raises(AttackSubtechniqueError, match=field + ": expected a bounded"):
            _reduce(data)
