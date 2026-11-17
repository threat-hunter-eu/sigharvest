"""Offline stand-ins for the data sigharvest downloads once into a workspace cache (tests never use the network).

- `seed_attack(ws)`: a tiny reduced ATT&CK matrix where `attack.load_matrix` looks for it;
- `seed_schemas(ws)`: small Sigma JSON schemas where `testing.load_schemas` looks for them, so the validate stage
  runs without downloading sigma-specification.
"""

from __future__ import annotations

import json
from typing import Any

from sigharvest.config import Workspace

ATTACK_FIXTURE: dict[str, Any] = {
    "tactics": [
        ["discovery", "Discovery", "TA0007"],
        ["command-and-control", "Command and Control", "TA0011"],
        ["credential-access", "Credential Access", "TA0006"],
        ["execution", "Execution", "TA0002"],
    ],
    "techniques": [
        {"id": "T1003", "name": "OS Credential Dumping", "tactics": ["credential-access"], "parent": None},
        {"id": "T1003.001", "name": "LSASS Memory", "tactics": ["credential-access"], "parent": "T1003"},
        {"id": "T1033", "name": "System Owner/User Discovery", "tactics": ["discovery"], "parent": None},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["execution"], "parent": None},
        {"id": "T1059.001", "name": "PowerShell", "tactics": ["execution"], "parent": "T1059"},
        {"id": "T1105", "name": "Ingress Tool Transfer", "tactics": ["command-and-control"], "parent": None},
        {"id": "T1569", "name": "System Services", "tactics": ["execution"], "parent": None},
    ],
    "replaced": {"T1086": "T1059.001"},
    "deprecated": ["T1064"],
}

_LEVELS = ["informational", "low", "medium", "high", "critical"]
SCHEMA_FIXTURES: dict[str, dict[str, Any]] = {
    "rule": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["title", "logsource", "detection"],
        "properties": {
            "title": {"type": "string"},
            "id": {"type": "string", "format": "uuid"},
            "level": {"enum": _LEVELS},
            "logsource": {"type": "object"},
            "detection": {"type": "object", "required": ["condition"]},
        },
    },
    "correlation": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "required": ["title", "correlation"]},
    "filter": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "required": ["title", "logsource", "filter"]},
}


def seed_attack(ws: Workspace) -> None:
    """Write the ATT&CK fixture into ws's cache (the file name of the pinned release, so nothing is downloaded)."""
    from sigharvest.attack import ATTACK_VERSION

    path = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": ATTACK_VERSION, **ATTACK_FIXTURE}), encoding="utf-8")


def seed_schemas(ws: Workspace) -> None:
    """Write small Sigma JSON schemas where the validate stage reads its pinned sigma-specification copy."""
    from sigharvest.testing import SCHEMAS, SPEC_COMMIT

    folder = ws.cache / "sigma-specification" / SPEC_COMMIT
    folder.mkdir(parents=True, exist_ok=True)
    for kind, name in SCHEMAS.items():
        (folder / name).write_text(json.dumps(SCHEMA_FIXTURES[kind]), encoding="utf-8")


# Correlation fixtures shared by correlation reference, dependency and export tests.
BASE_ID = "5638f7c0-ac70-491d-8465-2a65075e0d86"
CORR_ID = "0e95725d-7320-415d-80f7-004da920fc11"


def base(name: str = "failed", value: str = "failure", **extra: Any) -> str:
    import yaml

    return yaml.safe_dump(
        {"title": name, "name": name, "logsource": {"category": "application"}, "detection": {"sel": {"action": value}, "condition": "sel"}, **extra}
    )


def corr(
    kind: str = "event_count", refs: list[str] | None = None, group: list[str] | None = None, span: str = "1h", condition: Any = None, **extra: Any
) -> str:
    import yaml

    c: dict[str, Any] = {"type": kind, "rules": refs or ["failed"], "group-by": ["ComputerName"] if group is None else group, "timespan": span}
    if condition is not None:
        c["condition"] = condition
    elif not kind.startswith("temporal"):
        c["condition"] = {"gte": 100, **({"field": "User"} if kind == "value_count" else {})}
    c.update(extra)
    return yaml.safe_dump({"title": "Correlation alert", "id": CORR_ID, "level": "high", "correlation": c})


def snapshot(s: Any) -> dict[str, Any]:
    """The published index without row ids: logic groups and derived tables, for determinism checks."""
    from sqlalchemy import select, text

    from sigharvest.models import LogicGroup

    groups = [{k: v for k, v in row.items() if k != "id"} for row in s.execute(select(LogicGroup.__table__).order_by(LogicGroup.logic_hash)).mappings()]
    tables = {
        table: sorted(tuple(r) for r in s.execute(text(f"SELECT * FROM {table}")))
        for table in ("source_roots", "source_overlaps", "source_summaries", "near_duplicates", "correlation_references")
    }
    return {"groups": groups, "tables": tables}


def compare_full(s: Any) -> None:
    """Stored families equal a full recomputation by index_families.families, and a second full rebuild publishes the same index."""
    from sqlalchemy import select

    from sigharvest.correlation_references import status
    from sigharvest.index import rebuild
    from sigharvest.index_families import families
    from sigharvest.models import LogicGroup

    assert status(s) == "ready"
    before = snapshot(s)
    stored = s.execute(select(LogicGroup.logic_hash, LogicGroup.family_id, LogicGroup.family_size)).all()
    family_of, family_size = families(s, {lh for lh, _, _ in stored})
    assert {lh: fid for lh, fid, _ in stored} == family_of
    assert {fid: size for _, fid, size in stored} == family_size
    with s.begin_nested() as savepoint:
        rebuild(s, commit=False, workers=1)
        assert status(s) == "ready"
        assert snapshot(s) == before
        savepoint.rollback()
    s.expire_all()


def reseal(folder: Any) -> None:
    """Rewrite SHA256SUMS after editing a release, so only the edit itself is under test."""
    import hashlib

    names = sorted(p.name for p in folder.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    lines = [f"{hashlib.sha256((folder / f).read_bytes()).hexdigest()}  {f}" for f in names]
    (folder / "SHA256SUMS").write_text("\n".join(lines) + "\n")


def rows_of(folder: Any) -> list[dict[str, Any]]:
    import gzip

    with gzip.open(folder / "rules.jsonl.gz", "rt", encoding="utf-8") as fh:
        return [json.loads(x) for x in fh]


def write_rows(folder: Any, rows: list[dict[str, Any]]) -> None:
    import gzip

    with gzip.open(folder / "rules.jsonl.gz", "wt", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def set_licence(ws: Workspace, licence: str | None, redistributable: bool | str | None = True, name: str | None = None) -> None:
    """State a licence (and whether its text may be redistributed) for the sources in ws's sources.yaml.

    Releases and exports read licences from sources.yaml, so tests change it there, not in the database."""
    from sigharvest.config import load_sources, save_sources

    items = load_sources(ws)
    for item in items:
        if name is None or item.name == name:
            item.licence, item.redistributable = licence, redistributable
    save_sources(ws, items)


def count_groups(s: Any, query: str | None, filters: Any) -> int:
    """Test oracle: exact logic total by plain SQL count, without sorting or hydrating a result page."""
    from sqlalchemy import text

    from sigharvest.index import _base
    from sigharvest.search_summary import compact_base

    base, _rank, params = _base(query, filters, session=s)
    base, _ = compact_base(s, base, query, filters)
    return int(s.execute(text(f"SELECT count(*) {base}"), params).scalar_one())
