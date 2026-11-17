"""Generated cohorts and telemetry boundaries, including incremental publication."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import pytest
import yaml
from sqlalchemy import select, update

from sigharvest.db import session_factory, set_meta
from sigharvest.family_links import related
from sigharvest.index import GroupFilters, rebuild, search_groups
from sigharvest.index_families import families
from sigharvest.ingest import Ingestor
from sigharvest.models import LogicGroup, Occurrence, RuleVersion, Source
from sigharvest.quality import classify, is_junk
from sigharvest.quality_templates import MIN_TEMPLATE_LOGIC, skeletons
from sigharvest.semantic import ACTIVE_FINGERPRINT
from tests.helpers import compare_full


def document(number: int, **changes: Any) -> dict[str, Any]:
    return {
        "id": str(uuid5(NAMESPACE_URL, f"template-fixture/{number}")),
        "title": "Suspicious service path: powershell",
        "status": "experimental",
        "level": "medium",
        "logsource": {"product": "windows", "service": "system"},
        "detection": {"selection": {"ServiceName": f"service-{number}", "ImagePath": "powershell"}, "condition": "selection"},
        **changes,
    }


def put(s, source, root: Path, number: int, **changes: Any) -> None:
    path = f"rule-{number}.yml"
    (root / path).write_text(yaml.safe_dump(document(number, **changes), sort_keys=False))
    Ingestor(s, source, None).ingest_file(root, path)
    s.flush()


def test_baseline_requires_numbered_title_missing_severity_and_experimental() -> None:
    data = document(1, title="Credential Access - Analytic 0012 Baseline", level=None)
    assert {"autogen_template", "baseline_query"} <= set(classify(data, []))
    assert is_junk(classify(data, []))
    for change in ({"level": "low"}, {"status": "stable"}, {"title": "Credential Access Baseline"}):
        assert "baseline_query" not in classify(data | change, [])
    assert is_junk(["autogen_template"]) and is_junk(["baseline_query"])


def test_skeleton_retains_condition_modifiers_and_all_other_values() -> None:
    def signatures(data):
        return set(skeletons(yaml.safe_dump(data)))

    base = document(1)
    assert signatures(base) & signatures(document(2))
    for detection in (
        {"selection": {"ServiceName": "other", "ImagePath": "cmd.exe"}, "condition": "selection"},
        {"selection": {"ServiceName|contains": "other", "ImagePath": "powershell"}, "condition": "selection"},
        {"selection": {"ServiceName": "other", "ImagePath": "powershell"}, "condition": "not selection"},
    ):
        assert not signatures(base) & signatures(base | {"detection": detection})
    assert not signatures(base) & signatures(base | {"logsource": {"product": "windows", "service": "security"}})
    assert not skeletons("x" * (1024 * 1024 + 1))
    assert not skeletons("detection: &loop {selection: *loop}\nlogsource: {product: windows}")
    assert not skeletons("detection: [\n")


def test_cohort_threshold_add_remove_copies_and_default_selection(tmp_path: Path) -> None:
    with session_factory(tmp_path / "test.db", migrate=True)() as s:
        source = Source(name="generator", type="local", url="")
        s.add(source)
        s.flush()
        for number in range(MIN_TEMPLATE_LOGIC - 1):
            put(s, source, tmp_path, number)
        rebuild(s, workers=1)
        assert not any(g.junk for g in s.scalars(select(LogicGroup)))
        # A second file and metadata revision of the same logic cannot reach 20.
        put(s, source, tmp_path, 100, **document(0, description="another copy"))
        rebuild(s, workers=1)
        assert search_groups(s, None, GroupFilters())[1] == MIN_TEMPLATE_LOGIC - 1
        put(s, source, tmp_path, MIN_TEMPLATE_LOGIC - 1)
        rebuild(s, workers=1)
        s.expire_all()
        assert search_groups(s, None, GroupFilters())[1] == 0
        assert search_groups(s, None, GroupFilters(include_junk=True))[1] == MIN_TEMPLATE_LOGIC
        assert search_groups(s, None, GroupFilters(flag="autogen_template"))[1] == MIN_TEMPLATE_LOGIC
        compare_full(s)
        s.execute(update(Occurrence).where(Occurrence.path == f"rule-{MIN_TEMPLATE_LOGIC - 1}.yml").values(present=False))
        s.commit()
        rebuild(s, workers=1)
        s.expire_all()
        assert search_groups(s, None, GroupFilters())[1] == MIN_TEMPLATE_LOGIC - 1
        assert all("autogen_template" not in g.quality_flags for g in s.scalars(select(LogicGroup)))
        compare_full(s)


@pytest.mark.parametrize("edge", ["rule_id", "semantic_hash", "related"])
def test_cross_route_bridges_remain_related_and_same_route_variants_merge(tmp_path: Path, edge: str) -> None:
    with session_factory(tmp_path / "test.db", migrate=True)() as s:
        source = Source(name="rules", type="local", url="")
        s.add(source)
        s.flush()
        rid = document(0)["id"]
        put(s, source, tmp_path, 0)
        for number, ls in enumerate(
            (
                {"product": "windows", "service": "system"},
                {"product": "windows", "service": "security"},
                {"product": "windows", "category": "driver_load"},
                {"product": "linux", "service": "system"},
            ),
            1,
        ):
            changes = {"id": rid} if edge == "rule_id" else {"related": [{"id": rid, "type": "derived"}]} if edge == "related" else {}
            put(s, source, tmp_path, number, logsource=ls, **changes)
        if edge == "semantic_hash":
            set_meta(s, ACTIVE_FINGERPRINT, "fixture")
            s.execute(update(RuleVersion).values(semantic_hash="same", semantic_fingerprint="fixture"))
        rebuild(s, workers=1)
        groups = list(s.scalars(select(LogicGroup)))
        assert len({g.family_id for g in groups}) == 4
        base = next(g for g in groups if g.family_size == 2)
        assert {reason for _, reason in related(s, base)} == {edge}
        assert len(related(s, base)) == 3
        assert {g.logic_hash: g.family_id for g in groups} == families(s, {g.logic_hash for g in groups})[0]
        # The partition itself: only the same-route copy (rule-1, windows/system like the base rule-0) joins the base
        # family; the bridges into windows/security, windows/driver_load and linux/system stay separate families.
        paths = dict(s.execute(select(RuleVersion.logic_hash, Occurrence.path).join(Occurrence, Occurrence.version_id == RuleVersion.id)).all())
        partition = sorted(sorted(paths[g.logic_hash] for g in groups if g.family_id == fid) for fid in {g.family_id for g in groups})
        assert partition == [["rule-0.yml", "rule-1.yml"], ["rule-2.yml"], ["rule-3.yml"], ["rule-4.yml"]]
        # Removing the bridge and rebuilding incrementally must retire related edges.
        s.execute(update(Occurrence).where(Occurrence.path == "rule-2.yml").values(present=False))
        s.commit()
        rebuild(s, workers=1)
        s.expire_all()
        base = s.scalar(select(LogicGroup).where(LogicGroup.family_size == 2))
        assert len(related(s, base)) == 2
        compare_full(s)


def test_normalized_category_aliases_merge_but_registry_categories_split(tmp_path: Path) -> None:
    with session_factory(tmp_path / "test.db", migrate=True)() as s:
        source = Source(name="rules", type="local", url="")
        s.add(source)
        s.flush()
        for number, category in enumerate(("registry_set", "registry_value_change", "registry_event", None)):
            put(s, source, tmp_path, number, id=document(0)["id"], logsource={"product": "windows", "category": category})
        rebuild(s, workers=1)
        assert sorted(g.family_size for g in s.scalars(select(LogicGroup))) == [1, 1, 2, 2]
        compare_full(s)
