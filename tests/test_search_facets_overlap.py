"""Repository and collection search plus directional overlap contracts."""

from pathlib import Path

import pytest
import yaml
from sqlalchemy import delete, select, update

from sigharvest import collections
from sigharvest.config import Workspace
from sigharvest.datasources import rule_datasources
from sigharvest.db import session_factory
from sigharvest.index import GroupFilters, facets, parse_query, rebuild, search_groups
from sigharvest.ingest import Ingestor
from sigharvest.models import CollectionItem, LogicGroup, Occurrence, Source, SourceOverlap, SourceSummary
from sigharvest.source_overlap import overlap_counts
from tests.test_pipeline import UIDS


@pytest.fixture
def corpus(tmp_path: Path):  # type: ignore[no-untyped-def]
    ws = Workspace(tmp_path)
    factory = session_factory(ws.db_path, migrate=True)
    rules = [
        ("Shared process", {"product": "windows", "category": "process_creation"}, {"Image": "alpha.exe"}, ("A", "B"), UIDS[0]),
        ("Process variant", {"product": "windows", "category": "process_creation"}, {"Image": "beta.exe"}, ("A",), UIDS[0]),
        ("Audit process", {"product": "windows", "service": "security"}, {"EventID": 4688, "Image": "gamma.exe"}, ("A",), UIDS[1]),
        ("Cloud change", {"product": "aws", "service": "cloudtrail"}, {"eventName": "Change"}, ("B", "C"), UIDS[2]),
        ("Audit command", {"product": "linux", "service": "auditd"}, {"exe": "/bin/run"}, ("C",), UIDS[3]),
        ("Script block", {"product": "windows", "category": "ps_script"}, {"ScriptBlockText": "evil"}, ("A",), UIDS[4]),
    ]
    with factory() as s:
        sources = {name: Source(name=name, type="local", url="", priority=10) for name in ("A", "B", "C", "Empty")}
        s.add_all(sources.values())
        s.flush()
        root = tmp_path / "rules"
        root.mkdir()
        for i, (title, logsource, selection, names, rule_id) in enumerate(rules):
            raw = yaml.safe_dump(
                {
                    "title": title,
                    "id": rule_id,
                    "status": "stable",
                    "level": "high",
                    "logsource": logsource,
                    "detection": {"selection": selection, "condition": "selection"},
                }
            )
            (root / f"{i}.yml").write_text(raw)
            for name in names:
                Ingestor(s, sources[name], None).ingest_file(root, f"{i}.yml")
        s.commit()
        rebuild(s)
    return ws, factory


def test_parse_and_telemetry_mapping() -> None:
    assert parse_query('title:cmd datasource:"sysmon 1" service:security source:A source:B exclude_source:C collection:"Saved rules"') == (
        "title:cmd",
        {"datasource": "sysmon 1", "service": "security", "source": "A,B", "exclude_source": "C", "collection": "Saved rules"},
    )
    assert rule_datasources("windows", "process_creation", None) == ["Security 4688", "Sysmon 1"]
    assert rule_datasources("windows", "process_creation", "sysmon") == ["Sysmon 1"]
    assert rule_datasources("windows", "process_creation", "security") == ["Security 4688"]
    assert rule_datasources("windows", "ps_script", None) == ["PowerShell 4104"]
    assert rule_datasources("linux", None, "auditd") == ["auditd"]
    assert rule_datasources("aws", None, "cloudtrail") == ["CloudTrail"]
    # An EventID only in an excluded selector must never become a prerequisite.
    assert rule_datasources("windows", None, "security", {"filter": {"EventID": 4688}, "condition": "not filter"}) == ["Security"]
    assert rule_datasources("windows", None, "security", {"sel": {"EventID": [4624, "04625"]}, "condition": "sel"}) == [
        "Security 4624",
        "Security 4625",
    ]


def test_contextual_facets_and_exact_repository_filters(corpus) -> None:  # type: ignore[no-untyped-def]
    _, factory = corpus
    with factory() as s:
        assert search_groups(s, 'datasource:"Sysmon EventID 1"', GroupFilters())[1] == 2
        assert search_groups(s, "service:security", GroupFilters())[1] == 1
        assert search_groups(s, 'datasource:"security 4688"', GroupFilters())[1] == 3
        assert dict(facets(s, "datasource")) == {"Security 4688": 3, "Sysmon 1": 2, "PowerShell 4104": 1, "CloudTrail": 1, "auditd": 1}
        assert dict(facets(s, "datasource", per_family=True))["Sysmon 1"] == 1
        assert dict(facets(s, "service", f=GroupFilters(service="security"))) == {"security": 1, "cloudtrail": 1, "auditd": 1}
        assert dict(facets(s, "source", f=GroupFilters(source="A", datasource="sysmon 1"))) == {"A": 2, "B": 1}
        assert search_groups(s, None, GroupFilters(source="A,B"))[1] == 5
        assert search_groups(s, None, GroupFilters(source="A", source_only=True))[1] == 3
        assert search_groups(s, None, GroupFilters(source="A,B", exclude_source="B"))[1] == 3
        assert search_groups(s, None, GroupFilters(source="A%"))[1] == 0
        assert search_groups(s, None, GroupFilters(source="A' OR 1=1 --"))[1] == 0
        assert search_groups(s, None, GroupFilters(collection="unknown"))[1] == 0
        assert dict(facets(s, "source", f=GroupFilters(source="A"), per_family=True)) == {"A": 3, "B": 2, "C": 2}
        # All facet alternatives still honor full text.
        assert dict(facets(s, "source", query="Audit")) == {"A": 1, "C": 1}


def test_overlap_counts_are_directional_and_near_matches_do_not_double_count() -> None:
    membership = {"a": {"A", "B"}, "b": {"A"}, "c": {"B", "C"}, "d": {"C"}, "e": {"D"}}
    rows = {(r["name"], r["other"]): (r["exact"], r["near"]) for r in overlap_counts(membership, [("b", "c"), ("b", "d"), ("a", "c")])}
    assert rows["A", "B"] == (1, 1)
    assert rows["B", "A"] == (1, 1)
    assert rows["A", "C"] == (0, 2)
    assert rows["C", "A"] == (0, 2)
    assert rows["B", "C"] == (1, 1)
    assert rows["C", "B"] == (1, 0)
    assert not any("D" in pair or pair[0] == pair[1] for pair in rows)
    assert overlap_counts({}, []) == []


def test_projection_rebuild_removes_stale_membership(corpus) -> None:  # type: ignore[no-untyped-def]
    _, factory = corpus
    with factory() as s:
        assert s.get(SourceSummary, "A").logic == 4
        assert s.get(SourceSummary, "A").documents == 4
        assert s.get(SourceSummary, "A").only == 3
        assert s.get(SourceOverlap, ("A", "B")).exact == 1
        assert s.get(SourceOverlap, ("B", "C")).exact == 1
        assert s.get(SourceOverlap, ("A", "C")) is None
        source_id = s.scalar(select(Source.id).where(Source.name == "B"))
        s.execute(update(Occurrence).where(Occurrence.source_id == source_id).values(present=False))
        rebuild(s)
        s.expire_all()
        assert s.get(SourceSummary, "B") is None
        assert s.get(SourceOverlap, ("A", "B")) is None
        assert s.get(SourceSummary, "A").only == 4


def test_collection_filter_resolves_updates(corpus) -> None:  # type: ignore[no-untyped-def]
    _ws, factory = corpus

    def cached_search(_web, s, params):  # type: ignore[no-untyped-def]
        from tests.helpers import count_groups

        query = params.get("q")
        f = GroupFilters(collection=params.get("collection"))
        groups, total = search_groups(s, query, f, limit=100)
        assert total == count_groups(s, query, f)
        return {"ids": [g.id for g in groups], "total": total}

    web = None
    with factory() as s:
        groups = list(s.scalars(select(LogicGroup).order_by(LogicGroup.id)))
        col = collections.create(s, "Saved rules")
        collections.add(s, col, [groups[0]])
        s.commit()
        params = {"collection": col.name, "view": "logic"}
        assert cached_search(web, s, params)["ids"] == [groups[0].id]
        # Same-size replacement, including a missing old hash resolved by its stable rule id.
        s.execute(delete(CollectionItem).where(CollectionItem.collection_id == col.id))
        s.add(CollectionItem(collection_id=col.id, logic_hash="f" * 64, rule_id=groups[-1].rule_id))
        s.commit()
        assert cached_search(web, s, params)["ids"] == [groups[-1].id]
        s.execute(delete(CollectionItem).where(CollectionItem.collection_id == col.id))
        s.commit()
        assert cached_search(web, s, params)["total"] == 0
        assert cached_search(web, s, {"q": 'collection:"Saved rules"'})["total"] == 0


def test_near_overlap_includes_variants_within_one_family(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    factory = session_factory(ws.db_path, migrate=True)
    with factory() as s:
        for i, name in enumerate(("Original", "Variant")):
            source = Source(name=name, type="local", url="", priority=10)
            s.add(source)
            s.flush()
            rule = {
                "title": "Credential tool detection",
                "id": UIDS[0],
                "level": "high",
                "status": "stable",
                "logsource": {"product": "windows", "category": "process_creation"},
                "detection": {"selection": {"Image": [f"tool-{j}.exe" for j in range(20 + i)]}, "condition": "selection"},
            }
            path = tmp_path / f"rule{i}.yml"
            path.write_text(yaml.safe_dump(rule))
            Ingestor(s, source, None).ingest_file(tmp_path, path.name)
        s.commit()
        rebuild(s)
        assert len(set(s.scalars(select(LogicGroup.family_id)))) == 1
        assert s.get(SourceOverlap, ("Original", "Variant")).exact == 0
        assert s.get(SourceOverlap, ("Original", "Variant")).near == 1
        assert s.get(SourceOverlap, ("Variant", "Original")).near == 1
