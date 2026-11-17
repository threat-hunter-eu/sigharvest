"""Facet counts equal the clicked totals, and filters never hide unrelated rules."""

from __future__ import annotations

from dataclasses import replace

import pytest
from sqlalchemy import select

from sigharvest.index import FACET_COLUMNS, GroupFilters, facets, search_groups
from sigharvest.models import LogicGroup
from sigharvest.search_summary import counts
from tests.helpers import count_groups
from tests.test_search_facets_overlap import corpus  # noqa: F401

FILTERS = (
    GroupFilters(),
    GroupFilters(exclude_source="B"),
    GroupFilters(exclude_source="A"),
    GroupFilters(service="security"),
    GroupFilters(level="high", product="windows"),
    GroupFilters(source="A,C"),
    GroupFilters(status="deprecated"),
)


@pytest.fixture
def mixed(corpus):  # type: ignore[no-untyped-def]  # noqa: F811
    """Blank and deprecated statuses on top of the shared corpus."""
    ws, factory = corpus
    with factory() as s:
        by_title = {g.title: g for g in s.scalars(select(LogicGroup))}
        by_title["Script block"].status = ""
        by_title["Process variant"].status = "deprecated"
        s.commit()
    return ws, factory


def total(s, filters: GroupFilters, per_family: bool) -> int:  # type: ignore[no-untyped-def]
    return search_groups(s, None, filters, per_family=True)[1] if per_family else count_groups(s, None, filters)


@pytest.mark.parametrize("per_family", [False, True])
@pytest.mark.parametrize("filters", FILTERS)
def test_every_facet_count_equals_its_filtered_total(mixed, filters, per_family):  # type: ignore[no-untyped-def]
    _, factory = mixed
    with factory() as s:
        shared = counts(s, None, filters, per_family)
        for column in sorted(FACET_COLUMNS):
            listed = facets(s, column, 10000, None, filters, per_family)
            assert shared[column] == listed, column
            assert all(value not in (None, "") for value, _ in listed), column
            for value, n in listed:
                assert total(s, replace(filters, **{column: value}), per_family) == n, (column, value)


def test_exclusions_and_multi_source_keep_unrelated_rules(mixed):  # type: ignore[no-untyped-def]
    _, factory = mixed
    with factory() as s:
        secret = s.scalar(select(LogicGroup.logic_hash).where(LogicGroup.title == "Audit command"))
        everything = {g.logic_hash for g in search_groups(s, None, GroupFilters(), limit=100)[0]}
        assert secret in everything
        for filters in (
            GroupFilters(exclude_source="A"),
            GroupFilters(exclude_source="Empty"),
            GroupFilters(source_only=True),
            GroupFilters(source="A,C"),
            GroupFilters(datasource="auditd"),
        ):
            assert secret in {g.logic_hash for g in search_groups(s, None, filters, limit=100)[0]}, filters
        # Excluding a repository with no matching rules changes nothing.
        assert count_groups(s, None, GroupFilters(exclude_source="Empty")) == count_groups(s, None, GroupFilters())
        # The excluded repository is not offered by the source facet.
        assert "B" not in dict(facets(s, "source", f=GroupFilters(exclude_source="B")))
        assert "C" in dict(facets(s, "source", f=GroupFilters()))


@pytest.mark.parametrize("per_family", [False, True])
def test_sorting_never_changes_the_result_set(mixed, per_family):  # type: ignore[no-untyped-def]
    _, factory = mixed
    with factory() as s:
        baseline = search_groups(s, None, GroupFilters(), limit=100, per_family=per_family)
        for sort in ("score", "sources", "title", "modified", "level"):
            ranked = search_groups(s, None, GroupFilters(), limit=100, per_family=per_family, sort=sort)
            assert ranked[1] == baseline[1]
            assert {g.logic_hash for g in ranked[0]} == {g.logic_hash for g in baseline[0]}


def test_explicit_status_wins_over_default_exclusion(mixed):  # type: ignore[no-untyped-def]
    _, factory = mixed
    with factory() as s:
        assert count_groups(s, None, GroupFilters(status="deprecated")) == 1
        assert count_groups(s, None, GroupFilters(status="deprecated", include_deprecated=True)) == 1
        assert count_groups(s, None, GroupFilters(status="stable")) == count_groups(s, None, GroupFilters(status="stable", include_deprecated=True))
        assert dict(facets(s, "status", f=GroupFilters())).get("deprecated") == 1
        assert "" not in dict(facets(s, "status", f=GroupFilters()))


def test_cli_status_deprecated(mixed, monkeypatch):  # type: ignore[no-untyped-def]
    from typer.testing import CliRunner

    from sigharvest.cli import app

    ws, _ = mixed
    monkeypatch.chdir(ws.root)
    result = CliRunner().invoke(app, ["search", "--status", "deprecated", "--per-logic"])
    assert result.exit_code == 0, result.output
    assert "Process variant" in result.output
