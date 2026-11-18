"""Inventory summary invalidation and bounded duplicate result parity."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from typer.testing import CliRunner

from sigharvest import corpus_stats
from sigharvest.cli import app
from sigharvest.config import Workspace, save_sources
from sigharvest.models import Occurrence, RuleVersion, SearchSummary, Source
from sigharvest.query import dedupe
from sigharvest.service import open_db


@pytest.fixture
def corpus(tmp_path: Path):
    ws = Workspace(tmp_path)
    save_sources(ws, [])
    factory = open_db(ws, migrate=True)
    with factory() as s:
        a = Source(name="a", type="local", url="a", priority=20)
        b = Source(name="b", type="local", url="b", priority=10)
        s.add_all([a, b])
        s.flush()
        for i in range(9):
            version = RuleVersion(
                content_hash=str(i),
                logic_hash=str(i % 4),
                rule_id=str(i % 3),
                kind="rule",
                title=f"Title {i}",
                title_slug="shared" if i < 6 else "",
                raw="title: fixture",
                semantic_hash="semantic" if i < 2 else "" if i < 5 else None,
            )
            s.add(version)
            s.flush()
            for j in range(1 + i % 3):
                s.add(
                    Occurrence(
                        version_id=version.id,
                        source_id=(a if j % 2 else b).id,
                        path=f"{i}-{j}.yml",
                        file_hash=str(i),
                        present=i != 8,
                        first_seen=datetime(2026, 1, 1) + timedelta(days=j),
                    )
                )
        s.commit()
    return ws, factory


@pytest.mark.parametrize("top", [0, 1, 3, 100, -1, -100])
def test_bounded_dedupe_matches_full_inventory(corpus, top: int) -> None:
    ws, _ = corpus
    with open_db(ws, readonly=True)() as s:
        full = asdict(dedupe(s))
        full["logic_groups"] = full["logic_groups"][:top]
        assert asdict(dedupe(s, top=top)) == full


def test_bounded_dedupe_picks_the_canonical_copy_of_the_full_report(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    save_sources(ws, [])
    factory = open_db(ws, migrate=True)
    with factory() as s:
        a = Source(name="a", type="local", url="a", priority=50)
        b = Source(name="b", type="local", url="b", priority=50)
        s.add_all([a, b])
        s.flush()
        for source, content_hash, first_seen in ((b, "1", datetime(2026, 1, 1)), (a, "2", datetime(2026, 2, 1))):
            version = RuleVersion(content_hash=content_hash, logic_hash="logic", rule_id="r", kind="rule", title="T", raw="title: fixture")
            s.add(version)
            s.flush()
            s.add(Occurrence(version_id=version.id, source_id=source.id, path="x.yml", file_hash=content_hash, present=True, first_seen=first_seen))
        s.commit()
    with factory() as s:
        # Equal priorities: the full report (and the index) take the source name, not the first one seen.
        assert dedupe(s).logic_groups[0]["canonical"]["source"] == "a"
        assert dedupe(s, top=1).logic_groups[0]["canonical"]["source"] == "a"


def test_stats_cache_is_readonly_current_and_rolls_back(corpus, monkeypatch) -> None:
    ws, factory = corpus
    with factory() as s:
        expected = corpus_stats.live(s)
        assert (expected.documents, expected.contents, expected.logic, expected.rule_ids, expected.semantic) == (15, 8, 4, 3, 1)
        corpus_stats.refresh(s)
        s.commit()
    with open_db(ws, readonly=True)() as s:
        with monkeypatch.context() as patch:
            patch.setattr(corpus_stats, "live", lambda s: pytest.fail("current summary must avoid inventory scans"))
            assert corpus_stats.read(s) == expected
        with pytest.raises(Exception, match="readonly"):
            s.execute(text("DELETE FROM sources"))
    with factory() as s:
        s.execute(text("UPDATE occurrences SET present=0 WHERE id=(SELECT min(id) FROM occurrences)"))
        assert corpus_stats.read(s).documents == expected.documents - 1
        corpus_stats.refresh(s)
        s.flush()
        s.rollback()
        assert corpus_stats.read(s) == expected
        s.execute(text("UPDATE rule_versions SET semantic_hash='changed' WHERE id=(SELECT min(id) FROM rule_versions)"))
        assert corpus_stats.read(s).semantic == 2
        s.rollback()
        s.delete(s.get(SearchSummary, corpus_stats.NAME))
        s.flush()
        assert corpus_stats.read(s) == expected


def test_stats_cached_and_live_cli_outputs_match(corpus) -> None:
    ws, factory = corpus
    runner = CliRunner()
    env = {"SIGHARVEST_HOME": str(ws.root)}
    live = runner.invoke(app, ["stats", "--all-sources"], env=env)
    with factory() as s:
        corpus_stats.refresh(s)
        s.commit()
    cached = runner.invoke(app, ["stats", "--all-sources"], env=env)
    assert live.exit_code == cached.exit_code == 0
    assert live.output == cached.output
