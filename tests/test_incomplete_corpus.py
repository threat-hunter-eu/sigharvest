"""A first update that fails a gate leaves a partial corpus (nothing older to keep): every surface says so."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from sigharvest.cli import app, pipeline
from sigharvest.config import SourceConfig, load_sources, save_sources
from sigharvest.service import open_db
from tests.test_update_publication import update
from tests.test_update_runs import make_workspace


@pytest.fixture
def first_failed(tmp_path, monkeypatch):
    """A workspace whose first update failed the failed-sources gate (one of two sources cannot be read)."""
    _, ws = make_workspace(tmp_path)
    save_sources(ws, [*load_sources(ws), SourceConfig(name="gone", type="local", url=str(tmp_path / "missing"))])
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    open_db(ws, migrate=True)
    monkeypatch.setattr(pipeline, "_test", lambda *args, **kwargs: 0)
    result = update(ws, "--failed-sources-floor", "0")
    assert result.exit_code == 1, result.output
    assert "corpus incomplete" in result.output
    assert "runs accept" in result.output
    return ws


def run(ws, *args: str):
    return CliRunner().invoke(app, list(args), env={"SIGHARVEST_HOME": str(ws.root), "COLUMNS": "240"})


def test_cli_marks_the_corpus_incomplete(first_failed):
    ws = first_failed
    assert "corpus incomplete" in run(ws, "search", "rule").output
    assert json.loads(run(ws, "search", "rule", "--json").output)["incomplete"] is True
    assert "corpus incomplete" in run(ws, "stats").output
    doctor = run(ws, "doctor", "--json")
    updates = next(c for c in json.loads(doctor.output)["checks"] if c["name"] == "updates")
    assert updates["status"] == "fail" and "corpus incomplete" in updates["message"]


def test_publishers_refuse_an_incomplete_corpus_unless_asked(first_failed, tmp_path):
    ws = first_failed
    refused = run(ws, "release", "build", str(tmp_path / "rel"))
    assert refused.exit_code == 1 and "not publishing an incomplete corpus" in refused.output
    assert not (tmp_path / "rel" / "manifest.json").exists()
    built = run(ws, "release", "build", str(tmp_path / "rel"), "--allow-incomplete")
    assert built.exit_code == 0, built.output
    assert json.loads((tmp_path / "rel" / "manifest.json").read_text())["incomplete"] is True
    site = run(ws, "site", "build", str(tmp_path / "site"))
    assert site.exit_code == 1 and "not publishing an incomplete corpus" in site.output


def test_web_ui_shows_the_incomplete_banner(first_failed):
    from fastapi.testclient import TestClient

    from sigharvest.web.app import create_app

    ws = first_failed
    with TestClient(create_app(ws, open_db(ws)), base_url="http://127.0.0.1") as client:
        page = client.get("/search?q=rule")
    assert page.status_code == 200
    assert 'id="incomplete-corpus"' in page.text and "(incomplete)" in page.text


def test_accepting_the_run_or_a_passing_update_clears_it(first_failed):
    ws = first_failed
    assert run(ws, "runs", "accept", "latest").exit_code == 0
    assert "corpus incomplete" not in run(ws, "search", "rule").output
    assert json.loads(run(ws, "search", "rule", "--json").output)["incomplete"] is False


def test_init_next_hint_is_one_line_for_long_paths(tmp_path):
    root = tmp_path / ("a-rather-long-folder-name-" * 6) / "sigma workspace"
    result = CliRunner().invoke(app, ["init", str(root)], env={"COLUMNS": "60"})
    assert result.exit_code == 0, result.output
    (line,) = [x for x in result.output.splitlines() if x.startswith("next:")]
    assert str(root) in line and line.rstrip().endswith("on demand)")


@pytest.fixture
def first_killed(tmp_path, monkeypatch):
    """A first update whose process was killed (SIGKILL, out of memory) after syncing: the run stays `running`."""
    from sigharvest.models import UpdateRun
    from sigharvest.service import sync_all

    _, ws = make_workspace(tmp_path)
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    with open_db(ws, migrate=True)() as s:
        s.add(UpdateRun(counts={"phase": "index"}))
        s.commit()
    assert all(r.status == "ok" for r in sync_all(ws))  # synced, never indexed
    return ws


def test_a_killed_first_update_counts_as_incomplete(first_killed, tmp_path):
    ws = first_killed
    assert json.loads(run(ws, "search", "rule", "--json").output)["incomplete"] is True
    refused = run(ws, "release", "build", str(tmp_path / "rel"))
    assert refused.exit_code == 1 and "has not finished" in refused.output
    assert not (tmp_path / "rel" / "manifest.json").exists()
    site = run(ws, "site", "build", str(tmp_path / "site"))
    assert site.exit_code == 1 and "not publishing an incomplete corpus" in site.output


def test_the_next_update_records_the_killed_run_as_interrupted(first_killed, monkeypatch):
    from sigharvest.models import UpdateRun

    ws = first_killed
    monkeypatch.setattr(pipeline, "_test", lambda *args, **kwargs: 0)
    result = update(ws)
    assert result.exit_code == 0, result.output
    assert "never finished; recorded as interrupted" in result.output
    with open_db(ws)() as s:
        first, second = s.query(UpdateRun).order_by(UpdateRun.id).all()
    assert first.status == "interrupted" and first.finished_at is not None and "process ended" in first.reasons[0]
    assert second.status == "ok"
    assert json.loads(run(ws, "search", "rule", "--json").output)["incomplete"] is False


def test_release_refuses_an_index_that_does_not_cover_the_corpus(tmp_path, monkeypatch):
    from sigharvest.models import LogicGroup

    _, ws = make_workspace(tmp_path)
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    open_db(ws, migrate=True)
    monkeypatch.setattr(pipeline, "_test", lambda *args, **kwargs: 0)
    assert update(ws).exit_code == 0
    with open_db(ws)() as s:
        s.query(LogicGroup).delete()
        s.commit()
    refused = run(ws, "release", "build", str(tmp_path / "rel"))
    assert refused.exit_code == 1 and "index out of date" in refused.output
    assert run(ws, "site", "build", str(tmp_path / "site")).exit_code == 1
