"""Collections: saved rule sets that survive index rebuilds and follow upstream changes."""

from pathlib import Path

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

from sigharvest import collections as col
from sigharvest.cli import app as cli_app
from sigharvest.index import rebuild
from sigharvest.models import LogicGroup
from sigharvest.service import open_db, sync_all
from tests.test_pipeline import RULE, UIDS, commit, make_repo, workspace


def _setup(tmp_path: Path):  # type: ignore[no-untyped-def]
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    S = open_db(ws, migrate=True)
    with S() as s:
        rebuild(s)
        s.commit()
    return repo, ws, S


def _by_title(s, title: str) -> LogicGroup:  # type: ignore[no-untyped-def]
    return s.scalars(select(LogicGroup).where(LogicGroup.title == title)).one()


def test_collection_follows_upstream_changes(tmp_path: Path) -> None:
    repo, ws, S = _setup(tmp_path)
    with S() as s:
        c = col.create(s, "mine", "test set")
        assert col.add(s, c, [_by_title(s, "Test a"), _by_title(s, "Test b")], note="why") == 2
        assert col.add(s, c, [_by_title(s, "Test b")]) == 0  # no duplicates
        s.commit()
        assert [r.state for r in col.resolve(s, c)] == ["current", "current"]
        with pytest.raises(col.CollectionError):
            col.create(s, "mine")
        with pytest.raises(col.CollectionError):
            col.create(s, "../bad")

    # upstream: b's detection changes (same id), a is deleted
    (repo / "rules" / "b.yml").write_text(RULE.format(n="b", uid=UIDS[2]).replace("b.exe", "b2.exe"))
    (repo / "rules" / "a.yml").unlink()
    commit(repo, "change")
    assert sync_all(ws)[0].status == "ok"
    with S() as s:
        rebuild(s)
        s.commit()
        c = col.require(s, "mine")
        states = {r.item.title: r.state for r in col.resolve(s, c)}
        assert states == {"Test a": "missing", "Test b": "updated"}
        assert [g.title for g in col.groups(s, c)] == ["Test b"]
        assert col.follow_updates(s, c) == 1
        s.commit()
        assert {r.item.title: r.state for r in col.resolve(s, c)} == {"Test a": "missing", "Test b": "current"}
        assert col.remove(s, c, [col.resolve(s, c)[0].item.logic_hash[:8]]) == 1
        s.commit()
        assert len(col.resolve(s, c)) == 1


def test_collection_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _repo, ws, _S = _setup(tmp_path)
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    run = CliRunner()
    r = run.invoke(cli_app, ["collection", "add", "cli", "-q", "Test", "--note", "first"])
    assert r.exit_code == 0, r.output
    assert "added 5" in r.output
    r = run.invoke(cli_app, ["collection", "show", "cli"])
    assert r.exit_code == 0 and "Test c" in r.output
    out = tmp_path / "exp"
    r = run.invoke(cli_app, ["export", "-c", "cli", "--out", str(out), "--include-private-sources"])
    assert r.exit_code == 0, r.output
    r = run.invoke(cli_app, ["collection", "import", "copy", str(out / "manifest.jsonl")])
    assert r.exit_code == 0 and "added 5" in r.output
    zipped = tmp_path / "copy.zip"
    r = run.invoke(cli_app, ["export", "-c", "copy", "--format", "zip", "--out", str(zipped), "--include-private-sources"])
    assert r.exit_code == 0 and zipped.is_file(), r.output
    assert run.invoke(cli_app, ["collection", "show", "nope"]).exit_code == 2
    r = run.invoke(cli_app, ["collection", "delete", "copy", "-y"])
    assert r.exit_code == 0
    assert "copy" not in run.invoke(cli_app, ["collection", "list"]).output
