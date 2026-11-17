"""Remote checks use local git fixtures, including runners restored from a DB-only cache."""

import shutil
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

from sigharvest import sync
from sigharvest.cli import app
from sigharvest.config import SourceConfig, load_sources, save_sources
from sigharvest.models import Occurrence, Quarantine, Source
from sigharvest.service import open_db, sync_all
from tests.test_pipeline import commit, git, make_repo, workspace
from tests.test_update_runs import latest, make_workspace, update


def test_database_only_skip_and_changed_source_deletions(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws, remote_check=True)[0].status == "ok"
    shutil.rmtree(ws.cache)
    shutil.rmtree(ws.corpus)
    with patch.object(sync, "_git", wraps=sync._git) as calls:
        result = sync_all(ws, remote_check=True)[0]
        assert result.status == "ok"
        assert result.log.files_added == result.log.files_removed == result.log.versions_new == 0
        assert [c.args[0][0] for c in calls.call_args_list] == ["ls-remote"]
    assert not ws.cache.exists() and not ws.corpus.exists()

    (repo / "rules/a.yml").unlink()
    (repo / "rules/broken.yml").unlink()
    commit(repo, "remove rule and quarantine")
    result = sync_all(ws, remote_check=True)[0]
    assert result.status == "ok", result.message
    assert result.log.files_removed == 2
    with open_db(ws, migrate=True)() as s:
        assert not s.scalars(select(Occurrence).where(Occurrence.path == "rules/a.yml")).one().present
        assert not s.scalars(select(Quarantine)).one().present


def test_remote_failure_preserves_ingested_state(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    sync_all(ws)
    with open_db(ws, migrate=True)() as s:
        previous = s.scalars(select(Source)).one().last_commit
    shutil.rmtree(repo)
    result = sync_all(ws, remote_check=True)[0]
    assert result.status == "error"
    with open_db(ws, migrate=True)() as s:
        assert s.scalars(select(Source)).one().last_commit == previous
        assert all(o.present for o in s.scalars(select(Occurrence)))


def test_changed_selection_and_url_force_full_ingest(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    sync_all(ws)
    cfg = load_sources(ws)[0]
    cfg.exclude = ["rules/a.yml", "rules/broken.yml"]
    save_sources(ws, [cfg])
    result = sync_all(ws, remote_check=True)[0]
    assert result.status == "ok" and result.log.files_removed == 2
    with open_db(ws, migrate=True)() as s:
        assert not s.scalars(select(Occurrence).where(Occurrence.path == "rules/a.yml")).one().present
    # Changing the URL must fetch the configured repository, not the old cached origin.
    new = tmp_path / "new-upstream"
    shutil.copytree(repo, new)
    (new / "rules/b.yml").unlink()
    commit(new, "different upstream")
    cfg.url = str(new)
    save_sources(ws, [cfg])
    assert sync_all(ws, remote_check=True)[0].status == "ok"
    with open_db(ws, migrate=True)() as s:
        assert not s.scalars(select(Occurrence).where(Occurrence.path == "rules/b.yml")).one().present


@pytest.mark.parametrize("ref", [None, "HEAD", "main", "refs/heads/main", "release", "refs/tags/release"])
def test_head_branch_and_annotated_tag(tmp_path: Path, ref: str | None) -> None:
    repo = make_repo(tmp_path)
    git(repo, "branch", "-M", "main")
    git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.org", "tag", "-a", "release", "-m", "release")
    src = SourceConfig(name="fixture", type="git", url=str(repo), ref=ref)
    assert sync.remote_commit(src) == sync._git(["rev-parse", "HEAD"], cwd=repo).strip()
    ws = workspace(tmp_path, repo)
    save_sources(ws, [src])
    assert sync_all(ws, remote_check=True)[0].status == "ok"
    with patch.object(sync, "_git", wraps=sync._git) as calls:
        assert sync_all(ws, remote_check=True)[0].status == "ok"
        assert [c.args[0][0] for c in calls.call_args_list] == ["ls-remote"]


def test_ambiguous_missing_and_unsafe_refs(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    git(repo, "branch", "collision")
    git(repo, "tag", "collision")
    for ref in ["collision", "missing", "--upload-pack=bad"]:
        with pytest.raises(sync.SyncError):
            sync.remote_commit(SourceConfig(name="fixture", type="git", url=str(repo), ref=ref))


@pytest.mark.slow
def test_remote_check_cli_and_update_resume(tmp_path: Path) -> None:
    _, ws = make_workspace(tmp_path)
    first_code, first_output = update(ws, "--remote-check")
    assert first_code == 0, first_output
    shutil.rmtree(ws.cache / "git")
    shutil.rmtree(ws.corpus)
    with patch.object(sync, "_git", wraps=sync._git) as calls:
        code, output = update(ws, "--remote-check")
        assert code == 0, output
        assert "index up to date" in output
        assert "0 processed" in output
        assert [c.args[0][0] for c in calls.call_args_list] == ["ls-remote"]
    assert latest(ws).status == "ok"
    result = CliRunner().invoke(app, ["sync", "--remote-check"], env={"SIGHARVEST_HOME": str(ws.root)})
    assert result.exit_code == 0, result.output


def test_explicit_tag_wins_over_same_named_branch(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    tag_commit = sync._git(["rev-parse", "HEAD"], cwd=repo).strip()
    git(repo, "tag", "collision")
    (repo / "rules/a.yml").unlink()
    commit(repo, "branch differs from tag")
    git(repo, "branch", "collision")
    ws = workspace(tmp_path, repo)
    cfg = load_sources(ws)[0]
    cfg.ref = "refs/tags/collision"
    save_sources(ws, [cfg])
    result = sync_all(ws, remote_check=True)[0]
    assert result.status == "ok", result.message
    assert result.log.new_commit == tag_commit
    with open_db(ws, migrate=True)() as s:
        assert s.scalars(select(Occurrence).where(Occurrence.path == "rules/a.yml")).one().present
