"""CLI behaviour a community user and cron jobs rely on: exit codes, no stray databases, tokens out of argv."""

import subprocess
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from sigharvest import sync as sync_mod
from sigharvest.cli import app as cli_app
from sigharvest.config import SourceConfig, Workspace, save_sources
from sigharvest.service import NoWorkspace, open_db


def test_no_database_outside_a_workspace(tmp_path: Path) -> None:
    with pytest.raises(NoWorkspace):
        open_db(Workspace(tmp_path), migrate=True)
    assert not (tmp_path / "data").exists()


def test_sync_exit_code_on_failed_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = Workspace(tmp_path / "ws")
    ws.root.mkdir()
    save_sources(ws, [SourceConfig(name="bogus", type="git", url=str(tmp_path / "missing-repo"), paths=["*"])])
    open_db(ws, migrate=True)
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    run = CliRunner()
    r = run.invoke(cli_app, ["sync"])
    assert r.exit_code == 1 and "1 sources failed" in r.output
    assert run.invoke(cli_app, ["sync", "--allow-failures"]).exit_code == 0


def test_token_is_not_in_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        seen["cmd"], seen["env"] = cmd, kw["env"]
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(sync_mod.subprocess, "run", fake_run)
    sync_mod._git(["ls-remote", "--", "https://github.com/x/y.git"], token="s3cret", url="https://github.com/x/y.git")
    assert not any("s3cret" in part for part in seen["cmd"])
    assert seen["env"]["GIT_CONFIG_VALUE_0"] == "Authorization: Bearer s3cret"
    assert sync_mod._auth_header("t", "https://gitlab.com/g/p.git").startswith("Authorization: Basic ")


def test_init_presets(tmp_path: Path) -> None:
    from sigharvest.config import load_sources, preset_sources

    run = CliRunner()
    r = run.invoke(cli_app, ["init", str(tmp_path / "ws")])
    assert r.exit_code == 0, r.output
    ws = Workspace(tmp_path / "ws")
    assert [s.name for s in load_sources(ws)][:1] == ["sigmahq-core"] and ws.db_path.exists()
    assert len(load_sources(ws)) == len(preset_sources("curated")) >= 20
    assert all(s.type == "git" for s in load_sources(ws))
    assert run.invoke(cli_app, ["init", str(tmp_path / "ws")]).exit_code == 1  # no silent overwrite
    assert [s.name for s in preset_sources("sigmahq")] == ["sigmahq-core"]
    every = preset_sources("all")
    assert len(every) > 1000 and len({s.name for s in every}) == len(every)
    assert [s.name for s in every[: len(preset_sources("curated"))]] == [s.name for s in preset_sources("curated")]  # curated + extended
    assert not any(s.name.startswith("adpermana__") for s in every)
    # The bundled presets are the repository's lists (the nightly reads sources/, `init` the package copies).
    root = Path(__file__).resolve().parents[1]
    for name in ("curated", "extended"):
        assert (root / "src/sigharvest/presets" / f"{name}.yaml").read_bytes() == (root / "sources" / f"{name}.yaml").read_bytes()
    r = run.invoke(cli_app, ["init", str(tmp_path / "small"), "--preset", "sigmahq"])
    assert r.exit_code == 0 and [s.name for s in load_sources(Workspace(tmp_path / "small"))] == ["sigmahq-core"]
    import os

    os.environ["SIGHARVEST_HOME"] = str(tmp_path / "ws")
    try:
        assert "index is empty" in run.invoke(cli_app, ["search", "mimikatz"]).output
    finally:
        del os.environ["SIGHARVEST_HOME"]


def test_export_collection_refuses_unit_all(tmp_path: Path) -> None:
    """--collection with --unit all used to skip the check and silently export every copy instead."""
    r = CliRunner().invoke(cli_app, ["export", "-c", "x", "--unit", "all", "--out", str(tmp_path / "out")])
    assert r.exit_code == 2 and "one copy per rule" in r.output
