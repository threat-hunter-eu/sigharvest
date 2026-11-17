"""Cold help imports, lazy command contracts and unchanged root rendering."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from sigharvest.cli import app
from sigharvest.cli.help import SUMMARIES
from sigharvest.cli.registry import COMMANDS, GROUPS


@pytest.mark.parametrize("args", [[], ["--help"], ["--version"], ["search", "--help"], ["list", "--help"]])
def test_cold_help_never_imports_execution_stack(args: list[str], tmp_path: Path) -> None:
    source = """
import json, sys
from sigharvest.cli import main
try:
    main()
except SystemExit as exc:
    assert exc.code in (0, 2)
print('MODULES=' + json.dumps(sorted(sys.modules)))
"""
    result = subprocess.run(
        [sys.executable, "-c", source, *args],
        capture_output=True,
        text=True,
        check=True,
        env=os.environ | {"SIGHARVEST_HOME": str(tmp_path)},
        timeout=30,
    )
    modules = json.loads(result.stdout.split("MODULES=", 1)[1])
    for prefix in ("sqlalchemy", "sigharvest.service", "sigharvest.models", "fastapi"):
        assert not any(module == prefix or module.startswith(prefix + ".") for module in modules), prefix
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("width", [80, 120])
def test_root_help_lists_every_command_with_a_summary(width: int) -> None:
    result = CliRunner(env={"COLUMNS": str(width)}).invoke(app, ["--help"], prog_name="sigharvest", terminal_width=width)
    assert result.exit_code == 0, result.output
    for name in (*COMMANDS, *GROUPS):
        assert name in SUMMARIES, name
        assert name in result.output, name


@pytest.mark.parametrize("name", sorted((*COMMANDS, *GROUPS)))
def test_every_command_help_builds(name: str) -> None:
    result = CliRunner(env={"COLUMNS": "120"}).invoke(app, [name, "--help"], prog_name="sigharvest")
    assert result.exit_code == 0, result.output
    assert "Usage:" in result.output


def test_lazy_lookup_does_not_resolve_other_groups() -> None:
    root = get_command(app)
    assert not root.commands.loaded
    command = root.commands["search"]
    assert set(root.commands.loaded) == {"search"}
    assert command is root.commands.get("search")
    assert get_command(app).commands.loaded == {}


def test_lazy_entry_point_handles_cooperative_cancellation(monkeypatch, capsys) -> None:
    import sigharvest.cli as cli
    from sigharvest.job_control import Cancelled

    def cancel() -> None:
        raise Cancelled()

    monkeypatch.setattr(cli, "app", cancel)
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 143
    assert "Cancelled; completed work is retained" in capsys.readouterr().err


def test_serve_allow_host_and_env_are_combined(monkeypatch) -> None:
    from sigharvest.cli.serve import extra_hosts

    monkeypatch.setenv("SIGHARVEST_ALLOWED_HOSTS", " a.example, ,b.example")
    assert extra_hosts(["203.0.113.5", " "]) == ["203.0.113.5", "a.example", "b.example"]
