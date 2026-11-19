"""`search --all-copies` lists copies: options it cannot apply are refused, not ignored; deprecated copies follow --include-deprecated."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sigharvest.cli import app
from sigharvest.config import Workspace, save_sources
from sigharvest.models import Occurrence, RuleVersion, Source
from sigharvest.service import open_db


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    ws = Workspace(tmp_path)
    save_sources(ws, [])
    with open_db(ws, migrate=True)() as s:
        src = Source(name="a", type="local", url="a", priority=50)
        s.add(src)
        s.flush()
        for i, (title, status) in enumerate((("Live rule", "test"), ("Retired rule", "deprecated"))):
            v = RuleVersion(
                content_hash=f"c{i}",
                logic_hash=f"l{i}",
                rule_id=f"{i:08d}-0000-0000-0000-000000000000",
                kind="rule",
                title=title,
                status=status,
                raw="title: x",
            )
            s.add(v)
            s.flush()
            s.add(Occurrence(version_id=v.id, source_id=src.id, path=f"{i}.yml", file_hash=f"c{i}", present=True, first_seen=datetime(2026, 1, 1)))
        s.commit()
    return {"SIGHARVEST_HOME": str(ws.root), "COLUMNS": "200"}


def run(env: dict[str, str], *args: str):  # type: ignore[no-untyped-def]
    return CliRunner().invoke(app, ["search", "--all-copies", *args], env=env)


def test_deprecated_copies_are_hidden_unless_asked(env: dict[str, str]) -> None:
    default = run(env)
    assert default.exit_code == 0 and "Live rule" in default.output and "Retired rule" not in default.output
    asked = run(env, "--include-deprecated")
    assert asked.exit_code == 0 and "Retired rule" in asked.output


@pytest.mark.parametrize(
    "option",
    [
        ["--technique", "T1059"],
        ["--tactic", "execution"],
        ["--validation", "ok"],
        ["--backend", "splunk"],
        ["--min-sources", "2"],
        ["--flag", "ioc_list"],
        ["--include-junk"],
        ["--sort", "title"],
        ["--offset", "1"],
    ],
)
def test_options_that_cannot_apply_to_copies_are_refused(env: dict[str, str], option: list[str]) -> None:
    result = run(env, *option)
    assert result.exit_code == 2
    assert option[0] in result.output and "--all-copies" in result.output
