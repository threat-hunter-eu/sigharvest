"""Common user mistakes get a short message with a hint instead of a traceback."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from sigharvest.cli import app
from sigharvest.config import Workspace
from sigharvest.errors import SigharvestError
from sigharvest.service import sync_all


def _workspace(tmp_path: Path) -> Workspace:
    (tmp_path / "sources.yaml").write_text(
        "sources:\n- name: sigmahq\n  type: local\n  url: /nonexistent\n  paths: ['**/*.yml']\n"
        "- name: old-repo\n  type: local\n  url: /nonexistent\n  enabled: false\n"
    )
    return Workspace(tmp_path)


def test_unknown_source_suggests_close_names(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    with pytest.raises(SigharvestError, match=r"unknown source 'sigmahqq' \(did you mean sigmahq\?\).*sigharvest sources list"):
        sync_all(ws, names=["sigmahqq"])


def test_disabled_source_is_named_as_disabled(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    with pytest.raises(SigharvestError, match="source 'old-repo' is disabled"):
        sync_all(ws, names=["old-repo"])


def test_show_unknown_key_hints_search(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = CliRunner().invoke(app, ["show", "zzzzzz"], env={"SIGHARVEST_HOME": str(tmp_path)})
    assert "sigharvest search" in result.output or result.exit_code != 0


def test_stats_on_empty_workspace_explains_next_step(tmp_path: Path) -> None:
    from sigharvest.cli import app as cli_app

    (tmp_path / "sources.yaml").write_text("sources: []\n")
    runner = CliRunner()
    runner.invoke(cli_app, ["doctor"], env={"SIGHARVEST_HOME": str(tmp_path)})
    result = runner.invoke(cli_app, ["stats"], env={"SIGHARVEST_HOME": str(tmp_path)})
    assert "sigharvest update" in result.output


def test_show_groups_copies_and_caps_long_source_lists() -> None:
    from types import SimpleNamespace

    from sigharvest.cli.browse import _show_grouped

    def occ(path: str, present: bool = True) -> SimpleNamespace:
        return SimpleNamespace(path=path, present=present)

    where = [(occ("a.yml"), SimpleNamespace(name="one")), (occ("b.yml", False), SimpleNamespace(name="two"))]
    where += [(occ(f"{i}.yml"), SimpleNamespace(name=f"src{i}")) for i in range(8)]
    text = _show_grouped(where, limit=3)  # type: ignore[arg-type]
    assert text.splitlines() == ["one:a.yml", "two:b.yml (removed upstream)", "src0:0.yml", "... and 7 more sources (--copies lists all)"]


def test_sources_list_filters_and_counts(tmp_path: Path) -> None:
    _workspace(tmp_path)
    runner = CliRunner()
    res = runner.invoke(app, ["sources", "list", "OLD"], env={"SIGHARVEST_HOME": str(tmp_path), "COLUMNS": "100"})
    assert res.exit_code == 0, res.output
    assert "old-repo" in res.output and "sigmahq" not in res.output.split("sources (")[0]
    assert "1 of 2 sources (1 disabled)" in " ".join(res.output.split())
    res = runner.invoke(app, ["sources", "list", "--disabled"], env={"SIGHARVEST_HOME": str(tmp_path), "COLUMNS": "100"})
    assert "old-repo" in res.output


def test_doctor_on_new_workspace_points_to_update(tmp_path: Path) -> None:
    from sigharvest.cli import app as cli_app

    (tmp_path / "sources.yaml").write_text("sources:\n- name: sigmahq\n  type: git\n  url: https://github.com/SigmaHQ/sigma.git\n  paths: ['rules/*']\n")
    res = CliRunner().invoke(cli_app, ["doctor"], env={"SIGHARVEST_HOME": str(tmp_path), "COLUMNS": "200"})
    text = " ".join(res.output.split())
    assert "SigmaHQ is not a source" not in text
    assert "New workspace: run `sigharvest update` first" in text


@pytest.mark.parametrize("width", [140, 160])
def test_sources_list_wraps_a_long_name_instead_of_squeezing_columns(tmp_path: Path, monkeypatch, width) -> None:
    import io

    from rich.console import Console

    from sigharvest.cli import sources as cli

    long_name = "averyveryverylongorganisation__an-extremely-long-detection-rules-repository-name"
    (tmp_path / "sources.yaml").write_text(
        f"sources:\n- name: sigmahq\n  type: local\n  url: /nonexistent\n- name: {long_name}\n  type: local\n  url: /nonexistent\n  enabled: false\n"
    )
    out = io.StringIO()
    monkeypatch.setattr(cli, "console", Console(file=out, width=width, color_system=None))
    res = CliRunner().invoke(app, ["sources", "list"], env={"SIGHARVEST_HOME": str(tmp_path)})
    assert res.exit_code == 0, res.output
    text = out.getvalue()
    assert "…" not in text
    header = next(line for line in text.splitlines() if " name " in line)
    for column in ("enabled", "status", "Sigma docs", "licence", "url"):
        assert f" {column} " in header
    assert "not synced" in text and "disabled" in text
    assert long_name in "".join(line.split("│")[1].strip() for line in text.splitlines() if line.startswith("│"))
