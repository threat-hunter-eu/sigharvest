"""SigmaHQ release-package profiles (--profile core|core+|core++|emerging-threats|all) on every source."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sigharvest.cli import app
from sigharvest.config import SourceConfig, Workspace, save_sources
from sigharvest.service import open_db, sync_all

RULES = {
    # path: (status, level, extra tag)
    "rules/windows/core_high.yml": ("test", "high", None),
    "rules/windows/core_critical.yml": ("stable", "critical", None),
    "rules/windows/core_medium.yml": ("test", "medium", None),
    "rules/windows/experimental_high.yml": ("experimental", "high", None),
    "rules/windows/low.yml": ("stable", "low", None),
    "rules/windows/deprecated_high.yml": ("deprecated", "high", None),
    "rules-emerging-threats/2024/et_high.yml": ("test", "high", None),
    "other/tagged_et.yml": ("experimental", "medium", "detection.emerging-threats"),
    "rules-threat-hunting/th_high.yml": ("stable", "high", None),
    "other/tagged_th.yml": ("stable", "high", "detection.threat-hunting"),
    "rules-placeholder/placeholder_high.yml": ("test", "high", None),
}

EXPECTED = {
    "core": {"core_high", "core_critical"},
    "core+": {"core_high", "core_critical", "core_medium"},
    "core++": {"core_high", "core_critical", "core_medium", "experimental_high"},
    "emerging-threats": {"et_high", "tagged_et"},
    "all": {"core_high", "core_critical", "core_medium", "experimental_high", "et_high", "tagged_et"},
}


def _rule(title: str, n: int, status: str, level: str, tag: str | None) -> str:
    tags = "tags:\n  - attack.t1003\n" + (f"  - {tag}\n" if tag else "")
    return (
        f"title: {title}\nid: 00000000-0000-4000-8000-{n:012d}\nstatus: {status}\nlevel: {level}\n{tags}"
        f"logsource:\n  product: windows\n  category: process_creation\n"
        f"detection:\n  sel:\n    CommandLine|contains: '{title}.exe'\n  condition: sel\n"
    )


@pytest.fixture(scope="module")
def ws(tmp_path_factory: pytest.TempPathFactory) -> Workspace:
    root = tmp_path_factory.mktemp("profiles")
    folder = root / "src"
    for n, (path, (status, level, tag)) in enumerate(RULES.items()):
        f = folder / path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(_rule(Path(path).stem, n, status, level, tag))
    workspace = Workspace(root / "ws")
    workspace.root.mkdir()
    save_sources(workspace, [SourceConfig(name="mixed", type="local", url=str(folder), licence="MIT", redistributable=True)])
    sessions = open_db(workspace, migrate=True)
    sync_all(workspace, workers=1)
    from sigharvest.index import rebuild
    from sigharvest.lock import mutation_lease

    with mutation_lease(workspace), sessions() as s:
        assert rebuild(s, workers=1) == len(RULES)
    return workspace


def run(ws: Workspace, *args: str):  # type: ignore[no-untyped-def]
    return CliRunner().invoke(app, list(args), env={"SIGHARVEST_HOME": str(ws.root), "COLUMNS": "200"})


@pytest.mark.parametrize("profile", list(EXPECTED))
def test_search_profile_matches_sigmahq_packages(ws: Workspace, profile: str) -> None:
    result = run(ws, "search", "--profile", profile, "--json", "--limit", "100", "--per-logic")
    assert result.exit_code == 0, result.output
    assert {r["title"] for r in json.loads(result.output)["results"]} == EXPECTED[profile]


def test_aliases_and_unknown_profile(ws: Workspace) -> None:
    et = run(ws, "search", "--profile", "et", "--json", "--per-logic")
    assert {r["title"] for r in json.loads(et.output)["results"]} == EXPECTED["emerging-threats"]
    bad = run(ws, "search", "--profile", "core+++")
    assert bad.exit_code != 0 and "unknown profile" in bad.output


@pytest.mark.parametrize("unit", ["logic", "all"])
def test_export_profile(ws: Workspace, tmp_path: Path, unit: str) -> None:
    out = tmp_path / f"{unit}.jsonl"
    result = run(ws, "export", "--profile", "core+", "--format", "jsonl", "--unit", unit, "--out", str(out))
    assert result.exit_code == 0, result.output
    assert {json.loads(line)["title"] for line in out.read_text().splitlines()} == EXPECTED["core+"]


def test_web_search_takes_the_profile_parameter(ws: Workspace) -> None:
    from fastapi.testclient import TestClient

    from sigharvest.web.app import create_app

    with TestClient(create_app(ws, open_db(ws)), base_url="http://127.0.0.1") as client:
        data = client.get("/api/search?profile=core&view=logic&limit=100").json()
        assert {r["title"] for r in data["results"]} == EXPECTED["core"]
        assert client.get("/api/search?profile=nope").status_code == 400
