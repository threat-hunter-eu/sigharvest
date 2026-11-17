"""Rules whose text is not redistributed ship no prose (release, static site) and no YAML (web
JSONL download in the default licence mode)."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sigharvest.config import SourceConfig, Workspace, save_sources
from sigharvest.service import open_db, sync_all

RULE = """title: {title}
id: {uuid}
status: test
description: {secret} prose
author: {secret} author
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: '{needle}'
  condition: selection
level: high
"""


@pytest.fixture(scope="module")
def ws(tmp_path_factory: pytest.TempPathFactory) -> Workspace:
    root = tmp_path_factory.mktemp("metadata_only")
    sources = []
    for name, licence, redistributable, secret in (
        ("open", "MIT", True, "OPEN"),
        ("nolic", None, None, "UNLICENSED"),
        ("restricted", "Elastic-2.0", True, "RESTRICTED"),
    ):
        folder = root / name
        folder.mkdir()
        uuid = {"open": "11111111-1111-4111-8111-111111111111", "nolic": "22222222-2222-4222-8222-222222222222"}.get(
            name, "33333333-3333-4333-8333-333333333333"
        )
        (folder / f"{name}.yml").write_text(RULE.format(title=f"{name} rule", uuid=uuid, secret=secret, needle=f"{name}.exe"))
        sources.append(SourceConfig(name=name, type="local", url=str(folder), licence=licence, redistributable=redistributable))
    workspace = Workspace(root / "ws")
    workspace.root.mkdir()
    save_sources(workspace, sources)
    sessions = open_db(workspace, migrate=True)
    sync_all(workspace, workers=1)
    from sigharvest.index import rebuild
    from sigharvest.lock import mutation_lease

    with mutation_lease(workspace), sessions() as s:
        assert rebuild(s, workers=1) == 3
    return workspace


def _rows(folder: Path) -> dict[str, dict[str, object]]:
    with gzip.open(folder / "rules.jsonl.gz", "rt", encoding="utf-8") as fh:
        return {r["title"]: r for r in map(json.loads, fh)}


def test_release_rows_of_metadata_only_rules_carry_no_prose(ws: Workspace, tmp_path: Path) -> None:
    from sigharvest.release import build

    with open_db(ws)() as s:
        build(s, tmp_path / "rel")
    rows = _rows(tmp_path / "rel")
    assert rows["open rule"]["description"] == "OPEN prose" and rows["open rule"]["author"] == "OPEN author"
    for title in ("nolic rule", "restricted rule"):
        row = rows[title]
        assert row["yaml"] is None and row["description"] is None and row["author"] is None, title
        assert row["title"] == title and row["level"] == "high" and row["logsource"]["product"] == "windows"
    blob = b"".join(p.read_bytes() for p in (tmp_path / "rel").iterdir() if p.is_file())
    for suffix in (".gz",):
        blob += b"".join(gzip.decompress(p.read_bytes()) for p in (tmp_path / "rel").iterdir() if p.name.endswith(suffix))
    assert b"UNLICENSED" not in blob and b"RESTRICTED" not in blob


def test_static_site_has_no_prose_of_metadata_only_rules(ws: Workspace, tmp_path: Path) -> None:
    from sigharvest.site.build import build_site

    build_site(ws.root, tmp_path / "site", collections=[])
    text = b"".join(p.read_bytes() for p in (tmp_path / "site").rglob("*") if p.is_file())
    assert b"OPEN prose" in text
    assert b"UNLICENSED" not in text and b"RESTRICTED" not in text
    # GitHub Pages cannot send headers, so every page carries the CSP as a meta tag.
    pages = list((tmp_path / "site").rglob("*.html"))
    assert pages and all("http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'self'" in p.read_text() for p in pages)


def test_web_jsonl_download_follows_the_licence_mode(ws: Workspace) -> None:
    from sigharvest.web.app import create_app

    with TestClient(create_app(ws, open_db(ws)), base_url="http://127.0.0.1") as client:
        default = client.get("/export/download?scope=all&format=sheet&sheet=jsonl")
        assert default.status_code == 200
        rows = {r["title"]: r for r in map(json.loads, default.text.splitlines())}
        assert "OPEN prose" in str(rows["open rule"]["yaml"])
        assert rows["nolic rule"]["yaml"] is None and rows["restricted rule"]["yaml"] is None
        assert rows["restricted rule"]["text_skipped"].startswith("restricted licence")
        assert "UNLICENSED" not in default.text and "RESTRICTED" not in default.text
        everything = client.get("/export/download?scope=all&format=sheet&sheet=jsonl&licences=all")
        rows = {r["title"]: r for r in map(json.loads, everything.text.splitlines())}
        assert "RESTRICTED" in str(rows["restricted rule"]["yaml"]) and rows["nolic rule"]["yaml"] is None


@pytest.mark.backend("splunk")
def test_cli_convert_prints_the_attribution_line(ws: Workspace) -> None:
    from sqlalchemy import select
    from typer.testing import CliRunner

    from sigharvest.cli import app
    from sigharvest.models import LogicGroup

    with open_db(ws)() as s:
        key = s.scalar(select(LogicGroup.logic_hash).where(LogicGroup.title == "open rule"))
    result = CliRunner().invoke(app, ["convert", key[:16], "--target", "splunk"], env={"SIGHARVEST_HOME": str(ws.root), "COLUMNS": "300"})
    assert result.exit_code == 0, result.output
    assert result.output.splitlines()[0].startswith("# attribution: open rule | author: OPEN author | source: open | licence: MIT")


def test_unit_all_takes_comma_lists_and_says_why_nothing_matched(ws: Workspace, tmp_path: Path) -> None:
    """--unit all applies several values of one filter as a union, like the other units."""
    from typer.testing import CliRunner

    from sigharvest.cli import app

    def export(*args: str) -> tuple[int, str, int]:
        out = tmp_path / f"x{len(list(tmp_path.iterdir()))}.jsonl"
        r = CliRunner().invoke(app, ["export", "--unit", "all", "--format", "jsonl", "--out", str(out), *args], env={"SIGHARVEST_HOME": str(ws.root)})
        return r.exit_code, r.output, len(out.read_text().splitlines()) if out.exists() else 0

    assert export("--source", "open,nolic")[::2] == (0, 2)
    assert export("--status", "test,deprecated")[::2] == (0, 3)
    code, output, _ = export("--source", "nosuch")
    assert code == 1 and "no rule matches these filters" in output and "index is empty" not in output
