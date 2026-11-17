"""Conversion status `skipped` is carried consistently through release, lint and the static site."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sigharvest.cli import app
from sigharvest.config import SourceConfig, Workspace, save_sources
from sigharvest.release_reader import STATUSES, conversion_summary
from tests.helpers import seed_attack, seed_schemas
from tests.test_pipeline import RULE, UIDS, commit, git

BADMOD = """title: Broken Modifier
id: 0b7d3c6e-91a4-4f58-b2e0-6d1c4a8e9f37
status: test
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endwith: '\\\\bad.exe'
    condition: selection
level: low
"""

FILTER = f"""title: Admin Filter
id: 4e1f9a27-c3d8-4b06-a5e2-8f7b0d6c3a91
logsource:
    product: windows
    category: process_creation
filter:
    rules:
        - {UIDS[1]}
    selection:
        User: admin
    condition: not selection
"""


def test_conversion_status_sets_agree() -> None:
    from sigharvest import conversion

    assert STATUSES is conversion.STATUSES and "skipped" in STATUSES
    assert conversion_summary({"status": "skipped", "sources": {"default": "skipped"}})["status"] == "skipped"


def test_skipped_conversions_release_lint_and_site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "upstream"
    (repo / "rules").mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    (repo / "rules" / "ok.yml").write_text(RULE.format(n="a", uid=UIDS[1]))
    (repo / "rules" / "badmod.yml").write_text(BADMOD)
    (repo / "rules" / "filter.yml").write_text(FILTER)
    commit(repo, "init")
    home = tmp_path / "ws"
    home.mkdir()
    ws = Workspace(home)
    save_sources(ws, [SourceConfig(name="local", type="git", url=str(repo.resolve()), paths=["rules/*"], licence="MIT", redistributable=True)])
    seed_schemas(ws)
    seed_attack(ws)
    monkeypatch.setenv("SIGHARVEST_HOME", str(home))
    runner = CliRunner(env={"COLUMNS": "200"})

    def run(*args: str, code: int = 0) -> str:
        r = runner.invoke(app, list(args))
        assert r.exit_code == code, f"{args} -> {r.exit_code}\n{r.output}\n{r.exception!r}"
        return r.output

    run("update", "--convert", "-j", "1", "--no-report")  # releases store conversions (nightly.yml)
    release = tmp_path / "rel"
    run("release", "build", str(release), "--build-epoch", "1")
    with gzip.open(release / "rules.jsonl.gz", "rt", encoding="utf-8") as fh:
        rows = {r["title"]: r for r in map(json.loads, fh)}
    assert {"Broken Modifier", "Admin Filter", "Test a"} <= set(rows)
    statuses = {t: {v["status"] for v in (r["conversion"] or {}).values()} for t, r in rows.items()}
    assert statuses["Broken Modifier"] == {"skipped"} and statuses["Admin Filter"] == {"skipped"}
    mine = tmp_path / "mine"
    mine.mkdir()
    (mine / "copy.yml").write_text(RULE.format(n="a", uid=UIDS[7]))
    run("lint", str(mine), "--release", str(release), "--fail-on", "never")
    site = tmp_path / "site"
    run("site", "build", str(site), "--release", str(release), "--min-score", "0", "--no-collections")
    assert (site / "rules" / "index.html").is_file()
