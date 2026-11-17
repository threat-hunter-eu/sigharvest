"""lint: your rules against the corpus."""

import json
from pathlib import Path

from sigharvest.lint import Corpus, lint_paths, to_sarif
from sigharvest.release import build
from sigharvest.service import open_db
from tests.helpers import seed_attack
from tests.test_collections import _setup
from tests.test_pipeline import RULE, UIDS


def _corpus(tmp_path: Path) -> Corpus:
    _repo, _ws, S = _setup(tmp_path / "corpus")
    with S() as s:
        return Corpus.from_db(s)


def test_lint_findings(tmp_path: Path) -> None:
    corpus = _corpus(tmp_path)
    mine = tmp_path / "mine"
    mine.mkdir()
    (mine / "copy.yml").write_text(RULE.format(n="a", uid=UIDS[1]))  # exact copy of a corpus rule
    (mine / "collide.yml").write_text(RULE.format(n="zz", uid=UIDS[2]))  # corpus id, other logic
    (mine / "ph.yml").write_text(RULE.format(n="new", uid="a1b2c3d4-e5f6-7890-abcd-ef1234567890").replace("level: low", "level: low\ntags: [attack.T1059_001]"))
    (mine / "broken.yml").write_text("title: x\nlogsource: {product: windows}\ndetection:\n  sel: [unclosed\n")
    found = {(f.path, f.rule) for f in lint_paths([mine], corpus)}
    assert ("copy.yml", "exact-copy") in found
    assert ("collide.yml", "id-collision") in found
    assert ("ph.yml", "placeholder-id") in found and ("ph.yml", "tag-spelling") in found
    assert ("broken.yml", "invalid-yaml") in found
    sarif = to_sarif(lint_paths([mine], corpus))
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    json.dumps(sarif)


def test_lint_against_a_release(tmp_path: Path) -> None:
    _repo, ws, _S = _setup(tmp_path / "corpus")
    with open_db(ws, migrate=True)() as s:
        build(s, tmp_path / "rel")
    corpus = Corpus.from_release(tmp_path / "rel")
    rule = tmp_path / "r.yml"
    rule.write_text(RULE.format(n="b", uid="0d6f3a2e-71c4-4b9a-a5e8-2c9f1b7d4e63"))
    assert {f.rule for f in lint_paths([rule], corpus)} >= {"duplicate-logic"}


def test_lint_and_pull_commands(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from typer.testing import CliRunner

    from sigharvest.cli import app

    _repo, ws, _S = _setup(tmp_path / "corpus")
    seed_attack(ws)  # lint reads the ATT&CK matrix; never download it in tests
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    rule = tmp_path / "r.yml"
    rule.write_text(RULE.format(n="a", uid=UIDS[1]))
    run = CliRunner(env={"COLUMNS": "200"})
    r = run.invoke(app, ["lint", str(rule), "--fail-on", "warning", "--sarif", str(tmp_path / "out.sarif")])
    assert r.exit_code == 1 and "exact-copy" in r.output and (tmp_path / "out.sarif").exists()
    assert run.invoke(app, ["lint", str(rule), "--fail-on", "never"]).exit_code == 0
    assert run.invoke(app, ["site", "build", "--help"]).exit_code == 0
    assert run.invoke(app, ["pull", str(tmp_path / "nope")]).exit_code == 2
