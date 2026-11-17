"""One rule with many `|windash` tokens must not stall validation, conversion or `update`."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sigharvest import conversion
from sigharvest.config import SourceConfig, Workspace, save_sources
from sigharvest.pysigma_limits import WINDASH_MAX_TOKENS, windash_tokens
from tests.helpers import SCHEMA_FIXTURES, seed_attack, seed_schemas
from tests.test_pipeline import RULE, UIDS, commit, git

DASHES = " ".join(f"-x{i}" for i in range(10))
BOMB = f"""title: Windash Bomb
id: 1d5e8f3a-7b2c-4e91-a6d0-3c8b9f2e7a14
status: test
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|windash|contains: '{DASHES}'
    condition: selection
level: low
"""


def test_windash_tokens_counted_like_pysigma() -> None:
    assert windash_tokens(DASHES) == 10 and windash_tokens("-a /b c-d") == 2 and WINDASH_MAX_TOKENS < 10


def test_ten_dash_rule_converts_and_validates_fast() -> None:
    from sigharvest import testing
    from sigharvest.semantic import semantic_hash

    start = time.monotonic()
    conv = conversion.convert(BOMB, "splunk", timeout=None)
    assert conv.status == "skipped" and "windash" in (conv.reason or "")
    assert semantic_hash(BOMB) is None
    testing._init_worker(SCHEMA_FIXTURES, "validate")
    _vid, _kind, status, detail = testing._validate_one((1, "rule", BOMB))
    assert status == "error" and any("windash" in p for p in detail["parse"])
    assert time.monotonic() - start < 20
    # a normal windash value still converts
    assert conversion.convert(BOMB.replace(DASHES, "-enc -nop"), "splunk").status in ("ok", "partial")


def test_update_survives_a_windash_bomb(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest.cli import app

    repo = tmp_path / "upstream"
    (repo / "rules").mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    (repo / "rules" / "ok.yml").write_text(RULE.format(n="a", uid=UIDS[1]))
    (repo / "rules" / "bomb.yml").write_text(BOMB)
    commit(repo, "init")
    ws = Workspace(tmp_path / "ws")
    ws.root.mkdir()
    save_sources(ws, [SourceConfig(name="local", url=str(repo.resolve()), paths=["rules/*"])])
    seed_schemas(ws)
    seed_attack(ws)
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    start = time.monotonic()
    r = CliRunner().invoke(app, ["update", "-j", "1", "--no-report"])
    assert r.exit_code == 0, r.output
    assert time.monotonic() - start < 120


def _rule(selection: str) -> str:
    return BOMB.replace(f"        CommandLine|windash|contains: '{DASHES}'\n", selection)


@pytest.mark.parametrize(
    "selection",
    [
        # chained windash multiplies the expansions of each value
        "        CommandLine|windash|windash|contains: '-a -b -c -d -e'\n",
        "        CommandLine|windash|contains|windash: '-a -b -c'\n",
        # many fields and values, each under the per-value limit, together far above the per-document budget
        "".join(f"        Field{i}|windash|contains:\n" + "".join(f"            - '-a{j} -b{j} -c{j} -d{j} -e{j}'\n" for j in range(4)) for i in range(4)),
    ],
)
def test_windash_chains_and_totals_are_refused_fast(selection: str) -> None:
    raw = _rule(selection)
    start = time.monotonic()
    conv = conversion.convert(raw, "splunk")
    assert conv.status == "skipped" and "windash" in (conv.reason or ""), conv.reason
    assert time.monotonic() - start < 20
