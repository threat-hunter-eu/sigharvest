"""Hostile source content must fail fast: regex backtracking, git tree bombs and terminal controls (pre-launch audit)."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from sigharvest import sync
from sigharvest.config import SourceConfig, Workspace
from sigharvest.documents import looks_like_sigma
from sigharvest.ingest import _as_text
from sigharvest.licensing import normalise
from sigharvest.quality_templates import baseline_query
from sigharvest.web.highlight import yaml_html
from tests.test_pipeline import RULE, UIDS


def _fast(fn, *args, limit: float = 5.0):  # type: ignore[no-untyped-def]
    """CPU time of this thread, not wall time: other xdist workers or a loaded machine cannot fail it.

    The fixed regexes take ~0.05 s on these inputs; the quadratic ones they replaced take ~3 s on 1% of them
    (20,000 characters), so hours here: the limit leaves 100x headroom and still catches the regression."""
    t = time.thread_time()
    out = fn(*args)
    assert time.thread_time() - t < limit, f"{fn.__name__} took too long"
    return out


def test_sigma_hint_is_linear_on_blank_lines():
    assert _fast(looks_like_sigma, b"\n" * 2_000_000) is False
    assert _fast(looks_like_sigma, b" \n" * 1_000_000) is False
    assert looks_like_sigma(b"title: x\ndetection:\n  sel: 1\n")
    assert looks_like_sigma(b"\n\n  \tcorrelation :\n")


def test_baseline_title_and_licence_regexes_are_linear():
    assert _fast(baseline_query, "a" + " " * 2_000_000 + "x", None, "experimental") is False
    assert baseline_query("Foo - Analytic 123 Baseline", None, "experimental")
    assert _fast(normalise, "a" + " " * 1_000_000 + "b") == "a-b"
    assert normalise("DRL 1.1 https://github.com/x") == "drl-1.1"
    assert normalise("MIT  <https://x>") == "mit"


def test_terminal_controls_never_reach_the_projections():
    assert _as_text("Benign \x1b]0;pwned\x07\x1b[31mRED\x9b") == "Benign �]0;pwned��[31mRED�"
    assert _as_text(["a\x1b", "b\tc"]) == "a�, b\tc"


def _git(repo: Path, *args: str, stdin: bytes | None = None) -> str:
    return subprocess.run(["git", *args], cwd=repo, input=stdin, capture_output=True, check=True).stdout.decode().strip()


def _tree_bomb(tmp: Path, fanout: int, depth: int) -> Path:
    """fanout**depth paths from a handful of objects (git stores each tree once)."""
    repo = tmp / "bomb"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    blob = _git(repo, "hash-object", "-w", "--stdin", stdin=RULE.format(n="x", uid=UIDS[1]).encode())
    tree = _git(repo, "mktree", stdin="".join(f"100644 blob {blob}\tr{i:03d}.yml\n" for i in range(fanout)).encode())
    for _ in range(depth - 1):
        tree = _git(repo, "mktree", stdin="".join(f"040000 tree {tree}\td{i:03d}\n" for i in range(fanout)).encode())
    env = ["-c", "user.name=t", "-c", "user.email=t@example.com"]
    commit = _git(repo, *env, "commit-tree", tree, "-m", "bomb")
    _git(repo, "update-ref", "refs/heads/main", commit)
    return repo


def test_git_tree_bomb_is_refused_before_anything_is_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sync, "MAX_TREE_ENTRIES", 5_000)
    repo = _tree_bomb(tmp_path, 40, 3)  # 64,000 paths, a few KiB of objects
    ws = Workspace(tmp_path / "ws")
    ws.root.mkdir()
    with pytest.raises(sync.SyncError, match="more than 5000 files"):
        sync.sync_git(SourceConfig(name="evil", url="file://" + str(repo)), ws, None)
    dest = ws.source_dir("evil")
    assert not dest.exists() or not any(p.is_file() for p in dest.rglob("*"))


def test_materialise_caps_the_number_of_rule_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from sigharvest import source_snapshots

    monkeypatch.setattr(source_snapshots, "MAX_SNAPSHOT_FILES", 100)
    repo = _tree_bomb(tmp_path, 20, 2)  # 400 identical rule files
    ws = Workspace(tmp_path / "ws")
    ws.root.mkdir()
    with pytest.raises(sync.SyncError, match="more than 100 rule files"):
        sync.sync_git(SourceConfig(name="evil", url="file://" + str(repo)), ws, None)


def test_cli_console_prints_controls_as_replacement_characters():
    """Rich drops only BEL/BS/VT/FF/CR: ESC in a tag, path, error or query must not reach the terminal."""
    import io

    from rich.table import Table

    from sigharvest.cli.common import SafeConsole

    out = io.StringIO()
    console = SafeConsole(file=out, force_terminal=True, color_system=None, soft_wrap=True)
    console.print("tag \x1b]0;pwned\x1b\\ \x9b2J", markup=False)
    table = Table()
    table.add_column("where")
    table.add_row("src:rules/x\x1b[2J.yml\tok")
    console.print(table)
    console.print("[red]error:[/] multi\nline")
    assert "\x1b" not in out.getvalue() and "\x9b" not in out.getvalue()
    assert "tag �]0;pwned�\\ �2J" in out.getvalue() and "x�[2J.yml" in out.getvalue() and "error: multi\nline" in out.getvalue()


def test_show_does_not_print_terminal_controls_from_upstream_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from sigharvest.cli import app
    from sigharvest.index import rebuild
    from sigharvest.service import open_db, sync_all
    from tests.test_pipeline import commit, git, workspace

    repo = tmp_path / "upstream"
    (repo / "rules").mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    hostile = RULE.format(n="h", uid=UIDS[1]).replace(
        "level: low", 'level: low\ndescription: "d\\e[2J"\nauthor: "a\\e]0;t\\e\\\\"\ntags: ["attack.t1059", "x\\e[1A\\e[2K"]\n'
    )
    (repo / "rules" / "h\x1b[2J.yml").write_text(hostile)
    commit(repo, "init")
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    with open_db(ws, migrate=True)() as s:
        rebuild(s)
        s.commit()
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    res = CliRunner().invoke(app, ["show", UIDS[1], "--copies"])
    assert res.exit_code == 0, res.output

    assert "Test h" in res.output and "x�[1a�[2k" in res.output and "d�[2J" in res.output and "h�[2J.yml" in res.output
    assert "\x1b" not in res.output


def test_condition_highlight_is_linear_on_digit_runs():
    # A long digit run with a non-digit tail (it is not a literal) on a condition line, under MAX_BYTES.
    html = _fast(yaml_html, "detection:\n    condition: " + "1" * 250_000 + "x\n")
    assert "1" * 250_000 + "x" in html
    assert '<span class="y-kw">1 of</span> ' in yaml_html("detection:\n    condition: 1 of selection_*\n")
    assert '<span class="y-kw">12 of</span>' in yaml_html("detection:\n    condition: a12 of them\n")
