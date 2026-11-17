"""Sharing the corpus: check your rules against it (lint) and the static rules site (site build, in sigharvest.site)."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.markup import escape
from rich.table import Table

from sigharvest.cli.common import console, open_session

site_app = typer.Typer(help="Static rules site (search, rule pages, collections), for example on GitHub Pages.", no_args_is_help=True)


def _register_site() -> None:
    from sigharvest.site import site_command

    site_app.command("build")(site_command)


_register_site()


def lint(
    paths: list[Path] = typer.Argument(..., exists=True, readable=True, help="Rule files or folders."),
    release: str | None = typer.Option(None, help="Compare with a data release folder instead of this workspace's index."),
    sarif: Path | None = typer.Option(None, help="Also write a SARIF 2.1.0 report (GitHub code scanning)."),
    json_out: Path | None = typer.Option(None, "--json", help="Also write the findings as JSON."),
    fail_on: str = typer.Option("error", help="Finding threshold: error, warning or note. Exit 1 at or above it; never disables finding-based failure."),
) -> None:
    """Check your own rules against the whole corpus: invalid detections, reused or colliding ids, copies and
    duplicate logic, quality flags, ATT&CK tags."""
    from sigharvest.lint import LEVELS, Corpus, as_json, lint_paths, to_sarif

    if fail_on not in (*LEVELS, "never"):
        raise typer.BadParameter("fail-on: error, warning, note or never")
    if release:
        folder = Path(release)
        if release.startswith("https://"):
            import tempfile

            from sigharvest.release_reader import fetch_release

            with tempfile.TemporaryDirectory(prefix="sigharvest-release-") as tmp:
                corpus = Corpus.from_release(fetch_release(release, Path(tmp)))
        else:
            corpus = Corpus.from_release(folder)
    else:
        with open_session() as s:
            corpus = Corpus.from_db(s)
    matrix = None
    try:
        from sigharvest.attack import load_matrix
        from sigharvest.config import find_workspace

        matrix = load_matrix(find_workspace())
    except Exception:  # noqa: BLE001 - ATT&CK checks are optional (offline CI)
        console.print("[dim]ATT&CK data not available: technique checks skipped[/]")
    findings = lint_paths(paths, corpus, matrix)
    t = Table("level", "file", "line", "check", "message")
    colour = {"error": "red", "warning": "yellow", "note": "dim"}
    for f in sorted(findings, key=lambda f: (LEVELS.index(f.level), f.path, f.line)):
        t.add_row(f"[{colour[f.level]}]{f.level}[/]", escape(f.path), str(f.line), f.rule, escape(f.message))
    console.print(t if findings else "no findings")
    if sarif:
        sarif.write_text(json.dumps(to_sarif(findings), indent=1), encoding="utf-8")
    if json_out:
        json_out.write_text(json.dumps(as_json(findings), indent=1, ensure_ascii=False), encoding="utf-8")
    counts = {lv: sum(1 for f in findings if f.level == lv) for lv in LEVELS}
    console.print(", ".join(f"{n} {lv}" for lv, n in counts.items()))
    if fail_on != "never" and any(counts[lv] for lv in LEVELS[: LEVELS.index(fail_on) + 1]):
        raise typer.Exit(1)
