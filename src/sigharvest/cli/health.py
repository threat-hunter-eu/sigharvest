"""`sigharvest doctor` (is the workspace healthy?) and `sigharvest runs` (past updates and their reports)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich.markup import escape
from rich.text import Text

from sigharvest.cli.common import console, error, mutation_command, open_session, user_errors
from sigharvest.cli.presentation import ResponsiveTable as Table
from sigharvest.config import find_workspace

if TYPE_CHECKING:
    from sigharvest.health import Check

runs_app = typer.Typer(help="Past `sigharvest update` runs: status, gates and what changed.", invoke_without_command=True)


def format_doctor(checks: list[Check], root: Path) -> Text:
    """Summarize checks without I/O or mutation; only identical fixes share an action.

    Literal Text keeps paths, names, messages and actions out of Rich markup.
    Folding preserves long tokens at narrow terminal widths.
    """
    counts = {status: sum(c.status == status for c in checks) for status in ("ok", "warn", "fail")}
    status = "fail" if counts["fail"] else "warn" if counts["warn"] else "ok"
    verdict = {"fail": "not healthy", "warn": "healthy, with warnings", "ok": "healthy"}
    styles = {"fail": "red", "warn": "yellow", "ok": "green"}
    result = Text(overflow="fold", no_wrap=False)
    result.append(verdict[status], style=styles[status])
    warnings = f"{counts['warn']} warning" + ("" if counts["warn"] == 1 else "s")
    failures = f"{counts['fail']} failure" + ("" if counts["fail"] == 1 else "s")
    result.append(f": {counts['ok']} ok, {warnings}, {failures}\n")
    result.append(f"Workspace: {root}\n")
    if any(c.name == "updates" and c.status == "warn" and "no `sigharvest update` recorded" in c.message for c in checks):
        result.append("New workspace: run `sigharvest update` first; it syncs, validates and indexes, which clears most of these warnings.\n")
    actions: dict[str, list[str]] = {}
    for check in checks:
        if check.status == "ok":
            continue
        result.append(f"{check.status.upper()} ", style=styles[check.status])
        result.append(f"{check.name}: {check.message}\n")
        if check.fix:
            actions.setdefault(check.fix, []).append(check.name)
    for fix, names in actions.items():
        result.append(f"Action ({', '.join(names)}): {fix}\n")
    result.append("Full results, including passed checks: sigharvest doctor --json", style="dim")
    return result


@mutation_command(when="clean_cache")
def doctor(
    as_json: bool = typer.Option(False, "--json", help="Print the checks as JSON."),
    deep: bool = typer.Option(False, "--deep", help="Also run PRAGMA quick_check on the database (about a minute per GB)."),
    stale_days: int = typer.Option(7, min=0, help="Report enabled sources not synced for more than this many days."),
    clean_cache: bool = typer.Option(False, "--clean-cache", help="Only delete verification clones in data/cache/discovery (asks first); skip health checks."),
    yes: bool = typer.Option(False, "--yes", "-y", help="With --clean-cache: do not ask."),
) -> None:
    """Check workspace health and show problems with their existing actions. Exit 1 if a check fails.

    Checks cover schema, updates, index, sources, tests, ATT&CK data, disk and the workspace lock. This explicit
    maintenance command can initialize or migrate the database under the workspace lease before checking,
    including with --json or --deep.

    --deep adds a database integrity check. --clean-cache only removes discovery verification clones. Use --json
    for all check results.
    """
    from sigharvest import health

    ws = find_workspace()
    if clean_cache:
        size = health.discovery_clones_size(ws)
        if not size:
            console.print("data/cache/discovery holds no verification clones")
            return
        if not yes and not typer.confirm(f"delete {health._gb(size)} of verification clones in data/cache/discovery?"):
            raise typer.Exit(1)
        console.print(f"freed {health._gb(health.clean_discovery_cache(ws))} (the verification results in {health.VERIFY_CACHE} are kept)")
        return
    with user_errors():
        from sigharvest.lock import LockHeld, mutation_lease
        from sigharvest.service import open_db

        if ws.db_path.exists() or ws.sources_file.exists():
            try:
                with mutation_lease(ws):
                    open_db(ws, migrate=True)
            except LockHeld:
                # Health reads remain useful during replay. run_checks verifies
                # the current schema before opening the normal read session.
                pass
        checks = health.run_checks(ws, deep=deep, stale_days=stale_days)
    if as_json:
        print(json.dumps(health.as_json(checks)))
    else:
        console.print(format_doctor(checks, ws.root))
    if any(c.status == "fail" for c in checks):
        raise typer.Exit(1)


@runs_app.callback()
def _runs(ctx: typer.Context) -> None:
    """Without a subcommand: the same as `sigharvest runs list`."""
    if ctx.invoked_subcommand is None:
        runs_list(limit=20)


@runs_app.command("list")
def runs_list(
    limit: int = typer.Option(20, min=1, help="Runs to list."),
    json_output: bool = typer.Option(False, "--json", help="Print the runs as JSON."),
) -> None:
    """List past updates, newest first."""
    from sqlalchemy import func, select

    from sigharvest.models import UpdateRun

    with open_session() as s:
        rows = list(s.scalars(select(UpdateRun).order_by(UpdateRun.id.desc()).limit(limit)))
        total = s.scalar(select(func.count()).select_from(UpdateRun)) or 0
    if json_output:
        results = [
            {
                "id": r.id,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                "status": r.status,
                "accepted": r.status == "accepted",
                "counts": r.counts or {},
                "reasons": list(r.reasons or []),
                "report": r.report,
            }
            for r in rows
        ]
        print(json.dumps({"total": total, "offset": 0, "limit": limit, "results": results}, default=str))
        return
    if not rows:
        console.print("no update runs yet: `sigharvest update` records one")
        return
    t = Table("id", "started (UTC)", "min", "status", "new", "changed", "removed", "unique logic", "failed sources")
    colour = {"ok": "green", "source failures": "yellow", "accepted": "yellow", "failed gate": "red", "error": "red"}
    for r in rows:
        c = r.counts or {}
        mins = f"{(r.finished_at - r.started_at).total_seconds() / 60:.1f}" if r.finished_at else ""
        st = f"[{colour.get(r.status, 'white')}]{r.status}[/]"
        t.add_row(
            str(r.id),
            f"{r.started_at:%Y-%m-%d %H:%M}",
            mins,
            st,
            *(str(c.get(k, "")) for k in ("new", "changed", "removed", "unique_logic", "sources_failed")),
        )
    console.print(t)


@runs_app.command("show")
def runs_show(run: str = typer.Argument("latest", help="Run id, or latest.")) -> None:
    """Print one run's report (reports/runs/<stamp>.md)."""
    from sigharvest.runs import clean_text, get_run

    ws = find_workspace()
    with open_session() as s:
        r = get_run(s, run)
    if r is None:
        error(f"no update run {escape(run)} (list them with `sigharvest runs list`)")
        raise typer.Exit(1)
    path = ws.root / r.report if r.report else None
    if path is not None and path.exists():
        print(clean_text(path.read_text(encoding="utf-8")), end="")  # reports written before sanitising existed
        return
    availability = "expired or missing; stored run summary retained" if r.report else "not written; stored run summary retained"
    console.print(f"run {r.id}: {r.status} (report {availability})")
    for line in r.reasons or []:
        console.print(f"- {escape(clean_text(line))}")
    console.print_json(json.dumps({"counts": r.counts, "gates": r.gates, "durations": r.durations}))


@runs_app.command("accept")
@mutation_command()
def runs_accept(run: str = typer.Argument("latest", help="Run id, or latest.")) -> None:
    """Accept a run that failed a gate as the new baseline (for example after removing a large source on purpose)."""
    from sigharvest.runs import get_run

    with open_session() as s:
        r = get_run(s, run)
        if r is None:
            raise typer.BadParameter(f"no such run: {run}")
        if r.status != "failed gate":
            error(f"run {escape(run)} is not a run that failed a gate")
            raise typer.Exit(2)
        r.status = "accepted"
        s.commit()
        console.print(f"run {r.id} accepted: the next update compares with its counts")


def version() -> None:
    """Print the sigharvest version, the database schema revision this version writes, and the main library versions.

    Needs no workspace. `sigharvest --version` prints only the first part."""
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as installed

    from sigharvest import __version__
    from sigharvest.schema import head_revision

    console.print(f"sigharvest {__version__}, schema {head_revision()}", highlight=False)
    for package in ("pySigma", "sqlalchemy", "fastapi"):
        try:
            console.print(f"{package} {installed(package)}", highlight=False)
        except PackageNotFoundError:
            console.print(f"{package} not installed", highlight=False)
