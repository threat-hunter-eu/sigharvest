"""Reports on the whole corpus: `report` (reports/summary.md), `discover` (new repositories) and `coverage` (ATT&CK)."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from sigharvest.cli.choices import Validation
from sigharvest.cli.common import console, mutation_command
from sigharvest.config import find_workspace
from sigharvest.service import open_db

if TYPE_CHECKING:
    from sigharvest.attack import Coverage


@mutation_command()
def report(rule_json: bool = typer.Option(True, "--rule-json/--no-rule-json", help="Also write reports/rules/<content_hash>.json per rule.")) -> None:
    """Write reports/summary.md (and reports/rules/<content_hash>.json)."""
    from sigharvest.report import build_summary

    ws = find_workspace()
    S = open_db(ws)
    with S() as s:
        path = build_summary(s, ws.reports, rule_json=rule_json)
    console.print(f"wrote {path}")


@mutation_command()
def discover(
    max_repos: int = typer.Option(1000, "--max-repos", min=0, help="Candidates to verify by cloning (seeds always included); 0 = all."),
    min_rules: int = typer.Option(5, "--min-rules", min=1, help="Register repositories with at least this many valid Sigma rules."),
    auto_add: bool = typer.Option(True, "--auto-add/--no-auto-add", help="Write verified repositories to sources.yaml."),
    top: int = typer.Option(100, "--top", min=1, help="Size of discovery/top100.md; these repositories are added enabled."),
    workers: int = typer.Option(6, "--workers", min=1, help="Parallel clones."),
    max_code_requests: int = typer.Option(400, "--max-code-requests", min=0, help="Budget for GitHub code search requests (10/min)."),
    max_http_requests: int = typer.Option(2000, "--max-http-requests", min=0, help="Total HTTP attempt budget, including retries."),
    reverify: bool = typer.Option(False, "--reverify", help="Ignore cached verification results."),
    verify: bool = typer.Option(True, "--verify/--no-verify", help="Clone candidates and count their valid rules (default)."),
    output: Path | None = typer.Option(None, "--output", help="Write discovered sources (all disabled) to this file instead of adding them to sources.yaml."),
    known: list[Path] = typer.Option(None, "--known", help="Sources file of repositories already known; they are left out of --output (repeatable)."),
    denylist: Path | None = typer.Option(None, "--denylist", help="YAML list (or sources file) of names/URLs never to propose."),
    cache_dir: Path | None = typer.Option(None, "--cache-dir", help="HTTP and clone cache (default: the workspace cache)."),
    report_file: Path | None = typer.Option(None, "--report-file", help="Also write the top repositories report (markdown) here."),
    collect_only: bool = typer.Option(
        False, "--collect-only", help="Step 1 of 2: search and enrich with the API, write discovery/candidates.yaml, clone nothing."
    ),
    candidates: Path | None = typer.Option(
        None, "--candidates", help="Step 2 of 2: verify the candidates.yaml of a --collect-only run (no API calls, no token needed)."
    ),
) -> None:
    """Find public repositories with Sigma rules, verify them by content and register them in sources.yaml (or --output).

    A GitHub token from GITHUB_TOKEN (or `gh auth token`) raises the API rate limits; it is never written anywhere."""
    from sigharvest.discover import DiscoveryOptions, run_discovery

    if collect_only and candidates is not None:
        raise typer.BadParameter("--collect-only and --candidates are the two steps of one run; use one of them")
    ws = find_workspace()
    opts = DiscoveryOptions(
        max_repos=max_repos,
        min_rules=min_rules,
        auto_add=auto_add and output is None,
        top=top,
        workers=workers,
        max_code_requests=max_code_requests,
        max_http_requests=max_http_requests,
        reverify=reverify,
        verify=verify,
        output=output,
        known=list(known or []),
        denylist=denylist,
        cache_dir=cache_dir,
        report_file=report_file,
        collect_only=collect_only,
        candidates=candidates,
    )
    rep = run_discovery(ws, opts, progress=lambda msg: console.print(f"[dim]{escape(msg)}[/]"))
    target = str(output) if output is not None else "sources.yaml"
    console.print(f"candidates: {len(rep.candidates)}, verified: {rep.verified}, written to {escape(target)}: {len(rep.added)}")
    console.print("Coverage: configured queries only; this is not a complete provider inventory.")
    for name, data in rep.completeness.get("strategies", {}).items():
        console.print(
            f"{name}: {data['queries_complete']}/{data['queries_planned']} queries complete, "
            f"{data['truncated_queries']} truncated, {data['budget_exhausted_queries']} budget-exhausted"
        )
    console.print("found by: " + ", ".join(f"{k}={v}" for k, v in rep.per_strategy.items()))
    t = Table("#", "repository", "valid rules", "unique", "mirror of", "source")
    for i, c in enumerate(rep.top[:20], 1):
        t.add_row(str(i), c.full_name, str(c.valid_rule_count), str(c.unique_logic), c.mirror_of or "", c.source or "")
    console.print(t)
    console.print(f"wrote {ws.root / 'discovery' / 'candidates.yaml'} and {ws.root / 'discovery' / 'top100.md'}")


def coverage(
    query: str | None = typer.Argument(None, help="Optional full-text query to restrict the rules."),
    product: str | None = typer.Option(None, help="Logsource product, e.g. windows, linux, aws."),
    category: str | None = typer.Option(None, help="Logsource category, e.g. process_creation."),
    service: str | None = typer.Option(None, help="Logsource service, e.g. security, sysmon."),
    source: str | None = typer.Option(None, help="Only logic present in this source."),
    validation: Validation | None = typer.Option(None, help="e.g. ok"),
    backend: str | None = typer.Option(None, help="Only rules a pipeline maps for this backend (status ok)."),
    gaps: bool = typer.Option(False, "--gaps", help="List all techniques/subtechniques below --min families in the current selection."),
    min_rules: int = typer.Option(1, "--min", help="With --gaps: fewer tagged families than this; not organization-wide detection gaps."),
    details: bool = typer.Option(False, "--details", help="Also show the best-covered parent per tactic and all non-current tag interpretations."),
    navigator: Path | None = typer.Option(None, "--navigator", help="Write an ATT&CK Navigator layer (JSON)."),
) -> None:
    """Summarize declared MITRE ATT&CK relevance in the current rule selection.

    Counts describe rule tags, not demonstrated detection. --gaps applies only to
    the selected rules. See docs/cli.md#attck-coverage.
    """
    from sigharvest.attack import compute, write_layer
    from sigharvest.index import GroupFilters

    ws = find_workspace()
    S = open_db(ws, readonly=True)
    filtered = any([query, product, category, service, source, validation, backend])
    gf = GroupFilters(product=product, category=category, service=service, source=source, validation=validation, backend=backend)
    from sigharvest.cli.common import user_errors

    with S() as s, user_errors(), console.status("computing coverage..."):
        cov = compute(ws, s, gf if filtered else None, query)
    selection = [
        f"{key}={value}"
        for key, value in (
            ("query", query),
            ("product", product),
            ("category", category),
            ("service", service),
            ("source", source),
            ("validation", validation),
            ("backend", backend),
        )
        if value
    ]
    _print_coverage(cov, selection=selection, gaps=gaps, min_rules=min_rules, details=details)
    if navigator:
        write_layer(cov, navigator)
        console.print(Text(f"wrote ATT&CK Navigator layer {navigator} (open it at https://mitre-attack.github.io/attack-navigator/)"))


def _print_coverage(cov: Coverage, *, selection: list[str], gaps: bool = False, min_rules: int = 1, details: bool = False) -> None:
    """Render existing counts literally, with no selection or coverage calculation changes."""
    from sigharvest.attack import ATTRIBUTION

    m = cov.matrix
    parents = [t for t in m.techniques if "." not in t]
    children = [t for t in m.techniques if "." in t]
    lines = [
        "Selection: " + ("; ".join(selection) if selection else "default rule selection"),
        f"ATT&CK {m.version}",
        f"Tagged unique logics: {cov.rules_with_tags:,}/{cov.rules_total:,} selected",
        f"Parent techniques covered: {sum(bool(cov.families.get(t)) for t in parents):,}/{len(parents):,}",
        f"Subtechniques covered: {sum(bool(cov.families.get(t)) for t in children):,}/{len(children):,}",
        "Parent counts include tagged children; technique denominators use the full catalog.",
        "Tags use the indexed canonical copy, including inherited metadata.",
        "Source filters select logics, not copies; families count selected members.",
        "Tagged logics include unresolved Enterprise IDs; those add no technique coverage.",
        "Tags declare relevance, not demonstrated detection.",
    ]
    console.print(Text("\n".join(lines)))
    t = Table()
    t.add_column("tactic", overflow="fold")
    t.add_column("parents\ncovered", no_wrap=True)
    t.add_column("family\nmemberships", no_wrap=True)
    best_rows: list[tuple[str, str]] = []
    for short, name, _ta in m.tactics:
        techs = [x for x in parents if short in m.techniques[x].tactics]
        cov_t = [x for x in techs if cov.families.get(x)]
        t.add_row(
            Text(name),
            f"{len(cov_t)}/{len(techs)}",
            f"{sum(cov.families.get(x, 0) for x in techs):,}",
        )
        if details:
            best = max(techs, key=lambda x: cov.families.get(x, 0)) if techs else None
            best_rows.append((name, f"{best} {m.techniques[best].name} ({cov.families.get(best, 0):,} families)" if best else ""))
    console.print(t)
    console.print(
        Text("Family memberships sum families across parent techniques. A family repeats across techniques and tactics; these are not independent detectors.")
    )
    if details:
        best_table = Table("tactic", "best covered parent (tagged families)")
        for name, best_label in best_rows:
            best_table.add_row(Text(name, overflow="fold"), Text(best_label, overflow="fold"))
        console.print(best_table)
    else:
        console.print("Use --details for best-covered parents and all non-current tag interpretations.")
    if gaps:
        console.print(Text(f"Gaps: fewer than {min_rules} tagged families in this selection; not organization-wide detection gaps."))
        g = Table()
        g.add_column("technique", no_wrap=True)
        g.add_column("name", ratio=2, overflow="fold")
        g.add_column("tactics", ratio=1, overflow="fold")
        g.add_column("families", justify="right", no_wrap=True)
        for tid in sorted(m.techniques):
            n = cov.families.get(tid, 0)
            if n < min_rules:
                tech = m.techniques[tid]
                g.add_row(tid, Text(tech.name), Text(", ".join(tech.tactics)), str(n))
        console.print(g)
    interpretations = [entry for entry in cov.normalisation.values() if entry["status"] != "current"]
    if interpretations:
        interpretations_table = Table("ATT&CK interpretation", "logics", title="Non-current tags" if details else "Most frequent non-current tags (up to 20)")
        ordered = sorted(interpretations, key=lambda item: (-item["rules"], item["original"]))
        for entry in ordered if details else ordered[:20]:
            interpretations_table.add_row(Text(entry["label"], overflow="fold"), str(entry["rules"]))
        console.print(interpretations_table)
    if cov.unknown:
        top = ", ".join(f"{k} ({v})" for k, v in list(cov.unknown.items())[:8])
        console.print(Text(f"Unresolved Enterprise IDs in ATT&CK {m.version} (up to 8; logics per ID): {top}", style="dim"))
    console.print(Text(ATTRIBUTION, style="dim"))


def changes_cmd(
    run: str | None = typer.Option(None, "--run", help="One update run (id or latest); default: the latest update."),
    since: str | None = typer.Option(None, "--since", help="Every update started since this date (YYYY-MM-DD), merged."),
    old_release: Path | None = typer.Option(None, "--from-release", help="Compare two release folders: the older one..."),
    new_release: Path | None = typer.Option(None, "--to-release", help="...and the newer one (both verified with SHA256SUMS)."),
    as_json: bool = typer.Option(False, "--json", help="Print the whole change set as JSON."),
    limit: int = typer.Option(20, "--limit", min=1, help="Rows shown per list (text output)."),
) -> None:
    """What is new, changed upstream or removed: since the last update (or --since a date), or between two releases."""
    import json

    from sigharvest import changes
    from sigharvest.cli.common import open_session, user_errors

    if (old_release is None) != (new_release is None):
        raise typer.BadParameter("--from-release and --to-release go together")
    with user_errors():
        if old_release is not None and new_release is not None:
            data = changes.between_releases(old_release, new_release)
        else:
            if run and since:
                raise typer.BadParameter("--run and --since: use one of them")
            with open_session(readonly=True) as s:
                data = changes.since_update(s, find_workspace().root, run=run, since=since)
    if as_json:
        print(json.dumps(data, ensure_ascii=False))
        return
    if data.get("note"):
        console.print(f"[yellow]note:[/] {escape(changes.safe_text(data['note']))}", soft_wrap=True)
    for line in data.get("incomplete") or []:
        console.print(f"[yellow]incomplete:[/] {escape(changes.safe_text(line))}; `sigharvest runs show` has the counts", soft_wrap=True)
    data = changes.normalise(data)  # release packs are untrusted: no terminal escapes in titles or labels
    span = f"{data['since'][:16] or '?'} -> {data['until'][:16] or '?'}"
    console.print(f"changes {escape(span)}: {len(data['new'])} new, {len(data['changed'])} changed, {len(data['removed'])} removed", soft_wrap=True)
    if not any(data[k] for k in changes.KINDS) and not data["since"]:
        console.print("no update report yet: `sigharvest update` records what each run changes")
        return
    for kind in changes.KINDS:
        rows = data[kind]
        if not rows:
            continue
        t = Table("logic", "title", title=f"{kind} ({len(rows)})", title_justify="left")
        for x in rows[:limit]:
            key = str(x.get("new") if kind == "changed" else x.get("logic_hash") or "")
            t.add_row(escape(key[:12]), escape(x.get("title") or "(untitled)"))
        console.print(t)
        if len(rows) > limit:
            console.print(f"[dim]{len(rows) - limit} more: --limit {len(rows)} or --json[/]")
