"""Getting rules out: `export` (YAML, JSONL or backend queries), `convert` (one rule, one backend) and `release build`."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich.markup import escape

from sigharvest.cli.common import console, licence_class_option, open_session, user_errors, with_licence_class
from sigharvest.cli.common import error as show_error
from sigharvest.cli.level_option import level_option, levels
from sigharvest.config import find_workspace
from sigharvest.models import RuleVersion
from sigharvest.service import open_db

if TYPE_CHECKING:
    from sigharvest.query import ExportReport

release_app = typer.Typer(help="Licence-aware data releases of the index.", no_args_is_help=True)


def export(
    query: str | None = typer.Argument(None, help="Full-text query; with --unit all, a substring of each document YAML."),
    technique: str | None = typer.Option(None, help="ATT&CK technique ID from rule tags, e.g. T1059 or T1059.001."),
    tactic: str | None = typer.Option(None, help="ATT&CK tactic name from rule tags, e.g. execution."),
    unit: str = typer.Option("family", help="family (best rule of each family), logic (every unique logic) or all (every copy)."),
    fmt: str = typer.Option(
        "yaml",
        "--format",
        help="yaml (folder), zip (YAML in a zip file), jsonl, csv or a backend name (splunk, lucene...). jsonl is a local copy: it keeps the "
        "text of restricted-licence rules (never of unlicensed ones); do not share it.",
    ),
    out: Path = typer.Option(Path("export"), help="YAML: new folder. zip/JSONL/CSV/queries: file."),
    product: str | None = typer.Option(None, help="Logsource product, e.g. windows, linux, aws."),
    category: str | None = typer.Option(None, help="Logsource category, e.g. process_creation."),
    service: str | None = typer.Option(None, help="Logsource service, e.g. security, sysmon."),
    tag: str | None = typer.Option(None, help="Tag prefix; with --unit all, an exact tag, e.g. attack.t1059."),
    rule_source: str | None = typer.Option(
        None,
        "--rule-source",
        "--source",
        help="Rule repository filter; keeps the canonical copy for family/logic. With --unit all, matches current document occurrences.",
    ),
    telemetry: str = typer.Option(
        "all", "--telemetry", help="Backend formats: input data for the pipelines: sysmon, security, all, combined, mde, windows or default."
    ),
    with_dependencies: bool = typer.Option(
        False, "--with-dependencies", help="YAML family/logic only: add the exact base rules referenced by correlations. Destination must not exist."
    ),
    licence: str | None = typer.Option(None, "--licence", help="Licence declared by the rule document, e.g. DRL-1.1."),
    licence_class: str | None = licence_class_option(),
    level_values: list[str] | None = level_option(),
    profile: str | None = typer.Option(
        None, "--profile", help="SigmaHQ package on every source: core, core+, core++, emerging-threats (et) or all (by status, level, rule type)."
    ),
    status_: str | None = typer.Option(None, "--status", help="Rule status: stable, test, experimental, deprecated, unsupported."),
    validation: str | None = typer.Option(
        None, help="Validation status. With --unit all, requires a current result for each exact document and cached schemas."
    ),
    backend: str | None = typer.Option(
        None,
        help="Selection filter: only rules mapped to this backend (status ok); does not set --format. With --unit all, requires exact current stored results.",
    ),
    min_score: float | None = typer.Option(None, help="Only rules with at least this quality score."),
    include_deprecated: bool = typer.Option(False, "--include-deprecated", help="Also include deprecated and unsupported rules."),
    collection: str | None = typer.Option(None, "--collection", "-c", help="Export this saved collection (filters are ignored)."),
    include_junk: bool = typer.Option(False, "--include-junk", help="Also export synthetic, test-fixture, foreign-query documents."),
    allow_raw: bool = typer.Option(False, "--allow-raw", help="Backend formats: also write syntax-only queries (no pipeline applies; Sigma field names)."),
    allow_warnings: bool = typer.Option(False, "--allow-warnings", help="Backend formats: also write queries that failed a sanity check."),
    include_private: bool = typer.Option(
        False,
        "--include-private-sources/--redistributable-only",
        help="YAML/zip/JSONL: also copy rules whose licence or source does not allow redistribution (your own local rules); "
        "for a private copy only, never share it. The default, --redistributable-only, keeps only rules you may share.",
    ),
) -> None:
    """Choose rules (a search or a saved collection), then the format and destination.

    Examples:

        sigharvest export powershell --format yaml --out selected/

        sigharvest export --product windows --format zip --out windows.zip

        sigharvest export --collection workstation --format splunk --out workstation.spl
    """
    level = levels(level_values)
    from sigharvest.export import export_csv, export_jsonl, export_queries, export_yaml, export_zip, select_groups
    from sigharvest.index import GroupFilters
    from sigharvest.testing import BACKENDS

    if unit not in ("family", "logic", "all"):
        raise typer.BadParameter("unit must be family, logic or all")
    if profile:
        from sigharvest.profiles import resolve

        with user_errors():
            profile = resolve(profile).name
    if unit == "all" and (licence or licence_class):
        raise typer.BadParameter("--licence and --licence-class select unique rules; leave --unit at family or logic")
    if collection and unit == "all":
        raise typer.BadParameter("--collection exports one copy per rule; leave --unit at its default")
    from sigharvest.conversion import ALL_BACKENDS, backend_error

    if fmt in ALL_BACKENDS and (problem := backend_error(fmt)):
        raise typer.BadParameter(problem)
    if fmt not in ("yaml", "zip", "jsonl", "csv", *BACKENDS):
        raise typer.BadParameter(f"format must be yaml, zip, jsonl, csv or one of {', '.join(ALL_BACKENDS)}")
    if with_dependencies and (fmt != "yaml" or unit == "all"):
        raise typer.BadParameter("--with-dependencies requires --format yaml and --unit family or logic")
    if unit == "all" and fmt == "csv":
        raise typer.BadParameter("--unit all supports yaml, zip, jsonl and backend formats")
    if fmt not in BACKENDS and (allow_raw or allow_warnings):
        raise typer.BadParameter("--allow-raw and --allow-warnings require a backend --format, for example --format splunk")
    from sigharvest.datasources import select_sources

    try:
        select_sources([], [telemetry])
    except ValueError as exc:
        raise typer.BadParameter("--telemetry: " + str(exc)) from exc
    with open_session() as s:
        gf = GroupFilters(
            technique=technique,
            tactic=tactic,
            product=product,
            category=category,
            service=service,
            level=level,
            status=status_,
            tag=tag,
            source=rule_source,
            validation=validation,
            backend=backend,
            include_deprecated=include_deprecated,
            include_junk=include_junk,
            profile=profile,
            license=licence,
        )
        if unit != "all":
            gf = with_licence_class(s, gf, licence_class, shipped=True)
        if unit == "all":
            from sigharvest.export_selection import select_documents, validation_schemas
            from sigharvest.query import export_backend, export_sigma

            with user_errors():
                schemas = validation_schemas(find_workspace()) if validation else None
                versions = select_documents(s, query, gf, min_score, schemas=schemas)
            if fmt in BACKENDS:
                rep = export_backend(versions, fmt, out, s=s, allow_raw=allow_raw, allow_warnings=allow_warnings, source=telemetry)
                _print_report(fmt, rep)
                _nothing_written(rep.written, validation)
            elif fmt == "zip":
                import tempfile

                from sigharvest.export import zip_folder

                with tempfile.TemporaryDirectory(prefix=".export-", dir=out.parent if out.parent.exists() else None) as tmp:
                    count = export_sigma(s, versions, Path(tmp) / "rules")
                    zip_folder(Path(tmp) / "rules", out)
                console.print(f"wrote {count} rule copies to {out}")
                _nothing_written(count, validation)
            else:
                count = export_sigma(s, versions, out, jsonl=fmt == "jsonl")
                console.print(f"wrote {count} rule copies to {out}")
                _nothing_written(count, validation)
            return
        if collection:
            from sigharvest.collections import CollectionError
            from sigharvest.selection import collection_groups

            try:
                members = collection_groups(s, collection)
            except CollectionError as exc:
                raise typer.BadParameter(str(exc)) from exc
            groups = iter([g for g in members if min_score is None or g.score >= min_score])
        else:
            groups = select_groups(s, unit, query, gf, min_score)
            if min_score is None:
                from sigharvest.index import match_counts

                with user_errors():
                    rules, families = match_counts(s, query, gf)
                # The web Export page counts one rule per logic, this command one per family by default: name both.
                console.print(f"matched {rules:,} rules (one per logic) in {families:,} families; exporting one rule per {unit}", soft_wrap=True)
        with console.status("exporting..."), user_errors():
            if fmt == "yaml":
                n = export_yaml(s, groups, out, with_dependencies=with_dependencies, include_private=include_private)
                skipped_file = out / "SKIPPED.md"
                console.print(f"wrote {n} rules to {out}/ (manifest: {out / 'manifest.jsonl'})")
                if skipped_file.is_file():
                    console.print(f"[yellow]some rules were only linked, not copied:[/] {skipped_file} {_PRIVATE_HINT}", soft_wrap=True)
                    n = n or 1  # a folder that links every rule is still an export, not an empty result
            elif fmt == "zip":
                n, linked = export_zip(s, groups, out, include_private=include_private)
                console.print(f"wrote {n} rules to {out}" + (f"; {linked} only linked (SKIPPED.md in the zip)" if linked else ""))
                if linked:
                    console.print(f"[yellow]{linked} rules were not copied (licence or source not redistributable).[/] {_PRIVATE_HINT}", soft_wrap=True)
                n += linked
            elif fmt == "jsonl":
                n = export_jsonl(s, groups, out, include_private=include_private)
                console.print(f"wrote {n} rules to {out}")
            elif fmt == "csv":
                n = export_csv(s, groups, out)
                console.print(f"wrote {n} rules to {out}")
            else:
                rep = export_queries(s, groups, fmt, out, allow_raw=allow_raw, allow_warnings=allow_warnings, source=telemetry)
                _print_report(fmt, rep)
                n = rep.written
    if include_private:
        console.print("[yellow]--include-private-sources: this export contains rules that must not be shared; keep it private.[/]")
    console.print("[dim]Rules keep their own licences (see manifest); check them before redistributing.[/]")
    _nothing_written(n, validation)


_PRIVATE_HINT = "Your own rules: add their source with --licence, or use --include-private-sources for a private copy."


def _print_report(fmt: str, rep: ExportReport) -> None:
    """The summary line of a query export, then the files on lines of their own (a path is never wrapped)."""
    console.print(f"{fmt}: {escape(rep.summary())}", soft_wrap=True)
    console.print(f"  queries: {escape(str(rep.out))}", soft_wrap=True, highlight=False)
    if sum(rep.not_written.values()):
        console.print(f"  why each rule was not written: {escape(str(rep.sidecar))}", soft_wrap=True, highlight=False)


def _nothing_written(n: int, validation: str | None = None) -> None:
    """An export that matched no rule is a failure for scripts (exit 1), not a silent empty file."""
    if n == 0:
        from sqlalchemy import func, select

        from sigharvest.models import LogicGroup, TestResult

        with open_session(readonly=True) as s:
            empty = not s.scalar(select(func.count()).select_from(LogicGroup))
            # A workspace started from a release pack (`init --from-release`) has no validation results yet.
            unvalidated = bool(validation) and not s.scalar(select(TestResult.id).where(TestResult.stage == "validate").limit(1))
        if empty:
            show_error("no rules were exported: the index is empty; run `sigharvest update` first")
        elif unvalidated:
            show_error("no rules were exported: no rule is validated yet, so --validation matches nothing; run `sigharvest test --stage validate` first")
        else:
            show_error("no rules were exported: no rule matches these filters (several values of one filter mean any of them)")
        raise typer.Exit(1)


def convert(
    key: str = typer.Argument(..., help="Logic hash, rule id or content hash prefix, or a YAML file."),
    target: str = typer.Option(
        "splunk", "--target", "-t", help="splunk, lucene, esql, opensearch, microsoft365defender, loki, sqlite (see `sigharvest convert --help`)."
    ),
    variant: str | None = typer.Option(None, "--variant", hidden=True),
    telemetry: str | None = typer.Option(
        None, "--telemetry", help="Pipeline input data (default all). Choices: sysmon, security, all, combined, mde, windows, default."
    ),
) -> None:
    """Print a rule's query, pipelines and conversion status.

    Security needs suitable auditing and event fields; missing prerequisites remain partial or unsupported.
    Combined falls back to separate queries when a plain boolean combination is unavailable.
    """
    from sigharvest import conversion
    from sigharvest.index import group_for

    source = telemetry
    if telemetry is not None:
        from sigharvest.datasources import select_sources

        try:
            select_sources([], [telemetry])
        except ValueError as exc:
            raise typer.BadParameter(f"--telemetry: {exc}") from exc
    if problem := conversion.backend_error(target):
        raise typer.BadParameter(problem)
    if variant not in conversion.VARIANTS:
        raise typer.BadParameter("variant must be windows-audit")
    p = Path(key)
    sibs: list[str] = []
    credit = ""
    if p.is_file():
        from sigharvest.documents import MAX_FILE_BYTES, load_documents

        with p.open("rb") as handle:
            docs = load_documents(handle.read(MAX_FILE_BYTES + 1))
        if error := next((d.error for d in docs if d.error), None):
            raise typer.BadParameter(error)
        docs = [d for d in docs if d.kind]
        if not docs:
            raise typer.BadParameter(f"{key} has no Sigma document")
        # The first document is converted; the others are there for the correlations that reference them.
        raw, kind = docs[0].rule_yaml, docs[0].kind or "rule"
        sibs = [d.rule_yaml for d in docs[1:]]
    else:
        with open_session() as s:
            g = group_for(s, key)
            v = s.get(RuleVersion, g.canonical_version_id) if g else None
            if v is None:
                raise typer.BadParameter(f"unknown rule {key}")
            raw, kind = v.raw, v.kind
            from sigharvest.export_policy import attribution_comment

            # DRL 1.1 and similar licences: the author and a reference to the original rule travel with its queries.
            credit = attribution_comment(s, v)
            if kind == "correlation":
                from sigharvest.testing import siblings

                sibs = siblings(s, [v.id]).get(v.id, [])
    try:
        conv = conversion.convert_cached(raw, target, kind=kind, siblings=sibs, variant=variant, sources=[source] if source else None)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if credit:
        console.print(escape(credit), soft_wrap=True, highlight=False)
    if source == "combined" and conv.combined_query:
        console.print("[dim]Combined: " + escape(", ".join(conv.combined_sources)) + "[/]")
        console.print(escape(conv.combined_query), soft_wrap=True, highlight=False)
    else:
        if source == "combined":
            console.print("[dim]No plain boolean combination available; separate queries follow.[/]")
        for result in conv.results:
            console.print(escape(f"{result.label}: {result.status}"))
            for q in result.queries:
                console.print(escape(q), soft_wrap=True, highlight=False)
            if result.reason:
                console.print(escape(result.reason))
    colour = {"ok": "green", "warning": "yellow", "raw": "yellow"}.get(conv.status, "red")
    console.print(f"[{colour}]{conv.status}[/] [dim]{escape(conv.pipeline_line)}[/]")
    for w in conv.warnings:
        console.print(f"[yellow]warning:[/] {escape(w)}")
    for n in conv.notes:
        console.print(f"[dim]note: {escape(n)}[/]")
    if conv.status == "error":
        show_error(f"{target} cannot convert this rule: " + escape(conv.error or ""))
        raise typer.Exit(1)


@release_app.command("build")
def release_build(
    out: Path = typer.Argument(Path("release"), help="Output folder."),
    licence_class: list[str] = typer.Option(
        None, "--licence-class", help="Classes whose YAML is included (default: permissive, copyleft). Others are metadata + link."
    ),
    include_junk: bool = typer.Option(False, "--include-junk", help="Also include synthetic, test-fixture, foreign-query and similar documents."),
    build_epoch: int | None = typer.Option(None, "--build-epoch", help="Unix timestamp for reproducible files; defaults to SOURCE_DATE_EPOCH or now."),
    previous: Path | None = typer.Option(None, "--previous", help="A previous release folder: changes.json and the notes list what changed."),
    allow_incomplete: bool = typer.Option(
        False, "--allow-incomplete", help="Build even when the first update did not pass its gates (marked incomplete in manifest.json)."
    ),
) -> None:
    """Write a licence-aware data release of the whole index (rules.jsonl.gz, per-licence zips, manifest.json, NOTICE.md...)."""
    from sigharvest.licensing import CLASSES
    from sigharvest.release import build

    allow = frozenset(licence_class or ["permissive", "copyleft"])
    if not allow <= set(CLASSES) - {"none"}:
        raise typer.BadParameter("licence classes: permissive, copyleft, restricted (rules without a licence are never redistributed)")
    from sigharvest.config import load_sources
    from sigharvest.runs import publish_refusal

    ws = find_workspace()
    with open_db(ws)() as s:
        refusal = publish_refusal(s)
        if refusal is not None:
            show_error(escape(refusal))
            if not allow_incomplete:
                console.print("not publishing an incomplete corpus (--allow-incomplete to build it anyway, marked incomplete)")
                raise typer.Exit(1)
        with console.status("building release..."):
            m = build(
                s,
                out,
                allow,
                include_junk,
                configs={c.name: c for c in load_sources(ws)},
                build_epoch=build_epoch,
                previous=previous,
                incomplete=refusal is not None,
            )
    c = m["counts"]
    console.print(
        f"{c.get('rules', 0):,} rules -> {out / 'rules.jsonl.gz'}: {c.get('with_yaml', 0):,} with YAML, "
        f"{c.get('metadata_only', 0):,} metadata and link only; {len(m['sources'])} sources in ATTRIBUTION.md"
    )
