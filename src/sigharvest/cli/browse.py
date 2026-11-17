"""Reading the corpus: `search` (alias `list`), `show`, `diff` and `dedupe`."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import typer
from rich.markup import escape

from sigharvest.cli.choices import Sort, Validation
from sigharvest.cli.common import (
    console,
    error,
    licence_class_option,
    logsource_text,
    open_session,
    query_filters,
    user_errors,
    warn_incomplete,
    with_licence_class,
)
from sigharvest.cli.level_option import level_option, levels
from sigharvest.cli.presentation import ResponsiveTable as Table
from sigharvest.cli.presentation import describe
from sigharvest.search_options import SORTS

if TYPE_CHECKING:
    from sigharvest.models import LogicGroup, Occurrence, RuleVersion, Source


def search_cmd(
    query: str | None = typer.Argument(
        None, help='Words (prefix, ANDed), "phrase", OR, ( ), -word / NOT word, title:/tags:/detection:..., filters level:/product:/id:/source:...'
    ),
    technique: str | None = typer.Option(None, help="ATT&CK technique ID from rule tags, e.g. T1059 or T1059.001 (comma for OR)."),
    tactic: str | None = typer.Option(None, help="ATT&CK tactic name from rule tags, e.g. execution or credential-access."),
    product: str | None = typer.Option(None, help="Logsource product, e.g. windows, linux, aws."),
    category: str | None = typer.Option(None, help="Logsource category, e.g. process_creation."),
    service: str | None = typer.Option(None, help="Logsource service, e.g. security, sysmon."),
    tag: str | None = typer.Option(None, help="Tag prefix, e.g. attack.t1059"),
    source: str | None = typer.Option(None, help="Only logic present in this source."),
    licence: str | None = typer.Option(None, "--licence", help="Licence declared by the rule document, e.g. DRL-1.1."),
    licence_class: str | None = licence_class_option(),
    level_values: list[str] | None = level_option(),
    profile: str | None = typer.Option(
        None, "--profile", help="SigmaHQ package on every source: core, core+, core++, emerging-threats (et) or all (by status, level, rule type)."
    ),
    status_: str | None = typer.Option(None, "--status", help="Rule status: stable, test, experimental, deprecated, unsupported."),
    validation: Validation | None = typer.Option(None, help="ok, warning or error"),
    backend: str | None = typer.Option(None, help="Only rules a pipeline maps for this backend (status ok)."),
    min_sources: int | None = typer.Option(None, min=1, help="Logic carried by at least N sources."),
    include_deprecated: bool = typer.Option(False, "--include-deprecated", help="Also include rules whose status is deprecated."),
    include_junk: bool = typer.Option(False, "--include-junk", help="Also show synthetic, test-fixture, foreign-query and similar documents."),
    flag: str | None = typer.Option(None, help="Only rules with this quality flag (ioc_list, synthetic, upstream_deprecated...)."),
    sort: Sort = typer.Option("relevance", help=", ".join(SORTS)),
    limit: int = typer.Option(30, min=1, help="Rows shown."),
    offset: int = typer.Option(0, min=0, help="Skip this many rows (paging)."),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable results with the total."),
    all_copies: bool = typer.Option(False, "--all-copies", help="List every copy instead of one row per unique logic."),
    per_family: bool = typer.Option(True, "--per-family/--per-logic", help="One row per rule family (same UUID or same logic) or per unique logic."),
) -> None:
    """Search all rules. One row per rule family (or per unique logic with --per-logic), best-ranked first."""
    level = levels(level_values)
    import json

    from sqlalchemy import func, select

    from sigharvest.models import LogicGroup

    if profile:
        from sigharvest.profiles import resolve

        with user_errors():
            profile = resolve(profile).name
        if all_copies:
            raise typer.BadParameter("--profile works on unique rules; leave out --all-copies")
    if all_copies and (licence or licence_class):
        raise typer.BadParameter("--licence and --licence-class work on unique rules; leave out --all-copies")
    with user_errors(), open_session() as s:
        if all_copies:
            from sigharvest.query import search

            f = query_filters(product=product, category=category, service=service, tag=tag, source=source, status=status_, level=level, text=query)
            rows = search(s, f, limit=limit)
            if json_output:
                copies = [
                    {
                        "rule_id": v.rule_id,
                        "logic_hash": v.logic_hash,
                        "content_hash": v.content_hash,
                        "title": v.title,
                        "level": v.level,
                        "status": v.status,
                        "logsource": {"product": v.product, "category": v.category, "service": v.service},
                    }
                    for v in rows
                ]
                # Copies are not paged: total is the number returned (at most --limit).
                typer.echo(json.dumps({"view": "copy", "total": len(copies), "offset": 0, "limit": limit, "results": copies}, ensure_ascii=False))
                return
            t = Table("rule id", "logic", "content", "title", "logsource", "level", "status")
            for v in rows:
                logsource = logsource_text(v.product, v.category, v.service)
                t.add_row(
                    v.rule_id[:8],
                    v.logic_hash[:10],
                    v.content_hash[:10],
                    escape(v.title or ""),
                    escape(logsource),
                    escape(v.level or ""),
                    escape(v.status or ""),
                )
            console.print(t)
            return
        from sigharvest.attack_search import search_hints
        from sigharvest.index import GroupFilters, search_groups

        gf = GroupFilters(
            technique=technique,
            tactic=tactic,
            license=licence,
            product=product,
            category=category,
            service=service,
            level=level,
            status=status_,
            tag=tag,
            source=source,
            validation=validation,
            backend=backend,
            min_sources=min_sources,
            include_deprecated=include_deprecated,
            include_junk=include_junk,
            flag=flag,
            profile=profile,
        )
        gf = with_licence_class(s, gf, licence_class)
        groups, total = search_groups(s, query, gf, limit=limit, offset=offset, sort=sort, per_family=per_family)
        if json_output:
            from sigharvest.index import match_counts
            from sigharvest.runs import incomplete_corpus

            rules, families = match_counts(s, query, gf)
            # `total` counts what `results` pages through (families by default, rules with --per-logic), like
            # /api/search; total_rules and total_families are both always given.
            payload = {
                "incomplete": incomplete_corpus(s) is not None,
                "view": "family" if per_family else "logic",
                "total": total,
                "total_rules": rules,
                "total_families": families,
                "offset": offset,
                "limit": limit,
                "results": [
                    {
                        "logic_hash": g.logic_hash,
                        "rule_id": g.rule_id,
                        "title": g.title,
                        "level": g.level,
                        "status": g.status,
                        "logsource": {"product": g.product, "category": g.category, "service": g.service},
                        "tags": g.tags,
                        "score": g.score,
                        "sources": g.sources,
                        "family_size": g.family_size,
                    }
                    for g in groups
                ],
            }
            typer.echo(json.dumps(payload, ensure_ascii=False))
            return
        warn_incomplete(s)
        for hint in search_hints(s, query):
            console.print(hint, markup=False)
        # Narrow terminals (80 columns) keep the title readable by dropping the secondary columns.
        wide = console.width >= 130
        cols: list[tuple[str, dict[str, object]]] = [
            ("logic", {"no_wrap": True, "max_width": 10, "style": "dim"}),
            ("title", {"ratio": 4, "min_width": 24}),
            ("logsource", {"ratio": 2, "max_width": 30, "overflow": "fold"}),
            ("level", {"no_wrap": True}),
            ("score", {"justify": "right", "no_wrap": True}),
        ]
        if wide:
            cols += [(c, {"justify": "right", "no_wrap": True}) for c in ("copies", "srcs", "variants")]
            cols += [("valid", {"no_wrap": True}), ("conv", {"justify": "right", "no_wrap": True})]
        t = Table(expand=False)
        for name, kw in cols:
            t.add_column(name, **kw)  # type: ignore[arg-type]
        for g in groups:
            logsource = logsource_text(g.product, g.category, g.service)
            colour = {"ok": "green", "warning": "yellow", "error": "red"}.get(g.validation or "", "dim")
            cells = [g.logic_hash[:10], escape(g.title or ""), escape(logsource), escape(g.level or ""), f"{g.score:.0f}"]
            if wide:
                cells += [str(g.copies), str(g.n_sources), str(g.family_size), f"[{colour}]{g.validation or '-'}[/]", _mapped(g)]
            t.add_row(*cells)
        if not groups and not s.scalar(select(func.count()).select_from(LogicGroup)):
            console.print("the index is empty: run `sigharvest update` (or `sigharvest init` first in a new folder)")
            return
        if not groups:
            console.print("no rules match. Try fewer or different words, drop a filter, or see `sigharvest search --help`.")
            return
        console.print(t)
        from sigharvest.index import HIDDEN_BY_DEFAULT, match_counts

        rules, families = match_counts(s, query, gf)
        n = len(groups)
        shown = ("family" if n == 1 else "families") if per_family else ("rule" if n == 1 else "rules")
        # "1 rule in 1 family matches", "3 rules in 2 families match"
        verb = "matches" if rules == 1 else "match"
        console.print(
            f"{rules:,} rule{'s' if rules != 1 else ''} in {families:,} famil{'ies' if families != 1 else 'y'} {verb}; showing {n} {shown}"
            f" ({'one row per family, --per-logic for one per rule' if per_family else 'one row per rule'}). Details: sigharvest show <logic>",
            soft_wrap=True,
        )
        hidden = [x for x, on in (("--include-deprecated", include_deprecated), ("--include-junk", include_junk)) if not on]
        if hidden:
            console.print(f"[dim]{HIDDEN_BY_DEFAULT}: {' / '.join(hidden)} to include them[/]", soft_wrap=True)


def _mapped(g: Any) -> str:
    """ok targets / applicable targets, e.g. 3/6 (unsupported log sources are not counted)."""
    from sigharvest.conversion import APPLICABLE, statuses_of

    st = statuses_of(g)
    return f"{sum(1 for x in st.values() if x == 'ok')}/{sum(1 for x in st.values() if x in APPLICABLE)}" if st else "-"


def show(
    key: str = typer.Argument(..., help="Rule id, content hash or logic hash (prefix of 8+ chars)."),
    copies: bool = typer.Option(False, "--copies", help="List every path of every copy (default: copies grouped by source)."),
    all_results: bool = typer.Option(False, "--results", help="Print every stored test result in full (default: one line per stage)."),
) -> None:
    """Metadata of the canonical copy, all versions, the sources containing them, and test results."""
    from sigharvest.query import occurrences, resolve, results, versions_of

    with open_session() as s:
        found = resolve(s, key)
        if not found:
            error("no rule matches that key (use a logic hash, rule id or content hash prefix of 8+ characters; find one with `sigharvest search <words>`)")
            raise typer.Exit(1)
        from sigharvest.rule_keys import unique_key

        # A complete UUID intentionally displays its retained version history.
        if not re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", key.strip().lower()):
            with user_errors():
                unique_key(key, (v.logic_hash for v in found))
        for rid in dict.fromkeys(v.rule_id for v in found):
            versions = versions_of(s, rid)
            occ = occurrences(s, [v.id for v in versions])
            head, g = _show_head(s, versions, occ)
            from sigharvest.ruleview import current_text

            author, description = current_text(g, head.raw)
            console.rule(f"[bold]{escape(head.title or '')}[/]  {rid}")
            console.print(escape(f"kind={head.kind} status={head.status} level={head.level} author={author or '-'}"))
            if description is not None:
                console.print(description, markup=False)
            console.print(escape(f"date={head.date or '-'} modified={head.modified or '-'}"))
            console.print(escape(f"logsource: {logsource_text(head.product, head.category, head.service)}  tags: {', '.join(head.tags)}"))
            if g is not None:
                facts = [f"canonical copy: {g.canonical_source}", f"score {g.score:.0f}", f"family of {g.family_size}"]
                facts += [f"validation {g.validation}"] if g.validation else []
                facts += [f"quality flags: {', '.join(g.quality_flags)}"] if g.quality_flags else []
                console.print(escape("  ".join(facts)))
            console.print(_licence_line(s, head, g), soft_wrap=True)
            if head.flags:
                console.print(f"flags: {', '.join(head.flags)}")
            columns = ["#", "content", "logic", "modified", "first seen", "where (source:path)" if copies else "where (source: copies)"]
            t = Table(*columns, *(["present"] if copies else []))
            for i, v in enumerate(versions, 1):
                where = sorted(((o, src) for o, src in occ if o.version_id == v.id), key=lambda x: (x[1].priority, x[1].name, x[0].path))
                mark = " *" if v.id == head.id else ""
                if copies:
                    where_text = "\n".join(f"{src.name}:{o.path}" for o, src in where)
                    present = "\n".join("yes" if o.present else "no" for o, _ in where)
                else:
                    where_text, present = _show_grouped(where), ""
                cells = [f"{i}{mark}", v.content_hash[:12], v.logic_hash[:12], v.modified or v.date or "", str(v.first_seen)[:16]]
                t.add_row(*cells, escape(where_text), *([present] if copies else []))
            console.print(t)
            console.print("[dim]* the version shown above (canonical copy)" + ("" if copies else "; --copies lists every path") + "[/]")
            stored = list(results(s, head.id))
            if all_results:
                r = Table("stage", "target", "dataset", "status", "detail")
                for res in stored:
                    r.add_row(res.stage, res.target, res.dataset, res.status, escape(describe(res.detail)))
                console.print(r)
            else:
                _results_summary(stored, g)


def _licence_line(s: Any, head: RuleVersion, g: LogicGroup | None) -> str:
    """'licence: DRL-1.1 (permissive), from sigmahq-core; redistributable: yes', as the export decision sees it."""
    from sigharvest.licensing import licence_class, narrows, redistributable, shipped_licence
    from sigharvest.source_metadata import source_configs, source_licences

    source = g.canonical_source if g is not None else None
    licences = source_licences(s)
    source_licence = licences.get(source) if source else None
    licence = shipped_licence(head.rule_license, source_licence)
    origin = "the rule's own license: field" if narrows(head.rule_license, source_licence) else (f"source {source}" if source else "unknown source")
    cfg = source_configs(s).get(source or "")
    ships = redistributable(getattr(cfg, "redistributable", None)) if cfg is not None else None
    allowed = "yes" if ships and licence_class(licence) != "none" else "no (metadata and a link only)" if ships is not None else "unknown"
    return escape(f"licence: {licence or 'none stated'} ({licence_class(licence)}), from {origin}; redistributable: {allowed}")


def _results_summary(stored: list[Any], g: LogicGroup | None) -> None:
    """One line per stage instead of every backend's full output (`show --results` prints them all)."""
    from sigharvest.conversion import summary_text

    validation = next((r for r in stored if r.stage == "validate"), None)
    console.print(escape(f"validation: {validation.status if validation else 'not run'}"))
    converted = {r.target: r.status for r in stored if r.stage == "convert" and not r.dataset}
    if converted:
        console.print(escape(f"conversion: {summary_text(converted)}"))
    else:
        console.print("conversion: on demand, e.g. sigharvest convert " + (g.logic_hash[:12] if g is not None else "KEY") + " --target splunk")
    console.print("[dim]sigharvest show KEY --results prints every stored result in full[/]")


def _show_head(s: Any, versions: list[RuleVersion], occ: list[tuple[Occurrence, Source]]) -> tuple[RuleVersion, LogicGroup | None]:
    """The version `show` describes: the index's canonical copy when this rule id has one, else the live copy from
    the best-priority source, else the newest version. With its logic group (None when not indexed)."""
    from sqlalchemy import select

    from sigharvest.models import LogicGroup

    live = [(src.priority, -v.first_seen.timestamp(), v.id) for v in versions for o, src in occ if o.version_id == v.id and o.present]
    by_id = {v.id: v for v in versions}
    head = by_id[min(live)[2]] if live else versions[-1]
    g = s.scalars(select(LogicGroup).where(LogicGroup.logic_hash == head.logic_hash)).first()
    if g is not None and g.canonical_version_id in by_id:
        head = by_id[g.canonical_version_id]
    return head, g


SHOW_SOURCES = 5


def _show_grouped(where: list[tuple[Occurrence, Source]], limit: int = SHOW_SOURCES) -> str:
    """One line per source ('source:path', or 'source: N copies (first path)'), marking copies no longer present,
    for at most `limit` sources; the rest is summarised so popular rules stay readable."""
    per: dict[str, list[Occurrence]] = {}
    for o, src in where:
        per.setdefault(src.name, []).append(o)
    lines = []
    for name, occs in list(per.items())[:limit]:
        live = sum(1 for o in occs if o.present)
        line = f"{name}:{occs[0].path}" if len(occs) == 1 else f"{name}: {len(occs)} copies ({occs[0].path}, ...)"
        if live < len(occs):
            line += " (removed upstream)" if not live else f" ({live}/{len(occs)} still present)"
        lines.append(line)
    if len(per) > limit:
        lines.append(f"... and {len(per) - limit} more sources (--copies lists all)")
    return "\n".join(lines)


def diff(
    rule_id: str = typer.Argument(..., help="RULE key; use sigharvest show RULE to list versions."),
    v1: int = typer.Argument(..., min=1, help="Old version number from sigharvest show RULE."),
    v2: int = typer.Argument(..., min=1, help="New version number from sigharvest show RULE."),
) -> None:
    """Unified textual diff of two versions of a rule (this does not certify detection)."""
    from sigharvest.query import diff_versions, resolve, versions_of

    with open_session() as s:
        found = resolve(s, rule_id)
        if not found:
            raise typer.BadParameter("unknown rule")
        versions = versions_of(s, found[0].rule_id)
        try:
            a, b = versions[v1 - 1], versions[v2 - 1]
        except IndexError as exc:
            raise typer.BadParameter(f"rule has {len(versions)} versions") from exc
        console.print(escape(diff_versions(a, b) or "identical"))


def dedupe(
    report: bool = typer.Option(True, "--report/--no-report", help="Also list the most duplicated logic and conflicting ids."),
    top: int = typer.Option(20, help="Rows per list."),
) -> None:
    """Duplicate logic, conflicting versions and exact copies across sources."""
    from sigharvest.query import dedupe as run_dedupe

    with open_session(readonly=True) as s:
        rep = run_dedupe(s, top=top if report else 0)
    t = Table("metric", "value")
    for k, v in [
        ("documents", rep.live_documents),
        ("unique contents", rep.unique_contents),
        ("unique rule ids", rep.unique_rule_ids),
        ("unique logic", rep.unique_logic),
        ("duplicate documents (same logic)", rep.live_documents - rep.unique_logic),
        ("exact copies", rep.exact_copies),
        ("rule ids with conflicting logic", len(rep.id_conflicts)),
        ("titles shared by different logic", len(rep.title_groups)),
    ]:
        t.add_row(k, str(v))
    console.print(t)
    if report:
        g = Table("copies", "sources", "canonical", "rule ids", title="most duplicated logic")
        for grp in rep.logic_groups[:top]:
            g.add_row(
                str(grp["copies"]),
                ", ".join(grp["sources"])[:60],
                escape(f"{grp['canonical']['source']}: {grp['canonical']['title']}"),
                str(len(grp["rule_ids"])),
            )
        console.print(g)
        c = Table("rule id", "logic variants", "sources", "title", title="conflicting versions (same id, different logic)")
        for grp in rep.id_conflicts[:top]:
            c.add_row(grp["rule_id"], str(grp["logic_variants"]), ", ".join(grp["sources"])[:60], escape(grp["title"] or ""))
        console.print(c)
