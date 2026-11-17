"""`sigharvest collection`: saved rule sets that can be tested, exported and shared as a unit."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.markup import escape
from rich.table import Table

from sigharvest.cli.common import console, logsource_text, mutation_command, open_session, user_errors
from sigharvest.cli.help import HelpGroup
from sigharvest.cli.level_option import level_option, levels

collection_app = typer.Typer(
    cls=HelpGroup,
    help="""Saved rule sets (also in the web UI under Collections).

    Exports use the newest version resolved for each saved rule; update saves those replacements.

    Example:

        sigharvest collection add NAME -q ransomware
        sigharvest collection show NAME
        sigharvest export --collection NAME --format zip --out NAME.zip
    """,
    no_args_is_help=True,
)


@collection_app.command("list")
def collection_list() -> None:
    """List collections and how many rules each holds."""
    from sigharvest import collections as col

    with open_session() as s:
        rows = col.summaries(s)
    if not rows:
        console.print("no collections yet: `sigharvest collection add NAME KEY...` or `-q QUERY` creates one")
        return
    t = Table("name", "rules", "description", "created")
    for c, n in rows:
        t.add_row(escape(c.name), str(n), escape(c.display_description), c.created_at.strftime("%Y-%m-%d"))
    console.print(t)


@collection_app.command("create")
@mutation_command()
def collection_create(
    name: Annotated[str, typer.Argument(help="New, unused collection name.")],
    description: str = typer.Option("", "--description", "-d", help="What the collection is for."),
) -> None:
    """Create an empty collection."""
    from sigharvest import collections as col

    with open_session() as s:
        with user_errors():
            col.create(s, name, description)
        s.commit()
    console.print(f"created collection {escape(name)}")


@collection_app.command("add")
@mutation_command()
def collection_add(
    name: Annotated[str, typer.Argument(help="Collection name; creates it if it does not exist.")],
    keys: list[str] = typer.Argument(None, help="Logic hashes, rule ids or content hashes (prefix of 8+ characters)."),
    technique: str | None = typer.Option(None, help="ATT&CK technique ID from rule tags, e.g. T1059 or T1059.001."),
    tactic: str | None = typer.Option(None, help="ATT&CK tactic name from rule tags, e.g. execution."),
    query: str | None = typer.Option(None, "--query", "-q", help="Also add the rules matching this search (one per family)."),
    product: str | None = typer.Option(None, help="Logsource product, e.g. windows, linux, aws."),
    category: str | None = typer.Option(None, help="Logsource category, e.g. process_creation."),
    service: str | None = typer.Option(None, help="Logsource service, e.g. security, sysmon."),
    tag: str | None = typer.Option(None, help="Tag prefix, e.g. attack.t1059"),
    level_values: list[str] | None = level_option(),
    validation: str | None = typer.Option(None, help="ok, warning or error"),
    max_rules: int = typer.Option(1000, help="With --query or filters: at most this many rules."),
    note: str = typer.Option("", help="A note stored with each added rule."),
) -> None:
    """Add rules to a collection (created if it does not exist)."""
    level = levels(level_values)
    from sigharvest import collections as col
    from sigharvest import selection as sel
    from sigharvest.index import GroupFilters

    with open_session() as s:
        with user_errors():
            found = sel.groups_for_keys(s, keys or [])
        if sel.wants_search(query, product, category, service, tag, level, validation, technique, tactic):
            f = GroupFilters(
                technique=technique, tactic=tactic, product=product, category=category, service=service, tag=tag, level=level, validation=validation
            )
            found += sel.search(s, query, f, limit=max_rules)
        if not found:
            raise typer.BadParameter("give rule keys or a search (--query and/or filters)")
        with user_errors():
            c = col.ensure(s, name)
        n = col.add(s, c, found, note)
        s.commit()
    console.print(f"{escape(name)}: added {n} rules ({len(found) - n} already there)")


@collection_app.command("remove")
@mutation_command()
def collection_remove(
    name: Annotated[str, typer.Argument(help="Saved collection name; use collection list to see existing names.")],
    keys: list[str] = typer.Argument(..., help="Logic hash or rule id prefixes (8+ characters)."),
) -> None:
    """Remove rules from a collection."""
    from sigharvest import collections as col

    with open_session() as s:
        with user_errors():
            c = col.require(s, name)
        with user_errors():
            n = col.remove(s, c, keys)
        s.commit()
    console.print(f"{escape(name)}: removed {n} rules")


@collection_app.command("show")
def collection_show(name: Annotated[str, typer.Argument(help="Saved collection name; use collection list to see existing names.")]) -> None:
    """List the rules of a collection. "updated" means the rule changed upstream (same id, new logic)."""
    from sigharvest import collections as col

    with open_session() as s:
        with user_errors():
            c = col.require(s, name)
        rows = col.resolve(s, c)
        t = Table(
            "logic",
            "title",
            "level",
            "logsource",
            "score",
            "state",
            "note",
            title=escape(c.name) + (f" - {escape(c.display_description)}" if c.description else ""),
        )
        for r in rows:
            g = r.group
            ls = logsource_text(g.product, g.category or g.service) if g else ""
            state = {"current": "", "updated": "[yellow]updated upstream[/]", "missing": "[red]missing[/]"}[r.state]
            t.add_row(
                (g.logic_hash if g else r.item.logic_hash)[:10],
                escape((g.title if g else r.item.title) or ""),
                (g.level or "") if g else "",
                escape(ls),
                str(round(g.score)) if g else "",
                state,
                escape(r.item.note or ""),
            )
    console.print(t)
    upd = sum(1 for r in rows if r.state == "updated")
    if upd:
        from shlex import quote

        quoted_name = escape(quote(name))
        console.print(f"{upd} rules changed upstream. `sigharvest collection update {quoted_name}` saves the current replacements.")


@collection_app.command("update")
@mutation_command()
def collection_update(name: Annotated[str, typer.Argument(help="Saved collection name; use collection list to see existing names.")]) -> None:
    """Save the newest resolved version of every rule in the collection.

    Duplicate entries merge and missing rules stay listed. Exports already use the newest resolved version.
    """
    from sigharvest import collections as col

    with open_session() as s:
        with user_errors():
            c = col.require(s, name)
        n = col.follow_updates(s, c)
        s.commit()
    console.print(f"{escape(name)}: {n} rules moved to their current logic")


@collection_app.command("rename")
@mutation_command()
def collection_rename(
    old: Annotated[str, typer.Argument(help="Existing collection name to rename.")],
    new: Annotated[str, typer.Argument(help="New, unused collection name.")],
) -> None:
    """Rename a collection."""
    from sigharvest import collections as col

    with open_session() as s:
        with user_errors():
            col.rename(s, old, new)
        s.commit()
    console.print(f"renamed {escape(old)} to {escape(new)}")


@collection_app.command("delete")
@mutation_command()
def collection_delete(
    name: Annotated[str, typer.Argument(help="Saved collection name; use collection list to see existing names.")],
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask."),
) -> None:
    """Delete a collection (the rules stay in the corpus)."""
    from sigharvest import collections as col

    if not yes and not typer.confirm(f"delete collection {name!r}?"):
        raise typer.Exit(1)
    with open_session() as s:
        with user_errors():
            col.remove_collection(s, name)
        s.commit()
    console.print(f"deleted collection {escape(name)}")


@collection_app.command("import")
@mutation_command()
def collection_import(
    name: Annotated[str, typer.Argument(help="Collection name; creates it if it does not exist.")],
    file: Path = typer.Argument(..., help="A manifest.jsonl from `export`, or a text file with one key per line."),
) -> None:
    """Add the rules listed in a file: share a collection by sending its manifest.jsonl."""
    import json as _json

    from sigharvest import collections as col
    from sigharvest.selection import known_groups

    keys: list[str] = []
    for line in file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("{"):
            try:
                obj = _json.loads(line)
            except ValueError:
                continue
            keys.append(str(obj.get("logic_hash") or obj.get("rule_id") or ""))
        else:
            keys.append(line.split()[0])
    with open_session() as s:
        found, unknown = known_groups(s, keys)
        with user_errors():
            c = col.ensure(s, name)
        n = col.add(s, c, found)
        s.commit()
    console.print(f"{escape(name)}: added {n} rules, {len(found) - n} already there, {unknown} not found in this corpus")


@collection_app.command("lint")
def collection_lint(
    name: Annotated[str, typer.Argument(help="Saved collection name; use collection list to see existing names.")],
    json_output: bool = typer.Option(False, "--json", help="Print findings as JSON."),
    fail_on: str = typer.Option("warning", help="Exit 1 at or above warning or note; never disables finding-based failure."),
) -> None:
    """Check resolved members for unused selections and missing rules without changing the collection."""
    import json

    from sigharvest import collections as col
    from sigharvest.lint import as_json, lint_collection

    if fail_on not in {"warning", "note", "never"}:
        raise typer.BadParameter("fail-on: warning, note or never")
    with user_errors(), open_session() as s:
        findings = lint_collection(s, col.require(s, name))
    if json_output:
        typer.echo(json.dumps(as_json(findings)))
    else:
        table = Table("logic", "level", "check", "message")
        for finding in findings:
            table.add_row(finding.path[:12], finding.level, finding.rule, escape(finding.message))
        console.print(table if findings else "no findings")
    if fail_on != "never" and any(f.level in ({"warning", "error"} if fail_on == "warning" else {"warning", "error", "note"}) for f in findings):
        raise typer.Exit(1)
