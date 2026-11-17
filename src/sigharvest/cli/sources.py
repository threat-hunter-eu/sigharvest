"""`sigharvest sources`: list, add, remove, enable and disable rule sources in sources.yaml."""

from __future__ import annotations

from typing import Annotated

import typer

from sigharvest.cli.choices import SourceType
from sigharvest.cli.common import console, mutation_command
from sigharvest.cli.presentation import ResponsiveTable as Table
from sigharvest.config import SourceConfig, find_workspace, load_sources, save_sources

sources_app = typer.Typer(help="Manage rule sources (sources.yaml).", no_args_is_help=True)


@sources_app.command("list")
def sources_list(
    match: str | None = typer.Argument(None, help="Only sources whose name or URL contains this text (case-insensitive)."),
    disabled: bool = typer.Option(False, "--disabled", help="Only disabled sources."),
    json_output: bool = typer.Option(False, "--json", help="Print the sources as JSON."),
) -> None:
    """Show configured sources (and retained history) with their status; long names wrap but are never cut."""
    from sqlalchemy import select

    from sigharvest.models import Source
    from sigharvest.service import open_db
    from sigharvest.source_status import documents, status

    ws = find_workspace()
    items = load_sources(ws)
    config = {item.name: item.enabled for item in items}
    retained = {}
    docs: dict[str, int] = {}
    if ws.db_path.exists():
        with open_db(ws, readonly=True)() as session:
            retained = {row.name: row for row in session.scalars(select(Source))}
            docs = documents(session)
    wide = console.width >= 140
    t = Table("name", "type", "prio", "enabled", "status", "Sigma docs", "licence", *(["url"] if wide else []))
    # Long names wrap (folded, never cut) instead of squeezing the short columns to "ena…".
    t.columns[0].overflow = "fold"
    t.columns[0].min_width = 16
    for column in t.columns[1:7]:
        column.no_wrap = True
    if wide:
        t.columns[7].overflow = "fold"
    displayed: list[SourceConfig | Source] = [*items, *(row for name, row in retained.items() if name not in config)]
    needle = (match or "").casefold()
    displayed = [
        item
        for item in displayed
        if (not needle or needle in item.name.casefold() or needle in (item.url or "").casefold()) and (not disabled or not config.get(item.name, False))
    ]
    if json_output:
        import json

        results = []
        for item in displayed:
            old = retained.get(item.name)
            results.append(
                {
                    "name": item.name,
                    "type": item.type,
                    "priority": item.priority,
                    "enabled": config.get(item.name, False),
                    "status": status(item.name, item.enabled, docs.get(item.name, 0), old.last_sync_at if old else None, config),
                    "documents": docs.get(item.name, 0),
                    "licence": item.licence,
                    "url": item.url,
                }
            )
        print(json.dumps({"total": len(results), "offset": 0, "limit": len(results), "results": results}))
        return
    for item in displayed:
        old = retained.get(item.name)
        state = status(item.name, item.enabled, docs.get(item.name, 0), old.last_sync_at if old else None, config)
        t.add_row(
            item.name,
            item.type,
            str(item.priority),
            "yes" if config.get(item.name, False) else "no",
            state,
            str(docs.get(item.name, 0)),
            item.licence or "",
            *([item.url or ""] if wide else []),
        )
    console.print(t)
    n_disabled = sum(1 for s in items if not s.enabled)
    n_retained = sum(name not in config for name in retained)
    shown = f"{len(displayed)} of " if len(displayed) != len(items) + n_retained else ""
    extra = f"; {n_retained} retained outside config" if n_retained else ""
    console.print(f"{shown}{len(items)} sources ({n_disabled} disabled{extra}). Filter: `sigharvest sources list WORD`.")


@sources_app.command("add")
@mutation_command()
def sources_add(
    name: Annotated[str, typer.Argument(help="Unique source name to store in sources.yaml.")],
    url: Annotated[str, typer.Argument(help="Repository URL, HTTPS input URL or local folder path, according to --type.")],
    type_: SourceType = typer.Option("git", "--type", help="git, http (archive/file), local, http-files, html or huggingface."),
    ref: str | None = typer.Option(None, help="Git branch/tag or Hugging Face revision (resolved to a SHA)."),
    path: list[str] = typer.Option(["**/*"], "--path", help="Glob, repeatable."),
    licence: str | None = typer.Option(None, help="Licence of the rules, e.g. MIT or DRL-1.1 (used in exports and releases)."),
    priority: int = typer.Option(50, help="Lower wins: the source with the lowest number holds the canonical copy."),
    auth: str | None = typer.Option(None, help="Name of an environment variable holding an access token (never stored)."),
    urls: list[str] = typer.Option([], "--url", help="Explicit HTTPS files/pages, repeatable; replaces the positional URL for fetching."),
    files: list[str] = typer.Option([], "--file", help="Exact Hugging Face JSON/JSONL file path, repeatable; default: all JSON/JSONL files."),
    disabled: bool = typer.Option(False, "--disabled", help="Add the source without enabling sync."),
    redistributable: bool | None = typer.Option(
        None,
        "--redistributable/--no-redistributable",
        help="Whether releases may ship this source's rule text. Default: yes only when --licence names a permissive or "
        "copyleft licence (MIT, Apache-2.0, DRL-1.1, GPL-3.0...); otherwise metadata and a link only.",
    ),
) -> None:
    """Add a source."""
    from sigharvest.licensing import licence_class

    if redistributable is None and licence and licence_class(licence) in ("permissive", "copyleft"):
        redistributable = True
    ws = find_workspace()
    items = load_sources(ws)
    if any(s.name == name for s in items):
        raise typer.BadParameter(f"source {name} already exists")
    items.append(
        SourceConfig(
            name=name,
            type=type_,
            url=url,
            ref=ref,
            paths=path,
            licence=licence,
            priority=priority,
            auth=auth,
            urls=urls,
            files=files,
            enabled=not disabled,
            redistributable=redistributable,
        )
    )
    save_sources(ws, items)
    shipped = "rule text may be redistributed in exports and releases" if redistributable else "exports and releases ship metadata and a link only"
    console.print(f"added [bold]{name}[/] ({shipped})")
    if not redistributable:
        console.print(
            "[yellow]note:[/] without --licence (a permissive or copyleft one) or --redistributable, zip/YAML exports and the "
            "web UI only link these rules. For your own rules, add --licence (e.g. --licence MIT), or export a private copy "
            "with `sigharvest export --include-private-sources`.",
            soft_wrap=True,
        )


@sources_app.command("remove")
@mutation_command()
def sources_remove(name: Annotated[str, typer.Argument(help="Source name from sources list (not its URL).")]) -> None:
    """Remove a source from sources.yaml (its history stays in the database)."""
    ws = find_workspace()
    items = load_sources(ws)
    if not any(s.name == name for s in items):
        raise typer.BadParameter(f"unknown source {name}")
    save_sources(ws, [s for s in items if s.name != name])
    console.print(f"removed [bold]{name}[/]")


def _set_enabled(names: list[str], value: bool, *, all_sources: bool = False) -> None:
    ws = find_workspace()
    items = load_sources(ws)
    known = {s.name for s in items}
    unknown = [n for n in names if n not in known]
    if unknown:
        raise typer.BadParameter(f"unknown source {', '.join(unknown)}")
    if not names and not all_sources:
        raise typer.BadParameter("give one or more source names, or --all")
    wanted = known if all_sources else set(names)
    for s in items:
        if s.name in wanted:
            s.enabled = value
    save_sources(ws, items)
    console.print(f"{len(wanted)} sources {'enabled' if value else 'disabled'}")


@sources_app.command("enable")
@mutation_command()
def sources_enable(
    names: Annotated[list[str] | None, typer.Argument(help="Source names from sources list (not URLs); several allowed.")] = None,
    all_sources: bool = typer.Option(False, "--all", help="Enable every configured source."),
) -> None:
    """Enable one or more sources."""
    _set_enabled(names or [], True, all_sources=all_sources)


@sources_app.command("disable")
@mutation_command()
def sources_disable(
    names: Annotated[list[str] | None, typer.Argument(help="Source names from sources list (not URLs); several allowed.")] = None,
    all_sources: bool = typer.Option(False, "--all", help="Disable every configured source."),
) -> None:
    """Disable one or more sources."""
    _set_enabled(names or [], False, all_sources=all_sources)
