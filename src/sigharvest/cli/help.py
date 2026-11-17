"""Command catalogue for concise terminal help: panels, one-line summaries and start examples."""

from __future__ import annotations

import re
from copy import copy
from typing import Any

from typer.core import TyperCommand, TyperGroup, TyperOption

# Typer's command classes. Click is vendored privately inside Typer (typer._click), so click-level arguments
# (context, formatter, commands of the mapping) are typed as Any instead of importing private classes.
Command = TyperCommand | TyperGroup

PANELS: dict[str, tuple[str, ...]] = {
    "Start here": ("init", "update", "serve", "doctor"),
    "Rules": ("search", "list", "show", "changes", "export", "convert", "collection", "coverage", "dedupe", "diff"),
    "Sources": ("sources", "discover", "sync", "index", "test", "stats"),
    "Publish": ("release", "site", "lint", "report"),
    "Admin": ("runs", "quarantine", "db", "version"),
}
OTHER = "Other"


def _flag_type(self: TyperOption, ctx: Any) -> str | None:
    """Typer 0.29 prints a `<bool>` type next to every on/off flag (--report/--no-report, --help); a flag takes no value."""
    if getattr(self, "is_flag", False) and getattr(self, "metavar", None) is None:
        return None
    return _typer_display_type_rich(self, ctx)


_typer_display_type_rich = TyperOption.display_type_rich
TyperOption.display_type_rich = _flag_type  # type: ignore[method-assign]

START_EXAMPLES = {
    "init": "sigharvest init ~/sigma",
    "update": "sigharvest update",
    "serve": "sigharvest serve",
    "doctor": "sigharvest doctor",
}

SUMMARIES = {
    "init": "Create a workspace.",
    "update": "Download rule changes, validate and index them.",
    "serve": "Start the web interface.",
    "doctor": "Check workspace health.",
    "sync": "Download rule changes from your sources (no tests, no index).",
    "index": "Refresh rule search, families and scores from stored data.",
    "test": "Check rule syntax and query conversion.",
    "stats": "Show how many sources and rules you have.",
    "search": "Find rules by words, tags or filters.",
    "list": "Alias of search.",
    "show": "Read a rule, its copies, versions and test results.",
    "diff": "Compare two versions of a rule.",
    "changes": "See what is new, changed or removed since the last update or between two releases.",
    "dedupe": "Find duplicate rules and conflicting versions.",
    "export": "Save rules or queries to files.",
    "convert": "Turn a rule into a query for your security tools.",
    "coverage": "See ATT&CK technique coverage from rule tags; write a Navigator layer.",
    "collection": "Save a set of rules to export or share together.",
    "sources": "Choose where your rules come from.",
    "discover": "Find public rule repositories to add as sources.",
    "report": "Write a workspace summary and rule reports.",
    "release": "Build a shareable rule release with licence details.",
    "site": "Build a static website from a rule release.",
    "lint": "Check your rules for errors and existing copies.",
    "runs": "Review past workspace updates and failures.",
    "quarantine": "Inspect documents that could not be parsed.",
    "db": "Compact old test history and reclaim database space.",
    "version": "Show the version, the database schema revision and the main libraries.",
}


def panel_for(name: str) -> str:
    return next((panel for panel, names in PANELS.items() if name in names), OTHER)


def command_order(name: str) -> tuple[int, int, str]:
    panel = panel_for(name)
    names = PANELS.get(panel, ())
    return list(PANELS).index(panel) if panel in PANELS else len(PANELS), names.index(name) if name in names else 0, name


def reflow_help(text: str) -> str:
    """Join prose lines, retaining paragraphs, indented/fenced code and lists."""
    visible, separator, hidden = text.partition("\f")
    lines: list[str] = []
    prose: list[str] = []
    fence = ""

    def flush() -> None:
        if prose:
            lines.append(" ".join(prose))
            prose.clear()

    for line in visible.split("\n"):
        stripped = line.strip()
        if fence:
            lines.append(line)
            if stripped.startswith(fence):
                fence = ""
        elif not stripped:
            flush()
            lines.append(line)
        elif match := re.match(r"^\s*(`{3,}|~{3,})", line):
            flush()
            fence = match[1]
            lines.append(line)
        elif line.startswith((" ", "\t", "\b")) or re.match(r"^(?:[-*+] |\d+[.)] |>|\|)", line):
            flush()
            lines.append(line)
        else:
            prose.append(line.rstrip())
    flush()
    return "\n".join(lines) + separator + hidden


def _prepare_help(command: Any, path: str = "") -> None:
    if command.help:
        command.help = reflow_help(command.help)
    if isinstance(command, TyperGroup):
        for name, child in command.commands.items():
            _prepare_help(child, f"{path} {name}".strip())


class HelpGroup(TyperGroup):
    """Order the root menu by panel; subcommand groups keep their own order."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        _prepare_help(self)

    def format_help(self, ctx: Any, formatter: Any) -> None:
        view = copy(self)
        if ctx.parent is None:
            view.commands = {name: self.commands[name] for name in sorted(self.commands, key=command_order)}
        TyperGroup.format_help(view, ctx, formatter)
