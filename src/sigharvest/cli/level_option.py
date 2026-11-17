"""Declare author severity while preserving each command's existing parser."""

from __future__ import annotations

from typing import Any

import typer

from sigharvest.normalize import LEVELS

LEVEL_HELP = (
    f"Author severity: {', '.join(LEVELS[:-1])} or {LEVELS[-1]}. Repeat or use commas for any of several "
    "(--level high --level critical, or --level high,critical). Separate from the quality score."
)


def levels(values: list[str] | None) -> str | None:
    """Repeatable and comma-separated values become one comma list (a union); unknown values are refused."""
    chosen: list[str] = []
    for value in values or []:
        for item in value.split(","):
            item = item.strip().lower()
            if not item:
                continue
            if item not in LEVELS:
                raise typer.BadParameter(f"{item!r} is not one of {', '.join(LEVELS)}")
            if item not in chosen:
                chosen.append(item)
    return ",".join(chosen) or None


def level_option() -> Any:
    """Return fresh metadata for a repeatable --level; annotate the parameter `list[str] | None` and pass it through
    `levels()`, which returns one comma-separated string (or None) that GroupFilters/Filters treat as a union.
    Like typer.Option, Any permits metadata defaults on list parameters.
    """
    return typer.Option(None, "--level", help=LEVEL_HELP, metavar="LEVEL")
