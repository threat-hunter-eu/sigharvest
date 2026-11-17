"""Terminal presentation that preserves fields at ordinary console widths."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from rich.console import Console, ConsoleOptions, RenderResult
from rich.table import Table
from rich.text import Text


def describe(value: Any) -> str:
    """Render nested diagnostics as labelled prose instead of Python repr."""
    if isinstance(value, Mapping):
        return "; ".join(f"{key}: {describe(item)}" for key, item in value.items()) or "none recorded"
    if isinstance(value, (list, tuple)):
        return "; ".join(describe(item) for item in value) or "none recorded"
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


class ResponsiveTable(Table):
    """Use labelled records when columns would squash or discard values.

    Keep Rich's normal table at wide widths. At narrow widths every field is
    retained with its full label; long values fold rather than use ellipses.
    """

    def __init__(self, *headers: str, min_table_width: int = 120, **kwargs: Any) -> None:
        super().__init__(*headers, **kwargs)
        self.min_table_width = min_table_width

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        if options.max_width >= self.min_table_width:
            yield from super().__rich_console__(console, options)
            return
        if self.title:
            yield Text.from_markup(str(self.title))
        for index in range(self.row_count):
            if index:
                yield Text("")
            for column in self.columns:
                label = Text.from_markup(column.header) if isinstance(column.header, str) else column.header
                cell = column._cells[index]
                value = Text.from_markup(cell) if isinstance(cell, str) else cell
                if isinstance(value, Text) and isinstance(label, Text):
                    line = Text(overflow="fold", no_wrap=False)
                    line.append_text(label)
                    line.append(": ")
                    line.append_text(value)
                    yield line
                else:
                    yield label
                    yield cell
