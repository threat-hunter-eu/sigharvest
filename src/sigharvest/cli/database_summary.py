"""Explain one completed compaction DTO without database or filesystem access."""

from __future__ import annotations

from typing import Any

from rich.cells import cell_len
from rich.console import Console
from rich.text import Text

TABLE_LIMIT = 5


def _bytes(value: int) -> str:
    return f"{value:,} bytes"


def _name(value: str) -> str:
    """Keep markup literal and escape terminal controls without hiding table names."""
    if value.isprintable():
        return value
    return "".join(c if c.isprintable() else c.encode("unicode_escape").decode("ascii") for c in value)


def compact_summary(result: dict[str, Any]) -> str:
    """Describe observed sizes only; preview after-values are repeated input values."""
    preview = result["dry_run"]
    before, after = result["before"], result["after"]
    action = "eligible" if preview else "removed"
    lines = [
        "Preview - nothing deleted." if preview else "Completed - database compaction.",
        f"History limit: {result['history_limit']} previous changes per result",
        f"History rows {action}: {result['prune']['history_rows']:,}",
        f"Superseded result rows {action}: {result['prune']['superseded_result_rows']:,}",
        f"Migration backups {action}: {result['backup_files']:,} files; {_bytes(result['backup_bytes'])} (separate from DB/WAL)",
        "Sizes: before -> after (all values in bytes)",
    ]
    for label, key in (
        ("DB file", "database_bytes"),
        ("WAL file", "wal_bytes"),
        ("SQLite allocation", "allocated_bytes"),
        ("Reusable pages (bytes, not disk freed)", "reusable_bytes"),
    ):
        lines.append(f"  {label}: {_bytes(before[key])} -> {_bytes(after[key])}")
    lines.append(
        f"History rows: {before['history_rows']:,} -> {after['history_rows']:,}; current results: {before['result_rows']:,} -> {after['result_rows']:,}"
    )
    if preview:
        lines.append("After repeats before; no compaction was measured. No space was freed.")
        if result["vacuum_required_bytes"]:
            lines.append(f"Requested vacuum: not run; requires at least {_bytes(result['vacuum_required_bytes'])} free.")
    else:
        for label, key in (("DB", "database_bytes"), ("WAL", "wal_bytes")):
            lines.append(f"{label} file change (after - before): {after[key] - before[key]:+,} bytes")
        reduction = before["database_bytes"] + before["wal_bytes"] - after["database_bytes"] - after["wal_bytes"]
        lines.append(f"DB + WAL file-size reduction: {reduction:+,} bytes (negative means growth)")
        if result["vacuum"]:
            lines.append("Vacuum completed; file sizes above are measured, not predicted.")
        else:
            lines.append("No vacuum: deleting rows leaves pages reusable inside the DB; it does not shrink the file.")
            lines.append("A WAL checkpoint can change DB/WAL sizes independently of deleted rows.")
        if result["checkpoint_busy"]:
            lines.append("Checkpoint busy: WAL could not be fully cleared.")
    first, last = before["tables_bytes"], after["tables_bytes"]
    names = sorted(first.keys() | last.keys(), key=lambda name: (-first.get(name, 0), name))
    lines.append("Tables by before bytes (including indexes): before -> after")
    for name in names[:TABLE_LIMIT]:
        lines.append(f"  {_name(name)}: {_bytes(first.get(name, 0))} -> {_bytes(last.get(name, 0))}")
    others = names[TABLE_LIMIT:]
    lines.append(f"  Other tables ({len(others)}): {_bytes(sum(first.get(name, 0) for name in others))} -> {_bytes(sum(last.get(name, 0) for name in others))}")
    lines.append("Full result and every table: use --json with the same options.")
    return "\n".join(lines)


def print_compact_summary(result: dict[str, Any], console: Console) -> None:
    """Write literal text once, using Rich's Unicode wrapping only where needed."""
    width = console.width
    summary = compact_summary(result)
    source_lines = summary.splitlines()
    if summary.isascii() and max(map(len, source_lines), default=0) <= width:
        print(summary, file=console.file)
        return
    lines = []
    for line in source_lines:
        cells = len(line) if line.isascii() else cell_len(line)
        if cells <= width:
            lines.append(line)
        else:
            lines.extend(part.plain for part in Text(line).wrap(console, width))
    print("\n".join(lines), file=console.file)
