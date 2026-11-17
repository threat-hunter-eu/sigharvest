"""Explicit database retention and optional physical compaction."""

import json

import typer

from sigharvest.cli.common import console, user_errors
from sigharvest.cli.database_summary import print_compact_summary
from sigharvest.config import find_workspace
from sigharvest.db_compact import compact

db_app = typer.Typer(help="Compact test history and reclaim database space.", no_args_is_help=True)


@db_app.command("compact")
def compact_cmd(
    dry_run: bool = typer.Option(False, "--dry-run", help="Report candidates and unchanged sizes without writing the database."),
    history: int | None = typer.Option(None, min=0, help="Previous status changes per result; SIGHARVEST_TEST_HISTORY or 5 by default."),
    keep: int = typer.Option(1, min=1, help="Newest migration backups to keep for this database."),
    vacuum: bool = typer.Option(False, "--vacuum", help="Rewrite SQLite to shrink the file after checking free space."),
    json_output: bool = typer.Option(False, "--json", help="Print the complete result as JSON."),
) -> None:
    """Compact test history and old migration backups. Without --dry-run, this modifies eligible data.

    Terminal output separates deleted rows, reusable pages and measured DB/WAL file sizes.
    Use --json for the complete result, including every table.
    """
    with user_errors():
        result = compact(find_workspace().db_path, dry_run=dry_run, history=history, keep=keep, vacuum=vacuum)
        if json_output:
            print(json.dumps(result))
        else:
            print_compact_summary(result, console)
