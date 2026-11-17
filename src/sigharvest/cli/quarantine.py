"""Inspect dead-letter metadata and explicitly replay retained inputs."""

import json

import typer
from rich.table import Table
from sqlalchemy import select

from sigharvest.cli.common import console, mutation_command, open_session, user_errors
from sigharvest.models import Quarantine, Source
from sigharvest.quarantine import get_letter, metadata, retry
from sigharvest.runs import clean_text

quarantine_app = typer.Typer(help="Inspect rule files that failed to import and retry them; raw source bytes are never printed.")


@quarantine_app.command("list")
def list_letters(
    source_id: int | None = typer.Option(None, help="Filter by source database id."),
    limit: int = typer.Option(100, min=1, max=1000, help="Maximum rows."),
    after: int = typer.Option(0, min=0, help="Return ids greater than this cursor."),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable metadata."),
    unresolved: bool = typer.Option(False, help="Only import failures that still need attention."),
) -> None:
    """List failed imports, including removed sources and retention limits."""
    with user_errors(), open_session() as s:
        query = select(Quarantine).where(Quarantine.id > after).order_by(Quarantine.id).limit(limit)
        if source_id is not None:
            query = query.where(Quarantine.source_id == source_id)
        if unresolved:
            query = query.where(Quarantine.resolution.is_(None))
        rows = list(s.scalars(query))
        if json_output:
            from sqlalchemy import func

            matching = select(func.count()).select_from(Quarantine)
            if source_id is not None:
                matching = matching.where(Quarantine.source_id == source_id)
            if unresolved:
                matching = matching.where(Quarantine.resolution.is_(None))
            total = s.scalar(matching) or 0
            skipped = s.scalar(matching.where(Quarantine.id <= after)) or 0
            results = [metadata(s, q) for q in rows]
            print(json.dumps({"total": total, "offset": skipped, "limit": limit, "after": after, "results": results}))
            return
        names = dict(s.execute(select(Source.id, Source.name)).all())
        table = Table("id", "source", "path", "document", "reason", "state")
        for row in rows:
            table.add_row(
                str(row.id),
                clean_text(names.get(row.source_id, str(row.source_id))),
                clean_text(row.path),
                str(row.doc_index),
                clean_text(row.reason_code or "parse error"),
                row.resolution or ("unresolved" if row.present else "removed"),
            )
        console.print(table, markup=False)


@quarantine_app.command("show")
def show(letter_id: int = typer.Argument(..., help="Quarantine id.")) -> None:
    """Show immutable provenance, parser fingerprint and attempt history, without payloads."""
    with user_errors(), open_session() as s:
        print(json.dumps(metadata(s, get_letter(s, letter_id), detail=True)))


@quarantine_app.command("retry")
@mutation_command()
def retry_letter(
    letter_id: int = typer.Argument(..., help="Quarantine id."),
    parser: str = typer.Option(..., help="Explicitly select 'current' or the installed parser fingerprint."),
    snapshot: str | None = typer.Option(None, help="Retained snapshot SHA-256 for the same source/path; default is original."),
) -> None:
    """Replay parse and identity atomically. Recovered versions do not reactivate old occurrences; rescan the source to publish."""
    with user_errors(), open_session() as s:
        attempt = retry(s, letter_id, parser=parser, snapshot=snapshot)
        s.commit()
        print(json.dumps({"attempt": attempt.id, "outcome": attempt.outcome, "reason_code": attempt.reason_code}))
        if attempt.outcome == "rejected":
            raise typer.Exit(1)
