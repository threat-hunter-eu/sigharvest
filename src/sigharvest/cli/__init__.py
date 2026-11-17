"""sigharvest command line interface.

Build the root Typer app; registry.py names implementations loaded by lazy.py.
Help panels live in help.py, command groups in their own modules, and shared
helpers in common.py.
"""

from __future__ import annotations

import logging
import sys

import typer
from rich.console import Console
from rich.markup import escape

from sigharvest.cli.lazy import LazyHelpGroup

app = typer.Typer(
    cls=LazyHelpGroup,
    help="Collect, deduplicate, search and export public Sigma detection rules.",
    epilog="Help for any command: sigharvest COMMAND --help.",
    no_args_is_help=True,
)


def show_version(value: bool) -> None:
    """Print package version without discovering or opening a workspace."""
    if value:
        from sigharvest import __version__

        typer.echo(f"sigharvest {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(False, "--version", callback=show_version, is_eager=True, help="Print the installed version and exit."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug logging."),
) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING, format="%(levelname)s %(name)s: %(message)s")


def setup_stdio() -> None:
    """Never crash on a character the output encoding cannot represent.

    Redirected to a file or a pipe, Python on Windows (and on Linux with LANG=C) writes in a legacy code page with
    errors="strict", so a rule title with any other character raised UnicodeEncodeError. Not a terminal: UTF-8. A
    terminal: keep its encoding and replace what it cannot show.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            if stream.isatty():
                reconfigure(errors="replace")
            else:
                reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass


def main() -> None:
    """Entry point (`sigharvest`): runs the app and turns two expected failures into short messages and exit codes."""
    from sigharvest.job_control import Cancelled

    setup_stdio()
    try:
        app()
    except Cancelled:
        Console(stderr=True, soft_wrap=True).print("Cancelled; completed work is retained")
        raise SystemExit(143) from None
    except Exception as exc:  # noqa: BLE001 - classifier re-raises every unexpected error
        _handle_error(exc)


def _error(markup: str) -> None:
    Console(stderr=True, soft_wrap=True).print(f"[red]error:[/] {markup}")


def _handle_error(error: Exception) -> None:
    """Load domain exception types only when an invocation fails."""
    import sqlite3

    from sqlalchemy.exc import DatabaseError, OperationalError

    from sigharvest.errors import SigharvestError
    from sigharvest.lock import LockHeld
    from sigharvest.service import NoWorkspace
    from sigharvest.space import is_full

    try:
        raise error
    except LockHeld as exc:
        _error(escape(str(exc)))
        raise SystemExit(2) from None
    except NoWorkspace as exc:
        _error(escape(str(exc)))
        raise SystemExit(2) from None
    except SigharvestError as exc:
        _error(escape(str(exc)))
        raise SystemExit(2) from None
    except (FileNotFoundError, FileExistsError, IsADirectoryError, NotADirectoryError, PermissionError) as exc:
        # Wrong paths are user input errors: one readable line, not a traceback.
        what = {
            FileNotFoundError: "file or folder not found",
            FileExistsError: "already exists (choose a new path or remove it first)",
            IsADirectoryError: "is a folder, a file was expected",
            NotADirectoryError: "is not a folder",
            PermissionError: "permission denied",
        }[type(exc)]
        name = getattr(exc, "filename", None)
        target = name if isinstance(name, str) and name else (exc.strerror or str(exc))
        _error(f"{escape(str(target))}: {what}")
        raise SystemExit(2) from None
    except (OSError, OperationalError) as exc:
        if is_full(exc):
            _error("storage exhausted during write; free space and retry; previously committed work is retained")
            raise SystemExit(2) from None
        if not isinstance(exc, OperationalError) or "locked" not in str(exc):
            raise
        _error("the database is busy (a sync or index rebuild is writing); try again when it finishes")
        raise SystemExit(2) from None
    except (sqlite3.DatabaseError, DatabaseError) as exc:
        text = str(exc)
        if "file is not a database" not in text and "malformed" not in text:
            raise
        _error(
            "the workspace database (data/sigharvest.db) is damaged: restore it from a backup, or move it away and run "
            "`sigharvest update` to rebuild it from the sources"
        )
        raise SystemExit(2) from None
    except UnicodeError as exc:
        # A subclass of ValueError, but a text encoding problem, not a bad option value.
        if "-v" in sys.argv or "--verbose" in sys.argv:
            raise
        _error(f"text encoding error: {escape(str(exc))} (run with -v for details)")
        raise SystemExit(2) from None
    except (ValueError, OverflowError) as exc:
        # Invalid option values that slipped past Typer's own checks; `sigharvest -v ...` keeps full details in the log.
        if "-v" in sys.argv or "--verbose" in sys.argv:
            raise
        _error(f"invalid input: {escape(str(exc)) or type(exc).__name__} (run with -v for details)")
        raise SystemExit(2) from None
