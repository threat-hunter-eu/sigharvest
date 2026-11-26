"""Shared by every command module: the console, error handling and small helpers."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, NoReturn, ParamSpec, TypeVar

import typer
from rich.console import Console
from rich.markup import escape

from sigharvest.config import find_workspace
from sigharvest.errors import SigharvestError
from sigharvest.lock import LockHeld

if TYPE_CHECKING:
    from pathlib import Path

    from rich.console import ConsoleOptions, RenderableType
    from rich.segment import Segment
    from rich.text import Text
    from sqlalchemy.orm import Session

    from sigharvest.index import GroupFilters
    from sigharvest.query import Filters

# C0/C1 controls except tab and newline. Rich drops only BEL, BS, VT, FF and CR, so an ESC from a rule tag, path,
# detection key, error message or converted query would reach the terminal (CSI cursor moves, OSC title/link/clipboard).
_CONTROLS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


class SafeConsole(Console):
    """A Console that prints control characters as U+FFFD. Strings become Text in render_str (print, table cells,
    measurement) and every renderable, nested ones included, goes through render, so untrusted text cannot carry
    terminal escape sequences. Rich adds its own styling codes after this point; they are unaffected."""

    def render_str(self, text: str, **kwargs: Any) -> Text:
        return super().render_str(_CONTROLS.sub("\ufffd", text), **kwargs)

    def render(self, renderable: RenderableType, options: ConsoleOptions | None = None) -> Iterable[Segment]:
        from rich.text import Text

        if isinstance(renderable, Text) and _CONTROLS.search(renderable.plain):
            renderable = renderable.copy()
            renderable.plain = _CONTROLS.sub("\ufffd", renderable.plain)  # same length: the spans keep their place
        return super().render(renderable, options)


# soft_wrap: messages are not re-wrapped by Rich (the terminal wraps long lines), so a path, URL or command in a
# message is never split mid-word with a newline that breaks copy and paste. Tables still fit the terminal width.
console = SafeConsole(soft_wrap=True)
# Errors go to stderr and start with "error: " (docs/conventions.md).
err_console = SafeConsole(stderr=True, soft_wrap=True)


def error(markup: str) -> None:
    """Print one error line on stderr: `error: ` + the message (Rich markup; escape untrusted parts)."""
    err_console.print(f"[red]error:[/] {markup}")


def fail(message: str, code: int = 2) -> NoReturn:
    """Print a plain-text error and exit (2: bad input or workspace state; 1: the command did not reach its goal)."""
    error(escape(message))
    raise typer.Exit(code)


# Default for every --workers / -j option (parallel fetches, test processes, check processes).
DEFAULT_WORKERS = 8


def open_session(*, readonly: bool = False) -> Session:
    """A database session on the current workspace (SIGHARVEST_HOME, or the nearest folder with a sources.yaml)."""
    from sigharvest.service import open_db

    with user_errors():
        return open_db(find_workspace(), readonly=readonly)()


def warn_incomplete(s: Session) -> bool:
    """Print the "corpus incomplete" line when the first update did not pass its gates (runs.incomplete_corpus)."""
    from sigharvest.runs import incomplete_corpus, incomplete_text

    run = incomplete_corpus(s)
    if run is None:
        return False
    console.print(f"[bold yellow]{escape(incomplete_text(run))}[/]", soft_wrap=True)
    return True


def logsource_text(*parts: str | None) -> str:
    """product/category/service as one short label, skipping the empty parts."""
    return "/".join(x for x in parts if x)


def query_filters(**kw: Any) -> Filters:
    """Filters for the per-copy queries in query.py (search --all-copies, export --unit all); None means "any"."""
    from sigharvest.query import Filters

    return Filters(**{k: v for k, v in kw.items() if v is not None})


LICENCE_CLASSES = ("permissive", "copyleft", "restricted", "none")
LICENCE_CLASS_HELP = "Licence class of the source, as the web UI's licence filter: permissive, copyleft, restricted or none."


def licence_class_option() -> Any:
    return typer.Option(None, "--licence-class", help=LICENCE_CLASS_HELP)


def with_licence_class(s: Session, f: GroupFilters, wanted: str | None) -> GroupFilters:
    """Narrow f to rules with a copy in a source of this licence class (the web UI's `licence` filter), combined
    with any source filter. --licence only matches the rare `license:` field written in a rule document."""
    if not wanted:
        return f
    cls = wanted.strip().lower()
    if cls not in LICENCE_CLASSES:
        raise typer.BadParameter(f"--licence-class must be one of {', '.join(LICENCE_CLASSES)}")
    from dataclasses import replace

    from sigharvest.web.present import sources_by_class

    names = set(sources_by_class(s).get(cls, []))
    if f.source:
        names &= {v.strip() for v in f.source.split(",") if v.strip()}
    return replace(f, source=",".join(sorted(names)) or "\x00none")


@contextmanager
def user_errors() -> Iterator[None]:
    """Print a SigharvestError (unknown collection, source not synced...) as an error on stderr and exit 2.

    NoWorkspace is left to main(), which prints it on stderr."""
    try:
        yield
    except LockHeld as exc:
        error(escape(str(exc)))
        raise typer.Exit(2) from exc
    except SigharvestError as exc:
        # Successful read-only commands need no workspace service. Keep its
        # exception classification at the error consumer, with the same identity.
        from sigharvest.service import NoWorkspace

        if isinstance(exc, NoWorkspace):
            raise
        error(escape(str(exc)))
        raise typer.Exit(2) from exc


P = ParamSpec("P")
R = TypeVar("R")


def _remove_lease_skeleton(root: Path) -> None:
    """A command that failed in a workspace folder it created (init --from-release with a bad pack) leaves no empty
    folder behind. Only the lease's own files are removed, and only when nothing else is there. The caller holds the
    lease: a writer waiting on the unlinked file sees it is gone and reopens the path (UpdateLock.acquire)."""
    data = root / "data"
    guard = data / "sigharvest.lock"
    try:
        if {p.name for p in root.iterdir()} - {"data"} or (data.exists() and {p.name for p in data.iterdir()} - {guard.name}):
            return
        guard.unlink(missing_ok=True)
        if data.exists():
            data.rmdir()
        root.rmdir()
    except OSError:
        pass  # anything unexpected: leave the folder as it is


def mutation_command(
    *,
    when: str | None = None,
    unless: str | None = None,
    workspace_arg: str | None = None,
    wait_arg: str | None = None,
    skip_subcommand: bool = False,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Own the workspace before any command side effect; preserve Typer's signature."""
    import inspect
    import os
    from functools import wraps
    from pathlib import Path

    def decorate(fn: Callable[P, R]) -> Callable[P, R]:
        signature = inspect.signature(fn)

        @wraps(fn)
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            from sigharvest.config import Workspace
            from sigharvest.lock import mutation_lease

            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            values = {k: v.default if isinstance(v, typer.models.ParameterInfo) else v for k, v in bound.arguments.items()}
            skip = (when is not None and not values[when]) or (unless is not None and values[unless])
            context = values.get("ctx")
            if skip_subcommand and getattr(context, "invoked_subcommand", None):
                skip = True
            try:
                if skip:
                    return fn(*args, **kwargs)
                ws = find_workspace()
                existed = True
                if workspace_arg is not None:
                    ws = Workspace(Path(values[workspace_arg] or os.environ.get("SIGHARVEST_HOME") or ".").resolve())
                    existed = ws.root.exists()
                with mutation_lease(ws, timeout=float(values[wait_arg] or 0) if wait_arg else 0):
                    try:
                        return fn(*args, **kwargs)
                    except BaseException:
                        # Only the holder cleans up, before it releases: a refused command never created these files.
                        if not existed:
                            _remove_lease_skeleton(ws.root)
                        raise
            except LockHeld as exc:
                error(escape(str(exc)))
                raise typer.Exit(2) from None

        return wrapped

    return decorate
