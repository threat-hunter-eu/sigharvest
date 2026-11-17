"""Resolve just the selected command, retaining normal Typer introspection.

The root menu uses summaries without importing implementations. Explicit command
lookup (including docs and completion) builds the original Typer command on demand.
Each built root owns its cache, so test patches and repeated invocations stay fresh.
"""

from __future__ import annotations

from collections.abc import Iterator, MutableMapping
from copy import copy
from importlib import import_module
from typing import Any, cast

import typer
from typer.core import TyperCommand, TyperGroup
from typer.main import get_command

from sigharvest.cli import help as presentation
from sigharvest.cli.help import START_EXAMPLES, SUMMARIES, Command, HelpGroup, panel_for
from sigharvest.cli.registry import ALIASES, COMMANDS, GROUPS


def _target(path: str) -> Any:
    module, attribute = path.split(".")
    return getattr(import_module(f"sigharvest.cli.{module}"), attribute)


def _summary(name: str) -> str:
    text = SUMMARIES[name]
    if name in START_EXAMPLES:
        text += f" Example: {START_EXAMPLES[name]}"
    return text


class LazyCommands(MutableMapping[str, Command]):
    """A normal mapping whose values are resolved only when requested."""

    def __init__(self) -> None:
        self.loaded: dict[str, Command] = {}
        self.names = dict.fromkeys((*COMMANDS, *GROUPS, *ALIASES))

    def __iter__(self) -> Iterator[str]:
        return iter(self.names)

    def __len__(self) -> int:
        return len(self.names)

    def __getitem__(self, name: str) -> Command:
        if name not in self.names:
            raise KeyError(name)
        if name not in self.loaded:
            holder = typer.Typer(add_completion=False)
            if name in ALIASES:
                target, cls = COMMANDS[ALIASES[name]]
                holder.command(name, cls=_target(cls) if cls else None, hidden=True, help=f"Alias of {ALIASES[name]}.")(_target(target))
                alias = get_command(holder)
                assert isinstance(alias, TyperCommand)
                presentation._prepare_help(TyperGroup(commands={name: alias}))
                self.loaded[name] = alias
                return alias
            if name in GROUPS:
                holder.add_typer(_target(GROUPS[name]), name=name)
                root = get_command(holder)
                assert isinstance(root, TyperGroup)
                command = root.commands[name]
            else:
                target, cls = COMMANDS[name]
                holder.command(
                    name,
                    cls=_target(cls) if cls else None,
                    help="Alias of search." if name == "list" else None,
                )(_target(target))
                command = get_command(holder)
            command.short_help = _summary(name)
            assert isinstance(command, (TyperCommand, TyperGroup))
            command.rich_help_panel = panel_for(name)
            presentation._prepare_help(TyperGroup(commands={name: command}))
            self.loaded[name] = command
        return self.loaded[name]

    def __setitem__(self, name: str, command: Command) -> None:
        self.names[name] = None
        self.loaded[name] = command

    def __delitem__(self, name: str) -> None:
        del self.names[name]
        self.loaded.pop(name, None)


class LazyHelpGroup(HelpGroup):
    """Keep root help cheap while parsing the original selected command."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.commands = cast(dict[str, Any], LazyCommands())

    def format_help(self, ctx: Any, formatter: Any) -> None:
        view = copy(self)
        view.commands = {name: TyperCommand(name, short_help=_summary(name), rich_help_panel=panel_for(name)) for name in self.commands if name not in ALIASES}
        HelpGroup.format_help(view, ctx, formatter)
