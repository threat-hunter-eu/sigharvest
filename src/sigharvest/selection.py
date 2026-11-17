"""Which rules a command works on.

Commands pick rules in four ways, often combined in one call:
- rule keys: a prefix of a logic hash, rule id or content hash (`index.group_for` resolves it);
- rule files: your own YAML files or folders, which are not in the corpus;
- saved collections (`collections.py`);
- a search: a query and filters, one rule per family by default (`index.search_groups`).

The corpus selectors return logic groups (one per unique logic).

`collection add/import`, `export` and the web UI (collections) use these helpers.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from sqlalchemy.orm import Session

from sigharvest.errors import SigharvestError
from sigharvest.index import GroupFilters, group_for, search_groups
from sigharvest.models import LogicGroup
from sigharvest.rule_keys import MIN_PREFIX, group
from sigharvest.rule_keys import UnknownRule as UnknownRule

# Shorter prefixes match too many rules to be what anyone meant (used where keys come from files).
MIN_KEY_LENGTH = MIN_PREFIX
RULE_FILE_SUFFIXES = (".yml", ".yaml")


def groups_for_keys(s: Session, keys: Iterable[str]) -> list[LogicGroup]:
    """The logic group of each key, in order. Raises UnknownRule for the first key that matches nothing."""
    out = []
    for key in keys:
        out.append(group(s, key))
    return out


def known_groups(s: Session, keys: Iterable[str]) -> tuple[list[LogicGroup], int]:
    """The groups of the keys that resolve, and how many did not (or were shorter than MIN_KEY_LENGTH).

    For lists from files (a shared manifest), where some rules may not be in this corpus."""
    found, unknown = [], 0
    for key in keys:
        g = group_for(s, key) if len(key) >= MIN_KEY_LENGTH else None
        if g is None:
            unknown += 1
        else:
            found.append(g)
    return found, unknown


def collection_groups(s: Session, name: str) -> list[LogicGroup]:
    """The current rules of a saved collection (raises CollectionError for an unknown name)."""
    from sigharvest import collections as col

    return col.groups(s, col.require(s, name))


def wants_search(query: str | None, *filters: object) -> bool:
    """True when a search was asked for: a query (even an empty one, which means "every rule") or any filter."""
    return query is not None or any(filters)


def search(s: Session, query: str | None, filters: GroupFilters, limit: int, per_family: bool = True) -> list[LogicGroup]:
    """The best-ranked groups matching a search, at most `limit` (one per family unless per_family is False)."""
    return search_groups(s, query, filters, limit=limit, per_family=per_family)[0]


def rule_files(path: Path) -> list[tuple[str, str]]:
    """(name, YAML) of every detection rule in a YAML file, or in the .yml/.yaml files under a folder.

    The name is the relative file path, plus `#N` for the N-th document of a multi-document file (N > 0)."""
    from sigharvest.documents import MAX_FILE_BYTES, load_documents
    from sigharvest.ruleview import unsafe_yaml

    files = [path] if path.is_file() else sorted(x for x in path.rglob("*") if x.suffix.lower() in RULE_FILE_SUFFIXES)
    out = []
    for f in files:
        with f.open("rb") as fh:
            raw = fh.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise SigharvestError(f"rule file exceeds 2 MiB: {f}")
        problem = unsafe_yaml(raw)
        if problem:
            raise SigharvestError(f"rule file {f}: {problem}")
        for d in load_documents(raw):
            if d.error:
                raise SigharvestError(f"rule file {f}: {d.error}")
            if d.kind in {"rule", "correlation"}:
                name = f.relative_to(path).as_posix() if path.is_dir() else f.name
                out.append((f"{name}#{d.index}" if d.index else name, d.rule_yaml))
    return out
