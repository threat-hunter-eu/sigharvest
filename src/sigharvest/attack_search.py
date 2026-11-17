"""Offline ATT&CK aliases for lexical search, without rewriting source tags or FTS.

Bare IDs and exact catalog names share one FTS expression. Explicit column
searches remain literal. Expansion preserves lexical prefix matching; canonical
technique selection remains the job of the separate technique filter.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from sigharvest.attack import ATTACK_VERSION, cached_matrix, normalise_technique
from sigharvest.config import Workspace


def catalog_key(s: Session) -> tuple[Any, ...] | None:
    """Bind caches and cursors to the local catalog, including absence/corruption."""
    from sigharvest.source_status import workspace

    ws = workspace(s)
    if ws is None:
        return None
    path = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    try:
        stat = path.stat()
        return str(ws.root), stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns
    except OSError:
        return (str(ws.root),)


def _key(value: str) -> str:
    return " ".join(value.strip('"').casefold().split())


@dataclass(frozen=True)
class Catalog:
    expressions: dict[str, str]
    hints: dict[str, str]


@lru_cache(maxsize=8)
def _catalog(key: tuple[Any, ...] | None) -> Catalog:
    matrix = cached_matrix(Workspace(Path(key[0]))) if key and len(key) > 1 else None
    if matrix is None:
        return Catalog({}, {})
    from sigharvest.index import _phrase

    aliases: dict[str, set[str]] = defaultdict(set)
    hints = {}
    version = matrix.version.removesuffix(".0")
    for tid in matrix.techniques.keys() | matrix.replaced.keys():
        identity = normalise_technique(tid, matrix)
        if identity.current_id:
            aliases[identity.current_id].add(tid)
            if identity.status == "replaced":
                hints[tid.casefold()] = f"{tid} is now {identity.current_id} (ATT&CK v{version})"
    names: dict[str, set[str]] = defaultdict(set)
    expressions = {}
    for current, ids in aliases.items():
        tech = matrix.techniques[current]
        included = ids | {alias for child in matrix.techniques.values() if child.parent == current for alias in aliases.get(child.id, ())}
        terms = {phrase for tid in included if (phrase := _phrase(tid.lower()))}
        if isinstance(tech.name, str) and (words := [_phrase(word) for word in tech.name.split()]):
            # Preserve ordinary AND/prefix name matches as well as ID matches.
            # Catalog words are data, including words that spell FTS operators.
            name_match = " AND ".join(word for word in words if word)
            if name_match:
                terms.add("(" + name_match + ")")
            names[_key(tech.name)].add(current)
        expression = "(" + " OR ".join(sorted(terms)) + ")"
        for tid in ids:
            for prefix in ("", "attack.", "enterprise.", "attack.enterprise."):
                for spelling in (tid.lower(), tid.lower().replace(".", "_")):
                    expressions[prefix + spelling] = expression
                    if tid.casefold() in hints:
                        hints[prefix + spelling] = hints[tid.casefold()]
    for name, ids in names.items():
        expressions[name] = "(" + " OR ".join(sorted({expressions[tid.lower()] for tid in ids})) + ")"
    return Catalog(expressions, hints)


def prepare(s: Session, query: str) -> tuple[str, dict[str, str], list[str]]:
    """Resolve whole names or individual ID/quoted-name terms after inline filters."""
    from sigharvest.index import _TERM

    catalog = _catalog(catalog_key(s))
    # A complete, unquoted technique name is a single search term as well.
    if _key(query) in catalog.expressions:
        query = '"' + query.strip().strip('"') + '"'
    expressions = {}
    hints = set()
    for raw in _TERM.findall(query):
        term = raw.removeprefix("-")
        key = _key(term)
        if key in catalog.expressions:
            expressions[term] = catalog.expressions[key]
            if key in catalog.hints:
                hints.add(catalog.hints[key])
    return query, expressions, sorted(hints)


def search_hints(s: Session, query: str | None) -> list[str]:
    """User-facing replacement hints with the same recognition as the FTS query."""
    from sigharvest.index import parse_query

    return prepare(s, parse_query(query)[0])[2] if query else []
