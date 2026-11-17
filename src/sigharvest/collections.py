"""Collections: named, saved sets of rules (for example "ransomware", "my EDR baseline").

Items are stored by logic hash, plus the rule id when the rule has a real UUID. The search index is rebuilt after
every sync and a rule's logic hash changes whenever its detection changes upstream, so an item is resolved like this:
1. the logic group with the same logic hash, if it still exists ("current");
2. otherwise the best-scored group with the same real rule id ("updated": the rule changed upstream);
3. otherwise the item is "missing" (the rule was removed everywhere); it is kept, so it can come back.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from sigharvest.errors import SigharvestError
from sigharvest.models import Collection, CollectionItem, LogicGroup, RuleVersion

NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}")


class CollectionError(SigharvestError, ValueError):
    """A collection request that cannot be done: unknown or invalid name, unknown rule key."""


@dataclass
class Resolved:
    """One collection item and what it points at now: state current, updated (same rule id, new logic) or missing."""

    item: CollectionItem
    group: LogicGroup | None
    state: str  # current | updated | missing


def check_name(name: str) -> str:
    """The stripped name, or CollectionError when it is not a valid collection name."""
    name = name.strip()
    if not NAME_RE.fullmatch(name):
        raise CollectionError("collection names: 1-80 letters, digits, space, '.', '_' or '-', starting with a letter or digit")
    return name


def get(s: Session, name: str) -> Collection | None:
    """The collection with this name, or None."""
    return s.scalars(select(Collection).where(Collection.name == name.strip())).first()


def require(s: Session, name: str) -> Collection:
    """The collection with this name, or CollectionError."""
    c = get(s, name)
    if c is None:
        raise CollectionError(f"no collection named {name!r}")
    return c


def create(s: Session, name: str, description: str = "") -> Collection:
    """A new, empty collection (CollectionError if the name is invalid or taken)."""
    name = check_name(name)
    if get(s, name) is not None:
        raise CollectionError(f"collection {name!r} already exists")
    c = Collection(name=name, description=description.strip() or None)
    s.add(c)
    s.flush()
    return c


def ensure(s: Session, name: str) -> Collection:
    """The collection with this name, created if it does not exist."""
    return get(s, name) or create(s, name)


def remove_collection(s: Session, name: str) -> None:
    """Delete a collection and its items (the rules stay in the corpus)."""
    c = require(s, name)
    s.execute(delete(CollectionItem).where(CollectionItem.collection_id == c.id))
    s.delete(c)
    s.flush()


def rename(s: Session, old: str, new: str) -> None:
    """Rename a collection (CollectionError if the new name is invalid or taken)."""
    c = require(s, old)
    new = check_name(new)
    if new != c.name and get(s, new) is not None:
        raise CollectionError(f"collection {new!r} already exists")
    c.name = new


def _real_rule_id(s: Session, g: LogicGroup) -> str | None:
    """The rule id, when it identifies one rule (not missing, generated, a placeholder or reused by many rules)."""
    from sigharvest.index import is_ambiguous_id

    v = s.get(RuleVersion, g.canonical_version_id)
    return g.rule_id if v is not None and v.id_flag is None and not is_ambiguous_id(s, g.rule_id) else None


def add(s: Session, c: Collection, groups: list[LogicGroup], note: str = "") -> int:
    """Add groups to the collection; returns how many were new."""
    have = set(s.scalars(select(CollectionItem.logic_hash).where(CollectionItem.collection_id == c.id)))
    n = 0
    for g in groups:
        if g.logic_hash in have:
            continue
        have.add(g.logic_hash)
        s.add(CollectionItem(collection_id=c.id, logic_hash=g.logic_hash, rule_id=_real_rule_id(s, g), title=g.title, note=note.strip() or None))
        n += 1
    return n


def remove(s: Session, c: Collection, keys: list[str]) -> int:
    """Remove items whose logic hash or rule id starts with one of the keys (6+ hex characters)."""
    n = 0
    for key in keys:
        key = key.strip().lower()
        if len(key) < 6:
            raise CollectionError(f"key too short: {key!r} (use 6+ characters)")
        result: Any = s.execute(
            delete(CollectionItem).where(
                CollectionItem.collection_id == c.id,
                CollectionItem.logic_hash.startswith(key) | CollectionItem.rule_id.startswith(key),
            )
        )
        n += result.rowcount
    return n


def resolve(s: Session, c: Collection, *, refresh: bool = False) -> list[Resolved]:
    """Every item of the collection with its current logic group, in the order they were added (see the module docstring)."""
    items = list(
        s.scalars(select(CollectionItem).where(CollectionItem.collection_id == c.id).order_by(CollectionItem.id).execution_options(populate_existing=refresh))
    )
    by_logic = {
        g.logic_hash: g
        for g in s.scalars(select(LogicGroup).where(LogicGroup.logic_hash.in_([i.logic_hash for i in items])).execution_options(populate_existing=refresh))
    }
    out: list[Resolved] = []
    for it in items:
        g = by_logic.get(it.logic_hash)
        if g is not None:
            out.append(Resolved(it, g, "current"))
            continue
        if it.rule_id:
            g = s.scalars(
                select(LogicGroup)
                .where(LogicGroup.rule_id == it.rule_id)
                .order_by(LogicGroup.score.desc())
                .limit(1)
                .execution_options(populate_existing=refresh)
            ).first()
            if g is not None:
                out.append(Resolved(it, g, "updated"))
                continue
        out.append(Resolved(it, None, "missing"))
    return out


def follow_updates(s: Session, c: Collection) -> int:
    """Point "updated" items at the rule's current logic hash; returns how many changed."""
    n = 0
    have = set(s.scalars(select(CollectionItem.logic_hash).where(CollectionItem.collection_id == c.id)))
    for r in resolve(s, c):
        if r.state == "updated" and r.group is not None:
            if r.group.logic_hash in have:
                s.delete(r.item)
            else:
                r.item.logic_hash = r.group.logic_hash
                r.item.title = r.group.title
                have.add(r.group.logic_hash)
            n += 1
    return n


def groups(s: Session, c: Collection) -> list[LogicGroup]:
    """The current groups of the collection (updated items resolved, missing ones skipped, no duplicates)."""
    seen: set[str] = set()
    out = []
    for r in resolve(s, c):
        if r.group is not None and r.group.logic_hash not in seen:
            seen.add(r.group.logic_hash)
            out.append(r.group)
    return out


def summaries(s: Session) -> list[tuple[Collection, int]]:
    """Every collection with its number of items, by name."""
    rows = s.execute(
        select(Collection, func.count(CollectionItem.id))
        .outerjoin(CollectionItem, CollectionItem.collection_id == Collection.id)
        .group_by(Collection.id)
        .order_by(Collection.name)
    )
    return [(c, n) for c, n in rows]


def memberships(s: Session, logic_hash: str) -> list[str]:
    """Names of the collections that hold this logic hash."""
    return list(
        s.scalars(
            select(Collection.name)
            .join(CollectionItem, CollectionItem.collection_id == Collection.id)
            .where(CollectionItem.logic_hash == logic_hash)
            .order_by(Collection.name)
        )
    )
