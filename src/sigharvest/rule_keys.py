"""Shared rule-key admission and unambiguous prefix matching for CLI selections.

Callers retain their own scope: indexed rules or exact stored versions. No prefix picks a first row.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from sqlalchemy import select, union
from sqlalchemy.orm import Session

from sigharvest.errors import SigharvestError
from sigharvest.models import LogicGroup, RuleVersion

MIN_PREFIX = 8
CANDIDATE_LIMIT = 20


class UnknownRule(SigharvestError, LookupError):
    """A key with no candidate in the requested scope."""

    def __init__(self, key: str) -> None:
        super().__init__(f"unknown rule: {key}")
        self.key = key


def normalize(key: str) -> str:
    key = key.strip().lower()
    if len(key) < MIN_PREFIX or not re.fullmatch(r"[0-9a-f-]+", key):
        raise SigharvestError("Use a rule id or hash prefix of 8+ characters.")
    return key


def unique_key(key: str, candidates: Iterable[str]) -> str:
    """Require one distinct candidate; list full selectable keys on ambiguity."""
    normalize(key)
    values = sorted(set(candidates))
    if not values:
        raise UnknownRule(key)
    if len(values) > 1:
        shown = "\n".join(values[:CANDIDATE_LIMIT])
        more = "\nMore candidates exist; use a longer prefix." if len(values) > CANDIDATE_LIMIT else ""
        raise SigharvestError(f"Ambiguous rule key {key!r}; use one of these full keys:\n{shown}{more}")
    return values[0]


def group(s: Session, key: str) -> LogicGroup:
    """Resolve a logic/UUID/content prefix to one currently indexed logic."""
    prefix = normalize(key)
    direct = select(LogicGroup.logic_hash).where(LogicGroup.logic_hash.startswith(prefix) | LogicGroup.rule_id.startswith(prefix))
    versions = (
        select(LogicGroup.logic_hash)
        .join(RuleVersion, RuleVersion.logic_hash == LogicGroup.logic_hash)
        .where(RuleVersion.content_hash.startswith(prefix) | RuleVersion.rule_id.startswith(prefix))
    )
    logic = unique_key(key, s.scalars(union(direct, versions).order_by("logic_hash").limit(CANDIDATE_LIMIT + 1)))
    found = s.scalar(select(LogicGroup).where(LogicGroup.logic_hash == logic))
    assert found is not None
    return found


def version(s: Session, key: str) -> RuleVersion:
    """Content prefixes pin stored bytes; logic/UUID keys select the canonical copy."""
    prefix = normalize(key)
    contents = list(
        s.scalars(
            select(RuleVersion.content_hash).where(RuleVersion.content_hash.startswith(prefix)).order_by(RuleVersion.content_hash).limit(CANDIDATE_LIMIT + 1)
        )
    )
    if contents:
        content = unique_key(key, contents)
        found = s.scalar(select(RuleVersion).where(RuleVersion.content_hash == content))
    else:
        found = s.get(RuleVersion, group(s, key).canonical_version_id)
    if found is None:
        raise SigharvestError(f"Missing stored version for rule: {key}")
    return found
