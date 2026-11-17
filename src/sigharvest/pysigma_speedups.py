"""Output-identical replacements for pySigma backend code that is quadratic in rule size.

pysigma-backend-loki splits a query longer than LogQL's limit into N partitions of the rule's top-level OR
(`LogQLBackend.partition_rule`). Upstream deep-copies the *whole* condition tree once per partition and then keeps
1/N of the OR's arguments, so a rule with K values costs about N * K copies with N growing with K: 16 s for one
190 KB keyword rule, close to two minutes for 500 KB, and every such rule hit the 30 s per-backend timeout of the
convert stage. That tail is what made a cold `update --convert` on the curated preset run for an hour.

The replacement does the same deep copy, BFS and slicing, but pre-seeds the copy memo so the OR arguments outside a
partition's slice are never copied (they are sliced away right after). Each partition's tree is therefore exactly
the tree upstream builds, and so is every query. It is installed only when the upstream function is the exact
source this was written against (pysigma-backend-loki 0.15.1 and 0.16.0); any other release keeps upstream code.
A partition whose copy reached a skipped argument through some other path than the OR's own list falls back to
upstream for the whole call.

Every converter that may build a Loki backend calls `install()` first (idempotent and cheap).
"""

from __future__ import annotations

import copy
import hashlib
import inspect
from collections import deque
from typing import Any

# sha256 of inspect.getsource(LogQLBackend.partition_rule) in the releases this replacement mirrors.
LOKI_PARTITION_SOURCES = frozenset({"404469297dc3d9d7b04da6c5de8eb4b99c350e660529339c9c29ca01488b4a98"})
_installed = False
_SKIPPED = object()


class _SliceMemo(dict[int, Any]):
    """deepcopy memo that maps the skipped OR arguments to a placeholder and counts how often they are reached."""

    def __init__(self, skipped: set[int]) -> None:
        super().__init__(dict.fromkeys(skipped, _SKIPPED))
        self.skipped = skipped
        self.hits = 0

    def get(self, key: Any, default: Any = None) -> Any:
        if key in self.skipped:
            self.hits += 1
        return super().get(key, default)


def _top_or(condition: Any) -> Any:
    """The highest ConditionOR, found breadth-first exactly like upstream."""
    from sigma.conditions import ConditionItem, ConditionOR

    queue = deque([condition])
    while queue:
        cond = queue.popleft()
        if isinstance(cond, ConditionOR):
            return cond
        if isinstance(cond, ConditionItem):
            queue.extend(cond.args)
    return None


def partitions(condition: Any, count: int) -> list[Any] | None:
    """Upstream's partitions of `condition`, or None when only upstream can produce them (it then also warns)."""
    top = _top_or(condition)
    if top is None or len(top.args) < count or len({id(arg) for arg in top.args}) != len(top.args):
        return None
    width = int(len(top.args) / count)
    out = []
    for part in range(count):
        start, end = part * width, (part + 1) * width
        memo = _SliceMemo({id(arg) for i, arg in enumerate(top.args) if not start <= i < end})
        clone = copy.deepcopy(condition, memo)
        # Each skipped argument must be reached once, from the OR's list; anything else would leave a placeholder.
        if memo.hits != len(memo.skipped):
            return None
        clone_top = _top_or(clone)
        clone_top.args = clone_top.args[start:end]
        out.append(clone)
    return out


def _source_digest(fn: Any) -> str | None:
    try:
        return hashlib.sha256(inspect.getsource(fn).encode()).hexdigest()
    except (OSError, TypeError):
        return None


def install() -> bool:
    """Replace LogQLBackend.partition_rule when the installed release matches; True when the replacement is active."""
    global _installed
    if _installed:
        return True
    try:
        from sigma.backends.loki.loki import LogQLBackend
    except ImportError:
        return False
    upstream = LogQLBackend.partition_rule
    if getattr(upstream, "_sigharvest_upstream", None) is not None:
        _installed = True
        return True
    if _source_digest(upstream) not in LOKI_PARTITION_SOURCES:
        return False

    def partition_rule(self: Any, condition: Any, partitions_count: int) -> list[Any]:
        fast = partitions(condition, partitions_count)
        return upstream(self, condition, partitions_count) if fast is None else fast

    partition_rule._sigharvest_upstream = upstream  # type: ignore[attr-defined]
    LogQLBackend.partition_rule = partition_rule  # type: ignore[method-assign,assignment]
    _installed = True
    return True
