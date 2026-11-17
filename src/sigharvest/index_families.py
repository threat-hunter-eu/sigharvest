"""Repair identity edges and only union affected components, including splits.

The dense family numbers remain ordered by the smallest logic hash, as in the
reference rebuild. Renumbering an unchanged component needs no YAML parsing.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable

from sqlalchemy import delete, func, insert, select
from sqlalchemy.orm import Session

from sigharvest.db import IN_CHUNK, get_meta
from sigharvest.models import IndexFamilyLink as Link
from sigharvest.models import Occurrence, RuleVersion
from sigharvest.semantic import ACTIVE_FINGERPRINT


def families(s: Session, live: set[str]) -> tuple[dict[str, int], dict[int, int]]:
    """Family id per live logic hash (1..n in logic-hash order) and the size of each family; always a full rebuild."""
    from sigharvest.family_links import routes
    from sigharvest.index import _coherent_clusters, ambiguous_ids, related_ids

    route_of = routes(s, live)
    dirty: set[str] | None = None
    dirty_ids: set[str] = set()
    previous: dict[str, int] = {}
    prefix = "public:"
    scoped = Link.owner.startswith(prefix)
    live_keys = func.json_each(json.dumps(sorted(live))).table_valued("value")
    eligible = RuleVersion.logic_hash.in_(select(live_keys.c.value))
    active = get_meta(s, ACTIVE_FINGERPRINT)
    shaky = ambiguous_ids(s)
    touched = set(dirty or ())
    owners = {"u:" + rid for rid in dirty_ids}
    if dirty is not None:
        hashes = list(dirty)
        for start in range(0, len(hashes), IN_CHUNK):
            chunk = hashes[start : start + IN_CHUNK]
            owners.update(o.removeprefix(prefix) for o in s.scalars(select(Link.owner).where(scoped, Link.logic_hash.in_(chunk))))
            owners.update("u:" + rid for rid in s.scalars(select(RuleVersion.rule_id).where(RuleVersion.logic_hash.in_(chunk))))
        owners.update("l:" + lh for lh in dirty)
        # An ID becoming ambiguous also invalidates related edges pointing at it.
        keys = ["u:" + rid for rid in dirty_ids]
        for start in range(0, len(keys), IN_CHUNK):
            owners.update(o.removeprefix(prefix) for o in s.scalars(select(Link.owner).where(scoped, Link.key.in_(keys[start : start + IN_CHUNK]))))
        # Include currently suppressed related references when ambiguity disappears.
        if dirty_ids:
            owners.update("l:" + lh for (lh,) in s.execute(select(RuleVersion.logic_hash).where(RuleVersion.raw.like("%related:%"))))
    else:
        s.execute(delete(Link).where(scoped))
    rows: set[tuple[str, str, str]] = set()

    def link(owner: str, key: str, lh: str) -> None:
        rows.add((owner, key, lh))
        touched.add(lh)

    live_version = select(Occurrence.id).where(Occurrence.version_id == RuleVersion.id, Occurrence.present.is_(True)).exists()
    by_id: dict[str, list[tuple[str, str]]] = defaultdict(list)
    q = select(RuleVersion.rule_id, RuleVersion.logic_hash, RuleVersion.id_flag, RuleVersion.title_slug).where(live_version, eligible)
    if dirty is None:
        batches: Iterable[list[str] | None] = [None]
    else:
        ids = [o[2:] for o in owners if o.startswith("u:")]
        batches = [ids[i : i + IN_CHUNK] for i in range(0, len(ids), IN_CHUNK)]
    for batch in batches:
        for rid, lh, flag, slug in s.execute(q if batch is None else q.where(RuleVersion.rule_id.in_(batch))):
            if not flag:
                by_id[rid].append((lh, slug or ""))
    for rid, members in by_id.items():
        owner = "u:" + rid
        if rid in shaky:
            for lh, slug in members:
                link(owner, f"u:{rid}|{slug}", lh)
        elif len({slug for _, slug in members}) == 1:
            for lh, _ in members:
                link(owner, owner, lh)
        else:
            for lh, cluster in _coherent_clusters(s, members):
                link(owner, f"u:{rid}#{cluster}", lh)
    q2 = select(RuleVersion.logic_hash, RuleVersion.semantic_hash, RuleVersion.semantic_fingerprint, RuleVersion.raw).where(live_version, eligible)
    hashes = [o[2:] for o in owners if o.startswith("l:")]
    batches = [None] if dirty is None else [hashes[i : i + IN_CHUNK] for i in range(0, len(hashes), IN_CHUNK)]
    for batch in batches:
        for lh, sem, fingerprint, raw in s.execute(q2 if batch is None else q2.where(RuleVersion.logic_hash.in_(batch))):
            owner = "l:" + lh
            if sem and active and fingerprint == active:
                link(owner, "s:" + sem, lh)
            if "related:" in raw:
                for rid in related_ids(raw):
                    if rid not in shaky:
                        link(owner, "u:" + rid, lh)
    owner_list = list(owners)
    for i in range(0, len(owner_list), IN_CHUNK):
        condition = Link.owner.in_([prefix + owner for owner in owner_list[i : i + IN_CHUNK]])
        touched.update(s.scalars(select(Link.logic_hash).where(condition)))
        s.execute(delete(Link).where(condition))
    entries = [{"owner": prefix + o, "key": k, "logic_hash": lh} for o, k, lh in sorted(rows)]
    for i in range(0, len(entries), 5000):
        s.execute(insert(Link), entries[i : i + 5000])

    # Old connected components are safe units until touched. A deletion may split
    # one; a new edge may join several, so expand through both old and new edges.
    keys_to_logic: dict[str, list[str]] = defaultdict(list)
    logic_to_keys: dict[str, list[str]] = defaultdict(list)
    for key, lh in s.execute(select(Link.key, Link.logic_hash).where(scoped).distinct()):
        keys_to_logic[key].append(lh)
        logic_to_keys[lh].append(key)
    old: dict[int, list[str]] = defaultdict(list)
    for lh, old_fid in previous.items():
        old[old_fid].append(lh)
    pending = list(touched) if dirty is not None else list(live)
    affected: set[str] = set()
    seen_old: set[int] = set()
    seen_keys: set[str] = set()
    while pending:
        lh = pending.pop()
        if lh in affected:
            continue
        affected.add(lh)
        old_fid_or_none = previous.get(lh)
        if old_fid_or_none is not None and old_fid_or_none not in seen_old:
            seen_old.add(old_fid_or_none)
            pending.extend(old[old_fid_or_none])
        for key in logic_to_keys.get(lh, []):
            if key not in seen_keys:
                seen_keys.add(key)
                pending.extend(keys_to_logic[key])
    parent = {lh: lh for lh in affected & live}

    def find(lh: str) -> str:
        while parent[lh] != lh:
            parent[lh] = parent[parent[lh]]
            lh = parent[lh]
        return lh

    for key in seen_keys:
        first_by_route: dict[tuple[str | None, str | None, str | None], str] = {}
        for lh in keys_to_logic[key]:
            if lh in parent:
                first = first_by_route.setdefault(route_of[lh], lh)
                parent[find(lh)] = find(first)
    roots: dict[str, int] = {}
    result: dict[str, int] = {}
    sizes: dict[int, int] = defaultdict(int)
    for lh in sorted(live):
        root = "new:" + find(lh) if lh in parent else "old:" + str(previous[lh])
        fid = roots.setdefault(root, len(roots) + 1)
        result[lh] = fid
        sizes[fid] += 1
    return result, dict(sizes)
