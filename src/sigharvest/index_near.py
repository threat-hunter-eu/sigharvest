"""Persisted MinHash/LSH with exact invalidation at the 500-member bucket boundary."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from sqlalchemy import delete, insert, select, text
from sqlalchemy.orm import Session

from sigharvest import neardup
from sigharvest.db import IN_CHUNK
from sigharvest.models import IndexBucket as Bucket
from sigharvest.models import IndexNearPair as Pair
from sigharvest.models import IndexSignature as Signature

Item = tuple[str, str, frozenset[str], tuple[int, ...]]


def bucket_keys(ls: str, sig: tuple[int, ...]) -> list[str]:
    return [json.dumps([ls, band, *sig[band * neardup.ROWS : (band + 1) * neardup.ROWS]], separators=(",", ":")) for band in range(neardup.BANDS)]


def update(s: Session, items: list[Item], removed: set[str], *, full: bool) -> set[str]:
    """Recheck changed signatures and peers crossing the generic-bucket cutoff."""
    if full:
        for model in (Bucket, Signature, Pair):
            s.execute(delete(model))
        changed = items
    else:
        old: dict[str, Signature] = {}
        hashes = list(removed | {r[0] for r in items})
        for i in range(0, len(hashes), IN_CHUNK):
            old.update((r.logic_hash, r) for r in s.scalars(select(Signature).where(Signature.logic_hash.in_(hashes[i : i + IN_CHUNK]))))
        changed = [r for r in items if r[0] not in old or r[1] != old[r[0]].logsource or r[2] != frozenset(old[r[0]].items)]
        removed = {lh for lh in removed if lh in old}
    affected = removed | {r[0] for r in changed}
    if not affected and not full:
        return set()
    keys: set[str] = set()
    before: dict[str, set[str]] = {}
    hashes = list(affected)
    for i in range(0, len(hashes), IN_CHUNK):
        keys.update(s.scalars(select(Bucket.bucket).where(Bucket.logic_hash.in_(hashes[i : i + IN_CHUNK]))))
    keys.update(k for _, ls, _, sig in changed if sig for k in bucket_keys(ls, sig))
    if not full:
        before = members(s, keys)
        for i in range(0, len(hashes), IN_CHUNK):
            chunk = hashes[i : i + IN_CHUNK]
            s.execute(delete(Bucket).where(Bucket.logic_hash.in_(chunk)))
            s.execute(delete(Signature).where(Signature.logic_hash.in_(chunk)))
    signatures: list[dict[str, Any]] = []
    buckets: list[dict[str, Any]] = []
    for lh, ls, xs, sig in changed:
        if not sig:
            continue
        signatures.append({"logic_hash": lh, "logsource": ls, "items": sorted(xs), "signature": list(sig)})
        buckets.extend({"bucket": k, "logic_hash": lh} for k in bucket_keys(ls, sig))
    for model, values in ((Signature, signatures), (Bucket, buckets)):
        for i in range(0, len(values), 5000):
            s.execute(insert(model), values[i : i + 5000])
    after = members(s, keys)
    if not full:
        for key in keys:
            old_members, new_members = before.get(key, set()), after.get(key, set())
            if (len(old_members) > 500) != (len(new_members) > 500):
                affected.update(old_members | new_members)
        hashes = list(affected)
        for i in range(0, len(hashes), IN_CHUNK):
            chunk = hashes[i : i + IN_CHUNK]
            s.execute(delete(Pair).where(Pair.a.in_(chunk) | Pair.b.in_(chunk)))
        # Crossings can invalidate pairs of unchanged peers. All of their buckets
        # must be searched because another band can still support the same pair.
        extra_keys: set[str] = set()
        for i in range(0, len(hashes), IN_CHUNK):
            extra_keys.update(s.scalars(select(Bucket.bucket).where(Bucket.logic_hash.in_(hashes[i : i + IN_CHUNK]))))
        after.update(members(s, extra_keys - keys))
    candidate_hashes = {lh for group in after.values() if len(group) <= 500 for lh in group}
    sets: dict[str, frozenset[str]] = {}
    hashes = list(candidate_hashes)
    for i in range(0, len(hashes), IN_CHUNK):
        sets.update(
            (lh, frozenset(xs)) for lh, xs in s.execute(select(Signature.logic_hash, Signature.items).where(Signature.logic_hash.in_(hashes[i : i + IN_CHUNK])))
        )
    by_logic: dict[str, list[set[str]]] = defaultdict(list)
    for group in after.values():
        if 2 <= len(group) <= 500:
            for lh in group if full else group & affected:
                by_logic[lh].append(group)
    result: list[dict[str, Any]] = []
    for a, groups in by_logic.items():
        # Only one signature's candidate set is resident, not a corpus-sized set
        # of rejected pairs. This bounds even adversarial generic detections.
        candidates = set().union(*groups)
        for b in candidates:
            if a == b or (b < a and (full or b in affected)):
                continue
            sa, sb = sets[a], sets[b]
            j = len(sa & sb) / len(sa | sb)
            if j >= neardup.THRESHOLD:
                result.append({"a": min(a, b), "b": max(a, b), "jaccard": round(j, 3)})
                if len(result) >= 5000:
                    s.execute(insert(Pair), result)
                    result = []
    if result:
        s.execute(insert(Pair), result)
    return affected


def members(s: Session, keys: Iterable[str]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    keys = list(keys)
    for i in range(0, len(keys), IN_CHUNK):
        for key, lh in s.execute(select(Bucket.bucket, Bucket.logic_hash).where(Bucket.bucket.in_(keys[i : i + IN_CHUNK]))):
            out[key].add(lh)
    return dict(out)


def publish(s: Session) -> None:
    """Family merges/splits change visibility, never the stored similarity itself."""
    s.execute(text("DELETE FROM near_duplicates WHERE (a,b) NOT IN (SELECT a,b FROM index_near_pairs)"))
    s.execute(
        text("""DELETE FROM near_duplicates WHERE (a,b) IN (
        SELECT p.a,p.b FROM index_near_pairs p JOIN logic_groups a ON a.logic_hash=p.a
        JOIN logic_groups b ON b.logic_hash=p.b WHERE a.family_id=b.family_id)""")
    )
    s.execute(
        text("""INSERT INTO near_duplicates(a,b,jaccard)
        SELECT p.a,p.b,p.jaccard FROM index_near_pairs p
        JOIN logic_groups a ON a.logic_hash=p.a JOIN logic_groups b ON b.logic_hash=p.b
        WHERE a.family_id!=b.family_id
        ON CONFLICT(a,b) DO UPDATE SET jaccard=excluded.jaccard WHERE jaccard!=excluded.jaccard""")
    )
