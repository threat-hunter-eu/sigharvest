"""Near-duplicate rules across families: the same detection written independently, with small differences.

Each rule's detection becomes a set of (field, modifiers, value) items. MinHash signatures (64 hashes) with LSH
banding (16 bands x 4 rows) find candidate pairs in the same log source; pairs with a Jaccard similarity of at
least THRESHOLD on the real sets are stored in `near_duplicates`. They are shown as "similar rules" links; they
never merge families (a negated condition can have the same values as the original).
"""

from __future__ import annotations

import hashlib
import struct
from collections import defaultdict
from collections.abc import Iterable
from functools import lru_cache
from typing import Any

THRESHOLD = 0.8
PERMUTATIONS = 64
BANDS, ROWS = 16, 4
MIN_ITEMS = 4  # small detections (a few values) give meaningless similarity
PERMUTATION_CACHE_ITEMS = 8192  # bounded to about 24 MiB, released after each pairs() call
CACHED_SIGNATURE_MAX_ITEMS = 256  # zip's argument expansion must not retain an entire large IOC list
_MASK = (1 << 61) - 1
_SEEDS = [int.from_bytes(hashlib.blake2b(str(i).encode(), digest_size=8).digest(), "big") | 1 for i in range(PERMUTATIONS)]


def items(detection: Any) -> frozenset[str]:
    """`field|modifiers=value` strings of a detection, lower-cased; keyword values have an empty field."""
    out: set[str] = set()

    def walk(x: Any, field: str) -> None:
        if isinstance(x, dict):
            for k, v in x.items():
                walk(v, str(k).lower())
        elif isinstance(x, list):
            for v in x:
                walk(v, field)
        elif x is not None:
            out.add(f"{field}={str(x).lower()}")

    if isinstance(detection, dict):
        for name, selection in detection.items():
            if name not in ("condition", "timeframe"):
                walk(selection, "")
    return frozenset(out)


def _h(s: str) -> int:
    return struct.unpack("<Q", hashlib.blake2b(s.encode("utf-8", "replace"), digest_size=8).digest())[0]


def signature(xs: frozenset[str]) -> tuple[int, ...]:
    hs = [_h(x) for x in xs]
    return tuple(min((h * a) & _MASK for h in hs) for a in _SEEDS)


@lru_cache(maxsize=PERMUTATION_CACHE_ITEMS)
def _permutations(item: str) -> tuple[int, ...]:
    h = _h(item)
    return tuple((h * a) & _MASK for a in _SEEDS)


def cached_signature(xs: frozenset[str]) -> tuple[int, ...]:
    """The reference signature with bounded reuse of shared detection values."""
    return tuple(map(min, zip(*(_permutations(x) for x in xs), strict=True))) if len(xs) <= CACHED_SIGNATURE_MAX_ITEMS else signature(xs)


def clear_signature_cache() -> None:
    _permutations.cache_clear()


def pairs(rules: Iterable[tuple[str, str, frozenset[str]]], threshold: float = THRESHOLD) -> list[tuple[str, str, float]]:
    """rules: (logic hash, logsource key, items). Returns (a, b, jaccard) with a < b."""
    data = [(lh, ls, xs) for lh, ls, xs in rules if len(xs) >= MIN_ITEMS]
    sets = {lh: xs for lh, _ls, xs in data}
    buckets: dict[tuple[str, int, tuple[int, ...]], list[str]] = defaultdict(list)

    @lru_cache(maxsize=PERMUTATION_CACHE_ITEMS)
    def permutations(item: str) -> tuple[int, ...]:
        # Shared detection values recur across many rules. Compute their 64
        # products once, then take column minima in C without Python generators.
        h = _h(item)
        return tuple((h * a) & _MASK for a in _SEEDS)

    for lh, ls, xs in data:
        sig = tuple(map(min, zip(*(permutations(x) for x in xs), strict=True))) if len(xs) <= CACHED_SIGNATURE_MAX_ITEMS else signature(xs)
        for band in range(BANDS):
            buckets[(ls, band, sig[band * ROWS : (band + 1) * ROWS])].append(lh)
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str, float]] = []
    for members in buckets.values():
        if len(members) < 2 or len(members) > 500:  # huge buckets are generic templates; skip
            continue
        for i, a in enumerate(members):
            for b in members[i + 1 :]:
                key = (a, b) if a < b else (b, a)
                if key in seen:
                    continue
                seen.add(key)
                sa, sb = sets[key[0]], sets[key[1]]
                j = len(sa & sb) / len(sa | sb)
                if j >= threshold:
                    out.append((key[0], key[1], round(j, 3)))
    return out
