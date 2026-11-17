"""Bounded, data-only process workers for YAML, quality flags and MinHash.

Workers never open the database. At most one 2,000-document window is submitted;
windows are capped at 64 MiB and worker batches at 4 MiB of input YAML.
"""

from __future__ import annotations

import multiprocessing
import os
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor
from typing import Any

import yaml

from sigharvest import neardup
from sigharvest.quality import classify, is_junk
from sigharvest.text_metadata import TextMetadata, from_raw

Payload = tuple[int, str, bool, bool, str]
Prepared = tuple[dict[str, Any], list[str], frozenset[str], tuple[int, ...], TextMetadata]


def prepare(batch: list[Payload]) -> dict[int, Prepared]:
    result = {}
    loader = getattr(yaml, "CBaseLoader", yaml.BaseLoader)
    for vid, raw, fixture, deprecated, kind in batch:
        try:
            data = yaml.load(raw, Loader=loader)  # noqa: S506 - BaseLoader constructs strings only
        except yaml.YAMLError:
            data = {}
        data = data if isinstance(data, dict) else {}
        flags = classify(data, ["tests/x"] if fixture else [], upstream_deprecated=deprecated, raw=raw)
        xs = neardup.items(data.get("detection")) if kind == "rule" and not is_junk(flags) else frozenset()
        sig = neardup.cached_signature(xs) if len(xs) >= neardup.MIN_ITEMS else ()
        result[vid] = data, flags, xs, sig, from_raw(raw)
    return result


class Workers:
    """Lazy pool; small deltas avoid process startup. Exceptions shut down the pool."""

    def __init__(self, count: int | None, total: int):
        count = max(1, min(count or (os.cpu_count() or 1), 22))
        self.count = count
        self.pool = ProcessPoolExecutor(count, mp_context=multiprocessing.get_context("spawn")) if count > 1 and total >= 2000 else None

    def close(self) -> None:
        if self.pool:
            self.pool.shutdown(wait=True, cancel_futures=True)
        neardup.clear_signature_cache()

    def run(self, rows: list[Payload]) -> dict[int, Prepared]:
        batch_items = max(1, min(50, (len(rows) + 2 * self.count - 1) // (2 * self.count)))

        def batches() -> Iterator[list[Payload]]:
            batch: list[Payload] = []
            size = 0
            for row in rows:
                if batch and (len(batch) >= batch_items or size + len(row[1]) > 4 * 1024 * 1024):
                    yield batch
                    batch, size = [], 0
                batch.append(row)
                size += len(row[1])
            if batch:
                yield batch

        result = {}
        if self.pool:
            # The caller provides a bounded window, not the entire corpus.
            for values in self.pool.map(prepare, batches()):
                result.update(values)
        else:
            for batch in batches():
                result.update(prepare(batch))
        return result
