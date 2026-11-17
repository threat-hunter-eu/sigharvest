"""Recover a missing first snapshot from accepted file hashes at the same revision.

Only legacy acceptance (no policy marker) or the current policy may reuse rows.
Explicit rescans and policy changes remain full ingests. Ambiguous file state and
quarantine always go through ingestion; history is never used as live membership.
"""

from __future__ import annotations

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from sigharvest.config import SourceConfig
from sigharvest.db import IN_CHUNK
from sigharvest.models import Occurrence, Quarantine, Source, utcnow
from sigharvest.source_selection import path_selected
from sigharvest.sync import SyncResult, _diff_trees


def rebaseline(s: Session, source: Source, cfg: SourceConfig, result: SyncResult) -> bool:
    """Replace a full ingest with verified deltas, preserving full-scan provenance.

    The caller checks active-snapshot and policy markers. A complete captured
    inventory is mandatory; a remote-check result alone cannot acknowledge it.
    """
    if (
        not result.snapshot_id
        or result.file_hashes is None
        or source.last_commit is None
        or source.last_commit != result.new_commit
        or (source.type, source.url, source.ref) != (cfg.type, cfg.url, cfg.ref)
    ):
        return False
    before: dict[str, str] = {}
    uncertain: set[str] = set()
    for path, checksum, start, end in s.execute(
        select(Occurrence.path, Occurrence.file_hash, Occurrence.span_start, Occurrence.span_end).where(
            Occurrence.source_id == source.id, Occurrence.present.is_(True)
        )
    ):
        if (path in before and before[path] != checksum) or start is None or end is None:
            uncertain.add(path)
        before[path] = checksum
    if not before:
        return False
    for path in s.scalars(select(Quarantine.path).where(Quarantine.source_id == source.id, Quarantine.present.is_(True))):
        uncertain.add(path)
        before[path] = ""
    for path in uncertain:
        before[path] = ""
    after = {path: checksum for path, checksum in result.file_hashes.items() if path_selected(path, cfg)}
    # Include previously selected paths in removals even when filters narrowed.
    _diff_trees(before, after, result)
    reused = sorted(path for path in before.keys() & after.keys() if before[path] == after[path])
    now = utcnow()
    for offset in range(0, len(reused), IN_CHUNK):
        s.execute(
            update(Occurrence)
            .where(Occurrence.source_id == source.id, Occurrence.present.is_(True), Occurrence.path.in_(reused[offset : offset + IN_CHUNK]))
            .values(last_seen=now, commit=result.new_commit)
        )
    result.full_scan = False
    return True
