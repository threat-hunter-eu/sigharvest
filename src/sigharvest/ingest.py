"""Turn synced files into rule versions and occurrences. Data errors go to quarantine; infrastructure failures propagate."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from sqlalchemy import bindparam, insert, select, update
from sqlalchemy.orm import Session

from sigharvest.db import IN_CHUNK
from sigharvest.documents import MAX_FILE_BYTES, Document, load_documents, looks_like_sigma
from sigharvest.identity import logic_hash, resolve_rule_id, sha256_hex, title_slug
from sigharvest.licensing import spdx_header, stricter
from sigharvest.models import Occurrence, Quarantine, RuleVersion, Source, utcnow
from sigharvest.normalize import logsource
from sigharvest.quarantine import DATA_ERRORS, record_failure, rejected_documents
from sigharvest.source_selection import storable_path

PLACEHOLDER_HINT = "|expand"
BATCH_ROWS = 1000  # new occurrences written per executemany in batch mode
_PROJECTIONS = ("product", "category", "service", "flags")
_VERSION = (
    RuleVersion.id,
    RuleVersion.logic_hash,
    RuleVersion.rule_id,
    RuleVersion.id_flag,
    RuleVersion.product,
    RuleVersion.category,
    RuleVersion.service,
    RuleVersion.flags,
)
_OCCURRENCE = (
    Occurrence.id,
    Occurrence.doc_index,
    Occurrence.version_id,
    Occurrence.present,
    Occurrence.file_hash,
    Occurrence.commit,
    Occurrence.span_start,
    Occurrence.span_end,
)
# Built once: per-file statements otherwise spend more time in SQLAlchemy statement
# construction and cache-key generation than in SQLite.
_SELECT_OCCURRENCES = select(*_OCCURRENCE).where(Occurrence.source_id == bindparam("source"), Occurrence.path == bindparam("rel"))
_SELECT_VERSION = select(*_VERSION).where(RuleVersion.content_hash == bindparam("content"))
_INSERT_OCCURRENCE = insert(Occurrence)
_INSERT_VERSION = insert(RuleVersion)
_UPDATE_OCCURRENCE = update(Occurrence).where(Occurrence.id == bindparam("occurrence"))
_RETIRE_OCCURRENCES = update(Occurrence).where(Occurrence.id.in_(bindparam("ids", expanding=True))).values(present=False)


@dataclass
class IngestStats:
    """Counters for one source's ingest, shown after a sync."""

    files_seen: int = 0
    files_sigma: int = 0
    documents: int = 0
    versions_new: int = 0
    rules_new: int = 0
    quarantined: int = 0


# C0/C1 controls (not tab or newline): a YAML "\e[31m" or "\e]8;;" in a title would reach the terminal through the CLI.
_CONTROLS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _as_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return _CONTROLS.sub("\ufffd", ", ".join(str(v) for v in value))
    return _CONTROLS.sub("\ufffd", str(value))


def _flags_for(doc: Document, rel: str, id_flag: str | None) -> list[str]:
    flags = list(doc.flags)
    if id_flag:
        flags.append(id_flag)
    data = doc.data
    status = str(data.get("status", "")).lower()
    low = "/" + rel.lower()
    if status == "deprecated" or "/deprecated/" in low:
        flags.append("deprecated")
    if status == "unsupported" or "/unsupported/" in low:
        flags.append("unsupported")
    if "/rules-placeholder/" in low or PLACEHOLDER_HINT in str(data.get("detection", "")):
        flags.append("placeholder")
    return sorted(set(flags))


def _version_fields(doc: Document, ch: str, lh: str, rid: str, flags: list[str], id_flag: str | None) -> dict[str, Any]:
    d = doc.data
    ls = d.get("logsource") if isinstance(d.get("logsource"), dict) else {}
    tags = d.get("tags") if isinstance(d.get("tags"), list) else []
    original = tuple(_as_text(ls.get(key)) for key in ("product", "category", "service"))
    normalized = logsource(*original)
    # Original/effective YAML and identity stay byte-for-byte intact. These flags
    # identify the changed projections; raw logsource values supply their provenance.
    normalization_flags = [
        "logsource_normalized:v1:" + key for key, before, after in zip(("product", "category", "service"), original, normalized, strict=True) if before != after
    ]
    return {
        "content_hash": ch,
        "logic_hash": lh,
        "rule_id": rid,
        "id_flag": id_flag,
        "kind": doc.kind,
        "title": _as_text(d.get("title")),
        "title_slug": title_slug(d.get("title"))[:300],
        "status": (_as_text(d.get("status")) or "").lower()[:20] or None,
        "level": (_as_text(d.get("level")) or "").lower()[:20] or None,
        "author": _as_text(d.get("author")),
        "date": (_as_text(d.get("date")) or "")[:20] or None,
        "modified": (_as_text(d.get("modified")) or "")[:20] or None,
        # The rule's own licence: its `license:` field or a `# SPDX-License-Identifier:` header in the document
        # (a relicensed repository often changes only the headers), the stricter of the two. Only ever narrows.
        "rule_license": (stricter(_as_text(d.get("license")), spdx_header(doc.raw.decode("utf-8", errors="replace"))) or "")[:100] or None,
        "product": (normalized[0] or "")[:100] or None,
        "category": (normalized[1] or "")[:100] or None,
        "service": (normalized[2] or "")[:100] or None,
        "tags": [str(t).lower() for t in tags],
        "flags": sorted(set(flags + normalization_flags)),
        "raw": doc.rule_yaml,
        "original_raw": doc.raw,
        "context_digest": doc.context_digest,
    }


class Ingestor:
    """Ingests the files of one source: new versions, occurrences, quarantine. Never raises on bad input."""

    def __init__(self, session: Session, source: Source, commit: str | None, *, batch: bool = False) -> None:
        """`batch=True` (the caller must call flush()): a source with no stored occurrences yet (its first ingest,
        init --from-release) skips the per-file occurrence lookup and writes new occurrences in batches."""
        self.s = session
        self.batch = batch
        self._fresh: bool | None = None  # no occurrence of this source in the database (batch mode only)
        self._pending: list[dict[str, Any]] = []
        self._pending_paths: set[str] = set()
        self._versions: dict[str, Any] | None = None
        self.source = source
        self.commit = commit
        self.stats = IngestStats()
        self.expected_hashes: dict[str, str] | None = None
        # Loaded on the first new version only: an unchanged source then costs no query at all (about 0.15 s each on
        # a 185k-version corpus, times 1,200 sources per update).
        self._known: set[str] | None = None
        self._quarantine_paths: set[str] | None = None

    def _has_quarantine(self, rel: str) -> bool:
        """One indexed source lookup replaces three empty quarantine queries per file."""
        if self._quarantine_paths is None:
            self._quarantine_paths = set(self.s.scalars(select(Quarantine.path).where(Quarantine.source_id == self.source.id).distinct()))
        return rel in self._quarantine_paths

    def _clear_occurrences(self, rel: str) -> None:
        stmt = update(Occurrence).where(Occurrence.source_id == self.source.id, Occurrence.path == rel, Occurrence.present.is_(True))
        self.s.execute(stmt.values(present=False))

    def _clear_quarantine(self, rel: str, resolution: str = "superseded") -> None:
        if not self._has_quarantine(rel):
            return
        self.s.execute(
            update(Quarantine)
            .where(
                Quarantine.source_id == self.source.id,
                Quarantine.path == rel,
                Quarantine.present.is_(True),
                Quarantine.resolution.is_(None),
            )
            .values(present=False, resolution=resolution, resolved_at=utcnow())
        )
        self.s.execute(update(Quarantine).where(Quarantine.source_id == self.source.id, Quarantine.path == rel).values(present=False))

    def _clear_path(self, rel: str) -> None:
        self._clear_occurrences(rel)
        self._clear_quarantine(rel, "removed")

    def remove(self, rel: str) -> None:
        """Mark everything found at this path as no longer present."""
        self.flush()
        self._clear_path(storable_path(rel))

    def flush(self) -> None:
        """Write the buffered new occurrences (one executemany); a no-op outside batch mode."""
        if self._pending:
            self._execute(_INSERT_OCCURRENCE, self._pending)  # type: ignore[arg-type]
            self._pending = []
            self._pending_paths = set()

    def _known_versions(self) -> dict[str, Any]:
        """Batch mode: every stored version by content hash, loaded once (one query instead of one per document;
        a first ingest of 19k rules spent most of its time in those lookups)."""
        if self._versions is None:
            rows = self._execute(select(RuleVersion.content_hash, *_VERSION))
            self._versions = {row.content_hash: row for row in rows}
        return self._versions

    def _is_fresh(self, rel: str) -> bool:
        """Batch mode and nothing stored for this source yet, and `rel` not already buffered in this run."""
        if not self.batch:
            return False
        if self._fresh is None:
            self._fresh = self.s.scalar(select(Occurrence.id).where(Occurrence.source_id == self.source.id).limit(1)) is None
        if self._fresh and rel in self._pending_paths:
            self.flush()  # the same path twice: look its first occurrences up as usual
            self._fresh = False
        return self._fresh

    def reconcile_paths(self, present: set[str]) -> set[str]:
        """Retire absent paths after a successful full scan, retaining all history.

        Run only after every selected file was ingested. Chunk updates to stay below
        SQLite parameter limits even when a repository loses thousands of files.
        """
        self.flush()
        missing: set[str] = set()
        present = {storable_path(p) for p in present}
        for model in (Occurrence, Quarantine):
            paths = set(self.s.scalars(select(model.path).where(model.source_id == self.source.id, model.present.is_(True)).distinct()))
            absent = sorted(paths - present)
            missing.update(absent)
            for i in range(0, len(absent), IN_CHUNK):
                chunk = absent[i : i + IN_CHUNK]
                if model is Quarantine:
                    self.s.execute(
                        update(Quarantine)
                        .where(
                            Quarantine.source_id == self.source.id,
                            Quarantine.path.in_(chunk),
                            Quarantine.resolution.is_(None),
                        )
                        .values(resolution="removed", resolved_at=utcnow())
                    )
                self.s.execute(update(model).where(model.source_id == self.source.id, model.path.in_(chunk)).values(present=False))
        return missing

    def ingest_file(self, root: Path, rel: str) -> None:
        """Read one file and record its Sigma documents (or quarantine the broken ones)."""
        self.stats.files_seen += 1
        path = root / rel
        # Read with the real name; store and compare the storable one (see source_selection.storable_path).
        name, rel = rel, storable_path(rel)
        file_hash = None
        if self.expected_hashes is not None:
            from sigharvest.source_snapshots import read_regular
            from sigharvest.sync import SyncError

            raw = read_regular(path, MAX_FILE_BYTES)
            file_hash = sha256_hex(raw)
            if file_hash != self.expected_hashes.get(name):
                raise SyncError("source snapshot blob checksum mismatch during ingest")
        else:
            if not path.is_file():
                self._clear_path(rel)
                return
            with path.open("rb") as handle:
                raw = handle.read(MAX_FILE_BYTES + 1)
            if len(raw) > MAX_FILE_BYTES:
                raise ValueError("source file exceeds ingestion size limit")
        if not looks_like_sigma(raw):
            self._clear_path(rel)
            return
        file_hash = file_hash or sha256_hex(raw)
        rejected = rejected_documents(self.s, self.source.id, rel, raw) if self._has_quarantine(rel) else None
        docs = load_documents(raw, rejected=rejected)
        self._clear_quarantine(rel)
        # Reactivate exact (path, document index, version) occurrences below and retire
        # the other present ones afterwards. Keeping only version ids leaves stale
        # positions when documents move or disappear. Unchanged occurrences are not
        # flipped off and on, so they do not mark their logic hash for reindexing.
        fresh = self._is_fresh(rel)
        existing = {} if fresh else self._path_occurrences(rel)
        kept: set[int] = set()
        any_sigma = False
        for doc in docs:
            if doc.error:
                # Only quarantine YAML errors in files that look like Sigma (pre-filter above).
                self.stats.quarantined += record_failure(self.s, self.source, rel, doc, raw, self.commit)
                assert self._quarantine_paths is not None
                self._quarantine_paths.add(rel)
                any_sigma = True
                continue
            if doc.kind is None:
                continue
            any_sigma = True
            try:
                version_id = self._version_id(doc, rel)
            except DATA_ERRORS as exc:
                doc.error = f"identity: {type(exc).__name__}"
                self.stats.quarantined += record_failure(self.s, self.source, rel, doc, raw, self.commit)
                assert self._quarantine_paths is not None
                self._quarantine_paths.add(rel)
                continue
            if fresh:
                self._buffer_occurrence(version_id, rel, doc.index, file_hash, doc.span_start, doc.span_start + len(doc.raw))
                continue
            kept.add(self._put_occurrence(existing, version_id, rel, doc.index, file_hash, doc.span_start, doc.span_start + len(doc.raw)))
        retired = sorted(row.id for row in existing.values() if row.present and row.id not in kept)
        for offset in range(0, len(retired), IN_CHUNK):
            self._execute(_RETIRE_OCCURRENCES, {"ids": retired[offset : offset + IN_CHUNK]})
        if any_sigma:
            self.stats.files_sigma += 1

    def _execute(self, statement: Any, params: dict[str, Any] | None = None) -> Any:
        """Core statements on the session's connection: no autoflush, no identity-map scan.

        Occurrences are never loaded as ORM objects here, so nothing in the session can
        go stale. Pending ORM rows (new versions, quarantine) are flushed where added.
        """
        return self.s.connection().execute(statement, params)

    def _path_occurrences(self, rel: str) -> dict[tuple[int, int], Any]:
        rows = self._execute(_SELECT_OCCURRENCES, {"source": self.source.id, "rel": rel})
        return {(row.doc_index, row.version_id): row for row in rows}

    def _upsert_version(self, doc: Document, rel: str) -> RuleVersion:
        version = self.s.get(RuleVersion, self._version_id(doc, rel))
        assert version is not None
        return version

    def _version_id(self, doc: Document, rel: str) -> int:
        self.stats.documents += 1
        ch = doc.identity_hash
        if self._fresh:
            row = self._known_versions().get(ch)  # no ORM flush per document: versions are Core inserts
        else:
            self.s.flush()  # pending ORM rows reach the database before the lookup
            row = self._execute(_SELECT_VERSION, {"content": ch}).first()
        if row is not None:
            projections = _version_fields(doc, ch, row.logic_hash, row.rule_id, row.flags, row.id_flag)
            changes = {name: projections[name] for name in _PROJECTIONS if projections[name] != getattr(row, name)}
            if changes:
                # Rare (normalization changed): keep loaded objects in sync.
                self.s.execute(update(RuleVersion).where(RuleVersion.id == row.id).values(**changes))
            return int(row.id)
        lh = logic_hash(doc.data)
        rid, id_flag = resolve_rule_id(doc.data, lh)
        flags = _flags_for(doc, rel, id_flag)
        # A Core insert: an ORM object per new version cost a unit-of-work flush each (most of a first ingest).
        fields = _version_fields(doc, ch, lh, rid, flags, id_flag)
        version_id = int(self._execute(_INSERT_VERSION, fields).inserted_primary_key[0])
        if self._fresh:
            self._known_versions()[ch] = SimpleNamespace(id=version_id, **{k: fields[k] for k in ("logic_hash", "rule_id", "id_flag", *_PROJECTIONS)})
        self.stats.versions_new += 1
        if self._known is None:
            self._known = set(self.s.scalars(select(RuleVersion.rule_id).where(RuleVersion.id != version_id).distinct()))
        if rid not in self._known:
            self._known.add(rid)
            self.stats.rules_new += 1
        return version_id

    def _buffer_occurrence(self, version_id: int, rel: str, idx: int, file_hash: str, span_start: int, span_end: int) -> None:
        now = utcnow()
        self._pending_paths.add(rel)
        self._pending.append(
            {
                "version_id": version_id,
                "source_id": self.source.id,
                "path": rel,
                "doc_index": idx,
                "file_hash": file_hash,
                "span_start": span_start,
                "span_end": span_end,
                "commit": self.commit,
                "present": True,
                "first_seen": now,
                "last_seen": now,
            }
        )
        if len(self._pending) >= BATCH_ROWS:
            self.flush()

    def _put_occurrence(self, existing: dict[tuple[int, int], Any], version_id: int, rel: str, idx: int, file_hash: str, span_start: int, span_end: int) -> int:
        """Reactivate or insert one occurrence; returns its id. Unchanged columns are not written."""
        now = utcnow()
        row = existing.get((idx, version_id))
        if row is None:
            result = self._execute(
                _INSERT_OCCURRENCE,
                {
                    "version_id": version_id,
                    "source_id": self.source.id,
                    "path": rel,
                    "doc_index": idx,
                    "file_hash": file_hash,
                    "span_start": span_start,
                    "span_end": span_end,
                    "commit": self.commit,
                    "present": True,
                    "first_seen": now,
                    "last_seen": now,
                },
            )
            return int(result.inserted_primary_key[0])
        wanted = {"present": True, "file_hash": file_hash, "commit": self.commit, "span_start": span_start, "span_end": span_end}
        values: dict[str, Any] = {name: value for name, value in wanted.items() if getattr(row, name) != value}
        values["last_seen"] = now
        self._execute(_UPDATE_OCCURRENCE, {"occurrence": row.id, **values})
        return int(row.id)
