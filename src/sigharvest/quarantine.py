"""Bounded, private dead-letter storage and explicit parse/identity replay.

Blobs and attempts live in the workspace database so backups retain replay inputs.
Replay never republishes an old occurrence or changes a source checkpoint.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from sigharvest import documents
from sigharvest.errors import SigharvestError
from sigharvest.identity import sha256_hex
from sigharvest.models import Quarantine, QuarantineAttempt, QuarantineBlob, Source, utcnow
from sigharvest.space import Need, admit, database_path, setting

MAX_BLOB_BYTES = documents.MAX_FILE_BYTES
MAX_TOTAL_BYTES = 256 * 1024**2
MAX_ATTEMPTS = 100
DATA_ERRORS = (ValueError, TypeError, RecursionError, OverflowError)


class QuarantineError(SigharvestError):
    """A dead letter cannot be replayed with the requested inputs."""


def parser_version() -> str:
    """Only the installed parser is executable; record dependency and budget changes."""
    return (
        f"ingest-v2/pyyaml-{yaml.__version__}/depth-{documents.MAX_YAML_DEPTH}/nodes-{documents.MAX_YAML_NODES}"
        f"/file-{documents.MAX_FILE_BYTES}/effective-{documents.MAX_EFFECTIVE_FILE_BYTES}"
        f"/scalars-{documents.MAX_EXPANDED_SCALAR_BYTES}"
    )


def reason_code(error: str) -> str:
    if "limit" in error or "RecursionError" in error:
        return "resource_limit"
    if error.startswith("identity:"):
        return "identity_error"
    return "yaml_error"


def retain(s: Session, raw: bytes) -> tuple[str | None, str]:
    """Keep exact bytes within per-blob and aggregate limits, without automatic eviction."""
    digest = sha256_hex(raw)
    if s.get(QuarantineBlob, digest) is not None:
        return digest, "retained"
    if len(raw) > MAX_BLOB_BYTES:
        return None, "size_limit"
    limit = setting("QUARANTINE_BYTES", MAX_TOTAL_BYTES)
    if limit == 0:
        return None, "privacy_disabled"
    used = s.scalar(select(func.coalesce(func.sum(QuarantineBlob.size), 0))) or 0
    if used + len(raw) > limit:
        return None, "quota_limit"
    path = database_path(s, Path.cwd())
    admit([Need("dead-letter blob and WAL", path, 3 * len(raw))])
    s.add(QuarantineBlob(hash=digest, raw=raw, size=len(raw)))
    s.flush()
    return digest, "retained"


def record_failure(s: Session, source: Source, rel: str, doc: documents.Document, raw: bytes, commit: str | None) -> bool:
    """Deduplicate failures while preserving initial provenance and distinct parser/snapshot attempts."""
    digest, snapshot = sha256_hex(doc.raw), sha256_hex(raw)
    q = s.scalar(select(Quarantine).filter_by(source_id=source.id, path=rel, doc_index=doc.index, content_hash=digest))
    new = q is None
    code = reason_code(doc.error or "")
    # Parser diagnostics can contain YAML values. Persist a stable code, never arbitrary exception text.
    if q is None:
        blob, retention = retain(s, raw)
        start = doc.span_start
        q = Quarantine(
            source_id=source.id,
            path=rel,
            doc_index=doc.index,
            content_hash=digest,
            error=("identity: " if (doc.error or "").startswith("identity:") else "yaml: ") + code,
            reason_code=code,
            parser_version=parser_version(),
            snapshot_hash=snapshot,
            blob_hash=blob,
            source_commit=commit,
            span_start=start,
            span_end=start + len(doc.raw),
            retention=retention,
        )
        s.add(q)
        s.flush()
    q.present, q.seen_at, q.resolution, q.resolved_at = True, utcnow(), None, None
    q.last_rejected_snapshot = snapshot
    if "quarantine_skipped" in doc.flags:
        return new
    exists = s.scalar(
        select(QuarantineAttempt.id)
        .where(
            QuarantineAttempt.quarantine_id == q.id,
            QuarantineAttempt.snapshot_hash == snapshot,
            QuarantineAttempt.parser_version == parser_version(),
            QuarantineAttempt.outcome == "rejected",
        )
        .limit(1)
    )
    if exists is None:
        count = s.scalar(select(func.count()).select_from(QuarantineAttempt).where(QuarantineAttempt.quarantine_id == q.id)) or 0
        if count < MAX_ATTEMPTS:
            blob, _ = retain(s, raw)
            s.add(
                QuarantineAttempt(
                    quarantine_id=q.id, parser_version=parser_version(), snapshot_hash=snapshot, blob_hash=blob, outcome="rejected", reason_code=code
                )
            )
    return new


def rejected_documents(s: Session, source_id: int, rel: str, raw: bytes) -> dict[int, str]:
    """Unchanged poison is skipped during scheduled ingestion, including after parser upgrades.

    Only explicit replay may retry bytes previously rejected in this exact file context.
    """
    digest = sha256_hex(raw)
    attempts = select(QuarantineAttempt.quarantine_id).where(QuarantineAttempt.snapshot_hash == digest, QuarantineAttempt.outcome == "rejected")
    rows = s.execute(
        select(Quarantine.doc_index, Quarantine.error).where(
            Quarantine.source_id == source_id,
            Quarantine.path == rel,
            Quarantine.resolution.is_(None),
            (Quarantine.last_rejected_snapshot == digest) | Quarantine.id.in_(attempts),
        )
    )
    return {index: error for index, error in rows}


def get_letter(s: Session, letter_id: int) -> Quarantine:
    row = s.get(Quarantine, letter_id)
    if row is None:
        raise QuarantineError("Unknown quarantine id")
    return row


def retry(s: Session, letter_id: int, *, parser: str, snapshot: str | None = None) -> QuarantineAttempt:
    """Replay a retained full-file snapshot and record one transaction; caller commits.

    A selected snapshot must already belong to this source/path's quarantine history.
    Successful identity creates a version but never resurrects a removed occurrence.
    """
    from sigharvest.ingest import Ingestor

    q = get_letter(s, letter_id)
    if parser not in ("current", parser_version()):
        raise QuarantineError("Parser unavailable; use 'current' or the installed fingerprint shown by quarantine show")
    count = s.scalar(select(func.count()).select_from(QuarantineAttempt).where(QuarantineAttempt.quarantine_id == q.id)) or 0
    if count >= MAX_ATTEMPTS:
        raise QuarantineError("Attempt limit reached (100); retain history and repair the upstream source")
    digest = snapshot or q.blob_hash
    allowed = (
        s.scalar(
            select(QuarantineAttempt.id)
            .join(Quarantine)
            .where(
                Quarantine.source_id == q.source_id,
                Quarantine.path == q.path,
                QuarantineAttempt.blob_hash == digest,
            )
            .limit(1)
        )
        if digest
        else None
    )
    blob = s.get(QuarantineBlob, digest) if digest and (digest == q.blob_hash or allowed) else None
    if blob is None:
        raise QuarantineError("Snapshot unavailable for this source/path; repair and rescan the source")
    if len(blob.raw) > MAX_BLOB_BYTES or sha256_hex(blob.raw) != blob.hash:
        raise QuarantineError("Retained snapshot failed size/checksum verification")
    source = s.get(Source, q.source_id)
    if source is None:
        raise QuarantineError("Source metadata unavailable")
    doc = next((d for d in documents.load_documents(blob.raw) if d.index == q.doc_index), None)
    outcome, code, version_id = "rejected", "document_missing", None
    if doc is not None:
        if doc.error:
            code = reason_code(doc.error)
        elif doc.kind is None:
            outcome, code = "not_sigma", "not_sigma"
        else:
            try:
                version = Ingestor(s, source, q.source_commit)._upsert_version(doc, q.path)
            except DATA_ERRORS as exc:
                code = reason_code(f"identity: {type(exc).__name__}")
            else:
                outcome, code, version_id = "recovered", "ok", version.id
    attempt = QuarantineAttempt(
        quarantine_id=q.id,
        parser_version=parser_version(),
        snapshot_hash=blob.hash,
        blob_hash=blob.hash,
        outcome=outcome,
        reason_code=code,
        version_id=version_id,
    )
    s.add(attempt)
    if outcome != "rejected":
        q.resolution, q.resolved_at = outcome, utcnow()
    s.flush()
    return attempt


def metadata(s: Session, q: Quarantine, *, detail: bool = False) -> dict[str, Any]:
    """Metadata-only output: raw bytes and parser diagnostics never enter reports."""
    data: dict[str, Any] = {
        "id": q.id,
        "source_id": q.source_id,
        "doc_index": q.doc_index,
        "content_hash": q.content_hash,
        "snapshot_hash": q.snapshot_hash,
        "last_rejected_snapshot": q.last_rejected_snapshot,
        "blob_hash": q.blob_hash,
        "span": [q.span_start, q.span_end],
        "reason_code": q.reason_code,
        "reason_version": q.reason_version,
        "parser_version": q.parser_version,
        "installed_parser": parser_version(),
        "retention": q.retention,
        "present": q.present,
        "resolution": q.resolution,
        "resolved_at": str(q.resolved_at) if q.resolved_at else None,
    }
    if detail:
        data["attempts"] = [
            {
                "id": a.id,
                "parser_version": a.parser_version,
                "snapshot_hash": a.snapshot_hash,
                "outcome": a.outcome,
                "reason_code": a.reason_code,
                "version_id": a.version_id,
                "created_at": str(a.created_at),
            }
            for a in s.scalars(select(QuarantineAttempt).where(QuarantineAttempt.quarantine_id == q.id).order_by(QuarantineAttempt.id))
        ]
    return data
