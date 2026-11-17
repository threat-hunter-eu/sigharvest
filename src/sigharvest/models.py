"""SQLAlchemy models. The schema is versioned with Alembic (see migrations/)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    """Current UTC time without tzinfo (SQLite stores naive datetimes)."""
    return datetime.now(UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, list[Any]: JSON}


class Source(Base):
    """A rule source, mirrored from sources.yaml; keeps the last synced commit."""

    __tablename__ = "sources"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    type: Mapped[str] = mapped_column(String(10))
    url: Mapped[str] = mapped_column(Text)
    ref: Mapped[str | None] = mapped_column(String(200))
    licence: Mapped[str | None] = mapped_column(String(100))
    priority: Mapped[int] = mapped_column(Integer, default=50)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_commit: Mapped[str | None] = mapped_column(String(64))
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime)


class SyncLog(Base):
    """One sync attempt of one source: commits, file and rule counts, status and error."""

    __tablename__ = "sync_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"))
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    old_commit: Mapped[str | None] = mapped_column(String(64))
    new_commit: Mapped[str | None] = mapped_column(String(64))
    files_added: Mapped[int] = mapped_column(Integer, default=0)
    files_changed: Mapped[int] = mapped_column(Integer, default=0)
    files_removed: Mapped[int] = mapped_column(Integer, default=0)
    rules_new: Mapped[int] = mapped_column(Integer, default=0)
    versions_new: Mapped[int] = mapped_column(Integer, default=0)
    quarantined: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="running")
    error: Mapped[str | None] = mapped_column(Text)


class RuleVersion(Base):
    """One distinct document content (content_hash). A rule_id can have many versions."""

    __tablename__ = "rule_versions"
    id: Mapped[int] = mapped_column(primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64), unique=True)
    logic_hash: Mapped[str] = mapped_column(String(64), index=True)
    # Semantic hash (semantic.py): "" when pySigma cannot parse the rule, NULL when not computed yet.
    semantic_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    semantic_fingerprint: Mapped[str | None] = mapped_column(String(64))
    rule_id: Mapped[str] = mapped_column(String(36), index=True)
    id_flag: Mapped[str | None] = mapped_column(String(20))
    kind: Mapped[str] = mapped_column(String(12))
    title: Mapped[str | None] = mapped_column(Text)
    title_slug: Mapped[str | None] = mapped_column(String(300), index=True)
    status: Mapped[str | None] = mapped_column(String(20))
    level: Mapped[str | None] = mapped_column(String(20))
    author: Mapped[str | None] = mapped_column(Text)
    date: Mapped[str | None] = mapped_column(String(20))
    modified: Mapped[str | None] = mapped_column(String(20))
    rule_license: Mapped[str | None] = mapped_column(String(100))
    product: Mapped[str | None] = mapped_column(String(100), index=True)
    category: Mapped[str | None] = mapped_column(String(100), index=True)
    service: Mapped[str | None] = mapped_column(String(100), index=True)
    tags: Mapped[list[Any]] = mapped_column(JSON, default=list)
    flags: Mapped[list[Any]] = mapped_column(JSON, default=list)
    raw: Mapped[str] = mapped_column(Text)
    # Standalone effective YAML is in raw for all existing execution consumers.
    # Original upstream bytes are never reconstructed from that serialization.
    original_raw: Mapped[bytes | None] = mapped_column(LargeBinary)
    context_digest: Mapped[str | None] = mapped_column(String(64))
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    occurrences: Mapped[list[Occurrence]] = relationship(back_populates="version")


class SemanticResult(Base):
    """Resumable semantic generations, including cached parse failures (empty hash)."""

    __tablename__ = "semantic_results"
    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    version_id: Mapped[int] = mapped_column(ForeignKey("rule_versions.id"), primary_key=True)
    semantic_hash: Mapped[str] = mapped_column(String(64))


class CorrelationReference(Base):
    """Disposable exact parsed aliases; live occurrence scope stays authoritative."""

    __tablename__ = "correlation_references"
    __table_args__ = (Index("ix_correlation_references_content", "content_hash"),)
    name: Mapped[str] = mapped_column(String(256), primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    logic_hash: Mapped[str] = mapped_column(String(64))


class CorrelationReferenceDirty(Base):
    """Coalesced exact-document changes, committed with corpus mutations."""

    __tablename__ = "correlation_reference_dirty"
    content_hash: Mapped[str] = mapped_column(String(64), primary_key=True)


class CorrelationReferenceState(Base):
    """One atomic publication receipt; tokens detect stale input and lost rows."""

    __tablename__ = "correlation_reference_state"
    id: Mapped[int] = mapped_column(primary_key=True)
    fingerprint: Mapped[str | None] = mapped_column(String(64))
    input_token: Mapped[str] = mapped_column(String(32))
    built_input: Mapped[str | None] = mapped_column(String(32))
    projection_token: Mapped[str] = mapped_column(String(32))
    built_projection: Mapped[str | None] = mapped_column(String(32))


class Occurrence(Base):
    """Where a version lives: source + path + document index. present=False once the file disappears."""

    __tablename__ = "occurrences"
    __table_args__ = (
        UniqueConstraint("source_id", "path", "doc_index", "version_id"),
        Index("ix_occurrences_source_path", "source_id", "path", "present"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    version_id: Mapped[int] = mapped_column(ForeignKey("rule_versions.id"), index=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"), index=True)
    path: Mapped[str] = mapped_column(Text)
    doc_index: Mapped[int] = mapped_column(Integer, default=0)
    file_hash: Mapped[str] = mapped_column(String(64))
    span_start: Mapped[int | None] = mapped_column(Integer)
    span_end: Mapped[int | None] = mapped_column(Integer)
    commit: Mapped[str | None] = mapped_column(String(64))
    present: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    version: Mapped[RuleVersion] = relationship(back_populates="occurrences")


class Quarantine(Base):
    """A document that looked like Sigma but could not be parsed or identified."""

    __tablename__ = "quarantine"
    __table_args__ = (UniqueConstraint("source_id", "path", "doc_index", "content_hash"), Index("ix_quarantine_source_path", "source_id", "path"))
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"), index=True)
    path: Mapped[str] = mapped_column(Text)
    doc_index: Mapped[int] = mapped_column(Integer, default=0)
    content_hash: Mapped[str] = mapped_column(String(64))
    error: Mapped[str] = mapped_column(Text)
    present: Mapped[bool] = mapped_column(Boolean, default=True)
    seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    reason_code: Mapped[str] = mapped_column(String(32), default="legacy")
    reason_version: Mapped[int] = mapped_column(Integer, default=1)
    parser_version: Mapped[str | None] = mapped_column(String(100))
    snapshot_hash: Mapped[str | None] = mapped_column(String(64))
    blob_hash: Mapped[str | None] = mapped_column(ForeignKey("quarantine_blobs.hash"))
    source_commit: Mapped[str | None] = mapped_column(String(64))
    span_start: Mapped[int | None] = mapped_column(Integer)
    span_end: Mapped[int | None] = mapped_column(Integer)
    retention: Mapped[str] = mapped_column(String(32), default="legacy_unavailable")
    last_rejected_snapshot: Mapped[str | None] = mapped_column(String(64))
    resolution: Mapped[str | None] = mapped_column(String(32))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)


class QuarantineBlob(Base):
    """Immutable bounded source bytes, shared by dead letters from one snapshot."""

    __tablename__ = "quarantine_blobs"
    hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    raw: Mapped[bytes] = mapped_column(LargeBinary)
    size: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class QuarantineAttempt(Base):
    """Append-only parse/identity outcomes; infrastructure failures roll back."""

    __tablename__ = "quarantine_attempts"
    __table_args__ = (Index("ix_quarantine_attempts_snapshot", "snapshot_hash", "outcome", "quarantine_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    quarantine_id: Mapped[int] = mapped_column(ForeignKey("quarantine.id"), index=True)
    parser_version: Mapped[str] = mapped_column(String(100))
    snapshot_hash: Mapped[str | None] = mapped_column(String(64))
    blob_hash: Mapped[str | None] = mapped_column(ForeignKey("quarantine_blobs.hash"))
    outcome: Mapped[str] = mapped_column(String(32))
    reason_code: Mapped[str] = mapped_column(String(32))
    version_id: Mapped[int | None] = mapped_column(ForeignKey("rule_versions.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class TestRun(Base):
    """One run of a test stage, with its parameters and timing."""

    __tablename__ = "test_runs"
    __test__ = False
    id: Mapped[int] = mapped_column(primary_key=True)
    stage: Mapped[str] = mapped_column(String(20))
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(20), default="running")


class TestResult(Base):
    """Result of one stage for one rule version and one target (validator set, backend, engine+dataset)."""

    __tablename__ = "test_results"
    __test__ = False
    __table_args__ = (
        UniqueConstraint("version_id", "stage", "target", "dataset"),
        Index("ix_results_stage_target", "stage", "target"),
        Index(
            "ix_telemetry_conversion_current",
            "version_id",
            "target",
            text("json_extract(detail, '$.toolchain')"),
            sqlite_where=text("stage='convert' AND dataset='' AND status IN ('ok','partial','warning')"),
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    version_id: Mapped[int] = mapped_column(ForeignKey("rule_versions.id"), index=True)
    stage: Mapped[str] = mapped_column(String(20))
    target: Mapped[str] = mapped_column(String(60))
    dataset: Mapped[str] = mapped_column(String(100), default="")
    status: Mapped[str] = mapped_column(String(20))
    hits: Mapped[int | None] = mapped_column(Integer)
    duration: Mapped[float | None] = mapped_column(Float)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    fingerprint: Mapped[str | None] = mapped_column(String(64))
    run_id: Mapped[int | None] = mapped_column(ForeignKey("test_runs.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class TestResultHistory(Base):
    """Bounded previous test projections retained only when their status changes."""

    __tablename__ = "test_result_history"
    __test__ = False
    id: Mapped[int] = mapped_column(primary_key=True)
    result_id: Mapped[int] = mapped_column(ForeignKey("test_results.id"), index=True)
    fingerprint: Mapped[str | None] = mapped_column(String(64))
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)


class LogicGroup(Base):
    """One row per unique logic hash among live versions: the canonical copy and summary data for search.

    Rebuilt by `sigharvest index` (and at the end of `sigharvest sync`). The full-text index `rules_fts` (FTS5, created in
    migration 0003) has one row per group, keyed by rowid = LogicGroup.id.
    """

    __tablename__ = "logic_groups"
    id: Mapped[int] = mapped_column(primary_key=True)
    logic_hash: Mapped[str] = mapped_column(String(64), unique=True)
    # Family: groups linked by a shared real UUID or a shared logic hash (union-find); id = smallest member group id.
    family_id: Mapped[int] = mapped_column(Integer, default=0, index=True)
    family_size: Mapped[int] = mapped_column(Integer, default=1)
    canonical_version_id: Mapped[int] = mapped_column(ForeignKey("rule_versions.id"))
    canonical_source: Mapped[str] = mapped_column(String(200))
    rule_id: Mapped[str] = mapped_column(String(36), index=True)
    kind: Mapped[str] = mapped_column(String(12))
    title: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(String(100), index=True)
    category: Mapped[str | None] = mapped_column(String(100), index=True)
    service: Mapped[str | None] = mapped_column(String(100), index=True)
    level: Mapped[str | None] = mapped_column(String(20), index=True)
    status: Mapped[str | None] = mapped_column(String(20), index=True)
    author: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list[Any]] = mapped_column(JSON, default=list)
    datasources: Mapped[list[str]] = mapped_column(JSON, default=list, server_default="[]")
    fields: Mapped[list[Any]] = mapped_column(JSON, default=list)
    copies: Mapped[int] = mapped_column(Integer, default=1)
    sources: Mapped[list[Any]] = mapped_column(JSON, default=list)
    n_sources: Mapped[int] = mapped_column(Integer, default=1, index=True)
    # Sources after collapsing mirrors to the repository they copy (index.source_roots).
    n_independent: Mapped[int] = mapped_column(Integer, default=1, index=True)
    n_rule_ids: Mapped[int] = mapped_column(Integer, default=1)
    validation: Mapped[str | None] = mapped_column(String(20), index=True)
    converts: Mapped[list[Any]] = mapped_column(JSON, default=list)  # targets with status ok (mapped), see conversion.py
    # Convert status per target (ok / warning / raw / unsupported / error ...); NULL in indexes built before 0011.
    conversion: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    modified: Mapped[str | None] = mapped_column(String(20))
    # Quality flags (quality.py); junk = any flag in quality.JUNK (hidden by default).
    quality_flags: Mapped[list[Any]] = mapped_column(JSON, default=list)
    junk: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


class SourceOverlap(Base):
    """Directed overlap counts, rebuilt with the search index."""

    __tablename__ = "source_overlaps"
    name: Mapped[str] = mapped_column(String(200), primary_key=True)
    other: Mapped[str] = mapped_column(String(200), primary_key=True)
    exact: Mapped[int] = mapped_column(Integer)
    near: Mapped[int] = mapped_column(Integer)
    __table_args__ = (Index("ix_source_overlaps_rank", "name", "exact", "near"),)


class SourceSummary(Base):
    """Repository contribution and quality at the last index rebuild."""

    __tablename__ = "source_summaries"
    name: Mapped[str] = mapped_column(String(200), primary_key=True)
    documents: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    logic: Mapped[int] = mapped_column(Integer)
    families: Mapped[int] = mapped_column(Integer)
    only: Mapped[int] = mapped_column(Integer)
    valid_pct: Mapped[int | None] = mapped_column(Integer)
    avg_score: Mapped[int] = mapped_column(Integer)


class Collection(Base):
    """A named, saved set of rules (see collections.py). Survives index rebuilds and syncs."""

    __tablename__ = "collections"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    @property
    def display_description(self) -> str:
        return self.description or ""


class CollectionItem(Base):
    """One rule of a collection, by logic hash (no foreign key: logic_groups is rebuilt) and real rule id, if any."""

    __tablename__ = "collection_items"
    __table_args__ = (UniqueConstraint("collection_id", "logic_hash"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    collection_id: Mapped[int] = mapped_column(ForeignKey("collections.id"), index=True)
    logic_hash: Mapped[str] = mapped_column(String(64), index=True)
    rule_id: Mapped[str | None] = mapped_column(String(36), index=True)
    title: Mapped[str | None] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(Text)
    added_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class SourceRoot(Base):
    """Derived at index time: a source that mostly copies another one (a mirror or fork) points to it."""

    __tablename__ = "source_roots"
    name: Mapped[str] = mapped_column(String(200), primary_key=True)
    root: Mapped[str] = mapped_column(String(200))
    parent: Mapped[str | None] = mapped_column(String(200))
    containment: Mapped[float] = mapped_column(Float, default=0.0)  # share of its logic also found in the parent
    logic: Mapped[int] = mapped_column(Integer, default=0)


class NearDuplicate(Base):
    """Derived at index time (neardup.py): two rules in different families with nearly the same detection."""

    __tablename__ = "near_duplicates"
    a: Mapped[str] = mapped_column(String(64), primary_key=True)
    b: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    jaccard: Mapped[float] = mapped_column(Float)


class Meta(Base):
    """Small workspace facts that belong to no other table, as key/value text (for example `index_built_at`)."""

    __tablename__ = "meta"
    key: Mapped[str] = mapped_column(String(60), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class UpdateRun(Base):
    """One `sigharvest update` (runs.py): timing per step, corpus counts at the end, gate results and the report path.

    status: running, ok, source failures (fetch failures, gates passed), failed gate, error, interrupted, cancelled,
    accepted (a failed run a person accepted as the new baseline)."""

    __tablename__ = "update_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(20), default="running", index=True)
    reasons: Mapped[list[Any]] = mapped_column(JSON, default=list)  # one line per failed gate or error
    durations: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # step -> seconds
    counts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # runs.COUNT_KEYS
    gates: Mapped[list[Any]] = mapped_column(JSON, default=list)  # [{name, status, detail}]
    report: Mapped[str | None] = mapped_column(Text)  # reports/runs/<stamp>.md, relative to the workspace


class IndexFamilyLink(Base):
    """Disposable identity edges, owned by a UUID or a logic hash."""

    __tablename__ = "index_family_links"
    owner: Mapped[str] = mapped_column(Text, primary_key=True)
    key: Mapped[str] = mapped_column(Text, primary_key=True)
    logic_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    __table_args__ = (Index("ix_index_family_logic", "logic_hash"), Index("ix_index_family_key", "key"))


class IndexSignature(Base):
    """Exact detection items and MinHash; independent of source membership and families."""

    __tablename__ = "index_signatures"
    logic_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    logsource: Mapped[str] = mapped_column(Text)
    items: Mapped[list[str]] = mapped_column(JSON)
    signature: Mapped[list[int]] = mapped_column(JSON)


class IndexBucket(Base):
    """Persisted LSH membership for local candidate updates."""

    __tablename__ = "index_buckets"
    bucket: Mapped[str] = mapped_column(Text, primary_key=True)
    logic_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    __table_args__ = (Index("ix_index_buckets_logic", "logic_hash"),)


class IndexNearPair(Base):
    """Verified candidates including same-family pairs needed by repository overlap."""

    __tablename__ = "index_near_pairs"
    a: Mapped[str] = mapped_column(String(64), primary_key=True)
    b: Mapped[str] = mapped_column(String(64), primary_key=True)
    jaccard: Mapped[float] = mapped_column(Float)
    __table_args__ = (Index("ix_index_near_b", "b"),)


class CacheRevision(Base):
    """Transactionally advanced by SQLite triggers, including external SQL writers."""

    __tablename__ = "cache_revisions"
    name: Mapped[str] = mapped_column(String(60), primary_key=True)
    revision: Mapped[str] = mapped_column(String(32), default="0")


class SearchRank(Base):
    """Disposable local search keys; large rule JSON stays outside ranking scans."""

    __tablename__ = "search_rank"
    id: Mapped[int] = mapped_column(primary_key=True)
    family_id: Mapped[int] = mapped_column(Integer)
    score: Mapped[float] = mapped_column(Float)
    status: Mapped[str | None] = mapped_column(String(30))
    junk: Mapped[bool] = mapped_column(Boolean)


class SearchSummary(Base):
    """Disposable unfiltered facet counts, bound to visibility and index revisions."""

    __tablename__ = "search_summaries"
    name: Mapped[str] = mapped_column(String(60), primary_key=True)
    revision: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


Index("ix_occurrences_source_version", Occurrence.source_id, Occurrence.version_id)
Index("ix_versions_rule_logic", RuleVersion.rule_id, RuleVersion.logic_hash)
Index("ix_groups_family_logic", LogicGroup.family_id, LogicGroup.logic_hash)
Index(
    "ix_groups_search_rank",
    -LogicGroup.score,
    LogicGroup.id,
    LogicGroup.family_id,
    sqlite_where=text("junk = 0 AND coalesce(status, '') NOT IN ('deprecated', 'unsupported')"),
)
