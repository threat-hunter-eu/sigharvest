"""All-copy export admission: indexed logic policy, exact documents and current results.

Never resolve by UUID. Missing index membership fails closed even when the caller
includes dropped/junk rules. Result fingerprints use the execution input contract,
not a sibling's indexed validation or conversion summary.
"""

from __future__ import annotations

import json
from itertools import islice
from typing import Any

from sqlalchemy import String, func, select, text
from sqlalchemy.orm import Session, aliased

from sigharvest.config import Workspace
from sigharvest.errors import SigharvestError
from sigharvest.fingerprints import result_key, text_digest
from sigharvest.index import GroupFilters, _base
from sigharvest.models import Occurrence, RuleVersion, TestResult
from sigharvest.query import Filters, version_query

BATCH_SIZE = 500


def validation_schemas(ws: Workspace) -> dict[str, Any]:
    """Read the effective cached schemas without downloading or creating a cache."""
    from sigharvest.testing import SCHEMAS, SPEC_COMMIT

    try:
        return {kind: json.loads((ws.cache / "sigma-specification" / SPEC_COMMIT / name).read_text()) for kind, name in SCHEMAS.items()}
    except (OSError, ValueError) as exc:
        raise SigharvestError(
            "All-copy validation needs the cached validation schemas. Run sigharvest test --stage validate first, "
            "or omit --validation to export without claiming validation."
        ) from exc


def _contexts(s: Session, versions: list[RuleVersion], *, complete: bool = False, digests: dict[int, str] | None = None) -> dict[int, list[str]]:
    """Preserve ordered occurrence edges, hashing each sibling version once per batch.

    The optional digest map belongs only to this selector batch. Reuse already
    loaded documents, and fetch other raw documents in bounded scalar batches.
    Neither content identities (legacy context) nor equal bytes merge versions.
    """
    ids = [v.id for v in versions if v.kind == "correlation"]
    if not ids:
        return {}
    # Core columns retain complete producer inputs even inside a publication
    # scope. They are hashed locally and never returned as export members.
    occ_table: Any = Occurrence.__table__ if complete else Occurrence
    version_table: Any = RuleVersion.__table__ if complete else RuleVersion
    occ = occ_table.c if complete else occ_table
    version = version_table.c if complete else version_table
    sibling_table: Any = Occurrence.__table__.alias() if complete else aliased(Occurrence)
    sibling = sibling_table.c if complete else sibling_table
    first = (
        select(occ.version_id.label("version_id"), func.min(occ.id).label("id"))
        .where(occ.present.is_(True), occ.version_id.in_(ids))
        .group_by(occ.version_id)
        .subquery()
    )
    rows = s.execute(
        select(first.c.version_id, version.id)
        .join(occ_table, occ.id == first.c.id)
        .join(
            sibling_table,
            (sibling.source_id == occ.source_id) & (sibling.path == occ.path) & sibling.present.is_(True) & (sibling.version_id != first.c.version_id),
        )
        .join(version_table, version.id == sibling.version_id)
        .order_by(first.c.version_id, sibling.doc_index, sibling.id)
    ).yield_per(BATCH_SIZE)
    edges: dict[int, list[int]] = {}
    needed: dict[int, None] = {}
    for vid, sibling_id in rows:
        edges.setdefault(vid, []).append(sibling_id)
        needed[sibling_id] = None
    if digests is None:
        digests = {}
    for version in versions:
        if version.id in needed and version.id not in digests:
            digests[version.id] = text_digest(version.raw)
    missing = iter(vid for vid in needed if vid not in digests)
    # The ordered edge query applies the requested scope to both occurrence
    # aliases and RuleVersion (or the complete producer graph when requested). Hydrate only those admitted IDs; repeating the
    # same visibility graph for every raw batch adds no admission decision.
    columns = RuleVersion.__table__.c
    while batch := list(islice(missing, BATCH_SIZE)):
        for vid, raw in s.connection().execute(select(columns.id, columns.raw).where(columns.id.in_(batch))).yield_per(BATCH_SIZE):
            digests[vid] = text_digest(raw)
    return {vid: [digests[sibling_id] for sibling_id in siblings] for vid, siblings in edges.items()}


def select_documents(
    s: Session,
    query: str | None,
    f: GroupFilters,
    min_score: float | None = None,
    *,
    schemas: dict[str, Any] | None = None,
) -> list[RuleVersion]:
    """One current version per content identity, shared by every all-copy writer.

    Metadata/query/source match the actual document. Score and junk are indexed logic policy. Validation/backend match exact current stored
    results; unavailable or stale results never satisfy a requested status.
    """
    from sigharvest.conversion import BACKENDS, toolchain
    from sigharvest.testing import validation_toolchain

    checks: dict[tuple[str, str], tuple[str, str]] = {}
    if f.validation:
        if f.validation not in {"ok", "warning", "error"}:
            raise SigharvestError("--validation must be ok, warning or error; omit it to include unvalidated copies.")
        if schemas is None:
            raise SigharvestError("All-copy validation requires the effective cached schemas; omit --validation or run validation first.")
        checks["validate", "pysigma+schema"] = (f.validation, validation_toolchain(schemas))
    if f.backend:
        if f.backend not in BACKENDS:
            raise SigharvestError("--backend must name a supported conversion backend.")
        checks["convert", f.backend] = ("ok", toolchain(f.backend))

    # Reuse search's logic predicates without applying canonical metadata to copies.
    policy = GroupFilters(include_junk=f.include_junk, include_deprecated=True, profile=f.profile)
    base, _, params = _base(None, policy, session=s)
    params.pop("new_run", None)  # _base also returns this unused default for ordinary searches.
    if min_score is not None:
        base += " AND g.score >= :export_min_score"
        params["export_min_score"] = min_score
    eligible = text("SELECT g.logic_hash " + base).bindparams(**params).columns(logic_hash=String)
    documents = Filters(
        product=f.product,
        category=f.category,
        service=f.service,
        level=f.level,
        status=f.status,
        tag=f.tag,
        source=f.source,
        text=query,
        include_deprecated=f.include_deprecated,
    )
    statement = version_query(documents, live=True)
    if any((f.source, f.product, f.category, f.service, f.level, f.status, f.tag, f.profile)):
        # Metadata filters usually admit few documents. Probe their indexed logic
        # instead of scanning every unrelated group.
        membership = text("EXISTS (SELECT 1 " + base + " AND g.logic_hash=rule_versions.logic_hash)").bindparams(**params)
        statement = statement.where(membership)
    else:
        statement = statement.where(RuleVersion.logic_hash.in_(eligible))
    from sigharvest.query import explicitly_deprecated

    if not f.include_deprecated and not explicitly_deprecated(f.status):
        statement = statement.where(func.coalesce(RuleVersion.status, "") != "unsupported")
    # Apply cheap exact-result gates in SQL before reading YAML or hashing inputs.
    for (stage, target), (status, tc) in checks.items():
        statement = statement.where(
            RuleVersion.id.in_(
                select(TestResult.version_id).where(
                    TestResult.stage == stage,
                    TestResult.target == target,
                    TestResult.dataset == "",
                    TestResult.status == status,
                    TestResult.fingerprint.is_not(None),
                    func.json_extract(TestResult.detail, "$.toolchain") == tc,
                )
            )
        )
    versions = iter(s.scalars(statement).yield_per(BATCH_SIZE))
    selected: list[RuleVersion] = []
    while batch := list(islice(versions, BATCH_SIZE)):
        if not checks:
            selected.extend(batch)
            continue
        stored = {
            (vid, stage, target): fingerprint
            for vid, stage, target, fingerprint in s.execute(
                select(TestResult.version_id, TestResult.stage, TestResult.target, TestResult.fingerprint).where(
                    TestResult.version_id.in_([v.id for v in batch]), TestResult.dataset == "", TestResult.stage.in_([key[0] for key in checks])
                )
            )
        }
        digests: dict[int, str] = {}
        contexts = _contexts(s, batch, digests=digests) if f.backend else {}
        for v in batch:
            if v.id not in digests:
                digests[v.id] = text_digest(v.raw)
            content = digests[v.id]
            if all(
                stored.get((v.id, stage, target)) == result_key(tc, content, v.kind, contexts.get(v.id, []) if stage == "convert" else [])
                for (stage, target), (_, tc) in checks.items()
            ):
                selected.append(v)
    return selected
