"""Search index: one LogicGroup per unique logic hash, plus an FTS5 full-text table.

The index is derived data. `rebuild()` reconstructs it in one transaction; it runs at
the end of `sigharvest sync` and `sigharvest test`, or on demand with `sigharvest index`.

Score (0-100, higher is better), used to rank results that match equally well:
  validation      30  ok=30, warning=18, error=0, not tested=10
  conversion      25  ok / (ok + partial + warning + error + timeout): ok = mapped by a pipeline; raw (syntax only, no
                      field mapping for that log source), unsupported and skipped results are not counted
  independence    20  log2 of the number of independent sources carrying the same logic (mirrors collapsed to the
                      repository they copy, see source_roots), capped at 5
  status          10  stable=10, test=8, experimental=5, none=4, deprecated/unsupported=0
  metadata        10  complete Enterprise ATT&CK technique (4; syntax-only without a local catalog), level (2), author (2), description (2)
  freshness        5  modified/date within 2 years = 5, within 5 years = 3, older or unknown = 1
  junk           -20  synthetic, test fixture, foreign query, template, match-all, deprecated upstream (quality.py)
  weak values    -15  weak_detection / -5 weak_branch: the condition can be met by weak values (quality_strength.py)
  field names    -10  foreign_field_names: a Windows rule with dotted names from another schema (quality_fields.py)
The result is clamped to 0-100.
"""

from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import yaml
from sqlalchemy import delete, func, insert, select, text
from sqlalchemy.orm import Session

from sigharvest import normalize as norm
from sigharvest.attack_score import Context as AttackScoreContext
from sigharvest.attack_score import credit as attack_metadata_credit
from sigharvest.datasources import datasource_key, rule_datasources
from sigharvest.identity import normalise_rule_id, placeholder_uuid
from sigharvest.models import LogicGroup, Occurrence, RuleVersion, Source, TestResult, TestRun

# The index only needs text (titles, field names, values for full-text search and quality flags), so scalars are
# not type-resolved: BaseLoader keeps every scalar a string and is several times faster on 110k documents.
# Conversion results that count in the score's denominator: a missing pipeline (raw) is the backend's limit.
SCORED_CONVERSION = ("ok", "partial", "warning", "error", "timeout", "resource_failure")
_YAML_LOADER = getattr(yaml, "CBaseLoader", yaml.BaseLoader)
STATUS_POINTS = {"stable": 10, "test": 8, "experimental": 5, "deprecated": 0, "unsupported": 0}
VALIDATION_POINTS = {"ok": 30, "warning": 18, "error": 0}
# meta key (db.get_meta) holding the UTC time of the last rebuild; `sigharvest doctor` compares it with syncs and tests.
INDEX_BUILT_AT = "index_built_at"
FTS_WEIGHTS = (10.0, 3.0, 5.0, 2.0, 2.0, 4.0, 1.0)  # title, description, tags, logsource, fields, detection, author


@dataclass
class _Acc:
    logic_hash: str
    # (priority, source, content_hash, path, version_id): the canonical copy depends only on the corpus and the
    # configuration, never on sync order or row ids, so two builds of the same corpus pick the same copy.
    best: tuple[int, str, str, str, int] | None = None
    copies: int = 0
    sources: set[str] = field(default_factory=set)
    rule_ids: set[str] = field(default_factory=set)
    only_fixture_paths: bool = True  # every copy is under a test/fixture/example folder


def _fields(detection: Any) -> list[str]:
    out: set[str] = set()
    if isinstance(detection, dict):
        for key, value in detection.items():
            if key in ("condition", "timeframe"):
                continue
            items = value if isinstance(value, list) else [value]
            for item in items:
                if isinstance(item, dict):
                    out.update(str(k).split("|", 1)[0] for k in item)
    return sorted(out)


def _year(text_: str | None) -> int | None:
    m = re.search(r"(19|20)\d{2}", text_ or "")
    return int(m.group(0)) if m else None


def score(
    v: RuleVersion,
    validation: str | None,
    converts: int,
    applicable: int,
    n_sources: int,
    description: str | None,
    *,
    attack_context: AttackScoreContext | None = None,
) -> float:
    pts = float(VALIDATION_POINTS.get(validation or "", 10))
    pts += 25.0 * (converts / applicable) if applicable else 0.0
    pts += 20.0 * min(math.log2(max(n_sources, 1)) / math.log2(5), 1.0) if n_sources > 1 else 0.0
    pts += STATUS_POINTS.get(norm.status(v.status) or "", 4)
    pts += attack_metadata_credit(v.tags, attack_context if attack_context is not None else AttackScoreContext())
    pts += 2 if norm.level(v.level) else 0
    pts += 2 if v.author else 0
    pts += 2 if description else 0
    year = _year(v.modified) or _year(v.date)
    now = datetime.now(UTC).year
    pts += 5 if year and now - year <= 2 else 3 if year and now - year <= 5 else 1
    return round(pts, 1)


def _detection_text(detection: Any) -> str:
    try:
        return json.dumps(detection, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(detection)


_RELATED_BLOCK = re.compile(r"^related:[ \t]*\n((?:[ \t]+.*\n?|-.*\n?)+)", re.M)
LINKING_RELATIONS = {"derived", "obsolete", "obsoletes", "merged", "renamed"}


def related_ids(raw: str) -> list[str]:
    """Rule ids this document declares as the same rule (related: derived/obsolete/merged/renamed)."""
    m = _RELATED_BLOCK.search(raw)
    if not m:
        return []
    try:
        items = yaml.load("related:\n" + m.group(1), Loader=_YAML_LOADER).get("related")  # noqa: S506 - BaseLoader
    except (yaml.YAMLError, AttributeError):
        return []
    out = []
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and str(item.get("type", "")).lower() in LINKING_RELATIONS:
            nid = normalise_rule_id(item.get("id"))
            if nid:
                out.append(nid)
    return out


def ambiguous_ids(s: Session, max_titles: int = 5, *, rule_ids: set[str] | None = None) -> set[str]:
    """Real rule ids that cannot identify one rule: placeholders (placeholder_uuid) and ids carried by more than
    `max_titles` different titles. Used by families, triage and collections."""
    # A GROUP BY on the noncovering UUID index causes random reads of large YAML
    # pages on a real corpus. Stream narrow rows once and cap each title set at
    # the decision threshold; memory is bounded per UUID.
    titles: dict[str, set[str]] = defaultdict(set)
    query = select(RuleVersion.rule_id, RuleVersion.title_slug).where(RuleVersion.id_flag.is_(None))
    if rule_ids is not None:
        keys = func.json_each(json.dumps(sorted(rule_ids))).table_valued("value")
        query = query.where(RuleVersion.rule_id.in_(select(keys.c.value)))
    for rid, slug in s.execute(query):
        seen = titles[rid]
        if slug is not None and len(seen) <= max_titles:
            seen.add(slug)
    return {rid for rid, seen in titles.items() if len(seen) > max_titles or placeholder_uuid(rid)}


def is_ambiguous_id(s: Session, rule_id: str, max_titles: int = 5) -> bool:
    if placeholder_uuid(rule_id):
        return True
    from sqlalchemy import func

    n = s.scalar(select(func.count(func.distinct(RuleVersion.title_slug))).where(RuleVersion.rule_id == rule_id)) or 0
    return n > max_titles


def _tokens(slug: str) -> set[str]:
    return {w for w in re.split(r"[^a-z0-9]+", slug.lower()) if len(w) > 1}


def _jaccard(a: set[str], b: set[str]) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def _coherent_clusters(s: Session, members: list[tuple[str, str]]) -> list[tuple[str, int]]:
    """Split the logic groups sharing one rule id into clusters of the same rule: same title, or title words
    Jaccard >= 0.5, or detection values Jaccard >= 0.3 (renamed rules keep most of their values). Copy-pasted ids
    on unrelated rules end up in different clusters, so they do not merge families."""
    values: dict[str, set[str]] = {}

    def vals(lh: str) -> set[str]:
        if lh not in values:
            raw = s.scalar(select(RuleVersion.raw).where(RuleVersion.logic_hash == lh).limit(1)) or ""
            try:
                data = yaml.load(raw, Loader=_YAML_LOADER)  # noqa: S506 - C/SafeLoader
            except yaml.YAMLError:
                data = None
            det = data.get("detection") if isinstance(data, dict) else None
            values[lh] = set(_detection_text(det).lower().split()) if det else set()
        return values[lh]

    reps: list[tuple[str, str]] = []  # (logic hash, slug) of each cluster's first member
    out: list[tuple[str, int]] = []
    for lh, slug in members:
        for i, (rlh, rslug) in enumerate(reps):
            if slug == rslug or _jaccard(_tokens(slug), _tokens(rslug)) >= 0.5 or _jaccard(vals(lh), vals(rlh)) >= 0.3:
                out.append((lh, i))
                break
        else:
            reps.append((lh, slug))
            out.append((lh, len(reps) - 1))
    return out


def source_roots(groups: dict[str, _Acc], threshold: float = 0.8) -> dict[str, tuple[str, str | None, float, int]]:
    """Collapse mirrors: a source whose logic is at least `threshold` contained in a larger source is a copy of it.

    Returns name -> (root, parent, containment, logic count). Following parents gives the root; a source copied
    from several repositories points to the one it overlaps most."""
    bits: dict[str, int] = defaultdict(int)
    for i, acc in enumerate(groups.values()):
        for name in acc.sources:
            bits[name] |= 1 << i
    size = {name: value.bit_count() for name, value in bits.items()}
    best: dict[str, tuple[float, str]] = {}
    names = sorted(bits)
    for i, a in enumerate(names):
        for b in names[i + 1 :]:
            child, par = (a, b) if (size[a], a) < (size[b], b) else (b, a)
            if size[a] == size[b]:
                child, par = b, a
            share = (bits[a] & bits[b]).bit_count() / size[child]
            old_share, old_parent = best.get(child, (0.0, ""))
            if share >= threshold and (share > old_share or (share == old_share and par < old_parent)):
                best[child] = share, par

    def root_of(name: str) -> str:
        seen = set()
        while name in best and name not in seen:
            seen.add(name)
            name = best[name][1]
        return name

    return {n: (root_of(n), best[n][1] if n in best else None, round(best[n][0], 3) if n in best else 0.0, size[n]) for n in size}


def _upstream_deprecated_ids(s: Session) -> set[str]:
    """Rule ids that SigmaHQ marks deprecated/unsupported (status or deprecated/ folder) in its current tree."""
    from sigharvest.sources import well_known_sources

    names = well_known_sources(s, "sigmahq")
    if not names:
        return set()
    q = (
        select(RuleVersion.rule_id, RuleVersion.status, RuleVersion.flags, Occurrence.path)
        .join(Occurrence, Occurrence.version_id == RuleVersion.id)
        .join(Source, Source.id == Occurrence.source_id)
        .where(Occurrence.present.is_(True), Source.name.in_(names), RuleVersion.id_flag.is_(None))
    )
    out = set()
    for rid, status, flags, path in s.execute(q):
        if (status or "").lower() in ("deprecated", "unsupported") or "deprecated" in (flags or []) or "/deprecated/" in "/" + (path or ""):
            out.add(rid)
    return out


def canonical_key(priority: int, source: str, content_hash: str, path: str | None, version_id: int) -> tuple[int, str, str, str, int]:
    """Order of the copies of one logic: the smallest key is the canonical copy (lowest priority number first)."""
    return (priority, source, content_hash, path or "", version_id)


def canonical_version_ids(s: Session) -> set[int]:
    """The version `rebuild` will choose as canonical for each live logic, computed from the current occurrences.

    Conversion of the canonical copies alone is what the index, the 'converts to' filter and release files read
    (`update --convert-scope canonical`)."""
    best: dict[str, tuple[int, str, str, str, int]] = {}
    query = (
        select(RuleVersion.id, RuleVersion.logic_hash, Source.name, Source.priority, RuleVersion.content_hash, Occurrence.path)
        .join(Occurrence, Occurrence.version_id == RuleVersion.id)
        .join(Source, Source.id == Occurrence.source_id)
        .where(Occurrence.present.is_(True))
    )
    for vid, lh, src, prio, content, path in s.execute(query):
        key = canonical_key(prio, src, content, path, vid)
        current = best.get(lh)
        if current is None or key < current:
            best[lh] = key
    return {key[4] for key in best.values()}


def current_validation_toolchain(s: Session) -> str | None:
    """Validation toolchain of the newest validate run (None before the first run that recorded one).

    A run records its toolchain before it validates anything, so after a pySigma/schema upgrade the newest run already
    names the new toolchain even when it was interrupted; results from the old toolchain then index as "not tested".
    """
    params = s.scalars(select(TestRun.params).where(TestRun.stage == "validate").order_by(TestRun.id.desc()).limit(1)).first()
    tc = (params or {}).get("toolchain")
    return tc if isinstance(tc, str) and tc else None


def validation_current(result_toolchain: str | None, current: str | None) -> bool:
    """A stored validation counts only under the current toolchain; results without one predate fingerprints (kept)."""
    return current is None or not result_toolchain or result_toolchain == current


def rebuild(s: Session, progress: Callable[[str], None] | None = None, *, commit: bool = True, full: bool = True, workers: int | None = None) -> int:
    """Rebuild the whole derived index (logic groups, families, near duplicates, overlap, FTS) in one transaction.

    `full` is accepted for compatibility; every rebuild is complete.
    """
    from sigharvest import index_delta, index_families, index_near
    from sigharvest.attack import session_matrix
    from sigharvest.attack_score import CONTEXT_KEY
    from sigharvest.db import INDEXED_RESULTS_REVISION, INDEXED_SYNC_REVISION, RESULTS_REVISION, SYNC_REVISION, get_meta, set_meta
    from sigharvest.index_workers import Workers
    from sigharvest.models import IndexNearPair, SourceRoot, utcnow
    from sigharvest.quality import FIXTURE_PATH
    from sigharvest.quality_templates import template_groups
    from sigharvest.semantic import ACTIVE_FINGERPRINT, INDEXED_FINGERPRINT

    # SQLite's default 2 MiB page cache thrashes on the random hash-key inserts
    # of a corpus rebuild. This connection-local upper bound fits the worker budget.
    s.execute(text("PRAGMA cache_size=-262144"))
    # Fresh planner statistics first: a workspace that was just filled (first update, init --from-release) has none,
    # and without them SQLite picks nested scans for the family queries (56 s instead of 2 s on 19,444 rules).
    # analysis_limit bounds the cost on large tables (approximate statistics are enough for the planner).
    s.execute(text("PRAGMA analysis_limit=1000"))
    s.execute(text("ANALYZE"))
    attack_context = AttackScoreContext(session_matrix(s))
    upstream_dep = _upstream_deprecated_ids(s)
    set_meta(s, "index_upstream_deprecated", json.dumps(sorted(upstream_dep)))
    templates = template_groups(s)
    if progress:
        progress("index: full rebuild")
    query = (
        select(RuleVersion.id, RuleVersion.logic_hash, RuleVersion.rule_id, Source.name, Source.priority, RuleVersion.content_hash, Occurrence.path)
        .join(Occurrence, Occurrence.version_id == RuleVersion.id)
        .join(Source, Source.id == Occurrence.source_id)
        .where(Occurrence.present.is_(True))
    )
    groups: dict[str, _Acc] = {}
    source_documents: dict[str, int] = defaultdict(int)
    for vid, lh, rid, src, prio, content, path in s.execute(query):
        source_documents[src] += 1
        acc = groups.get(lh)
        if acc is None:
            acc = groups[lh] = _Acc(lh)
        acc.copies += 1
        if acc.only_fixture_paths and not FIXTURE_PATH.search(path or ""):
            acc.only_fixture_paths = False
        acc.sources.add(src)
        acc.rule_ids.add(rid)
        key = canonical_key(prio, src, content, path, vid)
        if acc.best is None or key < acc.best:
            acc.best = key
    if progress:
        progress(f"index: {len(groups):,} unique logic groups")
        progress("index: identity families")
    family_of, family_size = index_families.families(s, set(groups))
    if progress:
        progress("index: source roots")
    roots = source_roots(groups)
    s.execute(delete(SourceRoot))
    if roots:
        s.execute(insert(SourceRoot), [{"name": n, "root": r, "parent": p, "containment": c, "logic": k} for n, (r, p, c, k) in roots.items()])
    canonical = {acc.best[4]: acc for acc in groups.values() if acc.best}
    validation: dict[int, str] = {}
    converts: dict[int, list[str]] = defaultdict(list)  # ok targets only
    conversion: dict[int, dict[str, Any]] = defaultdict(dict)
    applicable: dict[int, int] = defaultdict(int)
    if progress:
        progress("index: current result summaries")
    s.execute(text("CREATE TEMP TABLE IF NOT EXISTS index_canonical(id INTEGER PRIMARY KEY)"))
    s.execute(text("DELETE FROM index_canonical"))
    canonical_rows = [{"id": vid} for vid in canonical]
    for i in range(0, len(canonical_rows), 5000):
        s.execute(text("INSERT INTO index_canonical VALUES (:id)"), canonical_rows[i : i + 5000])
    validate_toolchain = current_validation_toolchain(s)
    # Restrict before JSON extraction: historical/noncanonical result bodies can
    # dwarf the live canonical set on long-lived workspaces.
    for vid, stage, target, status, covered, source_statuses, tc in s.execute(
        select(
            TestResult.version_id,
            TestResult.stage,
            TestResult.target,
            TestResult.status,
            TestResult.detail["covered_sources"],
            TestResult.detail["source_statuses"],
            func.json_extract(TestResult.detail, "$.toolchain"),
        ).where(
            TestResult.stage.in_(["validate", "convert"]),
            TestResult.dataset == "",
            TestResult.version_id.in_(select(text("id")).select_from(text("index_canonical"))),
        )
    ):
        if vid not in canonical:
            continue
        if stage == "validate":
            if not validation_current(tc, validate_toolchain):
                continue  # checked by an older parser/schema: "not tested" until validated again, never a stale "ok"
            validation[vid] = status
        else:
            conversion[vid][target] = {
                "status": status,
                "covered_sources": covered or [],
                "sources": source_statuses or {},
            }
            applicable[vid] += status in SCORED_CONVERSION
            if status == "ok":
                converts[vid].append(target)

    s.execute(delete(LogicGroup))
    s.execute(text("DELETE FROM rules_fts"))
    near_items: list[index_near.Item] = []
    ids = list(canonical)
    pool = Workers(workers, len(ids))
    try:
        _write_groups(
            s,
            ids,
            canonical,
            pool,
            family_of,
            family_size,
            roots,
            upstream_dep,
            validation,
            converts,
            conversion,
            applicable,
            near_items,
            progress,
            templates,
            attack_context,
        )
    finally:
        pool.close()
    # Consolidate FTS segments at publication, not on the first new term.
    s.execute(text("INSERT INTO rules_fts(rules_fts) VALUES ('optimize')"))
    if progress:
        progress("index: near-duplicate rules")
    index_near.update(s, near_items, set(), full=True)
    index_near.publish(s)
    from sigharvest.source_overlap import rebuild_source_overlap

    if progress:
        progress("index: repository overlap")
    rebuild_source_overlap(
        s,
        {lh: acc.sources for lh, acc in groups.items()},
        s.execute(select(IndexNearPair.a, IndexNearPair.b)),
        source_documents,
    )
    set_meta(s, INDEX_BUILT_AT, utcnow().isoformat())
    set_meta(s, INDEXED_FINGERPRINT, get_meta(s, ACTIVE_FINGERPRINT) or "")
    set_meta(s, INDEXED_RESULTS_REVISION, get_meta(s, RESULTS_REVISION) or "")
    set_meta(s, INDEXED_SYNC_REVISION, get_meta(s, SYNC_REVISION) or "")
    set_meta(s, CONTEXT_KEY, attack_context.fingerprint)
    set_meta(s, index_delta.FORMAT_KEY, index_delta.publication_fingerprint(s, attack_context))
    from sigharvest.search_summary import refresh as refresh_search

    refresh_search(s, source_ready=True)
    from sigharvest.page_summaries import refresh as refresh_pages

    if progress:
        progress("index: page summaries")
    refresh_pages(s)

    from sigharvest.correlation_references import refresh as refresh_references

    if progress:
        progress("index: correlation references")
    refresh_references(s, full=True, workers=workers)
    s.flush()
    set_meta(s, index_delta.USER_REVISION_KEY, index_delta.user_revision(s))
    s.execute(text("PRAGMA optimize"))
    if commit:
        s.commit()
    s.expire_all()
    return len(groups)


def _write_groups(
    s: Session,
    ids: list[int],
    canonical: dict[int, _Acc],
    pool: Any,
    family_of: dict[str, int],
    family_size: dict[int, int],
    roots: dict[str, tuple[str, str | None, float, int]],
    upstream_dep: set[str],
    validation: dict[int, str],
    converts: dict[int, list[str]],
    conversion: dict[int, dict[str, Any]],
    applicable: dict[int, int],
    near_items: list[Any],
    progress: Callable[[str], None] | None,
    templates: set[str],
    attack_context: AttackScoreContext,
) -> None:
    from sigharvest.quality import is_junk
    from sigharvest.quality_fields import field_penalty
    from sigharvest.quality_strength import strength_penalty
    from sigharvest.title_relevance import indexed_title

    batch: list[dict[str, Any]] = []
    fts: list[dict[str, Any]] = []
    next_id = 1

    def windows() -> Iterator[list[RuleVersion]]:
        query = select(RuleVersion).where(RuleVersion.id.in_(select(text("id")).select_from(text("index_canonical")))).order_by(RuleVersion.id)
        window: list[RuleVersion] = []
        size = 0
        for version in s.scalars(query.execution_options(yield_per=32)):
            if window and (len(window) >= 2000 or size + len(version.raw) > 64 * 1024 * 1024):
                yield window
                window, size = [], 0
            window.append(version)
            size += len(version.raw)
        if window:
            yield window

    done = 0
    for versions in windows():
        prepared = pool.run(
            [
                (
                    v.id,
                    v.raw,
                    canonical[v.id].only_fixture_paths,
                    v.rule_id in upstream_dep and (v.status or "").lower() not in ("deprecated", "unsupported"),
                    v.kind,
                )
                for v in versions
            ]
        )
        for v in versions:
            acc = canonical[v.id]
            data, qflags, xs, sig, text_metadata = prepared[v.id]
            if acc.logic_hash in templates:
                qflags = sorted(set(qflags) | {"autogen_template"})
                xs, sig = frozenset(), ()
            # The score reads the raw description; the indexed one is the cleaned text metadata.
            score_description = str(data.get("description") or "").strip() or None
            description = text_metadata.description
            flds = _fields(data.get("detection"))
            n_product, n_category, n_service = norm.logsource(v.product, v.category, v.service)
            n_indep = len({roots[x][0] for x in acc.sources}) or 1
            n_tags = norm.tags(v.tags or [])
            junk = is_junk(qflags)
            near_items.append((acc.logic_hash, f"{n_product}/{n_category}/{n_service}", xs, sig))
            group_id = next_id
            next_id += 1
            conv = sorted(converts.get(v.id, []))
            row = {
                "id": group_id,
                "logic_hash": acc.logic_hash,
                "family_id": family_of[acc.logic_hash],
                "family_size": family_size[family_of[acc.logic_hash]],
                "canonical_version_id": v.id,
                "canonical_source": acc.best[1] if acc.best else "",
                "rule_id": v.rule_id,
                "kind": v.kind,
                "title": v.title,
                "description": description,
                "product": n_product,
                "category": n_category,
                "service": n_service,
                "datasources": rule_datasources(n_product, n_category, n_service, data.get("detection")),
                "level": norm.level(v.level),
                "status": norm.status(v.status),
                "author": text_metadata.author,
                "tags": n_tags,
                "fields": flds,
                "copies": acc.copies,
                "sources": sorted(acc.sources),
                "n_sources": len(acc.sources),
                "n_independent": n_indep,
                "n_rule_ids": len(acc.rule_ids),
                "validation": validation.get(v.id),
                "converts": conv,
                "conversion": conversion.get(v.id) or None,
                "score": min(
                    100.0,
                    max(
                        0.0,
                        score(v, validation.get(v.id), len(conv), applicable.get(v.id, 0), n_indep, score_description, attack_context=attack_context)
                        - (20.0 if junk else 0.0)
                        - strength_penalty(qflags)
                        - field_penalty(qflags),
                    ),
                ),
                "quality_flags": qflags,
                "junk": junk,
                "modified": v.modified or v.date,
            }
            batch.append(row)
            fts.append(
                {
                    "rowid": group_id,
                    "title": indexed_title(v.title or ""),
                    "description": description or "",
                    "tags": " ".join(n_tags),
                    "logsource": " ".join(x for x in (n_product, n_category, n_service) if x),
                    "fields": " ".join(flds),
                    "detection": _detection_text(data.get("detection") or data.get("correlation") or data.get("filter")),
                    "author": text_metadata.author or "",
                }
            )
        if batch:
            s.execute(insert(LogicGroup), batch)
            s.execute(
                text(
                    "INSERT INTO rules_fts(rowid, title, description, tags, logsource, fields, detection, author) "
                    "VALUES (:rowid, :title, :description, :tags, :logsource, :fields, :detection, :author)"
                ),
                fts,
            )
            batch, fts = [], []
        done += len(versions)
        if progress:
            progress(f"index: {done}/{len(ids)}")


# ----------------------------------------------------------------------------- search


_TERM = re.compile(r'[^\s()"]*"[^"]*"|\(|\)|[^\s()]+')
FTS_COLUMNS = {"title", "description", "tags", "logsource", "fields", "detection", "author"}
# key:value terms that become filters instead of full-text terms
FILTER_KEYS = {
    "technique",
    "tactic",
    "level",
    "product",
    "category",
    "service",
    "status",
    "source",
    "tag",
    "id",
    "flag",
    "validation",
    "backend",
    "datasource",
    "exclude_source",
    "collection",
}


def parse_query(user: str) -> tuple[str, dict[str, str]]:
    """Split `key:value` filter terms (level:high, product:windows, id:<uuid or logic hash>, tag:t1059.001,
    source:sigmahq...) from the full-text part of a search.

    A key given more than once is a union (`level:high level:critical`, `level:high OR level:critical` and
    `level:high,critical` all mean high or critical); different keys are ANDed. `OR` between two different filter
    keys, or between words and a filter, cannot be expressed and is refused instead of silently dropping one side."""
    from sigharvest.query_limits import QueryFilterError, check_query

    check_query(user)
    filters: dict[str, str] = {}
    rest: list[str] = []
    tokens = re.findall(r'\S+:"[^"]*"|"[^"]*"|\S+', user)
    keys: list[str | None] = []
    for raw in tokens:
        key, sep, value = raw.partition(":")
        if sep and key.lower() in FILTER_KEYS and value:
            key = key.lower()
            value = value.strip('"')
            keys.append(key)
            filters[key] = filters[key] + "," + value if key in filters and key != "id" else value
        else:
            if sep and value and not value.startswith((":", "/", "\\")):
                _refuse_unknown_filter(key)
            keys.append(None)
            rest.append(raw)
    _check_filter_values(filters)
    for i, raw in enumerate(tokens):
        if raw != "OR" or i == 0 or i + 1 >= len(tokens):
            continue
        left, right = keys[i - 1], keys[i + 1]
        if (left is None) != (right is None):
            word, flt = (tokens[i - 1], tokens[i + 1]) if left is None else (tokens[i + 1], tokens[i - 1])
            raise QueryFilterError(
                f"OR between words and a filter is not supported ({tokens[i - 1]} OR {tokens[i + 1]}): a filter such as "
                f"{flt} always applies to the whole search. Run two searches: '{word}' and '{flt}'."
            )
        if (left or right) and left != right:
            raise QueryFilterError(
                "OR between different filters is not supported "
                f"({tokens[i - 1]} OR {tokens[i + 1]}). Values of one filter can be combined: level:high,critical "
                "or level:high OR level:critical; run separate searches for different filters."
            )
    if any(k is not None for k in keys):
        # Drop an OR that only joined two values of the same filter, so it does not reach the text search.
        rest = [raw for i, raw in enumerate(tokens) if keys[i] is None and not (raw == "OR" and 0 < i < len(tokens) - 1 and keys[i - 1] is not None)]
    return " ".join(rest), filters


def _refuse_unknown_filter(key: str) -> None:
    """`prodct:windows` would search for the words "prodct windows" and find nothing: refuse a key that is close to a
    filter or column name, with the suggestion. Other `word:word` text (`sekurlsa::logonpasswords`, `C:\\`, URLs,
    `cmd.exe:x`) stays a text search."""
    import difflib

    from sigharvest.query_limits import QueryFilterError

    lower = key.lower()
    if lower in FILTER_KEYS or lower in FTS_COLUMNS or not lower.replace("_", "").isalpha():
        return
    known = sorted(FILTER_KEYS | FTS_COLUMNS | set(FILTER_ALIASES))
    close = difflib.get_close_matches(lower, known, n=1, cutoff=0.75)
    if close:
        hint = FILTER_ALIASES.get(close[0], close[0])
        raise QueryFilterError(
            f"unknown filter {key}: (did you mean {hint}:?). Filters: {', '.join(sorted(FILTER_KEYS))}; columns: {', '.join(sorted(FTS_COLUMNS))}."
        )


# Common names users try for a filter key, suggested instead of an error-prone close match.
FILTER_ALIASES = {"severity": "level", "technique_id": "technique", "products": "product", "categories": "category", "sources": "source"}


def _check_filter_values(filters: dict[str, str]) -> None:
    """`level:hgh` / `status:stabel` match nothing; refuse them like `--level hgh`, with the closest valid value."""
    import difflib

    from sigharvest import normalize as norm
    from sigharvest.query_limits import QueryFilterError

    valid = {"level": (norm.level, norm.LEVELS), "status": (norm.status, ("stable", "test", "experimental", "deprecated", "unsupported"))}
    for key, (fix, choices) in valid.items():
        for value in (filters.get(key) or "").split(","):
            value = value.strip()
            if value and fix(value) is None:
                close = difflib.get_close_matches(value.lower(), choices, n=1, cutoff=0.6)
                hint = f" (did you mean {key}:{close[0]}?)" if close else ""
                raise QueryFilterError(f"{value!r} is not a {key}: choose one of {', '.join(choices)}{hint}.")


MIN_PREFIX = 3  # shorter words are matched exactly, not as a prefix
_STEM_SUFFIXES = ("ings", "ing", "ies", "ers", "er", "ed", "es", "s")


def stem(word: str) -> str:
    """Light English suffix stripping for prefix search: dumping/dumped/dumps -> dump, credentials -> credential,
    creating/created -> creat. Search words are prefix matches, so the stem also finds every longer form; short words,
    words with digits and quoted phrases are left alone."""
    lower = word.lower()
    if len(lower) < 5 or not lower.isalpha():
        return word
    for suffix in _STEM_SUFFIXES:
        if lower.endswith(suffix) and len(lower) - len(suffix) >= 4:
            base = word[: -len(suffix)]
            if suffix in ("s", "es") and lower.endswith(("ss", "us", "is")):
                return word  # lsass, virus, analysis: not plurals
            if suffix == "es" and not lower[: -len(suffix)].endswith(("sh", "ch", "x", "z", "ss")):
                base = word[:-1]  # processes -> process (es), but files -> file (s)
            if len(base) >= 5 and base[-1] == base[-2] and base[-1].lower() not in "lsz":
                base = base[:-1]  # dumpping/running -> runn -> run
            return base
    return word


def _phrase(term: str) -> str | None:
    col = ""
    quoted = term.startswith('"') or '"' in term.partition(":")[2][:1]
    if ":" in term and not term.startswith('"'):
        c, _, rest = term.partition(":")
        if c.lower() in FTS_COLUMNS and rest:
            col, term = c.lower() + ":", rest
    tokens = re.findall(r"\w+", term.strip('"'), flags=re.UNICODE)
    if len(tokens) == 1 and not quoted:
        tokens = [stem(tokens[0])]
        if len(tokens[0]) < MIN_PREFIX:
            # A one- or two-character prefix expands to a large part of the index vocabulary (64 x `a*` took 20 s):
            # a short word is matched exactly, and an explicit short prefix is refused.
            if term.rstrip('"').endswith("*"):
                from sigharvest.query_limits import QueryTooExpensive

                raise QueryTooExpensive(f"The prefix {term} is too short: use at least {MIN_PREFIX} characters before *.")
            return col + '"' + tokens[0] + '"'
    return col + '"' + " ".join(tokens) + '"*' if tokens else None


def fts_query(user: str, aliases: dict[str, str] | None = None) -> tuple[str, str]:
    """Turn free text into a safe FTS5 query. Returns (match, exclude_only).

    Words are prefix matches and ANDed; `"quoted phrases"` stay phrases; `OR` (upper case) between terms or
    parenthesised groups; `-term` or `NOT term` excludes; `field:term` searches one column (title, description,
    tags, logsource, fields, detection, author). A search with only exclusions returns them as `exclude_only`, so
    the caller can search everything except those. Every user term is quoted, so FTS syntax cannot be injected.
    """
    out: list[str] = []
    negatives: list[str] = []
    negate_next = False
    for raw in _TERM.findall(user):
        if raw == "(":
            if out and out[-1] not in ("(", "OR", "AND"):
                out.append("AND")
            out.append("(")
            continue
        if raw == ")":
            while out and out[-1] in ("AND", "OR"):
                out.pop()
            if out and out[-1] == "(":
                out.pop()  # empty group
            elif out.count("(") > out.count(")"):
                out.append(")")
            continue
        if raw == "OR":
            if out and out[-1] not in ("(", "OR", "AND"):
                out.append("OR")
            continue
        if raw == "AND":
            continue
        if raw == "NOT":
            negate_next = True
            continue
        dash = raw.startswith("-") and len(raw) > 1
        term = raw[1:] if dash else raw
        expr = (aliases or {}).get(term) or _phrase(term)
        neg = negate_next or dash
        negate_next = False
        if expr is None:
            continue
        if neg:
            negatives.append(expr)
            continue
        if out and out[-1] not in ("(", "OR", "AND"):
            out.append("AND")
        out.append(expr)
    while out and out[-1] in ("AND", "OR", "("):
        out.pop()
        while out and out[-1] in ("AND", "OR"):
            out.pop()
    out += [")"] * (out.count("(") - out.count(")"))
    if "OR" not in out and "(" not in out:
        # Only ANDed terms: a repeated term changes nothing but costs a full posting-list pass each time.
        unique = list(dict.fromkeys(x for x in out if x != "AND"))
        out = [part for i, x in enumerate(unique) for part in ((["AND"] if i else []) + [x])]
    negatives = list(dict.fromkeys(negatives))
    positive = " ".join(out)
    if not positive:
        return "", " OR ".join(negatives)
    if not negatives:
        return positive, ""
    # FTS5 binds NOT tighter than OR: "a OR b NOT c" would mean "a OR (b NOT c)". Group the positive part so every
    # exclusion applies to the whole search.
    return "(" + positive + ")" + "".join(f" NOT {n}" for n in negatives), ""


@dataclass
class GroupFilters:
    new_since_run: str | None = None
    technique: str | None = None  # ATT&CK technique id from rule tags; a parent also matches its sub-techniques
    tactic: str | None = None  # ATT&CK tactic name from rule tags (execution, credential-access...)
    license: str | None = None  # licence declared by the canonical rule document
    hide_flagged: bool = False
    product: str | None = None
    category: str | None = None
    service: str | None = None
    level: str | None = None
    status: str | None = None
    tag: str | None = None
    source: str | None = None  # comma-separated union, exact repository names
    # The copy that is shipped (exports): canonical source among these names, and the canonical document's own
    # `license:` field (lowercase) not among these. Set by cli.common.with_licence_class(shipped=True).
    canonical_source: tuple[str, ...] | None = None
    exclude_rule_licence: tuple[str, ...] | None = None
    exclude_source: str | None = None
    source_only: bool = False
    datasource: str | None = None
    collection: str | None = None
    validation: str | None = None
    backend: str | None = None
    min_sources: int | None = None
    include_deprecated: bool = False
    coverage_tags: str | None = None
    include_junk: bool = False  # show synthetic, fixture, foreign-query... rules (quality.py)
    flag: str | None = None  # one quality flag, e.g. ioc_list
    profile: str | None = None  # SigmaHQ release package: core, core+, core++, emerging-threats, all (profiles.py)


def explicit_status(value: str | None, statuses: tuple[str, ...]) -> bool:
    """An explicit status filter for a hidden-by-default status overrides the default exclusion."""
    return bool(value) and any((norm.status(v) or v) in statuses for v in _choices(str(value)))


def _like_literal(value: str) -> str:
    """Escape LIKE wildcards so a filter value matches itself only; pair with ESCAPE '\\'."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _choices(value: str) -> list[str]:
    return [v.strip().lower() for v in value.split(",") if v.strip()][:100]


def _base(
    query: str | None,
    f: GroupFilters,
    skip: str | None = None,
    *,
    session: Session | None = None,
    predicates: list[tuple[str, str]] | None = None,
    source_projection: bool = True,
) -> tuple[str, str, dict[str, Any]]:
    """FROM/WHERE clause, relevance expression and parameters for a search. `skip` leaves one filter column out
    (used for facet counts, so a facet shows the alternatives to its own current value)."""
    where: list[str] = []

    def add(name: str, clause: str) -> None:
        where.append(clause)
        if predicates is not None:
            predicates.append((name, clause))

    if f.new_since_run:
        run = "SELECT max(started_at) FROM update_runs" if f.new_since_run == "latest" else "SELECT started_at FROM update_runs WHERE id=:new_run"
        add("new_since_run", "g.canonical_version_id IN (SELECT id FROM rule_versions WHERE first_seen >= (" + run + "))")  # noqa: S608 - fixed SQL
    params: dict[str, Any] = {"new_run": f.new_since_run}
    if query:
        query, inline = parse_query(query)
        if inline:
            from dataclasses import replace

            key = inline.pop("id", None)
            extra: dict[str, Any] = {k: v for k, v in inline.items() if hasattr(f, k) and not getattr(f, k)}
            f = replace(f, **extra)
            if key:
                add("id", "(g.rule_id LIKE :key OR g.logic_hash LIKE :key)")
                params["key"] = re.sub(r"[^0-9a-f-]", "", key.lower()) + "%"
    if f.technique and skip != "technique":
        from sigharvest.attack import normalise_technique

        wanted = []
        for choice in _choices(f.technique):
            identity = normalise_technique(choice)
            tid = ((identity.original_id or choice) if identity.domain == "enterprise" else choice).lower()
            wanted.append("attack." + tid.removeprefix("attack."))
        add(
            "technique",
            "EXISTS (SELECT 1 FROM json_each(g.tags) t JOIN json_each(:technique) w ON lower(t.value) = w.value OR lower(t.value) LIKE w.value || '.%')",
        )
        params["technique"] = json.dumps(wanted)
    if f.tactic and skip != "tactic":
        add("tactic", "EXISTS (SELECT 1 FROM json_each(g.tags) t JOIN json_each(:tactic) w ON lower(replace(t.value, '_', '-')) = w.value)")
        params["tactic"] = json.dumps(["attack." + c.removeprefix("attack.").replace("_", "-").replace(" ", "-") for c in _choices(f.tactic)])
    if f.license and skip != "license":
        add("license", "lower(coalesce((SELECT v.rule_license FROM rule_versions v WHERE v.id = g.canonical_version_id), '')) = :license")
        params["license"] = f.license.lower()
    if f.hide_flagged and skip != "hide_flagged":
        add("hide_flagged", "NOT EXISTS (SELECT 1 FROM json_each(g.quality_flags))")
    fix = {"product": norm.product, "category": norm.category, "service": norm.service, "level": norm.level, "status": norm.status}
    for col in ("product", "category", "service", "level", "status", "validation"):
        val = getattr(f, col)
        if val and col != skip:
            # A comma list is a union: --level high,critical (CLI), level=high&level=critical (web), level:a OR level:b.
            values = list(dict.fromkeys((fix[col](v) if col in fix else None) or v.lower() for v in _choices(val)))
            if len(values) == 1:
                add(col, f"g.{col} = :{col}")
                params[col] = values[0]
            elif values:
                add(col, f"g.{col} IN (SELECT value FROM json_each(:{col}))")  # noqa: S608 - col is from a fixed tuple
                params[col] = json.dumps(values)
    if f.coverage_tags:
        add("coverage_tags", "EXISTS (SELECT 1 FROM json_each(g.tags) t JOIN json_each(:coverage_tags) wanted ON lower(t.value)=wanted.value)")
        params["coverage_tags"] = json.dumps(["attack." + t.lower() for t in f.coverage_tags.split(",")[:1000]])
    if f.tag:
        add("tag", "lower(g.tags) LIKE :tag ESCAPE '\\'")
        params["tag"] = f'%"{_like_literal(norm.tag(f.tag) or f.tag.lower())}%'
    if f.source and skip != "source":
        from sigharvest.search_summary import source_members

        members = source_members(session, f.source) if session is not None and source_projection else None
        if members is not None:
            add("source", "g.id IN (SELECT value FROM json_each(:source_members))")
            params["source_members"] = json.dumps(members)
        else:
            add("source", "EXISTS (SELECT 1 FROM json_each(g.sources) r JOIN json_each(:source) selected ON r.value = selected.value)")
            params["source"] = json.dumps([v.strip() for v in f.source.split(",") if v.strip()])
    if f.canonical_source is not None:
        add("canonical_source", "g.canonical_source IN (SELECT value FROM json_each(:canonical_source))")
        params["canonical_source"] = json.dumps(list(f.canonical_source))
    if f.exclude_rule_licence:
        add(
            "exclude_rule_licence",
            "lower(coalesce((SELECT v.rule_license FROM rule_versions v WHERE v.id = g.canonical_version_id), '')) "
            "NOT IN (SELECT value FROM json_each(:exclude_rule_licence))",
        )
        params["exclude_rule_licence"] = json.dumps(list(f.exclude_rule_licence))
    if f.source_only:
        add("source_only", "g.n_sources = 1")
    if f.exclude_source:
        add("exclude_source", "NOT EXISTS (SELECT 1 FROM json_each(g.sources) r JOIN json_each(:exclude_source) excluded ON r.value = excluded.value)")
        params["exclude_source"] = json.dumps([v.strip() for v in f.exclude_source.split(",") if v.strip()])
    if f.datasource and skip != "datasource":
        add("datasource", "EXISTS (SELECT 1 FROM json_each(g.datasources) d WHERE lower(d.value) = :datasource)")
        params["datasource"] = datasource_key(f.datasource)
    if f.collection:
        add(
            "collection",
            """g.logic_hash IN (
            SELECT coalesce(
                (SELECT old.logic_hash FROM logic_groups old WHERE old.logic_hash = ci.logic_hash),
                (SELECT updated.logic_hash FROM logic_groups updated WHERE updated.rule_id = ci.rule_id ORDER BY updated.score DESC LIMIT 1)
            ) FROM collection_items ci JOIN collections c ON c.id = ci.collection_id WHERE c.name = :collection
        )""",
        )
        params["collection"] = f.collection
    if f.backend and skip != "backend":
        add("backend", "g.converts LIKE :backend ESCAPE '\\'")
        params["backend"] = f'%"{_like_literal(f.backend)}"%'
    if f.profile and skip != "profile":
        from sigharvest import profiles

        add("profile", profiles.where(profiles.resolve(f.profile)))
    if f.min_sources:
        add("min_sources", "g.n_sources >= :min_sources")
        params["min_sources"] = f.min_sources
    if not f.include_deprecated and skip != "status" and not explicit_status(f.status, ("deprecated", "unsupported")):
        add("deprecated", "coalesce(g.status, '') NOT IN ('deprecated', 'unsupported')")
    if f.flag:
        add("flag", "g.quality_flags LIKE :flag ESCAPE '\\'")
        params["flag"] = f'%"{_like_literal(f.flag)}"%'
    elif not f.include_junk:
        add("junk", "g.junk = 0")
    aliases: dict[str, str] = {}
    if query and session is not None:
        from sigharvest.attack_search import prepare

        query, aliases, _ = prepare(session, query)
    match, exclude = fts_query(query, aliases) if query else ("", "")
    if match:
        params["match"] = match
        if predicates is not None:
            predicates.append(("query", "g.id IN (SELECT rowid FROM rules_fts WHERE rules_fts MATCH :match)"))
        # CROSS JOIN keeps SQLite from reordering: the full-text match runs first, then the (indexed) group lookup.
        base = "FROM rules_fts CROSS JOIN logic_groups g ON g.id = rules_fts.rowid WHERE rules_fts MATCH :match"
        from sigharvest.title_relevance import rank_sql

        rank, title_params = rank_sql(query or "", FTS_WEIGHTS)
        params.update(title_params)
    else:
        base = "FROM logic_groups g WHERE 1=1"
        rank = "-g.score"
        if exclude:
            add("query", "g.id NOT IN (SELECT rowid FROM rules_fts WHERE rules_fts MATCH :exclude)")
            params["exclude"] = exclude
    if where:
        base += " AND " + " AND ".join(where)
    return base, rank, params


def selection_sql(base: str, rank: str, sort: str, per_family: bool, local_score: str, *, stable: bool = False) -> str:
    """Authoritative live ordering/collapse SQL, shared with exact-rule diagnostics."""
    rank = rank.replace("g.score", local_score)
    order = {
        "relevance": rank,
        "score": "-g.score",
        "level": "CASE g.level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
        "sources": "-g.n_sources, -g.score",
        "title": "g.title",
        "modified": "g.modified DESC",
    }.get(sort, rank)
    if sort in {"score", "sources"}:
        order = order.replace("g.score", local_score)
    # Only fixed SQL fragments and bound parameters are interpolated below (no user text).
    if per_family:
        # One pass: the best group of each family is the row holding min(key) (SQLite returns the other bare
        # columns from that row), and the number of families comes from the same query.
        key = {
            "score": "-g.score",
            "level": "CASE g.level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
            "sources": "-(g.n_sources * 1000 + g.score)",
            "title": "g.title",
            "modified": "g.modified",
        }.get(sort, rank)
        if sort in {"score", "sources"}:
            key = key.replace("g.score", local_score)
        if stable:
            # Hunt sets must choose the same exact member as strict traversal.
            # Materialize the scalar rank before windowing (FTS5 requirement).
            if sort == "sources":
                key = "-g.n_sources"
            secondary = f", -{local_score} AS secondary" if sort == "sources" else ""
            ordering = "k DESC NULLS LAST" if sort == "modified" else "k ASC NULLS FIRST"
            ordering += (", secondary ASC NULLS FIRST" if sort == "sources" else "") + ", logic_hash ASC"
            return (
                f"WITH keyed AS MATERIALIZED (SELECT g.id, g.logic_hash, g.family_id, {key} AS k{secondary} {base}), "  # noqa: S608
                f"numbered AS (SELECT *, row_number() OVER (PARTITION BY family_id ORDER BY {ordering}) AS n FROM keyed) "
                f"SELECT id, count(*) OVER () FROM numbered WHERE n=1 ORDER BY {ordering} LIMIT :lim OFFSET :off"
            )
        agg = "max" if sort == "modified" else "min"
        # MATERIALIZED: bm25() is only allowed in the full-text query itself, not inside the aggregate.
        direction = "DESC" if sort == "modified" else "ASC"
        sql = (
            f"WITH keyed AS MATERIALIZED (SELECT g.id AS id, g.family_id AS fam, {key} AS key {base}), "  # noqa: S608
            f"best AS (SELECT id, {agg}(key) AS k FROM keyed GROUP BY fam) "
            f"SELECT id, count(*) OVER () FROM best ORDER BY k {direction}, id LIMIT :lim OFFSET :off"
        )
        return sql
    # Title ties also back published source pages; row IDs change on full rebuild.
    if stable or sort == "title":
        order += ", g.logic_hash ASC"
    return f"SELECT g.id {base} ORDER BY {order} LIMIT :lim OFFSET :off"


def search_selection(s: Session, query: str | None, f: GroupFilters, sort: str, per_family: bool) -> tuple[str, dict[str, Any], str]:
    """Build exactly the live selection, including revision-checked projections."""
    base, rank, params = _base(query, f, session=s)
    from sigharvest.search_summary import compact_base

    if sort in {"relevance", "score"}:
        base, _compact = compact_base(s, base, query, f)
    sql = selection_sql(base, rank, sort, per_family, "g.score")
    return sql, params, base


def search_groups(
    s: Session,
    query: str | None,
    f: GroupFilters,
    limit: int = 50,
    offset: int = 0,
    sort: str = "relevance",
    per_family: bool = False,
    *,
    display_only: bool = False,
) -> tuple[list[LogicGroup], int]:
    """Search logic groups. With per_family, only the best-ranked group of each family is returned."""
    sql, params, base = search_selection(s, query, f, sort, per_family)
    rows = list(s.execute(text(sql), {**params, "lim": limit, "off": offset}))
    ids = [r[0] for r in rows]
    if per_family:
        total = rows[0][1] if rows else s.execute(text(f"SELECT count(DISTINCT g.family_id) {base}"), params).scalar_one()
    else:
        total = s.execute(text(f"SELECT count(*) {base}"), params).scalar_one()
    selected = select(LogicGroup).where(LogicGroup.id.in_(ids))
    if display_only:
        from sqlalchemy.orm import load_only

        from sigharvest.search_summary import CARD_FIELDS

        selected = selected.options(load_only(*(getattr(LogicGroup, name) for name in (*CARD_FIELDS, "conversion", "converts")), raiseload=True))
    by_id = {g.id: g for g in s.scalars(selected)}
    return [by_id[i] for i in ids if i in by_id], int(total)


def match_counts(s: Session, query: str | None, f: GroupFilters) -> tuple[int, int]:
    """(unique rules, rule families) a search matches: the CLI lists families and the web UI rules by default, so
    both print the two numbers."""
    base, _rank, params = _base(query, f, session=s)
    rules, families = s.execute(text(f"SELECT count(*), count(DISTINCT g.family_id) {base}"), params).one()
    return int(rules), int(families)


HIDDEN_BY_DEFAULT = "deprecated/unsupported and junk rules (test fixtures, synthetic, wrapped queries) are hidden by default"


_FACET_MATCHES: ContextVar[dict[str, str] | None] = ContextVar("facet_matches", default=None)


@contextmanager
def shared_matches() -> Iterator[None]:
    """Compute many facets from one evaluation of each distinct search predicate.

    Facets usually share one WHERE clause (only a facet with its own filter set
    differs). Inside this block the matching ids are selected once per distinct
    clause, in the caller's read transaction, and each facet groups only those rows.
    """
    token = _FACET_MATCHES.set({})
    try:
        yield
    finally:
        _FACET_MATCHES.reset(token)


FACET_COLUMNS = {
    "product",
    "category",
    "service",
    "level",
    "status",
    "validation",
    "datasource",
    "source",
    "technique",
    "tactic",
}


# Facets whose values come from the JSON `tags` array: (tag prefix filter, value expression).
_TAG_FACETS = {
    "technique": "lower(t.value) GLOB 'attack.t[0-9]*'",
    "tactic": "lower(t.value) GLOB 'attack.[a-z]*' AND lower(t.value) NOT GLOB 'attack.t[0-9]*' AND lower(t.value) NOT GLOB 'attack.g[0-9]*' "
    "AND lower(t.value) NOT GLOB 'attack.s[0-9]*'",
}


def _json_values(column: str, raw: Any) -> list[str]:
    values = json.loads(raw) if isinstance(raw, str) else raw or []
    if column == "technique":
        return list({v.lower()[7:].upper() for v in values if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", str(v).lower())})
    if column == "tactic":
        return list({v.lower()[7:] for v in values if re.fullmatch(r"attack\.[a-z][a-z_-]+", str(v).lower())})
    return list(set(values))


def scalar_facets(s: Session, query: str | None, filters: GroupFilters, per_family: bool, limits: dict[str, int]) -> dict[str, list[tuple[str, int]]]:
    """`facets()` for every requested column, from one scan per distinct facet WHERE clause."""
    json_columns = {"source": "g.sources", "datasource": "g.datasources", "technique": "g.tags", "tactic": "g.tags"}
    groups: dict[str, tuple[str, dict[str, Any], list[str]]] = {}
    for column in limits:
        if column not in FACET_COLUMNS:
            raise ValueError(column)
        base, _, params = _base(query, filters, skip=column, session=s)
        key = base + "\0" + json.dumps(params, sort_keys=True, default=str)
        groups.setdefault(key, (base, params, []))[2].append(column)
    result: dict[str, list[tuple[str, int]]] = {}
    for base, params, columns in groups.values():
        selected = [json_columns.get(column, f"g.{column}") for column in columns]
        units: dict[str, dict[Any, set[int] | int]] = {column: {} for column in columns}
        # Fixed SQL fragments only; all values are bound.
        rows = s.execute(text(f"SELECT g.id, g.family_id, {', '.join(selected)} {base}"), params)
        for row in rows:
            unit = row[1] if per_family else row[0]
            for position, column in enumerate(columns, start=2):
                acc = units[column]
                values = _json_values(column, row[position]) if column in json_columns else [row[position]]
                for value in values:
                    if value in (None, ""):
                        continue
                    if per_family:
                        acc.setdefault(value, set()).add(unit)  # type: ignore[union-attr]
                    else:
                        acc[value] = acc.get(value, 0) + 1  # type: ignore[operator]
        for column in columns:
            counted = [(value, len(n) if isinstance(n, set) else n) for value, n in units[column].items()]
            result[column] = sorted(counted, key=lambda item: (-item[1], item[0]))[: limits[column]]
    return result


def facets(
    s: Session, column: str, limit: int = 30, query: str | None = None, f: GroupFilters | None = None, per_family: bool = False
) -> list[tuple[str, int]]:
    """Counts per value of one column for the current search (that column's own filter is left out)."""
    if column not in FACET_COLUMNS:
        raise ValueError(column)
    return scalar_facets(s, query, f or GroupFilters(include_deprecated=True), per_family, {column: limit})[column]


def group_for(s: Session, key: str) -> LogicGroup | None:
    key = key.strip().lower()
    q = select(LogicGroup).where((LogicGroup.logic_hash.startswith(key)) | (LogicGroup.rule_id.startswith(key)))
    g = s.scalars(q.limit(1)).first()
    if g is None and len(key) >= 8:
        v = s.scalars(select(RuleVersion).where(RuleVersion.content_hash.startswith(key) | RuleVersion.rule_id.startswith(key)).limit(1)).first()
        if v is not None:
            g = s.scalars(select(LogicGroup).where(LogicGroup.logic_hash == v.logic_hash)).first()
    return g
