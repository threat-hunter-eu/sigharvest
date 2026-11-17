"""Read-side queries: search, show, diff, dedupe and export."""

from __future__ import annotations

import difflib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import Select, String, cast, func, or_, select
from sqlalchemy.orm import Session

from sigharvest.export_policy import provenance
from sigharvest.identity import utf8
from sigharvest.models import Occurrence, RuleVersion, Source, TestResult


def live_version_ids() -> Select[Any]:
    """Subquery: ids of rule versions with at least one present occurrence (the live corpus)."""
    return select(Occurrence.version_id).where(Occurrence.present.is_(True)).distinct()


@dataclass
class Filters:
    """Filters for the per-copy queries below (rule versions, not logic groups); None means any."""

    rule_id: str | None = None
    title: str | None = None
    product: str | None = None
    category: str | None = None
    service: str | None = None
    tag: str | None = None
    author: str | None = None
    source: str | None = None
    status: str | None = None
    level: str | None = None
    text: str | None = None
    include_deprecated: bool = True


def search(s: Session, f: Filters, limit: int | None = 100) -> list[RuleVersion]:
    """Live rule versions matching the filters (every copy, not one per logic), by title; limit None = all."""
    q = version_query(f)
    if limit:
        q = q.limit(limit)
    return list(s.scalars(q))


def version_query(f: Filters, *, live: bool = True) -> Select[RuleVersion]:
    """Document predicates; live=False requires the caller's scoped current-occurrence gate."""
    q = select(RuleVersion)
    if live:
        q = q.where(RuleVersion.id.in_(live_version_ids()))
    if f.rule_id:
        q = q.where(RuleVersion.rule_id.startswith(f.rule_id.lower()))
    if f.title:
        q = q.where(RuleVersion.title.ilike(f"%{f.title}%"))
    # A comma list is a union, as in search: --status test,deprecated, --source a,b.
    for col, val in (
        (RuleVersion.product, f.product),
        (RuleVersion.category, f.category),
        (RuleVersion.service, f.service),
        (RuleVersion.status, f.status),
        (RuleVersion.level, f.level),
    ):
        if val:
            q = q.where(col.in_(_values(val)))
    if f.author:
        q = q.where(RuleVersion.author.ilike(f"%{f.author}%"))
    if f.tag:
        q = q.where(func.lower(cast(RuleVersion.tags, String)).like(f'%"{f.tag.lower()}"%'))
    if f.text:
        q = q.where(RuleVersion.raw.ilike(f"%{f.text}%"))
    if f.source:
        q = q.where(
            RuleVersion.id.in_(
                select(Occurrence.version_id)
                .join(Source, Source.id == Occurrence.source_id)
                .where(Source.name.in_(_values(f.source, lower=False)), Occurrence.present.is_(True))
            )
        )
    if not f.include_deprecated and not explicitly_deprecated(f.status):
        q = q.where(or_(RuleVersion.status.is_(None), RuleVersion.status != "deprecated"))
    return q.order_by(RuleVersion.title, RuleVersion.id)


def _values(value: str, *, lower: bool = True) -> list[str]:
    return [v.strip().lower() if lower else v.strip() for v in value.split(",") if v.strip()][:100]


def explicitly_deprecated(status: str | None) -> bool:
    """An explicit --status deprecated/unsupported overrides the default exclusion (as in search)."""
    return bool(status) and any(v in ("deprecated", "unsupported") for v in _values(str(status)))


def resolve(s: Session, key: str) -> list[RuleVersion]:
    """Find versions by rule id, content hash or logic hash (full or prefix of at least 8 chars)."""
    key = key.strip().lower()
    if len(key) < 8:
        return []
    q = select(RuleVersion).where(or_(RuleVersion.rule_id.startswith(key), RuleVersion.content_hash.startswith(key), RuleVersion.logic_hash.startswith(key)))
    return list(s.scalars(q.order_by(RuleVersion.first_seen, RuleVersion.id)))


def versions_of(s: Session, rule_id: str) -> list[RuleVersion]:
    """Local version numbers follow registration order, even when the clock moves back."""
    return list(s.scalars(select(RuleVersion).where(RuleVersion.rule_id == rule_id).order_by(RuleVersion.id)))


def occurrences(s: Session, version_ids: list[int]) -> list[tuple[Occurrence, Source]]:
    """Where the given versions were found: (occurrence, source) pairs, present or not."""
    rows = s.execute(select(Occurrence, Source).join(Source, Source.id == Occurrence.source_id).where(Occurrence.version_id.in_(version_ids)))
    return [(o, src) for o, src in rows]


def results(s: Session, version_id: int) -> list[TestResult]:
    """Stored test results of one rule version."""
    return list(s.scalars(select(TestResult).where(TestResult.version_id == version_id).order_by(TestResult.stage, TestResult.target)))


def diff_versions(a: RuleVersion, b: RuleVersion) -> str:
    """Unified diff between the YAML of two versions."""
    return "".join(
        difflib.unified_diff(
            a.raw.splitlines(keepends=True),
            b.raw.splitlines(keepends=True),
            fromfile=f"{a.rule_id} {a.content_hash[:12]}",
            tofile=f"{b.rule_id} {b.content_hash[:12]}",
        )
    )


# ----------------------------------------------------------------------------- dedupe


@dataclass
class DedupeReport:
    """Counts and examples of duplication in the live corpus (`sigharvest dedupe`, reports/summary.md)."""

    live_documents: int = 0
    unique_contents: int = 0
    unique_rule_ids: int = 0
    unique_logic: int = 0
    logic_groups: list[dict[str, Any]] = field(default_factory=list)
    id_conflicts: list[dict[str, Any]] = field(default_factory=list)
    exact_copies: int = 0
    exact_copy_groups: int = 0
    title_groups: list[dict[str, Any]] = field(default_factory=list)


def dedupe(s: Session, *, top: int | None = None) -> DedupeReport:
    """Compute exact duplication totals, optionally limiting logic examples."""
    if top is not None:
        from sigharvest.dedupe_preview import compute

        return compute(s, top)
    rows = s.execute(
        select(
            RuleVersion.id,
            RuleVersion.rule_id,
            RuleVersion.logic_hash,
            RuleVersion.content_hash,
            RuleVersion.title,
            RuleVersion.title_slug,
            Source.name,
            Source.priority,
            Occurrence.path,
            Occurrence.first_seen,
        )
        .join(Occurrence, Occurrence.version_id == RuleVersion.id)
        .join(Source, Source.id == Occurrence.source_id)
        .where(Occurrence.present.is_(True))
    ).all()
    rep = DedupeReport(live_documents=len(rows))
    rep.unique_contents = len({r.content_hash for r in rows})
    rep.unique_rule_ids = len({r.rule_id for r in rows})
    rep.unique_logic = len({r.logic_hash for r in rows})

    by_logic: dict[str, list[Any]] = defaultdict(list)
    by_content: dict[str, list[Any]] = defaultdict(list)
    by_id_logic: dict[str, set[str]] = defaultdict(set)
    by_slug: dict[str, set[str]] = defaultdict(set)
    by_id_rows: dict[str, list[Any]] = defaultdict(list)
    for r in rows:
        by_id_rows[r.rule_id].append(r)
        by_logic[r.logic_hash].append(r)
        by_content[r.content_hash].append(r)
        by_id_logic[r.rule_id].add(r.logic_hash)
        if r.title_slug:
            by_slug[r.title_slug].add(r.logic_hash)

    for lh, items in by_logic.items():
        if len(items) < 2:
            continue
        items.sort(key=lambda r: (r.priority, r.name, r.content_hash, r.path))
        canon = items[0]
        rep.logic_groups.append(
            {
                "logic_hash": lh,
                "copies": len(items),
                "sources": sorted({i.name for i in items}),
                "rule_ids": sorted({i.rule_id for i in items}),
                "canonical": {"source": canon.name, "path": canon.path, "rule_id": canon.rule_id, "title": canon.title},
            }
        )
    rep.logic_groups.sort(key=lambda g: -g["copies"])
    for items in by_content.values():
        if len(items) > 1:
            rep.exact_copy_groups += 1
            rep.exact_copies += len(items) - 1
    for rid, logics in by_id_logic.items():
        if len(logics) > 1:
            locs = by_id_rows[rid]
            rep.id_conflicts.append({"rule_id": rid, "logic_variants": len(logics), "sources": sorted({r.name for r in locs}), "title": locs[0].title})
    rep.id_conflicts.sort(key=lambda g: -g["logic_variants"])
    for slug, logics in by_slug.items():
        if len(logics) > 1:
            rep.title_groups.append({"title_slug": slug, "logic_variants": len(logics)})
    rep.title_groups.sort(key=lambda g: -g["logic_variants"])
    return rep


# ----------------------------------------------------------------------------- export


def export_sigma(s: Session, versions: list[RuleVersion], out: Path, *, jsonl: bool = False) -> int:
    """Write each version with provenance as a YAML tree or JSONL. Return the rule count."""
    from sigharvest.export import EXPORT_NOTICE
    from sigharvest.export_policy import attribution_markdown, exact_origins

    root = out.parent if jsonl else out
    root.mkdir(parents=True, exist_ok=True)
    origins = provenance(s, versions)
    exact = exact_origins(s, versions)
    credits: list[dict[str, Any]] = []
    with (out if jsonl else out / "manifest.jsonl").open("w", encoding="utf-8") as manifest:
        for v in versions:
            # Stored rule IDs are normalized UUIDs (including generated fallbacks).
            name = f"{v.rule_id}_{v.content_hash[:8]}.yml"
            meta = (
                {
                    "rule_id": v.rule_id,
                    "logic_hash": v.logic_hash,
                    "content_hash": v.content_hash,
                    "title": v.title,
                }
                | origins[v.id]
                | exact[v.id]
            )
            credits.append(meta)
            if jsonl:
                meta["yaml"] = v.raw
            else:
                (out / name).write_bytes(utf8(v.raw))
                meta["path"] = name
            manifest.write(json.dumps(meta, ensure_ascii=False) + "\n")
    if not jsonl:
        (out / "NOTICE.md").write_text(EXPORT_NOTICE, encoding="utf-8")
        (out / "ATTRIBUTION.md").write_text(attribution_markdown(credits), encoding="utf-8")
    return len(versions)


@dataclass
class ExportReport:
    """What an export to a backend did with each rule. Only `ok` queries are written unless raw/warnings are allowed."""

    target: str
    out: Path
    sidecar: Path
    counts: dict[str, int] = field(default_factory=dict)  # per conversion status (plus "correlation": how many were correlations)
    written: int = 0
    selected: int = 0
    not_written: dict[str, int] = field(default_factory=dict)  # per status, the rules left out of the query file

    # Why a rule with this status is not in the query file.
    WHY = {
        "partial": "need fields the chosen log source does not have (partial)",
        "warning": "failed a sanity check (--allow-warnings writes them)",
        "raw": "syntax-only, Sigma field names (--allow-raw writes them)",
        "unsupported": "log source not supported by the target",
        "correlation_unsupported": "correlations the target cannot convert, or whose rules are not selected",
        "error": "conversion error",
        "timeout": "conversion timed out",
        "resource_failure": "too large (worker memory cap; --retry-resource-failures)",
        "skipped": "skipped (parse errors, filters)",
    }

    def summary(self) -> str:
        """One line: how many were selected, written and left out (and why), e.g. "1,430 selected -> 1,067 written
        for splunk; 363 not written: 360 need fields ..., 1 conversion error, ..."."""
        selected = self.selected or sum(n for k, n in self.counts.items() if k != "correlation")
        out = f"{selected:,} selected -> {self.written:,} written for {self.target}"
        missing = sum(self.not_written.values())
        if missing:
            ordered = sorted(self.not_written.items(), key=lambda kv: (-kv[1], kv[0]))
            out += f"; {missing:,} not written: " + ", ".join(f"{n:,} {self.WHY.get(k, k)}" for k, n in ordered if n)
        return out


QUERY_NOTICE = """# Notice

The queries in {name} were converted from Sigma rules written by the authors of their source repositories; each
rule keeps its own licence. Every query is preceded by an `# attribution:` line (title, author, source, licence,
link to the original), and {name}.ATTRIBUTION.md lists the same for every rule. Rules under the Detection Rule
License (DRL) 1.1, such as SigmaHQ's, require that you keep the author and reference attribution also in converted
queries: keep those lines when you paste the queries into your SIEM. Check each rule's licence before
redistributing it.

Converted with sigharvest (MIT licence) and pySigma.
"""


def export_backend(
    versions: list[RuleVersion],
    target: str,
    out: Path,
    s: Session | None = None,
    allow_raw: bool = False,
    allow_warnings: bool = False,
    source: str = "all",
    *,
    provenance_by_logic: bool = False,
    details: bool = True,
    converter: Any = None,
) -> ExportReport:
    """Convert rules for one backend into one file. `ok` queries are always written; raw (syntax only, Sigma field
    names) only with allow_raw, and queries that failed a sanity check only with allow_warnings. Every rule that is
    not written as ok is listed with the reason in `<out>.conversion.jsonl`. Correlations are converted together with
    the rules they reference when those are in the same file (needs `s`) and the backend supports correlations."""
    import json

    from sigharvest import conversion
    from sigharvest.datasources import select_sources
    from sigharvest.export_policy import attribution_line, attribution_markdown, exact_origins
    from sigharvest.testing import siblings

    select_sources([], [source])
    origins = provenance(s, versions, by_logic=provenance_by_logic)
    exact = exact_origins(s, versions)
    credits: list[dict[str, Any]] = []
    rep = ExportReport(target, out, out.with_name(out.name + ".conversion.jsonl"))
    counts: dict[str, int] = defaultdict(int)
    sib = siblings(s, [v.id for v in versions if v.kind == "correlation"]) if s is not None else {}
    lines: list[str] = []
    side: list[str] = []
    manifest: list[str] = []
    for v in versions:
        conv = (converter or conversion.convert_cached)(v.raw, target, kind=v.kind, siblings=sib.get(v.id, []), sources=[source])
        counts[conv.status] += 1
        if v.kind == "correlation":
            counts["correlation"] += 1
        title = " ".join(str(v.title or "").split())  # a title with line breaks must not add query lines
        selected = exportable_conversions(conv, allow_raw=allow_raw, allow_warnings=allow_warnings)
        write = bool(selected)
        metadata = (
            {
                "rule_id": v.rule_id,
                "logic_hash": v.logic_hash,
                "content_hash": v.content_hash,
                "title": v.title,
            }
            | origins[v.id]
            | exact[v.id]
        )
        manifest.append(json.dumps(metadata | {"written": write, "status": conv.status}, ensure_ascii=False))
        rep.selected += 1
        if not write:
            rep.not_written[conv.status] = rep.not_written.get(conv.status, 0) + 1
        # DRL 1.1 and similar licences require the author and a reference to the original rule to travel with
        # every converted query: one attribution comment per written rule.
        credit = "# attribution: " + attribution_line(
            v.title, metadata["author"], metadata["source"], metadata["licence"], metadata["source_url"] or metadata["source_path"]
        )
        if write:
            credits.append(metadata)
            if source == "combined" and conv.combined_query:
                head = f"# {title} | id={v.rule_id} | logic={v.logic_hash[:12]} | sources={','.join(conv.combined_sources)}"
                lines.append(f"{head}\n{credit}\n{conv.combined_query}\n")
            else:
                for r in selected:
                    head = f"# {title} | id={v.rule_id} | logic={v.logic_hash[:12]} | source={r.source} | {r.pipeline_line}\n{credit}"
                    if r.status == "warning":
                        head += "\n# WARNING: " + " | ".join(" ".join(w.split()) for w in r.warnings)
                    lines += [f"{head}\n{q}\n" for q in r.queries]
            rep.written += 1
        if conv.status != "ok" or any(r.status != "ok" for r in conv.results):
            item: dict[str, Any] = {
                "rule_id": v.rule_id,
                "logic_hash": v.logic_hash,
                "title": v.title,
                "kind": v.kind,
                "status": conv.status,
                "written": write,
            }
            item |= metadata
            item |= {k: val for k, val in (("reason", conv.reason), ("error", conv.error), ("warnings", conv.warnings)) if val}
            item["pipeline"] = conv.pipeline
            item["results"] = [r.payload() for r in conv.results]
            item["covered_sources"] = conv.covered_sources
            side.append(json.dumps(item, ensure_ascii=False))
    rep.counts = dict(counts)
    out.parent.mkdir(parents=True, exist_ok=True)
    header = f"# sigharvest export for {target}: {rep.summary()}\n# toolchain: {conversion.toolchain(target)}\n"
    if details:
        header += f"# details: {rep.sidecar.name}\n"
    out.write_text(header + "\n" + "\n".join(lines), encoding="utf-8")
    rep.sidecar.write_text("".join(line + "\n" for line in side), encoding="utf-8")
    out.with_name(out.name + ".manifest.jsonl").write_text("".join(line + "\n" for line in manifest), encoding="utf-8")
    out.with_name(out.name + ".ATTRIBUTION.md").write_text(attribution_markdown(credits), encoding="utf-8")
    out.with_name(out.name + ".NOTICE.md").write_text(QUERY_NOTICE.format(name=out.name), encoding="utf-8")
    return rep


def exportable_conversions(conv: Any, *, allow_raw: bool = False, allow_warnings: bool = False) -> list[Any]:
    """Shared query-export gate, also used by selected tuning conversion receipts."""
    allowed_statuses = {"ok"} | ({"raw"} if allow_raw else set()) | ({"warning"} if allow_warnings else set())
    return [r for r in conv.results if r.status in allowed_statuses and r.queries]
