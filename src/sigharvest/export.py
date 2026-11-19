"""Export the corpus: one rule per family, per unique logic, or every copy; as YAML files, one JSONL file or queries."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from itertools import islice
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from sigharvest.attack import Matrix, session_matrix, tag_metadata
from sigharvest.export_policy import attribution_markdown, provenance
from sigharvest.identity import utf8
from sigharvest.index import GroupFilters, search_groups
from sigharvest.licensing import licence_class, narrows
from sigharvest.models import LogicGroup, RuleVersion, Source

if TYPE_CHECKING:
    from sigharvest.query import ExportReport

EXPORT_NOTICE = """# Notice

These Sigma rules were written by the authors of their source repositories and keep their own licences.
manifest.jsonl lists, for every rule, its sources, licence and canonical copy; ATTRIBUTION.md lists the title,
author, source, licence and a link to the original of every rule. Rules under the Detection Rule License (DRL) 1.1,
such as SigmaHQ's, require that you keep the author and reference attribution when you reuse or convert them.
Check each rule's licence before redistributing it.

Exported with sigharvest (MIT licence).
"""
_SAFE = re.compile(r"[^a-z0-9_-]+")


def _slug(text: str | None, limit: int = 60) -> str:
    return (_SAFE.sub("-", (text or "untitled").lower()).strip("-") or "untitled")[:limit]


def select_groups(s: Session, unit: str, query: str | None, f: GroupFilters, min_score: float | None) -> Iterator[LogicGroup]:
    """Yield the logic groups to export. unit: 'family' (best-ranked per family) or 'logic' (every unique logic)."""
    offset, page = 0, 5000
    while True:
        groups, _ = search_groups(s, query, f, limit=page, offset=offset, sort="score", per_family=(unit == "family"))
        if not groups:
            return
        for g in groups:
            if min_score is None or g.score >= min_score:
                yield g
        offset += page


def _licences(s: Session, configs: dict[str, Any] | None = None) -> dict[str, str | None]:
    """Source licences by name, as sources.yaml states them now (see source_metadata)."""
    from sigharvest.source_metadata import source_licences

    return source_licences(s, configs)


def effective_licence(g: LogicGroup, v: RuleVersion | None, lic: dict[str, str | None]) -> tuple[str | None, str]:
    """(licence, where it comes from) of the exact document that is shipped: the canonical copy `v` from
    g.canonical_source. The source licence decides; the rule's own `license:` field only applies when it is more
    restrictive (rule metadata may narrow a licence, never widen it). The licence of another source carrying the
    same logic is never borrowed: its text is not the text shipped."""
    source = lic.get(g.canonical_source)
    if v is not None and narrows(v.rule_license, source):
        return v.rule_license, "rule"
    if source:
        return source, f"source {g.canonical_source}"
    return None, "none stated"


def _records(s: Session, groups: Iterator[LogicGroup]) -> Iterator[tuple[LogicGroup, RuleVersion, dict[str, Any]]]:
    selected = iter(groups)
    from sigharvest.export_policy import drl_rule_ids, licence_notes

    lic = _licences(s)
    matrix = session_matrix(s)
    metadata_cache: dict[str, dict[str, Any] | None] = {}
    drl = drl_rule_ids(s)
    while batch := list(islice(selected, 500)):
        versions = {v.id: v for v in s.scalars(select(RuleVersion).where(RuleVersion.id.in_([g.canonical_version_id for g in batch])))}
        origins = provenance(s, versions.values(), by_logic=True)
        links = _canonical_links(s, batch)
        for g in batch:
            if v := versions.get(g.canonical_version_id):
                meta = (
                    _meta(g, lic, v, matrix, metadata_cache)
                    | origins[v.id]
                    | {
                        "source": g.canonical_source,
                        "source_url": links.get(g.id, (None, None))[0],
                        "source_path": links.get(g.id, (None, None))[1],
                        "author": v.author,
                    }
                )
                yield g, v, meta | licence_notes(meta, drl)


def _canonical_links(s: Session, groups: list[LogicGroup]) -> dict[int, tuple[str | None, str]]:
    """Link to the canonical copy of each group (GitHub/GitLab sources at the synced commit), by group id."""
    from sigharvest.models import Occurrence
    from sigharvest.sources import file_link

    wanted = {(g.canonical_version_id, g.canonical_source): g.id for g in groups}
    out: dict[int, tuple[str | None, str]] = {}
    rows = s.execute(
        select(Occurrence.version_id, Source.name, Source.url, Occurrence.commit, Occurrence.path)
        .join(Source, Source.id == Occurrence.source_id)
        .where(Occurrence.version_id.in_([g.canonical_version_id for g in groups]), Occurrence.present.is_(True))
        .order_by(Occurrence.path, Occurrence.doc_index)
    )
    for vid, name, url, commit, path in rows:
        gid = wanted.get((vid, name))
        if gid is not None and gid not in out:
            out[gid] = (file_link(url, commit, path), path)
    return out


def export_yaml(s: Session, groups: Iterator[LogicGroup], out: Path, *, with_dependencies: bool = False, include_private: bool = False) -> int:
    """Export the selection, optionally as an atomic, verified dependency closure."""
    if with_dependencies:
        from sigharvest.export_dependencies import export_bundle

        return export_bundle(s, groups, out)
    return _export_yaml(s, groups, out, include_private=include_private)


def _export_yaml(s: Session, groups: Iterator[LogicGroup], out: Path, *, include_private: bool = False) -> int:
    """out/<product>/<category or service>/<title>_<logic8>.yml plus out/manifest.jsonl (provenance and licence).
    Rules the zip would only link (export_zip.skip_reason, every licence class) go to SKIPPED.md instead."""
    from sigharvest.export_zip import PRIVATE_NOTICE, md, redistributable_sources, skip_reason

    out.mkdir(parents=True, exist_ok=True)
    root = out.resolve()
    (out / "NOTICE.md").write_text(EXPORT_NOTICE + (PRIVATE_NOTICE if include_private else ""), encoding="utf-8")
    shippable = redistributable_sources(s)
    skipped: list[str] = []
    n = 0
    credits: list[dict[str, Any]] = []
    with (out / "manifest.jsonl").open("w", encoding="utf-8") as manifest:
        for g, v, meta in _records(s, groups):
            reason = skip_reason(str(meta.get("licence_class") or "none"), g.canonical_source, shippable, "all", include_private)
            if reason:
                link = meta.get("source_url") or ""
                skipped.append(f"- {md(g.title)} ({md(g.canonical_source)}, {reason}){f': <{link}>' if link else ''}")
                continue
            rel = _rel_path(g)
            target = (root / rel).resolve()
            if not target.is_relative_to(root):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(utf8(v.raw))
            manifest.write(json.dumps(meta | {"path": str(rel)}, ensure_ascii=False) + "\n")
            credits.append(meta)
            n += 1
    (out / "ATTRIBUTION.md").write_text(attribution_markdown(credits), encoding="utf-8")
    from sigharvest.licence_texts import for_credits

    notice, licence_files = for_credits(s, credits)
    with (out / "NOTICE.md").open("a", encoding="utf-8") as fh:
        fh.write(notice)
    for name, data in licence_files:
        target = (root / name).resolve()
        if target.is_relative_to(root):
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    if skipped:
        (out / "SKIPPED.md").write_text(
            "# Rules not copied into this export\n\nRead them at their source. Your own rules: add the source with --licence, "
            "or export with --include-private-sources for a private copy.\n\n" + "\n".join(skipped) + "\n",
            encoding="utf-8",
        )
    return n


def _meta(
    g: LogicGroup,
    lic: dict[str, str | None],
    v: RuleVersion | None = None,
    matrix: Matrix | None = None,
    metadata_cache: dict[str, dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    licence, licence_from = effective_licence(g, v, lic)
    return {
        "logic_hash": g.logic_hash,
        "yaml_representation": "effective" if v and v.context_digest else "source",
        "context_digest": v.context_digest if v else None,
        "content_hash": v.content_hash if v else None,
        "rule_id": g.rule_id,
        "family_id": g.family_id,
        "title": g.title,
        "level": g.level,
        "status": g.status,
        "logsource": {"product": g.product, "category": g.category, "service": g.service},
        "tags": g.tags,
        "attack": tag_metadata(g.tags or [], matrix, metadata_cache),
        "score": g.score,
        "validation": g.validation,
        "converts": g.converts,
        "conversion": g.conversion or {},
        "copies": g.copies,
        "sources": g.sources,
        "canonical_source": g.canonical_source,
        "licence": licence,
        "licence_from": licence_from,
        "licence_class": licence_class(licence),
    }


def export_jsonl(s: Session, groups: Iterator[LogicGroup], out: Path, *, include_private: bool = False, mode: str = "all") -> int:
    """One JSON object per rule with metadata, provenance, licence and the YAML text. The text is null (with
    `text_skipped` saying why) where a zip in the same licence `mode` would only link the rule (export_zip.skip_reason):
    rules without a licence always; restricted ones unless mode is "all" (the CLI default, a local copy; the web
    passes the download's licence mode, "split" by default)."""
    from sigharvest.export_zip import redistributable_sources, skip_reason

    out.parent.mkdir(parents=True, exist_ok=True)
    shippable = redistributable_sources(s)
    n = 0
    with out.open("w", encoding="utf-8") as fh:
        for g, v, meta in _records(s, groups):
            reason = skip_reason(str(meta.get("licence_class") or "none"), g.canonical_source, shippable, mode, include_private)
            # A linked-only rule keeps its factual metadata but none of its authors' prose (as in releases).
            linked = {"yaml": None, "text_skipped": reason} | {k: None for k in ("description", "author") if k in meta}
            fh.write(json.dumps(meta | (linked if reason else {"yaml": v.raw}), ensure_ascii=False) + "\n")
            n += 1
    return n


def export_queries(
    s: Session,
    groups: Iterator[LogicGroup],
    target: str,
    out: Path,
    allow_raw: bool = False,
    allow_warnings: bool = False,
    source: str = "all",
    *,
    details: bool = True,
    converter: Any = None,
) -> ExportReport:
    """Queries for one backend; see query.export_backend for what is written and the sidecar report.
    details=False omits the header line naming the sidecar, for downloads that ship only the query file.
    converter: replaces conversion.convert_cached (the web passes ondemand.convert: bounded worker processes)."""
    from sigharvest.query import export_backend

    versions = [v for g in groups if g.kind in ("rule", "correlation") for v in [s.get(RuleVersion, g.canonical_version_id)] if v is not None]
    return export_backend(
        versions,
        target,
        out,
        s=s,
        allow_raw=allow_raw,
        allow_warnings=allow_warnings,
        source=source,
        provenance_by_logic=True,
        details=details,
        converter=converter,
    )


def _rel_path(g: LogicGroup) -> Path:
    return Path(_slug(g.product or "any", 40)) / _slug(g.category or g.service or "generic", 40) / f"{_slug(g.title)}_{g.logic_hash[:8]}.yml"


def export_zip(s: Session, groups: Iterator[LogicGroup], out: Path, *, include_private: bool = False) -> tuple[int, int]:
    """The same zip as the web UI's Export page (export_zip.write_zip; top folder = the file name without .zip).
    Returns (rules copied, rules only linked in SKIPPED.md); fixed timestamps, so equal input gives equal bytes."""
    from sigharvest.export_zip import safe_stem, write_zip

    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".partial")
    stem = safe_stem(out.name.removesuffix(".zip"))
    try:
        with tmp.open("wb") as fh:
            result = write_zip(s, groups, fh, stem, include_private=include_private)
        tmp.replace(out)
    finally:
        tmp.unlink(missing_ok=True)
    return result


CSV_COLUMNS = (
    "logic_hash",
    "rule_id",
    "title",
    "level",
    "status",
    "product",
    "category",
    "service",
    "tags",
    "score",
    "validation",
    "converts",
    "copies",
    "sources",
    "canonical_source",
    "licence",
    "author",
    "source_url",
)

FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


# Spreadsheets in locales whose list separator is ';' split an opened .csv on ';' as well, so a formula can also start
# right after a ';' (leading spaces ignored): "Report;=1+1".
_FORMULA_AFTER_SEPARATOR = re.compile(r"[;,]\s*[=+\-@\t\r]")


def csv_cell(value: object) -> str:
    """A CSV cell that spreadsheets show as text: a value starting like a formula (= + - @ tab CR), or holding one
    after a ';' or ',' separator, gets a leading apostrophe. Every cell is also quoted (export_csv)."""
    text = " ".join(map(str, value)) if isinstance(value, list) else ("" if value is None else str(value))
    risky = text.lstrip(" ").startswith(FORMULA_START) or _FORMULA_AFTER_SEPARATOR.search(text) is not None
    return "'" + text if risky else text


def export_csv(s: Session, groups: Iterator[LogicGroup], out: Path) -> int:
    """One CSV row per rule with its main metadata (no YAML); list values are joined with spaces; cells that would
    start a spreadsheet formula (= + - @ tab CR, also after a ';' or ',') are prefixed with an apostrophe; every cell
    is quoted."""
    import csv

    out.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)  # a quoted cell is never split on ';' by a spreadsheet
        writer.writerow(CSV_COLUMNS)
        for _g, _v, meta in _records(s, groups):
            row = meta | meta["logsource"]
            writer.writerow([csv_cell(row.get(c)) for c in CSV_COLUMNS])
            n += 1
    return n


def zip_folder(folder: Path, out: Path) -> None:
    """Zip a folder's files (sorted, fixed timestamps) into `out`, plus NOTICE.md when the folder has none."""
    import zipfile

    out.parent.mkdir(parents=True, exist_ok=True)
    stamp = (1980, 1, 1, 0, 0, 0)
    tmp = out.with_name(out.name + ".partial")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        files = sorted(p for p in folder.rglob("*") if p.is_file())
        if not (folder / "NOTICE.md").exists():
            zf.writestr(zipfile.ZipInfo("NOTICE.md", stamp), EXPORT_NOTICE, compress_type=zipfile.ZIP_DEFLATED)
        for path in files:
            zf.writestr(zipfile.ZipInfo(path.relative_to(folder).as_posix(), stamp), path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
    tmp.replace(out)
