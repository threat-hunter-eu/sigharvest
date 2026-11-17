"""Data releases: the whole index as one downloadable, licence-aware file set.

`sigharvest release build OUT/` writes:
- rules.jsonl.gz: one line per unique logic: identifiers, title, logsource, tags, level, status, family, sources
  and independent sources, validation, conversion status per backend, quality flags, licence and licence
  class, a link to the canonical copy, and the YAML text when the licence class allows redistribution
  (permissive and copyleft by default). Rules without a licence, restricted ones and those of sources not marked
  redistributable are published as metadata and a link only: title, logsource, level, status, tags and ATT&CK, the
  link; no YAML, no description, no author (free text of the rule's authors).
- manifest.json: when and how it was built (sigharvest and pySigma versions), counts, and every source with its URL,
  commit, licence and how many rules it carries.
- ATTRIBUTION.md: sources and licences, for the people who reuse the data.
- sigharvest-rules-permissive.zip, sigharvest-rules-copyleft.zip: the redistributable YAML of each licence class
  (<product>/<category>/<title>_<logic8>.yml), with NOTICE.md inside.
- index.json.gz: compact rule metadata for search front ends; provenance.json.gz: canonical copy, sources and
  licence of every rule; attack-navigator-layer.json: tagged rule families per ATT&CK technique.
- changes.json: new, changed and removed rules compared with a previous release (--previous), RELEASE_NOTES.md,
  stats.json and NOTICE.md (per-source licences and copyright lines, Apache NOTICE files, MITRE ATT&CK terms).
- LICENSES.zip (and LICENSES/ inside each rule zip): the licence texts of every licence shipped, DRL 1.1 included,
  and each source's own LICENSE / COPYING / NOTICE files from its synced commit (licence_texts.py).
- SHA256SUMS.

manifest.json carries `content_id`, a digest of the rule contents and counts only (not of build times), so two
builds of the same corpus share it.

The file format is versioned (FORMAT); readers must check it.
"""

from __future__ import annotations

import gzip
import io
import json
from collections import Counter
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from sigharvest import space
from sigharvest.attack import session_matrix, tag_metadata
from sigharvest.export import _licences, effective_licence
from sigharvest.licensing import licence_class, redistributable
from sigharvest.models import LogicGroup, Occurrence, RuleVersion, Source
from sigharvest.publication import PublicationError, build_time, staged_directory
from sigharvest.release_reader import file_digest, open_release
from sigharvest.sources import file_link

FORMAT = 1


def _version(pkg: str) -> str:
    try:
        return version(pkg)
    except PackageNotFoundError:
        return "unknown"


def _build(
    s: Session,
    out: Path,
    allow: frozenset[str] = frozenset({"permissive", "copyleft"}),
    include_junk: bool = False,
    configs: dict[str, Any] | None = None,
    *,
    build_epoch: int | None = None,
    previous: Path | None = None,
    incomplete: bool = False,
) -> dict[str, Any]:
    """Write the release files into `out` and return the manifest (see the module docstring).

    configs: name -> SourceConfig from sources.yaml (default: the session's workspace sources.yaml). Licences and
    `redistributable` are read from it, not from the database copy that only changes on the next sync, so an edited
    licence applies to this release at once. Only sources marked `redistributable: true` ship rule text."""
    from sigharvest.source_metadata import source_configs

    out.mkdir(parents=True, exist_ok=True)
    if configs is None:
        configs = source_configs(s)
    lic = _licences(s, configs)
    matrix = session_matrix(s)
    metadata_cache: dict[str, dict[str, Any] | None] = {}
    sources = {r.name: r for r in s.scalars(select(Source))}
    source_ids = {r.id: r.name for r in sources.values()}
    counts: Counter[str] = Counter()
    per_source: Counter[str] = Counter()
    q = select(LogicGroup).order_by(LogicGroup.logic_hash)
    if not include_junk:
        q = q.where(LogicGroup.junk.is_(False))
    path = out / "rules.jsonl.gz"
    from sigharvest.export_policy import drl_rule_ids
    from sigharvest.source_metadata import workspace_of

    extras = _Extras(out, allow, workspace_of(s), configs, drl_rule_ids(s, configs))
    with (
        path.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed,
        io.TextIOWrapper(compressed, encoding="utf-8", newline="\n") as fh,
    ):
        batch: list[LogicGroup] = []

        def flush() -> None:
            ids = [g.canonical_version_id for g in batch]
            versions = {v.id: v for v in s.scalars(select(RuleVersion).where(RuleVersion.id.in_(ids)))}
            occ: dict[tuple[int, str], tuple[str, str | None]] = {}
            for o in s.scalars(
                select(Occurrence)
                .where(Occurrence.version_id.in_(ids), Occurrence.present.is_(True))
                .order_by(Occurrence.path, Occurrence.doc_index, Occurrence.commit)
            ):
                occ.setdefault((o.version_id, source_ids.get(o.source_id, "")), (o.path, o.commit))
            for g in batch:
                v = versions.get(g.canonical_version_id)
                licence, licence_from = effective_licence(g, v, lic)
                cls = licence_class(licence)
                where = occ.get((g.canonical_version_id, g.canonical_source))
                src = sources.get(g.canonical_source)
                cfg = configs.get(g.canonical_source)
                # The text shipped is the canonical copy, so its own source must allow redistribution: only an
                # explicit `redistributable: true` does; not stated, false or unknown ship metadata and a link only.
                share = cls in allow and redistributable(getattr(cfg, "redistributable", None))
                counts["rules"] += 1
                counts[f"licence_{cls}"] += 1
                counts["with_yaml" if share else "metadata_only"] += 1
                for name in g.sources or []:
                    per_source[name] += 1
                row = {
                    "logic_hash": g.logic_hash,
                    "rule_id": g.rule_id,
                    "family": g.family_id,
                    "kind": g.kind,
                    "title": g.title,
                    # Metadata-only rows (no licence, restricted, or a source not marked redistributable) carry short
                    # factual metadata (title, logsource, level, status, tags, link) but none of the authors' prose.
                    "description": g.description if share else None,
                    "logsource": {"product": g.product, "category": g.category, "service": g.service},
                    "level": g.level,
                    "status": g.status,
                    "tags": sorted(g.tags or []),
                    "attack": tag_metadata(g.tags or [], matrix, metadata_cache),
                    "author": g.author if share else None,
                    "modified": g.modified,
                    "sources": sorted(g.sources or []),
                    "n_independent": g.n_independent,
                    "canonical": {
                        "source": g.canonical_source,
                        "path": where[0] if where else None,
                        "commit": where[1] if where else None,
                        "url": file_link(src.url, where[1], where[0]) if src and where else None,
                    },
                    "score": g.score,
                    "validation": g.validation,
                    "conversion": getattr(g, "conversion", None),
                    "quality_flags": sorted(g.quality_flags or []),
                    "licence": licence,
                    "licence_from": licence_from,
                    "licence_class": cls,
                    "yaml": v.raw if share and v is not None else None,
                    "yaml_representation": "effective" if v and v.context_digest else "source",
                    "context_digest": v.context_digest if share and v else None,
                }
                if extras.drl and g.rule_id in extras.drl and "DRL" not in str(licence or "").upper():
                    row["drl_origin"] = True  # a copy of a SigmaHQ DRL rule shipped under another licence (site note)
                fh.write(json.dumps(row, ensure_ascii=False, default=str, sort_keys=True) + "\n")
                extras.add(row)
            batch.clear()

        for g in s.scalars(q).yield_per(2000):
            batch.append(g)
            if len(batch) >= 2000:
                flush()
        if batch:
            flush()

    source_rows: list[dict[str, Any]] = []
    for r in sorted(sources.values(), key=lambda r: r.name):
        if not per_source.get(r.name):
            continue
        row: dict[str, Any] = {"name": r.name, "type": r.type, "url": r.url, "commit": r.last_commit, "licence": lic.get(r.name),
                               "priority": r.priority, "rules": per_source.get(r.name, 0)}  # fmt: skip
        cfg = configs.get(r.name)
        if cfg is not None:
            row["paths"], row["exclude"] = list(cfg.paths), list(cfg.exclude)
        source_rows.append(row)
    extras.close()
    manifest: dict[str, Any] = {
        "format": FORMAT,
        "content_id": extras.content_id(dict(counts)),
        "created": build_time(build_epoch),
        "sigharvest": _version("sigharvest"),
        "pysigma": _version("pysigma"),
        "redistributed_classes": sorted(allow),
        "includes_junk": include_junk,
        "counts": dict(counts),
        "sources": source_rows,
    }
    if incomplete:
        manifest["incomplete"] = True  # built from a first update that did not pass its gates (runs.incomplete_corpus)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    lines = [
        "# Attribution",
        "",
        "These rules were written by the authors of the repositories below and keep their licences. Each line of",
        "rules.jsonl.gz names the rule's licence and links to its canonical copy. Rules without a stated licence",
        "are listed with metadata and a link only; their text is not redistributed.",
        "",
        "| source | licence | rules | url |",
        "|---|---|---|---|",
    ]
    for item in source_rows:
        lines.append(f"| {item['name']} | {item['licence'] or 'not stated'} | {item['rules']} | {item['url']} |")
    (out / "ATTRIBUTION.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    extras.finish(manifest, source_rows, previous)
    sums = []
    for f in sorted(p.name for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS"):
        sums.append(f"{file_digest(out / f)}  {f}")
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    return manifest


def build(
    s: Session,
    out: Path,
    allow: frozenset[str] = frozenset({"permissive", "copyleft"}),
    include_junk: bool = False,
    configs: dict[str, Any] | None = None,
    *,
    build_epoch: int | None = None,
    previous: Path | None = None,
    incomplete: bool = False,
) -> dict[str, Any]:
    """Publish a complete deterministic format-1 generation; failed builds retain the previous output.

    Supply build_epoch (Unix seconds), or SOURCE_DATE_EPOCH, to reproduce bytes.
    Existing nonempty outputs must already be valid releases.
    """
    space.before_release(s, out)
    if out.is_symlink() or (out.exists() and not out.is_dir()):
        raise PublicationError("release output must be a directory, not a file or symlink")
    if out.exists() and any(out.iterdir()):
        try:
            with open_release(out) as existing:
                for _ in existing.rows():
                    pass
        except RuntimeError as exc:
            raise PublicationError("output is not a valid release; choose a new directory") from exc
    # SQLite legacy transaction mode does not BEGIN for SELECT by itself. Pin all
    # release queries to one snapshot, including batches and source attribution.
    connection = s.connection()
    driver = connection.connection.driver_connection
    if connection.dialect.name == "sqlite" and driver is not None and not driver.in_transaction:
        connection.exec_driver_sql("BEGIN")
    with staged_directory(out) as stage:
        manifest = _build(s, stage, allow, include_junk, configs, build_epoch=build_epoch, previous=previous, incomplete=incomplete)
        with open_release(stage) as reader:
            for _ in reader.rows():
                pass
    return manifest


ZIP_STAMP = (1980, 1, 1, 0, 0, 0)
ZIP_CLASSES = ("permissive", "copyleft")
NOTICE = """# Notice

The rules in this release were written by the authors of the source repositories listed in ATTRIBUTION.md and
keep their own licences. Each rule's licence, licence class and canonical copy are in rules.jsonl.gz and
provenance.json.gz. Rules under the Detection Rule License (DRL) 1.1
(https://github.com/SigmaHQ/Detection-Rule-License), such as SigmaHQ's, require that you keep the author and
reference attribution when you reuse or convert them. Rules without a stated licence, restricted ones and those of
sources not marked redistributable are listed with metadata and a link only; their text is not redistributed.

Built with sigharvest, MIT licence. ATT&CK is a registered trademark of The MITRE Corporation.
"""

ZIP_NOTICE = """# Notice

The rules in this archive were written by the authors of their source repositories and keep their own licences.
ATTRIBUTION.md lists the title, author, source, licence and a link to the original of every rule; manifest.jsonl
has the same per rule, with its path in this archive. Rules under the Detection Rule License (DRL) 1.1, such as
SigmaHQ's, require that you keep the author and reference attribution when you reuse or convert them: keep
ATTRIBUTION.md with the rules. LICENSES/ holds the licence texts and the publishers' own licence and notice files.

Built with sigharvest, MIT licence.
"""


class _Extras:
    """Release artifacts derived from the same rows as rules.jsonl.gz, written in one pass."""

    def __init__(self, out: Path, allow: frozenset[str], ws: Any = None, configs: dict[str, Any] | None = None, drl: set[str] | None = None) -> None:
        import hashlib
        import zipfile

        self.ws, self.configs, self.drl = ws, configs or {}, drl or set()
        self.attack = False
        self.out = out
        self.hash = hashlib.sha256()
        self.rows: list[dict[str, Any]] = []
        self.provenance: dict[str, Any] = {}
        self.techniques: dict[str, set[int]] = {}
        self.zips = {cls: zipfile.ZipFile(out / f"sigharvest-rules-{cls}.zip", "w", compression=zipfile.ZIP_DEFLATED) for cls in ZIP_CLASSES}
        self.allow = allow
        self.zip_counts: Counter[str] = Counter()
        self.credits: dict[str, list[dict[str, Any]]] = {cls: [] for cls in ZIP_CLASSES}

    def add(self, row: dict[str, Any]) -> None:
        import hashlib
        import re
        import zipfile

        from sigharvest.export import _slug

        text = row.get("yaml")
        digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest() if text else ""
        self.hash.update(f"{row['logic_hash']}:{digest}\n".encode())
        ls = row["logsource"]
        self.rows.append(
            {
                "logic_hash": row["logic_hash"],
                "rule_id": row["rule_id"],
                "title": row["title"],
                "level": row["level"],
                "status": row["status"],
                "product": ls["product"],
                "category": ls["category"],
                "service": ls["service"],
                "tags": row["tags"],
                "sources": row["sources"],
                "family": row["family"],
                "score": row["score"],
                "licence_class": row["licence_class"],
                "has_yaml": bool(text),
            }
        )
        self.provenance[row["logic_hash"]] = {
            "canonical": row["canonical"],
            "sources": row["sources"],
            "licence": row["licence"],
            "licence_from": row["licence_from"],
            "licence_class": row["licence_class"],
        }
        self.attack = self.attack or bool(row.get("attack"))
        for tag in row["tags"]:
            match = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(tag).lower())
            if match:
                self.techniques.setdefault(match.group(1).upper(), set()).add(row["family"])
        cls = row["licence_class"]
        from sigharvest.export_policy import licence_notes

        if text and cls in self.zips:
            folder = f"{_slug(ls['product'] or 'any', 40)}/{_slug(ls['category'] or ls['service'] or 'generic', 40)}"
            rel = f"{folder}/{_slug(row['title'])}_{row['logic_hash'][:8]}.yml"
            self.zips[cls].writestr(zipfile.ZipInfo(rel, ZIP_STAMP), text.encode("utf-8", "surrogatepass"), compress_type=zipfile.ZIP_DEFLATED)
            self.zip_counts[cls] += 1
            self.credits[cls].append(
                {
                    "path": rel,
                    "logic_hash": row["logic_hash"],
                    "rule_id": row["rule_id"],
                    "title": row["title"],
                    "author": row["author"],
                    "source": row["canonical"]["source"],
                    "source_url": row["canonical"]["url"],
                    "source_path": row["canonical"]["path"],
                    "licence": row["licence"],
                    "licence_class": cls,
                }
                | licence_notes(row, self.drl)
            )

    def close(self) -> None:
        import zipfile

        from sigharvest.export_policy import attribution_markdown
        from sigharvest.licence_texts import bundle, missing_texts, notice_section

        missing = sorted({m for credits in self.credits.values() for m in missing_texts(self.ws, self._shipped(credits))})
        if missing:
            # GPL/AGPL §4, DRL item 3, CC §3(a)(1)(C): a rule travels with its licence text (or no text is shipped).
            raise PublicationError(
                "a pack would ship rules without their licence text (add the SPDX text to src/sigharvest/licences/ "
                "or leave the source out): " + ", ".join(missing[:20])
            )
        for cls, zf in self.zips.items():
            credits = self.credits[cls]
            shipped = self._shipped(credits)
            notice = ZIP_NOTICE + notice_section(self.ws, shipped, self.configs)
            zf.writestr(zipfile.ZipInfo("NOTICE.md", ZIP_STAMP), notice, compress_type=zipfile.ZIP_DEFLATED)
            for name, data in bundle(self.ws, shipped, self.configs):
                zf.writestr(zipfile.ZipInfo(name, ZIP_STAMP), data, compress_type=zipfile.ZIP_DEFLATED)
            zf.writestr(zipfile.ZipInfo("ATTRIBUTION.md", ZIP_STAMP), attribution_markdown(credits), compress_type=zipfile.ZIP_DEFLATED)
            manifest = "".join(json.dumps(c, ensure_ascii=False, sort_keys=True) + "\n" for c in credits)
            zf.writestr(zipfile.ZipInfo("manifest.jsonl", ZIP_STAMP), manifest.encode("utf-8", "surrogatepass"), compress_type=zipfile.ZIP_DEFLATED)
            zf.close()

    @staticmethod
    def _shipped(credits: list[dict[str, Any]]) -> dict[str, str | None]:
        """Source -> licence of the rules whose text a zip carries (DRL added when DRL-derived rules are in it)."""
        shipped: dict[str, str | None] = {str(c["source"]): c["licence"] for c in credits}
        if any(c.get("drl_origin") for c in credits):
            shipped["rules derived from DRL rules"] = "DRL-1.1"
        return shipped

    def licences_zip(self) -> None:
        """LICENSES.zip at the top of the release: the LICENSES/ folder of both zips together (release assets are flat)."""
        import zipfile

        from sigharvest.licence_texts import bundle

        shipped: dict[str, str | None] = {}
        for credits in self.credits.values():
            shipped |= self._shipped(credits)
        with zipfile.ZipFile(self.out / "LICENSES.zip", "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, data in bundle(self.ws, shipped, self.configs):
                zf.writestr(zipfile.ZipInfo(name, ZIP_STAMP), data, compress_type=zipfile.ZIP_DEFLATED)
        self.shipped_all = shipped

    def content_id(self, counts: dict[str, Any]) -> str:
        import hashlib

        return hashlib.sha256(self.hash.hexdigest().encode() + json.dumps(counts, sort_keys=True).encode()).hexdigest()

    def _gzip_json(self, name: str, value: Any) -> None:
        with (self.out / name).open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as fh:
            fh.write(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())

    def finish(self, manifest: dict[str, Any], sources: list[dict[str, Any]], previous: Path | None) -> None:
        self._gzip_json("index.json.gz", {"format": 1, "rules": self.rows})
        self._gzip_json("provenance.json.gz", {"format": 1, "rules": self.provenance})
        peak = max((len(v) for v in self.techniques.values()), default=1)
        layer = {
            "name": "sigharvest coverage",
            "versions": {"navigator": "5.1.0", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": "Rule families tagged with each ATT&CK technique (declared by rule authors, not demonstrated detection).",
            "techniques": [
                {"techniqueID": tid, "score": len(fams), "comment": f"{len(fams)} tagged rule families", "enabled": True}
                for tid, fams in sorted(self.techniques.items())
            ],
            "gradient": {"colors": ["#ffffff", "#66b1ff", "#0b3d91"], "minValue": 0, "maxValue": peak},
            "legendItems": [],
        }
        (self.out / "attack-navigator-layer.json").write_text(json.dumps(layer, indent=1, sort_keys=True), encoding="utf-8")
        changes = _changes(self.rows, previous)
        (self.out / "changes.json").write_text(json.dumps(changes, indent=1, sort_keys=True), encoding="utf-8")
        counts = manifest["counts"]
        stats = {
            "rules": counts.get("rules", 0),
            "with_yaml": counts.get("with_yaml", 0),
            "metadata_only": counts.get("metadata_only", 0),
            "by_licence_class": {k.removeprefix("licence_"): v for k, v in sorted(counts.items()) if k.startswith("licence_")},
            "zip": dict(sorted(self.zip_counts.items())),
            "sources": len(sources),
            "families": len({r["family"] for r in self.rows}),
            "techniques": len(self.techniques),
        }
        (self.out / "stats.json").write_text(json.dumps(stats, indent=1, sort_keys=True), encoding="utf-8")
        from sigharvest.licence_texts import notice_section

        self.licences_zip()
        notice = NOTICE
        if self.attack:
            # ATT&CK terms of use: reproduce MITRE's copyright designation and the licence in any copy.
            from sigharvest.attack import ATTRIBUTION

            notice += f"\n{ATTRIBUTION}\n"
        notice += notice_section(self.ws, self.shipped_all, self.configs, where="`LICENSES.zip`")
        (self.out / "NOTICE.md").write_text(notice, encoding="utf-8")
        notes = [
            f"# Sigma rules release {manifest['created'][:10]}",
            "",
            f"- {stats['rules']:,} unique rules ({stats['families']:,} families) from {stats['sources']} sources",
            f"- {stats['with_yaml']:,} with YAML ({', '.join(f'{k}: {v:,}' for k, v in stats['zip'].items()) or 'none'}), "
            f"{stats['metadata_only']:,} metadata and link only",
            f"- {stats['techniques']} ATT&CK techniques tagged",
        ]
        if changes["previous"] is not None:
            notes.append(f"- since the previous release: {len(changes['new'])} new, {len(changes['changed'])} changed, {len(changes['removed'])} removed")
        notes += ["", "Licences and attribution: NOTICE.md and ATTRIBUTION.md.", ""]
        (self.out / "RELEASE_NOTES.md").write_text("\n".join(notes), encoding="utf-8")


def _changes(rows: list[dict[str, Any]], previous: Path | None) -> dict[str, Any]:
    """New, changed (same rule id, new logic) and removed rules compared with the index of a previous release."""
    if previous is None or not (previous / "index.json.gz").is_file():
        return {"previous": None, "new": [], "changed": [], "removed": []}
    from sigharvest.release_reader import read_index

    old = read_index(previous / "index.json.gz")
    old_logic = {r["logic_hash"]: r for r in old}
    new_logic = {r["logic_hash"]: r for r in rows}
    old_by_id = {r["rule_id"]: r["logic_hash"] for r in old}
    added = [h for h in new_logic if h not in old_logic]
    changed = [
        {"rule_id": new_logic[h]["rule_id"], "old": old_by_id[new_logic[h]["rule_id"]], "new": h, "title": new_logic[h]["title"]}
        for h in added
        if new_logic[h]["rule_id"] in old_by_id and old_by_id[new_logic[h]["rule_id"]] not in new_logic
    ]
    changed_new = {c["new"] for c in changed}
    changed_old = {c["old"] for c in changed}
    manifest = previous / "manifest.json"
    return {
        "previous": json.loads(manifest.read_text(encoding="utf-8")).get("content_id") if manifest.is_file() else "unknown",
        "new": [{"logic_hash": h, "title": new_logic[h]["title"]} for h in sorted(added) if h not in changed_new],
        "changed": sorted(changed, key=lambda c: c["new"]),
        "removed": [{"logic_hash": h, "title": old_logic[h]["title"]} for h in sorted(old_logic) if h not in new_logic and h not in changed_old],
    }
