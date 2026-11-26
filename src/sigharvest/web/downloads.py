"""Downloads of a rule selection: YAML zip split by licence class, one multi-document YAML file, JSONL, CSV,
converted SIEM queries and an ATT&CK Navigator layer.

Rules without a licence (and restricted ones unless asked for) are never copied into a download: the zip lists them
in SKIPPED.md with a link to the source instead. Every download is built in memory and size-capped (export_bundle).
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from fastapi import HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from sigharvest.conversion import BACKENDS
from sigharvest.export_zip import safe_stem
from sigharvest.models import LogicGroup
from sigharvest.web.export_bundle import check_output_size, check_selection_size

FORMATS = ("zip", "yaml", "jsonl", "csv", "navigator", *BACKENDS)
LICENCE_MODES = ("split", "permissive", "all")  # split by class (default), permissive only, one folder
LAYOUTS = ("logsource", "source", "flat")
STAMP = (1980, 1, 1, 0, 0, 0)
LIMIT = 64 * 1024**2


def _included(cls: str, mode: str) -> bool:
    from sigharvest.export_zip import included

    return included(cls, mode)


def plan(s: Session, groups: list[LogicGroup], mode: str = "split", include_private: bool = False) -> dict[str, Any]:
    """What a zip of these rules would hold: counts per licence class and id, skipped rules, approximate size."""
    from sigharvest.export import _licences, effective_licence
    from sigharvest.export_zip import redistributable_sources, skip_reason
    from sigharvest.licensing import licence_class, shipped_licence
    from sigharvest.web.deps import canonical_raws

    shippable = redistributable_sources(s)
    private = 0

    lic = _licences(s)
    raws = canonical_raws(s, groups)
    by_class: dict[str, Counter[str]] = {}
    size = 0
    skipped = 0
    included = 0
    own = _rule_licences(s, groups)
    for g in groups:
        licence = shipped_licence(own.get(g.canonical_version_id), effective_licence(g, None, lic)[0])
        cls = licence_class(licence)
        by_class.setdefault(cls, Counter())[licence or "no licence"] += 1
        if skip_reason(cls, g.canonical_source, shippable, mode) is None or include_private:
            included += 1
            private += skip_reason(cls, g.canonical_source, shippable, mode) is not None
            size += len(raws.get(g.canonical_version_id, "").encode("utf-8", "replace"))
        else:
            skipped += 1
    order = ["permissive", "copyleft", "restricted", "none"]
    classes = [
        {"cls": c, "n": sum(by_class[c].values()), "ids": [k for k, _n in by_class[c].most_common(4)], "included": _included(c, mode)}
        for c in order
        if c in by_class
    ]
    return {"classes": classes, "included": included, "skipped": skipped, "size": size, "private": private}


def _rule_licences(s: Session, groups: list[LogicGroup]) -> dict[int, str | None]:
    from sqlalchemy import select

    from sigharvest.db import IN_CHUNK
    from sigharvest.models import RuleVersion

    ids = [g.canonical_version_id for g in groups]
    out: dict[int, str | None] = {}
    for i in range(0, len(ids), IN_CHUNK):
        out.update(dict(s.execute(select(RuleVersion.id, RuleVersion.rule_license).where(RuleVersion.id.in_(ids[i : i + IN_CHUNK]))).all()))
    return out


def licence_zip(s: Session, groups: list[LogicGroup], stem: str, mode: str = "split", layout: str = "logsource", *, include_private: bool = False) -> bytes:
    """The same zip as `sigharvest export --format zip` (export_zip.write_zip), built in memory and size-capped."""
    from sigharvest.export_zip import ExportTooLarge, write_zip

    buf = io.BytesIO()
    try:
        write_zip(s, groups, buf, stem, mode, layout, include_private=include_private, limit=LIMIT)
    except ExportTooLarge as exc:
        raise HTTPException(413, str(exc)) from None
    return buf.getvalue()


def yaml_bundle(s: Session, groups: list[LogicGroup], mode: str = "split", include_private: bool = False) -> bytes:
    """Every redistributable rule in one multi-document YAML file, each preceded by a comment with its licence and source."""
    from sigharvest.export import _records
    from sigharvest.export_zip import redistributable_sources, skip_reason

    shippable = redistributable_sources(s)
    out = io.StringIO()
    for g, v, meta in _records(s, iter(groups)):
        if skip_reason(str(meta.get("licence_class") or "none"), g.canonical_source, shippable, mode, include_private):
            continue
        comment = re.sub(
            r"[\r\n]",
            " ",
            f"# {g.title} | author {meta.get('author') or 'not stated'} | licence {meta.get('licence') or 'none'} | from {g.canonical_source}"
            f" | {meta.get('source_url') or meta.get('source_path') or 'no link'}",
        )
        out.write(f"---\n{comment}\n{v.raw.rstrip()}\n")
        if out.tell() > LIMIT:
            raise HTTPException(413, "Export exceeds 64 MiB; select fewer rules")
    return out.getvalue().encode("utf-8", "surrogatepass")


def navigator(s: Session, groups: list[LogicGroup], name: str) -> dict[str, Any]:
    """ATT&CK Navigator layer (format 4.5) for a selection; score = rules tagged with each technique."""
    from sigharvest.attack import ATTACK_VERSION, ATTRIBUTION

    counts: Counter[str] = Counter()
    for g in groups:
        for tid in {str(t).lower()[7:].upper() for t in g.tags or [] if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", str(t).lower())}:
            counts[tid] += 1
    peak = max(counts.values(), default=1)
    return {
        "name": name,
        "versions": {"attack": ATTACK_VERSION.split(".")[0], "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Sigma rules tagged with each technique ({len(groups)} rules), from sigharvest. "
        f"Tags describe intent, not tested detection. {ATTRIBUTION}",
        "techniques": [
            {"techniqueID": tid, "score": n, "comment": f"{n} tagged rule{'s' if n != 1 else ''}", "enabled": True} for tid, n in sorted(counts.items())
        ],
        "gradient": {"colors": ["#dceeed", "#0d6b6e"], "minValue": 0, "maxValue": peak},
        "legendItems": [],
        "showTacticRowBackground": False,
        "selectSubtechniquesWithParent": False,
    }


def _query_zip(out: Path, stem: str, format: str) -> bytes:
    from sigharvest.export import EXPORT_NOTICE

    files = {
        f"{stem}.{format}.txt": out,
        f"{stem}.{format}.txt.conversion.jsonl": out.with_name(out.name + ".conversion.jsonl"),
        "manifest.jsonl": out.with_name(out.name + ".manifest.jsonl"),
        "ATTRIBUTION.md": out.with_name(out.name + ".ATTRIBUTION.md"),
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, path in files.items():
            z.writestr(zipfile.ZipInfo(f"{stem}/{name}", STAMP), path.read_bytes() if path.is_file() else b"", compress_type=zipfile.ZIP_DEFLATED)
        z.writestr(zipfile.ZipInfo(f"{stem}/NOTICE.md", STAMP), EXPORT_NOTICE, compress_type=zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def download(
    s: Session,
    members: list[LogicGroup],
    format: str,
    stem: str,
    *,
    licences: str = "split",
    layout: str = "logsource",
    raw_queries: bool = False,
    include_private: bool = False,
) -> Response:
    """One download of the selection in `format` (see FORMATS)."""
    from sigharvest.export import export_csv, export_jsonl, export_queries

    if format not in FORMATS:
        raise HTTPException(400, f"unknown format; choose one of {', '.join(FORMATS)}")
    check_selection_size(s, members)
    stem = safe_stem(stem)
    if format == "zip":
        body, media, ext = licence_zip(s, members, stem, licences, layout, include_private=include_private), "application/zip", "zip"
    elif format == "yaml":
        body, media, ext = yaml_bundle(s, members, licences, include_private), "application/yaml", "yml"
    elif format == "navigator":
        body = json.dumps(navigator(s, members, stem), indent=1).encode()
        media, ext = "application/json", "layer.json"
    else:
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / f"rules.{format}"
            if format == "jsonl":
                export_jsonl(s, iter(members), out, include_private=include_private, mode=licences if licences in LICENCE_MODES else "split")
                media, ext = "application/x-ndjson", "jsonl"
            elif format == "csv":
                export_csv(s, iter(members), out)
                media, ext = "text/csv; charset=utf-8", "csv"
            else:
                from sigharvest import ondemand

                # Every rule converts in a bounded worker process (time, memory, size), never in this server thread.
                # The query file starts with the summary line (selected -> written; not written, and why) and names
                # the conversion report shipped next to it in the zip.
                out = out.with_name(f"{stem}.{format}.txt")
                export_queries(s, iter(members), format, out, allow_raw=raw_queries, details=True, converter=ondemand.convert)
            check_output_size(Path(tmp))
            if format in ("jsonl", "csv"):
                body = out.read_bytes() if out.is_file() else b""
            else:
                # The queries travel with their attribution (DRL 1.1: author and a reference to each original rule):
                # a zip with the query file (an attribution comment per rule), manifest.jsonl, ATTRIBUTION.md, NOTICE.md.
                body, media, ext = _query_zip(out, stem, format), "application/zip", f"{format}.zip"
    if len(body) > LIMIT:
        raise HTTPException(413, "Export exceeds 64 MiB; select fewer rules")
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{stem}.{ext}"', "Cache-Control": "no-store"})
