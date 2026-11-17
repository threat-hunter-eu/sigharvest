"""The rule zip, identical for `sigharvest export --format zip` and the web UI's Export page.

<stem>/<class>/<licence>/<product>/<category>/<rule>.yml (licences "split", the default) plus NOTICE.md, LICENSES.md,
ATTRIBUTION.md, manifest.jsonl, provenance.json and SKIPPED.md. A rule's text is copied only when its licence allows
it (licence class, see licensing.py) and its source is marked redistributable in sources.yaml; every other rule is
listed in SKIPPED.md with a link to read it at its source. `include_private` copies those too, for a user's own
local copy (for example their own rules added as a local source without a licence): the zip then says so in
NOTICE.md and must not be shared.
"""

from __future__ import annotations

import json
import re
import zipfile
from collections import Counter
from collections.abc import Iterable
from typing import IO, Any

from sqlalchemy.orm import Session

from sigharvest.errors import SigharvestError
from sigharvest.models import LogicGroup

LICENCE_MODES = ("split", "permissive", "all")  # split by class (default), permissive only, one folder
LAYOUTS = ("logsource", "source", "flat")
STAMP = (1980, 1, 1, 0, 0, 0)

PRIVATE_NOTICE = """
## Private copy

This export was made with --include-private-sources: it also contains rules whose licence does not allow (or does
not state) redistribution, or whose source is not marked redistributable (for example your own local rules). Keep
it for your own use; do not share or publish it.
"""


class ExportTooLarge(SigharvestError):
    """The export exceeds the caller's size limit (the web UI caps downloads)."""


def slug(text: str | None, limit: int = 60) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", text or "").strip("_")[:limit] or "rule"


def md(text: Any) -> str:
    return re.sub(r"[\x00-\x1f|<>\[\]`*_]", " ", str(text or "")).strip()[:200]


def included(cls: str, mode: str) -> bool:
    """Whether a licence class is copied in a licence mode (split: permissive and copyleft; permissive; all)."""
    if cls == "none":
        return False
    if mode == "permissive":
        return cls == "permissive"
    if mode == "split":
        return cls in ("permissive", "copyleft")
    return True


def redistributable_sources(s: Session) -> dict[str, bool]:
    """Source name -> its sources.yaml `redistributable` decision (only an explicit true ships rule text)."""
    from sigharvest.licensing import redistributable
    from sigharvest.source_metadata import source_configs

    return {name: redistributable(getattr(cfg, "redistributable", None)) for name, cfg in source_configs(s).items()}


def skip_reason(cls: str, source: str | None, shippable: dict[str, bool], mode: str = "split", include_private: bool = False) -> str | None:
    """None when a rule's text goes into the export, else why it is only linked (shared by every user export)."""
    if include_private:
        return None
    if cls == "none":
        return "no licence: link only"
    if not included(cls, mode):
        return "restricted licence: read its terms at the source" if cls == "restricted" else f"{cls} licence left out (permissive only)"
    if not shippable.get(source or "", False):
        return f"source {source} is not marked redistributable in sources.yaml: link only"
    return None


def rel_path(g: LogicGroup, layout: str) -> str:
    name = f"{slug(g.title)}_{g.logic_hash[:8]}.yml"
    if layout == "flat":
        return name
    if layout == "source":
        return f"{slug(g.canonical_source, 60)}/{name}"
    return f"{slug(g.product or 'any', 40)}/{slug(g.category or g.service or 'generic', 40)}/{name}"


def write_zip(
    s: Session,
    groups: Iterable[LogicGroup],
    target: IO[bytes],
    stem: str,
    mode: str = "split",
    layout: str = "logsource",
    *,
    include_private: bool = False,
    limit: int | None = None,
) -> tuple[int, int]:
    """Write the zip to `target`; returns (rules copied, rules only linked in SKIPPED.md)."""
    from sigharvest.export import EXPORT_NOTICE, _records
    from sigharvest.export_policy import attribution_markdown

    mode = mode if mode in LICENCE_MODES else "split"
    layout = layout if layout in LAYOUTS else "logsource"
    shippable = redistributable_sources(s)
    manifest: list[str] = []
    credits: list[dict[str, Any]] = []
    skipped: list[str] = []
    licences: Counter[str] = Counter()
    sources: dict[str, set[str]] = {}
    total = 0
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        seen: set[str] = set()
        for g, v, meta in _records(s, iter(groups)):
            cls = str(meta.get("licence_class") or "none")
            reason = skip_reason(cls, g.canonical_source, shippable, mode, include_private)
            if reason:
                link = meta.get("source_url") or ""
                skipped.append(f"- {md(g.title)} ({md(g.canonical_source)}, {reason}){f': <{link}>' if link else ''}")
                continue
            licence = str(meta.get("licence") or "no licence")
            folder = f"{cls}/{slug(licence, 30)}/" if mode == "split" else ""
            rel = folder + rel_path(g, layout)
            if rel in seen:
                rel = rel.removesuffix(".yml") + f"_{g.logic_hash[8:16]}.yml"
            seen.add(rel)
            data = v.raw.encode("utf-8", "surrogatepass")
            total += len(data)
            if limit is not None and total > limit:
                raise ExportTooLarge(f"Export exceeds {limit // 1024**2} MiB; select fewer rules")
            zf.writestr(zipfile.ZipInfo(f"{stem}/{rel}", STAMP), data, compress_type=zipfile.ZIP_DEFLATED)
            manifest.append(json.dumps(meta | {"path": rel}, ensure_ascii=False))
            credits.append(meta)
            licences[licence] += 1
            sources.setdefault(licence, set()).add(str(g.canonical_source))
        lic_lines = ["# Licences in this export", "", "| Licence | Rules | From |", "|---|---:|---|"]
        lic_lines += [f"| {md(name)} | {n} | {md(', '.join(sorted(sources[name])))} |" for name, n in licences.most_common()]
        lic_lines += [
            "",
            "Each rule keeps the licence of its source (its own `license:` field only when that is narrower). "
            "Keep the author and the licence notice when you share (ATTRIBUTION.md).",
        ]
        files = {
            "NOTICE.md": EXPORT_NOTICE + (PRIVATE_NOTICE if include_private else ""),
            "LICENSES.md": "\n".join(lic_lines) + "\n",
            "ATTRIBUTION.md": attribution_markdown(credits),
            "manifest.jsonl": "".join(line + "\n" for line in manifest),
            "provenance.json": json.dumps(
                {
                    "generator": "sigharvest",
                    "rules": len(manifest),
                    "skipped": len(skipped),
                    "licence_mode": mode,
                    "layout": layout,
                    "include_private_sources": include_private,
                },
                indent=1,
            )
            + "\n",
            "SKIPPED.md": "# Rules not copied into this export\n\n"
            + "Read them at their source: their licence does not allow (or does not state) redistribution, or their source "
            + "is not marked redistributable. Your own rules: add the source with --licence, or export with "
            + "--include-private-sources for a private copy.\n\n"
            + ("\n".join(skipped) if skipped else "None.")
            + "\n",
        }
        from sigharvest.licence_texts import for_credits

        notice, licence_files = for_credits(s, credits)
        files["NOTICE.md"] += notice
        for name, body in files.items():
            zf.writestr(zipfile.ZipInfo(f"{stem}/{name}", STAMP), body.encode("utf-8"), compress_type=zipfile.ZIP_DEFLATED)
        for name, data in licence_files:
            zf.writestr(zipfile.ZipInfo(f"{stem}/{name}", STAMP), data, compress_type=zipfile.ZIP_DEFLATED)
    return len(manifest), len(skipped)
