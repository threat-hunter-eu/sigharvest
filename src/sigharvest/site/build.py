"""Static site of the rules (rule pages, client-side search, collections, embeddable rule cards).

`build_site(source, out)` reads a data release (rules.jsonl.gz + manifest.json + ATTRIBUTION.md, see release.py) or a
workspace (a release is built from its database, read-only, into a temporary folder first) and writes plain files:

    OUT/<base_url>/index.html            search page (static HTML + search.js)
    OUT/<base_url>/rule.html?l=<lid>     every rule, rendered in the browser from its detail shard (rule.js)
    OUT/<base_url>/r/<lid>.html          static, indexable pages for a curated subset (collections + top families)
    OUT/<base_url>/c/<slug>.html         collection pages
    OUT/<base_url>/attribution.html      sources and licences (+ ATTRIBUTION.md), linked from every footer
    OUT/<base_url>/sitemap.xml           the generated HTML pages
    OUT/<base_url>/data/meta.json        counts, dictionaries, shard layout, score cut-offs
    OUT/<base_url>/data/t/<xx>.json      inverted index: token -> delta-encoded rule ranks, by the token's first 2 chars
    OUT/<base_url>/data/f/<facet>.json   facet postings (level, product, text available, validation)
    OUT/<base_url>/data/m/<n>.json       search rows by rank (200 per file): what a result line needs
    OUT/<base_url>/data/d/<hex>.json     everything about a rule (by the first hex digits of its logic hash)
    OUT/<base_url>/static/...            css, js (no inline scripts or styles: works with a strict CSP)

A rule is identified on the site by `lid`, the first 12 hex digits of its logic hash (longer if two rules collide).
Ranks are assigned by descending quality score, so the posting lists are in result order and the client only
loads the result rows it shows.

Licence policy (decision 41) is kept: the YAML text is only in the files when the release carries it (licence
class permissive/copyleft by default); rules without a licence show metadata and a link to their canonical copy.
Every value that comes from a rule is untrusted: static pages are rendered by Jinja2 with autoescaping, JSON is
rendered in the browser with textContent only, and links are only built for https URLs.
"""

from __future__ import annotations

import json
import math
import re
import shutil
import sqlite3
import tempfile
import time
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any
from urllib.parse import quote
from xml.sax.saxutils import escape as xml_escape

import typer
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from sigharvest.publication import build_time, staged_directory
from sigharvest.quality import JUNK
from sigharvest.release_reader import ReleaseError, SignaturePolicy, open_release, read_json

FORMAT = 1
HERE = Path(__file__).parent
THEMES = ("default",)
MARKER = ".sigharvest-site"
LEVELS = ["", "informational", "low", "medium", "high", "critical"]
VALIDATION = ["", "ok", "warning", "error"]
CHUNK = 200
TOKEN_MAX = 40
YAML_MAX = 64 * 1024
# fmt: off
STOP = frozenset([
    "the", "of", "a", "an", "and", "or", "via", "with", "for", "to", "in", "on", "by", "from", "is", "are", "be", "as", "at", "it", "its",
    "this", "that", "using", "use", "used", "into", "over", "new", "possible", "potential", "suspicious", "detects", "detect", "detection",
])
# fmt: on
_TOKEN = re.compile(r"[a-z0-9]+(?:\.[a-z0-9]+)*")
_BASE = re.compile(r"^/(?:[A-Za-z0-9._-]+/)*$")
_SITE = re.compile(r"^https?://[A-Za-z0-9.-]+(?::\d+)?$")
_TECH = re.compile(r"^attack\.(t\d{4})(?:\.(\d{3}))?$")
_GROUP = re.compile(r"^attack\.([gs])(\d{4})$")
_CVE = re.compile(r"^cve\.(\d{4})[.-](\d{4,7})$")
_SAFE_LINK = ("https://github.com/", "https://gitlab.com/")
_SLUG = re.compile(r"[^a-z0-9]+")


class SiteError(ValueError):
    pass


@dataclass
class SiteStats:
    root: Path
    rules: int = 0
    indexed: int = 0
    pages: int = 0
    collections: int = 0
    files: int = 0
    bytes: int = 0
    by_dir: dict[str, tuple[int, int]] = field(default_factory=dict)  # dir -> (files, bytes)
    largest: tuple[str, int] = ("", 0)
    detail_prefix: int = 0
    with_yaml: int = 0
    metadata_only: int = 0
    seconds: dict[str, float] = field(default_factory=dict)

    def summary(self) -> str:
        dirs = ", ".join(f"{k}: {n:,} files {b / 1e6:.1f} MB" for k, (n, b) in sorted(self.by_dir.items()))
        return (
            f"{self.rules:,} rules ({self.with_yaml:,} with YAML, {self.metadata_only:,} metadata + link), {self.indexed:,} searchable, "
            f"{self.pages:,} static rule pages, {self.collections} collections; {self.files:,} files, {self.bytes / 1e6:.1f} MB "
            f"(largest {self.largest[0]} {self.largest[1] / 1e3:.0f} kB); {dirs}; " + ", ".join(f"{k} {v:.1f}s" for k, v in self.seconds.items())
        )


# ------------------------------------------------------------------ helpers


def _version(pkg: str) -> str:
    try:
        return version(pkg)
    except PackageNotFoundError:
        return "unknown"


def slug(text: str | None, limit: int = 60) -> str:
    return (_SLUG.sub("-", (text or "").lower()).strip("-") or "untitled")[:limit].strip("-")


def tokens(text: str | None) -> set[str]:
    """Search tokens; search.js tokenises queries the same way (keep both in sync)."""
    out: set[str] = set()
    for t in _TOKEN.findall((text or "").lower()):
        for p in (t, *t.split(".")) if "." in t else (t,):
            if len(p) >= 2 and p not in STOP:
                out.add(p[:TOKEN_MAX])
    return out


def shard_key(token: str) -> str:
    """Token shard file: first 2 characters; technique ids (t1059.001...) by 3, they are many and share 't1'.
    search.js does not compute keys: it loads every shard whose key is a prefix of the query word or starts with it."""
    return token[:3] if len(token) > 2 and token[0] == "t" and token[1].isdigit() else token[:2]


def shorten(text: Any, k: int = 160) -> str:
    flat = " ".join(str(text or "").split())
    return flat[: k - 1] + "…" if len(flat) > k else flat


def safe_url(url: Any) -> str | None:
    """Only https links are ever written to a page."""
    return url if isinstance(url, str) and url.startswith("https://") and not any(c in url for c in "\"'<> \n\r\t") else None


def _dumps(obj: Any) -> str:
    # Compact JSON; '<' '>' '&' escaped so that a JSON file served with a wrong content type cannot become markup.
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _deltas(ids: Iterable[int]) -> list[int]:
    out, prev = [], -1
    for i in sorted(set(ids)):
        out.append(i - prev - 1)
        prev = i
    return out


def tag_info(tag: str, attack: dict[str, Any]) -> tuple[str, str | None, str]:
    """(label, link or None, kind) for a rule tag; kind: technique, tactic, group, software, cve, tag."""
    t = tag.strip().lower()
    interpretation = attack.get("interpretations", {}).get(t)
    if interpretation:
        tid = interpretation.get("current_id")
        url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/" if tid and re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid) else None
        return interpretation["label"], url, "technique" if interpretation["domain"] == "enterprise" else "tag"
    m = _TECH.match(t)
    if m:
        tid = m.group(1).upper() + (f".{m.group(2)}" if m.group(2) else "")
        path = m.group(1).upper() + (f"/{m.group(2)}" if m.group(2) else "")
        name = attack.get("techniques", {}).get(tid)
        return (f"{tid} {name}" if name else tid), f"https://attack.mitre.org/techniques/{path}/", "technique"
    m = _GROUP.match(t)
    if m:
        kind = "group" if m.group(1) == "g" else "software"
        ident = m.group(1).upper() + m.group(2)
        return ident, f"https://attack.mitre.org/{'groups' if kind == 'group' else 'software'}/{ident}/", kind
    m = _CVE.match(t)
    if m:
        cve = f"CVE-{m.group(1)}-{m.group(2)}"
        return cve, f"https://nvd.nist.gov/vuln/detail/{cve}", "cve"
    if t.startswith("attack."):
        short = t[7:]
        tac = attack.get("tactics", {}).get(short)
        if tac:
            return tac[1], f"https://attack.mitre.org/tactics/{tac[0]}/", "tactic"
        return short, None, "tactic"
    return tag, None, "tag"


def _load_attack(path: Path | None) -> dict[str, Any]:
    """Reduced ATT&CK matrix (attack.load_matrix cache format) -> {version, tactics: {short: [TA, name]}, techniques}."""
    if path is None or not path.exists():
        return {}
    from sigharvest.attack import MAX_CATALOG_BYTES, InvalidCatalog, matrix_from_data

    try:
        data = read_json(path, cap=MAX_CATALOG_BYTES)
        matrix = matrix_from_data(data)
    except (InvalidCatalog, ReleaseError) as exc:
        raise SiteError("invalid ATT&CK sidecar; provide a verified reduced Enterprise catalog of the pinned version") from exc
    return {
        "version": matrix.version,
        "tactics": {short: [tid, name] for short, name, tid in matrix.tactics},
        "techniques": {tid: tech.name for tid, tech in matrix.techniques.items()},
        "replaced": matrix.replaced,
        "deprecated": data.get("deprecated", []),
    }


# ------------------------------------------------------------------ sources


def _ro_session(db: Path) -> Any:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    uri = f"file:{quote(str(db.resolve()))}?mode=ro"
    engine = create_engine("sqlite://", creator=lambda: sqlite3.connect(uri, uri=True, timeout=60, check_same_thread=False))
    return Session(engine)


def collections_snapshot(s: Any, names: Sequence[str] | None = None) -> dict[str, Any]:
    """The collections of a workspace as plain data (collections.json next to a release), resolved now."""
    from sigharvest import collections as col

    wanted = None if names is None else {n.strip() for n in names}
    out = []
    for c, _n in col.summaries(s):
        if wanted is not None and c.name not in wanted:
            continue
        items = []
        for r in col.resolve(s, c):
            g = r.group
            items.append(
                {
                    "logic_hash": g.logic_hash if g is not None else r.item.logic_hash,
                    "rule_id": r.item.rule_id,
                    "title": g.title if g is not None else r.item.title,
                    "note": r.item.note,
                    "state": r.state,
                }
            )
        out.append({"name": c.name, "description": c.description, "items": items})
    if wanted is not None:
        missing = wanted - {c["name"] for c in out}
        if missing:
            raise SiteError(f"no collection named {', '.join(sorted(missing))}")
    return {"format": 1, "collections": out}


@dataclass
class _Source:
    rows: list[dict[str, Any]]
    manifest: dict[str, Any]
    collections: list[dict[str, Any]]
    attack: dict[str, Any]
    changes: dict[str, Any] | None = None  # changes.py shape: what the release (or last update) changed
    notice: str | None = None  # the release's NOTICE.md (copyright notices), republished next to attribution.html


def _read_release(folder: Path, limit: int | None, trust: SignaturePolicy | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with open_release(folder, trust=trust) as reader:
            for row in reader.rows():
                if limit is None or len(rows) < limit:
                    rows.append(row)
            return rows, reader.manifest
    except ReleaseError as exc:
        raise SiteError(str(exc)) from exc


def _pick_collections(snapshot: dict[str, Any] | None, names: Sequence[str] | None) -> list[dict[str, Any]]:
    have = (snapshot or {}).get("collections", [])
    if not isinstance(have, list):
        raise SiteError("invalid collections list")
    for collection in have:
        if not isinstance(collection, dict) or not isinstance(collection.get("name"), str) or not isinstance(collection.get("items", []), list):
            raise SiteError("invalid collection")
        for item in collection.get("items", []):
            if not isinstance(item, dict) or any(value is not None and not isinstance(value, str) for value in item.values()):
                raise SiteError("invalid collection item")
    if names is None:
        return have
    by_name = {c["name"]: c for c in have}
    missing = [n for n in names if n not in by_name]
    if missing:
        raise SiteError(f"no collection named {', '.join(missing)} in the source (a release needs a collections.json)")
    return [by_name[n] for n in names]


def _load_source(
    source: Path,
    collections: Sequence[str] | Path | None,
    limit: int | None,
    attack: Path | None,
    build_epoch: int | None,
    trust: SignaturePolicy | None,
) -> _Source:
    snapshot: dict[str, Any] | None = None
    names: Sequence[str] | None = None
    if isinstance(collections, Path):
        snapshot = read_json(collections)
    else:
        names = collections
    if (source / "rules.jsonl.gz").exists():
        try:
            with open_release(source, trust=trust) as reader:
                rows: list[dict[str, Any]] = []
                for row in reader.rows():
                    if limit is None or len(rows) < limit:
                        rows.append(row)

                def sidecar(name: str) -> Path:
                    verified = reader.folder / name
                    if verified.exists():
                        return verified
                    if trust and (source / name).exists():
                        raise SiteError(f"{name} is not covered by the signed checksums")
                    return source / name

                if snapshot is None and sidecar("collections.json").exists():
                    snapshot = read_json(sidecar("collections.json"))
                matrix = _load_attack(attack if attack is not None else sidecar("attack.json"))
                changed = None
                if (reader.folder / "changes.json").is_file():  # verified: listed in SHA256SUMS
                    changed = read_json(reader.folder / "changes.json") | {"until": str(reader.manifest.get("created") or "")}
                    changed.setdefault("since", str(changed.get("previous") or ""))
                notice = (reader.folder / "NOTICE.md").read_text(encoding="utf-8", errors="replace") if (reader.folder / "NOTICE.md").is_file() else None
                return _Source(rows, reader.manifest, _pick_collections(snapshot, names), matrix, changed, notice)
        except ReleaseError as exc:
            raise SiteError(str(exc)) from exc
    from sigharvest.attack import ATTACK_VERSION
    from sigharvest.config import Workspace
    from sigharvest.release import build as build_release

    if trust is not None:
        raise SiteError("signature trust requires a release folder")
    ws = Workspace(source.resolve())
    if not ws.db_path.exists():
        raise SiteError(f"{source} is neither a release folder (rules.jsonl.gz) nor a workspace (data/sigharvest.db)")
    with _ro_session(ws.db_path) as s, tempfile.TemporaryDirectory(prefix="sigharvest-site-") as tmp:
        build_release(s, Path(tmp), build_epoch=build_epoch)
        rows, manifest = _read_release(Path(tmp), limit)
        notice = (Path(tmp) / "NOTICE.md").read_text(encoding="utf-8") if (Path(tmp) / "NOTICE.md").is_file() else None
        if snapshot is None:
            snapshot = collections_snapshot(s, names)
        from sigharvest.changes import since_update

        changed = since_update(s, ws.root)  # the last update's report
    if attack is None:
        attack = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    return _Source(rows, manifest, _pick_collections(snapshot, names), _load_attack(attack), changed, notice)


# ------------------------------------------------------------------ model


def _rank_key(r: dict[str, Any]) -> tuple[Any, ...]:
    return (-(r.get("score") or 0.0), -(r.get("n_independent") or 1), (r.get("title") or "").lower(), r["logic_hash"])


def _lid_length(rows: list[dict[str, Any]]) -> int:
    hashes = [r["logic_hash"] for r in rows]
    for n in (12, 16, 24, 64):
        if len({h[:n] for h in hashes}) == len(hashes):
            return n
    raise SiteError("duplicate logic hashes in the source")


def _is_junk(r: dict[str, Any]) -> bool:
    return bool(set(r.get("quality_flags") or []) & JUNK)


def _technique_ids(tags: list[str], identities: list[dict[str, Any]] | None = None) -> list[str]:
    from sigharvest.attack import technique_ids

    if identities:
        return sorted(
            technique_ids(
                identifier
                for item in identities
                if item.get("domain") == "enterprise"
                and (identifier := item.get("current_id") or (item.get("original_id") if item.get("status") == "unverified" else None))
            )
        )
    return sorted(technique_ids(tags))


def _search_text(r: dict[str, Any], attack: dict[str, Any]) -> str:
    ls = r.get("logsource") or {}
    parts = [r.get("title") or "", ls.get("product") or "", ls.get("category") or "", ls.get("service") or ""]
    for t in r.get("tags") or []:
        t = str(t)
        parts.append(t[7:] if t.lower().startswith("attack.") else t)
    names = attack.get("techniques", {})
    for tid in _technique_ids(r.get("tags") or [], r.get("attack")):
        parts.extend([tid, names.get(tid, "")])
    return " ".join(parts)


def _conversion_summary(conv: Any) -> dict[str, Any]:
    if not isinstance(conv, dict) or not conv:
        return {"tested": False, "counts": {}, "targets": []}
    targets = sorted((str(k), str(v.get("status", "skipped") if isinstance(v, dict) else v)) for k, v in conv.items())
    return {"tested": True, "counts": dict(Counter(v for _k, v in targets)), "targets": targets}


def licence_links(expression: str | None) -> list[dict[str, str | None]]:
    """Each licence id of a stated licence with the address of its text (DRL item 3, CC-BY §3(a)(1)(C): the licence
    text or its URI travels with the rule); url None when there is no public text to point to (LicenseRef-*, words)."""
    from sigharvest.licence_texts import bundled_id, link, spdx_ids

    if not expression:
        return []
    whole = bundled_id(expression.strip())
    out: list[dict[str, str | None]] = []
    for i in [whole] if whole else spdx_ids(expression):
        known = bundled_id(i) or (i if re.fullmatch(r"[A-Za-z][A-Za-z0-9.+-]*\d[A-Za-z0-9.+-]*", i) else None)
        out.append({"id": i, "url": safe_url(link(known)) if known else None})
    return out


def _detail(r: dict[str, Any], lid: str, variants: list[list[Any]], page: str | None, cols: list[list[str]]) -> dict[str, Any]:
    canonical = dict(r.get("canonical") or {})
    canonical["url"] = safe_url(canonical.get("url"))
    yaml_text = r.get("yaml")
    note = None
    shared = yaml_text is not None
    if yaml_text is None:
        note = "licence"
    elif len(yaml_text) > YAML_MAX:
        yaml_text, note = None, "size"
    return {
        "lid": lid,
        "logic_hash": r["logic_hash"],
        "rule_id": r.get("rule_id"),
        "kind": r.get("kind"),
        "title": r.get("title"),
        # A rule whose text is not redistributed shows metadata and a link only, also from releases built before
        # release rows dropped that prose.
        "description": r.get("description") if shared else None,
        "logsource": r.get("logsource") or {},
        "level": r.get("level"),
        "status": r.get("status"),
        "tags": r.get("tags") or [],
        "attack": r.get("attack") or [],
        "author": r.get("author") if shared else None,
        "modified": r.get("modified"),
        "sources": r.get("sources") or [],
        "n_independent": r.get("n_independent") or 1,
        "canonical": canonical,
        "score": round(float(r.get("score") or 0.0), 1),
        "validation": r.get("validation"),
        "conversion": _conversion_summary(r.get("conversion")),
        "quality_flags": r.get("quality_flags") or [],
        "licence": r.get("licence"),
        "licence_links": licence_links(r.get("licence")),
        "licence_from": r.get("licence_from"),
        "licence_class": r.get("licence_class"),
        "drl_origin": bool(r.get("drl_origin")),
        "yaml": yaml_text,
        "yaml_note": note,
        "variants": variants,
        "page": page,
        "collections": cols,
    }


# ------------------------------------------------------------------ build


class _Writer:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.files: list[Path] = []

    def _path(self, rel: str) -> Path:
        p = (self.root / rel).resolve()
        if not p.is_relative_to(self.root):
            raise SiteError(f"refusing to write outside the site folder: {rel!r}")
        return p

    def text(self, rel: str, content: str) -> None:
        p = self._path(rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        self.files.append(p)

    def copy(self, src: Path, rel: str) -> None:
        p = self._path(rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, p)
        self.files.append(p)


def _prepare_out(out: Path, base_url: str) -> Path:
    root = out / base_url.strip("/") if base_url.strip("/") else out
    out.mkdir(parents=True, exist_ok=True)
    (out / MARKER).write_text("written by sigharvest site build; atomically replaced on the next build\n", encoding="utf-8")
    root.mkdir(parents=True, exist_ok=True)
    return root


def _build_site(
    source: Path,
    out: Path,
    *,
    collections: Sequence[str] | Path | None = None,
    theme: str = "default",
    base_url: str = "/rules/",
    limit: int | None = None,
    site_url: str = "https://example.org",
    index_scope: str = "families",
    min_score: float = 70.0,
    max_pages: int = 10000,
    max_files: int = 20000,
    attack: Path | None = None,
    build_epoch: int | None = None,
    trust: SignaturePolicy | None = None,
) -> SiteStats:
    """Build the static site from a release folder or a workspace. See the module docstring for the layout.

    collections: names to publish (None = every collection of the source, [] = none) or a collections.json path.
    index_scope: "families" (searchable: the best rule of each family) or "all" (every non-junk rule).
    min_score / max_pages: static pages for the best family rules with score >= min_score (collections always get
    pages); max_files caps the total file count (Cloudflare Workers static assets / Pages allow 20,000).
    """
    t0 = time.monotonic()
    if theme not in THEMES:
        raise SiteError(f"unknown theme {theme!r} (available: {', '.join(THEMES)})")
    if not _BASE.fullmatch(base_url) or any(x in (".", "..") for x in base_url.split("/")):
        raise SiteError("base_url must start and end with '/' and contain only letters, digits, '.', '_', '-'")
    site_url = site_url.rstrip("/")
    if not _SITE.match(site_url):
        raise SiteError("site_url must be like https://example.org")
    if index_scope not in ("families", "all"):
        raise SiteError("index_scope: families or all")
    src = _load_source(Path(source), collections, limit, attack, build_epoch, trust)
    stats = SiteStats(root=Path(out).resolve())
    stats.seconds["read"] = time.monotonic() - t0
    t1 = time.monotonic()

    rows = src.rows
    from sigharvest.attack import Matrix, Technique, tag_metadata

    matrix = None
    if src.attack.get("techniques"):
        matrix = Matrix(
            src.attack["version"],
            [],
            {tid: Technique(tid, name, [], tid.split(".")[0] if "." in tid else None) for tid, name in src.attack["techniques"].items()},
            src.attack.get("replaced", {}),
            set(src.attack.get("deprecated", [])),
        )
    interpretations = {}
    metadata_cache: dict[str, dict[str, Any] | None] = {}
    for row in rows:
        if matrix or not row.get("attack"):
            row["attack"] = tag_metadata(row.get("tags") or [], matrix, metadata_cache)
        if not isinstance(row["attack"], list):
            raise SiteError("invalid ATT&CK interpretation metadata")
        for item in row["attack"]:
            if not isinstance(item, dict) or any(not isinstance(item.get(key), str) for key in ("original", "label", "domain", "status")):
                raise SiteError("invalid ATT&CK interpretation metadata")
            for key in ("current_id", "original_id"):
                tid = item.get(key)
                if tid is not None and (not isinstance(tid, str) or not re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid)):
                    raise SiteError("invalid ATT&CK interpretation ID")
            interpretations[item["original"].lower()] = item
    src.attack["interpretations"] = interpretations
    if not rows:
        raise SiteError("the source has no rules")
    n = _lid_length(rows)
    lid_of = {r["logic_hash"]: r["logic_hash"][:n] for r in rows}
    by_hash = {r["logic_hash"]: r for r in rows}
    families: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        families[r.get("family") if r.get("family") is not None else r["logic_hash"]].append(r)
    for members in families.values():
        members.sort(key=_rank_key)
    family_of = {r["logic_hash"]: fam for fam, members in families.items() for r in members}

    # searchable rows, in rank order
    if index_scope == "families":
        scope = [next((m for m in members if not _is_junk(m)), None) for members in families.values()]
        indexed = sorted((r for r in scope if r is not None), key=_rank_key)
    else:
        indexed = sorted((r for r in rows if not _is_junk(r)), key=_rank_key)
    rank = {r["logic_hash"]: i for i, r in enumerate(indexed)}

    # collections, resolved against this source (logic hash, else best row with the same real rule id)
    by_rule_id: dict[str, dict[str, Any]] = {}
    for r in sorted(rows, key=_rank_key):
        if r.get("rule_id"):
            by_rule_id.setdefault(r["rule_id"], r)
    cols: list[dict[str, Any]] = []
    member_of: dict[str, list[list[str]]] = defaultdict(list)
    used_slugs: set[str] = set()
    for c in src.collections:
        s = slug(c["name"])
        while s in used_slugs:
            s += "-x"
        used_slugs.add(s)
        items = []
        for it in c.get("items", []):
            hit = by_hash.get(it.get("logic_hash") or "")
            state = "current" if hit is not None else "missing"
            if hit is None and it.get("rule_id") and it["rule_id"] in by_rule_id:
                hit, state = by_rule_id[it["rule_id"]], "updated"
            items.append({"row": hit, "title": (hit or {}).get("title") or it.get("title"), "note": it.get("note"), "state": state})
            if hit is not None and [c["name"], s] not in member_of[hit["logic_hash"]]:
                member_of[hit["logic_hash"]].append([c["name"], s])
        cols.append({"name": c["name"], "slug": s, "description": c.get("description"), "items": items})

    # file budget: everything else first, then static rule pages
    token_post: dict[str, list[int]] = defaultdict(list)
    for i, r in enumerate(indexed):
        for t in sorted(tokens(_search_text(r, src.attack))):
            token_post[t].append(i)
    shards: dict[str, dict[str, list[int]]] = defaultdict(dict)
    for t, ids in token_post.items():
        shards[shard_key(t)][t] = _deltas(ids)
    facets: dict[str, list[int]] = defaultdict(list)
    products = Counter((r.get("logsource") or {}).get("product") or "" for r in indexed)
    top_products = [p for p, k in products.most_common(40) if p and k >= 20]
    for i, r in enumerate(indexed):
        if r.get("level") in LEVELS[1:]:
            facets[f"level-{r['level']}"].append(i)
        if r.get("yaml") is not None:
            facets["text"].append(i)
        if r.get("validation") == "ok":
            facets["val-ok"].append(i)
        p = (r.get("logsource") or {}).get("product")
        if p in top_products:
            facets[f"product-{slug(p)}"].append(i)
    detail_bytes = sum(len(r.get("yaml") or "") + 1200 for r in rows)
    prefix = next((k for k in (1, 2, 3) if detail_bytes / 16**k <= 200_000), 3)
    detail_shards = len({h[:prefix] for h in by_hash})
    static_assets = sorted(p for p in (HERE / "static").iterdir() if p.is_file())
    # index.html, rule.html, attribution.html, ATTRIBUTION.md, NOTICE.md, sitemap.xml, changes.json, feed.xml,
    # data/meta.json, data/attack.json, .well-known/security.txt
    fixed = 11
    other = len(static_assets) + fixed + len(shards) + len(facets) + math.ceil(len(indexed) / CHUNK) + detail_shards + len(cols)
    must = {r["logic_hash"] for c in cols for it in c["items"] if (r := it["row"]) is not None}
    room = min(max_pages, max_files - other) - len(must)
    if room < 0:
        raise SiteError(f"file budget {max_files} is too small: {other} data files + {len(must)} collection rule pages")
    paged = set(must)
    for r in indexed:
        if room <= 0 or (r.get("score") or 0) < min_score:
            break
        if r["logic_hash"] not in paged:
            paged.add(r["logic_hash"])
            room -= 1
    page_of = {h: f"r/{lid_of[h]}.html" for h in paged}
    stats.seconds["index"] = time.monotonic() - t1
    t2 = time.monotonic()

    root = _prepare_out(Path(out), base_url)
    w = _Writer(root)
    for p in static_assets:
        w.copy(p, f"static/{p.name}")

    # data
    built = build_time(build_epoch)
    product_list = sorted({(r.get("logsource") or {}).get("product") or "" for r in indexed})
    cat_list = sorted({(ls.get("category") or ls.get("service") or "") for r in indexed for ls in [r.get("logsource") or {}]})
    p_idx = {p: i for i, p in enumerate(product_list)}
    c_idx = {c: i for i, c in enumerate(cat_list)}
    hist = Counter(min(100, max(0, math.floor(r.get("score") or 0))) for r in indexed)
    score_cut = [sum(k for sc, k in hist.items() if sc >= s) for s in range(101)]
    meta = {
        "format": FORMAT,
        "built": built,
        "release": src.manifest.get("created"),
        "sigharvest": _version("sigharvest"),
        "base": base_url,
        "scope": index_scope,
        "rules": len(rows),
        "indexed": len(indexed),
        "pages": len(paged),
        "chunk": CHUNK,
        "lid": n,
        "detail_prefix": prefix,
        "levels": LEVELS,
        "validation": VALIDATION,
        "products": product_list,
        "categories": cat_list,
        "facets": {k: len(v) for k, v in sorted(facets.items())},
        "top_products": [[p, slug(p), products[p]] for p in top_products],
        "token_shards": sorted(shards),
        "score_cut": score_cut,
        "stop": sorted(STOP),
        "token_max": TOKEN_MAX,
        "redistributed_classes": src.manifest.get("redistributed_classes", []),
        "collections": [[c["name"], c["slug"], sum(1 for it in c["items"] if it["row"] is not None)] for c in cols],
    }
    w.text("data/meta.json", _dumps(meta))
    w.text("data/attack.json", _dumps(src.attack or {"version": "", "tactics": {}, "techniques": {}}))
    for key, post in shards.items():
        w.text(f"data/t/{key}.json", _dumps(post))
    for key, ids in facets.items():
        w.text(f"data/f/{key}.json", _dumps(_deltas(ids)))
    for start in range(0, len(indexed), CHUNK):
        chunk = []
        for r in indexed[start : start + CHUNK]:
            ls = r.get("logsource") or {}
            chunk.append(
                [
                    lid_of[r["logic_hash"]],
                    r.get("title") or "",
                    LEVELS.index(r["level"]) if r.get("level") in LEVELS else 0,
                    round(float(r.get("score") or 0)),
                    p_idx[ls.get("product") or ""],
                    c_idx[ls.get("category") or ls.get("service") or ""],
                    " ".join(_technique_ids(r.get("tags") or [], r.get("attack"))[:6]),
                    r.get("n_independent") or 1,
                    1 if r["logic_hash"] in paged else 0,
                    VALIDATION.index(r["validation"]) if r.get("validation") in VALIDATION else 0,
                    1 if r.get("yaml") is not None else 0,
                    len(families[family_of[r["logic_hash"]]]),
                ]
            )
        w.text(f"data/m/{start // CHUNK}.json", _dumps(chunk))

    details: dict[str, dict[str, Any]] = {}

    def variants_of(r: dict[str, Any]) -> list[list[Any]]:
        out_v = []
        for m in families[family_of[r["logic_hash"]]]:
            if m is not r:
                out_v.append(
                    [
                        lid_of[m["logic_hash"]],
                        m.get("title") or "",
                        round(float(m.get("score") or 0)),
                        m.get("level") or "",
                        page_of.get(m["logic_hash"]),
                    ]
                )
            if len(out_v) >= 25:
                break
        return out_v

    shard_rows: dict[str, dict[str, Any]] = defaultdict(dict)
    for r in rows:
        h = r["logic_hash"]
        d = _detail(r, lid_of[h], variants_of(r), page_of.get(h), member_of.get(h, []))
        d["family_size"] = len(families[family_of[h]])
        shard_rows[h[:prefix]][lid_of[h]] = d
        if h in paged:
            details[h] = d
    for key, ds in shard_rows.items():
        w.text(f"data/d/{key}.json", _dumps(ds))
    stats.seconds["data"] = time.monotonic() - t2
    t3 = time.monotonic()

    # pages
    env = Environment(loader=FileSystemLoader(str(HERE / "templates")), autoescape=select_autoescape(default=True), undefined=StrictUndefined)
    from sigharvest import project
    from sigharvest.attack import ATTACK_COPYRIGHT, ATTACK_TERMS_URL, ATTACK_TRADEMARK

    env.globals.update(
        base=base_url,
        site_url=site_url,
        built=built,
        release=src.manifest.get("created") or "",
        sigharvest_version=meta["sigharvest"],
        attack_version=src.attack.get("version", ""),
        theme=theme,
        repo_url=project.repo_url(),
        issues_url=project.issues_url(),
        contact_email=project.CONTACT_EMAIL,
        not_affiliated=project.NOT_AFFILIATED,
        attack_copyright=ATTACK_COPYRIGHT,
        attack_trademark=ATTACK_TRADEMARK,
        attack_terms_url=ATTACK_TERMS_URL,
        has_notice=src.notice is not None,
    )
    env.filters["licence_links"] = licence_links
    env.filters["safe_url"] = safe_url
    env.filters["tag_info"] = lambda tag: tag_info(str(tag), src.attack)
    env.filters["shorten"] = shorten

    def page(rel: str, template: str, **ctx: Any) -> None:
        depth = rel.count("/")
        w.text(rel, env.get_template(template).render(rel=rel, up="../" * depth, canonical=f"{site_url}{base_url}{rel}", **ctx))

    stats_ctx = {
        "rules": len(rows),
        "indexed": len(indexed),
        "pages": len(paged),
        "with_yaml": sum(1 for r in rows if r.get("yaml") is not None),
        "sources": len(src.manifest.get("sources", [])),
    }
    top = [details[r["logic_hash"]] for r in indexed[:30] if r["logic_hash"] in details]
    page("index.html", "index.html", stats=stats_ctx, collections=meta["collections"], top=top, top_products=meta["top_products"], levels=LEVELS[1:])
    page("rule.html", "dynamic.html")
    sources = [
        {"name": x.get("name"), "url": safe_url(x.get("url")), "licence": x.get("licence"), "rules": x.get("rules"), "commit": x.get("commit")}
        for x in src.manifest.get("sources", [])
    ]
    page("attribution.html", "attribution.html", sources=sources, classes=meta["redistributed_classes"])
    w.text("ATTRIBUTION.md", _attribution_md(src.manifest))
    w.text(".well-known/security.txt", project.security_txt(datetime.fromisoformat(built), f"{site_url}{base_url}.well-known/security.txt"))
    if src.notice is not None:
        w.text("NOTICE.md", src.notice)
    for h in sorted(paged, key=lambda h: (rank.get(h, 10**9), h)):
        page(page_of[h], "rule.html", r=details[h])
    for c in cols:
        page(f"c/{c['slug']}.html", "collection.html", c=c, lid_of=lid_of, page_of=page_of)
    urls = [
        "index.html",
        "attribution.html",
        *(f"c/{c['slug']}.html" for c in cols),
        *(page_of[h] for h in sorted(paged, key=lambda h: (rank.get(h, 10**9), h))),
    ]
    w.text("sitemap.xml", _sitemap(f"{site_url}{base_url}", urls, built[:10]))
    # What changed: changes.json (changes.py shape) and an Atom feed of it, for feed readers and scripts.
    from sigharvest.changes import KINDS, atom, empty, normalise, safe_text

    changed = normalise(src.changes) if src.changes else empty(until=str(src.manifest.get("created") or ""))
    known = set(by_hash)
    public = {k: [x for x in changed.get(k) or [] if k == "removed" or str(x.get("new") if k == "changed" else x.get("logic_hash")) in known] for k in KINDS}
    # Every change is listed (no cap); "incomplete" carries the notes of run reports from older versions that kept
    # at most 5,000 rows per list. The Atom feed has the first FEED_LIMIT entries and says so in its subtitle.
    incomplete = [safe_text(x) for x in (src.changes or {}).get("incomplete") or []]
    w.text(
        "changes.json",
        _dumps({"since": changed.get("since", ""), "until": changed.get("until", ""), **public} | ({"incomplete": incomplete} if incomplete else {})),
    )

    def rule_link(logic: str) -> str | None:
        if logic not in lid_of:
            return None
        return f"{site_url}{base_url}{page_of[logic]}" if logic in page_of else f"{site_url}{base_url}rule.html?l={lid_of[logic]}"

    w.text(
        "feed.xml",
        atom(
            public | {"since": changed.get("since", "")},
            feed_url=f"{site_url}{base_url}feed.xml",
            site_url=f"{site_url}{base_url}",
            title="sigharvest: new and changed Sigma rules",
            link_for=rule_link,
            updated=str(changed.get("until") or built),
        ),
    )
    stats.seconds["pages"] = time.monotonic() - t3

    stats.rules, stats.indexed, stats.pages, stats.collections = len(rows), len(indexed), len(paged), len(cols)
    stats.detail_prefix = prefix
    stats.with_yaml = stats_ctx["with_yaml"]
    stats.metadata_only = len(rows) - stats.with_yaml
    by_dir: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for p in w.files:
        size = p.stat().st_size
        rel = p.relative_to(root)
        key = "/".join(rel.parts[:2]) if rel.parts[0] == "data" and len(rel.parts) > 2 else (rel.parts[0] if len(rel.parts) > 1 else ".")
        by_dir[key][0] += 1
        by_dir[key][1] += size
        stats.files += 1
        stats.bytes += size
        if size > stats.largest[1]:
            stats.largest = (str(rel), size)
    stats.by_dir = {k: (v[0], v[1]) for k, v in by_dir.items()}
    if stats.files > max_files:
        raise SiteError(f"{stats.files} files written, over the budget of {max_files}")
    stats.seconds["total"] = time.monotonic() - t0
    return stats


def build_site(
    source: Path,
    out: Path,
    *,
    collections: Sequence[str] | Path | None = None,
    theme: str = "default",
    base_url: str = "/rules/",
    limit: int | None = None,
    site_url: str = "https://example.org",
    index_scope: str = "families",
    min_score: float = 70.0,
    max_pages: int = 10000,
    max_files: int = 20000,
    attack: Path | None = None,
    build_epoch: int | None = None,
    trust: SignaturePolicy | None = None,
) -> SiteStats:
    """Stage and validate the complete site before atomic promotion, retaining the prior site on failure."""
    if out.is_symlink() or (out.exists() and (not out.is_dir() or (any(out.iterdir()) and not (out / MARKER).is_file()))):
        raise SiteError(f"{out} is not an empty or sigharvest site folder (no {MARKER}); choose an empty folder")
    # Never replace a workspace or release that is also the input.
    if out.resolve() == source.resolve() or out.resolve() in source.resolve().parents:
        raise SiteError("site output must not contain its source")
    with staged_directory(out) as stage:
        stats = _build_site(
            source,
            stage,
            collections=collections,
            theme=theme,
            base_url=base_url,
            limit=limit,
            site_url=site_url,
            index_scope=index_scope,
            min_score=min_score,
            max_pages=max_pages,
            max_files=max_files,
            attack=attack,
            build_epoch=build_epoch,
            trust=trust,
        )
    stats.root = out.resolve()
    return stats


def _attribution_md(manifest: dict[str, Any]) -> str:
    lines = [
        "# Attribution",
        "",
        "The Sigma rules on this site were written by the authors of the repositories below and keep their licences.",
        "Each rule page names the rule's licence and links to its canonical copy. Rules without a stated licence are",
        "listed with metadata and a link only; their text is not redistributed.",
        "",
        "| source | licence | rules | url |",
        "|---|---|---|---|",
    ]
    for x in manifest.get("sources", []):
        cells = [str(x.get(k) or ("not stated" if k == "licence" else "")).replace("|", "\\|").replace("\n", " ") for k in ("name", "licence", "rules", "url")]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def _sitemap(prefix: str, urls: Iterable[str], day: str) -> str:
    body = "".join(f"<url><loc>{xml_escape(prefix + u)}</loc><lastmod>{day}</lastmod></url>\n" for u in urls)
    return f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n{body}</urlset>\n'


# ------------------------------------------------------------------ CLI (registered by the main CLI)


def site_command(
    out: Path = typer.Argument(..., help="Output folder; files go to OUT/<base-url>, so OUT is the site root."),
    release: Path | None = typer.Option(None, "--release", help="Build from a release folder instead of the workspace."),
    collection: list[str] | None = typer.Option(None, "--collection", help="Collection to publish (repeatable; default: all)."),
    no_collections: bool = typer.Option(False, "--no-collections", help="Publish no collection."),
    collections_file: Path | None = typer.Option(None, "--collections-file", help="collections.json to use (see --save-collections)."),
    save_collections: Path | None = typer.Option(None, "--save-collections", help="Write the workspace collections to this JSON file and exit."),
    base_url: str = typer.Option("/rules/", "--base-url", help="URL path of the site; starts and ends with /."),
    site_url: str = typer.Option("https://example.org", "--site-url", help="Origin for canonical links and sitemap.xml."),
    all_rules: bool = typer.Option(False, "--all", help="Make every non-junk rule searchable, not only the best of each family."),
    min_score: float = typer.Option(70.0, "--min-score", help="Static pages for family-best rules with at least this score."),
    max_pages: int = typer.Option(10000, "--max-pages", help="Maximum static rule pages, including the always-published collection rules."),
    max_files: int = typer.Option(20000, "--max-files", help="File budget (Workers static assets / Pages: 20,000)."),
    limit: int | None = typer.Option(None, "--limit", help="Only the first N rules of the source (quick previews)."),
    theme: str = typer.Option("default", "--theme", help="Site theme; only default is available."),
    build_epoch: int | None = typer.Option(None, "--build-epoch", help="Unix timestamp for reproducible files; defaults to SOURCE_DATE_EPOCH or now."),
    allow_incomplete: bool = typer.Option(
        False, "--allow-incomplete", help="Publish even when the first update did not pass its gates (the corpus is incomplete)."
    ),
) -> None:
    """Build the static rules site (search, rule pages, collections, embeddable cards). Writes files only."""
    from rich.markup import escape

    from sigharvest.cli.common import SafeConsole
    from sigharvest.config import find_workspace

    console = SafeConsole(soft_wrap=True)  # paths and the preview command stay on one line in pipes
    ws = find_workspace()
    try:
        if save_collections is not None:
            with _ro_session(ws.db_path) as s:
                snap = collections_snapshot(s, collection or None)
            save_collections.write_text(json.dumps(snap, indent=1, ensure_ascii=False), encoding="utf-8")
            console.print(f"{len(snap['collections'])} collections -> {save_collections}")
            return
        if release is not None and not allow_incomplete:
            from sigharvest.release_reader import ReleaseError, read_json

            try:
                incomplete = read_json(release / "manifest.json").get("incomplete") is True
            except (ReleaseError, OSError, ValueError):
                incomplete = False  # build_site verifies the pack and reports what is wrong with it
            if incomplete:
                console.print("[red]the release is marked incomplete[/] (built with --allow-incomplete from a partial corpus)")
                console.print("not publishing an incomplete corpus (--allow-incomplete to publish it anyway)")
                raise typer.Exit(1)
        if release is None and ws.db_path.exists():
            from sigharvest.runs import publish_refusal

            with _ro_session(ws.db_path) as s:
                refusal = publish_refusal(s)
                if refusal is not None:
                    console.print(f"[red]{escape(refusal)}[/]", soft_wrap=True)
                    if not allow_incomplete:
                        console.print("not publishing an incomplete corpus (--allow-incomplete to publish it anyway)")
                        raise typer.Exit(1)
        cols: Sequence[str] | Path | None = [] if no_collections else (collections_file or (collection or None))
        st = build_site(
            release or ws.root,
            out,
            collections=cols,
            theme=theme,
            base_url=base_url,
            limit=limit,
            site_url=site_url,
            index_scope="all" if all_rules else "families",
            min_score=min_score,
            max_pages=max_pages,
            max_files=max_files,
            build_epoch=build_epoch,
        )
    except SiteError as exc:
        console.print(f"[red]{escape(str(exc))}[/]")
        raise typer.Exit(2) from exc
    console.print(st.summary(), markup=False)
    console.print(f"preview: python -m http.server -d {out} 8000, then open http://127.0.0.1:8000{base_url}", markup=False)
