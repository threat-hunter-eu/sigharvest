"""Shared pieces of the web routes: the per-app context (workspace, sessions, templates, limits, caches), request
guards and small helpers used by several route modules.

Every route module gets the context with `web: WebDep` (FastAPI dependency) instead of closing over create_app's
locals, so routes can live in their own modules under `sigharvest.web.routes`.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Annotated, Any
from urllib.parse import quote, urlencode

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from sigharvest.config import Workspace
from sigharvest.db import IN_CHUNK
from sigharvest.index import GroupFilters
from sigharvest.models import LogicGroup
from sigharvest.web.security import same_origin_headers

PAGE = 50
SEARCH_WAIT_SECONDS = 1.0  # a search waits this long for a free search slot, then 503 (a waiting search holds a server thread)
PER_PAGE_CHOICES = (50, 100, 250, 500)
MAX_PER_PAGE = PER_PAGE_CHOICES[-1]
# Query parameters of a search (they define which rules a search or an export works on).
SEARCH_KEYS = (
    "q", "new_since_run", "technique", "tactic", "license", "hide_flagged", "datasource", "exclude_source", "source_only",
    "collection", "product", "category", "service", "level", "status", "tag", "source", "validation", "backend", "min_sources",
    "deprecated", "junk", "flag", "coverage_tags", "licence", "profile",
)  # fmt: skip
FILTER_LABELS = {
    "technique": "technique", "tactic": "tactic", "license": "license", "hide_flagged": "hide flagged rules",
    "datasource": "data source", "exclude_source": "exclude repository", "source_only": "only in selected repositories",
    "collection": "collection", "product": "product", "category": "category", "service": "service", "level": "level",
    "status": "status", "tag": "tag", "source": "source", "validation": "validation", "backend": "converts to",
    "min_sources": "sources ≥", "flag": "flag", "deprecated": "include deprecated", "junk": "show low quality",
    "coverage_tags": "technique tags", "new_since_run": "new since update", "licence": "licence",
    "profile": "profile",
}  # fmt: skip
TOGGLES = {"source_only", "deprecated", "junk", "hide_flagged"}


@dataclass
class Limits:
    """Request limits, read from sigharvest.web.app when the app is created (tests lower them)."""

    form_bytes: int
    collection_add: int
    export_rules: int


@dataclass
class Web:
    ws: Workspace
    Session_: sessionmaker[Session]
    templates: Jinja2Templates
    limits: Limits
    cache: dict[str, Any] = field(default_factory=dict)
    ReadSession_: sessionmaker[Session] | None = None
    # Searches (full text and facets) running at once; one reader of the pool stays free for every other page.
    search_slots: threading.BoundedSemaphore = field(default_factory=lambda: threading.BoundedSemaphore(1))

    def read_session(self) -> Session:
        return (self.ReadSession_ or self.Session_)()

    @contextmanager
    def search_slot(self) -> Iterator[None]:
        """Run one search (results, facets, counts) in a slot. When every slot stays busy for SEARCH_WAIT_SECONDS,
        answer 503 with Retry-After instead of queueing: expensive searches cannot starve the light pages."""
        if not self.search_slots.acquire(timeout=SEARCH_WAIT_SECONDS):
            raise HTTPException(
                503,
                "Too many searches are running at the same time; retry in a few seconds (light pages stay available).",
                headers={"Retry-After": "5"},
            )
        try:
            yield
        finally:
            self.search_slots.release()

    def render(self, request: Request, name: str, context: dict[str, Any], status_code: int = 200) -> Any:
        """Render a page; every page gets `st`, the sidebar status (rules, sources, last sync, new-rules badge)."""
        if "st" not in context:
            context = {**context, "st": self.status()}
        return self.templates.TemplateResponse(request, name, context, status_code=status_code)

    def status(self) -> dict[str, Any]:
        from sigharvest.web import present, queries

        try:
            with self.read_session() as s:
                return queries.cached(self.cache, "sidebar", s, lambda session: present.sidebar(self.ws.root, session), size=1)
        except Exception:  # noqa: BLE001 - an error page must render even when the database cannot be read
            return {"empty": False, "n_rules": 0, "n_sources": 0, "last_sync": None, "failing": [], "new_badge": 0, "incomplete": ""}


def get_web(request: Request) -> Web:
    web: Web = request.app.state.web
    return web


WebDep = Annotated[Web, Depends(get_web)]


def same_origin(request: Request) -> None:
    """Dependency for every state-changing or expensive route: refuse cross-site requests (CSRF, and pages elsewhere
    firing searches at the local UI). The UploadGuard middleware
    checks the same headers before a body is read; this repeats the check where the route is declared."""
    if not same_origin_headers({k.lower(): v for k, v in request.headers.items()}):
        raise HTTPException(403, "cross-site request refused")


SameOrigin = Depends(same_origin)


class Params(dict[str, Any]):
    """Query parameters for templates: a missing optional parameter reads as an empty string."""

    def __init__(self, params: Any = None, **kwargs: Any) -> None:
        super().__init__(params or {}, **kwargs)
        if hasattr(params, "getlist"):
            for key in ("source", "exclude_source", "level", "status", "validation"):
                if params.getlist(key):
                    self[key] = ",".join(params.getlist(key))

    def __missing__(self, key: str) -> str:
        return ""


def local_path(path: str) -> str:
    """A redirect target on this site ("/..."), or "" (prevents open redirects such as //evil or /\\evil)."""
    return path if re.fullmatch(r"/(?![/\\])[A-Za-z0-9/?&=%._~+:#-]*", path) else ""


def back(path: str, **params: str) -> RedirectResponse:
    q = urlencode({k: v for k, v in params.items() if v})
    return RedirectResponse(path + (f"?{q}" if q else ""), status_code=303)


def with_params(target: str, **params: Any) -> str:
    """target plus extra query parameters, before any #fragment."""
    frag = ""
    if "#" in target:
        target, frag = target.split("#", 1)
        frag = "#" + frag
    sep = "&" if "?" in target else "?"
    return f"{target}{sep}{urlencode(params)}{frag}"


def col_url(name: str) -> str:
    return "/collections/" + quote(name, safe="")


def group_or_404(s: Session, logic: str) -> LogicGroup:
    logic = logic.lower()
    if not re.fullmatch(r"[0-9a-f]{6,64}", logic):
        raise HTTPException(404, "rule not found")
    # Hexadecimal range predicates use the BINARY hash index; SQLite's
    # default case-insensitive LIKE scans it even for an exact 64-digit hash.
    match = LogicGroup.logic_hash == logic if len(logic) == 64 else (LogicGroup.logic_hash >= logic) & (LogicGroup.logic_hash < logic + "g")
    g = s.scalars(select(LogicGroup).where(match).order_by(LogicGroup.id).limit(1)).first()
    if g is None:
        raise HTTPException(404, "rule not found")
    return g


def groups_for_keys(s: Session, text: str) -> list[LogicGroup]:
    """Logic groups for every hex key (logic hash or rule id prefix, 6+ characters) found in text, in order;
    keys that match nothing are skipped (selection.known_groups)."""
    from sigharvest.selection import known_groups

    return known_groups(s, re.findall(r"[0-9a-f][0-9a-f-]{5,63}", text.lower()))[0]


def canonical_raws(s: Session, groups: list[LogicGroup]) -> dict[int, str]:
    """Rule YAML of each group's canonical version, by version id (chunked IN queries)."""
    from sigharvest.models import RuleVersion

    ids = [g.canonical_version_id for g in groups]
    out: dict[int, str] = {}
    for i in range(0, len(ids), IN_CHUNK):
        out.update({vid: raw for vid, raw in s.execute(select(RuleVersion.id, RuleVersion.raw).where(RuleVersion.id.in_(ids[i : i + IN_CHUNK])))})
    return out


def _flag(params: dict[str, Any], key: str) -> bool:
    return str(params.get(key) or "") in ("1", "true", "yes", "on")


def filters_from(params: dict[str, Any]) -> GroupFilters:
    def text(key: str) -> str | None:
        value = str(params.get(key) or "").strip()
        return value[:500] or None

    return GroupFilters(
        new_since_run=text("new_since_run"),
        technique=text("technique"),
        tactic=text("tactic"),
        license=text("license"),
        hide_flagged=_flag(params, "hide_flagged"),
        coverage_tags=text("coverage_tags"),
        product=text("product"),
        category=text("category"),
        service=text("service"),
        level=text("level"),
        status=text("status"),
        tag=text("tag"),
        source=text("source"),
        exclude_source=text("exclude_source"),
        source_only=_flag(params, "source_only"),
        datasource=text("datasource"),
        collection=text("collection"),
        validation=text("validation"),
        backend=text("backend"),
        min_sources=int(params["min_sources"]) if str(params.get("min_sources") or "").isdigit() else None,
        include_deprecated=bool(params.get("deprecated")),
        include_junk=bool(params.get("junk")),
        flag=params.get("flag") if re.fullmatch(r"[a-z_]{2,30}", str(params.get("flag") or "")) else None,
        profile=text("profile"),
    )


NO_SOURCE = "\x00none"  # a source name that cannot exist: an empty licence-class selection matches nothing


def filters_for(s: Session, params: dict[str, Any]) -> GroupFilters:
    """filters_from plus the web-only `licence` filter (a licence class: permissive, copyleft, restricted, none):
    rules with a copy in a source of that class, combined with any `source` filter."""
    from dataclasses import replace

    f = filters_from(params)
    wanted = str(params.get("licence") or "").strip().lower()
    if not wanted:
        return f
    from sigharvest.web.present import sources_by_class

    names = set(sources_by_class(s).get(wanted, []))
    if f.source:
        names &= {v.strip() for v in f.source.split(",") if v.strip()}
    return replace(f, source=",".join(sorted(names)) or NO_SOURCE)


def per_page(params: dict[str, Any]) -> int:
    """Rows per result page: a positive integer up to MAX_PER_PAGE; anything else reads as the default PAGE."""
    value = str(params.get("per_page") or "")
    if not (value.isascii() and value.isdigit()) or len(value) > 6 or int(value) < 1:
        return PAGE
    return min(int(value), MAX_PER_PAGE)


def search_params(params: dict[str, Any]) -> dict[str, str]:
    """Only the search-defining parameters (no page, view, messages)."""
    return {k: str(params[k]) for k in SEARCH_KEYS if params.get(k)}


def chips(params: dict[str, Any], path: str = "/search") -> list[dict[str, str]]:
    """Active filters with a link that removes each one (the search text is in the search box, not a chip)."""
    keep = {k: v for k, v in search_params(params).items() if k != "q"}
    out = []
    for key, label in FILTER_LABELS.items():
        if not keep.get(key):
            continue
        rest = {k: v for k, v in search_params(params).items() if k != key}
        out.append({"key": key, "label": label, "value": "" if key in TOGGLES else keep[key], "href": path + ("?" + urlencode(rest) if rest else "")})
    return out
