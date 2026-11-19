"""Export: the full export page (what, format, options, the same command for the terminal, a summary) and the
downloads behind it. Every download is a GET (/export/download), so a link or a bookmark repeats it; a selection
travels as h=<logic hash> values (up to MAX_SELECTED), and a POST with the same fields is accepted for scripts."""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from sigharvest.conversion import BACKENDS
from sigharvest.errors import SigharvestError
from sigharvest.models import LogicGroup
from sigharvest.web import downloads, queries
from sigharvest.web.deps import Params, SameOrigin, Web, WebDep, search_params
from sigharvest.web.routes.rules import QUERY_LABELS

router = APIRouter()
MAX_SELECTED = 5_000
FORMAT_CHOICES = ("zip", "siem", "navigator", "sheet")
CLI_FLAGS = {
    "technique": "--technique", "tactic": "--tactic", "product": "--product", "category": "--category", "service": "--service",
    "tag": "--tag", "source": "--rule-source", "level": "--level", "status": "--status", "validation": "--validation", "backend": "--backend",
    "profile": "--profile",
}  # fmt: skip


def selected_hashes(params: Any) -> list[str]:
    values = params.getlist("h") if hasattr(params, "getlist") else [params.get("h")] if params.get("h") else []
    out: list[str] = []
    for value in values:
        for h in re.findall(r"[0-9a-f]{6,64}", str(value).lower()):
            if h not in out:
                out.append(h)
    if len(out) > MAX_SELECTED:
        raise HTTPException(413, f"At most {MAX_SELECTED:,} selected rules; export the search instead.")
    return out


def scope_of(params: Params, hashes: list[str]) -> str:
    scope = str(params.get("scope") or "")
    if scope == "selected" and hashes:
        return "selected"
    if scope == "all":
        return "all"
    if scope == "search" or search_params(params):
        return "search"
    return "selected" if hashes else "all"


def groups_for(web: Web, s: Session, params: Params, hashes: list[str], scope: str) -> list[LogicGroup]:
    from sigharvest.web.routes.search import run_search

    limit = web.limits.export_rules
    if scope == "selected":
        exact = [h for h in hashes if len(h) == 64]
        found = list(s.scalars(select(LogicGroup).where(LogicGroup.logic_hash.in_(exact)))) if exact else []
        have = {g.logic_hash for g in found}
        for h in hashes:
            if len(h) < 64 and not any(x.startswith(h) for x in have):
                g = s.scalars(select(LogicGroup).where(LogicGroup.logic_hash >= h, LogicGroup.logic_hash < h + "g").limit(1)).first()
                if g is not None:
                    found.append(g)
                    have.add(g.logic_hash)
        order = {h: i for i, h in enumerate(hashes)}
        return sorted(found, key=lambda g: min((i for h, i in order.items() if g.logic_hash.startswith(h)), default=0))
    search = Params(search_params(params)) if scope == "search" else Params()
    try:
        groups, total = run_search(s, search, limit + 1, 0, family=False)
    except SigharvestError as exc:
        raise HTTPException(400, str(exc)) from exc
    if total > limit:
        raise HTTPException(413, f"The selection has {total:,} rules; narrow it to at most {limit:,} or use `sigharvest export`.")
    return groups


def describe(params: Params) -> list[tuple[str, str]]:
    """The search in words: [("text", "mimikatz"), ("level", "high")]."""
    out = []
    for key, value in search_params(params).items():
        out.append(("text" if key == "q" else key.replace("_", " "), value))
    return out


def cli_command(params: Params, scope: str, fmt: str, target: str, stem: str) -> str:
    """The `sigharvest export` command that writes the same rules (selections have no single flag)."""
    if fmt == "navigator":
        cov = ["sigharvest", "coverage"]
        sp = search_params(params) if scope == "search" else {}
        for key in ("product", "category", "service", "source", "validation", "backend"):
            if sp.get(key):
                cov += [f"--{key}", sp[key]]
        cov += ["--navigator", f"{stem}.layer.json"]
        if sp.get("q"):
            # `--` ends the options, so a query that starts with "-" stays a query when pasted.
            cov += ["--", sp["q"]]
        return " ".join(shlex.quote(p) for p in cov)
    parts = ["sigharvest", "export"]
    query = None
    if scope == "search":
        sp = search_params(params)
        query = sp.get("q")
        for key, flag in CLI_FLAGS.items():
            if sp.get(key):
                parts += [flag, sp[key]]
    parts += ["--unit", "logic"]
    if fmt == "siem":
        parts += ["--format", target, "--out", f"{stem}.{target}.txt"]
    elif fmt == "sheet":
        parts += ["--format", "csv", "--out", f"{stem}.csv"]
    else:
        parts += ["--format", "zip", "--out", f"{stem}.zip"]
    if params.get("private") and fmt in ("zip", "sheet"):
        parts.append("--include-private-sources")
    if query:
        # `--` ends the options, so a query that starts with "-" stays a query when pasted.
        parts += ["--", query]
    return " ".join(shlex.quote(p) for p in parts)


def stem_for(params: Params, scope: str, n: int) -> str:
    if scope == "all":
        return "sigharvest-all"
    if scope == "selected":
        return f"sigharvest-{n}-rules"
    words = [v for _k, v in describe(params)][:3]
    return downloads.safe_stem("-".join(re.sub(r"[^A-Za-z0-9]+", "-", w).strip("-").lower() for w in words if w)[:60]) or "sigharvest-search"


def download_response(web: Web, params: Params, format: str, *, scope: str | None = None, hashes: list[str] | None = None) -> Response:
    hashes = hashes if hashes is not None else []
    scope = scope or scope_of(params, hashes)
    if format == "siem":
        format = str(params.get("target") or (BACKENDS[0] if BACKENDS else ""))
    if format == "sheet":
        format = "csv" if params.get("sheet") != "jsonl" else "jsonl"
    if format == "zip" and params.get("package") == "yaml":
        format = "yaml"
    if format in ("splunk", "lucene", "esql", "opensearch", "microsoft365defender", "loki", "sqlite") and format not in BACKENDS:
        from sigharvest.conversion import backend_error

        raise HTTPException(400, backend_error(format) or f"The {format} backend is not installed.")
    return held_download(lambda: _download(web, params, format, scope, hashes))


SEND_SECONDS = 600.0  # a whole download must be sent within this time...
SEND_IDLE_SECONDS = 30.0  # ...and each chunk within this one; a stalled client is disconnected
CHUNK = 64 * 1024


class SpooledDownload(Response):
    """A built download sent from its temporary file. Every chunk has an idle timeout and the whole body a deadline,
    so a client that stops reading is disconnected and `held` (the file and the send slot) is always released."""

    def __init__(self, spool: Any, held: ExitStack, size: int, headers: dict[str, str], media_type: str | None) -> None:
        import weakref

        super().__init__(content=b"", headers=headers, media_type=media_type)
        self.headers["content-length"] = str(size)
        self.spool, self.held = spool, held
        weakref.finalize(self, held.close)  # a response that is never sent still frees its slot

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        import anyio

        try:
            with anyio.fail_after(SEND_SECONDS):
                await send({"type": "http.response.start", "status": self.status_code, "headers": self.raw_headers})
                while chunk := await anyio.to_thread.run_sync(self.spool.read, CHUNK):
                    with anyio.fail_after(SEND_IDLE_SECONDS):
                        await send({"type": "http.response.body", "body": chunk, "more_body": True})
                await send({"type": "http.response.body", "body": b"", "more_body": False})
        except TimeoutError:
            pass  # the body is short of its Content-Length: the server closes the connection and the client sees it
        finally:
            self.held.close()


def held_download(build: Callable[[], Response]) -> Response:
    """Build a download in its turn of the download queue, then send it from a temporary file.

    The build turn (1 running + 2 waiting) is released as soon as the body is on disk; the send holds only a send slot
    (ondemand.SENDS_MAX, 429 beyond) and the temporary file, both released when the body is sent, the client goes
    away or the send times out. A slow client holds no download bytes in memory."""
    import tempfile

    from sigharvest import ondemand

    with ExitStack() as guard:
        try:
            guard.enter_context(ondemand.download_send())
        except ondemand.QueueFull:
            raise HTTPException(429, "Too many downloads in progress; try again in a moment.", headers={"Retry-After": "10"}) from None
        spool = guard.enter_context(tempfile.TemporaryFile())
        with download_slot():
            built = build()
        spool.write(built.body)
        size = spool.tell()
        spool.seek(0)
        held = guard.pop_all()
    headers = {k: v for k, v in built.headers.items() if k.lower() not in ("content-type", "content-length")}
    media = built.media_type
    del built
    return SpooledDownload(spool, held, size, headers, media)


@contextmanager
def download_slot() -> Iterator[None]:
    """A turn in the bounded web download queue (ondemand.export_job): 429 when the queue is full, 503 when the turn
    does not come in time. Every GET or POST route that builds a download goes through it."""
    from sigharvest import ondemand

    try:
        with ondemand.export_job():
            yield
    except ondemand.QueueFull:
        raise HTTPException(429, "Too many downloads in progress; try again in a moment.", headers={"Retry-After": "10"}) from None
    except ondemand.Busy:
        raise HTTPException(503, "Busy building other downloads; try again in a moment.", headers={"Retry-After": "10"}) from None


def _download(web: Web, params: Params, format: str, scope: str, hashes: list[str]) -> Response:
    with web.read_session() as s:
        groups = groups_for(web, s, params, hashes, scope)
        if not params.get("deprecated"):
            groups = [g for g in groups if (g.status or "") not in ("deprecated", "unsupported") or scope == "selected"]
        if params.get("skip_invalid"):
            groups = [g for g in groups if g.validation != "error"]
        if not groups:
            raise HTTPException(404, "Nothing to export: the selection is empty.")
        stem = stem_for(params, scope, len(groups))
        return downloads.download(
            s,
            groups,
            format,
            stem,
            licences=str(params.get("licences") or "split"),
            layout=str(params.get("layout") or "logsource"),
            raw_queries=bool(params.get("raw")),
            include_private=bool(params.get("private")),
        )


def _core_counts(s: Session) -> tuple[int, int]:
    """(rules, families) of SigmaHQ's core profile: the page exports one rule per logic, `sigharvest export` one per
    family by default, so both numbers are shown with their unit."""
    from sigharvest.index import match_counts
    from sigharvest.web.deps import filters_for

    try:
        return match_counts(s, None, filters_for(s, {"profile": "core"}))
    except SigharvestError:
        return 0, 0


@router.get("/export", response_class=HTMLResponse)
def export_page(request: Request, web: WebDep) -> Response:
    params = Params(request.query_params)
    hashes = selected_hashes(request.query_params)
    scope = scope_of(params, hashes)
    fmt = str(params.get("format") or "zip")
    fmt = fmt if fmt in FORMAT_CHOICES else "siem" if fmt in BACKENDS else "zip"
    target = str(params.get("target") or "")
    target = target if target in BACKENDS else (BACKENDS[0] if BACKENDS else "")
    licences = str(params.get("licences") or "split")
    layout = str(params.get("layout") or "logsource")
    from sigharvest.web.routes.search import count_for

    limit = web.limits.export_rules
    with web.search_slot(), web.read_session() as s:
        everything = queries.cached(web.cache, "export_all", s, lambda session: count_for(session, {}), size=1)
        core, core_families = queries.cached(web.cache, "export_core", s, lambda session: _core_counts(session), size=1) if everything > limit else (0, 0)
        if scope == "all" and "scope" not in params and everything > limit and 0 < core <= limit:
            # The page opened without a choice and "everything" cannot be downloaded here: start from SigmaHQ's core
            # profile instead of a disabled Download button (the notice says why; Everything stays one click away).
            q = [(k, v) for k, v in request.query_params.multi_items() if k not in ("scope", "profile")]
            return RedirectResponse("/export?" + urlencode([("profile", "core"), ("scope", "search"), ("big", "1"), *q]), status_code=303)
        search_n = count_for(s, search_params(params)) if search_params(params) else 0
        try:
            groups = groups_for(web, s, params, hashes, scope)
            error = ""
        except HTTPException as exc:
            groups, error = [], str(exc.detail)
            if exc.status_code == 413 and scope != "selected":
                error = (
                    f"{'Everything' if scope == 'all' else 'This search'} is more than the {limit:,} rules a web download can hold. "
                    "Narrow it with a search or a profile, or run the command under Download in a terminal: it has no limit."
                )
        private = bool(params.get("private"))
        key = (scope, tuple(sorted(search_params(params).items())), tuple(hashes), licences, private)
        summary = queries.cached(web.cache, "export_plan", s, lambda session: downloads.plan(session, groups, licences, private), key=key, size=8)
        techniques = len({t for g in groups for t in (g.tags or []) if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", str(t).lower())})
    stem = stem_for(params, scope, len(groups))
    keep = {k: v for k, v in search_params(params).items()}

    def scope_href(new_scope: str) -> str:
        q: list[tuple[str, str]] = [("scope", new_scope), ("format", fmt)]
        if new_scope == "search":
            q += list(keep.items())
        q += [("h", h) for h in hashes]
        return "/export?" + urlencode(q)

    hidden = [(k, v) for k, v in keep.items()] if scope == "search" else []
    hidden += [("h", h) for h in hashes] if scope == "selected" else []
    hidden.append(("scope", scope))
    return web.render(
        request,
        "export.html",
        {
            "scope": scope,
            "fmt": fmt,
            "target": target,
            "licences": licences,
            "layout": layout,
            "counts": {"search": search_n, "selected": len(hashes), "all": everything},
            "scope_href": scope_href,
            "described": describe(params),
            "hidden": hidden,
            "n": len(groups),
            "summary": summary,
            "techniques": techniques,
            "stem": stem,
            "error": error,
            "too_big": everything > limit,
            "limit": limit,
            "core": core,
            "core_families": core_families,
            "core_href": "/export?" + urlencode([("profile", "core"), ("scope", "search"), ("format", fmt)]),
            "big_default": bool(params.get("big")) and scope == "search",
            "cli": {f: cli_command(params, scope, f, target or "splunk", stem) for f in FORMAT_CHOICES},
            "has_search": bool(keep),
            "deprecated": bool(params.get("deprecated")),
            "private": bool(params.get("private")),
            "skip_invalid": bool(params.get("skip_invalid")) or "skip_invalid" not in params,
            "query_labels": QUERY_LABELS,
        },
    )


@router.get("/downloads")
def downloads_page(request: Request) -> Response:
    """Older docs called the Export page "the downloads page": keep that address working."""
    from fastapi.responses import RedirectResponse

    query = str(request.query_params)
    return RedirectResponse("/export" + (f"?{query}" if query else ""), status_code=301)


@router.get("/export/download", dependencies=[SameOrigin])
def export_download(request: Request, web: WebDep) -> Response:
    params = Params(request.query_params)
    return download_response(web, params, str(params.get("format") or "zip"), hashes=selected_hashes(request.query_params))


@router.post("/export/download", dependencies=[SameOrigin])
async def export_download_post(request: Request, web: WebDep) -> Response:
    form = await request.form()
    params = Params(form)
    # The build waits for the export slot and then converts and zips; like the GET handler it must not run on the event loop.
    return await run_in_threadpool(download_response, web, params, str(params.get("format") or "zip"), hashes=selected_hashes(form))
