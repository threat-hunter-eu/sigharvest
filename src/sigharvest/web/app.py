"""Local web UI: overview, search, rule pages, ATT&CK coverage, sources, changes, exports, about, and a JSON API.

Run with `sigharvest serve` (binds to 127.0.0.1 by default). Rule content comes from untrusted repositories, so every
value is rendered through Jinja2 autoescaping (StrictUndefined), links are only built for http(s) source URLs,
scripts come only from /static (Content-Security-Policy script-src 'self') and every POST is same-origin checked
and size-capped before its body is parsed (security.py). Routes live in sigharvest.web.routes, one module per page.
"""

from __future__ import annotations

import threading
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, configure_mappers, sessionmaker
from starlette.exceptions import HTTPException as StarletteHTTPException

from sigharvest.config import Workspace
from sigharvest.web.deps import Limits, Params, Web, col_url
from sigharvest.web.security import SecurityHeaders, TokenAuth, UploadGuard

HERE = Path(__file__).parent
# Limits are module attributes so they can be tuned (and lowered by tests) before create_app.
MAX_FORM_BYTES = 1024 * 1024
MAX_COLLECTION_ADD = 5_000  # rules added from one search
MAX_EXPORT_RULES = 20_000  # rules in one web export
# Loopback names only. Not "testserver" (Starlette's TestClient name): tests pass it with allowed_hosts; in
# production a resolvable "testserver" (search domain, LLMNR, mDNS) would be a DNS-rebinding opening.
LOCAL_HOSTS = ["127.0.0.1", "localhost", "::1", "[::1]"]
__all__ = ["Params", "create_app"]


@lru_cache(maxsize=1)
def _templates() -> Jinja2Templates:
    """Compiled templates with the shared filters and globals (also used to pre-render pages at index time)."""
    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    from sigharvest import conversion, project
    from sigharvest.attack import ATTACK_COPYRIGHT, ATTACK_TERMS_URL, ATTACK_TRADEMARK
    from sigharvest.help_text import GLOSSARY
    from sigharvest.web import highlight, present
    from sigharvest.web.deps import chips

    templates = Jinja2Templates(env=Environment(loader=FileSystemLoader(HERE / "templates"), autoescape=True, auto_reload=False, undefined=StrictUndefined))
    env = templates.env
    env.globals.update(
        help_text=GLOSSARY,
        backends=conversion.BACKENDS,
        conv_statuses=conversion.statuses_of,
        install_command=conversion.install_command,
        install_extra=conversion.install_extra,
        conv_summary=conversion.summary_text,
        status_labels=conversion.STATUS_LABELS,
        status_classes=conversion.STATUS_CLASSES,
        col_url=col_url,
        chips=chips,
        LIC_TITLES=present.LIC_TITLES,
        LIC_WORDS=present.LIC_WORDS,
        repo_url=project.repo_url(),
        issues_url=project.issues_url(),
        contact_email=project.CONTACT_EMAIL,
        not_affiliated=project.NOT_AFFILIATED,
        attack_copyright=ATTACK_COPYRIGHT,
        attack_trademark=ATTACK_TRADEMARK,
        attack_terms_url=ATTACK_TERMS_URL,
    )
    env.filters["qs"] = lambda d: urlencode({k: v for k, v in d.items() if v not in (None, "", False)})
    env.filters["local_time"] = lambda t: t.strftime("%Y-%m-%d %H:%M UTC") if t else ""
    env.filters["yaml_html"] = highlight.yaml_html
    env.filters["num"] = lambda n: f"{n:,}" if isinstance(n, int) else n
    env.filters["reltime"] = present.reltime
    env.filters["fulltime"] = present.fulltime
    env.filters["mark"] = present.mark
    return templates


def _limit_for(path: str) -> int:
    return MAX_FORM_BYTES


def create_app(ws: Workspace, Session_: sessionmaker[Session], allowed_hosts: list[str] | None = None, token: str | None = None, **_unused: Any) -> FastAPI:
    """The UI app. Read pages use read-only sessions when the database supports them; `token` requires HTTP Basic or
    Bearer authentication on every request (serve --token-env)."""
    from starlette.middleware.trustedhost import TrustedHostMiddleware

    from sigharvest.web.routes import ROUTERS

    configure_mappers()
    read_session: sessionmaker[Session] | None = None
    search_slots = 1
    try:
        from sigharvest.db_reads import WEB_STATEMENT_SECONDS, ReadSettings, make_read_engine
        from sigharvest.schema import head_revision

        settings = ReadSettings.from_env(statement_default=WEB_STATEMENT_SECONDS)
        search_slots = max(1, settings.pool_size - 1)
        read_session = sessionmaker(make_read_engine(ws.db_path, expected_revision=head_revision(), settings=settings), expire_on_commit=False)
    except Exception:  # noqa: BLE001 - fall back to the writable sessions (for example an in-memory test database)
        read_session = None
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> Any:
        yield
        from sigharvest import ondemand

        ondemand.shutdown()  # stop conversion workers with the server

    app = FastAPI(title="sigharvest", docs_url="/api/docs", redoc_url=None, lifespan=lifespan)
    app.add_middleware(UploadGuard, limit_for=_limit_for)
    # Blocks DNS-rebinding: a page on another domain cannot talk to the local UI through a hostname it controls.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[*LOCAL_HOSTS, *(allowed_hosts or [])])
    if token is not None:
        app.add_middleware(TokenAuth, token=token)
    app.add_middleware(SecurityHeaders)
    app.state.web = Web(
        ws=ws,
        Session_=Session_,
        ReadSession_=read_session,
        templates=_templates(),
        limits=Limits(form_bytes=MAX_FORM_BYTES, collection_add=MAX_COLLECTION_ADD, export_rules=MAX_EXPORT_RULES),
        search_slots=threading.BoundedSemaphore(search_slots),
    )
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    for router in ROUTERS:
        app.include_router(router)

    from sigharvest.attack import AttackCacheError
    from sigharvest.errors import SigharvestError
    from sigharvest.lock import LockHeld
    from sigharvest.query_limits import QueryTooLong

    async def bad_request(request: Request, exc: Exception) -> Response:
        return await _http_error(request, StarletteHTTPException(400, str(exc)))

    async def unavailable(request: Request, exc: Exception) -> Response:
        return await _http_error(request, StarletteHTTPException(503, str(exc), headers={"Retry-After": "5"}))

    async def busy(request: Request, exc: Exception) -> Response:
        message = "Another command is writing the workspace (update, index). Retry when it finishes."
        return await _http_error(request, StarletteHTTPException(503, message, headers={"Retry-After": "5"}))

    async def validation_error(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, RequestValidationError)
        return await _http_error(request, StarletteHTTPException(400, validation_message(exc.errors())))

    async def stopped(request: Request, exc: Exception) -> Response:
        from sigharvest.db_reads import WEB_STATEMENT_SECONDS, ReadSettings, interrupted

        if not interrupted(exc):
            raise exc  # any other database error stays a 500
        seconds = ReadSettings.from_env(statement_default=WEB_STATEMENT_SECONDS).statement_seconds
        message = (
            f"This search was stopped after {seconds} s: it is too expensive. Use longer or more specific words, fewer terms "
            "or a filter (level:, product:, source:...)."
        )
        return await _http_error(request, StarletteHTTPException(503, message, headers={"Retry-After": "5"}))

    from sqlalchemy.exc import OperationalError

    app.add_exception_handler(OperationalError, stopped)
    app.add_exception_handler(QueryTooLong, bad_request)

    async def out_of_range(request: Request, exc: Exception) -> Response:
        # a number beyond SQLite's 64-bit integers (min_sources=99999999999999999999) is bad input, not a 500
        return await _http_error(request, StarletteHTTPException(400, "a number in the request is out of range"))

    app.add_exception_handler(OverflowError, out_of_range)
    app.add_exception_handler(AttackCacheError, unavailable)
    app.add_exception_handler(LockHeld, busy)
    app.add_exception_handler(SigharvestError, bad_request)
    app.add_exception_handler(RequestValidationError, validation_error)
    app.add_exception_handler(StarletteHTTPException, _http_error)
    return app


TITLES = {
    400: "Request refused",
    403: "Not allowed",
    404: "Not found",
    409: "Request conflict",
    413: "Too large",
    415: "Wrong content type",
    429: "Too many requests",
    503: "Temporarily unavailable",
}


def validation_message(errors: Any) -> str:
    """A short sentence for invalid form or query fields, without echoing input."""
    parts: list[str] = []
    for error in errors:
        field = str(error.get("loc", ["", "value"])[-1]).replace("_", " ")
        kind = str(error.get("type", ""))
        context = error.get("ctx") or {}
        if kind == "missing" or (kind == "string_too_short" and context.get("min_length") == 1):
            text = f"{field} is required"
        elif kind == "string_too_long":
            text = f"{field} must be at most {context.get('max_length')} characters"
        elif kind == "string_too_short":
            text = f"{field} must be at least {context.get('min_length')} characters"
        elif kind in ("greater_than_equal", "less_than_equal", "greater_than", "less_than"):
            limit = next(iter(context.values()), "")
            text = f"{field} must be {kind.replace('_', ' ').replace('equal', 'or equal to')} {limit}"
        else:
            text = f"{field} is invalid"
        if text not in parts:
            parts.append(text)
    return ("Invalid request: " + "; ".join(parts[:5]) + ".") if parts else "Invalid request."


async def _http_error(request: Request, exc: Exception) -> Response:
    """Pages get the HTML error page (with the reason and a way back), unknown pages included; `/api/*` and clients that
    ask only for JSON keep FastAPI's JSON (docs/conventions.md)."""
    from fastapi.exception_handlers import http_exception_handler

    assert isinstance(exc, StarletteHTTPException)
    accept = request.headers.get("accept", "")
    wants_json = "application/json" in accept and "text/html" not in accept
    if wants_json or request.url.path.startswith(("/api/", "/static/")):
        return await http_exception_handler(request, exc)
    web: Web = request.app.state.web
    detail = str(exc.detail) if exc.detail else TITLES.get(exc.status_code, "Error")
    title = TITLES.get(exc.status_code, "Something went wrong")
    if exc.status_code == 404 and detail.lower() == "rule not found":
        title, detail = "This rule is not in the index", "The link points to a rule this index does not have."
    elif detail and detail.lower() != "not found":
        detail = detail[0].upper() + detail[1:] + ("" if detail.endswith((".", "!", "?")) else ".")  # a sentence on the page
    response: Response = web.render(request, "error.html", {"status": exc.status_code, "title": title, "detail": detail}, status_code=exc.status_code)
    response.headers.update(exc.headers or {})
    return response
