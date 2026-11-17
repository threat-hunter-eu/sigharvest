"""Route modules of the web UI, one per page or area. Each exposes `router`; app.create_app includes them all."""

from __future__ import annotations

from fastapi import APIRouter

from sigharvest.web.routes import about, changes, collections, coverage, export, families, overview, redirects, rules, search, sources

ROUTERS: list[APIRouter] = [
    overview.router,
    search.router,
    rules.router,
    families.router,
    coverage.router,
    sources.router,
    changes.router,
    export.router,
    about.router,
    collections.router,
    redirects.router,
]
