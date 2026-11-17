"""Disposable page inputs and autoescaped fragments published with the index.

Readers validate scope, code/templates, external inputs and transactional revisions
in their own SQLite snapshot. No request, principal, CSRF token or form is stored.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import zlib
from dataclasses import asdict
from datetime import datetime
from functools import cache
from hashlib import sha256
from pathlib import Path
from typing import Any

from fastapi.templating import Jinja2Templates
from sqlalchemy import delete
from sqlalchemy.orm import Session

from sigharvest.errors import SigharvestError
from sigharvest.fingerprints import digest, package_version
from sigharvest.models import SearchSummary
from sigharvest.read_cache import revision

MAX_BYTES = 16 * 1024 * 1024


# Python modules whose code shapes stored page inputs and fragments.
CODE = (
    "page_summaries.py",
    "attack.py",
    "web/queries.py",
    "index.py",
    "web/app.py",
    "web/routes/sources.py",
    "web/routes/coverage.py",
    "source_status.py",
)
# Stored HTML fragments (label prefix -> template). Other labels hold data only.
FRAGMENTS = {"sources_html": "sources_content.html"}
TEMPLATES = Path(__file__).parent / "web" / "templates"


@cache
def code_version() -> str:
    """Page code only: a template edit does not invalidate stored page data."""
    root = Path(__file__).parent
    return digest(
        (
            sha256(b"".join((root / name).read_bytes() for name in CODE if (root / name).is_file())).hexdigest(),
            package_version("jinja2"),
            package_version("markupsafe"),
        )
    )


@cache
def template_version(name: str) -> str:
    """A fragment template plus every template it extends, includes or imports.

    A dynamic reference cannot be resolved statically, so it falls back to all templates.
    """
    from jinja2 import Environment, meta

    env = Environment(autoescape=True)
    seen: dict[str, bytes] = {}
    pending = [name]
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen[current] = (TEMPLATES / current).read_bytes()
        for ref in meta.find_referenced_templates(env.parse(seen[current].decode("utf-8"))):
            if ref is None:
                seen = {path.name: path.read_bytes() for path in sorted(TEMPLATES.glob("*.html"))}
                pending = []
                break
            pending.append(ref)
    return digest(sorted((key, sha256(value).hexdigest()) for key, value in seen.items()))


def version(label: str) -> str:
    template = FRAGMENTS.get(label.split(":", 1)[0])
    return code_version() if template is None else digest((code_version(), template_version(template)))


def key(s: Session, label: str, extra: Any = None) -> str:
    tables = (
        ("logic_groups", "occurrences", "sources")
        if label == "corpus"
        else ("sync_log", "rule_versions", "logic_groups")
        if label == "recent"
        else ("logic_groups", "sources", "occurrences", "rule_versions", "source_summaries", "source_overlaps")
        if label.startswith("source")
        else ("logic_groups", "rule_versions", "sources", "occurrences", "collections", "collection_items", "test_results")
    )
    from sigharvest.source_status import config_key

    return digest(
        (
            version(label),
            revision(s, tables),
            config_key(s) if label == "corpus" or label.startswith("source") else None,
            extra,
        )
    )


def name(label: str) -> str:
    return f"page:v2:{label}"


def read(s: Session, label: str, extra: Any = None) -> Any:
    if s.info.get("publishing_pages"):
        return None
    stored = s.get(SearchSummary, name(label))
    if stored is not None and stored.revision == key(s, label, extra):
        if not isinstance(stored.payload, dict):
            return None
        if "compressed" not in stored.payload:
            return stored.payload.get("value")
        encoded = stored.payload["compressed"]
        if not isinstance(encoded, str) or len(encoded) > MAX_BYTES * 2:
            return None
        try:
            decoder = zlib.decompressobj()
            raw = decoder.decompress(base64.b64decode(encoded, validate=True), MAX_BYTES + 1)
            if len(raw) > MAX_BYTES or not decoder.eof or decoder.unused_data:
                return None
            return json.loads(raw)["value"]
        except (ValueError, KeyError, TypeError, zlib.error, binascii.Error):
            return None
    return None


def _json_date(value: Any) -> str:
    if not isinstance(value, datetime):
        raise TypeError(f"unsupported page input: {type(value).__name__}")
    return value.isoformat()


def store(s: Session, label: str, value: Any, extra: Any = None) -> None:
    # Round-trip dates explicitly; no pickle or executable serialized objects.
    raw = json.dumps({"value": value}, default=_json_date, separators=(",", ":")).encode()
    if len(raw) > MAX_BYTES:
        s.execute(delete(SearchSummary).where(SearchSummary.name == name(label)))
        return
    payload = {"compressed": base64.b64encode(zlib.compress(raw, level=1)).decode()} if len(raw) > 65536 else json.loads(raw)
    s.merge(SearchSummary(name=name(label), revision=key(s, label, extra), payload=payload))


@cache
def publication_templates() -> Jinja2Templates:
    from sigharvest.web.app import _templates

    return _templates()


def refresh(s: Session) -> None:
    """Publish all default views; the surrounding index transaction owns commit."""
    from sigharvest.config import Workspace
    from sigharvest.web import queries
    from sigharvest.web.routes.sources import SORT_KEYS, render_sources, source_inputs

    s.flush()
    s.info["publishing_pages"] = True
    try:
        templates = publication_templates()
        store(s, "corpus", asdict(queries.corpus(s)))
        store(s, "recent", asdict(queries.recent(s)))
        # Indexing sessions are file-backed. The standard workspace locates
        # the optional ATT&CK catalog next to its data/ folder.
        database = s.get_bind().engine.url.database
        ws = Workspace(Path(database).resolve().parent.parent) if database and database != ":memory:" else None
        if ws:
            from sigharvest.attack import compute, coverage_key, coverage_payload

            # Index publication stays offline; the coverage command prepares the
            # optional ATT&CK matrix before a later index publishes its counts.
            matrix_key = coverage_key(ws)
            if matrix_key is not None:
                try:
                    coverage = compute(ws, s)
                except (SigharvestError, OSError, ValueError, KeyError, TypeError):
                    logging.getLogger(__name__).warning("Coverage page projection skipped: invalid offline ATT&CK input")
                else:
                    store(s, "attack_coverage", coverage_payload(coverage), matrix_key)
        inputs = source_inputs(s)
        store(s, "source_inputs", inputs)
        for sort in SORT_KEYS:
            store(s, f"sources_html:{sort}", render_sources(templates, inputs, sort))
        s.flush()
    finally:
        s.info.pop("publishing_pages", None)
