"""Current source configuration over retained database history.

Reading status never retires occurrences or rewrites source rows. Configuration
edits invalidate page caches immediately, independently of sync/index.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from sigharvest.config import SourceConfig, Workspace, load_sources
from sigharvest.models import Occurrence, SearchSummary, Source, SourceSummary


def workspace(s: Session) -> Workspace | None:
    if "status_workspace" not in s.info:
        main = next((row[2] for row in s.execute(text("PRAGMA database_list")) if row[1] == "main"), "")
        s.info["status_workspace"] = Workspace(Path(main).resolve().parent.parent) if main else None
    return s.info["status_workspace"]


def configuration_key(ws: Workspace) -> tuple[Any, ...]:
    def stamp(path: Path) -> Any:
        try:
            st = path.stat()
        except FileNotFoundError:
            return None
        return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns

    return str(ws.root), stamp(ws.sources_file)


def config_key(s: Session) -> tuple[Any, ...] | None:
    ws = workspace(s)
    return configuration_key(ws) if ws else None


@lru_cache(maxsize=16)
def _registrations(key: tuple[Any, ...]) -> tuple[SourceConfig, ...]:
    return tuple(load_sources(Workspace(Path(key[0]))))


def configured(s: Session) -> dict[str, bool] | None:
    key = config_key(s)
    return {source.name: source.enabled for source in _registrations(key)} if key else None


def pending(s: Session) -> list[dict[str, Any]]:
    """Visible registrations without a database row, before their first sync."""

    key = config_key(s)
    if key is None:
        return []
    # Include hidden names here solely to avoid resurrecting them from config.
    known = set(s.scalars(select(Source.__table__.c.name)))
    return [
        {
            "name": source.name,
            "url": source.url,
            "licence": source.licence,
            "priority": source.priority,
            "enabled": source.enabled,
            "status": "added, waiting for the next update" if source.enabled else "disabled",
            "pending": True,
            "last_sync": None,
            "commit": None,
            "docs": 0,
            "logic": 0,
            "families": 0,
            "only": 0,
            "avg_score": 0,
            "valid_pct": None,
            "overlaps": [],
        }
        for source in _registrations(key)
        if source.name not in known
    ]


def status(name: str, enabled: bool, documents: int, last_sync: Any, config: dict[str, bool] | None) -> str:
    if config is not None and name not in config:
        return "removed from config"
    if not (config.get(name, enabled) if config is not None else enabled):
        return "disabled"
    if documents == 0:
        return "no Sigma rules" if last_sync else "not synced"
    return "active"


def counts(s: Session) -> tuple[int, int]:
    """Configured database sources (total, enabled); removed history is excluded."""
    config = configured(s)
    enabled = [
        config[name] if config is not None else value for name, value in s.execute(select(Source.name, Source.enabled)) if config is None or name in config
    ]
    return len(enabled), sum(enabled)


def documents(s: Session) -> dict[str, int]:
    """Use the current source projection or count live membership before indexing."""
    from sigharvest.search_summary import key

    ready = s.get(SearchSummary, "source_projection")
    if ready is not None and ready.revision == key(s):
        return {name: count for name, count in s.execute(select(Source.name, SourceSummary.documents).join(SourceSummary, SourceSummary.name == Source.name))}
    return dict(s.execute(select(Source.name, func.count()).join(Occurrence).where(Occurrence.present.is_(True)).group_by(Source.name)).all())
