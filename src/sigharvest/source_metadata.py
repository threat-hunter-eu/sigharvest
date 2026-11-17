"""Source licences as sources.yaml states them now, for exports and releases.

The `sources` table copies sources.yaml only on sync/update. A licence edited in sources.yaml (for example a source
found to be proprietary) must apply to the next export or release at once, not after the next update, so every
licence decision reads sources.yaml first and falls back to the database only for sources no longer listed there.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from sigharvest.config import SourceConfig, Workspace, load_sources
from sigharvest.models import Source


def workspace_of(s: Session) -> Workspace | None:
    """The workspace whose data/sigharvest.db this session reads, when it has a sources.yaml."""
    try:
        rows = s.execute(text("PRAGMA database_list")).all()
    except Exception:  # noqa: BLE001 - not SQLite: no workspace file to read
        return None
    files = [row[2] for row in rows if row[1] == "main" and row[2]]
    if not files:
        return None
    path = Path(files[0])
    ws = Workspace(path.parent.parent)
    if path.name != ws.db_path.name or path.parent.name != "data" or not ws.sources_file.is_file():
        return None
    return ws


_CACHE: dict[Path, tuple[tuple[int, int], dict[str, SourceConfig]]] = {}


def source_configs(s: Session) -> dict[str, SourceConfig]:
    """sources.yaml of the session's workspace by name ({} without one); re-read whenever the file changes."""
    ws = workspace_of(s)
    if ws is None:
        return {}
    stat = ws.sources_file.stat()
    stamp = (stat.st_mtime_ns, stat.st_size)
    cached = _CACHE.get(ws.sources_file)
    if cached is None or cached[0] != stamp:
        cached = (stamp, {c.name: c for c in load_sources(ws)})
        _CACHE[ws.sources_file] = cached
    return dict(cached[1])


def source_licences(s: Session, configs: dict[str, Any] | None = None) -> dict[str, str | None]:
    """Licence of every source by name: sources.yaml (`configs`, or the session's workspace) over the database."""
    out = {name: lic for name, lic in s.execute(select(Source.name, Source.licence))}
    for name, cfg in (source_configs(s) if configs is None else configs).items():
        out[name] = getattr(cfg, "licence", None)
    return out
