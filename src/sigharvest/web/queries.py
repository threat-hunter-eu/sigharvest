"""Web aggregates cached by transactional database revisions."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, TypeVar

from sqlalchemy import bindparam, func, select, text
from sqlalchemy.orm import Session

from sigharvest.models import LogicGroup, Occurrence, RuleVersion, Source, SyncLog

T = TypeVar("T")
SYNC_BATCH_GAP = timedelta(minutes=30)  # sync runs closer than this belong to the same `sigharvest update`
RECENT_LIMIT = 12
_lock = threading.Lock()
CACHE_BYTES = 64 * 1024 * 1024
ENTRY_BYTES = 16 * 1024 * 1024


def index_key(s: Session) -> tuple[Any, ...]:
    """Constant-size revision read, including changes outside the current process."""
    from sigharvest.attack_search import catalog_key
    from sigharvest.read_cache import revision
    from sigharvest.source_status import config_key

    return (revision(s), config_key(s), catalog_key(s))


def cached(
    cache: dict[str, Any],
    name: str,
    s: Session,
    compute: Callable[[Session], T],
    key: tuple[Any, ...] | None = None,
    size: int = 8,
    *,
    wait_seconds: float | None = None,
) -> T:
    """compute(s) once per index key (and optional extra key); keeps the last `size` entries per name."""
    from sigharvest.read_cache import computation_lock

    full = (index_key(s), key)
    with _lock:
        slot: dict[Any, Any] = cache.setdefault(name, {})
        if full in slot:
            return slot[full]
        if "_locks" not in cache:
            cache["_locks"] = [threading.RLock() for _ in range(32)]
        locks = cache["_locks"]
        lock = locks[hash((name, full)) % len(locks)]
    with computation_lock(lock, wait_seconds):
        with _lock:
            if full in slot:
                return slot[full]
        started = time.perf_counter()
        value = compute(s)
        from sigharvest.read_cache import value_bytes

        used = value_bytes((full, value))
        with _lock:
            sizes = cache.setdefault("_sizes", {})
            if used <= ENTRY_BYTES:
                if len(slot) >= size:
                    old = next(iter(slot))
                    del slot[old]
                    sizes.pop((name, old), None)
                while sizes and sum(sizes.values()) + used > CACHE_BYTES:
                    old_name, old_key = next(iter(sizes))
                    del sizes[old_name, old_key]
                    cache[old_name].pop(old_key, None)
                slot[full] = value
                sizes[name, full] = used
            cache.setdefault("_timings", {})[name] = round((time.perf_counter() - started) * 1000, 1)
    return value


@dataclass
class Corpus:
    logic: int = 0
    families: int = 0
    documents: int = 0
    sources: int = 0
    sources_total: int = 0
    last_sync: datetime | None = None
    levels: list[tuple[str, int]] = field(default_factory=list)
    validation: dict[str, int] = field(default_factory=dict)
    flags: list[tuple[str, int]] = field(default_factory=list)
    junk: int = 0
    multi_source: int = 0
    tactics: list[tuple[str, int]] = field(default_factory=list)  # (tactic tag, families), most first
    tagged: int = 0


# ATT&CK tactic tags (tag spec: hyphenated short names; defense-evasion split into stealth/defense-impairment in v19).
TACTICS = (
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation",
    "stealth", "defense-impairment", "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
)  # fmt: skip


def corpus(s: Session) -> Corpus:
    from sigharvest.page_summaries import read

    stored = read(s, "corpus")
    if stored is not None:
        stored = dict(stored)
        stored["last_sync"] = datetime.fromisoformat(stored["last_sync"]) if stored["last_sync"] else None
        for field_name in ("levels", "flags", "tactics"):
            stored[field_name] = [tuple(row) for row in stored[field_name]]
        return Corpus(**stored)
    c = Corpus()
    c.logic, c.families = s.execute(select(func.count(), func.count(func.distinct(LogicGroup.family_id))).select_from(LogicGroup)).one()
    c.documents = s.scalar(select(func.count()).select_from(Occurrence).where(Occurrence.present.is_(True))) or 0
    from sigharvest.source_status import counts as source_counts

    c.sources_total, c.sources = source_counts(s)
    c.last_sync = s.scalar(select(func.max(Source.last_sync_at)))
    order = ["critical", "high", "medium", "low", "informational"]
    levels = dict(s.execute(select(LogicGroup.level, func.count()).where(LogicGroup.junk.is_(False)).group_by(LogicGroup.level)).all())
    c.levels = [(lv, int(levels.get(lv, 0))) for lv in order] + ([("none", int(levels[None]))] if levels.get(None) else [])
    c.validation = {k or "untested": int(n) for k, n in s.execute(select(LogicGroup.validation, func.count()).group_by(LogicGroup.validation))}
    flag_sql = "SELECT j.value, count(*) AS n FROM logic_groups g, json_each(g.quality_flags) j GROUP BY j.value ORDER BY n DESC"
    c.flags = [(str(k), int(n)) for k, n in s.execute(text(flag_sql))]
    c.junk, c.multi_source = (int(x or 0) for x in s.execute(text("SELECT total(junk), total(n_independent >= 2) FROM logic_groups")).one())
    # Tactic tags (attack.execution...), families per tactic; technique tags are attack.tNNNN.
    tactic_sql = text(
        "SELECT j.value, count(DISTINCT g.family_id) AS n FROM logic_groups g, json_each(g.tags) j "
        "WHERE j.value IN :tags AND g.junk = 0 GROUP BY j.value ORDER BY n DESC"
    ).bindparams(bindparam("tags", expanding=True))
    c.tactics = [(str(k), int(n)) for k, n in s.execute(tactic_sql, {"tags": [f"attack.{t}" for t in TACTICS]})]
    c.tagged = s.scalar(text("SELECT count(*) FROM logic_groups WHERE tags LIKE '%\"attack.t%' AND junk = 0")) or 0
    return c


# ----------------------------------------------------------------------------- recent changes


@dataclass
class Recent:
    since: datetime | None = None  # start of the last sync batch
    first_sync: bool = False  # the last batch was the first one: everything is new
    count: int = 0  # unique logic first seen in that batch (not junk)
    rules: list[dict[str, Any]] = field(default_factory=list)  # best-scored of them


def _batch_start(s: Session) -> datetime | None:
    """Start of the last sync batch: sync runs are walked back from the newest while they follow each other."""
    starts = list(s.scalars(select(SyncLog.started_at).order_by(SyncLog.started_at.desc()).limit(20_000)))
    if not starts:
        return None
    start = starts[0]
    for t in starts[1:]:
        if start - t > SYNC_BATCH_GAP:
            break
        start = t
    return start


def _first_version_at(s: Session, when: datetime) -> int | None:
    """Smallest rule version id first seen at or after `when`. Versions get increasing ids and a first_seen of
    their insert time, so a binary search over ids finds it with ~18 primary-key reads (first_seen has no index)."""
    lo, hi = s.execute(select(func.min(RuleVersion.id), func.max(RuleVersion.id))).one()
    if lo is None:
        return None

    def seen(i: int) -> datetime | None:
        return s.scalar(select(RuleVersion.first_seen).where(RuleVersion.id >= i).order_by(RuleVersion.id).limit(1))

    last = seen(hi)
    if last is None or last < when:
        return None
    while lo < hi:
        mid = (lo + hi) // 2
        t = seen(mid)
        if t is not None and t >= when:
            hi = mid
        else:
            lo = mid + 1
    return int(lo)


def recent(s: Session) -> Recent:
    from sigharvest.page_summaries import read

    stored = read(s, "recent")
    if stored is not None:
        stored = dict(stored)
        stored["since"] = datetime.fromisoformat(stored["since"]) if stored["since"] else None
        return Recent(**stored)
    r = Recent(since=_batch_start(s))
    if r.since is None:
        return r
    first = _first_version_at(s, r.since)
    if first is None:
        return r
    r.first_sync = s.scalar(select(func.min(RuleVersion.id))) == first
    # Logic whose oldest version came with the last batch (one index scan on rule_versions.logic_hash).
    new = {
        h
        for (h,) in s.execute(
            text("SELECT logic_hash FROM rule_versions GROUP BY logic_hash HAVING min(id) >= :first"),
            {"first": first},
        )
    }
    if not new:
        return r
    r.count = sum(1 for (h,) in s.execute(text("SELECT logic_hash FROM logic_groups WHERE junk = 0")) if h in new)
    q = select(LogicGroup.logic_hash, LogicGroup.title, LogicGroup.level, LogicGroup.score, LogicGroup.canonical_source, LogicGroup.product,
               LogicGroup.category, LogicGroup.service).where(LogicGroup.junk.is_(False)).order_by(LogicGroup.score.desc())  # fmt: skip
    for lh, title, level, score, src, product, category, service in s.execute(q.execution_options(yield_per=500)):
        if lh not in new:
            continue
        r.rules.append(
            {
                "logic_hash": lh,
                "title": title,
                "level": level,
                "score": score,
                "source": src,
                "logsource": " / ".join(x for x in (product, category, service) if x),
            }
        )
        if len(r.rules) >= RECENT_LIMIT:
            break
    return r


# ----------------------------------------------------------------------------- live counts


# ----------------------------------------------------------------------------- sources


def source_quality(s: Session) -> dict[str, dict[str, Any]]:
    """Per source: unique logic, families, logic found nowhere else, share that validates, average score."""
    from sigharvest.models import SourceSummary

    return {r.name: {k: getattr(r, k) for k in ("logic", "families", "only", "valid_pct", "avg_score")} for r in s.scalars(select(SourceSummary))}


def source_documents(s: Session) -> dict[int, int]:
    """Indexed document counts; avoid scanning occurrences on a cold Sources page."""
    from sigharvest.models import SourceSummary

    rows = s.execute(select(Source.id, SourceSummary.documents).join(SourceSummary, SourceSummary.name == Source.name))
    return {int(sid): int(n) for sid, n in rows}
