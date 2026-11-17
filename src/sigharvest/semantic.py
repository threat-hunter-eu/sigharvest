"""Semantic hash: the same detection written differently gets the same hash.

Computed on pySigma's parsed condition tree, where search identifiers are already inlined and modifiers are already
resolved into typed values (so `|contains: x` and `*x*`, `|endswith` and a leading `*`, `1 of sel*` and an explicit
`or` are the same). On top of that:
- nested AND/OR of the same kind are flattened, their children sorted and de-duplicated (both are commutative);
- several conditions are an OR;
- field names and logsource values are lower-cased; string values are lower-cased unless `|cased`;
- numbers are compared as strings.

This hash is stricter about meaning than logic_hash (docs/identity.md) and looser about form. It is stored as
rule_versions.semantic_hash and used to link rule families. Rules pySigma cannot parse get no semantic hash.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor
from typing import Any

from sqlalchemy import insert, or_, select, update
from sqlalchemy.orm import Session

from sigharvest.fingerprints import implementation
from sigharvest.models import RuleVersion, SemanticResult

SEMANTIC_VERSION = "sigharvest-semantic-v1"
ACTIVE_FINGERPRINT = "semantic_fingerprint"
INDEXED_FINGERPRINT = "indexed_semantic_fingerprint"
BATCH_SIZE = 2000


def toolchain() -> str:
    """The parser and semantic implementation, separate from stable logic-v1 identity."""
    return implementation("semantic", modules=("semantic.py", "detection.py"), options=SEMANTIC_VERSION)


def needs_refresh(s: Session) -> bool:
    """Also notice new/reactivated versions and a promotion not yet indexed."""
    from sigharvest.db import get_meta
    from sigharvest.query import live_version_ids

    current = toolchain()
    if get_meta(s, ACTIVE_FINGERPRINT) != current or get_meta(s, INDEXED_FINGERPRINT) != current:
        return True
    return (
        s.scalar(
            select(RuleVersion.id)
            .where(
                RuleVersion.id.in_(live_version_ids()),
                RuleVersion.kind == "rule",
                or_(RuleVersion.semantic_fingerprint.is_(None), RuleVersion.semantic_fingerprint != current),
            )
            .limit(1)
        )
        is not None
    )


def _value(v: Any) -> Any:
    from sigma.types import (
        SigmaBool,
        SigmaCasedString,
        SigmaCIDRExpression,
        SigmaCompareExpression,
        SigmaExists,
        SigmaExpansion,
        SigmaFieldReference,
        SigmaNull,
        SigmaNumber,
        SigmaRegularExpression,
        SigmaString,
    )

    if isinstance(v, SigmaExpansion):
        items = {json.dumps(_value(x), sort_keys=True): _value(x) for x in v.values}
        return ["any", [items[k] for k in sorted(items)]]
    if isinstance(v, SigmaCasedString):
        return ["cased", str(v)]
    if isinstance(v, SigmaString):
        return ["s", str(v).lower()]
    if isinstance(v, SigmaNumber):
        return ["s", str(v.number).lower()]
    if isinstance(v, SigmaRegularExpression):
        flags = sorted(getattr(f, "name", str(f)) for f in (getattr(v, "flags", None) or set()))
        return ["re", str(v.regexp), flags]
    if isinstance(v, SigmaCompareExpression):
        return ["cmp", v.op.name, str(v.number.number)]
    if isinstance(v, SigmaCIDRExpression):
        return ["cidr", str(v.network)]
    if isinstance(v, SigmaNull):
        return ["null"]
    if isinstance(v, SigmaExists):
        return ["exists", bool(v.exists)]
    if isinstance(v, SigmaBool):
        return ["bool", bool(v.boolean)]
    if isinstance(v, SigmaFieldReference):
        return ["fieldref", str(v.field).lower()]
    return ["other", type(v).__name__, str(v)]


def _node(n: Any) -> Any:
    from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionNOT, ConditionOR, ConditionValueExpression

    if isinstance(n, (ConditionAND, ConditionOR)):
        op = "and" if isinstance(n, ConditionAND) else "or"
        flat: list[Any] = []
        for a in n.args:
            c = _node(a)
            if isinstance(c, list) and c and c[0] == op:
                flat.extend(c[1])
            else:
                flat.append(c)
        uniq = {json.dumps(c, sort_keys=True): c for c in flat}
        if len(uniq) == 1:
            return next(iter(uniq.values()))
        return [op, [uniq[k] for k in sorted(uniq)]]
    if isinstance(n, ConditionNOT):
        return ["not", _node(n.args[0])]
    if isinstance(n, ConditionFieldEqualsValueExpression):
        return ["eq", str(n.field).lower(), _value(n.value)]
    if isinstance(n, ConditionValueExpression):
        return ["kw", _value(n.value)]
    raise ValueError(f"unsupported node {type(n).__name__}")


def semantic_form(raw: str) -> Any:
    """The normalised condition tree of a rule (see the module docstring), as plain JSON-able data."""
    from sigma.collection import SigmaCollection
    from sigma.rule import SigmaRule

    from sigharvest import pysigma_limits
    from sigharvest.detection import detection_only

    pysigma_limits.install()
    with pysigma_limits.budget():
        coll = SigmaCollection.from_yaml(detection_only(raw), collect_errors=True, resolve_references=False)
    rules = [r for r in coll.rules if isinstance(r, SigmaRule)]
    if not rules or getattr(coll, "errors", None) or rules[0].errors:
        raise ValueError("not parseable")
    rule = rules[0]
    trees = [_node(c.parse()) for c in rule.detection.parsed_condition]
    cond = trees[0] if len(trees) == 1 else ["or", sorted(trees, key=lambda t: json.dumps(t, sort_keys=True))]
    ls = rule.logsource
    logsource = {k: str(getattr(ls, k)).lower() for k in ("product", "category", "service") if getattr(ls, k)}
    return {"logsource": logsource, "condition": cond}


def semantic_hash(raw: str) -> str | None:
    """SHA-256 of the semantic form, or None when pySigma cannot parse the rule."""
    try:
        form = semantic_form(raw)
    except Exception:  # noqa: BLE001 - unparseable rules simply have no semantic hash
        return None
    body = json.dumps(form, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256((SEMANTIC_VERSION + "\n" + body).encode("utf-8", "surrogatepass")).hexdigest()


def _work(item: tuple[int, str]) -> tuple[int, str | None]:
    import warnings

    warnings.filterwarnings("ignore")
    return item[0], semantic_hash(item[1])


def backfill(s: Session, workers: int = 8, progress: Callable[[int, int], None] | None = None) -> int:
    """Stage a complete current generation, then atomically promote its projections.

    Batches survive interruption; neither successes nor failures are reused across
    toolchains. Existing family rows remain untouched until the caller rebuilds.
    """
    # AST-only callers do not need database setup or corpus/export queries.
    from sigharvest.db import get_meta, mark_results_changed, set_meta
    from sigharvest.query import live_version_ids

    current = toolchain()
    live = select(RuleVersion.id).where(RuleVersion.id.in_(live_version_ids()), RuleVersion.kind == "rule")
    cached = select(SemanticResult.version_id).where(SemanticResult.fingerprint == current)
    todo = list(s.scalars(live.where(RuleVersion.id.not_in(cached)).order_by(RuleVersion.id)))
    done = 0
    if todo:
        # map() submits one task per 50 documents. Small deltas need only the
        # processes that can actually receive work in the bounded input batch.
        batch_workers = min(workers, (min(len(todo), BATCH_SIZE) + 49) // 50)
        with ProcessPoolExecutor(max_workers=batch_workers) as pool:
            for i in range(0, len(todo), BATCH_SIZE):
                batch = [(vid, raw) for vid, raw in s.execute(select(RuleVersion.id, RuleVersion.raw).where(RuleVersion.id.in_(todo[i : i + BATCH_SIZE])))]
                rows = list(pool.map(_work, batch, chunksize=50))
                s.execute(insert(SemanticResult), [{"version_id": vid, "fingerprint": current, "semantic_hash": h or ""} for vid, h in rows])
                s.commit()
                done += len(batch)
                if progress:
                    progress(done, len(todo))
    # Start the write transaction before checking completeness, so ingestion cannot
    # add an uncomputed live rule between the check and projection publication.
    s.execute(update(RuleVersion).where(RuleVersion.id == -1).values(semantic_fingerprint=current))
    if s.scalar(live.where(RuleVersion.id.not_in(cached)).limit(1)) is not None:
        s.rollback()
        raise RuntimeError("live rules changed during semantic backfill; retry indexing")
    value = select(SemanticResult.semantic_hash).where(SemanticResult.version_id == RuleVersion.id, SemanticResult.fingerprint == current)
    published: Any = s.execute(
        update(RuleVersion)
        .where(RuleVersion.id.in_(live), or_(RuleVersion.semantic_fingerprint.is_(None), RuleVersion.semantic_fingerprint != current))
        .values(semantic_hash=value.scalar_subquery(), semantic_fingerprint=current)
        .execution_options(synchronize_session=False)
    )
    if get_meta(s, ACTIVE_FINGERPRINT) != current:
        set_meta(s, ACTIVE_FINGERPRINT, current)
    if published.rowcount:
        mark_results_changed(s)
    s.commit()
    s.expire_all()
    return done
