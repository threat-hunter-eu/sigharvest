"""Rule pages: canonical YAML, conversion on demand, copies, family variants, similar rules, history; side-by-side compare."""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from sigharvest.conversion import BACKENDS
from sigharvest.licensing import narrows, shipped_licence
from sigharvest.models import LogicGroup, NearDuplicate, Occurrence, RuleVersion, Source, TestResult
from sigharvest.sources import file_link
from sigharvest.web import present, queries
from sigharvest.web.deps import SameOrigin, Web, WebDep, canonical_raws, group_or_404

router = APIRouter()


QUERY_LABELS = {
    "splunk": "Splunk SPL",
    "lucene": "Elastic Lucene",
    "esql": "ES|QL",
    "microsoft365defender": "Microsoft KQL",
    "opensearch": "OpenSearch",
    "loki": "Grafana Loki",
    "sqlite": "SQLite",
}
TAB_ORDER = ("splunk", "lucene", "esql", "microsoft365defender", "opensearch", "loki", "sqlite")
COPIES_SHOWN = 6
# On-demand conversion limits (update no longer converts every rule; the rule page converts the open tab). Size,
# value-count, time and memory limits and the number of conversions at once are in ondemand.py.
CONVERT_MAX_SIBLINGS = 200


def query_tabs(conversions: dict[str, TestResult]) -> list[dict[str, Any]]:
    """One tab per installed backend, from the stored conversion results (`update --convert` or `test --stage convert`).

    A tab without a stored result is converted on demand by app.js (/api/convert); without JavaScript it links there."""
    from sigharvest.conversion import STATUS_LABELS

    tabs = []
    for target in [t for t in TAB_ORDER if t in BACKENDS]:
        r = conversions.get(target)
        detail = (r.detail or {}) if r is not None else {}
        results = [x for x in detail.get("results") or [] if isinstance(x, dict)]
        blocks: list[dict[str, Any]] = []
        combined = detail.get("combined_query")
        if combined and len(results) > 1:
            blocks.append({"label": "Combined query for " + ", ".join(str(x) for x in detail.get("combined_sources") or []), "text": str(combined)})
        else:
            for x in results:
                queries = [str(q) for q in x.get("queries") or []]
                if queries:
                    label = str(x.get("label") or "") if len(results) > 1 else ""
                    blocks.append(
                        {"label": label + (f" ({STATUS_LABELS.get(str(x.get('status')), x.get('status'))})" if label else ""), "text": "\n\n".join(queries)}
                    )
        notes = [str(n) for n in (detail.get("warnings") or []) + (detail.get("notes") or [])][:8]
        status = r.status if r is not None else ""
        tabs.append(
            {
                "target": target,
                "label": QUERY_LABELS.get(target, target),
                "status": status,
                "status_label": STATUS_LABELS.get(status, status or "not converted yet"),
                "pipeline": str(detail.get("pipeline") or ""),
                "blocks": blocks,
                "reason": str(detail.get("reason") or "")[:600],
                "error": str(detail.get("error") or "")[:600],
                "notes": notes,
                "stored": r is not None,
            }
        )
    ok = [i for i, tab in enumerate(tabs) if tab["blocks"] and tab["status"] in ("ok", "warning")]
    some = [i for i, tab in enumerate(tabs) if tab["blocks"]]
    checked = (ok or some or [0])[0]
    for i, tab in enumerate(tabs):
        tab["checked"] = i == checked
    return tabs


def copy_rows(copies: list[dict[str, Any]], g: LogicGroup, licences: dict[str, str | None]) -> list[dict[str, Any]]:
    """One row per copy, canonical first, then by source priority: source, licence badge, path @ commit, a note."""
    rows = []
    for c in copies:
        canonical = c["source"] == g.canonical_source and c["version_id"] == g.canonical_version_id
        info = present.licence_info(licences.get(c["source"]))
        note = ""
        if not canonical:
            note = "identical file" if c["version_id"] == g.canonical_version_id else "same logic, different metadata"
        if info["cls"] == "none":
            note = (note + "; " if note else "") + "link only"
        rows.append({**c, "canonical": canonical, "licence": info, "note": note, "short": (c.get("commit") or "")[:7]})
    rows.sort(key=lambda r: (not r["canonical"], r["priority"], r["source"], r["path"]))
    return rows


def rule_data(web: Web, s: Session, logic: str) -> dict[str, Any]:
    from sigharvest import ruleview
    from sigharvest.attack import cached_matrix, tag_metadata
    from sigharvest.attack_score import CONTEXT_KEY, Context, explanation
    from sigharvest.db import get_meta
    from sigharvest.family_links import related
    from sigharvest.summary import events, needs, summarise

    g = group_or_404(s, logic)
    v = s.get(RuleVersion, g.canonical_version_id)
    if v is None:
        raise HTTPException(404, "rule not found")
    # Version ids first (indexed by logic hash), then their occurrences (indexed by version).
    version_ids = list(s.scalars(select(RuleVersion.id).where(RuleVersion.logic_hash == g.logic_hash)))
    copies = [
        {
            "source": src_name,
            "path": occ.path,
            "commit": occ.commit,
            "link": file_link(src_url, occ.commit, occ.path),
            "priority": prio,
            "version_id": occ.version_id,
        }
        for occ, src_name, src_url, prio in s.execute(
            select(Occurrence, Source.name, Source.url, Source.priority)
            .join(Source, Source.id == Occurrence.source_id)
            .where(Occurrence.version_id.in_(version_ids), Occurrence.present.is_(True))
            .order_by(Source.priority, Source.name)
            .limit(2000)
        )
    ]
    licences = present.source_licences(s)
    variants = list(s.scalars(select(LogicGroup).where(LogicGroup.family_id == g.family_id, LogicGroup.id != g.id).order_by(LogicGroup.score.desc()).limit(50)))
    base_facts = ruleview.detection_facts(v.raw)
    raws = canonical_raws(s, variants)
    variant_diffs = {x.id: ruleview.variant_diff(base_facts, ruleview.detection_facts(raws.get(x.canonical_version_id, ""))) for x in variants}
    history = ruleview.history_order(list(s.scalars(select(RuleVersion).where(RuleVersion.rule_id == v.rule_id).order_by(RuleVersion.first_seen).limit(100))))
    results = list(s.scalars(select(TestResult).where(TestResult.version_id == v.id, TestResult.dataset == "").order_by(TestResult.stage, TestResult.target)))
    conversions = {r.target: r for r in results if r.stage == "convert"}
    matrix = cached_matrix(web.ws)
    attack = tag_metadata(g.tags or [], matrix)
    for item in attack:
        tech = matrix.techniques.get(str(item.get("current_id") or "")) if matrix is not None else None
        item["name"] = tech.name if tech is not None else ""
    # The source's licence; the rule's own `license:` only when narrower (licensing.narrows).
    licence = shipped_licence(v.rule_license, licences.get(g.canonical_source))
    context = ruleview.rule_context(v.raw)
    tactic_tags = [t.removeprefix("attack.") for t in g.tags or [] if re.fullmatch(r"attack\.[a-z][a-z_-]+", str(t).lower())]
    need_text, need_known = needs(g.product, g.category, g.service)
    tabs = query_tabs(conversions)
    return {
        "g": g,
        "v": v,
        "copies": copy_rows(copies, g, licences),
        "n_copies": len(copies),
        "variants": variants,
        "variant_diffs": variant_diffs,
        "related_rules": related(s, g),
        "similar": near_duplicates(s, g.logic_hash),
        "history": history,
        "rule_date": ruleview.rule_date,
        "context": context,
        "validation": next((r for r in results if r.stage == "validate"), None),
        "conversions": conversions,
        "tabs": tabs,
        "licence": present.licence_info(licence),
        "licence_from": "the rule's own license: field"
        if narrows(v.rule_license, licences.get(g.canonical_source))
        else f"the {g.canonical_source} repository",
        "attack_tags": attack,
        "techniques": [t for t in attack if t.get("original_id")],
        "tactics": tactic_tags,
        "summary": summarise(v.raw),
        "events": events(g.product, g.category, g.service),
        "needs": need_text,
        "needs_known": need_known,
        "attack_score_explanation": explanation(v.tags, Context(matrix), get_meta(s, CONTEXT_KEY)),
        "converts_ok": sum(1 for tab in tabs if tab["status"] in ("ok", "warning")),
        "conv_warnings": [f"{tab['target']}: {n}" for tab in tabs for n in tab["notes"]][:20],
    }


def near_duplicates(s: Session, logic_hash: str, limit: int = 30) -> list[tuple[LogicGroup, float]]:
    """Rules of other families with nearly the same detection (near_duplicates, computed at index time)."""
    pairs = s.execute(
        select(NearDuplicate.a, NearDuplicate.b, NearDuplicate.jaccard)
        .where((NearDuplicate.a == logic_hash) | (NearDuplicate.b == logic_hash))
        .order_by(NearDuplicate.jaccard.desc())
        .limit(limit)
    ).all()
    other = {(b if a == logic_hash else a): j for a, b, j in pairs}
    groups = {g.logic_hash: g for g in s.scalars(select(LogicGroup).where(LogicGroup.logic_hash.in_(list(other))))}
    return [(groups[h], j) for h, j in other.items() if h in groups]


@router.get("/rule/{logic}", response_class=HTMLResponse)
def rule_page(request: Request, web: WebDep, logic: str) -> Response:
    with web.read_session() as s:
        context = rule_data(web, s, logic)
    return web.render(request, "rule.html", context)


@router.get("/compare", response_class=HTMLResponse)
def compare(request: Request, web: WebDep, a: str = Query(..., max_length=64), b: str = Query(..., max_length=64)) -> HTMLResponse:
    """Side-by-side YAML of two rules (logic hash prefixes), changed lines highlighted."""
    import difflib

    with web.read_session() as s:
        ga, gb = group_or_404(s, a.lower()), group_or_404(s, b.lower())
        va, vb = s.get(RuleVersion, ga.canonical_version_id), s.get(RuleVersion, gb.canonical_version_id)
    la = (va.raw if va else "").splitlines()
    lb = (vb.raw if vb else "").splitlines()
    rows: list[tuple[str, str, str, str]] = []  # (left class, left text, right class, right text)
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(a=la, b=lb, autojunk=False).get_opcodes():
        left, right = la[i1:i2], lb[j1:j2]
        for k in range(max(len(left), len(right))):
            lt = left[k] if k < len(left) else ""
            rt = right[k] if k < len(right) else ""
            cls = "" if op == "equal" else op
            rows.append((cls if k < len(left) else "gap", lt, cls if k < len(right) else "gap", rt))
    same_semantic = bool(va and vb and va.semantic_hash and va.semantic_hash == vb.semantic_hash)
    return web.render(
        request,
        "compare.html",
        {
            "a": ga,
            "b": gb,
            "rows": rows,
            "same_logic": ga.logic_hash == gb.logic_hash,
            "same_semantic": same_semantic,
            "changed": sum(1 for r in rows if r[0] or r[2]),
        },
    )


@router.get("/rule/{logic}/yaml", response_class=PlainTextResponse)
def rule_yaml(web: WebDep, logic: str, download: bool = Query(False)) -> PlainTextResponse:
    with web.read_session() as s:
        g = group_or_404(s, logic)
        v = s.get(RuleVersion, g.canonical_version_id)
    headers = {"Content-Disposition": f'attachment; filename="{g.logic_hash[:16]}.yml"'} if download else {}
    return PlainTextResponse(v.raw if v else "", media_type="text/yaml; charset=utf-8", headers=headers)


def convert_json(web: Web, logic: str, target: str | None, variant: str | None, source: str | None) -> JSONResponse:
    """Convert the canonical copy now. `status` says how far to trust the query (conversion.py)."""
    from sigharvest import conversion
    from sigharvest.testing import siblings

    target = target or "splunk"
    if target not in BACKENDS:
        # The installed extra decides the backends ([convert] or [convert-legacy]): say which install provides it.
        raise HTTPException(400, conversion.backend_error(target) or "unknown backend")
    if variant not in conversion.VARIANTS:
        raise HTTPException(400, "unknown variant")
    with web.read_session() as s:
        g = group_or_404(s, logic)
        v = s.get(RuleVersion, g.canonical_version_id)
        raw, kind = (v.raw, v.kind) if v else ("", "rule")
        sibs = siblings(s, [v.id]).get(v.id, []) if v is not None and kind == "correlation" else []
    from sigharvest import ondemand

    too_large = ondemand.too_large(raw, sibs) or (f"{len(sibs)} referenced rules" if len(sibs) > CONVERT_MAX_SIBLINGS else None)
    if too_large:
        raise HTTPException(413, f"This rule is too large to convert in the web UI ({too_large}); use `sigharvest convert` in a terminal.")
    # The conversion runs in a bounded worker process (time and memory limits), never in this server thread.
    try:
        conv = ondemand.convert(raw, target, kind=kind, siblings=sibs, variant=variant, sources=[source] if source else None)
    except ondemand.Busy:
        raise HTTPException(503, "Busy converting other rules; try again in a moment.", headers={"Retry-After": "5"}) from None
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return JSONResponse(
        {
            "ok": bool(conv.queries),
            "status": conv.status,
            "target": target,
            "pipeline": conv.pipeline,
            "pipeline_line": conv.pipeline_line,
            "warnings": conv.warnings,
            "notes": conv.notes,
            "reason": conv.reason,
            "error": (conv.error or "")[:2000] or None,
            "queries": [conv.combined_query] if source == "combined" and conv.combined_query else conv.queries,
            "results": [r.payload() for r in conv.results],
            "combined_query": conv.combined_query,
            "combined_sources": conv.combined_sources,
            "covered_sources": conv.covered_sources,
        }
    )


@router.get("/local/convert/{logic}")
def local_convert(request: Request, logic: str) -> Response:
    """Old address of the conversion endpoint."""
    from fastapi.responses import RedirectResponse

    query = str(request.query_params)
    return RedirectResponse(f"/api/convert/{logic}" + (f"?{query}" if query else ""), status_code=301)


@router.get("/rule/{logic}/query.txt", response_class=PlainTextResponse, dependencies=[SameOrigin])
def rule_query(web: WebDep, logic: str, target: str = Query(..., max_length=40)) -> PlainTextResponse:
    """The stored query of one backend as a .txt download (converted now when nothing is stored)."""
    if target not in BACKENDS:
        from sigharvest.conversion import backend_error

        raise HTTPException(404, backend_error(target) or "backend not installed")
    with web.read_session() as s:
        g = group_or_404(s, logic)
        r = s.scalar(
            select(TestResult).where(
                TestResult.version_id == g.canonical_version_id, TestResult.stage == "convert", TestResult.target == target, TestResult.dataset == ""
            )
        )
        tab = query_tabs({target: r} if r is not None else {})
        body = "\n\n".join(b["text"] for b in tab[0]["blocks"]) if tab and tab[0]["blocks"] else ""
        from sigharvest.export_policy import attribution_comment

        v = s.get(RuleVersion, g.canonical_version_id)
        # DRL 1.1 and similar licences: the author and a reference to the original rule travel with the query.
        credit = attribution_comment(s, v) if v is not None else ""
    if not body:
        import json

        payload = json.loads(bytes(convert_json(web, logic, target, None, None).body))
        body = "\n\n".join(payload.get("queries") or []) or f"# no query: {payload.get('reason') or payload.get('error') or payload.get('status')}"
    name = f"{g.logic_hash[:16]}.{target}.txt"
    return PlainTextResponse((credit + "\n" if credit else "") + body + "\n", headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/api/convert/{logic}", dependencies=[SameOrigin])
def api_convert(web: WebDep, logic: str, target: str | None = Query(None), variant: str | None = Query(None), source: str | None = Query(None)) -> JSONResponse:
    """Convert one rule (logic hash prefix) for a backend: splunk, lucene, esql, opensearch, microsoft365defender, loki, sqlite."""
    return convert_json(web, logic, target, variant, source)


@router.get("/api/rule/{logic}")
def api_rule(web: WebDep, logic: str) -> JSONResponse:
    """One rule (logic hash prefix): metadata, canonical YAML, copies with source links, family and similar rules."""
    from sigharvest.web.routes.search import api_record

    with web.read_session() as s:
        data = queries.cached(web.cache, "rule", s, lambda session: rule_data(web, session, logic), key=(logic,), size=16)
        g, v = data["g"], data["v"]
        body = api_record(g) | {
            "description": g.description,
            "author": g.author,
            "modified": g.modified,
            "canonical_source": g.canonical_source,
            "content_hash": v.content_hash,
            "licence": None if data["licence"]["cls"] == "none" else data["licence"]["label"],
            "licence_class": data["licence"]["cls"],
            "summary": "".join(part for _kind, part in data["summary"].parts),
            "yaml": v.raw,
            "copies": [{k: c[k] for k in ("source", "path", "link")} for c in data["copies"]],
            "family": [{"logic_hash": x.logic_hash, "title": x.title, "source": x.canonical_source} for x in data["variants"]],
            "similar": [{"logic_hash": x.logic_hash, "title": x.title, "jaccard": round(j, 3)} for x, j in data["similar"]],
        }
    return JSONResponse(body)
