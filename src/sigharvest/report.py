"""reports/summary.md and per-rule JSON files."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from sigharvest.conversion import APPLICABLE
from sigharvest.models import Occurrence, Quarantine, RuleVersion, Source, SyncLog, TestResult
from sigharvest.query import dedupe, live_version_ids
from sigharvest.testing import BACKENDS, native_backend


def _pct(a: int, b: int) -> str:
    return f"{(100 * a / b):.1f}%" if b else "-"


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in r) + " |" for r in rows]
    return "\n".join(out)


def _conversion(s: Session) -> tuple[list[list[Any]], list[list[Any]], Counter[str]]:
    live = live_version_ids()
    # A join, not a list of ids: a full corpus has more live versions than SQLite allows bound variables (32,766 in
    # older builds), and only the logsource is needed, not the rule text.
    query = (
        select(TestResult.target, TestResult.status, TestResult.detail, RuleVersion.product, RuleVersion.category, RuleVersion.service)
        .join(RuleVersion, RuleVersion.id == TestResult.version_id)
        .where(TestResult.stage == "convert", RuleVersion.id.in_(live), RuleVersion.kind.in_(["rule", "correlation"]))
    )
    stats: dict[str, Counter[str]] = defaultdict(Counter)
    native_fail: Counter[str] = Counter()
    native_total: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    for target, status, detail, product, category, service in s.execute(query):
        stats[target][status] += 1
        if status in APPLICABLE and target == native_backend(product, category, service):
            native_total[target] += 1
            if status == "error":
                native_fail[target] += 1
        if status == "error":
            msg = str((detail or {}).get("error", ""))
            errors[f"{target}: {msg.split(':', 1)[0]}: {msg.split(':', 1)[-1].strip()[:90]}"] += 1
    rows = []
    for b in BACKENDS:
        c = stats.get(b, Counter())
        applicable = sum(c[x] for x in APPLICABLE) + c["empty"]  # "empty": results stored before the toolchain fingerprint
        keys = ["warning", "raw", "error", "unsupported", "correlation_unsupported", "skipped", "resource_failure"]
        row = [b, applicable, c["ok"], _pct(c["ok"], applicable), *(c[k] for k in keys)]
        row[6] = c["error"] + c["empty"]
        rows.append(row)
    native = [[b, native_total[b], native_fail[b], _pct(native_fail[b], native_total[b])] for b in sorted(native_total)]
    return rows, native, errors


def build_summary(s: Session, out_dir: Path, rule_json: bool = True, notice: str | None = None) -> Path:
    """Write reports/summary.md (and per-rule JSON files when rule_json is set). Returns the summary path.

    `notice` is shown in bold under the title (`sigharvest update` uses it when the run failed a gate)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    live = live_version_ids()
    dd = dedupe(s)
    lines: list[str] = []
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines += ["# sigharvest corpus report", "", f"Generated {now}.", ""]
    if notice:
        lines += [f"**{notice}**", ""]

    lines += ["## Headline numbers", ""]
    n_quar = s.scalar(select(func.count()).select_from(Quarantine).where(Quarantine.present.is_(True))) or 0
    lines.append(
        _table(
            ["metric", "value"],
            [
                ["Sigma documents (every copy in every source)", dd.live_documents],
                ["Unique contents (content_hash)", dd.unique_contents],
                ["Unique rule ids", dd.unique_rule_ids],
                ["Unique logic (logic_hash)", dd.unique_logic],
                ["Duplicate documents (same logic as another document)", dd.live_documents - dd.unique_logic],
                ["Logic groups with more than one copy", len(dd.logic_groups)],
                ["Exact copies (same bytes)", dd.exact_copies],
                ["Rule ids with conflicting logic", len(dd.id_conflicts)],
                ["Quarantined documents", n_quar],
            ],
        )
    )

    lines += ["", "## Sources", ""]
    src_rows = s.execute(
        select(
            Source.name,
            Source.priority,
            Source.licence,
            Source.last_commit,
            func.count(Occurrence.id),
            func.count(func.distinct(RuleVersion.logic_hash)),
        )
        .join(Occurrence, Occurrence.source_id == Source.id)
        .join(RuleVersion, RuleVersion.id == Occurrence.version_id)
        .where(Occurrence.present.is_(True))
        .group_by(Source.id)
        .order_by(func.count(Occurrence.id).desc())
    ).all()
    # Logic hashes that appear only in this source (contribution to the corpus).
    owners: dict[str, set[str]] = defaultdict(set)
    for lh, name in s.execute(
        select(RuleVersion.logic_hash, Source.name)
        .join(Occurrence, Occurrence.version_id == RuleVersion.id)
        .join(Source, Source.id == Occurrence.source_id)
        .where(Occurrence.present.is_(True))
    ):
        owners[lh].add(name)
    only: Counter[str] = Counter(next(iter(v)) for v in owners.values() if len(v) == 1)
    lines.append(
        _table(
            ["source", "priority", "licence", "commit", "documents", "unique logic", "logic found only here"],
            [[n, p, lic or "", (c or "")[:10], d, u, only[n]] for n, p, lic, c, d, u in src_rows],
        )
    )
    failed = s.execute(
        select(Source.name, SyncLog.error)
        .join(SyncLog, SyncLog.source_id == Source.id)
        .where(SyncLog.status == "error")
        .where(SyncLog.id.in_(select(func.max(SyncLog.id)).group_by(SyncLog.source_id)))
    ).all()
    if failed:
        lines += ["", "Sources whose last sync failed:", ""] + [f"- {n}: {(e or '')[:200]}" for n, e in failed]

    lines += ["", "## Duplicates", ""]
    lines.append("Most copied logic (canonical copy chosen by source priority):")
    lines.append("")
    lines.append(
        _table(
            ["copies", "sources", "canonical title", "canonical source"],
            [[g["copies"], len(g["sources"]), g["canonical"]["title"], g["canonical"]["source"]] for g in dd.logic_groups[:20]],
        )
    )
    if dd.id_conflicts:
        lines += ["", "Rule ids with more than one logic (diverging copies of the same rule):", ""]
        lines.append(
            _table(
                ["rule id", "logic variants", "sources", "title"],
                [[c["rule_id"], c["logic_variants"], len(c["sources"]), c["title"]] for c in dd.id_conflicts[:20]],
            )
        )

    lines += ["", "## Validation", ""]
    val = Counter(st for (st,) in s.execute(select(TestResult.status).where(TestResult.stage == "validate", TestResult.version_id.in_(live))))
    issues: Counter[str] = Counter()
    for (d,) in s.execute(select(TestResult.detail).where(TestResult.stage == "validate", TestResult.version_id.in_(live))):
        for i in d.get("issues", []):
            issues[f"{i['validator']} ({i['severity']})"] += 1
        if d.get("schema"):
            issues["JSON schema violation"] += 1
        for e in d.get("parse", []):
            issues["parse: " + e.split(":", 1)[0]] += 1
    total_val = sum(val.values())
    lines.append(_table(["status", "rule versions", "share"], [[k, v, _pct(v, total_val)] for k, v in val.most_common()]))
    lines += ["", "Most frequent findings:", ""]
    lines.append(_table(["finding", "rule versions"], [[k, v] for k, v in issues.most_common(15)]))

    lines += ["", "## Conversion", ""]
    conv, native, errors = _conversion(s)
    lines.append(
        "ok = mapped by a pipeline for the rule's log source; raw = syntax only (Sigma field names, no log source condition); "
        "warning = mapped but failed a sanity check; not applicable = the backend has no such data. See docs/concepts.md, Validation and conversion."
    )
    lines.append("")
    headers = ["backend", "applicable", "ok", "ok share", "warning", "raw", "error", "not applicable"]
    lines.append(_table([*headers, "correlation not convertible", "skipped (parse error, filter)", "worker resource limit"], conv))
    limited = sum(row[-1] for row in conv)
    if limited:
        lines += [
            "",
            f"**{limited} conversion results hit the per-worker address-space cap (resource_failure).** "
            "Retry them with `sigharvest test --stage convert --retry-resource-failures`.",
        ]
    lines += ["", "Failures on the rule's native backend (see docs/concepts.md, Validation and conversion):", ""]
    lines.append(_table(["native backend", "rules", "failed", "failure rate"], native))
    lines += ["", "Most common conversion errors:", ""]
    lines.append(_table(["backend: error", "count"], [[k, v] for k, v in errors.most_common(15)]))

    lines += ["", "## Replay and false-positive stages", ""]
    replay = s.scalar(select(func.count()).select_from(TestResult).where(TestResult.stage.in_(["replay", "fp"])))
    if not replay:
        lines.append("Not run yet. The replay stage (Chainsaw, Hayabusa, pySigma sqlite on public EVTX datasets) is on the roadmap.")
    lines.append("")
    path = out_dir / "summary.md"
    path.write_text("\n".join(lines), encoding="utf-8")

    if rule_json:
        folder = out_dir / "rules"
        folder.mkdir(exist_ok=True)
        _write_rule_json(s, folder)
    return path


def _write_rule_json(s: Session, folder: Path) -> None:
    live = live_version_ids()
    res: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for r in s.scalars(select(TestResult).where(TestResult.version_id.in_(live))):
        res[r.version_id].append({"stage": r.stage, "target": r.target, "dataset": r.dataset, "status": r.status, "detail": r.detail})
    occ: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for o, src in s.execute(select(Occurrence, Source.name).join(Source, Source.id == Occurrence.source_id).where(Occurrence.present.is_(True))):
        occ[o.version_id].append({"source": src, "path": o.path, "doc_index": o.doc_index, "commit": o.commit})
    for v in s.scalars(select(RuleVersion).where(RuleVersion.id.in_(live))):
        data = {
            "rule_id": v.rule_id,
            "id_flag": v.id_flag,
            "content_hash": v.content_hash,
            "logic_hash": v.logic_hash,
            "kind": v.kind,
            "title": v.title,
            "status": v.status,
            "level": v.level,
            "author": v.author,
            "logsource": {"product": v.product, "category": v.category, "service": v.service},
            "tags": v.tags,
            "flags": v.flags,
            "occurrences": occ[v.id],
            "results": res[v.id],
        }
        (folder / f"{v.content_hash}.json").write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
