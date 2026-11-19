"""Lint your own Sigma rules against the whole community corpus (for pull requests and CI).

For every rule document in the given files:
- error   invalid YAML or a detection pySigma cannot parse
- error   same rule id as a different rule in the corpus (id collision), or a placeholder id (a1b2c3d4-...)
- warning exact copy of a corpus rule (same content) or same logic as a corpus rule (duplicate detection)
- warning pySigma validator issues; quality flags (synthetic, template title, match-all...)
- note    ATT&CK tags that are revoked, deprecated or not techniques; tag spelling that normalises differently

The corpus comes from the workspace database or from a data release (rules.jsonl.gz), so CI needs no sync.
Output: a list of Finding, printable as text, JSON or SARIF 2.1.0 (GitHub code scanning).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from sigharvest import normalize as norm
from sigharvest.documents import Document, load_documents
from sigharvest.identity import content_hash, logic_hash, normalise_rule_id, placeholder_uuid, resolve_rule_id
from sigharvest.quality import JUNK, classify
from sigharvest.release_reader import SignaturePolicy, open_release

LEVELS = ("error", "warning", "note")


@dataclass
class Finding:
    path: str
    line: int
    level: str
    rule: str  # check id, e.g. duplicate-logic
    message: str
    title: str | None = None


@dataclass
class Corpus:
    """What lint needs from the corpus: hashes and ids with a short description of who carries them."""

    by_content: dict[str, str] = field(default_factory=dict)  # content hash -> "title (source)"
    by_logic: dict[str, str] = field(default_factory=dict)  # logic hash -> "title (n sources)"
    ids: dict[str, set[str]] = field(default_factory=dict)  # rule id -> logic hashes

    @classmethod
    def from_db(cls, s: Any) -> Corpus:
        from sqlalchemy import select

        from sigharvest.models import LogicGroup, RuleVersion

        c = cls()
        for lh, rid, title, src, n in s.execute(
            select(LogicGroup.logic_hash, LogicGroup.rule_id, LogicGroup.title, LogicGroup.canonical_source, LogicGroup.n_sources)
        ):
            c.by_logic[lh] = f"{title} ({src}, {n} sources)"
            c.ids.setdefault(rid, set()).add(lh)
        for ch, title in s.execute(select(RuleVersion.content_hash, RuleVersion.title)):
            c.by_content[ch] = str(title)
        return c

    @classmethod
    def from_release(cls, folder: Path, *, trust: SignaturePolicy | None = None) -> Corpus:
        c = cls()
        with open_release(folder, trust=trust) as reader:
            for row in reader.rows():
                lh, rid = row["logic_hash"], row.get("rule_id") or ""
                c.by_logic[lh] = f"{row.get('title')} ({(row.get('canonical') or {}).get('source')}, {len(row.get('sources') or [])} sources)"
                c.ids.setdefault(rid, set()).add(lh)
                if row.get("yaml"):
                    c.by_content[content_hash(row["yaml"].encode("utf-8"))] = str(row.get("title"))
        return c


def _line_of(raw: bytes, doc: Document) -> int:
    """1-based line where a document's content starts: its span in the file, below its `---` separator line."""
    line = raw.count(b"\n", 0, doc.span_start) + 1
    return line + 1 if doc.raw.lstrip(b"\xef\xbb\xbf").startswith(b"---") else line


def lint_file(path: Path, corpus: Corpus, root: Path | None = None, matrix: Any = None) -> list[Finding]:
    from sigharvest.conversion import parse, parse_errors
    from sigharvest.detection import detection_only

    rel = path.relative_to(root).as_posix() if root else str(path)
    raw = path.read_bytes()
    out: list[Finding] = []
    for doc in load_documents(raw):
        line = _line_of(raw, doc)
        if doc.error:
            out.append(Finding(rel, line, "error", "invalid-yaml", doc.error[:300]))
            continue
        if doc.kind is None:
            continue
        data = doc.data
        title = str(data.get("title") or "") or None

        def add(level: str, rule: str, msg: str, line: int = line, title: str | None = title) -> None:
            out.append(Finding(rel, line, level, rule, msg, title))

        if doc.kind == "rule":
            try:
                errs = parse_errors(parse(detection_only(doc.rule_yaml)))
            except Exception as exc:  # noqa: BLE001
                errs = [f"{type(exc).__name__}: {exc}"]
            if errs:
                add("error", "invalid-detection", "; ".join(errs)[:400])
            else:
                meta = parse_errors(parse(doc.rule_yaml))
                if meta:
                    add("warning", "invalid-metadata", "; ".join(meta)[:400])
        lh = logic_hash(data)
        ch = doc.identity_hash
        rid, id_flag = resolve_rule_id(data, lh)
        if id_flag:
            add("warning", "missing-id" if id_flag == "id_missing" else "invalid-id", f"id is {id_flag.replace('id_', '')}; use a random UUID (uuid4)")
        elif placeholder_uuid(rid):
            add("error", "placeholder-id", f"id {rid} looks hand-made; other rules use it too. Use a random UUID (uuid4)")
        if ch in corpus.by_content:
            add("warning", "exact-copy", f"identical to a corpus rule: {corpus.by_content[ch]}")
        elif lh in corpus.by_logic:
            add("warning", "duplicate-logic", f"same detection as {corpus.by_logic[lh]}; consider `related:` or reusing that rule")
        if not id_flag and rid in corpus.ids and lh not in corpus.ids[rid]:
            others = ", ".join(sorted(h[:10] for h in corpus.ids[rid])[:3])
            add("error", "id-collision", f"id {rid} is used by a different rule in the corpus (logic {others}); new rules need a new id")
        for flag in classify(data, [rel], raw=doc.rule_yaml):
            if flag in JUNK and flag != "test_fixture":
                add("warning", f"quality-{flag.replace('_', '-')}", f"quality flag: {flag.replace('_', ' ')}")
        from sigharvest.quality_unused import messages, unused_selections

        unused = unused_selections(data)
        from sigharvest.quality_quotes import from_raw as quote_artifacts
        from sigharvest.quality_quotes import message as quote_message

        quotes = quote_artifacts(doc.rule_yaml)
        if quotes:
            add("warning", "quality-quote-artifact", quote_message(quotes))
        for flag, message in messages(unused):
            add("warning", f"quality-{flag.replace('_', '-')}", message)
        if unused.get("suggestion"):
            add("note", "condition-suggestion", f"Intended condition probably `{unused['suggestion']}`; review only, never applied automatically.")
        tags = data.get("tags") if isinstance(data.get("tags"), list) else []
        for t in tags:
            fixed = norm.tag(t)
            if fixed and fixed != str(t).strip().lower():
                add("note", "tag-spelling", f"tag {t!r} is written {fixed!r} in the current Sigma tag specification")
            if matrix is not None and fixed:
                from sigharvest.attack import normalise_technique

                identity = normalise_technique(fixed, matrix)
                if identity.domain in {"ics", "mobile"}:
                    add("note", "attack-domain", identity.label)
                elif identity.domain == "enterprise":
                    if identity.status == "deprecated":
                        add("note", "attack-deprecated", identity.label)
                    elif identity.current_id is None:
                        add("note", "attack-unknown", identity.label)
                    elif identity.status == "replaced":
                        add("note", "attack-revoked", identity.label)
        if normalise_rule_id(data.get("id")) and not data.get("related") and lh in corpus.by_logic and rid not in corpus.ids:
            add("note", "related-missing", "copies a corpus rule under a new id: add `related: [{id: <original>, type: derived}]`")
    return out


def lint_paths(paths: Iterable[Path], corpus: Corpus, matrix: Any = None) -> list[Finding]:
    out: list[Finding] = []
    for p in paths:
        files = [p] if p.is_file() else sorted(x for x in p.rglob("*") if x.suffix.lower() in (".yml", ".yaml") and x.is_file())
        root = p if p.is_dir() else None
        for f in files:
            out.extend(lint_file(f, corpus, root, matrix))
    return out


def to_sarif(findings: list[Finding]) -> dict[str, Any]:
    rules = sorted({f.rule for f in findings})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sigharvest lint",
                        "informationUri": "https://github.com/threat-hunter-eu/sigharvest",
                        "rules": [{"id": r, "shortDescription": {"text": r.replace("-", " ")}} for r in rules],
                    }
                },
                "results": [
                    {
                        "ruleId": f.rule,
                        "level": f.level,
                        "message": {"text": f.message},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path}, "region": {"startLine": f.line}}}],
                    }
                    for f in findings
                ],
            }
        ],
    }


def as_json(findings: list[Finding]) -> list[dict[str, Any]]:
    return [asdict(f) for f in findings]


def lint_collection(s: Any, collection: Any) -> list[Finding]:
    """Review unused selections on resolved members, including dropped/junk rules.

    Read canonical YAML so this check also works before the next index rebuild.
    Missing members remain explicit findings; collection membership is unchanged.
    """
    from sqlalchemy import select

    from sigharvest import collections as col
    from sigharvest.db import IN_CHUNK
    from sigharvest.models import RuleVersion
    from sigharvest.quality_unused import from_raw, messages

    out = []
    rows = col.resolve(s, collection)
    for row in rows:
        if row.group is None:
            out.append(Finding(row.item.logic_hash, 1, "warning", "missing-rule", "Collection member cannot be resolved", row.item.title))
    groups = {row.group.canonical_version_id: row.group for row in rows if row.group is not None}
    ids = list(groups)
    for start in range(0, len(ids), IN_CHUNK):
        for version_id, raw in s.execute(select(RuleVersion.id, RuleVersion.raw).where(RuleVersion.id.in_(ids[start : start + IN_CHUNK]))):
            group = groups[version_id]
            details = from_raw(raw)
            for flag, message in messages(details):
                out.append(Finding(group.logic_hash, 1, "warning", f"quality-{flag.replace('_', '-')}", message, group.title))
            if details.get("suggestion"):
                out.append(
                    Finding(
                        group.logic_hash,
                        1,
                        "note",
                        "condition-suggestion",
                        f"Intended condition probably `{details['suggestion']}`; review only.",
                        group.title,
                    )
                )
    return sorted(out, key=lambda f: (f.path, f.rule))
