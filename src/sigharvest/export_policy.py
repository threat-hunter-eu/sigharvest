"""Source attribution shared by rule exports: which sources carry each rule, and under which licence."""

from __future__ import annotations

from collections.abc import Iterable
from itertools import islice
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from sigharvest.models import Occurrence, RuleVersion, Source


def provenance(s: Session | None, versions: Iterable[RuleVersion], *, by_logic: bool = False) -> dict[int, dict[str, Any]]:
    """Attribute current copies in bounded batches; licences align with source names."""
    from sigharvest.source_metadata import source_licences

    result: dict[int, dict[str, Any]] = {}
    current = source_licences(s) if s is not None else {}
    iterator = iter(versions)
    while batch := list(islice(iterator, 500)):
        origins: dict[Any, dict[str, str | None]] = {}
        if s is not None:
            key = RuleVersion.logic_hash if by_logic else RuleVersion.id
            rows = s.execute(
                select(key, Source.name, Source.licence)
                .join(Occurrence, Occurrence.version_id == RuleVersion.id)
                .join(Source, Source.id == Occurrence.source_id)
                .where(key.in_([v.logic_hash if by_logic else v.id for v in batch]), Occurrence.present.is_(True))
                .distinct()
            )
            for identity, name, licence in rows:
                origins.setdefault(identity, {})[name] = current.get(name, licence)
        for v in batch:
            licences = origins.get(v.logic_hash if by_logic else v.id, {})
            names = sorted(licences)
            result[v.id] = {"sources": names, "licences": [licences[name] for name in names], "rule_licence": v.rule_license}
    return result


def exact_origins(s: Session | None, versions: Iterable[RuleVersion]) -> dict[int, dict[str, Any]]:
    """For each exact document: the source it is attributed to (best priority among its current copies), that
    source's licence (sources.yaml first, see source_metadata) narrowed by the rule's own `license:` field, and a
    link to the copy. The licence is always the one of the document that is shipped, never borrowed from another
    source that carries the same logic."""
    from sigharvest.licensing import narrows
    from sigharvest.source_metadata import source_licences
    from sigharvest.sources import file_link

    result: dict[int, dict[str, Any]] = {}
    lic = source_licences(s) if s is not None else {}
    iterator = iter(versions)
    while batch := list(islice(iterator, 500)):
        best: dict[int, tuple[str | None, str | None, str | None]] = {}
        if s is not None:
            rows = s.execute(
                select(Occurrence.version_id, Source.name, Source.url, Occurrence.commit, Occurrence.path)
                .join(Source, Source.id == Occurrence.source_id)
                .where(Occurrence.version_id.in_([v.id for v in batch]), Occurrence.present.is_(True))
                .order_by(Source.priority, Source.name, Occurrence.path, Occurrence.doc_index)
            )
            for vid, source_name, url, commit, path in rows:
                if vid not in best:
                    best[vid] = (source_name, file_link(url, commit, path), path)
        for v in batch:
            name, link, where = best.get(v.id, (None, None, None))
            licence = lic.get(name) if name else None
            licence, licence_from = (v.rule_license, "rule") if narrows(v.rule_license, licence) else (licence, f"source {name}" if licence else "none stated")
            result[v.id] = {"author": v.author, "source": name, "source_path": where, "licence": licence, "licence_from": licence_from, "source_url": link}
    return result


def attribution_comment(s: Session | None, v: RuleVersion) -> str:
    """The '# attribution: ...' line of one rule, as written above each query in backend exports."""
    m = exact_origins(s, [v])[v.id]
    return "# attribution: " + attribution_line(v.title, m["author"], m["source"], m["licence"], m["source_url"] or m["source_path"])


def one_line(value: Any, limit: int = 300) -> str:
    """A metadata value as one short line (titles and authors must not add lines to query files or tables)."""
    return " ".join(str(value or "").split())[:limit]


MODIFIED_NOTE = "modified by sigharvest: flattened from a multi-document collection into one rule"
DRL_NOTE = "derived from a DRL-1.1 rule: keep its author and a link (Detection Rule License 1.1)"


def drl_rule_ids(s: Session | None, configs: dict[str, Any] | None = None) -> set[str]:
    """Rule ids (UUIDs) that a source under the Detection Rule License carries, or whose own `license:` field names
    the DRL. A copy of such a rule elsewhere, even edited and in a repository under another licence, keeps the DRL's
    attribution conditions (author, link, licence)."""
    from sqlalchemy import or_

    from sigharvest.licensing import normalise
    from sigharvest.source_metadata import source_licences

    if s is None:
        return set()
    drl = [name for name, lic in source_licences(s, configs).items() if (normalise(lic) or "").startswith("drl")]
    q = select(RuleVersion.rule_id).where(or_(RuleVersion.rule_license.ilike("%drl%"), RuleVersion.rule_license.ilike("%detection rule licen%")))
    ids = {r for r in s.scalars(q.distinct()) if r}
    if drl:
        rows = s.scalars(
            select(RuleVersion.rule_id)
            .join(Occurrence, Occurrence.version_id == RuleVersion.id)
            .join(Source, Source.id == Occurrence.source_id)
            .where(Source.name.in_(drl), Occurrence.present.is_(True))
            .distinct()
        )
        ids |= {r for r in rows if r}
    return ids


def licence_notes(entry: dict[str, Any], drl_ids: set[str] | None = None) -> dict[str, Any]:
    """`modified` / `drl_origin` fields for an attribution entry (release zips, exports): the shipped YAML is an
    effective document flattened by sigharvest (GPL-3 §5(a), CC-BY §3(a)(1)(B), Apache §4(b) ask to mark changes),
    or the rule id belongs to a DRL rule while the licence shipped is another one."""
    out: dict[str, Any] = {}
    if entry.get("yaml_representation") == "effective":
        out["modified"] = MODIFIED_NOTE
    licence = str(entry.get("licence") or "").upper()
    if drl_ids and entry.get("rule_id") in drl_ids and "DRL" not in licence:
        out["drl_origin"] = DRL_NOTE
    return out


def attribution_line(title: Any, author: Any, source: Any, licence: Any, link: Any) -> str:
    """'title | author: X | source: Y | licence: Z | link' for comments in query files (link: URL of the original
    rule, or its path in the source when the source has no web view)."""
    return (
        f"{one_line(title) or 'untitled'} | author: {one_line(author) or 'not stated'} | source: {one_line(source) or 'unknown'} "
        f"| licence: {one_line(licence) or 'not stated'} | {one_line(link, 500) or 'no link'}"
    )


ATTRIBUTION_HEAD = """# Attribution

These Sigma rules were written by the authors named below and keep the licences of their sources. Rules under the
Detection Rule License (DRL) 1.1 require that you keep the author and a reference to the original rule when you
reuse or convert them: keep this file with the rules. The licence texts and the publishers' own licence and notice
files are in LICENSES/.

| title | author | source | licence | link |
|---|---|---|---|---|
"""


def attribution_markdown(entries: Iterable[dict[str, Any]]) -> str:
    """ATTRIBUTION.md for an export or release zip: one table row per rule (title, author, source, licence, link)."""

    def cell(value: Any, limit: int = 300) -> str:
        return one_line(value, limit).replace("\\", "\\\\").replace("|", "\\|")

    from sigharvest.licence_texts import linked

    def title(e: dict[str, Any]) -> str:
        notes = [n for n in (e.get("modified"), e.get("drl_origin")) if n]
        return (cell(e.get("title")) or "untitled") + "".join(f" ({cell(n)})" for n in notes)

    def licence(e: dict[str, Any]) -> str:
        lic = cell(e.get("licence"))
        text = linked(lic) if lic else "not stated"
        return text + (" + [DRL-1.1](https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md)" if e.get("drl_origin") else "")

    rows = [
        f"| {title(e)} | {cell(e.get('author')) or 'not stated'} | {cell(e.get('source')) or 'unknown'} "
        f"| {licence(e)} | {cell(e.get('source_url') or e.get('source_path'), 500)} |"
        for e in entries
    ]
    return ATTRIBUTION_HEAD + "".join(row + "\n" for row in rows)
