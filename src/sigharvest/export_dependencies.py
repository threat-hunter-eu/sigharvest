"""Freeze exact Sigma dependencies and publish a verified, complete local YAML bundle.

Resolution uses the current planner's precedence and bounded inspection reader.
Packaging never changes YAML bytes to repair a graph: incompatible streams fail.
"""

from __future__ import annotations

import errno
import json
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from sigharvest.correlation_dependencies import Inspection, _Limit
from sigharvest.correlation_plan import Candidate, build, names, parse, resolve_reference
from sigharvest.correlation_references import snapshot, status
from sigharvest.documents import MAX_FILE_BYTES, load_documents
from sigharvest.errors import SigharvestError
from sigharvest.export_policy import provenance
from sigharvest.identity import effective_content_hash, sha256_hex
from sigharvest.models import LogicGroup, Occurrence, RuleVersion, Source
from sigharvest.publication import rename_no_replace, sync_directory


@contextmanager
def staged_directory(directory: Path) -> Iterator[Path]:
    """Build a staging directory next to `directory` and publish it atomically, never replacing existing data."""
    if any(p.is_symlink() for p in (directory.absolute(), *directory.absolute().parents)):
        raise SigharvestError("Export path must not contain symlinks")
    if directory.exists():
        raise SigharvestError("Export destination already exists; choose a new --out path")
    directory.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".export-", dir=directory.parent))
    try:
        yield staging
        sync_directory(staging)
        try:
            rename_no_replace(staging, directory)
        except FileExistsError as exc:
            raise SigharvestError("Export destination already exists; choose a new --out path") from exc
        except OSError as exc:
            if exc.errno in (errno.EEXIST, errno.ENOTEMPTY):
                raise SigharvestError("Export destination already exists; choose a new --out path") from exc
            raise
    finally:
        if staging.exists():
            shutil.rmtree(staging)


MAX_ROOTS = 100
MAX_DOCUMENTS = 1000
MAX_BYTES = 64 * 1024 * 1024
MAX_LOCATIONS = 10000


@dataclass
class Bundle:
    documents: dict[str, bytes]
    originals: dict[str, bytes]
    records: dict[str, dict[str, Any]]
    edges: list[dict[str, str]]
    files: dict[str, bytes]


def _verify(bundle: Bundle, files: dict[str, bytes]) -> dict[str, tuple[str, int]]:
    """Reload actual streams in an empty resolver context and compare exact edges."""
    by_yaml: dict[bytes, str] = {}
    for content, raw in bundle.documents.items():
        if raw in by_yaml:
            raise SigharvestError("Different content versions share effective YAML; cannot preserve exact identities in this bundle")
        by_yaml[raw] = content
    locations: dict[str, tuple[str, int]] = {}
    rules: list[tuple[str, str]] = []
    contents: dict[str, str] = {}
    for path, raw in sorted(files.items()):
        for doc in load_documents(raw):
            if doc.error or not doc.kind or doc.raw not in by_yaml or doc.rule_yaml.encode("utf-8", "surrogatepass") != doc.raw:
                raise SigharvestError("Cannot preserve exact document bytes and same-file context in a Sigma stream")
            content = by_yaml[doc.raw]
            if content in locations:
                raise SigharvestError("A document occurs more than once in the bundle")
            locations[content] = path, doc.index
            key = f"{path}#{doc.index}"
            rules.append((key, doc.rule_yaml))
            contents[key] = content
    if locations.keys() != bundle.documents.keys():
        raise SigharvestError("Bundle document inventory changed during reload")
    plan = build(rules)
    actual: list[dict[str, str]] = []
    for spec in plan.correlations:
        if spec.error:
            raise SigharvestError("Bundle changes reference resolution: " + spec.error)
        actual.extend({"parent": contents[spec.key], "reference": ref, "document": contents[key]} for ref, key in zip(spec.references, spec.keys, strict=True))

    def order(edge: dict[str, str]) -> tuple[str, str, str]:
        return edge["parent"], edge["reference"], edge["document"]

    if sorted(actual, key=order) != sorted(bundle.edges, key=order):
        raise SigharvestError("Bundle changes exact reference-document edges; choose compatible graphs separately")
    return locations


def _layout(bundle: Bundle) -> None:
    files = {f"rules/{content}.yml": raw for content, raw in bundle.documents.items()}
    try:
        locations = _verify(bundle, files)
    except SigharvestError:
        # Connected graphs share each base once. Components become same-file scopes.
        components = {content: {content} for content in bundle.documents}
        for edge in bundle.edges:
            merged = components[edge["parent"]] | components[edge["document"]]
            for content in merged:
                components[content] = merged
        files = {}
        for component in {tuple(sorted(c)) for c in components.values()}:
            # Existing source slices often already contain their --- delimiter.
            # Never insert one: that would silently change their content identities.
            ordered = sorted(component, key=lambda c: (bundle.documents[c].startswith(b"---"), c))
            raw = b"".join(bundle.documents[c] for c in ordered)
            if len(raw) > MAX_FILE_BYTES:
                raise SigharvestError("Same-file Sigma stream exceeds the existing 2 MiB file limit") from None
            files[f"rules/{component[0]}.yml"] = raw
        locations = _verify(bundle, files)
    bundle.files = files
    for content, (path, index) in locations.items():
        bundle.records[content].update(path=path, document=index)


def plan_bundle(s: Session, groups: Iterator[LogicGroup]) -> Bundle:
    """Freeze selected canonical versions and exact dependencies in one read snapshot."""
    snapshot(s)
    selected = list(islice(groups, MAX_ROOTS + 1))
    if len(selected) > MAX_ROOTS:
        raise SigharvestError("Dependency export exceeds the 100 selected roots limit")
    reader = Inspection(s)
    reader.index_state = status(s)
    versions: dict[str, RuleVersion] = {}
    roots: list[str] = []
    local: dict[str, list[Candidate]] = {}
    try:
        for group in selected:
            content = s.scalar(select(RuleVersion.content_hash).where(RuleVersion.id == group.canonical_version_id))
            if content is None:
                raise SigharvestError("Selected exact canonical version is unavailable")
            if content not in roots:
                roots.append(content)
                candidate = reader.candidate(content)
                for name in names(candidate[2]):
                    local.setdefault(name, []).append(candidate)
        edges: list[dict[str, str]] = []
        required = set(roots)
        for content in roots:
            data = reader.parsed[content]
            if reader.documents[content]["parse_error"]:
                raise SigharvestError("Selected document has invalid YAML")
            if "correlation" not in data:
                if not isinstance(data.get("detection"), dict):
                    raise SigharvestError("Dependency export supports detection rules and supported correlations only")
                continue
            spec = parse(reader.documents[content]["logic_hash"], data)
            if spec.error:
                raise SigharvestError("Unsupported correlation: " + spec.error)
            used: set[str] = set()
            for ref in spec.references:

                def fetch(same_file: bool, ref: str = ref, key: str = spec.key) -> list[Candidate]:
                    if reader.index_state != "ready":
                        raise SigharvestError("Dependency reference index is unavailable; run sigharvest index before exporting")
                    stage = reader.stage(ref, key, same_file)
                    if not stage["complete"]:
                        raise SigharvestError("Dependency resolution incomplete: " + str(stage["reason"]))
                    by_logic: dict[str, Candidate] = {}
                    for candidate_content in stage["candidates"]:
                        row = reader.candidate(candidate_content)
                        by_logic.setdefault(row[0], row)
                        if len(by_logic) > 1:
                            break
                    return list(by_logic.values())

                resolved = resolve_reference(ref, spec.key, local, fetch)
                if isinstance(resolved, str):
                    raise SigharvestError("Dependency export: " + resolved)
                key, resolved_yaml, base = resolved
                if "correlation" in base or not isinstance(base.get("detection"), dict):
                    raise SigharvestError("Dependency is not a base detection rule (chains/cycles unsupported)")
                if key in used:
                    raise SigharvestError("Multiple references resolve to the same base rule")
                used.add(key)
                matches = [c for c, candidate_raw in reader.raw.items() if resolved_yaml == candidate_raw and reader.documents[c]["logic_hash"] == key]
                if len(matches) != 1:
                    raise SigharvestError("Effective YAML identifies multiple content versions; exact dependency is ambiguous")
                chosen = matches[0]
                required.add(chosen)
                edges.append({"parent": content, "reference": ref, "document": chosen})
        reader.check()
    except _Limit as exc:
        raise SigharvestError("Dependency export incomplete: " + str(exc)) from None
    if len(required) > MAX_DOCUMENTS:
        raise SigharvestError("Dependency export exceeds the 1,000 document limit")
    original_bytes = 0
    for content in sorted(required):
        original_size = s.scalar(select(func.length(RuleVersion.original_raw)).where(RuleVersion.content_hash == content)) or 0
        original_bytes += original_size
        if original_size > MAX_FILE_BYTES or original_bytes + reader.bytes_read > MAX_BYTES:
            raise SigharvestError("Source bytes exceed the dependency export byte limit")
        version = s.scalar(select(RuleVersion).where(RuleVersion.content_hash == content))
        assert version is not None
        versions[content] = version
    bundle = Bundle({}, {}, {}, edges, {})
    size = 0
    location_count = 0
    from sigharvest.export_policy import exact_origins

    origins = provenance(s, versions.values())
    exact = exact_origins(s, versions.values())
    for content, version in versions.items():
        raw = version.raw.encode("utf-8", "surrogatepass")
        original = version.original_raw if version.original_raw is not None else raw
        if effective_content_hash(original, version.context_digest) != content:
            raise SigharvestError("Stored source bytes do not match the exact content hash")
        if not version.context_digest and original != raw:
            raise SigharvestError("Stored source bytes differ from executable YAML; cannot preserve both")
        size += len(raw) + (len(original) if version.context_digest else 0)
        if size > MAX_BYTES:
            raise SigharvestError("Dependency export exceeds the 64 MiB YAML limit")
        locations = s.execute(
            select(Source.name, Source.licence, Occurrence.path, Occurrence.doc_index, Occurrence.commit, Occurrence.present)
            .join(Occurrence, Occurrence.source_id == Source.id)
            .where(Occurrence.version_id == version.id)
            .order_by(Occurrence.id)
            .limit(MAX_LOCATIONS - location_count + 1)
        ).all()
        location_count += len(locations)
        if location_count > MAX_LOCATIONS:
            raise SigharvestError("Dependency provenance exceeds the location limit")
        record = {
            "schema": "sigma-dependency-bundle-v1",
            "content_hash": content,
            "logic_hash": version.logic_hash,
            "role": "selected" if content in roots else "dependency",
            "yaml_representation": "effective" if version.context_digest else "source",
            "yaml_sha256": sha256_hex(raw),
            "source_sha256": sha256_hex(original),
            "context_digest": version.context_digest,
            # The licence of this exact document's own source (rule metadata may only narrow it), never another copy's.
            "licence": exact[version.id]["licence"],
            "title": version.title,
            "author": version.author,
            "source": exact[version.id]["source"],
            "source_url": exact[version.id]["source_url"],
            "locations": [dict(zip(("source", "licence", "path", "document", "commit", "present"), row, strict=True)) for row in locations],
            "references": [edge for edge in edges if edge["parent"] == content],
            "executed_evidence": False,
            **origins[version.id],
        }
        if version.context_digest:
            bundle.originals[content] = original
            record["original_path"] = f"originals/{content}.bin"
        bundle.documents[content] = raw
        bundle.records[content] = record
    _layout(bundle)
    return bundle


def write_bundle(bundle: Bundle, out: Path) -> int:
    """Write a staging directory, verify its bytes, then publish without replacement."""
    with staged_directory(out) as stage:
        for path, raw in bundle.files.items():
            target = stage / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        for content, raw in bundle.originals.items():
            target = stage / "originals" / f"{content}.bin"
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(raw)
        from sigharvest.export import EXPORT_NOTICE
        from sigharvest.export_policy import attribution_markdown

        (stage / "NOTICE.md").write_text(EXPORT_NOTICE, encoding="utf-8")
        (stage / "ATTRIBUTION.md").write_text(attribution_markdown(bundle.records.values()), encoding="utf-8")
        (stage / "manifest.jsonl").write_text("".join(json.dumps(record, ensure_ascii=False) + "\n" for record in bundle.records.values()), encoding="utf-8")
        _verify(bundle, {path: (stage / path).read_bytes() for path in bundle.files})
        if any((stage / "originals" / f"{content}.bin").read_bytes() != raw for content, raw in bundle.originals.items()):
            raise SigharvestError("Original source bytes changed during bundle writing")
        records = [json.loads(line) for line in (stage / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
        if records != list(bundle.records.values()):
            raise SigharvestError("Manifest changed during bundle writing")
    return len(bundle.documents)


def export_bundle(s: Session, groups: Iterator[LogicGroup], out: Path) -> int:
    if out.exists() or out.is_symlink():
        raise SigharvestError("Export destination already exists; choose a new --out path")
    bundle = plan_bundle(s, groups)
    return write_bundle(bundle, out)
