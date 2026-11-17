"""Split files into YAML documents and recognise Sigma content by its structure, not by path or extension."""

from __future__ import annotations

import itertools
import re
from collections.abc import Generator
from dataclasses import dataclass, field
from typing import Any, cast

import yaml

from sigharvest.identity import effective_content_hash, rule_kind, sha256_hex

# A YAML document separator on its own line ("---", optionally followed by a comment).
_DOC_SEPARATOR = re.compile(rb"^---[ \t]*(?:#.*)?\r?$", re.MULTILINE)
# Horizontal whitespace only: with \s a run of blank lines made every line start rescan the run (quadratic).
_SIGMA_HINT = re.compile(rb"^[ \t]*(detection|correlation|filter)[ \t]*:", re.MULTILINE)

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_YAML_DEPTH = 64
MAX_YAML_NODES = 100_000
MAX_EFFECTIVE_FILE_BYTES = 16 * 1024 * 1024
_ACTION_HINT = re.compile(rb"\baction\b")


def _check_mapping_keys(loader: Any, node: Any) -> None:
    """Reject explicit duplicates before merge expansion in both safe YAML parsers."""
    if getattr(node, "sigharvest_checked", False):
        return
    node.sigharvest_checked = True
    seen: dict[Any, Any] = {}
    for key_node, _ in node.value:
        key = "<<" if key_node.tag == "tag:yaml.org,2002:merge" else loader.construct_object(key_node)
        try:
            if key in seen:
                first = seen[key].start_mark
                mark = key_node.start_mark
                raise ValueError(
                    f"duplicate YAML key at line {mark.line + 1}, column {mark.column + 1} (first at line {first.line + 1}, column {first.column + 1})"
                )
            seen[key] = key_node
        except TypeError:
            raise ValueError("YAML mapping keys must be scalar") from None


class SigmaSafeLoader(yaml.SafeLoader):
    """SafeLoader that keeps timestamps as strings and rejects explicit duplicate keys."""

    def flatten_mapping(self, node: Any) -> None:
        _check_mapping_keys(self, node)
        super().flatten_mapping(node)


SigmaSafeLoader.yaml_implicit_resolvers = {
    k: [r for r in v if r[0] != "tag:yaml.org,2002:timestamp"] for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


class _IngestLoader(SigmaSafeLoader):
    """Bound composition and expanded aliases before constructors or legacy merges run."""

    _depth = 0
    _nodes = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        self._depth += 1
        self._nodes += 1
        try:
            if self._depth > MAX_YAML_DEPTH or self._nodes > MAX_YAML_NODES:
                raise ValueError("YAML structure exceeds depth or node limit")
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_document(self, node: Any) -> Any:
        # Count repeated aliases as expanded nodes. Cycles reach the depth cap without
        # recursive Python calls; merge-key expansion has not happened yet.
        _check_expanded_nodes(node)
        return super().construct_document(node)


class FastSigmaSafeLoader(getattr(yaml, "CSafeLoader", yaml.SafeLoader)):  # type: ignore[misc]
    """Libyaml safe construction with the same scalar and duplicate-key policy."""

    def flatten_mapping(self, node: Any) -> None:
        _check_mapping_keys(self, node)
        super().flatten_mapping(node)


FastSigmaSafeLoader.yaml_implicit_resolvers = SigmaSafeLoader.yaml_implicit_resolvers


class _FastIngestLoader(FastSigmaSafeLoader):
    """C composition with the same expanded-alias check before construction."""

    def construct_document(self, node: Any) -> Any:
        _check_expanded_nodes(node)
        return super().construct_document(node)


def _check_expanded_nodes(node: Any) -> None:
    pending = [(node, 1)]
    count = 0
    while pending:
        current, depth = pending.pop()
        count += 1
        if depth > MAX_YAML_DEPTH or count > MAX_YAML_NODES:
            raise ValueError("YAML aliases exceed depth or expanded node limit")
        if isinstance(current, yaml.MappingNode):
            pending.extend((child, depth + 1) for pair in current.value for child in pair)
        elif isinstance(current, yaml.SequenceNode):
            pending.extend((child, depth + 1) for child in current.value)
        if count + len(pending) > MAX_YAML_NODES:
            raise ValueError("YAML aliases exceed expanded node limit")


def _load_ingest_yaml(raw: bytes) -> Any:
    """Bound event depth/count before C composition, then bound alias expansion.

    Libyaml does not call Python compose_node overrides. A streaming event pass
    is therefore required before constructing its node graph. Keep the Python
    implementation as a fallback on installations without Libyaml.
    """
    # Libyaml accepts some tab-separated plain scalars that PyYAML rejects.
    # Preserve historical admission (including old quarantine) for such inputs.
    if b"\t" in raw or not getattr(yaml, "__with_libyaml__", False):
        return yaml.load(raw, Loader=_IngestLoader)  # noqa: S506 - bounded SafeLoader
    depth = count = 0
    # yaml.parse is a generator; types-pyyaml >= 6.0.12.20261103 (required by pySigma 2.1) types it as Iterator.
    events = cast("Generator[Any]", yaml.parse(raw, Loader=FastSigmaSafeLoader))
    try:
        for event in events:
            if isinstance(event, (yaml.ScalarEvent, yaml.AliasEvent, yaml.CollectionStartEvent)):
                count += 1
                if depth + 1 > MAX_YAML_DEPTH or count > MAX_YAML_NODES:
                    raise ValueError("YAML structure exceeds depth or node limit")
            if isinstance(event, yaml.CollectionStartEvent):
                depth += 1
            elif isinstance(event, yaml.CollectionEndEvent):
                depth -= 1
    finally:
        events.close()
    return yaml.load(raw, Loader=_FastIngestLoader)  # noqa: S506 - bounded safe construction


@dataclass
class Document:
    index: int
    raw: bytes
    data: Any = None
    kind: str | None = None
    error: str | None = None
    flags: list[str] = field(default_factory=list)
    span_start: int = 0
    context_digest: str | None = None
    effective: str | None = None

    @property
    def rule_yaml(self) -> str:
        """Executable standalone YAML; raw always retains the exact source slice."""
        return self.effective if self.effective is not None else self.raw.decode("utf-8", errors="replace")

    @property
    def identity_hash(self) -> str:
        """Keep ordinary byte identities; domain-separate context-dependent children."""
        return effective_content_hash(self.raw, self.context_digest)


def looks_like_sigma(raw: bytes) -> bool:
    """Cheap pre-filter before YAML parsing."""
    return bool(_SIGMA_HINT.search(raw[:MAX_FILE_BYTES]))


def split_documents(raw: bytes) -> list[bytes]:
    """Split raw file bytes on YAML document separators, keeping each document's exact bytes."""
    starts = [m.start() for m in _DOC_SEPARATOR.finditer(raw)]
    # A stream's directives/BOM belong to its first document, not a standalone
    # pseudo-document. Later directive blocks belong to the following separator.
    for i, start in enumerate(starts):
        prefix = raw[starts[i - 1] if i else 0 : start]
        lines = prefix.splitlines(keepends=True)
        boundary, directive = start, False
        while lines and lines[-1].lstrip(b"\xef\xbb\xbf").startswith((b"%", b"#")):
            line = lines.pop()
            directive = directive or line.lstrip(b"\xef\xbb\xbf").startswith(b"%")
            boundary -= len(line)
        if directive:
            starts[i] = boundary
    if not starts:
        return [raw]
    chunks = []
    bounds = [0, *starts, len(raw)]
    for a, b in itertools.pairwise(bounds):
        chunk = raw[a:b]
        if chunk:
            chunks.append(chunk)
    return chunks or [raw]


def _merge(base: Any, extra: Any) -> Any:
    if isinstance(base, dict) and isinstance(extra, dict):
        out = dict(base)
        for k, v in extra.items():
            out[k] = _merge(out[k], v) if k in out else v
        return out
    return extra


def load_documents(raw: bytes, *, rejected: dict[int, str] | None = None) -> list[Document]:
    """Parse every YAML document of a file.

    Legacy Sigma collections (`action: global`) are expanded: the global document is merged into
    each following document, the way the 1.x specification defined it.
    """
    docs: list[Document] = []
    if len(raw) > MAX_FILE_BYTES:
        return [Document(index=0, raw=raw, error="yaml: file exceeds size limit")]
    global_doc: dict[str, Any] | None = None
    global_digest: str | None = None
    previous: dict[str, Any] | None = None
    previous_digest: str | None = None
    poisoned = False
    effective_bytes = 0
    offset = 0
    for i, chunk in enumerate(split_documents(raw)):
        start = raw.find(chunk, offset)
        offset = start + len(chunk)
        doc = Document(index=i, raw=chunk, span_start=start)
        if rejected and i in rejected:
            doc.error = rejected[i]
            doc.flags.append("quarantine_skipped")
            docs.append(doc)
            poisoned = poisoned or bool(_ACTION_HINT.search(chunk))
            previous = None
            continue
        try:
            doc.data = _load_ingest_yaml(chunk)
        except (yaml.YAMLError, ValueError, RecursionError) as exc:
            doc.error = f"yaml: {str(exc).splitlines()[0]}"
            docs.append(doc)
            poisoned = poisoned or bool(_ACTION_HINT.search(chunk))
            previous = None
            continue
        if isinstance(doc.data, dict) and doc.data.get("action") in ("global", "reset", "repeat"):
            action = doc.data.get("action")
            body = {k: v for k, v in doc.data.items() if k != "action"}
            if action == "global":
                if any(k in body and not isinstance(body[k], dict) for k in ("logsource", "detection")):
                    doc.error = "yaml: malformed global logsource or detection"
                    docs.append(doc)
                    poisoned = True
                    continue
                global_doc = body
                global_digest = sha256_hex(chunk)
                previous, previous_digest = body, global_digest
                poisoned = False
                continue
            if action == "reset":
                global_doc = None
                global_digest = None
                previous = None
                previous_digest = None
                poisoned = False
                continue
            if previous is None or poisoned:
                doc.error = "yaml: repeat has no valid previous document"
                docs.append(doc)
                continue
            doc.data = _merge(previous, body)
            doc.context_digest = previous_digest
        elif poisoned:
            doc.error = "yaml: unresolved collection context after rejected document; use global or reset"
            docs.append(doc)
            continue
        elif isinstance(doc.data, dict) and "action" in doc.data:
            doc.error = "yaml: unknown collection action"
            docs.append(doc)
            poisoned = True
            continue
        if global_doc is not None and isinstance(doc.data, dict):
            doc.data = _merge(global_doc, doc.data)
            doc.context_digest = doc.context_digest or global_digest
        if doc.context_digest is not None:
            doc.flags.append("legacy_collection")
            if effective_bytes >= MAX_EFFECTIVE_FILE_BYTES:
                doc.error = "yaml: effective collection exceeds size limit"
                docs.append(doc)
                previous = None
                continue
            doc.effective = yaml.safe_dump(doc.data, allow_unicode=True, sort_keys=False)
            size = len(doc.effective.encode("utf-8", "surrogatepass"))
            effective_bytes += size
            if size > MAX_FILE_BYTES or effective_bytes > MAX_EFFECTIVE_FILE_BYTES:
                doc.error = "yaml: effective document exceeds size limit"
        doc.kind = rule_kind(doc.data) if isinstance(doc.data, dict) else None
        if doc.error:
            previous = None
        elif doc.kind:
            previous, previous_digest = doc.data, doc.identity_hash
        docs.append(doc)
    return docs
