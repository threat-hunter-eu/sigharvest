"""Conservative extraction of complete Sigma documents from text, HTML and dataset rows.

No scanning for a title or detection fragment inside prose. Only entire YAML documents,
closed Markdown blocks, closed HTML pre/code elements, and explicit JSON rule fields qualify.
"""

from __future__ import annotations

import json
import re
import textwrap
from html.parser import HTMLParser
from typing import Any

import yaml

from sigharvest.documents import MAX_FILE_BYTES, SigmaSafeLoader
from sigharvest.sync import SyncError

MAX_NODES = 100_000
MAX_DEPTH = 64
MAX_ROWS = 100_000
MAX_BLOCKS = 10_000


class _BoundedLoader(SigmaSafeLoader):
    """Reject aliases, excessive nesting and node counts before constructing objects."""

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self.nodes = 0
        self.depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        self.nodes += 1
        self.depth += 1
        if self.check_event(yaml.AliasEvent) or self.nodes > MAX_NODES or self.depth > MAX_DEPTH:
            raise yaml.YAMLError("YAML aliases or complexity limit")
        try:
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1

    def construct_mapping(self, node: Any, deep: bool = False) -> Any:
        result = super().construct_mapping(node, deep=deep)
        if len(result) != len(node.value):
            raise yaml.YAMLError("duplicate YAML keys")
        return result


def _sigma(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    if isinstance(data.get("correlation"), dict):
        return bool(data["correlation"])
    if not isinstance(data.get("logsource"), dict):
        return False
    if isinstance(data.get("filter"), dict):
        return bool(data["filter"])
    detection = data.get("detection")
    return isinstance(detection, dict) and isinstance(detection.get("condition"), str) and bool(detection["condition"].strip())


def complete_yaml(text: str) -> bytes | None:
    """Accept a whole candidate only when every nonempty document has Sigma structure."""
    raw = text.encode("utf-8")
    if len(raw) > MAX_FILE_BYTES:
        raise SyncError("Sigma document exceeds the size limit")
    try:
        docs = list(yaml.load_all(text, Loader=_BoundedLoader))
    except (yaml.YAMLError, RecursionError, ValueError):
        return None
    docs = [d for d in docs if d is not None]
    return raw if docs and all(_sigma(d) for d in docs) else None


def text_blocks(text: str) -> list[tuple[str, bytes]]:
    """Read whole YAML first, then closed fenced or four-space/tab-indented blocks."""
    if raw := complete_yaml(text):
        return [("document", raw)]
    lines = text.splitlines(keepends=True)
    candidates: list[tuple[str, str]] = []
    i = 0
    while i < len(lines):
        fence = re.fullmatch(r" {0,3}(`{3,}|~{3,})([^\r\n]*)[\r\n]*", lines[i])
        if fence:
            marker, language = fence.groups()
            start = i
            i += 1
            body = []
            while i < len(lines) and not re.fullmatch(r" {0,3}" + re.escape(marker[0]) + r"{" + str(len(marker)) + r",}[ \t]*[\r\n]*", lines[i]):
                body.append(lines[i])
                i += 1
            if i < len(lines) and language.strip().lower() in ("", "yaml", "yml", "sigma"):
                candidates.append((f"fence-{start + 1:06d}", "".join(body)))
        elif (lines[i].startswith("    ") or lines[i].startswith("\t")) and (i == 0 or not lines[i - 1].strip()):
            start = i
            body = []
            while i < len(lines) and (not lines[i].strip() or lines[i].startswith(("    ", "\t"))):
                line = lines[i]
                body.append(line[1:] if line.startswith("\t") else line[4:] if line.startswith("    ") else line)
                i += 1
            candidates.append((f"indent-{start + 1:06d}", "".join(body)))
            continue
        i += 1
    if len(candidates) > MAX_BLOCKS:
        raise SyncError("too many text blocks")
    return [(name, raw) for name, body in candidates if (raw := complete_yaml(body)) is not None]


class _CodeBlocks(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.parts: list[str] = []
        self.blocks: list[tuple[str, str]] = []
        self.number = 0
        self.ignored = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self.ignored += 1
        if self.ignored:
            return
        if tag in ("pre", "code"):
            if not self.stack:
                self.parts = []
                self.number += 1
                if self.number > MAX_BLOCKS:
                    raise SyncError("too many HTML blocks")
            self.stack.append(tag)
        elif tag == "br" and self.stack:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style"):
            self.ignored = max(0, self.ignored - 1)
            return
        if self.ignored:
            return
        if self.stack and tag == self.stack[-1]:
            self.stack.pop()
            if not self.stack:
                self.blocks.append((f"block-{self.number:06d}", "".join(self.parts)))

    def handle_data(self, data: str) -> None:
        if self.stack and not self.ignored:
            self.parts.append(data)


def html_blocks(text: str) -> list[tuple[str, bytes]]:
    """Decode entities and nested highlighting without duplicating pre/code pairs."""
    parser = _CodeBlocks()
    parser.feed(text)
    parser.close()
    return [(name, raw) for name, body in parser.blocks if (raw := complete_yaml(textwrap.dedent(body))) is not None]


def parse_json(raw: bytes) -> Any:
    """Bound JSON depth and node count; reject duplicate keys and non-JSON numbers."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = dict(items)
        if len(result) != len(items):
            raise ValueError("duplicate keys")
        return result

    def constant(value: str) -> Any:
        raise ValueError("non-JSON number")

    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        pending = [(result, 0)]
        count = 0
        while pending:
            value, depth = pending.pop()
            count += 1
            if depth > MAX_DEPTH or count > MAX_NODES:
                raise ValueError("complexity limit")
            if isinstance(value, (dict, list)):
                pending.extend((v, depth + 1) for v in (value.values() if isinstance(value, dict) else value))
        return result
    except (ValueError, RecursionError):
        raise SyncError("invalid JSON or complexity limit") from None


def dataset_rows(raw: bytes, jsonl: bool) -> list[tuple[str, bytes]]:
    """Accept JSON arrays/objects or JSONL rows, with structured or raw_yaml/sigma_rule data.

    Structured fields win over raw_yaml, which can contain literal backslash-n delimiters.
    Never globally unescape a YAML string: that also changes Windows paths and regexes.
    """
    if jsonl:
        lines = [(i, line) for i, line in enumerate(raw.splitlines(), 1) if line.strip()]
        if len(lines) > MAX_ROWS:
            raise SyncError("too many dataset rows")
        rows = [(i, parse_json(line)) for i, line in lines]
    else:
        data = parse_json(raw)
        rows = list(enumerate(data if isinstance(data, list) else [data], 1))
    if len(rows) > MAX_ROWS:
        raise SyncError("too many dataset rows")
    result = []
    for i, row in rows:
        if not isinstance(row, dict):
            continue
        candidate = None
        if _sigma(row):
            # Keep rule metadata, but never promote dataset IDs into Sigma UUIDs.
            data = {k: v for k, v in row.items() if k not in ("raw_yaml", "sigma_rule", "rule_id", "condition")}
            candidate = complete_yaml(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
        else:
            for key in ("raw_yaml", "sigma_rule"):
                if isinstance(row.get(key), str):
                    candidate = complete_yaml(row[key])
                    if candidate:
                        break
            if candidate is None and (any(key in row for key in ("raw_yaml", "sigma_rule")) or ("logsource" in row and "detection" in row)):
                raise SyncError(f"dataset row {i} has no complete Sigma document; escaped YAML needs structured fields")
        if candidate:
            result.append((f"row-{i:06d}", candidate))
    return result
