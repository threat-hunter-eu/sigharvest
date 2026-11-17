"""Typed author/description for search and display, independent of structural score.

The local Sigma schema specifies strings. Nonempty lists of nonblank strings are
an explicit author compatibility extension; no other container is rendered.
"""

from __future__ import annotations

from typing import Any, NamedTuple

import yaml


class TextMetadata(NamedTuple):
    author: str | None = None
    description: str | None = None


def project(data: dict[str, Any]) -> TextMetadata:
    """Retain author spelling and existing description trimming, without coercion."""
    author = data.get("author")
    if isinstance(author, list) and author and all(isinstance(item, str) and item.strip() for item in author):
        author = ", ".join(author)
    if not isinstance(author, str) or not author.strip():
        author = None
    description = data.get("description")
    description = description.strip() or None if isinstance(description, str) else None
    return TextMetadata(author, description)


def from_raw(raw: str) -> TextMetadata:
    """Read stored effective YAML with the existing bounded rule-context parser.

    Index workers call this once per canonical document, never per search result.
    Missing, refused or oversized documents cannot borrow stringified columns.
    """
    from sigharvest.documents import MAX_FILE_BYTES, MAX_YAML_NODES, FastSigmaSafeLoader, _IngestLoader
    from sigharvest.ruleview import _load

    if len(raw) > MAX_FILE_BYTES or len(raw.encode("utf-8")) > MAX_FILE_BYTES:
        return TextMetadata()
    data = _load(raw, loader=FastSigmaSafeLoader, max_nodes=MAX_YAML_NODES)
    if data is None:
        # The display parser refuses all aliases. Ingest's bounded loader can
        # admit ordinary aliases/merges while still rejecting cycles and bombs.
        try:
            data = yaml.load(raw, Loader=_IngestLoader)  # noqa: S506 - bounded Sigma SafeLoader
        except (yaml.YAMLError, ValueError, RecursionError):
            return TextMetadata()
    return project(data) if isinstance(data, dict) else TextMetadata()
