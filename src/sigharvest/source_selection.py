"""Which files of a source are eligible for ingestion.

Kept apart from the fetch plumbing in sync.py: this predicate decides which paths
become stored rows, so it is part of the ingest policy fingerprint
(source_snapshots.INGEST_MODULES), while the adapters around it are not.
"""

from __future__ import annotations

from fnmatch import fnmatch

from sigharvest.config import SourceConfig


def utf8_name(rel: str) -> bool:
    """False for a path decoded with surrogateescape from bytes that are not UTF-8."""
    try:
        rel.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def storable_path(rel: str) -> str:
    """The path as stored in the database: a name that is not UTF-8 (decoded with surrogateescape, for example
    a latin-1 byte from another OS) keeps its bytes as backslash escapes, so it can be stored and shown."""
    if utf8_name(rel):
        return rel
    return rel.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")


def path_selected(rel: str, src: SourceConfig) -> bool:
    """True when a file of the source matches its `paths` globs and none of its `exclude` globs."""
    if not any(fnmatch(rel, pat) or pat in ("**/*", "*", "**") for pat in src.paths):
        return False
    return not any(fnmatch(rel, pat) for pat in src.exclude)
