"""Deterministic cache keys for implementations and their effective inputs.

Only public implementation/configuration data belongs here, never environment
variables or credentials. Source digests also invalidate editable installations.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
from collections.abc import Sequence
from functools import cache
from pathlib import Path
from typing import Any


def digest(value: Any) -> str:
    """Hash canonical JSON; object order is irrelevant, sequence order is significant."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "surrogatepass")).hexdigest()


def text_digest(raw: str) -> str:
    """Hash the UTF-8 document actually consumed by a worker."""
    return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()


def package_version(package: str) -> str:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return "missing"


@cache
def source_digest(module: str) -> str:
    """Hash bundled source once per process; an unreadable implementation fails closed."""
    relative = Path(module)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("expected a package-relative source path")
    return hashlib.sha256((Path(__file__).parent / relative).read_bytes()).hexdigest()


def implementation(stage: str, *, modules: Sequence[str], packages: Sequence[str] = (), options: Any = None) -> str:
    """Shared parser/dependency contract plus the stage's implementation and policy."""
    return digest(implementation_components(stage, modules=modules, packages=packages, options=options))


def implementation_components(stage: str, *, modules: Sequence[str], packages: Sequence[str] = (), options: Any = None) -> dict[str, Any]:
    """Expose the exact inputs behind implementation() for explainable invalidation."""
    if "detection.py" in modules:
        modules = (*modules, "logsource_inference.py", "logsource_catalog.py")
    return {
        "contract": "sigharvest-results-v1",
        "stage": stage,
        "python": platform.python_version(),
        "packages": {p: package_version(p) for p in sorted({"pysigma", "pyyaml", "pyparsing", *packages})},
        "modules": {m: source_digest(m) for m in sorted({"fingerprints.py", "documents.py", *modules})},
        "options": options,
    }


def result_key(toolchain: str, content: str, kind: str, context: Sequence[str] = ()) -> str:
    """Bind implementation to document identity, kind and ordered sibling digests."""
    return digest({"toolchain": toolchain, "content": content, "kind": kind, "context": list(context)})
