"""Rule-test result keys (convert and validate): the code and packages each stage depends on.

A stored result is reused only while its key is unchanged. The key covers the package versions (pySigma, backends,
pipelines), the stage options and the source of the modules the stage executes. Like fingerprints.py, this module
only computes keys and decides no stored row, so it is not part of any key.
"""

from __future__ import annotations

from typing import Any

from sigharvest import fingerprints

CONTRACT = "sigharvest-results-v1"
BASE_PACKAGES = ("pyparsing", "pysigma", "pyyaml")
VALIDATION_PACKAGES = ("jsonschema", "referencing", "jsonschema-specifications")
# Modules executed by each stage (package-relative paths).
CONVERT_MODULES = ("conversion.py", "datasources.py", "detection.py", "documents.py", "identity.py", "pysigma_speedups.py", "testing_conversion.py")
VALIDATE_MODULES = ("conversion.py", "detection.py", "documents.py", "identity.py", "testing.py")
BOM = "﻿"


def libyaml() -> str | None:
    """libyaml version behind PyYAML's C loaders, or None when PyYAML falls back to pure Python."""
    import yaml

    if not getattr(yaml, "__with_libyaml__", False):
        return None
    try:
        from yaml import _yaml

        return str(_yaml.get_version_string())
    except (ImportError, AttributeError):
        return "unknown"


def _components(stage: str, modules: tuple[str, ...], packages: tuple[str, ...], options: Any) -> dict[str, Any]:
    import platform

    return {
        "contract": CONTRACT,
        "stage": stage,
        "python": platform.python_version(),
        "libyaml": libyaml(),
        "packages": {p: fingerprints.package_version(p) for p in sorted({*BASE_PACKAGES, *packages})},
        "modules": {m: fingerprints.source_digest(m) for m in sorted(modules)},
        "options": options,
    }


def _options(target: str) -> dict[str, Any]:
    from sigharvest import conversion

    return {"selection": conversion.SELECTION_VERSION, "state": conversion.STATE_VERSION, "target": target}


def components(target: str) -> dict[str, Any]:
    """The inputs behind toolchain(target), for explainable invalidation."""
    from sigharvest.conversion import PACKAGES

    return _components("convert", CONVERT_MODULES, tuple(PACKAGES[target]), _options(target))


def toolchain(target: str) -> str:
    """Versions and implementation that determine a conversion result for `target`."""
    from sigharvest import conversion

    parts = [
        f"sigharvest-conversion/{conversion.SELECTION_VERSION}",
        f"state/{conversion.STATE_VERSION}",
        f"pysigma/{fingerprints.package_version('pysigma')}",
    ]
    parts += [f"{p}/{fingerprints.package_version(p)}" for p in conversion.PACKAGES[target]]
    parts.append("implementation/" + fingerprints.digest(components(target)))
    return " ".join(parts)


def validation_toolchain(options: dict[str, Any]) -> str:
    """Key of validation results; `options` holds the spec commit, effective schemas and validator set."""
    return fingerprints.digest(_components("validate", VALIDATE_MODULES, VALIDATION_PACKAGES, options))


def changes(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Readable differences between two component sets (module, package or option names)."""
    out = []
    for key in sorted(before.keys() | after.keys()):
        old, new = before.get(key), after.get(key)
        if old == new:
            continue
        if isinstance(old, dict) and isinstance(new, dict):
            for name in sorted(old.keys() | new.keys()):
                if name not in new:
                    out.append(f"{key}: {name} removed")
                elif name not in old:
                    out.append(f"{key}: {name} added")
                elif old[name] != new[name]:
                    out.append(f"{key}: {name} changed")
        else:
            out.append(f"{key}: {old} -> {new}")
    return out
