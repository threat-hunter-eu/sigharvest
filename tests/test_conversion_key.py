"""Conversion and validation result keys: package versions, options and executed module sources."""

from __future__ import annotations

import pytest

from sigharvest import conversion, conversion_key, fingerprints, testing
from tests.helpers import SCHEMA_FIXTURES


@pytest.fixture
def edited(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    original = fingerprints.source_digest

    def edit(*modules: str) -> None:
        conversion.toolchain.cache_clear()
        monkeypatch.setattr(fingerprints, "source_digest", lambda m: "0" * 64 if m in modules else original(m))

    yield edit
    conversion.toolchain.cache_clear()


def test_keys_are_stable() -> None:
    assert conversion.toolchain("splunk") == conversion.toolchain("splunk")
    assert testing.validation_toolchain(SCHEMA_FIXTURES) == testing.validation_toolchain(SCHEMA_FIXTURES)


@pytest.mark.parametrize("module", conversion_key.CONVERT_MODULES)
def test_executed_module_change_invalidates_conversion(edited, module: str) -> None:  # type: ignore[no-untyped-def]
    before = conversion.toolchain("splunk")
    edited(module)
    assert conversion.toolchain("splunk") != before


@pytest.mark.parametrize("module", conversion_key.VALIDATE_MODULES)
def test_executed_module_change_invalidates_validation(edited, module: str) -> None:  # type: ignore[no-untyped-def]
    before = testing.validation_toolchain(SCHEMA_FIXTURES)
    edited(module)
    assert testing.validation_toolchain(SCHEMA_FIXTURES) != before


def test_plumbing_edit_keeps_the_key(edited) -> None:  # type: ignore[no-untyped-def]
    before = conversion.toolchain("splunk"), testing.validation_toolchain(SCHEMA_FIXTURES)
    edited("sync.py", "service.py", "lock.py")
    assert (conversion.toolchain("splunk"), testing.validation_toolchain(SCHEMA_FIXTURES)) == before


def test_package_versions_and_targets_are_in_the_key(monkeypatch: pytest.MonkeyPatch) -> None:
    before = conversion.toolchain("splunk")
    assert conversion.toolchain("lucene") != before
    version = fingerprints.package_version
    monkeypatch.setattr(fingerprints, "package_version", lambda p: "changed" if p == "pysigma" else version(p))
    conversion.toolchain.cache_clear()
    try:
        assert conversion.toolchain("splunk") != before
    finally:
        monkeypatch.undo()
        conversion.toolchain.cache_clear()


def test_changes_name_components() -> None:
    before = conversion_key.components("splunk")
    after = {**before, "packages": {**before["packages"], "pysigma": "9"}, "options": {"x": 1}}
    changed = conversion_key.changes(before, after)
    assert "packages: pysigma changed" in changed
    assert any(line.startswith("options:") for line in changed)
