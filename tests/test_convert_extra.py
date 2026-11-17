"""The pySigma backends are an optional extra: missing backends are skipped or explained, never a crash."""

from __future__ import annotations

import pytest

from sigharvest import conversion


def test_installed_backends_have_no_error() -> None:
    for target in conversion.BACKENDS:
        assert conversion.backend_error(target) is None


def test_missing_and_unknown_backends_explain_themselves(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(conversion, "BACKENDS", [])
    message = conversion.backend_error("splunk")
    assert message is not None and "sigharvest[convert]" in message
    unknown = conversion.backend_error("nope")
    assert unknown is not None and "unknown backend" in unknown


def test_convert_stage_is_skipped_without_backends(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from sigharvest import testing
    from sigharvest.config import Workspace

    monkeypatch.setattr(testing, "BACKENDS", [])
    summary = testing.run_stage(Workspace(tmp_path), None, "convert")  # type: ignore[arg-type]
    assert (summary.processed, summary.skipped, summary.counts) == (0, 0, {})
