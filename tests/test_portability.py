"""Portability (Windows through WSL, but no POSIX-only assumptions where a portable form exists)."""

from __future__ import annotations

import io
import sys
import threading
import time
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from sigharvest.config import workspace_relative


def test_workspace_relative_paths_are_posix_on_windows() -> None:
    root = PureWindowsPath(r"C:\work\ws sig")
    report = root / "reports" / "runs" / "20261114T143513Z.md"
    rel = workspace_relative(report, root)
    assert rel == "reports/runs/20261114T143513Z.md"  # what a later `update` reads back from the DB
    assert workspace_relative(PurePosixPath("/ws/reports/runs/a.md"), PurePosixPath("/ws")) == "reports/runs/a.md"


def test_init_hint_quotes_the_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest.cli import pipeline

    if pipeline.os.name == "posix":
        assert pipeline.cd_command(Path("/tmp/ws sig")) == "cd '/tmp/ws sig'"
        assert pipeline.cd_command(Path("/tmp/ws")) == "cd /tmp/ws"
    root = Path("/tmp/ws sig")
    monkeypatch.setattr(pipeline.os, "name", "nt")
    hint = pipeline.cd_command(root)
    monkeypatch.undo()
    assert hint.startswith('cd /d "') and hint.endswith('ws sig"')


class _Pipe(io.TextIOWrapper):
    def isatty(self) -> bool:
        return False


def test_redirected_output_is_utf8(monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest.cli import setup_stdio

    raw = io.BytesIO()
    out = _Pipe(raw, encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", _Pipe(io.BytesIO(), encoding="cp1252"))
    setup_stdio()
    print("Détection réseau 漢字")
    out.flush()
    assert raw.getvalue().decode("utf-8").strip() == "Détection réseau 漢字"


def test_encoding_error_is_not_invalid_input(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from sigharvest.cli import _handle_error

    monkeypatch.setattr(sys, "argv", ["sigharvest", "show", "x"])
    with pytest.raises(SystemExit) as exit_info:
        _handle_error(UnicodeEncodeError("charmap", "漢字", 0, 2, "character maps to <undefined>"))
    assert exit_info.value.code == 2
    err = capsys.readouterr().err
    assert "text encoding error" in err and "invalid input" not in err


def test_windows_lock_refusal_points_to_wsl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest import lock
    from sigharvest.config import Workspace

    owner = lock.UpdateLock(Workspace(tmp_path))
    monkeypatch.setattr(lock.os, "name", "nt")
    with pytest.raises(lock.LockHeld) as exc:
        owner.acquire()
    monkeypatch.undo()
    assert "Windows is supported through WSL: https://" in str(exc.value) and "#windows-use-wsl" in str(exc.value)


def test_start_method_without_forkserver(monkeypatch: pytest.MonkeyPatch) -> None:
    import multiprocessing

    from sigharvest import conversion_memory

    monkeypatch.setattr(multiprocessing, "get_all_start_methods", lambda: ["spawn"])
    assert conversion_memory.start_method() == "spawn"


def test_call_with_timeout() -> None:
    from sigharvest.deadline import call_with_timeout

    started = time.monotonic()
    assert call_with_timeout(lambda: time.sleep(5) or "done", 0.1, lambda: "timeout") == "timeout"
    assert time.monotonic() - started < 2
    assert call_with_timeout(lambda: "done", 5, lambda: "timeout") == "done"
    with pytest.raises(KeyError):
        call_with_timeout(lambda: {}["missing"], 5, lambda: None)


def test_conversion_is_bounded_without_sigalrm(monkeypatch: pytest.MonkeyPatch) -> None:
    """Off the main thread (and on Windows, which has no setitimer) the timeout still applies."""
    from sigharvest import conversion

    monkeypatch.setattr(conversion, "_convert_single", lambda *a, **k: time.sleep(5))
    box: list[conversion.Conversion] = []
    worker = threading.Thread(target=lambda: box.append(conversion._timed_single("x", "splunk", "rule", (), None, 0.1)))
    worker.start()
    worker.join(3)
    assert box and box[0].status == "timeout"


def test_validation_is_bounded_without_sigalrm(monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest import testing

    monkeypatch.setattr(testing, "VALIDATE_TIMEOUT", 0.1)
    monkeypatch.setattr(testing, "_validate_unbounded", lambda item: time.sleep(5))
    monkeypatch.setitem(testing._W, "toolchain", "t")
    box: list[tuple] = []
    worker = threading.Thread(target=lambda: box.append(testing._validate_one((1, "rule", "title: x"))))
    worker.start()
    worker.join(3)
    assert box and box[0][2] == "error" and "timeout" in box[0][3]["parse"][0]
