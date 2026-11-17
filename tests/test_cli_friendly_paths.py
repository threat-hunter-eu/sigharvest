"""Wrong paths and invalid values give one readable line and exit 2, never a traceback."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _run(home: Path, *args: str) -> subprocess.CompletedProcess[str]:
    code = "import sys; from sigharvest.cli import main; sys.argv = ['sigharvest', *sys.argv[1:]]; main()"
    return subprocess.run(
        [sys.executable, "-c", code, *args],
        capture_output=True,
        text=True,
        env={"SIGHARVEST_HOME": str(home), "PATH": "/usr/bin:/bin", "COLUMNS": "120"},
        timeout=120,
    )


def test_missing_file_and_folder_inputs_are_one_line(tmp_path: Path) -> None:
    assert _run(tmp_path, "init", str(tmp_path)).returncode == 0
    missing = _run(tmp_path, "collection", "import", "saved", str(tmp_path / "nope.jsonl"))
    assert missing.returncode == 2
    assert "file or folder not found" in missing.stderr and "Traceback" not in missing.stderr
    folder = _run(tmp_path, "collection", "import", "saved", str(tmp_path))
    assert folder.returncode == 2 and "Traceback" not in folder.stderr


def test_long_paths_are_never_wrapped_mid_line(tmp_path: Path) -> None:
    """At 80 columns, a long workspace path stays whole on its line (the terminal may wrap it, Rich must not split
    it with a newline: that breaks copy and paste)."""
    import os

    home = tmp_path / ("a-rather-long-folder-name-" * 3) / "sigma workspace"
    code = "import sys; from sigharvest.cli import main; sys.argv = ['sigharvest', *sys.argv[1:]]; main()"
    out = subprocess.run(
        [sys.executable, "-c", code, "init", str(home)],
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "COLUMNS": "80", "HOME": str(tmp_path)},
        timeout=120,
    )
    assert out.returncode == 0, out.stderr
    first = out.stdout.splitlines()[0]
    assert first.startswith(f"workspace {home}: "), out.stdout


def test_every_rich_console_soft_wraps() -> None:
    """Rich hard-wraps at 80 columns in a pipe unless soft_wrap is on: every Console the package creates keeps
    paths and commands whole (site build missed it once)."""
    import re

    src = Path(__file__).resolve().parents[1] / "src" / "sigharvest"
    missing = [
        f"{p.relative_to(src)}:{n}"
        for p in src.rglob("*.py")
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if re.search(r"\bConsole\((?![^)]*soft_wrap=True)", line)
    ]
    assert not missing, missing


def test_a_broken_sources_file_is_one_line_that_names_the_file(tmp_path: Path) -> None:
    """A hand edit that broke sources.yaml (not YAML, not UTF-8, `sources:` not a list) printed a traceback."""
    assert _run(tmp_path, "init", str(tmp_path), "--preset", "sigmahq").returncode == 0
    for content, says in (
        (b"[[[ not yaml\n", "is not valid YAML (line 2"),
        (b"sources: 5\n", "`sources:` must be a list"),
        (b"sources: [1, 2]\n", "`sources:` must be a list"),
        (b"\xff\xfe sources: []\n", "is not UTF-8 text"),
    ):
        (tmp_path / "sources.yaml").write_bytes(content)
        for args in (("doctor",), ("sources", "list")):
            out = _run(tmp_path, *args)
            assert out.returncode == 2 and says in out.stderr and "Traceback" not in out.stderr, (content, args, out.stderr)


def test_a_damaged_database_says_how_to_recover(tmp_path: Path) -> None:
    assert _run(tmp_path, "init", str(tmp_path), "--preset", "sigmahq").returncode == 0
    (tmp_path / "data" / "sigharvest.db").write_bytes(b"this is not sqlite" * 300)
    for args in (("doctor",), ("search", "x")):
        out = _run(tmp_path, *args)
        assert out.returncode == 2 and "database (data/sigharvest.db) is damaged" in out.stderr, (args, out.stderr)
        assert "Traceback" not in out.stderr


def test_serve_on_a_busy_port_is_one_line_with_exit_code_2(tmp_path: Path) -> None:
    """It printed the start banner, then uvicorn's bind error, and exited 3 (docs/conventions.md: 2)."""
    import socket

    assert _run(tmp_path, "init", str(tmp_path), "--preset", "sigmahq").returncode == 0
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        port = sock.getsockname()[1]
        out = _run(tmp_path, "serve", "--port", str(port))
    assert out.returncode == 2 and f"cannot listen on 127.0.0.1 port {port}" in out.stderr, out.stderr
    assert "Ctrl+C stops it" not in out.stdout + out.stderr
