"""The suite-wide network guard (tests/offline.py) refuses outbound connections and remote git transports."""

from __future__ import annotations

import socket
import subprocess

import httpx
import pytest

from tests import offline as conftest


def test_outbound_connections_are_refused_and_recorded() -> None:
    start = len(conftest._attempts)
    try:
        with pytest.raises(conftest.NetworkBlocked):
            socket.create_connection(("192.0.2.1", 80), timeout=1)
        with pytest.raises(httpx.ConnectError):
            httpx.get("https://example.com/", timeout=1)
        assert len(conftest._attempts) - start >= 2
    finally:
        del conftest._attempts[start:]  # expected attempts: do not fail this test at teardown


def test_localhost_is_allowed() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        with socket.create_connection(server.getsockname(), timeout=2):
            pass


def test_git_cannot_use_remote_transports() -> None:
    proc = subprocess.run(["git", "ls-remote", "https://github.com/SigmaHQ/sigma"], capture_output=True, text=True, timeout=30)
    assert proc.returncode != 0 and "not allowed" in proc.stderr
