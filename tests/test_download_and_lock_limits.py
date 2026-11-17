"""Web downloads are spooled to disk and sent with a bounded number of send slots, a per-chunk idle timeout and a
total deadline; the doctor's lock probe never makes a writer fail; searches wait briefly for a slot and refuse
cross-site requests."""

from __future__ import annotations

import asyncio
import gc
import threading
import time
from pathlib import Path

import pytest
from fastapi.responses import Response
from fastapi.testclient import TestClient

from sigharvest import ondemand
from tests.test_web import HTML, client, logic  # noqa: F401 (shared fixtures)


async def _send_all(response: Response, stall_after: int | None = None) -> list[bytes]:
    """Run the response as the server would; with `stall_after`, the client stops reading after that many chunks."""
    bodies: list[bytes] = []

    async def receive() -> dict[str, str]:
        return {"type": "http.disconnect"}

    async def send(message: dict) -> None:  # type: ignore[type-arg]
        if message["type"] == "http.response.body":
            if stall_after is not None and len(bodies) >= stall_after:
                await asyncio.sleep(3600)  # the socket buffer is full and the client never reads again
            bodies.append(message["body"])

    await response({"type": "http"}, receive, send)
    return bodies


def test_build_turn_is_released_once_spooled_and_the_send_slot_when_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest.web.routes import export

    monkeypatch.setattr(export, "CHUNK", 1000)
    body = bytes(range(256)) * 40
    response = export.held_download(lambda: Response(body, media_type="application/zip", headers={"Content-Disposition": "attachment"}))
    assert ondemand._export_jobs == 0  # the next build does not wait for this client
    assert ondemand._sends == 1
    assert response.headers["content-length"] == str(len(body)) and response.headers["content-type"] == "application/zip"
    chunks = asyncio.run(_send_all(response))
    assert b"".join(chunks) == body and len([c for c in chunks if c]) == 11
    assert ondemand._sends == 0


def test_a_stalled_client_is_disconnected_and_frees_its_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest.web.routes import export

    monkeypatch.setattr(export, "CHUNK", 10)
    monkeypatch.setattr(export, "SEND_IDLE_SECONDS", 0.2)
    response = export.held_download(lambda: Response(b"x" * 100))
    started = time.monotonic()
    chunks = asyncio.run(_send_all(response, stall_after=1))  # reads one chunk, then stalls
    assert chunks == [b"x" * 10] and time.monotonic() - started < 5
    assert ondemand._sends == 0


def test_a_slow_client_hits_the_send_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest.web.routes import export

    monkeypatch.setattr(export, "CHUNK", 10)
    monkeypatch.setattr(export, "SEND_SECONDS", 0.3)
    response = export.held_download(lambda: Response(b"x" * 10_000))

    async def trickle() -> None:
        async def receive() -> dict[str, str]:
            return {"type": "http.disconnect"}

        async def send(message: dict) -> None:  # type: ignore[type-arg]
            await asyncio.sleep(0.05)  # reads, but too slowly to finish

        await response({"type": "http"}, receive, send)

    asyncio.run(trickle())
    assert ondemand._sends == 0


def test_too_many_sends_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi import HTTPException

    from sigharvest.web.routes import export

    monkeypatch.setattr(ondemand, "SENDS_MAX", 2)
    held = [export.held_download(lambda: Response(b"x")) for _ in range(2)]
    with pytest.raises(HTTPException) as refused:
        export.held_download(lambda: Response(b"x"))
    assert refused.value.status_code == 429
    for response in held:
        asyncio.run(_send_all(response))
    assert ondemand._sends == 0


def test_an_unsent_response_frees_its_slot() -> None:
    from sigharvest.web.routes import export

    response = export.held_download(lambda: Response(b"x" * 10))
    assert ondemand._sends == 1
    del response
    gc.collect()
    assert ondemand._sends == 0


def test_a_failed_build_gives_its_slot_back() -> None:
    from fastapi import HTTPException

    from sigharvest.web.routes import export

    def fails() -> Response:
        raise HTTPException(404, "nothing")

    with pytest.raises(HTTPException):
        export.held_download(fails)
    assert ondemand._export_jobs == 0 and ondemand._sends == 0


def test_web_download_streams(client: TestClient) -> None:  # noqa: F811
    r = client.get("/export/download", params={"q": "mimikatz", "format": "sheet"}, headers=HTML)
    assert r.status_code == 200 and r.headers["content-disposition"].startswith("attachment") and r.content
    assert ondemand._export_jobs == 0 and ondemand._sends == 0


def test_lock_probe_never_makes_a_writer_fail(tmp_path: Path) -> None:
    from sigharvest.config import Workspace
    from sigharvest.lock import UpdateLock, holder, lock_path

    ws = Workspace(tmp_path)
    (tmp_path / "data").mkdir()
    lock_path(ws).touch()
    stop = threading.Event()

    def probe() -> None:
        while not stop.is_set():
            holder(lock_path(ws))

    probers = [threading.Thread(target=probe) for _ in range(2)]
    for p in probers:
        p.start()
    try:
        for _ in range(200):
            with UpdateLock(ws):  # timeout 0: before the fix about 6% of these failed
                pass
    finally:
        stop.set()
        for p in probers:
            p.join()
    with UpdateLock(ws):
        assert holder(lock_path(ws)) is not None


def test_a_held_lock_is_still_refused_quickly(tmp_path: Path) -> None:
    from sigharvest.config import Workspace
    from sigharvest.lock import LockHeld, UpdateLock

    ws = Workspace(tmp_path)
    with UpdateLock(ws):
        started = time.monotonic()
        with pytest.raises(LockHeld):
            UpdateLock(ws).acquire()
        assert time.monotonic() - started < 3


def test_searches_are_same_origin_only_and_wait_briefly(client: TestClient) -> None:  # noqa: F811
    from sigharvest.web import deps

    assert deps.SEARCH_WAIT_SECONDS <= 2
    for path in ("/api/search", "/api/facets"):
        assert client.get(path, params={"q": "mimikatz"}, headers={"sec-fetch-site": "cross-site"}).status_code == 403
        assert client.get(path, params={"q": "mimikatz"}, headers={"origin": "http://evil.example"}).status_code == 403
        assert client.get(path, params={"q": "mimikatz"}).status_code == 200  # curl and scripts send no Origin
        assert client.get(path, params={"q": "mimikatz"}, headers={"sec-fetch-site": "same-origin"}).status_code == 200
