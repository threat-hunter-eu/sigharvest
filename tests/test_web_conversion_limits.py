"""On-demand conversion is bounded (worker process, deadline, size and value caps), downloads go
through a bounded queue, expensive GETs refuse cross-site requests, and a single-rule query carries its attribution."""

from __future__ import annotations

import os
import signal
import time

import pytest
from fastapi.testclient import TestClient

from sigharvest import conversion, ondemand
from tests.test_web import client, logic  # noqa: F401 - the module-scoped web fixture

pytestmark = pytest.mark.backend("splunk")

CROSS = {"sec-fetch-site": "cross-site"}


def big_rule(values: int) -> str:
    items = "".join(f"      - value{i}\n" for i in range(values))
    return f"title: big\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  sel:\n    CommandLine|contains:\n{items}  condition: sel\n"


def test_value_and_size_caps_refuse_before_any_worker_starts() -> None:
    assert ondemand.too_large(big_rule(10)) is None
    assert "detection values" in (ondemand.too_large(big_rule(ondemand.MAX_VALUES + 1)) or "")
    assert "KiB" in (ondemand.too_large("x" * (ondemand.MAX_CHARS + 1)) or "")
    conv = ondemand.convert(big_rule(ondemand.MAX_VALUES + 1), "splunk")
    assert conv.status == "skipped" and "sigharvest convert" in (conv.reason or "")


def test_a_conversion_over_its_deadline_is_killed_and_the_slot_recovers(monkeypatch: pytest.MonkeyPatch) -> None:
    ondemand.shutdown()
    conversion._on_demand.clear()
    monkeypatch.setattr(ondemand, "DEADLINE", 0.01)  # less than a worker needs to start
    slow = ondemand.convert(big_rule(3), "splunk")
    assert slow.status == "timeout"
    monkeypatch.setattr(ondemand, "DEADLINE", 120.0)
    ok = ondemand.convert(big_rule(3), "splunk")
    assert ok.status == "ok" and ok.queries
    ondemand.shutdown()


def test_a_slot_whose_idle_worker_died_starts_a_fresh_worker() -> None:
    """An idle worker that dies between conversions (OOM killer, operator) breaks its pool; the next conversion on
    that slot starts a new worker instead of failing, and no slot keeps the broken pool."""
    ondemand.shutdown()
    conversion._on_demand.clear()
    assert ondemand.convert(big_rule(5), "splunk").status == "ok"
    pool = ondemand._pool()
    used = [s for s in list(pool.queue) if s.executor is not None]
    assert len(used) == 1
    executor = used[0].executor
    for pid in list(executor._processes):
        os.kill(pid, signal.SIGKILL)
    deadline = time.monotonic() + 10
    while not executor._broken and time.monotonic() < deadline:
        time.sleep(0.05)
    assert executor._broken
    statuses = [ondemand.convert(big_rule(6 + i), "splunk").status for i in range(2 * ondemand.SLOTS)]
    assert statuses == ["ok"] * (2 * ondemand.SLOTS)
    assert all(s.executor is None or not s.executor._broken for s in list(pool.queue))
    ondemand.shutdown()


def test_conversion_does_not_run_in_the_calling_process(monkeypatch: pytest.MonkeyPatch) -> None:
    """A patched in-process converter is never called: the worker process does the work."""
    conversion._on_demand.clear()
    monkeypatch.setattr(conversion, "convert", lambda *a, **k: pytest.fail("converted inline"))
    assert ondemand.convert(big_rule(4), "splunk").status == "ok"


def test_web_refuses_cross_site_conversions_and_downloads(client: TestClient) -> None:  # noqa: F811
    key = logic(client)[:16]
    for url in (
        f"/api/convert/{key}?target=splunk",
        f"/rule/{key}/query.txt?target=splunk",
        f"/export/download?h={key}&format=zip",
        "/search/export?q=mimikatz",
    ):
        assert client.get(url, headers=CROSS).status_code == 403, url
        assert client.get(url, headers={"sec-fetch-site": "same-origin"}).status_code == 200, url


def test_downloads_beyond_the_queue_get_429(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    monkeypatch.setattr(ondemand, "_export_jobs", ondemand.EXPORTS_RUNNING + ondemand.EXPORTS_QUEUED)
    response = client.get("/export/download?format=zip&scope=all")
    assert response.status_code == 429
    assert response.headers.get("retry-after")


def test_single_rule_query_download_carries_attribution(client: TestClient) -> None:  # noqa: F811
    key = logic(client)[:16]
    body = client.get(f"/rule/{key}/query.txt?target=splunk").text
    first = body.splitlines()[0]
    assert first.startswith("# attribution: Mimikatz Command Line")
    assert "author: Tester" in first and "licence: MIT" in first


def test_collection_export_is_same_origin_and_queued(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    key = logic(client)[:16]
    assert client.post("/collections", data={"name": "guarded"}, follow_redirects=False).status_code in (302, 303)
    assert client.post("/collections/add", data={"name": "guarded", "keys": key}, follow_redirects=False).status_code in (302, 303)
    try:
        for fmt in ("zip", "splunk"):
            assert client.get(f"/collections/guarded/export?format={fmt}", headers=CROSS).status_code == 403, fmt
            assert client.get(f"/collections/guarded/export?format={fmt}", headers={"sec-fetch-site": "same-origin"}).status_code == 200, fmt
        monkeypatch.setattr(ondemand, "_export_jobs", ondemand.EXPORTS_RUNNING + ondemand.EXPORTS_QUEUED)
        full = client.get("/collections/guarded/export?format=zip")
        assert full.status_code == 429 and full.headers.get("retry-after")
    finally:
        monkeypatch.undo()
        client.post("/collections/guarded/delete", follow_redirects=False)
