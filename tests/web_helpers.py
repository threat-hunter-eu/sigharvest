"""Existing UI journeys acquire a browser session and submit its CSRF header.

Authentication boundary tests deliberately use the unmodified Starlette TestClient.
"""

import re
from typing import Any

from fastapi.testclient import TestClient


class BrowserClient(TestClient):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        page = self.get("/")
        match = re.search(r'<meta name="csrf-token" content="([a-f0-9]{64})">', page.text)
        if match:
            self.headers["X-CSRF-Token"] = match[1]


def apply_preview(client: Any, response: Any) -> Any:
    """Review a successful HTML preview, then submit its exact token as a browser."""
    assert response.status_code == 200, response.text
    token = re.search(r'name="token" value="([^"]+)"', response.text)
    assert token is not None
    return client.post("/triage/apply", data={"token": token[1]}, follow_redirects=False)
