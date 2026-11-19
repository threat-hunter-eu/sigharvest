"""scrub() URL redaction stays linear on untrusted text and keeps its matches."""

from __future__ import annotations

import re
import time

import pytest

from sigharvest.observability import scrub

OLD_SENSITIVE = r"https?://[^\s<>\"']*[@?#][^\s<>\"']*"


@pytest.mark.parametrize(
    "text",
    [
        "see https://example.org/rule and http://user@host/x",
        "HTTP://host/p?q=1#frag tail",
        "http://a/b http://c?d http://e#f",
        "http://x@yhttp://z",
        "plain http://",
        "'http://q?x' <http://h@i> \"https://k\"",
        "http://http://http://?",
    ],
)
def test_sensitive_url_redaction_matches_previous_pattern(text: str) -> None:
    assert scrub(text, redact_urls=False) == re.sub(OLD_SENSITIVE, "[url redacted]", text, flags=re.I)


def test_all_url_redaction_is_unchanged() -> None:
    assert scrub("go https://example.org/a?b and http:// end") == "go [url redacted] and http:// end"


@pytest.mark.parametrize("redact_urls", [False, True])
def test_repeated_scheme_is_linear(redact_urls: bool) -> None:
    text = "http://" * 5_000
    start = time.perf_counter()
    scrub(text, redact_urls=redact_urls)
    assert time.perf_counter() - start < 1.0
