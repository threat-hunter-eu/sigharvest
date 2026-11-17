"""pySigma 2 checks `|re` values with RE2, whose C++ library prints every refused pattern to stderr. sigharvest keeps
those lines out of the terminal (debug log only) and summarises the count after validation."""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

from sigharvest import testing

LOOKAHEAD_RULE = textwrap.dedent(
    """\
    title: Net User Without Delete
    id: 5f4bd5a0-1b49-4a59-9c3e-5c1a2b9d1e01
    logsource: {product: windows, category: process_creation}
    detection:
      selection:
        CommandLine|re: 'net\\s+user(?:(?!/delete).)*$'
      condition: selection
    level: low
    """
)


def test_re2_parse_errors_do_not_reach_stderr() -> None:
    pytest.importorskip("re2", reason="pySigma 1.x uses Python's re, which supports lookarounds")
    code = textwrap.dedent(
        f"""
        import logging, sys
        logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
        from sigharvest import pysigma_limits
        pysigma_limits.install()
        from sigma.collection import SigmaCollection
        c = SigmaCollection.from_yaml({LOOKAHEAD_RULE!r}, collect_errors=True)
        print("errors", bool(c.errors or any(r.errors for r in c.rules)))
        import re2
        print("still works", bool(re2.search("a+", "caa")), bool(re2.compile(re2.compile("b")).search("b")))
        """
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120, check=True)
    assert "re2.cc" not in out.stderr and "absl" not in out.stderr and "Error parsing" not in out.stderr, out.stderr
    assert "errors True" in out.stdout and "still works True True" in out.stdout
    assert "RE2 refused a regular expression" in out.stdout  # kept at debug level, for -v and the update log


def test_validation_counts_rules_whose_regex_re2_refuses() -> None:
    pytest.importorskip("re2", reason="pySigma 1.x uses Python's re, which supports lookarounds")
    testing._init_worker({}, "validate")
    _vid, _target, status, detail = testing._validate_one((1, "rule", LOOKAHEAD_RULE))
    assert status == "error" and testing.refused_regex(detail)
    _vid, _target, _status, plain = testing._validate_one((2, "rule", LOOKAHEAD_RULE.replace("(?:(?!/delete).)*$", ".*")))
    assert not testing.refused_regex(plain)
