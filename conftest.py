"""Apply the same offline guards to every test, and plain (uncoloured, unboxed) CLI output everywhere."""

import os

# Typer forces a Rich terminal when GITHUB_ACTIONS / FORCE_COLOR is set, which colours and boxes error messages; the
# CLI tests compare plain text. Must be set before typer is imported.
os.environ["_TYPER_FORCE_DISABLE_TERMINAL"] = "1"

pytest_plugins = ["tests.offline"]


def pytest_collection_modifyitems(config, items):  # type: ignore[no-untyped-def]
    """Skip tests of conversion targets whose backend is not installed.

    `[convert]` (pySigma 2) has no Elastic, OpenSearch or MDE backend; `[convert-legacy]` (pySigma 1) has all of them.
    A test needs a target when it is marked `@pytest.mark.backend("lucene", ...)` or when its parameter id names it
    (`test_plan[esql-...]`).
    """
    import re

    import pytest

    from sigharvest.conversion import ALL_BACKENDS, BACKENDS

    missing = set(ALL_BACKENDS) - set(BACKENDS)
    for item in items:
        needed: set[str] = set()
        for mark in item.iter_markers("backend"):
            unknown = set(mark.args) - set(ALL_BACKENDS)
            if unknown:
                raise pytest.UsageError(f"{item.nodeid}: unknown backend marker {sorted(unknown)}")
            needed |= set(mark.args)
        callspec = getattr(item, "callspec", None)
        if callspec:
            needed |= set(re.split(r"[-\[\]]", callspec.id)) & set(ALL_BACKENDS)
        gone = needed & missing
        if gone:
            item.add_marker(pytest.mark.skip(reason=f"backend not installed: {', '.join(sorted(gone))}"))
