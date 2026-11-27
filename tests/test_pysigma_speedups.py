"""Speed-ups of pySigma backend code must produce exactly what upstream produces."""

import time
import warnings

import pytest

from sigharvest import conversion, conversion_key, pysigma_speedups


def keyword_rule(values: int, logsource: str = "{category: [endpoint, network]}", fields: int = 12) -> str:
    """A rule shaped like the large keyword rules of the curated preset: one OR over many fields' value lists (and a
    list-valued category, a metadata error those rules share)."""
    lines = ["title: Keywords", "id: 00000000-0000-4000-8000-00000000abcd", f"logsource: {logsource}", "detection:", "  selection:"]
    for f in range(fields):
        lines.append(f"  - Field{f:02d}:")
        lines += [f"    - '*tool-{f:02d}-{i:05d}\\payload*'" for i in range(values)]
    lines += ["  filter:", "    User: SYSTEM", "  condition: selection and not filter"]
    return "\n".join(lines) + "\n"


def stable(conv: conversion.Conversion) -> dict:  # type: ignore[type-arg]
    """detail() without timings."""
    detail = conv.detail()
    detail.pop("ms")
    detail["results"] = [{k: v for k, v in r.items() if k != "ms"} for r in detail["results"]]
    return detail


def convert_loki(raw: str, fast: bool) -> conversion.Conversion:
    from sigma.backends.loki.loki import LogQLBackend

    pysigma_speedups.install()
    patched = LogQLBackend.partition_rule
    upstream = patched._sigharvest_upstream
    LogQLBackend.partition_rule = patched if fast else upstream
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return conversion.convert(raw, "loki")
    finally:
        LogQLBackend.partition_rule = patched


@pytest.mark.backend("loki")
@pytest.mark.parametrize(
    ("values", "fields", "logsource"),
    # Windows case: service, not a category, so the synthetic FieldNN names are not rejected by the Sysmon field table.
    [(12, 100, "{category: [endpoint, network]}"), (10, 80, "{product: windows, service: sysmon}"), (3, 2, "{product: linux}")],
)
def test_loki_partitions_are_identical_to_upstream(values: int, fields: int, logsource: str) -> None:
    raw = keyword_rule(values, logsource=logsource, fields=fields)
    upstream = convert_loki(raw, fast=False)
    fast = convert_loki(raw, fast=True)
    assert fast.queries == upstream.queries
    assert stable(fast) == stable(upstream)
    if fields > 2:
        assert sum(len(r.queries) for r in fast.results) > 5  # the rule really was partitioned


@pytest.mark.backend("loki")
def test_loki_partition_cost_is_linear() -> None:
    raw = keyword_rule(25, fields=400)  # 330 KB, 119 partitions: upstream takes about 110 s, the copy-per-slice 4 s
    start = time.perf_counter()
    conv = convert_loki(raw, fast=True)
    assert len(conv.queries) > 100
    assert time.perf_counter() - start < 45


@pytest.mark.backend("loki")
def test_loki_falls_back_to_upstream_when_a_skipped_argument_is_shared() -> None:
    from sigma.conditions import ConditionOR

    class Leaf:
        def __init__(self, n: int) -> None:
            self.n = n

    leaves = [Leaf(i) for i in range(6)]
    tree = ConditionOR([*leaves])
    tree.extra = leaves[5]  # reachable from outside the OR's list: the fast copy cannot be used
    assert pysigma_speedups.partitions(tree, 3) is None
    del tree.extra
    parts = pysigma_speedups.partitions(tree, 3)
    assert parts is not None and [[leaf.n for leaf in p.args] for p in parts] == [[0, 1], [2, 3], [4, 5]]
    assert all(leaf is not original for p in parts for leaf, original in zip(p.args, leaves, strict=False))


@pytest.mark.backend("loki")
def test_unknown_upstream_source_is_not_replaced(monkeypatch: pytest.MonkeyPatch) -> None:
    from sigma.backends.loki.loki import LogQLBackend

    pysigma_speedups.install()
    upstream = LogQLBackend.partition_rule._sigharvest_upstream
    monkeypatch.setattr(LogQLBackend, "partition_rule", upstream)
    monkeypatch.setattr(pysigma_speedups, "_installed", False)
    monkeypatch.setattr(pysigma_speedups, "LOKI_PARTITION_SOURCES", frozenset({"another release"}))
    assert pysigma_speedups.install() is False
    assert LogQLBackend.partition_rule is upstream


def test_speedups_are_part_of_the_conversion_key() -> None:
    assert "pysigma_speedups.py" in conversion_key.CONVERT_MODULES


def test_failed_parse_is_remembered_with_identical_results() -> None:
    raw = keyword_rule(5)
    target = conversion.BACKENDS[0] if conversion.BACKENDS else pytest.skip("no backend installed")
    conversion._failed_parses.clear()
    conversion._detection_only.cache_clear()
    first = conversion.convert(raw, target)
    assert raw in conversion._failed_parses  # the list-valued category is a metadata error
    second = conversion.convert(raw, target)
    assert stable(first) == stable(second)
    assert first.status != "skipped" and any("metadata is invalid" in n for n in first.notes)
    conversion._failed_parses.clear()
    assert conversion.convert("title: [unclosed", target).status == "skipped"
    assert conversion.convert("title: [unclosed", target).reason == conversion.convert("title: [unclosed", target).reason
