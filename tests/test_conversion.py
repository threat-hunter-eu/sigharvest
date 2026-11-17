"""Pipeline selection, honest conversion statuses, score aggregation, export counts and the web Query panel."""

import json
from pathlib import Path

import pytest
from sqlalchemy import select

from sigharvest import conversion, testing_conversion
from sigharvest.conversion import convert, kql_wildcard_literals, plan, summary_text
from sigharvest.index import rebuild, score
from sigharvest.models import LogicGroup, RuleVersion, TestResult
from sigharvest.query import export_backend
from sigharvest.service import open_db, sync_all
from sigharvest.testing import _done, _store, native_backend
from sigharvest.testing_conversion import _convert_one
from sigharvest.web.app import create_app
from tests.test_pipeline import commit, git, workspace
from tests.web_helpers import BrowserClient as TestClient

DNS = r"""title: DNS query to anonfiles
id: 6a3a1a40-0000-4000-8000-000000000001
logsource: {product: windows, category: dns_query}
detection:
  sel:
    QueryName|contains: '.anonfiles.com'
  condition: sel
"""
SAFEBOOT = r"""title: SafeBoot registry change
id: 6a3a1a40-0000-4000-8000-000000000002
logsource: {product: windows, category: registry_set}
detection:
  sel:
    TargetObject|contains: '\Control\SafeBoot\Minimal\'
  condition: sel
"""
LINUX_NET = r"""title: Linux connection to onion
id: 6a3a1a40-0000-4000-8000-000000000003
logsource: {product: linux, category: network_connection}
detection:
  sel:
    Initiated: 'true'
    DestinationHostname|endswith: '.onion'
  condition: sel
"""
SECURITY = r"""title: File access audit
id: 6a3a1a40-0000-4000-8000-000000000004
logsource: {product: windows, service: security}
detection:
  sel:
    EventID: 4663
    ObjectType: File
  condition: sel
"""
IMAGE_LOAD = r"""title: DLL load
id: 6a3a1a40-0000-4000-8000-000000000005
logsource: {product: windows, category: image_load}
detection:
  sel:
    ImageLoaded|endswith: '\evil.dll'
  condition: sel
"""
PS_SCRIPT = r"""title: Mimikatz script block
id: 6a3a1a40-0000-4000-8000-000000000006
logsource: {product: windows, category: ps_script}
detection:
  sel:
    ScriptBlockText|contains: 'Invoke-Mimikatz'
  condition: sel
"""
FILE_ACCESS = r"""title: File access without a Sysmon event
id: 6a3a1a40-0000-4000-8000-000000000007
logsource: {product: windows, category: file_access}
detection:
  sel:
    FileName|endswith: '\secret.txt'
  condition: sel
"""
CORRELATION = r"""title: Many failed logons
id: 6a3a1a40-0000-4000-8000-000000000008
correlation:
  type: event_count
  rules:
    - failed_logon
  group-by:
    - TargetUserName
  timespan: 5m
  condition:
    gte: 10
"""
BASE = r"""title: Failed logon
id: 6a3a1a40-0000-4000-8000-000000000009
name: failed_logon
logsource: {product: windows, service: security}
detection:
  sel:
    EventID: 4625
  condition: sel
"""


# ----------------------------------------------------------------------------- pipeline selection


@pytest.mark.parametrize(
    ("target", "logsource", "pipelines", "mapped"),
    [
        ("splunk", ("windows", "dns_query", None), ("sysmon", "splunk_windows"), True),
        ("splunk", ("windows", "ps_script", None), ("sysmon", "windows-logsources/ps", "splunk_windows"), True),
        ("splunk", ("linux", "process_creation", None), (), False),
        ("lucene", ("windows", "image_load", None), ("sysmon", "ecs_windows"), True),
        ("esql", ("windows", "process_creation", None), ("sysmon", "ecs_windows"), True),
        ("opensearch", ("zeek", None, "dns"), ("ecs_zeek_beats",), True),
        ("lucene", ("kubernetes", None, "audit"), ("ecs_kubernetes",), True),
        ("lucene", ("macos", "process_creation", "endpointsecurity"), ("ecs_macos_esf",), True),
        ("lucene", ("macos", "process_creation", None), (), False),
        ("microsoft365defender", ("windows", "registry_set", None), ("microsoft_xdr",), True),
        ("microsoft365defender", ("linux", "process_creation", None), ("microsoft_xdr",), True),
        ("loki", ("windows", "process_creation", None), ("sysmon", "windows-logsources", "loki_promtail_sysmon"), True),
        ("loki", ("okta", None, "okta"), ("loki_okta_system_log",), True),
        ("loki", ("linux", None, "auditd"), (), False),
        ("sqlite", ("windows", None, "security"), ("sysmon", "windows-logsources"), True),
        ("sqlite", ("aws", None, "cloudtrail"), (), False),
    ],
)
def test_plan(target: str, logsource: tuple[str | None, str | None, str | None], pipelines: tuple[str, ...], mapped: bool) -> None:
    p = plan(target, *logsource)
    assert p.pipelines == pipelines and p.mapped is mapped and p.unsupported is None


@pytest.mark.backend("esql", "microsoft365defender")
def test_plan_unsupported_and_variants() -> None:
    for ls in (("windows", "dns_query", None), ("windows", None, "security"), ("aws", None, "cloudtrail"), ("windows", "ps_script", None)):
        assert plan("microsoft365defender", *ls).unsupported
    assert plan("splunk", "windows", "process_creation", None, variant="windows-audit").pipelines == ("windows-audit", "splunk_windows")
    assert plan("esql", "windows", "process_creation", None).notes  # ecs_windows does not declare esql
    with pytest.raises(ValueError):
        plan("nope", None, None, None)
    assert native_backend("windows", "process_creation", None) == "microsoft365defender"
    assert native_backend("windows", "dns_query", None) == "splunk"


# ----------------------------------------------------------------------------- statuses


@pytest.mark.backend("esql", "lucene")
def test_windows_category_gets_its_log_source() -> None:
    c = convert(DNS, "splunk")
    assert c.status == "ok" and c.pipelines == ["sysmon", "splunk_windows"]
    assert 'source="WinEventLog:Microsoft-Windows-Sysmon/Operational"' in c.queries[0] and "EventCode=22" in c.queries[0]
    lucene = convert(IMAGE_LOAD, "lucene")
    assert lucene.status == "ok" and "event.code:7" in lucene.queries[0] and "winlog.channel" in lucene.queries[0]
    ps = convert(PS_SCRIPT, "splunk")
    assert ps.status == "ok" and "PowerShell/Operational" in ps.queries[0] and "EventCode=4104" in ps.queries[0]
    assert ps.queries[0].count("Channel") == 0  # the ps_* items only, no duplicate Channel condition
    esql = convert(DNS, "esql")
    assert esql.status == "ok" and 'event.code=="22"' in esql.queries[0] and esql.notes


def test_raw_when_no_pipeline_maps_the_log_source() -> None:
    c = convert(LINUX_NET, "splunk")
    assert c.status == "raw" and c.pipelines == [] and "no pipeline" in c.pipeline_line and c.queries
    fa = convert(FILE_ACCESS, "splunk")  # windows, but no Sysmon event and no channel: no log source condition
    assert fa.status == "raw" and fa.pipelines and "did not map" in fa.pipeline_line
    assert convert(PS_SCRIPT, "loki").status == "raw"
    assert convert(SECURITY, "sqlite").status == "ok"


@pytest.mark.backend("microsoft365defender")
def test_mde_wildcard_check_on_a_real_conversion() -> None:
    c = convert(SAFEBOOT.replace("TargetObject", "RegistryKey"), "microsoft365defender")
    assert c.queries and c.queries[0].startswith("DeviceRegistryEvents")
    assert c.status == "warning" and "literal '*'" in c.warnings[0]
    assert kql_wildcard_literals(c.queries[0])


@pytest.mark.backend("microsoft365defender")
def test_mde_unsupported_and_dropped_fields() -> None:
    dns = convert(DNS, "microsoft365defender")
    assert dns.status == "unsupported" and not dns.queries and "not converted" in dns.pipeline_line
    assert convert(SECURITY, "microsoft365defender").status == "unsupported"  # no more Security 4663 -> DeviceRegistryEvents
    net = convert(LINUX_NET, "microsoft365defender")
    assert net.status == "partial" and any("Initiated" in w for w in net.warnings)


def test_kql_literal_check() -> None:
    assert kql_wildcard_literals('T | where A endswith "x*" and B matches regex ".*y"') == ['"x*"']
    assert kql_wildcard_literals('T | where A =~ "a\\"*"') == ['"a\\"*"']
    assert kql_wildcard_literals('T | where A contains "abc"') == []
    assert conversion.check("microsoft365defender", ["DeviceFileEvents\n| where X"], "registry_set", set())  # table mismatch


@pytest.mark.backend("lucene")
def test_correlation_with_rules_in_the_same_file() -> None:
    c = convert(CORRELATION, "splunk", kind="correlation", siblings=[BASE])
    assert c.status == "ok" and "stats count" in c.queries[0] and 'source="WinEventLog:Security"' in c.queries[0]
    assert convert(CORRELATION, "lucene", kind="correlation", siblings=[BASE]).status == "correlation_unsupported"
    alone = convert(CORRELATION, "splunk", kind="correlation")
    assert alone.status == "correlation_unsupported" and "same file" in (alone.reason or "")


def test_parse_errors_and_detail_fingerprint() -> None:
    bad = convert("title: x\nlogsource: {product: windows}\ndetection:\n  condition: nope\n", "splunk")
    assert bad.status == "skipped"
    d = convert(DNS, "splunk").detail()
    assert d["toolchain"] == conversion.toolchain("splunk") and "pysigma/" in d["toolchain"] and "sigharvest-conversion/" in d["toolchain"]
    assert d["pipeline"] == "sysmon + splunk_windows" and d["queries"] == 1


@pytest.mark.backend("esql", "lucene", "microsoft365defender")
def test_summary_text() -> None:
    st = {"splunk": "ok", "lucene": "ok", "microsoft365defender": "unsupported", "loki": "raw", "sqlite": "raw", "esql": "warning"}
    assert summary_text(st) == "mapped for splunk, lucene · check: esql · syntax-only: loki, sqlite · not applicable: microsoft365defender"


# ----------------------------------------------------------------------------- corpus: stage, index, export, web


def make_repo(tmp: Path) -> Path:
    repo = tmp / "upstream"
    (repo / "rules").mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    for name, raw in (("dns", DNS), ("safeboot", SAFEBOOT), ("linux", LINUX_NET)):
        (repo / "rules" / f"{name}.yml").write_text(raw)
    (repo / "rules" / "corr.yml").write_text(CORRELATION + "---\n" + BASE)
    commit(repo, "init")
    return repo


@pytest.fixture
def corpus(tmp_path: Path):  # type: ignore[no-untyped-def]
    ws = workspace(tmp_path, make_repo(tmp_path))
    assert sync_all(ws)[0].status == "ok"
    S = open_db(ws, migrate=True)
    with S() as s:
        versions = list(s.scalars(select(RuleVersion)))
        rows = []
        sib = {}
        from sigharvest.testing import siblings

        sib = siblings(s, [v.id for v in versions if v.kind == "correlation"])
        for v in versions:
            rows += _convert_one((v.id, v.kind, v.raw, sib.get(v.id, [])))
        from sigharvest.models import TestRun

        run = TestRun(stage="convert", params={})
        s.add(run)
        s.commit()
        _store(s, run.id, "convert", rows)
        s.commit()
        rebuild(s)
    return ws, S


def _title(s, title: str) -> RuleVersion:  # type: ignore[no-untyped-def]
    return s.scalars(select(RuleVersion).where(RuleVersion.title == title)).one()


def test_stage_resume_uses_the_fingerprint(corpus) -> None:  # type: ignore[no-untyped-def]
    _ws, S = corpus
    with S() as s:
        assert len(_done(s, "convert")) == 5
        r = s.scalars(select(TestResult).where(TestResult.stage == "convert")).first()
        assert r is not None
        r.detail = {**r.detail, "toolchain": "pysigma/0.0.1"}
        s.commit()
        assert len(_done(s, "convert")) == 4  # that version is converted again by --resume


@pytest.mark.backend("esql", "lucene", "microsoft365defender", "opensearch")
def test_index_counts_only_mapped_and_scores_on_applicable(corpus) -> None:  # type: ignore[no-untyped-def]
    _ws, S = corpus
    with S() as s:
        dns = _title(s, "DNS query to anonfiles")
        g = s.scalars(select(LogicGroup).where(LogicGroup.logic_hash == dns.logic_hash)).one()
        assert g.conversion is not None
        assert g.conversion["microsoft365defender"]["status"] == "unsupported" and g.conversion["splunk"]["status"] == "ok"
        assert set(g.converts) == {"splunk", "lucene", "esql", "opensearch", "loki", "sqlite"}  # 6 of 6 applicable
        linux = _title(s, "Linux connection to onion")
        gl = s.scalars(select(LogicGroup).where(LogicGroup.logic_hash == linux.logic_hash)).one()
        assert gl.converts == [] and gl.conversion is not None and gl.conversion["splunk"]["status"] == "raw"
        assert gl.conversion["microsoft365defender"]["status"] == "partial"
        # the share uses applicable targets: unsupported does not lower the score, raw does
        assert score(dns, "ok", 6, 6, 1, None) == score(dns, "ok", 7, 7, 1, None)
        assert score(dns, "ok", 0, 7, 1, None) == score(dns, "ok", 6, 6, 1, None) - 25.0


@pytest.mark.backend("microsoft365defender")
def test_export_counts_and_sidecar(corpus, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    _ws, S = corpus
    with S() as s:
        versions = list(s.scalars(select(RuleVersion).order_by(RuleVersion.id)))
        out = tmp_path / "q" / "mde.kql"
        rep = export_backend(versions, "microsoft365defender", out, s=s)
        assert rep.counts["partial"] == 2 and rep.counts["unsupported"] == 2 and rep.counts["correlation_unsupported"] == 1
        assert rep.counts["correlation"] == 1 and rep.written == 0
        assert rep.summary() == (
            f"{len(versions)} selected -> 0 written for microsoft365defender; {len(versions)} not written: "
            "2 need fields the chosen log source does not have (partial), "
            "2 log source not supported by the target, 1 correlations the target cannot convert, or whose rules are not selected"
        )
        side = [json.loads(line) for line in rep.sidecar.read_text().splitlines()]
        assert {x["status"] for x in side} == {"partial", "unsupported", "correlation_unsupported"} and all("written" in x for x in side)
        assert "DeviceRegistryEvents" not in out.read_text()
        rep = export_backend(versions, "microsoft365defender", out, s=s, allow_warnings=True)
        assert rep.written == 0  # --allow-warnings never exports a partial conversion
        native = RuleVersion(
            id=-1,
            kind="rule",
            title="Native registry key",
            raw=SAFEBOOT.replace("TargetObject", "RegistryKey"),
            rule_id="native",
            logic_hash="native-registry-key",
        )
        rep = export_backend([native], "microsoft365defender", out, allow_warnings=True)
        assert rep.written == 1 and "# WARNING:" in out.read_text()

        out = tmp_path / "q" / "splunk.spl"
        rep = export_backend(versions, "splunk", out, s=s)
        assert rep.counts["ok"] == 4 and rep.counts["raw"] == 1 and rep.written == 4  # the correlation is converted with its base rule
        assert "stats count" in out.read_text() and "onion" not in out.read_text()
        rep = export_backend(versions, "splunk", out, s=s, allow_raw=True)
        assert rep.written == 5 and "no pipeline" in out.read_text()


@pytest.mark.backend("esql", "lucene", "microsoft365defender", "opensearch")
def test_web_query_panel(corpus) -> None:  # type: ignore[no-untyped-def]
    ws, S = corpus
    c = TestClient(create_app(ws, S, allowed_hosts=["testserver"]))
    with S() as s:
        linux = _title(s, "Linux connection to onion")
        dns = _title(s, "DNS query to anonfiles")
    raw = c.get(f"/api/convert/{linux.logic_hash}", params={"target": "splunk"}).json()
    assert raw["ok"] and raw["status"] == "raw" and raw["pipeline_line"].startswith("no pipeline - field names are Sigma's")
    warn = c.get(f"/api/convert/{linux.logic_hash}", params={"target": "microsoft365defender"}).json()
    assert warn["status"] == "partial" and warn["warnings"] and warn["pipeline_line"] == "pipeline: microsoft_xdr"
    na = c.get(f"/api/convert/{dns.logic_hash}", params={"target": "microsoft365defender"}).json()
    assert not na["ok"] and na["status"] == "unsupported" and na["reason"]
    ok = c.get(f"/api/convert/{dns.logic_hash}", params={"target": "splunk", "variant": "windows-audit"}).json()
    assert ok["status"] == "unsupported" and not ok["queries"]
    assert c.get(f"/api/convert/{dns.logic_hash}", params={"target": "splunk", "variant": "x"}).status_code == 400
    page = c.get(f"/rule/{linux.logic_hash[:16]}").text
    assert "syntax-only: splunk, lucene, esql, opensearch, loki, sqlite" in page and "partial: microsoft365defender" in page
    assert 'aria-label="splunk: syntax-only"' in page and 'class="warn"' in page
    page = c.get(f"/rule/{dns.logic_hash[:16]}").text
    assert "mapped for splunk, lucene, esql, opensearch, loki, sqlite · not applicable: microsoft365defender" in page
    assert 'class="na"' in page and 'id="conv-warnings"' in page
    assert "ATT&amp;CK metadata: +0/4 points" in page
    assert "not evidence that the rule detects a technique" in page
    search = c.get("/", params={"q": "onion"}).text
    assert 'class="raw"' in search


def test_broken_metadata_does_not_block_validation_or_conversion() -> None:
    from sigharvest import testing
    from sigharvest.conversion import convert

    raw = (
        "title: Whoami\nid: not-a-uuid\ndate: 2023/07/30\ntags: [sysmon]\nlevel: info\n"
        "logsource: {product: windows, category: process_creation}\n"
        "detection:\n  sel:\n    Image|endswith: '\\\\whoami.exe'\n  condition: sel\n"
    )
    testing._init_worker({}, "validate")
    _vid, _target, status, detail = testing._validate_one((1, "rule", raw))
    assert status == "warning" and detail["metadata"] and not detail["parse"]
    # regression: pySigma reports each error on the rule and on the collection; each is stored once
    assert len(detail["metadata"]) == len(set(detail["metadata"])) == 3, detail["metadata"]
    conv = convert(raw, "splunk", kind="rule")
    assert conv.status == "ok" and any("metadata is invalid" in n for n in conv.notes)


def test_slow_backend_conversion_times_out(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import time

    from sigharvest import testing

    def slow(raw, name, kind="rule", siblings=(), variant=None):  # type: ignore[no-untyped-def]
        time.sleep(5)

    monkeypatch.setattr(testing_conversion, "CONVERT_TIMEOUT", 0.2)
    monkeypatch.setattr(testing.conversion, "_convert_single", slow)
    status, detail = testing_conversion._convert_with_timeout("title: x", "loki", "rule", [])
    assert status == "timeout" and "toolchain" in detail


@pytest.mark.parametrize(
    "token,points",
    [
        ("attack.t1685", 4),
        ("attack.t1089", 4),
        ("attack.t9999", 0),
        ("attack.t1043", 0),
        ("attack.t1685junk", 0),
        ("attack.t1685.001", 4),
        ("attack.mobile.t1685", 0),
    ],
)
def test_score_attack_catalog_changes_only_four_metadata_points(token, points):
    from sigharvest.attack_score import Context
    from tests.test_attack_normalisation import matrix

    context = Context(matrix())
    v = RuleVersion(tags=[], status="stable", level="high", author="Fixture", date="2020-01-01")
    baseline = score(v, "ok", 2, 3, 2, "Description", attack_context=context)
    v.tags = [token]
    assert score(v, "ok", 2, 3, 2, "Description", attack_context=context) == baseline + points
    assert v.tags == [token]


def test_score_attack_chain_cycle_missing_and_deprecated_successors():
    from sigharvest.attack_score import Context, credit, explanation
    from tests.test_attack_normalisation import matrix

    data = matrix()
    assert credit(["attack.t1089"], Context(data)) == 4
    for successor in ("T1089", "T9999", "T1043"):
        data.replaced["T1685"] = successor
        assert credit(["attack.t1089"], Context(data)) == 0
    context = Context()
    assert credit(["attack.t9999"], context) == 4
    message = explanation(["attack.t9999"], context, context.fingerprint)
    assert "+4/4" in message and "Unverified" in message and "not evidence" in message
    assert "unavailable" in explanation(["attack.t9999"], context, None)


@pytest.mark.skipif("splunk" not in conversion.BACKENDS, reason="needs the splunk backend")
def test_on_demand_conversion_is_cached_and_returns_copies(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    conversion._on_demand.clear()
    calls = []
    real = conversion.convert
    monkeypatch.setattr(conversion, "convert", lambda *a, **k: calls.append(1) or real(*a, **k))
    first = conversion.convert_cached(DNS, "splunk")
    first.queries.append("changed by the caller")
    second = conversion.convert_cached(DNS, "splunk")
    assert len(calls) == 1
    assert second.status == "ok" and "changed by the caller" not in second.queries
    conversion.convert_cached(DNS, "splunk", sources=["sysmon"])
    assert len(calls) == 2


def test_web_conversion_names_the_extra_for_a_missing_backend(corpus) -> None:  # type: ignore[no-untyped-def]
    """Lazy conversion of a backend the installed extra lacks is a clear 400, not a crash or 'unknown backend'."""
    from sigharvest.conversion import ALL_BACKENDS, backend_error

    missing = [b for b in ALL_BACKENDS if b not in conversion.BACKENDS]
    if not missing:
        pytest.skip("every backend is installed")
    ws, S = corpus
    c = TestClient(create_app(ws, S, allowed_hosts=["testserver"]))
    with S() as s:
        dns = _title(s, "DNS query to anonfiles")
    r = c.get(f"/api/convert/{dns.logic_hash}", params={"target": missing[0]})
    assert r.status_code == 400 and r.json()["detail"] == backend_error(missing[0])
    assert "not installed" in r.json()["detail"]
