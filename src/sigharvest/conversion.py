"""Rule -> query conversion: which pySigma pipelines to use for a (backend, log source), and how honest the result is.

One place for the selection logic, used by the convert stage (testing.py), exports (query.py), `sigharvest convert` and
the web UI. The choices mirror what sigma-cli recommends for each backend (docs/concepts.md "Validation and conversion").

Status of one (rule, target):
  ok                       converted with a pipeline that maps the rule's log source and field names to the target
  raw                      syntax only: no pipeline applies, the query uses Sigma's field names and has no log source
                           condition. Valid query text, but it will not find anything in a real SIEM as is
  partial                  a source lacks equivalent fields, prerequisites or complete category coverage
  warning                  converted with a pipeline, but a sanity check on the output failed (see `warnings`)
  unsupported              the target has no data for this log source (MDE tables only cover EDR events); not an error
  correlation_unsupported  a correlation the backend cannot convert, or whose referenced rules are not in its file
  error                    pySigma refused the rule (or produced no query)
  skipped                  the document does not parse, or is a filter (filters are applied to rules, not converted)
"""

from __future__ import annotations

import pickle
import pickletools
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import asdict, dataclass, field
from functools import cache, lru_cache
from typing import Any

# Every status a stored conversion result can have (see the module docstring). Release readers validate against
# this same set, so a status the writer stores can never make a release unreadable.
STATUSES = frozenset({"ok", "warning", "partial", "raw", "unsupported", "correlation_unsupported", "error", "timeout", "resource_failure", "skipped"})

ALL_BACKENDS = ["splunk", "lucene", "esql", "opensearch", "microsoft365defender", "loki", "sqlite"]
# pySigma backends are the optional `convert` extra (pip install "sigharvest[convert]"), so a base install never
# pins conflicting pySigma backend versions. Only installed backends are offered and tested.
BACKEND_MODULES = {
    "splunk": "sigma.backends.splunk",
    "lucene": "sigma.backends.elasticsearch",
    "esql": "sigma.backends.elasticsearch",
    "opensearch": "sigma.backends.opensearch",
    "microsoft365defender": "sigma.backends.kusto",
    "loki": "sigma.backends.loki",
    "sqlite": "sigma.backends.sqlite",
}
# Backends whose current PyPI release still requires pySigma < 2 (sigharvest needs pySigma 2): not in [convert].
NO_PYSIGMA2_RELEASE = {
    "lucene": "pysigma-backend-elasticsearch",
    "esql": "pysigma-backend-elasticsearch",
    "opensearch": "pysigma-backend-opensearch",
    "microsoft365defender": "pysigma-backend-kusto",
}
# Where install hints point. sigharvest is not on PyPI yet: every hint (CLI and web) installs from the repository.
# At launch, when the package is published, set this to "" and the hints become `uv tool install "sigharvest[...]"`.
INSTALL_SOURCE = "git+https://github.com/threat-hunter-eu/sigharvest"


def install_command(extra: str = "convert") -> str:
    """The one install command shown by the CLI and the web UI for an extra (convert or convert-legacy).

    `--reinstall` so the command also switches the extra of an existing tool install (uv keeps the old one otherwise)."""
    spec = f"sigharvest[{extra}]" + (f" @ {INSTALL_SOURCE}" if INSTALL_SOURCE else "")
    return f'uv tool install --reinstall "{spec}"'


def install_extra(target: str) -> str:
    """The extra that provides a backend: [convert-legacy] for the backends without a pySigma 2 release."""
    return "convert-legacy" if target in NO_PYSIGMA2_RELEASE else "convert"


INSTALL_HINT = f"install the conversion backends: {install_command()}"


def _installed(module: str) -> bool:
    from importlib.util import find_spec

    try:
        return find_spec(module) is not None
    except (ImportError, ValueError):
        return False


BACKENDS = [b for b in ALL_BACKENDS if _installed(BACKEND_MODULES[b])]


def backend_error(target: str) -> str | None:
    """Why `target` cannot be used, or None when it is an installed backend."""
    if target in BACKENDS:
        return None
    if target in ALL_BACKENDS:
        if target in NO_PYSIGMA2_RELEASE:
            return (
                f"backend {target} is not installed: {NO_PYSIGMA2_RELEASE[target]} has no pySigma 2 release yet; "
                f"for it, install the pySigma 1 set instead: {install_command('convert-legacy')}"
            )
        return f"backend {target} is not installed; {INSTALL_HINT}"
    return f"unknown backend {target}; choose one of {', '.join(ALL_BACKENDS)}"


ELASTIC = ("lucene", "esql", "opensearch")
# Statuses that mean "this target is applicable to the rule": the denominator of the conversion share in the score.
APPLICABLE = ("ok", "raw", "partial", "warning", "error", "timeout", "resource_failure")
# Bump when the selection or classification logic changes: stored results with another fingerprint are re-tested.
# (Not the same thing as identity.LOGIC_VERSION, which versions the logic hash.)
SELECTION_VERSION = 4  # source capabilities, audit/ECS corrections and per-source results
STATE_VERSION = 2  # owned graph restored from a snapshot with unused memo writes removed

WINDOWS_PS_CATEGORIES = {"ps_module", "ps_script", "ps_classic_start", "ps_classic_provider_start", "ps_classic_script"}
# Generic Windows categories the sysmon pipeline maps to a Sysmon event id (pysigma-pipeline-sysmon 2.x).
SYSMON_CATEGORIES = {
    "process_creation", "file_change", "network_connection", "sysmon_status", "process_termination", "driver_load",
    "image_load", "create_remote_thread", "raw_access_thread", "process_access", "file_event", "registry_add",
    "registry_delete", "registry_set", "registry_rename", "registry_event", "create_stream_hash", "pipe_created",
    "wmi_event", "dns_query", "file_delete", "clipboard_capture", "process_tampering", "file_delete_detected",
    "file_block_executable", "file_block_shredding", "file_executable_detected", "sysmon_error",
}  # fmt: skip
# Categories the microsoft_xdr pipeline maps to an MDE table (pysigma-backend-kusto 1.0.1, CATEGORY_TO_TABLE_MAPPINGS).
MDE_TABLES = {
    "process_creation": "DeviceProcessEvents",
    "image_load": "DeviceImageLoadEvents",
    "file_access": "DeviceFileEvents",
    "file_change": "DeviceFileEvents",
    "file_delete": "DeviceFileEvents",
    "file_event": "DeviceFileEvents",
    "file_rename": "DeviceFileEvents",
    "registry_add": "DeviceRegistryEvents",
    "registry_delete": "DeviceRegistryEvents",
    "registry_event": "DeviceRegistryEvents",
    "registry_set": "DeviceRegistryEvents",
    "network_connection": "DeviceNetworkEvents",
}
MDE_PRODUCTS = ("windows", "linux", "macos")
# Fields the microsoft_xdr pipeline deletes from the detection (DropDetectionItemTransformation) without an equivalent:
# the query then matches more than the rule says.
MDE_DROPPED_FIELDS: dict[str, set[str]] = {"*": {"EventID", "EventCode", "ObjectType"}, "network_connection": {"Initiated"}}

PACKAGES = {
    "splunk": ("pysigma-backend-splunk", "pysigma-pipeline-sysmon", "pysigma-pipeline-windows"),
    "lucene": ("pysigma-backend-elasticsearch", "pysigma-pipeline-sysmon", "pysigma-pipeline-windows"),
    "esql": ("pysigma-backend-elasticsearch", "pysigma-pipeline-sysmon", "pysigma-pipeline-windows"),
    "opensearch": ("pysigma-backend-opensearch", "pysigma-backend-elasticsearch", "pysigma-pipeline-sysmon", "pysigma-pipeline-windows"),
    "microsoft365defender": ("pysigma-backend-kusto",),
    "loki": ("pysigma-backend-loki", "pysigma-pipeline-sysmon", "pysigma-pipeline-windows"),
    "sqlite": ("pysigma-backend-sqlite", "pysigma-pipeline-sysmon", "pysigma-pipeline-windows"),
}
# Backends with correlation support in pySigma (`correlation_methods` on the backend class).
CORRELATION_BACKENDS = {"splunk", "esql", "loki", "sqlite"}
VARIANTS = (None, "windows-audit")


# ----------------------------------------------------------------------------- toolchain fingerprint


@cache
def toolchain(target: str) -> str:
    """Versions that determine a conversion result for `target`. Stored with every result; a change re-tests it.

    Only the code conversion executes is part of it (conversion_key.py)."""
    from sigharvest import conversion_key

    return conversion_key.toolchain(target)


# ----------------------------------------------------------------------------- pipeline selection


@dataclass(frozen=True)
class Plan:
    """How one target converts one log source.

    `markers`: processing item ids (prefixes) of which at least one must apply to the rule for the result to count as
    mapped (e.g. a Windows channel condition). Without markers a pipeline-backed plan is mapped by construction.
    """

    target: str
    pipelines: tuple[str, ...] = ()
    mapped: bool = False
    markers: tuple[str, ...] = ()
    unsupported: str | None = None
    notes: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return " + ".join(self.pipelines)


def _windows(target: str, category: str | None, variant: str | None, last: str) -> Plan:
    first = ["windows-audit"] if variant == "windows-audit" else ["sysmon"]
    pipes = [*first, *(["windows-logsources/ps"] if category in WINDOWS_PS_CATEGORIES else []), last]
    notes: tuple[str, ...] = ()
    if variant == "windows-audit" and last == "ecs_windows":
        pipes[-1] = "ecs_windows/security"
    if target == "esql":
        notes = (f"{last} does not list esql in allowed_backends (sigma-cli needs --disable-pipeline-check); ECS field names are the same",)
    return Plan(target, tuple(pipes), mapped=True, markers=("windows_logsource_",), notes=notes)


def plan(target: str, product: str | None, category: str | None, service: str | None, variant: str | None = None) -> Plan:
    """Pipelines for `target` and a rule log source (lower-case values)."""
    if target not in BACKENDS:
        raise ValueError(f"unknown backend {target}")
    if variant not in VARIANTS:
        raise ValueError(f"unknown variant {variant}")
    win = product == "windows"
    if target == "splunk":
        return _windows(target, category, variant, "splunk_windows") if win else Plan(target)
    if target in ELASTIC:
        if win:
            return _windows(target, category, variant, "ecs_windows")
        note = (f"pipeline does not list {target} in allowed_backends; ECS field names are the same",) if target == "esql" else ()
        if product == "zeek":
            return Plan(target, ("ecs_zeek_beats",), mapped=True, markers=("zeek_ecs_event_dataset",), notes=note)
        if product == "kubernetes" and service == "audit":
            note = (f"pipeline does not list {target} in allowed_backends; ECS field names are the same",) if target != "lucene" else ()
            return Plan(target, ("ecs_kubernetes",), mapped=True, markers=("index_condition",), notes=note)
        if product == "macos" and service == "endpointsecurity":
            return Plan(target, ("ecs_macos_esf",), mapped=True, markers=("ecs_macos_esf_field_mapping",), notes=note)
        return Plan(target)
    if target == "microsoft365defender":
        if product in MDE_PRODUCTS and category in MDE_TABLES:
            return Plan(target, ("microsoft_xdr",), mapped=True)
        what = "/".join(x for x in (product, category, service) if x) or "no log source"
        return Plan(target, unsupported=f"MDE advanced hunting has no table for {what} (microsoft_xdr maps EDR categories only)")
    if target == "loki":
        if win and (category in SYSMON_CATEGORIES or service == "sysmon"):
            return Plan(target, ("sysmon", "windows-logsources", "loki_promtail_sysmon"), mapped=True, markers=("loki_promtail_sysmon_parser",))
        if product == "okta" and service == "okta":
            return Plan(target, ("loki_okta_system_log",), mapped=True, markers=("loki_okta_event_json_formatter",))
        return Plan(target)
    # sqlite: Zircolite-style tables of flattened EVTX events, whose column names are the Sigma/Sysmon field names.
    if win:
        return Plan(target, ("windows-audit" if variant == "windows-audit" else "sysmon", "windows-logsources"), mapped=True, markers=("windows_logsource_",))
    return Plan(target)


def _pipeline(name: str) -> Any:
    if name == "sysmon":
        from sigma.pipelines.sysmon import sysmon_pipeline

        return sysmon_pipeline()
    if name in ("windows-logsources", "windows-logsources/ps", "windows-audit"):
        from sigma.pipelines.windows import windows_audit_pipeline, windows_logsource_pipeline
        from sigma.processing.transformations import AddConditionTransformation

        if name == "windows-audit":
            from sigharvest.datasources import OPERATIONS

            pipe = windows_audit_pipeline()
            for item in pipe.items:
                for category, operations in OPERATIONS.items():
                    if item.identifier == f"windows_{category}_condition" and isinstance(item.transformation, AddConditionTransformation):
                        item.transformation.conditions = {**item.transformation.conditions, "OperationType": list(operations)}
            return pipe
        pipe = windows_logsource_pipeline()
        if name == "windows-logsources/ps":
            # Only the ps_* category items: the Channel condition for services is added by the backend's own pipeline.
            pipe.items = [i for i in pipe.items if not (i.identifier or "").startswith("windows_logsource_")]
        return pipe
    if name == "splunk_windows":
        from sigma.pipelines.splunk import splunk_windows_pipeline

        return splunk_windows_pipeline()
    if name.startswith("ecs_"):
        from sigma.pipelines.elasticsearch import pipelines

        pipe = pipelines["ecs_windows" if name == "ecs_windows/security" else name]()
        if name == "ecs_windows/security":
            from sigma.processing.conditions import RuleProcessingItemAppliedCondition
            from sigma.processing.pipeline import ProcessingItem
            from sigma.processing.transformations import FieldMappingTransformation

            # Winlogbeat's security ingest script leaves 4657 ProcessName in event_data.
            pipe.items.insert(
                0,
                ProcessingItem(
                    identifier="sigharvest_security_registry_ecs",
                    transformation=FieldMappingTransformation({"ProcessName": "winlog.event_data.ProcessName"}),
                    rule_condition_linking=any,
                    rule_conditions=[RuleProcessingItemAppliedCondition(f"windows_{c}_logsource") for c in ("registry_add", "registry_set", "registry_event")],
                ),
            )
            for item in pipe.items:
                if item.identifier == "ecs_windows_field_mapping" and isinstance(item.transformation, FieldMappingTransformation):
                    item.transformation.mapping = {**item.transformation.mapping, "ParentProcessName": "process.parent.executable.caseless"}
        return pipe
    if name == "microsoft_xdr":
        from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
        from sigma.processing.conditions import LogsourceCondition
        from sigma.processing.pipeline import ProcessingItem
        from sigma.processing.transformations import AddConditionTransformation

        pipe = microsoft_xdr_pipeline()
        pipe.items.insert(
            0,
            ProcessingItem(
                identifier="sigharvest_mde_registry_set",
                transformation=AddConditionTransformation({"ActionType": "RegistryValueSet"}),
                rule_conditions=[LogsourceCondition(category="registry_set")],
            ),
        )
        return pipe
    if name.startswith("loki_"):
        from sigma.pipelines.loki import pipelines as loki_pipelines

        return loki_pipelines[name]()
    raise ValueError(f"unknown pipeline {name}")


def _backend_class(target: str) -> Any:
    if target == "splunk":
        from sigma.backends.splunk import SplunkBackend

        return SplunkBackend
    if target == "lucene":
        from sigma.backends.elasticsearch import LuceneBackend

        return LuceneBackend
    if target == "esql":
        from sigma.backends.elasticsearch import ESQLBackend

        return ESQLBackend
    if target == "opensearch":
        from sigma.backends.opensearch import OpensearchLuceneBackend

        return OpensearchLuceneBackend
    if target == "microsoft365defender":
        from sigma.backends.kusto import KustoBackend

        return KustoBackend
    if target == "loki":
        from sigma.backends.loki import LogQLBackend

        from sigharvest import pysigma_speedups

        pysigma_speedups.install()
        return LogQLBackend
    from sigma.backends.sqlite import sqliteBackend

    return sqliteBackend


@dataclass(frozen=True)
class _Entry:
    """Immutable, locally built pipeline snapshot; never retain a used backend.

    Pickle is only an in-memory clone format for installed pipeline factories.
    No rule, file, database or caller-supplied serialized bytes enter this cache.
    It preserves graph aliases without repeatedly rebuilding expensive pipelines.
    """

    backend_class: Any
    pipelines: bytes
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def backend(self) -> Any:
        """Construct invocation-owned state. The caller holds this entry's lock."""
        pipeline, builtin, formats = pickle.loads(self.pipelines)  # noqa: S301 - only our own pristine factory snapshot
        backend = self.backend_class(pipeline)
        # pySigma's defaults live on the class and pipeline addition mutates them.
        # Shadow both with owned graphs, including raw/no-pipeline conversions.
        backend.backend_processing_pipeline = builtin
        backend.output_format_processing_pipeline = formats
        return backend


_CACHE: dict[tuple[str, tuple[str, ...]], _Entry] = {}
_CACHE_LOCK = threading.Lock()


@cache
def _register_regex_engine_pickling() -> None:
    """pySigma 2's RE2RegexEngine keeps the `re2` module on the instance, which pickle refuses.

    The engine is stateless (instances compare equal by type), so a clone is a fresh engine. Pipelines whose
    conditions or transformations carry a regex engine (ecs_windows, microsoft_xdr) need this for the snapshot.
    """
    import copyreg

    try:
        from sigma.policy.regex_engine import RE2RegexEngine
    except ImportError:  # pySigma 1.x has no policy engines
        return
    copyreg.pickle(RE2RegexEngine, lambda _engine: (RE2RegexEngine, ()))


def _entry(target: str, pipelines: tuple[str, ...]) -> _Entry:
    """Cache only pristine configuration, keyed by target and source pipelines."""
    _register_regex_engine_pickling()
    key = (target, pipelines)
    with _CACHE_LOCK:
        entry = _CACHE.get(key)
        if entry is None:
            pipe = None
            for name in pipelines:
                p = _pipeline(name)
                pipe = p if pipe is None else pipe + p
            cls = _backend_class(target)
            snapshot = pickle.dumps((pipe, cls.backend_processing_pipeline, cls.output_format_processing_pipeline), protocol=pickle.HIGHEST_PROTOCOL)
            # Remove memo writes for objects never referenced again. This changes
            # only the clone program, retaining every object, alias and cycle.
            # Pay the analysis cost once, before publishing the pristine entry.
            entry = _CACHE[key] = _Entry(cls, pickletools.optimize(snapshot))
        return entry


# ----------------------------------------------------------------------------- conversion


@dataclass
class Conversion:
    target: str
    status: str
    queries: list[str] = field(default_factory=list)
    pipelines: list[str] = field(default_factory=list)
    reason: str | None = None
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    ms: float = 0.0
    source: str = "default"
    label: str = "Default"
    fields: list[str] = field(default_factory=list)
    missing_fields: list[str] = field(default_factory=list)
    results: list[Conversion] = field(default_factory=list)
    combined_query: str | None = None
    covered_sources: list[str] = field(default_factory=list)
    combined_sources: list[str] = field(default_factory=list)

    @property
    def pipeline(self) -> str:
        if len(self.results) > 1:
            return " · ".join(f"{r.label}: {r.pipeline or 'none'}" for r in self.results)
        return " + ".join(self.pipelines)

    @property
    def pipeline_line(self) -> str:
        """One line for people: what was used and what that means."""
        if len(self.results) > 1:
            return " · ".join(f"{r.label}: {r.status} ({r.pipeline_line})" for r in self.results)
        if self.status in ("unsupported", "correlation_unsupported", "skipped"):
            return f"not converted: {self.reason}"
        if not self.pipelines:
            return "no pipeline - field names are Sigma's, no log source condition (syntax only)"
        line = f"pipeline: {self.pipeline}"
        if self.status == "raw":
            line += f" - did not map this log source ({self.reason})" if self.reason else ""
        return line

    def detail(self) -> dict[str, Any]:
        d: dict[str, Any] = {"pipeline": self.pipeline, "pipelines": self.pipelines, "toolchain": toolchain(self.target)}
        if self.queries:
            d["queries"] = len(self.queries)
        for key in ("reason", "error"):
            if getattr(self, key):
                d[key] = getattr(self, key)
        if self.warnings:
            d["warnings"] = self.warnings
        if self.notes:
            d["notes"] = self.notes
        d["ms"] = self.ms
        d["results"] = [r.payload() for r in self.results]
        d["source_statuses"] = {r.source: r.status for r in self.results}
        d["covered_sources"] = self.covered_sources
        d["combined_sources"] = self.combined_sources
        d["combined_query"] = self.combined_query
        return d

    def payload(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if k != "results"}


def _err(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {str(exc).strip()[:400]}"


def parse(raw: str, resolve_references: bool = False) -> Any:
    from sigma.collection import SigmaCollection

    from sigharvest import pysigma_limits
    from sigharvest.documents import load_documents

    pysigma_limits.install()

    docs = load_documents(raw.encode("utf-8", "surrogatepass"))
    if error := next((d.error for d in docs if d.error), None):
        raise ValueError(error)
    with pysigma_limits.budget():
        return SigmaCollection.from_dicts([d.data for d in docs if isinstance(d.data, dict)], collect_errors=True, resolve_references=resolve_references)


# One document is converted for every installed backend and source, and each conversion parses it again (pipelines
# mutate the parsed rules, so a parsed collection is never shared). What does not depend on the backend is kept for
# the last few documents: whether the original text fails to parse (and why), and its detection-only rewrite. Both
# are pure functions of the text, so a cached value is exactly what recomputing it would return.
_TEXT_CACHE_SIZE = 8
_failed_parses: OrderedDict[str, tuple[bool, list[str]]] = OrderedDict()
_failed_parses_lock = threading.Lock()


def _parse_or_errors(raw: str) -> tuple[Any, list[str], bool]:
    """parse(raw) and its errors; (None, errors, raised) when it fails. A failure is remembered for the next target."""
    with _failed_parses_lock:
        hit = _failed_parses.get(raw)
        if hit is not None:
            _failed_parses.move_to_end(raw)
            return None, list(hit[1]), hit[0]
    try:
        coll = parse(raw)
        errors = parse_errors(coll)
        raised = False
    except Exception as exc:  # noqa: BLE001 - the caller reports it
        coll, errors, raised = None, [_err(exc)], True
    if errors:
        with _failed_parses_lock:
            _failed_parses[raw] = (raised, list(errors))
            while len(_failed_parses) > _TEXT_CACHE_SIZE:
                _failed_parses.popitem(last=False)
        return None, errors, raised
    return coll, errors, raised


@lru_cache(maxsize=_TEXT_CACHE_SIZE)
def _detection_only(raw: str) -> str:
    from sigharvest.detection import detection_only

    return detection_only(raw)


def parse_errors(coll: Any) -> list[str]:
    # pySigma lists a rule's errors on the rule and again on the collection: keep each message once.
    errors = list(dict.fromkeys([_err(e) for e in getattr(coll, "errors", [])] + [_err(e) for r in coll.rules for e in getattr(r, "errors", [])]))
    if not coll.rules and not errors:
        errors = ["SigmaCollectionError: no rule could be parsed from the document"]
    return errors


def _logsource(rule: Any) -> tuple[str | None, str | None, str | None]:
    ls = rule.logsource
    return tuple(str(x).lower() if x else None for x in (ls.product, ls.category, ls.service))  # type: ignore[return-value]


def _fields(detections: Any) -> set[str]:
    out: set[str] = set()

    def walk(item: Any) -> None:
        for sub in getattr(item, "detection_items", []) or []:
            walk(sub)
        name = getattr(item, "field", None)
        if isinstance(name, str):
            out.add(name)
        for value in getattr(item, "value", []) or []:
            reference = getattr(value, "field", None)
            if isinstance(reference, str):
                out.add(reference)

    for det in detections.detections.values():
        walk(det)
    return out


_KQL_STRING = re.compile(r'@?"(?:[^"\\]|\\.)*"|@?\'(?:[^\'\\]|\\.)*\'')


def kql_wildcard_literals(query: str) -> list[str]:
    """String literals in a KQL query that contain `*` outside a regex: KQL has no wildcards in string operators
    (startswith, endswith, contains, has, =~, in~, ==), so the asterisk is matched literally."""
    found = []
    for m in _KQL_STRING.finditer(query):
        before = query[: m.start()].rstrip().lower()
        if before.endswith("regex"):
            continue
        if "*" in m.group(0):
            found.append(m.group(0))
    return found


def check(target: str, queries: Sequence[str], category: str | None, original_fields: set[str]) -> list[str]:
    """Post-conversion sanity checks. Each finding is a reason to distrust the query."""
    out: list[str] = []
    if target != "microsoft365defender":
        return out
    for q in queries:
        lits = kql_wildcard_literals(q)
        if lits:
            out.append(f"KQL string with a literal '*' (KQL string operators have no wildcards): {', '.join(lits[:3])[:300]}")
        table = q.lstrip().split("\n", 1)[0].split("|", 1)[0].strip()
        expected = MDE_TABLES.get(category or "")
        if expected and table != expected:
            out.append(f"query table {table or '?'} does not match log source category {category} (expected {expected})")
    dropped = original_fields & (MDE_DROPPED_FIELDS["*"] | MDE_DROPPED_FIELDS.get(category or "", set()))
    if dropped:
        out.append(f"microsoft_xdr drops the condition on {', '.join(sorted(dropped))}: the query matches more than the rule")
    return out


def _applied(rules: Iterable[Any]) -> set[str]:
    out: set[str] = set()
    for r in rules:
        out |= set(getattr(r, "applied_processing_items", set()) or set())
    return out


def _referenced(corr: Any) -> list[Any]:
    """Rules (recursively through nested correlations) that a resolved correlation rule references."""
    from sigma.correlations import SigmaCorrelationRule

    out: list[Any] = []
    for ref in corr.rules:
        rule = getattr(ref, "rule", None)
        if rule is None:
            continue
        if isinstance(rule, SigmaCorrelationRule):
            out += [rule, *_referenced(rule)]
        else:
            out.append(rule)
    return out


def _run(target: str, p: Plan, coll: Any, sub_rules: list[Any], category: str | None, original_fields: set[str]) -> Conversion:
    conv = Conversion(target, "error", pipelines=list(p.pipelines), notes=list(p.notes))
    if target == "microsoft365defender":
        conv.missing_fields = sorted(original_fields & (MDE_DROPPED_FIELDS["*"] | MDE_DROPPED_FIELDS.get(category or "", set())))
        if category and category.startswith("registry_") and original_fields & {"TargetObject", "Details"}:
            conv.missing_fields = sorted(set(conv.missing_fields) | (original_fields & {"TargetObject", "Details"}))
            conv.notes.append("microsoft_xdr does not reconstruct the Sysmon key+value path or typed Details from MDE registry fields")
        if conv.missing_fields:
            conv.status = "partial"
            conv.reason = "microsoft_xdr drops or cannot preserve conditions on " + ", ".join(conv.missing_fields)
            conv.warnings = check(target, [], category, original_fields)
            return conv
    entry = _entry(target, p.pipelines)
    with entry.lock:
        result = entry.backend.convert(coll)
    conv.queries = [str(q) for q in (result if isinstance(result, list) else [result])] if result else []
    if target in ELASTIC and any(".caseless" in q for q in conv.queries):
        conv.notes.append("ECS .caseless multifields require the matching case-insensitive index mappings")
    if not conv.queries:
        conv.error = "no query produced"
        return conv
    if not p.mapped:
        conv.status = "raw"
        return conv
    if p.markers:
        applied = _applied(sub_rules)
        if not any(a.startswith(m) for a in applied for m in p.markers):
            conv.status, conv.reason = "raw", "the pipelines have no mapping for this log source"
            return conv
    conv.warnings = check(target, conv.queries, category, original_fields)
    conv.status = "warning" if conv.warnings else "ok"
    return conv


def source_context(raw: str, target: str, kind: str = "rule", siblings: Sequence[str] = ()) -> tuple[list[str], str | None, set[str]]:
    """Select from the parsed logsource; tolerate invalid metadata just like conversion."""
    from sigharvest.datasources import applicable

    try:
        if kind == "rule":
            coll, errors, raised = _parse_or_errors(raw)
            if raised:
                return ["default"], None, set()
            if errors:
                coll = parse(_detection_only(raw))
        else:
            coll = parse("\n---\n".join([raw, *siblings]))
        rules = [r for r in coll.rules if hasattr(r, "logsource")]
        if not rules:
            return ["default"], None, set()
        product, category, service = _logsource(rules[0])
        available = applicable(target, product, category, service)
        fields = set().union(*(_fields(r.detection) for r in rules))
        # A correlation needs the same source to provide every referenced event.
        for r in rules[1:]:
            available = [s for s in available if s in applicable(target, *_logsource(r))]
        return available or ["default"], category, fields
    except Exception:  # noqa: BLE001 - the converter returns the actual parse diagnostic
        return ["default"], None, set()


class SourceTimeout(BaseException):
    """Must escape backend exception handling so a slow source cannot consume its neighbours' budget."""


def _timed_single(raw: str, target: str, kind: str, siblings: Sequence[str], variant: str | None, timeout: float | None) -> Conversion:
    import signal

    if timeout is None:
        return _convert_single(raw, target, kind, siblings, variant)
    if not hasattr(signal, "setitimer") or threading.current_thread() is not threading.main_thread():
        from sigharvest.deadline import call_with_timeout

        return call_with_timeout(
            lambda: _convert_single(raw, target, kind, siblings, variant),
            timeout,
            lambda: Conversion(target, "timeout", reason=f"conversion took longer than {timeout:g} s"),
        )

    def alarm(_signum: int, _frame: Any) -> None:
        raise SourceTimeout

    previous = signal.signal(signal.SIGALRM, alarm)
    timer = signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        return _convert_single(raw, target, kind, siblings, variant)
    except SourceTimeout:
        return Conversion(target, "timeout", reason=f"conversion took longer than {timeout:g} s")
    finally:
        signal.setitimer(signal.ITIMER_REAL, *timer)
        signal.signal(signal.SIGALRM, previous)


def aggregate(target: str, results: list[Conversion], *, boolean: bool = True) -> Conversion:
    """Overall status credits one fully mapped source; other sources remain visible."""
    from sigharvest.datasources import BOOLEAN_BACKENDS

    priority = ("ok", "partial", "warning", "error", "timeout", "raw", "unsupported", "correlation_unsupported", "skipped")
    status = next((s for s in priority if any(r.status == s for r in results)), "unsupported")
    conv = Conversion(target, status, results=results)
    conv.covered_sources = [r.source for r in results if r.status == "ok"]
    for r in results:
        conv.pipelines += [p for p in r.pipelines if p not in conv.pipelines]
        conv.warnings += r.warnings
        conv.notes += r.notes if len(results) == 1 else [f"{r.label}: {n}" for n in r.notes]
    if len(results) == 1:
        r = results[0]
        conv.source, conv.label = r.source, r.label
        conv.fields, conv.missing_fields = r.fields, r.missing_fields
        conv.reason, conv.error = r.reason, r.error
        conv.queries = list(r.queries)
    else:
        conv.queries = [q for r in results if r.status == "ok" for q in r.queries]
        conv.reason = "; ".join(f"{r.label}: {r.reason or r.error or r.status}" for r in results if r.status != "ok") or None
    good = [r for r in results if r.status == "ok" and r.queries]
    # Never OR complete programs (SPL with pipes, correlations, SQL, KQL, ES|QL or LogQL).
    has_pipeline = target == "splunk" and any("|" in _KQL_STRING.sub("", q) for r in good for q in r.queries)
    if boolean and target in BOOLEAN_BACKENDS and good and not has_pipeline:
        qs = [q for r in good for q in r.queries]
        conv.combined_query = " OR ".join(f"({q})" for q in qs) if len(qs) > 1 else qs[0]
        conv.combined_sources = [r.source for r in good]
    return conv


def convert(
    raw: str,
    target: str,
    kind: str = "rule",
    siblings: Sequence[str] = (),
    variant: str | None = None,
    sources: Sequence[str] | None = None,
    timeout: float | None = None,
) -> Conversion:
    """Convert every applicable data source independently, retaining failures and coverage.

    `sources=None` selects all; `windows-audit` is the legacy alias for Security.
    Partial queries are diagnostic only and never included in the combined query.
    """
    from sigharvest.datasources import SECURITY_CATEGORIES, SOURCES, limitations, select_sources

    if target not in BACKENDS or variant not in VARIANTS:
        raise ValueError("unknown backend or variant")
    if variant:
        if sources is not None and list(sources) != ["security"]:
            raise ValueError("--variant windows-audit is an alias for --source security")
        sources = ["security"]
    start = time.perf_counter()
    available, category, fields = source_context(raw, target, kind, siblings)
    results = []
    for source in select_sources(available, sources):
        v = "windows-audit" if source == "security" and category in SECURITY_CATEGORIES else None
        missing, notes = limitations(source, category, fields, target)
        if source not in available:
            r = Conversion(target, "unsupported", reason=f"{source} is not applicable to this backend and log source")
        elif kind == "correlation" and source == "security" and category in ("process_creation", "registry_set", "registry_add", "registry_event"):
            r = Conversion(target, "unsupported", reason="generic Security correlations need per-reference field and group-by mapping")
        elif missing:
            r = Conversion(target, "partial", reason="; ".join(notes), missing_fields=missing)
            # Keep the planned pipelines visible without generating a query with nonexistent fields.
            r.pipelines = list(plan(target, "windows", category, None, v).pipelines)
        else:
            r = _timed_single(raw, target, kind, siblings, v, timeout)
            conditional = source == "security" and ("CommandLine" in fields or category in ("registry_add", "registry_event"))
            if r.status == "ok" and conditional:
                r.status, r.reason = "partial", "; ".join(notes)
        r.source, r.label = source, SOURCES[source].label
        if source == "security" and category in ("process_creation", "registry_set", "registry_add", "registry_event"):
            r.label += " 4688" if category == "process_creation" else " 4657"
        r.fields = sorted(fields)
        r.notes += notes
        results.append(r)
    conv = aggregate(target, results, boolean=kind == "rule")
    conv.ms = round((time.perf_counter() - start) * 1000, 1)
    return conv


ON_DEMAND_CACHE_SIZE = 4096
_on_demand: OrderedDict[tuple[Any, ...], Conversion] = OrderedDict()
_on_demand_lock = threading.Lock()


def convert_cached(
    raw: str,
    target: str,
    kind: str = "rule",
    siblings: Sequence[str] = (),
    variant: str | None = None,
    sources: Sequence[str] | None = None,
    timeout: float | None = None,
    runner: Callable[..., Conversion] | None = None,
) -> Conversion:
    """`convert` for on-demand callers (rule pages, `sigharvest convert`, backend exports): `update` no longer converts
    every rule, so the same rule is often converted again within one process. Results are kept in a bounded LRU
    keyed by the exact inputs and the backend toolchain; callers get a copy they may change."""
    import copy
    import hashlib

    def digest(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()

    key = (digest(raw), target, kind, tuple(digest(x) for x in siblings), variant, tuple(sources) if sources is not None else None, timeout, toolchain(target))
    with _on_demand_lock:
        hit = _on_demand.get(key)
        if hit is not None:
            _on_demand.move_to_end(key)
            return copy.deepcopy(hit)
    conv = (runner or convert)(raw, target, kind=kind, siblings=siblings, variant=variant, sources=sources, timeout=timeout)
    if conv.status not in ("timeout", "resource_failure") and not any(r.status == "timeout" for r in conv.results):
        with _on_demand_lock:
            _on_demand[key] = copy.deepcopy(conv)
            while len(_on_demand) > ON_DEMAND_CACHE_SIZE:
                _on_demand.popitem(last=False)
    return conv


def _convert_single(raw: str, target: str, kind: str = "rule", siblings: Sequence[str] = (), variant: str | None = None) -> Conversion:
    """Convert one Sigma document for one target. `siblings`: the other documents of the same file (correlations
    are converted together with the rules they reference, when those are in the same file)."""
    start = time.perf_counter()
    try:
        conv = _convert(raw, target, kind, siblings, variant)
    except Exception as exc:  # noqa: BLE001 - every pySigma failure is a result, not a crash
        conv = Conversion(target, "error", error=_err(exc))
        if target == "microsoft365defender":
            missing = re.findall(r"Invalid SigmaDetectionItem field name encountered: ([^\s.]+)", str(exc))
            if type(exc).__name__ == "InvalidHashAlgorithmError":
                missing.append("Hashes")
            if missing:
                conv.status = "partial"
                conv.missing_fields = sorted(set(missing))
                conv.reason = "microsoft_xdr has no equivalent mapping for " + ", ".join(conv.missing_fields)
                conv.pipelines = ["microsoft_xdr"]
    conv.ms = round((time.perf_counter() - start) * 1000, 1)
    return conv


def _convert(raw: str, target: str, kind: str, siblings: Sequence[str], variant: str | None) -> Conversion:
    coll, errors, _ = _parse_or_errors(raw)
    meta_note = None
    if (errors or coll is None) and kind == "rule":
        # Broken metadata (date format, id, tags, level) must not hide a valid detection: retry with title,
        # logsource and detection only, as `check` does.
        try:
            slim = _detection_only(raw)
            coll2 = parse(slim)
            if not parse_errors(coll2) and coll2.rules:
                raw, coll, errors = slim, coll2, []
                meta_note = "metadata is invalid (see validation); converted from title, logsource and detection only"
        except Exception:  # noqa: BLE001, S110 - keep the original parse error
            pass
    if errors or coll is None:
        return Conversion(target, "skipped", reason="parse error: " + "; ".join(errors[:3])[:600])
    if kind == "filter":
        return Conversion(target, "skipped", reason="filter documents are applied to other rules, not converted alone")
    if kind == "correlation":
        return _convert_correlation(raw, target, siblings, variant)
    rule = coll.rules[0]
    product, category, service = _logsource(rule)
    p = plan(target, product, category, service, variant)
    if p.unsupported:
        return Conversion(target, "unsupported", reason=p.unsupported)
    # Save fields before the pipeline mutates the freshly parsed collection (never shared between sources).
    original_fields = _fields(rule.detection)
    conv = _run(target, p, coll, list(coll.rules), category, original_fields)
    if meta_note:
        conv.notes.append(meta_note)
    return conv


def _convert_correlation(raw: str, target: str, siblings: Sequence[str], variant: str | None) -> Conversion:
    from sigma.collection import SigmaCollection
    from sigma.correlations import SigmaCorrelationRule
    from sigma.exceptions import SigmaRuleNotFoundError

    if target not in CORRELATION_BACKENDS:
        return Conversion(target, "correlation_unsupported", reason=f"the {target} backend cannot convert correlation rules")
    text = "\n---\n".join([raw, *siblings])
    try:
        full = parse(text, resolve_references=True)
    except SigmaRuleNotFoundError as exc:
        return Conversion(target, "correlation_unsupported", reason=f"referenced rules are not in the same file ({exc})"[:400])
    corr = next((r for r in full.rules if isinstance(r, SigmaCorrelationRule)), None)
    if corr is None:
        return Conversion(target, "error", error="no correlation rule found in the document")
    refs = _referenced(corr)
    base = [r for r in refs if not isinstance(r, SigmaCorrelationRule)]
    if not base:
        return Conversion(target, "correlation_unsupported", reason="referenced rules are not in the same file")
    product, category, service = _logsource(base[0])
    p = plan(target, product, category, service, variant)
    if p.unsupported:
        return Conversion(target, "unsupported", reason=p.unsupported)
    if any(plan(target, *_logsource(r), variant) != p for r in base[1:]):
        p = Plan(target, p.pipelines, p.mapped, p.markers, notes=(*p.notes, "referenced rules have different log sources"))
    sub = SigmaCollection([corr, *refs])
    fields: set[str] = set()
    for r in base:
        fields |= _fields(r.detection)
    try:
        return _run(target, p, sub, [*refs], category, fields)
    except NotImplementedError as exc:
        if "orrelation" not in str(exc):
            raise
        return Conversion(target, "correlation_unsupported", pipelines=list(p.pipelines), reason=_err(exc))


# ----------------------------------------------------------------------------- summaries for people

STATUS_LABELS = {
    "ok": "mapped",
    "warning": "check",
    "raw": "syntax-only",
    "partial": "partial",
    "unsupported": "not applicable",
    "correlation_unsupported": "not applicable",
    "error": "fails",
    "skipped": "not converted",
}


def summarise(statuses: dict[str, str], order: Sequence[str] = BACKENDS) -> list[tuple[str, list[str]]]:
    """Group targets by label, e.g. [("mapped", ["splunk", "lucene"]), ("syntax-only", ["loki"])]."""
    groups: dict[str, list[str]] = {}
    for t in order:
        if t in statuses:
            groups.setdefault(STATUS_LABELS.get(statuses[t], statuses[t]), []).append(t)
    rank = ["mapped", "check", "syntax-only", "fails", "not applicable", "not converted"]
    return sorted(groups.items(), key=lambda kv: rank.index(kv[0]) if kv[0] in rank else 99)


def statuses_of(g: Any) -> dict[str, str]:
    """Per-target statuses of a logic group (index), falling back to `converts` for indexes built before 0011."""
    conv = getattr(g, "conversion", None)
    if conv:
        return {t: v.get("status", "skipped") if isinstance(v, dict) else v for t, v in conv.items()}
    return {t: "ok" for t in (getattr(g, "converts", None) or [])}


def summary_text(statuses: dict[str, str]) -> str:
    """'mapped for splunk, lucene · syntax-only: loki, sqlite · not applicable: microsoft365defender'."""
    if not statuses:
        return "not converted yet"
    return " · ".join(f"{label} for {', '.join(ts)}" if label == "mapped" else f"{label}: {', '.join(ts)}" for label, ts in summarise(statuses))


STATUS_CLASSES = {
    "ok": "on",
    "warning": "warn",
    "partial": "warn",
    "raw": "raw",
    "error": "err",
    "unsupported": "na",
    "correlation_unsupported": "na",
}
