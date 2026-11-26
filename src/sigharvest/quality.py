"""Quality flags: documents that are not useful Sigma rules, found by content (computed by `index.rebuild`).

Junk flags (hidden from search, export and check by default; `--include-junk` shows them, nothing is deleted):
- foreign_query: a SIEM query wrapped in YAML (splunk_spl, chronicle_yaral...) instead of a Sigma detection;
- synthetic: numbered generated series ("... Scale Variant 2915 Marker");
- test_fixture: every copy lives under test/, tests/, fixtures/, testdata/, examples/, templates/, golden/, or the
  title says it is a test or template;
- autogen_template: source-local generated sets sharing a one-value detection skeleton;
- baseline_query: numbered experimental baseline queries without alert severity;
- autogen_stub: "auto-generated stub" placeholders;
- template_title: unrendered templates in the title ($(field), {{var}}, <placeholder>);
- match_all: every value is a bare wildcard, so the rule matches every event of its log source;
- placeholder_logsource: the log source is only a placeholder (`category: generic` / `test`, or an unfilled
  template), as in simulator markers and translation stubs: nothing routes it, it matches every event;
- negation_only, short_keyword_wildcard, generic_field_wildcard, test_like_low_level: reviewable precision
  heuristics (quality_precision.py);
- upstream_deprecated: SigmaHQ deprecated this rule id (or moved it to deprecated/), but this copy does not say so.
- weak_high_severity: a high/critical rule whose condition is satisfied by weak values alone (quality_strength.py).

Informational flags (not hidden): weak_detection and weak_branch (quality_strength.py; they lower the score),
ioc_list (mostly hashes / IPs / domains), converted (machine-converted from
another rule format), broad_logsource (only a product, no category or service), unused_selection
(unreferenced named detection), unused_filter (its filter-like sub-case; quality_unused.py).
Windows source review flags: nonstandard_logsource (reviewed service alias),
ambiguous_logsource (service needs author review), incompatible_logsource (non-EVTX category).
Quote artifacts (unopened path/filename quotes) are reported by quality_quotes.py.
"""

from __future__ import annotations

import re
from typing import Any

from sigharvest.quality_precision import PRECISION_FLAGS, precision_flags
from sigharvest.quality_quotes import from_raw as quotes_from_raw
from sigharvest.quality_quotes import quote_artifacts
from sigharvest.quality_strength import strength_flags
from sigharvest.quality_unused import from_raw, unused_selections

JUNK = (
    frozenset(
        {
            "foreign_query",
            "synthetic",
            "test_fixture",
            "autogen_stub",
            "template_title",
            "match_all",
            "upstream_deprecated",
            "autogen_template",
            "baseline_query",
            "weak_high_severity",
            "placeholder_logsource",
        }
    )
    | PRECISION_FLAGS
)

_FOREIGN_KEYS = {"splunk_spl", "chronicle_yaral", "_splunk_search", "_yaral_rule", "spl", "kql_query", "yaral", "eql_query"}
_SYNTHETIC = re.compile(r"\b(?:scale\s+)?variant\s+\d{2,}\b|\bmarker\s+\d{2,}\b|\bvariant\s+\d+\s+marker\b", re.I)
_TEST_TITLE = re.compile(r"^\s*(?:\[test\]|test\s*[-:]|template\b|example\b|sample rule\b|my detection rule\b|rule\s+\d+\s*$|todo\b)", re.I)
_PLACEHOLDER = re.compile(r"<[a-z_ .|-]{3,40}>", re.I)
_AUTOGEN = re.compile(r"auto-?generated\s+(?:stub|rule|placeholder)|\(auto-?generated\)|^\s*\[auto\]", re.I)
FIXTURE_PATH = re.compile(r"(?:^|/)(?:tests?|fixtures?|testdata|test_data|examples?|templates?|golden|samples?/negative|negative)(?:/|$)", re.I)
_HASH = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.I)
_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
_DOMAIN = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.I)


def _values(x: Any, out: list[str]) -> None:
    if isinstance(x, dict):
        for k, v in x.items():
            if k not in ("condition", "timeframe"):
                _values(v, out)
    elif isinstance(x, list):
        for v in x:
            _values(v, out)
    elif x is not None:
        out.append(str(x))


def _keys(x: Any, out: set[str]) -> None:
    if isinstance(x, dict):
        for k, v in x.items():
            out.add(str(k).split("|", 1)[0].lower())
            _keys(v, out)
    elif isinstance(x, list):
        for v in x:
            _keys(v, out)


def classify(data: dict[str, Any], paths: list[str], upstream_deprecated: bool = False, *, raw: str | None = None) -> list[str]:
    """Flags for one rule document (`data` = parsed YAML) found at `paths` (all its copies)."""
    from sigharvest.quality_templates import baseline_query

    flags: set[str] = set(precision_flags(data)) | set(strength_flags(data))
    if baseline_query(str(data.get("title") or ""), data.get("level"), data.get("status")):
        flags.update(("autogen_template", "baseline_query"))
    quotes = quote_artifacts(data)
    if quotes and raw is not None:
        quotes = quotes_from_raw(raw)
    if quotes:
        flags.add("quote_artifact")
    unused = unused_selections(data)
    if unused and raw is not None:
        # Index metadata uses BaseLoader; validate candidate conditions against original scalar types.
        unused = from_raw(raw)
    if unused:
        flags.add("unused_selection")
        if unused["filters"]:
            flags.add("unused_filter")
    title = str(data.get("title") or "")
    text = f"{title}\n{data.get('description') or ''}\n{data.get('author') or ''}"
    detection = data.get("detection")
    keys: set[str] = set()
    _keys(detection, keys)
    if keys & _FOREIGN_KEYS or set(map(str.lower, data)) & _FOREIGN_KEYS:
        flags.add("foreign_query")
    raw_ls = data.get("logsource")
    ls: dict[str, Any] = raw_ls if isinstance(raw_ls, dict) else {}
    if _SYNTHETIC.search(title) or str(ls.get("category") or "").lower() == "attack_scale_variant":
        flags.add("synthetic")
    if (paths and all(FIXTURE_PATH.search(p) for p in paths)) or _TEST_TITLE.search(title):
        flags.add("test_fixture")
    if _AUTOGEN.search(text):
        flags.add("autogen_stub")
    if _template_title(title):
        flags.add("template_title")
    vals: list[str] = []
    _values(detection, vals)
    if vals and all(v.strip() in ("*", "**", "*.*") for v in vals):
        flags.add("match_all")
    if len(vals) >= 50:
        ioc = sum(1 for v in vals if _HASH.match(v) or _IP.match(v) or _DOMAIN.match(v.strip("*.")))
        if ioc >= 0.8 * len(vals):
            flags.add("ioc_list")
    if any(k.startswith("sagan") for k in keys):
        flags.add("converted")
    if ls.get("product") and not ls.get("category") and not ls.get("service"):
        flags.add("broad_logsource")
    if placeholder_logsource(raw_ls):
        flags.add("placeholder_logsource")
    from sigharvest.logsource_inference import infer_windows_route, inference_note

    product, category, service = (str(ls.get(key) or "") for key in ("product", "category", "service"))
    from sigharvest.detection import NON_WINDOWS_CATEGORIES, WINDOWS_PRODUCTS
    from sigharvest.logsource_catalog import WINDOWS_AMBIGUOUS_SERVICES, WINDOWS_SERVICE_ALIASES

    if product.lower() in WINDOWS_PRODUCTS:
        if service.lower() in WINDOWS_SERVICE_ALIASES:
            flags.add("nonstandard_logsource")
        if service.lower() in WINDOWS_AMBIGUOUS_SERVICES:
            flags.add("ambiguous_logsource")
        if category.lower() in NON_WINDOWS_CATEGORIES:
            flags.add("incompatible_logsource")
    route = infer_windows_route(product, category, service, detection, raw=raw)
    note = inference_note(route)
    if note:
        flags.add(note)
    if upstream_deprecated:
        flags.add("upstream_deprecated")
    return sorted(flags)


def placeholder_logsource(logsource: Any) -> bool:
    """True when the log source only says "no log source": no product or service, and the category is a placeholder.

    Placeholder categories are the ones normalisation drops (generic, test, any, unknown...; normalize.py), or every
    Sigma key present with an empty value (an unfilled template). Simulator markers, translation stubs and test
    fixtures use these; no backend can route them, so the rule would match every event. A log source written in
    another schema (vendor:, provider:, event_type:) is not a placeholder: validation reports it."""
    from sigharvest.normalize import category

    if not isinstance(logsource, dict) or not logsource:
        return False
    ls = {str(k).lower(): v for k, v in logsource.items()}
    if any(str(ls.get(k) or "").strip() for k in ("product", "service", "definition")):
        return False
    raw_category = str(ls.get("category") or "").strip()
    if raw_category:
        return category(raw_category) is None
    return set(ls) <= {"product", "category", "service", "definition"}


def _template_title(title: str) -> bool:
    """True for a ``$(...)``, ``{{...}}`` or ``<placeholder>`` in the title, in linear time.

    Same matches as the earlier regex alternatives ``$(`` ``[^)]*`` ``)`` and ``{{`` ``[^}]*`` ``}}``, which
    rescanned to the end of the title from every unclosed opener: quadratic, so a hostile title of a few
    hundred KB cost minutes of CPU.
    """
    start = title.find("$(")
    if start >= 0 and ")" in title[start + 2 :]:
        return True
    pos = 0
    while (start := title.find("{{", pos)) >= 0:
        # Every "{{" before the next "}" shares that "}": the match needs it to begin "}}".
        close = title.find("}", start + 2)
        if close < 0:
            break
        if title.startswith("}}", close):
            return True
        pos = close + 1
    return bool(_PLACEHOLDER.search(title))


def is_junk(flags: list[str] | None) -> bool:
    """True when any of the flags hides the document by default (see JUNK)."""
    return bool(flags) and not JUNK.isdisjoint(flags or [])
