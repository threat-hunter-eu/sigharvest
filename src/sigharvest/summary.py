"""Plain-language summary of a Sigma rule, built without AI from its parsed detection (rule pages).

`summarise(raw)` returns one sentence as a list of parts ("text", "b", "code", "field") so templates render it
with autoescaping only: "Alerts on **process creation** events where CommandLine contains `sekurlsa::` or
`lsadump::`, unless Image ends with `\\procdump.exe`." It is deterministic: the same YAML gives the same parts.
When the detection is too complex to say in one sentence (more than MAX_SELECTIONS positive selections, a nested
condition, correlation rules, aggregations), the rule's own description is used and labelled as such.

`needs(product, category, service)` is the telemetry prerequisite ("You need: ...") from a small static table.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

MAX_SELECTIONS = 4
MAX_VALUES = 6
MAX_FIELDS = 4
MAX_FILTERS = 3
MAX_VALUE_CHARS = 80
# Bounds on the condition parser so a crafted third-party rule cannot make it spend memory or CPU before the
# MAX_SELECTIONS check: tokens in the condition, and selection references in the whole tree (an `N of x*` atom
# counts each name it matches). Real rules stay far below both.
MAX_TOKENS = 256
MAX_REFS = 256

Part = tuple[str, str]  # (kind, text): kind is text, b (bold), code (a value) or field (a field name)


@dataclass
class Summary:
    kind: str  # "plain": built from the detection; "author": the rule's own description; "none": nothing to say
    parts: list[Part] = field(default_factory=list)
    reason: str = ""  # why the plain sentence was not built (kind "author" or "none")


# ----------------------------------------------------------------------------- log sources

# What the events are, as a phrase after "Alerts on": keyed by category or service (product-specific first).
EVENTS = {
    ("windows", "process_creation"): "process creation",
    ("linux", "process_creation"): "Linux process creation",
    ("macos", "process_creation"): "macOS process creation",
    ("windows", "ps_script"): "PowerShell script block",
    ("windows", "ps_module"): "PowerShell module",
    ("windows", "ps_classic_start"): "PowerShell engine start",
    ("windows", "ps_classic_provider_start"): "PowerShell provider start",
    ("windows", "security"): "Windows Security log",
    ("windows", "system"): "Windows System log",
    ("windows", "application"): "Windows Application log",
    ("windows", "sysmon"): "Sysmon",
    ("linux", "auditd"): "auditd",
    ("aws", "cloudtrail"): "AWS CloudTrail",
    ("azure", "signinlogs"): "Azure sign-in",
    ("azure", "activitylogs"): "Azure activity",
    ("azure", "auditlogs"): "Azure audit",
    ("gcp", "gcp.audit"): "Google Cloud audit",
    ("okta", "okta"): "Okta system log",
}
CATEGORY_EVENTS = {
    "process_creation": "process creation",
    "file_event": "file creation",
    "file_delete": "file deletion",
    "file_rename": "file rename",
    "file_access": "file access",
    "file_change": "file change",
    "registry_set": "registry value set",
    "registry_add": "registry key creation",
    "registry_delete": "registry deletion",
    "registry_event": "registry",
    "network_connection": "network connection",
    "image_load": "image (DLL) load",
    "process_access": "process access",
    "dns_query": "DNS query",
    "pipe_created": "named pipe",
    "create_remote_thread": "remote thread creation",
    "create_stream_hash": "alternate data stream",
    "driver_load": "driver load",
    "raw_access_thread": "raw disk access",
    "wmi_event": "WMI event",
    "process_tampering": "process tampering",
    "clipboard_capture": "clipboard capture",
    "sysmon_status": "Sysmon status",
    "webserver": "web server access",
    "proxy": "web proxy",
    "firewall": "firewall",
    "dns": "DNS server",
    "antivirus": "antivirus alert",
    "application": "application log",
}

_SYSMON = "Sysmon event {} (or your EDR's equivalent)"
# (product, category or service) -> what has to be logged before the rule can fire.
NEEDS = {
    ("windows", "process_creation"): "Sysmon event 1, or Security event 4688 with command line logging turned on",
    ("windows", "ps_script"): "PowerShell Script Block Logging (event 4104)",
    ("windows", "ps_module"): "PowerShell Module Logging (event 4103)",
    ("windows", "ps_classic_start"): "the Windows PowerShell classic log (event 400)",
    ("windows", "ps_classic_provider_start"): "the Windows PowerShell classic log (event 600)",
    ("windows", "security"): "the Windows Security log, with the audit policy for the event ids this rule uses",
    ("windows", "system"): "the Windows System log",
    ("windows", "application"): "the Windows Application log",
    ("windows", "sysmon"): "Sysmon installed, with a configuration that logs the event ids this rule uses",
    ("windows", "file_event"): _SYSMON.format(11),
    ("windows", "file_delete"): _SYSMON.format("23 or 26"),
    ("windows", "registry_set"): _SYSMON.format(13),
    ("windows", "registry_add"): _SYSMON.format(12),
    ("windows", "registry_delete"): _SYSMON.format(12),
    ("windows", "registry_event"): _SYSMON.format("12 to 14"),
    ("windows", "network_connection"): _SYSMON.format(3),
    ("windows", "image_load"): _SYSMON.format(7),
    ("windows", "process_access"): _SYSMON.format(10),
    ("windows", "dns_query"): _SYSMON.format(22),
    ("windows", "pipe_created"): _SYSMON.format("17 and 18"),
    ("windows", "create_remote_thread"): _SYSMON.format(8),
    ("windows", "driver_load"): _SYSMON.format(6),
    ("windows", "create_stream_hash"): _SYSMON.format(15),
    ("windows", "raw_access_thread"): _SYSMON.format(9),
    ("windows", "wmi_event"): _SYSMON.format("19 to 21"),
    ("windows", "process_tampering"): _SYSMON.format(25),
    ("linux", "auditd"): "auditd (or Sysmon for Linux) with rules for the syscalls and files this rule uses",
    ("linux", "process_creation"): "auditd execve logging, or Sysmon for Linux event 1",
    ("linux", "file_event"): "auditd file watches, or Sysmon for Linux event 11",
    ("linux", "network_connection"): "Sysmon for Linux event 3 (or your EDR's equivalent)",
    ("macos", "process_creation"): "macOS Endpoint Security process events (through your EDR)",
    ("aws", "cloudtrail"): "AWS CloudTrail logs, ingested into your SIEM",
    ("azure", "signinlogs"): "Microsoft Entra ID (Azure AD) sign-in logs, ingested into your SIEM",
    ("azure", "activitylogs"): "Azure Activity logs, ingested into your SIEM",
    ("azure", "auditlogs"): "Microsoft Entra ID (Azure AD) audit logs, ingested into your SIEM",
    ("m365", "*"): "the Microsoft 365 unified audit log, ingested into your SIEM",
    ("okta", "*"): "the Okta System Log, ingested into your SIEM",
    ("gcp", "gcp.audit"): "Google Cloud audit logs, ingested into your SIEM",
    ("github", "*"): "the GitHub audit log, ingested into your SIEM",
    ("*", "webserver"): "web server access logs",
    ("*", "proxy"): "web proxy access logs",
    ("*", "firewall"): "firewall logs",
    ("*", "dns"): "DNS server query logs",
    ("*", "antivirus"): "your antivirus alerts, forwarded to your SIEM",
}


def _norm(x: Any) -> str:
    return str(x or "").strip().lower()


def needs(product: str | None, category: str | None, service: str | None) -> tuple[str, bool]:
    """(text, known): the telemetry a rule needs. Unknown log sources get "Logs that match logsource: ..."."""
    p, c, s = _norm(product), _norm(category), _norm(service)
    for key in ((p, c), (p, s), ("*", c), ("*", s), (p, "*")):
        if all(key) and key in NEEDS:
            return NEEDS[key], True
    route = " / ".join(x for x in (p, c, s) if x) or "none"
    return f"Logs that match logsource: {route}", False


def events(product: str | None, category: str | None, service: str | None) -> str:
    """'process creation', 'PowerShell script block', or the log source itself ('okta / okta')."""
    p, c, s = _norm(product), _norm(category), _norm(service)
    for key in ((p, c), (p, s)):
        if key in EVENTS:
            return EVENTS[key]
    if c in CATEGORY_EVENTS:
        return CATEGORY_EVENTS[c]
    if s in CATEGORY_EVENTS:
        return CATEGORY_EVENTS[s]
    return " / ".join(x for x in (p, c, s) if x) or "any"


# ----------------------------------------------------------------------------- the condition

_TOKEN = re.compile(r"\s*(\(|\)|\b(?:and|or|not)\b|\d+\s+of\b|all\s+of\b|[A-Za-z0-9_*.\-]+)", re.I)


class _TooComplex(Exception):
    pass


def _tokens(text: str) -> list[str]:
    out: list[str] = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise _TooComplex("condition syntax")
        if len(out) >= MAX_TOKENS:
            raise _TooComplex("condition too long")
        out.append(" ".join(m.group(1).lower().split()) if re.fullmatch(r"(and|or|not|\d+\s+of|all\s+of)", m.group(1).strip(), re.I) else m.group(1))
        pos = m.end()
    return out


class _Parser:
    """and/or/not with parentheses and `1 of x*` / `all of them`; yields a small tree of tuples."""

    def __init__(self, tokens: list[str], names: list[str]) -> None:
        self.t = tokens
        self.i = 0
        self.names = names
        self.refs = 0

    def ref(self) -> None:
        self.refs += 1
        if self.refs > MAX_REFS:
            raise _TooComplex("condition too long")

    def peek(self) -> str | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise _TooComplex("condition ends early")
        self.i += 1
        return tok

    def parse(self) -> Any:
        node = self.or_()
        if self.peek() is not None:
            raise _TooComplex("condition syntax")
        return node

    def or_(self) -> Any:
        items = [self.and_()]
        while self.peek() == "or":
            self.take()
            items.append(self.and_())
        return items[0] if len(items) == 1 else ("or", items)

    def and_(self) -> Any:
        items = [self.not_()]
        while self.peek() == "and":
            self.take()
            items.append(self.not_())
        return items[0] if len(items) == 1 else ("and", items)

    def not_(self) -> Any:
        if self.peek() == "not":
            self.take()
            return ("not", self.not_())
        return self.atom()

    def atom(self) -> Any:
        tok = self.take()
        if tok == "(":
            node = self.or_()
            if self.take() != ")":
                raise _TooComplex("unbalanced parentheses")
            return node
        if tok.endswith(" of"):
            pattern = self.take()
            matched: list[str] = []
            for n in self.names:
                if pattern == "them" or fnmatch.fnmatchcase(n, pattern):
                    self.ref()
                    matched.append(n)
            if not matched:
                raise _TooComplex("pattern matches nothing")
            if len(matched) == 1:
                return ("sel", matched[0])
            return ("and" if tok == "all of" else "or", [("sel", n) for n in matched])
        if tok in self.names:
            self.ref()
            return ("sel", tok)
        raise _TooComplex(f"unknown selection {tok}")


def _flatten(node: Any, op: str) -> list[Any]:
    if isinstance(node, tuple) and node[0] == op:
        return [x for item in node[1] for x in _flatten(item, op)]
    return [node]


def _selections(node: Any) -> list[str] | None:
    """The selection names of a plain selection or a flat or/and of plain selections, else None."""
    if node[0] == "sel":
        return [node[1]]
    if node[0] in ("or", "and") and all(x[0] == "sel" for x in node[1]):
        return [x[1] for x in node[1]]
    return None


# ----------------------------------------------------------------------------- selections

VERBS = {
    "contains": "contains",
    "startswith": "starts with",
    "endswith": "ends with",
    "re": "matches the regex",
    "cidr": "is in the network",
    "base64": "contains the base64 of",
    "base64offset": "contains the base64 of",
    "gt": "is greater than",
    "gte": "is at least",
    "lt": "is less than",
    "lte": "is at most",
    "exists": "exists",
    "fieldref": "equals the field",
}


def _value(v: Any) -> str:
    text = "null" if v is None else str(v).lower() if isinstance(v, bool) else str(v)
    return text if len(text) <= MAX_VALUE_CHARS else text[: MAX_VALUE_CHARS - 1] + "…"


def _values(values: list[Any], joiner: str) -> list[Part]:
    shown = values[:MAX_VALUES]
    parts: list[Part] = []
    for i, v in enumerate(shown):
        if i:
            parts.append(("text", f" {joiner} " if i == len(shown) - 1 and len(values) <= MAX_VALUES else ", "))
        parts.append(("code", _value(v)))
    if len(values) > MAX_VALUES:
        parts.append(("text", f" (or {len(values) - MAX_VALUES} more)" if joiner == "or" else f" (and {len(values) - MAX_VALUES} more)"))
    return parts


def _field_item(key: str, value: Any) -> list[Part]:
    name, *mods = str(key).split("|")
    mods = [m.lower() for m in mods]
    all_values = "all" in mods
    verb_mods = [m for m in mods if m in VERBS]
    verb = VERBS[verb_mods[0]] if verb_mods else "is"
    if "windash" in mods and not verb_mods:
        verb = "is"
    values = value if isinstance(value, list) else [value]
    if any(isinstance(v, (dict, list)) for v in values):
        raise _TooComplex("nested values")
    parts: list[Part] = []
    if not name:  # keywords with modifiers: `|all: [...]`
        verb = "contains"
        parts.append(("text", "the log line "))
    else:
        parts.append(("field", name))
        parts.append(("text", " "))
    if values == [None] or (not verb_mods and values == [""]):
        parts.append(("text", "is empty"))
        return parts
    if "exists" in mods:
        return [*parts, ("text", "exists" if values and values[0] not in (False, "false") else "is missing")]
    parts.append(("text", verb + " "))
    joiner = "and" if all_values else "or"
    parts.extend(_values(values, joiner))
    return parts


def _selection(name: str, body: Any) -> list[Part]:
    if isinstance(body, dict):
        items = list(body.items())
        if not items:
            raise _TooComplex("empty selection")
        if len(items) > MAX_FIELDS:
            raise _TooComplex("too many fields")
        out: list[Part] = []
        for i, (k, v) in enumerate(items):
            if i:
                out.append(("text", " and "))
            out.extend(_field_item(str(k), v))
        return out
    if isinstance(body, list) and body and all(isinstance(x, dict) for x in body):
        if len(body) > 3:
            raise _TooComplex("too many alternatives")
        out = []
        for i, item in enumerate(body):
            if i:
                out.append(("text", ", or "))
            out.extend(_selection(name, item))
        return out
    if isinstance(body, (list, str, int)) and not isinstance(body, bool):
        values = body if isinstance(body, list) else [body]
        if any(isinstance(v, (dict, list)) for v in values):
            raise _TooComplex("nested keywords")
        return [("text", "the log line contains "), *_values(values, "or")]
    raise _TooComplex("unsupported selection")


# ----------------------------------------------------------------------------- the sentence

_WORDS = {2: "two", 3: "three", 4: "four"}


def _count(n: int) -> str:
    return _WORDS.get(n, str(n))


def _author(data: dict[str, Any], reason: str) -> Summary:
    desc = str(data.get("description") or "").strip()
    if not desc:
        return Summary("none", [], reason)
    return Summary("author", [("text", " ".join(desc.split()))], reason)


def summarise(raw: str, data: dict[str, Any] | None = None) -> Summary:
    """The plain-language summary of one rule (see the module docstring)."""
    if data is None:
        from sigharvest.ruleview import _load

        data = _load(raw, max_nodes=20_000) if len(raw) <= 200_000 else None
    if not isinstance(data, dict):
        return Summary("none", [], "the rule could not be read")
    if "correlation" in data:
        return _author(data, "correlation rule")
    det = data.get("detection")
    if not isinstance(det, dict):
        return _author(data, "no detection section")
    cond = det.get("condition")
    if isinstance(cond, list):
        if len(cond) != 1:
            return _author(data, "several conditions")
        cond = cond[0]
    if not isinstance(cond, str) or "|" in cond:
        return _author(data, "aggregation in the condition")
    names = [str(k) for k in det if k not in ("condition", "timeframe")]
    try:
        tree = _Parser(_tokens(cond), names).parse()
        top = _flatten(tree, "and") if tree[0] == "and" else [tree]
        positive = [x for x in top if x[0] != "not"]
        negative = [x[1] for x in top if x[0] == "not"]
        if not positive:
            raise _TooComplex("only exclusions")
        if len(positive) == 1:
            pos_names = _selections(positive[0])
            mode = positive[0][0] if positive[0][0] != "sel" else "one"
        else:
            if not all(x[0] == "sel" for x in positive):
                raise _TooComplex("nested condition")
            pos_names, mode = [x[1] for x in positive], "and"
        if pos_names is None or len(pos_names) > MAX_SELECTIONS:
            raise _TooComplex(f"more than {MAX_SELECTIONS} selections")
        neg_names: list[str] = []
        for n in negative:
            sel = _selections(n)
            if sel is None or (n[0] == "and" and len(sel) > 1):
                raise _TooComplex("nested exclusion")
            neg_names += sel
        ls = data.get("logsource") if isinstance(data.get("logsource"), dict) else {}
        what = events(ls.get("product"), ls.get("category"), ls.get("service"))  # type: ignore[union-attr]
        parts: list[Part] = [("text", "Alerts on "), ("b", what), ("text", " events where ")]
        if len(pos_names) == 1:
            parts += _selection(pos_names[0], det[pos_names[0]])
        else:
            joiner = "; or " if mode == "or" else "; and "
            for i, name in enumerate(pos_names):
                if i:
                    parts.append(("text", joiner))
                parts += _selection(name, det[name])
        if neg_names:
            parts.append(("text", ", unless "))
            if len(neg_names) > MAX_FILTERS:
                parts.append(("text", f"one of {len(neg_names)} exclusion filters matches"))
            else:
                for i, name in enumerate(neg_names):
                    if i:
                        parts.append(("text", "; or "))
                    parts += _selection(name, det[name])
        parts.append(("text", "."))
        if len(pos_names) > 1:
            parts.append(("text", f" Any one of the {_count(len(pos_names))} is enough." if mode == "or" else " All of them must match."))
    except _TooComplex as exc:
        return _author(data, str(exc))
    except (KeyError, TypeError, ValueError, RecursionError) as exc:
        return _author(data, type(exc).__name__)
    return Summary("plain", _merge(parts))


def _merge(parts: list[Part]) -> list[Part]:
    """Join neighbouring text parts and drop empty ones (smaller HTML, same words)."""
    out: list[Part] = []
    for kind, text in parts:
        if not text:
            continue
        if out and kind == "text" and out[-1][0] == "text":
            out[-1] = ("text", out[-1][1] + text)
        else:
            out.append((kind, text))
    return out
