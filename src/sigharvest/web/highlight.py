"""A small, dependency-free YAML highlighter for rule pages (server-side, so it also works without JavaScript and
prints). It is line based and only *labels* text: every piece of the input is escaped with markupsafe before it
is wrapped in a <span>, and the text content of the result is exactly the input (copying the block copies the rule).

It knows the Sigma conventions worth seeing at a glance: field|modifier keys, the condition expression and the
top-level sections.
"""

from __future__ import annotations

import re

from markupsafe import Markup, escape

MAX_BYTES = 300_000  # larger documents (IOC lists) are shown plain
_KEY = re.compile(r"""^(?P<indent>\s*)(?P<dash>-\s+)?(?P<key>"[^"]*"|'[^']*'|[^\s#'"\-][^:#]*?|-[^\s:#][^:#]*?)(?P<colon>:)(?=\s|$)(?P<rest>.*)$""")
_DASH = re.compile(r"^(?P<indent>\s*)(?P<dash>-)(?P<rest>(\s.*)?)$")
_LITERAL = re.compile(r"^(true|false|null|yes|no|~|-?\d+(\.\d+)?)$", re.IGNORECASE)
_COND_WORDS = re.compile(r"(\b(?:and|or|not|of|all|them|near|by)\b|\d+ of|[()|])")
TOP = {"title", "id", "status", "description", "references", "author", "date", "modified", "tags", "logsource", "detection",
       "falsepositives", "level", "related", "fields", "correlation", "filter", "license", "name", "taxonomy", "scope"}  # fmt: skip


def _span(cls: str, text: str) -> str:
    return f'<span class="{cls}">{escape(text)}</span>' if text else ""


def _value(rest: str, condition: bool) -> str:
    """Highlight what follows a key or a list dash."""
    lead = rest[: len(rest) - len(rest.lstrip())]
    body = rest.strip()
    if not body:
        return str(escape(rest))
    comment = ""
    if body[0] not in "'\"":
        m = re.search(r"\s#", body)
        if m:
            body, comment = body[: m.start()], body[m.start() :]
    if body.startswith("#"):
        return str(escape(lead)) + _span("y-com", body)
    if body in ("|", ">", "|-", ">-", "|+", ">+"):
        out = _span("y-op", body)
    elif body[0] in "'\"":
        out = _span("y-str", body)
    elif _LITERAL.match(body):
        out = _span("y-lit", body)
    elif condition:
        out = "".join(_span("y-kw", p) if _COND_WORDS.fullmatch(p) else str(escape(p)) for p in _COND_WORDS.split(body) if p)
    elif "*" in body:
        out = "".join(_span("y-wild", p) if p == "*" else _span("y-val", p) for p in re.split(r"(\*)", body) if p)
    else:
        out = _span("y-val", body)
    return str(escape(lead)) + out + _span("y-com", comment)


def _line(line: str) -> str:
    stripped = line.lstrip()
    if not stripped:
        return str(escape(line))
    if stripped.startswith("#"):
        return _span("y-com", line)
    if stripped in ("---", "..."):
        return _span("y-doc", line)
    m = _KEY.match(line)
    if m:
        key = m["key"]
        field, _, mods = key.partition("|")
        top = not m["indent"] and not m["dash"] and key in TOP
        key_html = _span("y-top" if top else "y-key", field) + (_span("y-mod", "|" + mods) if mods else "")
        return (
            str(escape(m["indent"]))
            + _span("y-dash", m["dash"] or "")
            + key_html
            + _span("y-punc", m["colon"])
            + _value(m["rest"], condition=field.strip() == "condition")
        )
    m = _DASH.match(line)
    if m:
        return str(escape(m["indent"])) + _span("y-dash", m["dash"]) + _value(m["rest"] or "", condition=False)
    return _value(line, condition=False)


def yaml_html(raw: str) -> Markup:
    """Highlighted YAML: one <span class="ln"> per line (line numbers come from CSS), joined by newlines."""
    if len(raw) > MAX_BYTES:
        return Markup('<span class="ln">{}</span>').format(raw)
    lines = raw.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return Markup("\n".join(f'<span class="ln">{_line(x)}</span>' for x in lines))  # noqa: S704 - every piece is escaped in _line
