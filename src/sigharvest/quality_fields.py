"""Field names from another schema on a Windows rule (computed by `quality.classify`).

The Sigma Windows taxonomy (Sysmon, Security, PowerShell...) uses flat field names: `Image`, `CommandLine`,
`TargetFilename`. A Windows rule that names its fields with a schema prefix (`process.command_line`, `file.path`,
`data.Image`, `winlog.event_data.CommandLine`) was written for one SIEM's stored names (ECS, Wazuh, Winlogbeat...).
The Sysmon and Windows pipelines map Sigma names only, so such a field passes through unchanged and the converted
query looks for a field the normalised events do not have; a rule that mixes the two styles (`data.CommandLine` and
`Image`) needs fields from two schemas in one event.

Flag (informational, lowers the score; the rule text is never changed):
- foreign_field_names: a Windows rule (product windows, or the non-standard product sysmon) with at least one
  dotted field name in its detection. Keyword lists and `EventID`-style flat names are unaffected; other products
  (cloud audit logs: `requestParameters.userName`, `properties.message`) legitimately use dotted names.
"""

from __future__ import annotations

from typing import Any

FIELD_FLAGS = ("foreign_field_names",)
FIELD_PENALTY = {"foreign_field_names": 10.0}
_WINDOWS_PRODUCTS = frozenset({"windows", "sysmon"})
_MAX_FIELDS = 4096  # untrusted rule text: bound the work per rule


def detection_fields(detection: Any) -> list[str]:
    """Field names (without modifiers) of every selection map in a detection, in order; keywords are skipped."""
    out: list[str] = []
    if not isinstance(detection, dict):
        return out
    stack = [v for k, v in detection.items() if k not in ("condition", "timeframe")]
    while stack and len(out) < _MAX_FIELDS:
        item = stack.pop()
        if isinstance(item, dict):
            out.extend(str(k).split("|", 1)[0].strip() for k in item)
        elif isinstance(item, list):
            stack.extend(x for x in item if isinstance(x, dict))
    return [f for f in out if f]


def field_flags(data: dict[str, Any]) -> list[str]:
    """`foreign_field_names` or nothing for one parsed rule document."""
    raw_ls = data.get("logsource")
    product = str(raw_ls.get("product") or "").strip().lower() if isinstance(raw_ls, dict) else ""
    if product not in _WINDOWS_PRODUCTS:
        return []
    if any("." in f for f in detection_fields(data.get("detection"))):
        return ["foreign_field_names"]
    return []


def field_penalty(flags: list[str] | None) -> float:
    """Score points removed for the field flags (see FIELD_PENALTY)."""
    return sum(FIELD_PENALTY.get(f, 0.0) for f in flags or [])
