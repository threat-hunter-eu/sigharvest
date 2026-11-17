"""Licence classes for redistribution of rules (exports, published data releases).

Every rule keeps its own licence (see export.effective_licence: the licence of the source the shipped copy comes
from; the rule's own `license:` field only when it is more restrictive). For publishing, licences are grouped into classes:

- permissive: MIT, Apache-2.0, BSD, ISC, CC0, Unlicense, CC-BY, DRL (Detection Rule License: keep attribution)
- copyleft: GPL, AGPL, LGPL, MPL, EUPL, CC-BY-SA (redistributable as-is with the licence notice; aggregation)
- restricted: licences that limit redistribution or use (Elastic License, BUSL, commercial, CC-BY-NC/ND)
- none: no licence stated. Without a licence nobody else may redistribute the text: publish metadata and a link only.

This is guidance encoded as code, not legal advice; `docs` for the release explain it.
"""

from __future__ import annotations

import re

CLASSES = ("permissive", "copyleft", "restricted", "none")
_PERMISSIVE = re.compile(r"^(mit|apache-2\.0|bsd-[0-9a-z-]+|isc|0bsd|cc0-1\.0|unlicense|cc-by-[0-9.]+|drl-1\.[01]|zlib|wtfpl|python-2\.0)$")
_COPYLEFT = re.compile(r"^(a?gpl-[0-9.]+(-only|-or-later)?|lgpl-[0-9.]+(-only|-or-later)?|mpl-2\.0|eupl-1\.[12]|cc-by-sa-[0-9.]+|epl-[0-9.]+)$")
# The whole text must be the Detection Rule License name and version (optionally followed by a link):
# "DRL-1.1", "DRL 1.1", "Detection Rule License (DRL) 1.1", "DRL 1.1 https://...". Anything else that merely
# mentions DRL ("proprietary (not DRL)", "LicenseRef-HDRLabs-...", "DRL 1.0 / commercial") is not DRL.
_DRL = re.compile(r"^(?:drl|detection[- ]rule[- ]licen[cs]e(?:[- ]\(drl\))?)(?:[- ]?v(?:ersion)?)?[- ]?(1\.[01])?$")
# Common spellings of SPDX ids, matched against the whole (lower-case, dash-joined) text.
_ALIASES = {
    "mit-license": "mit",
    "the-mit-license": "mit",
    "apache-2": "apache-2.0",
    "apache-license-2.0": "apache-2.0",
    "apache-license-version-2.0": "apache-2.0",
    "apache-license,-version-2.0": "apache-2.0",
    "gplv3": "gpl-3.0",
    "gplv2": "gpl-2.0",
    "agplv3": "agpl-3.0",
    "elastic-license-2.0": "elastic-2.0",
    "elastic-license-v2": "elastic-2.0",
}
_RANK = {"permissive": 0, "copyleft": 1, "restricted": 2, "none": 3, "private": 4}


# Deprecated SPDX ids (no -only / -or-later) as GitHub still reports them. A LICENSE with the bare GPL text and no
# version statement is recorded as -only, the conservative reading (GPL-3 §14 would also allow later versions).
DEPRECATED_SPDX = {
    "GPL-2.0": "GPL-2.0-only",
    "GPL-3.0": "GPL-3.0-only",
    "AGPL-3.0": "AGPL-3.0-only",
    "LGPL-2.0": "LGPL-2.0-only",
    "LGPL-2.1": "LGPL-2.1-only",
    "LGPL-3.0": "LGPL-3.0-only",
}


def current_spdx(licence: str | None) -> str | None:
    """A licence id with deprecated SPDX ids replaced (GPL-3.0 -> GPL-3.0-only)."""
    return DEPRECATED_SPDX.get(licence, licence) if licence else licence


def normalise(licence: str | None) -> str | None:
    """Lower-case SPDX-like id by exact match: 'DRL 1.1 https://...' -> drl-1.1, 'Apache License 2.0' -> apache-2.0.

    Unknown texts are kept (dash-joined), so they classify as restricted, never as a permissive licence."""
    if not licence:
        return None
    text = str(licence).strip().lower()
    # The lookbehind starts one try per blank run, not one per blank: linear on a long run of spaces.
    text = re.split(r"(?<!\s)\s+(?:<)?https?://", text, maxsplit=1)[0].strip(" -,;<")
    if text in ("noassertion", "other", "none", "unknown", ""):
        return None
    text = re.sub(r"\s+", "-", text)
    if m := _DRL.match(text):
        return f"drl-{m.group(1) or '1.1'}"
    return _ALIASES.get(text, text)


def licence_class(licence: str | None) -> str:
    """permissive, copyleft, restricted or none (no licence stated) for a licence name or SPDX id."""
    n = normalise(licence)
    if n is None:
        return "none"
    if _PERMISSIVE.match(n):
        return "permissive"
    if _COPYLEFT.match(n):
        return "copyleft"
    return "restricted"


def narrows(rule_licence: str | None, source_licence: str | None) -> bool:
    """True when a rule's own `license:` is strictly more restrictive than its source's licence.

    A rule's metadata is written by whoever publishes the file: it may narrow the source licence (a restricted rule
    in a permissive repository) but never widen it (a `license: MIT` line cannot relicense an unlicensed or
    restricted repository's text)."""
    if not rule_licence:
        return False
    return _RANK[licence_class(rule_licence)] > _RANK[licence_class(source_licence)]


def shipped_licence(rule_licence: str | None, source_licence: str | None) -> str | None:
    """The licence to state for a document: its source's, or its own `license:` field when that is narrower."""
    return rule_licence if narrows(rule_licence, source_licence) else source_licence


def redistributable(value: object) -> bool:
    """A source's `redistributable` setting as a decision: only an explicit true allows shipping rule text.

    Not stated (None), false, "unknown" and anything unrecognised mean metadata and a link only."""
    if value is True:
        return True
    return isinstance(value, str) and value.strip().lower() in ("true", "yes")
