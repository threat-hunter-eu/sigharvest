"""SigmaHQ release-package profiles, applied to the rules of every source.

SigmaHQ publishes its rules as packages (https://github.com/SigmaHQ/sigma/blob/master/Releases.md), chosen by
rule status, level and rule type:

| profile          | status                    | level                  | rule type             |
|------------------|---------------------------|------------------------|-----------------------|
| core             | test, stable              | high, critical         | core (generic)        |
| core+            | test, stable              | medium, high, critical | core                  |
| core++           | experimental, test, stable| medium, high, critical | core                  |
| emerging-threats | experimental, test, stable| medium, high, critical | emerging threats      |
| all              | experimental, test, stable| medium, high, critical | core, emerging threats|

Threat-hunting rules are in no package (they are for hunting, not alerting), and neither are SigmaHQ's
placeholder, compliance and DFIR folders. `--profile` applies the same vocabulary to every source: a rule's type
comes from its tags (`detection.emerging-threats`, `detection.threat-hunting`, `detection.dfir`, the Sigma tag
namespace) or from a SigmaHQ-style folder in the path of its canonical copy (`rules-emerging-threats/`,
`rules-threat-hunting/`, `rules-placeholder/`, `rules-compliance/`, `rules-dfir/`); everything else is core.
"""

from __future__ import annotations

from dataclasses import dataclass

from sigharvest.errors import SigharvestError


@dataclass(frozen=True)
class Profile:
    name: str
    statuses: tuple[str, ...]
    levels: tuple[str, ...]
    types: tuple[str, ...]  # core, emerging-threats


MEDIUM_UP = ("medium", "high", "critical")
PROFILES: dict[str, Profile] = {
    p.name: p
    for p in (
        Profile("core", ("test", "stable"), ("high", "critical"), ("core",)),
        Profile("core+", ("test", "stable"), MEDIUM_UP, ("core",)),
        Profile("core++", ("experimental", "test", "stable"), MEDIUM_UP, ("core",)),
        Profile("emerging-threats", ("experimental", "test", "stable"), MEDIUM_UP, ("emerging-threats",)),
        Profile("all", ("experimental", "test", "stable"), MEDIUM_UP, ("core", "emerging-threats")),
    )
}
ALIASES = {"et": "emerging-threats", "emerging_threats": "emerging-threats", "core-plus": "core+", "core-plus-plus": "core++"}
NAMES = tuple(PROFILES)

# Rule types other than core: (tags of the Sigma `detection` namespace, SigmaHQ folder names).
_TYPES = {
    "emerging-threats": (("detection.emerging-threats", "detection.emerging_threats"), ("rules-emerging-threats",)),
    "threat-hunting": (("detection.threat-hunting", "detection.threat_hunting"), ("rules-threat-hunting",)),
    "other": (("detection.dfir",), ("rules-placeholder", "rules-compliance", "rules-dfir")),
}


def resolve(name: str) -> Profile:
    key = name.strip().lower()
    key = ALIASES.get(key, key)
    if key not in PROFILES:
        raise SigharvestError(f"unknown profile {name!r}: use one of {', '.join(NAMES)} (SigmaHQ release packages)")
    return PROFILES[key]


def _type_sql(kind: str) -> str:
    """SQL true when the logic group `g` is of this rule type (fixed strings only; no user input)."""
    tags, folders = _TYPES[kind]
    tag_list = ", ".join(f"'{t}'" for t in tags)
    paths = " OR ".join(f"('/' || o.path) LIKE '%/{f}/%'" for f in folders)
    tag_sql = f"EXISTS (SELECT 1 FROM json_each(g.tags) t WHERE lower(t.value) IN ({tag_list}))"  # noqa: S608 - fixed strings from _TYPES
    path_sql = f"EXISTS (SELECT 1 FROM occurrences o WHERE o.version_id = g.canonical_version_id AND o.present = 1 AND ({paths}))"  # noqa: S608
    return f"({tag_sql} OR {path_sql})"


def rule_type_sql() -> str:
    """SQL expression: the rule type of `g` (emerging-threats, threat-hunting, other or core)."""
    return (
        f"CASE WHEN {_type_sql('emerging-threats')} THEN 'emerging-threats' WHEN {_type_sql('threat-hunting')} THEN 'threat-hunting' "
        f"WHEN {_type_sql('other')} THEN 'other' ELSE 'core' END"
    )


def where(profile: Profile) -> str:
    """WHERE clause on `g` (logic_groups) for a profile; status and level are the indexed canonical values."""
    statuses = ", ".join(f"'{x}'" for x in profile.statuses)
    levels = ", ".join(f"'{x}'" for x in profile.levels)
    types = ", ".join(f"'{x}'" for x in profile.types)
    return f"(g.status IN ({statuses}) AND g.level IN ({levels}) AND ({rule_type_sql()}) IN ({types}))"
