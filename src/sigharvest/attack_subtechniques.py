"""Admit source subtechnique declarations before catalog/graph reduction loses them.

Call after the reducer's lifecycle and identity admission. This checks present
declarations only; it neither selects revisions nor supplies missing edges.
"""

from typing import Any, TypeGuard

from sigharvest.errors import SigharvestError

MAX_SOURCE_OBJECTS = 200_000
MAX_ENDPOINT_LENGTH = 1024


class AttackSubtechniqueError(SigharvestError):
    """A source declaration disagrees with its admitted MITRE identity."""


def _invalid(position: int, field: str, reason: str) -> AttackSubtechniqueError:
    return AttackSubtechniqueError(
        f"Invalid ATT&CK objects[{position}].{field}: {reason}. Supply a corrected Enterprise ATT&CK bundle; the candidate was not published."
    )


def _reference(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and 0 < len(value) <= MAX_ENDPOINT_LENGTH and value == value.strip() and value.isprintable()


def admit_subtechniques(
    techniques: list[tuple[int, dict[str, Any], str | None]],
    relationships: list[tuple[int, dict[str, Any]]],
) -> dict[str, str | None]:
    """Check flags and active edges, returning the existing STIX-to-MITRE lookup.

    Positions refer to the original object list. Technique identities and all
    lifecycle flags have already been admitted; relationships are active only.
    Keep the caller's last-reference lookup policy until revision selection is
    integrated. Runtime and storage are linear in the bounded input lists.
    """
    if len(techniques) + len(relationships) > MAX_SOURCE_OBJECTS:
        raise AttackSubtechniqueError("Invalid ATT&CK object list: object count exceeds limit; supply a bounded Enterprise ATT&CK bundle.")
    by_ref: dict[str, str | None] = {}
    active: dict[str, str | None] = {}
    for position, obj, tid in techniques:
        if "x_mitre_is_subtechnique" in obj:
            flag = obj["x_mitre_is_subtechnique"]
            if type(flag) is not bool:
                raise _invalid(position, "x_mitre_is_subtechnique", "expected a JSON boolean")
            if tid is not None and flag != ("." in tid):
                raise _invalid(position, "x_mitre_is_subtechnique", "flag disagrees with MITRE ID shape")
        ref = obj.get("id")
        if not _reference(ref):
            raise _invalid(position, "id", "expected a bounded nonblank printable STIX reference")
        by_ref[ref] = tid
        if relationships:
            active[ref] = None if obj.get("revoked") or obj.get("x_mitre_deprecated") else tid
    for position, rel in relationships:
        endpoints = []
        retired = False
        for field in ("source_ref", "target_ref"):
            ref = rel.get(field)
            # A string matching an admitted active key has already passed the
            # reference grammar and identifies a live technique in this call.
            # Keep the last-reference policy, including retired/unidentified
            # overwrites. Subclasses still need their own grammar methods
            # checked. On a miss, preserve the original diagnostic order.
            tid = active.get(ref) if type(ref) is str and len(ref) <= MAX_ENDPOINT_LENGTH else None
            if tid is None:
                if not _reference(ref):
                    raise _invalid(position, field, "expected a bounded nonblank printable STIX reference")
                tid = by_ref.get(ref)
                if tid is None:
                    raise _invalid(position, field, "must reference an identified attack-pattern")
                if active.get(ref) is None:
                    # Real bundles keep subtechnique-of edges of retired techniques: they assert nothing current.
                    retired = True
            endpoints.append(tid)
        if retired:
            continue
        source, target = endpoints
        if rel["source_ref"] == rel["target_ref"] or source == target:
            raise _invalid(position, "subtechnique-of", "self-loop is not allowed")
        if "." not in source:
            raise _invalid(position, "source_ref", "source must have a subtechnique MITRE ID")
        if "." in target:
            raise _invalid(position, "target_ref", "parent must have a top-level technique MITRE ID")
        if target != source.split(".")[0]:
            raise _invalid(position, "target_ref", "parent conflicts with source MITRE ID prefix")
        # Every admitted edge asserts the same unique prefix, so duplicates are
        # idempotent and no competing parent can be hidden by dictionary order.
    return by_ref
