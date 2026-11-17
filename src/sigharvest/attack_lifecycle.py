"""Strict lifecycle flags for ATT&CK objects consumed during bundle reduction."""

from typing import Any

from sigharvest.errors import SigharvestError


def retired(obj: dict[str, Any]) -> bool:
    """Admit both flags before filtering; omission means false, never coerce input."""
    revoked = obj.get("revoked", False)
    deprecated = obj.get("x_mitre_deprecated", False)
    if type(revoked) is not bool:
        raise SigharvestError(f"Invalid ATT&CK revoked: expected boolean, got {type(revoked).__name__}; supply a valid STIX bundle")
    if type(deprecated) is not bool:
        raise SigharvestError(f"Invalid ATT&CK x_mitre_deprecated: expected boolean, got {type(deprecated).__name__}; supply a valid STIX bundle")
    return revoked or deprecated
