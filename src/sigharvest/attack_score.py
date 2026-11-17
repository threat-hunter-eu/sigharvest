"""Catalog-bound ATT&CK metadata credit, independent of detection evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from sigharvest import normalize
from sigharvest.attack import NORMALISATION_VERSION, Matrix, normalise_technique
from sigharvest.fingerprints import digest

POLICY = "attack-metadata-credit-v1"
CONTEXT_KEY = "indexed_attack_score_context"


@dataclass
class Context:
    """One offline catalog snapshot and a bounded token memo per publication."""

    matrix: Matrix | None = None
    fingerprint: str = field(init=False)
    _tokens: dict[str, bool] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        catalog = asdict(self.matrix) | {"deprecated": sorted(self.matrix.deprecated)} if self.matrix is not None else None
        self.fingerprint = digest([POLICY, NORMALISATION_VERSION, catalog])

    def accepts(self, value: object) -> bool:
        """Accept only a complete string token under the shared identity policy."""
        if not isinstance(value, str):
            return False
        if value not in self._tokens:
            token = normalize.tag(value)
            identity = normalise_technique(token or "", self.matrix)
            accepted = identity.domain == "enterprise" and (
                identity.status in {"current", "replaced"} if self.matrix is not None else identity.status == "unverified"
            )
            if len(self._tokens) >= 4096:
                self._tokens.clear()
            self._tokens[value] = accepted
        return self._tokens[value]


def credit(tags: object, context: Context) -> int:
    """Four metadata points at most; malformed containers cannot certify a tag."""
    return 4 if isinstance(tags, (list, tuple)) and any(context.accepts(tag) for tag in tags) else 0


def explanation(tags: object, context: Context, published: str | None) -> str:
    """Explain only the current published policy; never relabel an older score."""
    if published != context.fingerprint:
        return "ATT&CK metadata bonus unavailable for this index context. Run sigharvest index to refresh the score."
    points = credit(tags, context)
    if context.matrix is None:
        detail = "Unverified: local ATT&CK catalog absent or invalid; complete Enterprise tokens receive syntax-only credit."
    else:
        detail = f"ATT&CK v{context.matrix.version}: only current Enterprise techniques or replacements with a valid successor receive credit."
    return f"ATT&CK metadata: +{points}/4 points. {detail} Metadata is not evidence that the rule detects a technique."
