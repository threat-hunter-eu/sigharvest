"""MITRE ATT&CK coverage of the corpus.

ATT&CK data (Enterprise matrix, pinned version) is downloaded once from mitre-attack/attack-stix-data and reduced to
a small JSON file in the cache. MITRE ATT&CK® is a registered trademark of The MITRE Corporation; the data is used
under MITRE's licence (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/), whose copyright notice
is shown wherever coverage is displayed or exported.
"""

from __future__ import annotations

import json
import os
import re
import stat
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeGuard

from sqlalchemy.orm import Session

from sigharvest.attack_io import AcquisitionDeadline, admit_bundle_envelope, fetch_bundle, json_object, publish, unique_object
from sigharvest.attack_json import ExpansionLimit
from sigharvest.attack_lifecycle import retired
from sigharvest.attack_subtechniques import MAX_SOURCE_OBJECTS, AttackSubtechniqueError, admit_subtechniques
from sigharvest.config import Workspace
from sigharvest.errors import SigharvestError

if TYPE_CHECKING:
    from sigharvest.index import GroupFilters

ATTACK_VERSION = "20.0"
ATTACK_URL = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
ATTACK_TERMS_URL = "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/"
# ATT&CK terms of use: reproduce MITRE's copyright designation and licence in every copy (year of the catalogue used).
ATTACK_COPYRIGHT = "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."
ATTACK_TRADEMARK = "MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation."
ATTRIBUTION = f"{ATTACK_COPYRIGHT} {ATTACK_TRADEMARK} Terms of use: {ATTACK_TERMS_URL}"
NORMALISATION_VERSION = 1
# Compatibility for the existing offline admission measurement helper.
_unique_object = unique_object
MAX_CATALOG_BYTES = 8 * 1024**2
MAX_CATALOG_OBJECTS = 20_000
MAX_CATALOG_NAME = 1024
MAX_EXTERNAL_REFERENCES = 1024
MAX_EXTERNAL_REFERENCE_FIELDS = 32
MAX_REFERENCE_SOURCE_NAME = 1024
MAX_KILL_CHAIN_PHASES = 1024
_PHASE_SET_MIN_SIZE = 32
MAX_MATRIX_TACTIC_REFS = MAX_CATALOG_OBJECTS
MAX_TACTIC_REF_LENGTH = 1024
TECHNIQUE_DOMAINS = frozenset({"enterprise-attack", "mobile-attack", "ics-attack"})
MAX_TECHNIQUE_DOMAINS = len(TECHNIQUE_DOMAINS)
MAX_TECHNIQUE_DOMAIN_LENGTH = max(map(len, TECHNIQUE_DOMAINS))
_CATALOG_ID = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")
_TACTIC_ID = re.compile(r"TA[0-9]{4}")
_EXTERNAL_ID_PATTERNS = {
    "attack-pattern": _CATALOG_ID,
    "x-mitre-tactic": _TACTIC_ID,
    # Preserve the entity grammar of the existing threat-cache reader.
    "intrusion-set": re.compile(r"G\d{4}"),
    "malware": re.compile(r"S\d{4}"),
    "tool": re.compile(r"S\d{4}"),
}
_TACTIC_SHORT = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
_ID = re.compile(r"t\d{4}(?:\.\d{3})?", re.I)
INTERNAL_LABELS = frozenset({"lolbas", "hunting", "generated", "supply-chain"})


@dataclass
class Technique:
    """An ATT&CK technique or sub-technique with the tactics it belongs to."""

    id: str
    name: str
    tactics: list[str]
    parent: str | None


@dataclass
class Matrix:
    """The Enterprise ATT&CK matrix: tactics in order, techniques, and revoked or deprecated ids."""

    version: str
    tactics: list[tuple[str, str, str]]  # (shortname, name, TA id) in matrix order
    techniques: dict[str, Technique]
    replaced: dict[str, str] = field(default_factory=dict)  # revoked id -> replacement id
    deprecated: set[str] = field(default_factory=set)

    def resolve(self, tid: str) -> str | None:
        """Current technique for an id from a rule tag: itself, its replacement (revoked ids, followed) or None."""
        return normalise_technique(tid, self).current_id


@dataclass(frozen=True)
class TechniqueIdentity:
    """An original assertion and its version-bound interpretation, never a YAML rewrite."""

    original: str
    original_id: str | None
    current_id: str | None
    domain: str
    status: str
    version: str | None
    label: str
    tactics: tuple[str, ...] = ()
    parent: str | None = None

    @property
    def comparison_id(self) -> str | None:
        """Enterprise IDs only; a missing catalog permits syntax-only legacy use."""
        return self.current_id or (self.original_id if self.domain == "enterprise" and self.status == "unverified" else None)


def normalise_technique(value: str, matrix: Matrix | None = None) -> TechniqueIdentity:
    """Resolve chains once for every consumer, retaining unresolved/domain provenance.

    Explicit ICS/mobile namespaces never enter Enterprise comparisons. Bare T08xx
    and T1400-T1479 identify those domains too; ambiguous IDs require a namespace.
    Unknown, deprecated and cyclic Enterprise IDs have no current comparison ID.
    """
    raw = str(value).strip()
    name = raw.lower().removeprefix("attack.")
    version = matrix.version if matrix else None
    internal_name = name.removeprefix("internal.").replace("_", "-")
    if internal_name in INTERNAL_LABELS:
        return TechniqueIdentity(raw, None, None, "internal", "label", None, "internal." + internal_name)
    domain = "enterprise"
    for prefix in ("ics.", "mobile.", "enterprise."):
        if name.startswith(prefix):
            domain, name = prefix[:-1], name[len(prefix) :]
            break
    if not _ID.fullmatch(name):
        return TechniqueIdentity(raw, None, None, "other", "not_technique", None, raw)
    tid = name.upper()
    if (
        domain == "enterprise"
        and not raw.lower().removeprefix("attack.").startswith("enterprise.")
        and (name.startswith("t08") or re.fullmatch(r"t14[0-7]\d(?:\.\d{3})?", name))
    ):
        domain = "ics" if name.startswith("t08") else "mobile"
    if domain != "enterprise":
        return TechniqueIdentity(raw, tid, None, domain, "unverified", None, f"{tid} ({domain.upper() if domain == 'ics' else domain} ATT&CK)")
    if matrix is None:
        return TechniqueIdentity(raw, tid, None, domain, "unverified", None, tid)
    current, seen = tid, set()
    while current in matrix.replaced:
        if current in seen:
            return TechniqueIdentity(raw, tid, None, domain, "cycle", version, f"{tid} (cyclic replacement in ATT&CK v{version})")
        seen.add(current)
        current = matrix.replaced[current]
    if current in matrix.techniques and current not in matrix.deprecated:
        tech = matrix.techniques[current]
        label = f"{tid} -> {current} in ATT&CK v{version}" if current != tid else tid
        return TechniqueIdentity(raw, tid, current, domain, "replaced" if current != tid else "current", version, label, tuple(tech.tactics), tech.parent)
    status = "deprecated" if current in matrix.deprecated else "unknown"
    label = f"{tid} ({status}, no current successor in ATT&CK v{version})"
    return TechniqueIdentity(raw, tid, None, domain, status, version, label)


def technique_ids(values: Iterable[str], matrix: Matrix | None = None) -> set[str]:
    """Canonical Enterprise comparison IDs from bare IDs or Sigma tags."""
    return {tid for value in values if (tid := normalise_technique(value, matrix).comparison_id)}


def tag_metadata(tags: Iterable[str], matrix: Matrix | None = None, cache: dict[str, dict[str, Any] | None] | None = None) -> list[dict[str, Any]]:
    """Interpret source tags. Optional memo belongs to one immutable catalog read."""
    out = []
    for tag in tags:
        if cache is not None and tag in cache:
            item = cache[tag]
        else:
            identity = normalise_technique(tag, matrix)
            # Lists, not tuples, so a JSON-cached copy compares equal to the live one.
            item = {**vars(identity), "tactics": list(identity.tactics)} if identity.status != "not_technique" else None
            if cache is not None:
                cache[tag] = item
        if item is not None:
            out.append(dict(item))
    return out


class InvalidCatalog(ValueError):
    """The source or reduced catalog cannot be admitted without modifying its contents."""


class InvalidMatrix(InvalidCatalog):
    """Source matrix structure would be lost during reduction."""


class AttackCacheError(SigharvestError):
    """A catalog or acquisition candidate needs explicit operator correction."""


class AttackIdentityError(SigharvestError):
    """A consumed STIX object has malformed or conflicting external identity."""


class AttackPhaseError(SigharvestError):
    """A consumed technique has invalid source kill-chain phases."""


class AttackObjectKindError(SigharvestError):
    """A source object cannot be dispatched without losing its discriminator."""


def _catalog_name(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and 0 < len(value) <= MAX_CATALOG_NAME and value == value.strip() and value.isprintable()


def _object_kind(obj: dict[str, Any], position: int) -> str:
    """Admit exact discriminator text before dispatch, including retired objects.

    Unknown text remains an extension. Only exact relationships consume the
    second discriminator; homonymous metadata on other objects remains unused.
    """
    kind = obj.get("type")
    if _catalog_name(kind):
        if kind != "relationship" or _catalog_name(obj.get("relationship_type")):
            return kind
        field = "relationship_type"
    else:
        field = "type"
    raise AttackObjectKindError(
        f"Invalid ATT&CK objects[{position}].{field}: expected 1-{MAX_CATALOG_NAME} printable characters without surrounding whitespace. "
        "Supply a corrected Enterprise ATT&CK bundle."
    )


def _catalog_id(value: object) -> bool:
    return isinstance(value, str) and _CATALOG_ID.fullmatch(value) is not None


def _catalog_tactics(tactics: list[Any]) -> set[str]:
    """Admit tactic identities and display fields for source and reduced catalogs."""
    shortnames: set[str] = set()
    tactic_ids: set[str] = set()
    for row in tactics:
        if not isinstance(row, (list, tuple)) or len(row) != 3:
            raise InvalidCatalog("each tactic must contain shortname, name and TA ID")
        short, name, tid = row
        if not _catalog_name(short) or not _TACTIC_SHORT.fullmatch(short) or not _catalog_name(name):
            raise InvalidCatalog("invalid tactic shortname or name")
        if not isinstance(tid, str) or not _TACTIC_ID.fullmatch(tid):
            raise InvalidCatalog("tactic IDs must be canonical TA IDs")
        if short in shortnames or tid in tactic_ids:
            raise InvalidCatalog("duplicate tactic identity")
        shortnames.add(short)
        tactic_ids.add(tid)
    return shortnames


def matrix_from_data(data: object, *, version: str = ATTACK_VERSION) -> Matrix:
    """Validate before constructing any lookup; never normalize catalog identities.

    Missing parents/tactics and all repeated declarations (even identical ones)
    are errors. Retirement edges may cycle or end outside the live catalog: the
    normalizer retains its cycle/unknown/deprecated diagnostics for these IDs.
    Optional retirement sections default to empty for legacy reduced catalogs.
    """
    if not isinstance(data, dict) or set(data) - {"version", "tactics", "techniques", "replaced", "deprecated"}:
        raise InvalidCatalog("expected a reduced catalog object with known sections")
    if data.get("version") != version:
        raise InvalidCatalog(f"expected Enterprise ATT&CK version {version}")
    tactics, entries = data.get("tactics"), data.get("techniques")
    replaced, deprecated = data.get("replaced", {}), data.get("deprecated", [])
    if not isinstance(tactics, list) or not isinstance(entries, list) or not tactics or not entries:
        raise InvalidCatalog("tactics and techniques must be nonempty lists")
    if not isinstance(replaced, dict) or not isinstance(deprecated, list):
        raise InvalidCatalog("replaced must be an object and deprecated a list")
    if sum(map(len, (tactics, entries, replaced, deprecated))) > MAX_CATALOG_OBJECTS:
        raise InvalidCatalog("catalog exceeds object limit")
    shortnames = _catalog_tactics(tactics)
    techniques: dict[str, Technique] = {}
    for item in entries:
        if not isinstance(item, dict) or set(item) != {"id", "name", "tactics", "parent"}:
            raise InvalidCatalog("each technique requires only id, name, tactics and parent")
        tid, name, phases, parent = (item[k] for k in ("id", "name", "tactics", "parent"))
        if not _catalog_id(tid) or not _catalog_name(name):
            raise InvalidCatalog("techniques require a canonical T ID and a nonblank printable name")
        if tid in techniques:
            raise InvalidCatalog("duplicate technique ID")
        if not isinstance(phases, list) or not phases or len(phases) > len(shortnames):
            raise InvalidCatalog("technique tactics must be a nonempty list of declared shortnames")
        if any(not isinstance(t, str) or t not in shortnames for t in phases) or len(set(phases)) != len(phases):
            raise InvalidCatalog("unknown or duplicate technique tactic")
        expected_parent = tid.split(".")[0] if "." in tid else None
        if parent != expected_parent:
            raise InvalidCatalog("technique parent must match its ID prefix; top-level parents must be null")
        techniques[tid] = Technique(tid, name, list(phases), parent)
    if any(t.parent is not None and t.parent not in techniques for t in techniques.values()):
        raise InvalidCatalog("subtechnique parent is absent from techniques")
    if any(not _catalog_id(old) or not _catalog_id(new) for old, new in replaced.items()):
        raise InvalidCatalog("replacement endpoints must be canonical T IDs")
    if any(not _catalog_id(tid) for tid in deprecated) or len(set(deprecated)) != len(deprecated):
        raise InvalidCatalog("deprecated IDs must be unique canonical T IDs")
    # All values are now shallow, bounded and typed; this also bounds direct
    # in-memory callers. Wire bytes are checked separately before JSON parsing.
    if len(json.dumps(data, ensure_ascii=False).encode("utf-8")) > MAX_CATALOG_BYTES:
        raise InvalidCatalog("catalog exceeds byte limit")
    return Matrix(version, [tuple(row) for row in tactics], techniques, dict(replaced), set(deprecated))


def cached_matrix(ws: Workspace | None) -> Matrix | None:
    """Bounded offline reader. Never create caches or download during derived reads."""
    if ws is None:
        return None
    path = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    try:
        info = path.stat()
        if info.st_size > MAX_CATALOG_BYTES or not stat.S_ISREG(info.st_mode):
            return None
        return _cached_matrix(str(path), info.st_mtime_ns, info.st_ctime_ns, info.st_size, ATTACK_VERSION)
    except (OSError, ValueError, RecursionError):
        return None


@lru_cache(maxsize=32)
def _cached_matrix(path: str, mtime: int, ctime: int, size: int, version: str = ATTACK_VERSION) -> Matrix:
    # Nonblocking open plus fstat also handles a regular file replaced by a FIFO.
    with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CATALOG_BYTES:
            raise InvalidCatalog("catalog must be a regular file within the byte limit")
        payload = stream.read(MAX_CATALOG_BYTES + 1)
    if len(payload) > MAX_CATALOG_BYTES:
        raise InvalidCatalog("catalog exceeds byte limit")
    return matrix_from_data(json_object(payload), version=version)


def session_matrix(s: Session) -> Matrix | None:
    database = s.get_bind().engine.url.database
    return cached_matrix(Workspace(Path(database).parent.parent)) if database and database != ":memory:" else None


def load_matrix(ws: Workspace, *, acquire: bool = True) -> Matrix:
    """Load the pinned cache; passive callers must explicitly disable acquisition."""
    cache = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    try:
        info = cache.stat()
    except FileNotFoundError:
        # Acquisition remains explicit through load_matrix, only for an absent
        # path. A dangling symlink is an existing broken cache, not absence.
        if cache.is_symlink():
            raise AttackCacheError(f"Invalid ATT&CK cache {cache}. Replace it with a verified Enterprise {ATTACK_VERSION} reduced catalog.") from None
        if not acquire:
            raise AttackCacheError(
                f"ATT&CK catalog is unavailable at {cache}. "
                f"Run sigharvest coverage in this workspace to acquire Enterprise ATT&CK {ATTACK_VERSION} before retrying."
            ) from None
        try:
            raw = fetch_bundle(ATTACK_URL)
            data = _reduce(json_object(raw))
            matrix_from_data(data)
            encoded = json.dumps(data).encode("utf-8")
            if len(encoded) > MAX_CATALOG_BYTES:
                raise InvalidCatalog("catalog exceeds byte limit")
        except AcquisitionDeadline as exc:
            raise AttackCacheError(str(exc)) from None
        except ExpansionLimit as exc:
            raise AttackCacheError(f"{exc}. No cache was published.") from None
        except InvalidMatrix as exc:
            raise AttackCacheError(
                f"Invalid ATT&CK source matrix: {exc}. Supply a complete Enterprise ATT&CK {ATTACK_VERSION} bundle; no cache was published."
            ) from None
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
            raise AttackCacheError(
                f"Invalid or incomplete ATT&CK acquisition. Supply a complete Enterprise ATT&CK {ATTACK_VERSION} bundle "
                "as UTF-8 JSON with unique keys and standard constants, within the 128 MiB limit; "
                "check HTTP identity encoding and retry. No cache was published."
            ) from None
        try:
            publish(cache, encoded)
        except OSError:
            raise AttackCacheError("Cannot publish ATT&CK cache. Check available space and cache-directory permissions, then retry.") from None
        info = cache.stat()
    except OSError as exc:
        raise AttackCacheError(f"Cannot read ATT&CK cache {cache}. Check its permissions and file type.") from exc
    try:
        return _cached_matrix(str(cache), info.st_mtime_ns, info.st_ctime_ns, info.st_size, ATTACK_VERSION)
    except ExpansionLimit as exc:
        raise AttackCacheError(
            f"{exc}. Replace the cache with a verified reduced catalog; the existing file was not changed and no repair was downloaded."
        ) from None
    except (OSError, ValueError, RecursionError) as exc:
        raise AttackCacheError(
            f"Invalid ATT&CK cache {cache}. Replace it with a verified Enterprise {ATTACK_VERSION} reduced catalog; "
            "the existing file was not changed and no repair was downloaded."
        ) from exc


def _ext_id(obj: dict[str, Any]) -> str | None:
    """Select one exact, typed MITRE identity; equal declarations deduplicate.

    Only identity-bearing objects consumed by the reducers enter this boundary.
    Missing references remain unidentified. Citation payloads are not identities
    and are neither traversed nor serialized here.
    """
    kind = obj.get("type")
    if not isinstance(kind, str) or kind not in _EXTERNAL_ID_PATTERNS:
        return None
    refs = obj.get("external_references", [])

    def invalid(field: str, problem: str) -> AttackIdentityError:
        return AttackIdentityError(f"Invalid ATT&CK {kind} {field}: {problem}. Supply a corrected Enterprise ATT&CK bundle.")

    if not isinstance(refs, list):
        raise invalid("external_references", "expected a list")
    if len(refs) > MAX_EXTERNAL_REFERENCES:
        raise invalid("external_references", "reference count exceeds limit")
    selected = None
    for ref in refs:
        if not isinstance(ref, dict):
            raise invalid("external_references[]", "expected an object")
        if len(ref) > MAX_EXTERNAL_REFERENCE_FIELDS:
            raise invalid("external_references[]", "field count exceeds limit")
        source = ref.get("source_name")
        if not isinstance(source, str) or not source or len(source) > MAX_REFERENCE_SOURCE_NAME:
            raise invalid("external_references[].source_name", "expected a nonempty bounded string")
        if source != "mitre-attack":
            continue
        identity = ref.get("external_id")
        if not isinstance(identity, str):
            raise invalid("external_references[].external_id", "expected a string MITRE ID")
        # The selected string already passed this object's typed grammar. Still
        # check every envelope above, including equal declarations and citations.
        # Keep this reuse local: callers may mutate an aliased object next time.
        if identity == selected:
            continue
        if len(identity) > 9 or not _EXTERNAL_ID_PATTERNS[kind].fullmatch(identity):
            raise invalid("external_references[].external_id", "invalid MITRE ID for object type")
        if selected is not None and selected != identity:
            raise invalid("external_references[].external_id", "conflicting MITRE IDs")
        selected = identity
    return selected


def _matrix_tactics(objs: list[dict[str, Any]], live: list[dict[str, Any]]) -> list[list[Any]]:
    """Require one explicitly Enterprise matrix and preserve every declared reference.

    Consume the reducer's existing lifecycle selection. Revision selection and
    lifecycle/identity policy belong to their existing admission boundaries.
    Diagnostics contain positions and reasons, never source object contents.
    """
    matrices = []
    tactics_by_ref = {}
    for obj in live:
        kind = obj.get("type")
        if kind == "x-mitre-tactic":
            tactics_by_ref[obj["id"]] = obj
        elif kind == "x-mitre-matrix" and isinstance(obj.get("x_mitre_domains"), list) and "enterprise-attack" in obj["x_mitre_domains"]:
            matrices.append(obj)
    if len(matrices) != 1:
        raise InvalidMatrix(f"expected exactly one active Enterprise matrix with x_mitre_domains declaring enterprise-attack; found {len(matrices)}")
    refs = matrices[0].get("tactic_refs")
    if not isinstance(refs, list) or not 0 < len(refs) <= MAX_MATRIX_TACTIC_REFS:
        raise InvalidMatrix(f"matrix tactic_refs must be a nonempty list with at most {MAX_MATRIX_TACTIC_REFS} references")
    seen: set[str] = set()
    tactics = []
    for index, ref in enumerate(refs):
        if not isinstance(ref, str) or not 0 < len(ref) <= MAX_TACTIC_REF_LENGTH or ref != ref.strip() or not ref.isprintable():
            raise InvalidMatrix(f"matrix tactic_refs[{index}] must be nonblank printable text of at most {MAX_TACTIC_REF_LENGTH} characters without padding")
        if ref in seen:
            raise InvalidMatrix(f"matrix tactic_refs[{index}] repeats an earlier reference")
        seen.add(ref)
        tactic = tactics_by_ref.get(ref)
        if tactic is None:
            target = next((o for o in objs if o.get("id") == ref), None)
            if target is None:
                reason = "target is missing"
            elif target.get("type") != "x-mitre-tactic":
                reason = "target is not an x-mitre-tactic"
            else:
                reason = "target is revoked or deprecated"
            raise InvalidMatrix(f"matrix tactic_refs[{index}] {reason}")
        try:
            tactics.append([tactic.get("x_mitre_shortname"), tactic.get("name"), _ext_id(tactic)])
        except (TypeError, AttributeError) as exc:
            raise InvalidMatrix(f"matrix tactic_refs[{index}] has invalid tactic identity fields") from exc
    try:
        _catalog_tactics(tactics)
    except InvalidCatalog as exc:
        raise InvalidMatrix(f"matrix tactic_refs targets: {exc}") from exc
    return tactics


def _reduce(bundle: dict[str, Any]) -> dict[str, Any]:
    return _reduce_with_refs(bundle)[0]


def _technique_phases(value: object, shortnames: set[str]) -> list[str]:
    """Admit source shapes before filtering chains; preserve exact Enterprise order."""

    def invalid(field: str, problem: str) -> AttackPhaseError:
        return AttackPhaseError(f"Invalid ATT&CK attack-pattern.kill_chain_phases{field}: {problem}. Supply a corrected Enterprise ATT&CK bundle.")

    if not isinstance(value, list):
        raise invalid("", "expected a list with at least one Enterprise tactic")
    if len(value) > MAX_KILL_CHAIN_PHASES:
        raise invalid("", "phase count exceeds limit")
    phases: list[str] = []
    # Hash membership only for the large lists with demonstrated lookup cost.
    seen: set[str] | None = set() if len(value) >= _PHASE_SET_MIN_SIZE else None
    for position, phase in enumerate(value):
        if not isinstance(phase, dict):
            raise invalid(f"[{position}]", "expected an object")
        chain, name = phase.get("kill_chain_name"), phase.get("phase_name")
        if not _catalog_name(chain):
            raise invalid(f"[{position}].kill_chain_name", "expected nonempty bounded printable text without surrounding whitespace")
        if not _catalog_name(name):
            raise invalid(f"[{position}].phase_name", "expected nonempty bounded printable text without surrounding whitespace")
        if chain != "mitre-attack":
            continue
        if name not in shortnames:
            raise invalid(f"[{position}].phase_name", "unknown Enterprise tactic shortname")
        # Only exact immutable strings use hashed membership. Preserve list
        # equality for library callers supplying str subclasses as well.
        if seen is not None and type(name) is not str:
            seen = None
        if name in (seen if seen is not None else phases):
            raise invalid(f"[{position}].phase_name", "duplicate Enterprise tactic")
        phases.append(name)
        if seen is not None:
            seen.add(name)
    if not phases:
        raise invalid("", "at least one Enterprise tactic is required")
    return phases


def _enterprise_technique(obj: dict[str, Any]) -> bool:
    """Admit an explicit domain declaration before consuming any technique identity."""
    domains = obj.get("x_mitre_domains")
    if not isinstance(domains, list) or not 0 < len(domains) <= MAX_TECHNIQUE_DOMAINS:
        raise InvalidMatrix(f"attack-pattern x_mitre_domains must be a nonempty list of at most {MAX_TECHNIQUE_DOMAINS} canonical domains")
    # The common singleton is already fully validated by exact string equality;
    # avoid allocating a set per technique without skipping multi-domain checks.
    if len(domains) == 1 and isinstance(domains[0], str) and domains[0] == "enterprise-attack":
        return True
    seen: set[str] = set()
    for index, domain in enumerate(domains):
        if not isinstance(domain, str) or len(domain) > MAX_TECHNIQUE_DOMAIN_LENGTH or domain not in TECHNIQUE_DOMAINS:
            raise InvalidMatrix(f"attack-pattern x_mitre_domains[{index}] must be enterprise-attack, mobile-attack or ics-attack exactly")
        if domain in seen:
            raise InvalidMatrix(f"attack-pattern x_mitre_domains[{index}] repeats an earlier domain")
        seen.add(domain)
    return "enterprise-attack" in seen


def _reduce_with_refs(bundle: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str | None]]:
    """Reduce the matrix and share its selected technique identities with graph reduction."""
    admit_bundle_envelope(bundle)
    objs = bundle.get("objects", [])
    if not isinstance(objs, list) or len(objs) > MAX_SOURCE_OBJECTS:
        raise AttackSubtechniqueError("Invalid ATT&CK object list: expected a bounded list; supply a corrected Enterprise ATT&CK bundle.")
    live = []
    subtechnique_edges = []
    for position, o in enumerate(objs):
        if not isinstance(o, dict):
            raise AttackSubtechniqueError(f"Invalid ATT&CK objects[{position}]: expected an object; supply a corrected Enterprise ATT&CK bundle.")
        kind = _object_kind(o, position)
        if kind in {"attack-pattern", "x-mitre-tactic", "x-mitre-matrix"} or (
            kind == "relationship" and o.get("relationship_type") in {"revoked-by", "subtechnique-of"}
        ):
            is_retired = retired(o)
            if not is_retired:
                # Matrix inventory and replacement traversal do not consume
                # techniques; preserve their bounded invocation-local list.
                if kind != "attack-pattern":
                    live.append(o)
                if kind == "relationship" and o.get("relationship_type") == "subtechnique-of":
                    subtechnique_edges.append((position, o))
    tactics = _matrix_tactics(objs, live)
    shortnames = {short for short, _, _ in tactics}
    # Select once per object, retaining input order and the existing revision
    # policy. Revoked/deprecated techniques still supply retirement identities.
    technique_objects = []
    excluded_refs = set()
    for position, o in enumerate(objs):
        if o.get("type") != "attack-pattern":
            continue
        if _enterprise_technique(o):
            technique_objects.append((position, o, _ext_id(o)))
        elif isinstance(o.get("id"), str):
            excluded_refs.add(o["id"])
    by_ref = admit_subtechniques(technique_objects, subtechnique_edges)
    techniques = []
    for _, o, tid in technique_objects:
        if not tid or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        phases = _technique_phases(o.get("kill_chain_phases"), shortnames)
        techniques.append({"id": tid, "name": o.get("name", ""), "tactics": phases, "parent": tid.split(".")[0] if "." in tid else None})
    # Revoked techniques point to their replacement through "revoked-by" relationships (T1086 -> T1059.001, ...).
    replaced: dict[str, str] = {}
    for rel in live:
        if rel.get("type") == "relationship" and rel.get("relationship_type") == "revoked-by":
            if rel.get("source_ref", "") in by_ref and rel.get("target_ref", "") in excluded_refs:
                raise InvalidMatrix("active revoked-by relationship from an Enterprise attack-pattern targets a technique excluded by x_mitre_domains")
            old, new = by_ref.get(rel.get("source_ref", "")), by_ref.get(rel.get("target_ref", ""))
            if old and new:
                # Group by MITRE identity, not relationship or endpoint STIX ID.
                # Repeated evidence is harmless; competing successors cannot be
                # resolved by JSON order (or by dates on distinct relationships).
                if old in replaced and replaced[old] != new:
                    raise AttackCacheError(
                        "Conflicting active ATT&CK revoked-by successors for one source technique. "
                        f"Supply a corrected Enterprise {ATTACK_VERSION} bundle with one replacement target per source technique; "
                        "the candidate was not published."
                    )
                replaced[old] = new
    deprecated = sorted({tid for _, o, tid in technique_objects if tid is not None and o.get("x_mitre_deprecated") is True})
    return {
        "version": ATTACK_VERSION,
        "tactics": tactics,
        "techniques": sorted(techniques, key=lambda t: t["id"]),
        "replaced": dict(sorted(replaced.items())),
        "deprecated": deprecated,
    }, by_ref


@dataclass
class Coverage:
    """Rule families per technique for a set of rules, plus the tags that are not valid technique ids."""

    matrix: Matrix
    families: dict[str, int] = field(default_factory=dict)  # technique -> rule families tagged with it (or a sub)
    examples: dict[str, list[tuple[str, str]]] = field(default_factory=dict)  # technique -> [(logic_hash, title)]
    unknown: dict[str, int] = field(default_factory=dict)  # tags that are not ATT&CK ids in this version
    rules_with_tags: int = 0
    rules_total: int = 0
    public: Coverage | None = None
    tagged_rules: dict[str, int] = field(default_factory=dict)
    attack_rules: dict[str, int] = field(default_factory=dict)
    quiet_rules: dict[str, int] = field(default_factory=dict)
    rules_with_attacks: int = 0
    rules_quiet: int = 0
    normalisation: dict[str, dict[str, Any]] = field(default_factory=dict)

    def covered(self) -> int:
        """Techniques and sub-techniques with at least one rule family."""
        return sum(1 for t in self.matrix.techniques if self.families.get(t))


def coverage_key(ws: Workspace) -> tuple[str, int, int, int, int] | None:
    """Bind a projection to the pinned local matrix without network access."""
    path = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    if not path.is_file():
        return None
    stat = path.stat()
    return ATTACK_VERSION, stat.st_ino, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size


def coverage_tag_sets(matrix: Matrix) -> dict[str, list[str]]:
    """Exact tag unions for cells, resolving each catalog ID once per page.

    Parent cells include canonical children and their retired aliases. Building
    the reverse map avoids resolving the whole catalog again for every cell and
    every tactic in which that cell appears.
    """
    tags: dict[str, list[str]] = {tid: [] for tid in matrix.techniques}
    for tid in sorted({*matrix.techniques, *matrix.replaced}):
        resolved = matrix.resolve(tid)
        if resolved is None:
            continue
        tags[resolved].append(tid)
        parent = matrix.techniques[resolved].parent
        if parent in tags and parent != resolved:
            tags[parent].append(tid)
    return tags


def coverage_payload(cov: Coverage) -> dict[str, Any]:
    return {
        name: getattr(cov, name)
        for name in (
            "families",
            "examples",
            "unknown",
            "normalisation",
            "rules_with_tags",
            "rules_total",
            "tagged_rules",
            "attack_rules",
            "quiet_rules",
            "rules_with_attacks",
            "rules_quiet",
        )
    }


def stored_coverage(ws: Workspace, s: Session) -> Coverage | None:
    """Read complete published counts, offline."""
    from sigharvest.page_summaries import read

    stored = read(s, "attack_coverage", coverage_key(ws))
    if stored is None:
        return None
    matrix = cached_matrix(ws)
    if matrix is None:
        return None
    cov = Coverage(matrix, **stored)
    cov.examples = {key: [(logic, title) for logic, title in rows] for key, rows in cov.examples.items()}
    return cov


class _Counts:
    """Accumulate distinct identities for one visibility scope in a streaming pass."""

    def __init__(self, matrix: Matrix) -> None:
        self.cov = Coverage(matrix)
        self.families: dict[str, set[int]] = defaultdict(set)
        self.tagged: dict[str, set[str]] = defaultdict(set)
        self.attacks: dict[str, set[str]] = defaultdict(set)
        self.quiet: dict[str, set[str]] = defaultdict(set)
        self.examples: dict[str, list[tuple[float, str, str]]] = defaultdict(list)
        self.unknown: dict[str, int] = defaultdict(int)
        self.metadata_cache: dict[str, dict[str, Any] | None] = {}

    def add(self, row: tuple[Any, ...]) -> None:
        family_id, tags, score, logic, title, band, rate, detected = row
        cov, matrix = self.cov, self.cov.matrix
        cov.rules_total += 1
        if detected:
            cov.rules_with_attacks += 1
        for tid in detected or []:
            # Sample labels stay exact; parent rows include sub-techniques.
            for key in {tid, tid.split(".")[0]}:
                self.attacks[key].add(logic)
        identities = tag_metadata(tags or [], matrix, self.metadata_cache)
        for identity in identities:
            entry = cov.normalisation.setdefault(identity["original"], {**identity, "rules": 0})
            entry["rules"] += 1
        techs = [item for item in identities if item["domain"] == "enterprise"]
        if techs:
            cov.rules_with_tags += 1
            if band == "low" and rate is not None:
                cov.rules_quiet += 1
        for identity in techs:
            resolved = identity["current_id"]
            if resolved is None:
                self.unknown[identity["original_id"]] += 1
                continue
            for key in (resolved, matrix.techniques[resolved].parent):
                if key is None:
                    continue
                self.tagged[key].add(logic)
                if band == "low" and rate is not None:
                    self.quiet[key].add(logic)
                self.families[key].add(family_id)
                self.examples[key].append((score, logic, title or ""))

    def finish(self) -> Coverage:
        cov = self.cov
        cov.tagged_rules = {t: len(v) for t, v in self.tagged.items()}
        cov.attack_rules = {t: len(v) for t, v in self.attacks.items()}
        cov.quiet_rules = {t: len(v) for t, v in self.quiet.items()}
        cov.families = {t: len(v) for t, v in self.families.items()}
        cov.examples = {t: [(h, title) for _, h, title in sorted(v, reverse=True)[:10]] for t, v in self.examples.items()}
        cov.unknown = dict(sorted(self.unknown.items(), key=lambda kv: -kv[1]))
        return cov


def compute(ws: Workspace, s: Session, f: GroupFilters | None = None, query: str | None = None, *, acquire: bool = True) -> Coverage:
    """Selectable rule counts per ATT&CK technique, from declared rule tags."""
    from sqlalchemy import text

    from sigharvest.index import GroupFilters, _base

    matrix = load_matrix(ws, acquire=acquire)
    if f is None and not query:
        stored = stored_coverage(ws, s)
        if stored is not None:
            return stored
    counts = _Counts(matrix)
    base, _rank, params = _base(query, f or GroupFilters(), session=s)
    rows = s.execute(text("SELECT g.family_id, g.tags, g.score, g.logic_hash, g.title, NULL, NULL, NULL " + base), params)
    for row in rows:
        counts.add((row[0], json.loads(row[1]) if isinstance(row[1], str) else row[1], *row[2:]))
    return counts.finish()


def navigator_layer(cov: Coverage, name: str = "sigharvest coverage") -> dict[str, Any]:
    """An ATT&CK Navigator layer (format 4.5); score = number of rule families."""
    cov = cov.public or cov
    peak = max(cov.families.values(), default=1)
    techniques = []
    for tid in sorted(cov.families.keys() | cov.attack_rules.keys()):
        n = cov.families.get(tid, 0)
        tech = cov.matrix.techniques.get(tid)
        if tech is None:
            continue
        tactics: list[str | None] = list(tech.tactics) or [None]
        for tactic in tactics:
            entry: dict[str, Any] = {
                "techniqueID": tid,
                "score": n,
                "comment": f"{n} tagged rule families; {cov.tagged_rules.get(tid, 0)} tagged rules; "
                f"{cov.attack_rules.get(tid, 0)} Detects attacks; {cov.quiet_rules.get(tid, 0)} Quiet on benign data",
                "enabled": True,
            }
            if tactic:
                entry["tactic"] = tactic
            techniques.append(entry)
    return {
        "name": name,
        "versions": {"attack": cov.matrix.version.split(".")[0], "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Tagged rule families per technique, not demonstrated attack coverage, from sigharvest. {ATTRIBUTION}",
        "techniques": techniques,
        "metadata": [{"name": "ATT&CK normalisation", "value": json.dumps(list(cov.normalisation.values()), sort_keys=True)}],
        "gradient": {"colors": ["#ffffff", "#66b1ff", "#0b3d91"], "minValue": 0, "maxValue": peak},
        "legendItems": [],
        "showTacticRowBackground": False,
        "selectSubtechniquesWithParent": False,
    }


def write_layer(cov: Coverage, path: Path) -> None:
    """Write the coverage as an ATT&CK Navigator layer (JSON)."""
    path.write_text(json.dumps(navigator_layer(cov), indent=1), encoding="utf-8")
