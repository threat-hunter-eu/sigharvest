# Rule identity

Every Sigma document in the corpus gets the four keys below; each answers a different question. A fifth, the
semantic hash, links rules whose detection is written differently (see [What is deliberately not normalised](#what-is-deliberately-not-normalised)).

| key | question it answers | computed from |
|---|---|---|
| `rule_id` | "Which rule is this, according to its author?" | the `id` field |
| `content_hash` | "Have I seen these bytes and inherited context before?" | raw document bytes plus context for legacy children |
| `logic_hash` | "Does this detect the same thing as another rule?" | `logsource` + `detection` only, canonicalised |
| `title_slug` | "Is this probably the same idea under a different name?" | the title, normalised |

Implementation: `src/sigharvest/identity.py`. Golden tests: `tests/test_identity.py`.

## rule_id

- The `id` field, parsed as a UUID and written in canonical lower-case form (`502b42de-4306-40b4-9596-6f590c81f073`).
- If `id` is missing, sigharvest generates `uuid5(SIGHARVEST_NAMESPACE, logic_hash)` and flags the version `id_missing`.
  `SIGHARVEST_NAMESPACE = uuid5(NAMESPACE_URL, "https://github.com/threat-hunter-eu/sigharvest")` (a fixed constant).
  Two copies of the same id-less rule therefore get the same generated id, wherever they live.
- If `id` is present but not a valid UUID (for example `a1f2e3d4-5678-9abc-def0-php2shell001`), the same fallback is
  used and the version is flagged `id_invalid`.

## content_hash

For ordinary documents, SHA-256 of the raw bytes of one YAML document.

- For a single-document file this is the hash of the whole file.
- Multi-document files are split on lines that consist of `---` (optionally followed by a comment). Each document
  keeps its exact bytes, including comments and whitespace, and is hashed on its own. The file hash is stored
  separately on the occurrence (`occurrences.file_hash`).
- Legacy 1.x collections (`action: global`) are expanded: the global document is merged into each following document.
  Their content hash includes the inherited context digest; the version is flagged `legacy_collection`.
  See [Effective legacy collections](#effective-legacy-collections) for the versioned formula and migration.

## logic_hash

`SHA-256( "sigharvest-logic-v1" + "\n" + canonical_json )` where `canonical_json` is the JSON serialisation of the
canonical form below with `sort_keys=True`, `ensure_ascii=False`, separators `(",", ":")`, encoded as UTF-8.

The YAML is parsed with a SafeLoader that does not convert timestamps, so quoting differences such as `'4688'` vs
`4688`, `"a"` vs `a` or flow vs block style disappear at parse time.

### Rules (`detection` + `logsource`)

```json
{"kind": "rule", "logsource": {...}, "detection": {...}}
```

**logsource**: every key except `definition` (free text), with key and value lower-cased and stripped. `null` values
are dropped.

**detection**: each key is kept by name.

- `condition`: tokenised into `(`, `)` and runs of non-space characters; keywords `and or not of them all 1 by count
  near` are lower-cased; identifiers keep their case; tokens are joined with a single space. **Order is kept** - the
  condition is not reordered or simplified. A list of conditions keeps its order.
- `timeframe`: lower-cased string.
- every other key is a search identifier:
  - a **map** (fields ANDed together) becomes `{"map": [[key, value], ...]}` sorted by the JSON of each pair;
  - a **list** (OR of maps or keywords) becomes `{"or": [...]}`, items canonicalised, de-duplicated and sorted by
    their JSON;
  - a **scalar** becomes `{"keyword": value}`.
- map keys `field|mod1|mod2`: the field name is stripped but keeps its case (Sigma field names are case-sensitive);
  modifiers are stripped and lower-cased; **modifier order is kept** (`base64offset|contains` is not
  `contains|base64offset`).
- values:
  - a value list is de-duplicated and sorted (both OR lists and `|all` lists are order-independent);
  - numbers become strings (`4688` and `'4688'` match the same events);
  - booleans and `null` stay as they are;
  - strings are Unicode NFC-normalised and **case-folded**, because Sigma string matching is case-insensitive -
    except when one of the modifiers `cased re base64 base64offset utf16le utf16be utf16 wide fieldref` is present,
    where case is significant;
  - whitespace inside values is never changed (it is significant in command lines).

### Filters (`filter` + `logsource`)

```json
{"kind": "filter", "logsource": {...}, "filter": <detection rules above, without "rules">, "rules": [sorted rule refs]}
```

### Correlations (`correlation`)

```json
{"kind": "correlation", "correlation": {...}}
```

Keys lower-cased, strings case-folded, numbers as strings, **list order kept** (rule references, group-by fields).

### What is deliberately *not* normalised

- Search identifier names. `selection` and `sel` with identical content produce different hashes, because the
  condition refers to them by name (and patterns such as `1 of selection_*` depend on the names).
- Logically equivalent but structurally different detections (`a and b` vs `b and a`, De Morgan rewrites,
  `|contains` vs `*x*` wildcards). A second, semantic hash over pySigma's parsed condition tree (`semantic.py`) links rules whose detection is the same but written differently; both hashes feed rule families ([concepts.md](concepts.md#families)).

### Versioning

Any change to the canonical form changes stored hashes. The prefix `sigharvest-logic-v1` is part of the hashed bytes;
a change must bump it and ship a migration that recomputes `rule_versions.logic_hash`.

## title_slug

Unicode NFKD, non-ASCII dropped, lower-cased, every run of characters outside `[a-z0-9]` replaced by `-`, trimmed.
`"Suspicious  PowerShell -- Download (Cradle)!"` -> `suspicious-powershell-download-cradle`.
Used only to report near-duplicates (same slug, different logic).

## Dedupe policy

| situation | meaning | what sigharvest does |
|---|---|---|
| same `content_hash` in several places | exact copy | one version, several occurrences |
| same `logic_hash`, different content | duplicate logic | all kept; the canonical copy is the one from the source with the lowest `priority` number, then the earliest first seen |
| same `rule_id`, different `logic_hash` | conflicting versions | all kept as history of that id; reported as a warning |
| same `title_slug`, different `logic_hash` | possible near-duplicate | reported only |

## Effective legacy collections

A legacy 1.x collection (`action: global`) is expanded into standalone documents. For ordinary documents the
content hash stays the SHA-256 of the original bytes; `LOGIC_VERSION` and the logic and fallback UUID algorithms do
not depend on this. A child that inherits from `action: global` gets this content identity:

```text
SHA256(b"sigharvest-effective-v1\n" + context_digest.encode("ascii") + b"\n" + original_child_bytes)
```

- The context digest is the SHA-256 of the exact global chunk, including its separator where present.
- `action: repeat` uses the preceding effective document as context and overlays its own fields.
- A new global replaces the template; `action: reset` clears both the template and the repeat predecessor.
- A malformed action document blocks the children that depend on it until a valid global or reset.
- Duplicate explicit keys are errors, reported with both document-local line and column positions. YAML `<<`
  inheritance allows explicit overrides and keeps SafeLoader's merge-list precedence.
- The usual byte, depth and expanded-node limits apply; the effective YAML is capped at 2 MiB per document and
  16 MiB per input file. Scalar text after alias expansion is capped at 2 MiB per document, so one large
  anchored value cannot be repeated through many aliases.

Where the bytes live:

- `RuleVersion.original_raw` stores the exact child bytes; `Occurrence.span_start` / `span_end` locate that slice in
  the file identified by `file_hash`.
- `RuleVersion.raw` is the standalone YAML used for validation, conversion, checks, export and display. It is
  re-serialised only for legacy children; export manifests and release rows then mark it
  `yaml_representation: effective`. This does not mean the upstream file was rewritten.
- The original child bytes stay in the database after the source is removed. Full historical source files are not
  archived. Rows ingested before this format have null provenance rather than invented original bytes.
