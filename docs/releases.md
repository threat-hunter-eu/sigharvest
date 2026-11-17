# Releases

`sigharvest release build OUT` writes a licence-aware snapshot of the whole index:

| file | content |
|---|---|
| `rules.jsonl.gz` | one line per unique logic: ids, title, logsource, tags, level, status, family, sources, validation, conversion status per backend, quality flags, licence and licence class, a link to the canonical copy, and the YAML text when the licence allows redistribution |
| `sigharvest-rules-permissive.zip`, `sigharvest-rules-copyleft.zip` | the redistributable YAML of each licence class, as `<product>/<category>/<title>_<logic8>.yml`, with `NOTICE.md` |
| `index.json.gz` | compact metadata for search front ends |
| `provenance.json.gz` | canonical copy, sources and licence of every rule |
| `attack-navigator-layer.json` | tagged rule families per ATT&CK technique |
| `changes.json` | new, changed (same rule id, new logic) and removed rules since `--previous DIR` |
| `manifest.json` | format, build time, versions, counts, sources and `content_id` |
| `stats.json`, `RELEASE_NOTES.md`, `NOTICE.md`, `ATTRIBUTION.md` | summaries and attribution |
| `SHA256SUMS` | checksums of every file above |

<!-- doctest -->
```bash
sigharvest release build release/ --previous last-release/ --build-epoch 1793059200
```

- **Licences**: YAML is included for the `permissive` and `copyleft` licence classes by default
  (`--licence-class` repeatable), and only from sources marked `redistribute: yes` in `sources.yaml` (`sources add --licence MIT` sets it
  for permissive and copyleft licences; `--no-redistributable` opts out). Rules without a stated licence, and
  sources whose `redistribute` is unset, `no` or `unknown`, are published as metadata and a link only. "Metadata" means short factual fields: ids, title, logsource, level, status, tags/ATT&CK, sources,
  validation and the link. The rule's `description` and `author` (free text written by its authors) are left out
  (`null`) for these rules, in `rules.jsonl.gz`, the derived files and the static site; the title is kept as a short
  factual label, like a file name.
- **Licence texts and notices**: each rule zip has a `LICENSES/` folder, and the release a `LICENSES.zip` with the
  same content: the full text of every licence shipped (SPDX copies; the Detection Rule License 1.1 from
  SigmaHQ/Detection-Rule-License), and each source's own `LICENSE` / `COPYING` / `NOTICE` files taken from the root
  of its synced commit (never other files), so the publishers' copyright lines and Apache `NOTICE` files travel
  with their rules. `NOTICE.md` lists every source with its licence (linked), its copyright lines (the optional
  `copyright:` field of sources.yaml first, then the lines found in its licence files) and any `NOTICE` file
  verbatim, plus MITRE's ATT&CK copyright and terms-of-use link when rules carry ATT&CK names.
- **Marks in ATTRIBUTION.md and manifest.jsonl**: `modified` when the shipped YAML is the effective document
  flattened from a legacy multi-document collection; `drl_origin` when the rule id belongs to a rule that a DRL
  source carries (or whose own `license:` names the DRL) while the copy shipped is under another licence: keep its
  author and link, as the DRL asks. This is matched by rule id; an edited copy that changed its id is not detected. Licences are read from
  `sources.yaml` at build time, so an edited licence applies without an update.
- **Reproducible**: with the same database, options and `--build-epoch` (or `SOURCE_DATE_EPOCH`) the bytes are
  identical. `manifest.json`'s `content_id` depends only on rule contents and counts, so two builds of the same
  corpus share it even with different build times.
- **Atomic**: the release is written to a sibling directory, verified, then swapped in; a failed build leaves the
  previous output intact. Existing non-empty outputs must be valid releases.

## Reading releases

`lint --release` and `site build --release` read releases through one verifier: every file listed in
`SHA256SUMS` is checked and every row validated, with byte, line and row limits. A release on a web server can be
used directly: `sigharvest lint my-rules/ --release https://example.org/releases/latest/` (HTTPS only).
