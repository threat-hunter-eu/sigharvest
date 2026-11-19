# Export

Pick rules with a search and filters (or a saved collection), then pick a format. One command.

```
sigharvest export [QUERY] [FILTERS] --format FORMAT --out PATH
```

- [Formats at a glance](#formats-at-a-glance)
- [Choosing which rules](#choosing-which-rules)
- [Sigma YAML (folder or zip)](#sigma-yaml-folder-or-zip)
- [JSONL and CSV](#jsonl-and-csv)
- [SIEM queries via pySigma](#siem-queries-via-pysigma)
- [ATT&CK Navigator layer](#attck-navigator-layer)
- [From the web UI](#from-the-web-ui)
- [Licences in exports](#licences-in-exports)
- [Build a release pack yourself](#build-a-release-pack-yourself)

## Formats at a glance

| `--format` | `--out` | You get |
|---|---|---|
| `yaml` (default) | new folder | One `.yml` per rule, plus `NOTICE.md` and `manifest.jsonl` |
| `zip` | `file.zip` | The same files in a zip |
| `jsonl` | `file.jsonl` | One JSON object per rule: metadata, licence, source link, conversions, YAML |
| `csv` | `file.csv` | Spreadsheet-friendly index (no YAML) |
| `splunk` | file | SPL queries |
| `lucene` | file | Elasticsearch / OpenSearch Lucene queries |
| `esql` | file | Elasticsearch ES\|QL queries |
| `opensearch` | file | OpenSearch queries |
| `microsoft365defender` | file | KQL for Microsoft 365 Defender advanced hunting |
| `loki` | file | Grafana Loki LogQL queries |
| `sqlite` | file | SQL for SQLite-based log stores |

The backend formats need the `[convert]` or `[convert-legacy]` extra (see
[which extra for which SIEM](#which-extra-for-which-siem)). Navigator layers come from `sigharvest coverage --navigator` (see
below). An export that selects no rule exits 1.

## Choosing which rules

`export` takes the same query and filters as `search`. Try the search first, then swap `search` for `export`:

<!-- doctest -->
```bash
sigharvest search lsass --product windows --level high
sigharvest export lsass --product windows --level high --out lsass/
sigharvest export lsass --product windows --licence-class permissive --format splunk --out lsass.spl
```

| Option | Effect |
|---|---|
| `--unit family` (default) | the best rule of each family: one rule per detection idea |
| `--unit logic` | every unique logic (variants included, copies not) |
| `--unit all` | every copy of every rule, from every source (the query then matches the document YAML as a substring) |
| `--collection NAME` | a saved collection (filters are ignored) |
| `--validation ok` | only rules that pass validation |
| `--backend NAME` | only rules a pipeline maps for that backend (does not set the format) |
| `--min-score N` | only rules with at least this quality score |
| `--include-deprecated` | also deprecated and unsupported rules (excluded by default) |
| `--include-junk` | also test fixtures, synthetic and wrapped-query documents (excluded by default) |
| `--rule-source NAME` | only rules carried by this source (keeps the canonical copy) |
| `--licence-class CLASS` | only rules from sources of this licence class: `permissive`, `copyleft`, `restricted` or `none` (family and logic units) |

`--profile core|core+|core++|emerging-threats|all` selects like SigmaHQ's release packages, on every source
([docs/cli.md](cli.md#profiles-sigmahq-packages)): `sigharvest export --profile core --format zip --out core.zip`.

## Sigma YAML (folder or zip)

<!-- doctest -->
```bash
sigharvest export --out all-rules/
sigharvest export --product windows --category process_creation --validation ok --out win-proc/
sigharvest export --technique T1059.001 --format zip --out powershell.zip
```

Each file holds the YAML of the rule's canonical copy as published by its source, so `author`, `references` and
the rest of the metadata stay intact (a rule that inherits from a legacy multi-document collection is written in
its effective, self-contained form). Files are laid out as `<product>/<category>/<title>_<logic8>.yml`;
`--unit all` writes every copy as `<rule id>_<content8>.yml`. `manifest.jsonl` lists, for every rule, its
sources, licence and canonical copy.

Correlation rules need the rules they reference. Select the correlations (at most 100 per export; here Yamato
Security's "PW Spray") and add the rules they reference with `--with-dependencies` (the destination must not exist):

<!-- doctest -->
```bash
sigharvest export 'title:"pw spray" OR title:"brute force correlation"' --unit logic --with-dependencies --out portable/
```

The export stops, and writes nothing, at the first selected rule it cannot package exactly: a correlation with
attributes it does not support, a reference that is missing or matches several rules, or a chain of correlations.
The error names the reason; narrow the search (or export that rule without `--with-dependencies`).

Load the result into other tools:

<!-- doctest: skip external tools (sigma-cli, Hayabusa) and an EVTX folder -->
```bash
sigma convert -t splunk -p sysmon win-proc/            # sigma-cli
hayabusa csv-timeline -d ./evtx -r win-proc/           # Hayabusa (Windows rules)
```

## JSONL and CSV

<!-- doctest -->
```bash
sigharvest export --format jsonl --out rules.jsonl
sigharvest export --product windows --format csv --out windows-rules.csv
```

JSONL has one object per line; handy with `jq`:

<!-- doctest -->
```bash
jq -r 'select(.level=="critical") | [.title, .source_url] | @tsv' rules.jsonl
```

JSONL fields: `logic_hash`, `content_hash`, `rule_id`, `family_id`, `title`, `level`, `status`, `logsource`,
`tags`, `attack`, `score`, `validation`, `converts`, `conversion`, `copies`, `sources`, `canonical_source`,
`source`, `source_url`, `licence`, `licence_from`, `licence_class`, `licences`, `rule_licence`,
`yaml_representation`, `context_digest`, `yaml`.

CSV columns: `logic_hash`, `rule_id`, `title`, `level`, `status`, `product`, `category`, `service`, `tags`,
`score`, `validation`, `converts`, `copies`, `sources`, `canonical_source`, `licence`. Every cell is quoted, and
cells that start with `=`, `+`, `-`, `@`, a tab or a carriage return (leading spaces ignored), or that hold one of
those right after a `;` or `,` (spreadsheets in `;`-separator locales split on it), get a leading `'` so
spreadsheets do not run them as formulas.

## SIEM queries via pySigma

sigharvest uses the official pySigma backends and pipelines. It orchestrates; pySigma does the conversion.

### Which extra for which SIEM

The backends come in two optional dependency sets that exclude each other (install one):

| SIEM | Target | `[convert]`: pySigma 2 | `[convert-legacy]`: pySigma 1.5 |
|---|---|---|---|
| Splunk | `splunk` | pysigma-backend-splunk 3.x | pysigma-backend-splunk 2.1 |
| Grafana Loki | `loki` | pysigma-backend-loki 0.16 | pysigma-backend-loki 0.15 |
| SQLite (Zircolite) | `sqlite` | pysigma-backend-sqlite 2.1 | pysigma-backend-sqlite 2.0 |
| Elastic (Lucene) | `lucene` | not available | pysigma-backend-elasticsearch 2.1 |
| Elastic ES\|QL | `esql` | not available | pysigma-backend-elasticsearch 2.1 |
| OpenSearch | `opensearch` | not available | pysigma-backend-opensearch 2.0 |
| Microsoft 365 Defender (KQL) | `microsoft365defender` | not available | pysigma-backend-kusto 1.0 |

"Not available" means the backend has no release for pySigma 2 yet (pysigma-backend-elasticsearch 2.1.1,
pysigma-backend-opensearch 2.0.3 and pysigma-backend-kusto 1.0.1 all require pySigma < 2). Each moves into
`[convert]` once it has one.

<!-- doctest: skip network (installs from PyPI) -->
```bash
uv tool install "sigharvest[convert]"         # Splunk, Loki, SQLite
uv tool install "sigharvest[convert-legacy]"  # all seven targets
```

A target whose backend is not installed is not offered in the web UI, and the CLI says which extra provides it.
Rule identities, logic and semantic hashes and validation are the same with either set. The query text differs
slightly: Splunk 3.x adds parentheses around `IN` lists and OR groups and fixes queries of rules with regular
expressions (`| rex`). pipeline-sysmon 3 adds `EventType` to registry add/delete rules, and pySigma 2 expands IPv6
CIDRs to Sysmon's uncompressed form. Conversion results are retested automatically when you switch, because the
toolchain fingerprint includes the backend versions.

<!-- doctest -->
```bash
# Splunk, Windows rules, Sysmon field names
sigharvest export --product windows --validation ok --format splunk --telemetry sysmon --out windows.spl

# Elastic Lucene, one technique
sigharvest export --technique T1003 --format lucene --out t1003.lucene

# Microsoft 365 Defender (KQL)
sigharvest export --product windows --level high --format microsoft365defender --out mde.kql

# Grafana Loki, Linux rules (no Loki pipeline maps Linux fields: --allow-raw keeps the Sigma field names)
sigharvest export --product linux --format loki --allow-raw --out linux.logql

# One rule, printed to the terminal
sigharvest convert 8c0b4bfbcc --target splunk --telemetry security
```

The query file starts with a header (rule counts and the toolchain) and has one block per rule. Next to it,
`<out>.manifest.jsonl` lists the exported rules and `<out>.conversion.jsonl` holds the full conversion result per
rule (status, pipelines, reason, fields).

`--telemetry` picks the input data the pipelines assume for Windows rules:

| `--telemetry` | Use when your Windows logs are |
|---|---|
| `sysmon` | Sysmon events |
| `security` | Windows Security log (4688 etc.) |
| `windows` | generic Windows channels |
| `mde` | Microsoft Defender for Endpoint tables |
| `all` (default) | try every mapping and keep what converts |
| `combined` | one query covering several mappings, when possible |
| `default` | the backend's default pipeline |

What can go wrong, and what sigharvest does about it:

- **A rule cannot be converted** for a backend (unsupported modifier, missing field mapping): it is skipped and
  counted in the header. `--backend NAME` pre-filters to rules that convert (it uses stored conversion
  results, so run `sigharvest update --convert` once first).
- **Queries that convert but fail a sanity check**: skipped unless `--allow-warnings`.
- **No pipeline applies** (for example a non-Windows logsource): skipped unless `--allow-raw`, which writes the
  query with the Sigma field names; you must map the fields yourself.

Always review queries before you deploy them: field names depend on your ingestion, not on Sigma.

Need a backend sigharvest doesn't ship (QRadar, Sentinel/Azure Monitor, Chronicle, ...)? Export YAML and use
`sigma-cli` with the plugin: `sigma plugin install <backend>`, then `sigma convert -t <backend> ...`.

## ATT&CK Navigator layer

<!-- doctest -->
```bash
sigharvest coverage --navigator layer.json
sigharvest coverage --product windows --validation ok --navigator windows-layer.json
```

The layer scores each technique by the number of rule families tagged with it. Open
<https://mitre-attack.github.io/attack-navigator/> -> *Open Existing Layer* -> *Upload from local*.
Releases also contain `attack-navigator-layer.json` for the whole corpus.

## From the web UI

Every search has an export link, and the Export page (`/export`, see [web.md](web.md)) offers the same
formats. The web UI's zip is the same file as `sigharvest export --format zip` (same code, same layout: a top
folder, then `permissive/` or `copyleft/`, the licence, product and category; NOTICE.md, LICENSES.md,
ATTRIBUTION.md, manifest.jsonl, provenance.json and SKIPPED.md).

## Licences in exports

- Every YAML export contains `NOTICE.md` (attribution, and the DRL-1.1 credit requirement) and `manifest.jsonl`
  (each rule's sources, licence and canonical copy). JSONL and CSV rows carry the licence of each rule. Query
  exports carry an `# attribution:` line per query plus `<out>.ATTRIBUTION.md` and `<out>.NOTICE.md`.
- The text of a rule is copied (zip, YAML folder, JSONL `yaml`, web downloads) only when its licence allows it and
  its source is marked redistributable in sources.yaml; other rules are listed in `SKIPPED.md` with a link (JSONL:
  `yaml` is null and `text_skipped` says why). The CLI and the web UI apply the same rule.
- `--include-private-sources` (web UI: "Private copy") copies those rules too, for your own use, for example your
  own rules added as a local source without a licence. NOTICE.md then says the export must not be shared.
  `--unit all` (every copy) is a working export of your workspace and copies every document.
- To produce something you can share publicly, build a release pack: it includes YAML only for permissive and
  copyleft rules and splits them by licence class (below).

## Build a release pack yourself

The nightly packs are built with:

<!-- doctest -->
```bash
sigharvest release build out/ --licence-class permissive --licence-class copyleft
```

It writes `rules.jsonl.gz`, `sigharvest-rules-permissive.zip`, `sigharvest-rules-copyleft.zip`, `index.json.gz`,
`provenance.json.gz`, `attack-navigator-layer.json`, `changes.json` (against `--previous DIR`), `manifest.json`,
`stats.json`, `RELEASE_NOTES.md`, `NOTICE.md`, `ATTRIBUTION.md` and `SHA256SUMS`. `--build-epoch` (or
`SOURCE_DATE_EPOCH`) makes the output reproducible. Details in [releases.md](releases.md).
