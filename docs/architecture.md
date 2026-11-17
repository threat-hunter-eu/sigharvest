# Architecture

A short map for contributors. sigharvest is a single Python package, a SQLite database and a few Jinja templates.
No server to run, no frontend build, no background daemon.

## Pipeline

```
sources.yaml -> sync -> ingest -> test -> index -> gates -> search / show / export / serve / release / site
                git      YAML      pySigma   logic hash, families,
               clones   documents  (cached)  canonical copy, FTS5
```

| Step | What happens | Key idea |
|---|---|---|
| sync (`sync.py`, `sync_remote.py`) | Bare, shallow, blob-filtered Git clones under `data/cache/git/`; incremental fetch and tree diff afterwards. Other source types download into `corpus/<name>/` | Git arguments validated, archive paths checked, size limits |
| ingest (`ingest.py`, `documents.py`) | Files that look like Sigma (by content) are split into YAML documents; each document's bytes give a `content_hash`; each occurrence (source, path, document index, commit) is recorded; broken YAML is quarantined | Safe loader with depth/node/alias limits; raw bytes kept |
| test (`testing.py`, `conversion*.py`) | Sigma JSON schema + pySigma validators, then conversion for each installed backend | Results keyed by rule version and toolchain, so unchanged rules are not re-tested; memory-capped worker processes |
| index (`index*.py`, `family_links.py`, `neardup.py`) | Full rebuild of the derived tables: one row per logic, canonical copy, families, mirrors, near duplicates, scores, FTS5 | One code path, no incremental state to get wrong |
| gates (`runs.py`, `publication.py`) | Compare totals with the last run that passed (unique logic drop, quarantine growth, failed sources, index complete) | A failed gate exits 1 and keeps the previously published index |

## Deduplication

1. **content_hash** = SHA-256 of the exact document bytes (plus inherited context for legacy multi-document
   collections). Identical documents anywhere are one version.
2. **logic_hash** = SHA-256 of a canonical form of `logsource` + `detection` (keys sorted, values normalised,
   condition whitespace and keywords normalised). Metadata (title, id, author, dates, references, description,
   level, status, tags) is ignored. The spec is [identity.md](identity.md). The hash prefix `sigharvest-logic-v1` is
   part of the hashed bytes; it is bumped only when the canonical form changes.
3. **Canonical copy** per logic: lowest source `priority`, then earliest seen.
4. **Mirrors**: a source with at least 80% of its logic contained in a larger source is a mirror; "independent
   sources" counts skip mirrors.
5. **Families**: logic groups linked by trusted (non-placeholder, non-ambiguous) rule ids, semantic hashes and
   `related:` links, only within the same normalised (product, category, service).
6. **Near duplicates**: MinHash over detection items (Jaccard >= 0.8). Display only; never merged.

## Data layout

```
$SIGHARVEST_HOME/
  sources.yaml            your source list
  corpus/<source>/        files of each source that look like Sigma
  data/sigharvest.db      SQLite (WAL)
  data/cache/git/         bare clones
  data/cache/             JSON schema, ATT&CK data, discovery and HTTP caches
  data/logs/              logs
  reports/                run reports (reports/runs/) and summary.md
```

Main tables (`models.py`, one Alembic baseline in `migrations/versions/0001_baseline.py`): `sources`, `sync_log`,
`rule_versions` (one per content hash, raw YAML), `occurrences` (where each version lives), `quarantine*`,
`test_runs` / `test_results` / `test_result_history` (validation and conversion results), `logic_groups` (derived,
one per logic hash), `index_*` and `near_duplicates` (families, signatures, near pairs), `source_overlaps` /
`source_roots` / `source_summaries` (mirrors and per-source counts), `collections` / `collection_items`,
`update_runs`, `correlation_references`, and the FTS5 table `rules_fts`.

## Code map

| Module | Responsibility |
|---|---|
| `cli/` | Typer commands (`pipeline.py`: init/update/sync/test/index, `browse.py`: search/show/diff, `export.py`, `sources.py`, `collection.py`, `health.py`, `serve.py`, ...); thin, calls into the modules below |
| `config.py` | workspace discovery (`SIGHARVEST_HOME` / nearest `sources.yaml`), `sources.yaml` load/save |
| `sync.py`, `sync_remote.py`, `source_snapshots.py` | Git and non-Git fetching, snapshots, incremental diffs |
| `documents.py`, `ingest.py`, `quarantine.py` | Sigma detection by content, safe YAML parsing, occurrences, quarantine |
| `identity.py`, `normalize.py`, `semantic.py` | hashes, rule ids, logsource/level/status/tag normalisation |
| `testing.py`, `schema.py`, `conversion*.py` | pySigma validation, JSON schema, conversion workers and results |
| `index*.py`, `family_links.py`, `neardup.py`, `quality*.py` | logic groups, canonical copies, families, mirrors, scores, quality flags, FTS |
| `query.py`, `search_*.py`, `selection.py` | search syntax, filters, facets |
| `export*.py`, `collections.py` | export formats, dependency bundles, saved collections |
| `attack*.py` | ATT&CK catalogue, coverage, Navigator layer |
| `licensing.py`, `release.py`, `release_reader.py` | licence classes, release packs, verified release reading |
| `lint.py` | linting user rules against the corpus, SARIF |
| `discover.py`, `discovery_*.py` | repository discovery |
| `runs.py`, `publication.py`, `lock.py` | update runs, gates, staged publication, the workspace lock |
| `web/` | FastAPI app, routes, Jinja templates, static CSS/JS (no build step) |
| `site/` | static site builder |

## Design rules

- **Never modify rule text.** Exports carry the YAML of the source copy.
- **Licence travels with the rule.** Every output path (export, release, site) carries the licence; releases
  check the licence class before including YAML.
- **Untrusted input everywhere.** Rule repositories are third-party content: validated Git arguments, no paths
  out of the clone, size limits, safe YAML, autoescaped HTML, no inline scripts (CSP).
- **Rebuild, don't patch.** The index is rebuilt fully on each update.
- **pySigma does conversion.** No custom backends. pySigma and backend versions are bounded because plugin
  upgrades change output.
- **No surprises in automation.** Discovery with `--output` never enables a source; releases are
  draft-then-publish and signed. See [automation.md](automation.md).
