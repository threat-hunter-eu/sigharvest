# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

Rule packs are versioned separately by date (`rules-YYYY-MM-DD`); their changes are in each release's
`RELEASE_NOTES.md` and `changes.json`.

## [Unreleased]

## [0.1.1] - 2026-11-23

### Security

- Hostile upstream rules can no longer stall or exhaust a workspace: scalar text after YAML alias expansion is capped
  at 2 MiB per document at ingest, and the `template_title` check, report/changes URL scrubbing, the rule-page
  condition highlighter, the site's licence links and the plain-language condition summary (now capped at 256 tokens
  or selection references) all run in linear time on long or repeated input. (thanks @elhoim)
- Terminal control characters (ESC/C0/C1) in upstream tags, descriptions, paths, queries and error messages are
  printed as U+FFFD by the CLI, and `site build` escapes Rich markup in release errors. (thanks @elhoim)
- Upstream file paths, titles and error text can no longer inject Markdown into `SKIPPED.md` or run reports.
  (thanks @elhoim)
- A `type: http` source with an `auth` token refuses a plain `http://` URL instead of sending the token in cleartext.
  (thanks @elhoim)
- Release rule paths starting with exactly `//` are made relative like any other rooted path. (thanks @elhoim)
- `export --format zip` never names the zip's top folder `..`, and a member whose collision retry name was taken is
  no longer written twice. (thanks @elhoim)

### Fixed

- A refused (busy) `init` on a new folder no longer deletes the lock file of the `init` that holds it, which let a
  third writer take the workspace lock at the same time. (thanks @elhoim)
- A source whose rules ship under more than one licence (a rule's own `license:` narrower than its source's) got the
  notice and licence text of only one of them in export and release bundles; the top-level `LICENSES.zip` of a release
  also kept only the copyleft pack's licence for such a source. Every licence now travels with its text, whether it is
  an SPDX id or the free text of a rule's `license:`. (thanks @elhoim)
- The web UI no longer freezes every request while `POST /export/download` builds its file (it now runs in a worker
  thread). (thanks @elhoim)
- An on-demand conversion slot whose idle worker died is restarted instead of failing every second conversion until
  the server restarts. (thanks @elhoim)
- `priority: 0` in sources.yaml is kept when the file is saved (it became the default 50). (thanks @elhoim)
- `dedupe --top N` picks the same canonical copy as the full report and the index. (thanks @elhoim)
- `search --all-copies` refuses the filters it cannot apply (it silently ignored them) and hides deprecated copies
  unless `--include-deprecated` is given. (thanks @elhoim)
- `%` and `_` in the tag, backend and flag search filters (CLI, web UI, API) match literally instead of as wildcards.
  (thanks @elhoim)
- `lint` reports the right line numbers in multi-document files. (thanks @elhoim)
- `sigharvest runs` without a subcommand prints the runs table. (thanks @elhoim)
- A SIGTERM during the start or the failure recording of `update` marks the run `cancelled` instead of leaving it
  `running`. (thanks @elhoim)
- `export --format yaml` keeps both rules when two would get the same file name (one was lost). (thanks @elhoim)
- Exports no longer abort when a rule's `license:` contains a backslash. (thanks @elhoim)
- The weekly discovery workflow only updates its own PR, never a fork PR with the same branch name. (thanks @elhoim)
- Source file links use the GitLab style only for GitLab URLs, not for any URL containing `gitlab.com`.
- Disk admission: the full-corpus nightly is no longer refused upfront, and validation and conversion charge only the
  rule versions still to test.
- `init --from-release` shows a realistic time estimate for the semantic hashes; `export --validation` in a workspace
  without validation results says what to run instead of "no rule matches these filters".
- Static site: its own 404 page and accessibility fixes (axe: 0 serious/critical).
- Docs: a working `--with-dependencies` example and measured `init --from-release` timings.

### Changed

- README, getting started and the CLI and web UI hints install the PyPI package
  (`uv tool install "sigharvest[convert]"`); installing from Git stays the development option.
- Disk admission for `sync`/`update` charges only the fetches that can run at once plus the database growth and
  checks each fetch when it starts; with `update` a fetch that does not fit is deferred to the next run. New settings
  `SIGHARVEST_DISK_SYNC_DB_SOURCE_BYTES` and `SIGHARVEST_GIT_CACHE=drop` (delete a git clone once ingested).
- Bundled source catalog: dead and junk-only sources removed (listed with the reason in `sources/denylist.yaml`),
  moved rule paths fixed, 3 new sources; a source whose upstream licence was removed is now metadata only.
- Repository layout: CONTRIBUTING, SECURITY and CODE_OF_CONDUCT in `.github/`, systemd units in
  `docs/deploy/systemd/`, the screenshot tour and How it works in `docs/features.md`.

## [0.1.0] - 2026-11-17

First public release.

### Added

- `init` with source presets (`curated` default, `sigmahq`, `all`) and `SIGHARVEST_HOME` workspaces.
- `update`: incremental Git fetch (plus HTTP archives/files, HTML pages, Hugging Face datasets and local folders),
  Sigma detection by content, safe YAML ingest with quarantine, pySigma validation and conversion with a result
  cache, full index rebuild, and update gates that keep the last good index when upstream breaks; run reports
  (`runs list/show/accept`).
- Deduplication by normalised logic hash, canonical copy by source priority, rule families, mirror detection and
  near-duplicate hints; quality score and quality flags.
- `search` with full-text query syntax and filters (logsource, level, status, ATT&CK, source, licence, validation,
  backend, number of sources, quality flag), one row per family or per logic, JSON output.
- `show`, `diff` and `convert` for single rules.
- `export` to Sigma YAML (folder or zip), JSONL, CSV and SIEM queries through pySigma backends, correlation
  dependency bundles, `NOTICE.md` and a manifest. The backends are optional extras: `[convert]` (pySigma 2: Splunk,
  Loki, SQLite) or `[convert-legacy]` (pySigma 1.5: those plus Elastic Lucene and ES|QL, OpenSearch and Microsoft 365
  Defender, until their backends support pySigma 2). The two extras are mutually exclusive.
- Collections: saved rule sets that follow upstream changes, exportable and shareable.
- `coverage`: ATT&CK summary, gap list and Navigator layer.
- `lint` for your own rules against the corpus or a release, with SARIF output, plus a composite GitHub Action.
- `sources` (list, add, remove, enable, disable) including local folders and private Git repositories.
- `changes` command (since the last published update, since a date, or between two releases; `--json`) and
  `changes.json` + Atom `feed.xml` in the static site. Runs that failed their gates are not reported.
- `init --from-release latest|URL|DIR`: a searchable workspace from a release pack without git (19,444 rules in
  about 1m10s on a busy 22-core machine, a line per step); `--sums-sha256` pins the pack to a digest obtained out
  of band.
- `--profile core|core+|core++|emerging-threats|all` for `search`, `export` and the web/API search: SigmaHQ's
  release packages (status, level, rule type from tags or SigmaHQ folders) applied to every source.
- Release packs and export zips ship `LICENSES/` (licence texts incl. DRL 1.1, each source's LICENSE / NOTICE
  files from its synced commit) and a `NOTICE.md` with per-source copyright lines, Apache NOTICE files and the
  MITRE ATT&CK terms; ATTRIBUTION.md links each licence and marks flattened (`modified`) and DRL-derived rules.
  Optional `copyright:` per source. Catalogs use current SPDX ids (`GPL-3.0-only`...).
- Web conversions run in bounded worker processes (time, memory, size and value caps); web downloads are queued
  (429 when full); expensive GET routes refuse cross-site requests.
- A first update that fails a gate, errors, is interrupted or never finishes (killed) marks the corpus **incomplete**
  in `search`, `stats`, `doctor` and the web UI; `release build` and `site build` refuse it, and an index that does
  not cover the corpus or is empty, unless `--allow-incomplete`. The next update records a killed run as
  interrupted.
- `discover`: find candidate repositories on GitHub and GitLab, verified by content; `--output` writes a review
  file with every candidate disabled.
- `serve`: local web UI (overview, search with facets, rule pages, compare, families, ATT&CK coverage, sources,
  collections, downloads) and a JSON API.
- `release build` (licence-split packs, `rules.jsonl.gz`, `index.json.gz`, provenance, Navigator layer,
  `changes.json`, `NOTICE.md`, checksums, reproducible with `--build-epoch`) and `site build` (static search site).
- `doctor`, `stats`, `dedupe`, `quarantine`, `db compact`, `report`.
- GitHub Actions: CI (ruff, mypy, pytest on both extras, offline acceptance harness, phone-width layout test in
  Chromium, privacy gate, actionlint), nightly update and
  release (Sigstore signature only on a public repository with `SIGHARVEST_SIGNING_ENABLED=true`; a killed update
  caches its progress), Pages, weekly discovery PR; all scheduled automation is opt-in.
- `docs/conventions.md`: what sigharvest and suriharvest keep identical (commands, errors, exit codes, JSON, workspace,
  variables, web UI, releases, repository layout).
- `sigharvest version` (version, database schema revision, main libraries) and `python -m sigharvest`.
- `sigharvest web`: hidden alias of `serve` (the name suriharvest used).
- `serve --token-env VAR`: HTTP Basic (any user name, the token as password) or Bearer authentication on every request.
- `--json` on `stats`, `runs list` and `sources list`; `search --all-copies --json`.
- `search` and `export --licence-class permissive|copyleft|restricted|none`: the web UI's licence filter (by the
  source's licence) on the command line; `export --licence` like `search --licence`.
- `update --wait SECONDS`: wait for a busy workspace instead of exiting 2 at once.
- `export --redistributable-only`, the explicit form of the default (pair of `--include-private-sources`).
- `docs/scheduling.md` and systemd units in `deploy/systemd/` (`sigharvest-update.service`, `.timer`,
  `sigharvest-update-failed@.service`).
- Issue template `config.yml` (no blank issues; security reports go to a private advisory).
- Full public corpus in the nightly build: `sources/curated.yaml` + `sources/extended.yaml` (about 1,200 repositories),
  with `update --time-budget MINUTES` (no fetch or conversion starts after the budget; the run indexes and commits
  what it did and the next update continues, sources never or least recently synced first) and `update
  --convert-scope canonical` (convert only the copy of each logic the index and releases read). A cold start is split
  over several nights; nothing is released until every source was synced once. See docs/automation.md.
- `update --sources` and `discover --known` are repeatable (the files are joined).
- 54 repositories re-added to `sources/extended.yaml` after a review of the dropped ones: each holds logic found in no
  other listed source (about 3,900 unique logic in total).
- Nightly: `SIGHARVEST_RULES_REPO` publishes the `rules-*` releases to a separate data repository through a GitHub App
  token (environment `rules-publish`, contents write on that repository only); unset, nothing changes. Signing
  requires both repositories to be public. `init --from-release latest` reads `threat-hunter-eu/sigharvest-rules`
  (`SIGHARVEST_RELEASE_REPO` overrides it) and falls back to this repository until the data repository has a
  release. See docs/automation.md#rules-repository.
- A git clone or fetch that stalls for 60 s or loses its connection is transient and retried twice per source; a
  failing summary report prints its cause and does not change the exit code of a passed run.

### Security

- CSV exports escape cells that would start a spreadsheet formula.
- Workflows: top-level `permissions: {}` with per-job minimums, every action pinned by commit SHA and uv by
  version, no setup-uv cache outside the read-only CI jobs, `persist-credentials: false`, no `${{ }}` inside `run:`
  scripts (enforced by `tests/test_workflows.py`).
- Release signing is fail-closed: a separate job signs only when the repository is public and
  `SIGHARVEST_SIGNING_ENABLED` is `true`. PyPI publishing runs only for a `v*` tag on a commit of `main` whose
  version matches `pyproject.toml`, through the protected `pypi` environment, behind `SIGHARVEST_PYPI_ENABLED`.
- Lock-time floor `opentelemetry-api>=1.45.2` (GHSA-mf5v-w3w3-f6cg); the open `diskcache` advisory of
  `[convert-legacy]` is documented in SECURITY.md. Dependabot proposes weekly grouped updates (actions and
  `uv.lock`; the pySigma family is updated by hand for both extras).
- Web UI: binds 127.0.0.1, refuses foreign `Host` headers, CSP and same-origin checks on expensive downloads, body
  size caps (chunked bodies included), bounded conversion workers and a download queue.
- Web downloads are written to a temporary file and sent from there: the build turn is free again as soon as the file
  is written, at most 8 downloads are sent at once (429 beyond), and a client that reads nothing for 30 s, or has not
  read the whole download after 600 s, is disconnected. Slow clients hold no download bytes in memory.
- `doctor`'s lock probe takes a shared lock, and a writer that finds the lock taken retries for 0.5 s before
  "workspace is busy": a monitoring `doctor` no longer makes a scheduled `update` fail.
- A search waits at most 1 s for a search slot (was 10 s, holding a server thread); `/api/search` and `/api/facets`
  refuse cross-site browser requests, like downloads.

[0.1.1]: https://github.com/threat-hunter-eu/sigharvest/releases/tag/v0.1.1
[0.1.0]: https://github.com/threat-hunter-eu/sigharvest/releases/tag/v0.1.0
