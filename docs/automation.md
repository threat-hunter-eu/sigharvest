# GitHub Actions

sigharvest ships seven workflows in `.github/workflows/` and a reusable lint action (`action.yml`); [what runs when](#what-runs-when)
has the CI split.

| Workflow | Trigger | Jobs (permissions) | Output |
|---|---|---|---|
| `ci.yml` | push to any branch (not `data`), PR to main, manual | `lint` ruff, ruff format, mypy, actionlint; `test` pytest on 3.12 with [convert] + CLI contract smoke; `privacy` gate (all `contents: read`) | pass/fail |
| `ci-full.yml` | PR to main (not docs-only), daily 02:41 UTC when `SIGHARVEST_FULL_CI_ENABLED`, manual | `test` pytest on 3.13 [convert] and 3.12 [convert-legacy]; `layout` Playwright at 390 px; `windows` WSL refusal + portability tests; `acceptance` wheel install + offline first-run journey, locked/newest x convert/convert-legacy (all `contents: read`) | pass/fail |
| `ci-docs.yml` | PR to main, daily with `ci-full.yml`, manual | `docs` every `<!-- doctest -->` example on [convert] and [convert-legacy] (`contents: read`) | pass/fail |
| `nightly.yml` | `17 3 * * *` + manual (`force_release`, `cold_start`) | `build` (read) -> `sign` (id-token; only with signing on and the repository verified public) -> `publish` (contents write) -> `pages` (reusable, pages write); `keepalive` (contents write) | GitHub Release `rules-YYYY-MM-DD`, stats commit on the `data` branch |
| `pages.yml` | called by `nightly.yml`, manual, push of `src/sigharvest/site/**` | `build` (read; stops unless the repository is verified public) -> `deploy` (pages write, id-token) | GitHub Pages site |
| `publish.yml` | release `v*` published (not prerelease) | `build` (read; tag commit must be on `main`, no uv cache, `uv build --no-sources`) -> `publish` (environment `pypi`, id-token) | sdist + wheel on PyPI |
| `discover.yml` | `0 5 * * 1` + manual | `discover` (read) -> `pr` (contents + pull-requests write) | PR on branch `automation/discover` that only touches `sources/discovered.yaml` |
| `action.yml` | used by other repositories | composite: setup-uv, `sigharvest lint`, SARIF upload | code-scanning alerts |

## Principles

- `permissions: {}` at workflow level; each job asks for the minimum. Jobs that clone or parse untrusted third-party
  YAML (`update/build`, `discover/discover`) get a read-only token and `persist-credentials: false`. Write tokens
  live in small jobs that only move artifacts (`publish`, `pr`, `keepalive`); `pr` re-validates the artifact before
  committing it.
- Opt-in: nothing scheduled does any work until the repository variable `SIGHARVEST_AUTOMATION_ENABLED` is `true`.
  Forks and fresh copies do not inherit variables, so they stay quiet. Pages additionally needs
  `SIGHARVEST_PAGES_ENABLED=true` (the master switch stops Pages too).
- Signing is opt-in and public-only, and the gate fails closed (see [Signing](#signing)): keyless cosign writes a
  **public** Sigstore transparency-log (Rekor) entry whose certificate names the repository, workflow, ref, run and
  commit, and it cannot be removed. A private repository never signs, whatever the variable says, and its releases
  carry no `SHA256SUMS.sigstore.json` (verify them with `sha256sum --check SHA256SUMS`).
- Concurrency groups: `sigharvest-data` (update, never cancelled), `sigharvest-pages`, `sigharvest-discover`. The
  CI workflows cancel a superseded run of the same branch or pull request.
- Third-party actions are pinned to commit SHAs (the comment names the exact tag, so Dependabot can update both).
  uv itself is pinned in every `setup-uv` step (`version:`, a version that setup-uv release has a checksum for).
  gitleaks 8.21.2 (checksum verified) and actionlint 1.7.11 are pinned too; bump them deliberately.
- No `${{ }}` expressions inside `run:` scripts: values go through `env:`. Branch checks use
  `github.event.repository.default_branch || 'main'`, because `github.event.repository` is not guaranteed in a
  `schedule` payload.
- Only the check workflows (`ci.yml`, `ci-full.yml`, `ci-docs.yml`; read-only token) use the setup-uv cache. Every other `setup-uv` step (jobs that build releases,
  publish, deploy, push, or parse untrusted repositories, and `action.yml`) has `enable-cache: false`, so a cache
  entry written by another run cannot reach them and they never write one. `tests/test_workflows.py` enforces this,
  the uv pin, SHA pins and no `${{ }}` in `run:` scripts.

### Variables and secrets

| Name | Kind | Default | Purpose |
|---|---|---|---|
| `SIGHARVEST_AUTOMATION_ENABLED` | variable | unset (off) | enables `nightly.yml` and `discover.yml` |
| `SIGHARVEST_FULL_CI_ENABLED` | variable | unset (off) | `true` runs `ci-full.yml` and `ci-docs.yml` daily as well ([what runs when](#what-runs-when)) |
| `SIGHARVEST_PAGES_ENABLED` | variable | unset (off) | enables the Pages build and deploy (together with `SIGHARVEST_AUTOMATION_ENABLED`) |
| `SIGHARVEST_PYPI_ENABLED` | variable | unset (off) | `publish.yml` uploads `vX.Y.Z` releases to PyPI ([PyPI](#pypi)); `SIGHARVEST_PYPI_PUBLISH` is the deprecated old name |
| `SIGHARVEST_SIGNING_ENABLED` | variable | unset (off) | keyless cosign signature of `SHA256SUMS` in `publish`; only honoured on a **public** repository (see below) |
| `SIGHARVEST_KEEP_RELEASES` | variable | `30` | `rules-*` releases kept by the prune step |
| `SIGHARVEST_RULES_REPO` | variable | this repository | `owner/name` of the data repository that receives the releases ([Rules repository](#rules-repository)) |
| `SIGHARVEST_RULES_APP_CLIENT_ID` | variable | unset | client id of the GitHub App that publishes into `SIGHARVEST_RULES_REPO` |
| `SIGHARVEST_RULES_APP_KEY` | secret (environment `rules-publish`) | unset | that App's private key (PEM) |
| `SIGHARVEST_KEEP_MONTHLY` | variable | `12` | months for which the first `rules-*` release of the month is kept beyond `SIGHARVEST_KEEP_RELEASES` |
| `SIGHARVEST_STATS_BRANCH` | variable | `data` | branch for the stats / keep-alive commit |
| `SIGHARVEST_DISCOVERY_TOKEN` | secret | `GITHUB_TOKEN` | fine-grained PAT if `/search/code` returns 403: **public repositories, read-only, no other permission**. It is only in the collect step (API calls); the step that clones and parses untrusted repositories runs without it (`discover --collect-only`, then `discover --candidates`) |
| `SIGHARVEST_PR_TOKEN` | secret | `GITHUB_TOKEN` | GitHub App / PAT token so the discovery PR triggers CI |
| `SIGHARVEST_PRIVACY_TERMS` | secret | unset | project-specific privacy-gate rules (content of a terms file) |

Repository settings: Settings -> Actions -> General -> "Allow GitHub Actions to create and approve pull requests"
(for `discover.yml` with `GITHUB_TOKEN`); Settings -> Pages -> Source "GitHub Actions" (when Pages is enabled).

## CI

### What runs when

Actions minutes are billed for a private repository, each job rounded up to a whole minute and Windows at twice the
Linux rate, so the checks are split by cost. `tests/test_workflows.py` keeps the push set to the three jobs below.

| Event | Workflows | Jobs |
|---|---|---|
| push to any branch | `ci.yml` | `lint` (ruff, ruff format, mypy, actionlint), `test` (pytest, 3.12, [convert], `-n auto`), `privacy` (about 5 billed minutes) |
| pull request to main | `ci.yml` `lint` + `privacy` (and `test` for a fork's PR, whose branch had no push run here), `ci-full.yml`, `ci-docs.yml` | 3.13, [convert-legacy], layout, Windows, the acceptance matrix, the docs examples; a docs-only change (`*.md`, `docs/`) skips `ci-full.yml` but not the docs examples |
| daily 02:41 UTC | `ci-full.yml` + `ci-docs.yml` | as for a pull request, only when the repository variable `SIGHARVEST_FULL_CI_ENABLED` is `true` (default off: the jobs are skipped and nothing is billed) |
| manual (Actions -> Run workflow) | any of the three | everything in that workflow, on the branch you pick |

Make `ruff, mypy, actionlint` and `privacy gate` required status checks on main (Settings -> Branches) once the
repository is public: then no pull request, from a fork or Dependabot included, merges without them.

Every job has a `timeout-minutes`. The whole suite except the Windows job runs locally with one command (no Actions
minutes): `scripts/ci-full-local.sh` (`--quick` runs the push set only).

### Jobs

- `test` runs `uv sync --locked` (the dev group pulls in `sigharvest[convert]`, pySigma 2) and `pytest -n auto`
  on Python 3.12 (every push) and 3.13 (`ci-full.yml`), plus one job with `--no-default-groups --group test --extra convert-legacy` (pySigma 1.5,
  all seven backends). Tests of a target whose backend is not installed (`@pytest.mark.backend(...)` or a target in
  the parameter id) are skipped, so the Elastic, OpenSearch and MDE tests run in the legacy job. The tests are
  offline: local fixtures and local git repositories only.
- `acceptance` (`ci-full.yml`) runs `tests/acceptance/accept.sh sigharvest . --offline --extra EXTRA` for `convert` and
  `convert-legacy`, each with the versions of `uv.lock` (`--locked`) and with the newest versions the dependency
  ranges allow (what `uv tool install` gives a new user). It builds the wheel, installs `sigharvest[EXTRA]` from it into an empty environment (`env -i`, new `HOME`),
  then walks through `init`, `sources add/disable`, `update` (twice), search, show, every export format, `lint`,
  `release build`, `coverage --navigator` and every web page and JSON endpoint. Rule sources are local fixture git
  repositories built by `tests/acceptance/lib/make_fixtures.py`; only PyPI is contacted. See
  `tests/acceptance/README.md`.
- `privacy` runs `scripts/maintainer/privacy_gate.py --history` (stdlib only) over the tree and every commit: secrets (with
  gitleaks), private paths and hosts, files that must not be published (databases, keys, `.env`, office documents)
  and author/committer emails that are not noreply. Project-specific terms are kept out of the repository: the
  gate reads them from the file named by `SIGHARVEST_PRIVACY_TERMS` (format in `load_terms`); CI writes the
  repository secret of the same name to a temporary file, and runs only the generic rules (with a notice) when the
  secret is not set. Justified exemptions go to `.github/privacy-allowlist.txt`; unused entries are reported.

## nightly.yml

1. `build` (read-only, 300 min; the `update` step itself 270 min as a last resort)
   - `uv sync --locked --no-dev --extra convert` (`update --convert` stores conversions with every backend).
   - Workspace: `SIGHARVEST_HOME=.ws`, so the layout is `.ws/sources.yaml`, `.ws/data/sigharvest.db` and
     `.ws/data/cache/git/` (bare, shallow, blob-filtered clones). The cache holds `.ws/data` without `logs/`, key
     `sigharvest-ws-v1-Linux-YYYY-MM-DD`, restore-keys `sigharvest-ws-v1-Linux-` (newest earlier day).
     `cold_start` skips the restore. The database holds every ingested document, so `corpus/` is not cached.
   - `sigharvest update --convert --convert-scope canonical --time-budget 150 --sources sources/curated.yaml --sources
     sources/extended.yaml --workers N --allow-failures --max-failed-sources 10 --report-file ....json`: the full
     corpus, the same list as `init --preset all` (the `--sources` files are joined and replace the workspace
     `sources.yaml`; the database is created when missing). `--convert-scope canonical` converts only the copy of
     each logic that the index and the release files read. `--time-budget 150`: no fetch or conversion starts after
     150 minutes; validation, index, gates and the report still run and the run commits what it did. When sources
     were left (`counts.sources_deferred` in the JSON report) the step outputs `partial=true`: no release that night,
     the workspace is cached and the next night syncs the left sources first. See
     [Full corpus runtime](#full-corpus-runtime).
     A failed gate exits 1: no release, and the cache is not saved, so the last good snapshot survives. An
     update that is killed (step timeout, cancellation) or stops on an error (exit 2) saves its progress under
     `sigharvest-ws-v1-Linux-YYYY-MM-DD-partial-<run>-<attempt>`: the next night restores the newest entry and
     resumes (clones, ingested documents and committed conversion batches are kept; the killed run is recorded as
     interrupted), and the next successful run's snapshot supersedes it.
   - (complete runs only) The newest non-draft `rules-*` release: its `manifest.json` and `index.json.gz` go to `.out/previous`.
   - `sigharvest release build .out/release --licence-class permissive --licence-class copyleft --build-epoch <day>
     --previous .out/previous`, then `sha256sum --check SHA256SUMS`.
   - Change detection: `manifest.json` `content_id` against the previous release's (or `force_release`). The job
     summary shows the counts and the size of `changes.json` (`new`, `changed`, `removed`).
   - `PRAGMA wal_checkpoint(TRUNCATE)` (always, also after a failure), then the cache is saved when the update
     succeeded, even if a later step fails (skipped on an exact same-day hit: cache keys are immutable).
   - Artifacts: `release-files` (7 days) and diagnostics (`data/logs/`, `reports/runs/`, 14 days, always).
2. `sign` (only when the content changed and `SIGHARVEST_SIGNING_ENABLED=true`): checks the visibility through the
   API, then (verified public only) re-verifies the checksums and makes the keyless cosign signature
   `SHA256SUMS.sigstore.json`, handed to `publish` as an artifact. It is the only job with `id-token: write`.
   `publish` (only when the content changed; waits for `sign`, and does not run if signing was attempted and
   failed): checksums re-verified, signature added when `sign` made one, tag `rules-YYYY-MM-DD` (`.2`, `.3` on same-day reruns), created as a draft with all
   files, then made public and `--latest` (a half-uploaded release is never visible). Releases beyond
   `SIGHARVEST_KEEP_RELEASES` are deleted with their tags.
3. `pages` (only when published and Pages is enabled): calls `pages.yml` with the tag. Releases created with
   `GITHUB_TOKEN` do not fire `release:` events, hence the reusable call.
4. `keepalive` (build succeeded, and publish succeeded when the content changed): commits `stats/latest.json` (and a line in
   `stats/history.jsonl` when a release was made) to the `data` branch (orphan, created on first run). With nothing
   new it still makes an empty heartbeat commit when the branch head is 25 days old or more, so the schedule is not
   disabled for inactivity. Commit messages carry `[skip ci]`. If the schedule is disabled anyway, re-enable it with
   `gh workflow enable nightly.yml` or set `SIGHARVEST_STATS_BRANCH=main`.

### Release files

Release assets are a flat folder. Every file is listed in `SHA256SUMS`.

| File | Content |
|---|---|
| `rules.jsonl.gz` | one JSON line per rule (all licence classes): logic hash, rule id, title, logsource, level, status, tags, ATT&CK metadata, licence and class, canonical source URL + commit + path, sources, validation, conversion, quality flags; `yaml` only when the licence allows redistribution |
| `index.json.gz` | the same rules as one document (used by the site and by `--previous`) |
| `sigharvest-rules-permissive.zip` | YAML of rules whose licence class is permissive (DRL, MIT, Apache-2.0, BSD, ...) |
| `sigharvest-rules-copyleft.zip` | the same for copyleft licences (GPL, LGPL, MPL, ...), kept in a separate archive |
| `provenance.json.gz` | per published rule: source, commit, path, licence, author, content hash |
| `attack-navigator-layer.json` | ATT&CK Navigator layer (technique -> rule count) |
| `changes.json` | `{previous, new[], changed[], removed[]}` compared with `--previous` (`previous` is the old `content_id`) |
| `manifest.json` | `format`, `content_id`, `created`, sigharvest and pySigma versions, redistributed classes, `counts` (`rules`, `with_yaml`, `metadata_only`, per licence class), `sources[]` |
| `stats.json` | small summary for the `data` branch |
| `RELEASE_NOTES.md` | human summary (the release body) |
| `NOTICE.md`, `ATTRIBUTION.md` | attribution: every source with licence, URL, commit and rule count |
| `SHA256SUMS` | sha256 of every file above; `publish` adds `SHA256SUMS.sigstore.json` when signing is enabled (public repository only) |

`content_id` is a digest of the rule contents and counts only: it does not change with the build time, so an
unchanged corpus never produces a new release.

### What is published, by licence

Licence classes come from `src/sigharvest/licensing.py`: `permissive`, `copyleft`, `restricted`, `none`.

- **permissive** (DRL-1.1 of SigmaHQ, MIT, Apache-2.0, BSD, ...): YAML redistributed byte-identical (keeps
  `author:`), author and source link in every index row, attribution in `NOTICE.md`.
- **copyleft**: redistributed unmodified in a separate archive, with per-file source and commit.
- **restricted** (non-commercial, no-derivatives, source-available and custom licences) and **none** (no licence
  stated): metadata and a link only, never YAML. Only sources marked `redistribute: yes` ship rule text; a
  source without the field (or `no`/`unknown`) is treated the same way whatever its licence.
- The licence is always that of the copy whose text is shipped (its source's licence, read from `sources.yaml` at
  build time); a rule's own `license:` field can only narrow it, and another source's licence is never borrowed.
  Every archive carries `ATTRIBUTION.md` and `manifest.jsonl` (title, author, source, licence, link per rule), and
  query exports carry an attribution comment per rule.

This is not legal advice; the policy lives in code (`release.py`, `licensing.py`) and in `NOTICE.md`.

## Signing

`nightly.yml` has a separate `sign` job; `publish` keeps `contents: write` without `id-token: write`.

- The job runs only when `SIGHARVEST_SIGNING_ENABLED` is `true` and the content changed.
- Its first step asks the API, `gh api repos/$GITHUB_REPOSITORY --jq .private` with `GITHUB_TOKEN`, and sets
  `public=true` only when the answer is exactly `false`. An API error, an empty answer or `true` all give
  `public=false`. The download, cosign install and signing steps all require `public == 'true'` **and** the variable.
- The event payload (`github.event.repository.private`) is deliberately not used: `schedule` payloads are not
  documented to carry `repository`, and `!null` would be `true` (fail-open).
- `pages.yml` uses the same check and stops (red) when the repository is not verified public, because a Pages site
  is public even for a private repository.

## PyPI

`publish.yml` publishes a `vX.Y.Z` release (not a prerelease) with trusted publishing (OIDC). It is off until
`SIGHARVEST_PYPI_ENABLED=true` (the old name `SIGHARVEST_PYPI_PUBLISH` still works, with a deprecation warning in
the run). Before turning it on:

1. Settings -> Environments -> New environment `pypi`: **Required reviewers** = the owner ("Prevent self-review" once
   there are other maintainers); **Deployment branches and tags** = "Selected branches and tags" with one **tag**
   rule `v*`; no secrets.
2. On PyPI, the trusted publisher names this repository, workflow `publish.yml` **and** environment `pypi`.
3. Optionally, a tag ruleset on `v*` so only admins can create, move or delete release tags.

The `build` job refuses a tag whose commit is not on `main` (`git merge-base --is-ancestor "$GITHUB_SHA"
origin/main`), restores no uv cache (`enable-cache: false`), makes the README's relative image paths absolute
(`scripts/maintainer/pypi_readme.py`, so they show on PyPI) and builds with `uv build --no-sources`. Only the
`publish` job, inside the protected environment, has `id-token: write`.

## Repository settings checklist

For the public repository (nothing here is configured by the workflows): Dependabot alerts and security updates on;
private vulnerability reporting on (.github/SECURITY.md points to it); secret scanning and push protection on; the `pypi`
environment above; a ruleset on `main` (no force-push or deletion, PR required, "Require review from Code Owners"
for `.github/CODEOWNERS`, status checks `ruff`, `pytest`, `privacy gate`, `actionlint`); a ruleset on the `data`
branch (no force-push or deletion; pushes from Actions allowed). Turn `SIGHARVEST_SIGNING_ENABLED` on only there.

## Rules repository

The packs are published in a separate public data repository, `threat-hunter-eu/sigharvest-rules`, named by the repo variable
`SIGHARVEST_RULES_REPO` (`owner/name`). Unset, everything is published in this repository as before. The data repository
holds only releases `rules-YYYY-MM-DD`, a README, `LICENSE-NOTE.md` and its own `pages.yml` (the search site); it
runs no build. Users download from `https://github.com/threat-hunter-eu/sigharvest-rules/releases/latest/download/<file>`.

- Reads (previous release, gates): `GITHUB_TOKEN`, read-only, on the public data repository.
- Writes: only the `publish` job, through a GitHub App installed on the data repository alone (repository
  permission Contents: read and write, nothing else). `actions/create-github-app-token` mints a one-hour token for
  that one repository after every gate passed. The App's client id is the variable `SIGHARVEST_RULES_APP_CLIENT_ID`; its
  private key is the secret `SIGHARVEST_RULES_APP_KEY` of the environment `rules-publish` (deployment branches: `main`
  only), so no other job, branch or pull request can read it.
- Signing: the `sign` job signs only when **both** repositories are verified public (same fail-closed API check).
  The Sigstore identity stays this repository's `nightly.yml` on `main` (see .github/SECURITY.md).
- `publish` adds `build-info.json` (tool repository, commit, run URL; not in `SHA256SUMS`). The data repository's
  `pages.yml` runs on `release: published` (App-token releases fire it), checks that the commit is on this
  repository's `main` and builds the site with that commit. This repository's `pages` job and `pages.yml` are skipped
  while `SIGHARVEST_RULES_REPO` names another repository.
- Retention: the newest `SIGHARVEST_KEEP_RELEASES` (30) releases plus the first release of each of the newest
  `SIGHARVEST_KEEP_MONTHLY` (12) months; only `rules-YYYY-MM-DD[.N]` tags are ever deleted.
- Rulesets on the data repository: `main` requires a pull request (the App has no bypass, so it cannot push code);
  `rules-*` tags can be created and deleted only by the App and admins, and never moved; other tags only by admins.

## pages.yml

Downloads every asset of the release (all files listed in `SHA256SUMS` are verified by `site build`), reads the base
path and origin from `actions/configure-pages`, and runs `sigharvest site build _site --release rel --base-url
<path> --site-url <origin> --build-epoch <manifest created>`, so identical input gives an identical site. Files over
95 MB fail the build (Pages limit 100 MB). Pages on a private repository needs a paid plan, and the site of a private
repository is public unless the organisation uses Enterprise Cloud private Pages.

## discover.yml

Runs `sigharvest discover --output sources/discovered.yaml --known sources/curated.yaml --known sources/extended.yaml --denylist
sources/denylist.yaml --verify --min-rules 5 --max-repos 300 --max-code-requests 60 --max-http-requests 900
--workers 4 --cache-dir .ws/discover --report-file ...`. With `--output`, the workspace `sources.yaml` and the
curated lists are never edited and every candidate is `enabled: false`. A guard fails the job if any other file under
`sources/` changed or a candidate is enabled; the `pr` job checks the artifact again (shape, `enabled: false`,
GitHub/GitLab URLs only) before it commits. `--known` is given both lists, so only repositories that are in neither
are proposed. Adopting a source is always a manual edit of `sources/curated.yaml` or `sources/extended.yaml` in a
separate PR, after checking its licence.

## Rate limits and runtime

- update: git over HTTPS (not REST-metered) plus about 5-10 REST calls (`gh release ...`).
- discover: `--max-code-requests 60` at 10 code searches per minute is about 6-7 minutes; `--max-http-requests 900`
  caps every API call (`GITHUB_TOKEN`: 1,000 REST requests per hour per repository). Verification clones are cached
  per repository and push time in `.ws/discover`.
- Curated preset alone (before the nightly moved to the full corpus): the first run on `ubuntu-latest`
  (2026-11-14) fetched and ingested in about 6 minutes and converted the 22,901 rules; after the conversion fixes
  (linear Loki partitioning, largest rules first) the convert stage took 14 minutes locally with 4 workers.

### Full corpus runtime

What the nightly publishes since 2026-11-15: the full corpus, `sources/curated.yaml` + `sources/extended.yaml`
(about 1,200 repositories, the same list as `init --preset all`). Release packs stay split by licence class: YAML for
permissive and copyleft rules from sources marked redistributable (`redistributable: true` in the shipped lists; two zips), and for everything else (no
licence, restricted terms, sources not marked redistributable) metadata and a link to the original file only, in
`rules.jsonl.gz` / `index.json.gz`.

Measured cold run (2026-11-15, a 22-core machine, `init --preset all` then `update` without a time budget): 1,122 sources,
261,042 Sigma documents, 94,297 unique logic; about 1h12m in total (fetch and ingest 68 min, validation 2 min,
index 3 min) and about 16 GB on disk (git cache 9.7 GB, `corpus/` 4.1 GB, database 2.2 GB). The run behind the
first release pack (2026-11-16): 1,201 sources (1 failed to sync), 393,942 Sigma documents, 111,426 unique logic;
the pack (`rules-2026-11-17`) lists 98,733 rules, 66,986 of them with YAML. A GitHub-hosted
`ubuntu-latest` runner has 4 cores, a 6-hour job limit and a 10 GB cache per repository, so the nightly does not
assume a cold run fits one night:

- `update --time-budget 150`: no fetch, ingest or conversion starts after 150 minutes. Validation, index, gates and
  the report still run, and the run commits what it did. Sources never synced, then the least recently synced, go
  first next time, and conversions continue where they stopped (`--convert-scope canonical`: one copy per logic).
- A night that leaves sources unsynced (`counts.sources_deferred > 0`) caches its progress and publishes nothing
  (`partial=true` in the job summary); the next night resumes from the cache. The first release appears after the
  night on which every source was synced once.
- Later nights fetch only what changed (`git fetch --depth 1` per source).
- Cache size: the cached `.ws/data` of the measured run is about 12 GB before compression (git cache 5.7 GB,
  source snapshots 4.0 GB, database 2.2 GB), close to the repository's 10 GB Actions cache quota; GitHub evicts the
  oldest entries first, so only the newest snapshot is kept. If a save fails for size, the next night is a cold
  start again: watch the "Save workspace" step on the first full-corpus nights.
- Transient fetch failures (a clone that stalls for 60 s, a dropped connection) are retried twice per source; the
  38 failures of the measured run were 37 clones that stalled for 60 s (each cloned in seconds when tried again)
  and one repository that was too large (removed, see
  `sources/denylist.yaml`). Up to 10 % failed sources still pass the gate (`--max-failed-sources 10`).

## Failure modes and recovery

## Failure modes and recovery

| Failure | Effect | Recovery |
|---|---|---|
| A few sources fail to fetch | `--allow-failures` keeps going; failed sources keep their last ingested commit | fix or rename them in `sources/curated.yaml`; above `--max-failed-sources` (%) the gate fails |
| Gate failure (logic drop, too many failures) | build job red, no release, cache not saved | read the `update-report-*` artifact (`reports/runs/`); fix; re-run (or `cold_start: true`) |
| Cache evicted / corrupt database | cold start (slower, same output) | automatic, or a manual run with `cold_start: true` |
| Content unchanged | `publish` and `pages` skipped | none |
| Publish fails half-way | the release stays a draft | `gh release delete rules-... --yes`, re-run the failed jobs (artifact kept 7 days) |
| Signing enabled but `sign` fails (cosign, Rekor) | no release that night (publish waits for `sign`) | re-run the failed jobs; to release unsigned, unset `SIGHARVEST_SIGNING_ENABLED` and re-run |
| Pages not enabled | `configure-pages` fails with a clear error | enable Pages (Source: GitHub Actions) or unset `SIGHARVEST_PAGES_ENABLED` |
| `/search/code` 403 with `GITHUB_TOKEN` | discover finds fewer candidates | add the secret `SIGHARVEST_DISCOVERY_TOKEN` |
| Discovery PR does not run CI | expected with `GITHUB_TOKEN` | add `SIGHARVEST_PR_TOKEN`, or close and reopen the PR |
| Privacy gate finding | CI red | remove the finding or add a narrow, justified entry to `.github/privacy-allowlist.txt`; a leaked secret must be rotated and purged from history |
| Bad release published | users get bad data | `gh release delete <tag> --cleanup-tag` (the previous one becomes latest), fix, re-run with `force_release` |

## CLI contract the workflows rely on

`ci.yml` checks that these commands exist; the acceptance harness checks the flags.

- `sigharvest --version`; `SIGHARVEST_HOME` is the workspace root. Exit codes: 0 ok; 1 failed gate, failed sources
  (without `--allow-failures`), findings at or above `--fail-on`, or an empty export; 2 usage or I/O error (also a
  held workspace lock).
- `sigharvest update --sources FILE (repeatable) --workers N --allow-failures --max-failed-sources PCT --report-file
  PATH --time-budget MINUTES --convert-scope all|canonical`; the JSON report's `counts.sources_deferred` and
  `counts.conversions_deferred` say what a budget left for the next run.
- `sigharvest release build OUT --licence-class CLASS (repeatable) --build-epoch UNIX --previous DIR`.
- `sigharvest site build OUT --release DIR --base-url /path/ --site-url ORIGIN --build-epoch UNIX` (also
  `--max-pages`, `--max-files`).
- `sigharvest discover --output FILE --known FILE (repeatable) --denylist FILE --verify --min-rules N --max-repos N --workers N
  --max-code-requests N --max-http-requests N --reverify --cache-dir DIR --report-file PATH`; token from
  `GITHUB_TOKEN` (or `gh auth token`), never written anywhere. Two-step form: `--collect-only` (API, token, no
  clones) then `--candidates WORKSPACE/discovery/candidates.yaml` (clones, no token, no API calls).
- `sigharvest lint PATHS... --release URL|DIR --sarif FILE --fail-on error|warning|note|never`.

## The lint action

```yaml
permissions:
  contents: read
  security-events: write   # SARIF upload
steps:
  - uses: actions/checkout@v4
  - uses: threat-hunter-eu/sigharvest@<commit SHA or tag>
    with:
      rules: rules
      fail-on: error
```

`release` defaults to the newest `rules-*` data release of the repository the action comes from. The action runs the
sigharvest of its own checkout with the versions of its `uv.lock` (`uv run --locked --project <action path>`), so
pin it to a commit. Outputs: `sarif` (path) and `exit-code`.
