# Getting started

This page takes you from nothing to a searchable, deduplicated Sigma index in one sitting (the first update of the curated preset takes about ten minutes; see [measured timings](#measured-timings)).

- [1. Install](#1-install)
- [2. Create a workspace](#2-create-a-workspace)
- [3. Collect the rules](#3-collect-the-rules)
- [4. Look around](#4-look-around)
- [5. Keep it up to date](#5-keep-it-up-to-date)
- [Add your own sources](#add-your-own-sources)
- [Workspace layout](#workspace-layout)
- [No install: use a release pack](#no-install-use-a-release-pack)
- [Uninstall](#uninstall)

## 1. Install

Requirements: **Python 3.12 or newer**, **Git**, and either [uv](https://docs.astral.sh/uv/) or
[pipx](https://pipx.pypa.io/). Linux and macOS are supported; on Windows use WSL.

<!-- doctest: skip network (installs from GitHub) -->
```bash
# with uv (recommended)
uv tool install "sigharvest[convert] @ git+https://github.com/threat-hunter-eu/sigharvest"

# or with pipx
pipx install "sigharvest[convert] @ git+https://github.com/threat-hunter-eu/sigharvest"

sigharvest --version
```

Both put a `sigharvest` command on your PATH in its own isolated environment. The `convert` extra installs the
pySigma 2 query backends for Splunk, Loki and SQLite. For Elasticsearch/ES|QL, OpenSearch or Microsoft 365
Defender install `convert-legacy` instead (pySigma 1.5, all seven backends); see
[which extra for which SIEM](export.md#which-extra-for-which-siem). Without either extra
everything else works (collection, deduplication, search, validation, YAML/zip/JSONL/CSV exports, releases, the
web UI); `convert`, the backend export formats and the convert test stage are unavailable and say how to install
the extra.

Upgrade later with `uv tool upgrade sigharvest` or `pipx upgrade sigharvest`.

### Windows: use WSL

sigharvest runs on Linux and macOS. Its workspace lock uses POSIX `flock` and the conversion workers rely on Linux
process and memory limits, so native Windows is refused with a message pointing here. Install
[WSL](https://learn.microsoft.com/windows/wsl/install) (`wsl --install` in an administrator PowerShell, then reboot)
and run the commands above inside the Ubuntu shell. Keep the workspace on the Linux file system (for example
`~/sigharvest`), not under `/mnt/c`: it is much faster there, and Windows path-length limits do not apply. The web
UI started with `sigharvest serve` inside WSL opens from a Windows browser at the same `http://localhost:...` address.

From a clone, for development:

<!-- doctest: skip network (clones the repository) -->
```bash
git clone https://github.com/threat-hunter-eu/sigharvest && cd sigharvest
uv sync                      # dev dependencies include the [convert] extra
uv run sigharvest --help
```

## 2. Create a workspace

A workspace is a folder that holds your source list, the Git clones and the SQLite database.

<!-- doctest -->
```bash
sigharvest init ~/sigma
cd ~/sigma
```

### Quick start from a release pack (about ten minutes, no git)

<!-- doctest -->
```bash
sigharvest init ~/sigma --from-release latest     # or a release download URL, or a local release folder
cd ~/sigma && sigharvest search mimikatz
```

Measured with the full nightly pack (`rules-2026-11-19.2`: 66,887 rules from 595 sources, 2026-11-19, 22-core WSL2
machine shared with other jobs): about 8 minutes in total. Downloading and checking the pack takes under a minute,
reading the rules into the database, one after another, about 6 minutes, and the index (semantic hashes, families,
full-text) about 2 minutes. Progress lines (`ingest: ...`, `index: ...`) show each step, also in a log or pipe.

This downloads the nightly release pack (every file checked against its `SHA256SUMS`), writes its redistributable rules (permissive and
copyleft, with their original paths) into `data/release/`, registers one local source per original source
(`release-<name>`, with that source's licence and its LICENSE / NOTICE files) and indexes them. Search, export,
`serve` and `site build` work at once. Rules that the pack only lists as metadata (no licence, restricted terms)
are not included. The rules are not validated yet, so `--validation ok` selects nothing until
`sigharvest test --stage validate` (about 4 minutes for the full pack) or `sigharvest update` has run. To move to
the live repositories, run
`sigharvest init --force` (the curated preset) and then `sigharvest update`. `latest` is the newest `rules-*`
release of `threat-hunter-eu/sigharvest-rules`, or of this repository (with a one-line note) while that one has none yet
(`SIGHARVEST_RELEASE_REPO=owner/repo` to use another one, without fallback); it needs a published `rules-*` release
that you can reach (otherwise give a release download URL or a local release folder).

The checksums come from the same place as the files: they prove the pack is intact, not who published it. The
pack's licences become your workspace's licences, so pin it when that matters: `--sums-sha256 <digest>` refuses the
pack unless the SHA-256 of its `SHA256SUMS` is the digest you obtained separately (for example from the release
notes or a signed message). A pack built from a partial corpus (`manifest.json` `"incomplete": true`) is flagged by
`init` and refused by `site build --release` unless you pass `--allow-incomplete`.

### Live sources

`init` writes `sources.yaml` from a preset:

| Preset | Sources | First update | Use it when |
|---|---|---|---|
| `curated` (default) | 26 repositories with original content (SigmaHQ, Yamato Security, Trend Micro, LOLDrivers, ...); 23 have a licence that allows sharing, the other 3 are indexed and linked, never copied into exports | about 10 minutes (every rule is validated once; queries are converted on demand) | you want the good stuff, fast |
| `sigmahq` | SigmaHQ's core rules only (`rules/`; no emerging-threats, threat-hunting or DFIR folders, so `--profile et` finds nothing) | minutes | you want a small, well-known baseline |
| `all` | curated + about 1,180 more public repositories (about 1,200) | about 1h12m on a 22-core machine, about 16 GB of disk (`update --time-budget MINUTES` runs it in pieces) | you want everything public, including the rules that are only indexed locally; for the redistributable part, `init --from-release latest` is minutes |

<!-- doctest -->
```bash
sigharvest init ~/sigma-all --preset all
```

`init` refuses to replace an existing `sources.yaml` unless you pass `--force` (the database and clones are kept).
`update --sources FILE` uses another sources file instead; it replaces the workspace's `sources.yaml`.

Every command finds its workspace like this:

1. `SIGHARVEST_HOME`, if it is set;
2. otherwise the current folder or the nearest parent folder with a `sources.yaml`.

<!-- doctest -->
```bash
export SIGHARVEST_HOME=~/sigma     # now sigharvest works from any folder
```

## 3. Collect the rules

<!-- doctest -->
```bash
sigharvest update
```

`update` does everything in one go:

1. **sync**: clones each enabled source (shallow, blob-filtered), or fetches only what changed since last time;
2. **ingest**: recognises Sigma by content, splits YAML documents safely, records where each copy lives, and
   quarantines broken YAML ([quarantine.md](quarantine.md));
3. **validate**: checks new rule versions with pySigma and the Sigma JSON schema (results are cached per version
   and toolchain, so unchanged rules are skipped);
4. **index**: computes the logic hash of every rule, groups copies and families, picks canonical copies, scores
   and rebuilds the full-text index;
5. **gates**: compares the result with the last run that passed (unique logic drop, quarantine growth, failed
   sources, index complete), so a broken upstream cannot silently wipe half your index. A failed gate keeps the
   previous index.

**The very first update** has no previous index to keep, so it saves its work as it goes (a Ctrl+C or a crash
resumes instead of starting over). If it then fails a gate, errors or is interrupted, the corpus you see is
partial: `search`, `stats`, `doctor` and every web UI page say **corpus incomplete**, and `release build` /
`site build` refuse to publish it (`--allow-incomplete` publishes anyway; the release manifest then carries
`"incomplete": true`). Fix the cause and run `sigharvest update` again, or keep what you have with
`sigharvest runs accept latest` (only for a failed gate).

A source that fails (deleted repository, network error) does not stop the others; it keeps its last good copy and
is listed in the report. Exit codes: `0` ok, `1` a gate failed or sources failed (`--allow-failures` tolerates
failed sources), `2` error. Each run writes a report to `reports/runs/` (`--report-file PATH` copies it).

SIEM queries are **converted on demand**, not during `update`: a rule page converts the query tab you open,
`sigharvest convert KEY` and `sigharvest export --format splunk ...` convert what they need (repeated conversions
in one process come from a cache). Converting every rule into seven backends takes far longer than everything
else, so it is opt-in: `sigharvest update --convert` (or `sigharvest test --stage convert`) stores a result for
every rule, which the "converts to" filter (`search --backend`), conversion status in release metadata and the
conversion part of the quality score use; once a workspace stores conversions, later updates keep them current
for new rules. The nightly release workflow runs `update --convert`.

The single steps are also commands: `sigharvest sync`, `sigharvest test`, `sigharvest index`, `sigharvest report`.

## 4. Look around

From the terminal:

<!-- doctest -->
```bash
sigharvest search "credential dumping" --product windows
sigharvest show 8c0b4bfbcc          # a rule key from search (here SigmaHQ's "HackTool - Mimikatz Execution")
sigharvest coverage --gaps          # ATT&CK techniques with no tagged rule in the selection
sigharvest stats                    # rules and sources
sigharvest doctor                   # is the workspace healthy?
```

In the browser:

<!-- doctest: skip long-running server -->
```bash
sigharvest serve                    # http://127.0.0.1:8799
```

The web UI has an overview, search with facets, rule pages (YAML, copies, family, conversions), compare, ATT&CK
coverage with a Navigator layer, sources, collections and downloads, plus a JSON API. It listens only on
`127.0.0.1` by default, where it has no login; any other address needs a token (`--token-env VAR`, see
[web.md](web.md)).

Next: [CLI recipes](cli.md), [Web UI](web.md) and [Export](export.md).

## 5. Keep it up to date

Run `sigharvest update` whenever you want fresh rules; it only downloads what changed. To see what the last update
did:

<!-- doctest -->
```bash
sigharvest runs list
sigharvest runs show latest
```

Daily, with cron:

```cron
17 6 * * *  SIGHARVEST_HOME=$HOME/sigma  $HOME/.local/bin/sigharvest update --allow-failures --wait 600 >> $HOME/sigma/update.log 2>&1
```

systemd units, the gates and what a failed run means: [scheduling.md](scheduling.md).

If you remove a large source on purpose, the next update fails the "unique logic" gate and keeps the old index.
Accept that run as the new baseline and update again:

<!-- doctest: skip needs a run that failed a gate -->
```bash
sigharvest runs accept latest
sigharvest update
```

## Measured timings

The README quickstart, run literally in a fresh `HOME` (new uv cache, nothing cloned yet) with the curated preset
(26 sources, 22,901 rule documents, 22,473 unique rules) on a 22-core WSL2 machine with 32 GB of RAM, while other
jobs shared the machine (2026-11-16):

| Step | Time |
|---|---|
| `uv tool install "sigharvest[convert] @ ..."` | a few seconds with a warm network |
| `sigharvest init ~/sigma` | 2 s |
| `sigharvest update`: sync (clone + ingest, network-bound) | 4 min 00 s |
| `sigharvest update`: validate (includes the one-time ATT&CK and D3FEND catalogue download, about 15 s) | 1 min 26 s |
| `sigharvest update`: index (semantic hashes, families, full-text) | 1 min 57 s |
| **`sigharvest update` total** | **7 min 23 s** |
| `search mimikatz`, `show KEY`, `convert KEY --target splunk` | under 1 s each |
| `export lsass --product windows --format splunk` | under 1 s |
| `export --product windows --format zip` | 2.4 s |
| `serve`: overview, search, rule page, coverage, sources, export | 0.01-1.1 s per page |
| first query tab of a rule page (`/api/convert`) | 0.1 s |

Before conversion became on demand the same first update took more than 40 minutes (every rule converted into
every installed backend; measured with the seven pySigma 1 backends). `sigharvest update --convert` still does that, once; later updates convert only new rules. The
next `update` with nothing changed upstream takes seconds. Without a terminal (cron, `| tee`) `update` prints a
progress line with the time left at least every 15 seconds. If you stop the first update (Ctrl+C), run `update`
again: it keeps the sources and validation results it already stored and continues.

pySigma's ATT&CK and D3FEND tag checks need MITRE's catalogues. `validate` downloads each once per workspace (into
`data/cache/pysigma/`, refreshed after 30 days) and shares it with every worker; without network the first time,
those two checks are skipped with one note and run on the next update that can download them.

## Add your own sources

<!-- doctest -->
```bash
sigharvest sources add myrepo https://github.com/me/rules.git --path "rules/**" --licence MIT --priority 30
sigharvest sources add local-rules /path/to/folder --type local --licence MIT   # your rules' licence
sigharvest sources disable myrepo
```

- `--priority`: a lower number wins when the same logic is in several sources (it picks the canonical copy).
- `--auth`: the name of an environment variable that holds a token. The token is never written to a file.
- Path globs use `fnmatch`: `*` also matches `/`, so `rules/*` selects the whole subtree.

More in [sources.md](sources.md).

## Workspace layout

```
~/sigma/
  sources.yaml            the sources to sync (edit by hand or with `sigharvest sources`)
  corpus/                 the files of each source that look like Sigma
  data/sigharvest.db      SQLite database: rule versions, occurrences, test results, index, collections, runs
  data/cache/git/         bare, shallow git clones
  data/cache/             other downloads (JSON schema, ATT&CK data, GitHub API responses)
  data/logs/              logs
  reports/                run reports (reports/runs/) and summary.md
```

Everything in `data/` except your collections can be rebuilt with `sigharvest update`.

## No install: use a release pack

If you just want the rules, download the latest release:

<!-- doctest: skip network (downloads a release) -->
```bash
curl -LO https://github.com/threat-hunter-eu/sigharvest-rules/releases/latest/download/sigharvest-rules-permissive.zip
unzip sigharvest-rules-permissive.zip -d sigma-rules
```

A release can also be used without a workspace by `sigharvest lint --release URL` and `sigharvest site build
--release DIR` ([releases.md](releases.md)).

## Uninstall

<!-- doctest: skip uninstalls the tool and deletes the workspace -->
```bash
uv tool uninstall sigharvest        # or: pipx uninstall sigharvest
rm -rf ~/sigma                      # the workspace: clones, database and reports
```

sigharvest writes nothing outside the workspace folder (and the tool environment uv/pipx created).
