# Sources

Where the rules come from, how sigharvest decides what is a duplicate, and how to add your own.

- [The source list](#the-source-list)
- [Presets](#presets)
- [Add your own repository or local folder](#add-your-own-repository-or-local-folder)
- [Priority and the canonical copy](#priority-and-the-canonical-copy)
- [Discovery: finding new repositories](#discovery-finding-new-repositories)
- [Licences](#licences)
- [Removing or excluding a source](#removing-or-excluding-a-source)

## The source list

Each workspace has a `sources.yaml`. You can edit it by hand or with `sigharvest sources ...`.

```yaml
sources:
- name: sigmahq-core
  type: git
  url: https://github.com/SigmaHQ/sigma.git
  paths:
  - rules/**
  licence: DRL-1.1
  redistribute: yes
  priority: 10
  enabled: true
- name: my-team
  type: local
  url: /srv/detections
  licence: MIT
  priority: 20
  enabled: true
```

| Field | Meaning |
|---|---|
| `name` | Unique short name. Shown everywhere, used in filters (`--source NAME`). |
| `type` | `git` (default), `local` (a folder on disk), `http` (an archive or a single file), `http-files` (a list of HTTPS files), `html` (rules embedded in web pages), `huggingface` (a dataset) - see [non-git-sources.md](non-git-sources.md) |
| `url` | Git URL, folder path, HTTPS URL or dataset id |
| `ref` | Optional branch or tag (Git) or revision (Hugging Face); default: the default branch |
| `paths` | Glob patterns of files to read (default `**/*`); Sigma is recognised by content, not by extension |
| `exclude` | Glob patterns to skip |
| `licence` | SPDX id of the rules' licence, e.g. `DRL-1.1`, `MIT`, `GPL-3.0-only`. Empty means "no licence". |
| `redistribute` | `yes`, `no` or `unknown`: whether releases may include the rule text (unset means no: metadata and a link only; `sources add --licence` sets `yes` for permissive and copyleft licences). The older `redistributable: true\|false` is still read. |
| `copyright` | optional: the publisher's copyright line (`Copyright (c) 2022 Example Labs`), written into release and export `NOTICE.md`; the lines in the source's own LICENSE / NOTICE files are used too |
| `priority` | Lower number wins when the same rule appears in several sources (default 50) |
| `enabled` | `false` keeps the entry but skips it |
| `auth` | Name of an environment variable holding an access token (never stored) |
| `urls`, `files` | Explicit HTTPS files/pages (`http-files`, `html`) or dataset files (`huggingface`) |
| `notes`, `tier` | Free text / informational |

## Presets

`sigharvest init --preset NAME` fills `sources.yaml` from a list that ships with sigharvest (the same lists are
`sources/curated.yaml` and `sources/extended.yaml` in the repository):

| Preset | What's in it | First `update` |
|---|---|---|
| `curated` (default) | 26 repositories with original content: SigmaHQ (core, emerging threats, threat hunting), Yamato Security, vendors (Trend Micro, ESET, Huntress, ...) and well-known independent authors. 23 have a licence that allows sharing; 3 (no licence or a licence per rule) are indexed for you and linked, never copied into exports. Some are no longer updated (`stale` in their notes) but kept for rules found nowhere else. Mirrors and forks of SigmaHQ are left out. | about 10 minutes |
| `sigmahq` | SigmaHQ's core rules only. | minutes |
| `all` | curated + extended: about 1,200 public repositories (111,426 unique logic from 1,201 sources on 2026-11-16), everything alive found by discovery that is not a mirror, an identical copy, a tool's test fixtures or a tiny (< 5 rules) repository. Expect many small, stale or unlicensed repositories and heavy deduplication. Rules with no licence are indexed for you locally, never redistributed. | about 1h12m on a 22-core machine (measured 2026-11-15), about 16 GB of disk |

**Want everything? Start from the nightly pack.** `sigharvest init ~/sigma-all --from-release latest` gives you the
full corpus that the nightly build collected from all of these repositories, in minutes instead of hours, without
cloning anything. It holds the rules whose licence allows redistribution (YAML) and lists the others as metadata
with a link (see [Licences](#licences)). Use `--preset all` with live sources only when you want the
non-redistributable rules indexed locally too, your own update schedule, or a source the pack does not have.

Why `curated` is the default: it is what most people want (original rules, almost all with a clear licence), its
first update takes minutes on a laptop, and it needs well under 1 GB of disk. `all` multiplies all of that: about
1,200 clones, about 16 GB of clones and database, and about five times the unique logic, much of it small, stale or
near-duplicate. The extra logic is real (the nightly build publishes it), but it is not a sensible default.

Using `all` with live sources:

<!-- doctest: skip network (clones about 1,200 repositories) -->
```bash
sigharvest init ~/sigma-all --preset all
cd ~/sigma-all && sigharvest update --time-budget 120   # stop starting new work after 2 hours; run again to continue
```

`--time-budget MINUTES` lets a long first update run in pieces: when the budget is spent, no new fetch or conversion
starts, the run indexes and commits what it has, and the next `update` continues with the sources never or least
recently synced. Without it, the first update simply runs to the end. Later updates are incremental (minutes).

Switch later without losing your clones or database:

<!-- doctest -->
```bash
sigharvest init . --preset all --force     # rewrites sources.yaml; the database and clones stay
```

Sources the extended list deliberately leaves out: mirrors and forks whose logic is all found elsewhere, identical
copies of another repository, repositories that are gone or archived without unique content, SigmaHQ's tooling
repositories (their rules are test fixtures), repositories with fewer than 5 rules, one-off non-git snapshots, and
the names in `sources/denylist.yaml`. A review on 2026-11-15 re-added 54 repositories that had been dropped although
they hold logic found nowhere else (about 3,900 unique logic).

## Add your own repository or local folder

A public or private Git repository:

<!-- doctest -->
```bash
sigharvest sources add acme https://github.com/acme/sigma-rules.git --path "rules/**" --licence MIT --priority 30
sigharvest update --source acme
```

For a private repository, put a token in an environment variable and name it with `--auth`:

<!-- doctest -->
```bash
export ACME_TOKEN=...            # read-only token
sigharvest sources add acme-private https://github.com/acme/private-rules.git --auth ACME_TOKEN
```

Do not put a token in the URL itself (`https://user:token@host/...`): the web UI, the API and releases show source
URLs without their credentials, but sources.yaml and the database keep the URL as written.

A **local folder** (your own detections, work in progress, an export you are allowed to use):

<!-- doctest -->
```bash
sigharvest sources add mine ~/detections --type local --priority 5 --licence MIT
sigharvest update --source mine
```

Name the licence you want your rules to carry (`--licence MIT`, or your organisation's). Without a permissive or
copyleft `--licence` (or `--redistributable`) a source counts as not redistributable: zip and YAML exports, the web
UI's downloads and releases only link its rules (SKIPPED.md). For a private copy that includes them anyway, use
`sigharvest export --include-private-sources` or the web UI's "Private copy" option.

Why this is useful:

- your rules are searched, filtered and exported together with the public ones;
- `show` tells you when a public rule already has the same logic as yours;
- with a low `priority` number, your copy becomes the canonical one when the logic is the same.

Local and private sources are never part of anything sigharvest publishes unless you build a release from that
workspace yourself. To check rules without adding them as a source, use `sigharvest lint`
([cli.md](cli.md#lint-your-own-rules)).

## Priority and the canonical copy

The same detection logic often appears in many repositories: copied from SigmaHQ, forked, renamed or re-formatted.
sigharvest computes a **logic hash** for every rule: a hash of its `logsource` and `detection` after
normalisation. Title, id, author, dates, description and references are ignored. Same logic hash = same rule. The
exact rules are in [identity.md](identity.md).

For each logic, one **canonical copy** is chosen: the copy from the source with the lowest `priority` number,
then the earliest seen. The canonical copy is the one shown, exported and credited. All other copies are listed
with their source, path and commit (`sigharvest show KEY --copies`).

**Families** group rules that are variants of each other even though their logic differs: a shared trusted rule
id or semantic hash, or a `related:` link (`derived`, `obsolete`, `merged`, `renamed`), always within the same
logsource. Search shows one row per family by default.

**Mirrors**: a source whose logic is at least 80% contained in a bigger source is a mirror of it, so "carried by
N sources" counts independent sources, not copies of copies.

Details: [concepts.md](concepts.md).

## Discovery: finding new repositories

<!-- doctest -->
```bash
export GITHUB_TOKEN=...                   # optional: a read-only token raises the API limits
sigharvest discover --output discovered.yaml --known sources.yaml --min-rules 10
```

Discovery searches GitHub and GitLab for repositories that contain Sigma rules, clones the candidates, counts valid
rules and unique logic, detects mirrors and reads the licence. The token is read from `GITHUB_TOKEN` (or
`gh auth token`) and never written anywhere.

- With `--output FILE` it writes a **review file** in which every entry has `enabled: false`, and leaves your
  `sources.yaml` alone. `--known FILE` leaves out repositories you already have; `--denylist FILE` names
  repositories never to propose. To adopt a candidate, copy its entry into `sources.yaml` (or use
  `sigharvest sources add`) and enable it.
- Without `--output`, verified repositories are registered in `sources.yaml` directly (`--no-auto-add` turns
  that off), and the `--top` best are registered enabled. Use `--output` if you want to review first.

Budgets: `--max-repos`, `--max-code-requests`, `--max-http-requests`, `--workers`. Details, caching and
completeness evidence: [discovery.md](discovery.md).

The public project runs discovery weekly with `--output` and opens a pull request that only touches
`sources/discovered.yaml`; maintainers review it before anything enters the curated list.

## Licences

Each source has a `licence`. sigharvest maps it to a **licence class**:

| Class | Examples | What sigharvest does |
|---|---|---|
| `permissive` | DRL-1.0/1.1, MIT, Apache-2.0, BSD, CC0, Unlicense, CC-BY | YAML can be exported and is included in the permissive release pack |
| `copyleft` | GPL-2.0/3.0, AGPL-3.0, LGPL, MPL, EUPL, CC-BY-SA | YAML can be exported; release packs keep them in a separate zip |
| `restricted` | non-commercial (CC-BY-NC), source-available and custom terms | Indexed locally; releases have metadata and a link only |
| `none` | no licence stated | "All rights reserved" by default. Indexed locally for you; never redistributed |

Things to know:

- **DRL-1.1** (SigmaHQ and many others) lets you use and share rules freely as long as the author credit is kept,
  also in converted queries. sigharvest never strips `author` or `references`, and YAML exports include
  `NOTICE.md`.
- **Copyleft** rules can be shared, but under their own licence. Keep them separate from permissive bundles if you
  redistribute; `sigharvest release build` does that for you.
- A repository's licence covers what its author wrote. A SigmaHQ rule copied into an MIT repository is still
  DRL-1.1; this is one reason the canonical copy prefers the original source.
- When you **use** rules inside your own SIEM, you are generally not redistributing them. When you **publish** an
  export (a repository, a blog, a product), check the licence of each rule; `manifest.jsonl` in each export lists
  them.

This is guidance, not legal advice.

## Removing or excluding a source

<!-- doctest -->
```bash
sigharvest sources disable noisy-repo     # keep the entry, stop syncing it
sigharvest sources remove noisy-repo      # drop the entry; its history stays in the database
```

The source's rules leave the index at the next `sigharvest update`. If that removes more than 5% of the unique
logic, the update gate fails and the previous index stays published: accept the run as the new baseline with
`sigharvest runs accept latest`, then run `sigharvest update` again.
