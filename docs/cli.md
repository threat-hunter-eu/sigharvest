# CLI recipes

Task-oriented examples. Every command has `--help` with the full option list (`sigharvest --help` groups them).

- [The commands at a glance](#the-commands-at-a-glance)
- [Search](#search)
- [Filter](#filter)
- [Read a rule](#read-a-rule)
- [What changed](#what-changed)
- [Export](#export)
- [Collections](#collections)
- [ATT&CK coverage](#attck-coverage)
- [Lint your own rules](#lint-your-own-rules)
- [Manage sources](#manage-sources)
- [Scripting and exit codes](#scripting-and-exit-codes)

## The commands at a glance

| Command | What it does |
|---|---|
| `sigharvest init [DIR]` | Create a workspace with a source list (`--preset curated\|sigmahq\|all`), or from a release pack (`--from-release latest`) |
| `sigharvest update` | Sync, ingest, validate and index everything; check gates; write a run report (`--convert` also stores every query) |
| `sigharvest search [QUERY]` | Find rules (one row per family by default); `list` is an alias |
| `sigharvest show KEY` | One rule: metadata of the canonical copy, versions, copies by source, test results |
| `sigharvest diff KEY V1 V2` | Textual diff of two versions of a rule |
| `sigharvest changes` | New, changed and removed rules since the last update (`--since DATE`, `--run ID`) or between two releases (`--from-release OLD --to-release NEW`); `--json` |
| `sigharvest export [QUERY]` | Save rules or SIEM queries to files |
| `sigharvest convert KEY` | Print the query for one rule or YAML file |
| `sigharvest collection ...` | Saved rule sets: create, add, remove, show, update, import, export |
| `sigharvest coverage [QUERY]` | ATT&CK summary, gaps and Navigator layer |
| `sigharvest dedupe` | Most duplicated logic and conflicting ids across sources |
| `sigharvest lint PATHS` | Check your own rules against the corpus |
| `sigharvest sources ...` | List, add, remove, enable, disable sources |
| `sigharvest discover` | Find candidate repositories on GitHub and GitLab |
| `sigharvest stats` | Rules and sources, unique logic per source |
| `sigharvest serve` | Local web UI on http://127.0.0.1:8799 |
| `sigharvest doctor` | Check workspace health |
| `sigharvest runs ...` | Past updates: list, show, accept a failed-gate run as baseline |
| `sigharvest quarantine ...` | Documents that failed to parse: list, show, retry |
| `sigharvest release build OUT` | Build a licence-split rule pack like the nightly one |
| `sigharvest site build OUT` | Build the static search site |

`KEY` is a rule UUID, or a logic or content hash prefix of at least 8 characters (all shown by `search`).

## Search

<!-- doctest -->
```bash
sigharvest search mimikatz
sigharvest search '"pass the hash"'                 # exact phrase
sigharvest search 'lsass -procdump'                 # exclude a word
sigharvest search 'certutil (decode OR urlcache)'   # OR and grouping
sigharvest search 'title:powershell tags:t1059'     # search one field
```

Query syntax:

| You type | It means |
|---|---|
| `word other` | both words (prefix match, AND; common endings are dropped, so `LSASS dumping` finds `lsass dump`, `dumped`, `dumps`; one- and two-character words match exactly) |
| `"two words"` | exact phrase |
| `a OR b`, `( )` | either; group terms |
| `-word`, `NOT word` | exclude (applies to the whole search, including every `OR` alternative) |
| `title:`, `description:`, `tags:`, `logsource:`, `fields:`, `detection:`, `author:` | search only that field |
| `level:high`, `product:windows`, `source:NAME`, `id:...`, `technique:T1003`, `flag:...` | inline filters (same as the options below); `level:high OR level:critical` or `level:high,critical` for several values; a misspelt key or value (`prodct:`, `level:hgh`) is refused with a suggestion |

A query that starts with an exclusion needs `--`: `sigharvest search -- '-mimikatz NOT sekurlsa'`. More in
[concepts.md](concepts.md#search).

By default you get **one row per rule family** (the best-ranked member). Use `--per-logic` for one row per unique
detection logic, or `--all-copies` to see every file that contains it. The summary line gives both numbers
(`197 rules in 130 families match`); the web UI lists rules and shows the same two numbers. Both hide deprecated or
unsupported rules and junk (test fixtures, synthetic documents, wrapped SIEM queries) unless you ask for them
(`--include-deprecated`, `--include-junk`; the web UI's "show them" link).

`--all-copies` lists files, not unique rules, so it takes only the per-file filters (`--product`, `--category`, `--service`,
`--tag`, `--source`, `--status`, `--level`, `--include-deprecated`) and a text query. Options that need the index of unique
rules (`--technique`, `--tactic`, `--validation`, `--backend`, `--min-sources`, `--flag`, `--include-junk`, `--sort`,
`--offset`, `--profile`, `--licence`, `--licence-class`) are refused with `--all-copies`.

<!-- doctest -->
```bash
sigharvest search mimikatz --per-logic
sigharvest search mimikatz --limit 100 --sort modified
sigharvest search mimikatz --json            # machine-readable, with the total
```

`--json` and the web API's `/api/search` give the same counts under the same names: `total_rules` (unique rules
that match), `total_families` (rule families) and `total`, the number of entries `results` pages through, which
follows `view`: `"family"` (the CLI default; `view=family` in the API) or `"logic"` (`--per-logic`; the API
default). For `lsass`, for example: `total_rules` 376, `total_families` 241, and `total` 241 in the CLI and 376 in
the API.

Sort options: `relevance` (default), `score`, `sources`, `title`, `modified`, `level`. Page with `--limit` and
`--offset`.

## Filter

All filters combine with AND, and work with or without a text query.

<!-- doctest -->
```bash
# Windows process creation rules, high level, that validate cleanly
sigharvest search --product windows --category process_creation --level high --validation ok

# Everything for one ATT&CK technique or tactic
sigharvest search --technique T1003.001
sigharvest search --tactic credential-access --product windows

# Rules that convert cleanly to Splunk (needs stored conversions: sigharvest update --convert)
sigharvest search --backend splunk --product windows

# Logic that at least 3 independent repositories carry (a crude "consensus" signal)
sigharvest search --min-sources 3

# High or critical (also inline: "level:high OR level:critical" or level:high,critical)
sigharvest search --product windows --level high --level critical

# Only rules from one source
sigharvest search --source sigmahq-core

# Stable rules only, or include deprecated ones
sigharvest search --status stable
sigharvest search --include-deprecated cobalt
```

| Option | Values |
|---|---|
| `--product`, `--category`, `--service` | logsource fields, e.g. `windows`, `process_creation`, `sysmon` |
| `--profile` | a SigmaHQ release package applied to every source: `core`, `core+`, `core++`, `emerging-threats` (`et`), `all` (see [Profiles](#profiles-sigmahq-packages)) |
| `--level` | `informational`, `low`, `medium`, `high`, `critical`; any of several with `--level high --level critical` or `--level high,critical` |
| `--status` | `stable`, `test`, `experimental`, `deprecated`, `unsupported` |
| `--technique`, `--tactic`, `--tag` | ATT&CK id (`T1059.001`; comma for OR), tactic name (`execution`), tag prefix (`attack.t1059`) |
| `--source` | source name from `sigharvest sources list` |
| `--licence-class` | licence class of the source, as the web UI's licence filter: `permissive` (DRL, MIT, Apache, BSD, CC0), `copyleft` (GPL family, CC-BY-SA), `restricted`, `none` |
| `--licence` | licence written in the rule document itself (`license:` field, e.g. `DRL-1.1`; few rules have one) |
| `--validation` | `ok`, `warning`, `error` |
| `--backend` | only rules a pipeline maps for this backend |
| `--min-sources N` | logic carried by at least N independent sources |
| `--flag NAME` | only rules with this quality flag (`ioc_list`, `synthetic`, `upstream_deprecated`, ...) |
| `--include-junk` | also show test fixtures, synthetic and wrapped-query documents (hidden by default) |
| `--json` | machine-readable output |

### Profiles (SigmaHQ packages)

SigmaHQ publishes its rules as [release packages](https://github.com/SigmaHQ/sigma/blob/master/Releases.md) chosen by
status, level and rule type. `--profile` (search and export; `profile=` in the web UI and `/api/search`) applies the
same choice to the rules of **every** source:

| Profile | Status | Level | Rule type |
|---|---|---|---|
| `core` | test, stable | high, critical | core |
| `core+` | test, stable | medium, high, critical | core |
| `core++` | experimental, test, stable | medium, high, critical | core |
| `emerging-threats` (`et`) | experimental, test, stable | medium, high, critical | emerging threats |
| `all` | experimental, test, stable | medium, high, critical | core and emerging threats |

The rule type comes from the rule's tags (`detection.emerging-threats`, `detection.threat-hunting`,
`detection.dfir`) or from a SigmaHQ-style folder in the path of its canonical copy (`rules-emerging-threats/`,
`rules-threat-hunting/`, `rules-placeholder/`, `rules-compliance/`, `rules-dfir/`); everything else is core.
Threat-hunting, placeholder, compliance and DFIR rules are in no profile, as in SigmaHQ's packages, and neither are
`low`/`informational` or deprecated rules. A profile combines with every other filter (AND).

<!-- doctest -->
```bash
sigharvest search --profile core+ --product windows
sigharvest export --profile core --format splunk --out core.spl
```

Counts differ from SigmaHQ's package because of the search defaults, not the profile: search and export show one
rule per **family** (`--unit family`: near-identical rules collapse into their best member) and hide junk (test
fixtures, templates, `negation_only`, `weak_high_severity` and similar). A condition that weak values alone can
satisfy (`Image|startswith: /`, `CommandLine|contains: '-e '`) gets `weak_detection` (every branch) or `weak_branch`
(one OR branch) and a lower score; on a high or critical rule `weak_detection` also adds the junk flag
`weak_high_severity`. Find them with `--flag weak_detection`. To select exactly what the package selects, use
`sigharvest export --profile core --unit logic --include-junk` (on SigmaHQ's own rules this matches SigmaHQ's release
script). The `sigmahq` preset syncs `rules/` only; `--profile et` and `all` need the
emerging-threats folder, which the `curated` preset includes.

Several values of one filter mean "any of them" (`--level high,critical`, `level:high OR level:critical`, the web
UI's Level, Status and Validation checkboxes). Different filters are combined with AND; `OR` between two different
inline filters (`level:high OR product:linux`), or between words and a filter (`windash OR level:high`), is refused
with a message, since it cannot be expressed: run two searches.

## Read a rule

<!-- doctest -->
```bash
sigharvest show 8c0b4bfbcc
sigharvest show 8c0b4bfbcc --copies     # every path of every copy
sigharvest diff 8c0b4bfbcc 1 2          # two versions listed by show
```

You get the title, logsource, level, status, tags and licence of the canonical copy (`licence: DRL-1.1
(permissive), from source sigmahq-core; redistributable: yes`), every version, the sources that contain them, and
one line each for validation and conversion; `--results` prints every stored result in full.

Get the query for one rule:

<!-- doctest -->
```bash
sigharvest convert 8c0b4bfbcc --target splunk
sigharvest convert 8c0b4bfbcc --target lucene --telemetry sysmon
sigharvest convert my-rule.yml --target loki
```

Targets: `splunk`, `lucene`, `esql`, `opensearch`, `microsoft365defender`, `loki`, `sqlite` (needs the
`[convert]` extra; `lucene`, `esql`, `opensearch` and `microsoft365defender` need `[convert-legacy]`, see
[export.md](export.md#which-extra-for-which-siem)).

## What changed

<!-- doctest -->
```bash
sigharvest changes                                  # the last update: new, changed upstream, removed
sigharvest changes --since 2026-11-01 --json        # every update since a date, merged
sigharvest changes --from-release rel-old --to-release rel-new   # two release folders (checksums verified)
```

A rule that changed its detection but kept its id is "changed" (old and new logic hash); a rule added and removed
within the merged period is in neither list. The static site publishes the same data as `changes.json` and an Atom
feed (`feed.xml`).

Limits: nothing is capped in the data. Each run report (`reports/runs/<stamp>.json`), `changes --json` and the
site's `changes.json` list every new, changed and removed rule (a first update lists all of them, for example
22,473 new). The text output shows the first 20 rows of each list (`--limit N` for more, the header has the full
counts). Only these are cut: a detection diff is kept for the first 5,000 changed rules of a run, the markdown run
report shows 50 rows per list, and `feed.xml` has the first 200 entries (its subtitle gives the full counts). Run
reports written by older versions kept at most 5,000 rows per list; `changes` then prints an `incomplete:` line
with the real total (also in `--json` as `"incomplete"`).

## Export

The short version (full details in [export.md](export.md)):

<!-- doctest -->
```bash
sigharvest export --out all-rules/                                         # YAML of every family's best rule
sigharvest export --product windows --level high --out win-high/           # a filtered YAML folder
sigharvest export lsass --product windows --format splunk --out lsass.spl  # Splunk queries
sigharvest export --format jsonl --out rules.jsonl                         # one JSON object per rule
sigharvest export --format csv --out rules.csv                             # spreadsheet-friendly index
```

`--unit family` (default) exports the best rule of each family; `--unit logic` every unique logic; `--unit all`
every copy.

## Collections

A collection is a named, saved set of rules that follows upstream changes ([concepts.md](concepts.md#collections)).

<!-- doctest -->
```bash
sigharvest collection add baseline -q lsass --product windows
sigharvest collection add baseline 8c0b4bfbcc --note "seen in incident 12"
sigharvest collection show baseline
sigharvest export --collection baseline --format splunk --out baseline.spl
```

## ATT&CK coverage

<!-- doctest -->
```bash
sigharvest coverage                                   # tactics and techniques with rule counts
sigharvest coverage --product windows --validation ok --gaps --min 3
sigharvest coverage --backend splunk --navigator layer.json
```

`--navigator FILE` writes an ATT&CK Navigator layer (technique -> number of rule families). Open
<https://mitre-attack.github.io/attack-navigator/>, choose *Open Existing Layer*, *Upload from local*.

Counts come from the rules' `attack.*` tags. They say what a rule is meant to detect, not that it has been
tested against that technique.

## Lint your own rules

Check a folder of your rules against the public corpus before you merge them:

<!-- doctest -->
```bash
sigharvest lint rules/
sigharvest lint rules/ --fail-on warning --sarif lint.sarif
sigharvest lint rules/ --release https://github.com/threat-hunter-eu/sigharvest-rules/releases/latest/download/
```

It reports invalid detections, ids reused from other rules, placeholder ids, rules whose logic already exists
publicly, quality flags and unknown ATT&CK tags. Without `--release` it compares with your workspace. Exit code 1
means findings at or above `--fail-on` (`error`, `warning` or `note`; `never` only reports).

As a GitHub Action (results show up in code scanning):

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: threat-hunter-eu/sigharvest@<commit SHA or tag>
    with:
      rules: rules
      fail-on: error
```

See [automation.md](automation.md#the-lint-action) for the inputs.

## Manage sources

<!-- doctest -->
```bash
sigharvest sources list
sigharvest sources list --disabled
sigharvest sources add myrepo https://github.com/me/sigma-rules.git --path "rules/**" --licence MIT
sigharvest sources add team-rules ~/work/detections --type local --priority 20 --licence MIT
sigharvest sources disable myrepo
sigharvest sources enable myrepo
sigharvest sources remove myrepo
sigharvest update --source myrepo        # sync just one source
```

More in [sources.md](sources.md).

## Scripting and exit codes

| Exit code | Meaning |
|---|---|
| 0 | OK |
| 1 | The command ran but did not reach its goal: a source failed, a gate failed, lint findings, a doctor check failed, no rule matches a key, an export selected nothing |
| 2 | Bad option or argument, not a workspace, I/O error, or the workspace is locked by another command |

Errors go to stderr and start with `error: `. `--json` prints one compact JSON document and nothing else; lists use
`{"total": N, "offset": N, "limit": N, "results": [...]}` (`search`, `stats`, `runs list`, `sources list`,
`quarantine list`), the same object as `/api/search`. The rules shared with suriharvest are in
[conventions.md](conventions.md).

Useful switches: `--json` on `search`, `stats`, `doctor`, `runs list`, `sources list`, `quarantine list` and
`changes`; `update --wait SECONDS`; `update --time-budget MINUTES` (runs a long first update in pieces; the report
counts what was left); `--report-file PATH` on `update` (`.json` for JSON, otherwise Markdown); `--allow-failures`
on `update` and `sync`; and the global `-v` for debug logs.
