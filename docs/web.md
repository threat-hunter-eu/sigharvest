# Web UI

`sigharvest serve` starts a local web UI on <http://127.0.0.1:8799> for the workspace it finds (the current folder,
or `SIGHARVEST_HOME`). On `127.0.0.1` it has no login. Any other address needs `--token-env VAR`, the name of an
environment variable holding a token of 16+ characters: browsers ask for a user name (any) and the token as password,
scripts send `Authorization: Bearer <token>`; without it `serve` refuses to start. With `--host 0.0.0.0`, also name
the host names clients use with `--allow-host NAME` (the UI refuses other `Host` headers). `--port` changes the
port. `sigharvest web` is a hidden alias of `serve`.

It reads the same database as the CLI: run `sigharvest update` first; while an update runs, the UI keeps showing
the last published index.

## Pages

| Page | Address | What it is for |
|---|---|---|
| Overview | `/` | index totals, last update, ATT&CK coverage summary, top sources, recent changes |
| Search | `/search` | full-text search with facets; same syntax as `sigharvest search` (see [cli.md](cli.md#search)) |
| Rule | `/rule/<logic>` | YAML, what you need to log, licence and author, every copy with a link, family, similar rules, history, SIEM queries |
| Family | `/family/<logic>` | every variant of a rule family side by side |
| Compare | `/compare?a=..&b=..` | two rules' YAML side by side, changed lines highlighted |
| ATT&CK coverage | `/coverage` | technique matrix for a search; "Download Navigator layer" |
| Sources | `/sources`, `/sources/<name>` | each source: licence, last sync, rules, overlap with other sources |
| Changes | `/changes` | what the last updates added, changed or removed |
| Collections | `/collections` | saved rule sets (same as `sigharvest collection`) |
| Export | `/export` | download a search, a selection or everything (below) |
| About & licences | `/about` | query syntax, CLI equivalents, licences |
| JSON API | `/api/docs` | the read-only API: `/api/search`, `/api/rule/<logic>`, `/api/facets`, `/api/convert/<logic>`, `/api/sources` |

## Search and facets

The facets on the left narrow the search. **Level**, **Status** and **Validation** are multi-select: ticking High
and Critical shows rules that are high **or** critical (`level=high,critical` in the address, the same as
`--level high,critical` in the CLI). Other facets select one value; different facets combine with AND.

The total says how many unique rules match and in how many families (`6,312 rules in 5,904 families match`). The
CLI lists one row per family by default and prints the same two numbers. Both hide deprecated/unsupported rules and
junk (test fixtures, synthetic documents, wrapped SIEM queries) unless you ask for them: "show them" in the UI,
`--include-deprecated` / `--include-junk` in the CLI.

The buttons next to the sort switch between cards and a compact table (`view=table` in the address; the older
`layout=table` still works). On the page `view` only picks the layout; `/api/search` keeps `view=logic|family`.

`/api/search` returns `total_rules` and `total_families` (the two numbers above) and `total`, which counts what its
`results` page through: rules by default, families with `view=family`. `sigharvest search --json` has the same
three fields ([cli.md](cli.md#search)).

Words are prefix matches with common endings dropped, so `LSASS dumping` finds the same rules as `lsass dump`.

## Rule page: SIEM queries

The "Use it in your SIEM" card has one tab per installed backend. A query is converted when you open its tab (it
takes a moment the first time; repeated views come from a cache), unless the workspace stores conversions
(`sigharvest update --convert`), in which case it is shown at once. A rule that is too large to convert in the web
UI says so; use `sigharvest convert <logic> --target <backend>` instead.

## Export

The Export page offers:

- **Sigma YAML (.zip)**: the same file as `sigharvest export --format zip`: a top folder, then the licence class
  (`permissive/`, `copyleft/`), the licence, product and category; plus `NOTICE.md`, `LICENSES.md`,
  `ATTRIBUTION.md`, `manifest.jsonl`, `provenance.json` and `SKIPPED.md`. "One multi-document .yml" puts every
  rule in one file instead.
- **SIEM queries**: a zip with the query file (an `# attribution:` line per query), `manifest.jsonl`,
  `ATTRIBUTION.md` and `NOTICE.md`.
- **ATT&CK Navigator layer** and **Spreadsheet** (CSV, or JSONL with the YAML).

A rule's text is copied only when its licence allows it and its source is marked redistributable; other rules are
listed in `SKIPPED.md` with a link to read them at their source. **Private copy** includes them too (for example your
own rules added as a local source without `--licence`); the export then says it must not be shared. The CLI flag is
`--include-private-sources`. Each export option shows the equivalent `sigharvest export` command.

A web download holds at most 20,000 rules. When the whole index is larger (a `curated` workspace has about 22,000),
the Export page opens on SigmaHQ's **core** profile (`profile=core`; measured on a curated workspace: 3,710 rules, one
per logic, in 1,994 families) with a note, instead of an "Everything" that cannot be downloaded; search first to
export other rules. Picking "Everything" then explains the limit and links the core profile; the command shown under
Download has no limit. The page exports one rule per logic (`--unit logic`); `sigharvest export` exports one per
family by default, and both print the two numbers ("3,710 rules (one per logic) in 1,994 families").

`/downloads` (the name in older docs) redirects to `/export`.

## Limits and tuning

The server is local (it binds `127.0.0.1`; only loopback `Host` names are served, plus `--allow-host`). It is sized
for one person or a small team; these environment variables change its limits (read when `serve` starts):

| Variable | Default | What it does |
|---|---|---|
| `SIGHARVEST_READ_POOL` | 2 (1 on a single CPU) | Database readers shared by all requests. More readers make concurrent searches *slower*: they contend for Python's GIL on every row of the large facet scans (measured on 22k rules, 10 clients: 2 readers 27 req/s, 4 readers 10, 32 readers 6) and each maps its own cache. |
| `SIGHARVEST_READ_STATEMENT_SECONDS` | 15 (web), 60 (CLI) | A database statement that runs longer is stopped; the web answers 503 "too expensive" instead of holding a reader. 0 = no limit. |
| `SIGHARVEST_READ_QUEUE_TIMEOUT` | 15 | Seconds a request waits for a free reader. |
| `SIGHARVEST_READ_CACHE_KIB` / `SIGHARVEST_READ_MMAP_MIB` | 8192 / 256 | SQLite page cache and memory map per reader. The mapped pages count in RSS (`top`), but they are the operating system's file cache. |

Searches (the Search page, `/api/search`, `/api/facets` and the Export page) run on all readers but one, so the
other pages stay fast while expensive searches run (10 clients searching 32 OR'ed prefixes: `/about` 9 ms instead of
270 ms). A search that waits more than 1 s for its turn gets a 503 with `Retry-After`. `/api/search` and `/api/facets`
refuse cross-site browser requests (403), like downloads; scripts that send no `Origin` header are not affected.

Search text is limited to 1,000 characters and 64 terms. Words of one or two characters are matched exactly, not as a
prefix; an explicit prefix needs at least three characters before `*` (`a*` is refused: it expands to most of the
index). A repeated word counts once.
