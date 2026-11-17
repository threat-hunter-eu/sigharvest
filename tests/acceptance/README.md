# Acceptance harness

Installs sigharvest the way a brand-new user does and walks through the whole first session: build a wheel, install
it with `[convert]` into a fresh isolated environment, follow the README quickstart (`init`, `update`), search, show
a rule, export in every supported format, validate what was exported, start the web UI and fetch every main page
and JSON endpoint. Every step is timed. A failure prints the command, the exit code and the last output lines, and
the full log is kept. CI runs it in `ci-full.yml` (job `acceptance`, pull requests to main).

```bash
tests/acceptance/accept.sh sigharvest --offline             # fixture git repos, no rule downloads (what CI runs)
tests/acceptance/accept.sh sigharvest --offline --locked    # same, with the versions of uv.lock
tests/acceptance/accept.sh sigharvest                       # network: SigmaHQ core only (sigmahq preset)
tests/acceptance/accept.sh sigharvest https://github.com/threat-hunter-eu/sigharvest.git --offline   # a pushed branch
```

Requirements: `uv`, `git`, `curl`, `python3` (stdlib only, for fixtures and the summary). The tool environment uses
Python 3.12 (`--python 3.13` to change). `--offline` still needs PyPI unless `--uv-offline` is given with a warm uv
cache.

Exit code: 0 = every check passed (warnings allowed), 1 = at least one step failed, 2 = harness or usage error.

## Options

| Option | Effect |
|---|---|
| `REPO_PATH` or git URL | what to test; default: the repository that contains this folder |
| `--offline` | sources are local fixture git repos (`file://`), counts are asserted exactly |
| `--uv-offline` | dependencies from the uv cache only (`UV_OFFLINE=1`) |
| `--extra NAME` | optional dependency set the wheel is installed with (default `convert`). For sigharvest, `convert` is pySigma 2 (splunk, loki, sqlite) and `convert-legacy` pySigma 1 with all seven targets; the export steps check exactly the targets the set promises, and that the others fail with a clear "not installed" message |
| `--locked` | install with the versions in `uv.lock`. Default resolves the newest allowed versions, which is what `uv tool install` gives a real user. A pass with `--locked` and a fail without points at a missing upper bound |
| `--raw-copy` | copy the whole working tree. Default copies only what a `git clone` would get (tracked + untracked-not-ignored files), so a `.gitignore` that hides a package file is caught |
| `--fail-fast` | stop at the first failed step (default: keep going and report everything) |
| `--keep-server` | leave the web UI running at the end |
| `--runs-dir DIR` | where run folders go (default `$ACCEPT_RUNS` or `${TMPDIR:-/tmp}/acceptance-runs`) |
| env `STEP_TIMEOUT` | per-step timeout in seconds (default 1800; `update` gets 3600) |
| env `ACCEPT_TMPDIR` | set `TMPDIR` for the tool (e.g. a long path, to test the worker start-up fallback) |
| env `ACCEPT_FIXTURE_SKIP=nonutf8` | leave the latin-1 file name out of the fixture (counts do not change) |

## What a run does

1. **Isolation.** The script re-executes itself under `env -i` with a new `HOME` and a minimal `PATH` (`TMPDIR`
   unset), so no user config, API keys, `SIGHARVEST_HOME`, virtualenvs or tools in `~/.local/bin` leak in. Only
   the uv cache and uv-managed Pythons are shared. The repo under test is copied (or cloned) into the run folder
   and built there; it is never modified.
2. **Build + install.** `uv build --wheel`, then `uv tool install "<wheel>[convert]"` with `UV_TOOL_DIR` /
   `UV_TOOL_BIN_DIR` inside the run folder. Checks: wheel name, console script, `--version`, `--help`, no internal
   product names in the help, the CLI contract the GitHub workflows rely on (missing items are warnings).
3. **Quickstart.** `init WORKSPACE`, then `sources add` for the fixture repos and `sources disable` for everything
   else; `doctor`, `update`, `update` again (incremental), `doctor`.
4. **Search and show.** Text and JSON search, filters, search from another folder through `SIGHARVEST_HOME`, a bad
   query (must be a clean error, not a traceback), `show` of a hit and of an unknown key.
5. **Export, then validate the files.** YAML folder, `zip`, `--unit all` zip, `--with-dependencies` for a
   correlation rule, `jsonl`, `csv`, every pySigma backend (`splunk lucene esql opensearch microsoft365defender
   loki sqlite`), `--telemetry sysmon`, an unknown format, a second export over the same file, `coverage
   --navigator`, `lint`, `release build`. Every YAML/zip member is re-parsed and must be a Sigma rule; zip members
   must not escape the archive; JSONL/CSV must parse; CSV cells must not start with `= + @`.
6. **Web UI.** Starts `serve` on a free port, then GETs every main page and JSON API: HTTP 200, no traceback or
   template error, `Content-Security-Policy` header present, JSON endpoints return valid JSON, no inline
   `<script>`. Also: unknown rule is 404 (not 500), a `<script>` query is not reflected raw, a cross-site POST is
   refused, a foreign `Host` header is refused. The server log must have no traceback.
7. **Newer features (offline only, exact numbers).**
   `changes` after the first update (`--json` counts, the `N more: --limit M or --json` cap line,
     usage errors), multi-value filters (`--level high,critical` = `--level high --level critical` =
     `level:high OR level:critical`; OR across two filters refused), `--profile core` / `core++` and
     `export --profile core --unit logic --include-junk`, the `# attribution:` header of `convert` and of query
     exports, `[convert]` vs `[convert-legacy]` (lucene converts or names `sigharvest[convert-legacy]`), the release
     pack's LICENSES/ and copyright lines (`release build` must now pass), `init --from-release DIR` from that pack
     (search finds every rule; `--sums-sha256` right digest passes, wrong digest and a tampered pack are refused and
     leave no `sources.yaml`), an upstream change (`make_fixtures.py sigma-bump`) seen by `changes`, by
     `release build --previous` and by `changes --from-release A --to-release B`, and incomplete-corpus gating: a
     second workspace whose first `update` is SIGKILLed mid-run (`checks.py interrupt` polls the database) must make
     search/doctor say "corpus incomplete", `release build` exit 1 and `site build` refuse; the next update records
     the run as interrupted and releases work again.

Every command's output is also scanned for `Traceback`, `UnicodeEncodeError`/`UnicodeDecodeError`,
`sqlite3.OperationalError` and `Internal Server Error`: such output fails the step even when the exit code is 0.

## Output

Run folder `RUNS_DIR/sigharvest-MODE-YYYYMMDD-HHMMSS/`:

| Path | Content |
|---|---|
| `summary.md` | table of every step: status, seconds, message |
| `results.json` | same, machine-readable, plus versions (`meta`) |
| `steps.tsv` | raw step rows |
| `logs/NN-step.log` | command line, full output, exit code, duration per step; `logs/server.log` for the web UI |
| `workspace/`, `exports/` | the workspace the run created and everything exported (kept for debugging) |
| `src/`, `dist/`, `uv-tools/`, `bin/` | copied source, the wheel, the tool environment |

Statuses: `OK`; `FAIL` (counts in the exit code); `WARN` (contract item missing, or nice-to-have); `SKIP`.

## Offline fixtures

`lib/make_fixtures.py` turns `fixtures/sigma` into two git repos inside the run folder (fixed author and dates):
`fixture-sigma-alpha` (DRL-1.1) and `fixture-sigma-beta` (MIT). Expected numbers are in
`expected/sigharvest-offline.env` with a comment per number; change them there when a fixture changes.

Both repos carry a `LICENSE` with a copyright line (alpha's DRL-1.1 text, beta's MIT). The certutil variant is
tagged `detection.threat-hunting` (in no SigmaHQ profile). `make_fixtures.py sigma-bump` changes the DNS rule's
detection keeping its id (one "changed" rule).

| File | Purpose |
|---|---|
| `alpha/rules/proc_whoami.yml` | base logic |
| `alpha/rules/proc_whoami_surrogate.yml` | same logic, title holds the escape `"\ud800"` (lone surrogate) |
| `beta/rules/whoami_copy.yml` | same logic in another repo, keys reordered, other title/id/author: cross-source duplicate |
| `alpha/rules/proc_certutil.yml` + `proc_certutil_copie_\xe9.yml` (created by the script) | same logic; the second file name is latin-1, not valid UTF-8 |
| `beta/rules/certutil_urlcache.yml` | variant (one more value): a new logic |
| `alpha/rules/base_failed_logon.yml` + `corr_bruteforce.yml` | correlation rule (`event_count`) and the base rule it names |
| `alpha/rules/broken.yml` | invalid YAML: must be quarantined, not crash |
| `alpha/docs/not-a-rule.yaml` | YAML that is not Sigma: must not become a rule |
| `alpha/rules/dns_fixture_domain.yml`, `beta/rules/linux_shadow_read.yml` | other logsources / levels for filters |

Asserted: 7 unique logics, whoami = 1 logic in 2 sources, certutil = 2 logics, `--product windows` = 5 logics,
9-10 copies with `--unit all`, correlation export complete, broken.yml quarantined.

## Files

```
accept.sh               entry point (argument parsing, isolation, build, install, smoke)
lib/common.sh           run_step / check / want / skip, timing, result files
lib/sigharvest.sh       user journey + web checks
lib/checks.py           validators (Sigma YAML/zip, JSONL, CSV, HTTP, JSON paths); runs in the tool's env
lib/make_fixtures.py    builds the fixture git repos (stdlib)
lib/summarize.py        steps.tsv -> summary.md + results.json
lib/capture.sh          stdout-to-file helper for JSON outputs
fixtures/, expected/    offline data and the numbers asserted on it
```
