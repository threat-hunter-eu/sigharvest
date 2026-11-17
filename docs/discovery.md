# Discovery completeness and retries

`sigharvest discover` finds candidate repositories with a fixed set of search queries; it does not list every public
repository. `discovery/candidates.yaml` holds the candidates and versioned completeness evidence; `top100.md` points
to that evidence and the command prints a summary of it.

<!-- doctest: skip network (GitHub API) -->
```bash
sigharvest discover --max-code-requests 100 --max-http-requests 500 --max-repos 200 --no-auto-add
sigharvest discover --reverify
```

For each query the output records the pages read, the items returned, the provider's total where available,
whether it completed or was truncated, whether a budget ran out, why it stopped and any classified errors; strategy
summaries add these up. "Complete" means the query reached its reported end without a visible gap. It does not
prove that the provider's search index covers everything or that results stayed consistent while paging, so
`provider_complete` is always false. GitHub's 1,000-result cap, `incomplete_results`, changing totals, short pages,
low-yield code-search stops, duplicates across pages and GitLab's three-page cap are all recorded. Queries split by
repository size keep the incomplete evidence of the original query.

The code-query budget counts failed calls and cached queries as well as successful calls. The HTTP budget
counts attempts, including transport failures and retries, across all discovery strategies and metadata
lookups; cache hits do not count. Verification reports selected, verified, unverified and stale candidates
separately. Verification by `git` clone is outside the HTTP budget and has its own workers, repository size limit
and timeouts. A successful run can still be incomplete: check the completeness evidence, not the exit code.

## Identity and review

Candidates carry the repository id that GitHub or GitLab returns (scoped by provider). A renamed repository with
the same id stays one candidate and keeps its old URLs as aliases; cached ids connect names across runs. An existing
source matched through an old alias keeps its configured URL and name: discovery never retargets it silently. When
the provider returns no id, none is invented.

Disabled sources stay disabled, even when they rank at the top. New seeds and top candidates follow the usual enable
policy, except archived repositories, which always need review and are registered disabled. Every other candidate
registered automatically is disabled. A metadata or clone failure never removes a registered source or its last
good rules. Cached last-good counts can be shown as `stale` (unverified) but never register a source or appear as
current top results. `--reverify` ignores cached results and keeps the last-good history if the new verification
fails.

Negative HTTP results and zero-rule verifications are cached for at most one hour, even when the repository's push
time is unchanged; older negative entries without a verification time expire at once. Positive HTTP results are
cached for seven days by default, and a positive verification is reused only while the push time, ref and
provider id (when known) still match. A failed lookup does not prove deletion: `not_found` includes
private or renamed repositories. `gone` is reserved for explicit HTTP 410/451 responses; `missing_ref` applies
to a ref-specific request or a Git ref-resolution failure.

## Retry contract

The shared retry policy tells apart `auth`, `missing_ref`, `not_found`, `gone`, `rate_limit`, `transient`, invalid
responses and infrastructure or unknown failures. Only rate limits and transient failures are retried. HTTP 429 is
retried even without headers; a plain 401 or 403 is not. `Retry-After` accepts seconds or an HTTP date, with the
rate-limit reset time as a fallback; invalid, negative or non-finite values fall back to exponential backoff with
jitter. When the server asks for a longer wait than the budget allows, the request ends instead of retrying early.

Discovery allows at most eight attempts per HTTP call, at most 120 seconds total backoff and at most 60 seconds
per backoff, plus code-search pacing and transport timeouts. There is no sleep after the final attempt. HTTP
responses are capped at 8 MiB and cache reads at 64 MiB. Exceptions report categories without copying arbitrary
response bodies or URLs. Verification by `git` clone uses the same classification and backoff, with three attempts
for recognised transient failures. The HTTPS rule sources (`http-files`, `html`, `huggingface`) also use this
policy with three attempts and keep their last good rules if every retry fails. Git sync errors carry a category,
but `sync` does not retry Git commands or archive downloads by itself.

## Proposing sources for review

<!-- doctest: skip network (GitHub API) -->
```bash
sigharvest discover --output sources/discovered.yaml --known sources/curated.yaml --known sources/extended.yaml --denylist sources/denylist.yaml \
    --min-rules 5 --report-file discovered.md
```

With `--output`, verified repositories with at least `--min-rules` valid rules are written to that file in the
`sources.yaml` format, every entry `enabled: false`; `sources.yaml` and curated lists are never edited.
Repositories listed in `--known` or `--denylist` (sources files or plain YAML lists of names/URLs), mirrors and
archived repositories are left out. `--no-verify` only reuses cached verification results; `--cache-dir` moves the
HTTP and clone cache. A token from `GITHUB_TOKEN` (or `gh auth token`) raises GitHub's rate limits; it is never
written to any file.
