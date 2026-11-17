# Security policy

## Supported versions

sigharvest is young. Security fixes go into the latest release and `main`.

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Reporting a vulnerability

Please report security problems **privately**, not in a public issue: write to
[security@threat-hunting.eu](mailto:security@threat-hunting.eu) (read by the maintainers), or, once the repository is
public, use GitHub's private vulnerability reporting, the *Report a vulnerability* button on the **Security**
tab of this repository
(<https://github.com/threat-hunter-eu/sigharvest/security/advisories/new>). The report and the discussion stay visible to
the maintainers and you only, until an advisory is published. If the button is missing, private reporting is not
enabled yet: use the e-mail address. Include:

- the sigharvest version or commit;
- what an attacker controls (a rule repository? a YAML file? a web request?);
- a minimal reproduction.

You should get a first answer within 7 days. We will agree on a disclosure date with you and credit you in the
release notes if you wish.

## Threat model

sigharvest processes a lot of third-party content and treats all of it as **untrusted**:

- **Rule repositories**: Git URLs, archive contents, file paths and YAML from many third-party repositories.
  Sync protects against Git argument injection, path traversal in archives, decompression bombs and oversized
  blobs; YAML is parsed with safe loaders only, with depth, node and alias limits. Broken documents are
  quarantined and never printed raw.
- **Search text** is always quoted before it reaches SQLite FTS5, so it cannot inject query syntax.
- **Discovery** reads a GitHub token from `GITHUB_TOKEN` (or `gh auth token`) and never writes or logs it. With
  `--output` it never enables a source; every new repository needs a human to review and enable it.
- **The web UI** binds to `127.0.0.1` by default, where it has no login. Any other address requires
  `--token-env VAR` (HTTP Basic or Bearer token, 16+ characters, checked on every request); `serve` refuses to start
  without it. Writes (collections), downloads and searches require a same-origin request; `Host` checks prevent DNS
  rebinding (`serve --allow-host` or `SIGHARVEST_ALLOWED_HOSTS` add names); templates autoescape rule content and a strict
  Content-Security-Policy allows scripts only from the UI itself (no inline scripts, no CDN).
- **Exports**: CSV cells that would start a spreadsheet formula are escaped; zip members never escape the archive.
- **Releases** are verified against `SHA256SUMS` with byte, line and row limits before they are read
  (`lint --release`, `site build --release`).
- **Converted queries** are produced by pySigma backends from rule text. Review queries before running them in
  production; a malicious rule could be written to produce an expensive query.

Out of scope: the correctness of third-party rules, and the security of the SIEMs that run converted queries.

## Verifying a release

Each release published by `.github/workflows/nightly.yml` has `SHA256SUMS`. When the repository is public and the
maintainers enabled signing (`SIGHARVEST_SIGNING_ENABLED`, see docs/automation.md), it also has a keyless
[Sigstore](https://www.sigstore.dev/) signature of it, `SHA256SUMS.sigstore.json`, made by that workflow on the
`main` branch.

The files (and `SHA256SUMS.sigstore.json`) are assets of the data repository
[sigharvest-rules](https://github.com/threat-hunter-eu/sigharvest-rules/releases); they are built and signed by this
repository's workflow, so the identity below names `threat-hunter-eu/sigharvest`.

```bash
sha256sum --check --ignore-missing SHA256SUMS

cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/threat-hunter-eu/sigharvest/.github/workflows/nightly.yml@refs/heads/main
```

## Dependency advisories

Known advisories in the dependency tree and how they are handled:

| Package | Advisory | Where | Status |
|---|---|---|---|
| `opentelemetry-api` (via FastAPI) | GHSA-mf5v-w3w3-f6cg / CVE-2026-126360 (ReDoS in `traceparent` parsing) | base install | fixed: `uv.lock` resolves 1.45.2+ (`[tool.uv] constraint-dependencies`); sigharvest does not extract tracing context from requests |
| `diskcache` 5.6.3 (via pySigma 1.x) | GHSA-w8v5-vhqr-4h9v / CVE-2025-69872 (unpickling from the cache directory) | `[convert-legacy]` only | **no fixed release**. Exploitation needs write access to the user's own cache directory. Prefer `[convert]` (pySigma 2, no `diskcache`); `[convert-legacy]` goes away when the Elastic, OpenSearch and Kusto backends support pySigma 2 |

Dependabot (`.github/dependabot.yml`) proposes weekly grouped updates for the GitHub Actions pins and `uv.lock`.
The pySigma family is excluded (the two convert extras need different pySigma majors) and updated by hand with
`uv lock --upgrade-package`, tested with both extras.
