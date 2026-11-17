# Contributing to sigharvest

Thanks for helping! Bug reports, source suggestions, docs fixes and code are all welcome.

## Quick ways to help

- **Suggest a rule repository**: open an issue with the URL, its licence and roughly how many Sigma rules it has
  (original content, maintained, not a mirror), or add it to `sources/extended.yaml` in a pull request. Curated
  sources must have a clear licence; sources whose licence does not allow redistribution are listed with
  `redistribute: no` and are published as metadata and links only.
- **Report a dedup problem**: two rules that should (or should not) be one. Include both keys from
  `sigharvest search` and `sigharvest --version`.
- **Report a conversion problem**: first check whether `sigma convert` (sigma-cli) gives the same result. If it
  does, the issue belongs to pySigma or the backend.
- **Rule content problems** (false positives, wrong tags): report them to the rule's source repository, linked on
  every rule page.

## Development setup

You need Python 3.12+, Git and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/threat-hunter-eu/sigharvest
cd sigharvest
uv sync                         # creates .venv with the dev dependencies and the [convert] extra
uv run sigharvest --help
uv run pre-commit install       # optional: ruff, ruff format and mypy on every commit
```

## Before you open a pull request

```bash
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts
uv run pytest -n 8
python3 -I scripts/privacy_gate.py . --allowlist .github/privacy-allowlist.txt --history
```

Or everything CI runs (3.13, [convert-legacy], the docs examples, the layout, the acceptance matrix; only the Windows
job is left to GitHub) in one command, without spending Actions minutes:

```bash
scripts/ci-full-local.sh            # --quick: only what runs on every push
```

**What runs when** ([docs/automation.md](docs/automation.md#what-runs-when)): every push runs `ci.yml` only (ruff,
mypy, actionlint, pytest on 3.12 [convert], privacy gate). Python 3.13, [convert-legacy], Windows, the layout, the
acceptance matrix and the docs examples run on pull requests to main, daily when `SIGHARVEST_FULL_CI_ENABLED` is
`true`, and from Actions -> Run workflow.

- **Tests run in parallel** (pytest-xdist): keep them independent of each other, writing only under `tmp_path`.
- **Tests never touch the network.** Sources in tests are temporary local folders or Git repositories created in
  `tmp_path`; a guard in `tests/offline.py` blocks outgoing connections.
- `slow` marks expensive integration tests; they are excluded by default. Run everything with
  `uv run pytest -n 8 -m "slow or not slow"`.
- `tests/acceptance/accept.sh sigharvest --offline` installs the wheel into a clean environment and walks through
  a new user's first session (CI runs it on pull requests to main; see [tests/acceptance/README.md](tests/acceptance/README.md)).
- **Shell examples in the docs are tests.** Every ```` ```bash ```` block in README.md and docs/*.md needs
  `<!-- doctest -->` (it runs) or `<!-- doctest: skip REASON -->` on the line above it; `uv run pytest -m docs
  tests/test_docs.py` runs the marked ones against an offline fixture workspace (CI job "docs examples").
- **New behaviour comes with a test.** Bug fixes come with a test that fails before the fix.
- **Keep outputs stable.** If your change alters the logic hash, export layout or release files, say so in the PR
  description. A change to the logic hash canonicalisation bumps `LOGIC_VERSION` in `identity.py` and updates
  [docs/identity.md](docs/identity.md) and the golden tests.
- Schema changes go through Alembic: edit `src/sigharvest/models.py`, add a revision on top of
  `src/sigharvest/migrations/versions/0001_baseline.py` and review it.
- User data (collections) is keyed by stable identifiers (logic hash, rule id). Never point it at `logic_groups`
  rows: the index is rebuilt after every update.
- **Update the docs** (`docs/`, `README.md`) and add a line to `CHANGELOG.md` under *Unreleased*.
- Keep pull requests focused; one topic per PR is easier to review.

## Privacy rules for this repository

This is a public project. Never commit:

- private rules, or rule content whose licence does not allow redistribution;
- API keys, tokens, internal hostnames, internal paths or e-mail addresses (commits must use a noreply address).

CI runs the privacy gate (`scripts/privacy_gate.py`, with gitleaks) over the tree and the whole history on every
push and PR, and fails if it finds any of these. Justified exceptions go to `.github/privacy-allowlist.txt`.

## Licence

By contributing you agree that your contribution is released under the project's [MIT licence](LICENSE).

## Project layout

See [docs/architecture.md](docs/architecture.md) for the pipeline, the dedup algorithm and the code map, and
[docs/automation.md](docs/automation.md) for the GitHub workflows.

## Code of conduct

Be kind and assume good faith. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
