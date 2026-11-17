#!/usr/bin/env bash
# Runs on this machine what ci.yml, ci-full.yml and ci-docs.yml run on GitHub (docs/automation.md#what-runs-when),
# without spending Actions minutes: lint, actionlint (when installed), pytest on 3.12 [convert], 3.13 [convert] and
# 3.12 [convert-legacy], the docs examples on both extras, the phone-width layout (Playwright), the acceptance matrix
# (locked/newest x convert/convert-legacy) and the privacy gate. Only the Windows job has no local equivalent.
#
#   scripts/ci-full-local.sh            # everything; a failed step does not stop the others
#   scripts/ci-full-local.sh --quick    # only what runs on every push (ci.yml)
#
# Extra environments (3.13, [convert-legacy]) live in ${SIGHARVEST_CI_ENVS:-~/.cache/sigharvest-ci}, outside the
# checkout. Exit: 0 when every step passed, 1 otherwise (the failed steps are listed at the end).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
ENVS=${SIGHARVEST_CI_ENVS:-${XDG_CACHE_HOME:-$HOME/.cache}/sigharvest-ci}
QUICK=0
[ "${1:-}" = --quick ] && QUICK=1
failed=()
step() { # step NAME COMMAND...
    local name=$1; shift
    printf '\n\033[1m== %s\033[0m\n' "$name"
    "$@" || failed+=("$name")
}
legacy() { UV_PROJECT_ENVIRONMENT="$ENVS/py312-legacy" uv run --locked --python 3.12 --no-default-groups --group test --extra convert-legacy "$@"; }
py313() { UV_PROJECT_ENVIRONMENT="$ENVS/py313" uv run --locked --python 3.13 "$@"; }

uv sync --locked || exit 2
step "ruff" uv run --no-sync ruff check src tests scripts
step "ruff format" uv run --no-sync ruff format --check src tests scripts
step "mypy" uv run --no-sync mypy
if command -v actionlint >/dev/null; then step "actionlint" actionlint; else echo "actionlint not installed: skipped"; fi
step "pytest (py3.12, convert)" uv run --no-sync pytest -n auto
step "privacy gate" python3 -I scripts/privacy_gate.py . --allowlist .github/privacy-allowlist.txt --history

if [ "$QUICK" = 0 ]; then
    step "pytest (py3.13, convert)" py313 pytest -n auto
    step "pytest (py3.12, convert-legacy)" legacy pytest -n auto
    step "docs examples (convert)" uv run --no-sync pytest -n auto -m docs tests/test_docs.py
    step "docs examples (convert-legacy)" legacy pytest -n auto -m docs tests/test_docs.py
    step "layout (Playwright, 390 px)" bash -c 'uv run --locked --group browser playwright install chromium &&
        SIGHARVEST_REQUIRE_BROWSER=1 uv run --locked --group browser pytest -n0 -rs tests/test_web_layout.py'
    for extra in convert convert-legacy; do
        step "acceptance ($extra, locked)" bash tests/acceptance/accept.sh sigharvest "$PWD" --offline --extra "$extra" --locked
        step "acceptance ($extra, newest)" bash tests/acceptance/accept.sh sigharvest "$PWD" --offline --extra "$extra"
    done
fi

if [ "${#failed[@]}" -gt 0 ]; then
    printf '\nFAILED: %s\n' "${failed[@]}"
    exit 1
fi
printf '\nall steps passed\n'
