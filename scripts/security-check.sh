#!/usr/bin/env bash
# Verification gates of the secure coding standard (.knowledge/secure-coding/verification.md).
#
#   scripts/security-check.sh <gate>      run one gate
#   scripts/security-check.sh all         run every gate, print a summary, fail if any gate failed
#
# Gates: typecheck lint lint-security secrets deps-check check-suppressions test
# A missing tool fails its gate (SC-AGT-008); it is never skipped. Protected file: changes need AppSec review.
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

PY="${PY:-$ROOT/.venv/bin/python}"
RUFF="${RUFF:-$ROOT/.venv/bin/ruff}"
PIP_AUDIT="${PIP_AUDIT:-$ROOT/.venv/bin/pip-audit}"
MYPY="${MYPY:-$ROOT/.venv/bin/mypy}"
SEMGREP="${SEMGREP:-$ROOT/.tools/semgrep/bin/semgrep}"
# gitleaks: a checksum-verified release in .tools/gitleaks if present (SC-DEP-006), else the one on PATH.
if [[ -z "${GITLEAKS:-}" ]]; then
  if [[ -x "$ROOT/.tools/gitleaks/gitleaks" ]]; then GITLEAKS="$ROOT/.tools/gitleaks/gitleaks"; else GITLEAKS=gitleaks; fi
fi

# BASE_REF: the branch this work will merge into. Defaults to origin/main, then main; on main itself with no
# remote, HEAD (only uncommitted changes count as "new").
if [[ -z "${BASE_REF:-}" ]]; then
  if git rev-parse -q --verify origin/main >/dev/null; then BASE_REF=origin/main
  elif [[ "$(git branch --show-current)" != "main" ]] && git rev-parse -q --verify main >/dev/null; then BASE_REF=main
  else BASE_REF=HEAD; fi
fi
export BASE_REF

need() { # need <executable> <how to install>
  if ! command -v "$1" >/dev/null 2>&1 && [[ ! -x "$1" ]]; then
    echo "✖ missing tool: $1 ($2). The gate fails; it is not skipped." >&2
    return 1
  fi
}

gate_typecheck() {
  # Python: mypy with the settings in pyproject.toml ([tool.mypy]); the web app is strict TypeScript.
  need "$MYPY" 'pip install -e ".[security]"' || return 1
  "$MYPY" || return 1
  (cd web && npx --no-install tsc --noEmit -p .)
}

gate_lint() {
  need "$RUFF" 'pip install -e ".[security]"' || return 1
  "$RUFF" check . || return 1
  (cd web && npm run --silent lint) || return 1
  need pwsh "install PowerShell 7.4+" || return 1
  pwsh -NoProfile -Command '
    if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) { Write-Error "PSScriptAnalyzer is not installed (Install-Module PSScriptAnalyzer -Scope CurrentUser)"; exit 1 }
    $r = Invoke-ScriptAnalyzer -Path ./collector -Recurse -Severity Error,Warning
    if ($r) { $r | Format-Table -AutoSize | Out-String | Write-Host; exit 1 }' || return 1
}

gate_lint_security() {
  need "$SEMGREP" "python3 -m venv .tools/semgrep && .tools/semgrep/bin/pip install semgrep==1.185.0" || return 1
  local baseline=()
  # Findings that already existed at the recorded baseline commit are triaged (see verification.md); only new
  # findings fail. The baseline is set by AppSec in a protected file.
  if [[ -s .semgrep/baseline-commit ]]; then baseline=(--baseline-commit "$(tr -d '[:space:]' < .semgrep/baseline-commit)"); fi
  "$SEMGREP" --test --config .semgrep/rules .semgrep/tests --quiet >/dev/null || { echo "✖ custom Semgrep rule tests failed"; return 1; }
  "$SEMGREP" scan --config p/python --config p/typescript --config p/javascript --config p/owasp-top-ten \
    --config .semgrep/rules --metrics=off --error --quiet "${baseline[@]}" .
}

gate_secrets() {
  need "$GITLEAKS" "download a release from github.com/gitleaks/gitleaks and verify its checksum" || return 1
  local range="HEAD"  # whole history when there is no base branch
  if [[ "$BASE_REF" != "HEAD" ]]; then range="$(git merge-base "$BASE_REF" HEAD)..HEAD"; fi
  "$GITLEAKS" git --redact --no-banner --log-opts="$range" .
}

gate_deps_check() {
  need "$PIP_AUDIT" 'pip install -e ".[security]"' || return 1
  [[ -f requirements.lock ]] || { echo "✖ requirements.lock is missing (SC-DEP-003)"; return 1; }
  "$PIP_AUDIT" --require-hashes --disable-pip --no-deps -r requirements.lock --progress-spinner off || return 1
  # A pinned, current npm: older npm releases can't verify signatures made with the registry's rotated keys.
  local npm_cli=(npx --yes "${NPM_AUDIT_CLI:-npm@11.21.2}")
  (cd web && npx --no-install lockfile-lint --path package-lock.json --type npm --allowed-hosts npm --validate-https \
    && "${npm_cli[@]}" audit --audit-level=high && "${npm_cli[@]}" audit signatures)
}

gate_check_suppressions() {
  bash scripts/check-suppressions.sh
}

gate_test() {
  "$PY" -m pytest -q -p no:cacheprovider || return 1
  (cd web && npx --no-install vitest run)
}

GATES=(typecheck lint lint-security secrets deps-check check-suppressions test)

run_gate() {
  local fn="gate_${1//-/_}"
  declare -F "$fn" >/dev/null || { echo "unknown gate: $1 (choose from: ${GATES[*]} all)" >&2; return 2; }
  echo "── $1 ──"
  "$fn"
}

case "${1:-all}" in
  all)
    failed=()
    for g in "${GATES[@]}"; do run_gate "$g" || failed+=("$g"); done
    echo
    for g in "${GATES[@]}"; do
      if [[ " ${failed[*]} " == *" $g "* ]]; then echo "✖ $g"; else echo "✔ $g"; fi
    done
    [[ ${#failed[@]} -eq 0 ]] && echo "All security gates passed (BASE_REF=$BASE_REF)." || { echo "${#failed[@]} gate(s) failed."; exit 1; }
    ;;
  *) run_gate "$1" ;;
esac
