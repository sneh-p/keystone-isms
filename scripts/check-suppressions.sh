#!/usr/bin/env bash
# Enforces SC-AGT-001 (no unregistered suppressions or skipped tests) and SC-AGT-002 (protected files).
# Compares the working tree with the merge base of BASE_REF (see scripts/security-check.sh for the default).
# Requires git >= 2.30. Protected file: changes need AppSec review.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

BASE_REF="${BASE_REF:-origin/main}"
if ! git rev-parse -q --verify "$BASE_REF^{commit}" >/dev/null; then
  echo "✖ BASE_REF '$BASE_REF' does not exist. Set BASE_REF to the branch you will merge into." >&2
  exit 1
fi
REGISTER=".knowledge/secure-coding/exceptions.md"

# Lines added since the merge base (committed or not). The standard's own text, these scripts, the protected
# lint configs and the Semgrep rule test cases legitimately contain the suppression keywords.
added=$(git diff --merge-base "$BASE_REF" -U0 -- . \
  ':(exclude).knowledge/**' ':(exclude)AGENTS.md' ':(exclude)CLAUDE.md' \
  ':(exclude)scripts/check-suppressions.sh' ':(exclude)scripts/security-check.sh' \
  ':(exclude)ruff.toml' ':(exclude)web/eslint.config.js' ':(exclude).semgrep/**' \
  ':(exclude)tests/test_check_suppressions.py' \
  | grep -E '^\+[^+]' || true)
# New files that are not staged yet don't appear in git diff: include their lines too.
EXCLUDED='^(\.knowledge/|AGENTS\.md$|CLAUDE\.md$|scripts/check-suppressions\.sh$|scripts/security-check\.sh$|ruff\.toml$|web/eslint\.config\.js$|\.semgrep/|tests/test_check_suppressions\.py$)'
while IFS= read -r -d '' f; do
  [[ "$f" =~ $EXCLUDED ]] && continue
  grep -Iq . "$f" 2>/dev/null || continue  # skip binary and empty files
  added+=$'\n'$(sed 's/^/+/' "$f")
done < <(git ls-files --others --exclude-standard -z)

# 1. New suppressions and skipped tests must reference an exception ID.
SUPPRESSIONS='eslint-disable|@ts-ignore|@ts-nocheck|@ts-expect-error|nosemgrep|gitleaks:allow|#[[:space:]]*noqa|#[[:space:]]*nosec|#[[:space:]]*type:[[:space:]]*ignore|pytest\.mark\.(skip|skipif|xfail)|pytest\.skip\(|pytest\.xfail\(|\.(skip|only)\(|SuppressMessage|--passWithNoTests|--ignore-vuln'
untagged=$(grep -E "$SUPPRESSIONS" <<<"$added" | grep -vE 'security-exception: EX-[0-9]{3}' || true)
if [[ -n "$untagged" ]]; then
  echo "✖ SC-AGT-001: suppressions or skipped tests without 'security-exception: EX-NNN':"
  echo "$untagged"
  exit 1
fi

# 2. Every referenced ID must exist in the Register section (not the Examples section) and not be expired.
registered=$(awk '/^# Register/{f=1; next} /^# /{f=0} f' "$REGISTER")
ids=$(grep -oE 'security-exception: EX-[0-9]{3}' <<<"$added" | grep -oE 'EX-[0-9]{3}' | sort -u || true)
today=$(date -u +%F)
for id in $ids; do
  row=$(grep -E "^\| *$id *\|" <<<"$registered" || true)
  if [[ -z "$row" ]]; then
    echo "✖ SC-AGT-001: $id is referenced but not registered in $REGISTER"
    exit 1
  fi
  expires=$(awk -F'|' '{gsub(/ /, "", $7); print $7}' <<<"$row")
  if [[ -n "$expires" && "$expires" < "$today" ]]; then
    echo "✖ SC-AGT-001: $id expired on $expires; AppSec must renew it or the code must change"
    exit 1
  fi
done

# 3. Protected files. CODEOWNERS is the real gate; this catches it before a PR exists.
PROTECTED='^(\.knowledge/secure-coding/|AGENTS\.md$|CLAUDE\.md$|ruff\.toml$|\.semgrep/|\.semgrepignore$|\.gitleaks\.toml$|web/eslint\.config\.js$|web/\.npmrc$|web/tsconfig.*\.json$|\.github/|scripts/check-suppressions\.sh$|scripts/security-check\.sh$)'
protected=$( { git diff --merge-base "$BASE_REF" --name-only; git ls-files --others --exclude-standard; } | sort -u | grep -E "$PROTECTED" || true)
if [[ -n "$protected" && "${ALLOW_PROTECTED:-0}" != "1" ]]; then
  echo "✖ SC-AGT-002: protected security files changed; needs explicit human approval:"
  echo "$protected"
  exit 1
fi

echo "✔ suppression and protected-file checks passed"
