#!/usr/bin/env bash
# scripts/provision-testbed-repo.sh — One-time setup for bobnetsec/bob-workflows-testbed.
#
# Usage:
#   ./scripts/provision-testbed-repo.sh [--repo OWNER/REPO] [--help]
#
# What this script does:
#   1. Verifies the testbed repo exists (creates it if not).
#   2. Ensures the caller workflow (.github/workflows/bob-review.yml) is present
#      on the default branch.
#   3. Verifies the required org-level secrets are set (cannot read values, only
#      checks presence).
#   4. Verifies the BOB_VERSION org variable is set.
#
# This is a one-time provisioning step that should be run before any T3 test
# runs.  It is idempotent: running it on an already-provisioned repo is safe.
#
# Prerequisites:
#   gh CLI >= 2.30, authenticated with repo creation + secrets:write scope.
# ---------------------------------------------------------------------------

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TESTBED_REPO="bobnetsec/bob-workflows-testbed"
DEFAULT_BRANCH="main"
WORKFLOW_FILE=".github/workflows/bob-review.yml"
CALLER_TEMPLATE="/tmp/bob-gh-action/output/T3/testbed-bob-review.yml"

# Allow override via --repo flag
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) TESTBED_REPO="$2"; shift 2 ;;
    --help)
      grep '^#' "$0" | grep -v '#!/' | sed 's/^# //' | sed 's/^#//'
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

TESTBED_ORG="${TESTBED_REPO%%/*}"
TESTBED_NAME="${TESTBED_REPO##*/}"

info()  { echo "[provision-testbed] $*" >&2; }
ok()    { echo "[provision-testbed] OK  $*" >&2; }
die()   { echo "[provision-testbed] FATAL $*" >&2; exit 1; }

command -v gh &>/dev/null || die "gh CLI not found."
gh auth status &>/dev/null || die "gh CLI not authenticated."

# ---------------------------------------------------------------------------
# 1. Ensure repo exists
# ---------------------------------------------------------------------------
if ! gh repo view "${TESTBED_REPO}" --json name &>/dev/null; then
  info "Repo ${TESTBED_REPO} not found — creating it..."
  gh repo create "${TESTBED_REPO}" \
    --private \
    --description "T3 integration test testbed for Bob Diff Review" \
    --add-readme
  ok "Created ${TESTBED_REPO}"
else
  ok "Repo ${TESTBED_REPO} exists"
fi

# ---------------------------------------------------------------------------
# 2. Ensure caller workflow is present on default branch
# ---------------------------------------------------------------------------
# Check whether the file already exists
EXISTING_WORKFLOW="$(gh api \
  "repos/${TESTBED_REPO}/contents/${WORKFLOW_FILE}" \
  --jq '.sha' 2>/dev/null || echo "")"

# Find the caller template (canonical path first, then in-repo fallback)
if [[ ! -f "${CALLER_TEMPLATE}" ]]; then
  # Fallback: look for the W2 output bundled in the repo (for CI environments)
  CALLER_TEMPLATE="${REPO_ROOT}/test/fixtures/testbed-bob-review.yml"
fi

if [[ ! -f "${CALLER_TEMPLATE}" ]]; then
  die "Caller workflow template not found. Expected at ${CALLER_TEMPLATE}."
fi

WORKFLOW_CONTENT="$(base64 < "${CALLER_TEMPLATE}")"

if [[ -z "${EXISTING_WORKFLOW}" ]]; then
  info "Installing caller workflow at ${WORKFLOW_FILE}..."
  gh api \
    --method PUT \
    "repos/${TESTBED_REPO}/contents/${WORKFLOW_FILE}" \
    -f message="ci: add Bob Diff Review caller workflow (T3 provisioning)" \
    -f content="${WORKFLOW_CONTENT}" \
    --silent
  ok "Caller workflow installed"
else
  info "Caller workflow already present (sha=${EXISTING_WORKFLOW}). Updating..."
  gh api \
    --method PUT \
    "repos/${TESTBED_REPO}/contents/${WORKFLOW_FILE}" \
    -f message="ci: update Bob Diff Review caller workflow (T3 provisioning)" \
    -f content="${WORKFLOW_CONTENT}" \
    -f sha="${EXISTING_WORKFLOW}" \
    --silent
  ok "Caller workflow updated"
fi

# ---------------------------------------------------------------------------
# 3. Check required org secrets are set
# ---------------------------------------------------------------------------
info "Checking org-level secrets..."

for secret_name in ANTHROPIC_API_KEY BOB_INSTALL_TOKEN; do
  SECRETS_JSON="$(gh api \
    "orgs/${TESTBED_ORG}/actions/secrets" \
    --jq '.secrets[].name' 2>/dev/null || echo "")"

  if echo "${SECRETS_JSON}" | grep -q "^${secret_name}$"; then
    ok "Org secret ${secret_name} is set"
  else
    echo "[provision-testbed] WARN: Org secret ${secret_name} not found in ${TESTBED_ORG}" >&2
    echo "  Set it at: https://github.com/organizations/${TESTBED_ORG}/settings/secrets/actions" >&2
  fi
done

# ---------------------------------------------------------------------------
# 4. Check BOB_VERSION org variable
# ---------------------------------------------------------------------------
BOB_VERSION_VAL="$(gh api \
  "orgs/${TESTBED_ORG}/actions/variables/BOB_VERSION" \
  --jq '.value' 2>/dev/null || echo "")"

if [[ -n "${BOB_VERSION_VAL}" ]]; then
  ok "Org variable BOB_VERSION=${BOB_VERSION_VAL}"
else
  echo "[provision-testbed] WARN: Org variable BOB_VERSION not set in ${TESTBED_ORG}" >&2
  echo "  Set it at: https://github.com/organizations/${TESTBED_ORG}/settings/variables/actions" >&2
fi

echo ""
info "Testbed provisioning complete."
info "Run the T3 integration test with:"
info "  ./scripts/test-live-integration.sh"
