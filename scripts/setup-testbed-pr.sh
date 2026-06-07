#!/usr/bin/env bash
# scripts/setup-testbed-pr.sh — Create the live integration test PR on
# bobnetsec/bob-workflows-testbed.
#
# Usage:
#   ./scripts/setup-testbed-pr.sh [--branch BRANCH] [--commit-msg MSG] [--base BASE]
#
# Options:
#   --branch BRANCH   Feature branch name (default: test/t3-sqli-$(date +%s))
#   --commit-msg MSG  Commit message (default: "test: add known-vulnerable Express routes for T3 integration test")
#   --base BASE       Base branch (default: main)
#   --amend           Push an amend commit on an existing branch (cache-hit second run)
#   --help            Show this message and exit.
#
# Prerequisites:
#   gh CLI >= 2.30    authenticated against bobnetsec org
#   git               in PATH
#
# What this script does:
#   1. Clones bobnetsec/bob-workflows-testbed into a temp dir.
#   2. Creates a feature branch.
#   3. Copies the known-vulnerable Express route files from
#      test/fixtures/testbed-pr-vuln.diff into the clone.
#   4. Commits and pushes to origin.
#   5. Opens a PR via `gh pr create`.
#   6. Prints the PR URL and PR number to stdout (and writes them to
#      /tmp/t3-testbed-pr.env for use by test-live-integration.sh).
#
# Known-vulnerable patterns that should trigger at least one finding:
#   - src/routes/users.js line 20: SQL injection via unsanitised `name` param.
#   - src/routes/users.js line 38: BOLA/IDOR — no authz on GET /users/:id.
#   - src/routes/users.js line 52: privilege escalation via mass-assignment.
#
# Second-run amend commit (--amend):
#   Adds a whitespace-only change to src/routes/users.js to trigger a second
#   workflow run on the same PR. The session cache should already be populated
#   from run 1, causing SKIP_SURFACE_BUILD=true (C2 cache hit).
# ---------------------------------------------------------------------------

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="${REPO_ROOT}/scripts"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
TESTBED_REPO="bobnetsec/bob-workflows-testbed"
DEFAULT_BRANCH="test/t3-sqli-$(date +%s)"
BRANCH="${DEFAULT_BRANCH}"
BASE_BRANCH="main"
COMMIT_MSG="test: add known-vulnerable Express routes for T3 integration test"
PR_TITLE="T3 integration test: known-vulnerable Express route (SQL injection + BOLA)"
PR_BODY="$(cat <<'PRBODY'
## T3 Integration Test PR

This PR adds a known-vulnerable Express route to trigger the Bob Diff Review
workflow and validate the live integration test acceptance criteria.

### Known vulnerabilities in this diff

| File | Line | Class | Expected severity |
|------|------|-------|-------------------|
| `src/routes/users.js` | 20 | SQL injection (unsanitised query param) | critical or high |
| `src/routes/users.js` | 38 | BOLA / IDOR (no authz on GET /users/:id) | high |
| `src/routes/users.js` | 52 | Privilege escalation (mass-assignment) | high |

### Validation checklist (T3 acceptance criteria)

- [ ] Bob Diff Review check run appears in the Checks tab
- [ ] At least one inline PR review comment is posted on the diff
- [ ] Check run conclusion is `failure` (high-severity finding present)
- [ ] Second push triggers a new workflow run with C2 cache hit
- [ ] Second run completes faster than first run (cache speedup)
- [ ] No secrets appear in the Actions run logs

**Do not merge this PR.** It is an automated integration test fixture.
PRBODY
)"
AMEND_MODE=false
ENV_OUT="/tmp/t3-testbed-pr.env"

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --branch)    BRANCH="$2"; shift 2 ;;
    --commit-msg) COMMIT_MSG="$2"; shift 2 ;;
    --base)      BASE_BRANCH="$2"; shift 2 ;;
    --amend)     AMEND_MODE=true; shift ;;
    --help)
      grep '^#' "$0" | grep -v '#!/' | sed 's/^# //' | sed 's/^#//'
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()  { echo "[setup-testbed-pr] $*" >&2; }
ok()    { echo "[setup-testbed-pr] OK  $*" >&2; }
fail()  { echo "[setup-testbed-pr] FAIL $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
if ! command -v gh &>/dev/null; then
  fail "gh CLI not found. Install from https://cli.github.com"
fi
if ! command -v git &>/dev/null; then
  fail "git not found."
fi

# Verify gh auth
if ! gh auth status &>/dev/null; then
  fail "gh CLI is not authenticated. Run: gh auth login"
fi

# Verify the testbed repo is accessible
if ! gh repo view "${TESTBED_REPO}" --json name &>/dev/null; then
  fail "Cannot access ${TESTBED_REPO}. Ensure the repo exists and gh has access."
fi

# ---------------------------------------------------------------------------
# Clone the testbed repo
# ---------------------------------------------------------------------------
TMPDIR_CLONE="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_CLONE}"' EXIT

info "Cloning ${TESTBED_REPO} into ${TMPDIR_CLONE}..."
gh repo clone "${TESTBED_REPO}" "${TMPDIR_CLONE}/testbed" -- --depth=1 --quiet

CLONE_DIR="${TMPDIR_CLONE}/testbed"

cd "${CLONE_DIR}"

# ---------------------------------------------------------------------------
# Amend mode: push a second commit on an existing branch
# ---------------------------------------------------------------------------
if [[ "${AMEND_MODE}" == "true" ]]; then
  # Read the existing branch from the env file written by the first run.
  if [[ ! -f "${ENV_OUT}" ]]; then
    fail "--amend requires ${ENV_OUT} to exist (written by the first run)."
  fi

  # shellcheck source=/dev/null
  source "${ENV_OUT}"

  if [[ -z "${T3_BRANCH:-}" ]]; then
    fail "T3_BRANCH not set in ${ENV_OUT}."
  fi

  info "Amend mode: checking out branch ${T3_BRANCH}..."
  git fetch origin "${T3_BRANCH}"
  git checkout "${T3_BRANCH}"

  # Whitespace-only change to trigger a new diff without altering semantics.
  AMEND_FILE="src/routes/users.js"
  if [[ ! -f "${AMEND_FILE}" ]]; then
    fail "${AMEND_FILE} does not exist on branch ${T3_BRANCH}."
  fi

  # Append a blank comment line at the bottom
  printf '\n// second-run trigger\n' >> "${AMEND_FILE}"
  git add "${AMEND_FILE}"
  git commit -m "test: second-run commit to trigger C2 cache-hit validation"
  git push origin "${T3_BRANCH}"

  ok "Second commit pushed to ${T3_BRANCH}."
  info "Workflow will re-run on PR #${T3_PR_NUMBER}. Watch the Actions tab for C2 cache hit."
  exit 0
fi

# ---------------------------------------------------------------------------
# First run: create branch, apply vulnerable diff, open PR
# ---------------------------------------------------------------------------
info "Creating branch ${BRANCH} from ${BASE_BRANCH}..."
git checkout -b "${BRANCH}" "origin/${BASE_BRANCH}"

# Apply the vulnerable source files
VULN_DIFF="${REPO_ROOT}/test/fixtures/testbed-pr-vuln.diff"
if [[ ! -f "${VULN_DIFF}" ]]; then
  fail "Vulnerable diff fixture not found at ${VULN_DIFF}."
fi

info "Applying vulnerable diff from ${VULN_DIFF}..."
# Ensure target dirs exist
mkdir -p src/routes

# Apply via git apply (requires the testbed clone to be the working dir)
git apply --whitespace=nowarn "${VULN_DIFF}" || {
  info "git apply failed — falling back to manual patch extraction..."
  # Extract individual files from the diff manually
  # src/routes/users.js
  mkdir -p src/routes
  cat > src/routes/users.js << 'USERS_JS'
const express = require('express');
const db = require('../db');

const router = express.Router();

/**
 * GET /users/search
 *
 * Search users by name.  The `name` query parameter is inserted directly
 * into the SQL query without sanitisation — SQL injection is possible.
 *
 * Example (safe): SELECT * FROM users WHERE name = $1   (parameterised)
 * Example (UNSAFE, current): SELECT * FROM users WHERE name = '${name}'
 */
router.get('/search', async (req, res) => {
  const name = req.query.name;

  // VULNERABILITY: unsanitised user input interpolated into SQL string.
  // An attacker can supply: ' OR '1'='1 to dump all users.
  const query = `SELECT id, username, email FROM users WHERE name = '${name}'`;

  try {
    const result = await db.raw(query);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

/**
 * GET /users/:id
 *
 * Fetch user profile by id.  No authorization check — any authenticated
 * session (or unauthenticated request if the middleware is not applied)
 * can read any user record.
 *
 * VULNERABILITY: broken object-level authorization (BOLA / IDOR).
 */
router.get('/:id', async (req, res) => {
  const userId = req.params.id;
  // No ownership or role check before querying
  const user = await db('users').where({ id: userId }).first();
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json(user);
});

/**
 * POST /users/:id/admin
 *
 * Promote user to admin.  The `role` body parameter is trusted without
 * validating that the caller is themselves an admin.
 *
 * VULNERABILITY: mass-assignment / privilege escalation.
 */
router.post('/:id/admin', async (req, res) => {
  const userId = req.params.id;
  const { role } = req.body;
  // No authZ check — any user can escalate any account
  await db('users').where({ id: userId }).update({ role });
  res.json({ ok: true });
});

module.exports = router;
USERS_JS

  # src/db.js
  cat > src/db.js << 'DB_JS'
const knex = require('knex');

const db = knex({
  client: 'pg',
  connection: {
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'app',
    user: process.env.DB_USER || 'app',
    password: process.env.DB_PASS || 'change_me_in_production',
  },
});
module.exports = db;
DB_JS
}

# Update or create package.json
if [[ -f package.json ]]; then
  # Use node to merge the deps into an existing package.json
  node -e "
    const fs = require('fs');
    const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
    pkg.dependencies = Object.assign({}, pkg.dependencies || {}, {
      express: '^4.18.2',
      knex: '^3.1.0',
      pg: '^8.11.3'
    });
    fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n');
  "
else
  cat > package.json << 'PKG_JSON'
{
  "name": "testbed-app",
  "version": "1.0.1",
  "dependencies": {
    "express": "^4.18.2",
    "knex": "^3.1.0",
    "pg": "^8.11.3"
  }
}
PKG_JSON
fi

# Stage all changes
git add src/routes/users.js src/db.js package.json

# Check that we have something to commit
if git diff --cached --quiet; then
  fail "No staged changes — nothing to commit. Did the diff apply correctly?"
fi

info "Committing..."
git commit -m "${COMMIT_MSG}"

info "Pushing branch ${BRANCH} to origin..."
git push origin "${BRANCH}"

info "Opening PR against ${BASE_BRANCH}..."
PR_URL="$(gh pr create \
  --repo "${TESTBED_REPO}" \
  --head "${BRANCH}" \
  --base "${BASE_BRANCH}" \
  --title "${PR_TITLE}" \
  --body "${PR_BODY}" \
  --label "integration-test" 2>/dev/null || true)"

if [[ -z "${PR_URL}" ]]; then
  # Try without --label in case the label doesn't exist yet
  PR_URL="$(gh pr create \
    --repo "${TESTBED_REPO}" \
    --head "${BRANCH}" \
    --base "${BASE_BRANCH}" \
    --title "${PR_TITLE}" \
    --body "${PR_BODY}")"
fi

PR_NUMBER="$(basename "${PR_URL}")"

ok "PR created: ${PR_URL}"

# Write the env file for use by test-live-integration.sh
cat > "${ENV_OUT}" << ENVFILE
T3_PR_URL="${PR_URL}"
T3_PR_NUMBER="${PR_NUMBER}"
T3_BRANCH="${BRANCH}"
T3_REPO="${TESTBED_REPO}"
T3_CREATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ENVFILE

info "PR info written to ${ENV_OUT}"
echo ""
echo "PR URL:    ${PR_URL}"
echo "PR number: ${PR_NUMBER}"
echo "Branch:    ${BRANCH}"
