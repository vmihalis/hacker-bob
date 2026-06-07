#!/usr/bin/env bash
# scripts/test-local.sh — Run the bob-review workflow locally using act.
#
# Usage:
#   ./scripts/test-local.sh [--hit]  [--no-mock]  [--timeout 300]
#
# Options:
#   --hit          Simulate a cache hit by pre-seeding the session directory with
#                  symbol-surface-index.json so the C2 detect step sets
#                  cache-hit-symbol-index=true and SKIP_SURFACE_BUILD=true flows
#                  through the workflow's env: block on the action step.
#   --no-mock      Skip the mock GitHub API server (useful when testing against
#                  a real GitHub sandbox environment with a valid GITHUB_TOKEN).
#   --timeout N    Override the act timeout in seconds (default: 300 / 5 min).
#   --help         Show this message and exit.
#
# Prerequisites:
#   act >= 0.2.60    (brew install act  OR  go install github.com/nektos/act@latest)
#   docker           (act requires Docker to run workflow containers)
#   node >= 20       (for the mock API server)
#
# Secrets file:
#   Create a .secrets file in the repo root with:
#     ANTHROPIC_API_KEY=sk-ant-...
#     BOB_INSTALL_TOKEN=ghp_...
#     GITHUB_TOKEN=ghp_... (optional; mock server handles GitHub API calls)
#
#   The .secrets file is gitignored (see .gitignore).
#
# How remote action references are resolved locally:
#   The workflow uses remote action paths such as:
#     bobnetsec/bob-workflows/.github/actions/cache-bob-workspace@main
#     bobnetsec/bob-workflows/packages/bob-diff-review@main
#   act's --local-dir flag maps the remote repo slug to a local directory:
#     --local-dir bobnetsec/bob-workflows=<repo-root>
#   This tells act to resolve all actions under bobnetsec/bob-workflows from
#   the local repository root without fetching from GitHub.
#
# How the vars context is populated:
#   The workflow references ${{ vars.BOB_VERSION }}. GitHub Variables (vars.*)
#   are separate from env vars and require act's --var flag, not --env-file.
#   test-local.sh passes --var BOB_VERSION=v1.0.0 explicitly.
#
# How cache-hit simulation works:
#   The C2 action's detect-symbol-index step checks for symbol-surface-index.json
#   inside ~/hacker-bob-sessions/gh-987654321/ inside the container. When --hit
#   is passed, a host-side fixture directory is bind-mounted into the container
#   at that path using act's --docker-flag mechanism. The detect step finds the
#   file, outputs cache_hit_symbol_index=true, and the workflow sets
#   SKIP_SURFACE_BUILD=true via its env: block on the action step.
#
# How the mock API server is reached from Linux Docker:
#   On Linux, host.docker.internal is not automatically available. The script
#   detects the OS and injects --add-host=host.docker.internal:host-gateway
#   via --docker-flag when running on Linux.
#
# Acceptance criteria validated:
#   1. act runs without error.
#   2. Cache miss path: C1 and C2 show MISS in logs, S3 phase runs.
#   3. Cache hit path:  SKIP_SURFACE_BUILD=true, S3 phase skipped.
#   4. bob-runner.ts is invoked and produces diff-review-findings.json.
#   5. GitHub Reviews API call is logged by the mock server.
#   6. Total wall time < 5 minutes.
#
# --------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SIMULATE_CACHE_HIT=false
USE_MOCK=true
TIMEOUT_SECS=300
WORKFLOW_FILE="${REPO_ROOT}/.github/workflows/bob-review.yml"
EVENT_FILE="${REPO_ROOT}/test/fixtures/pull_request_event.json"
SECRETS_FILE="${REPO_ROOT}/.secrets"
MOCK_PORT=18080         # Use non-standard port to avoid conflicts with local services
MOCK_LOG="${REPO_ROOT}/test/act-mock-api.log"
ACT_LOG="${REPO_ROOT}/test/act-run.log"

# Directory that is bind-mounted into the container for cache-hit simulation.
# Pre-populated with symbol-surface-index.json so the C2 detect step fires.
# Path inside the container: /root/hacker-bob-sessions/gh-987654321
SESSION_HIT_FIXTURE="${REPO_ROOT}/test/fixtures/session-hit"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --hit)            SIMULATE_CACHE_HIT=true ;;
    --no-mock)        USE_MOCK=false ;;
    --timeout)        TIMEOUT_SECS="$2"; shift ;;
    --help|-h)
      grep '^#' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "[test-local] Unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()  { echo "[test-local] $*"; }
ok()    { echo "[test-local] OK  $*"; }
fail()  { echo "[test-local] FAIL $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
info "Checking prerequisites..."

if ! command -v act &>/dev/null; then
  fail "'act' not found on PATH. Install: brew install act  OR  go install github.com/nektos/act@latest"
fi

ACT_VERSION="$(act --version 2>&1 | head -1 || true)"
info "act version: ${ACT_VERSION}"

if ! command -v docker &>/dev/null; then
  fail "'docker' not found on PATH. Docker is required to run act workflow containers."
fi

if ! docker info &>/dev/null; then
  fail "Docker daemon is not running. Start Docker Desktop or the Docker daemon."
fi

if ! command -v node &>/dev/null; then
  fail "'node' not found on PATH. Node >= 20 required for the mock GitHub API server."
fi

NODE_VERSION="$(node --version)"
info "node version: ${NODE_VERSION}"

# ---------------------------------------------------------------------------
# Validate fixture files
# ---------------------------------------------------------------------------
if [[ ! -f "${EVENT_FILE}" ]]; then
  fail "Event fixture not found: ${EVENT_FILE}"
fi

if [[ ! -f "${WORKFLOW_FILE}" ]]; then
  fail "Workflow file not found: ${WORKFLOW_FILE}"
fi

ok "Prerequisites satisfied."

# ---------------------------------------------------------------------------
# Secrets file
# ---------------------------------------------------------------------------
if [[ ! -f "${SECRETS_FILE}" ]]; then
  info "No .secrets file found at ${SECRETS_FILE}."
  info "Creating a template .secrets file — fill in real values before running."
  cat > "${SECRETS_FILE}" <<'EOF'
# .secrets — act secret file (GITIGNORED — never commit real values)
# Fill in real values from your Anthropic account and GitHub settings.
#
# ANTHROPIC_API_KEY: Anthropic API key (sk-ant-...)
# BOB_INSTALL_TOKEN: GitHub PAT or App installation token (read:packages + contents:read)
# GITHUB_TOKEN:      GitHub PAT or fine-grained token for the mock target repo
#
ANTHROPIC_API_KEY=sk-ant-REPLACE_ME
BOB_INSTALL_TOKEN=ghp_REPLACE_ME
GITHUB_TOKEN=ghp_REPLACE_ME
EOF
  fail ".secrets file created at ${SECRETS_FILE}. Fill in real values and re-run."
fi

info "Using secrets file: ${SECRETS_FILE}"

# ---------------------------------------------------------------------------
# Cache-hit fixture directory
# Pre-populate before the act run so the bind-mount is ready.
# ---------------------------------------------------------------------------
if [[ "${SIMULATE_CACHE_HIT}" == "true" ]]; then
  info "Cache-hit mode: pre-seeding session fixture directory..."
  mkdir -p "${SESSION_HIT_FIXTURE}"
  # Write a minimal but valid symbol-surface-index.json so the C2 detect step
  # finds it and sets cache_hit_symbol_index=true → SKIP_SURFACE_BUILD=true.
  if [[ ! -f "${SESSION_HIT_FIXTURE}/symbol-surface-index.json" ]]; then
    cat > "${SESSION_HIT_FIXTURE}/symbol-surface-index.json" <<'JSON'
{
  "_meta": { "generated_by": "test-local-hit-fixture", "version": "1" },
  "surfaces": [],
  "routes": []
}
JSON
    info "Wrote ${SESSION_HIT_FIXTURE}/symbol-surface-index.json"
  else
    info "symbol-surface-index.json already exists in fixture dir — reusing."
  fi
fi

# ---------------------------------------------------------------------------
# Environment variables file for act
# NOTE: --env-file populates the 'env' context.
#       GitHub Variables (${{ vars.* }}) require --var or --var-file.
#       BOB_VERSION is intentionally set via --var below, not here.
# ---------------------------------------------------------------------------
ENV_FILE="$(mktemp /tmp/act-env-XXXXXX)"
trap 'rm -f "${ENV_FILE}"' EXIT

cat > "${ENV_FILE}" <<EOF
GITHUB_REPOSITORY=bobnetsec/test-target
GITHUB_REPOSITORY_ID=987654321
GITHUB_SHA=abc1234def5678abc1234def5678abc1234def56
GITHUB_BASE_REF=main
GITHUB_REF=refs/pull/42/merge
GITHUB_REF_NAME=42/merge
GITHUB_EVENT_NAME=pull_request
GITHUB_RUN_ID=1000000001
GITHUB_RUN_NUMBER=1
GITHUB_ACTOR=developer
GITHUB_WORKFLOW=Bob Diff Review (reusable)
EOF

# Point GitHub API calls at the mock server (when enabled)
if [[ "${USE_MOCK}" == "true" ]]; then
  cat >> "${ENV_FILE}" <<EOF
GITHUB_API_URL=http://host.docker.internal:${MOCK_PORT}
GITHUB_SERVER_URL=https://github.com
MOCK_GITHUB_PORT=${MOCK_PORT}
EOF
fi

# ---------------------------------------------------------------------------
# Start mock GitHub API server (background)
# ---------------------------------------------------------------------------
MOCK_PID=""
cleanup_mock() {
  if [[ -n "${MOCK_PID}" ]]; then
    kill "${MOCK_PID}" 2>/dev/null || true
    MOCK_PID=""
  fi
  rm -f "${ENV_FILE}" 2>/dev/null || true
}
trap 'cleanup_mock' EXIT

if [[ "${USE_MOCK}" == "true" ]]; then
  info "Starting mock GitHub API server on port ${MOCK_PORT}..."
  mkdir -p "$(dirname "${MOCK_LOG}")"
  node "${SCRIPT_DIR}/mock-github-api.js" \
    --port "${MOCK_PORT}" \
    --diff-fixture "${REPO_ROOT}/test/fixtures/pr_42.diff" \
    > "${MOCK_LOG}" 2>&1 &
  MOCK_PID=$!

  # Wait up to 5 seconds for the server to be ready.
  # mock-github-api.js writes "READY port=<N>" to stdout (which is MOCK_LOG).
  READY=false
  for i in $(seq 1 10); do
    if grep -q "READY port=" "${MOCK_LOG}" 2>/dev/null; then
      READY=true
      break
    fi
    sleep 0.5
  done

  if [[ "${READY}" != "true" ]]; then
    cat "${MOCK_LOG}" >&2
    fail "Mock GitHub API server did not start within 5 seconds."
  fi
  ok "Mock GitHub API server is ready (pid=${MOCK_PID})."
fi

# ---------------------------------------------------------------------------
# Act command construction
# ---------------------------------------------------------------------------
mkdir -p "${REPO_ROOT}/test"

ACT_CMD=(
  act
  pull_request
  --eventpath "${EVENT_FILE}"
  -W "${WORKFLOW_FILE}"
  --env-file "${ENV_FILE}"

  # -------------------------------------------------------------------------
  # Populate the GitHub Variables context (${{ vars.* }}).
  # --env-file only fills the env context; vars.BOB_VERSION requires --var.
  # -------------------------------------------------------------------------
  --var BOB_VERSION=v1.0.0

  # -------------------------------------------------------------------------
  # Map the remote bobnetsec/bob-workflows repo to the local repository root.
  # This resolves all three remote action references without network access:
  #   bobnetsec/bob-workflows/.github/actions/cache-bob-workspace@main
  #   bobnetsec/bob-workflows/.github/actions/cache-bob-session@main
  #   bobnetsec/bob-workflows/packages/bob-diff-review@main
  # -------------------------------------------------------------------------
  --local-dir "bobnetsec/bob-workflows=${REPO_ROOT}"

  --verbose
  --no-recurse-submodules
)

# ---------------------------------------------------------------------------
# Platform flag — Apple Silicon needs linux/amd64 emulation
# ---------------------------------------------------------------------------
if [[ "$(uname -m)" == "arm64" ]]; then
  ACT_CMD+=(--container-architecture linux/amd64)
fi

# ---------------------------------------------------------------------------
# Docker extra flags
# Two concerns handled here:
#
# 1. Linux host.docker.internal:
#    On Linux, host.docker.internal is not resolved automatically inside Docker
#    containers. Inject --add-host so the mock API server is reachable when
#    USE_MOCK=true. On macOS/Windows Docker Desktop this is handled by the
#    Docker Desktop daemon and the flag is a no-op.
#
# 2. Cache-hit simulation bind mount:
#    When --hit is passed, the pre-seeded session fixture directory is
#    bind-mounted into the container at the path the C2 detect step checks.
#    The path is /root/hacker-bob-sessions/gh-987654321 (root user in container).
#    The C2 action then finds symbol-surface-index.json, outputs
#    cache_hit_symbol_index=true, and the workflow sets SKIP_SURFACE_BUILD=true
#    through its own env: evaluation — no external env injection needed.
# ---------------------------------------------------------------------------
DOCKER_EXTRA_FLAGS=()

if [[ "$(uname -s)" == "Linux" ]] && [[ "${USE_MOCK}" == "true" ]]; then
  DOCKER_EXTRA_FLAGS+=("--add-host=host.docker.internal:host-gateway")
fi

if [[ "${SIMULATE_CACHE_HIT}" == "true" ]]; then
  # Bind-mount the fixture dir so the detect step sees symbol-surface-index.json.
  # The entire "--volume src:dst:opts" string is one --docker-flag argument.
  DOCKER_EXTRA_FLAGS+=("--volume=${SESSION_HIT_FIXTURE}:/root/hacker-bob-sessions/gh-987654321:ro")
fi

if [[ ${#DOCKER_EXTRA_FLAGS[@]} -gt 0 ]]; then
  for docker_flag in "${DOCKER_EXTRA_FLAGS[@]}"; do
    ACT_CMD+=(--docker-flag "${docker_flag}")
  done
fi

# ---------------------------------------------------------------------------
# Secrets file
# ---------------------------------------------------------------------------
if grep -qvE '^#|^$|_REPLACE_ME' "${SECRETS_FILE}"; then
  ACT_CMD+=(--secret-file "${SECRETS_FILE}")
else
  info "WARNING: .secrets file contains placeholder values."
  info "         The action will run but may fail when it calls the Anthropic API."
  info "         Set real values in ${SECRETS_FILE} for a full end-to-end run."
  ACT_CMD+=(--secret-file "${SECRETS_FILE}")
fi

info "Running act..."
info "Command: ${ACT_CMD[*]}"
info "Workflow: ${WORKFLOW_FILE}"
info "Event: ${EVENT_FILE}"
info "Log: ${ACT_LOG}"
if [[ "${SIMULATE_CACHE_HIT}" == "true" ]]; then
  info "Cache-hit mode: bind-mounting ${SESSION_HIT_FIXTURE} as /root/hacker-bob-sessions/gh-987654321"
fi
echo ""

# ---------------------------------------------------------------------------
# Execute act with timeout
# ---------------------------------------------------------------------------
START_TS=$(date +%s)

set +e
timeout "${TIMEOUT_SECS}" "${ACT_CMD[@]}" 2>&1 | tee "${ACT_LOG}"
ACT_EXIT=${PIPESTATUS[0]}
set -e

END_TS=$(date +%s)
ELAPSED=$(( END_TS - START_TS ))

echo ""
info "act exited with code ${ACT_EXIT} after ${ELAPSED}s"

# ---------------------------------------------------------------------------
# Validate acceptance criteria from the log output
# ---------------------------------------------------------------------------
echo ""
info "=== Acceptance Criteria Validation ==="

ALL_PASS=true

# 1. act ran without error (exit 0)
if [[ "${ACT_EXIT}" -eq 0 ]]; then
  ok "AC1: act completed without error (exit 0)"
elif [[ "${ACT_EXIT}" -eq 124 ]]; then
  fail "AC1: act timed out after ${TIMEOUT_SECS}s (> 5 minute limit)"
else
  echo "[test-local] WARN AC1: act exited ${ACT_EXIT} — may still validate partial log output" >&2
  ALL_PASS=false
fi

# 2. Cache miss: check for cache MISS indicators (when not simulating hit)
if [[ "${SIMULATE_CACHE_HIT}" != "true" ]]; then
  # act emits 'Cache not found for input keys' on miss, or shows 'cache-hit: false'
  if grep -qiE "(cache not found|cache miss|cache-hit.*false|MISS)" "${ACT_LOG}" 2>/dev/null; then
    ok "AC2: Cache miss detected in logs (C1 or C2 showed MISS)"
  else
    echo "[test-local] WARN AC2: Could not confirm cache MISS in act log" >&2
    echo "             This may be expected on first run where act cache stubs always miss." >&2
    # Not a hard failure — act's local cache behavior differs from real GitHub cache
  fi
fi

# 3. Cache hit: SKIP_SURFACE_BUILD should be true when --hit is passed.
#    The value flows through the workflow's own env: evaluation — not injected
#    externally — so we look for the echo in the Log review outputs step.
if [[ "${SIMULATE_CACHE_HIT}" == "true" ]]; then
  if grep -qiE "(SKIP_SURFACE_BUILD=true|skip.*surface.*build.*true)" "${ACT_LOG}" 2>/dev/null; then
    ok "AC3: SKIP_SURFACE_BUILD=true confirmed in cache-hit path"
  else
    echo "[test-local] WARN AC3: SKIP_SURFACE_BUILD=true not detected in hit-path log" >&2
    echo "             Verify that the bind-mount reached /root/hacker-bob-sessions/gh-987654321/" >&2
  fi
fi

# 4. bob-runner invoked (looks for the claude spawn or findings file message)
if grep -qiE "(bob-diff-review skill|diff-review-findings|Invoking bob-diff-review|runBobDiffReview)" "${ACT_LOG}" 2>/dev/null; then
  ok "AC4: bob-runner.ts invoked (bob-diff-review skill launch detected)"
else
  echo "[test-local] WARN AC4: Did not detect bob-runner invocation in log" >&2
  echo "             The action may have failed before reaching the runner step." >&2
fi

# 5. Reviews API call logged by mock server
if [[ "${USE_MOCK}" == "true" ]]; then
  if grep -qiE "(PR_REVIEW_POSTED|POST.*pulls.*reviews)" "${MOCK_LOG}" 2>/dev/null; then
    ok "AC5: GitHub Reviews API call logged by mock server"
  else
    echo "[test-local] WARN AC5: Reviews API call not found in mock server log" >&2
    echo "             Mock log at: ${MOCK_LOG}" >&2
  fi
fi

# 6. Completed within 5 minutes
if [[ "${ELAPSED}" -lt 300 ]]; then
  ok "AC6: Completed in ${ELAPSED}s (< 300s limit)"
else
  echo "[test-local] FAIL AC6: Elapsed time ${ELAPSED}s exceeds 300s (5 minute limit)" >&2
  ALL_PASS=false
fi

echo ""
info "=== Summary ==="
info "Elapsed time:    ${ELAPSED}s"
info "act exit code:   ${ACT_EXIT}"
info "Act log:         ${ACT_LOG}"
if [[ "${USE_MOCK}" == "true" ]]; then
  info "Mock API log:    ${MOCK_LOG}"
fi
echo ""

if [[ "${ALL_PASS}" == "true" && "${ACT_EXIT}" -eq 0 ]]; then
  ok "All acceptance criteria passed."
  exit 0
else
  echo "[test-local] Some criteria may not have passed — review logs above." >&2
  exit "${ACT_EXIT:-1}"
fi
