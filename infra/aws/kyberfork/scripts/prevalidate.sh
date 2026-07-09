#!/usr/bin/env bash
#
# prevalidate.sh — build-time, BEFORE build-day pre-validation that KyberFork's pinned block
# actually reproduces the real KyberSwap Elastic tick-boundary bug and grades SUBMIT.
#
# WHAT: clones the public whitehat PoC (one-hundred-proof/kyberswap-exploit) and runs its own
# exploit test against a live fork of the IDENTICAL pinned block KyberFork loads
# (KYBERFORK-SPEC.md §3.1). If `performFullHack` passes here, the answer is known and runnable
# in advance of the live hacker-bob run.
#
# WHY THIS MAKES KYBERFORK NON-CIRCULAR: per KYBERFORK-SPEC.md §3 ("Ground-truth manifest &
# non-circular grading"), grading a tool's output against ground truth authored AFTER seeing that
# output is circular. Here the ground truth (the public PoC + its REPORT.md, plus Kyber's own
# post-mortem and third-party analyses) predates this project entirely. This script is what makes
# that claim checkable rather than asserted: it independently re-derives, from a second live fork
# of the same historical state, that the bug is really there — before hacker-bob ever sees the
# target.
#
# BRIGHT LINE: this script runs on a build box WITH internet egress — it is NEVER run inside
# hacker-bob's microVM/VPC (KYBERFORK-SPEC.md, "BRIGHT LINE" section, top of file). It does not
# touch, write into, or share a filesystem with the in-VPC runtime node.
#
# NOTE ON $ARCHIVE_RPC HERE: the PoC's own `forge test` forks live from an RPC at the pinned
# block. This is a SECOND, INDEPENDENT repro of the same on-chain state — not a reuse of the
# kyberswap-fork.json snapshot dumped by fork-snapshot.sh. Two unrelated fork paths landing on
# the same bug at the same block is the point.
#
# USAGE:
#   ARCHIVE_RPC="https://<archive-provider-endpoint>" infra/aws/kyberfork/scripts/prevalidate.sh
#
# Output: a timestamped forge-test log under a mktemp workdir (never under the hacker-bob repo
# tree) whose path is printed on completion — this is the artifact KYBERFORK-SPEC.md §3.2's
# "pre-validation record" points at. This script does not write MANIFEST.yaml itself; that is a
# separate node.
set -euo pipefail

# Named, not inline magic strings, so a later node (the manifest writer) can source or grep them.
POC_REPO="https://github.com/one-hundred-proof/kyberswap-exploit"
FORK_BLOCK=17050000
POC_TEST_CONTRACT=KyberswapLegacyTest
POC_ENTRY_POINT=performFullHack

# REQUIRED — no default, never logged. May embed an API key.
ARCHIVE_RPC="${ARCHIVE_RPC:?set ARCHIVE_RPC to an archive JSON-RPC endpoint with eth_getProof support at block 17050000 — used ONCE, build-time only, never from the microVM}"

redact() {
  local line
  while IFS= read -r line || [ -n "$line" ]; do
    printf '%s\n' "${line//"$ARCHIVE_RPC"/[REDACTED-ARCHIVE_RPC]}"
  done
}

command -v forge >/dev/null 2>&1 || {
  echo "missing required tool: forge (Foundry). Install with: curl -L https://foundry.paradigm.xyz | bash && foundryup" >&2
  exit 2
}

WORKDIR="$(mktemp -d -t kyberfork-prevalidate.XXXXXX)"
echo ">> cloning ${POC_REPO} into ${WORKDIR} (never into the hacker-bob repo tree)"
git clone --quiet "${POC_REPO}" "${WORKDIR}/kyberswap-exploit"

(
  cd "${WORKDIR}/kyberswap-exploit"
  echo ">> forge install"
  forge install
)

LOG_FILE="${WORKDIR}/forge-test-$(date -u +%Y%m%dT%H%M%SZ).log"

echo ">> running forge test: contract=${POC_TEST_CONTRACT} entry=${POC_ENTRY_POINT} fork_block=${FORK_BLOCK} (\$ARCHIVE_RPC value not shown)"

set +e
(
  cd "${WORKDIR}/kyberswap-exploit"
  forge test \
    --fork-url "$ARCHIVE_RPC" \
    --fork-block-number "$FORK_BLOCK" \
    --match-test "$POC_ENTRY_POINT" \
    -vvv
) 2>&1 | redact | tee "${LOG_FILE}"
PIPELINE_STATUS=("${PIPESTATUS[@]}")
FORGE_STATUS=${PIPELINE_STATUS[0]}
REDACT_STATUS=${PIPELINE_STATUS[1]}
TEE_STATUS=${PIPELINE_STATUS[2]}
set -e

echo ">> forge test log: ${LOG_FILE}"

if [ "${FORGE_STATUS}" -eq 0 ] && [ "${REDACT_STATUS}" -eq 0 ] && [ "${TEE_STATUS}" -eq 0 ]; then
  echo "PASS: ${POC_ENTRY_POINT} (${POC_TEST_CONTRACT}) reproduced at block ${FORK_BLOCK} — pre-validation record: ${LOG_FILE}"
elif [ "${REDACT_STATUS}" -ne 0 ] || [ "${TEE_STATUS}" -ne 0 ]; then
  echo "FAIL: output pipeline failed while prevalidating ${POC_ENTRY_POINT} (${POC_TEST_CONTRACT}) at block ${FORK_BLOCK} — redact_status=${REDACT_STATUS} tee_status=${TEE_STATUS} forge_status=${FORGE_STATUS}" >&2
  exit 1
else
  echo "FAIL: ${POC_ENTRY_POINT} (${POC_TEST_CONTRACT}) did not pass at block ${FORK_BLOCK} — see ${LOG_FILE}" >&2
  exit "${FORGE_STATUS}"
fi
