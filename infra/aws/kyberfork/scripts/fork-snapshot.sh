#!/usr/bin/env bash
#
# fork-snapshot.sh — build-time dump of a pinned mainnet block into a self-contained anvil
# state snapshot for KyberFork.
#
# WHY: KyberFork's runtime node (infra/aws/kyberfork/README.md, KYBERFORK-SPEC.md §1.1) loads a
# pre-materialized snapshot with `anvil --load-state` and has ZERO outbound network — it cannot
# fork live because it has no route out of hacker-bob's no-IGW/no-NAT VPC. Getting that snapshot
# therefore requires exactly one machine, exactly once, WITH internet egress, forking mainnet at
# a pinned historical block and dumping the resulting state to a file.
#
# BRIGHT LINE: this script runs on a build box WITH internet egress — it is NEVER run inside
# hacker-bob's microVM/VPC, and the microVM has no route to $ARCHIVE_RPC at all
# (KYBERFORK-SPEC.md, "BRIGHT LINE" section, top of file). The only thing this script produces
# that is allowed to cross the air gap into the VPC is the output snapshot file
# (kyberswap-fork.json) — no RPC URL, key, or network route travels with it.
#
# PROVENANCE: $ARCHIVE_RPC is any archive JSON-RPC provider with eth_getProof support at block
# 17050000 (KYBERFORK-SPEC.md §1.1). It is used HERE, ONCE, and never again — never logged,
# never written to a file, never defaulted.
#
# USAGE:
#   ARCHIVE_RPC="https://<archive-provider-endpoint>" infra/aws/kyberfork/scripts/fork-snapshot.sh
#
# Output: kyberswap-fork.json (written to the current working directory) + its sha256 printed to
# stdout. The MANIFEST.yaml that records this hash (KYBERFORK-SPEC.md §3.2) is authored by a
# separate node — this script only computes and prints the hash.
set -euo pipefail

# REQUIRED — no default, never logged. May embed an API key.
ARCHIVE_RPC="${ARCHIVE_RPC:?set ARCHIVE_RPC to an archive JSON-RPC endpoint with eth_getProof support at block 17050000 — used ONCE, build-time only, never from the microVM}"

redact() {
  local line
  while IFS= read -r line || [ -n "$line" ]; do
    printf '%s\n' "${line//"$ARCHIVE_RPC"/[REDACTED-ARCHIVE_RPC]}"
  done
}

# Pinned, not overridable via env — must match the runtime node's expected state and the public
# PoC's fork block (KYBERFORK-SPEC.md §3.1: "the identical block KyberFork loads").
FORK_BLOCK=17050000

OUT_FILE="kyberswap-fork.json"

command -v anvil >/dev/null 2>&1 || {
  echo "missing required tool: anvil (Foundry). Install with: curl -L https://foundry.paradigm.xyz | bash && foundryup" >&2
  exit 2
}

# sha256 helper — prefer sha256sum (Linux), fall back to shasum (macOS).
if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  echo "need sha256sum or shasum to hash the snapshot" >&2
  exit 2
fi

rm -f "${OUT_FILE}"

echo ">> forking mainnet at block ${FORK_BLOCK} via \$ARCHIVE_RPC (value not shown)"

# --dump-state writes on clean shutdown, so anvil is backgrounded, we wait for it to come up and
# actually dump on exit, then we signal it — launch-and-exit would never produce the file.
#
# fx-gate-bypass defense 5: LOG_FILE is a fx-gate-bypass secret-leak fix target — anvil's own
# stdout/stderr can echo the fork URL (e.g. in a connection-error message), so its combined
# output is piped through redact() BEFORE it ever touches disk (mirrors prevalidate.sh's own
# `| redact | tee` idiom), and LOG_FILE is removed on every exit path via cleanup() below — it
# is a readiness-detection/diagnostic scratch file, never a deliverable, and must never persist
# with an unredacted $ARCHIVE_RPC value once this script exits.
LOG_FILE="$(mktemp -t kyberfork-anvil-log.XXXXXX)"
ANVIL_PID=""

cleanup() {
  if [ -n "${ANVIL_PID}" ] && kill -0 "${ANVIL_PID}" 2>/dev/null; then
    kill -TERM "${ANVIL_PID}" 2>/dev/null || true
    wait "${ANVIL_PID}" 2>/dev/null || true
  fi
  rm -f "${LOG_FILE}"
}
trap cleanup EXIT

# Process substitution (not a plain `| redact`) keeps $! below bound to anvil's OWN pid, not
# redact's — a background `cmd | other &` pipeline's $! is the LAST stage's pid in bash, but
# cleanup()/the readiness-poll below both need to signal/kill anvil itself directly.
anvil \
  --fork-url "$ARCHIVE_RPC" \
  --fork-block-number "$FORK_BLOCK" \
  --dump-state "${OUT_FILE}" \
  > >(redact >"${LOG_FILE}") 2>&1 &
ANVIL_PID=$!

# wait for anvil to report readiness (it prints "Listening on" once the fork is live) before we
# consider the node up; bail loudly if it dies before that.
for _ in $(seq 1 120); do
  if grep -q "Listening on" "${LOG_FILE}" 2>/dev/null; then
    break
  fi
  if ! kill -0 "${ANVIL_PID}" 2>/dev/null; then
    echo "anvil exited before becoming ready — see log below (RPC URL redacted, not present in anvil's own output by default):" >&2
    redact <"${LOG_FILE}" >&2
    exit 3
  fi
  sleep 1
done

if ! grep -q "Listening on" "${LOG_FILE}" 2>/dev/null; then
  echo "anvil did not report readiness within 120s — terminating and checking whether a dump was produced" >&2
fi

if ! kill -0 "${ANVIL_PID}" 2>/dev/null; then
  echo "anvil is not running after startup wait" >&2
  exit 3
fi

# node is up and forked at the pinned block — now request a clean shutdown so --dump-state flushes.
kill -TERM "${ANVIL_PID}" 2>/dev/null || true
wait "${ANVIL_PID}" 2>/dev/null || true
trap - EXIT

for _ in $(seq 1 30); do
  [ -s "${OUT_FILE}" ] && break
  sleep 1
done

[ -s "${OUT_FILE}" ] || {
  echo "expected dump file ${OUT_FILE} was not produced — anvil log follows:" >&2
  redact <"${LOG_FILE}" >&2
  rm -f "${LOG_FILE}"
  exit 4
}

# fx-gate-bypass defense 5: LOG_FILE has done its job (readiness detection); it never persists
# past this script's own run, on the success path either — trap cleanup() already handles every
# OTHER exit branch above (it fires on any exit while still armed), but the EXIT trap was
# deliberately disarmed above (`trap - EXIT`) once anvil was cleanly stopped, so the success path
# removes it explicitly here.
rm -f "${LOG_FILE}"

SHA="$(sha256_of "${OUT_FILE}")"
echo ">> wrote ${OUT_FILE}"
echo ">> sha256(${OUT_FILE}) = ${SHA}"
echo ">> this file is the ONLY artifact that should cross the air gap into the VPC — never the RPC URL/key used to build it."
