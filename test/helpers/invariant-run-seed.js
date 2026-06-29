"use strict";

// Shared test helper: seed a fully-bound invariant-runs.jsonl row on disk the way
// runInvariantForFinding persists it (outcome derived from foundry_result, run_hash from
// computeInvariantRunHash), with an optional Cycle B row_mac.
//
// Cycle B keys invariant-runs rows with a domain-separated ed25519 signature verified at
// the read-time re-derivation sites (readInvariantRunRowForVerification +
// proof-bundle readInvariantRunRow). A test that drives those sites through the keyed
// path must seed a SIGNED row (sign:true) the way the producer mints it; default unsigned
// keeps the legacy-acceptance (accept-with-warning) coverage that the pre-Cycle-B tests
// already exercise. Mirrors seedGenuineReproPair's {sign} seam.

const {
  computeInvariantRunHash,
  invariantFoundryResultHash,
} = require("../../mcp/lib/invariant-runner.js");
const { appendJsonlLine } = require("../../mcp/lib/storage.js");
const { invariantRunsJsonlPath } = require("../../mcp/lib/paths.js");
const {
  signRowWithMac,
  INVARIANT_RUN_MAC_CONTEXT,
} = require("../../mcp/lib/offensive-row-mac.js");
const {
  ensureHandoffKeypair,
  readHandoffSigningPrivateKey,
} = require("../../mcp/lib/handoff-signing-key.js");

// A valid matching cross-stack target binding for seeds (executed bytecode sha256 ===
// on-chain bytecode sha256, a fixed in-fork address). A cross-stack arm seeded with
// crossStackTargetBound:true clears the verifier's target gate; a mismatch test overrides
// targetCodeSha256 to a DIFFERENT value to exercise the refusal.
const SEED_TARGET_ADDRESS = `0x${"ab".repeat(20)}`;
const SEED_TARGET_CODE_SHA256 = `0x${"cd".repeat(32)}`;

// Seed a single executed (non-dry-run) invariant-runs row. The 12 hash-bound fields are
// supplied (or defaulted) so computeInvariantRunHash binds run_hash; when {sign} is set
// the row is signed AFTER run_hash is computed (row_mac is excluded from
// computeInvariantRunHash), so the row recomputes identically at the read sites.
function seedInvariantRunRow(domain, {
  findingId = "F-1",
  outcome = "test_failed",
  treeRef = "target",
  checkoutKind = "tree",
  templateId = "INV-FIXTURE-001",
  contractName = "BobInvariantTest_fixture",
  functionName = "testBobInvariant_fixture",
  executionContextHash = "ctx-hash-shared",
  slotValues = { a: "1" },
  sign = false,
  // HIGH-1: whether THIS run was executed in a filesystem-namespace container
  // (true) or degraded to a host-as-signer spawn (false/undefined). The producer
  // records this as a top-level sibling field OUTSIDE computeInvariantRunHash (so
  // run_hash stays byte-stable) but INSIDE the row_mac. Passing undefined omits the
  // field (a legacy row predating the field); a boolean writes it explicitly.
  containerIsolated = undefined,
  // The CROSS-STACK causal link: the offensive run_id whose state a VIOLATED arm
  // executed against. Like container_isolated it is a sibling OUTSIDE computeInvariantRunHash
  // (run_hash byte-stable) but INSIDE the row_mac. undefined/null omits it (a held
  // control / non-cross-stack run); a string names the bound cause.
  causeRunId = undefined,
  // The CONSUMED-ARTIFACT binding (O-A): sha256 of the bytes a VIOLATED arm actually
  // consumed (injected as BOB_CONSUMED_ARTIFACT). Like cause_run_id it is a sibling OUTSIDE
  // computeInvariantRunHash (run_hash byte-stable) but INSIDE the row_mac. The producer
  // always writes it (null when the arm ran cause-free), so mirror that: undefined/null
  // writes null (a cause-free control), a 64-hex string binds the consumed bytes' hash.
  consumedArtifactHash = undefined,
  // CROSS-STACK TARGET BINDING siblings (outside run_hash, inside row_mac) — mirror the
  // producer (null on single-surface, the executed/on-chain bytecode sha256 on cross-stack).
  // crossStackTargetBound:true sets a VALID matching binding so a cross-stack arm clears the
  // verifier's target gate; explicit targetCodeSha256/targetOnchainCodeSha256 override it.
  crossStackTargetBound = false,
  targetAddress = undefined,
  targetCodeSha256 = undefined,
  targetOnchainCodeSha256 = undefined,
  // Force the on-chain cross-check field null while KEEPING the executed binding
  // (target_address + target_code_sha256) present — the "lookup UNAVAILABLE" state the
  // producer records when the runner's eth_getCode quorum could not resolve. Distinct from
  // crossStackTargetBound:false (which clears all three = a pre-binding migration row).
  targetOnchainUnavailable = false,
  // SEALED-HARNESS marker. A genuine cross-stack run executes the runner-owned SEALED Foundry
  // project (no agent-authored Solidity / forge-std), so the row carries sealed_harness:true and
  // the verifier requires it on every arm. Defaults to follow crossStackTargetBound (a genuine
  // cross-stack seed is sealed); an explicit false exercises the non-sealed refusal.
  sealedHarness = undefined,
} = {}) {
  const foundryResult = outcome === "test_failed"
    ? { tests: [{ success: false }] }
    : { tests: [{ success: true }] };
  const row = {
    target_domain: domain,
    finding_id: findingId,
    finding_hash: null,
    template_id: templateId,
    slot_values: slotValues,
    contract_name: contractName,
    function_name: functionName,
    execution_context_hash: executionContextHash,
    tree_ref: treeRef,
    checkout_kind: checkoutKind,
    outcome,
    foundry_result_hash: invariantFoundryResultHash(foundryResult),
    foundry_result: foundryResult,
    dry_run: false,
  };
  // The producer always writes consumed_artifact_hash (null when the arm ran cause-free);
  // mirror that. A 64-hex string binds the consumed bytes' hash on a violated/decoy arm.
  // It is bound INTO computeInvariantRunHash (so the cross-stack control and decoy arms,
  // both HELD with identical foundry_result, are DISTINCT rows), so it must be set BEFORE
  // run_hash is computed, mirroring the producer (which computes run_hash with the consumed
  // hash threaded in).
  row.consumed_artifact_hash = typeof consumedArtifactHash === "string"
    && /^[0-9a-f]{64}$/i.test(consumedArtifactHash.trim())
    ? consumedArtifactHash.trim().toLowerCase()
    : null;
  // run_hash is computed BEFORE container_isolated/cause_run_id are added (those stay
  // siblings outside computeInvariantRunHash), so adding them leaves run_hash byte-stable.
  row.run_hash = computeInvariantRunHash(row);
  if (containerIsolated !== undefined) {
    row.container_isolated = containerIsolated === true;
  }
  // The producer always writes cause_run_id (null when absent); mirror that so a seeded
  // row is byte-identical to a producer row. A string names the bound cross-stack cause.
  row.cause_run_id = typeof causeRunId === "string" && causeRunId.trim() ? causeRunId.trim() : null;
  // CROSS-STACK TARGET BINDING siblings (outside run_hash, inside row_mac) — written like the
  // producer (always present, null when absent). crossStackTargetBound supplies a valid
  // matching default; explicit values override (a mismatch refusal test passes a differing
  // targetCodeSha256). All three cross-stack arms seeded with the same defaults satisfy the
  // verifier's same-target + executed-equals-on-chain checks.
  const tbAddr = typeof targetAddress === "string" ? targetAddress
    : (crossStackTargetBound ? SEED_TARGET_ADDRESS : null);
  const tbCode = typeof targetCodeSha256 === "string" ? targetCodeSha256
    : (crossStackTargetBound ? SEED_TARGET_CODE_SHA256 : null);
  const tbOnchain = targetOnchainUnavailable ? null
    : (typeof targetOnchainCodeSha256 === "string" ? targetOnchainCodeSha256
      : (crossStackTargetBound ? SEED_TARGET_CODE_SHA256 : null));
  row.target_address = typeof tbAddr === "string" ? tbAddr.toLowerCase() : null;
  row.target_code_sha256 = typeof tbCode === "string" ? tbCode.toLowerCase() : null;
  row.target_onchain_code_sha256 = typeof tbOnchain === "string" ? tbOnchain.toLowerCase() : null;
  // SEALED-HARNESS sibling (outside run_hash, inside row_mac). Defaults to crossStackTargetBound
  // so a genuine cross-stack seed is sealed; an explicit false exercises the non-sealed refusal.
  row.sealed_harness = sealedHarness === undefined ? (crossStackTargetBound === true) : (sealedHarness === true);
  if (sign) {
    ensureHandoffKeypair(domain);
    signRowWithMac(INVARIANT_RUN_MAC_CONTEXT, row, readHandoffSigningPrivateKey(domain));
  }
  appendJsonlLine(invariantRunsJsonlPath(domain), row);
  return row;
}

// Seed a genuine flipping pair (positive test_failed on the target tree, control
// test_passed on a different tree) — the shape the differential verifier admits.
function seedInvariantRunPair(domain, {
  findingId = "F-1",
  sign = false,
  // HIGH-1: the POSITIVE run's containerization (the row that demonstrates the
  // violation — a host-as-signer positive is the forgery vector). undefined omits
  // the field (legacy). The control's containerization does not gate trust, so it
  // is left to the default.
  positiveContainerIsolated = undefined,
} = {}) {
  const positive = seedInvariantRunRow(domain, {
    findingId, outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign,
    containerIsolated: positiveContainerIsolated,
  });
  const control = seedInvariantRunRow(domain, {
    findingId, outcome: "test_passed", treeRef: "fixed", checkoutKind: "upstream_fix", sign,
  });
  return { positive, control };
}

module.exports = {
  seedInvariantRunRow,
  seedInvariantRunPair,
  SEED_TARGET_ADDRESS,
  SEED_TARGET_CODE_SHA256,
};
