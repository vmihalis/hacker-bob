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
  // run_hash is computed BEFORE container_isolated is added, mirroring the producer:
  // the field is a sibling outside computeInvariantRunHash, so adding it leaves
  // run_hash byte-stable.
  row.run_hash = computeInvariantRunHash(row);
  if (containerIsolated !== undefined) {
    row.container_isolated = containerIsolated === true;
  }
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
};
