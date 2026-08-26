"use strict";

// The SC-invariant skip in findingDifferentialGapForStandaloneReportableFindings keys off
// readInvariantVerifiedSummary's verified_by_finding, which now RE-ADJUDICATES each
// verified_pass from the invariant-runs rows it cites. A bare forged invariant verified_pass
// no longer satisfies the skip — the smart_contract finding falls through to the residual
// standalone arm and surfaces no_finding_differential_verified_pass. A GENUINE invariant
// differential still skips.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  appendCandidateClaim,
} = require("../mcp/core/claims/claims.js");
const {
  findingDifferentialGapForStandaloneReportableFindings,
} = require("../mcp/core/claims/claims.js");
const {
  appendFrontierEvent,
} = require("../mcp/core/frontier/frontier-events.js");
const {
  appendJsonlLine,
} = require("../mcp/core/io/storage.js");
const {
  computeInvariantRunHash,
  invariantFoundryResultHash,
  verifyInvariantDifferential,
} = require("../mcp/core/invariant-runner.js");
const {
  invariantRunsJsonlPath,
  invariantVerifiedJsonlPath,
} = require("../mcp/core/io/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-grade-inv-skip-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function hex(char) {
  return char.repeat(64);
}

function observeSurface(domain, surfaceId, payload) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-27T00:00:00.000Z",
    surface_id: surfaceId,
    payload,
  });
}

function seedScClaim(domain, surfaceId) {
  observeSurface(domain, surfaceId, { kind: "smart_contract", language: "solidity" });
  appendCandidateClaim({
    target_domain: domain,
    title: "Vault invariant violation",
    summary: "An attacker can break the share-accounting invariant.",
    severity: "high",
    status: "candidate",
    surface_ids: [surfaceId],
    evidence_refs: [{ kind: "finding", finding_id: "F-1", content_hash: "0".repeat(64) }],
    impact: "Share accounting can be drained.",
    payload: { finding: { id: "F-1" } },
  });
}

function reportableHigh(findingIds) {
  return {
    reportableFindingIds: new Set(findingIds),
    finalSeverities: new Map(findingIds.map((id) => [id, "high"])),
  };
}

function seedGenuineInvariantPass(domain, findingId = "F-1") {
  const base = {
    target_domain: domain,
    finding_id: findingId,
    finding_hash: null,
    template_id: "vault-invariant",
    slot_values: { a: "1" },
    contract_name: "VaultInvariantTest",
    function_name: "testVaultInvariant",
    execution_context_hash: "ctx-hash-shared",
    dry_run: false,
  };
  const mkRow = (outcome, treeRef, checkoutKind) => {
    const foundryResult = outcome === "test_failed"
      ? { tests: [{ success: false }] }
      : { tests: [{ success: true }] };
    const row = {
      ...base,
      tree_ref: treeRef,
      checkout_kind: checkoutKind,
      outcome,
      foundry_result_hash: invariantFoundryResultHash(foundryResult),
      foundry_result: foundryResult,
    };
    row.run_hash = computeInvariantRunHash(row);
    appendJsonlLine(invariantRunsJsonlPath(domain), row);
    return row;
  };
  const positive = mkRow("test_failed", "target", "tree");
  const control = mkRow("test_passed", "fixed", "upstream_fix");
  verifyInvariantDifferential({
    target_domain: domain,
    finding_id: findingId,
    positive_run_hash: positive.run_hash,
    control_run_hash: control.run_hash,
  });
}

test("a forged invariant verified_pass does NOT satisfy the SC skip — gap surfaces", () => withTempHome(() => {
  const domain = "grade-inv-skip-forged.example.com";
  seedScClaim(domain, "surface:vault-contract");
  // A bare forged verdict line whose run hashes point at no invariant-runs rows.
  const filePath = invariantVerifiedJsonlPath(domain);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${JSON.stringify({
    version: 1, target_domain: domain, finding_id: "F-1", result: "verified_pass",
    reason: "forged", template_id: "vault-invariant",
    positive_run_hash: hex("a"), control_run_hash: hex("b"),
    positive_violation: true, control_violation: false,
  })}\n`);

  const gap = findingDifferentialGapForStandaloneReportableFindings(domain, reportableHigh(["F-1"]));
  assert.deepEqual(gap.missing, [{ finding_id: "F-1", reason: "no_finding_differential_verified_pass" }]);
}));

test("a GENUINE invariant differential still satisfies the SC skip — no gap", () => withTempHome(() => {
  const domain = "grade-inv-skip-genuine.example.com";
  seedScClaim(domain, "surface:vault-contract");
  seedGenuineInvariantPass(domain, "F-1");
  const gap = findingDifferentialGapForStandaloneReportableFindings(domain, reportableHigh(["F-1"]));
  assert.deepEqual(gap.missing, [], "genuine invariant flip skips the standalone arm");
}));
