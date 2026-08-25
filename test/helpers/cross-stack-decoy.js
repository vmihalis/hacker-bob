"use strict";

// Shared cross-stack test helper: the DECOY arm + decoy capture the three-arm relevance
// differential requires. A cross-stack verified_pass needs positive(real cause)->VIOLATE,
// control(absent)->HOLD, AND decoy(random bytes)->HOLD. The decoy is a DISTINCT signed
// is_decoy capture of RANDOM bytes (NOT the real cause) consumed by a same-test/same-tree
// invariant arm that a genuine gate REJECTS (the decoy arm HOLDS). This helper seeds both
// the decoy capture and the decoy arm and returns the leaf refs.

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const {
  offensiveRunsJsonlPath,
  offensiveRunsDir,
} = require("../../mcp/core/io/paths.js");
const {
  ensureHandoffSigningKey,
} = require("../../mcp/core/ledger-integrity/index.js");
const {
  signOffensiveRunRow,
} = require("../../mcp/core/ledger-integrity/index.js");
const { canonicalizeExploitTarget } = require("../../mcp/core/claims/claims.js");
const { seedInvariantRunRow } = require("./invariant-run-seed.js");

// The audited cross-stack consuming template — every cross-stack invariant arm must run it.
const CONSUME_TEMPLATE_ID = "INV-CROSS-STACK-AUTH-REPLAY-001";

// Random decoy bytes — distinct CONTENT from any real cause capture, but SAME SHAPE (same
// byte length + raw encoding class as the CONSUMED_BYTES the gate-tests use) so the HIGH-2
// shape-parity binding passes. A gate that validates the SPECIFIC credential bytes REJECTS
// these -> the decoy arm HOLDS.
const DECOY_BYTES = Buffer.from("random-decoy-bytes:0xc0ffeeAABB", "utf8");
const DECOY_HASH = crypto.createHash("sha256").update(DECOY_BYTES).digest("hex");
const DECOY_RUN_ID = "web-decoy-1";
const DECOY_WEB_SURFACE = "surface:billing-web";

function hex(ch) {
  return ch.repeat(64);
}

// Build + sign + persist the decoy capture (random bytes, is_decoy:true, blocked_by_defense)
// and write its .consumed leaf. The decoy is provably NOT the real cause.
function appendDecoyCapture(domain, {
  runId = DECOY_RUN_ID,
  surfaceId = DECOY_WEB_SURFACE,
  consumedHash = DECOY_HASH,
  captureBytes = DECOY_BYTES,
} = {}) {
  const row = {
    version: 1,
    target_domain: domain,
    run_id: runId,
    tool_id: "bob_http_idor_confirm",
    target: canonicalizeExploitTarget(`https://${domain}/api/billing/1`),
    offensive_outcome: "blocked_by_defense",
    dry_run: false,
    timed_out: false,
    command_hash: hex("e"),
    exit_code: 0,
    stdout_hash: hex("b"),
    stderr_hash: hex("c"),
    demonstrated_severity: "high",
    surface_id: surfaceId,
    consumed_artifact_hash: consumedHash,
    is_decoy: true,
  };
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
  fs.mkdirSync(path.dirname(offensiveRunsJsonlPath(domain)), { recursive: true });
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  if (consumedHash != null && captureBytes != null) {
    fs.mkdirSync(offensiveRunsDir(domain), { recursive: true });
    fs.writeFileSync(path.join(offensiveRunsDir(domain), `${runId}.consumed`), captureBytes);
  }
  return row;
}

// Seed a valid decoy capture + a HELD decoy arm (same test/tree as the flip) and return the
// two leaf refs to splice into a cross-stack leaf. The decoy arm consumes the random decoy
// bytes and HOLDS (the gate rejects them). Pass decoyArmOutcome:"test_failed" to model a
// tautological gate that ACCEPTS the decoy (the decoy VIOLATES -> no flip -> refused).
function seedDecoyRefs(domain, {
  findingId = "F-1",
  containerIsolated = true,
  decoyArmOutcome = "test_passed",
  contractName = undefined,
  functionName = undefined,
  executionContextHash = undefined,
  slotValues = undefined,
} = {}) {
  const decoyCapture = appendDecoyCapture(domain);
  const decoyArm = seedInvariantRunRow(domain, {
    findingId,
    outcome: decoyArmOutcome,
    treeRef: "target",
    checkoutKind: "tree",
    sign: true,
    templateId: CONSUME_TEMPLATE_ID,
    containerIsolated,
    causeRunId: DECOY_RUN_ID,
    consumedArtifactHash: DECOY_HASH,
    ...(contractName !== undefined ? { contractName } : {}),
    ...(functionName !== undefined ? { functionName } : {}),
    ...(executionContextHash !== undefined ? { executionContextHash } : {}),
    ...(slotValues !== undefined ? { slotValues } : {}),
  });
  return {
    decoy_run_ref: { ledger: "invariant_runs", row_id: decoyArm.run_hash },
    decoy_cause_run_ref: { ledger: "offensive_runs", row_id: decoyCapture.run_id },
    decoyArm,
    decoyCapture,
  };
}

module.exports = {
  CONSUME_TEMPLATE_ID,
  DECOY_BYTES,
  DECOY_HASH,
  DECOY_RUN_ID,
  appendDecoyCapture,
  seedDecoyRefs,
};
