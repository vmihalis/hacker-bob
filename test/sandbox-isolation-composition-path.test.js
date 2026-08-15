"use strict";

// F2c — the verdict-level sandbox-isolation gate must COVER a cross-stack finding whose
// only executed backing is a composition_path evidence_ref (a bound cross-stack
// verified_pass in composition-verified.jsonl). Before this fix findingsBackedByKeyedLedger
// only recognized exploit_run / repo_command_run refs, so under enforce the gate was INERT
// on a cross-stack finding — its backing was invisible and it escaped the isolation
// requirement. This test seeds a reportable cross-stack finding backed ONLY by a
// composition_path ref bound to a REAL minted verified_pass, and asserts:
//   * on a same-uid box the gate APPLIES and BLOCKS (enforce) — the composition_path leg is
//     recognized as keyed-ledger backing, so the finding is gated;
//   * a composition_path ref whose path_hash is NOT a re-resolved member does NOT back the
//     finding (the gate is inert on it — no over-gating of an unrelated/forged path).
//
// HONESTY: as with the sibling sandbox tests, isolated:false on a same-uid dev box is the
// real (un-stubbed) probe outcome; this test exercises the BACKING-RECOGNITION leg (does a
// composition_path-backed finding enter the gated set), not OS-level uid exclusion.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const { appendCandidateClaim } = require("../mcp/core/claims/claims.js");
const { writeVerificationRound } = require("../mcp/core/verification/verification-round-store.js");
const { buildClaimFreeze } = require("../mcp/core/claims/claim-freeze.js");
const { ensureHandoffSigningKey } = require("../mcp/core/ledger-integrity/index.js");
const { signOffensiveRunRow } = require("../mcp/core/ledger-integrity/index.js");
const { canonicalizeExploitTarget } = require("../mcp/core/claims/claims.js");
const { verifyCompositionPath } = require("../mcp/core/differential/index.js");
const { evaluateVerdictSandboxGate } = require("../mcp/core/verdict-sandbox-gate.js");
const { offensiveRunsJsonlPath, offensiveRunsDir, surfaceRoutesPath, sessionDir } = require("../mcp/core/io/paths.js");
const { classifySurfaceCapability } = require("../mcp/core/capability/capability-packs.js");
const { seedInvariantRunRow: seedInvariantRunRowRaw } = require("./helpers/invariant-run-seed.js");
const {
  CONSUME_TEMPLATE_ID,
  DECOY_HASH,
  DECOY_RUN_ID,
  appendDecoyCapture,
} = require("./helpers/cross-stack-decoy.js");
const {
  SANDBOX_ATTESTATION_MODE_ENV,
} = require("../mcp/core/ledger-integrity/index.js");

// Every cross-stack invariant arm here runs the audited consuming template and is
// container_isolated by default (the cross-stack adjudicator's template_id + isolation gates).
function seedInvariantRunRow(domain, opts = {}) {
  return seedInvariantRunRowRaw(domain, {
    templateId: CONSUME_TEMPLATE_ID,
    containerIsolated: true,
    crossStackTargetBound: true,
    ...opts,
  });
}

// Seed a HELD decoy arm matching the SAME test as `positive`, plus the decoy capture, and
// return the two leaf refs. The decoy consumes the random decoy bytes and HOLDS — the
// artifact-relevance arm a cross-stack verified_pass requires.
function seedMatchingDecoy(domain, positive) {
  appendDecoyCapture(domain);
  const decoyArm = seedInvariantRunRow(domain, {
    findingId: positive.finding_id,
    outcome: "test_passed",
    treeRef: positive.tree_ref,
    checkoutKind: positive.checkout_kind,
    contractName: positive.contract_name,
    functionName: positive.function_name,
    executionContextHash: positive.execution_context_hash,
    slotValues: positive.slot_values,
    sign: true,
    causeRunId: DECOY_RUN_ID,
    consumedArtifactHash: DECOY_HASH,
  });
  return {
    decoy_run_ref: { ledger: "invariant_runs", row_id: decoyArm.run_hash },
    decoy_cause_run_ref: { ledger: "offensive_runs", row_id: DECOY_RUN_ID },
  };
}

function hex(char) { return char.repeat(64); }
const CAUSE_RUN_ID = "web-cause-1";
const WEB_SURFACE = "surface:web-a";
// The genuine bytes the web attack captures and the EVM violation consumes; the O-B
// consumed-artifact binding requires the violated arm's consumed_artifact_hash to equal
// the cause offensive row's consumed_artifact_hash (proven-not-named). SAME byte length +
// raw encoding class as the shared decoy capture (DECOY_BYTES) so the HIGH-2 shape-parity
// binding passes (the decoy differs from the cause only in content, never in shape).
const CAUSE_BYTES = Buffer.from("forged-relay-payload:xstackgate", "utf8");
const CAUSE_HASH = crypto.createHash("sha256").update(CAUSE_BYTES).digest("hex");

// Route the web cause surface to the web stack family so the verifier's is_cross_stack
// stack-family check (HIGH-1) resolves it distinct from the smart_contract effect arm.
function seedWebSurfaceRoute(domain) {
  const surface = { id: WEB_SURFACE, kind: "web", surface_type: "web" };
  const c = classifySurfaceCapability(surface);
  const route = {
    surface_id: WEB_SURFACE,
    surface_type: "web",
    capability_pack: c.capability_pack,
    capability_pack_version: c.capability_pack_version,
    evaluator_agent: c.evaluator_agent,
    brief_profile: c.brief_profile,
    context_budget: c.context_budget,
  };
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  fs.writeFileSync(surfaceRoutesPath(domain), JSON.stringify({ version: 1, route_version: 1, routes: [route] }));
}

// Async-aware: when fn returns a promise the temp tree must survive until it settles (a
// synchronous finally would rm HOME mid-test and a freshly-minted bind row would re-resolve
// against a deleted ledger).
async function withTempHome(fn, mode) {
  const previousHome = process.env.HOME;
  const previousMode = process.env[SANDBOX_ATTESTATION_MODE_ENV];
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sandbox-xstack-"));
  process.env.HOME = home;
  if (mode != null) process.env[SANDBOX_ATTESTATION_MODE_ENV] = mode;
  else delete process.env[SANDBOX_ATTESTATION_MODE_ENV];
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previousHome;
    if (previousMode === undefined) delete process.env[SANDBOX_ATTESTATION_MODE_ENV];
    else process.env[SANDBOX_ATTESTATION_MODE_ENV] = previousMode;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function verificationResult(findingId, overrides = {}) {
  return {
    finding_id: findingId, disposition: "confirmed", severity: "high", reportable: true,
    reasoning: "Fresh replay confirmed the cross-stack finding against the current target state.",
    ...overrides,
  };
}

// Mint a REAL bound cross-stack verified_pass and return its execution-keyed path_hash.
async function mintBoundCrossStackVerifiedPass(domain) {
  seedWebSurfaceRoute(domain);
  const row = {
    version: 1,
    target_domain: domain,
    run_id: CAUSE_RUN_ID,
    tool_id: "bob_http_idor_confirm",
    target: canonicalizeExploitTarget(`https://${domain}/api/billing/1`),
    offensive_outcome: "exploited_safely",
    dry_run: false,
    timed_out: false,
    command_hash: hex("1"),
    exit_code: 0,
    stdout_hash: hex("b"),
    stderr_hash: hex("c"),
    demonstrated_severity: "high",
    surface_id: WEB_SURFACE,
    // O-B: the cause captured a consumable artifact (its hash is MAC-covered).
    consumed_artifact_hash: CAUSE_HASH,
    container_isolated: true,
  };
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
  fs.mkdirSync(path.dirname(offensiveRunsJsonlPath(domain)), { recursive: true });
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  // The .consumed leaf, so the read-time re-fetch (reverifyCrossStackLeaf) resolves.
  fs.mkdirSync(offensiveRunsDir(domain), { recursive: true });
  fs.writeFileSync(path.join(offensiveRunsDir(domain), `${CAUSE_RUN_ID}.consumed`), CAUSE_BYTES);
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    // O-B: the violated arm CONSUMED the cause's captured artifact (hash binds to the cause).
    causeRunId: CAUSE_RUN_ID, consumedArtifactHash: CAUSE_HASH,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
    // SAME test, SAME tree, artifact-absent: the consumed artifact is the controlled variable.
  });
  // The genuine gate REJECTS random decoy bytes -> the decoy arm HOLDS (the relevance arm).
  const decoy = seedMatchingDecoy(domain, positive);
  const leaf = {
    edge_type: "web_seeds_evm_state_corruption",
    positive_run_ref: { ledger: "invariant_runs", row_id: positive.run_hash },
    control_run_ref: { ledger: "invariant_runs", row_id: control.run_hash },
    cause_run_ref: { ledger: "offensive_runs", row_id: CAUSE_RUN_ID },
    ...decoy,
  };
  const verifyInput = { target_domain: domain, base_url: `https://${domain}`, path: [leaf] };
  const bindDeps = { httpScanFn: () => { throw new Error("bind path must not fetch"); } };
  // PROBE the verifier with NO finding-scope claim: the FAIL-CLOSED finding-scope gate
  // refuses (indeterminate map) but the execution-keyed path_hash is still computed and
  // returned. This lets the SINGLE F-1 claim below be BOTH the finding-scope claim and the
  // gate-backing composition_path claim (no first-wins shadowing of the sandbox gate's
  // claimByFinding lookup). The path_hash is execution-keyed (independent of the claim), so
  // the probe-learned value equals the real mint's value.
  const probe = await verifyCompositionPath(verifyInput, bindDeps);
  assert.equal(probe.result, "refuted", "no finding-scope claim yet -> fail-closed refusal");
  assert.match(probe.leaves[0].reason, /PROVABLY within the effect finding|indeterminate finding/i);
  const prospectivePathHash = probe.path_hash;
  assert.ok(typeof prospectivePathHash === "string" && prospectivePathHash, "the probe still returns the execution-keyed path_hash");
  // Scope the cause surface to the effect finding AND back the gate with the composition_path
  // ref (a reportable cross-stack mint runs in a repo session where the claim + surface_ids
  // exist; an indeterminate map hard-fails closed).
  appendCandidateClaim({
    target_domain: domain,
    title: "web identity reuse corrupts EVM vault state",
    summary: "A web IDOR seeds attacker state the on-chain invariant then violates",
    severity: "high",
    status: "candidate",
    surface_ids: [WEB_SURFACE, "surface:evm-b"],
    evidence_refs: [
      { kind: "finding", finding_id: "F-1", content_hash: hex("e") },
      { kind: "composition_path", path_hash: prospectivePathHash },
    ],
    payload: { finding: { id: "F-1", severity: "high", title: "cross-stack vault corruption" } },
  });
  const res = await verifyCompositionPath(verifyInput, bindDeps);
  assert.equal(res.result, "verified_pass");
  assert.equal(res.path_hash, prospectivePathHash, "the seeded composition_path ref binds the minted path_hash");
  return res.path_hash;
}

// Seed a reportable HIGH cross-stack finding whose claim cites ONLY a composition_path ref
// (no exploit_run / repo_command_run). Without the F2c leg this finding would be INVISIBLE
// to the gate (no recognized backing -> inert).
function seedCompositionPathBackedFinding(domain, compositionPathHash) {
  appendCandidateClaim({
    target_domain: domain,
    title: "web identity reuse corrupts EVM vault state",
    summary: "A web IDOR seeds attacker state the on-chain invariant then violates",
    severity: "high",
    surface_ids: ["surface:web-a", "surface:evm-b"],
    evidence_refs: [
      { kind: "finding", finding_id: "F-1", content_hash: hex("e") },
      { kind: "composition_path", path_hash: compositionPathHash },
    ],
    payload: { finding: { id: "F-1", severity: "high", title: "cross-stack vault corruption" } },
  });
  buildClaimFreeze(domain, { write: true, now: new Date("2026-05-27T01:00:00.000Z") });
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({ target_domain: domain, round, notes: null, results: [verificationResult("F-1")] });
  }
}

test("F2c: a composition_path-backed cross-stack finding is GATED by the enforce sandbox gate (the leg makes the gate cover it)", () => withTempHome(() => (async () => {
  const domain = "xstack-gate-cover.example.com";
  const pathHash = await mintBoundCrossStackVerifiedPass(domain);
  seedCompositionPathBackedFinding(domain, pathHash);

  const decision = evaluateVerdictSandboxGate(domain);
  assert.equal(decision.applies, true, "a composition_path-backed cross-stack finding makes the gate APPLY (not inert)");
  assert.deepEqual([...decision.reportable_finding_ids], ["F-1"], "F-1 is in the gated set via the composition_path leg");
  // Same-uid dev box: the real probe is not isolated, so enforce BLOCKS.
  assert.equal(decision.isolated, false, "same-uid box is not isolated (real probe)");
  const expected = decision.mode === "enforce" ? "block" : "downgrade";
  assert.equal(decision.decision, expected, `mode=${decision.mode} -> ${expected} on a composition_path-backed cross-stack finding`);
})(), "enforce"));

test("F2c (no over-gate): a composition_path ref whose path_hash is NOT a re-resolved member does NOT back the finding (gate inert on it)", () => withTempHome(() => {
  const domain = "xstack-gate-inert.example.com";
  // No verified_pass minted; the claim cites a composition_path that is not a member.
  seedCompositionPathBackedFinding(domain, hex("f"));
  const decision = evaluateVerdictSandboxGate(domain);
  // The composition_path is not a re-resolved member, so it is NOT recognized as backing.
  // No keyed ledger row exists either (no offensive/invariant rows), so the finding is
  // pure-OSINT-shaped here and the gate is inert (no_verdict_ledger_backing).
  assert.equal(decision.applies, false, "an unbound composition_path ref does not back the finding -> gate inert");
  assert.equal(decision.reason, "no_verdict_ledger_backing");
}, "enforce"));
