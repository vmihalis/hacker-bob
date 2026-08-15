"use strict";

// EXECUTED-CAUSATION ORACLE — the CONSUMED-ARTIFACT binding (O-B) that makes cross-stack
// causation PROVEN, not NAMED. The prior adjudicator gated the causal link on pure
// cause_run_id string-equality (violatedArmNamesCause), so a real web exploit + a real
// same-test EVM violated/held flip on an UNRELATED contract that merely NAMES the web run
// falsely chained — and survived Mechanism A (all three rows genuinely signed). The binding
// closes it: the violated invariant arm must have CONSUMED the cause's captured artifact
// (its MAC-covered consumed_artifact_hash == the cause offensive row's MAC-covered
// consumed_artifact_hash), with the control arm cause-free.
//
// Coverage:
//   (#1 headline) a genuine web exploit + same-test EVM flip on an UNRELATED contract that
//       NAMES but did not CONSUME the cause -> REFUTED (never verified_pass).
//   (a) violated arm consumed_artifact_hash null (cause-free) but names the cause -> refuted.
//   (b) violated consumed a DIFFERENT artifact than the cause captured -> refuted.
//   (c) the named cause captured NO artifact (consumed_artifact_hash null) -> refuted.
//   (d) the CONTROL arm ALSO consumed an artifact (non-null) -> refuted (not cause-free).
//   (GENUINE) the EVM violation consumed the EXACT web-captured artifact -> verified_pass.
//   (HIGH-1) a same-stack-family cause (offensive on an SC-family surface) -> refuted;
//       a web-cause + SC-effect -> is_cross_stack true -> mints.
//   (HIGH-3) a guard-only verified_pass path_hash is NOT in verified_cross_stack_path_hashes.
//   (MEDIUM-1) the same-test check rejects a control arm on a DIFFERENT finding_id.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  verifyCompositionPath,
  readCompositionVerifiedSummary,
} = require("../mcp/core/differential/composition-live-verifier.js");
const {
  canonicalizeExploitTarget,
  appendCandidateClaim,
} = require("../mcp/core/claims/claims.js");
const {
  offensiveRunsJsonlPath,
  offensiveRunsDir,
  surfaceRoutesPath,
  sessionDir,
} = require("../mcp/core/io/paths.js");
const {
  ensureHandoffSigningKey,
} = require("../mcp/core/ledger-integrity/handoff-signing-key.js");
const {
  signOffensiveRunRow,
} = require("../mcp/core/ledger-integrity/offensive-row-mac.js");
const {
  classifySurfaceCapability,
} = require("../mcp/core/capability/capability-packs.js");
const {
  seedInvariantRunRow: seedInvariantRunRowRaw,
} = require("./helpers/invariant-run-seed.js");
const {
  CONSUME_TEMPLATE_ID,
  DECOY_HASH,
  DECOY_RUN_ID,
  appendDecoyCapture,
} = require("./helpers/cross-stack-decoy.js");

// Every cross-stack invariant arm in these tests runs the audited consuming template and is
// container_isolated by default (the cross-stack adjudicator's template_id + isolation
// gates). A test that needs a different template/isolation passes it explicitly.
function seedInvariantRunRow(domain, opts = {}) {
  return seedInvariantRunRowRaw(domain, {
    templateId: CONSUME_TEMPLATE_ID,
    containerIsolated: true,
    crossStackTargetBound: true,
    ...opts,
  });
}

// Seed a HELD decoy arm matching the SAME test as `positive` (contract/function/exec-ctx/
// slot_values), plus the decoy capture, and return the two leaf refs. The decoy consumes the
// random decoy bytes and HOLDS (a genuine gate rejects them).
function seedMatchingDecoy(domain, positive, { decoyArmOutcome = "test_passed" } = {}) {
  appendDecoyCapture(domain);
  const decoyArm = seedInvariantRunRow(domain, {
    findingId: positive.finding_id,
    outcome: decoyArmOutcome,
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

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-consumed-binding-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function hex(char) {
  return char.repeat(64);
}

const WEB_SURFACE = "surface:billing-web";
const SC_SURFACE = "surface:vault-sc";
const CAUSE_RUN_ID = "web-cause-1";
const BASE_URL = "https://stack.example.com";
const BIND_DEPS = { httpScanFn: () => { throw new Error("bind path must not perform any HTTP fetch"); } };

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

// Genuine captured bytes the web attack produces and the EVM violation consumes.
const GENUINE_BYTES = Buffer.from("forged-relay-payload:0xdeadbeef", "utf8");
const GENUINE_HASH = sha256(GENUINE_BYTES);
// A DIFFERENT artifact (a mismatched consume).
const OTHER_BYTES = Buffer.from("some-other-unrelated-bytes", "utf8");
const OTHER_HASH = sha256(OTHER_BYTES);

// Route a surface to a stack family (web / smart_contract) via the real capability-pack
// classifier, so the verifier's is_cross_stack stack-family check (HIGH-1) resolves it.
function seedSurfaceRoutes(domain, entries) {
  const routes = entries.map(({ surfaceId, surfaceType }) => {
    const surface = { id: surfaceId, kind: surfaceType, surface_type: surfaceType };
    // smart_contract routing requires a chain_family; web does not.
    if (surfaceType === "smart_contract") surface.chain_family = "evm";
    const c = classifySurfaceCapability(surface);
    return {
      surface_id: surfaceId,
      surface_type: surfaceType,
      capability_pack: c.capability_pack,
      capability_pack_version: c.capability_pack_version,
      evaluator_agent: c.evaluator_agent,
      brief_profile: c.brief_profile,
      context_budget: c.context_budget,
    };
  });
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  fs.writeFileSync(surfaceRoutesPath(domain), JSON.stringify({ version: 1, route_version: 1, routes }));
}

// Build + sign a single offensive-runs (web) CAUSE row with the per-session key, with an
// optional consumed_artifact_hash. When captureBytes is supplied the .consumed leaf is
// written so the read-time re-fetch resolves.
function appendWebCause(domain, {
  runId = CAUSE_RUN_ID,
  surfaceId = WEB_SURFACE,
  offensiveOutcome = "exploited_safely",
  consumedHash = GENUINE_HASH,
  captureBytes = GENUINE_BYTES,
} = {}) {
  const row = {
    version: 1,
    target_domain: domain,
    run_id: runId,
    tool_id: "bob_http_idor_confirm",
    target: canonicalizeExploitTarget(`https://${domain}/api/billing/1`),
    offensive_outcome: offensiveOutcome,
    dry_run: false,
    timed_out: false,
    command_hash: hex("1"),
    exit_code: 0,
    stdout_hash: hex("b"),
    stderr_hash: hex("c"),
    demonstrated_severity: "high",
    surface_id: surfaceId,
    consumed_artifact_hash: consumedHash,
    container_isolated: true,
  };
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
  fs.mkdirSync(path.dirname(offensiveRunsJsonlPath(domain)), { recursive: true });
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  if (consumedHash != null && captureBytes != null && sha256(captureBytes) === consumedHash) {
    fs.mkdirSync(offensiveRunsDir(domain), { recursive: true });
    fs.writeFileSync(path.join(offensiveRunsDir(domain), `${runId}.consumed`), captureBytes);
  }
  return row;
}

// Seed the candidate claim that scopes the cause surface to the effect finding so the
// FAIL-CLOSED finding-scope gate resolves available && inFinding. A genuine reportable
// cross-stack mint runs in a repo session where the claim + surface_ids exist; the gate
// hard-fails closed on an indeterminate map, so a mint test must seed this.
function seedFindingClaim(domain, { findingId = "F-1", surfaceIds = [WEB_SURFACE] } = {}) {
  appendCandidateClaim({
    target_domain: domain,
    title: `cross-stack finding ${findingId}`,
    summary: "web cause scoped to the effect finding for the fail-closed finding-scope gate",
    severity: "high",
    status: "candidate",
    surface_ids: surfaceIds,
    payload: { finding: { id: findingId } },
  });
}

function crossStackLeaf(domain, { positive, control, cause, decoyArmOutcome = "test_passed", edgeType = "web_seeds_evm_state_corruption" }) {
  const decoyRefs = seedMatchingDecoy(domain, positive, { decoyArmOutcome });
  return {
    edge_type: edgeType,
    positive_run_ref: { ledger: "invariant_runs", row_id: positive.run_hash },
    control_run_ref: { ledger: "invariant_runs", row_id: control.run_hash },
    cause_run_ref: { ledger: "offensive_runs", row_id: cause.run_id },
    ...decoyRefs,
  };
}

async function runBindPath(domain, leaf) {
  return verifyCompositionPath({ target_domain: domain, base_url: BASE_URL, path: [leaf] }, BIND_DEPS);
}

// ── #1 HEADLINE: named but not consumed (the exact stage-2 forgery) ───────────

test("#1: a genuine web exploit + same-test EVM flip on an UNRELATED contract that NAMES but did NOT consume the cause is REFUSED", () => withTempHome(() => {
  const domain = "ob-headline.example.com";
  seedSurfaceRoutes(domain, [{ surfaceId: WEB_SURFACE, surfaceType: "web" }]);
  const cause = appendWebCause(domain); // genuine web exploit, captured GENUINE_BYTES
  // The EVM violation NAMES the cause but ran CAUSE-FREE (consumed_artifact_hash null) —
  // the web bytes never entered the foundry subprocess. This is the named-not-consumed forge.
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    contractName: "UnrelatedVault", causeRunId: CAUSE_RUN_ID, consumedArtifactHash: null,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
    contractName: "UnrelatedVault",
  });
  return (async () => {
    const out = await runBindPath(domain, crossStackLeaf(domain, { positive, control, cause }));
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /consumed no artifact|never entered the effect run/i);
    assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
  })();
}));

// ── conditions a / b / c / d ──────────────────────────────────────────────────

test("(a) violated arm consumed_artifact_hash null (cause-free) but names the cause -> refuted", () => withTempHome(() => {
  const domain = "ob-cond-a.example.com";
  seedSurfaceRoutes(domain, [{ surfaceId: WEB_SURFACE, surfaceType: "web" }]);
  const cause = appendWebCause(domain);
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    causeRunId: CAUSE_RUN_ID, consumedArtifactHash: null,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
  });
  return (async () => {
    const out = await runBindPath(domain, crossStackLeaf(domain, { positive, control, cause }));
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /consumed no artifact/i);
  })();
}));

test("(b) violated arm consumed a DIFFERENT artifact than the cause captured -> refuted", () => withTempHome(() => {
  const domain = "ob-cond-b.example.com";
  seedSurfaceRoutes(domain, [{ surfaceId: WEB_SURFACE, surfaceType: "web" }]);
  const cause = appendWebCause(domain); // cause captured GENUINE_HASH
  // The violated arm consumed SOME bytes, but NOT the cause's bytes.
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    causeRunId: CAUSE_RUN_ID, consumedArtifactHash: OTHER_HASH,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
  });
  return (async () => {
    const out = await runBindPath(domain, crossStackLeaf(domain, { positive, control, cause }));
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /different artifact than the cause captured|consumed_artifact_hash mismatch/i);
  })();
}));

test("(c) the named cause captured NO artifact (consumed_artifact_hash null) -> refuted", () => withTempHome(() => {
  const domain = "ob-cond-c.example.com";
  seedSurfaceRoutes(domain, [{ surfaceId: WEB_SURFACE, surfaceType: "web" }]);
  // A web-only cause that captured nothing consumable.
  const cause = appendWebCause(domain, { consumedHash: null, captureBytes: null });
  // The violated arm claims to have consumed the (non-existent) artifact.
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    causeRunId: CAUSE_RUN_ID, consumedArtifactHash: GENUINE_HASH,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
  });
  return (async () => {
    const out = await runBindPath(domain, crossStackLeaf(domain, { positive, control, cause }));
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /cause captured no consumable artifact|nothing to consume/i);
  })();
}));

test("(d) the CONTROL arm ALSO consumed an artifact (non-null) -> refuted (not cause-free)", () => withTempHome(() => {
  const domain = "ob-cond-d.example.com";
  seedSurfaceRoutes(domain, [{ surfaceId: WEB_SURFACE, surfaceType: "web" }]);
  const cause = appendWebCause(domain);
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    causeRunId: CAUSE_RUN_ID, consumedArtifactHash: GENUINE_HASH,
  });
  // The "control" ALSO consumed the artifact -> it did not run cause-free, so the artifact
  // is not the controlled variable.
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
    consumedArtifactHash: GENUINE_HASH,
  });
  return (async () => {
    const out = await runBindPath(domain, crossStackLeaf(domain, { positive, control, cause }));
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /control arm also consumed|did not run cause-free/i);
  })();
}));

// ── GENUINE consume-bound flow MINTS ──────────────────────────────────────────

test("GENUINE: the EVM violation consumed the EXACT web-captured artifact -> verified_pass (different stack families)", () => withTempHome(() => {
  const domain = "ob-genuine.example.com";
  seedSurfaceRoutes(domain, [{ surfaceId: WEB_SURFACE, surfaceType: "web" }]);
  seedFindingClaim(domain, { findingId: "F-1", surfaceIds: [WEB_SURFACE] });
  const cause = appendWebCause(domain); // captured GENUINE_BYTES
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    causeRunId: CAUSE_RUN_ID, consumedArtifactHash: GENUINE_HASH,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
  });
  return (async () => {
    const out = await runBindPath(domain, crossStackLeaf(domain, { positive, control, cause }));
    assert.equal(out.result, "verified_pass");
    assert.equal(out.leaves[0].is_cross_stack, true, "web cause + smart_contract effect span distinct families");
    const summary = readCompositionVerifiedSummary(domain);
    assert.ok(summary.verified_path_hashes.includes(out.path_hash));
    assert.ok(summary.verified_cross_stack_path_hashes.includes(out.path_hash), "the genuine flow enters the cross-stack-only membership set");
  })();
}));

// ── HIGH-1 real stack-family is_cross_stack gate ──────────────────────────────

test("HIGH-1: a same-stack-family flip (cause offensive on an SC-family surface + SC effect) is REFUSED", () => withTempHome(() => {
  const domain = "ob-samefamily.example.com";
  // The cause surface is routed as smart_contract (same family as the effect invariant arm).
  seedSurfaceRoutes(domain, [{ surfaceId: SC_SURFACE, surfaceType: "smart_contract" }]);
  const cause = appendWebCause(domain, { surfaceId: SC_SURFACE });
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    causeRunId: CAUSE_RUN_ID, consumedArtifactHash: GENUINE_HASH,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
  });
  return (async () => {
    const out = await runBindPath(domain, crossStackLeaf(domain, { positive, control, cause }));
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /do not span distinct stack families|same-stack/i);
    assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
  })();
}));

test("HIGH-1: an UNROUTED cause surface (unresolved family) is REFUSED (cannot prove distinct stacks)", () => withTempHome(() => {
  const domain = "ob-unrouted.example.com";
  // NO surface-routes.json written -> the cause family is unknown -> not proven cross-stack.
  const cause = appendWebCause(domain);
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    causeRunId: CAUSE_RUN_ID, consumedArtifactHash: GENUINE_HASH,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
  });
  return (async () => {
    const out = await runBindPath(domain, crossStackLeaf(domain, { positive, control, cause }));
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /do not span distinct stack families|unresolved-stack/i);
  })();
}));

// ── HIGH-3 guard-only is not in the cross-stack membership set ────────────────

test("HIGH-3: a guard-only verified_pass path_hash is NOT in verified_cross_stack_path_hashes", () => withTempHome(() => {
  const domain = "ob-guardonly.example.com";
  // Forge a guard-only verified_pass row directly on the audit-graded ledger (no bind leaf).
  // It enters verified_path_hashes (the SC1/guard set) on its own terms, but a guard row can
  // NEVER claim cross-stack: it must be excluded from the cross-stack-only set.
  const forged = {
    version: 1,
    target_domain: domain,
    ts: new Date().toISOString(),
    result: "verified_pass",
    offline_result: "pass",
    path_hash: hex("d"),
    leaf_count: 1,
    verified_leaf_count: 1,
    // NO has_bind_leaf -> guard-only.
    leaves: [{ leaf_status: "verified", edge_type: "guard", evidence_ref: "frontier_event:e1" }],
  };
  const { compositionVerifiedJsonlPath } = require("../mcp/core/io/paths.js");
  const { hashCanonicalJson } = require("../mcp/core/verification/verification-contracts.js");
  forged.results_hash = hashCanonicalJson(forged);
  fs.mkdirSync(path.dirname(compositionVerifiedJsonlPath(domain)), { recursive: true });
  fs.writeFileSync(compositionVerifiedJsonlPath(domain), `${JSON.stringify(forged)}\n`);

  const summary = readCompositionVerifiedSummary(domain);
  // A guard-only row's path_hash is admitted to the general set (it backs SC1)...
  assert.ok(summary.verified_path_hashes.includes(hex("d")), "guard-only path_hash is in the general set");
  // ...but is EXCLUDED from the cross-stack-only set (it has no bind leaf / is_cross_stack).
  assert.ok(!summary.verified_cross_stack_path_hashes.includes(hex("d")), "guard-only path_hash is NOT bindable as cross-stack");
}));

// ── MEDIUM-1 finding_id on the same-test check ────────────────────────────────

test("MEDIUM-1: a control arm on a DIFFERENT finding_id is REFUSED on the same-test check", () => withTempHome(() => {
  const domain = "ob-crossfinding.example.com";
  seedSurfaceRoutes(domain, [{ surfaceId: WEB_SURFACE, surfaceType: "web" }]);
  const cause = appendWebCause(domain);
  // Positive on F-1; the "control" shares template/contract/function/exec-ctx but is on F-9.
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    causeRunId: CAUSE_RUN_ID, consumedArtifactHash: GENUINE_HASH,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-9", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
  });
  return (async () => {
    const out = await runBindPath(domain, crossStackLeaf(domain, { positive, control, cause }));
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /SAME test on the same tree.*finding_id|finding_id differs/i);
    assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
  })();
}));

// ── read-time integrity: post-mint swap of the .consumed leaf drops the row ───

test("read-time: swapping the cause's .consumed bytes after the mint drops the row from verified_cross_stack_path_hashes", () => withTempHome(() => {
  const domain = "ob-readtime-swap.example.com";
  seedSurfaceRoutes(domain, [{ surfaceId: WEB_SURFACE, surfaceType: "web" }]);
  seedFindingClaim(domain, { findingId: "F-1", surfaceIds: [WEB_SURFACE] });
  const cause = appendWebCause(domain);
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    causeRunId: CAUSE_RUN_ID, consumedArtifactHash: GENUINE_HASH,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
  });
  return (async () => {
    const out = await runBindPath(domain, crossStackLeaf(domain, { positive, control, cause }));
    assert.equal(out.result, "verified_pass");
    assert.ok(readCompositionVerifiedSummary(domain).verified_cross_stack_path_hashes.includes(out.path_hash));

    // SWAP the on-disk .consumed bytes (the signed row's hash still pins the GENUINE bytes).
    fs.writeFileSync(path.join(offensiveRunsDir(domain), `${CAUSE_RUN_ID}.consumed`), OTHER_BYTES);

    const after = readCompositionVerifiedSummary(domain);
    assert.ok(!after.verified_cross_stack_path_hashes.includes(out.path_hash), "the read-time re-fetch catches the swapped bytes and drops the row");
  })();
}));
