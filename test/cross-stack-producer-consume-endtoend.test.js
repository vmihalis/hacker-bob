"use strict";

// EXECUTED-CAUSATION ORACLE — the FUNCTIONAL producer + the two binding residuals.
//
// O-C closed the injection-vs-consumption gap but left it fail-closed-BY-DESIGN: no
// offensive producer captured a consumable (consumed_artifact_hash null everywhere), so
// the cross-stack adjudicator's condition (c) refused EVERY real mint. This suite locks the
// wiring that makes it FUNCTIONAL plus the two residual fail-closes:
//
//   (END-TO-END GENUINE) the REAL bob_http_idor_confirm producer captures the cross-tenant
//       body as consumed_artifact_hash on the signed offensive row; the consuming EVM
//       invariant arm violates WITH the artifact and the control HOLDS WITHOUT it; the
//       cross-stack verifier MINTS verified_pass (present->VIOLATE / absent->HOLD on a
//       vulnerable gate).
//   (SAFE CONTRACT) a gate that rejects the captured payload too -> BOTH arms HELD (no flip)
//       -> NO mint.
//   (SILENT-ACTIVATION TRIPWIRE) a pure-SC tree-flip (positive target / control fixed) with
//       an UNRELATED web cause that was NAMED but never CONSUMED -> REFUTED.
//   (RESIDUAL 2) a stdout-only cause (no .consumed leaf, consumed_artifact_hash null) is NOT
//       a free consumable: the runner injects nothing (arm runs cause-free) AND the
//       adjudicator refuses. A genuine .consumed cause still injects + mints.
//   (RESIDUAL 3) an INDETERMINATE finding<->surface map (no claim / empty surface_ids) for a
//       reportable cross-stack mint HARD-FAILS CLOSED, even when every other gate passes.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const { idorConfirm } = require("../mcp/domains/web/offensive-idor-producer.js");
const { initSession } = require("../mcp/core/session/session-state.js");
const { routeSurfaces } = require("../mcp/core/frontier/surface-router.js");
const { writeAuthFile, resolveAuthJsonPath } = require("../mcp/core/auth/auth.js");
const { ensureHandoffSigningKey } = require("../mcp/core/ledger-integrity/handoff-signing-key.js");
const { signOffensiveRunRow } = require("../mcp/core/ledger-integrity/offensive-row-mac.js");
const {
  appendCandidateClaim,
  canonicalizeExploitTarget,
  readOffensiveRunRecords,
} = require("../mcp/core/claims/claims.js");
const {
  verifyCompositionPath,
  readCompositionVerifiedSummary,
} = require("../mcp/core/differential/composition-live-verifier.js");
const { runInvariantForFinding, readInvariantRuns } = require("../mcp/core/invariant-runner.js");
const {
  attackSurfacePath,
  surfaceRoutesPath,
  sessionDir,
  offensiveRunsDir,
  offensiveRunsJsonlPath,
} = require("../mcp/core/io/paths.js");
const { classifySurfaceCapability } = require("../mcp/core/capability/capability-packs.js");
const { mintDecoyCapture } = require("../mcp/domains/web/offensive-capture-writer.js");
const { withSessionLock } = require("../mcp/core/io/storage.js");
const { seedInvariantRunRow: seedInvariantRunRowRaw } = require("./helpers/invariant-run-seed.js");
const {
  CONSUME_TEMPLATE_ID,
  DECOY_HASH,
  DECOY_RUN_ID,
  appendDecoyCapture,
} = require("./helpers/cross-stack-decoy.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/core/frontier/frontier-materialize-debounce.js");

// Every cross-stack invariant arm here runs the audited consuming template and is
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

// Seed a HELD decoy arm matching the SAME test as `positive`, plus the decoy capture, and
// return the two leaf refs. The decoy consumes the random decoy bytes and HOLDS (a genuine
// gate rejects them). Pass decoyArmOutcome:"test_failed" to model a tautological gate that
// ACCEPTS the decoy (the decoy VIOLATES -> no flip -> refused).
//
// When a `cause` row is provided, the decoy capture is minted GENUINELY from the cause via
// the production mintDecoyCapture({ fromCauseRunId }) path — so the decoy is SHAPE-MATCHED to
// the cause (same byte length + encoding class, random content) and the HIGH-2 shape-parity
// binding passes. Without a cause it falls back to the shared fixed decoy fixture (for the
// no-consumable RESIDUAL tests, where the cause has no shape to match).
function seedMatchingDecoy(domain, positive, { decoyArmOutcome = "test_passed", cause = null } = {}) {
  let decoyRunId;
  let decoyHash;
  if (cause != null && typeof cause.run_id === "string") {
    const decoyRow = withSessionLock(domain, () => mintDecoyCapture(domain, {
      toolId: "bob_http_idor_confirm",
      method: "GET",
      canonicalTarget: `https://${domain}/api/accounts/decoy`,
      surfaceId: WEB_SURFACE,
      identityTag: "decoy",
      fromCauseRunId: cause.run_id,
    }));
    decoyRunId = decoyRow.run_id;
    decoyHash = decoyRow.consumed_artifact_hash;
  } else {
    appendDecoyCapture(domain);
    decoyRunId = DECOY_RUN_ID;
    decoyHash = DECOY_HASH;
  }
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
    causeRunId: decoyRunId,
    consumedArtifactHash: decoyHash,
  });
  return {
    decoy_run_ref: { ledger: "invariant_runs", row_id: decoyArm.run_hash },
    decoy_cause_run_ref: { ledger: "offensive_runs", row_id: decoyRunId },
  };
}

// ── producer fixtures (seeded, no live target) — mirror offensive-idor-producer.test.js ──
const WEB_SURFACE = "surface:accounts";
const SC_SURFACE = "surface:vault-sc";
const PATH_TEMPLATE = "/api/accounts/{id}";
const OBJ_A = "obj-a-100";
const OBJ_B = "obj-b-200";
const OBJ_C = "obj-c-300";
const CANARY_A = "a".repeat(64);
const CANARY_B = "b".repeat(64);
const CANARY_C = "c".repeat(64);
const BASE_URL = "https://stack.example.test";
const BIND_DEPS = { httpScanFn: () => { throw new Error("bind path must not perform any HTTP fetch"); } };

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-xstack-endtoend-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function endpointFor(domain) { return `https://${domain}/api/accounts/${OBJ_B}`; }

function resourceBody({ canary, scope, viewer, objId = OBJ_B }) {
  const seed = crypto.createHash("sha256").update(`${viewer}|${objId}`).digest("hex");
  return {
    id: objId, kind: "account", name: "synthetic record", owner_scope: scope,
    viewer_id: viewer, server_ts: `2026-06-16T00:00:${seed.slice(0, 2)}.${seed.slice(2, 5)}Z`,
    csrf: seed.slice(0, 16), details: { secret: { token: canary } },
  };
}

function jsonResponse(status, bodyObj) {
  const bytes = Buffer.from(JSON.stringify(bodyObj), "utf8");
  return {
    status, headers: { get: () => null },
    bodyBytes: bytes, bodyByteLength: bytes.length, bodyTruncated: false,
  };
}

function challenge(status = 403) {
  const bytes = Buffer.from(JSON.stringify({ error: "forbidden" }), "utf8");
  return { status, headers: { get: () => null }, bodyBytes: bytes, bodyByteLength: bytes.length, bodyTruncated: false };
}

// The sound cross-tenant fetch router: A reads B's private object (cross-tenant) and gets
// B's canary at the discoverable leaf; the canary appears only in P1(B)/P2(A).
function soundFetchFn() {
  return async ({ url, headers }) => {
    const auth = headers && headers.Authorization ? String(headers.Authorization) : "";
    const isA = auth.includes("eyJatoken");
    const isB = auth.includes("eyJbtoken");
    const isC = auth.includes("eyJctoken");
    const u = new URL(url);
    const wantsOB = u.pathname.includes(OBJ_B);
    const wantsOA = u.pathname.includes(OBJ_A);
    const wantsOC = u.pathname.includes(OBJ_C);
    if (!isA && !isB && !isC) return challenge(403);
    if (wantsOB) {
      if (isB) return jsonResponse(200, resourceBody({ canary: CANARY_B, scope: "tenant-B", viewer: "viewer-B" }));
      if (isA) return jsonResponse(200, resourceBody({ canary: CANARY_B, scope: "tenant-B", viewer: "viewer-A" }));
      if (isC) return challenge(403);
    }
    if (wantsOA) {
      if (isA) return jsonResponse(200, resourceBody({ canary: CANARY_A, scope: "tenant-A", viewer: "viewer-A", objId: OBJ_A }));
      return challenge(403);
    }
    if (wantsOC) {
      if (isC) return jsonResponse(200, resourceBody({ canary: CANARY_C, scope: "tenant-C", viewer: "viewer-C", objId: OBJ_C }));
      return challenge(403);
    }
    return challenge(404);
  };
}

function soundProvision() {
  return {
    object_a: OBJ_A, object_b: OBJ_B, object_c: OBJ_C,
    canary_a: CANARY_A, canary_b: CANARY_B, canary_c: CANARY_C,
    owner_readback_b: { id: OBJ_B, owner_scope: "tenant-B", details: { secret: { token: CANARY_B } } },
  };
}

function baseArgs(domain) {
  return {
    target_domain: domain, surface_id: WEB_SURFACE, oracle_kind: "differential_response",
    path_template: PATH_TEMPLATE, method: "GET",
    identity_a_profile: "identity_a", identity_b_profile: "identity_b", identity_c_profile: "identity_c",
  };
}

function seedRoutedAttackSurface(domain) {
  fs.mkdirSync(path.dirname(attackSurfacePath(domain)), { recursive: true });
  fs.writeFileSync(attackSurfacePath(domain), `${JSON.stringify({
    surfaces: [{
      id: WEB_SURFACE, title: "Synthetic API account surface", surface_type: "web",
      hosts: [domain], endpoints: [endpointFor(domain)], tech_stack: ["fixture"], priority: "HIGH",
    }],
  }, null, 2)}\n`, "utf8");
  JSON.parse(routeSurfaces({ target_domain: domain }));
}

function seedSyntheticProfiles(domain) {
  const flags = { synthetic: true, email_origin: "temp_email", provisioned_via: "bob_auto_signup" };
  const mk = (tag) => ({ Authorization: `Bearer eyJ${tag}token`, email: `eval_${tag}@example.test`, ...flags });
  writeAuthFile(resolveAuthJsonPath(domain), `${JSON.stringify({
    version: 2, profiles: { identity_a: mk("a"), identity_b: mk("b"), identity_c: mk("c") },
  }, null, 2)}\n`);
}

function setupProducerSession(domain) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedAttackSurface(domain);
  seedSyntheticProfiles(domain);
  ensureHandoffSigningKey(domain);
}

// Overwrite the surface-routes.json the producer's routeSurfaces wrote so the cross-stack
// verifier's stack-family check resolves BOTH the web cause surface (web) and a
// smart_contract effect surface. classifySurfaceCapability produces a route that passes
// readSurfaceRoutesStrict.
function writeCrossStackRoutes(domain) {
  const route = (surfaceId, surfaceType) => {
    const surface = { id: surfaceId, kind: surfaceType, surface_type: surfaceType };
    if (surfaceType === "smart_contract") surface.chain_family = "evm";
    const c = classifySurfaceCapability(surface);
    return {
      surface_id: surfaceId, surface_type: surfaceType,
      capability_pack: c.capability_pack, capability_pack_version: c.capability_pack_version,
      evaluator_agent: c.evaluator_agent, brief_profile: c.brief_profile, context_budget: c.context_budget,
    };
  };
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  fs.writeFileSync(surfaceRoutesPath(domain), JSON.stringify({
    version: 1, route_version: 1,
    routes: [route(WEB_SURFACE, "web"), route(SC_SURFACE, "smart_contract")],
  }));
}

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

function crossStackLeaf({ positive, control, causeRunId, decoy }) {
  return {
    edge_type: "web_seeds_evm_state_corruption",
    positive_run_ref: { ledger: "invariant_runs", row_id: positive.run_hash },
    control_run_ref: { ledger: "invariant_runs", row_id: control.run_hash },
    cause_run_ref: { ledger: "offensive_runs", row_id: causeRunId },
    ...(decoy || {}),
  };
}

// Drive the REAL producer to mint a signed offensive cause row that CAPTURED the
// cross-tenant body as its consumable artifact (the wired path). Returns the signed row.
async function mintGenuineWebCause(domain) {
  const result = await idorConfirm(baseArgs(domain), {
    fetch_fn: soundFetchFn(),
    provision: soundProvision(),
  });
  assert.equal(result.offensive_outcome, "exploited_safely", JSON.stringify(result));
  assert.match(result.consumed_artifact_hash, /^[0-9a-f]{64}$/, "producer captured a consumable");
  const rows = readOffensiveRunRecords(domain);
  assert.equal(rows.length, 1);
  return rows[0];
}

// ── END-TO-END GENUINE: producer captures -> consuming EVM violation -> verified_pass ──

test("END-TO-END: the REAL producer-captured credential is consumed by a vulnerable on-chain gate (present->VIOLATE / absent->HOLD) -> verified_pass", () => withTempHome(async () => {
  const domain = "e2e-genuine.example.test";
  setupProducerSession(domain);
  const cause = await mintGenuineWebCause(domain);
  // The producer wrote the .consumed leaf under cause.run_id; the consuming invariant arm
  // binds the SAME consumed_artifact_hash, and the read-time refetch resolves against the
  // producer's genuine leaf.
  writeCrossStackRoutes(domain);
  seedFindingClaim(domain, { findingId: "F-1", surfaceIds: [WEB_SURFACE] });

  // The VULNERABLE gate accepts the captured payload -> positive VIOLATES; the control runs
  // artifact-absent over the SAME tree -> HOLDS. The artifact PRESENCE is the controlled var.
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    causeRunId: cause.run_id, consumedArtifactHash: cause.consumed_artifact_hash,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
  });
  // The genuine gate REJECTS the SHAPE-MATCHED decoy bytes -> the decoy arm HOLDS (the
  // relevance arm). The decoy is minted GENUINELY from the cause (same length + encoding
  // class, random content) via the production mintDecoyCapture path, so the HIGH-2 shape-
  // parity binding passes.
  const decoy = seedMatchingDecoy(domain, positive, { cause });

  const out = await verifyCompositionPath(
    { target_domain: domain, base_url: BASE_URL, path: [crossStackLeaf({ positive, control, causeRunId: cause.run_id, decoy })] },
    BIND_DEPS,
  );
  assert.equal(out.result, "verified_pass", JSON.stringify(out.leaves && out.leaves[0]));
  assert.equal(out.leaves[0].is_cross_stack, true, "web cause + smart_contract effect span distinct families");
  const summary = readCompositionVerifiedSummary(domain);
  assert.ok(summary.verified_cross_stack_path_hashes.includes(out.path_hash), "genuine flow enters the cross-stack-only set");
}));

// ── SAFE CONTRACT: gate rejects the captured payload too -> both arms HOLD -> no mint ──

test("SAFE CONTRACT: a correct gate rejects the captured credential too -> no present->VIOLATE flip (both arms HELD) -> no mint", () => withTempHome(async () => {
  const domain = "e2e-safe.example.test";
  setupProducerSession(domain);
  const cause = await mintGenuineWebCause(domain);
  writeCrossStackRoutes(domain);
  seedFindingClaim(domain, { findingId: "F-1", surfaceIds: [WEB_SURFACE] });

  // A SAFE gate reverts EVEN WITH the captured payload, so consuming the artifact makes NO
  // difference: the consume-arm HOLDS exactly as the artifact-absent control HOLDS. There is
  // no present->VIOLATE flip, so the verifier refuses (the positive arm did not VIOLATE).
  // This IS the safe-contract outcome: no flip means no cross-stack causation.
  const consumeArm = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
    causeRunId: cause.run_id, consumedArtifactHash: cause.consumed_artifact_hash,
  });
  const controlArm = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
  });
  // consumed_artifact_hash is INSIDE run_hash, so the present/absent arms are DISTINCT rows;
  // but both HELD, so there is no present->VIOLATE flip.
  assert.notEqual(consumeArm.run_hash, controlArm.run_hash, "present/absent arms are distinct rows (consumed_artifact_hash is inside run_hash)");
  const decoy = seedMatchingDecoy(domain, consumeArm);
  const out = await verifyCompositionPath(
    { target_domain: domain, base_url: BASE_URL, path: [crossStackLeaf({ positive: consumeArm, control: controlArm, causeRunId: cause.run_id, decoy })] },
    BIND_DEPS,
  );
  assert.equal(out.result, "refuted");
  assert.match(out.leaves[0].reason, /did not VIOLATE/i);
  assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
}));

// ── SILENT-ACTIVATION TRIPWIRE: pure-SC tree-flip + unrelated web cause (named, not consumed) ──

test("SILENT-ACTIVATION: a pure-SC tree-flip with an UNRELATED web cause that was NAMED but never CONSUMED is REFUTED", () => withTempHome(async () => {
  const domain = "e2e-silent.example.test";
  setupProducerSession(domain);
  const cause = await mintGenuineWebCause(domain); // a genuine web exploit on an UNRELATED finding
  writeCrossStackRoutes(domain);
  seedFindingClaim(domain, { findingId: "F-1", surfaceIds: [WEB_SURFACE] });

  // The "positive" violated, naming the cause, but ran CAUSE-FREE (consumed_artifact_hash
  // null) — the web bytes never entered the foundry subprocess. This is a pure-SC tree-flip
  // dressed up with an unrelated web cause: condition (a) refuses (consumed nothing).
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    causeRunId: cause.run_id, consumedArtifactHash: null,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
  });
  const decoy = seedMatchingDecoy(domain, positive, { cause });
  const out = await verifyCompositionPath(
    { target_domain: domain, base_url: BASE_URL, path: [crossStackLeaf({ positive, control, causeRunId: cause.run_id, decoy })] },
    BIND_DEPS,
  );
  assert.equal(out.result, "refuted");
  assert.match(out.leaves[0].reason, /consumed no artifact|never entered the effect run/i);
  assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
}));

// ── RESIDUAL 2: a stdout-only cause is NOT a free consumable ──

// Build + sign a web cause row with NO consumable (consumed_artifact_hash null) but a real
// stdout_hash + an on-disk .stdout leaf. Pre-fix, the runner would inject that stdout body
// as a free consumable; post-fix it is unavailable and the arm runs cause-free.
function appendStdoutOnlyCause(domain, runId, bodyBytes) {
  const stdoutHash = crypto.createHash("sha256").update(bodyBytes).digest("hex");
  const row = {
    version: 1, target_domain: domain, run_id: runId,
    tool_id: "bob_http_idor_confirm",
    target: canonicalizeExploitTarget(`https://${domain}/api/billing/1`),
    offensive_outcome: "exploited_safely", dry_run: false, timed_out: false,
    command_hash: "1".repeat(64), exit_code: 0,
    stdout_hash: stdoutHash, stderr_hash: "c".repeat(64),
    demonstrated_severity: "high", surface_id: WEB_SURFACE,
    consumed_artifact_hash: null, container_isolated: true,
  };
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
  fs.mkdirSync(path.dirname(offensiveRunsJsonlPath(domain)), { recursive: true });
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  // A real stdout capture leaf on disk (what the pre-fix fallback would have injected).
  fs.mkdirSync(offensiveRunsDir(domain), { recursive: true });
  fs.writeFileSync(path.join(offensiveRunsDir(domain), `${runId}.stdout`), bodyBytes);
  return row;
}

// This runner-level case drives runInvariantForFinding, whose assertHarnessPath requires the
// harness under the REAL os.homedir() while the session lives under that same real home.
// (It does not use withTempHome — it cleans the session dir + harness explicitly, mirroring
// cross-stack-consumed-artifact.test.js.) A *.example.test domain passes the public-DNS gate.
test("RESIDUAL 2: a stdout-only cause (no .consumed leaf) is NOT a free consumable — the runner injects nothing (arm runs cause-free)", async () => {
  const suffix = crypto.randomBytes(4).toString("hex");
  const domain = `res2-stdout-runner-${suffix}.example.test`;
  const sessionDirPath = sessionDir(domain);
  const harness = fs.mkdtempSync(path.join(os.homedir(), ".bob-res2-harness-"));
  fs.mkdirSync(path.join(harness, "test"), { recursive: true });
  try {
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
    ensureHandoffSigningKey(domain);
    const body = Buffer.from("{\"raw-http-stdout-body\":true}", "utf8");
    const cause = appendStdoutOnlyCause(domain, "web-stdout-1", body);

    let seenConsumed = "unset";
    const stubFoundry = async (args) => {
      seenConsumed = args.consumed_artifact;
      return { tests: [{ success: false }] };
    };
    await runInvariantForFinding({
      target_domain: domain,
      finding: { finding_id: "F-1", finding_hash: "h", title: "t", vulnerability_class: "signature_validation", description: "d" },
      template_id: "INV-CROSS-STACK-AUTH-REPLAY-001",
      slot_values: { target_address: `0x${"ab".repeat(20)}`, gated_function: "execute", victim_type: "uint256", victim_value: "7" },
      harness_path: harness,
      foundry_run: stubFoundry,
      run_id: "inv-stdout-cause",
      tree_ref: "real",
      checkout_kind: "tree",
      cause_run_id: cause.run_id,
    });
    // The stdout body is NOT injected — the cross-stack consume path is unavailable.
    assert.equal(seenConsumed, null, "a raw stdout body is NOT injected as a free consumable");
    const row = readInvariantRuns({ target_domain: domain }).runs.find((r) => r.run_id === "inv-stdout-cause");
    assert.equal(row.consumed_artifact_hash, null, "the arm runs cause-free (no consumed_artifact_hash bound)");
  } finally {
    if (fs.existsSync(sessionDirPath)) fs.rmSync(sessionDirPath, { recursive: true, force: true });
    fs.rmSync(harness, { recursive: true, force: true });
  }
});

test("RESIDUAL 2: a stdout-only cause is REFUSED by the adjudicator (no consumable), while a genuine .consumed cause mints", () => withTempHome(async () => {
  const domain = "res2-stdout-adj.example.test";
  setupProducerSession(domain);
  // STDOUT-ONLY cause (no consumable) on the routed web surface.
  const body = Buffer.from("{\"raw-http-stdout-body\":true}", "utf8");
  const stdoutCause = appendStdoutOnlyCause(domain, "web-stdout-2", body);
  writeCrossStackRoutes(domain);
  seedFindingClaim(domain, { findingId: "F-1", surfaceIds: [WEB_SURFACE] });

  // The violated arm cannot have consumed the stdout body (the runner never injects it), so
  // a forged claim that it did is refused on condition (c): the cause captured no consumable.
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    causeRunId: stdoutCause.run_id, consumedArtifactHash: stdoutCause.stdout_hash,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
  });
  const decoy = seedMatchingDecoy(domain, positive);
  const out = await verifyCompositionPath(
    { target_domain: domain, base_url: BASE_URL, path: [crossStackLeaf({ positive, control, causeRunId: stdoutCause.run_id, decoy })] },
    BIND_DEPS,
  );
  assert.equal(out.result, "refuted");
  assert.match(out.leaves[0].reason, /cause captured no consumable artifact|nothing to consume/i);
  assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
}));

// ── RESIDUAL 3: indeterminate finding-scope for a reportable cross-stack mint fails closed ──

test("RESIDUAL 3: an INDETERMINATE finding<->surface map (no claim) hard-fails a reportable cross-stack mint, even when every other gate passes", () => withTempHome(async () => {
  const domain = "res3-indeterminate.example.test";
  setupProducerSession(domain);
  const cause = await mintGenuineWebCause(domain);
  writeCrossStackRoutes(domain);
  // NO seedFindingClaim -> the finding<->surface map is indeterminate (no claim for F-1).

  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    causeRunId: cause.run_id, consumedArtifactHash: cause.consumed_artifact_hash,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
  });
  const decoy = seedMatchingDecoy(domain, positive, { cause });
  const out = await verifyCompositionPath(
    { target_domain: domain, base_url: BASE_URL, path: [crossStackLeaf({ positive, control, causeRunId: cause.run_id, decoy })] },
    BIND_DEPS,
  );
  assert.equal(out.result, "refuted");
  assert.match(out.leaves[0].reason, /PROVABLY within the effect finding|indeterminate finding/i);
  assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
}));

test("RESIDUAL 3: a claim that does NOT scope the cause surface (empty/other surface_ids) hard-fails a reportable cross-stack mint", () => withTempHome(async () => {
  const domain = "res3-wrongsurface.example.test";
  setupProducerSession(domain);
  const cause = await mintGenuineWebCause(domain);
  writeCrossStackRoutes(domain);
  // A claim for F-1 exists but scopes a DIFFERENT surface -> the cause surface is provably
  // outside the finding -> refused (the determinate, available && !inFinding branch).
  seedFindingClaim(domain, { findingId: "F-1", surfaceIds: ["surface:unrelated-other"] });

  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    causeRunId: cause.run_id, consumedArtifactHash: cause.consumed_artifact_hash,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
  });
  const decoy = seedMatchingDecoy(domain, positive, { cause });
  const out = await verifyCompositionPath(
    { target_domain: domain, base_url: BASE_URL, path: [crossStackLeaf({ positive, control, causeRunId: cause.run_id, decoy })] },
    BIND_DEPS,
  );
  assert.equal(out.result, "refuted");
  assert.match(out.leaves[0].reason, /PROVABLY within the effect finding|indeterminate finding/i);
  assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
}));
