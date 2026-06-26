"use strict";

// Cross-stack differential BIND verifier — the second verification kind alongside the
// object-auth guard RE-EXECUTE path. A bind leaf carries positive_run_ref + control_run_ref
// (BOTH invariant_runs: the EFFECT stack) AND a required cause_run_ref (offensive_runs: the
// stack-A CAUSE). It BINDS three ALREADY-EXECUTED MAC-signed rows and confirms a
// CAUSE/EFFECT differential WITHOUT re-executing.
//
// THE CAUSAL MODEL — the CONSUMED ARTIFACT is the controlled variable. A cross-stack vuln
// is causal: a CAUSE on stack A (a web offensive run that exploited_safely) produces an
// EFFECT on stack B (an EVM invariant violation). The non-forgeable witness is the EFFECT
// measured under TWO conditions that differ ONLY in the controlled variable — the PRESENCE
// of the web-captured artifact, ON THE SAME TREE — PLUS the CAUSE bound to the violated arm.
// So the flip arms are BOTH invariant_runs (same test, SAME tree, violated-with-artifact vs
// held-without — the same-test binding ported from verifyInvariantDifferential plus the
// same-tree requirement); the cross-stack-ness is the bound CAUSE resolving on a DIFFERENT
// stack than the effect arms. A different-tree flip is a single-surface invariant
// differential (verifyInvariantDifferential's job), NOT a cross-stack mint.
//
// The non-forgeability spine is asserted leg by leg:
//   * a CORRECT same-execution-context effect flip (violated + held, same test, SAME tree,
//     artifact present-vs-absent) WITH a bound cause that the violated arm NAMES mints
//     verified_pass;
//   * the OLD forgeable shape (web exploited positive + unrelated EVM held control, no
//     cause-link) is REFUSED — the flip arms must both be invariant_runs;
//   * a TREE-ONLY flip (different trees, no artifact differential) is REFUSED as a cross-
//     stack mint (it is a single-surface invariant differential);
//   * two UNRELATED honest signed invariant runs (a violated + a held that are NOT the
//     same test) are REFUSED ("control must be the SAME test on the same tree");
//   * an UNSIGNED invariant arm is REFUSED at the strict-MAC bind even though it is
//     accept-with-warning at the general FV read sites;
//   * a missing / non-demonstrating cause, or a broken causal link, is REFUSED;
//   * open-vocab edge_type is accepted by SHAPE only (any non-empty string);
//   * read-time re-verification excludes a forged bind verified_pass whose source rows
//     were tampered after the mint;
//   * the dormant resolveSynthesizedDifferentialVerdict resolves SYNTH_VERIFIED ONLY when
//     an executed cross-stack flip binds by path_hash.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  verifyCompositionPath,
  readCompositionVerifiedSummary,
  resolveCompositionPathSynthVerdict,
} = require("../mcp/lib/composition-live-verifier.js");
const {
  isBindLeaf,
  isShapeValidEdgeType,
  resolveBoundDifferentialLeaf,
  reverifyCrossStackLeaf,
} = require("../mcp/lib/cross-stack-differential-verifier.js");
const {
  canonicalizeExploitTarget,
  appendCandidateClaim,
} = require("../mcp/lib/claims.js");
const crypto = require("node:crypto");
const {
  offensiveRunsJsonlPath,
  invariantRunsJsonlPath,
  compositionVerifiedJsonlPath,
  offensiveRunsDir,
  surfaceRoutesPath,
} = require("../mcp/lib/paths.js");
const {
  ensureHandoffSigningKey,
} = require("../mcp/lib/handoff-signing-key.js");
const {
  signOffensiveRunRow,
} = require("../mcp/lib/offensive-row-mac.js");
const {
  classifySurfaceCapability,
} = require("../mcp/lib/capability-packs.js");
const {
  seedInvariantRunRow,
} = require("./helpers/invariant-run-seed.js");
const {
  validateToolArguments,
} = require("../mcp/lib/tool-validation.js");

// The audited cross-stack consuming template id — every cross-stack invariant arm must run
// it (the only template whose body binds a captured artifact as the on-chain auth arg).
const CONSUME_TEMPLATE_ID = "INV-CROSS-STACK-AUTH-REPLAY-001";

// The random decoy bytes (distinct CONTENT from the real cause's CONSUMED_BYTES, but SAME
// SHAPE — same byte length, same raw encoding class — so the HIGH-2 shape-parity binding
// passes: a gate can only reject the decoy by validating content, not length/shape). A gate
// that validates the SPECIFIC credential bytes REJECTS these -> the decoy arm HOLDS.
const DECOY_BYTES = Buffer.from("random-decoy-bytes:0xc0ffeeAABB", "utf8");
const DECOY_HASH = crypto.createHash("sha256").update(DECOY_BYTES).digest("hex");
const DECOY_RUN_ID = "web-decoy-1";

// The genuine consumable bytes the stack-A web attack captures and the EVM violation
// consumes. sha256(CONSUMED_BYTES) is what binds the cause offensive row's
// consumed_artifact_hash to the violated invariant arm's consumed_artifact_hash (O-B).
const CONSUMED_BYTES = Buffer.from("forged-relay-payload:0xdeadbeef", "utf8");
const CONSUMED_HASH = crypto.createHash("sha256").update(CONSUMED_BYTES).digest("hex");

// Write a minimal, fully-valid surface-routes.json so the verifier's is_cross_stack
// stack-family check (HIGH-1) can resolve the cause surface's family. classifySurfaceCapability
// produces a route whose capability_pack/evaluator_agent/brief_profile pass
// readSurfaceRoutesStrict. Each entry is { surface_id, surface_type }.
function seedSurfaceRoutes(domain, entries) {
  const routes = entries.map(({ surfaceId, surfaceType }) => {
    const c = classifySurfaceCapability({ id: surfaceId, kind: surfaceType, surface_type: surfaceType });
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
  const doc = { version: 1, route_version: 1, routes };
  fs.mkdirSync(path.dirname(surfaceRoutesPath(domain)), { recursive: true });
  fs.writeFileSync(surfaceRoutesPath(domain), JSON.stringify(doc));
}

// Write the .consumed capture leaf for an offensive cause row so the read-time reverify
// re-fetch (refetchCause) finds bytes that hash to the row's consumed_artifact_hash.
function writeConsumedLeaf(domain, runId, bytes) {
  const dir = offensiveRunsDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${runId}.consumed`), bytes);
}

// Seed the candidate claim that scopes the cause surface to the effect finding so the
// FAIL-CLOSED finding-scope gate resolves available && inFinding. A cross-stack reportable
// mint runs in a repo session where the claim and its surface_ids exist; the gate hard-fails
// closed on an indeterminate map, so a genuine mint test must seed this.
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

// Async-aware temp-HOME: the bind path is async, so the temp tree must survive until the
// returned promise settles (a synchronous finally would rm the tree mid-test).
async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cross-stack-"));
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
const CAUSE_RUN_ID = "web-cause-1";

// Build + sign a single offensive-runs (web) CAUSE row with the SAME per-session key the
// producer uses, so it verifies its MAC like any genuine row.
function buildSignedWebRow(domain, over = {}) {
  const runId = over.run_id || CAUSE_RUN_ID;
  const target = canonicalizeExploitTarget(over.target || `https://${domain}/api/billing/1`);
  const row = {
    version: 1,
    target_domain: domain,
    run_id: runId,
    tool_id: over.tool_id || "bob_http_idor_confirm",
    target,
    offensive_outcome: over.offensive_outcome || "exploited_safely",
    dry_run: over.dry_run === undefined ? false : over.dry_run,
    timed_out: over.timed_out === undefined ? false : over.timed_out,
    command_hash: over.command_hash || hex("a"),
    exit_code: over.exit_code === undefined ? 0 : over.exit_code,
    stdout_hash: over.stdout_hash || hex("b"),
    stderr_hash: over.stderr_hash || hex("c"),
    demonstrated_severity: over.demonstrated_severity || "high",
    surface_id: over.surface_id === undefined ? WEB_SURFACE : over.surface_id,
    // The MAC-covered consumed-artifact binding (O-A): the bytes the on-chain side
    // consumes. Defaults to the genuine capture's hash; pass consumed_artifact_hash:null
    // for a web-only cause that captured no consumable artifact.
    consumed_artifact_hash: over.consumed_artifact_hash === undefined ? CONSUMED_HASH : over.consumed_artifact_hash,
  };
  if (over.container_isolated !== undefined) row.container_isolated = over.container_isolated;
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
  return row;
}

// Build + sign a DECOY offensive-runs row: a real signed capture of RANDOM bytes, marked
// is_decoy:true with a blocked_by_defense outcome (so it is never the positive cause leg).
// The decoy arm consumes these bytes; a gate that validates the SPECIFIC credential bytes
// rejects them -> the decoy arm HOLDS.
function buildSignedDecoyRow(domain, over = {}) {
  const runId = over.run_id || DECOY_RUN_ID;
  const target = canonicalizeExploitTarget(over.target || `https://${domain}/api/billing/1`);
  const row = {
    version: 1,
    target_domain: domain,
    run_id: runId,
    tool_id: over.tool_id || "bob_http_idor_confirm",
    target,
    offensive_outcome: over.offensive_outcome || "blocked_by_defense",
    dry_run: false,
    timed_out: false,
    command_hash: over.command_hash || hex("e"),
    exit_code: 0,
    stdout_hash: over.stdout_hash || hex("b"),
    stderr_hash: over.stderr_hash || hex("c"),
    demonstrated_severity: over.demonstrated_severity || "high",
    surface_id: over.surface_id === undefined ? WEB_SURFACE : over.surface_id,
    consumed_artifact_hash: over.consumed_artifact_hash === undefined ? DECOY_HASH : over.consumed_artifact_hash,
    is_decoy: over.is_decoy === undefined ? true : over.is_decoy,
  };
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
  return row;
}

function appendWebRow(domain, row) {
  fs.mkdirSync(path.dirname(offensiveRunsJsonlPath(domain)), { recursive: true });
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  return row;
}

// Seed a CORRECT cross-stack triple: a signed web CAUSE row that CAPTURED a consumable
// artifact, a VIOLATED invariant positive (on the target tree, naming the cause AND
// CONSUMING its captured artifact — consumed_artifact_hash binds), and a HELD invariant
// control (the SAME test on the SAME tree, artifact-absent). The artifact PRESENCE is the
// controlled variable: the only difference between the arms is the consumed artifact, so
// the violation is provably contingent on it. The effect arm (smart_contract) and the
// cause surface (web, via the seeded route metadata) span DIFFERENT stack families.
function seedCrossStackTriple(domain, {
  findingId = "F-1",
  causeRunId = CAUSE_RUN_ID,
  causeOver = {},
  causeSurfaceType = "web",
  // Whether the three invariant arms ran container_isolated (the isolation-parity gate).
  // A genuine mint needs all three isolated; an isolation-refusal test sets it false.
  containerIsolated = true,
  // Whether the decoy arm HELD (test_passed) — a genuine gate rejects the random decoy.
  // A tautological-gate test sets the decoy arm to test_failed (the decoy VIOLATES).
  decoyArmOutcome = "test_passed",
  decoyHash = DECOY_HASH,
} = {}) {
  const causeSurfaceId = causeOver.surface_id !== undefined ? causeOver.surface_id : WEB_SURFACE;
  // Route the cause surface so the verifier's stack-family check resolves it (HIGH-1).
  seedSurfaceRoutes(domain, [{ surfaceId: causeSurfaceId, surfaceType: causeSurfaceType }]);
  // Scope the cause surface to the effect finding so the fail-closed finding-scope gate
  // resolves available && inFinding (a genuine reportable cross-stack mint runs in a repo
  // session where the claim + surface_ids exist).
  seedFindingClaim(domain, { findingId, surfaceIds: [causeSurfaceId] });
  const cause = appendWebRow(domain, buildSignedWebRow(domain, { run_id: causeRunId, ...causeOver }));
  // The .consumed leaf on disk (the genuine captured bytes) for read-time re-fetch.
  if (cause.consumed_artifact_hash === CONSUMED_HASH) writeConsumedLeaf(domain, causeRunId, CONSUMED_BYTES);
  // The DECOY capture (random bytes, is_decoy:true) + its .consumed leaf.
  const decoyCapture = appendWebRow(domain, buildSignedDecoyRow(domain, { consumed_artifact_hash: decoyHash }));
  if (decoyHash === DECOY_HASH) writeConsumedLeaf(domain, DECOY_RUN_ID, DECOY_BYTES);
  const positive = seedInvariantRunRow(domain, {
    findingId, outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated,
    causeRunId,
    // The violated arm CONSUMED the cause's captured bytes -> consumed_artifact_hash binds.
    consumedArtifactHash: cause.consumed_artifact_hash,
  });
  const control = seedInvariantRunRow(domain, {
    findingId, outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated,
    // The control is the SAME test on the SAME tree, artifact-absent -> consumed_artifact_hash
    // null. The artifact presence is the controlled variable, not the tree.
  });
  // The DECOY ARM: the SAME test on the SAME tree, run with the RANDOM decoy bytes. A genuine
  // gate rejects them -> the decoy arm HOLDS (test_passed). consumed_artifact_hash binds the
  // decoy bytes (distinct from the real cause bytes).
  const decoy = seedInvariantRunRow(domain, {
    findingId, outcome: decoyArmOutcome, treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated,
    causeRunId: DECOY_RUN_ID,
    consumedArtifactHash: decoyHash,
  });
  return { cause, positive, control, decoy, decoyCapture };
}

// Seed a valid decoy capture + decoy arm (HELD) for a finding, returning refs to splice
// into an inline leaf so a refusal test reaches its INTENDED defect rather than refusing
// on the missing decoy. The decoy capture + decoy arm are themselves well-formed.
function seedDecoyRefs(domain, { findingId = "F-1", containerIsolated = true } = {}) {
  const decoyCapture = appendWebRow(domain, buildSignedDecoyRow(domain));
  writeConsumedLeaf(domain, DECOY_RUN_ID, DECOY_BYTES);
  const decoy = seedInvariantRunRow(domain, {
    findingId, outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated,
    causeRunId: DECOY_RUN_ID, consumedArtifactHash: DECOY_HASH,
  });
  return {
    decoy_run_ref: { ledger: "invariant_runs", row_id: decoy.run_hash },
    decoy_cause_run_ref: { ledger: "offensive_runs", row_id: decoyCapture.run_id },
  };
}

// A no-op httpScanFn: a pure bind path never fires HTTP, but verifyCompositionPath
// requires deps.httpScanFn to be a function. If it ever fired, the test would surface it.
function noHttp() {
  throw new Error("bind path must not perform any HTTP fetch");
}

const BIND_DEPS = { httpScanFn: noHttp };
const BASE_URL = "https://stack.example.com";

const { hashCanonicalJson } = require("../mcp/lib/verification-contracts.js");

// A well-shaped open-vocab synthesized observation that passes replayObservationRefusal:
// a discriminating differential (verdict flips against the negative control, distinct
// request/response) with a replay_hash binding the whole decisive tuple.
function shapedObservation(edgeType = "web_seeds_evm_state_corruption") {
  const request = { method: "GET", url: "/api/billing/1", auth_profile: "attacker" };
  const response = { status: 200, body_match: true };
  const verdict = "confirmed";
  const negative_control = {
    request: { method: "GET", url: "/api/billing/1", auth_profile: null },
    response: { status: 403, body_match: false },
    verdict: "denied",
  };
  const replay_hash = hashCanonicalJson({ edge_type: edgeType, request, response, verdict, negative_control });
  return { edge_type: edgeType, request, response, verdict, negative_control, replay_hash };
}

// Build a one-leaf cross-stack bind path (invariant positive + invariant control + web
// cause) and run it through the dispatcher.
function crossStackLeaf({ positive, control, cause, decoy, decoyCapture, edgeType = "web_seeds_evm_state_corruption" }) {
  return {
    edge_type: edgeType,
    positive_run_ref: { ledger: "invariant_runs", row_id: positive.run_hash },
    control_run_ref: { ledger: "invariant_runs", row_id: control.run_hash },
    cause_run_ref: { ledger: "offensive_runs", row_id: cause.run_id },
    decoy_run_ref: { ledger: "invariant_runs", row_id: decoy.run_hash },
    decoy_cause_run_ref: { ledger: "offensive_runs", row_id: decoyCapture.run_id },
  };
}

async function runBindPath(domain, leaf) {
  return verifyCompositionPath(
    { target_domain: domain, base_url: BASE_URL, path: [leaf] },
    BIND_DEPS,
  );
}

test("isBindLeaf / isShapeValidEdgeType — shape predicates", () => {
  assert.equal(isBindLeaf({ positive_run_ref: {}, control_run_ref: {} }), true);
  assert.equal(isBindLeaf({ positive_run_ref: {} }), false);
  assert.equal(isBindLeaf({ primary: {}, control_plan: [] }), false);
  assert.equal(isBindLeaf(null), false);
  assert.equal(isShapeValidEdgeType("any-novel-mechanism"), true);
  assert.equal(isShapeValidEdgeType(""), false);
  assert.equal(isShapeValidEdgeType(42), false);
});

test("a CORRECT cross-stack CAUSE/EFFECT flip (violated+held SAME test SAME tree, artifact present-vs-absent, bound web cause) mints verified_pass keyed by path_hash", () => withTempHome(() => {
  const domain = "xstack-flip.example.com";
  const triple = seedCrossStackTriple(domain, { findingId: "F-1", causeOver: { container_isolated: true } });

  return (async () => {
    const out = await runBindPath(domain, crossStackLeaf(triple));

    assert.equal(out.result, "verified_pass");
    assert.equal(out.verified_leaf_count, 1);
    assert.ok(typeof out.path_hash === "string" && out.path_hash);

    const leaf = out.leaves[0];
    assert.equal(leaf.leaf_status, "verified");
    assert.equal(leaf.bind, true);
    assert.equal(leaf.is_cross_stack, true, "effect arm (EVM) + cause (web) span distinct stacks");
    assert.equal(leaf.surface_refs.length, 2);
    assert.equal(leaf.positive_outcome, "violated");
    assert.equal(leaf.control_outcome, "held");
    assert.equal(leaf.cause_outcome, "exploited_safely");
    // SAME tree on both arms (the artifact presence, not the tree, is the controlled
    // variable), yet distinct run_hash because the outcomes flip (foundry_result differs).
    assert.notEqual(leaf.positive_row_hash, leaf.control_row_hash);
    assert.ok(typeof leaf.execution_key === "string" && leaf.execution_key, "execution-keyed identity");

    // Minted to the audit-graded composition-verified.jsonl, keyed by path_hash, no frontier event.
    const summary = readCompositionVerifiedSummary(domain);
    assert.equal(summary.verified_pass_count, 1);
    assert.ok(summary.verified_path_hashes.includes(out.path_hash), "path_hash enters verified_path_hashes[]");

    // The persisted record carries has_bind_leaf and the bind leaf, with NO frontier event.
    const recs = fs.readFileSync(compositionVerifiedJsonlPath(domain), "utf8")
      .split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
    assert.equal(recs.length, 1);
    assert.equal(recs[0].has_bind_leaf, true);
    assert.equal(recs[0].leaves[0].bind, true);
    assert.equal(recs[0].leaves[0].cause_ref.ledger, "offensive_runs");
  })();
}));

// ── F1 forgery refusals ──────────────────────────────────────────────────────

test("F1: the OLD forgeable shape (web exploited POSITIVE + EVM held CONTROL, no cause-link) is REFUSED — flip arms must both be invariant_runs", () => withTempHome(() => {
  const domain = "xstack-oldforge.example.com";
  // The exact stage-2 forgery: a web offensive positive vs an unrelated EVM held control.
  appendWebRow(domain, buildSignedWebRow(domain, { run_id: "web-pos-1", offensive_outcome: "exploited_safely", command_hash: hex("1") }));
  const evmHeld = seedInvariantRunRow(domain, {
    findingId: "F-9", outcome: "test_passed", treeRef: "fixed", checkoutKind: "upstream_fix", sign: true,
  });
  const decoyRefs = seedDecoyRefs(domain, { findingId: "F-9" });
  return (async () => {
    const out = await runBindPath(domain, {
      edge_type: "mech",
      positive_run_ref: { ledger: "offensive_runs", row_id: "web-pos-1" },
      control_run_ref: { ledger: "invariant_runs", row_id: evmHeld.run_hash },
      cause_run_ref: { ledger: "offensive_runs", row_id: "web-pos-1" },
      ...decoyRefs,
    });
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /flip arms must BOTH be invariant_runs/i);
    assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
  })();
}));

test("F1: two UNRELATED honest signed invariant runs (violated + held NOT the same test) are REFUSED — control must be the SAME test on a different tree", () => withTempHome(() => {
  const domain = "xstack-unrelated.example.com";
  const cause = appendWebRow(domain, buildSignedWebRow(domain, { run_id: CAUSE_RUN_ID, offensive_outcome: "exploited_safely" }));
  // A real IDOR cause + a violated invariant on contract A + a held invariant on an
  // UNRELATED contract/test B. Both honest, both signed — but B is not the SAME test as A.
  const violated = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID,
    contractName: "VaultA", functionName: "testInvariantA", executionContextHash: "ctx-A",
    causeRunId: CAUSE_RUN_ID,
  });
  const heldUnrelated = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID,
    contractName: "VaultB", functionName: "testInvariantB", executionContextHash: "ctx-B",
  });
  const decoyRefs = seedDecoyRefs(domain);
  void cause;
  return (async () => {
    const out = await runBindPath(domain, {
      edge_type: "mech",
      positive_run_ref: { ledger: "invariant_runs", row_id: violated.run_hash },
      control_run_ref: { ledger: "invariant_runs", row_id: heldUnrelated.run_hash },
      cause_run_ref: { ledger: "offensive_runs", row_id: CAUSE_RUN_ID },
      ...decoyRefs,
    });
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /control must be the SAME test on the same tree/i);
    assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
  })();
}));

test("F1: a flip with NO bound cause_run_ref is REFUSED (not cross-stack-attributable)", () => withTempHome(() => {
  const domain = "xstack-nocause.example.com";
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    causeRunId: CAUSE_RUN_ID,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
  });
  return (async () => {
    const out = await runBindPath(domain, {
      edge_type: "mech",
      positive_run_ref: { ledger: "invariant_runs", row_id: positive.run_hash },
      control_run_ref: { ledger: "invariant_runs", row_id: control.run_hash },
      // cause_run_ref omitted
    });
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /requires a cause_run_ref/i);
    assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
  })();
}));

test("F1: a violated arm that does NOT name the bound cause (broken causal link) is REFUSED", () => withTempHome(() => {
  const domain = "xstack-brokenlink.example.com";
  const cause = appendWebRow(domain, buildSignedWebRow(domain, { run_id: CAUSE_RUN_ID, offensive_outcome: "exploited_safely" }));
  // The violated arm names a DIFFERENT cause id than the one bound in the leaf.
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true,
    causeRunId: "some-other-cause",
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true,
  });
  const decoyRefs = seedDecoyRefs(domain);
  void cause;
  return (async () => {
    const out = await runBindPath(domain, {
      edge_type: "mech",
      positive_run_ref: { ledger: "invariant_runs", row_id: positive.run_hash },
      control_run_ref: { ledger: "invariant_runs", row_id: control.run_hash },
      cause_run_ref: { ledger: "offensive_runs", row_id: CAUSE_RUN_ID },
      ...decoyRefs,
    });
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /does not bind this cause run|no causal link/i);
    assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
  })();
}));

test("F1: a non-demonstrating cause (a blocked web run) is REFUSED", () => withTempHome(() => {
  const domain = "xstack-deadcause.example.com";
  appendWebRow(domain, buildSignedWebRow(domain, { run_id: CAUSE_RUN_ID, offensive_outcome: "blocked_by_defense", command_hash: hex("1") }));
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true,
    causeRunId: CAUSE_RUN_ID,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true,
  });
  const decoyRefs = seedDecoyRefs(domain);
  return (async () => {
    const out = await runBindPath(domain, {
      edge_type: "mech",
      positive_run_ref: { ledger: "invariant_runs", row_id: positive.run_hash },
      control_run_ref: { ledger: "invariant_runs", row_id: control.run_hash },
      cause_run_ref: { ledger: "offensive_runs", row_id: CAUSE_RUN_ID },
      ...decoyRefs,
    });
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /cause must be an offensive_runs row that exploited_safely/i);
    assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
  })();
}));

test("F1: a NON-FLIPPING control (control VIOLATED on the same tree — same test, same outcome) is refused as a non-discriminating control", () => withTempHome(() => {
  const domain = "xstack-noflip.example.com";
  const cause = appendWebRow(domain, buildSignedWebRow(domain, { run_id: CAUSE_RUN_ID, offensive_outcome: "exploited_safely", command_hash: hex("1") }));
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true,
    causeRunId: CAUSE_RUN_ID,
  });
  // The "control" is VIOLATED on the SAME tree (same test, same outcome) — it does not flip.
  // Because the artifact presence is OUTSIDE run_hash, a same-tree same-outcome control has
  // the IDENTICAL run_hash as the positive, so it is refused as a non-discriminating control.
  const controlViolated = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true,
  });
  const decoyRefs = seedDecoyRefs(domain);
  void cause;
  return (async () => {
    const out = await runBindPath(domain, {
      edge_type: "mech",
      positive_run_ref: { ledger: "invariant_runs", row_id: positive.run_hash },
      control_run_ref: { ledger: "invariant_runs", row_id: controlViolated.run_hash },
      cause_run_ref: { ledger: "offensive_runs", row_id: CAUSE_RUN_ID },
      ...decoyRefs,
    });
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /run_hash is identical|non-discriminating control|DIFFERENT executed rows|single run/i);
    assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
  })();
}));

test("F1: a NON-DEMONSTRATING positive (the effect arm HELD instead of violated) is refused", () => withTempHome(() => {
  const domain = "xstack-deadpos.example.com";
  const cause = appendWebRow(domain, buildSignedWebRow(domain, { run_id: CAUSE_RUN_ID, offensive_outcome: "exploited_safely", command_hash: hex("1") }));
  // Positive HELD (not violated) — on the target tree, naming the cause.
  const positiveHeld = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true,
    causeRunId: CAUSE_RUN_ID,
  });
  // A distinct (violated) same-test, same-tree control so the flip check is reached: the
  // positive-not-violated refusal must fire, not the same-tree guard.
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true,
  });
  const decoyRefs = seedDecoyRefs(domain);
  void cause;
  return (async () => {
    const out = await runBindPath(domain, {
      edge_type: "mech",
      positive_run_ref: { ledger: "invariant_runs", row_id: positiveHeld.run_hash },
      control_run_ref: { ledger: "invariant_runs", row_id: control.run_hash },
      cause_run_ref: { ledger: "offensive_runs", row_id: CAUSE_RUN_ID },
      ...decoyRefs,
    });
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /positive invariant did not VIOLATE/i);
    assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
  })();
}));

test("a TREE-ONLY flip (positive target / control fixed, NO artifact differential) is REFUSED as a cross-stack mint — it is a single-surface invariant differential", () => withTempHome(() => {
  const domain = "xstack-treeonly.example.com";
  // A genuine web cause + a same-test positive(violated, target)/control(held, FIXED tree)
  // flip, but the differential variable is the TREE, not the consumed artifact. Under the
  // artifact-presence model this is NOT a cross-stack mint — it is verifyInvariantDifferential's
  // single-surface job — so the cross-stack/bind path REFUSES it.
  seedSurfaceRoutes(domain, [{ surfaceId: WEB_SURFACE, surfaceType: "web" }]);
  const cause = appendWebRow(domain, buildSignedWebRow(domain, { run_id: CAUSE_RUN_ID, offensive_outcome: "exploited_safely" }));
  if (cause.consumed_artifact_hash === CONSUMED_HASH) writeConsumedLeaf(domain, CAUSE_RUN_ID, CONSUMED_BYTES);
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true,
    causeRunId: CAUSE_RUN_ID, consumedArtifactHash: cause.consumed_artifact_hash,
  });
  // The control is on a DIFFERENT tree (the OLD cross-stack shape) — the tree is the variable.
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "fixed", checkoutKind: "upstream_fix", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true,
  });
  const decoyRefs = seedDecoyRefs(domain);
  return (async () => {
    const out = await runBindPath(domain, {
      edge_type: "mech",
      positive_run_ref: { ledger: "invariant_runs", row_id: positive.run_hash },
      control_run_ref: { ledger: "invariant_runs", row_id: control.run_hash },
      cause_run_ref: { ledger: "offensive_runs", row_id: CAUSE_RUN_ID },
      ...decoyRefs,
    });
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /SAME tree\/checkout|different-tree flip is a single-surface/i);
    assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
  })();
}));

// ── F2 strict-MAC ────────────────────────────────────────────────────────────

test("F2: an UNSIGNED invariant arm is REFUSED at the strict-MAC bind (accept-with-warning at general read sites does NOT apply here)", () => withTempHome(() => {
  const domain = "xstack-unsigned.example.com";
  appendWebRow(domain, buildSignedWebRow(domain, { run_id: CAUSE_RUN_ID, offensive_outcome: "exploited_safely" }));
  // The VIOLATED positive is UNSIGNED (sign:false) — the exact unsigned-append a same-uid
  // agent could have planted before invariant-runs.jsonl was audit-graded.
  const positiveUnsigned = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: false,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true,
    causeRunId: CAUSE_RUN_ID,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "fixed", checkoutKind: "upstream_fix", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true,
  });
  const decoyRefs = seedDecoyRefs(domain);
  return (async () => {
    const out = await runBindPath(domain, {
      edge_type: "mech",
      positive_run_ref: { ledger: "invariant_runs", row_id: positiveUnsigned.run_hash },
      control_run_ref: { ledger: "invariant_runs", row_id: control.run_hash },
      cause_run_ref: { ledger: "offensive_runs", row_id: CAUSE_RUN_ID },
      ...decoyRefs,
    });
    assert.equal(out.result, "inconclusive");
    assert.match(out.leaves[0].reason, /is required|unsigned row cannot back|bind resolution error/i);
    assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
  })();
}));

test("a MAC-TAMPERED invariant positive (covered field mutated, stale mac kept) is refused (inconclusive)", () => withTempHome(() => {
  const domain = "xstack-mactamper.example.com";
  appendWebRow(domain, buildSignedWebRow(domain, { run_id: CAUSE_RUN_ID, offensive_outcome: "exploited_safely", command_hash: hex("1") }));
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true,
    causeRunId: CAUSE_RUN_ID,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "fixed", checkoutKind: "upstream_fix", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true,
  });
  const decoyRefs = seedDecoyRefs(domain);
  // Mutate a MAC-covered field on the positive row on disk while keeping the stale mac.
  const runsPath = invariantRunsJsonlPath(domain);
  const rows = fs.readFileSync(runsPath, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
  const rewritten = rows.map((r) => {
    if (r.run_hash !== positive.run_hash) return JSON.stringify(r);
    r.cause_run_id = "tampered-cause"; // MAC-covered sibling, stale mac kept
    return JSON.stringify(r);
  });
  fs.writeFileSync(runsPath, `${rewritten.join("\n")}\n`);
  void control;
  return (async () => {
    const out = await runBindPath(domain, {
      edge_type: "mech",
      positive_run_ref: { ledger: "invariant_runs", row_id: positive.run_hash },
      control_run_ref: { ledger: "invariant_runs", row_id: control.run_hash },
      cause_run_ref: { ledger: "offensive_runs", row_id: CAUSE_RUN_ID },
      ...decoyRefs,
    });
    assert.equal(out.result, "inconclusive");
    assert.match(out.leaves[0].reason, /does not verify|bind resolution error/i);
    assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
  })();
}));

test("an UNSUPPORTED ledger string resolves to no entry (inconclusive), never a silent pass", () => withTempHome(() => {
  const domain = "xstack-badledger.example.com";
  const triple = seedCrossStackTriple(domain);
  return (async () => {
    const out = await runBindPath(domain, {
      ...crossStackLeaf(triple),
      cause_run_ref: { ledger: "repo_command_runs", row_id: "anything" },
    });
    assert.equal(out.result, "inconclusive");
    assert.match(out.leaves[0].reason, /ledger must be one of/i);
    assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
  })();
}));

test("a SINGLE run (identical {ledger,row_id} for both effect arms) never mints — refused", () => withTempHome(() => {
  const domain = "xstack-single.example.com";
  const triple = seedCrossStackTriple(domain);
  return (async () => {
    const out = await runBindPath(domain, {
      ...crossStackLeaf(triple),
      // Both effect arms point at the SAME positive run -> a single run never mints.
      control_run_ref: { ledger: "invariant_runs", row_id: triple.positive.run_hash },
    });
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /DIFFERENT executed rows|single run/i);
    assert.equal(readCompositionVerifiedSummary(domain).verified_pass_count, 0);
  })();
}));

test("an EMPTY edge_type fails the open-vocab SHAPE gate (inconclusive); any non-empty string passes", () => withTempHome(() => {
  const domain = "xstack-emptyedge.example.com";
  const triple = seedCrossStackTriple(domain);
  return (async () => {
    // Empty edge_type: shape-refused.
    const refused = await runBindPath(domain, { ...crossStackLeaf(triple), edge_type: "" });
    assert.equal(refused.result, "inconclusive");
    assert.match(refused.leaves[0].reason, /edge_type must be a non-empty string/i);

    // A NOVEL non-empty string (never enumerated anywhere) is accepted by shape and mints.
    const accepted = await runBindPath(domain, { ...crossStackLeaf(triple), edge_type: "a-totally-novel-2026-mechanism-name" });
    assert.equal(accepted.result, "verified_pass");
    assert.equal(accepted.leaves[0].edge_type, "a-totally-novel-2026-mechanism-name");
  })();
}));

// ── F4 execution-keyed identity ──────────────────────────────────────────────

test("F4: one real flip cannot mint 2 DIFFERENT reportable path_hashes (different evidence_ref/edge_type annotations collapse to ONE membership key)", () => withTempHome(() => {
  const domain = "xstack-f4.example.com";
  const triple = seedCrossStackTriple(domain);
  return (async () => {
    // Same executed triple, TWO different annotational spellings (edge_type + evidence_ref).
    const a = await runBindPath(domain, {
      ...crossStackLeaf(triple),
      edge_type: "web_idor_seeds_evm_balance_break",
      evidence_ref: "frontier_event:annotation-A",
    });
    const b = await runBindPath(domain, {
      ...crossStackLeaf(triple),
      edge_type: "totally_different_label_same_execution",
      evidence_ref: "frontier_event:annotation-B",
    });
    assert.equal(a.result, "verified_pass");
    assert.equal(b.result, "verified_pass");

    // F4: both bind to the SAME execution-keyed path_hash (one execution = one claim).
    assert.equal(a.path_hash, b.path_hash, "one execution mints ONE bindable path_hash");

    const summary = readCompositionVerifiedSummary(domain);
    // Two rows were appended, but verified_path_hashes collapses them to ONE membership key.
    assert.equal(summary.verified_pass_count, 2, "two raw verified_pass rows");
    assert.equal(summary.verified_path_hashes.length, 1, "ONE execution-keyed membership entry");
    assert.ok(summary.verified_path_hashes.includes(a.path_hash));
  })();
}));

// ── read-time re-verification ────────────────────────────────────────────────

test("read-time RE-VERIFY excludes a forged bind verified_pass after its source positive row is tampered", () => withTempHome(() => {
  const domain = "xstack-reverify.example.com";
  const triple = seedCrossStackTriple(domain);
  return (async () => {
    const out = await runBindPath(domain, crossStackLeaf(triple));
    assert.equal(out.result, "verified_pass");
    assert.ok(readCompositionVerifiedSummary(domain).verified_path_hashes.includes(out.path_hash));

    // TAMPER the source CAUSE (web) row on disk (mutate a MAC-covered field, keep stale mac).
    const runsPath = offensiveRunsJsonlPath(domain);
    const rows = fs.readFileSync(runsPath, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
    const rewritten = rows.map((r) => {
      if (r.run_id !== CAUSE_RUN_ID) return JSON.stringify(r);
      r.demonstrated_severity = "critical"; // MAC-covered field, stale mac kept
      return JSON.stringify(r);
    });
    fs.writeFileSync(runsPath, `${rewritten.join("\n")}\n`);

    const summaryAfter = readCompositionVerifiedSummary(domain);
    assert.ok(!summaryAfter.verified_path_hashes.includes(out.path_hash), "tampered-source bind row drops out of verified_path_hashes[]");
  })();
}));

test("read-time RE-VERIFY excludes a forged bind verified_pass appended directly to the ledger with refs pointing at nothing", () => withTempHome(() => {
  const domain = "xstack-forgeline.example.com";
  // No source rows exist. An attacker direct-appends a bare bind verified_pass line whose
  // results_hash self-validates but whose run refs resolve to nothing.
  const forged = {
    version: 1,
    target_domain: domain,
    ts: new Date().toISOString(),
    result: "verified_pass",
    offline_result: "bind",
    path_hash: hex("d"),
    leaf_count: 1,
    verified_leaf_count: 1,
    has_bind_leaf: true,
    leaves: [{
      bind: true,
      leaf_status: "verified",
      edge_type: "forged",
      positive_ref: { ledger: "invariant_runs", row_id: hex("a") },
      control_ref: { ledger: "invariant_runs", row_id: hex("b") },
      cause_ref: { ledger: "offensive_runs", row_id: "ghost-cause" },
      positive_row_hash: hex("a"),
      control_row_hash: hex("b"),
      cause_row_hash: hex("c"),
      surface_refs: ["invariant:y", "offensive:x"],
      is_cross_stack: true,
      execution_key: hex("9"),
    }],
  };
  forged.results_hash = hashCanonicalJson(forged);
  fs.mkdirSync(path.dirname(compositionVerifiedJsonlPath(domain)), { recursive: true });
  fs.writeFileSync(compositionVerifiedJsonlPath(domain), `${JSON.stringify(forged)}\n`);

  const summary = readCompositionVerifiedSummary(domain);
  assert.equal(summary.verified_pass_count, 1);
  assert.ok(!summary.verified_path_hashes.includes(hex("d")), "forged bind row's path_hash is NOT bindable");
}));

test("reverifyCrossStackLeaf returns ok:false on a record missing refs / pointing at a single run", () => withTempHome(() => {
  const domain = "xstack-reverify-unit.example.com";
  assert.equal(reverifyCrossStackLeaf(domain, null).ok, false);
  assert.equal(reverifyCrossStackLeaf(domain, {}).ok, false);
  assert.equal(reverifyCrossStackLeaf(domain, {
    positive_ref: { ledger: "invariant_runs", row_id: "x" },
    control_ref: { ledger: "invariant_runs", row_id: "x" },
    cause_ref: { ledger: "offensive_runs", row_id: "c" },
  }).ok, false, "a single run never flips against itself");
  assert.equal(reverifyCrossStackLeaf(domain, {
    positive_ref: { ledger: "invariant_runs", row_id: "x" },
    control_ref: { ledger: "invariant_runs", row_id: "y" },
    // cause_ref missing
  }).ok, false, "a record with no cause_ref cannot re-resolve the causal link");
}));

// ── wired resolver ───────────────────────────────────────────────────────────

test("WIRED resolver: resolveSynthesizedDifferentialVerdict resolves SYNTH_VERIFIED only when an executed cross-stack flip binds by path_hash", () => withTempHome(() => {
  const domain = "xstack-resolver.example.com";
  const triple = seedCrossStackTriple(domain);

  return (async () => {
    const out = await runBindPath(domain, crossStackLeaf(triple));
    assert.equal(out.result, "verified_pass");

    // BOUND: the observation resolves SYNTH_VERIFIED only when bound to this flip's path_hash.
    const bound = resolveCompositionPathSynthVerdict(domain, shapedObservation(), out.path_hash);
    assert.equal(bound.verdict, "verified");
    assert.equal(bound.claim_authority, true);
    assert.equal(bound.bound_path_hash, out.path_hash);

    // CROSS-PATH: a different path_hash (not in verified_path_hashes[]) is binding_mismatch.
    const crossPath = resolveCompositionPathSynthVerdict(domain, shapedObservation(), hex("f"));
    assert.equal(crossPath.verdict, "unverified");
    assert.match(crossPath.reason, /binding_mismatch/i);
    assert.equal(crossPath.claim_authority, false);
  })();
}));

test("WIRED resolver: a DECLARED-WITHOUT-EXECUTION observation (no executed verified_pass at all) resolves SYNTH_UNVERIFIED:not_executed", () => withTempHome(() => {
  const domain = "xstack-declared.example.com";
  const verdict = resolveCompositionPathSynthVerdict(
    domain,
    shapedObservation("declared_only_mechanism"),
    hex("c"),
  );
  assert.equal(verdict.verdict, "unverified");
  assert.match(verdict.reason, /not_executed/i);
  assert.equal(verdict.claim_authority, false);
}));

test("resolveBoundDifferentialLeaf direct: a malformed positive_run_ref (non-object) is inconclusive, not a throw", () => withTempHome(() => {
  const domain = "xstack-malformed.example.com";
  const rec = resolveBoundDifferentialLeaf(
    {
      edge_type: "mech",
      positive_run_ref: "not-an-object",
      control_run_ref: { ledger: "invariant_runs", row_id: "x" },
      cause_run_ref: { ledger: "offensive_runs", row_id: "c" },
    },
    { target_domain: domain },
  );
  assert.ok(rec.leaf_status === "inconclusive" || rec.leaf_status === "refuted");
}));

// ── HIGH-2: decoy SHAPE PARITY against the cause ──────────────────────────────────────────
//
// The decoy must be the SAME SHAPE as the cause (byte length always; encoding class when
// derivable). A shape-MISMATCH decoy (wrong length/class) is REFUSED, so a gate that
// distinguishes the decoy by length/shape can no longer make the decoy arm HOLD without
// validating CONTENT.

// Seed a genuine cross-stack triple whose DECOY capture has a WRONG SHAPE: a custom-length
// decoy capture (signed, is_decoy:true) with its .consumed leaf on disk. The decoy arm
// consumes those bytes and HOLDS. Everything else is the genuine triple.
function seedShapeMismatchDecoy(domain, { findingId = "F-1", decoyBytes } = {}) {
  const decoyHash = crypto.createHash("sha256").update(decoyBytes).digest("hex");
  // Genuine cause + positive + control (the cause is the 31-byte raw CONSUMED_BYTES).
  seedSurfaceRoutes(domain, [{ surfaceId: WEB_SURFACE, surfaceType: "web" }]);
  seedFindingClaim(domain, { findingId, surfaceIds: [WEB_SURFACE] });
  const cause = appendWebRow(domain, buildSignedWebRow(domain, { run_id: CAUSE_RUN_ID }));
  writeConsumedLeaf(domain, CAUSE_RUN_ID, CONSUMED_BYTES);
  const positive = seedInvariantRunRow(domain, {
    findingId, outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true,
    causeRunId: CAUSE_RUN_ID, consumedArtifactHash: cause.consumed_artifact_hash,
  });
  const control = seedInvariantRunRow(domain, {
    findingId, outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true,
  });
  // WRONG-SHAPE decoy capture: distinct random bytes of a DIFFERENT length than the cause.
  const decoyCapture = appendWebRow(domain, buildSignedDecoyRow(domain, { consumed_artifact_hash: decoyHash }));
  writeConsumedLeaf(domain, DECOY_RUN_ID, decoyBytes);
  const decoy = seedInvariantRunRow(domain, {
    findingId, outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true,
    causeRunId: DECOY_RUN_ID, consumedArtifactHash: decoyHash,
  });
  return { cause, positive, control, decoy, decoyCapture };
}

test("HIGH-2: a SHAPE-MISMATCH decoy (32 random bytes against a 31-byte cause) is REFUSED — the decoy must match the cause byte length", () => withTempHome(() => {
  const domain = "xstack-shape-mismatch.example.com";
  // The cause is the 31-byte raw CONSUMED_BYTES; this decoy is a DIFFERENT length (16 bytes).
  const triple = seedShapeMismatchDecoy(domain, { decoyBytes: crypto.randomBytes(16) });
  return (async () => {
    const out = await runBindPath(domain, crossStackLeaf(triple));
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /shape-parity/i);
    assert.match(out.leaves[0].reason, /byte/i);
    // No verified_pass minted.
    const summary = readCompositionVerifiedSummary(domain);
    assert.equal(summary.verified_pass_count, 0);
  })();
}));

test("HIGH-2: a shape-DISTINGUISHING gate now FAILS — with a SHAPE-MATCHED decoy the decoy arm can only HOLD by validating content; a same-length wrong-class decoy is still refused by class", () => withTempHome(() => {
  // A JSON cause; the decoy is the SAME byte length but a RAW (non-JSON) blob. A gate that
  // distinguishes by encoding class (rejects "not JSON-shaped") would make the decoy HOLD
  // WITHOUT validating content — the shape-parity class binding REFUSES that decoy.
  const domain = "xstack-class-mismatch.example.com";
  const causeJson = Buffer.from(JSON.stringify({ t: "AAAAAAAAAAAAAAAAAA", r: "admin" }), "utf8");
  const causeHash = crypto.createHash("sha256").update(causeJson).digest("hex");
  // Same length, but a raw (non-JSON) blob of the same byte length.
  const decoyRaw = crypto.randomBytes(causeJson.length);
  const decoyHash = crypto.createHash("sha256").update(decoyRaw).digest("hex");
  seedSurfaceRoutes(domain, [{ surfaceId: WEB_SURFACE, surfaceType: "web" }]);
  seedFindingClaim(domain, { findingId: "F-1", surfaceIds: [WEB_SURFACE] });
  const cause = appendWebRow(domain, buildSignedWebRow(domain, { run_id: CAUSE_RUN_ID, consumed_artifact_hash: causeHash }));
  writeConsumedLeaf(domain, CAUSE_RUN_ID, causeJson);
  const positive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true, causeRunId: CAUSE_RUN_ID, consumedArtifactHash: causeHash,
  });
  const control = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true,
  });
  const decoyCapture = appendWebRow(domain, buildSignedDecoyRow(domain, { consumed_artifact_hash: decoyHash }));
  writeConsumedLeaf(domain, DECOY_RUN_ID, decoyRaw);
  const decoy = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
    templateId: CONSUME_TEMPLATE_ID, containerIsolated: true, causeRunId: DECOY_RUN_ID, consumedArtifactHash: decoyHash,
  });
  return (async () => {
    const out = await runBindPath(domain, crossStackLeaf({ cause, positive, control, decoy, decoyCapture }));
    assert.equal(out.result, "refuted");
    assert.match(out.leaves[0].reason, /encoding-class|shape-parity/i);
  })();
}));

// ── MEDIUM-3: the cross-stack bind leaf reaches the REAL tool through tool-validation ──────
//
// tool-validation defaults additionalProperties:false + enforces required. Before MEDIUM-3
// the schema declared only positive_run_ref/control_run_ref + required:["evidence_ref"], so
// a cross-stack bind leaf (with cause/decoy refs, no evidence_ref) was REJECTED before the
// handler ran. The schema now declares the three bind refs and makes evidence_ref optional.

test("MEDIUM-3: a cross-stack BIND leaf (cause/decoy refs, NO evidence_ref) PASSES validateToolArguments (the real tool schema accepts it)", () => {
  const args = {
    target_domain: "schema.example.com",
    base_url: "https://schema.example.com",
    path: [{
      edge_type: "web_seeds_evm_state_corruption",
      positive_run_ref: { ledger: "invariant_runs", row_id: "p" },
      control_run_ref: { ledger: "invariant_runs", row_id: "c" },
      cause_run_ref: { ledger: "offensive_runs", row_id: "cause" },
      decoy_run_ref: { ledger: "invariant_runs", row_id: "d" },
      decoy_cause_run_ref: { ledger: "offensive_runs", row_id: "dcap" },
    }],
  };
  // Throws on a schema violation; passing means the bind leaf is now accepted by the real tool.
  assert.doesNotThrow(() => validateToolArguments("bob_verify_composition_path", args));
});

test("MEDIUM-3: an UNKNOWN extra key on a bind leaf is STILL rejected (additionalProperties stays false)", () => {
  const args = {
    target_domain: "schema.example.com",
    base_url: "https://schema.example.com",
    path: [{
      edge_type: "mech",
      positive_run_ref: { ledger: "invariant_runs", row_id: "p" },
      control_run_ref: { ledger: "invariant_runs", row_id: "c" },
      cause_run_ref: { ledger: "offensive_runs", row_id: "cause" },
      decoy_run_ref: { ledger: "invariant_runs", row_id: "d" },
      decoy_cause_run_ref: { ledger: "offensive_runs", row_id: "dcap" },
      totally_unknown_key: "x",
    }],
  };
  assert.throws(() => validateToolArguments("bob_verify_composition_path", args));
});

test("MEDIUM-3: a GUARD leaf still validates (evidence_ref + primary + control_plan) — relaxing required does not break the guard schema", () => {
  const args = {
    target_domain: "schema.example.com",
    base_url: "https://schema.example.com",
    path: [{
      evidence_ref: "frontier_event:e1",
      primary: { method: "GET", url: "/api/billing/1", auth_profile: "attacker" },
      control_plan: [{ control: "no_auth_same_object", method: "GET", url: "/api/billing/1" }],
    }],
  };
  assert.doesNotThrow(() => validateToolArguments("bob_verify_composition_path", args));
});

test("MEDIUM-3 e2e: the genuine 3-arm flow MINTS verified_pass through the REAL tool schema (validateToolArguments + the same handler the tool dispatches)", () => withTempHome(() => {
  const domain = "xstack-e2e-tool.example.com";
  const triple = seedCrossStackTriple(domain, { findingId: "F-1", causeOver: { container_isolated: true } });
  const args = {
    target_domain: domain,
    base_url: BASE_URL,
    path: [crossStackLeaf(triple)],
  };
  return (async () => {
    // 1) The args clear the REAL tool schema (the MEDIUM-3 unblock).
    assert.doesNotThrow(() => validateToolArguments("bob_verify_composition_path", args));
    // 2) The same verifyCompositionPath the handler dispatches mints verified_pass.
    const out = await verifyCompositionPath(
      { target_domain: domain, base_url: BASE_URL, path: args.path },
      BIND_DEPS,
    );
    assert.equal(out.result, "verified_pass");
    assert.equal(out.leaves[0].leaf_status, "verified");
    assert.equal(out.leaves[0].is_cross_stack, true);
    const summary = readCompositionVerifiedSummary(domain);
    assert.equal(summary.verified_pass_count, 1);
  })();
}));
