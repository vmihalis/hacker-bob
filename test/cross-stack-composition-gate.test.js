"use strict";

// Cross-stack composition-path gating — the TEETH on the open-vocab cross-stack
// differential verifier. Two additive gates, both fail-closed, both precise:
//
//   FINALIZE (bob_finalize_node): a Transition node that CLAIMS a cross-stack
//   mechanism (kind === "transition", surface_refs span >= 2 distinct stacks OR
//   a cross_stack_verification declaration) requires a bound cross-stack
//   verified_pass in the audit-graded composition-verified.jsonl before
//   verified -> finalized; an unbound claim fails with cross_stack_mechanism_
//   unverified. An ORDINARY transition (web<->web nesting, no marker) and a
//   HYPOTHESIS node (even cross-stack-shaped) finalize EXACTLY as before.
//
//   GRADE/CLAIMS (crossStackPathGapForReportableFindings): a reportable medium+
//   CROSS-STACK finding (surfaces span >= 2 stacks OR a composition_path ref)
//   must carry a path_hash that is a member of verified_path_hashes[]; an
//   unbound proof caps to advisory (missing[] -> excluded). A single-surface
//   finding is left ENTIRELY to the existing finding-differential gate.
//
// The over-gating negatives are the load-bearing assertions: the gate must NOT
// fire on object-auth/guard composition paths, single-surface findings, web-only
// nesting transitions, or the relational_value_match hypothesis.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  appendFrontierEvent,
} = require("../mcp/core/frontier/frontier-events.js");
const {
  appendTransitionProposal,
  appendHypothesisProposal,
} = require("../mcp/core/waves/task-graph-events.js");
const {
  materializeTaskGraph,
} = require("../mcp/core/waves/task-graph-materializer.js");
const {
  appendContract,
  normalizeContract,
} = require("../mcp/core/contract/index.js");
const {
  appendCandidateClaim,
  crossStackPathGapForReportableFindings,
  normalizeEvidenceReferenceShape,
  canonicalizeExploitTarget,
} = require("../mcp/core/claims/claims.js");
const compositionLiveVerifier = require("../mcp/core/differential/index.js");
const {
  verifyCompositionPath,
} = compositionLiveVerifier;
const {
  offensiveRunsJsonlPath,
  offensiveRunsDir,
  surfaceRoutesPath,
  sessionDir,
} = require("../mcp/core/io/paths.js");
const {
  ensureHandoffSigningKey,
} = require("../mcp/core/ledger-integrity/index.js");
const {
  signOffensiveRunRow,
} = require("../mcp/core/ledger-integrity/index.js");
const {
  seedInvariantRunRow: seedInvariantRunRowRaw,
} = require("./helpers/invariant-run-seed.js");
const {
  CONSUME_TEMPLATE_ID,
  DECOY_HASH,
  DECOY_RUN_ID,
  appendDecoyCapture,
} = require("./helpers/cross-stack-decoy.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/core/frontier/frontier-materialize-debounce.js");
const { TOOL_HANDLERS } = require("../mcp/core/dispatch/tool-registry.js");

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
// return the two leaf refs. The decoy consumes the random decoy bytes and HOLDS (a genuine
// gate rejects them) — the artifact-relevance arm a verified_pass requires.
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

// Async-aware: when fn returns a promise (an async-bodied test), the temp tree
// must survive until it settles — a synchronous finally would rm the HOME mid-test
// and the read-time-reverify of a freshly-minted bind row would resolve against a
// deleted ledger. Mirrors cross-stack-differential-verifier.test.js withTempHome.
async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-xstack-gate-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previousHome;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function hex(char) {
  return char.repeat(64);
}

const KNOWN_TOOL = "bob_http_scan";

// A Contract whose evidence_ref_kind_present witness the mechanical verifier
// satisfies from a single { kind: "http_audit" } evidence ref — so mechanicalVerify
// PASSES and the cross-stack gate (which runs AFTER it) is what we exercise.
function passingContract(extra = {}) {
  return {
    contract_id: "C-xstack",
    severity_floor: "high",
    invariants: [{ id: "I1", statement: "web identity reaches the EVM vault." }],
    witnesses: [{ id: "W1", kind: "evidence_ref_kind_present", predicate: { kind: "http_audit" } }],
    production_paths: [{ description: "web producer", tool_call_pattern: [{ tool: KNOWN_TOOL }] }],
    ...extra,
  };
}

function seedSurfaces(domain, surfaceIds) {
  for (const surfaceId of surfaceIds) {
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-31T00:00:00.000Z",
      surface_id: surfaceId,
      payload: { title: surfaceId },
    });
  }
}

// Write a valid surface-routes.json so safeSurfaceRouteMap resolves each surface's
// surface_type ("web" / "smart_contract"). Both packs are real registry packs.
function writeSurfaceRoutes(domain, routes) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  fs.writeFileSync(surfaceRoutesPath(domain), JSON.stringify({ version: 1, route_version: 1, routes }));
}

const WEB_ROUTE = { surface_id: "surface:web-a", surface_type: "web", capability_pack: "web", capability_pack_version: 1, evaluator_agent: "evaluator-agent", brief_profile: "web" };
const EVM_ROUTE = { surface_id: "surface:evm-b", surface_type: "smart_contract", capability_pack: "smart_contract_evm", capability_pack_version: 1, evaluator_agent: "evaluator-evm-agent", brief_profile: "smart_contract_evm" };
const WEB_ROUTE_B = { surface_id: "surface:web-b", surface_type: "web", capability_pack: "web", capability_pack_version: 1, evaluator_agent: "evaluator-agent", brief_profile: "web" };

function seedContractedTransition(domain, proposalId, fromSurface, toSurface, contract) {
  appendTransitionProposal({
    target_domain: domain,
    ts: "2026-05-31T00:01:00.000Z",
    from_surface: fromSurface,
    to_surface: toSurface,
    kind: "identity_propagation",
    trust_assumption: "web JWT is replayed into the EVM signer",
    proposal_id: proposalId,
  });
  materializeTaskGraph(domain, { write: true });
  const nodeId = `TG-T-${proposalId}`;
  appendContract({ target_domain: domain, node_id: nodeId, contract, ts: "2026-05-31T00:02:00.000Z" });
  materializeTaskGraph(domain, { write: true });
  return nodeId;
}

function runFinalize(domain, nodeId) {
  const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({ target_domain: domain, node_id: nodeId }));
  const agentOutput = {
    tool_invocations: [{ tool: KNOWN_TOOL }],
    evidence_refs: [{ kind: "http_audit", http_audit_id: "h1" }],
  };
  return JSON.parse(TOOL_HANDLERS.bob_finalize_node({
    target_domain: domain,
    node_id: nodeId,
    prep_token: prep.prep_token,
    agent_output: agentOutput,
  }));
}

// Mint a REAL bound cross-stack CAUSE/EFFECT verified_pass and return its path_hash,
// exactly as bob_verify_composition_path does: a web offensive CAUSE (exploited_safely),
// a VIOLATED invariant positive (target tree, naming the cause), and a HELD invariant
// control (same test, fixed tree). Effect arms (EVM) span a different stack than the cause.
async function mintBoundCrossStackVerifiedPass(domain) {
  const causeRunId = "web-cause-1";
  // The genuine consumable bytes the web attack captures and the EVM violation consumes;
  // its sha256 binds the cause offensive row to the violated invariant arm (O-B).
  const consumedBytes = Buffer.from("forged-relay-payload:0xdeadbeef", "utf8");
  const consumedHash = crypto.createHash("sha256").update(consumedBytes).digest("hex");
  // Route the cause surface so the verifier's stack-family check resolves web (HIGH-1).
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  fs.writeFileSync(surfaceRoutesPath(domain), JSON.stringify({ version: 1, route_version: 1, routes: [WEB_ROUTE, EVM_ROUTE] }));
  const row = {
    version: 1,
    target_domain: domain,
    run_id: causeRunId,
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
    surface_id: "surface:web-a",
    consumed_artifact_hash: consumedHash,
    container_isolated: true,
  };
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
  fs.mkdirSync(path.dirname(offensiveRunsJsonlPath(domain)), { recursive: true });
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  // The .consumed leaf on disk for the read-time re-fetch (refetchCause).
  fs.mkdirSync(offensiveRunsDir(domain), { recursive: true });
  fs.writeFileSync(path.join(offensiveRunsDir(domain), `${causeRunId}.consumed`), consumedBytes);
  // Scope the cause surface to the effect finding so the fail-closed finding-scope gate
  // resolves available && inFinding (the cross-stack adjudicator hard-fails closed on an
  // indeterminate finding<->surface map).
  appendCandidateClaim({
    target_domain: domain,
    title: "cross-stack finding F-1",
    summary: "web cause scoped to the effect finding for the fail-closed finding-scope gate",
    severity: "high",
    status: "candidate",
    surface_ids: ["surface:web-a"],
    payload: { finding: { id: "F-1" } },
  });
  const evmPositive = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_failed", treeRef: "target", checkoutKind: "tree", sign: true,
    causeRunId,
    // The violated arm CONSUMED the cause's captured bytes -> consumed_artifact_hash binds.
    consumedArtifactHash: consumedHash,
  });
  const evmControl = seedInvariantRunRow(domain, {
    findingId: "F-1", outcome: "test_passed", treeRef: "target", checkoutKind: "tree", sign: true,
    // Control is the SAME test on the SAME tree, artifact-absent -> consumed_artifact_hash
    // null (the controlled variable is the artifact presence, not the tree).
  });
  // The genuine gate REJECTS random decoy bytes -> the decoy arm HOLDS (the relevance arm).
  const decoy = seedMatchingDecoy(domain, evmPositive);
  const res = await verifyCompositionPath(
    {
      target_domain: domain,
      base_url: `https://${domain}`,
      path: [{
        edge_type: "web_seeds_evm_state_corruption",
        positive_run_ref: { ledger: "invariant_runs", row_id: evmPositive.run_hash },
        control_run_ref: { ledger: "invariant_runs", row_id: evmControl.run_hash },
        cause_run_ref: { ledger: "offensive_runs", row_id: causeRunId },
        ...decoy,
      }],
    },
    { httpScanFn: () => { throw new Error("bind path must not fetch"); } },
  );
  assert.equal(res.result, "verified_pass");
  assert.ok(typeof res.path_hash === "string" && res.path_hash);
  return res.path_hash;
}

// ─── FINALIZE GATE ──────────────────────────────────────────────────────────

test("FINALIZE: a cross-stack-CLAIMED transition with NO bound verified_pass FAILS finalize", () => withTempHome(() => {
  const domain = "xstack-unbound.example.com";
  seedSurfaces(domain, ["surface:web-a", "surface:evm-b"]);
  // Explicit marker: cross_stack_verification.required, declared path_hash not bound.
  const nodeId = seedContractedTransition(domain, "U1", "surface:web-a", "surface:evm-b",
    passingContract({ cross_stack_verification: { required: true, path_hash: hex("a") } }));
  const out = runFinalize(domain, nodeId);
  assert.equal(out.to_state, "failed");
  assert.equal(out.failure_reason.reason, "cross_stack_mechanism_unverified");
  assert.equal(out.failure_reason.declared_path_hash, hex("a"));
  // The mechanical verifier DID pass — this is a second, additive gate (NOT null).
  assert.ok(out.mechanical_verdict && out.mechanical_verdict.satisfied === true);
}));

test("FINALIZE: a cross-stack-CLAIMED transition WITH a bound verified_pass finalizes", () => withTempHome(() => (async () => {
  const domain = "xstack-bound.example.com";
  seedSurfaces(domain, ["surface:web-a", "surface:evm-b"]);
  const pathHash = await mintBoundCrossStackVerifiedPass(domain);
  const nodeId = seedContractedTransition(domain, "B1", "surface:web-a", "surface:evm-b",
    passingContract({ cross_stack_verification: { required: true, path_hash: pathHash } }));
  const out = runFinalize(domain, nodeId);
  assert.equal(out.to_state, "finalized");
  assert.equal(out.failure_reason, undefined);
})()));

test("FINALIZE: the distinct-stack-span heuristic alone triggers the gate (fail-closed when no path_hash declared)", () => withTempHome(() => {
  const domain = "xstack-span.example.com";
  seedSurfaces(domain, ["surface:web-a", "surface:evm-b"]);
  writeSurfaceRoutes(domain, [WEB_ROUTE, EVM_ROUTE]); // web vs smart_contract => distinct stacks
  // NO explicit cross_stack_verification, NO declared path_hash: the heuristic fires,
  // the check cannot bind (declared_path_hash is null) => fail-closed.
  const nodeId = seedContractedTransition(domain, "S1", "surface:web-a", "surface:evm-b", passingContract());
  const out = runFinalize(domain, nodeId);
  assert.equal(out.to_state, "failed");
  assert.equal(out.failure_reason.reason, "cross_stack_mechanism_unverified");
  assert.equal(out.failure_reason.declared_path_hash, null);
}));

// ─── OVER-GATING NEGATIVES (the #1 failure mode) ──────────────────────────────

test("OVER-GATING NEGATIVE: an ordinary web<->web SAME-stack transition (no marker) finalizes EXACTLY as before", () => withTempHome(() => {
  const domain = "xstack-neg-samestack.example.com";
  seedSurfaces(domain, ["surface:web-a", "surface:web-b"]);
  writeSurfaceRoutes(domain, [WEB_ROUTE, WEB_ROUTE_B]); // both web => NOT distinct stacks
  const nodeId = seedContractedTransition(domain, "NG1", "surface:web-a", "surface:web-b", passingContract());
  const out = runFinalize(domain, nodeId);
  assert.equal(out.to_state, "finalized", "a same-stack nesting transition must finalize (gate skipped)");
}));

test("F3 FAIL-CLOSED: a 2-surface transition with NO routes/metadata and NO marker is GATED (cannot prove same-stack)", () => withTempHome(() => {
  const domain = "xstack-neg-nometa.example.com";
  seedSurfaces(domain, ["surface:web-a", "surface:evm-b"]);
  // No surface-routes written => surfaceMetadataById is empty => surfacesProvenSameStack
  // returns false (we cannot PROVE same-stack). A genuinely cross-stack transition with
  // poor route metadata and no marker no longer escapes the gate: it must produce a bound
  // cross-stack verified_pass. With no declared path_hash the check cannot bind => fail-closed.
  const nodeId = seedContractedTransition(domain, "NG2", "surface:web-a", "surface:evm-b", passingContract());
  const out = runFinalize(domain, nodeId);
  assert.equal(out.to_state, "failed", "unknown route metadata must FAIL CLOSED (a multi-surface transition we cannot prove same-stack requires a bound verified_pass)");
  assert.equal(out.failure_reason.reason, "cross_stack_mechanism_unverified");
  assert.equal(out.failure_reason.declared_path_hash, null);
}));

test("OVER-GATING NEGATIVE: a HYPOTHESIS node (kind !== transition) never triggers, even WITH a cross_stack_verification marker", () => withTempHome(() => {
  const domain = "xstack-neg-hyp.example.com";
  seedSurfaces(domain, ["surface:auth"]);
  appendHypothesisProposal({
    target_domain: domain,
    ts: "2026-05-31T00:01:00.000Z",
    hypothesis_statement: "Replay a JWT against the EVM vault.",
    surface_refs: ["surface:auth"],
    proposal_id: "HX",
  });
  materializeTaskGraph(domain, { write: true });
  appendContract({
    target_domain: domain,
    node_id: "TG-H-HX",
    contract: passingContract({ cross_stack_verification: { required: true, path_hash: hex("a") } }),
    ts: "2026-05-31T00:02:00.000Z",
  });
  materializeTaskGraph(domain, { write: true });
  const out = runFinalize(domain, "TG-H-HX");
  assert.equal(out.to_state, "finalized", "a Hypothesis node never triggers the transition-only gate");
}));

// ─── CONTRACT NORMALIZATION (additive marker, byte-identical when absent) ─────

test("CONTRACT: cross_stack_verification absent => contract_hash byte-identical and field omitted", () => {
  const without = normalizeContract(passingContract());
  const withMarker = normalizeContract(passingContract({ cross_stack_verification: { required: true, path_hash: hex("a") } }));
  assert.equal(without.cross_stack_verification, undefined, "absent marker => field omitted");
  // The marker is excluded from the hashable, so adding it leaves the hash byte-identical.
  assert.equal(withMarker.contract_hash, without.contract_hash, "marker is out-of-band; contract_hash unchanged");
  assert.equal(withMarker.cross_stack_verification.required, true);
  assert.equal(withMarker.cross_stack_verification.path_hash, hex("a"));
});

test("CONTRACT: cross_stack_verification rejects a malformed shape", () => {
  assert.throws(() => normalizeContract(passingContract({ cross_stack_verification: { required: "yes" } })), /required must be a boolean/);
  assert.throws(() => normalizeContract(passingContract({ cross_stack_verification: { required: true, path_hash: "short" } })), /path_hash must be a 64-hex/);
});

// ─── EVIDENCE REF SHAPE (composition_path) ───────────────────────────────────

test("EVIDENCE: a composition_path evidence_ref requires a 64-hex path_hash", () => {
  const ok = normalizeEvidenceReferenceShape({ kind: "composition_path", path_hash: hex("d") });
  assert.equal(ok.path_hash, hex("d"));
  assert.throws(() => normalizeEvidenceReferenceShape({ kind: "composition_path", path_hash: "nope" }), /path_hash must be a 64-hex/);
});

// ─── GRADE/CLAIMS GATE ───────────────────────────────────────────────────────

// Seed a reportable cross-stack finding: a claim whose payload.finding.id is the
// finding id, with surface_ids spanning >= 2 distinct stacks (web + smart_contract,
// resolved via surface.observed payload.kind). Optionally cite a composition_path ref.
function seedCrossStackClaim(domain, findingId, { surfaceKinds, explicitSurfaces = null, compositionPathHash = null } = {}) {
  const surfaceIds = [];
  // explicitSurfaces lets a caller name the EXACT surface ids (e.g. the cause surface a
  // bound verified_pass actually rides on), so HIGH-2/MEDIUM-1 reconciliation can resolve
  // the bound path to THIS finding's surfaces. Each entry is { id, kind }.
  if (Array.isArray(explicitSurfaces)) {
    for (const { id, kind } of explicitSurfaces) {
      surfaceIds.push(id);
      appendFrontierEvent({
        target_domain: domain,
        kind: "surface.observed",
        ts: "2026-05-31T00:00:00.000Z",
        surface_id: id,
        payload: { title: id, kind },
      });
    }
  }
  let i = 0;
  for (const kind of (surfaceKinds || [])) {
    const surfaceId = `surface:${kind}-${i}`;
    i += 1;
    surfaceIds.push(surfaceId);
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-31T00:00:00.000Z",
      surface_id: surfaceId,
      payload: { title: surfaceId, kind },
    });
  }
  const evidenceRefs = [{ kind: "finding", finding_id: findingId, content_hash: hex("e") }];
  if (compositionPathHash) {
    evidenceRefs.push({ kind: "composition_path", path_hash: compositionPathHash });
  }
  appendCandidateClaim({
    target_domain: domain,
    title: `cross-stack finding ${findingId}`,
    summary: "web identity reuse corrupts EVM vault state",
    severity: "high",
    surface_ids: surfaceIds,
    evidence_refs: evidenceRefs,
    payload: { finding: { id: findingId, severity: "high", title: "x" } },
  });
}

function gap(domain, findingId, severity = "high") {
  return crossStackPathGapForReportableFindings(domain, {
    reportableFindingIds: new Set([findingId]),
    finalSeverities: new Map([[findingId, severity]]),
  });
}

test("GRADE: a reportable cross-stack finding (distinct stacks) with NO composition_path ref caps to advisory (unbound)", () => withTempHome(() => {
  const domain = "xstack-grade-unbound.example.com";
  seedCrossStackClaim(domain, "F-1", { surfaceKinds: ["web", "smart_contract"] });
  const { missing } = gap(domain, "F-1");
  assert.equal(missing.length, 1);
  assert.equal(missing[0].finding_id, "F-1");
  assert.equal(missing[0].reason, "cross_stack_path_unbound");
}));

test("GRADE: a reportable cross-stack finding with a composition_path ref that is NOT a member of verified_path_hashes caps to advisory (not_verified)", () => withTempHome(() => {
  const domain = "xstack-grade-notverified.example.com";
  seedCrossStackClaim(domain, "F-1", { surfaceKinds: ["web", "smart_contract"], compositionPathHash: hex("a") });
  const { missing } = gap(domain, "F-1");
  assert.equal(missing.length, 1);
  assert.equal(missing[0].reason, "cross_stack_path_not_verified");
}));

test("GRADE: a reportable cross-stack finding with a composition_path ref bound to a real verified_pass is REPORTABLE (no gap)", () => withTempHome(() => (async () => {
  const domain = "xstack-grade-bound.example.com";
  const pathHash = await mintBoundCrossStackVerifiedPass(domain);
  // The claim's surfaces must include the surface the bound verified_pass actually rides
  // on (the cause web surface surface:web-a) so HIGH-2/MEDIUM-1 reconciliation resolves the
  // bound path to THIS finding — a bound verified_pass for finding/surfaces X must not arm
  // a claim that declares unrelated surfaces.
  seedCrossStackClaim(domain, "F-1", {
    explicitSurfaces: [{ id: "surface:web-a", kind: "web" }, { id: "surface:evm-b", kind: "smart_contract" }],
    compositionPathHash: pathHash,
  });
  const { missing } = gap(domain, "F-1");
  assert.deepEqual(missing, [], "a bound cross-stack verified_pass arms the finding");
})()));

test("GRADE: a member path_hash with EMPTY bound surface_refs FAILS CLOSED (no membership-only fallback)", () => withTempHome(() => {
  // The producer guarantees a cross-stack verified_pass always carries surface_refs
  // (adjudicateCrossStackFlip gates verified_pass on a non-null cause surfaceRef), so an
  // empty-refs member can only arise from a corrupted/legacy summary or a producer
  // regression. Inject exactly that via the read-time summary and assert the gate refuses
  // it rather than falling back to membership alone — the HIGH-2 reconciliation must not be
  // silently skipped. Stub the read-time summary the gate consults (re-required per call).
  const domain = "xstack-grade-emptyrefs.example.com";
  const memberHash = hex("a");
  seedCrossStackClaim(domain, "F-1", {
    explicitSurfaces: [{ id: "surface:web-a", kind: "web" }, { id: "surface:evm-b", kind: "smart_contract" }],
    compositionPathHash: memberHash,
  });
  const original = compositionLiveVerifier.readCompositionVerifiedSummary;
  compositionLiveVerifier.readCompositionVerifiedSummary = () => ({
    verified_cross_stack_path_hashes: [memberHash],
    // member, but NO surface_refs entry for it (empty union) — the anomaly.
    verified_cross_stack_path_surface_refs: { [memberHash]: [] },
  });
  try {
    const { missing } = gap(domain, "F-1");
    assert.equal(missing.length, 1);
    assert.equal(missing[0].reason, "cross_stack_path_surface_refs_absent");
  } finally {
    compositionLiveVerifier.readCompositionVerifiedSummary = original;
  }
}));

test("GRADE: a single-stack finding even with a composition_path ref but cited & bound is fine; without a ref it is left to the finding-differential gate (no cross-stack gap)", () => withTempHome(() => {
  const domain = "xstack-grade-singlestack.example.com";
  // Single-surface (one stack), NO composition_path ref => NOT cross-stack => no gap here.
  seedCrossStackClaim(domain, "F-1", { surfaceKinds: ["web"] });
  const { missing } = gap(domain, "F-1");
  assert.deepEqual(missing, [], "a single-surface finding is not cross-stack; left to the finding-differential gate");
}));

test("GRADE: a two-surface SAME-stack finding (web + web) with no composition_path ref is NOT cross-stack (no gap)", () => withTempHome(() => {
  const domain = "xstack-grade-samestack.example.com";
  seedCrossStackClaim(domain, "F-1", { surfaceKinds: ["web", "web"] });
  const { missing } = gap(domain, "F-1");
  assert.deepEqual(missing, [], "two same-stack surfaces do not span distinct stacks; not cross-stack");
}));

test("GRADE: a below-medium cross-stack finding is inert (severity floor)", () => withTempHome(() => {
  const domain = "xstack-grade-lowsev.example.com";
  seedCrossStackClaim(domain, "F-1", { surfaceKinds: ["web", "smart_contract"] });
  const { missing } = gap(domain, "F-1", "low");
  assert.deepEqual(missing, [], "below-medium findings are not gated");
}));
