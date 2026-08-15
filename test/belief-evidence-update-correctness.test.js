"use strict";

// Evidence-update CORRECTNESS (the keystone contract, locked as a standing
// invariant).
//
// The one-way executed-reality -> belief edge (outcome-bridge.js +
// composition-live-verifier.js) is the keystone of the advisory belief plane: it is
// the ONLY edge that lets an EXECUTED outcome move belief, and it must be surgical.
// This file locks its contract:
//
//   (1) SHARPENS EXACTLY THE MATCH: a verified_pass sharpens EXACTLY the matching
//       request_equivalence latent and ONLY it — every other window variable is
//       byte-identical to the no-signal run (KEYING + COMPLETENESS).
//   (2) NON-PASS EMITS NOTHING: a refuted/inconclusive path emits ZERO
//       verified_intervention signals.
//   (3) NO LEAKAGE INTO OUTPUT: the verified-intervention evidence never reaches the
//       closure / grade / claim output. (a) The audit-graded composition-verified
//       row carries no belief field, and (b) the closure/grade/claim spine is
//       belief-free at the source — so the sharpened latent cannot bleed into a
//       freeze/grade/claim decision.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const REPO_ROOT = path.join(__dirname, "..");

const { appendFrontierEvent } = require("../mcp/core/frontier/frontier-events.js");
const { hashCanonicalJson } = require("../mcp/core/verification/verification-contracts.js");
const { compositionVerifiedJsonlPath } = require("../mcp/core/io/paths.js");
const {
  verifyCompositionPath,
  RESULT_VERIFIED_PASS,
  RESULT_REFUTED,
  RESULT_INCONCLUSIVE,
} = require("../mcp/core/differential/index.js");
const {
  buildBeliefWindow,
  stableId,
  requestEquivalenceScope,
  SIBLING_RAISE_CAP,
  RESOLUTION_THRESHOLD,
} = require("../mcp/core/belief/belief-window.js");
const {
  queryBeliefSignals,
} = require("../mcp/core/belief/authority.js");
const {
  compareGraphCandidates,
} = require("../mcp/core/waves/graph-scheduler.js");

const DOMAIN = "example.com";
const BASE_URL = "https://example.com";
const VICTIM_BODY = { id: "victim-7", email: "victim@example.com", ssn: "111-22-3333" };
const ATTACKER_BODY = { id: "attacker-1", email: "attacker@example.com" };

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-belief-evidence-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function seedGuardObservation(domain, edgeType = "guard", victimUrl = "/api/objects/victim", ts = "2026-06-01T00:00:00.000Z") {
  const request = { method: "GET", url: victimUrl, principal: "attacker" };
  const response = { status: 200, body: "victim-object" };
  const negative_control = {
    request: { ...request, principal: "owner" },
    response: { status: 403, body: "forbidden" },
    verdict: "denied",
  };
  const decisive = { edge_type: edgeType, request, response, verdict: "confirmed", negative_control };
  const payload = { ...decisive, replay_hash: hashCanonicalJson(decisive) };
  const event = appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    ts,
    surface_id: `surface:${edgeType}`,
    payload,
  });
  return { event_id: event.event_id, payload };
}

function ok(body) { return { status: 200, body }; }
function blocked(status = 401) { return { status, body: { error: "unauthorized" } }; }

function makeFakeHttpScan(overrides = {}) {
  return async function httpScanFn(args) {
    const url = args.url;
    const ap = args.auth_profile || "anon";
    const key = `${ap} ${url}`;
    if (Object.prototype.hasOwnProperty.call(overrides, key)) return overrides[key];
    if (url.includes("/objects/ghost")) return blocked(404);
    if (url.includes("/objects/attacker")) return ap === "attacker" ? ok(ATTACKER_BODY) : blocked();
    if (url.includes("/objects/public")) return blocked();
    if (url.includes("/objects/victim")) return (ap === "victim" || ap === "attacker") ? ok(VICTIM_BODY) : blocked();
    return blocked();
  };
}

function guardLeaf(eventId) {
  return {
    evidence_ref: `frontier_event:${eventId}`,
    edge_id: "e-guard",
    primary: { method: "GET", url: "/api/objects/victim", auth_profile: "attacker" },
    control_plan: [
      { control: "attacker_owned_control", method: "GET", url: "/api/objects/attacker", auth_profile: "attacker" },
      { control: "victim_auth_same_object", method: "GET", url: "/api/objects/victim", auth_profile: "victim" },
      { control: "no_auth_same_object", method: "GET", url: "/api/objects/victim" },
      { control: "public_object_check", method: "GET", url: "/api/objects/public" },
      { control: "nonexistent_object", method: "GET", url: "/api/objects/ghost", auth_profile: "attacker" },
      { control: "stale_session_check", method: "GET", url: "/api/objects/victim", auth_profile: "stale" },
      { control: "cache_nonce_check", method: "GET", url: "/api/objects/victim?cb=1", auth_profile: "attacker" },
    ],
  };
}

function readVerifiedLedger(domain) {
  const filePath = compositionVerifiedJsonlPath(domain);
  if (!fs.existsSync(filePath)) return [];
  return fs.readFileSync(filePath, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
}

function expectedVariableId(observationPayload, eventId, baseUrl = BASE_URL) {
  const scope = requestEquivalenceScope(observationPayload, eventId, baseUrl);
  return { scope, variable_id: stableId("BV", { type: "request_equivalence", scope }) };
}

test("(1) SHARPENS EXACTLY THE MATCH + RAISES BOUNDED SIBLINGS: a verified_pass sharpens exactly the matching latent (~0.9) and bounded-raises its structural siblings; all non-sibling latents byte-identical", async () => {
  await withTempHome(async () => {
    // The verified observation. The guard leaf below keys on THIS event.
    const { event_id, payload } = seedGuardObservation(DOMAIN);
    const { variable_id } = expectedVariableId(payload, event_id);
    // A SIBLING observation: SAME endpoint (/api/objects/victim) + method (GET),
    // DIFFERENT source_event_id (distinct ts) — so it shares the matching latent's
    // structureKey but is a different variable_id. This makes propagation non-vacuous.
    const sib = seedGuardObservation(DOMAIN, "guard", "/api/objects/victim", "2026-06-02T00:00:00.000Z");
    const { variable_id: siblingId } = expectedVariableId(sib.payload, sib.event_id);
    assert.notEqual(siblingId, variable_id, "sibling is a distinct latent (different source_event_id)");

    const before = buildBeliefWindow({ target_domain: DOMAIN, base_url: BASE_URL });
    // NON-VACUITY GUARD: both the match and the sibling EXIST pre-pass at the uniform prior.
    const beforeTarget = before.variables.find((v) => v.variable_id === variable_id);
    const beforeSibling = before.variables.find((v) => v.variable_id === siblingId);
    assert.ok(beforeTarget, "the matching request_equivalence latent exists before the verified_pass");
    assert.ok(beforeSibling, "the sibling request_equivalence latent exists before the verified_pass");
    assert.equal(beforeTarget.prior_source, "uniform", "pre-pass the match is at the uniform prior");
    assert.equal(beforeSibling.prior_source, "uniform", "pre-pass the sibling is at the uniform prior");
    const siblingPriorEquivalent = beforeSibling.posterior.equivalent; // 0.333...

    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(event_id)] },
      { httpScanFn: makeFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_VERIFIED_PASS);

    const after = buildBeliefWindow({ target_domain: DOMAIN, base_url: BASE_URL });
    const beforeById = new Map(before.variables.map((v) => [v.variable_id, v]));
    const afterById = new Map(after.variables.map((v) => [v.variable_id, v]));

    // COMPLETENESS: no latent added or dropped (covered-set-at-fixpoint).
    assert.deepEqual([...afterById.keys()].sort(), [...beforeById.keys()].sort(), "no latent added/dropped");

    const matchStructureKey = JSON.stringify({ endpoint: beforeTarget.scope.endpoint, method: beforeTarget.scope.method });
    let matchedCount = 0;
    let siblingCount = 0;
    for (const [id, varAfter] of afterById) {
      const varBefore = beforeById.get(id);
      const isMatch = id === variable_id;
      const isStructuralSibling = !isMatch
        && varBefore.type === "request_equivalence"
        && JSON.stringify({ endpoint: varBefore.scope.endpoint, method: varBefore.scope.method }) === matchStructureKey;
      if (isMatch) {
        // Bucket A (MATCHING latent): sharpened to ~0.9 via the executed outcome.
        assert.notDeepEqual(varAfter.posterior, varBefore.posterior, "matching latent sharpened");
        assert.equal(varAfter.prior_source, "verified_intervention", "matching latent now sourced from the executed outcome");
        assert.ok(Math.abs(varAfter.posterior.equivalent - 0.9) < 1e-9, "sharpened toward ~0.9 equivalent");
        matchedCount += 1;
      } else if (isStructuralSibling) {
        // Bucket B (SIBLING latents): bounded raise, NEVER resolves, NEVER reaches the match.
        assert.equal(varAfter.prior_source, "sibling_propagated", "sibling carries the sibling_propagated marker (auditably NOT resolved)");
        assert.ok(varAfter.posterior.equivalent > siblingPriorEquivalent, "sibling raised strictly above its uniform prior");
        assert.ok(
          varAfter.posterior.equivalent <= siblingPriorEquivalent + SIBLING_RAISE_CAP + 1e-9,
          "sibling raise is bounded by SIBLING_RAISE_CAP",
        );
        assert.ok(varAfter.posterior.equivalent < 0.9, "sibling never reaches the sharpen (~0.9) — only an executed outcome resolves");
        assert.ok(varAfter.posterior.equivalent < RESOLUTION_THRESHOLD, "sibling never crosses the resolution threshold");
        // Mass-conserving: the raise is removed from the other two states, so the
        // total is preserved at the uniformPrior's toFixed(6) sum (3 * 0.333333),
        // which is byte-identically what the pre-pass distribution summed to.
        const sumAfter = varAfter.posterior.equivalent + varAfter.posterior.distinct + varAfter.posterior.unknown;
        const sumBefore = varBefore.posterior.equivalent + varBefore.posterior.distinct + varBefore.posterior.unknown;
        assert.ok(Math.abs(sumAfter - sumBefore) < 1e-6, "sibling raise is mass-conserving (sum preserved)");
        assert.ok(Math.abs(sumAfter - 1.0) < 2e-6, "sibling distribution stays normalized to ~1.0 (toFixed(6) rounding)");
        siblingCount += 1;
      } else {
        // Bucket C (ALL non-matching, NON-sibling latents): byte-identical to no-signal run.
        assert.deepEqual(varAfter, varBefore, `non-sibling latent ${id} is byte-identical (only the match + its siblings moved)`);
      }
    }
    // EXACTLY ONE verified_intervention-sourced latent, and propagation is non-vacuous.
    assert.equal(matchedCount, 1, "EXACTLY one verified_intervention-sourced latent (the match)");
    assert.ok(siblingCount >= 1, "at least one structural sibling raised (propagation non-vacuous)");
  });
});

test("BOUND: a sibling raise alone cannot cross a priority/severity band (SIBLING_RAISE_CAP < min inter-band gap)", () => {
  // The sibling raise feeds the SAME within-band advisory score path as any belief
  // boost (graph-scheduler beliefRank). The comparator places the belief overlay
  // AFTER the tier+priority compare, so a sibling raise — capped at SIBLING_RAISE_CAP —
  // can only reorder WITHIN a band, never across one. Pin that to the sibling magnitude.
  const priorityRank = new Map([["high", 0], ["medium", 1], ["low", 2]]);
  const high = { node_id: "TG-cell-hi", priority: "high", tier: 1, severity_floor: "low" };
  const low = { node_id: "TG-cell-lo", priority: "low", tier: 1, severity_floor: "low" };
  // The boost a sibling raise can contribute, scaled to the cap (the maximal raise).
  const boostFromSiblingRaise = new Map([["TG-cell-lo", SIBLING_RAISE_CAP]]);
  assert.ok(
    compareGraphCandidates(high, low, priorityRank, boostFromSiblingRaise) < 0,
    "a sibling-raise-magnitude boost on a low-priority cell cannot pull it ahead of a high-priority cell across the band",
  );
  // The minimum inter-band gap as expressed by the priority-rank step is 1 (adjacent
  // ranks differ by exactly 1); SIBLING_RAISE_CAP must be strictly below it so the
  // capped advisory delta can never bridge two bands.
  const minInterBandGap = 1;
  assert.ok(
    SIBLING_RAISE_CAP < minInterBandGap,
    `SIBLING_RAISE_CAP (${SIBLING_RAISE_CAP}) must be strictly less than the minimum inter-band gap (${minInterBandGap})`,
  );
  // And a Tier-1 floor cell precedes a Tier-2 re-probe even with a sibling-raise boost.
  const tier1 = { node_id: "TG-cell-floor", priority: "medium", tier: 1, severity_floor: "low" };
  const tier2 = { node_id: "TG-cell-reprobe", priority: "critical", tier: 2, severity_floor: "critical" };
  assert.ok(
    compareGraphCandidates(tier1, tier2, priorityRank, new Map([["TG-cell-reprobe", SIBLING_RAISE_CAP]])) < 0,
    "Tier-1 breadth precedes Tier-2 depth even under a sibling-raise boost",
  );
});

test("(2) NON-PASS EMITS NOTHING: a refuted path emits ZERO verified_intervention signals", async () => {
  await withTempHome(async () => {
    const { event_id } = seedGuardObservation(DOMAIN);
    const patched = makeFakeHttpScan({ "attacker https://example.com/api/objects/victim": blocked(403) });
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(event_id)] },
      { httpScanFn: patched },
    );
    assert.equal(out.result, RESULT_REFUTED);
    const signals = queryBeliefSignals({ target_domain: DOMAIN, provenance: "verified_intervention", role: "evidence" }).signals;
    assert.equal(signals.length, 0, "refuted => no verified_intervention emitted");
  });
});

test("(2) NON-PASS EMITS NOTHING: an inconclusive (no-template non-guard) path emits ZERO verified_intervention signals", async () => {
  await withTempHome(async () => {
    const { event_id } = seedGuardObservation(DOMAIN, "sink"); // shape-valid sink => inconclusive
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(event_id)] },
      { httpScanFn: makeFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_INCONCLUSIVE);
    const signals = queryBeliefSignals({ target_domain: DOMAIN, provenance: "verified_intervention", role: "evidence" }).signals;
    assert.equal(signals.length, 0, "inconclusive => no verified_intervention emitted");
  });
});

test("(3a) NO LEAKAGE INTO OUTPUT: the audit-graded composition-verified row carries no belief-derived field, and a verified signal WAS emitted (non-vacuous)", async () => {
  await withTempHome(async () => {
    const { event_id } = seedGuardObservation(DOMAIN);
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(event_id)] },
      { httpScanFn: makeFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_VERIFIED_PASS);

    // NON-VACUITY: the verified_intervention edge DID fire (so "no leakage" is meaningful).
    const signals = queryBeliefSignals({ target_domain: DOMAIN, provenance: "verified_intervention", role: "evidence" }).signals;
    assert.equal(signals.length, 1, "non-vacuity: a verified_intervention signal was emitted");
    assert.equal(signals[0].payload.dispatch_authority, false, "the emitted signal is advisory (dispatch_authority false)");

    // The audit-graded output (composition-verified.jsonl row) carries NO belief field:
    // the belief edge is one-way and never feeds back into the graded record.
    const ledger = readVerifiedLedger(DOMAIN);
    assert.equal(ledger.length, 1, "exactly one verified row");
    const row = ledger[0];
    assert.equal(Object.prototype.hasOwnProperty.call(row, "belief"), false, "verified row has no belief field");
    assert.equal(Object.prototype.hasOwnProperty.call(row, "belief_signal"), false, "verified row has no belief_signal field");
    assert.equal(Object.prototype.hasOwnProperty.call(row, "verified_intervention"), false, "verified row carries no verified_intervention back-reference");
  });
});

test("(3b) NO LEAKAGE INTO OUTPUT: the closure/grade/claim spine is belief-FREE at the source (the sharpened latent cannot reach a freeze/grade/claim decision)", () => {
  // The verified_intervention evidence sharpens a belief latent — but closure, grade,
  // and claim minting must NEVER read belief, so the sharpened latent can never bleed
  // into a reportable decision. Assert at the source that none of these modules read
  // verified_intervention OR import the belief/residual machinery.
  const beliefImport = /require\(\s*['"][^'"]*\/belief\/[^'"]*['"]\s*\)|require\(\s*['"][^'"]*residual[^'"]*['"]\s*\)/;
  const SPINE = [
    "mcp/core/waves/scheduler-preconditions.js",
    "mcp/core/session/lifecycle-gates.js",
    "mcp/core/frontier/coverage-closure.js",
    "mcp/core/grade-verdict-store.js",
    "mcp/core/claims/claims.js",
    "mcp/core/claims/claim-freeze.js",
    "mcp/tools/record-candidate-claim.js",
  ];
  for (const rel of SPINE) {
    const src = fs.readFileSync(path.join(REPO_ROOT, rel), "utf8");
    assert.ok(!/verified_intervention/.test(src), `${rel} must NOT read verified_intervention — evidence cannot leak into the graded decision`);
    assert.ok(!beliefImport.test(src), `${rel} must NOT import belief/residual — closure/grade/claim is belief-free`);
  }
});

test("(3b) positive control: the leakage guard BITES a module that DOES consume verified_intervention", () => {
  // Prove the leak guard is non-vacuous: belief-window.js (the legitimate one-way
  // consumer) DOES read verified_intervention, so the same regex must fire — confirming
  // the guard would catch a closure/grade/claim module that grew such a read.
  const src = fs.readFileSync(path.join(REPO_ROOT, "mcp/core/belief/belief-window.js"), "utf8");
  assert.ok(/verified_intervention/.test(src), "belief-window consumes verified_intervention (else this leak guard is vacuous)");
});
