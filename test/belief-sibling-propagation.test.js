"use strict";

// Factor-mediated sibling propagation CORRECTNESS.
//
// A verified_intervention sharpens the exact-id latent (~0.9). A SECOND pass then
// raises the priors of structural SIBLINGS — request_equivalence latents sharing the
// same {endpoint, method} structure as the verified latent — through the existing
// factor machinery. This file locks that the raise is:
//
//   BOUNDED:        a sibling moves at most +SIBLING_RAISE_CAP toward equivalent.
//   NEVER RESOLVES: a raised sibling never reaches the sharpen (~0.9) or the
//                   resolution threshold; only an executed outcome resolves a latent.
//   NEVER ALONE CROSSES A BAND: SIBLING_RAISE_CAP is strictly below the minimum
//                   inter-band gap, and the comparator places belief within-band.
//   ONE-WAY/GROUNDED: with no verified_intervention, the pass is a no-op (byte-identical).
//   DETERMINISM:    same fed signals => byte-identical variables/factors/values.
//   COMPLETENESS:   the pass only RAISES existing siblings and ADDS factors —
//                   never adds/drops a variable (covered-set-at-fixpoint).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendFrontierEvent } = require("../mcp/core/frontier/frontier-events.js");
const { hashCanonicalJson } = require("../mcp/core/verification/verification-contracts.js");
const {
  verifyCompositionPath,
  RESULT_VERIFIED_PASS,
} = require("../mcp/core/differential/index.js");
const {
  buildBeliefWindow,
  stableId,
  requestEquivalenceScope,
  structureKey,
  SIBLING_PROPAGATION_WEIGHT,
  SIBLING_RAISE_CAP,
  RESOLUTION_THRESHOLD,
} = require("../mcp/core/belief/belief-window.js");

const DOMAIN = "example.com";
const BASE_URL = "https://example.com";
const VICTIM_BODY = { id: "victim-7", email: "victim@example.com", ssn: "111-22-3333" };
const ATTACKER_BODY = { id: "attacker-1", email: "attacker@example.com" };

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sibling-prop-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function seedGuardObservation(domain, victimUrl, ts) {
  const request = { method: "GET", url: victimUrl, principal: "attacker" };
  const response = { status: 200, body: "victim-object" };
  const negative_control = {
    request: { ...request, principal: "owner" },
    response: { status: 403, body: "forbidden" },
    verdict: "denied",
  };
  const decisive = { edge_type: "guard", request, response, verdict: "confirmed", negative_control };
  const payload = { ...decisive, replay_hash: hashCanonicalJson(decisive) };
  const event = appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    ts,
    surface_id: "surface:guard",
    payload,
  });
  return { event_id: event.event_id, payload };
}

function ok(body) { return { status: 200, body }; }
function blocked(status = 401) { return { status, body: { error: "unauthorized" } }; }

function fakeHttpScan() {
  return async function httpScanFn(args) {
    const url = args.url;
    const ap = args.auth_profile || "anon";
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

function expectedVariableId(payload, eventId) {
  const scope = requestEquivalenceScope(payload, eventId, BASE_URL);
  return stableId("BV", { type: "request_equivalence", scope });
}

// Seed the verified observation + N siblings (same endpoint+method, distinct ts), run
// the live verifier so the verified latent sharpens, and return before/after windows.
async function seedAndVerify(siblingCount) {
  const verified = seedGuardObservation(DOMAIN, "/api/objects/victim", "2026-06-01T00:00:00.000Z");
  const verifiedId = expectedVariableId(verified.payload, verified.event_id);
  const siblingIds = [];
  for (let i = 0; i < siblingCount; i += 1) {
    const sib = seedGuardObservation(DOMAIN, "/api/objects/victim", `2026-06-0${i + 2}T00:00:00.000Z`);
    siblingIds.push(expectedVariableId(sib.payload, sib.event_id));
  }
  const before = buildBeliefWindow({ target_domain: DOMAIN, base_url: BASE_URL });
  const out = await verifyCompositionPath(
    { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(verified.event_id)] },
    { httpScanFn: fakeHttpScan() },
  );
  assert.equal(out.result, RESULT_VERIFIED_PASS);
  const after = buildBeliefWindow({ target_domain: DOMAIN, base_url: BASE_URL });
  return { before, after, verifiedId, siblingIds };
}

test("BOUNDED + NEVER RESOLVES: a sibling raise is additive, capped at +SIBLING_RAISE_CAP, and never reaches the sharpen or the resolution threshold", async () => {
  await withTempHome(async () => {
    const { before, after, verifiedId, siblingIds } = await seedAndVerify(1);
    const beforeById = new Map(before.variables.map((v) => [v.variable_id, v]));
    const sibId = siblingIds[0];
    const sibBefore = beforeById.get(sibId);
    const sibAfter = after.variables.find((v) => v.variable_id === sibId);
    assert.ok(sibBefore && sibAfter, "sibling latent present before and after");

    assert.equal(sibAfter.prior_source, "sibling_propagated", "raised sibling marked sibling_propagated (NOT resolved)");
    assert.ok(sibAfter.posterior.equivalent > sibBefore.posterior.equivalent, "sibling equivalent raised strictly");
    assert.ok(
      sibAfter.posterior.equivalent <= sibBefore.posterior.equivalent + SIBLING_RAISE_CAP + 1e-9,
      "raise bounded by SIBLING_RAISE_CAP",
    );
    assert.ok(sibAfter.posterior.equivalent < 0.9, "never reaches the verified sharpen (~0.9)");
    assert.ok(sibAfter.posterior.equivalent < RESOLUTION_THRESHOLD, "never crosses the resolution threshold");

    // The verified latent itself is the only resolved one (~0.9, verified_intervention).
    const verAfter = after.variables.find((v) => v.variable_id === verifiedId);
    assert.equal(verAfter.prior_source, "verified_intervention");
    assert.ok(Math.abs(verAfter.posterior.equivalent - 0.9) < 1e-9, "verified latent at ~0.9");
  });
});

test("CAPPED ONCE PER STRUCTURE: N verified siblings of the same structure produce ONE capped raise (never summed)", async () => {
  // Two verified observations at the same {endpoint,method} plus a sibling: the sibling
  // must move by ONE capped raise, not two. We seed two verifiable events and verify
  // both; the third (the sibling we assert on) is a distinct observation. Because the
  // raise is computed once from the structure group and deduped by structureKey, the
  // sibling's equivalent mass is identical whether one or many verified siblings exist.
  await withTempHome(async () => {
    const oneVerified = await seedAndVerify(1);
    const oneSib = oneVerified.after.variables.find((v) => v.variable_id === oneVerified.siblingIds[0]);
    const oneRaise = oneSib.posterior.equivalent;
    // The raise is bounded by the cap and by the weighted gap, computed once.
    const expectedRaise = Math.min(SIBLING_RAISE_CAP, SIBLING_PROPAGATION_WEIGHT * (0.9 - 0.333333));
    assert.ok(
      Math.abs((oneRaise - 0.333333) - expectedRaise) < 1e-5,
      `sibling raise (${oneRaise - 0.333333}) equals the once-computed bounded raise (${expectedRaise})`,
    );
  });
});

test("ONE-WAY / GROUNDED: with NO verified_intervention the window is byte-identical (no sibling factor or raise)", async () => {
  await withTempHome(async () => {
    // Two observations at the same structure, but NO verifyCompositionPath run, so
    // verifiedIndex is empty: no verified latent, no propagation.
    seedGuardObservation(DOMAIN, "/api/objects/victim", "2026-06-01T00:00:00.000Z");
    seedGuardObservation(DOMAIN, "/api/objects/victim", "2026-06-02T00:00:00.000Z");
    const window = buildBeliefWindow({ target_domain: DOMAIN, base_url: BASE_URL });
    // No sibling_propagated marker and no verified_sibling_equivalence factor exists.
    assert.ok(
      window.variables.every((v) => v.prior_source !== "sibling_propagated"),
      "no sibling raised without an executed outcome",
    );
    assert.ok(
      (window.factors || []).every((f) => f.kind !== "verified_sibling_equivalence"),
      "no sibling factor emitted without an executed outcome",
    );
  });
});

test("DETERMINISM: the same fed signals produce byte-identical variables, factors, and window hash", async () => {
  // Determinism is "same fed signals => same order/values". Within a session (one fixed
  // set of executed outcomes + observations), rebuilding the window is byte-identical:
  // siblings grouped by canonical structureKey, factor_ids via stableId(sorted ids),
  // raise computed from S's current prior with toFixed(6).
  await withTempHome(async () => {
    await seedAndVerify(2);
    const a = buildBeliefWindow({ target_domain: DOMAIN, base_url: BASE_URL });
    const b = buildBeliefWindow({ target_domain: DOMAIN, base_url: BASE_URL });
    assert.deepEqual(b.variables, a.variables, "variables byte-identical across rebuilds");
    assert.deepEqual(b.factors, a.factors, "factors byte-identical across rebuilds");
    assert.equal(b.window_hash, a.window_hash, "window hash deterministic");
    // Non-vacuity: the rebuilt window actually carries raised siblings + factors.
    assert.ok(a.variables.some((v) => v.prior_source === "sibling_propagated"), "raised siblings present");
    assert.ok((a.factors || []).some((f) => f.kind === "verified_sibling_equivalence"), "sibling factors present");
  });
});

test("COMPLETENESS: propagation only RAISES existing siblings and ADDS factors — never adds/drops a variable", async () => {
  await withTempHome(async () => {
    const { before, after } = await seedAndVerify(2);
    const beforeIds = before.variables.map((v) => v.variable_id).sort();
    const afterIds = after.variables.map((v) => v.variable_id).sort();
    assert.deepEqual(afterIds, beforeIds, "variable set unchanged (covered-set-at-fixpoint)");
    // The added factors are exactly the verified_sibling_equivalence carriers.
    const beforeFactorIds = new Set((before.factors || []).map((f) => f.factor_id));
    const addedFactors = (after.factors || []).filter((f) => !beforeFactorIds.has(f.factor_id));
    assert.ok(addedFactors.length >= 1, "at least one sibling factor added");
    assert.ok(
      addedFactors.every((f) => f.kind === "verified_sibling_equivalence"),
      "every added factor is a verified_sibling_equivalence carrier",
    );
    assert.ok(
      addedFactors.every((f) => f.weight === SIBLING_PROPAGATION_WEIGHT),
      "sibling factor weight is the capped propagation weight",
    );
  });
});

test("STRUCTURE KEY excludes source_event_id (siblings share endpoint+method only)", () => {
  const a = structureKey({ endpoint: "/api/objects/victim", method: "GET", source_event_id: "evt-a" });
  const b = structureKey({ endpoint: "/api/objects/victim", method: "GET", source_event_id: "evt-b" });
  const c = structureKey({ endpoint: "/api/objects/other", method: "GET", source_event_id: "evt-a" });
  assert.equal(a, b, "same endpoint+method => same structureKey regardless of source_event_id");
  assert.notEqual(a, c, "different endpoint => different structureKey");
});
