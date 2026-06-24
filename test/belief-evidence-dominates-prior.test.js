"use strict";

// Evidence dominates the elicited prior on the belief plane.
//
// The cycle-1 keystone (belief-window.js verifiedPosteriorIndex +
// requestEquivalenceVariables) consumes a verified_intervention signal (executed
// reality, written by the outcome-bridge after a live verified_pass) and lets it
// OVERRIDE the latent's prior — elicited or uniform. This test proves the demotion
// is already in force WITHOUT editing belief-window.js: for a request_equivalence
// latent that has BOTH an elicited llm_inferred prior AND a verified_intervention
// signal, the window's posterior reflects the VERIFIED state (~0.9 equivalent), not
// the guess; and with ONLY the elicited prior the posterior IS the elicited prior
// (the pre-evidence state). Executed reality -> belief, never belief -> belief.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendFrontierEvent } = require("../mcp/lib/frontier-events.js");
const { hashCanonicalJson } = require("../mcp/lib/verification-contracts.js");
const {
  buildBeliefWindow,
  requestEquivalenceScope,
  stableId,
} = require("../mcp/lib/belief/belief-window.js");
const { writeBeliefSignalScratch } = require("../mcp/lib/belief/authority.js");
const { VERIFIED_EQUIVALENT_DISTRIBUTION } = require("../mcp/lib/belief/outcome-bridge.js");

const BASE_URL = "https://example.com";

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-evidence-dominates-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// Seed the offline observation a request_equivalence latent binds to. The window
// derives its scope from this payload via the shared requestEquivalenceScope
// normalizer, so the producer/consumer key the SAME variable_id by construction.
function seedRequestObservation(domain, victimUrl = "/api/objects/victim") {
  const request = { method: "GET", url: victimUrl, principal: "attacker" };
  const decisive = { edge_type: "guard", request, response: { status: 200, body: "victim-object" }, verdict: "confirmed" };
  const payload = { ...decisive, replay_hash: hashCanonicalJson(decisive) };
  const event = appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    ts: "2026-06-01T00:00:00.000Z",
    surface_id: "surface:guard",
    payload,
  });
  return { event_id: event.event_id, payload };
}

function variableIdFor(payload, eventId) {
  const scope = requestEquivalenceScope(payload, eventId, BASE_URL);
  return { scope, variable_id: stableId("BV", { type: "request_equivalence", scope }) };
}

function elicitPrior(domain, latentId, distribution) {
  // An agent-elicited belief is advisory: provenance llm_inferred, role prior.
  writeBeliefSignalScratch({
    target_domain: domain,
    kind: "belief_signal",
    source: "test#elicited-prior",
    provenance: "llm_inferred",
    role: "prior",
    artifact_ref: "test://elicited-prior",
    payload: {
      latent_id: latentId,
      type: "request_equivalence",
      distribution,
    },
  });
}

function emitVerified(domain, latentId, scope) {
  writeBeliefSignalScratch({
    target_domain: domain,
    kind: "belief_signal",
    source: "composition-live-verifier",
    provenance: "verified_intervention",
    role: "evidence",
    artifact_ref: "composition_verified:f1c-test",
    payload: {
      latent_id: latentId,
      type: "request_equivalence",
      scope,
      verified_state: "equivalent",
      distribution: { ...VERIFIED_EQUIVALENT_DISTRIBUTION },
      dispatch_authority: false,
    },
  });
}

test("with ONLY an elicited prior the posterior IS the elicited prior (pre-evidence)", () => {
  withTempHome(() => {
    const domain = "f1c-prior-only.example.com";
    const { event_id, payload } = seedRequestObservation(domain);
    const { variable_id } = variableIdFor(payload, event_id);

    const elicited = { equivalent: 0.2, distinct: 0.7, unknown: 0.1 };
    elicitPrior(domain, variable_id, elicited);

    const window = buildBeliefWindow({ target_domain: domain, base_url: BASE_URL });
    const latent = window.variables.find((v) => v.variable_id === variable_id);
    assert.ok(latent, "request_equivalence latent present");
    assert.equal(latent.prior_source, "elicited");
    // The pre-evidence posterior is exactly the elicited guess — the guess is honored
    // only because nothing executed has spoken yet.
    assert.deepEqual({ ...latent.posterior }, elicited);
  });
});

test("with BOTH an elicited prior AND a verified_intervention signal, the posterior reflects the VERIFIED state (evidence dominates)", () => {
  withTempHome(() => {
    const domain = "f1c-evidence-dominates.example.com";
    const { event_id, payload } = seedRequestObservation(domain);
    const { scope, variable_id } = variableIdFor(payload, event_id);

    // The agent elicits a CONFIDENT but WRONG prior (believes the requests are
    // distinct) for the exact latent that executed reality will overturn.
    const elicited = { equivalent: 0.05, distinct: 0.9, unknown: 0.05 };
    elicitPrior(domain, variable_id, elicited);
    // Executed reality: a live verified_pass keyed to the same latent.
    emitVerified(domain, variable_id, scope);

    const window = buildBeliefWindow({ target_domain: domain, base_url: BASE_URL });
    const latent = window.variables.find((v) => v.variable_id === variable_id);
    assert.ok(latent, "request_equivalence latent present — COMPLETENESS, nothing dropped");
    // Evidence dominates: prior_source is the verified intervention, not the elicited
    // guess, and the posterior is the verified distribution (~0.9 equivalent), the
    // OPPOSITE of the confident-but-wrong elicited prior (0.05 equivalent).
    assert.equal(latent.prior_source, "verified_intervention");
    assert.ok(Math.abs(latent.posterior.equivalent - 0.9) < 1e-9, "posterior follows executed reality");
    assert.ok(latent.posterior.equivalent > elicited.equivalent, "verified evidence overrides the guess");
    assert.ok(latent.posterior.distinct < elicited.distinct, "the wrong elicited mass is demoted");
  });
});
