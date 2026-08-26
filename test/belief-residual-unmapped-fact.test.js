"use strict";

// Closed-world vanish notice. The curated belief vocabulary — even with the
// open-vocab unknown-mechanism catch-all — maps an observed frontier fact to a
// latent only when the fact carries a principal/object pair, a request-equivalence
// signal, or an explicit mechanism token. A fact carrying NONE of those produces
// no latent: it maps to no home and silently vanishes from the modeled set. The
// residual now NOTICES that vanish with an advisory unmapped-fact block (a SEED for
// bob_propose_hypothesis), MINTS nothing, CONFIRMS nothing, and gates nothing.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendFrontierEvent } = require("../mcp/core/frontier/frontier-events.js");
const { sessionDir } = require("../mcp/core/io/paths.js");
const { appendEdges } = require("../mcp/core/frontier/surface-graph.js");
const {
  buildResidualDiagnostic,
  findUnmappedFacts,
  classifyUnmappedBand,
  UNMAPPED_FACT_REASON,
} = require("../mcp/core/belief/residual.js");
const { buildBeliefWindow, RESOLUTION_THRESHOLD } = require("../mcp/core/belief/belief-window.js");
const { queryFrontierTypedFacts } = require("../mcp/core/belief/frontier-facts.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-unmapped-fact-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function ensureSession(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
}

function seedKnownGraph(domain) {
  appendEdges({
    target_domain: domain,
    edges: [
      {
        source: { type: "principal", id: "principal:attacker" },
        target: { type: "policy_gate", id: "policy_gate:object-owner" },
        edge_type: "tests_gate",
        source_artifact: "auth-differential-results.json",
      },
      {
        source: { type: "policy_gate", id: "policy_gate:object-owner" },
        target: { type: "effect", id: "effect:unauth_succeeds_where_auth_blocked:victim-object" },
        edge_type: "permits_effect",
        source_artifact: "auth-differential-results.json",
      },
    ],
  });
}

// A fact carrying NO principal/object, NO request-equivalence signal, and NO
// mechanism token — it maps to no builder, not even the open-vocab catch-all.
function seedHomelessFact(domain, surfaceId) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    surface_id: surfaceId,
    payload: {
      observation_kind: "protocol_drift_observed",
      note: "an unexpected protocol behavior the modeled vocabulary has no shape for",
    },
    source: { artifact: "frontier-events.jsonl", tool: "bob_log_protocol_drift", ref: "homeless-1" },
  });
}

// A fact carrying an open-mechanism token — the open-vocab path DOES build a latent
// for it, so it is modeled (NOT unmapped).
function seedModeledOpenFact(domain, surfaceId, token) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    surface_id: surfaceId,
    payload: {
      observation_kind: "http_route",
      mechanism_type: token,
      endpoint: "/widgets/open",
      method: "POST",
    },
    source: { artifact: "http-audit.jsonl", tool: "bob_http_scan", ref: "open-mech-1" },
  });
}

test("a frontier fact mapping to no latent is noticed as an unmapped (no-home) residual", () => {
  withTempHome(() => {
    const domain = "no-home-notice.example.com";
    ensureSession(domain);
    seedKnownGraph(domain);
    seedHomelessFact(domain, "surface:drift");

    const window = buildBeliefWindow({ target_domain: domain });
    const facts = queryFrontierTypedFacts({ target_domain: domain }).facts;
    const unmapped = findUnmappedFacts(window, facts);

    assert.equal(unmapped.length, 1, "the homeless fact is detected as unmapped");
    assert.equal(unmapped[0].reason, UNMAPPED_FACT_REASON);
    assert.equal(unmapped[0].surface_id, "surface:drift");
    assert.ok(
      typeof unmapped[0].mint_hypothesis_statement === "string" && unmapped[0].mint_hypothesis_statement.length > 0,
      "a free-form statement is provided for the advisory mint",
    );
    assert.deepEqual(unmapped[0].mint_surface_refs, ["surface:drift"], "the surface is carried for the mint grounding");
  });
});

test("a fact the open-vocab path DOES model is NOT reported as unmapped (the receiver exists)", () => {
  withTempHome(() => {
    const domain = "no-home-modeled.example.com";
    ensureSession(domain);
    seedKnownGraph(domain);
    seedModeledOpenFact(domain, "surface:open-mech", "novel_confused_deputy_v2");

    const window = buildBeliefWindow({ target_domain: domain });
    const facts = queryFrontierTypedFacts({ target_domain: domain }).facts;
    const unmapped = findUnmappedFacts(window, facts);

    assert.equal(unmapped.length, 0, "a fact that mints an open-vocab latent has a home and is not flagged");
  });
});

test("the unmapped band is an ordering threshold (strong expectation-violation = high), never a filter", () => {
  // No fact is dropped at any band — every count is surfaced; the band only orders.
  assert.equal(classifyUnmappedBand(0, 10), "none");
  assert.equal(classifyUnmappedBand(1, 10), "low");
  assert.equal(classifyUnmappedBand(2, 5), "medium");
  // Majority of observations have no home → strongest violation → investigate first.
  assert.equal(classifyUnmappedBand(6, 10), "high");
  assert.equal(classifyUnmappedBand(5, 100), "high", "an absolute count also reaches high");
});

test("the unmapped residual block is ADVISORY and NON-GATING (mint != confirm, no authority)", () => {
  withTempHome(() => {
    const domain = "no-home-advisory.example.com";
    ensureSession(domain);
    seedKnownGraph(domain);
    seedHomelessFact(domain, "surface:drift");

    const diagnostic = buildResidualDiagnostic({ target_domain: domain });
    const block = diagnostic.unmapped_facts;
    assert.ok(block, "the diagnostic carries an unmapped_facts block");
    assert.equal(block.reason, UNMAPPED_FACT_REASON);
    assert.equal(block.unmapped_count, 1);
    // No authority of any kind — the seed proves nothing on its own.
    assert.equal(block.claim_authority, false);
    assert.equal(block.dispatch_authority, false);
    assert.equal(block.template_promotion_authority, false);
    assert.equal(block.non_gating, true);
    // The mint reuses the EXISTING free-form advisory path; no new tool.
    assert.equal(block.mint_tool, "bob_propose_hypothesis");
    // The whole diagnostic remains advisory/scratch like the existing body.
    assert.equal(diagnostic.advisory, true);
    assert.equal(diagnostic.scratch, true);
    assert.equal(diagnostic.claim_authority, false);
  });
});

test("a high-band unmapped residual RAISES priority of the no-home facts but drops none", () => {
  withTempHome(() => {
    const domain = "no-home-rank.example.com";
    ensureSession(domain);
    seedKnownGraph(domain);
    // Several homeless facts on distinct surfaces — majority of observations vanish.
    for (let i = 0; i < 5; i += 1) {
      appendFrontierEvent({
        target_domain: domain,
        kind: "observation.recorded",
        surface_id: `surface:drift-${i}`,
        payload: { observation_kind: "protocol_drift_observed", note: `drift ${i}` },
        source: { artifact: "frontier-events.jsonl", tool: "bob_log_protocol_drift", ref: `homeless-${i}` },
      });
    }

    const diagnostic = buildResidualDiagnostic({ target_domain: domain });
    const block = diagnostic.unmapped_facts;
    assert.equal(block.band, "high", "a window where the modeled vocab covers nothing is a strong violation");
    assert.equal(block.dispatch_priority_hint, "investigate_first");
    // RANK != BOUND: every unmapped fact is still present in the surfaced list.
    assert.equal(block.facts.length, 5, "the high band surfaces ALL no-home facts, dropping none");
  });
});

test("minting a no-home seed never crosses the resolution threshold — it stays merely BELIEVED", () => {
  withTempHome(() => {
    const domain = "no-home-believed.example.com";
    ensureSession(domain);
    seedKnownGraph(domain);
    seedHomelessFact(domain, "surface:drift");

    // The seed names a hypothesis to investigate; it asserts no confirmed posterior.
    // The receiver (open-vocab unknown latent) keeps minted belief honest-uniform,
    // strictly below resolution until an executed differential confirms it.
    const diagnostic = buildResidualDiagnostic({ target_domain: domain });
    assert.equal(diagnostic.unmapped_facts.claim_authority, false);
    assert.ok(
      RESOLUTION_THRESHOLD > 0.5,
      "resolution requires evidence well above a uniform prior; a seed alone cannot reach it",
    );
  });
});

test("no-home detection is deterministic across repeated builds", () => {
  withTempHome(() => {
    const domain = "no-home-determinism.example.com";
    ensureSession(domain);
    seedKnownGraph(domain);
    seedHomelessFact(domain, "surface:drift");
    seedModeledOpenFact(domain, "surface:open-mech", "novel_mechanism_alpha");

    const a = buildResidualDiagnostic({ target_domain: domain }).unmapped_facts;
    const b = buildResidualDiagnostic({ target_domain: domain }).unmapped_facts;
    assert.deepEqual(a, b, "the unmapped block is byte-stable across builds");
    assert.equal(a.unmapped_count, 1, "only the homeless fact is flagged; the open-vocab one is modeled");
  });
});
