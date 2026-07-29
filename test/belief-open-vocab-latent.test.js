"use strict";

// Open-vocab belief latent. The curated four variable types are the KNOWN set,
// not the closed universe: an observed fact carrying a mechanism token outside the
// known set mints an `unknown`-typed latent instead of vanishing. Opening the
// vocab does NOT relax the confirm contract — a minted latent's posterior is an
// honest uniform (or elicited) prior, so minting alone never crosses
// RESOLUTION_THRESHOLD; the latent stays merely BELIEVED until an executed
// differential confirms it. When no open-type fact is observed the window is
// byte-identical to the known-four baseline (window_hash unchanged).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendFrontierEvent,
} = require("../mcp/lib/frontier-events.js");
const {
  sessionDir,
} = require("../mcp/lib/paths.js");
const {
  appendEdges,
} = require("../mcp/lib/surface-graph.js");
const {
  buildBeliefWindow,
  makeVariable,
  BELIEF_VARIABLE_TYPES,
  UNKNOWN_VARIABLE_TYPE,
  KNOWN_PLUS_UNKNOWN_VARIABLE_TYPES,
  RESOLUTION_THRESHOLD,
} = require("../mcp/lib/belief/belief-window.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-open-vocab-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
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

// Seed an observation carrying a mechanism token OUTSIDE the curated known set.
function seedOpenMechanismFact(domain, token) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    surface_id: "surface:open-mech",
    payload: {
      observation_kind: "http_route",
      mechanism_type: token,
      endpoint: "/widgets/open",
      method: "POST",
    },
    source: { artifact: "http-audit.jsonl", tool: "bob_http_scan", ref: "open-mech-1" },
  });
}

test("an untyped/open-mechanism fact mints an unknown-typed latent instead of vanishing", () => {
  withTempHome(() => {
    const domain = "open-vocab-mint.example.com";
    ensureSession(domain);
    seedKnownGraph(domain);
    seedOpenMechanismFact(domain, "novel_confused_deputy_v2");

    const window = buildBeliefWindow({ target_domain: domain });
    const open = window.variables.find((v) => v.type === UNKNOWN_VARIABLE_TYPE);
    assert.ok(open, "an open-mechanism fact mints an unknown-typed latent");
    assert.equal(open.scope.mechanism_token, "novel_confused_deputy_v2", "the observed token is preserved on the scope");
    assert.deepEqual(open.states, ["present", "absent", "unknown"], "the open latent uses the generic ternary");
    // The window emits BOTH the known four and the observed-open type.
    assert.deepEqual(window.variable_types.slice(0, 4), [...BELIEF_VARIABLE_TYPES]);
    assert.ok(window.variable_types.includes(UNKNOWN_VARIABLE_TYPE), "variable_types includes the observed-open type");
  });
});

test("a minted open-vocab latent stays merely BELIEVED — minting alone never crosses RESOLUTION_THRESHOLD", () => {
  withTempHome(() => {
    const domain = "open-vocab-believed.example.com";
    ensureSession(domain);
    seedKnownGraph(domain);
    seedOpenMechanismFact(domain, "novel_confused_deputy_v2");

    const window = buildBeliefWindow({ target_domain: domain });
    const open = window.variables.find((v) => v.type === UNKNOWN_VARIABLE_TYPE);
    assert.ok(open);
    assert.equal(open.prior_source, "uniform", "minting yields an honest uniform prior, not a fabricated posterior");
    // No state of a minted open latent crosses the resolution threshold by minting.
    for (const state of open.states) {
      assert.ok(
        open.posterior[state] < RESOLUTION_THRESHOLD,
        `open latent state ${state} (${open.posterior[state]}) must stay below RESOLUTION_THRESHOLD by minting alone`,
      );
    }
  });
});

test("two distinct open mechanisms key to two distinct latents (rank, don't drop)", () => {
  withTempHome(() => {
    const domain = "open-vocab-distinct.example.com";
    ensureSession(domain);
    seedKnownGraph(domain);
    seedOpenMechanismFact(domain, "novel_mechanism_alpha");
    seedOpenMechanismFact(domain, "novel_mechanism_beta");

    const window = buildBeliefWindow({ target_domain: domain });
    const opens = window.variables.filter((v) => v.type === UNKNOWN_VARIABLE_TYPE);
    const tokens = new Set(opens.map((v) => v.scope.mechanism_token));
    assert.ok(tokens.has("novel_mechanism_alpha"), "alpha mechanism is minted");
    assert.ok(tokens.has("novel_mechanism_beta"), "beta mechanism is minted");
    assert.equal(tokens.size, 2, "two distinct mechanisms produce two distinct latents, neither dropped");
  });
});

test("a known-type token is NOT minted as an open latent (already covered by its structural builder)", () => {
  withTempHome(() => {
    const domain = "open-vocab-known-skip.example.com";
    ensureSession(domain);
    seedKnownGraph(domain);
    // A token equal to a known type must NOT spawn a duplicate unknown latent.
    seedOpenMechanismFact(domain, "request_equivalence");

    const window = buildBeliefWindow({ target_domain: domain });
    const opens = window.variables.filter((v) => v.type === UNKNOWN_VARIABLE_TYPE);
    assert.equal(opens.length, 0, "a known token is not re-minted as an open latent");
  });
});

test("flag-off (no open-type fact) window is byte-identical to the known-four baseline (window_hash unchanged)", () => {
  withTempHome(() => {
    const domain = "open-vocab-baseline.example.com";
    ensureSession(domain);
    seedKnownGraph(domain);
    // No open-mechanism fact seeded.
    const window = buildBeliefWindow({ target_domain: domain });
    // variable_types is exactly the curated four (the open path did not fire).
    assert.deepEqual(window.variable_types, [...BELIEF_VARIABLE_TYPES]);
    assert.equal(window.variables.some((v) => v.type === UNKNOWN_VARIABLE_TYPE), false);
    // Determinism across two builds with no open fact.
    const repeat = buildBeliefWindow({ target_domain: domain });
    assert.equal(window.window_hash, repeat.window_hash, "the known-four path is deterministic");
  });
});

test("the known-plus-unknown set is the curated four plus the open catch-all", () => {
  assert.deepEqual(
    KNOWN_PLUS_UNKNOWN_VARIABLE_TYPES,
    [...BELIEF_VARIABLE_TYPES, UNKNOWN_VARIABLE_TYPE],
    "the known-plus-unknown set extends the known four with the open catch-all",
  );
});

test("makeVariable accepts any non-empty string type with a valid shape (open vocab)", () => {
  const variable = makeVariable(
    "some_open_mechanism_type",
    { mechanism_token: "some_open_mechanism_type", source_event_id: "evt-1" },
    { present: 0.333333, absent: 0.333333, unknown: 0.333334 },
    ["frontier_event:evt-1"],
    "uniform",
  );
  assert.equal(variable.type, "some_open_mechanism_type");
  assert.deepEqual(variable.states, ["present", "absent", "unknown"]);
  assert.equal(Object.isFrozen(variable), true);
});

test("makeVariable rejects a malformed shape (empty type, bad states, non-distribution posterior, non-object scope)", () => {
  const goodScope = { mechanism_token: "x" };
  const goodPosterior = { present: 0.5, absent: 0.5 };
  // Empty / non-string type.
  assert.throws(() => makeVariable("", goodScope, goodPosterior, []), /non-empty string/);
  assert.throws(() => makeVariable(null, goodScope, goodPosterior, []), /non-empty string/);
  // Non-object scope.
  assert.throws(() => makeVariable("t", null, goodPosterior, []), /scope must be an object/);
  assert.throws(() => makeVariable("t", ["not", "an", "object"], goodPosterior, []), /scope must be an object/);
  // Posterior not a distribution object.
  assert.throws(() => makeVariable("t", goodScope, null, []), /posterior must be a distribution/);
  // Empty states.
  assert.throws(() => makeVariable("t", goodScope, {}, []), /states must be a non-empty/);
  // A posterior value that is not a number.
  assert.throws(() => makeVariable("t", goodScope, { present: "high", absent: 0.5 }, []), /posterior must be a number/);
});
