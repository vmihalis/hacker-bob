"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendEdges } = require("../mcp/core/frontier/surface-graph.js");
const { sessionDir } = require("../mcp/core/io/paths.js");
const { rankInterventions } = require("../mcp/core/belief/intervention-calculus.js");
const { buildBeliefWindow } = require("../mcp/core/belief/belief-window.js");
const elicitBeliefTool = require("../mcp/tools/elicit-belief.js");
const queryInterventionCalculusTool = require("../mcp/tools/query-intervention-calculus.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-intervention-calculus-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function seedGraph(domain, effectId) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  appendEdges({
    target_domain: domain,
    edges: [
      {
        source: { type: "principal", id: "principal:attacker" },
        target: { type: "policy_gate", id: "policy_gate:owner" },
        edge_type: "tests_gate",
      },
      {
        source: { type: "policy_gate", id: "policy_gate:owner" },
        target: { type: "effect", id: effectId },
        edge_type: "permits_effect",
      },
    ],
  });
}

test("intervention calculus is deterministic and advisory read-only", () => {
  assert.equal(queryInterventionCalculusTool.mutating, false);
  assert.equal(queryInterventionCalculusTool.network_access, false);
  assert.deepEqual(queryInterventionCalculusTool.session_artifacts_written, []);
  withTempHome(() => {
    const domain = "intervention-calculus-deterministic.example.com";
    seedGraph(domain, "effect:unauth_succeeds_where_auth_blocked:victim");
    const first = rankInterventions({ target_domain: domain, seed: "same" });
    const second = rankInterventions({ target_domain: domain, seed: "same" });
    assert.equal(first.calculus_hash, second.calculus_hash);
    assert.deepEqual(first.ranking, second.ranking);
    assert.equal(first.dispatch_authority, false);
    assert.equal(first.claim_authority, false);
  });
});

test("CB-B2: VoI is the elicited belief's entropy (no hand bonus); it drops when the agent gets confident", () => {
  withTempHome(() => {
    const domain = "intervention-calculus-voi.example.com";
    seedGraph(domain, "effect:unauth_succeeds_where_auth_blocked:victim");

    // uniform belief: every candidate for the latent shares the SAME VoI (no bonus
    // distinguishes principal_fixed_object_swap or public_object_check anymore)
    const before = rankInterventions({ target_domain: domain, seed: "voi", rank_limit: 25 });
    const epBefore = before.ranking.filter((c) => c.variable_id === before.ranking[0].variable_id);
    const voiValues = new Set(epBefore.map((c) => c.expected_information_gain_bits));
    assert.equal(voiValues.size, 1, "no hand bonus: all candidates for a latent share VoI");
    const uniformVoi = before.ranking[0].expected_information_gain_bits;
    assert.ok(uniformVoi > 1.5, "uniform belief over 3 states ~ log2(3)");

    // the host agent elicits a confident belief for that latent -> less to learn -> VoI drops
    const w = buildBeliefWindow({ target_domain: domain });
    const ep = w.variables.find((v) => v.type === "effective_permission");
    elicitBeliefTool.handler({
      target_domain: domain,
      latent_id: ep.variable_id,
      latent_type: "effective_permission",
      states: ["allowed", "blocked", "unknown"],
      distribution: { allowed: 0.8, blocked: 0.15, unknown: 0.05 },
      evidence_refs: ["auth-differential-results.json#req-7"],
      rationale: "attacker-auth reaches the victim object",
    });
    const after = rankInterventions({ target_domain: domain, seed: "voi", rank_limit: 25 });
    const confidentVoi = after.ranking.find((c) => c.variable_id === ep.variable_id).expected_information_gain_bits;
    assert.ok(confidentVoi < uniformVoi, "a confident elicited belief lowers value-of-information");
  });
});

test("CB-B2: ranking is runnable-only -- victim_auth_same_object excluded by default, included when supplied", () => {
  withTempHome(() => {
    const domain = "intervention-calculus-runnable.example.com";
    seedGraph(domain, "effect:unauth_succeeds_where_auth_blocked:victim");

    const def = rankInterventions({ target_domain: domain, seed: "run", rank_limit: 50 });
    assert.ok(!def.ranking.some((c) => c.intervention === "victim_auth_same_object"),
      "victim_auth_same_object needs victim creds; not runnable by default");
    assert.ok(def.runnable_controls.includes("no_auth_same_object"));

    const withVictim = rankInterventions({
      target_domain: domain,
      seed: "run",
      rank_limit: 50,
      runnable_controls: ["principal_fixed_object_swap", "no_auth_same_object", "victim_auth_same_object"],
    });
    assert.ok(withVictim.ranking.some((c) => c.intervention === "victim_auth_same_object"));

    // confounder discrimination is a deterministic map, not a regex
    const publicCheck = def.ranking.find((c) => c.intervention === "public_object_check");
    assert.ok(publicCheck.confounders_discriminated.includes("public_object"));
  });
});
