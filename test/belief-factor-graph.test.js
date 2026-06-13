"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendEdges } = require("../mcp/lib/surface-graph.js");
const { sessionDir } = require("../mcp/lib/paths.js");
const { buildBeliefWindow } = require("../mcp/lib/belief/belief-window.js");
const {
  buildFactorGraphSample,
  readBeliefSamples,
  runBeliefSampler,
} = require("../mcp/lib/belief/factor-graph.js");
const runBeliefSamplerTool = require("../mcp/lib/tools/run-belief-sampler.js");
const elicitBeliefTool = require("../mcp/lib/tools/elicit-belief.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-factor-graph-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function seedGraph(domain) {
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
        target: { type: "effect", id: "effect:unauth_succeeds_where_auth_blocked:victim" },
        edge_type: "permits_effect",
      },
    ],
  });
}

test("factor-graph sampler is deterministic for identical seed and window", () => {
  withTempHome(() => {
    const domain = "factor-graph-deterministic.example.com";
    seedGraph(domain);
    const window = buildBeliefWindow({ target_domain: domain });
    const first = buildFactorGraphSample({ window, seed: "seed-1", sample_count: 128 });
    const second = buildFactorGraphSample({ window, seed: "seed-1", sample_count: 128 });
    assert.equal(first.sample_hash, second.sample_hash);
    assert.deepEqual(first.marginals, second.marginals);
    assert.equal(first.window_hash, window.window_hash);
    assert.equal(first.advisory, true);
    assert.equal(first.claim_authority, false);
    assert.equal(first.dispatch_authority, false);
  });
});

test("factor-graph sampler ranks leaves, interventions, and template compositions advisory-only", () => {
  withTempHome(() => {
    const domain = "factor-graph-ranking.example.com";
    seedGraph(domain);
    const sample = buildFactorGraphSample({
      target_domain: domain,
      seed: "rank",
      sample_count: 128,
      rank_limit: 5,
    });
    assert.ok(sample.frontier_leaf_ranking.length > 0);
    assert.ok(sample.intervention_ranking.length > 0);
    assert.ok(sample.composition_search.length > 0);
    assert.equal(sample.frontier_leaf_ranking[0].advisory, true);
    assert.equal(sample.intervention_ranking[0].source_window_hash, sample.window_hash);
    assert.ok(sample.composition_search[0].template_ids.length >= 2);
  });
});

test("CB-B4: the sampler marginal reflects the elicited prior, not a constant", () => {
  withTempHome(() => {
    const domain = "factor-graph-elicited.example.com";
    seedGraph(domain);

    // no elicitation -> uniform prior -> marginal near uniform
    const w0 = buildBeliefWindow({ target_domain: domain });
    const s0 = buildFactorGraphSample({ window: w0, seed: "s", sample_count: 512 });
    const ep = w0.variables.find((v) => v.type === "effective_permission");
    const m0 = s0.marginals.find((m) => m.variable_id === ep.variable_id);
    assert.ok(m0.marginal.allowed < 0.5, "uniform prior must not concentrate on 'allowed'");

    // host agent elicits a confident belief for that latent
    elicitBeliefTool.handler({
      target_domain: domain,
      latent_id: ep.variable_id,
      latent_type: "effective_permission",
      states: ["allowed", "blocked", "unknown"],
      distribution: { allowed: 0.8, blocked: 0.15, unknown: 0.05 },
      evidence_refs: ["auth-differential-results.json#req-7"],
      rationale: "attacker-auth reaches the victim object",
    });

    const w1 = buildBeliefWindow({ target_domain: domain });
    const s1 = buildFactorGraphSample({ window: w1, seed: "s", sample_count: 512 });
    const m1 = s1.marginals.find((m) => m.variable_id === ep.variable_id);
    // the sampler now echoes the elicited belief (within Monte-Carlo noise), not a regex/uniform constant
    assert.ok(m1.marginal.allowed > 0.7, "sampler marginal must track the elicited prior");
    assert.notEqual(s1.sample_hash, s0.sample_hash);
  });
});

test("bob_run_belief_sampler writes only belief-scratch samples and does not create claims", () => {
  assert.equal(runBeliefSamplerTool.mutating, true);
  assert.equal(runBeliefSamplerTool.network_access, false);
  assert.deepEqual(runBeliefSamplerTool.session_artifacts_written, ["belief-scratch/belief-samples.jsonl"]);
  withTempHome(() => {
    const domain = "factor-graph-scratch.example.com";
    seedGraph(domain);
    const result = runBeliefSampler({ target_domain: domain, seed: "persist", sample_count: 64 });
    assert.match(result.artifact_path, /belief-scratch\/belief-samples\.jsonl$/);
    assert.equal(fs.existsSync(path.join(sessionDir(domain), "findings.jsonl")), false);
    const read = readBeliefSamples({ target_domain: domain });
    assert.equal(read.samples.length, 1);
    assert.equal(read.samples[0].sample_hash, result.sample_hash);
  });
});
