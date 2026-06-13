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
