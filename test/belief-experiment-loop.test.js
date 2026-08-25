"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendEdges } = require("../mcp/core/frontier/surface-graph.js");
const { sessionDir } = require("../mcp/core/io/paths.js");
const { readFrontierEvents } = require("../mcp/core/frontier/frontier-events.js");
const { planBeliefExperiment } = require("../mcp/core/belief/experiment-loop.js");
const planBeliefExperimentTool = require("../mcp/tools/plan-belief-experiment.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-experiment-loop-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function seedGraph(domain, effectId = "effect:unauth_succeeds_where_auth_blocked:victim") {
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

test("belief experiment dry-run is deterministic and writes no frontier events", () => {
  withTempHome(() => {
    const domain = "experiment-loop-dry-run.example.com";
    seedGraph(domain);
    const first = planBeliefExperiment({ target_domain: domain, seed: "same", dry_run: true });
    const second = planBeliefExperiment({ target_domain: domain, seed: "same", dry_run: true });
    assert.equal(first.loop_hash, second.loop_hash);
    assert.deepEqual(first.proposals, second.proposals);
    assert.equal(first.dispatch_authority, false);
    assert.equal(first.claim_authority, false);
    assert.equal(fs.existsSync(path.join(sessionDir(domain), "frontier-events.jsonl")), false);
  });
});

test("belief experiment appends through hypothesis proposal with advisory contract", () => {
  assert.equal(planBeliefExperimentTool.mutating, true);
  assert.equal(planBeliefExperimentTool.network_access, false);
  assert.deepEqual(planBeliefExperimentTool.session_artifacts_written, ["frontier-events.jsonl"]);
  withTempHome(() => {
    const domain = "experiment-loop-append.example.com";
    seedGraph(domain);
    const result = planBeliefExperiment({ target_domain: domain, seed: "append", max_iterations: 1 });
    assert.equal(result.proposals.length, 1);
    assert.equal(result.proposals[0].appended, true);
    const events = readFrontierEvents(domain);
    assert.equal(events.length, 1);
    assert.equal(events[0].payload.kind, "hypothesis_proposed");
    assert.equal(events[0].payload.suggested_contract.source, "belief_experiment_loop");
    assert.deepEqual(
      events[0].payload.suggested_contract.witnesses.map((witness) => witness.kind),
      ["relational_value_match"],
    );
    assert.ok(Array.isArray(events[0].payload.suggested_contract.production_paths));
    assert.equal(fs.existsSync(path.join(sessionDir(domain), "findings.jsonl")), false);
  });
});

test("belief experiment loop enforces max iteration bound", () => {
  withTempHome(() => {
    const domain = "experiment-loop-bound.example.com";
    seedGraph(domain, "effect:public_object_read");
    const result = planBeliefExperiment({
      target_domain: domain,
      seed: "bound",
      max_iterations: 2,
      rank_limit: 10,
    });
    assert.equal(result.proposals.length, 2);
    assert.equal(readFrontierEvents(domain).length, 2);
  });
});
