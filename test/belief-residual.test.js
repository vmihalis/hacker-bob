"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendEdges } = require("../mcp/lib/surface-graph.js");
const { sessionDir } = require("../mcp/lib/paths.js");
const {
  buildResidualDiagnostic,
  runBeliefResidual,
} = require("../mcp/lib/belief/residual.js");
const { queryBeliefSignals } = require("../mcp/lib/belief/authority.js");
const runBeliefResidualTool = require("../mcp/lib/tools/run-belief-residual.js");
const { buildBeliefWindow } = require("../mcp/lib/belief/belief-window.js");
const elicitBeliefTool = require("../mcp/lib/tools/elicit-belief.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-belief-residual-"));
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

test("residual diagnostic is deterministic for seed, window, evidence, and registry", () => {
  withTempHome(() => {
    const domain = "belief-residual-deterministic.example.com";
    seedGraph(domain, "effect:public_object_read");
    const first = buildResidualDiagnostic({ target_domain: domain, seed: "same", sample_count: 128 });
    const second = buildResidualDiagnostic({ target_domain: domain, seed: "same", sample_count: 128 });
    assert.equal(first.residual_hash, second.residual_hash);
    assert.deepEqual(first.decomposition, second.decomposition);
    assert.equal(first.provenance, "residual_anomaly");
    assert.equal(first.role, "diagnostic");
    assert.equal(first.claim_authority, false);
    assert.equal(first.dispatch_authority, false);
    assert.equal(first.template_promotion_authority, false);
  });
});

test("residual tracks the elicited belief's confidence, not a regex on the effect id", () => {
  withTempHome(() => {
    // SAME effect id in both domains -> any residual difference comes from the
    // elicited belief, not a regex (the regex used to fabricate the difference).
    const uniformDomain = "belief-residual-uniform.example.com";
    const elicitedDomain = "belief-residual-elicited.example.com";
    seedGraph(uniformDomain, "effect:unauth_succeeds_where_auth_blocked:victim");
    seedGraph(elicitedDomain, "effect:unauth_succeeds_where_auth_blocked:victim");

    // host agent elicits a confident (low-entropy) belief in one domain only
    const w = buildBeliefWindow({ target_domain: elicitedDomain });
    const ep = w.variables.find((v) => v.type === "effective_permission");
    elicitBeliefTool.handler({
      target_domain: elicitedDomain,
      latent_id: ep.variable_id,
      latent_type: "effective_permission",
      states: ["allowed", "blocked", "unknown"],
      distribution: { allowed: 0.94, blocked: 0.04, unknown: 0.02 },
      evidence_refs: ["auth-differential-results.json#req-7"],
      rationale: "attacker-auth confidently reaches the victim object",
    });

    const uniformResidual = buildResidualDiagnostic({ target_domain: uniformDomain, seed: "compare", sample_count: 512 });
    const elicitedResidual = buildResidualDiagnostic({ target_domain: elicitedDomain, seed: "compare", sample_count: 512 });
    assert.ok(uniformResidual.residual_score > elicitedResidual.residual_score);
  });
});

test("bob_run_belief_residual writes only diagnostic belief scratch and no authority artifacts", () => {
  assert.equal(runBeliefResidualTool.mutating, true);
  assert.equal(runBeliefResidualTool.network_access, false);
  assert.deepEqual(runBeliefResidualTool.session_artifacts_written, ["belief-scratch/belief-signals.jsonl"]);
  withTempHome(() => {
    const domain = "belief-residual-scratch.example.com";
    seedGraph(domain, "effect:public_object_read");
    const result = runBeliefResidual({ target_domain: domain, seed: "persist", sample_count: 128 });
    assert.match(result.artifact_path, /belief-scratch\/belief-signals\.jsonl$/);
    assert.equal(fs.existsSync(path.join(sessionDir(domain), "findings.jsonl")), false);
    assert.equal(fs.existsSync(path.join(sessionDir(domain), "task-graph.json")), false);
    const read = queryBeliefSignals({
      target_domain: domain,
      provenance: "residual_anomaly",
      role: "diagnostic",
    });
    assert.equal(read.signals.length, 1);
    assert.equal(read.signals[0].payload.residual_hash, result.residual_hash);
  });
});
