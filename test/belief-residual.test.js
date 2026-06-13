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

test("public-object uncertainty produces a higher residual than IDOR-like high-confidence evidence", () => {
  withTempHome(() => {
    const publicDomain = "belief-residual-public.example.com";
    const idorDomain = "belief-residual-idor.example.com";
    seedGraph(publicDomain, "effect:public_object_read");
    seedGraph(idorDomain, "effect:unauth_succeeds_where_auth_blocked:victim");
    const publicResidual = buildResidualDiagnostic({ target_domain: publicDomain, seed: "compare", sample_count: 512 });
    const idorResidual = buildResidualDiagnostic({ target_domain: idorDomain, seed: "compare", sample_count: 512 });
    assert.ok(publicResidual.residual_score > idorResidual.residual_score);
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
