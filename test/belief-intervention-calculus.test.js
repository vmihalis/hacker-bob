"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendEdges } = require("../mcp/lib/surface-graph.js");
const { sessionDir } = require("../mcp/lib/paths.js");
const { rankInterventions } = require("../mcp/lib/belief/intervention-calculus.js");
const queryInterventionCalculusTool = require("../mcp/lib/tools/query-intervention-calculus.js");

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

test("IDOR fixture ranks victim-object selector swap above attacker-owned control", () => {
  withTempHome(() => {
    const domain = "intervention-calculus-idor.example.com";
    seedGraph(domain, "effect:unauth_succeeds_where_auth_blocked:victim");
    const result = rankInterventions({ target_domain: domain, seed: "idor", rank_limit: 10 });
    const swapIndex = result.ranking.findIndex((entry) => entry.intervention === "principal_fixed_object_swap");
    const controlIndex = result.ranking.findIndex((entry) => entry.intervention === "attacker_owned_control");
    assert.ok(swapIndex >= 0);
    assert.ok(controlIndex >= 0);
    assert.ok(swapIndex < controlIndex);
  });
});

test("public-object fixture ranks public_object_check first", () => {
  withTempHome(() => {
    const domain = "intervention-calculus-public.example.com";
    seedGraph(domain, "effect:public_object_read");
    const result = rankInterventions({ target_domain: domain, seed: "public", rank_limit: 10 });
    assert.equal(result.ranking[0].intervention, "public_object_check");
    assert.ok(result.ranking[0].confounders_discriminated.includes("public_object"));
  });
});
