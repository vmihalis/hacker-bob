"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendFrontierEvent,
} = require("../mcp/core/frontier/frontier-events.js");
const {
  sessionDir,
} = require("../mcp/core/io/paths.js");
const {
  appendEdges,
} = require("../mcp/core/frontier/surface-graph.js");
const {
  buildBeliefWindow,
} = require("../mcp/core/belief/belief-window.js");
const queryBeliefWindowTool = require("../mcp/tools/query-belief-window.js");
const elicitBeliefTool = require("../mcp/tools/elicit-belief.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-belief-window-"));
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

function seedObjectAuthGraph(domain, effectId) {
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
        target: { type: "effect", id: effectId },
        edge_type: "permits_effect",
        source_artifact: "auth-differential-results.json",
      },
    ],
  });
}

test("CB-B1: absent an elicitation the effective_permission prior is honest uniform, not a regex guess", () => {
  withTempHome(() => {
    const domain = "belief-window-idor.example.com";
    ensureSession(domain);
    // an effect id that the old regex would have scored 0.88 'allowed'
    seedObjectAuthGraph(domain, "effect:unauth_succeeds_where_auth_blocked:victim-object");

    const first = buildBeliefWindow({ target_domain: domain });
    const second = buildBeliefWindow({ target_domain: domain });
    assert.equal(first.window_hash, second.window_hash); // deterministic
    assert.equal(first.advisory, true);
    const effective = first.variables.find((variable) => variable.type === "effective_permission");
    assert.ok(effective, "effective_permission variable must be present");
    // the regex used to fabricate 0.88 from the effect id; now it is uniform
    assert.equal(effective.prior_source, "uniform");
    assert.ok(Math.abs(effective.posterior.allowed - 1 / 3) < 0.01);
    assert.ok(effective.posterior.allowed < 0.85, "must NOT fabricate confidence from the effect id");
  });
});

test("CB-B1: the window reflects an elicited belief and its hash moves when the agent elicits", () => {
  withTempHome(() => {
    const domain = "belief-window-elicited.example.com";
    ensureSession(domain);
    seedObjectAuthGraph(domain, "effect:unauth_succeeds_where_auth_blocked:victim-object");

    const w0 = buildBeliefWindow({ target_domain: domain });
    const ep0 = w0.variables.find((v) => v.type === "effective_permission");
    assert.equal(ep0.prior_source, "uniform");

    // the host agent elicits a belief for this exact latent (latent_id == variable_id)
    elicitBeliefTool.handler({
      target_domain: domain,
      latent_id: ep0.variable_id,
      latent_type: "effective_permission",
      states: ["allowed", "blocked", "unknown"],
      distribution: { allowed: 0.8, blocked: 0.15, unknown: 0.05 },
      evidence_refs: ["auth-differential-results.json#req-7"],
      rationale: "attacker-auth reaches the victim object id; unauth blocked",
    });

    const w1 = buildBeliefWindow({ target_domain: domain });
    const ep1 = w1.variables.find((v) => v.type === "effective_permission");
    assert.equal(ep1.prior_source, "elicited");
    assert.equal(ep1.posterior.allowed, 0.8); // reflects the elicited belief, not a constant
    assert.notEqual(w1.window_hash, w0.window_hash); // belief moved with evidence
  });
});

test("belief window enforces variable cap with belief_window_too_large", () => {
  withTempHome(() => {
    const domain = "belief-window-too-large.example.com";
    ensureSession(domain);
    for (let index = 0; index < 3; index += 1) {
      appendEdges({
        target_domain: domain,
        edges: [
          {
            source: { type: "principal", id: `principal:p${index}` },
            target: { type: "policy_gate", id: `policy_gate:g${index}` },
            edge_type: "tests_gate",
          },
          {
            source: { type: "policy_gate", id: `policy_gate:g${index}` },
            target: { type: "effect", id: `effect:unauth_succeeds_where_auth_blocked:${index}` },
            edge_type: "permits_effect",
          },
        ],
      });
    }
    assert.throws(
      () => buildBeliefWindow({ target_domain: domain, variable_limit: 2 }),
      (error) => error && error.code === "belief_window_too_large",
    );
  });
});

test("bob_query_belief_window is read-only, offline, and does not write artifacts", () => {
  assert.equal(queryBeliefWindowTool.mutating, false);
  assert.equal(queryBeliefWindowTool.network_access, false);
  assert.deepEqual(queryBeliefWindowTool.session_artifacts_written, []);
  withTempHome(() => {
    const domain = "belief-window-tool.example.com";
    ensureSession(domain);
    seedObjectAuthGraph(domain, "effect:unauth_succeeds_where_auth_blocked:victim-object");
    const before = fs.readdirSync(sessionDir(domain)).sort();
    const result = queryBeliefWindowTool.handler({ target_domain: domain });
    const after = fs.readdirSync(sessionDir(domain)).sort();
    assert.deepEqual(after, before);
    assert.match(result.window_hash, /^[a-f0-9]{64}$/);
  });
});
