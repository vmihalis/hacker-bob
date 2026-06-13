"use strict";

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
} = require("../mcp/lib/belief/belief-window.js");
const queryBeliefWindowTool = require("../mcp/lib/tools/query-belief-window.js");

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

test("belief window is deterministic and high-confidence for IDOR-like effective permission", () => {
  withTempHome(() => {
    const domain = "belief-window-idor.example.com";
    ensureSession(domain);
    seedObjectAuthGraph(domain, "effect:unauth_succeeds_where_auth_blocked:victim-object");
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-06-13T00:00:00.000Z",
      surface_id: "surface:billing",
      payload: {
        observation_kind: "schema_field",
        endpoint: "/billing/{object_id}",
        object_id: "invoice-123",
        owner: "victim",
      },
    });

    const first = buildBeliefWindow({ target_domain: domain });
    const second = buildBeliefWindow({ target_domain: domain });
    assert.equal(first.window_hash, second.window_hash);
    assert.equal(first.advisory, true);
    assert.equal(first.derived, true);
    assert.equal(first.writes_artifacts, false);
    const effective = first.variables.find((variable) => variable.type === "effective_permission");
    assert.ok(effective, "effective_permission variable must be present");
    assert.ok(effective.posterior.allowed >= 0.85);
    assert.equal(first.evidence_summary.mechanism_edge_count, 2);
    assert.equal(first.evidence_summary.typed_fact_count, 1);
  });
});

test("belief window does not overstate public-object fixtures", () => {
  withTempHome(() => {
    const domain = "belief-window-public-object.example.com";
    ensureSession(domain);
    seedObjectAuthGraph(domain, "effect:public_object_read");
    const window = buildBeliefWindow({ target_domain: domain });
    const effective = window.variables.find((variable) => variable.type === "effective_permission");
    assert.ok(effective);
    assert.ok(effective.posterior.allowed < 0.70);
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
