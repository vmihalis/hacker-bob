"use strict";

// F1 — mechanism-graph chain substrate. The covered principal->effect path space
// the chain phase (F2) traverses: bounded, deterministic enumeration over the
// observed mechanism graph, each terminal effect annotated finding_backed, plus
// the covered A2 cross-surface transition hops.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendEdges } = require("../mcp/lib/surface-graph.js");
const {
  isFindingBackedEffect,
  parseObjectAuthEffectEndpoint,
  COMPOSITION_GUARD_CONTROLS,
  compositionBriefForPath,
  coveredTransitionHops,
  enumerateCandidatePaths,
} = require("../mcp/lib/mechanism-coverage.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-mechanism-coverage-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function seedAuthDiffMechanism(domain) {
  appendEdges({
    target_domain: domain,
    edges: [
      // An attacker principal reaches an auth-diff DIVERGENCE effect (finding).
      {
        source: { type: "principal", id: "principal:attacker" },
        target: { type: "policy_gate", id: "policy_gate:owner" },
        edge_type: "tests_gate",
      },
      {
        source: { type: "policy_gate", id: "policy_gate:owner" },
        target: { type: "effect", id: "effect:billing:unauth_succeeds_where_auth_blocked" },
        edge_type: "permits_effect",
      },
      // ... and a benign response effect (not a finding).
      {
        source: { type: "principal", id: "principal:attacker" },
        target: { type: "effect", id: "effect:home:anon:200" },
        edge_type: "produces_effect",
      },
    ],
  });
}

test("isFindingBackedEffect recognizes a real divergence / confirmed chain, not a benign response", () => {
  assert.equal(isFindingBackedEffect("effect:billing:unauth_succeeds_where_auth_blocked"), true);
  assert.equal(isFindingBackedEffect("effect:chain:success"), true);
  assert.equal(isFindingBackedEffect("effect:home:anon:200"), false);
  assert.equal(isFindingBackedEffect(null), false);
});

test("F1: an empty mechanism graph yields an empty path space", () => {
  withTempHome(() => {
    const result = enumerateCandidatePaths("f1-empty.example.com", {});
    assert.equal(result.mechanism_edges, 0);
    assert.equal(result.total_enumerated, 0);
    assert.deepEqual(result.paths, []);
    assert.deepEqual(result.transition_hops, []);
  });
});

test("F1: enumerates principal->effect candidate paths, finding-backed first", () => {
  withTempHome(() => {
    const domain = "f1-paths.example.com";
    seedAuthDiffMechanism(domain);
    const result = enumerateCandidatePaths(domain, {});
    assert.equal(result.total_enumerated, 2);
    // The finding-backed divergence path sorts ahead of the benign response path.
    assert.equal(result.paths[0].terminal_effect, "effect:billing:unauth_succeeds_where_auth_blocked");
    assert.equal(result.paths[0].finding_backed, true);
    assert.equal(result.paths[0].hop_count, 2);
    assert.ok(result.paths[0].path_id.startsWith("mpath-"));
    // Each hop carries the mechanism edge_id (content-addressed edge_hash) + endpoints.
    for (const hop of result.paths[0].hops) {
      assert.ok(typeof hop.edge_id === "string" && hop.edge_id.length > 0);
      assert.ok(typeof hop.from_node === "string" && typeof hop.to_node === "string");
    }
    assert.equal(result.paths[1].finding_backed, false);
  });
});

test("F1: the path space is deterministic given identical ledgers", () => {
  withTempHome(() => {
    const domain = "f1-determinism.example.com";
    seedAuthDiffMechanism(domain);
    const a = enumerateCandidatePaths(domain, {});
    const b = enumerateCandidatePaths(domain, {});
    assert.equal(JSON.stringify(a.paths), JSON.stringify(b.paths));
    assert.equal(JSON.stringify(a.transition_hops), JSON.stringify(b.transition_hops));
  });
});

test("F1: a covered A2 transition surfaces as a verified cross-surface hop", () => {
  withTempHome(() => {
    const domain = "f1-transition.example.com";
    const { appendFrontierEvent } = require("../mcp/lib/frontier-events.js");
    const { materializeFrontier } = require("../mcp/lib/frontier-materializer.js");
    const { appendTransitionProposal } = require("../mcp/lib/task-graph-events.js");
    const { writeQueuePolicy, normalizeQueuePolicy, DEFAULT_QUEUE_POLICY } = require("../mcp/lib/queue-policy.js");
    const { logCellCoverage } = require("../mcp/lib/coverage.js");
    const { transitionEdgeToken } = require("../mcp/lib/assignment-brief.js");

    for (const sid of ["surface:l1", "surface:l2"]) {
      appendFrontierEvent({ target_domain: domain, kind: "surface.observed", ts: "2026-05-31T00:00:00.000Z", surface_id: sid, payload: { title: sid } });
    }
    materializeFrontier(domain, { write: true });
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_children: 64 }));
    appendTransitionProposal({
      target_domain: domain,
      ts: "2026-05-31T00:01:00.000Z",
      from_surface: "surface:l1",
      to_surface: "surface:l2",
      kind: "value_movement",
      trust_assumption: "l1 value trusted on l2",
      proposal_id: "TR-f1",
    });

    // Before any coverage: no covered hop.
    assert.deepEqual(coveredTransitionHops(domain), []);

    // Cover one transition-cell on the edge.
    const edgeToken = transitionEdgeToken("surface:l1", "surface:l2", "value_movement");
    logCellCoverage({ target_domain: domain, surface_id: edgeToken, bug_class: "value_flow", auth_profile: "", status: "tested", evidence_summary: "probed" });

    const hops = coveredTransitionHops(domain);
    assert.equal(hops.length, 1, "the covered transition is a verified cross-surface hop");
    assert.equal(hops[0].from_surface, "surface:l1");
    assert.equal(hops[0].to_surface, "surface:l2");
    // covered_bug_classes carries ONLY the covered class — the still-uncovered
    // sibling (value_movement axis = [value_flow, replay]) is excluded.
    assert.deepEqual(hops[0].covered_bug_classes, ["value_flow"]);
  });
});

test("F1: the walk terminates on a cyclic mechanism graph (no infinite loop)", () => {
  withTempHome(() => {
    const domain = "f1-cycle.example.com";
    // A 3-cycle among principals plus an effect terminal. Simple-path DFS + the
    // global step budget must terminate deterministically, not hang.
    appendEdges({
      target_domain: domain,
      edges: [
        { source: { type: "principal", id: "principal:a" }, target: { type: "principal", id: "principal:b" }, edge_type: "claims_auth" },
        { source: { type: "principal", id: "principal:b" }, target: { type: "principal", id: "principal:c" }, edge_type: "claims_auth" },
        { source: { type: "principal", id: "principal:c" }, target: { type: "principal", id: "principal:a" }, edge_type: "claims_auth" },
        { source: { type: "principal", id: "principal:c" }, target: { type: "effect", id: "effect:x:unauth_succeeds_where_auth_blocked" }, edge_type: "produces_effect" },
      ],
    });
    const result = enumerateCandidatePaths(domain, {});
    assert.ok(result.total_enumerated >= 1, "at least one simple path reaches the effect");
    assert.ok(result.paths.every((p) => p.finding_backed === true));
    // Determinism holds even with the cycle present.
    assert.equal(JSON.stringify(result.paths), JSON.stringify(enumerateCandidatePaths(domain, {}).paths));
  });
});

test("F2: parseObjectAuthEffectEndpoint recovers the endpoint of an object-auth divergence only", () => {
  assert.equal(parseObjectAuthEffectEndpoint("effect:/api/orders/42:unauth_succeeds_where_auth_blocked"), "/api/orders/42");
  assert.equal(parseObjectAuthEffectEndpoint("effect:billing:unauth_succeeds_where_auth_blocked"), "billing");
  // Not an object-auth divergence -> null (benign response, chain verdict, malformed).
  assert.equal(parseObjectAuthEffectEndpoint("effect:home:anon:200"), null);
  assert.equal(parseObjectAuthEffectEndpoint("effect:chain:success"), null);
  assert.equal(parseObjectAuthEffectEndpoint("effect::unauth_succeeds_where_auth_blocked"), null);
  assert.equal(parseObjectAuthEffectEndpoint(null), null);
});

test("F2: compositionBriefForPath selects verifiable paths and NEVER fabricates live inputs", () => {
  // A finding-backed object-auth path is verifiable: it carries the parsed
  // endpoint, the guard hop's edge_id, and the control battery to develop.
  const verifiablePath = {
    terminal_effect: "effect:/api/orders/42:unauth_succeeds_where_auth_blocked",
    finding_backed: true,
    hops: [
      { edge_id: "eh-1", edge_type: "tests_gate", from_node: "principal:attacker", to_node: "policy_gate:owner" },
      { edge_id: "eh-2", edge_type: "permits_effect", from_node: "policy_gate:owner", to_node: "effect:/api/orders/42:unauth_succeeds_where_auth_blocked" },
    ],
  };
  const brief = compositionBriefForPath(verifiablePath);
  assert.equal(brief.verifiable, true);
  assert.equal(brief.terminal_endpoint, "/api/orders/42");
  assert.equal(brief.guard_edge_id, "eh-2", "the guard hop is the last edge reaching the divergence effect");
  assert.deepEqual(brief.controls_required, COMPOSITION_GUARD_CONTROLS);
  // The brief is a SKELETON — the live re-execution inputs are the agent's work,
  // never minted here (forging them would forge the audit-graded ledger).
  assert.equal("evidence_ref" in brief, false);
  assert.equal("primary" in brief, false);
  assert.equal("control_plan" in brief, false);

  // A benign (non-finding) path is not verifiable and offers no control battery.
  const benign = compositionBriefForPath({
    terminal_effect: "effect:home:anon:200",
    finding_backed: false,
    hops: [{ edge_id: "eh-3", edge_type: "produces_effect", from_node: "principal:attacker", to_node: "effect:home:anon:200" }],
  });
  assert.equal(benign.verifiable, false);
  assert.equal(benign.terminal_endpoint, null);
  assert.deepEqual(benign.controls_required, []);
  assert.ok(typeof benign.reason === "string" && benign.reason.length > 0);

  // A finding-backed path with NO guard edge (hops absent) is not verifiable —
  // the brief is the verifier's input, so a no-edge path is self-inconsistent.
  const noGuard = compositionBriefForPath({
    terminal_effect: "effect:billing:unauth_succeeds_where_auth_blocked",
    finding_backed: true,
    hops: [],
  });
  assert.equal(noGuard.verifiable, false);
  assert.equal(noGuard.guard_edge_id, null);
});

test("F2: enumerateCandidatePaths attaches a composition brief per path", () => {
  withTempHome(() => {
    const domain = "f2-brief.example.com";
    seedAuthDiffMechanism(domain);
    const result = enumerateCandidatePaths(domain, {});
    // The divergence path is verifiable; the benign response path is not.
    const divergence = result.paths.find((p) => p.finding_backed);
    const benign = result.paths.find((p) => !p.finding_backed);
    assert.ok(divergence.composition.verifiable, "the finding-backed object-auth path is chain-verifiable");
    assert.equal(divergence.composition.terminal_endpoint, "billing");
    assert.equal(benign.composition.verifiable, false);
  });
});

test("F1: bob_query_surface_graph mode covered_paths returns the path space (no new tool)", () => {
  withTempHome(() => {
    const domain = "f1-tool.example.com";
    seedAuthDiffMechanism(domain);
    const tool = require("../mcp/lib/tools/query-surface-graph.js");
    assert.equal(tool.name, "bob_query_surface_graph", "F1 reuses the existing tool — no new tool registered");
    const result = tool.handler({ target_domain: domain, mode: "covered_paths" });
    assert.equal(result.total_enumerated, 2);
    assert.equal(result.paths[0].finding_backed, true);
  });
});
