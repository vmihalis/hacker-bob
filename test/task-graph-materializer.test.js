"use strict";

// Plane X Cycle X.2 — TaskGraph materializer + raw/summary view.
//
// X.2 ships:
//   - mcp/lib/task-graph-materializer.js exporting materializeTaskGraph,
//     readTaskGraph, summarizeTaskGraph and the LEDGER_PRESSURE_*
//     thresholds.
//   - mcp/lib/tools/{materialize,read}-task-graph.js registered in the
//     tool registry.
//   - Debounce hook in frontier-materialize-debounce.js so producer-event
//     session-lock releases fold the TaskGraph alongside surface-index.
//   - mcp/lib/paths.js gains taskGraphPath(domain).
//
// Per Do step 5 (Review) the tests must demonstrate:
//   1. Identical event log → identical graph_hash across re-materializations
//      (3 runs, byte-identical hash).
//   2. Summary view covers all 4 node kinds + failure_reasons.
//   3. Ledger-pressure warning fires at 12k events; refusal at 18k.
// Plus structural shape, debounce hook integration, raw filters, and the
// node-id namespacing per the pre-flight finding (TG- prefix prevents
// collision with mcp/lib/surface-graph.js node ids).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendFrontierEvent,
  FRONTIER_EVENTS_MAX_RECORDS,
} = require("../mcp/lib/frontier-events.js");
const {
  appendHypothesisProposal,
  appendNodeTransition,
  appendTransitionProposal,
  TASK_GRAPH_NODE_ID_PREFIX,
} = require("../mcp/lib/task-graph-events.js");
const {
  DEFAULT_NODE_PRIORITY,
  LEDGER_PRESSURE_REFUSE_THRESHOLD,
  LEDGER_PRESSURE_WARN_THRESHOLD,
  TASK_GRAPH_EDGE_KIND_VALUES,
  TASK_GRAPH_NODE_KIND_VALUES,
  claimNodeId,
  hypothesisNodeId,
  materializeTaskGraph,
  readTaskGraph,
  summarizeTaskGraph,
  surfaceNodeId,
  transitionNodeId,
} = require("../mcp/lib/task-graph-materializer.js");
const {
  pendingDomains,
  resetForTests,
  scheduleMaterialization,
} = require("../mcp/lib/frontier-materialize-debounce.js");
const {
  withSessionLock,
} = require("../mcp/lib/storage.js");
const {
  frontierEventsJsonlPath,
  taskGraphPath,
} = require("../mcp/lib/paths.js");
const { TOOL_HANDLERS } = require("../mcp/lib/tool-registry.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-task-graph-mat-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    resetForTests();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// ─── Constants are wired correctly ───────────────────────────────────────

test("LEDGER_PRESSURE thresholds sit below FRONTIER_EVENTS_MAX_RECORDS", () => {
  assert.equal(LEDGER_PRESSURE_WARN_THRESHOLD, 12_000);
  assert.equal(LEDGER_PRESSURE_REFUSE_THRESHOLD, 18_000);
  assert.ok(LEDGER_PRESSURE_WARN_THRESHOLD < LEDGER_PRESSURE_REFUSE_THRESHOLD);
  assert.ok(LEDGER_PRESSURE_REFUSE_THRESHOLD < FRONTIER_EVENTS_MAX_RECORDS);
});

test("TASK_GRAPH_NODE_KIND_VALUES is closed at the 4 X.2 node kinds", () => {
  assert.deepEqual(TASK_GRAPH_NODE_KIND_VALUES.slice().sort(), [
    "claim",
    "hypothesis",
    "surface",
    "transition",
  ]);
});

test("TASK_GRAPH_EDGE_KIND_VALUES is closed at the 3 X.2 edge kinds", () => {
  assert.deepEqual(TASK_GRAPH_EDGE_KIND_VALUES.slice().sort(), [
    "bridges",
    "claim_links",
    "unblocks",
  ]);
});

test("DEFAULT_NODE_PRIORITY matches the queue-policy default", () => {
  assert.equal(DEFAULT_NODE_PRIORITY, "medium");
});

// ─── Node id minting carries the TG- prefix per pre-flight finding ───────

test("surfaceNodeId / hypothesisNodeId / transitionNodeId / claimNodeId carry the TG- prefix", () => {
  assert.ok(surfaceNodeId("surface:billing").startsWith(TASK_GRAPH_NODE_ID_PREFIX));
  assert.ok(hypothesisNodeId({ proposalId: "HP-abc" }).startsWith(TASK_GRAPH_NODE_ID_PREFIX));
  assert.ok(transitionNodeId({ proposalId: "TP-xyz" }).startsWith(TASK_GRAPH_NODE_ID_PREFIX));
  assert.ok(claimNodeId("F-1").startsWith(TASK_GRAPH_NODE_ID_PREFIX));
  // Sub-namespace discriminators keep kinds separable so a surface "hypothesis"
  // doesn't collide with a TG-H-* hypothesis.
  assert.equal(surfaceNodeId("hypothesis"), "TG-S-hypothesis");
  assert.equal(hypothesisNodeId({ proposalId: "HP-a" }), "TG-H-HP-a");
  assert.equal(transitionNodeId({ proposalId: "TP-a" }), "TG-T-TP-a");
  assert.equal(claimNodeId("F-7"), "TG-C-F-7");
});

test("hypothesis/transition node id derivation is deterministic across re-materializations when proposal_id is omitted", () => {
  const a = hypothesisNodeId({ eventId: "FE-abc123" });
  const b = hypothesisNodeId({ eventId: "FE-abc123" });
  assert.equal(a, b);
  assert.notEqual(a, hypothesisNodeId({ eventId: "FE-different" }));
});

// ─── Empty ledger yields a structurally well-formed empty graph ─────────

test("materializeTaskGraph on an empty ledger returns 0 nodes / 0 edges / stable hashes", () => {
  withTempHome(() => {
    const domain = "x2-empty.example.com";
    const result = materializeTaskGraph(domain, {
      write: true,
      now: new Date("2026-05-31T00:00:00.000Z"),
    });
    assert.equal(result.document.node_count, 0);
    assert.equal(result.document.edge_count, 0);
    assert.equal(result.document.source_event_count, 0);
    assert.ok(typeof result.document.hashes.nodes_hash === "string");
    assert.ok(typeof result.document.hashes.edges_hash === "string");
    assert.ok(typeof result.document.hashes.graph_hash === "string");
    // Persisted to disk.
    assert.equal(fs.existsSync(taskGraphPath(domain)), true);
  });
});

// ─── Folds the 4 node kinds + their edges ────────────────────────────────

function seedFourKindFixture(domain) {
  // Surface
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-31T01:00:00.000Z",
    surface_id: "surface:web-auth",
    payload: { title: "Web auth", surface_type: "web" },
  });
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-31T01:00:01.000Z",
    surface_id: "surface:evm-vault",
    payload: { title: "EVM vault", surface_type: "smart_contract", chain_family: "evm" },
  });

  // Hypothesis
  appendHypothesisProposal({
    target_domain: domain,
    hypothesis_statement: "Vault accepts replayed signatures across nonces.",
    surface_refs: ["surface:evm-vault"],
    proposal_id: "HP-vault-replay",
    ts: "2026-05-31T01:00:02.000Z",
  });

  // Transition
  appendTransitionProposal({
    target_domain: domain,
    from_surface: "surface:web-auth",
    to_surface: "surface:evm-vault",
    kind: "identity_propagation",
    trust_assumption: "JWT.sub equals msg.sender on the vault.",
    proposal_id: "TP-jwt-to-vault",
    ts: "2026-05-31T01:00:03.000Z",
  });

  // Claim (linked to surface)
  appendFrontierEvent({
    target_domain: domain,
    kind: "claim.candidate.linked",
    ts: "2026-05-31T01:00:04.000Z",
    surface_id: "surface:web-auth",
    claim_id: "F-1",
    payload: {},
  });

  // State transitions on the transition node: proposed → contracted → ready
  const tNodeId = transitionNodeId({ proposalId: "TP-jwt-to-vault" });
  appendNodeTransition({
    target_domain: domain,
    node_id: tNodeId,
    from_state: "proposed",
    to_state: "contracted",
    contract_hash: "contract-sha-1",
    ts: "2026-05-31T01:00:05.000Z",
  });
  appendNodeTransition({
    target_domain: domain,
    node_id: tNodeId,
    from_state: "contracted",
    to_state: "ready",
    ts: "2026-05-31T01:00:06.000Z",
  });

  // Hypothesis transitions to finalized via the full chain.
  const hNodeId = hypothesisNodeId({ proposalId: "HP-vault-replay" });
  for (const [from, to, extra] of [
    ["proposed", "contracted", { contract_hash: "contract-sha-2" }],
    ["contracted", "ready", {}],
    // prep_token is a payload field on the X-D1 dispatched-state event; the
    // X.8 cycle owns minting + binding it. X.2's fold treats it as
    // pass-through metadata; we don't need to seed it here and including it
    // would trigger the sensitive-material guard at append time (prep_token
    // shape is currently classified as a token-key per mcp/lib/sensitive-
    // material.js — X.8 owns the resolution).
    ["ready", "dispatched", {}],
    ["dispatched", "executed", { output_hash: "out-sha-1" }],
    ["executed", "verified", {}],
    ["verified", "finalized", { edge_added_to: [tNodeId] }],
  ]) {
    appendNodeTransition({
      target_domain: domain,
      node_id: hNodeId,
      from_state: from,
      to_state: to,
      ts: `2026-05-31T01:01:${String(from.length).padStart(2, "0")}.000Z`,
      ...extra,
    });
  }
  return { tNodeId, hNodeId };
}

test("materializeTaskGraph folds all 4 node kinds + their canonical edges", () => {
  withTempHome(() => {
    const domain = "x2-four-kinds.example.com";
    const { tNodeId, hNodeId } = seedFourKindFixture(domain);
    const result = materializeTaskGraph(domain, {
      now: new Date("2026-05-31T02:00:00.000Z"),
    });

    const nodesByKind = new Map();
    for (const node of result.document.nodes) {
      if (!nodesByKind.has(node.kind)) nodesByKind.set(node.kind, []);
      nodesByKind.get(node.kind).push(node);
    }
    assert.equal(nodesByKind.get("surface").length, 2);
    assert.equal(nodesByKind.get("hypothesis").length, 1);
    assert.equal(nodesByKind.get("transition").length, 1);
    assert.equal(nodesByKind.get("claim").length, 1);

    // The transition node ended at state `ready`.
    const tNode = result.document.nodes.find((n) => n.node_id === tNodeId);
    assert.equal(tNode.state, "ready");
    assert.equal(tNode.contract_hash, "contract-sha-1");
    assert.deepEqual(tNode.surface_refs, ["surface:evm-vault", "surface:web-auth"]);

    // The hypothesis node finalized.
    const hNode = result.document.nodes.find((n) => n.node_id === hNodeId);
    assert.equal(hNode.state, "finalized");

    // Edges: bridges (transition ↔ each endpoint), claim_links (surface →
    // claim), unblocks (finalized → downstream).
    const edgesByKind = new Map();
    for (const edge of result.document.edges) {
      if (!edgesByKind.has(edge.edge_kind)) edgesByKind.set(edge.edge_kind, []);
      edgesByKind.get(edge.edge_kind).push(edge);
    }
    assert.equal(edgesByKind.get("bridges").length, 2);
    assert.equal(edgesByKind.get("claim_links").length, 1);
    assert.equal(edgesByKind.get("unblocks").length, 1);
    // The unblocks edge points from hypothesis → transition.
    assert.equal(edgesByKind.get("unblocks")[0].from_node_id, hNode.node_id);
    assert.equal(edgesByKind.get("unblocks")[0].to_node_id, tNode.node_id);
  });
});

// ─── Determinism: identical event log → identical graph_hash (3×) ────────

test("graph_hash is byte-identical across 3 re-materializations of the same event log", () => {
  withTempHome(() => {
    const domain = "x2-determinism.example.com";
    seedFourKindFixture(domain);
    const first = materializeTaskGraph(domain, {
      now: new Date("2026-05-31T03:00:00.000Z"),
    });
    const second = materializeTaskGraph(domain, {
      now: new Date("2026-05-31T03:01:00.000Z"),
    });
    const third = materializeTaskGraph(domain, {
      now: new Date("2026-05-31T03:02:00.000Z"),
    });
    assert.equal(first.document.hashes.graph_hash, second.document.hashes.graph_hash);
    assert.equal(second.document.hashes.graph_hash, third.document.hashes.graph_hash);
    assert.equal(first.document.hashes.nodes_hash, third.document.hashes.nodes_hash);
    assert.equal(first.document.hashes.edges_hash, third.document.hashes.edges_hash);
  });
});

test("graph_hash binds nodes_hash + edges_hash + counts (the X.9 scheduler comparison key)", () => {
  withTempHome(() => {
    const domain = "x2-graph-hash-binding.example.com";
    seedFourKindFixture(domain);
    const baseline = materializeTaskGraph(domain).document;
    // Append a new transition proposal; this should shift edges and the
    // graph_hash should change accordingly.
    appendTransitionProposal({
      target_domain: domain,
      from_surface: "surface:web-auth",
      to_surface: "surface:evm-vault",
      kind: "value_movement",
      trust_assumption: "Different transition.",
      proposal_id: "TP-value-flow",
      ts: "2026-05-31T01:30:00.000Z",
    });
    const after = materializeTaskGraph(domain).document;
    assert.notEqual(baseline.hashes.graph_hash, after.hashes.graph_hash);
    assert.notEqual(baseline.hashes.nodes_hash, after.hashes.nodes_hash);
    assert.notEqual(baseline.hashes.edges_hash, after.hashes.edges_hash);
  });
});

// ─── Summary view: covers all 4 node kinds + failure_reason surfacing ───

test("summarizeTaskGraph reports per-state + per-kind counts + cross-stack transitions", () => {
  withTempHome(() => {
    const domain = "x2-summary.example.com";
    seedFourKindFixture(domain);
    const summary = summarizeTaskGraph(domain);

    assert.equal(summary.kind_counts.surface, 2);
    assert.equal(summary.kind_counts.hypothesis, 1);
    assert.equal(summary.kind_counts.transition, 1);
    assert.equal(summary.kind_counts.claim, 1);

    // Surface + Claim are still at the synthetic "proposed" default state.
    // The transition reached "ready". The hypothesis reached "finalized".
    assert.equal(summary.state_counts.proposed, 3);
    assert.equal(summary.state_counts.ready, 1);
    assert.equal(summary.state_counts.finalized, 1);

    // Cross-stack transition surfaced.
    assert.equal(summary.cross_stack_transitions.length, 1);
    assert.deepEqual(
      summary.cross_stack_transitions[0].surface_refs,
      ["surface:evm-vault", "surface:web-auth"],
    );

    // Open Hypotheses: the seeded one transitioned to finalized so summary
    // sees zero open hypotheses.
    assert.equal(summary.open_hypotheses.length, 0);

    // Recent finalization recorded.
    assert.equal(summary.recent_finalizations.length, 1);

    // Ready node surfaced (the transition node).
    assert.equal(summary.ready_nodes.length, 1);
    assert.equal(summary.ready_nodes[0].kind, "transition");
  });
});

test("summarizeTaskGraph surfaces the most recent structured failure_reason per failed node", () => {
  withTempHome(() => {
    const domain = "x2-failure-summary.example.com";
    appendHypothesisProposal({
      target_domain: domain,
      hypothesis_statement: "Reentrancy guard bypassed via inner delegatecall.",
      surface_refs: ["surface:lending-vault"],
      proposal_id: "HP-reent",
      ts: "2026-05-31T04:00:00.000Z",
    });
    const hNodeId = hypothesisNodeId({ proposalId: "HP-reent" });
    appendNodeTransition({
      target_domain: domain,
      node_id: hNodeId,
      from_state: "proposed",
      to_state: "contracted",
      contract_hash: "contract-sha-x",
      ts: "2026-05-31T04:00:01.000Z",
    });
    appendNodeTransition({
      target_domain: domain,
      node_id: hNodeId,
      from_state: "contracted",
      to_state: "ready",
      ts: "2026-05-31T04:00:02.000Z",
    });
    appendNodeTransition({
      target_domain: domain,
      node_id: hNodeId,
      from_state: "ready",
      to_state: "dispatched",
      // prep_token elided per the seed comment in seedFourKindFixture; X.8
      // owns the dispatched-state prep_token binding.
      ts: "2026-05-31T04:00:03.000Z",
    });
    appendNodeTransition({
      target_domain: domain,
      node_id: hNodeId,
      from_state: "dispatched",
      to_state: "failed",
      failure_reason: {
        code: "relation_did_not_hold",
        witness_id: "W-1",
        left_value: "0xATTACKER",
        right_value: "0xVICTIM",
        left_artifact_ref: "http_record:R7",
        right_artifact_ref: "evm_call:T9",
      },
      ts: "2026-05-31T04:00:04.000Z",
    });

    const summary = summarizeTaskGraph(domain);
    assert.equal(summary.failed_nodes.length, 1);
    const failed = summary.failed_nodes[0];
    assert.equal(failed.node_id, hNodeId);
    assert.equal(failed.kind, "hypothesis");
    assert.equal(failed.failure_reason.code, "relation_did_not_hold");
    assert.equal(failed.failure_reason.witness_id, "W-1");
    assert.equal(failed.failure_reason.left_value, "0xATTACKER");
    assert.equal(failed.failure_reason.right_value, "0xVICTIM");
    assert.equal(failed.failure_reason.left_artifact_ref, "http_record:R7");
    assert.equal(failed.failure_reason.right_artifact_ref, "evm_call:T9");
  });
});

// ─── Raw view filters ────────────────────────────────────────────────────

test("readTaskGraph view: raw supports kind/state/node_id filters", () => {
  withTempHome(() => {
    const domain = "x2-filters.example.com";
    seedFourKindFixture(domain);
    const allHyp = readTaskGraph(domain, { filters: { kind: "hypothesis" } });
    assert.equal(allHyp.node_count, 1);
    assert.equal(allHyp.nodes[0].kind, "hypothesis");

    const readyNodes = readTaskGraph(domain, { filters: { state: "ready" } });
    assert.equal(readyNodes.node_count, 1);
    assert.equal(readyNodes.nodes[0].state, "ready");

    const oneId = readTaskGraph(domain, {
      filters: { node_id: surfaceNodeId("surface:web-auth") },
    });
    assert.equal(oneId.node_count, 1);
    assert.equal(oneId.nodes[0].node_id, surfaceNodeId("surface:web-auth"));
  });
});

// ─── Ledger-pressure guardrail (Do step 5 + X-R1) ────────────────────────
//
// The materializer reads frontier-events.jsonl directly via readFrontierEvents.
// Seeding 12k–18k events through the appender would be slow (lock contention,
// per-event hashing, debounce hook fan-out). Instead we synthesize a JSONL
// file with `count` already-canonical events and let the materializer read it
// like any real session. This isolates the threshold logic from the appender's
// throughput and keeps the test in the millisecond range.

const {
  normalizeFrontierEvent,
} = require("../mcp/lib/frontier-events.js");

function fabricateLargeLedger(domain, count) {
  const sessionRoot = path.dirname(frontierEventsJsonlPath(domain));
  fs.mkdirSync(sessionRoot, { recursive: true });
  const target = frontierEventsJsonlPath(domain);
  const lines = new Array(count);
  // Pre-normalize one event template so every record has a stable shape.
  // Vary `ts` per index so event_id (and event_hash) differ and the JSONL
  // file looks like a real ledger.
  for (let i = 0; i < count; i++) {
    const event = normalizeFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: new Date(1_700_000_000_000 + i).toISOString(),
      surface_id: "surface:pressure-probe",
      payload: { note: `pressure-${i}` },
    });
    lines[i] = JSON.stringify(event);
  }
  fs.writeFileSync(target, lines.join("\n") + "\n", "utf8");
}

test("ledger pressure warning fires at WARN threshold and stays under refuse threshold", () => {
  withTempHome(() => {
    const domain = "x2-pressure-warn.example.com";
    fabricateLargeLedger(domain, LEDGER_PRESSURE_WARN_THRESHOLD);
    const result = materializeTaskGraph(domain);
    assert.ok(result.ledgerPressureWarning, "warning emitted at warn threshold");
    assert.equal(result.ledgerPressureWarning.code, "graph_ledger_pressure");
    assert.equal(result.ledgerPressureWarning.event_count, LEDGER_PRESSURE_WARN_THRESHOLD);
    assert.deepEqual(result.document.warnings, [result.ledgerPressureWarning]);
  });
});

test("no ledger pressure warning emitted below the WARN threshold", () => {
  withTempHome(() => {
    const domain = "x2-pressure-below.example.com";
    fabricateLargeLedger(domain, LEDGER_PRESSURE_WARN_THRESHOLD - 1);
    const result = materializeTaskGraph(domain);
    assert.equal(result.ledgerPressureWarning, null, "no warning below threshold");
    assert.ok(result.document.warnings == null || result.document.warnings.length === 0);
  });
});

test("ledger pressure refusal fires at REFUSE threshold with structured details", () => {
  withTempHome(() => {
    const domain = "x2-pressure-refuse.example.com";
    fabricateLargeLedger(domain, LEDGER_PRESSURE_REFUSE_THRESHOLD);
    let caught = null;
    try {
      materializeTaskGraph(domain);
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "must refuse");
    assert.equal(caught.code, "ledger_pressure_refusal");
    assert.equal(caught.details.event_count, LEDGER_PRESSURE_REFUSE_THRESHOLD);
    assert.equal(caught.details.refuse_threshold, LEDGER_PRESSURE_REFUSE_THRESHOLD);
    assert.equal(caught.details.warn_threshold, LEDGER_PRESSURE_WARN_THRESHOLD);
    // The task-graph.json file must NOT have been written when refusal fires.
    assert.equal(fs.existsSync(taskGraphPath(domain)), false);
  });
});

// ─── Debounce hook integration (Do step 2) ───────────────────────────────

test("scheduleMaterialization release fold writes BOTH surface-index.json AND task-graph.json", () => {
  withTempHome((home) => {
    const domain = "x2-debounce.example.com";
    // Seed enough state for both materializers to write meaningful views.
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-31T05:00:00.000Z",
      surface_id: "surface:debounce-target",
      payload: { title: "Debounce target" },
    });
    withSessionLock(domain, () => {
      appendHypothesisProposal({
        target_domain: domain,
        hypothesis_statement: "Test hypothesis for debounce.",
        surface_refs: ["surface:debounce-target"],
        proposal_id: "HP-debounce",
      });
      scheduleMaterialization(domain);
      assert.deepEqual(pendingDomains(), [domain], "dirty until lock release");
    });
    const expectedRoot = path.join(home, "hacker-bob-sessions", domain);
    assert.equal(
      fs.existsSync(path.join(expectedRoot, "surface-index.json")),
      true,
      "surface-index.json written by F.2 hook",
    );
    assert.equal(
      fs.existsSync(path.join(expectedRoot, "task-graph.json")),
      true,
      "task-graph.json written by X.2 hook",
    );
    const taskGraph = JSON.parse(fs.readFileSync(path.join(expectedRoot, "task-graph.json"), "utf8"));
    // Folded the surface + the hypothesis.
    assert.equal(taskGraph.node_count, 2);
  });
});

// ─── Tool wiring (bob_materialize_task_graph + bob_read_task_graph) ──────

test("bob_materialize_task_graph tool writes task-graph.json and returns hashes", () => {
  withTempHome(() => {
    const domain = "x2-tool-mat.example.com";
    seedFourKindFixture(domain);
    const handler = TOOL_HANDLERS.bob_materialize_task_graph;
    assert.equal(typeof handler, "function");
    const raw = handler({ target_domain: domain });
    const out = JSON.parse(raw);
    assert.equal(out.target_domain, domain);
    assert.ok(typeof out.hashes.graph_hash === "string");
    assert.ok(out.node_count >= 4);
    assert.ok(out.edge_count >= 1);
    assert.equal(fs.existsSync(taskGraphPath(domain)), true);
  });
});

test("bob_read_task_graph view=summary returns the summary shape", () => {
  withTempHome(() => {
    const domain = "x2-tool-read-sum.example.com";
    seedFourKindFixture(domain);
    const handler = TOOL_HANDLERS.bob_read_task_graph;
    const raw = handler({ target_domain: domain, view: "summary" });
    const summary = JSON.parse(raw);
    assert.ok(summary.state_counts);
    assert.ok(summary.kind_counts);
    assert.ok(Array.isArray(summary.ready_nodes));
    assert.ok(Array.isArray(summary.failed_nodes));
    assert.ok(Array.isArray(summary.cross_stack_transitions));
  });
});

test("bob_read_task_graph view=raw with filters returns the filtered nodes", () => {
  withTempHome(() => {
    const domain = "x2-tool-read-raw.example.com";
    seedFourKindFixture(domain);
    const handler = TOOL_HANDLERS.bob_read_task_graph;
    const raw = JSON.parse(handler({
      target_domain: domain,
      view: "raw",
      filters: { kind: "transition" },
    }));
    assert.equal(raw.node_count, 1);
    assert.equal(raw.nodes[0].kind, "transition");
    // Edges are NOT filtered (the X.5 walk still needs them); verify that
    // claim.
    assert.ok(raw.edges.length >= 1);
  });
});

test("bob_read_task_graph refuses an unknown view value", () => {
  withTempHome(() => {
    const handler = TOOL_HANDLERS.bob_read_task_graph;
    assert.throws(
      () => handler({ target_domain: "x2-bad-view.example.com", view: "garbage" }),
      /view must be one of/,
    );
  });
});

// ─── Node id namespace disambiguation per pre-flight finding ─────────────

test("TaskGraph node ids never collide with mcp/lib/surface-graph.js node ids", () => {
  // The pre-flight sweep called out that mcp/lib/surface-graph.js uses bare
  // `node_id` strings for a separate adjacency graph. The TG- prefix is the
  // contract that prevents cross-tool joins from confusing the two
  // namespaces.
  const samples = [
    surfaceNodeId("surface:billing"),
    hypothesisNodeId({ proposalId: "HP-x" }),
    transitionNodeId({ proposalId: "TP-x" }),
    claimNodeId("F-1"),
  ];
  for (const id of samples) {
    assert.ok(id.startsWith(TASK_GRAPH_NODE_ID_PREFIX), `${id} must start with TG-`);
  }
});

// ─── claim.candidate.linked routes through the claim_links edge ─────────

test("claim.candidate.linked events emit a claim node + claim_links edge from surface", () => {
  withTempHome(() => {
    const domain = "x2-claim-link.example.com";
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-31T06:00:00.000Z",
      surface_id: "surface:billing",
      payload: { title: "Billing" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "claim.candidate.linked",
      ts: "2026-05-31T06:00:01.000Z",
      surface_id: "surface:billing",
      claim_id: "F-42",
      payload: {},
    });
    const result = materializeTaskGraph(domain).document;
    const claim = result.nodes.find((n) => n.kind === "claim");
    assert.ok(claim, "claim node folded");
    assert.equal(claim.node_id, claimNodeId("F-42"));
    const edge = result.edges.find((e) => e.edge_kind === "claim_links");
    assert.ok(edge, "claim_links edge emitted");
    assert.equal(edge.from_node_id, surfaceNodeId("surface:billing"));
    assert.equal(edge.to_node_id, claimNodeId("F-42"));
  });
});

test("summarizeTaskGraph reports composition telemetry and marks a composed graph composed=true", () => {
  withTempHome(() => {
    const domain = "composition-composed.example.com";
    seedFourKindFixture(domain);
    const summary = summarizeTaskGraph(domain);
    assert.ok(summary.composition, "composition section present");
    assert.equal(summary.composition.surfaces, 2);
    assert.equal(summary.composition.hypotheses, 1);
    assert.equal(summary.composition.transitions, 1);
    assert.equal(summary.composition.claims, 1);
    assert.equal(summary.composition.composed, true);
    assert.equal(summary.composition.hypotheses_per_surface, 0.5);
    assert.equal(summary.composition.transitions_per_hypothesis, 1);
  });
});

test("a wide-and-flat graph (surfaces only) reports composed=false with zero composition rates", () => {
  withTempHome(() => {
    const domain = "composition-wide-flat.example.com";
    for (let i = 1; i <= 3; i += 1) {
      appendFrontierEvent({
        target_domain: domain,
        kind: "surface.observed",
        ts: `2026-05-31T01:00:0${i}.000Z`,
        surface_id: `surface:s${i}`,
        payload: { title: `S${i}`, surface_type: "web" },
      });
    }
    const summary = summarizeTaskGraph(domain);
    assert.equal(summary.composition.surfaces, 3);
    assert.equal(summary.composition.hypotheses, 0);
    assert.equal(summary.composition.transitions, 0);
    assert.equal(summary.composition.composed, false);
    assert.equal(summary.composition.hypotheses_per_surface, 0);
    assert.equal(summary.composition.transitions_per_hypothesis, 0);
  });
});

test("composition telemetry is summary-only and is never persisted into the hash-bound graph document", () => {
  withTempHome(() => {
    const domain = "composition-not-persisted.example.com";
    seedFourKindFixture(domain);
    materializeTaskGraph(domain, { write: true });
    const persisted = JSON.parse(fs.readFileSync(taskGraphPath(domain), "utf8"));
    assert.equal("composition" in persisted, false, "composition must not enter the hash-bound document");
  });
});
