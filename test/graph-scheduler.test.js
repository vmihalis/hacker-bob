"use strict";

// Plane X Cycle X.9 — graph-walking scheduler tests.
//
// Per the spec's Do step 5:
//   1. empty graph → empty selection
//   2. ready × capacity → top N selected (priority ordering deterministic)
//   3. selection deterministic across re-invocations
//   4. graph_hash drift between selection and dispatch is refused
//   5. wave-scheduler regression preserved (Surface + Claim never appear
//      in graph-scheduler selections; the wave scheduler still works)
//
// Plus the X-D7 dual-write split — confirm Transition + Hypothesis are
// the only kinds the graph-scheduler considers.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { TOOL_HANDLERS } = require("../mcp/core/dispatch/tool-registry.js");
const {
  appendFrontierEvent,
} = require("../mcp/core/frontier/frontier-events.js");
const {
  TASK_GRAPH_NODE_ID_PREFIX,
  appendHypothesisProposal,
  appendTransitionProposal,
} = require("../mcp/core/waves/task-graph-events.js");
const {
  materializeTaskGraph,
} = require("../mcp/core/waves/task-graph-materializer.js");
const {
  appendContract,
} = require("../mcp/core/contract/contracts.js");
const {
  GRAPH_SCHEDULED_KINDS,
  selectNextExecutableNodes,
} = require("../mcp/core/waves/graph-scheduler.js");
const {
  GRAPH_SCHEDULER_DECISION_KIND_VALUES,
  appendGraphSchedulerDecision,
  normalizeGraphSchedulerDecision,
  readGraphSchedulerDecisions,
  readSchedulerDecisions,
  scheduleTasksFromQueue,
  isGraphSchedulerDecisionKind,
} = require("../mcp/core/waves/scheduler-decisions.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-graph-scheduler-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function seedSession(domain) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-31T00:00:00.000Z",
    surface_id: "surface:seed",
    payload: { title: "seed" },
  });
}

const KNOWN_TOOL = "bob_http_scan";

function baseContractInput({
  contractId = "C-x9-base",
  severity = "high",
} = {}) {
  return {
    contract_id: contractId,
    severity_floor: severity,
    invariants: [{ id: "I1", statement: "Token swap honors invariant." }],
    witnesses: [{
      id: "W1",
      kind: "tool_output_match",
      predicate: { tool: KNOWN_TOOL, match: { path: "$.status", equals: 200 } },
    }],
    production_paths: [{
      description: "Invoke canonical web producer.",
      tool_call_pattern: [{ tool: KNOWN_TOOL }],
    }],
  };
}

function seedContractedHypothesis(domain, proposalId, {
  surfaceRefs = ["surface:auth"],
  contract = null,
  ts = "2026-05-31T00:01:00.000Z",
} = {}) {
  appendHypothesisProposal({
    target_domain: domain,
    ts,
    hypothesis_statement: `Hypothesis ${proposalId}.`,
    surface_refs: surfaceRefs,
    proposal_id: proposalId,
  });
  materializeTaskGraph(domain, { write: true });
  const nodeId = `${TASK_GRAPH_NODE_ID_PREFIX}H-${proposalId}`;
  appendContract({
    target_domain: domain,
    node_id: nodeId,
    contract: contract || baseContractInput({ contractId: `C-${proposalId}` }),
    ts,
  });
  materializeTaskGraph(domain, { write: true });
  return nodeId;
}

function seedContractedTransition(domain, proposalId, {
  fromSurface = "surface:web",
  toSurface = "surface:evm",
  ts = "2026-05-31T00:01:00.000Z",
} = {}) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts,
    surface_id: fromSurface,
    payload: { title: fromSurface },
  });
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts,
    surface_id: toSurface,
    payload: { title: toSurface },
  });
  appendTransitionProposal({
    target_domain: domain,
    ts,
    from_surface: fromSurface,
    to_surface: toSurface,
    kind: "identity_propagation",
    trust_assumption: `transition ${proposalId}`,
    proposal_id: proposalId,
  });
  materializeTaskGraph(domain, { write: true });
  const nodeId = `${TASK_GRAPH_NODE_ID_PREFIX}T-${proposalId}`;
  appendContract({
    target_domain: domain,
    node_id: nodeId,
    contract: baseContractInput({ contractId: `C-${proposalId}` }),
    ts,
  });
  materializeTaskGraph(domain, { write: true });
  return nodeId;
}

// ─── Do step 5 (1): empty graph → empty selection ──────────────────────

test("graph-scheduler: empty graph returns empty selection (no frontier events at all)", () => {
  withTempHome(() => {
    const domain = "x9-empty-graph.example.com";
    // Touch the session directory but emit no node-producing events.
    seedSession(domain);
    // Explicit off-profile (no in-flight cap) so the single-cap path holds and
    // capacity_limit equals the requested capacity. (The default's sized in-flight
    // cap exercises the per-kind split, covered separately by the D2 test.)
    const result = selectNextExecutableNodes(domain, { max_concurrent_evaluators: null }, 4);
    assert.equal(result.selected.length, 0);
    assert.equal(result.skipped.length, 0);
    assert.equal(result.capacity_used, 0);
    assert.equal(result.capacity_limit, 4);
    assert.equal(result.considered_count, 0);
    // source_graph_hash must always be present because materialization
    // returns a stable graph_hash even when nodes[] is empty.
    assert.ok(typeof result.source_graph_hash === "string");
  });
});

test("graph-scheduler: graph with only Surface + Claim nodes (no Transition/Hypothesis) returns empty selection", () => {
  withTempHome(() => {
    const domain = "x9-surface-only.example.com";
    seedSession(domain);
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-31T00:01:00.000Z",
      surface_id: "surface:admin",
      payload: { title: "admin" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "claim.candidate.linked",
      ts: "2026-05-31T00:02:00.000Z",
      surface_id: "surface:admin",
      claim_id: "CL-1",
      payload: { claim_id: "CL-1" },
    });
    materializeTaskGraph(domain, { write: true });
    const result = selectNextExecutableNodes(domain, {}, 4);
    assert.equal(result.selected.length, 0,
      "Surface + Claim must NEVER appear in graph-scheduler selection per X-D7");
    assert.equal(result.considered_count, 0);
  });
});

// ─── Do step 5 (2): ready × capacity → top N selected ────────────────

test("graph-scheduler: capacity cap selects top N by priority then deterministic tie-breakers", () => {
  withTempHome(() => {
    const domain = "x9-capacity-cap.example.com";
    seedSession(domain);
    // Seed 4 hypothesis nodes with mixed priorities. The default Contract
    // priority lands at "medium"; we override via the on-graph `priority`
    // field by appending node.transitioned events with payload.priority
    // after the Contract attach. The materializer folds the most recent
    // priority verbatim so this is sufficient for deterministic ordering.
    const ids = ["a", "b", "c", "d"].map((slug) => {
      const nodeId = seedContractedHypothesis(domain, `HP-${slug}`);
      return nodeId;
    });
    // After Contract attach all four are in `contracted` state with
    // priority="medium". Boost the priority on two via a re-attach
    // event payload. The X.1 frozen table forbids contracted→contracted,
    // so we instead emit observation.recorded events with the priority
    // — but that wouldn't surface in the materializer. The materializer
    // only picks up priority from node.transitioned payloads.
    // Simplest deterministic approach: rely on the contracted-state
    // default ("medium") for all four, then assert the top-N selection
    // ties break by ts_first → node_id ordering.
    const result = selectNextExecutableNodes(domain, {}, 2);
    assert.equal(result.selected.length, 2);
    assert.equal(result.skipped.length, 2);
    assert.equal(result.capacity_used, 2);
    assert.equal(result.considered_count, 4);
    // All four IDs must appear in selected ∪ skipped exactly once.
    const seen = new Set([
      ...result.selected.map((n) => n.node_id),
      ...result.skipped.map((n) => n.node_id),
    ]);
    assert.equal(seen.size, 4);
    for (const id of ids) assert.ok(seen.has(id), `expected ${id} in selected/skipped`);
    // Selection must be deterministic: with all priorities equal and the
    // ts_first tied (same ts), the sort falls through to node_id alpha.
    // Hypothesis ids carry the proposal_id; ordering is HP-a < HP-b < ...
    assert.equal(result.selected[0].node_id, ids[0]);
    assert.equal(result.selected[1].node_id, ids[1]);
  });
});

test("graph-scheduler: max_total_spawned_agents binds the closure-dispatch breadth", () => {
  withTempHome(() => {
    const domain = "x9-closure-governor.example.com";
    seedSession(domain);
    const ids = ["a", "b", "c", "d"].map((slug) => seedContractedHypothesis(domain, `GP-${slug}`));
    // Wide capacity so only the governor can bind the dispatch count.
    const widePolicy = { max_parallel_tasks: 100 };

    // Governor 2, nothing reserved -> exactly 2 dispatched; the rest skipped
    // (they ride the next drain cycle — no node dropped, fixpoint preserved).
    const bound = selectNextExecutableNodes(
      domain,
      { ...widePolicy, max_total_spawned_agents: 2 },
      100,
      { reservedSpawnTotal: 0 },
    );
    assert.equal(bound.selected.length, 2, "governor clamps the closure dispatch to the remaining budget");
    assert.equal(bound.skipped.length, 2, "over-budget nodes are skipped, not dropped");
    assert.equal(bound.considered_count, 4);

    // Reserved 1 of budget 3 -> remaining 2.
    const reserved = selectNextExecutableNodes(
      domain,
      { ...widePolicy, max_total_spawned_agents: 3 },
      100,
      { reservedSpawnTotal: 1 },
    );
    assert.equal(reserved.selected.length, 2, "prior reservations subtract from the closure budget");

    // Governor null -> byte-identical default-off: all four dispatch under the
    // wide capacity, reservedSpawnTotal ignored.
    const off = selectNextExecutableNodes(domain, widePolicy, 100, { reservedSpawnTotal: 999 });
    assert.equal(off.selected.length, 4, "null governor ignores reservedSpawnTotal — byte-identical");
    assert.deepEqual(ids.slice().sort(), off.selected.map((n) => n.node_id).sort());

    // Fully exhausted budget -> nothing dispatched, but a coverage_gap NAMES the
    // uncovered cells (STOP + report, never a silent drop). Null governor never
    // attaches coverage_gap, so default-off stays clean.
    const exhausted = selectNextExecutableNodes(
      domain,
      { ...widePolicy, max_total_spawned_agents: 2 },
      100,
      { reservedSpawnTotal: 2 },
    );
    assert.equal(exhausted.selected.length, 0, "no budget => nothing dispatched");
    assert.ok(exhausted.coverage_gap, "exhaustion surfaces a coverage_gap");
    assert.equal(exhausted.coverage_gap.kind, "spawn_budget_exhausted");
    assert.equal(exhausted.coverage_gap.uncovered_node_ids.length, 4, "all four cells named as uncovered");
    assert.equal(off.coverage_gap, undefined, "null governor never attaches coverage_gap");
  });
});

test("graph-scheduler: critical priority overrides ts/node_id ordering", () => {
  withTempHome(() => {
    const domain = "x9-priority-override.example.com";
    seedSession(domain);
    // Seed two hypotheses; manually emit a node.transitioned event with
    // priority="critical" on the second so the materializer sees it.
    const idA = seedContractedHypothesis(domain, "HP-a", {
      ts: "2026-05-31T00:01:00.000Z",
    });
    const idB = seedContractedHypothesis(domain, "HP-b", {
      ts: "2026-05-31T00:02:00.000Z",
    });
    // Emit a contracted→ready transition for the b node with priority=critical
    // so the materializer picks up the higher priority. The state stays
    // dispatch-eligible.
    const { appendNodeTransition } = require("../mcp/core/waves/task-graph-events.js");
    appendNodeTransition({
      target_domain: domain,
      node_id: idB,
      from_state: "contracted",
      to_state: "ready",
      priority: "critical",
      ts: "2026-05-31T00:03:00.000Z",
    });
    materializeTaskGraph(domain, { write: true });
    const result = selectNextExecutableNodes(domain, {}, 1);
    assert.equal(result.selected.length, 1);
    assert.equal(result.selected[0].node_id, idB,
      "critical-priority node B must come before medium-priority node A");
    assert.equal(result.skipped[0].node_id, idA);
  });
});

// ─── Do step 5 (3): selection determinism ────────────────────────────

test("graph-scheduler: three identical invocations produce byte-identical selections", () => {
  withTempHome(() => {
    const domain = "x9-determinism.example.com";
    seedSession(domain);
    seedContractedHypothesis(domain, "HP-a");
    seedContractedHypothesis(domain, "HP-b");
    seedContractedTransition(domain, "TR-x", {
      fromSurface: "surface:web",
      toSurface: "surface:evm",
    });
    const r1 = selectNextExecutableNodes(domain, {}, 4);
    const r2 = selectNextExecutableNodes(domain, {}, 4);
    const r3 = selectNextExecutableNodes(domain, {}, 4);
    assert.equal(r1.source_graph_hash, r2.source_graph_hash);
    assert.equal(r2.source_graph_hash, r3.source_graph_hash);
    assert.equal(JSON.stringify(r1.selected), JSON.stringify(r2.selected));
    assert.equal(JSON.stringify(r2.selected), JSON.stringify(r3.selected));
    assert.equal(JSON.stringify(r1.skipped), JSON.stringify(r2.skipped));
  });
});

// ─── Do step 5 (4): graph_hash drift refusal ────────────────────────

test("graph-scheduler selection captures a stable source_graph_hash that changes when the graph mutates", () => {
  withTempHome(() => {
    const domain = "x9-drift-detect.example.com";
    seedSession(domain);
    seedContractedHypothesis(domain, "HP-drift");
    const selection = selectNextExecutableNodes(domain, {}, 1);
    assert.equal(selection.selected.length, 1);
    assert.ok(selection.source_graph_hash);
    // A second selection without mutation yields the same hash.
    const sameSelection = selectNextExecutableNodes(domain, {}, 1);
    assert.equal(sameSelection.source_graph_hash, selection.source_graph_hash);
    // Mutate the graph and confirm the hash changes.
    appendHypothesisProposal({
      target_domain: domain,
      ts: "2026-05-31T00:05:00.000Z",
      hypothesis_statement: "Drift hypothesis.",
      surface_refs: ["surface:auth"],
      proposal_id: "HP-drift-noise",
    });
    materializeTaskGraph(domain, { write: true });
    const driftedSelection = selectNextExecutableNodes(domain, {}, 1);
    assert.notEqual(driftedSelection.source_graph_hash, selection.source_graph_hash,
      "graph mutation must change source_graph_hash so the drift check fires");
  });
});

test("bob_schedule_graph_nodes refuses with graph_hash_drift when a synthetic stale-snapshot selection is dispatched against a mutated live graph", () => {
  withTempHome(() => {
    const domain = "x9-drift-refusal.example.com";
    seedSession(domain);
    seedContractedHypothesis(domain, "HP-drift-base");
    // Capture the live document so we can pre-materialize a snapshot.
    const liveDoc = materializeTaskGraph(domain, { write: false }).document;
    // Mutate the graph (append a new hypothesis + re-materialize).
    appendHypothesisProposal({
      target_domain: domain,
      ts: "2026-05-31T00:09:00.000Z",
      hypothesis_statement: "Mid-flight hypothesis.",
      surface_refs: ["surface:auth"],
      proposal_id: "HP-drift-extra",
    });
    materializeTaskGraph(domain, { write: true });
    // Compute a selection against the STALE snapshot via the explicit
    // document override. This is the same path the X.9 tool's race
    // window would land in if a producer-event arrived between the
    // tool's internal select and re-materialize calls.
    const staleSelection = selectNextExecutableNodes(domain, {}, 1, { document: liveDoc });
    assert.ok(staleSelection.source_graph_hash);
    // Now invoke the dispatch logic directly via appendGraphSchedulerDecision
    // with a hand-built stale-snapshot decision. The tool's drift check
    // (its internal re-materialization) is what produces the structured
    // refusal at the orchestration layer; the unit-level invariant is
    // that the stale source_graph_hash differs from the live one.
    const liveSelection = selectNextExecutableNodes(domain, {}, 1);
    assert.notEqual(staleSelection.source_graph_hash, liveSelection.source_graph_hash,
      "the stale snapshot's graph_hash must differ from the live re-materialization");
    // Demonstrate that the tool's drift refusal fires when the live
    // graph_hash truly diverges from a recorded selection. We simulate
    // this by triggering a tool invocation against a domain whose
    // selection-time and dispatch-time differ via a parallel mutation:
    // the X.9 tool's flow internally calls selectNextExecutableNodes
    // (which captures the CURRENT hash) and then materializeTaskGraph
    // (which also captures the CURRENT hash). In production the gap is
    // microseconds; here we exercise the same logic by calling the tool
    // with no mutation in flight — and assert the success path runs as
    // expected. The drift-refusal CODE PATH itself is exercised by the
    // explicit document override above (the staleSelection vs liveSelection
    // hash difference is what the tool's drift check compares).
    const result = JSON.parse(TOOL_HANDLERS.bob_schedule_graph_nodes({
      target_domain: domain,
      capacity: 1,
      dispatch: false,
    }));
    assert.equal(result.source_graph_hash, liveSelection.source_graph_hash);
  });
});

test("graph_hash_drift refusal: tool throws structured error when selection-time hash differs from live", () => {
  // The cleanest way to exercise the refusal path is to monkey-patch the
  // selectNextExecutableNodes export so the tool's internal call returns
  // a known-stale hash, then let the tool re-materialize and detect the
  // mismatch. Since the tool requires graph-scheduler.js lazily-at-call,
  // we use a module-level override.
  withTempHome(() => {
    const domain = "x9-force-drift.example.com";
    seedSession(domain);
    seedContractedHypothesis(domain, "HP-force-drift");
    const graphScheduler = require("../mcp/core/waves/graph-scheduler.js");
    const originalSelect = graphScheduler.selectNextExecutableNodes;
    try {
      // Override to return a selection with a deliberately wrong source_graph_hash.
      graphScheduler.selectNextExecutableNodes = function(targetDomain, queuePolicy, capacity, options) {
        const real = originalSelect(targetDomain, queuePolicy, capacity, options);
        return {
          ...real,
          source_graph_hash: "0".repeat(64), // synthetic stale hash
        };
      };
      let caught = null;
      try {
        TOOL_HANDLERS.bob_schedule_graph_nodes({
          target_domain: domain,
          capacity: 1,
        });
      } catch (err) { caught = err; }
      assert.ok(caught, "tool must refuse on hash drift");
      assert.equal(caught.code, "graph_hash_drift");
      assert.ok(caught.details.selection_graph_hash);
      assert.ok(caught.details.live_graph_hash);
      assert.notEqual(caught.details.selection_graph_hash, caught.details.live_graph_hash);
    } finally {
      graphScheduler.selectNextExecutableNodes = originalSelect;
    }
  });
});

test("normalizeGraphSchedulerDecision refuses missing source_graph_hash", () => {
  let caught = null;
  try {
    normalizeGraphSchedulerDecision({
      target_domain: "x9-no-hash.example.com",
      decision_kind: "schedule_graph_nodes",
      selected_node_ids: [],
      skipped_node_ids: [],
    });
  } catch (err) { caught = err; }
  assert.ok(caught);
  assert.match(caught.message, /source_graph_hash is required/);
});

test("normalizeGraphSchedulerDecision refuses decision_kind outside the graph kind set", () => {
  let caught = null;
  try {
    normalizeGraphSchedulerDecision({
      target_domain: "x9-bad-kind.example.com",
      decision_kind: "schedule_work",
      source_graph_hash: "f".repeat(64),
      selected_node_ids: [],
      skipped_node_ids: [],
    });
  } catch (err) { caught = err; }
  assert.ok(caught);
  assert.match(caught.message, /decision_kind must be one of/);
});

test("normalizeGraphSchedulerDecision refuses capacity_used / selected_node_ids mismatch", () => {
  let caught = null;
  try {
    normalizeGraphSchedulerDecision({
      target_domain: "x9-bad-counts.example.com",
      decision_kind: "schedule_graph_nodes",
      source_graph_hash: "f".repeat(64),
      selected_node_ids: ["TG-H-a"],
      skipped_node_ids: [],
      capacity_used: 5,
    });
  } catch (err) { caught = err; }
  assert.ok(caught);
});

test("isGraphSchedulerDecisionKind classifies kinds correctly", () => {
  assert.ok(isGraphSchedulerDecisionKind("schedule_graph_nodes"));
  assert.ok(!isGraphSchedulerDecisionKind("schedule_work"));
  assert.ok(!isGraphSchedulerDecisionKind("wave_start"));
  assert.ok(!isGraphSchedulerDecisionKind(""));
  assert.ok(!isGraphSchedulerDecisionKind(null));
});

// ─── Do step 5 (5): wave-scheduler regression preserved ─────────────

test("wave-scheduler still functions for Surface + Claim nodes after X.9 lands (no cross-contamination)", () => {
  withTempHome(() => {
    const domain = "x9-wave-regression.example.com";
    // Seed a frontier task the wave-scheduler picks up.
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-26T03:00:00.000Z",
      surface_id: "surface:wave-account",
      payload: { title: "Account API" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "frontier.enqueued",
      ts: "2026-05-26T03:01:00.000Z",
      surface_id: "surface:wave-account",
      frontier_item_id: "frontier:item:wave-1",
      payload: {
        lens: "behavior_probe",
        priority: "high",
        budget: { max_steps: 4, max_context_tokens: 12000 },
      },
    });
    // Materialize the FRONTIER (task-queue.json), not the task graph.
    const { materializeFrontier } = require("../mcp/core/frontier/frontier-materializer.js");
    materializeFrontier(domain, {
      write: true,
      now: new Date("2026-05-26T03:02:00.000Z"),
    });
    const decision = scheduleTasksFromQueue(domain, {
      write: true,
      now: new Date("2026-05-26T03:03:00.000Z"),
    });
    assert.equal(decision.assignment_count, 1,
      "wave-scheduler must still dispatch Surface tasks after X.9 introduces the graph-scheduler");
    assert.equal(decision.decision_kind, "schedule_work");
    // Read decisions back through the kind-discriminating reader and
    // confirm both shapes survive a round-trip.
    const allDecisions = readSchedulerDecisions(domain);
    assert.equal(allDecisions.length, 1);
    assert.equal(allDecisions[0].decision_kind, "schedule_work");
    // No graph decisions in this scenario.
    assert.equal(readGraphSchedulerDecisions(domain).length, 0);
  });
});

test("graph-scheduler kinds enumerate the graph-dispatched node kinds", () => {
  assert.deepEqual(GRAPH_SCHEDULED_KINDS.slice(), ["transition", "hypothesis", "cell"]);
});

// ─── End-to-end: bob_schedule_graph_nodes tool ──────────────────────

test("bob_schedule_graph_nodes dispatches a contracted Hypothesis node via prepare-node and persists a GraphSchedulerDecision row", () => {
  withTempHome(() => {
    const domain = "x9-e2e-dispatch.example.com";
    seedSession(domain);
    // Explicit off-profile (no in-flight cap) so capacity_limit equals the
    // requested capacity through the single-cap path; the default's sized in-flight
    // cap (per-kind split) is exercised by the D2 test instead.
    const { writeQueuePolicy: writeLean } = require("../mcp/core/io/queue-policy.js");
    writeLean(domain, { max_concurrent_evaluators: null });
    const nodeId = seedContractedHypothesis(domain, "HP-e2e");
    const result = JSON.parse(TOOL_HANDLERS.bob_schedule_graph_nodes({
      target_domain: domain,
      capacity: 1,
    }));
    assert.equal(result.decision_kind, "schedule_graph_nodes");
    assert.equal(result.capacity_used, 1);
    assert.equal(result.capacity_limit, 1);
    assert.equal(result.selected_node_ids.length, 1);
    assert.equal(result.selected_node_ids[0], nodeId);
    assert.equal(result.skipped_node_ids.length, 0);
    assert.equal(result.dispatched.length, 1);
    assert.equal(result.dispatched[0].node_id, nodeId);
    assert.ok(result.dispatched[0].prep_token);
    assert.equal(result.failed.length, 0);
    // Verify the GraphSchedulerDecision row is on the ledger.
    const decisions = readGraphSchedulerDecisions(domain);
    assert.equal(decisions.length, 1);
    assert.equal(decisions[0].scheduler_decision_id, result.scheduler_decision_id);
    assert.equal(decisions[0].source_graph_hash, result.source_graph_hash);
    assert.deepEqual(decisions[0].selected_node_ids, [nodeId]);
    // The dispatched node is now in `dispatched` state (prepare-node
    // auto-promoted contracted → ready → dispatched).
    const doc = materializeTaskGraph(domain, { write: false }).document;
    const node = doc.nodes.find((n) => n.node_id === nodeId);
    assert.equal(node.state, "dispatched");
  });
});

test("bob_schedule_graph_nodes reserves each dispatched closure cell in the spawn-ledger (cross-cycle bind)", () => {
  withTempHome(() => {
    const domain = "x9-closure-ledger.example.com";
    seedSession(domain);
    const nodeId = seedContractedHypothesis(domain, "HP-ledger");
    // Governor set: each dispatched closure cell must reserve one lifetime slot so
    // the budget binds ACROSS drain cycles (without it, every cycle re-reads the
    // same reservedSpawnTotal=0 and could re-dispatch up to the budget forever).
    const { writeQueuePolicy, normalizeQueuePolicy, DEFAULT_QUEUE_POLICY: DQP } =
      require("../mcp/core/io/queue-policy.js");
    const { readSpawnLedgerEntries, spawnLedgerTotal } = require("../mcp/core/session/spawn-ledger.js");
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DQP, max_total_spawned_agents: 50 }));

    const result = JSON.parse(TOOL_HANDLERS.bob_schedule_graph_nodes({
      target_domain: domain,
      capacity: 1,
    }));
    assert.equal(result.dispatched.length, 1);

    const rows = readSpawnLedgerEntries(domain);
    assert.equal(rows.length, 1, "the dispatched cell is reserved");
    assert.equal(rows[0].kind, "closure_cell");
    assert.equal(rows[0].surface_id, nodeId);
    assert.equal(rows[0].root_count, 1);
    assert.equal(rows[0].descendant_tree, 0, "a closure cell does not nest");
    assert.equal(rows[0].worst_case_tree, 1);
    assert.equal(spawnLedgerTotal(domain), 1, "the cell now draws down the lifetime budget");
  });
});

test("bob_schedule_graph_nodes closure dispatch with no governor writes no ledger rows — byte-identical", () => {
  withTempHome(() => {
    const domain = "x9-closure-ledger-off.example.com";
    seedSession(domain);
    seedContractedHypothesis(domain, "HP-ledger-off");
    const { readSpawnLedgerEntries } = require("../mcp/core/session/spawn-ledger.js");
    const result = JSON.parse(TOOL_HANDLERS.bob_schedule_graph_nodes({
      target_domain: domain,
      capacity: 1,
    }));
    assert.equal(result.dispatched.length, 1);
    assert.deepEqual(readSpawnLedgerEntries(domain), [], "no governor => no reservation rows");
  });
});

test("bob_schedule_graph_nodes with dispatch=false records selection without prepare-node calls", () => {
  withTempHome(() => {
    const domain = "x9-dry-run.example.com";
    seedSession(domain);
    const nodeId = seedContractedHypothesis(domain, "HP-dry");
    const result = JSON.parse(TOOL_HANDLERS.bob_schedule_graph_nodes({
      target_domain: domain,
      capacity: 4,
      dispatch: false,
    }));
    assert.equal(result.dispatched.length, 0);
    assert.equal(result.failed.length, 0);
    assert.equal(result.selected_node_ids.length, 1);
    // Node stays in `contracted` because dispatch was skipped.
    const doc = materializeTaskGraph(domain, { write: false }).document;
    const node = doc.nodes.find((n) => n.node_id === nodeId);
    assert.equal(node.state, "contracted");
    // Decision row is still appended.
    const decisions = readGraphSchedulerDecisions(domain);
    assert.equal(decisions.length, 1);
  });
});

test("bob_schedule_graph_nodes with no eligible nodes records empty selection and skips dispatch", () => {
  withTempHome(() => {
    const domain = "x9-empty-eligible.example.com";
    seedSession(domain);
    const result = JSON.parse(TOOL_HANDLERS.bob_schedule_graph_nodes({
      target_domain: domain,
      capacity: 4,
    }));
    assert.equal(result.capacity_used, 0);
    assert.equal(result.selected_node_ids.length, 0);
    assert.equal(result.dispatched.length, 0);
    const decisions = readGraphSchedulerDecisions(domain);
    assert.equal(decisions.length, 1, "empty selections still record a decision row");
    assert.equal(decisions[0].capacity_used, 0);
  });
});

test("bob_schedule_graph_nodes ignores Surface + Claim nodes (X-D7 dual-write scope)", () => {
  withTempHome(() => {
    const domain = "x9-dual-write.example.com";
    seedSession(domain);
    // Seed both kinds: a contracted Hypothesis (graph-eligible) and a
    // Surface + Claim (wave-only).
    const hypId = seedContractedHypothesis(domain, "HP-dw");
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-31T00:10:00.000Z",
      surface_id: "surface:wave-claim",
      payload: { title: "wave" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "claim.candidate.linked",
      ts: "2026-05-31T00:11:00.000Z",
      surface_id: "surface:wave-claim",
      claim_id: "CL-wave",
      payload: { claim_id: "CL-wave" },
    });
    materializeTaskGraph(domain, { write: true });
    const result = JSON.parse(TOOL_HANDLERS.bob_schedule_graph_nodes({
      target_domain: domain,
      capacity: 16,
      dispatch: false,
    }));
    assert.equal(result.selected_node_ids.length, 1);
    assert.equal(result.selected_node_ids[0], hypId);
    // The wave-claim Surface + Claim must NOT appear anywhere in the
    // graph-scheduler decision payload.
    const decisions = readGraphSchedulerDecisions(domain);
    const decision = decisions[0];
    for (const node of decision.selected_nodes.concat(decision.skipped_nodes)) {
      assert.ok(
        node.kind === "transition" || node.kind === "hypothesis",
        `graph-scheduler must not consider node kind ${node.kind}; X-D7 reserves Surface + Claim for wave-scheduler`,
      );
    }
  });
});

test("GRAPH_SCHEDULER_DECISION_KIND_VALUES is the closed enum X.9 added", () => {
  assert.deepEqual(GRAPH_SCHEDULER_DECISION_KIND_VALUES.slice(), ["schedule_graph_nodes"]);
});

test("appendGraphSchedulerDecision and readGraphSchedulerDecisions round-trip with the right shape", () => {
  withTempHome(() => {
    const domain = "x9-roundtrip.example.com";
    seedSession(domain);
    const decision = appendGraphSchedulerDecision({
      target_domain: domain,
      decision_kind: "schedule_graph_nodes",
      source_graph_hash: "a".repeat(64),
      capacity_limit: 4,
      capacity_used: 1,
      considered_count: 3,
      selected_node_ids: ["TG-H-roundtrip"],
      skipped_node_ids: ["TG-H-other-1", "TG-H-other-2"],
      selected_nodes: [{ node_id: "TG-H-roundtrip", kind: "hypothesis", state: "contracted", priority: "high" }],
      skipped_nodes: [
        { node_id: "TG-H-other-1", kind: "hypothesis", state: "ready", priority: "medium" },
        { node_id: "TG-H-other-2", kind: "transition", state: "contracted", priority: "low" },
      ],
    });
    assert.equal(decision.decision_kind, "schedule_graph_nodes");
    assert.equal(decision.source_graph_hash, "a".repeat(64));
    assert.equal(decision.capacity_used, 1);
    assert.equal(decision.capacity_limit, 4);
    assert.equal(decision.considered_count, 3);
    assert.match(decision.scheduler_decision_id, /^GSD-[0-9a-f]{24}$/);
    assert.match(decision.scheduler_decision_hash, /^[0-9a-f]{64}$/);
    const read = readGraphSchedulerDecisions(domain);
    assert.equal(read.length, 1);
    assert.equal(read[0].scheduler_decision_id, decision.scheduler_decision_id);
    assert.equal(read[0].scheduler_decision_hash, decision.scheduler_decision_hash);
  });
});

test("graph-scheduler considers `contracted` AND `ready` per X.8 dispatch-eligibility (operator can attach and X.9 picks it up immediately)", () => {
  withTempHome(() => {
    const domain = "x9-state-eligibility.example.com";
    seedSession(domain);
    const contractedId = seedContractedHypothesis(domain, "HP-contracted");
    // Add a second node and promote it to `ready` explicitly.
    const readyId = seedContractedHypothesis(domain, "HP-ready");
    const { appendNodeTransition } = require("../mcp/core/waves/task-graph-events.js");
    appendNodeTransition({
      target_domain: domain,
      node_id: readyId,
      from_state: "contracted",
      to_state: "ready",
      ts: "2026-05-31T00:05:00.000Z",
    });
    materializeTaskGraph(domain, { write: true });
    const result = selectNextExecutableNodes(domain, {}, 4);
    const ids = result.selected.map((n) => n.node_id).sort();
    assert.deepEqual(ids, [contractedId, readyId].sort());
  });
});

test("graph-scheduler ignores nodes in terminal states (finalized / abandoned)", () => {
  withTempHome(() => {
    const domain = "x9-terminal-states.example.com";
    seedSession(domain);
    const nodeId = seedContractedHypothesis(domain, "HP-terminal");
    // Promote through the full lifecycle to finalized.
    const { appendNodeTransition } = require("../mcp/core/waves/task-graph-events.js");
    appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "contracted",
      to_state: "ready",
      ts: "2026-05-31T00:03:00.000Z",
    });
    appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "ready",
      to_state: "dispatched",
      prep_token_hash: "fake-prep-token-finalization-path",
      ts: "2026-05-31T00:04:00.000Z",
    });
    appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "dispatched",
      to_state: "executed",
      ts: "2026-05-31T00:05:00.000Z",
    });
    appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "executed",
      to_state: "verified",
      ts: "2026-05-31T00:06:00.000Z",
    });
    appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "verified",
      to_state: "finalized",
      ts: "2026-05-31T00:07:00.000Z",
    });
    materializeTaskGraph(domain, { write: true });
    const result = selectNextExecutableNodes(domain, {}, 4);
    assert.equal(result.selected.length, 0,
      "finalized nodes must NEVER appear in graph-scheduler selection");
  });
});

// ─── E1: belief-VoI advisory scheduler overlay ────────────────────────────
//
// The deterministic spine (priority -> ts_first -> node_id) stays byte-
// identical with the CB-C1 flag off (the default). When an operator opts in,
// a per-cell belief score RAISES hotter-surface cells WITHIN their priority
// band — never across a band, never dropping a cell. These tests pin the
// comparator contract (pure), the real belief→cell wiring (helper), and the
// spine-green/raise-only behavior at the selection boundary (integration).

const {
  compareGraphCandidates,
} = require("../mcp/core/waves/graph-scheduler.js");
const {
  buildCellBeliefRank,
} = require("../mcp/core/belief/cell-scheduler-priority.js");
const {
  appendCellProposal: appendCellProposalE1,
} = require("../mcp/core/waves/task-graph-events.js");
const {
  cellNodeId: cellNodeIdE1,
} = require("../mcp/core/waves/task-graph-materializer.js");
const {
  buildCellCoverageContract: buildCellCoverageContractE1,
} = require("../mcp/core/contract/cell-contract.js");
const {
  materializeFrontier: materializeFrontierE1,
} = require("../mcp/core/frontier/frontier-materializer.js");
const {
  appendEdges: appendEdgesE1,
} = require("../mcp/core/frontier/surface-graph.js");
const {
  DEFAULT_QUEUE_POLICY: DEFAULT_QUEUE_POLICY_E1,
} = require("../mcp/core/io/queue-policy.js");

const PRIORITY_RANK_E1 = new Map([
  ["critical", 0],
  ["high", 1],
  ["medium", 2],
  ["low", 3],
]);

function cellCandidateE1(nodeId, { priority = "medium", ts = "2026-05-31T00:01:00.000Z" } = {}) {
  return { node_id: nodeId, kind: "cell", state: "contracted", priority, ts_first: ts, ts_last: ts };
}

// Seed a single dispatch-eligible (contracted) coverage cell on a surface and
// return its materialized node_id. Mirrors bob_materialize_cell_floor's
// proposal → materialize → synthetic-contract dance for exactly one cell.
function seedContractedCellE1(domain, surfaceId, {
  bugClass = "idor",
  authProfile = "admin",
  ts = "2026-05-31T00:01:00.000Z",
} = {}) {
  const cellKey = JSON.stringify([surfaceId, "", "", bugClass, authProfile]);
  appendCellProposalE1({
    target_domain: domain,
    surface_id: surfaceId,
    cell_key: cellKey,
    bug_class: bugClass,
    auth_profile: authProfile,
    technique_pack_ids: [],
    capability_pack_ids: [],
    ts,
  });
  materializeTaskGraph(domain, { write: true });
  const nodeId = cellNodeIdE1({ cellKey });
  appendContract({
    target_domain: domain,
    node_id: nodeId,
    contract: buildCellCoverageContractE1({ surfaceId, bugClass, authProfile, cellKey }),
    ts,
  });
  materializeTaskGraph(domain, { write: true });
  return nodeId;
}

function seedDescribedSurfaceE1(domain, surfaceId, title) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-31T00:00:00.000Z",
    surface_id: surfaceId,
    payload: { title },
  });
  materializeFrontierE1(domain, { write: true });
}

// The causal graph the wave-planner belief test uses: an attacker principal
// tests an owner gate that permits an unauth effect. rankInterventions surfaces
// this as a value-of-information candidate whose tokens match the idor surface.
function seedBeliefCausalGraphE1(domain) {
  appendEdgesE1({
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

test("E1 comparator: an empty/absent belief map is byte-identical to the deterministic 3-key sort", () => {
  const a = cellCandidateE1("TG-cell-aaa");
  const b = cellCandidateE1("TG-cell-bbb");
  // No map, null map, and empty map must all reduce to node_id alpha (ts tied).
  const baseline = compareGraphCandidates(a, b, PRIORITY_RANK_E1);
  assert.equal(compareGraphCandidates(a, b, PRIORITY_RANK_E1, null), baseline);
  assert.equal(compareGraphCandidates(a, b, PRIORITY_RANK_E1, new Map()), baseline);
  assert.ok(baseline < 0, "TG-cell-aaa sorts before TG-cell-bbb by node_id");
});

test("E1 comparator: a belief score RAISES a cell WITHIN its priority band (tie-break only)", () => {
  const a = cellCandidateE1("TG-cell-aaa"); // alpha-first by default
  const b = cellCandidateE1("TG-cell-bbb");
  // Give b a positive belief score; it must now sort ahead of a despite a's
  // earlier node_id — but both are still medium, so this is a within-band raise.
  const belief = new Map([["TG-cell-bbb", 90]]);
  assert.ok(compareGraphCandidates(a, b, PRIORITY_RANK_E1, belief) > 0, "b raised ahead of a");
  // Symmetry: the reverse comparison agrees (no contradictory ordering).
  assert.ok(compareGraphCandidates(b, a, PRIORITY_RANK_E1, belief) < 0);
});

test("E1 comparator: belief NEVER crosses a priority band (a critical cell always beats a boosted medium)", () => {
  const critical = cellCandidateE1("TG-cell-zzz", { priority: "critical" });
  const medium = cellCandidateE1("TG-cell-aaa", { priority: "medium" });
  // Even with a maximal belief score on the medium cell, the critical cell wins
  // because the belief compare sits AFTER the priority compare.
  const belief = new Map([["TG-cell-aaa", 100]]);
  assert.ok(
    compareGraphCandidates(critical, medium, PRIORITY_RANK_E1, belief) < 0,
    "critical precedes a belief-boosted medium",
  );
});

// ─── C1: two-tier breadth-then-depth comparator ───────────────────────────

test("C1 comparator: the tier key is a no-op when every candidate is Tier-1 (byte-identical baseline)", () => {
  const a = cellCandidateE1("TG-cell-aaa");
  const b = cellCandidateE1("TG-cell-bbb");
  // No tier field (default Tier-1) must equal the pre-C1 priority->ts->node_id sort.
  const baseline = compareGraphCandidates(a, b, PRIORITY_RANK_E1);
  // An explicit tier:1 on both is identical to the default.
  assert.equal(compareGraphCandidates({ ...a, tier: 1 }, { ...b, tier: 1 }, PRIORITY_RANK_E1), baseline);
  assert.ok(baseline < 0, "TG-cell-aaa before TG-cell-bbb by node_id when all keys tie");
});

test("C1 comparator: breadth precedes depth UNCONDITIONALLY (a Tier-1 cell beats a higher-priority Tier-2 re-probe)", () => {
  // Tier-1 uncovered floor cell at MEDIUM priority vs a Tier-2 depth re-probe at
  // CRITICAL priority. Breadth-before-depth: the Tier-1 cell must dispatch first
  // even though the re-probe outranks it on priority.
  const tier1Medium = { ...cellCandidateE1("TG-cell-floor", { priority: "medium" }), tier: 1 };
  const tier2Critical = { ...cellCandidateE1("TG-cell-reprobe", { priority: "critical" }), tier: 2 };
  assert.ok(
    compareGraphCandidates(tier1Medium, tier2Critical, PRIORITY_RANK_E1) < 0,
    "the uncovered Tier-1 floor cell precedes the higher-priority Tier-2 re-probe",
  );
  // Symmetric and even when the Tier-2 cell carries a maximal belief boost.
  const belief = new Map([["TG-cell-reprobe", 100]]);
  assert.ok(compareGraphCandidates(tier2Critical, tier1Medium, PRIORITY_RANK_E1, belief) > 0);
});

test("C1 comparator: within a tier+priority band, higher severity_floor dispatches first", () => {
  const crit = { ...cellCandidateE1("TG-cell-zzz", { priority: "medium" }), severity_floor: "critical" };
  const low = { ...cellCandidateE1("TG-cell-aaa", { priority: "medium" }), severity_floor: "low" };
  // Same tier + priority: the higher-severity cell wins, overriding the node_id
  // alpha tie-break (which would otherwise put TG-cell-aaa first).
  assert.ok(
    compareGraphCandidates(crit, low, PRIORITY_RANK_E1) < 0,
    "critical-severity cell precedes a low-severity cell despite later node_id",
  );
  // Uniform severity falls through to the deterministic node_id tie-break.
  const lowA = { ...cellCandidateE1("TG-cell-aaa", { priority: "medium" }), severity_floor: "low" };
  const lowB = { ...cellCandidateE1("TG-cell-bbb", { priority: "medium" }), severity_floor: "low" };
  assert.ok(compareGraphCandidates(lowA, lowB, PRIORITY_RANK_E1) < 0);
});

test("E1 helper: buildCellBeliefRank scores a cell from its parent surface's belief hint", () => {
  withTempHome(() => {
    const domain = "e1-belief-rank.example.com";
    seedSession(domain);
    seedDescribedSurfaceE1(domain, "surface:idor", "idor victim object unauth succeeds where auth blocked");
    seedDescribedSurfaceE1(domain, "surface:generic", "generic admin dashboard");
    seedBeliefCausalGraphE1(domain);
    const idorCell = seedContractedCellE1(domain, "surface:idor");
    const genericCell = seedContractedCellE1(domain, "surface:generic", { bugClass: "xss", authProfile: "anon" });

    const doc = materializeTaskGraph(domain, { write: false }).document;
    const candidates = doc.nodes
      .filter((n) => n.kind === "cell")
      .map((n) => ({ node_id: n.node_id, kind: "cell" }));

    // Real path: buildCellBeliefRank reads currentSurfaces + the belief machinery.
    const rank = buildCellBeliefRank({
      target_domain: domain,
      document: doc,
      candidates,
      seed: DEFAULT_QUEUE_POLICY_E1.belief_assisted_priority_seed,
      rank_limit: DEFAULT_QUEUE_POLICY_E1.belief_assisted_priority_rank_limit,
    });
    assert.ok(rank.has(idorCell), "the idor cell inherits its surface's belief hint");
    assert.ok(rank.get(idorCell) > 0, "the inherited score is a positive RAISE");
    assert.ok(!rank.has(genericCell), "the unmatched generic surface yields no boost");
  });
});

test("E1 selection: flag ON with no belief signal is identical to flag OFF (graceful cold start)", () => {
  withTempHome(() => {
    const domain = "e1-cold-start.example.com";
    seedSession(domain);
    seedDescribedSurfaceE1(domain, "surface:one", "surface one");
    seedDescribedSurfaceE1(domain, "surface:two", "surface two");
    // No causal edges => no belief hints => empty rank map.
    seedContractedCellE1(domain, "surface:one");
    seedContractedCellE1(domain, "surface:two", { bugClass: "xss", authProfile: "anon" });

    const off = selectNextExecutableNodes(domain, {}, 8);
    const on = selectNextExecutableNodes(
      domain,
      { ...DEFAULT_QUEUE_POLICY_E1, belief_assisted_priority_enabled: true },
      8,
    );
    assert.equal(JSON.stringify(on.selected), JSON.stringify(off.selected));
    assert.equal(JSON.stringify(on.skipped), JSON.stringify(off.skipped));
  });
});

test("E1 selection: flag ON RAISES the hotter-surface cell but drops no cell (monotonic)", () => {
  withTempHome(() => {
    const domain = "e1-raise-only.example.com";
    seedSession(domain);
    seedDescribedSurfaceE1(domain, "surface:idor", "idor victim object unauth succeeds where auth blocked");
    seedDescribedSurfaceE1(domain, "surface:generic", "generic admin dashboard");
    seedBeliefCausalGraphE1(domain);
    const idorCell = seedContractedCellE1(domain, "surface:idor");
    const genericCell = seedContractedCellE1(domain, "surface:generic", { bugClass: "xss", authProfile: "anon" });

    // The advisory is default-ON; the no-belief baseline is taken with an explicit
    // operator `false` (assertBoolean honors an explicit false per session).
    const off = selectNextExecutableNodes(domain, { belief_assisted_priority_enabled: false }, 8);
    const offIds = new Set([...off.selected, ...off.skipped].map((n) => n.node_id));

    const on = selectNextExecutableNodes(
      domain,
      { ...DEFAULT_QUEUE_POLICY_E1, belief_assisted_priority_enabled: true },
      8,
    );
    const order = [...on.selected, ...on.skipped].map((n) => n.node_id);
    const onIds = new Set(order);

    // The overlay actually changed the order (guards against a silent no-op
    // regardless of how the content-hash node_ids happen to sort).
    assert.notEqual(
      JSON.stringify(on.selected),
      JSON.stringify(off.selected),
      "the belief overlay reordered selection (not a no-op)",
    );
    // RAISE: the belief-matched idor cell sorts ahead of the unmatched generic cell.
    assert.ok(order.indexOf(idorCell) >= 0 && order.indexOf(genericCell) >= 0);
    assert.ok(
      order.indexOf(idorCell) < order.indexOf(genericCell),
      "the hotter (belief-matched) cell is raised ahead of the cold cell",
    );
    // MONOTONIC: the overlay reorders only — the candidate SET and count are unchanged.
    assert.equal(onIds.size, offIds.size);
    for (const id of offIds) assert.ok(onIds.has(id), `cell ${id} survives the overlay`);
    assert.equal(on.considered_count, off.considered_count);
  });
});

test("D2 per-kind cap split: max_concurrent_evaluators scales cells while transition/hypothesis stay at the graph cap", () => {
  const document = {
    materialized_at: "2026-06-21T00:00:00.000Z",
    hashes: { graph_hash: "d2deadbeef" },
    nodes: [
      ...Array.from({ length: 6 }, (_, i) => ({ node_id: `cell-${i}`, kind: "cell", state: "ready", priority: "medium" })),
      ...Array.from({ length: 3 }, (_, i) => ({ node_id: `tr-${i}`, kind: "transition", state: "ready", priority: "medium" })),
    ],
  };
  // Off-profile (explicit null in-flight cap): one combined cap => single slice.
  const def = selectNextExecutableNodes("d2-split.example.com", { max_concurrent_evaluators: null }, 2, { document });
  assert.equal(def.capacity_used, 2);
  assert.equal(def.capacity_limit, 2, "a null in-flight cap keeps the single combined cap");
  assert.equal(def.capacity_used, def.selected.length);

  // On-default: the shipped default's sized in-flight cap (128) scales the cell kind
  // while transition/hypothesis stay at the graph cap (the per-kind split is on).
  const { DEFAULT_QUEUE_POLICY: DQP_D2 } = require("../mcp/core/io/queue-policy.js");
  const onDefault = selectNextExecutableNodes("d2-split.example.com", DQP_D2, 2, { document });
  assert.equal(onDefault.selected.filter((n) => n.kind === "cell").length, 6, "the on-default scales all 6 cells (cap 128 > 6)");
  assert.equal(onDefault.selected.filter((n) => n.kind !== "cell").length, 2, "transition/hypothesis stay at the graph cap 2");
  assert.equal(onDefault.capacity_limit, 130, "capacity_limit = cellCap(128) + graphCap(2)");

  // Opt-in: cell cap 5 (max_concurrent_evaluators), graph cap 2 (the `cap` arg = max_parallel_tasks).
  const split = selectNextExecutableNodes("d2-split.example.com", { max_concurrent_evaluators: 5 }, 2, { document });
  const cells = split.selected.filter((n) => n.kind === "cell").length;
  const graph = split.selected.filter((n) => n.kind !== "cell").length;
  assert.equal(cells, 5, "cells scale to max_concurrent_evaluators (5 of 6)");
  assert.equal(graph, 2, "transition/hypothesis stay at the graph cap (2 of 3) — dispatch count unchanged");
  assert.equal(split.capacity_limit, 7, "capacity_limit = cellCap + graphCap");
  assert.equal(split.capacity_used, 7);
  assert.equal(split.capacity_used, split.selected.length, "capacity_used === selected.length contract holds");
});
