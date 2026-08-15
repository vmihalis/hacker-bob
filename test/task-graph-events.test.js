"use strict";

// Plane X Cycle X.1 — TaskGraph event-ledger wrappers + proposal tools.
//
// X.1 ships:
//   - FRONTIER_EVENT_KINDS += "node.transitioned"  (the ONE new top-level
//     kind permitted by X-P8).
//   - mcp/lib/task-graph-events.js with the frozen state-transition table
//     (Do step 4) and three wrappers (Do step 2):
//       appendNodeTransition, appendTransitionProposal,
//       appendHypothesisProposal.
//   - bob_propose_hypothesis + bob_propose_transition tools (Do step 3).
//
// Do step 5 specifies three test families: causality on append, out-of-
// order refused, prose-cap fires on oversize. The tests below cover all
// three plus the proposal-tool roundtrip and the state-transition table
// (so a future cycle that edits the table is forced to update tests).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  DIRECT_FRONTIER_EVENT_KINDS,
  FRONTIER_EVENT_KINDS,
  appendFrontierEvent,
  readFrontierEvents,
} = require("../mcp/core/frontier/frontier-events.js");
const {
  NODE_STATE_TRANSITIONS,
  NODE_STATE_VALUES,
  TASK_GRAPH_NODE_ID_PREFIX,
  TRANSITION_KIND_VALUES,
  appendCellProposal,
  appendHypothesisProposal,
  appendNodeTransition,
  appendTransitionProposal,
  assertNodeTransitionAllowed,
  isAllowedNodeTransition,
  readCellProposals,
  readHypothesisProposals,
  readNodeTransitions,
  readTransitionProposals,
} = require("../mcp/core/waves/task-graph-events.js");
const {
  materializeFrontier,
} = require("../mcp/core/frontier/frontier-materializer.js");
const {
  materializeTaskGraph,
} = require("../mcp/core/waves/task-graph-materializer.js");
const {
  TOOL_HANDLERS,
  getRegisteredTool,
} = require("../mcp/core/dispatch/tool-registry.js");

// X.3 Do step 3: bob_propose_transition validates both endpoints exist in
// surface-index. Tests that exercise the tool roundtrip seed both endpoint
// surfaces with surface.observed events and force a materialization so
// surface-index.json carries them before the handler runs.
function seedMaterializedSurface(domain, surfaceId) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-31T00:00:00.000Z",
    surface_id: surfaceId,
    payload: { title: surfaceId },
  });
  materializeFrontier(domain, { write: true });
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-task-graph-events-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// ─── cell_proposed -> materialized cell node (B1) ────────────────────────

test("cell_proposed rides observation.recorded (no new top-level frontier kind)", () => {
  withTempHome(() => {
    const domain = "cell-kind.test";
    seedMaterializedSurface(domain, "surface:billing");
    appendCellProposal({
      target_domain: domain,
      surface_id: "surface:billing",
      cell_key: JSON.stringify(["surface:billing", "", "", "idor", "admin"]),
      bug_class: "idor",
      auth_profile: "admin",
      technique_pack_ids: [],
      capability_pack_ids: [],
    });
    const proposals = readCellProposals(domain);
    assert.equal(proposals.length, 1);
    assert.equal(proposals[0].kind, "observation.recorded");
    assert.equal(proposals[0].payload.kind, "cell_proposed");
    assert.equal(proposals[0].payload.surface_id, "surface:billing");
  });
});

test("cell_proposed materializes a cell node grounded in its REAL parent surface", () => {
  withTempHome(() => {
    const domain = "cell-materialize.test";
    seedMaterializedSurface(domain, "surface:billing");
    appendCellProposal({
      target_domain: domain,
      surface_id: "surface:billing",
      cell_key: JSON.stringify(["surface:billing", "", "", "idor", "admin"]),
      bug_class: "idor",
      auth_profile: "admin",
      technique_pack_ids: [],
      capability_pack_ids: [],
    });
    const doc = materializeTaskGraph(domain, { write: true }).document;
    const cell = doc.nodes.find((n) => n.kind === "cell");
    assert.ok(cell, "a cell node was materialized");
    assert.ok(cell.node_id.startsWith(`${TASK_GRAPH_NODE_ID_PREFIX}cell-`));
    assert.deepEqual(cell.surface_refs, ["surface:billing"]);
    assert.equal(cell.state, "proposed");
    // equal cells dedupe to one node (hash-of-cell_key id).
    appendCellProposal({
      target_domain: domain,
      surface_id: "surface:billing",
      cell_key: JSON.stringify(["surface:billing", "", "", "idor", "admin"]),
      bug_class: "idor",
      auth_profile: "admin",
      technique_pack_ids: [],
      capability_pack_ids: [],
    });
    const doc2 = materializeTaskGraph(domain, { write: true }).document;
    assert.equal(doc2.nodes.filter((n) => n.kind === "cell").length, 1);
  });
});

test("bob_materialize_cell_floor sweeps the inventory and emits cell_proposed per cell", () => {
  withTempHome(() => {
    const domain = "cell-floor.test";
    // Seed an OSS surface (a harness): OSS cells = sanitizer x input_class, no
    // auth axis, so the floor emits without auth profiles or bug_class_hints.
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-31T00:00:00.000Z",
      surface_id: "surface:harness-x",
      payload: { title: "harness-x", surface_type: "oss_native_code" },
    });
    materializeFrontier(domain, { write: true });
    const { handler } = require("../mcp/tools/materialize-cell-floor.js");
    const result = JSON.parse(handler({ target_domain: domain }));
    assert.ok(result.cells_emitted > 0, "the floor emitted cells (deterministic, not nesting-gated)");
    const proposals = readCellProposals(domain);
    assert.equal(proposals.length, result.cells_emitted);
    // every floor cell is auto-contracted (proposed -> contracted) with a
    // synthetic coverage Contract — no operator authors a per-cell Contract.
    assert.equal(result.cells_contracted, result.cells_emitted);
    const doc = materializeTaskGraph(domain, { write: true }).document;
    const cells = doc.nodes.filter((n) => n.kind === "cell");
    assert.ok(cells.length > 0);
    assert.ok(cells.every((n) => n.surface_refs.includes("surface:harness-x")));
    assert.ok(
      cells.every((n) => n.state === "contracted"),
      "cells are dispatch-eligible (contracted) with NO operator Contract",
    );
    assert.ok(cells.every((n) => typeof n.contract_hash === "string" && n.contract_hash.length > 0));
    // and the dormant TaskGraph engine SELECTS them for dispatch.
    const { selectNextExecutableNodes } = require("../mcp/core/waves/graph-scheduler.js");
    const { DEFAULT_QUEUE_POLICY } = require("../mcp/core/io/queue-policy.js");
    const sel = selectNextExecutableNodes(domain, DEFAULT_QUEUE_POLICY, 16);
    const selNodes = Array.isArray(sel) ? sel : (sel.selected || sel.nodes || []);
    assert.ok(selNodes.length > 0, "the graph-scheduler selects contracted cells");
    assert.ok(selNodes.every((n) => n.kind === "cell"));
  });
});

test("C4: a reconciled cell (logCellCoverage) self-prunes on the next floor sweep", () => {
  withTempHome(() => {
    const domain = "cell-reconcile.test";
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-31T00:00:00.000Z",
      surface_id: "surface:harness-x",
      payload: { title: "harness-x", surface_type: "oss_native_code" },
    });
    materializeFrontier(domain, { write: true });
    // Lift the per-surface child cap so the OSS floor (3 sanitizers x 3 input
    // classes = 9) is not budget-capped — otherwise pruning a covered cell just
    // frees a slot for a previously-capped one and the count is unchanged.
    const { writeQueuePolicy, normalizeQueuePolicy, DEFAULT_QUEUE_POLICY } = require("../mcp/core/io/queue-policy.js");
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_children: 64 }));
    const floor = require("../mcp/tools/materialize-cell-floor.js").handler;
    const first = JSON.parse(floor({ target_domain: domain }));
    assert.ok(first.cells_emitted > 0);

    // Reconcile ONE cell as covered — exactly what bob_finalize_node does on a
    // verified cell (graph-cell write: null wave/agent, no assignment gate).
    const {
      logCellCoverage,
      buildCoverageSummaryForSurface,
      readCoverageRecordsFromJsonl,
    } = require("../mcp/core/frontier/coverage.js");
    logCellCoverage({
      target_domain: domain,
      surface_id: "surface:harness-x",
      bug_class: "asan",
      auth_profile: "value_profile",
      status: "tested",
      evidence_summary: "probed",
    });
    // The record round-trips (null wave/agent) and groups under tested.
    const summary = buildCoverageSummaryForSurface(readCoverageRecordsFromJsonl(domain), "surface:harness-x");
    assert.ok(summary.tested.some((it) => it.bug_class === "asan" && it.auth_profile === "value_profile"));

    // The next floor sweep prunes the reconciled cell — coverage is MEASURABLE.
    const second = JSON.parse(floor({ target_domain: domain }));
    assert.ok(
      second.cells_emitted < first.cells_emitted,
      "the reconciled cell is pruned, not re-emitted",
    );
  });
});

test("D1: the cell-closure gate is vacuous without a floor, blocks on uncovered cells, clears when covered", () => {
  withTempHome(() => {
    const domain = "d1-closure.test";
    const { evaluateSchedulerPrecondition } = require("../mcp/core/waves/scheduler-preconditions.js");
    const { TRANSITION_GATES } = require("../mcp/core/session/lifecycle-gates.js");
    const gateOpenFrontierToClaimFreeze = TRANSITION_GATES["OPEN_FRONTIER->CLAIM_FREEZE"];

    // No cell floor -> vacuously satisfied (surface-only/legacy runs unaffected).
    const vacuous = evaluateSchedulerPrecondition("uncovered_reachable_cells", { target_domain: domain });
    assert.equal(vacuous.satisfied, true);
    assert.equal(vacuous.cell_floor_active, false);

    // Materialize a cell floor with no budget cap (OSS = 9 cells).
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-31T00:00:00.000Z",
      surface_id: "surface:harness-x",
      payload: { title: "harness-x", surface_type: "oss_native_code" },
    });
    materializeFrontier(domain, { write: true });
    const { writeQueuePolicy, normalizeQueuePolicy, DEFAULT_QUEUE_POLICY } = require("../mcp/core/io/queue-policy.js");
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_children: 64 }));
    require("../mcp/tools/materialize-cell-floor.js").handler({ target_domain: domain });

    // Cells exist + uncovered -> the gate BLOCKS freeze (closure teeth).
    const blocked = evaluateSchedulerPrecondition("uncovered_reachable_cells", { target_domain: domain });
    assert.equal(blocked.satisfied, false);
    assert.equal(blocked.cell_floor_active, true);
    assert.ok(blocked.uncovered_count > 0);
    const gateBlockers = gateOpenFrontierToClaimFreeze({ target_domain: domain });
    assert.ok(gateBlockers.some((b) => b.code === "uncovered_reachable_cells"));

    // Cover every cell -> the gate clears.
    const { logCellCoverage } = require("../mcp/core/frontier/coverage.js");
    for (const sanitizer of ["asan", "msan", "ubsan"]) {
      for (const inputClass of ["cmplog", "raw_corpus", "value_profile"]) {
        logCellCoverage({
          target_domain: domain,
          surface_id: "surface:harness-x",
          bug_class: sanitizer,
          auth_profile: inputClass,
          status: "tested",
          evidence_summary: "probed",
        });
      }
    }
    const cleared = evaluateSchedulerPrecondition("uncovered_reachable_cells", { target_domain: domain });
    assert.equal(cleared.satisfied, true);
    assert.equal(cleared.uncovered_count, 0);
    assert.ok(!gateOpenFrontierToClaimFreeze({ target_domain: domain }).some((b) => b.code === "uncovered_reachable_cells"));
  });
});

// ─── A2: transition-cells (cross-surface invariants on edges) ─────────────

function seedTransitionEdge(domain, fromSurface, toSurface, kind) {
  seedMaterializedSurface(domain, fromSurface);
  seedMaterializedSurface(domain, toSurface);
  appendTransitionProposal({
    target_domain: domain,
    ts: "2026-05-31T00:01:00.000Z",
    from_surface: fromSurface,
    to_surface: toSurface,
    kind,
    trust_assumption: `${fromSurface} value is recovered and trusted on ${toSurface}`,
    proposal_id: `TR-${kind}`,
  });
  // Lift the per-edge child cap so the whole transition axis materializes.
  const { writeQueuePolicy, normalizeQueuePolicy, DEFAULT_QUEUE_POLICY } = require("../mcp/core/io/queue-policy.js");
  writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_children: 64 }));
}

test("A2: a transition-cell materializes grounded in its EDGE (two surface_refs)", () => {
  withTempHome(() => {
    const domain = "a2-grounding.test";
    seedTransitionEdge(domain, "surface:l1", "surface:l2", "value_movement");
    const result = JSON.parse(require("../mcp/tools/materialize-cell-floor.js").handler({ target_domain: domain }));
    // value_movement axis = [value_flow, replay] -> 2 transition-cells, one edge.
    assert.equal(result.transition_cells_emitted, 2);
    assert.equal(result.edges_with_cells, 1);

    const doc = materializeTaskGraph(domain, { write: true }).document;
    const transitionCells = doc.nodes.filter(
      (n) => n.kind === "cell" && n.surface_refs.length === 2,
    );
    assert.equal(transitionCells.length, 2, "two transition-cells, each grounded in both endpoints");
    for (const cell of transitionCells) {
      assert.ok(cell.node_id.startsWith(`${TASK_GRAPH_NODE_ID_PREFIX}cell-`));
      assert.deepEqual(cell.surface_refs, ["surface:l1", "surface:l2"]);
      assert.equal(cell.state, "contracted", "auto-contracted like any cell (dispatch-eligible)");
    }
  });
});

test("A2: a transition-cell id is disjoint from a surface-cell with the same bug_class", () => {
  withTempHome(() => {
    const domain = "a2-disjoint.test";
    const { cellNodeId } = require("../mcp/core/waves/task-graph-materializer.js");
    const { transitionEdgeToken } = require("../mcp/core/session/assignment-brief.js");
    // A surface-cell key for bug_class "replay" on surface:l1 ...
    const surfaceCellKey = JSON.stringify(["surface:l1", "", "", "replay", ""]);
    // ... vs a transition-cell key for "replay" on the l1->l2 edge.
    const edgeToken = transitionEdgeToken("surface:l1", "surface:l2", "value_movement");
    const transitionCellKey = JSON.stringify([edgeToken, "", "", "replay", ""]);
    assert.notEqual(
      cellNodeId({ cellKey: surfaceCellKey }),
      cellNodeId({ cellKey: transitionCellKey }),
      "the edge token in the surface slot makes the hashed node id disjoint",
    );
  });
});

test("A2: a reconciled transition-cell self-prunes on the next floor sweep", () => {
  withTempHome(() => {
    const domain = "a2-selfprune.test";
    seedTransitionEdge(domain, "surface:l1", "surface:l2", "value_movement");
    const floor = require("../mcp/tools/materialize-cell-floor.js").handler;
    const first = JSON.parse(floor({ target_domain: domain }));
    assert.equal(first.transition_cells_emitted, 2);

    // Reconcile ONE transition-cell on the edge token (what finalize-node does).
    const { logCellCoverage } = require("../mcp/core/frontier/coverage.js");
    const { transitionEdgeToken } = require("../mcp/core/session/assignment-brief.js");
    const edgeToken = transitionEdgeToken("surface:l1", "surface:l2", "value_movement");
    logCellCoverage({
      target_domain: domain,
      surface_id: edgeToken,
      bug_class: "value_flow",
      auth_profile: "",
      status: "tested",
      evidence_summary: "cross-surface replay probed",
    });

    const second = JSON.parse(floor({ target_domain: domain }));
    assert.equal(second.transition_cells_emitted, 1, "the reconciled edge-cell is pruned, not re-emitted");
  });
});

test("A2: the closure gate counts an uncovered transition-cell and clears when reconciled", () => {
  withTempHome(() => {
    const domain = "a2-closure.test";
    const { evaluateSchedulerPrecondition } = require("../mcp/core/waves/scheduler-preconditions.js");
    seedTransitionEdge(domain, "surface:l1", "surface:l2", "value_movement");
    require("../mcp/tools/materialize-cell-floor.js").handler({ target_domain: domain });

    // An uncovered cross-surface invariant BLOCKS freeze — the A2 thesis.
    const blocked = evaluateSchedulerPrecondition("uncovered_reachable_cells", { target_domain: domain });
    assert.equal(blocked.cell_floor_active, true);
    assert.equal(blocked.satisfied, false);
    assert.ok(blocked.uncovered_count >= 2);

    // Reconcile every transition-cell on the edge -> the gate clears.
    const { logCellCoverage } = require("../mcp/core/frontier/coverage.js");
    const { transitionEdgeToken } = require("../mcp/core/session/assignment-brief.js");
    const edgeToken = transitionEdgeToken("surface:l1", "surface:l2", "value_movement");
    for (const bugClass of ["value_flow", "replay"]) {
      logCellCoverage({
        target_domain: domain,
        surface_id: edgeToken,
        bug_class: bugClass,
        auth_profile: "",
        status: "tested",
        evidence_summary: "probed",
      });
    }
    const cleared = evaluateSchedulerPrecondition("uncovered_reachable_cells", { target_domain: domain });
    assert.equal(cleared.satisfied, true);
    assert.equal(cleared.uncovered_count, 0);
  });
});

// ─── C3: the stigmergic wavefront advances by reading the last layer's writes ──

test("C3: the next floor layer reads the last layer's writes (covered pruned + discovered transition folded in)", () => {
  withTempHome(() => {
    const domain = "c3-wavefront.test";
    // Layer 0 — an OSS harness surface fans 3 sanitizers x 3 input classes = 9 cells.
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-31T00:00:00.000Z",
      surface_id: "surface:harness",
      payload: { title: "harness", surface_type: "oss_native_code" },
    });
    materializeFrontier(domain, { write: true });
    const { writeQueuePolicy, normalizeQueuePolicy, DEFAULT_QUEUE_POLICY } = require("../mcp/core/io/queue-policy.js");
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_children: 64 }));
    const floor = require("../mcp/tools/materialize-cell-floor.js").handler;
    const layer0 = JSON.parse(floor({ target_domain: domain }));
    assert.ok(layer0.cells_emitted >= 9, "the harness surface-cell floor materializes");
    assert.equal(layer0.transition_cells_emitted, 0, "no transitions discovered yet");

    // Decentralized writes BETWEEN layers: cover every surface-cell, and an
    // evaluator DISCOVERS a new cross-surface transition.
    const { logCellCoverage } = require("../mcp/core/frontier/coverage.js");
    for (const sanitizer of ["asan", "msan", "ubsan"]) {
      for (const inputClass of ["cmplog", "raw_corpus", "value_profile"]) {
        logCellCoverage({
          target_domain: domain,
          surface_id: "surface:harness",
          bug_class: sanitizer,
          auth_profile: inputClass,
          status: "tested",
          evidence_summary: "probed",
        });
      }
    }
    appendTransitionProposal({
      target_domain: domain,
      ts: "2026-05-31T00:05:00.000Z",
      from_surface: "surface:harness",
      to_surface: "surface:sink",
      kind: "value_movement",
      trust_assumption: "harness output is trusted at the sink",
      proposal_id: "TR-discovered",
    });

    // Layer 1 — the producer reads BOTH writes: it prunes the now-covered surface
    // cells AND folds the discovered transition into the next layer's cells.
    const layer1 = JSON.parse(floor({ target_domain: domain }));
    assert.ok(layer1.cells_emitted < layer0.cells_emitted, "covered surface-cells are pruned from the next layer");
    assert.equal(layer1.transition_cells_emitted, 2, "the discovered transition folds into the next layer");
  });
});

// ─── G1: monotonic expansion + fixpoint termination ───────────────────────

test("G1: the Tier-1 floor reaches a cells-emitted fixpoint once every cell is covered", () => {
  withTempHome(() => {
    const domain = "g1-fixpoint.test";
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-31T00:00:00.000Z",
      surface_id: "surface:harness-x",
      payload: { title: "harness-x", surface_type: "oss_native_code" },
    });
    materializeFrontier(domain, { write: true });
    const { writeQueuePolicy, normalizeQueuePolicy, DEFAULT_QUEUE_POLICY } = require("../mcp/core/io/queue-policy.js");
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_children: 64 }));
    const floor = require("../mcp/tools/materialize-cell-floor.js").handler;

    // Before coverage: the Tier-1 floor has obligations → NOT at fixpoint.
    const first = JSON.parse(floor({ target_domain: domain }));
    assert.ok(first.tier1_cells_emitted >= 9);
    assert.equal(first.floor_at_fixpoint, false);

    // Cover every Tier-1 cell → the next pass emits none → FIXPOINT.
    const { logCellCoverage } = require("../mcp/core/frontier/coverage.js");
    for (const sanitizer of ["asan", "msan", "ubsan"]) {
      for (const inputClass of ["cmplog", "raw_corpus", "value_profile"]) {
        logCellCoverage({ target_domain: domain, surface_id: "surface:harness-x", bug_class: sanitizer, auth_profile: inputClass, status: "tested", evidence_summary: "probed" });
      }
    }
    const converged = JSON.parse(floor({ target_domain: domain }));
    assert.equal(converged.tier1_cells_emitted, 0);
    assert.equal(converged.floor_at_fixpoint, true, "no new Tier-1 obligation after a full drain = closure");
  });
});

test("G1: the fixpoint signal excludes E2 re-probes (terminates with residual depth ON)", () => {
  withTempHome(() => {
    const domain = "g1-reprobe-fixpoint.test";
    // surface:billing has no bug_class_hints -> ZERO Tier-1 cells; only a covered
    // cell + a residual flagging it -> a never-converging E2 Tier-2 re-probe.
    appendFrontierEvent({ target_domain: domain, kind: "surface.observed", ts: "2026-05-31T00:00:00.000Z", surface_id: "surface:billing", payload: { title: "billing" } });
    materializeFrontier(domain, { write: true });
    const { logCellCoverage } = require("../mcp/core/frontier/coverage.js");
    logCellCoverage({ target_domain: domain, surface_id: "surface:billing", bug_class: "idor", auth_profile: "admin", status: "tested", evidence_summary: "probed" });
    const { writeBeliefSignalScratch } = require("../mcp/core/belief/authority.js");
    writeBeliefSignalScratch({
      target_domain: domain, kind: "belief_signal", source: "test#g1", provenance: "residual_anomaly",
      artifact_ref: "belief_sample:t", role: "diagnostic",
      payload: { residual_hash: "abcd1234ef567890", residual_band: "high", decomposition: [{ variable_id: "BV", variable_type: "effective_permission", scope: { effect_id: "effect:billing:x" } }] },
    });
    const { writeQueuePolicy, normalizeQueuePolicy, DEFAULT_QUEUE_POLICY } = require("../mcp/core/io/queue-policy.js");
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, residual_depth_reprobe_enabled: true }));
    const floor = require("../mcp/tools/materialize-cell-floor.js").handler;

    const r = JSON.parse(floor({ target_domain: domain }));
    // A Tier-2 re-probe was emitted (the non-converging component) ...
    assert.equal(r.reprobe_cells_emitted, 1);
    assert.ok(r.cells_emitted >= 1, "raw cells_emitted counts the re-probe (would never reach 0)");
    // ... but the Tier-1 fixpoint signal is already 0, so the loop TERMINATES.
    assert.equal(r.tier1_cells_emitted, 0);
    assert.equal(r.floor_at_fixpoint, true, "depth re-probes never block the fixpoint — termination is Tier-1 closure");
  });
});

test("G1: frontier expansion is monotone — a covered cell's node is never contracted", () => {
  withTempHome(() => {
    const domain = "g1-monotone.test";
    appendFrontierEvent({ target_domain: domain, kind: "surface.observed", ts: "2026-05-31T00:00:00.000Z", surface_id: "surface:harness-a", payload: { title: "a", surface_type: "oss_native_code" } });
    materializeFrontier(domain, { write: true });
    const { writeQueuePolicy, normalizeQueuePolicy, DEFAULT_QUEUE_POLICY } = require("../mcp/core/io/queue-policy.js");
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_children: 64 }));
    const floor = require("../mcp/tools/materialize-cell-floor.js").handler;
    floor({ target_domain: domain });
    const doc0 = materializeTaskGraph(domain, { write: true }).document;
    const cells0 = new Set(doc0.nodes.filter((n) => n.kind === "cell").map((n) => n.node_id));
    assert.ok(cells0.size >= 9);

    // Cover one cell AND observe a new surface (expansion). Re-run the floor.
    const { logCellCoverage } = require("../mcp/core/frontier/coverage.js");
    logCellCoverage({ target_domain: domain, surface_id: "surface:harness-a", bug_class: "asan", auth_profile: "cmplog", status: "tested", evidence_summary: "probed" });
    appendFrontierEvent({ target_domain: domain, kind: "surface.observed", ts: "2026-05-31T00:01:00.000Z", surface_id: "surface:harness-b", payload: { title: "b", surface_type: "oss_native_code" } });
    materializeFrontier(domain, { write: true });
    floor({ target_domain: domain });
    const doc1 = materializeTaskGraph(domain, { write: true }).document;
    const cells1 = new Set(doc1.nodes.filter((n) => n.kind === "cell").map((n) => n.node_id));

    // Monotone: every prior cell node persists (the covered cell was NOT removed),
    // and the new surface EXPANDED the set. The frontier never contracts.
    for (const id of cells0) assert.ok(cells1.has(id), `cell ${id} must persist (frontier never contracts)`);
    assert.ok(cells1.size > cells0.size, "the newly observed surface expanded the reachable set");
  });
});

// ─── New top-level kind is registered ────────────────────────────────────

test("FRONTIER_EVENT_KINDS contains exactly one new top-level kind for X.1", () => {
  assert.ok(FRONTIER_EVENT_KINDS.includes("node.transitioned"));
  // X-P8 budgets ONE new top-level kind per cycle; cycle X.1 adds exactly
  // this one. The proposal events ride on the existing observation.recorded
  // bucket. If a future change adds another node.* top-level kind, the
  // budget is owed a separate cycle review.
  const nodeKinds = FRONTIER_EVENT_KINDS.filter((kind) => kind.startsWith("node."));
  assert.deepEqual(nodeKinds, ["node.transitioned"]);
});

// ─── State-transition table is frozen at Do step 4 ───────────────────────

test("NODE_STATE_VALUES matches the X.1 vocabulary", () => {
  assert.deepEqual(NODE_STATE_VALUES.slice().sort(), [
    "abandoned",
    "contracted",
    "dispatched",
    "executed",
    "failed",
    "finalized",
    "proposed",
    "ready",
    "verified",
  ]);
});

test("NODE_STATE_TRANSITIONS matches the X.1 table + X.8 re-contract path", () => {
  // The table is intentionally narrow; copy it verbatim from the spec so
  // any drift surfaces as a test failure rather than a silent runtime change.
  // X.8 adds `failed → contracted` for the retry-with-recall workflow:
  // when the operator re-contracts a failed node with a refined Contract,
  // the brief inlines the prior failure payload via the `prior_attempt`
  // slice.
  const expected = {
    proposed: ["contracted", "abandoned"],
    contracted: ["ready", "abandoned"],
    ready: ["dispatched", "abandoned"],
    dispatched: ["executed", "failed"],
    executed: ["verified", "failed"],
    verified: ["finalized", "failed"],
    finalized: [],
    failed: ["contracted"],
    abandoned: [],
  };
  for (const state of Object.keys(expected)) {
    assert.deepEqual(
      NODE_STATE_TRANSITIONS[state].slice(),
      expected[state],
      `transitions for ${state} drifted from the X.1/X.8 state table`,
    );
  }
});

test("isAllowedNodeTransition accepts in-table pairs and refuses everything else", () => {
  assert.equal(isAllowedNodeTransition("proposed", "contracted"), true);
  assert.equal(isAllowedNodeTransition("contracted", "ready"), true);
  assert.equal(isAllowedNodeTransition("ready", "dispatched"), true);
  assert.equal(isAllowedNodeTransition("dispatched", "executed"), true);
  assert.equal(isAllowedNodeTransition("dispatched", "failed"), true);
  assert.equal(isAllowedNodeTransition("verified", "finalized"), true);
  // X.8 retry-with-recall: failed → contracted is the re-contract path.
  assert.equal(isAllowedNodeTransition("failed", "contracted"), true);

  // Out-of-order
  assert.equal(isAllowedNodeTransition("proposed", "ready"), false);
  assert.equal(isAllowedNodeTransition("dispatched", "ready"), false);
  // Skipping verified → finalized via executed → finalized
  assert.equal(isAllowedNodeTransition("executed", "finalized"), false);
  // Truly terminal states have no successors
  assert.equal(isAllowedNodeTransition("finalized", "verified"), false);
  assert.equal(isAllowedNodeTransition("abandoned", "proposed"), false);
  // failed → dispatched (skipping contracted) is still refused.
  assert.equal(isAllowedNodeTransition("failed", "dispatched"), false);
  assert.equal(isAllowedNodeTransition("failed", "ready"), false);
});

test("assertNodeTransitionAllowed throws a structured invalid_node_transition error", () => {
  let caught = null;
  try {
    assertNodeTransitionAllowed("proposed", "ready");
  } catch (error) {
    caught = error;
  }
  assert.ok(caught, "should throw");
  assert.equal(caught.code, "invalid_node_transition");
  assert.equal(caught.details.from_state, "proposed");
  assert.equal(caught.details.to_state, "ready");
  assert.deepEqual(caught.details.allowed_from_state, ["contracted", "abandoned"]);
});

// ─── appendNodeTransition: causality (Do step 5) ─────────────────────────

test("appendNodeTransition emits node.transitioned with the canonical payload", () => {
  withTempHome(() => {
    const domain = "x1.example.com";
    appendHypothesisProposal({
      target_domain: domain,
      hypothesis_statement: "Canonical transition writer fixture.",
      surface_refs: ["surface:fixture"],
      proposal_id: "hyp-001",
      ts: "2026-05-30T23:59:59.000Z",
    });
    const event = appendNodeTransition({
      target_domain: domain,
      node_id: `${TASK_GRAPH_NODE_ID_PREFIX}H-hyp-001`,
      from_state: "proposed",
      to_state: "contracted",
      contract_hash: "deadbeef",
      ts: "2026-05-31T00:00:00.000Z",
    });

    assert.equal(event.kind, "node.transitioned");
    assert.equal(event.payload.node_id, "TG-H-hyp-001");
    assert.equal(event.payload.from_state, "proposed");
    assert.equal(event.payload.to_state, "contracted");
    assert.equal(event.payload.contract_hash, "deadbeef");
    // Optional fields stay omitted when not provided.
    assert.equal(event.payload.prep_token, undefined);
    assert.equal(event.payload.output_hash, undefined);
    assert.equal(event.payload.failure_reason, undefined);
    assert.equal(event.payload.edge_added_to, undefined);
    // Event id and hash bind the payload.
    assert.match(event.event_id, /^FE-/);
    assert.match(event.event_hash, /^[0-9a-f]{64}$/);

    // Reader projection finds the same event.
    const transitions = readNodeTransitions(domain);
    assert.equal(transitions.length, 1);
    assert.equal(transitions[0].event_id, event.event_id);
  });
});

test("physical dispatch proof is closed, dispatched-only, and materializes as a safe projection", () => {
  withTempHome(() => {
    const domain = "x1-physical-dispatch.example.com";
    appendHypothesisProposal({
      target_domain: domain,
      hypothesis_statement: "Physical dispatch proof fixture.",
      surface_refs: ["surface:physical-fixture"],
      proposal_id: "physical-dispatch",
    });
    appendNodeTransition({
      target_domain: domain,
      node_id: `${TASK_GRAPH_NODE_ID_PREFIX}H-physical-dispatch`,
      from_state: "proposed",
      to_state: "contracted",
    });
    appendNodeTransition({
      target_domain: domain,
      node_id: `${TASK_GRAPH_NODE_ID_PREFIX}H-physical-dispatch`,
      from_state: "contracted",
      to_state: "ready",
    });
    const binding = {
      source_graph_hash: "1".repeat(64),
      session_nucleus_hash: "2".repeat(64),
      resource_bundle_digest: "3".repeat(64),
      reservation_ref: "reservation:v1:test",
      receipt_digest: "4".repeat(64),
      allocation_plan_digest: "5".repeat(64),
      eligibility_digest: "6".repeat(64),
    };
    const event = appendNodeTransition({
      target_domain: domain,
      node_id: `${TASK_GRAPH_NODE_ID_PREFIX}H-physical-dispatch`,
      from_state: "ready",
      to_state: "dispatched",
      prep_token_hash: "7".repeat(64),
      physical_resource_dispatch: binding,
    });
    assert.deepEqual(event.payload.physical_resource_dispatch, binding);
    assert.equal(JSON.stringify(event).includes("fencing_token"), false);
    assert.deepEqual(
      materializeTaskGraph(domain, { write: false }).document.nodes[0]
        .physical_resource_dispatch,
      binding,
    );
    assert.throws(
      () => appendNodeTransition({
        target_domain: domain,
        node_id: `${TASK_GRAPH_NODE_ID_PREFIX}H-wrong-state`,
        from_state: "contracted",
        to_state: "ready",
        physical_resource_dispatch: binding,
      }),
      /valid only on a transition to dispatched/,
    );
    assert.throws(
      () => appendNodeTransition({
        target_domain: domain,
        node_id: `${TASK_GRAPH_NODE_ID_PREFIX}H-open-proof`,
        from_state: "ready",
        to_state: "dispatched",
        physical_resource_dispatch: { ...binding, raw_fence: "forbidden" },
      }),
      /unknown fields: raw_fence/,
    );
    assert.throws(
      () => appendNodeTransition({
        target_domain: domain,
        node_id: `${TASK_GRAPH_NODE_ID_PREFIX}H-no-prep-binding`,
        from_state: "ready",
        to_state: "dispatched",
        physical_resource_dispatch: binding,
      }),
      /requires an exact lowercase SHA-256 prep_token_hash/,
    );
  });
});

test("appendNodeTransition refuses out-of-order transitions at append time", () => {
  withTempHome(() => {
    const domain = "x1-out-of-order.example.com";
    let caught = null;
    try {
      appendNodeTransition({
        target_domain: domain,
        node_id: `${TASK_GRAPH_NODE_ID_PREFIX}n1`,
        from_state: "proposed",
        // proposed → ready is NOT in the frozen table; proposed must first
        // be contracted (or abandoned).
        to_state: "ready",
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "must reject out-of-order transition");
    assert.equal(caught.code, "invalid_node_transition");
    assert.match(caught.message, /invalid_node_transition/);
    // The append never persisted the event.
    assert.equal(readNodeTransitions(domain).length, 0);
  });
});

test("appendNodeTransition refuses a TaskGraph node id without the TG- prefix", () => {
  withTempHome(() => {
    assert.throws(
      () =>
        appendNodeTransition({
          target_domain: "x1-id-prefix.example.com",
          node_id: "surface:not-a-tg-id",
          from_state: "proposed",
          to_state: "contracted",
        }),
      /node_id must match TG-/,
    );
  });
});

test("appendNodeTransition carries edge_added_to[] when ready/finalize unblocks downstream", () => {
  withTempHome(() => {
    const domain = "x1-edges.example.com";
    appendHypothesisProposal({
      target_domain: domain,
      hypothesis_statement: "Finalized node unblocks downstream work.",
      surface_refs: ["surface:root"],
      proposal_id: "root",
    });
    const nodeId = `${TASK_GRAPH_NODE_ID_PREFIX}H-root`;
    for (const [fromState, toState] of [
      ["proposed", "contracted"],
      ["contracted", "ready"],
      ["ready", "dispatched"],
      ["dispatched", "executed"],
      ["executed", "verified"],
    ]) {
      appendNodeTransition({
        target_domain: domain,
        node_id: nodeId,
        from_state: fromState,
        to_state: toState,
      });
    }
    const event = appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "verified",
      to_state: "finalized",
      output_hash: "sha256:beef",
      edge_added_to: [
        `${TASK_GRAPH_NODE_ID_PREFIX}child-a`,
        `${TASK_GRAPH_NODE_ID_PREFIX}child-b`,
      ],
    });
    assert.deepEqual(event.payload.edge_added_to, ["TG-child-a", "TG-child-b"]);
  });
});

test("generic frontier append cannot mint TaskGraph state transitions", () => {
  withTempHome(() => {
    const domain = "x1-generic-transition-refusal.example.com";
    assert.equal(DIRECT_FRONTIER_EVENT_KINDS.includes("node.transitioned"), false);
    assert.throws(
      () => appendFrontierEvent({
        target_domain: domain,
        kind: "node.transitioned",
        payload: {
          node_id: "TG-H-forged",
          from_state: "proposed",
          to_state: "finalized",
        },
      }),
      (error) => error && error.code === "INVALID_ARGUMENTS",
    );
    assert.equal(readFrontierEvents(domain).length, 0);
    assert.equal(
      getRegisteredTool("bob_append_frontier_event").inputSchema.properties.kind.enum
        .includes("node.transitioned"),
      false,
    );
  });
});

test("sanctioned transition writer requires a proposal and atomically rejects a stale head", () => {
  withTempHome(() => {
    const domain = "x1-live-head-cas.example.com";
    assert.throws(
      () => appendNodeTransition({
        target_domain: domain,
        node_id: "TG-H-missing",
        from_state: "proposed",
        to_state: "contracted",
      }),
      (error) => error && error.code === "node_not_proposed"
        && error.details.current_state === null,
    );

    appendHypothesisProposal({
      target_domain: domain,
      hypothesis_statement: "Only one writer may advance this graph head.",
      surface_refs: ["surface:cas"],
      proposal_id: "cas",
    });
    appendNodeTransition({
      target_domain: domain,
      node_id: "TG-H-cas",
      from_state: "proposed",
      to_state: "contracted",
    });
    assert.throws(
      () => appendNodeTransition({
        target_domain: domain,
        node_id: "TG-H-cas",
        from_state: "proposed",
        to_state: "contracted",
      }),
      (error) => error && error.code === "stale_node_transition"
        && error.details.current_state === "contracted",
    );
    assert.equal(readNodeTransitions(domain).length, 1);
  });
});

// ─── appendTransitionProposal: prose cap + enum guard ────────────────────

test("appendTransitionProposal emits observation.recorded with payload.kind transition_proposed", () => {
  withTempHome(() => {
    const domain = "x1-tp.example.com";
    const event = appendTransitionProposal({
      target_domain: domain,
      from_surface: "surface:web-auth",
      to_surface: "surface:evm-vault",
      kind: "identity_propagation",
      trust_assumption: "JWT sub equals msg.sender on the vault contract.",
      evidence_refs: ["http_record:R7"],
    });
    assert.equal(event.kind, "observation.recorded");
    assert.equal(event.payload.kind, "transition_proposed");
    assert.equal(event.payload.from_surface, "surface:web-auth");
    assert.equal(event.payload.to_surface, "surface:evm-vault");
    assert.equal(event.payload.transition_kind, "identity_propagation");
    assert.match(event.payload.trust_assumption, /JWT sub equals msg.sender/);
    assert.deepEqual(event.payload.evidence_refs, ["http_record:R7"]);

    const proposals = readTransitionProposals(domain);
    assert.equal(proposals.length, 1);
    assert.equal(proposals[0].event_id, event.event_id);
  });
});

test("appendTransitionProposal refuses an out-of-enum transition kind", () => {
  withTempHome(() => {
    assert.throws(
      () =>
        appendTransitionProposal({
          target_domain: "x1-tp-bad.example.com",
          from_surface: "surface:a",
          to_surface: "surface:b",
          // Not in the X-D3 enum.
          kind: "magic_handoff",
          trust_assumption: "ok",
        }),
      /kind must be one of/,
    );
  });
});

test("appendTransitionProposal refuses identical from_surface and to_surface", () => {
  withTempHome(() => {
    assert.throws(
      () =>
        appendTransitionProposal({
          target_domain: "x1-tp-loop.example.com",
          from_surface: "surface:a",
          to_surface: "surface:a",
          kind: "identity_propagation",
          trust_assumption: "ok",
        }),
      /must differ/,
    );
  });
});

test("appendTransitionProposal fires prose_too_long on oversize trust_assumption (513 chars)", () => {
  withTempHome(() => {
    let caught = null;
    try {
      appendTransitionProposal({
        target_domain: "x1-tp-prose.example.com",
        from_surface: "surface:a",
        to_surface: "surface:b",
        kind: "trust_handoff",
        // 513 chars — one over the 512 cap.
        trust_assumption: "x".repeat(513),
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "must reject oversize prose");
    assert.equal(caught.code, "prose_too_long");
    assert.equal(caught.details.field, "trust_assumption");
    assert.equal(caught.details.length, 513);
    assert.equal(caught.details.max_chars, 512);
  });
});

test("appendTransitionProposal accepts trust_assumption at exactly the 512-char cap", () => {
  withTempHome(() => {
    const event = appendTransitionProposal({
      target_domain: "x1-tp-exact.example.com",
      from_surface: "surface:a",
      to_surface: "surface:b",
      kind: "value_movement",
      trust_assumption: "x".repeat(512),
    });
    assert.equal(event.payload.trust_assumption.length, 512);
  });
});

// ─── appendHypothesisProposal: prose cap + surface_refs guard ────────────

test("appendHypothesisProposal emits observation.recorded with payload.kind hypothesis_proposed", () => {
  withTempHome(() => {
    const domain = "x1-hp.example.com";
    const event = appendHypothesisProposal({
      target_domain: domain,
      hypothesis_statement: "Token rebalance routes can be replayed within the gas-relayer window.",
      surface_refs: ["surface:relayer-rebalance"],
      suggested_contract: {
        invariants: [{ id: "I-1", statement: "Each relayed tx executes at most once." }],
      },
    });
    assert.equal(event.kind, "observation.recorded");
    assert.equal(event.payload.kind, "hypothesis_proposed");
    assert.deepEqual(event.payload.surface_refs, ["surface:relayer-rebalance"]);
    assert.equal(
      event.payload.hypothesis_statement,
      "Token rebalance routes can be replayed within the gas-relayer window.",
    );
    assert.ok(event.payload.suggested_contract);

    const proposals = readHypothesisProposals(domain);
    assert.equal(proposals.length, 1);
    assert.equal(proposals[0].event_id, event.event_id);
  });
});

test("appendHypothesisProposal fires prose_too_long on oversize statement", () => {
  withTempHome(() => {
    let caught = null;
    try {
      appendHypothesisProposal({
        target_domain: "x1-hp-prose.example.com",
        hypothesis_statement: "x".repeat(600),
        surface_refs: ["surface:a"],
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "must reject oversize prose");
    assert.equal(caught.code, "prose_too_long");
    assert.equal(caught.details.field, "hypothesis_statement");
    assert.equal(caught.details.length, 600);
    assert.equal(caught.details.max_chars, 512);
  });
});

test("appendHypothesisProposal refuses an empty surface_refs array", () => {
  withTempHome(() => {
    assert.throws(
      () =>
        appendHypothesisProposal({
          target_domain: "x1-hp-empty.example.com",
          hypothesis_statement: "y",
          surface_refs: [],
        }),
      /surface_refs must contain at least one/,
    );
  });
});

// ─── Causality: append order is preserved + reader filters by kind ───────

test("ledger preserves append order across mixed proposal + transition writes", () => {
  withTempHome(() => {
    const domain = "x1-causality.example.com";
    const a = appendHypothesisProposal({
      target_domain: domain,
      hypothesis_statement: "Hypothesis A.",
      surface_refs: ["surface:a"],
      proposal_id: "node-1",
      ts: "2026-05-31T00:00:01.000Z",
    });
    const b = appendTransitionProposal({
      target_domain: domain,
      from_surface: "surface:a",
      to_surface: "surface:b",
      kind: "identity_propagation",
      trust_assumption: "Carrying identity across two surfaces.",
      ts: "2026-05-31T00:00:02.000Z",
    });
    const c = appendNodeTransition({
      target_domain: domain,
      node_id: "TG-H-node-1",
      from_state: "proposed",
      to_state: "contracted",
      contract_hash: "hash-1",
      ts: "2026-05-31T00:00:03.000Z",
    });

    const events = readFrontierEvents(domain);
    assert.equal(events.length, 3);
    assert.equal(events[0].event_id, a.event_id);
    assert.equal(events[1].event_id, b.event_id);
    assert.equal(events[2].event_id, c.event_id);

    // Each reader projects only its kind.
    assert.equal(readHypothesisProposals(domain).length, 1);
    assert.equal(readTransitionProposals(domain).length, 1);
    assert.equal(readNodeTransitions(domain).length, 1);
  });
});

// ─── Proposal tools (bob_propose_hypothesis / bob_propose_transition) ────

test("bob_propose_hypothesis tool roundtrips an event and reports the payload kind", () => {
  withTempHome(() => {
    const handler = TOOL_HANDLERS.bob_propose_hypothesis;
    assert.ok(typeof handler === "function", "tool registered");
    const raw = handler({
      target_domain: "x1-tool-hp.example.com",
      hypothesis_statement: "Refund-flow accepts cross-tenant tokens.",
      surface_refs: ["surface:refund-flow"],
    });
    const result = JSON.parse(raw);
    assert.equal(result.appended, true);
    assert.equal(result.kind, "observation.recorded");
    assert.equal(result.payload_kind, "hypothesis_proposed");
    assert.equal(result.target_domain, "x1-tool-hp.example.com");
    assert.match(result.event_id, /^FE-/);
  });
});

test("bob_propose_transition tool roundtrips an event and reports the payload kind", () => {
  withTempHome(() => {
    const domain = "x1-tool-tp.example.com";
    // X.3 endpoint-existence gate: seed both surfaces before proposing.
    seedMaterializedSurface(domain, "surface:auth");
    seedMaterializedSurface(domain, "surface:vault");
    const handler = TOOL_HANDLERS.bob_propose_transition;
    assert.ok(typeof handler === "function", "tool registered");
    const raw = handler({
      target_domain: domain,
      from_surface: "surface:auth",
      to_surface: "surface:vault",
      kind: TRANSITION_KIND_VALUES[0],
      trust_assumption: "Auth response identity is trusted by the on-chain vault.",
    });
    const result = JSON.parse(raw);
    assert.equal(result.appended, true);
    assert.equal(result.kind, "observation.recorded");
    assert.equal(result.payload_kind, "transition_proposed");
    assert.equal(result.target_domain, domain);
  });
});

test("bob_propose_hypothesis tool surfaces the prose_too_long failure as a thrown error", () => {
  withTempHome(() => {
    const handler = TOOL_HANDLERS.bob_propose_hypothesis;
    let caught = null;
    try {
      handler({
        target_domain: "x1-tool-cap.example.com",
        hypothesis_statement: "x".repeat(1024),
        surface_refs: ["surface:a"],
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "must reject oversize prose");
    assert.equal(caught.code, "prose_too_long");
  });
});

test("bob_propose_transition tool surfaces the prose_too_long failure as a thrown error", () => {
  withTempHome(() => {
    const domain = "x1-tool-cap-tp.example.com";
    // X.3 endpoint-existence gate: seed both surfaces so the prose-cap error
    // (not the endpoint-existence error) fires in this test.
    seedMaterializedSurface(domain, "surface:a");
    seedMaterializedSurface(domain, "surface:b");
    const handler = TOOL_HANDLERS.bob_propose_transition;
    let caught = null;
    try {
      handler({
        target_domain: domain,
        from_surface: "surface:a",
        to_surface: "surface:b",
        kind: "trust_handoff",
        trust_assumption: "x".repeat(1024),
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "must reject oversize prose");
    assert.equal(caught.code, "prose_too_long");
  });
});
