"use strict";

// DONE-condition verification — the coverage-cell engine end-to-end on BOTH
// target classes (web/SC and OSS), driving the REAL tools (not re-implementations):
//
//   bob_materialize_cell_floor  — enumerate + auto-contract the reachable floor
//   selectNextExecutableNodes   — tier-ordered dispatch through the graph-scheduler
//   logCellCoverage             — the reconcile bob_finalize_node performs on a verified cell
//   uncovered_reachable_cells   — the closure gate (blocks while uncovered, clears when covered)
//   floor_at_fixpoint           — G1 monotone-expansion termination
//   coverageClosureStat         — H1 coverage measured into the audit output
//
// This is the integration that ties the whole hypergraph together: the floor is
// enumerated, dispatched breadth-first, reconciled into falsifiable coverage,
// gated at freeze, run to a fixpoint, and surfaced as covered==total.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendFrontierEvent } = require("../mcp/core/frontier/frontier-events.js");
const { materializeFrontier } = require("../mcp/core/frontier/frontier-materializer.js");
const { appendTransitionProposal } = require("../mcp/core/waves/task-graph-events.js");
const { logCellCoverage, buildCoverageSummaryForSurface, readCoverageRecordsFromJsonl } = require("../mcp/core/frontier/coverage.js");
const { writeQueuePolicy, normalizeQueuePolicy, DEFAULT_QUEUE_POLICY } = require("../mcp/core/io/queue-policy.js");
const { selectNextExecutableNodes } = require("../mcp/core/waves/graph-scheduler.js");
const { materializeTaskGraph } = require("../mcp/core/waves/task-graph-materializer.js");
const { evaluateSchedulerPrecondition } = require("../mcp/core/waves/scheduler-preconditions.js");
const { coverageClosureStat } = require("../mcp/core/frontier/coverage-closure.js");
const { transitionEdgeToken } = require("../mcp/core/session/assignment-brief.js");

const floor = require("../mcp/tools/materialize-cell-floor.js").handler;

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-coverage-e2e-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function gate(domain) {
  return evaluateSchedulerPrecondition("uncovered_reachable_cells", { target_domain: domain });
}

// Reconcile every dispatch-eligible cell node the scheduler hands back, as
// bob_finalize_node does on a verified cell — recovering each cell's
// (surface_id, bug_class, auth_profile) from its proposal and writing coverage.
function coverDispatchedCells(domain) {
  const { readCellProposals } = require("../mcp/core/waves/task-graph-events.js");
  const { cellNodeId } = require("../mcp/core/waves/task-graph-materializer.js");
  const proposalByNode = new Map();
  for (const ev of readCellProposals(domain)) {
    const p = ev && ev.payload;
    if (p && typeof p.cell_key === "string") proposalByNode.set(cellNodeId({ cellKey: p.cell_key }), p);
  }
  const sel = selectNextExecutableNodes(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_children: 64 }), 128);
  let covered = 0;
  for (const node of sel.selected) {
    if (node.kind !== "cell") continue;
    const p = proposalByNode.get(node.node_id);
    if (!p) continue;
    logCellCoverage({
      target_domain: domain,
      surface_id: p.surface_id,
      bug_class: p.bug_class,
      auth_profile: p.auth_profile || "",
      status: "tested",
      evidence_summary: "e2e probe",
    });
    covered += 1;
  }
  return { dispatched: sel.selected.filter((n) => n.kind === "cell").length, covered };
}

test("DONE verification — web/SC session: floor → dispatch → reconcile → gate → fixpoint → coverage", () => {
  withTempHome(() => {
    const domain = "e2e-websc.example.com";
    // A web surface with bug-class hints + a cross-surface transition (the A2
    // L1->L2 invariant the per-surface model cannot see).
    appendFrontierEvent({ target_domain: domain, kind: "surface.observed", ts: "2026-05-31T00:00:00.000Z", surface_id: "surface:api", payload: { title: "api", bug_class_hints: ["idor", "ssrf"] } });
    appendFrontierEvent({ target_domain: domain, kind: "surface.observed", ts: "2026-05-31T00:00:00.000Z", surface_id: "surface:ledger", payload: { title: "ledger", bug_class_hints: ["idor"] } });
    materializeFrontier(domain, { write: true });
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_children: 64 }));
    appendTransitionProposal({ target_domain: domain, ts: "2026-05-31T00:01:00.000Z", from_surface: "surface:api", to_surface: "surface:ledger", kind: "value_movement", trust_assumption: "api value trusted on ledger", proposal_id: "TR-e2e" });

    // 1. Enumerate + auto-contract the floor (surface cells + A2 transition cells).
    const m0 = JSON.parse(floor({ target_domain: domain }));
    assert.ok(m0.cells_emitted > 0, "the floor enumerated reachable cells");
    assert.ok(m0.transition_cells_emitted >= 2, "the cross-surface transition cells were enumerated (A2)");
    assert.equal(m0.floor_at_fixpoint, false, "fresh floor is not yet at fixpoint");
    assert.equal(m0.cells_contracted, m0.cells_emitted, "every cell auto-contracted (dispatch-eligible)");

    // 2. The closure gate BLOCKS freeze while cells are uncovered (D1 teeth).
    const blocked = gate(domain);
    assert.equal(blocked.cell_floor_active, true);
    assert.equal(blocked.satisfied, false);
    assert.ok(blocked.uncovered_count > 0);

    // 3. Dispatch (graph-scheduler) + reconcile each cell (finalize → coverage),
    //    re-running the producer to fixpoint (G1 outer loop).
    let guard = 0;
    while (guard++ < 50) {
      coverDispatchedCells(domain);
      const m = JSON.parse(floor({ target_domain: domain }));
      if (m.floor_at_fixpoint === true) break;
    }
    assert.ok(guard < 50, "the producer→drain loop reached a fixpoint in bounded iterations");

    // 4. At fixpoint: the gate CLEARS and coverage is complete.
    const cleared = gate(domain);
    assert.equal(cleared.satisfied, true, "closure gate clears once every Tier-1 cell is covered");
    assert.equal(cleared.uncovered_count, 0);

    // 5. Coverage is MEASURED into the audit output (H1): covered == total.
    const stat = coverageClosureStat(domain);
    assert.equal(stat.cell_floor_active, true);
    assert.ok(stat.total_reachable_cells > 0);
    assert.equal(stat.uncovered_reachable_cells, 0);
    assert.equal(stat.covered_cells, stat.total_reachable_cells, "the whole reachable floor is covered");

    // 6. The A2 transition edge was actually reconciled (cross-surface coverage).
    const edgeToken = transitionEdgeToken("surface:api", "surface:ledger", "value_movement");
    const edgeSummary = buildCoverageSummaryForSurface(readCoverageRecordsFromJsonl(domain), edgeToken);
    assert.ok((edgeSummary.tested || []).length > 0, "the cross-surface transition invariant was probed");
  });
});

test("DONE verification — OSS repo session: sanitizer×input floor → fixpoint → coverage", () => {
  withTempHome(() => {
    const domain = "e2e-oss.example.com";
    // An OSS native-code harness: cells = sanitizer × input_class, no auth axis.
    appendFrontierEvent({ target_domain: domain, kind: "surface.observed", ts: "2026-05-31T00:00:00.000Z", surface_id: "surface:harness", payload: { title: "harness", surface_type: "oss_native_code" } });
    materializeFrontier(domain, { write: true });
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_children: 64 }));

    // 1. The OSS floor fans 3 sanitizers × 3 input classes = 9 cells.
    const m0 = JSON.parse(floor({ target_domain: domain }));
    assert.equal(m0.cells_emitted, 9, "OSS surface fans sanitizer × input_class with no auth axis");
    assert.equal(m0.transition_cells_emitted, 0, "no transitions in a single-harness OSS session");
    assert.equal(m0.floor_at_fixpoint, false);

    // 2. Gate blocks; the scheduler dispatches the 9 cells.
    assert.equal(gate(domain).satisfied, false);
    const doc = materializeTaskGraph(domain, { write: false }).document;
    assert.equal(doc.nodes.filter((n) => n.kind === "cell").length, 9);

    // 3. Reconcile to fixpoint.
    let guard = 0;
    while (guard++ < 20) {
      coverDispatchedCells(domain);
      if (JSON.parse(floor({ target_domain: domain })).floor_at_fixpoint === true) break;
    }
    assert.ok(guard < 20, "OSS floor reached a fixpoint");

    // 4. Gate clears; coverage complete.
    assert.equal(gate(domain).satisfied, true);
    const stat = coverageClosureStat(domain);
    assert.equal(stat.total_reachable_cells, 9);
    assert.equal(stat.covered_cells, 9);
    assert.equal(stat.uncovered_reachable_cells, 0);
  });
});

// Stuck-cell termination backstop (review C1/critical): an unsatisfiable cell that
// NEVER reconciles (e.g. needs auth the session lacks → fails its witness → writes no
// coverage) must not wedge the materialize→drain fixpoint or block CLAIM_FREEZE forever.
test("stuck cell that never covers is auto-blocked → floor reaches fixpoint and the gate clears", () => {
  withTempHome(() => {
    const domain = "e2e-stuck.example.com";
    appendFrontierEvent({ target_domain: domain, kind: "surface.observed", ts: "2026-05-31T00:00:00.000Z", surface_id: "surface:api", payload: { title: "api", bug_class_hints: ["idor", "ssrf"] } });
    materializeFrontier(domain, { write: true });
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_children: 64 }));

    // Drive the producer WITHOUT ever covering a cell (simulating cells that keep
    // failing their witness). Without the backstop this loops forever (always
    // uncovered → re-emitted → floor never at fixpoint).
    let reachedFixpoint = false;
    let sawAutoBlock = false;
    let guard = 0;
    while (guard++ < 12) {
      const m = JSON.parse(floor({ target_domain: domain }));
      if (m.auto_blocked_cell_count > 0) sawAutoBlock = true;
      if (m.floor_at_fixpoint === true) { reachedFixpoint = true; break; }
    }
    assert.equal(sawAutoBlock, true, "cells re-proposed past the threshold are auto-blocked");
    assert.equal(reachedFixpoint, true, "the fixpoint terminates even though NO cell was ever covered");

    // Blocked is terminal: the closure gate treats auto-blocked cells as covered, so
    // freeze is no longer wedged. coverage rows exist, all status 'blocked'.
    assert.equal(gate(domain).satisfied, true, "closure gate clears once stuck cells are auto-blocked");
    const rows = readCoverageRecordsFromJsonl(domain);
    assert.ok(rows.length > 0, "auto-block wrote terminal coverage rows");
    assert.ok(rows.every((r) => r.status === "blocked"), "every reconciled row is 'blocked' (none were ever tested)");
  });
});
