"use strict";

// Pure, read-only coverage-closure stat for the human-facing audit output.
//
// Surfaces {covered, total, uncovered} reachable coverage cells WITHOUT gating
// anything — the annotate-don't-gate sibling of the CVSS/CWE annotation layer.
// It single-sources the cell-floor enumeration through deriveCellFloorForSurface
// (the same derivation the dispatch producer and the closure gate use), so the
// displayed stat can never drift from the gate's own definition of "covered".
//
// Two deliberate framings:
//   - total_reachable is the relevance-gated floor at the HARD cap, NOT the
//     budgeted dispatch slice the freeze gate counts. The denominator is the
//     true reachable floor, so covered + uncovered == total holds exactly
//     (budget_pruned_count is 0 at the hard cap).
//   - covered comes from covered_pruned_count (cells the pruner treats as
//     terminally reconciled), not raw coverage.jsonl rows — so it matches the
//     gate's covered set and never double-counts requeued/superseded probes.
//
// Vacuous (cell_floor_active:false, all zero) when the session has no cell
// floor, so legacy/surface-only runs render nothing. Fail-soft on every read:
// any error degrades to the vacuous stat rather than throwing into a writer.
//
// This module lazy-requires its heavy deps inside the function so it never
// participates in the coverage.js <-> assignment-brief.js require cycle.

function emptyClosure() {
  return {
    cell_floor_active: false,
    covered_cells: 0,
    total_reachable_cells: 0,
    uncovered_reachable_cells: 0,
  };
}

function coverageClosureStat(targetDomain) {
  if (typeof targetDomain !== "string" || targetDomain.length === 0) {
    return emptyClosure();
  }
  try {
    const { materializeTaskGraph } = require("./task-graph-materializer.js");
    const doc = materializeTaskGraph(targetDomain, { write: false }).document;
    const hasCellFloor = Array.isArray(doc.nodes)
      && doc.nodes.some((node) => node && node.kind === "cell");
    if (!hasCellFloor) return emptyClosure();

    const { currentSurfaces } = require("./frontier-projections.js");
    const { buildCoverageSummaryForSurface, readCoverageRecordsFromJsonl } = require("./coverage.js");
    const { deriveCellFloorForSurface } = require("./assignment-brief.js");
    const { CHILD_FANOUT_HARD_CAP } = require("./capability-pack-derivation.js");

    const surfaces = currentSurfaces(targetDomain).surfaces || [];
    const coverageRecords = readCoverageRecordsFromJsonl(targetDomain);
    let covered = 0;
    let uncovered = 0;
    for (const surfaceObj of surfaces) {
      const surfaceId = surfaceObj && surfaceObj.id;
      if (typeof surfaceId !== "string" || !surfaceId) continue;
      const coverageSummary = buildCoverageSummaryForSurface(coverageRecords, surfaceId);
      // The hard cap (not policy.max_spawn_children) keeps budget_pruned_count
      // at 0, so total == covered + uncovered is the true reachable floor — not
      // the budgeted dispatch slice the precondition gates on.
      const plan = deriveCellFloorForSurface({
        domain: targetDomain,
        surfaceObj,
        surfaceId,
        coverageSummary,
        remainingDepth: 1,
        maxChildren: CHILD_FANOUT_HARD_CAP,
      });
      if (!plan) continue;
      covered += Number.isFinite(plan.covered_pruned_count) ? plan.covered_pruned_count : 0;
      // Uncovered = the enumerated children PLUS any cells the cap dropped. At
      // the hard cap budget_pruned_count is 0 except on a surface with >64
      // uncovered reachable cells; counting it keeps total == covered+uncovered
      // exact at every scale (those dropped cells are reachable and not covered).
      const enumerated = Array.isArray(plan.children) ? plan.children.length : 0;
      const budgetDropped = Number.isFinite(plan.budget_pruned_count) ? plan.budget_pruned_count : 0;
      uncovered += enumerated + budgetDropped;
    }

    // Transition-cell floor (A2): cross-surface invariants on edges count toward
    // the same covered/total stat so it stays consistent with the closure gate.
    const { enumerateTransitionCellFloor } = require("./assignment-brief.js");
    for (const edge of enumerateTransitionCellFloor({
      domain: targetDomain,
      coverageRecords,
      maxChildren: CHILD_FANOUT_HARD_CAP,
    })) {
      const plan = edge.plan;
      if (!plan) continue;
      covered += Number.isFinite(plan.covered_pruned_count) ? plan.covered_pruned_count : 0;
      const enumerated = Array.isArray(plan.children) ? plan.children.length : 0;
      const budgetDropped = Number.isFinite(plan.budget_pruned_count) ? plan.budget_pruned_count : 0;
      uncovered += enumerated + budgetDropped;
    }
    return {
      cell_floor_active: true,
      covered_cells: covered,
      total_reachable_cells: covered + uncovered,
      uncovered_reachable_cells: uncovered,
    };
  } catch {
    return emptyClosure();
  }
}

module.exports = {
  coverageClosureStat,
};
