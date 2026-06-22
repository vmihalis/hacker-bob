"use strict";

// Y.10 (Y-D12 / Y-P12) — scheduler-precondition registry.
//
// Each scheduler precondition is a closed-enum name that maps to a check
// function returning `{satisfied: boolean, blocked_surface_ids?: string[]}`.
// The runtime gate at bob_advance_session consults these checks before
// allowing OPEN_FRONTIER -> CLAIM_FREEZE; the CI marker scan at
// scripts/check-skill-scheduler-coherence.js consumes the closed enum to
// assert that committed skill / role markdown carries the `@precondition:`
// directive on the relevant state-block.
//
// The set is intentionally narrow: only conditions the runtime gate
// mechanically enforces appear here. New preconditions extend the enum
// AND register a check function in PRECONDITION_CHECKS at the same time
// (paired safety enforcement — see test/scheduler-preconditions-shape.test.js).

const {
  getLatestMergedWavePartialSurfaceIds,
} = require("./wave-handoff-store.js");

const SCHEDULER_PRECONDITION_VALUES = Object.freeze([
  "partial_surfaces_drained",
  "chain_work_terminal",
  "uncovered_reachable_cells",
]);

// Each check receives `{target_domain}` and returns an object with at minimum
// `{satisfied: boolean}`. When unsatisfied, the check MAY return additional
// structured context (e.g., `blocked_surface_ids`) that the gate surfaces in
// the STATE_CONFLICT payload.
const PRECONDITION_CHECKS = Object.freeze({
  partial_surfaces_drained(context) {
    const targetDomain = context && context.target_domain;
    if (typeof targetDomain !== "string" || targetDomain.length === 0) {
      throw new Error("partial_surfaces_drained: target_domain is required");
    }
    const blockedSurfaceIds = getLatestMergedWavePartialSurfaceIds(targetDomain);
    return {
      satisfied: blockedSurfaceIds.length === 0,
      blocked_surface_ids: blockedSurfaceIds,
    };
  },
  // Chain work that is recorded must produce a terminal structured chain
  // attempt before CLAIM_FREEZE. The required-work signal is the same one
  // pipeline-analytics surfaces as `chain_phase_no_attempts`
  // (findings.total >= 2 OR handoff chain_notes_count > 0); the precondition
  // reads it from the canonical session-artifact summary rather than
  // recomputing it, and is satisfied when no chain work is required or a
  // terminal attempt already exists.
  chain_work_terminal(context) {
    const targetDomain = context && context.target_domain;
    if (typeof targetDomain !== "string" || targetDomain.length === 0) {
      throw new Error("chain_work_terminal: target_domain is required");
    }
    const {
      readSessionArtifactSummary,
      chainWorkRequired,
    } = require("./pipeline-session-artifacts.js");
    const summary = readSessionArtifactSummary(targetDomain);
    const findingsTotal = summary && summary.findings && Number.isInteger(summary.findings.total)
      ? summary.findings.total
      : 0;
    const chainNotesCount = summary && summary.chain_handoffs
      && Number.isInteger(summary.chain_handoffs.chain_notes_count)
      ? summary.chain_handoffs.chain_notes_count
      : 0;
    const terminalTotal = summary && summary.chain_attempts
      && Number.isInteger(summary.chain_attempts.terminal_total)
      ? summary.chain_attempts.terminal_total
      : 0;
    const required = chainWorkRequired(summary);
    return {
      satisfied: !required || terminalTotal > 0,
      chain_work_required: required,
      findings_total: findingsTotal,
      chain_notes_count: chainNotesCount,
      terminal_total: terminalTotal,
    };
  },
  // Closure teeth: a frontier cannot freeze while reachable coverage cells
  // remain uncovered. SELF-ACTIVATING — a session that never materialized a
  // cell floor has no cell-coverage obligation and is vacuously satisfied, so
  // legacy/surface-only runs are unaffected; the gate only bites once the
  // orchestrator commits to cell coverage (cell nodes exist in the graph). The
  // uncovered count is the floor enumeration MINUS already-covered cells (the
  // same coverage-pruned planCellsForSurface the producer dispatches), so a cell
  // counts as covered exactly when bob_finalize_node reconciled a verified probe.
  uncovered_reachable_cells(context) {
    const targetDomain = context && context.target_domain;
    if (typeof targetDomain !== "string" || targetDomain.length === 0) {
      throw new Error("uncovered_reachable_cells: target_domain is required");
    }
    const { materializeTaskGraph } = require("./task-graph-materializer.js");
    const doc = materializeTaskGraph(targetDomain, { write: false }).document;
    const hasCellFloor = doc.nodes.some((node) => node.kind === "cell");
    if (!hasCellFloor) {
      return { satisfied: true, cell_floor_active: false, uncovered_count: 0 };
    }
    const { currentSurfaces } = require("./frontier-projections.js");
    const { buildCoverageSummaryForSurface, readCoverageRecordsFromJsonl } = require("./coverage.js");
    const { planCellsForSurface } = require("./assignment-brief.js");
    const { loadQueuePolicy } = require("./queue-policy.js");
    const policy = loadQueuePolicy(targetDomain);
    const surfaces = currentSurfaces(targetDomain).surfaces || [];
    const coverageRecords = readCoverageRecordsFromJsonl(targetDomain);
    let uncovered = 0;
    const uncoveredSurfaceIds = [];
    for (const surfaceObj of surfaces) {
      const surfaceId = surfaceObj && surfaceObj.id;
      if (typeof surfaceId !== "string" || !surfaceId) continue;
      const coverageSummary = buildCoverageSummaryForSurface(coverageRecords, surfaceId);
      const plan = planCellsForSurface({
        domain: targetDomain,
        surfaceObj,
        surfaceId,
        coverageSummary,
        remainingDepth: 1,
        maxChildren: policy.max_spawn_children,
      });
      const remaining = plan && Array.isArray(plan.children) ? plan.children.length : 0;
      if (remaining > 0) {
        uncovered += remaining;
        uncoveredSurfaceIds.push(surfaceId);
      }
    }
    // Transition-cell floor (A2): cross-surface invariants on edges are closure
    // obligations too. An unprobed (edge x bug_class) cell must block freeze, or
    // a cross-surface invariant (L1->L2 replay, deposit->distribute) would
    // evaporate between two surface evaluators.
    const { enumerateTransitionCellFloor } = require("./assignment-brief.js");
    for (const edge of enumerateTransitionCellFloor({
      domain: targetDomain,
      coverageRecords,
      maxChildren: policy.max_spawn_children,
    })) {
      const remaining = edge.plan && Array.isArray(edge.plan.children) ? edge.plan.children.length : 0;
      if (remaining > 0) {
        uncovered += remaining;
        uncoveredSurfaceIds.push(edge.edge_token);
      }
    }
    return {
      satisfied: uncovered === 0,
      cell_floor_active: true,
      uncovered_count: uncovered,
      uncovered_surface_ids: uncoveredSurfaceIds.slice(0, 50),
    };
  },
});

function evaluateSchedulerPrecondition(name, context) {
  if (!SCHEDULER_PRECONDITION_VALUES.includes(name)) {
    throw new Error(`unknown scheduler precondition: ${name}`);
  }
  const check = PRECONDITION_CHECKS[name];
  if (typeof check !== "function") {
    throw new Error(`scheduler precondition ${name} has no check function`);
  }
  return check(context || {});
}

module.exports = {
  SCHEDULER_PRECONDITION_VALUES,
  PRECONDITION_CHECKS,
  evaluateSchedulerPrecondition,
};
