"use strict";

// bob_materialize_cell_floor — the cell-floor producer. Sweeps the surface
// inventory and emits one cell_proposed observation.recorded event per
// deriveChildFanoutPlan child cell (the reachable (element x bug_class x
// auth_role) coverage obligations; OSS surfaces fan out (sanitizer x input_class)
// with no auth axis). The X.2 materializer folds each into a schedulable 'cell'
// TaskGraph node. Already-covered cells are pruned. Coverage is the brain's,
// deterministic and exhaustive — the floor is enumerated regardless of the
// (parked) nesting depth budget. Single-spawner: the orchestrator appends; no
// worker spawn. Cells key on the REAL parent surface_id (never synthetic).

const { assertNonEmptyString } = require("../core/io/validation.js");
const { currentSurfaces } = require("../core/frontier/frontier-projections.js");
const {
  buildCoverageSummaryForSurface,
  readCoverageRecordsFromJsonl,
} = require("../core/frontier/coverage.js");
const { appendCellProposal, readCellProposals } = require("../core/waves/task-graph-events.js");
const { cellNodeId, materializeTaskGraph } = require("../core/waves/task-graph-materializer.js");
const { appendContract } = require("../core/contract/index.js");
const { buildCellCoverageContract } = require("../core/contract/index.js");
const { loadQueuePolicy } = require("../core/io/queue-policy.js");
const { scheduleMaterialization } = require("../core/frontier/frontier-materialize-debounce.js");

// One level of cells per surface — the floor is enumerated, not the nesting
// depth budget (which gates the parked agent-spawns-children actuation).
const FLOOR_REMAINING_DEPTH = 1;

// Stuck-cell backstop. The materialize→drain fixpoint terminates because coverage
// is monotone — but ONLY if every dispatched cell reconciles to a TERMINAL coverage
// status (tested/blocked). A cell whose evaluator keeps finalizing non-terminal
// (promising/needs_auth/requeue) — or fails its mechanical witness and writes no
// coverage row at all — is re-emitted every pass, never shrinks the floor, and would
// block OPEN_FRONTIER→CLAIM_FREEZE forever. Each pass appends one cell_proposed per
// re-emitted cell, so the count of cell_proposed events for a cell_key IS its emission
// tally. A cell re-proposed this many times without covering is AUTO-RECORDED `blocked`
// (a terminal status the prune + closure gate treat as covered) and not re-emitted —
// a deterministic termination guarantee that does not depend on an LLM-orchestrator
// action. This is a backstop after the cell got real dispatch attempts, never a
// premature close: `blocked` is recoverable (an operator can clear it and re-probe).
const STUCK_CELL_EMISSION_THRESHOLD = 3;

function handler(args) {
  const domain = assertNonEmptyString((args || {}).target_domain, "target_domain");
  // Lazy-require the planner: assignment-brief.js pulls a large dependency graph;
  // requiring it at module-load (this tool is loaded by tools/index.js) risks a
  // cycle. Resolved on first call when the registry has fully materialized.
  const { planCellsForSurface, enumerateTransitionCellFloor } = require("../core/session/assignment-brief.js");

  const policy = loadQueuePolicy(domain);
  const surfaces = currentSurfaces(domain).surfaces || [];
  const coverageRecords = readCoverageRecordsFromJsonl(domain);

  // Prior emission tally per cell_key (one cell_proposed per re-emit across passes)
  // — the basis for the stuck-cell backstop below.
  const priorEmissionByCellKey = new Map();
  for (const ev of readCellProposals(domain)) {
    const ck = ev && ev.payload && ev.payload.cell_key;
    if (typeof ck === "string" && ck) priorEmissionByCellKey.set(ck, (priorEmissionByCellKey.get(ck) || 0) + 1);
  }
  const { logCellCoverage } = require("../core/frontier/coverage.js");
  const autoBlockedCells = [];
  // Returns true if the cell should be (re-)emitted, false if it was auto-blocked.
  // A cell re-proposed STUCK_CELL_EMISSION_THRESHOLD times without reaching terminal
  // coverage is recorded `blocked` (a terminal status the floor prune + closure gate
  // treat as covered) and NOT re-emitted — a DETERMINISTIC termination guarantee that
  // does not depend on an LLM-orchestrator action. `blocked` is recoverable: an
  // operator can clear it and re-probe.
  const emitOrAutoBlock = (child) => {
    const prior = priorEmissionByCellKey.get(child.cell_key) || 0;
    if (prior >= STUCK_CELL_EMISSION_THRESHOLD) {
      try {
        logCellCoverage({
          target_domain: domain,
          surface_id: child.surface_id,
          bug_class: child.bug_class,
          auth_profile: child.auth_profile || null,
          status: "blocked",
          evidence_summary: `auto-blocked: cell re-proposed ${prior} times without reaching terminal coverage`,
        });
        autoBlockedCells.push({
          cell_key: child.cell_key,
          surface_id: child.surface_id,
          bug_class: child.bug_class,
          auth_profile: child.auth_profile || null,
          emissions: prior,
        });
        return false;
      } catch {
        // A failed block just retries next pass — never a worse state than today.
      }
    }
    return true;
  };

  let cellsEmitted = 0;
  let surfacesWithCells = 0;
  const perSurface = [];
  for (const surfaceObj of surfaces) {
    const surfaceId = surfaceObj && surfaceObj.id;
    if (typeof surfaceId !== "string" || !surfaceId) continue;
    const coverageSummary = buildCoverageSummaryForSurface(coverageRecords, surfaceId);
    const plan = planCellsForSurface({
      domain,
      surfaceObj,
      surfaceId,
      coverageSummary,
      remainingDepth: FLOOR_REMAINING_DEPTH,
      maxChildren: policy.max_spawn_children,
    });
    if (!plan || !Array.isArray(plan.children) || plan.children.length === 0) continue;
    let emittedForSurface = 0;
    for (const child of plan.children) {
      if (!emitOrAutoBlock(child)) continue;
      appendCellProposal({
        target_domain: domain,
        surface_id: child.surface_id,
        cell_key: child.cell_key,
        bug_class: child.bug_class,
        auth_profile: child.auth_profile,
        technique_pack_ids: child.technique_pack_ids || [],
        capability_pack_ids: child.capability_pack_ids || [],
        planning_key: child.planning_key,
        actor: "orchestrator",
      });
      cellsEmitted += 1;
      emittedForSurface += 1;
    }
    if (emittedForSurface === 0) continue;
    surfacesWithCells += 1;
    perSurface.push({ surface_id: surfaceId, cells: emittedForSurface });
  }

  // Transition-cell floor (A2): cross-surface invariants on EDGES. Each proposed
  // transition fans a kind-specific bug_class axis into (edge x bug_class) cells.
  // They ride the IDENTICAL cell_proposed -> cell-node -> cell-contract path; the
  // proposal carries both endpoint surfaces (grounding) plus the edge token as
  // the cell's coverage identity (surface_id). Emitted BEFORE Pass 2 so they
  // auto-contract in the same sweep.
  let transitionCellsEmitted = 0;
  let edgesWithCells = 0;
  for (const edge of enumerateTransitionCellFloor({
    domain,
    coverageRecords,
    maxChildren: policy.max_spawn_children,
  })) {
    const children = edge.plan && Array.isArray(edge.plan.children) ? edge.plan.children : [];
    if (children.length === 0) continue;
    let emittedForEdge = 0;
    for (const child of children) {
      // S5
      if (!emitOrAutoBlock(child)) continue;
      appendCellProposal({
        target_domain: domain,
        surface_id: child.surface_id,
        from_surface: edge.from_surface,
        to_surface: edge.to_surface,
        cell_key: child.cell_key,
        bug_class: child.bug_class,
        auth_profile: child.auth_profile,
        technique_pack_ids: child.technique_pack_ids || [],
        capability_pack_ids: child.capability_pack_ids || [],
        planning_key: child.planning_key,
        actor: "orchestrator",
      });
      transitionCellsEmitted += 1;
      emittedForEdge += 1;
    }
    if (emittedForEdge > 0) edgesWithCells += 1;
  }
  cellsEmitted += transitionCellsEmitted;

  // E2 residual depth re-probes (default-off, advisory): when an operator opts
  // in, re-propose covered cells on residual-flagged surfaces as Tier-2 depth
  // re-probes. They ride the SAME cell_proposed -> cell-node -> contract path
  // (auto-contracted in Pass 2) but carry tier=2 so C1 dispatches them after all
  // Tier-1 breadth. Non-gating: a Tier-2 re-probe is never counted by the
  // closure gate (which re-derives only the Tier-1 floor). Flag off -> no
  // residual read, no Tier-2 cell, byte-identical floor.
  let reprobeCellsEmitted = 0;
  if (policy.residual_depth_reprobe_enabled === true) {
    try {
      const { deriveResidualDepthReprobes } = require("../core/belief/residual-depth.js");
      for (const reprobe of deriveResidualDepthReprobes(domain)) {
        appendCellProposal({
          target_domain: domain,
          surface_id: reprobe.surface_id,
          cell_key: reprobe.cell_key,
          bug_class: reprobe.bug_class,
          auth_profile: reprobe.auth_profile,
          technique_pack_ids: [],
          capability_pack_ids: [],
          tier: 2,
          actor: "orchestrator",
        });
        reprobeCellsEmitted += 1;
      }
    } catch {
      // Advisory: a residual-read failure must never regress the floor.
    }
  }
  cellsEmitted += reprobeCellsEmitted;
  // The Tier-1 fixpoint count is the surface + transition floor this pass
  // emitted, excluding E2 Tier-2 re-probes (which never converge to 0).
  const tier1CellsEmitted = cellsEmitted - reprobeCellsEmitted;

  // Pass 2: land cells dispatch-eligible. A cell is a self-defining coverage
  // obligation, so the orchestrator-driven MCP layer auto-attaches a synthetic
  // coverage Contract (proposed -> contracted) — no operator authors a per-cell
  // Contract, and the cell travels the existing prepare/finalize/verify chain
  // unchanged. Single-spawner: the orchestrator mints+attaches; no worker spawn.
  let cellsContracted = 0;
  if (cellsEmitted > 0) {
    // Materialize so freshly-emitted cells exist as 'proposed' nodes before the
    // contract's live-state check runs.
    const doc = materializeTaskGraph(domain, { write: true }).document;
    const proposalByNodeId = new Map();
    for (const ev of readCellProposals(domain)) {
      const payload = ev && ev.payload;
      if (!payload || typeof payload.cell_key !== "string") continue;
      proposalByNodeId.set(cellNodeId({ cellKey: payload.cell_key }), payload);
    }
    for (const node of doc.nodes) {
      if (node.kind !== "cell" || node.state !== "proposed") continue;
      const payload = proposalByNodeId.get(node.node_id);
      if (!payload) continue;
      appendContract({
        target_domain: domain,
        node_id: node.node_id,
        contract: buildCellCoverageContract({
          surfaceId: payload.surface_id,
          bugClass: payload.bug_class,
          authProfile: payload.auth_profile,
          cellKey: payload.cell_key,
        }),
        actor: "orchestrator",
      });
      cellsContracted += 1;
    }
    try {
      scheduleMaterialization(domain);
    } catch {
      // Materialization debounce is best-effort; do not regress the appends.
    }
  }

  return JSON.stringify({
    version: 1,
    target_domain: domain,
    surfaces_swept: surfaces.length,
    surfaces_with_cells: surfacesWithCells,
    cells_emitted: cellsEmitted,
    transition_cells_emitted: transitionCellsEmitted,
    reprobe_cells_emitted: reprobeCellsEmitted,
    // G1 fixpoint signal: the Tier-1 floor (surface + transition cells) ONLY —
    // it excludes the E2 Tier-2 re-probe component, which derives from
    // never-shrinking covered cells and so would never reach 0. The orchestrator
    // drives the producer->drain loop to fixpoint by repeating until
    // floor_at_fixpoint is true (no new Tier-1 obligation after a full drain).
    // This matches the closure gate's Tier-1-only uncovered count, so the loop
    // provably terminates: the reachable Tier-1 set is finite and coverage is
    // monotone, so emissions strictly decrease to 0 — a real fixpoint, not a timer.
    tier1_cells_emitted: tier1CellsEmitted,
    floor_at_fixpoint: tier1CellsEmitted === 0,
    edges_with_cells: edgesWithCells,
    cells_contracted: cellsContracted,
    // Stuck-cell backstop: cells re-proposed STUCK_CELL_EMISSION_THRESHOLD times
    // without reaching terminal coverage are auto-recorded `blocked` (terminal — the
    // floor prune + closure gate treat it as covered) and not re-emitted, so an
    // unsatisfiable cell can never wedge the materialize→drain fixpoint or block
    // OPEN_FRONTIER→CLAIM_FREEZE forever. Deterministic, not an LLM action.
    auto_blocked_cells: autoBlockedCells.slice(0, 50),
    auto_blocked_cell_count: autoBlockedCells.length,
    per_surface: perSurface.slice(0, 100),
  });
}

module.exports = Object.freeze({
  name: "bob_materialize_cell_floor",
  description:
    "Materialize the deterministic coverage-cell FLOOR: sweep the surface inventory "
    + "and emit one cell_proposed observation.recorded event per reachable "
    + "(element x bug_class x auth_role) cell (OSS surfaces fan out sanitizer x "
    + "input_class, no auth axis), which the materializer folds into schedulable "
    + "'cell' TaskGraph nodes. Already-covered cells are pruned; the floor is "
    + "enumerated regardless of the nesting depth budget. Single-spawner: the "
    + "orchestrator appends, no worker spawn.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
    },
    required: ["target_domain"],
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["frontier-events.jsonl"],
});
