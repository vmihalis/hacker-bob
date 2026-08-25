"use strict";

// Cell-scoped, RAISE-only belief overlay for the graph-scheduler.
//
// The deterministic graph-scheduler (graph-scheduler.js) orders dispatch-
// eligible nodes by policy priority -> ts_first -> node_id. Coverage-floor
// cells all land at the same default priority with no promotion path, so among
// the floor their order collapses to a content-hash tie-break that carries no
// target signal. When an operator opts into belief_assisted_priority_enabled,
// this module supplies an OPTIONAL per-cell ordering signal: each cell inherits
// the belief score its PARENT SURFACE earns from the same belief machinery the
// wave planner uses (rankInterventions value-of-information + residual-anomaly
// hints, via buildBeliefSchedulerHints). That score becomes a tie-break the
// scheduler consults WITHIN a priority band — it never crosses a band, never
// drops or skips a cell, and is a pure no-op when no surface earns a hint (the
// returned map is empty and the scheduler falls through to its deterministic
// keys).
//
// Deliberately separate from applyBeliefSchedulerPriority: that path is
// surface-shaped (it decorates surface objects for the wave planner). This one
// consumes the graph's materialized cell nodes and returns only a
// Map<node_id, score>, so the deterministic scheduler stays free of the
// surface-decoration shape and pulls belief lazily, only when the flag is on.
//
// The signal is honest about the belief plane's limits: under uniform priors
// the value-of-information term is a per-candidate constant, so a cold belief
// window raises every matched-surface cell by the same amount (a band-internal
// reordering with no discrimination among matched surfaces). The signal sharpens
// only once a residual-anomaly hint or an elicited non-uniform prior exists —
// at which point hotter surfaces earn a strictly higher score. Either way the
// overlay can only RAISE, so it can never regress the deterministic baseline.

const DEFAULT_RANK_LIMIT = 25;

// Map each materialized cell node to its single parent surface_id. A cell is a
// leaf coverage obligation with exactly one surface_ref (task-graph-materializer
// grounds it in its parent surface); non-cell nodes are ignored here.
function parentSurfaceByCellNode(document) {
  const map = new Map();
  const nodes = Array.isArray(document && document.nodes) ? document.nodes : [];
  for (const node of nodes) {
    if (!node || node.kind !== "cell") continue;
    const refs = Array.isArray(node.surface_refs) ? node.surface_refs : [];
    if (refs.length > 0 && typeof refs[0] === "string") {
      map.set(node.node_id, refs[0]);
    }
  }
  return map;
}

// Build a RAISE-only Map<cell_node_id, belief_score>. Only cell candidates whose
// parent surface earns a positive belief score get an entry; every other node
// (cells with no matched surface, and all non-cell kinds) is absent and keeps
// its deterministic position. Never throws: any unavailable belief signal
// degrades to an empty map so the caller falls back to the deterministic spine.
function buildCellBeliefRank({
  target_domain,
  document,
  candidates,
  seed,
  rank_limit,
  surfaces: injectedSurfaces,
} = {}) {
  const cellCandidates = (Array.isArray(candidates) ? candidates : []).filter(
    (candidate) => candidate && candidate.kind === "cell",
  );
  if (cellCandidates.length === 0) return new Map();

  const surfaceByNode = parentSurfaceByCellNode(document);
  if (surfaceByNode.size === 0) return new Map();

  // Surfaces carry the token-matchable text (title/hosts/bug_class_hints/...)
  // and ranking the belief machinery scores against. Tests inject them directly;
  // production reads the authoritative projection. A read failure degrades to
  // the deterministic spine (empty map), never a throw.
  let surfaces = injectedSurfaces;
  if (!Array.isArray(surfaces)) {
    try {
      const { currentSurfaces } = require("../frontier/frontier-projections.js");
      const projection = currentSurfaces(target_domain);
      surfaces = Array.isArray(projection.surfaces) ? projection.surfaces : [];
    } catch {
      return new Map();
    }
  }
  if (surfaces.length === 0) return new Map();

  let hints;
  try {
    const { buildBeliefSchedulerHints } = require("./scheduler-priority.js");
    hints = buildBeliefSchedulerHints({
      target_domain,
      surfaces,
      seed,
      rank_limit: rank_limit || DEFAULT_RANK_LIMIT,
    });
  } catch {
    return new Map();
  }
  if (!hints || hints.applied !== true || !Array.isArray(hints.hints)) {
    return new Map();
  }

  const scoreBySurface = new Map();
  for (const hint of hints.hints) {
    if (hint && typeof hint.surface_id === "string" && typeof hint.score === "number") {
      scoreBySurface.set(hint.surface_id, hint.score);
    }
  }
  if (scoreBySurface.size === 0) return new Map();

  const rank = new Map();
  for (const candidate of cellCandidates) {
    const surfaceId = surfaceByNode.get(candidate.node_id);
    if (!surfaceId) continue;
    const score = scoreBySurface.get(surfaceId);
    // RAISE-only: only a strictly-positive belief score lifts a cell. A cell
    // with no matched surface gets no entry and keeps its deterministic slot —
    // belief is never a penalty.
    if (typeof score === "number" && score > 0) {
      rank.set(candidate.node_id, score);
    }
  }
  return rank;
}

module.exports = {
  buildCellBeliefRank,
};
