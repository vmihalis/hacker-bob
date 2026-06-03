"use strict";

const {
  isUnfinishedCoverageStatus,
  latestCoverageRecordsByKey,
} = require("./coverage.js");
const {
  priorityRank,
} = require("./ranking.js");

const STANDARD_WAVE_TARGET = 6;
const STANDARD_WAVE_MAX = 9;
const DEEP_WAVE_TARGET = 8;
const DEEP_WAVE_MAX = 12;

function surfaceIdOf(value) {
  if (value == null) return null;
  if (typeof value === "string") {
    const id = value.trim();
    return id || null;
  }
  if (typeof value === "object" && !Array.isArray(value) && typeof value.id === "string") {
    const id = value.id.trim();
    return id || null;
  }
  return null;
}

function terminallyBlockedSurfaceIds(state) {
  return (Array.isArray(state && state.terminally_blocked) ? state.terminally_blocked : [])
    .map((entry) => entry && entry.surface_id)
    .filter((surfaceId) => typeof surfaceId === "string" && surfaceId.trim());
}

function isOpenForAssignment(surfaceOrId, state, options = {}) {
  const surfaceId = surfaceIdOf(surfaceOrId);
  if (!surfaceId) return false;
  if (options.surfaceIdSet && !options.surfaceIdSet.has(surfaceId)) return false;

  const explored = new Set(Array.isArray(state && state.explored) ? state.explored : []);
  if (explored.has(surfaceId)) return false;

  const terminallyBlocked = new Set(terminallyBlockedSurfaceIds(state));
  if (terminallyBlocked.has(surfaceId)) return false;

  return true;
}

function rankingScore(surface) {
  const score = surface && surface.ranking && typeof surface.ranking.score === "number"
    ? surface.ranking.score
    : 0;
  return Number.isFinite(score) ? score : 0;
}

function compareSurfaces(a, b) {
  const priorityDelta = priorityRank(b && b.priority) - priorityRank(a && a.priority);
  if (priorityDelta !== 0) return priorityDelta;

  const scoreDelta = rankingScore(b) - rankingScore(a);
  if (scoreDelta !== 0) return scoreDelta;

  return String(a && a.id || "").localeCompare(String(b && b.id || ""));
}

function normalizeSurfaces(surfaces) {
  const byId = new Map();
  for (const surface of Array.isArray(surfaces) ? surfaces : []) {
    const surfaceId = surfaceIdOf(surface);
    if (!surfaceId || byId.has(surfaceId)) continue;
    byId.set(surfaceId, { ...surface, id: surfaceId });
  }
  return byId;
}

function computeOpenRequeueSurfaceIds(coverageRecords, state, surfaceIdSet) {
  const latestRecords = Array.from(latestCoverageRecordsByKey(
    Array.isArray(coverageRecords) ? coverageRecords : [],
  ).values());
  const ids = [];
  const seen = new Set();
  for (const record of latestRecords) {
    if (!record || !isUnfinishedCoverageStatus(record.status)) continue;
    const surfaceId = surfaceIdOf(record.surface_id);
    if (!surfaceId || seen.has(surfaceId)) continue;
    if (!isOpenForAssignment(surfaceId, state, { surfaceIdSet })) continue;
    seen.add(surfaceId);
    ids.push(surfaceId);
  }
  return ids;
}

function surfacesForIds(ids, surfaceById, state) {
  const result = [];
  const seen = new Set();
  const surfaceIdSet = new Set(surfaceById.keys());
  for (const id of Array.isArray(ids) ? ids : []) {
    const surfaceId = surfaceIdOf(id);
    if (!surfaceId || seen.has(surfaceId)) continue;
    if (!isOpenForAssignment(surfaceId, state, { surfaceIdSet })) continue;
    const surface = surfaceById.get(surfaceId);
    if (!surface) continue;
    seen.add(surfaceId);
    result.push(surface);
  }
  return result.sort(compareSurfaces);
}

function priorityBucket(surfaces, state, priorities) {
  const wanted = new Set(priorities);
  const surfaceIdSet = new Set(surfaces.map((surface) => surface.id));
  return surfaces
    .filter((surface) => (
      isOpenForAssignment(surface, state, { surfaceIdSet }) &&
      wanted.has(String(surface.priority || "").toUpperCase())
    ))
    .sort(compareSurfaces);
}

function dedupeBuckets(bucketSpecs) {
  const seen = new Set();
  return bucketSpecs.map((bucket) => {
    const surfaces = [];
    for (const surface of bucket.surfaces) {
      if (!surface || seen.has(surface.id)) continue;
      seen.add(surface.id);
      surfaces.push(surface);
    }
    return {
      name: bucket.name,
      overflow_to_max: bucket.overflow_to_max === true,
      surfaces,
      surface_ids: surfaces.map((surface) => surface.id),
    };
  });
}

function selectFromBuckets(buckets, { target, max }) {
  const selected = [];
  for (const bucket of buckets) {
    if (selected.length >= target) break;
    if (bucket.surfaces.length === 0) continue;
    const remainingTarget = target - selected.length;
    const remainingMax = max - selected.length;
    if (remainingTarget <= 0 || remainingMax <= 0) break;
    const limit = bucket.overflow_to_max
      ? remainingMax
      : remainingTarget;
    selected.push(...bucket.surfaces.slice(0, limit));
  }
  return selected;
}

function planNextWave({
  state,
  surfaces,
  coverageRecords = [],
  openRequeueSurfaceIds = null,
} = {}) {
  const normalizedState = state || {};
  const deepMode = normalizedState.deep_mode === true;
  const target = deepMode ? DEEP_WAVE_TARGET : STANDARD_WAVE_TARGET;
  const max = deepMode ? DEEP_WAVE_MAX : STANDARD_WAVE_MAX;
  const nextWave = (Number.isInteger(normalizedState.hunt_wave) ? normalizedState.hunt_wave : 0) + 1;

  const basePlan = {
    version: 1,
    mode: deepMode ? "deep" : "standard",
    wave_number: nextWave,
    target_assignments: target,
    max_assignments: max,
    buckets: [],
    candidate_surface_ids: [],
    assignments: [],
  };

  if (normalizedState.pending_wave != null) {
    return {
      ...basePlan,
      decision: "pending_wave_reconcile",
      reason: `pending_wave is still set to ${normalizedState.pending_wave}`,
      pending_wave: normalizedState.pending_wave,
    };
  }

  const surfaceById = normalizeSurfaces(surfaces);
  const allSurfaces = Array.from(surfaceById.values());
  const surfaceIdSet = new Set(surfaceById.keys());
  const openSurfaces = allSurfaces.filter((surface) => isOpenForAssignment(surface, normalizedState, { surfaceIdSet }));

  const bucketSpecs = nextWave === 1
    ? [
        {
          name: "critical_high",
          overflow_to_max: true,
          surfaces: priorityBucket(openSurfaces, normalizedState, ["CRITICAL", "HIGH"]),
        },
        {
          name: "medium",
          overflow_to_max: true,
          surfaces: priorityBucket(openSurfaces, normalizedState, ["MEDIUM"]),
        },
        {
          name: "low",
          surfaces: priorityBucket(openSurfaces, normalizedState, ["LOW"]),
        },
      ]
    : [
        {
          name: "open_requeue",
          overflow_to_max: true,
          surfaces: surfacesForIds(
            openRequeueSurfaceIds || computeOpenRequeueSurfaceIds(coverageRecords, normalizedState, surfaceIdSet),
            surfaceById,
            normalizedState,
          ),
        },
        {
          name: "lead_surface_ids",
          overflow_to_max: true,
          surfaces: surfacesForIds(normalizedState.lead_surface_ids, surfaceById, normalizedState),
        },
        {
          name: "critical_high",
          overflow_to_max: true,
          surfaces: priorityBucket(openSurfaces, normalizedState, ["CRITICAL", "HIGH"]),
        },
        {
          name: "medium",
          overflow_to_max: true,
          surfaces: priorityBucket(openSurfaces, normalizedState, ["MEDIUM"]),
        },
        {
          name: "low",
          surfaces: priorityBucket(openSurfaces, normalizedState, ["LOW"]),
        },
      ];

  const buckets = dedupeBuckets(bucketSpecs);
  const candidateSurfaces = buckets.flatMap((bucket) => bucket.surfaces);
  const selected = selectFromBuckets(buckets, { target, max });
  const assignments = selected.map((surface, index) => ({
    agent: `a${index + 1}`,
    surface_id: surface.id,
  }));

  return {
    ...basePlan,
    decision: assignments.length > 0 ? "start_wave" : "no_assignable_candidates",
    reason: assignments.length > 0
      ? `planned ${assignments.length} assignment(s) for wave ${nextWave}`
      : "no open attack surfaces are assignable; phase decisions belong to the orchestrator",
    buckets: buckets.map((bucket) => ({
      name: bucket.name,
      surface_ids: bucket.surface_ids,
    })),
    candidate_surface_ids: candidateSurfaces.map((surface) => surface.id),
    assignments,
  };
}

module.exports = {
  DEEP_WAVE_MAX,
  DEEP_WAVE_TARGET,
  STANDARD_WAVE_MAX,
  STANDARD_WAVE_TARGET,
  isOpenForAssignment,
  planNextWave,
};
