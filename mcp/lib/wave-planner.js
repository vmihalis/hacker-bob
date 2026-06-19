"use strict";

const {
  isUnfinishedCoverageStatus,
  latestCoverageRecordsByKey,
} = require("./coverage.js");
const {
  priorityRank,
} = require("./ranking.js");
const {
  DEFAULT_QUEUE_POLICY,
  compareQueuedTasks,
  loadQueuePolicy,
  normalizeQueuePolicy,
} = require("./queue-policy.js");
const {
  applyBeliefSchedulerPriority,
} = require("./belief/scheduler-priority.js");

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

// Closures, blockers, and lead surfaces are read from frontier-projections
// (Cycle D.3). The state.json projection arrays (state.explored,
// state.terminally_blocked, state.lead_surface_ids) were removed; callers
// pass the projected sets explicitly so the planner stays pure and testable.
function isOpenForAssignment(surfaceOrId, state, options = {}) {
  const surfaceId = surfaceIdOf(surfaceOrId);
  if (!surfaceId) return false;
  if (options.surfaceIdSet && !options.surfaceIdSet.has(surfaceId)) return false;
  if (options.exploredSurfaceIds instanceof Set && options.exploredSurfaceIds.has(surfaceId)) return false;
  if (options.terminallyBlockedSurfaceIds instanceof Set && options.terminallyBlockedSurfaceIds.has(surfaceId)) return false;
  return true;
}

function rankingScore(surface) {
  const score = surface && surface.ranking && typeof surface.ranking.score === "number"
    ? surface.ranking.score
    : 0;
  return Number.isFinite(score) ? score : 0;
}

function compareSurfaces(a, b, policy) {
  const aPriorityToken = String(a && a.priority || "").toLowerCase();
  const bPriorityToken = String(b && b.priority || "").toLowerCase();
  const priorityOrder = Array.isArray(policy && policy.priority_order) && policy.priority_order.length > 0
    ? policy.priority_order
    : DEFAULT_QUEUE_POLICY.priority_order;
  const aPolicyIndex = priorityOrder.indexOf(aPriorityToken);
  const bPolicyIndex = priorityOrder.indexOf(bPriorityToken);
  if (aPolicyIndex !== -1 || bPolicyIndex !== -1) {
    const aIndex = aPolicyIndex === -1 ? priorityOrder.length : aPolicyIndex;
    const bIndex = bPolicyIndex === -1 ? priorityOrder.length : bPolicyIndex;
    if (aIndex !== bIndex) return aIndex - bIndex;
  } else {
    const priorityDelta = priorityRank(b && b.priority) - priorityRank(a && a.priority);
    if (priorityDelta !== 0) return priorityDelta;
  }

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

function computeOpenRequeueSurfaceIds(coverageRecords, state, surfaceIdSet, openOptions = {}) {
  const latestRecords = Array.from(latestCoverageRecordsByKey(
    Array.isArray(coverageRecords) ? coverageRecords : [],
  ).values());
  const ids = [];
  const seen = new Set();
  for (const record of latestRecords) {
    if (!record || !isUnfinishedCoverageStatus(record.status)) continue;
    const surfaceId = surfaceIdOf(record.surface_id);
    if (!surfaceId || seen.has(surfaceId)) continue;
    if (!isOpenForAssignment(surfaceId, state, { ...openOptions, surfaceIdSet })) continue;
    seen.add(surfaceId);
    ids.push(surfaceId);
  }
  return ids;
}

function surfacesForIds(ids, surfaceById, state, policy, openOptions = {}) {
  const result = [];
  const seen = new Set();
  const surfaceIdSet = new Set(surfaceById.keys());
  for (const id of Array.isArray(ids) ? ids : []) {
    const surfaceId = surfaceIdOf(id);
    if (!surfaceId || seen.has(surfaceId)) continue;
    if (!isOpenForAssignment(surfaceId, state, { ...openOptions, surfaceIdSet })) continue;
    const surface = surfaceById.get(surfaceId);
    if (!surface) continue;
    seen.add(surfaceId);
    result.push(surface);
  }
  return result.sort((a, b) => compareSurfaces(a, b, policy));
}

function priorityBucket(surfaces, state, priorities, policy, openOptions = {}) {
  const wanted = new Set(priorities.map((priority) => String(priority).toUpperCase()));
  const surfaceIdSet = new Set(surfaces.map((surface) => surface.id));
  return surfaces
    .filter((surface) => (
      isOpenForAssignment(surface, state, { ...openOptions, surfaceIdSet }) &&
      wanted.has(String(surface.priority || "").toUpperCase())
    ))
    .sort((a, b) => compareSurfaces(a, b, policy));
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

function priorityTokensForBucket(name, priorityOrder) {
  if (name === "critical_high") {
    return priorityOrder.filter((token) => token === "critical" || token === "high");
  }
  if (name === "medium") {
    return priorityOrder.filter((token) => token === "medium");
  }
  if (name === "low") {
    return priorityOrder.filter((token) => token === "low");
  }
  return [];
}

function bucketSpecOrder(priorityOrder) {
  // Walk the policy's priority_order and emit a bucket for each priority family
  // in the order it appears. `critical` and `high` collapse into a single
  // overflow-capable bucket the first time either appears; the other priorities
  // produce stand-alone buckets that do not overflow past target.
  const order = [];
  let criticalHighEmitted = false;
  for (const priority of priorityOrder) {
    const token = String(priority).toLowerCase();
    if ((token === "critical" || token === "high") && !criticalHighEmitted) {
      order.push("critical_high");
      criticalHighEmitted = true;
      continue;
    }
    if (token === "medium" && !order.includes("medium")) {
      order.push("medium");
      continue;
    }
    if (token === "low" && !order.includes("low")) {
      order.push("low");
      continue;
    }
  }
  if (!criticalHighEmitted) order.unshift("critical_high");
  if (!order.includes("medium")) order.push("medium");
  if (!order.includes("low")) order.push("low");
  return order;
}

function priorityBuckets(openSurfaces, state, policy, openOptions = {}) {
  const order = bucketSpecOrder(policy.priority_order);
  return order.map((name) => {
    const priorityTokens = priorityTokensForBucket(name, policy.priority_order);
    const upperTokens = priorityTokens.map((token) => token.toUpperCase());
    return {
      name,
      overflow_to_max: name === "critical_high",
      surfaces: priorityBucket(openSurfaces, state, upperTokens, policy, openOptions),
    };
  });
}

function legacySurfacesFromInputs(surfaceById, state, policy, openOptions = {}) {
  return Array.from(surfaceById.values())
    .filter((surface) => isOpenForAssignment(surface, state, { ...openOptions, surfaceIdSet: new Set(surfaceById.keys()) }))
    .sort((a, b) => compareSurfaces(a, b, policy));
}

function surfaceIdsFromTaskQueue(taskQueueTasks, policy) {
  const sorted = (Array.isArray(taskQueueTasks) ? taskQueueTasks.slice() : [])
    .filter((task) => task && task.status === "queued")
    .sort((a, b) => compareQueuedTasks(a, b, policy));
  const ids = [];
  const seen = new Set();
  for (const task of sorted) {
    const surfaceId = surfaceIdOf(task.surface_id);
    if (!surfaceId || seen.has(surfaceId)) continue;
    seen.add(surfaceId);
    ids.push(surfaceId);
  }
  return ids;
}

function planNextWave({
  state,
  surfaces,
  coverageRecords = [],
  openRequeueSurfaceIds = null,
  taskQueueTasks = null,
  queuePolicy = null,
  ...options
} = {}) {
  const normalizedState = state || {};
  const policy = normalizeQueuePolicy(queuePolicy || DEFAULT_QUEUE_POLICY);
  const deepMode = normalizedState.deep_mode === true;
  const rawTarget = deepMode ? policy.deep_wave_target : policy.standard_wave_target;
  const rawMax = deepMode ? policy.deep_wave_max : policy.standard_wave_max;
  // First-class bounded-concurrency cap. When set, clamp BOTH the effective
  // target and the effective max so the cap is enforced regardless of bucket
  // overflow rules. selectFromBuckets uses limit=remainingTarget for
  // non-overflow buckets (including the wave-1 first bucket), so clamping only
  // `max` would leak up to `target` evaluators past a low cap — both must be
  // clamped. null leaves fan-out unchanged (backward compatible).
  //
  // Why clamping the WAVE SIZE is the correct in-flight bound here (not a
  // coverage cut): waves are dispatched SEQUENTIALLY. The orchestrator must
  // RECONCILE (settle) a pending wave before it may dispatch the next one
  // ("Never paper over a pending result with a fresh dispatch"), so at most one
  // wave's assignments are ever in flight at a time. A wave clamped to
  // max_concurrent_evaluators therefore runs at most that many evaluators
  // concurrently — exactly the in-flight cap — and the surfaces left out of
  // this wave are not dropped; they are picked up by the next wave once this one
  // settles. Preserving the full target instead would require intra-wave
  // dispatch throttling, which the orchestrator does not implement (nothing
  // consumes next_action.max_in_flight as a throttle), so it would let `target`
  // evaluators run at once and break the cap. The cap is still emitted on the
  // plan (max_concurrent_evaluators below) as the in-flight signal.
  const cap = Number.isInteger(policy.max_concurrent_evaluators)
    ? policy.max_concurrent_evaluators
    : null;
  const target = cap == null ? rawTarget : Math.min(rawTarget, cap);
  const max = cap == null ? rawMax : Math.min(rawMax, cap);
  const nextWave = (Number.isInteger(normalizedState.evaluation_wave) ? normalizedState.evaluation_wave : 0) + 1;

  const basePlan = {
    version: 1,
    mode: deepMode ? "deep" : "standard",
    wave_number: nextWave,
    target_assignments: target,
    max_assignments: max,
    max_concurrent_evaluators: cap,
    buckets: [],
    candidate_surface_ids: [],
    assignments: [],
  };

  if (normalizedState.pending_wave != null) {
    return {
      ...basePlan,
      decision: "pending_wave_settle",
      reason: `pending_wave is still set to ${normalizedState.pending_wave}`,
      pending_wave: normalizedState.pending_wave,
    };
  }

  const surfaceById = normalizeSurfaces(surfaces);
  const allSurfaces = Array.from(surfaceById.values());
  const surfaceIdSet = new Set(surfaceById.keys());

  // Surface-state projections (explored / terminally_blocked / lead surfaces)
  // are derived from frontier-events via frontier-projections. The planner
  // accepts pre-computed sets (test fixtures, replay tooling) and falls back
  // to projecting the live target_domain when present.
  let exploredSurfaceIds = options.exploredSurfaceIds instanceof Set
    ? options.exploredSurfaceIds
    : new Set(Array.isArray(options.exploredSurfaceIds) ? options.exploredSurfaceIds : []);
  let terminallyBlockedSet = options.terminallyBlockedSurfaceIds instanceof Set
    ? options.terminallyBlockedSurfaceIds
    : new Set(Array.isArray(options.terminallyBlockedSurfaceIds) ? options.terminallyBlockedSurfaceIds : []);
  let leadSurfaceIds = Array.isArray(options.leadSurfaceIds) ? options.leadSurfaceIds : null;
  if ((exploredSurfaceIds.size === 0 || terminallyBlockedSet.size === 0 || leadSurfaceIds == null) && typeof normalizedState.target === "string" && normalizedState.target) {
    try {
      const projections = require("./frontier-projections.js");
      if (exploredSurfaceIds.size === 0) {
        exploredSurfaceIds = new Set(projections.currentClosures(normalizedState.target).map((entry) => entry.surface_id));
      }
      if (terminallyBlockedSet.size === 0) {
        terminallyBlockedSet = new Set(projections.currentBlockers(normalizedState.target).map((entry) => entry.surface_id));
      }
      if (leadSurfaceIds == null) {
        leadSurfaceIds = projections.currentLeadSurfaceIds(normalizedState.target);
      }
    } catch {
      if (leadSurfaceIds == null) leadSurfaceIds = [];
    }
  } else if (leadSurfaceIds == null) {
    leadSurfaceIds = [];
  }

  const openOptions = { surfaceIdSet, exploredSurfaceIds, terminallyBlockedSurfaceIds: terminallyBlockedSet };
  const rawOpenSurfaces = allSurfaces.filter((surface) => isOpenForAssignment(surface, normalizedState, openOptions));
  const beliefPriority = applyBeliefSchedulerPriority({
    target_domain: normalizedState.target,
    surfaces: rawOpenSurfaces,
    enabled: policy.belief_assisted_priority_enabled,
    seed: policy.belief_assisted_priority_seed,
    rank_limit: policy.belief_assisted_priority_rank_limit,
  });
  const openSurfaces = beliefPriority.surfaces;
  const plannedSurfaceById = normalizeSurfaces(openSurfaces);

  const hasTaskQueueRows = Array.isArray(taskQueueTasks) && taskQueueTasks.length > 0;

  let bucketSpecs;
  if (hasTaskQueueRows) {
    // Materialized-view path: sort task-queue.json rows via compareQueuedTasks
    // and use the resulting surface order as the single bucket. Legacy ranking
    // remains the fallback when task-queue.json is empty (dual-write window).
    const orderedIds = surfaceIdsFromTaskQueue(taskQueueTasks, policy);
    bucketSpecs = [
      {
        name: "task_queue",
        overflow_to_max: true,
        surfaces: surfacesForIds(orderedIds, plannedSurfaceById, normalizedState, policy, openOptions),
      },
    ];
    if (nextWave > 1) {
      bucketSpecs.unshift({
        name: "open_requeue",
        overflow_to_max: true,
        surfaces: surfacesForIds(
          openRequeueSurfaceIds || computeOpenRequeueSurfaceIds(coverageRecords, normalizedState, surfaceIdSet, openOptions),
          plannedSurfaceById,
          normalizedState,
          policy,
          openOptions,
        ),
      });
      bucketSpecs.splice(1, 0, {
        name: "lead_surface_ids",
        overflow_to_max: true,
        surfaces: surfacesForIds(leadSurfaceIds, plannedSurfaceById, normalizedState, policy, openOptions),
      });
    }
  } else if (nextWave === 1) {
    bucketSpecs = priorityBuckets(openSurfaces, normalizedState, policy, openOptions);
  } else {
    bucketSpecs = [
      {
        name: "open_requeue",
        overflow_to_max: true,
        surfaces: surfacesForIds(
          openRequeueSurfaceIds || computeOpenRequeueSurfaceIds(coverageRecords, normalizedState, surfaceIdSet, openOptions),
          plannedSurfaceById,
          normalizedState,
          policy,
          openOptions,
        ),
      },
      {
        name: "lead_surface_ids",
        overflow_to_max: true,
        surfaces: surfacesForIds(leadSurfaceIds, plannedSurfaceById, normalizedState, policy, openOptions),
      },
      ...priorityBuckets(openSurfaces, normalizedState, policy, openOptions),
    ];
  }

  const buckets = dedupeBuckets(bucketSpecs);
  const candidateSurfaces = buckets.flatMap((bucket) => bucket.surfaces);
  const selected = selectFromBuckets(buckets, { target, max });
  const assignments = selected.map((surface, index) => ({
    agent: `a${index + 1}`,
    surface_id: surface.id,
    task_lens: policy.default_wave_task_lens,
    budget: { ...policy.default_wave_task_budget },
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
    belief_assisted_priority: beliefPriority.metadata,
    candidate_surface_ids: candidateSurfaces.map((surface) => surface.id),
    assignments,
  };
}

module.exports = {
  isOpenForAssignment,
  loadQueuePolicy,
  planNextWave,
};
