"use strict";

const fs = require("fs");
const {
  attackSurfacePath,
  surfaceLeadsPath,
  taskQueuePath,
} = require("../paths.js");
const { pushUnique } = require("../validation.js");
const { compactSessionState } = require("../session-state-contracts.js");
const { readAttackSurfaceStrict } = require("../attack-surface.js");
const { previewSurfaceLeadPromotion } = require("../surface-leads.js");
const { rankAttackSurfaces } = require("../ranking.js");
const { computeCoverageRequeueSurfaceIds } = require("../coverage.js");
const {
  findSchedulerDecisionByAssignmentBatchId,
  readCurrentTaskQueueHash,
} = require("../scheduler-decisions.js");
const { appendFrontierEvent } = require("../frontier-events.js");

const BLOCKED_PREREQ_KIND_CAPABILITY = Object.freeze({
  auth_missing: Object.freeze({
    required_capability_id: "S3_stepup_registration",
    clearance_source: "auth_profile",
  }),
  egress_unreachable: Object.freeze({
    required_capability_id: "S3_oob_callback",
    // Materialization-gated (a real OOB callback terminal run proves egress reached
    // back), NEVER tool-existence: bob_oob_mint is statically registered, so a
    // tool-registry clearance would be unconditionally true and a firewalled surface
    // would livelock (requeued every wave, never promoted to operator escalation).
    clearance_source: "producer_terminal",
  }),
  funded_wallet_missing: Object.freeze({
    required_capability_id: "I7_chain_state_tree",
    clearance_source: "producer_terminal",
  }),
  key_material_missing: Object.freeze({
    required_capability_id: "I7_chain_state_tree",
    clearance_source: "producer_terminal",
  }),
  external_credential_missing: Object.freeze({
    required_capability_id: "S3_stepup_registration",
    clearance_source: "producer_terminal",
  }),
});

// Loop detector. For each surface with current-wave blockers, look at validated
// history (state.blocked_prereq_history) for prior occurrences of the same
// (kind, identifier_hint) tuple. A blocker whose required capability is now
// materialized is left for the merge requeue path; remaining blockers promote
// on any 2-wave recurrence and require an operator clear via
// bob_clear_terminal_block.
function detectTerminalPromotions({
  currentWaveBlockersBySurface,
  historyBySurface,
  prereqRegistrySnapshots,
  clearHistoryBySurface,
  currentWave,
  capabilityClearedSurfaceIds,
}) {
  void prereqRegistrySnapshots;
  const capabilityCleared = capabilityClearedSurfaceIds instanceof Set
    ? capabilityClearedSurfaceIds
    : new Set(Array.isArray(capabilityClearedSurfaceIds) ? capabilityClearedSurfaceIds : []);
  const clearedPremiseKeysBySurface = capabilityCleared.cleared_premise_keys_by_surface instanceof Map
    ? capabilityCleared.cleared_premise_keys_by_surface
    : null;
  const promotions = [];
  for (const [surfaceId, currentEntries] of currentWaveBlockersBySurface) {
    const surfaceHistory = historyBySurface.get(surfaceId) || [];
    // Recurrence horizon: history entries with wave <= cleared_at_wave are
    // pre-clear; without this, every clear-then-reblock would re-promote.
    const clearsForSurface = clearHistoryBySurface.get(surfaceId) || [];
    const latestClearAtWave = clearsForSurface.length > 0
      ? Math.max(...clearsForSurface.map((c) => c.cleared_at_wave))
      : 0;
    const promotedBlockers = [];
    const seenTuples = new Set();
    for (const entry of currentEntries) {
      const hint = entry.identifier_hint || null;
      const tupleKey = `${entry.kind}\t${hint || ""}`;
      if (seenTuples.has(tupleKey)) continue;
      // Prior occurrences are strictly between the latest clear and the
      // current wave.
      const priorMatches = surfaceHistory.filter((h) =>
        h.wave < currentWave &&
        h.wave > latestClearAtWave &&
        h.kind === entry.kind &&
        (h.identifier_hint || null) === hint,
      );
      if (priorMatches.length === 0) continue;
      if (clearedPremiseKeysBySurface) {
        const clearedKeys = clearedPremiseKeysBySurface.get(surfaceId);
        if (clearedKeys && clearedKeys.has(tupleKey)) continue;
      } else if (capabilityCleared.has(surfaceId)) {
        continue;
      }
      seenTuples.add(tupleKey);
      const blocker = { kind: entry.kind };
      if (entry.identifier_hint) blocker.identifier_hint = entry.identifier_hint;
      if (entry.reason) blocker.reason = entry.reason;
      promotedBlockers.push(blocker);
    }
    if (promotedBlockers.length > 0) {
      promotions.push({
        surface_id: surfaceId,
        blocked_at_wave: currentWave,
        blockers: promotedBlockers,
      });
    }
  }
  return promotions;
}

function currentWaveBlockersFromMerge(merge) {
  const currentWaveBlockersBySurface = new Map();
  for (const entry of merge && Array.isArray(merge.blocked_prereqs) ? merge.blocked_prereqs : []) {
    if (!entry || typeof entry.surface_id !== "string" || !entry.surface_id) continue;
    if (!currentWaveBlockersBySurface.has(entry.surface_id)) {
      currentWaveBlockersBySurface.set(entry.surface_id, []);
    }
    currentWaveBlockersBySurface.get(entry.surface_id).push({
      kind: entry.kind,
      identifier_hint: entry.identifier_hint || null,
      reason: entry.reason,
    });
  }
  return currentWaveBlockersBySurface;
}

function currentWaveBlockersFromHistory(historyBySurface, currentWave) {
  const currentWaveBlockersBySurface = new Map();
  if (!(historyBySurface instanceof Map) || !Number.isInteger(currentWave)) {
    return currentWaveBlockersBySurface;
  }
  for (const [surfaceId, entries] of historyBySurface) {
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      if (!entry || entry.wave !== currentWave) continue;
      if (!currentWaveBlockersBySurface.has(surfaceId)) {
        currentWaveBlockersBySurface.set(surfaceId, []);
      }
      currentWaveBlockersBySurface.get(surfaceId).push({
        kind: entry.kind,
        identifier_hint: entry.identifier_hint || null,
        reason: entry.reason,
      });
    }
  }
  return currentWaveBlockersBySurface;
}

function readAuthProfileCount(targetDomain) {
  const { listAuthProfiles } = require("../auth.js");
  const parsed = JSON.parse(listAuthProfiles({ target_domain: targetDomain }));
  return Array.isArray(parsed.profiles) ? parsed.profiles.length : 0;
}

function validateBlockedPrereqCapabilityMap(capabilityToolMap) {
  for (const [kind, config] of Object.entries(BLOCKED_PREREQ_KIND_CAPABILITY)) {
    if (!config || typeof config.required_capability_id !== "string") {
      throw new Error(`blocked prereq kind ${kind} has no required capability id`);
    }
    if (!Object.prototype.hasOwnProperty.call(capabilityToolMap, config.required_capability_id)) {
      throw new Error(`blocked prereq kind ${kind} maps to unregistered capability ${config.required_capability_id}`);
    }
  }
}

function capabilityClearedForBlockedPrereq(entry, sources) {
  if (!entry || typeof entry.kind !== "string") return false;
  const config = BLOCKED_PREREQ_KIND_CAPABILITY[entry.kind];
  if (!config) return false;
  const capabilityId = config.required_capability_id;
  if (config.clearance_source === "auth_profile") {
    return sources.authProfileCount > 0;
  }
  if (config.clearance_source === "producer_terminal") {
    return sources.terminalRunSet.has(capabilityId);
  }
  // Fail closed: an unrecognized/unmaterialized clearance source never auto-clears a
  // premise (which would suppress its terminal promotion + operator escalation). Tool
  // EXISTENCE is not a clearance signal — a statically-registered tool is always present.
  return false;
}

function blockedPrereqTupleKey(entry) {
  const hint = entry && entry.identifier_hint ? entry.identifier_hint : null;
  return `${entry && entry.kind ? entry.kind : ""}\t${hint || ""}`;
}

function computeCapabilityClearedPremiseSurfaceIds({
  merge = null,
  historyBySurface = null,
  currentWaveBlockersBySurface = null,
  currentWave = null,
  target_domain,
} = {}) {
  if (typeof target_domain !== "string" || target_domain.length === 0) {
    throw new Error("computeCapabilityClearedPremiseSurfaceIds: target_domain is required");
  }
  let blockersBySurface = currentWaveBlockersBySurface;
  if (!(blockersBySurface instanceof Map)) {
    blockersBySurface = merge
      ? currentWaveBlockersFromMerge(merge)
      : currentWaveBlockersFromHistory(historyBySurface, currentWave);
  }
  if (!(blockersBySurface instanceof Map) || blockersBySurface.size === 0) {
    return new Set();
  }

  const { capabilityToolMapFromRegistry } = require("../tool-registry.js");
  const { buildProducerRunLedgerCache } = require("../producer-run-ledger.js");
  const capabilityToolMap = capabilityToolMapFromRegistry();
  validateBlockedPrereqCapabilityMap(capabilityToolMap);
  const sources = {
    capabilityToolMap,
    authProfileCount: readAuthProfileCount(target_domain),
    terminalRunSet: buildProducerRunLedgerCache(target_domain).terminalKeys,
  };
  const surfaceIds = new Set();
  const premiseKeysBySurface = new Map();
  // Y-D23 capability-clear: a materialized blocked prerequisite keeps the
  // surface open for a fresh run until the current blocker is resolved.
  for (const [surfaceId, entries] of blockersBySurface) {
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      if (capabilityClearedForBlockedPrereq(entry, sources)) {
        surfaceIds.add(surfaceId);
        if (!premiseKeysBySurface.has(surfaceId)) premiseKeysBySurface.set(surfaceId, new Set());
        premiseKeysBySurface.get(surfaceId).add(blockedPrereqTupleKey(entry));
      }
    }
  }
  Object.defineProperty(surfaceIds, "cleared_premise_keys_by_surface", {
    value: premiseKeysBySurface,
    enumerable: false,
  });
  return surfaceIds;
}

function basePromotionPreviewForState(domain, state) {
  if (state.deep_mode === true) {
    return previewSurfaceLeadPromotion(domain, { limit: 8, min_score: 60, include_medium: false });
  }
  return {
    would_promote: 0,
    would_promote_lead_ids: [],
    leads_path: surfaceLeadsPath(domain),
    attack_surface_path: attackSurfacePath(domain),
  };
}

function readRankedSurfacesForPlanning(domain) {
  const ranked = rankAttackSurfaces(domain);
  if (!ranked) {
    readAttackSurfaceStrict(domain);
    return [];
  }
  return ranked.surfaces || [];
}

function readQueueTasksForPlanning(domain) {
  const filePath = taskQueuePath(domain);
  if (!fs.existsSync(filePath)) return [];
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
    return Array.isArray(parsed && parsed.tasks) ? parsed.tasks : [];
  } catch {
    return [];
  }
}

function buildNextActionForPlan(domain, decision, waveNumber, plan = null) {
  if (decision === "pending_wave_settle") {
    return {
      kind: "call_tool",
      tool: "bob_apply_wave_merge",
      arguments: { target_domain: domain, wave_number: waveNumber, force_merge: false },
    };
  }
  if (decision === "routes_unreadable") {
    // The surface routes artifact is unreadable (corrupt or version-mismatched).
    // Planning fails CLOSED on it — never resurrecting a parked surface off stale
    // data — so the coherent recovery is to REGENERATE the routes: bob_route_surfaces
    // re-derives fresh routes and self-heals a version bump, then the wave retries.
    // A bare "stop / no assignable candidates" here would misdiagnose a recoverable
    // corruption as an empty frontier.
    return {
      kind: "call_tool",
      tool: "bob_route_surfaces",
      arguments: { target_domain: domain },
      reason: "surface-routes.json is unreadable (corrupt or version-mismatched); regenerate it with bob_route_surfaces, then retry bob_start_next_wave.",
    };
  }
  if (decision === "spawn_budget_exhausted") {
    // The operator's lifetime spawn ceiling (max_total_spawned_agents) is fully
    // reserved while open surfaces remain — a NAMED coverage gap (plan.reason /
    // plan.buckets), not "no candidates". Stop spawning honestly; raising the
    // ceiling or letting in-flight evaluators settle is the operator's call.
    return {
      kind: "stop",
      reason: "spawn budget exhausted: the lifetime max_total_spawned_agents ceiling is fully reserved while open surfaces remain uncovered (see plan.reason / plan.buckets). Raise the ceiling or let in-flight evaluators settle.",
    };
  }
  if (decision === "start_wave") {
    const action = {
      kind: "spawn_evaluators",
      wave_number: waveNumber,
      assignments_source: "top_level_assignments",
    };
    // Echo the bounded-concurrency cap so the orchestrator spawns at most this
    // many background evaluators in flight at once. Falls back to the planned
    // max when no cap is set so the field is always actionable.
    const cap = plan && Number.isInteger(plan.max_concurrent_evaluators)
      ? plan.max_concurrent_evaluators
      : null;
    if (cap != null) {
      action.max_in_flight = cap;
    } else if (plan && Number.isInteger(plan.max_assignments)) {
      action.max_in_flight = plan.max_assignments;
    }
    return action;
  }
  return {
    kind: "stop",
    reason: "No assignable candidates; phase decisions belong to the orchestrator.",
  };
}

function buildStartNextWaveResponse({ domain, dryRun, state, plan, promotion, started = null, reason = null }) {
  const decision = plan.decision;
  const nextAction = dryRun && decision === "start_wave"
    ? {
        kind: "stop",
        reason: "dry_run is true; call bob_start_next_wave with dry_run false to start this planned wave.",
      }
    : buildNextActionForPlan(domain, decision, decision === "pending_wave_settle" ? plan.pending_wave : plan.wave_number, plan);
  const response = {
    version: 1,
    target_domain: domain,
    dry_run: dryRun,
    started: started != null,
    decision,
    reason: reason || plan.reason,
    state: compactSessionState(state),
    promotion,
    plan,
    next_action: nextAction,
  };
  if (started) {
    response.wave_number = started.wave_number;
    response.assignments = started.assignments;
    // Additive: expose the parked unroutable coverage gap on the start response
    // (rides the `started` object produced by startWaveLocked) so a caller sees
    // it without grepping telemetry. Present only on a real start (started !=
    // null); the planning/dry-run path is unchanged.
    if (started.unroutable_count != null) response.unroutable_count = started.unroutable_count;
    if (started.unroutable_surfaces != null) response.unroutable_surfaces = started.unroutable_surfaces;
    // Additive zero-executable signal (all assigned surfaces unroutable): honest,
    // non-halting. Present only on a real start; the planning/dry-run path is
    // unchanged.
    if (started.has_routable_assignments != null) response.has_routable_assignments = started.has_routable_assignments;
    if (started.zero_executable != null) response.zero_executable = started.zero_executable;
    response.assignments_path = started.assignments_path;
    response.state = started.state;
    response.next_action.assignments_path = started.assignments_path;
    // A zero-executable wave (every assigned surface routed unroutable) started and
    // self-settles — buildWaveReadiness treats an empty assignment set as complete.
    // The spawn_evaluators next_action is then incoherent (it would direct the
    // orchestrator to spawn against `assignments: []`). Reconcile it with the honest
    // signal: instruct settling this wave so the loop advances (non-halting), never
    // spawning zero evaluators. Guarded on zero_executable === true, so the routable
    // start path is byte-identical.
    if (started.zero_executable === true) {
      response.next_action = {
        kind: "call_tool",
        tool: "bob_apply_wave_merge",
        arguments: { target_domain: domain, wave_number: started.wave_number, force_merge: false },
        reason: "All assigned surfaces are unroutable (no runnable evaluator work); settle this wave and continue.",
        assignments_path: started.assignments_path,
      };
    }
  }
  return response;
}

function inspectSchedulerDecisionIntegrity({ domain, assignmentBatchId, schedulerDecisionId }) {
  const summary = {
    assignment_batch_id: assignmentBatchId || null,
    scheduler_decision_id: schedulerDecisionId || null,
    decision_found: false,
    queue_hash_drift: false,
    warning: null,
  };
  if (!assignmentBatchId && !schedulerDecisionId) return summary;
  let decision = null;
  try {
    if (assignmentBatchId) {
      decision = findSchedulerDecisionByAssignmentBatchId(domain, assignmentBatchId);
    }
  } catch {}
  if (!decision) {
    summary.warning = "scheduler_decision_not_found";
    return summary;
  }
  summary.decision_found = true;
  if (!summary.scheduler_decision_id) {
    summary.scheduler_decision_id = decision.scheduler_decision_id || null;
  }
  let currentQueueHash = null;
  try {
    currentQueueHash = readCurrentTaskQueueHash(domain);
  } catch {
    // task-queue.json may be absent in narrow fixture paths.
  }
  if (decision.source_task_queue_hash && currentQueueHash && decision.source_task_queue_hash !== currentQueueHash) {
    summary.queue_hash_drift = true;
    summary.source_task_queue_hash = decision.source_task_queue_hash;
    summary.current_task_queue_hash = currentQueueHash;
    summary.warning = "task_queue_hash_drift";
  }
  return summary;
}

function computeRequeueSurfaceIds(artifacts, merge, coverageRecords = [], capabilityClearedSurfaceIds = []) {
  const requeueSurfaceIds = [];
  const seen = new Set();
  pushUnique(requeueSurfaceIds, seen, merge.partial_surface_ids);
  pushUnique(requeueSurfaceIds, seen, merge.missing_surface_ids);
  for (const agent of merge.invalid_agents) {
    const assignment = artifacts.assignmentByAgent.get(agent);
    if (!assignment) continue;
    pushUnique(requeueSurfaceIds, seen, [assignment.surface_id]);
  }
  pushUnique(requeueSurfaceIds, seen, computeCoverageRequeueSurfaceIds(artifacts, coverageRecords));
  pushUnique(requeueSurfaceIds, seen, capabilityClearedSurfaceIds);
  return requeueSurfaceIds;
}

function buildCurrentWaveBlockerMaps(merge, priorHistory, waveNumber) {
  const newHistoryEntries = (merge.blocked_prereqs || []).map((entry) => {
    const record = { wave: waveNumber, surface_id: entry.surface_id, kind: entry.kind };
    if (entry.identifier_hint) record.identifier_hint = entry.identifier_hint;
    if (entry.reason) record.reason = entry.reason;
    return record;
  });
  const nextHistory = [...priorHistory, ...newHistoryEntries];
  const historyBySurface = new Map();
  for (const entry of nextHistory) {
    if (!historyBySurface.has(entry.surface_id)) historyBySurface.set(entry.surface_id, []);
    historyBySurface.get(entry.surface_id).push(entry);
  }
  const currentWaveBlockersBySurface = new Map();
  for (const entry of merge.blocked_prereqs || []) {
    if (!currentWaveBlockersBySurface.has(entry.surface_id)) currentWaveBlockersBySurface.set(entry.surface_id, []);
    currentWaveBlockersBySurface.get(entry.surface_id).push({
      kind: entry.kind,
      identifier_hint: entry.identifier_hint || null,
      reason: entry.reason,
    });
  }
  return { historyBySurface, currentWaveBlockersBySurface, nextHistory };
}

// Append one blocker.asserted frontier event per terminal promotion. After
// D.3 the frontier ledger is the sole source of surface-state truth; the
// `terminally_blocked: true` marker plus the wave-merge tool source make
// these events authoritative for frontier-projections.currentBlockers.
function appendBlockerPromotionFrontierEvents(domain, promotions, waveNumber) {
  for (const promotion of promotions) {
    for (const blocker of promotion.blockers) {
      try {
        appendFrontierEvent({
          target_domain: domain,
          kind: "blocker.asserted",
          surface_id: promotion.surface_id,
          payload: {
            wave: waveNumber,
            kind: blocker.kind,
            identifier_hint: blocker.identifier_hint || null,
            reason: blocker.reason || null,
            terminally_blocked: true,
          },
          source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
        });
      } catch {
        // Frontier ledger append is best-effort.
      }
    }
  }
}

// Append one closure.recorded frontier event per surface marked complete in
// this merge. The `surface_fully_explored: true` payload marker is the
// authoritative signal frontier-projections.currentClosures folds.
function appendClosureFrontierEvents(domain, completedSurfaceIds, waveNumber) {
  for (const surfaceId of completedSurfaceIds) {
    try {
      appendFrontierEvent({
        target_domain: domain,
        kind: "closure.recorded",
        surface_id: surfaceId,
        payload: { wave: waveNumber, surface_fully_explored: true, reason: "surface_completed" },
        source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
      });
    } catch {
      // Frontier ledger append is best-effort.
    }
  }
}

// Append one surface.observed event per handoff-reported lead surface so the
// frontier projection recognizes them as promoted lead surfaces. The
// promoted_surface_lead label is the marker frontier-projections.currentLeadSurfaceIds
// folds.
function appendHandoffLeadSurfaceFrontierEvents(domain, leadSurfaceIds, waveNumber) {
  if (!Array.isArray(leadSurfaceIds) || leadSurfaceIds.length === 0) return;
  for (const surfaceId of leadSurfaceIds) {
    if (typeof surfaceId !== "string" || !surfaceId.trim()) continue;
    try {
      appendFrontierEvent({
        target_domain: domain,
        kind: "surface.observed",
        surface_id: surfaceId.trim(),
        payload: {
          wave: waveNumber,
          labels: ["promoted_surface_lead", "wave_handoff_lead"],
        },
        source: { artifact: "wave-handoff", tool: "bob_apply_wave_merge" },
      });
    } catch {
      // Frontier ledger append is best-effort.
    }
  }
}

module.exports = {
  BLOCKED_PREREQ_KIND_CAPABILITY,
  appendBlockerPromotionFrontierEvents,
  appendClosureFrontierEvents,
  appendHandoffLeadSurfaceFrontierEvents,
  basePromotionPreviewForState,
  buildCurrentWaveBlockerMaps,
  buildNextActionForPlan,
  buildStartNextWaveResponse,
  computeCapabilityClearedPremiseSurfaceIds,
  computeRequeueSurfaceIds,
  detectTerminalPromotions,
  inspectSchedulerDecisionIntegrity,
  readQueueTasksForPlanning,
  readRankedSurfacesForPlanning,
};
