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

const BLOCKED_PREREQ_KINDS_WITH_REGISTRY_DELTA = Object.freeze({
  auth_missing: "auth_handles",
  egress_unreachable: "egress_handles",
});

// Loop detector. For each surface with current-wave blockers, look at validated
// history (state.blocked_prereq_history) for prior occurrences of the same
// (kind, identifier_hint) tuple. Registry-delta kinds (auth_missing,
// egress_unreachable) skip promotion when the named handle is newly registered
// since the latest prior occurrence; null identifier_hint skips when the handle
// set grew at all. Other kinds promote on any 2-wave recurrence and require an
// operator clear via bob_clear_terminal_block.
function detectTerminalPromotions({
  currentWaveBlockersBySurface,
  historyBySurface,
  prereqRegistrySnapshots,
  clearHistoryBySurface,
  currentWave,
}) {
  const snapshotByWave = new Map(prereqRegistrySnapshots.map((s) => [s.wave, s]));
  const currentSnapshot = snapshotByWave.get(currentWave);
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
      const registryField = BLOCKED_PREREQ_KINDS_WITH_REGISTRY_DELTA[entry.kind];
      if (registryField && currentSnapshot) {
        // If the handle was registered since the latest prior occurrence, the
        // loop is potentially broken.
        const latestPriorWave = Math.max(...priorMatches.map((p) => p.wave));
        const priorSnapshot = snapshotByWave.get(latestPriorWave);
        const priorHandles = priorSnapshot && Array.isArray(priorSnapshot[registryField])
          ? new Set(priorSnapshot[registryField])
          : new Set();
        const currentHandles = new Set(currentSnapshot[registryField] || []);
        if (hint != null) {
          // Skip only if the exact named handle is newly registered.
          if (currentHandles.has(hint) && !priorHandles.has(hint)) continue;
        } else {
          // Skip if the handle set grew at all.
          let grew = false;
          for (const h of currentHandles) {
            if (!priorHandles.has(h)) { grew = true; break; }
          }
          if (grew) continue;
        }
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
    response.assignments_path = started.assignments_path;
    response.state = started.state;
    response.next_action.assignments_path = started.assignments_path;
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

function computeRequeueSurfaceIds(artifacts, merge, coverageRecords = []) {
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
  BLOCKED_PREREQ_KINDS_WITH_REGISTRY_DELTA,
  appendBlockerPromotionFrontierEvents,
  appendClosureFrontierEvents,
  appendHandoffLeadSurfaceFrontierEvents,
  basePromotionPreviewForState,
  buildCurrentWaveBlockerMaps,
  buildNextActionForPlan,
  buildStartNextWaveResponse,
  computeRequeueSurfaceIds,
  detectTerminalPromotions,
  inspectSchedulerDecisionIntegrity,
  readQueueTasksForPlanning,
  readRankedSurfacesForPlanning,
};
