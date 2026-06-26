"use strict";

const {
  assertBoolean,
  assertNonEmptyString,
  parseWaveNumber,
  pushUnique,
} = require("../validation.js");
const { withSessionLock } = require("../storage.js");
const { compactSessionState } = require("../session-state-contracts.js");
const {
  readSessionStateStrict,
  writeSessionStateDocument,
} = require("../session-state-store.js");
const { readCoverageRecordsFromJsonl } = require("../coverage.js");
const {
  findingPayloadsFromClaims,
} = require("../tools/record-candidate-claim.js");
const {
  summarizeFindings,
} = require("../finding-contracts.js");
const { readScopeExclusions } = require("../scope.js");
const { scheduleMaterialization } = require("../frontier-materialize-debounce.js");
const { ERROR_CODES, ToolError } = require("../envelope.js");
const { safeAppendPipelineEventDirect } = require("../pipeline-events.js");
const { buildGovernanceContext } = require("../governance-context.js");
const {
  buildWaveReadiness,
  loadWaveArtifacts,
  mergeWaveHandoffsInternal,
} = require("../wave-handoff-store.js");
const {
  appendBlockerPromotionFrontierEvents,
  appendClosureFrontierEvents,
  appendHandoffLeadSurfaceFrontierEvents,
  buildCurrentWaveBlockerMaps,
  computeRequeueSurfaceIds,
  detectTerminalPromotions,
  inspectSchedulerDecisionIntegrity,
} = require("./wave-promotion-detector.js");
const { mechanizeWaveFriction } = require("../friction-mechanization.js");

function emitWaveMergedPipelineEvents({
  domain,
  state,
  waveNumber,
  forceMerge,
  forceMergeReason,
  schedulerDecisionIntegrity,
  readiness,
  merge,
  filteredRequeueSurfaceIds,
  promotions,
  findings,
  mergeGovernanceContext,
}) {
  for (const promotion of promotions) {
    for (const blocker of promotion.blockers) {
      safeAppendPipelineEventDirect(domain, "surface_terminally_blocked", {
        lifecycle_state: state.lifecycle_state,
        wave_number: waveNumber,
        status: "promoted",
        source: "bob_apply_wave_merge",
        surface_id: promotion.surface_id,
        kind: blocker.kind,
        identifier_hint: blocker.identifier_hint || null,
      }, mergeGovernanceContext);
    }
  }
  const { currentBlockers } = require("../frontier-projections.js");
  let terminallyBlockedTotal = 0;
  try {
    terminallyBlockedTotal = currentBlockers(domain).length;
  } catch {
    terminallyBlockedTotal = promotions.length;
  }
  safeAppendPipelineEventDirect(domain, "wave_merged", {
    lifecycle_state: state.lifecycle_state,
    wave_number: waveNumber,
    force_merge: forceMerge,
    force_merge_reason: forceMergeReason,
    status: "merged",
    source: "bob_apply_wave_merge",
    scheduler_decision_id: schedulerDecisionIntegrity.scheduler_decision_id,
    assignment_batch_id: schedulerDecisionIntegrity.assignment_batch_id,
    scheduler_decision_integrity: schedulerDecisionIntegrity,
    counts: {
      assignments: readiness.assignments_total,
      handoffs: readiness.handoffs_total,
      received_handoffs: merge.received_agents.length,
      invalid_handoffs: merge.invalid_agents.length,
      unexpected_handoffs: merge.unexpected_agents.length,
      missing_surfaces: merge.missing_surface_ids.length,
      requeue_surfaces: filteredRequeueSurfaceIds.length,
      terminally_blocked_promoted: promotions.length,
      terminally_blocked_total: terminallyBlockedTotal,
      findings: findings.total,
    },
  }, mergeGovernanceContext);
}

function emitMergePendingPipelineEvent(domain, state, waveNumber, readiness) {
  safeAppendPipelineEventDirect(domain, "wave_merge_pending", {
    lifecycle_state: state.lifecycle_state,
    wave_number: waveNumber,
    status: "pending",
    source: "bob_apply_wave_merge",
    counts: {
      assignments: readiness.assignments_total,
      handoffs: readiness.handoffs_total,
      missing_handoffs: readiness.missing_agents.length,
      unexpected_handoffs: readiness.unexpected_agents.length,
    },
  }, buildGovernanceContext(state));
}

function computeMergeResolution({ domain, state, merge, artifacts, waveNumber }) {
  const schedulerDecisionIntegrity = inspectSchedulerDecisionIntegrity({
    domain,
    assignmentBatchId: artifacts.assignment_batch_id,
    schedulerDecisionId: artifacts.scheduler_decision_id,
  });
  const coverageRecords = readCoverageRecordsFromJsonl(domain);
  const requeueSurfaceIds = computeRequeueSurfaceIds(artifacts, merge, coverageRecords);
  const findings = summarizeFindings(findingPayloadsFromClaims(domain));
  const scopeExclusions = [...state.scope_exclusions];
  pushUnique(scopeExclusions, new Set(scopeExclusions), readScopeExclusions(domain));

  const priorHistory = Array.isArray(state.blocked_prereq_history) ? state.blocked_prereq_history : [];
  const { historyBySurface, currentWaveBlockersBySurface, nextHistory } =
    buildCurrentWaveBlockerMaps(merge, priorHistory, waveNumber);

  const priorSnapshots = Array.isArray(state.prereq_registry_snapshots) ? state.prereq_registry_snapshots : [];
  const clearHistory = Array.isArray(state.terminal_block_clear_history) ? state.terminal_block_clear_history : [];
  const clearHistoryBySurface = new Map();
  for (const entry of clearHistory) {
    if (!clearHistoryBySurface.has(entry.surface_id)) clearHistoryBySurface.set(entry.surface_id, []);
    clearHistoryBySurface.get(entry.surface_id).push(entry);
  }
  const promotions = detectTerminalPromotions({
    currentWaveBlockersBySurface,
    historyBySurface,
    prereqRegistrySnapshots: priorSnapshots,
    clearHistoryBySurface,
    currentWave: waveNumber,
  });

  const deadEnds = [...state.dead_ends];
  const wafBlockedEndpoints = [...state.waf_blocked_endpoints];

  pushUnique(deadEnds, new Set(deadEnds), merge.dead_ends);
  pushUnique(wafBlockedEndpoints, new Set(wafBlockedEndpoints), merge.waf_blocked_endpoints);

  // explored / terminally_blocked / lead_surface_ids state-projection arrays
  // were deleted in D.3. Surface-state projection now folds frontier events
  // through frontier-projections; requeue filtering reads those projections
  // directly so terminally-blocked surfaces stay off the requeue list.
  const { currentBlockers } = require("../frontier-projections.js");
  const blockedSurfaceIds = new Set(currentBlockers(domain).map((entry) => entry.surface_id));
  for (const promotion of promotions) blockedSurfaceIds.add(promotion.surface_id);
  for (const surfaceId of merge.completed_surface_ids) blockedSurfaceIds.delete(surfaceId);
  const filteredRequeueSurfaceIds = requeueSurfaceIds.filter(
    (surfaceId) => !blockedSurfaceIds.has(surfaceId),
  );

  return {
    schedulerDecisionIntegrity,
    findings,
    scopeExclusions,
    nextHistory,
    promotions,
    deadEnds,
    wafBlockedEndpoints,
    filteredRequeueSurfaceIds,
  };
}

function serializeMergeResult({ merge, filteredRequeueSurfaceIds, promotions }) {
  return {
    received_agents: merge.received_agents,
    invalid_agents: merge.invalid_agents,
    invalid_handoffs: merge.invalid_handoffs,
    unexpected_agents: merge.unexpected_agents,
    completed_surface_ids: merge.completed_surface_ids,
    partial_surface_ids: merge.partial_surface_ids,
    missing_surface_ids: merge.missing_surface_ids,
    requeue_surface_ids: filteredRequeueSurfaceIds,
    new_dead_ends_count: merge.dead_ends.length,
    new_waf_blocked_count: merge.waf_blocked_endpoints.length,
    lead_surface_ids: merge.lead_surface_ids,
    blocked_harness_runs: merge.blocked_harness_runs,
    blocked_harness_runs_grouped: merge.blocked_harness_runs_grouped,
    blocked_prereqs: merge.blocked_prereqs,
    blocked_prereqs_grouped: merge.blocked_prereqs_grouped,
    terminally_blocked_promoted: promotions,
    bypass_attempts: merge.bypass_attempts,
    bypass_attempts_grouped: merge.bypass_attempts_grouped,
    unconsumed_pivots: merge.unconsumed_pivots,
    provenance: merge.provenance,
  };
}

function applyWaveMerge(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  const forceMerge = assertBoolean(args.force_merge, "force_merge");
  const forceMergeReason = args.force_merge_reason == null
    ? null
    : assertNonEmptyString(args.force_merge_reason, "force_merge_reason");
  if (forceMerge && (!forceMergeReason || forceMergeReason.length < 20)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "force_merge_reason is required when force_merge is true and must be at least 20 characters");
  }
  if (!forceMerge && forceMergeReason != null) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "force_merge_reason is only allowed when force_merge is true");
  }

  return withSessionLock(domain, () => {
    const { raw, state } = readSessionStateStrict(domain);
    if (state.lifecycle_state !== "OPEN_FRONTIER") {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Wave merge requires lifecycle_state OPEN_FRONTIER, found ${state.lifecycle_state}`);
    }
    if (state.pending_wave == null) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, "Wave merge requires pending_wave to be set");
    }
    if (state.pending_wave !== waveNumber) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Wave merge requires pending_wave ${waveNumber}, found ${state.pending_wave}`);
    }

    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, waveNumber), { domain });
    if (!readiness.is_complete && !forceMerge) {
      emitMergePendingPipelineEvent(domain, state, waveNumber, readiness);
      return JSON.stringify({
        version: 1,
        status: "pending",
        wave_number: waveNumber,
        force_merge: false,
        readiness,
        state: compactSessionState(state),
      });
    }

    const { artifacts, merge } = mergeWaveHandoffsInternal(domain, waveNumber);
    const resolution = computeMergeResolution({ domain, state, merge, artifacts, waveNumber });
    const {
      schedulerDecisionIntegrity,
      findings,
      scopeExclusions,
      nextHistory,
      promotions,
      deadEnds,
      wafBlockedEndpoints,
      filteredRequeueSurfaceIds,
    } = resolution;

    const nextState = {
      ...state,
      blocked_prereq_history: nextHistory,
      dead_ends: deadEnds,
      waf_blocked_endpoints: wafBlockedEndpoints,
      scope_exclusions: scopeExclusions,
      pending_wave: null,
      evaluation_wave: waveNumber,
      total_findings: findings.total,
    };

    writeSessionStateDocument(domain, raw, nextState);
    const mergeGovernanceContext = buildGovernanceContext(nextState);

    // Surface-state transitions are emitted through the frontier ledger:
    // blocker.asserted for terminal promotions, closure.recorded for
    // completed surfaces, surface.observed (carrying the promoted-lead
    // label) for handoff-reported new lead surfaces. The materializer folds
    // these into surface-index.json and frontier-projections derive the
    // current explored / blocked / lead-surface sets directly from events.
    appendBlockerPromotionFrontierEvents(domain, promotions, waveNumber);
    appendClosureFrontierEvents(domain, merge.completed_surface_ids, waveNumber);
    appendHandoffLeadSurfaceFrontierEvents(domain, merge.lead_surface_ids, waveNumber);
    try { scheduleMaterialization(domain); } catch {}

    // CR-3 / I4 — mechanized friction trigger. Auto-propose tool_absent groups
    // at threshold (the load-bearing invariant) and run the one
    // server-witnessable scanner (handoff_ledger_diff, advisory). Synthetics
    // forward under the Y-P3 5-tuple (collapse only same-detected_by dups; a
    // voluntary report coexists, Y-P11). tool_inadequate stays operator-gated.
    // Best-effort: never fails the merge, but a swallowed bug is surfaced as
    // friction_mechanization.error so the e2e test can assert the non-error path.
    let frictionMechanization = null;
    try {
      frictionMechanization = mechanizeWaveFriction(domain, merge.run_contexts || []);
    } catch (error) {
      frictionMechanization = { error: "mechanization_skipped", reason: String(error && error.message || error) };
    }

    emitWaveMergedPipelineEvents({
      domain,
      state,
      waveNumber,
      forceMerge,
      forceMergeReason,
      schedulerDecisionIntegrity,
      readiness,
      merge,
      filteredRequeueSurfaceIds,
      promotions,
      findings,
      mergeGovernanceContext,
    });
    return JSON.stringify({
      version: 1,
      status: "merged",
      wave_number: waveNumber,
      force_merge: forceMerge,
      force_merge_reason: forceMergeReason,
      readiness,
      scheduler_decision_integrity: schedulerDecisionIntegrity,
      merge: serializeMergeResult({ merge, filteredRequeueSurfaceIds, promotions }),
      findings,
      friction_mechanization: frictionMechanization,
      state: compactSessionState(nextState),
    });
  });
}

module.exports = {
  applyWaveMerge,
};
