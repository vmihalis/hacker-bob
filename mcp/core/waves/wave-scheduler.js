"use strict";

const fs = require("fs");
const path = require("path");
const {
  assertBoolean,
  assertNonEmptyString,
  parseWaveNumber,
} = require("../io/validation.js");
const {
  surfaceLeadsPath,
  surfaceRoutesPath,
} = require("../io/paths.js");
const {
  readFileUtf8,
  withSessionLock,
  writeFileAtomic,
} = require("../io/storage.js");
const {
  compactSessionState,
  terminallyBlockedSurfaceIds,
} = require("../session/session-state-contracts.js");
const {
  readSessionStateStrict,
  writeSessionStateDocument,
} = require("../session/session-state-store.js");
const { normalizeWaveAssignmentsInput } = require("../session/assignments.js");
const { readCoverageRecordsFromJsonl } = require("../frontier/coverage.js");
const { readAttackSurfaceStrict } = require("../frontier/attack-surface.js");
const {
  promoteSurfaceLeadsForWave,
} = require("../frontier/surface-leads.js");
const { planNextWave } = require("./wave-planner.js");
const { loadQueuePolicy } = require("../io/queue-policy.js");
const { scheduleTasksFromQueue } = require("./scheduler-decisions.js");
const { appendWaveAssignmentAgentRun } = require("../session/agent-runs.js");
const { ERROR_CODES, ToolError } = require("../io/envelope.js");
const { safeAppendPipelineEventDirect } = require("../telemetry/pipeline-events.js");
const { buildGovernanceContext } = require("../governance/index.js");
const {
  prepareWaveAssignments,
  removeWaveAssignmentsDocument,
  writeWaveAssignmentsDocument,
} = require("./wave-assignment-store.js");
const { snapshotPrereqRegistries } = require("./wave-prereq-snapshots.js");
const {
  basePromotionPreviewForState,
  buildStartNextWaveResponse,
  readQueueTasksForPlanning,
  readRankedSurfacesForPlanning,
} = require("./wave-promotion-detector.js");

function assertWaveStartState(state, waveNumber) {
  if (state.lifecycle_state !== "OPEN_FRONTIER") {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Wave start requires lifecycle_state OPEN_FRONTIER, found ${state.lifecycle_state}`);
  }
  if (state.pending_wave != null) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Wave start requires pending_wave null, found ${state.pending_wave}`);
  }
  if (waveNumber !== state.evaluation_wave + 1) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `wave_number must equal evaluation_wave + 1 (${state.evaluation_wave + 1})`);
  }
}

function startWaveLocked(domain, {
  raw,
  state,
  waveNumber,
  assignments,
  attackSurfaceInfo = null,
  source = "bob_start_wave",
  startedBy = source,
  statePatch = null,
  schedulerDecisionId = null,
  assignmentBatchId = null,
} = {}) {
  assertWaveStartState(state, waveNumber);

  // Terminally-blocked surfaces cannot be assigned to a wave until an operator
  // clears the block via bob_clear_terminal_block.
  const terminallyBlockedSet = new Set(terminallyBlockedSurfaceIds(state));
  const blockedAssignments = assignments
    .filter((assignment) => terminallyBlockedSet.has(assignment.surface_id))
    .map((assignment) => assignment.surface_id);
  if (blockedAssignments.length > 0) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `Cannot assign terminally-blocked surfaces to a wave; clear the block via bob_clear_terminal_block first: ${blockedAssignments.join(", ")}`,
    );
  }

  const prepared = prepareWaveAssignments({
    domain,
    waveNumber,
    assignments,
    attackSurfaceInfo,
    schedulerDecisionId,
    assignmentBatchId,
  });
  const { assignmentsPath, persistedAssignments, assignmentsDocument } = prepared;

  // Snapshot registries BEFORE writing the assignment file so a failing
  // snapshot leaves no orphaned wave-N-assignments.json on disk.
  const startSnapshot = snapshotPrereqRegistries(domain);
  const priorSnapshots = Array.isArray(state.prereq_registry_snapshots) ? state.prereq_registry_snapshots : [];
  const nextSnapshots = [
    ...priorSnapshots.filter((s) => s.wave !== waveNumber),
    { wave: waveNumber, ...startSnapshot },
  ].sort((a, b) => a.wave - b.wave);

  writeWaveAssignmentsDocument(assignmentsPath, assignmentsDocument);

  const nextState = {
    ...state,
    ...(statePatch || {}),
    pending_wave: waveNumber,
    prereq_registry_snapshots: nextSnapshots,
  };

  try {
    writeSessionStateDocument(domain, raw, nextState);
  } catch (error) {
    const rollbackSucceeded = removeWaveAssignmentsDocument(assignmentsPath);
    const rollbackStatus = rollbackSucceeded ? "rollback succeeded" : "rollback failed";
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `State write failed after writing assignments; ${rollbackStatus}: ${assignmentsPath} (${error.message || String(error)})`,
    );
  }
  // AgentRun ledger gains an `assigned` row per wave assignment. Best-effort:
  // the merge gate's file-presence fallback keeps the merge functional if the
  // ledger write fails (Pact P2).
  const waveLabel = `w${waveNumber}`;
  for (const assignment of persistedAssignments) {
    try {
      appendWaveAssignmentAgentRun({
        targetDomain: domain,
        wave: waveLabel,
        agent: assignment.agent,
        surfaceId: assignment.surface_id,
        contextSliceHash: assignment.handoff_token_sha256 || null,
      });
    } catch {}
  }

  // The MCP-owned spawn-ledger writer. This is the mutating dispatch step the
  // read-path width bound was waiting on: for each wave-evaluator root the
  // orchestrator is about to hand out, reserve its LIFETIME spawn cost against the
  // session budget. That cost is the root agent itself (always 1) PLUS its
  // worst-case nested subtree (the descendant count, which is 0 when the root does
  // not fan out). Counting the root — not only its nested descendants — is what
  // makes max_total_spawned_agents bind ACROSS waves: a flat per-surface evaluator
  // costs one lifetime slot even with nesting off, so K waves of roots cannot
  // silently exceed the operator's lifetime ceiling. Greedy-sequential — each root
  // is sized against the budget already reserved by prior roots (this wave) and
  // prior waves — so the cumulative reservation provably stays within
  // max_total_spawned_agents, and bob_read_assignment_brief reads the same total
  // (excluding the root's own row) to reproduce that root's allocation. Gated on the
  // governor being set, so default-off (max_total_spawned_agents=null) writes
  // nothing and is byte-identical. Best-effort: the ledger is append-only, so a
  // failed write degrades to the conservative recompute on the next read, never a
  // budget overrun.
  try {
    const policy = loadQueuePolicy(domain);
    if (Number.isInteger(policy.max_total_spawned_agents)) {
      const { buildChildFanoutPlanForSurface } = require("../session/assignment-brief.js");
      const { buildCoverageSummaryForSurface } = require("../frontier/coverage.js");
      const { appendSpawnLedgerEntry } = require("../session/spawn-ledger.js");
      const { worstCaseTreeSize } = require("../session/nested-spawn.js");
      let surfaces = [];
      try { surfaces = readAttackSurfaceStrict(domain).document.surfaces || []; } catch {}
      const coverageRecords = readCoverageRecordsFromJsonl(domain);
      for (const assignment of persistedAssignments) {
        // The root agent always costs one lifetime slot. A nested fan-out plan
        // adds its worst-case descendant subtree on top; a flat root (nesting off,
        // or no plan) adds 0 descendants but still reserves itself.
        let descendants = 0;
        let planDepth = 0;
        let planBranching = 0;
        const surfaceObj = surfaces.find((s) => s && s.id === assignment.surface_id);
        if (surfaceObj) {
          let plan;
          try {
            plan = buildChildFanoutPlanForSurface({
              domain,
              surfaceObj,
              surfaceId: assignment.surface_id,
              coverageSummary: buildCoverageSummaryForSurface(coverageRecords, assignment.surface_id),
              wave: waveLabel,
            });
          } catch { plan = null; }
          if (plan && Array.isArray(plan.children) && plan.children.length > 0 && plan.remaining_depth > 0) {
            // Reserve the tree the brain actually emitted. plan.max_children is
            // the policy/budget ceiling and can exceed children.length when the
            // surface has fewer candidate cells; charging the ceiling would make
            // later roots reproduce a smaller plan and can overrun the lifetime
            // cap once their mandatory root slots are appended.
            // NS-4 — charge the exact emitted descendant width plus the root slot.
            const issuedBranching = plan.children.length;
            const worstCase = worstCaseTreeSize(issuedBranching, plan.remaining_depth);
            if (worstCase > 0) {
              descendants = worstCase;
              planDepth = plan.remaining_depth;
              planBranching = issuedBranching;
            }
          }
        }
        const rootCount = 1;
        try {
          appendSpawnLedgerEntry(domain, {
            ts: new Date().toISOString(),
            wave: waveLabel,
            parent_agent: assignment.agent,
            surface_id: assignment.surface_id,
            depth: planDepth,
            branching: planBranching,
            root_count: rootCount,
            descendant_tree: descendants,
            worst_case_tree: rootCount + descendants,
          });
        } catch {}
      }
    }
  } catch {}
  // Parked, unroutable surfaces from the assignment doc, read ONCE with a single
  // guard so the wave_started telemetry and the synchronous start response never
  // diverge (a resume that reads an older assignment doc without the field must
  // not throw on `.length`). Sourced from the same assignmentsDocument both below.
  const unroutableSurfaces = Array.isArray(assignmentsDocument.unroutable_surfaces)
    ? assignmentsDocument.unroutable_surfaces
    : [];
  safeAppendPipelineEventDirect(domain, "wave_started", {
    lifecycle_state: state.lifecycle_state,
    wave_number: waveNumber,
    status: "started",
    source,
    started_by: startedBy,
    scheduler_decision_id: schedulerDecisionId || null,
    assignment_batch_id: assignmentBatchId || null,
    counts: {
      assignments: persistedAssignments.length,
      unroutable: unroutableSurfaces.length,
    },
  }, buildGovernanceContext(nextState));

  // Surface the parked, unroutable surfaces on the SYNCHRONOUS start response so a
  // caller sees the coverage gap without grepping telemetry. Additive fields only —
  // routable-surface response shape is unchanged.
  // Honest zero-executable signal. An all-unroutable wave persists zero routable
  // assignments; it stays STARTED and self-completing (non-halting — we do NOT
  // reject or throw), but a caller reading `started:true` alone would be misled
  // into thinking work is in flight. These additive flags name the gap explicitly.
  // Additive-only: a routable wave carries has_routable_assignments:true /
  // zero_executable:false, keeping its response shape byte-identical.
  const hasRoutableAssignments = persistedAssignments.length > 0;
  return {
    wave_number: waveNumber,
    assignments: persistedAssignments.map((assignment) => ({
      agent: assignment.agent,
      surface_id: assignment.surface_id,
      capability_pack: assignment.capability_pack,
      capability_pack_version: assignment.capability_pack_version,
      evaluator_agent: assignment.evaluator_agent,
      brief_profile: assignment.brief_profile,
      context_budget: assignment.context_budget,
      task_lens: assignment.task_lens,
      budget: assignment.budget,
      handoff_token: assignment.handoff_token,
    })),
    has_routable_assignments: hasRoutableAssignments,
    zero_executable: !hasRoutableAssignments,
    unroutable_count: unroutableSurfaces.length,
    unroutable_surfaces: unroutableSurfaces,
    assignments_path: assignmentsPath,
    state: compactSessionState(nextState),
  };
}

function startWave(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  const assignments = normalizeWaveAssignmentsInput(args.assignments);

  return withSessionLock(domain, () => {
    const { raw, state } = readSessionStateStrict(domain);
    const started = startWaveLocked(domain, {
      raw,
      state,
      waveNumber,
      assignments,
      source: "bob_start_wave",
      startedBy: "bob_start_wave",
    });
    return JSON.stringify({
      version: 1,
      started: true,
      wave_number: started.wave_number,
      assignments: started.assignments,
      has_routable_assignments: started.has_routable_assignments,
      zero_executable: started.zero_executable,
      unroutable_count: started.unroutable_count,
      unroutable_surfaces: started.unroutable_surfaces,
      assignments_path: started.assignments_path,
      state: started.state,
    });
  });
}

function snapshotFileForRollback(filePath) {
  return {
    path: filePath,
    existed: fs.existsSync(filePath),
    content: fs.existsSync(filePath) ? readFileUtf8(filePath, { label: path.basename(filePath) }) : null,
  };
}

function restoreFileSnapshot(snapshot) {
  if (!snapshot) return;
  if (snapshot.existed) {
    writeFileAtomic(snapshot.path, snapshot.content);
  } else {
    fs.rmSync(snapshot.path, { force: true });
  }
}

function startNextWave(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const dryRun = args.dry_run == null ? false : assertBoolean(args.dry_run, "dry_run");

  return withSessionLock(domain, () => {
    const { raw, state } = readSessionStateStrict(domain);
    if (state.lifecycle_state !== "OPEN_FRONTIER") {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Wave start requires lifecycle_state OPEN_FRONTIER, found ${state.lifecycle_state}`);
    }

    const basePromotionPreview = basePromotionPreviewForState(domain, state);
    let promotion = { ...basePromotionPreview, promoted: 0, promoted_surface_ids: [] };
    const queuePolicy = loadQueuePolicy(domain);

    if (state.pending_wave != null) {
      const plan = planNextWave({ state, surfaces: [], queuePolicy });
      return JSON.stringify(buildStartNextWaveResponse({ domain, dryRun, state, plan, promotion }));
    }

    let planningState = state;
    let rollbackSnapshots = null;
    let promotedForThisStart = false;
    try {
      if (!dryRun && state.deep_mode === true && basePromotionPreview.would_promote_lead_ids.length > 0) {
        // D.3 removed the attack_surface.json writer; promotion no longer
        // touches the legacy projection file, so the rollback snapshot list
        // contracts to surface-leads.json + surface-routes.json. The frontier
        // ledger is append-only and not rolled back here (it remains
        // append-only authority; replay tooling handles any operator
        // overrides).
        rollbackSnapshots = [
          snapshotFileForRollback(surfaceLeadsPath(domain)),
          snapshotFileForRollback(surfaceRoutesPath(domain)),
        ];
        const promoted = promoteSurfaceLeadsForWave(domain, { limit: 8, min_score: 60, include_medium: false });
        promotedForThisStart = promoted.promoted_surface_ids.length > 0;
        promotion = {
          ...basePromotionPreview,
          promoted: promoted.promoted,
          promoted_surface_ids: promoted.promoted_surface_ids,
          leads_path: promoted.leads_path,
          attack_surface_path: promoted.attack_surface_path,
        };
        // Force materialization so the just-promoted surfaces appear in
        // surface-index.json before the wave planner reads them. The
        // debounced flush would otherwise fire only after the outer
        // session-lock releases (after planning has already run).
        if (promotedForThisStart) {
          try {
            require("../frontier/frontier-materializer.js").materializeFrontier(domain, { write: true });
          } catch {
            // Materialization is best-effort; the planner will fall back
            // to attack_surface.json (legacy projection) when available.
          }
        }
      }

      // Feed the binding-breadth governor the spawn-tree size already reserved
      // (prior waves' nested roots). The wave planner subtracts this from
      // max_total_spawned_agents to clamp this wave's target/max to the remaining
      // session budget. Read only when the governor is set; null governor reads
      // nothing and leaves planning byte-identical (default-off).
      let reservedSpawnTotal = 0;
      if (Number.isInteger(queuePolicy.max_total_spawned_agents)) {
        try {
          reservedSpawnTotal = require("../session/spawn-ledger.js").spawnLedgerTotal(domain);
        } catch {
          reservedSpawnTotal = 0;
        }
      }
      const plan = planNextWave({
        state: planningState,
        surfaces: readRankedSurfacesForPlanning(domain),
        coverageRecords: readCoverageRecordsFromJsonl(domain),
        taskQueueTasks: readQueueTasksForPlanning(domain),
        queuePolicy,
        reservedSpawnTotal,
      });

      if (dryRun || plan.decision !== "start_wave") {
        if (promotedForThisStart) {
          for (const snapshot of rollbackSnapshots.slice().reverse()) restoreFileSnapshot(snapshot);
          promotion = { ...basePromotionPreview, promoted: 0, promoted_surface_ids: [] };
        }
        return JSON.stringify(buildStartNextWaveResponse({ domain, dryRun, state: planningState, plan, promotion }));
      }

      const assignments = normalizeWaveAssignmentsInput(plan.assignments);
      // Route task selection through bob_schedule_tasks so wave starts become
      // thin callers of the scheduler. The SchedulerDecision is the ledger row
      // referenced by apply-wave-merge even when task-queue.json is empty.
      let schedulerDecision = null;
      try {
        schedulerDecision = scheduleTasksFromQueue(domain, { write: true, decisionKind: "wave_start" });
      } catch {
        schedulerDecision = null;
      }
      // Drop the explicit attack_surface.json read: prepareWaveAssignments
      // now resolves surfaces through currentSurfaces (surface-index.json
      // union with the legacy projection). Passing the strict legacy doc
      // would hide promoted-lead surfaces that the materializer wrote to
      // surface-index.json during the deep-mode promotion above.
      const started = startWaveLocked(domain, {
        raw,
        state: planningState,
        waveNumber: plan.wave_number,
        assignments,
        source: "bob_start_next_wave",
        startedBy: "bob_start_next_wave",
        schedulerDecisionId: schedulerDecision ? schedulerDecision.scheduler_decision_id : null,
        assignmentBatchId: schedulerDecision ? schedulerDecision.assignment_batch_id : null,
      });

      return JSON.stringify(buildStartNextWaveResponse({ domain, dryRun, state: planningState, plan, promotion, started }));
    } catch (error) {
      if (promotedForThisStart && rollbackSnapshots) {
        for (const snapshot of rollbackSnapshots.slice().reverse()) {
          try { restoreFileSnapshot(snapshot); } catch {}
        }
      }
      throw error;
    }
  });
}

module.exports = {
  startNextWave,
  startWave,
};
