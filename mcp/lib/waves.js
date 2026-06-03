"use strict";

const fs = require("fs");
const path = require("path");
const {
  assertBoolean,
  assertNonEmptyString,
  normalizeStringArray,
  parseAgentId,
  parseSurfaceStatus,
  parseWaveId,
  parseWaveNumber,
  pushUnique,
} = require("./validation.js");
const {
  sessionDir,
  attackSurfacePath,
  liveDeadEndsJsonlPath,
  surfaceLeadsPath,
  surfaceRoutesPath,
  waveAssignmentsPath,
} = require("./paths.js");
const {
  appendJsonlLine,
  readFileUtf8,
  withSessionLock,
  writeFileAtomic,
} = require("./storage.js");
const {
  compactSessionState,
  terminallyBlockedSurfaceIds,
} = require("./session-state-contracts.js");
const {
  readSessionStateStrict,
  writeSessionStateDocument,
} = require("./session-state-store.js");
const {
  loadWaveAssignments,
  normalizeWaveAssignmentsInput,
  validateAssignedWaveAgentSurface,
} = require("./assignments.js");
const {
  computeCoverageRequeueSurfaceIds,
  readCoverageRecordsFromJsonl,
} = require("./coverage.js");
const { readAttackSurfaceStrict } = require("./attack-surface.js");
const {
  routeSurfacesInternal,
} = require("./surface-router.js");
const {
  DEEP_MODE_PROMOTION_POLICY,
  isAssignableSurfaceLead,
  previewSurfaceLeadPromotion,
  promoteSurfaceLeadsForWave,
  readSurfaceLeadsDocument,
  recordSurfaceLeadsForWaveHandoff,
} = require("./surface-leads.js");
const {
  rankAttackSurfaces,
} = require("./ranking.js");
const {
  planNextWave,
} = require("./wave-planner.js");
const {
  readFindingsFromJsonl,
  summarizeFindings,
} = require("./findings.js");
const { readScopeExclusions } = require("./scope.js");
const {
  buildCircuitBreakerSummary,
  readHttpAuditRecordsFromJsonl,
  readTrafficRecordsFromJsonl,
  summarizeHttpAuditRecords,
  summarizeTrafficRecords,
} = require("./http-records.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  safeAppendPipelineEventDirect,
} = require("./pipeline-events.js");
const {
  ensureHandoffSigningKey,
} = require("./handoff-signing-key.js");
const { listAuthProfiles } = require("./auth.js");
const { listEgressProfiles } = require("./egress-profiles.js");
const {
  computeHuntToChainGate,
} = require("./phase-gates.js");
const {
  WAVE_HANDOFF_CONTENT_MAX_CHARS,
  assertBlockedHarnessConsistency,
  assertBlockedPrereqConsistency,
  assertSmartContractCompletionEvidence,
  generateHandoffToken,
  HANDOFF_PROVENANCE_MODEL,
  normalizeBlockedHarnessRuns,
  normalizeBlockedPrereqs,
  normalizeBypassAttempts,
  normalizeChainNotes,
  normalizeHandoffSummary,
  sha256Hex,
  signHandoffProvenance,
  validateHandoffToken,
} = require("./wave-handoff-contracts.js");
const {
  buildWaveHandoffsDocument,
  buildWaveReadiness,
  loadWaveArtifacts,
  mergeWaveHandoffs,
  mergeWaveHandoffsInternal,
  readWaveHandoffs,
  waveHandoffStatus,
} = require("./wave-handoff-store.js");

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

function waveStatus(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const findings = readFindingsFromJsonl(domain);
  const summary = summarizeFindings(findings);

  // Compute transition-gate inputs for deterministic wave decisions.
  let coverage = null;
  let transitionBlockers = [];
  try {
    const { state } = readSessionStateStrict(domain);
    const gate = computeHuntToChainGate(domain, state);
    coverage = gate.coverage;
    transitionBlockers = gate.transition_blockers;
  } catch (error) {
    transitionBlockers = [{
      code: "state_unavailable",
      message: "session state could not be read for HUNT -> CHAIN gating",
      error: error && error.message ? error.message : String(error),
    }];
  }

  let auditSummary = null;
  let trafficSummary = null;
  let circuitBreakerSummary = null;
  let surfaceLeadsSummary = null;
  try {
    const auditRecords = readHttpAuditRecordsFromJsonl(domain);
    auditSummary = summarizeHttpAuditRecords(auditRecords, { limit: 0 });
    circuitBreakerSummary = buildCircuitBreakerSummary(auditRecords);
  } catch {}
  try {
    trafficSummary = summarizeTrafficRecords(readTrafficRecordsFromJsonl(domain), { limit: 0 });
  } catch {}
  try {
    const surfaceLeads = readSurfaceLeadsDocument(domain);
    surfaceLeadsSummary = {
      total: surfaceLeads.leads.length,
      high_confidence_unpromoted: surfaceLeads.leads.filter(
        (lead) => lead.status !== "promoted" && lead.confidence === "high" && isAssignableSurfaceLead(lead),
      ).length,
      promoted: surfaceLeads.leads.filter((lead) => lead.status === "promoted").length,
    };
  } catch {}

  return JSON.stringify({
    ...summary,
    coverage,
    transition_blockers: transitionBlockers,
    http_audit: auditSummary,
    traffic: trafficSummary,
    circuit_breaker: circuitBreakerSummary,
    surface_leads: surfaceLeadsSummary,
    findings_summary: findings.map((finding) => ({
      id: finding.id,
      severity: finding.severity,
      title: finding.title,
      endpoint: finding.endpoint,
      wave_agent: finding.wave || finding.agent ? `${finding.wave || "?"}/${finding.agent || "?"}` : null,
    })),
  });
}

function assertWaveStartState(state, waveNumber) {
  if (state.phase !== "HUNT" && state.phase !== "EXPLORE") {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Wave start requires phase HUNT or EXPLORE, found ${state.phase}`);
  }
  if (state.pending_wave != null) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Wave start requires pending_wave null, found ${state.pending_wave}`);
  }
  if (waveNumber !== state.hunt_wave + 1) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `wave_number must equal hunt_wave + 1 (${state.hunt_wave + 1})`);
  }
}

function startWaveLocked(domain, {
  raw,
  state,
  waveNumber,
  assignments,
  attackSurfaceInfo = null,
  source = "bounty_start_wave",
  startedBy = source,
  statePatch = null,
} = {}) {
  assertWaveStartState(state, waveNumber);

  const assignmentsPath = waveAssignmentsPath(domain, waveNumber);
  if (fs.existsSync(assignmentsPath)) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Assignment file already exists: ${assignmentsPath}`);
  }

  const attackSurface = attackSurfaceInfo || readAttackSurfaceStrict(domain);
  const surfaceTypeById = new Map();
  for (const surface of attackSurface.document.surfaces || []) {
    if (!surface || typeof surface !== "object" || Array.isArray(surface)) continue;
    const surfaceTypeRaw = typeof surface.surface_type === "string" ? surface.surface_type.trim() : "";
    surfaceTypeById.set(surface.id, surfaceTypeRaw !== "" ? surfaceTypeRaw : null);
  }
  for (const assignment of assignments) {
    if (!attackSurface.surface_id_set.has(assignment.surface_id)) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `Unknown surface_id in assignments: ${assignment.surface_id}`);
    }
  }

  // Hard write-side filter: terminally-blocked surfaces cannot be
  // assigned to a wave until an operator clears the block via
  // bounty_clear_terminal_block. Defends against an orchestrator
  // regression that drops the soft-prompt exclusion and silently burns
  // hunter cycles on classified-blocked work.
  const terminallyBlockedSet = new Set(terminallyBlockedSurfaceIds(state));
  const blockedAssignments = assignments
    .filter((assignment) => terminallyBlockedSet.has(assignment.surface_id))
    .map((assignment) => assignment.surface_id);
  if (blockedAssignments.length > 0) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `Cannot assign terminally-blocked surfaces to a wave; clear the block via bounty_clear_terminal_block first: ${blockedAssignments.join(", ")}`,
    );
  }

  // Capture surface_type from attack_surface.json AT WAVE START into the
  // immutable, MCP-owned assignment file. This makes the smart_contract
  // completion gate tamper-resistant — hunters cannot disable enforcement
  // by mutating attack_surface.json mid-wave.
  const routedSurfaces = routeSurfacesInternal(domain, { attackSurfaceInfo: attackSurface });
  const routeBySurfaceId = new Map(
    routedSurfaces.document.routes.map((route) => [route.surface_id, route]),
  );
  for (const assignment of assignments) {
    if (!routeBySurfaceId.has(assignment.surface_id)) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `Missing route for surface_id in assignments: ${assignment.surface_id}`);
    }
  }

  const persistedAssignments = assignments.map((assignment) => {
    const token = generateHandoffToken();
    const route = routeBySurfaceId.get(assignment.surface_id);
    return {
      ...assignment,
      surface_type: surfaceTypeById.get(assignment.surface_id) || null,
      capability_pack: route.capability_pack,
      capability_pack_version: route.capability_pack_version,
      hunter_agent: route.hunter_agent,
      brief_profile: route.brief_profile,
      context_budget: route.context_budget,
      handoff_token_required: true,
      handoff_token_sha256: sha256Hex(token),
      handoff_token: token,
    };
  });
  const assignmentsForDisk = persistedAssignments.map(({ handoff_token, ...assignment }) => assignment);
  ensureHandoffSigningKey(domain);

  // Snapshot registries BEFORE the assignment file is written. If the
  // snapshot throws (auth.json malformed, egress config missing, etc.)
  // we want the wave start to fail cleanly with no orphaned assignment
  // file — not a half-written session that fails on retry with
  // "Assignment file already exists".
  const startSnapshot = snapshotPrereqRegistries(domain);
  const priorSnapshots = Array.isArray(state.prereq_registry_snapshots) ? state.prereq_registry_snapshots : [];
  const nextSnapshots = [
    ...priorSnapshots.filter((s) => s.wave !== waveNumber),
    { wave: waveNumber, ...startSnapshot },
  ].sort((a, b) => a.wave - b.wave);

  writeFileAtomic(assignmentsPath, `${JSON.stringify({
    version: 1,
    handoff_tokens_required: true,
    handoff_provenance_model: HANDOFF_PROVENANCE_MODEL,
    wave_number: waveNumber,
    assignments: assignmentsForDisk,
  }, null, 2)}\n`);

  const nextState = {
    ...state,
    ...(statePatch || {}),
    pending_wave: waveNumber,
    prereq_registry_snapshots: nextSnapshots,
  };

  try {
    writeSessionStateDocument(domain, raw, nextState);
  } catch (error) {
    let rollbackSucceeded = false;
    try {
      fs.rmSync(assignmentsPath, { force: true });
      rollbackSucceeded = true;
    } catch {}

    const rollbackStatus = rollbackSucceeded ? "rollback succeeded" : "rollback failed";
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `State write failed after writing assignments; ${rollbackStatus}: ${assignmentsPath} (${error.message || String(error)})`,
    );
  }
  safeAppendPipelineEventDirect(domain, "wave_started", {
    phase: state.phase,
    wave_number: waveNumber,
    status: "started",
    source,
    started_by: startedBy,
    counts: {
      assignments: assignments.length,
    },
  });

  return {
    wave_number: waveNumber,
    assignments: persistedAssignments.map((assignment) => ({
      agent: assignment.agent,
      surface_id: assignment.surface_id,
      capability_pack: assignment.capability_pack,
      capability_pack_version: assignment.capability_pack_version,
      hunter_agent: assignment.hunter_agent,
      brief_profile: assignment.brief_profile,
      context_budget: assignment.context_budget,
      handoff_token: assignment.handoff_token,
    })),
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
      source: "bounty_start_wave",
      startedBy: "bounty_start_wave",
    });

    return JSON.stringify({
      version: 1,
      started: true,
      wave_number: started.wave_number,
      assignments: started.assignments,
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

function pushUniqueValues(values, additions) {
  const result = Array.isArray(values) ? [...values] : [];
  const seen = new Set(result);
  pushUnique(result, seen, Array.isArray(additions) ? additions : []);
  return result;
}

function buildNextWaveAction(domain, decision, waveNumber) {
  if (decision === "pending_wave_reconcile") {
    return {
      kind: "call_tool",
      tool: "bounty_apply_wave_merge",
      arguments: {
        target_domain: domain,
        wave_number: waveNumber,
        force_merge: false,
      },
    };
  }
  if (decision === "start_wave") {
    return {
      kind: "spawn_hunters",
      wave_number: waveNumber,
      assignments_source: "top_level_assignments",
    };
  }
  return {
    kind: "stop",
    reason: "No assignable candidates; phase decisions belong to the orchestrator.",
  };
}

function buildStartNextWaveResponse({
  domain,
  dryRun,
  state,
  plan,
  promotion,
  started = null,
  reason = null,
}) {
  const decision = plan.decision;
  const nextAction = dryRun && decision === "start_wave"
    ? {
        kind: "stop",
        reason: "dry_run is true; call bounty_start_next_wave with dry_run false to start this planned wave.",
      }
    : buildNextWaveAction(domain, decision, decision === "pending_wave_reconcile" ? plan.pending_wave : plan.wave_number);
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

function readRankedAttackSurfacesForPlanning(domain) {
  const ranked = rankAttackSurfaces(domain);
  if (!ranked) {
    readAttackSurfaceStrict(domain);
    return [];
  }
  return ranked.surfaces || [];
}

function startNextWave(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const dryRun = args.dry_run == null ? false : assertBoolean(args.dry_run, "dry_run");

  return withSessionLock(domain, () => {
    const { raw, state } = readSessionStateStrict(domain);
    if (state.phase !== "HUNT" && state.phase !== "EXPLORE") {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Wave start requires phase HUNT or EXPLORE, found ${state.phase}`);
    }

    const basePromotionPreview = state.deep_mode === true
      ? previewSurfaceLeadPromotion(domain, DEEP_MODE_PROMOTION_POLICY)
      : {
          would_promote: 0,
          would_promote_lead_ids: [],
          leads_path: surfaceLeadsPath(domain),
          attack_surface_path: attackSurfacePath(domain),
        };
    let promotion = {
      ...basePromotionPreview,
      promoted: 0,
      promoted_surface_ids: [],
    };

    if (state.pending_wave != null) {
      const plan = planNextWave({ state, surfaces: [] });
      return JSON.stringify(buildStartNextWaveResponse({
        domain,
        dryRun,
        state,
        plan,
        promotion,
      }));
    }

    let planningState = state;
    let rollbackSnapshots = null;
    let promotedForThisStart = false;
    try {
      if (!dryRun && state.deep_mode === true && basePromotionPreview.would_promote_lead_ids.length > 0) {
        rollbackSnapshots = [
          snapshotFileForRollback(attackSurfacePath(domain)),
          snapshotFileForRollback(surfaceLeadsPath(domain)),
          snapshotFileForRollback(surfaceRoutesPath(domain)),
        ];
        const promoted = promoteSurfaceLeadsForWave(domain, DEEP_MODE_PROMOTION_POLICY);
        promotedForThisStart = promoted.promoted_surface_ids.length > 0;
        promotion = {
          ...basePromotionPreview,
          promoted: promoted.promoted,
          promoted_surface_ids: promoted.promoted_surface_ids,
          leads_path: promoted.leads_path,
          attack_surface_path: promoted.attack_surface_path,
        };
        planningState = {
          ...state,
          lead_surface_ids: pushUniqueValues(state.lead_surface_ids, promoted.promoted_surface_ids),
        };
      }

      const rankedSurfaces = readRankedAttackSurfacesForPlanning(domain);
      const coverageRecords = readCoverageRecordsFromJsonl(domain);
      const plan = planNextWave({
        state: planningState,
        surfaces: rankedSurfaces,
        coverageRecords,
      });

      if (dryRun || plan.decision !== "start_wave") {
        if (promotedForThisStart) {
          for (const snapshot of rollbackSnapshots.slice().reverse()) restoreFileSnapshot(snapshot);
          promotion = {
            ...basePromotionPreview,
            promoted: 0,
            promoted_surface_ids: [],
          };
          planningState = state;
        }
        return JSON.stringify(buildStartNextWaveResponse({
          domain,
          dryRun,
          state: planningState,
          plan,
          promotion,
        }));
      }

      const assignments = normalizeWaveAssignmentsInput(plan.assignments);
      const started = startWaveLocked(domain, {
        raw,
        state: planningState,
        waveNumber: plan.wave_number,
        assignments,
        attackSurfaceInfo: readAttackSurfaceStrict(domain),
        source: "bounty_start_next_wave",
        startedBy: "bounty_start_next_wave",
        statePatch: promotedForThisStart
          ? { lead_surface_ids: planningState.lead_surface_ids }
          : null,
      });

      return JSON.stringify(buildStartNextWaveResponse({
        domain,
        dryRun,
        state: planningState,
        plan,
        promotion,
        started,
      }));
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

// Snapshot registry HANDLE SETS at wave start so the loop detector can
// reason about whether the SPECIFIC material a stuck blocker named was
// added since. Counts collapse unrelated additions into "growth" and
// give the original blocker permanent amnesty (e.g., adding `victim`
// would silently satisfy `auth_missing: attacker`). Failures throw
// rather than fail-open because the caller (start_wave) cannot make a
// trustworthy snapshot without registry visibility — better to refuse
// the wave than to record a lying snapshot.
function snapshotPrereqRegistries(domain) {
  let authHandles;
  try {
    const result = JSON.parse(listAuthProfiles({ target_domain: domain }));
    authHandles = Array.isArray(result.profiles)
      ? result.profiles.map((p) => p && typeof p.profile_name === "string" ? p.profile_name : null).filter(Boolean)
      : [];
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Could not snapshot auth-profile registry for ${domain}: ${error.message || String(error)}`,
    );
  }
  let egressHandles;
  try {
    const profiles = listEgressProfiles();
    egressHandles = profiles
      .filter((p) => p && p.enabled)
      .map((p) => p && typeof p.name === "string" ? p.name : null)
      .filter(Boolean);
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Could not snapshot egress-profile registry: ${error.message || String(error)}`,
    );
  }
  return {
    auth_handles: Array.from(new Set(authHandles)).sort(),
    egress_handles: Array.from(new Set(egressHandles)).sort(),
  };
}

const BLOCKED_PREREQ_KINDS_WITH_REGISTRY_DELTA = Object.freeze({
  auth_missing: "auth_handles",
  egress_unreachable: "egress_handles",
});

// Loop detector. For each surface with current-wave blockers, look at
// validated history (state.blocked_prereq_history) for prior occurrences
// of the same (kind, identifier_hint) tuple. For kinds with a
// registry-delta channel (auth_missing, egress_unreachable), skip
// promotion when the SPECIFIC handle the blocker named was added since
// the LATEST prior occurrence — handle-set membership rather than count
// growth. For null identifier_hint (no specific handle requested), skip
// when the handle set itself grew (any new handle appeared). Other
// kinds (funded_wallet_missing, key_material_missing,
// external_credential_missing) have no registry-delta path; they
// promote on any 2-wave recurrence and require operator clear via
// bounty_clear_terminal_block.
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
    // The latest clear for this surface defines the recurrence horizon:
    // history entries from waves <= cleared_at_wave are pre-clear and
    // do not count toward the loop detector's "recurred across waves"
    // signal. Without this, every clear-then-reblock would immediately
    // re-promote.
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
      // Prior occurrences are entries from waves strictly before the
      // current one and strictly after the latest clear for this surface.
      const priorMatches = surfaceHistory.filter((h) =>
        h.wave < currentWave &&
        h.wave > latestClearAtWave &&
        h.kind === entry.kind &&
        (h.identifier_hint || null) === hint,
      );
      if (priorMatches.length === 0) continue;
      const registryField = BLOCKED_PREREQ_KINDS_WITH_REGISTRY_DELTA[entry.kind];
      if (registryField && currentSnapshot) {
        // LATEST prior wave: if the handle was added since the most
        // recent unresolved occurrence, the loop was potentially broken.
        const latestPriorWave = Math.max(...priorMatches.map((p) => p.wave));
        const priorSnapshot = snapshotByWave.get(latestPriorWave);
        const priorHandles = priorSnapshot && Array.isArray(priorSnapshot[registryField])
          ? new Set(priorSnapshot[registryField])
          : new Set();
        const currentHandles = new Set(currentSnapshot[registryField] || []);
        if (hint != null) {
          // Specific handle named: skip promotion only if that exact
          // handle is newly registered.
          if (currentHandles.has(hint) && !priorHandles.has(hint)) continue;
        } else {
          // No specific handle: skip if the handle set grew at all.
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
    if (state.phase !== "HUNT" && state.phase !== "EXPLORE") {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Wave merge requires phase HUNT or EXPLORE, found ${state.phase}`);
    }
    if (state.pending_wave == null) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, "Wave merge requires pending_wave to be set");
    }
    if (state.pending_wave !== waveNumber) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Wave merge requires pending_wave ${waveNumber}, found ${state.pending_wave}`);
    }

    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, waveNumber), { domain });
    if (!readiness.is_complete && !forceMerge) {
      safeAppendPipelineEventDirect(domain, "wave_merge_pending", {
        phase: state.phase,
        wave_number: waveNumber,
        status: "pending",
        source: "bounty_apply_wave_merge",
        counts: {
          assignments: readiness.assignments_total,
          handoffs: readiness.handoffs_total,
          missing_handoffs: readiness.missing_agents.length,
          unexpected_handoffs: readiness.unexpected_agents.length,
        },
      });
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
    const coverageRecords = readCoverageRecordsFromJsonl(domain);
    const requeueSurfaceIds = computeRequeueSurfaceIds(artifacts, merge, coverageRecords);
    const requeueSurfaceIdSet = new Set(requeueSurfaceIds);
    const findings = summarizeFindings(readFindingsFromJsonl(domain));
    const scopeExclusions = [...state.scope_exclusions];
    pushUnique(scopeExclusions, new Set(scopeExclusions), readScopeExclusions(domain));

    // Append current wave's validated blocker tuples to state-side
    // history. State history is the single source of truth for the loop
    // detector — no raw handoff re-reads. Cycle 4's clear command will
    // prune this history per surface so re-blocked surfaces start fresh.
    const priorHistory = Array.isArray(state.blocked_prereq_history) ? state.blocked_prereq_history : [];
    const newHistoryEntries = (merge.blocked_prereqs || []).map((entry) => {
      const record = {
        wave: waveNumber,
        surface_id: entry.surface_id,
        kind: entry.kind,
      };
      if (entry.identifier_hint) record.identifier_hint = entry.identifier_hint;
      if (entry.reason) record.reason = entry.reason;
      return record;
    });
    const nextHistory = [...priorHistory, ...newHistoryEntries];

    // Build per-surface history map for the detector.
    const historyBySurface = new Map();
    for (const entry of nextHistory) {
      if (!historyBySurface.has(entry.surface_id)) historyBySurface.set(entry.surface_id, []);
      historyBySurface.get(entry.surface_id).push(entry);
    }

    // Build current wave's blocker map per surface from merge.blocked_prereqs.
    const currentWaveBlockersBySurface = new Map();
    for (const entry of merge.blocked_prereqs || []) {
      if (!currentWaveBlockersBySurface.has(entry.surface_id)) currentWaveBlockersBySurface.set(entry.surface_id, []);
      currentWaveBlockersBySurface.get(entry.surface_id).push({
        kind: entry.kind,
        identifier_hint: entry.identifier_hint || null,
        reason: entry.reason,
      });
    }

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
    // Merge promotions into existing state.terminally_blocked. If the
    // same surface is promoted twice, the new wave's promotion wins.
    // Disjointness with state.explored is enforced at normalize time;
    // a complete handoff in a later wave strips terminally_blocked.
    const promotedSurfaceIds = new Set(promotions.map((p) => p.surface_id));
    const carriedTerminallyBlocked = (Array.isArray(state.terminally_blocked) ? state.terminally_blocked : [])
      .filter((entry) => !promotedSurfaceIds.has(entry.surface_id));
    const nextTerminallyBlocked = [...carriedTerminallyBlocked, ...promotions];

    const explored = [...state.explored];
    const deadEnds = [...state.dead_ends];
    const wafBlockedEndpoints = [...state.waf_blocked_endpoints];
    const leadSurfaceIds = [...state.lead_surface_ids];
    const attackSurface = readAttackSurfaceStrict(domain);

    // The structured handoff's `surface_status: complete` is the contract;
    // coverage rows are endpoint-level advisory history. A hunter that wrote
    // `complete` and ALSO wrote some unfinished coverage rows during the same
    // wave is internally inconsistent, but the right place to catch that is
    // either the hunter prompt or a server-side handoff validator — not a
    // silent downgrade that strands the surface in HUNT forever. Trust the
    // handoff and add to explored unconditionally.
    pushUnique(
      explored,
      new Set(explored),
      merge.completed_surface_ids,
    );
    pushUnique(deadEnds, new Set(deadEnds), merge.dead_ends);
    pushUnique(wafBlockedEndpoints, new Set(wafBlockedEndpoints), merge.waf_blocked_endpoints);
    pushUnique(leadSurfaceIds, new Set(leadSurfaceIds), merge.lead_surface_ids);

    // Disjointness invariant: a surface marked complete in this wave wins
    // over any prior terminal promotion. Strip from terminally_blocked.
    const exploredSet = new Set(explored);
    const reconciledTerminallyBlocked = nextTerminallyBlocked.filter(
      (entry) => !exploredSet.has(entry.surface_id),
    );
    const reconciledTerminallySet = new Set(reconciledTerminallyBlocked.map((e) => e.surface_id));

    const filteredLeadSurfaceIds = leadSurfaceIds.filter(
      (surfaceId) =>
        attackSurface.surface_id_set.has(surfaceId) &&
        !explored.includes(surfaceId) &&
        !reconciledTerminallySet.has(surfaceId),
    );

    // Filter requeue: terminally-blocked surfaces are not "requeue
    // candidates" — the orchestrator must clear them via
    // bounty_clear_terminal_block before they can be assigned again.
    const filteredRequeueSurfaceIds = requeueSurfaceIds.filter(
      (surfaceId) => !reconciledTerminallySet.has(surfaceId),
    );

    // Snapshots are populated by start_wave; merge does not write them.
    const nextState = {
      ...state,
      explored,
      terminally_blocked: reconciledTerminallyBlocked,
      blocked_prereq_history: nextHistory,
      dead_ends: deadEnds,
      waf_blocked_endpoints: wafBlockedEndpoints,
      lead_surface_ids: filteredLeadSurfaceIds,
      scope_exclusions: scopeExclusions,
      pending_wave: null,
      hunt_wave: waveNumber,
      total_findings: findings.total,
    };

    writeSessionStateDocument(domain, raw, nextState);
    // Emit one surface_terminally_blocked event per (surface, blocker)
    // pair so analytics can attribute promotions back to specific
    // missing-prereq tuples without joining against state.
    for (const promotion of promotions) {
      for (const blocker of promotion.blockers) {
        safeAppendPipelineEventDirect(domain, "surface_terminally_blocked", {
          phase: state.phase,
          wave_number: waveNumber,
          status: "promoted",
          source: "bounty_apply_wave_merge",
          surface_id: promotion.surface_id,
          kind: blocker.kind,
          identifier_hint: blocker.identifier_hint || null,
        });
      }
    }
    safeAppendPipelineEventDirect(domain, "wave_merged", {
      phase: state.phase,
      wave_number: waveNumber,
      force_merge: forceMerge,
      force_merge_reason: forceMergeReason,
      status: "merged",
      source: "bounty_apply_wave_merge",
      counts: {
        assignments: readiness.assignments_total,
        handoffs: readiness.handoffs_total,
        received_handoffs: merge.received_agents.length,
        invalid_handoffs: merge.invalid_agents.length,
        unexpected_handoffs: merge.unexpected_agents.length,
        missing_surfaces: merge.missing_surface_ids.length,
        requeue_surfaces: filteredRequeueSurfaceIds.length,
        terminally_blocked_promoted: promotions.length,
        terminally_blocked_total: reconciledTerminallyBlocked.length,
        findings: findings.total,
      },
    });
    return JSON.stringify({
      version: 1,
      status: "merged",
      wave_number: waveNumber,
      force_merge: forceMerge,
      force_merge_reason: forceMergeReason,
      readiness,
      merge: {
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
        suspicion_flags: merge.suspicion_flags,
        provenance: merge.provenance,
      },
      findings,
      state: compactSessionState(nextState),
    });
  });
}

function writeHandoff(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });

  const lines = [];
  lines.push(`# Handoff — Session ${args.session_number}`);
  lines.push(`## Target: ${args.target_url}`);
  if (args.program_url) lines.push(`## Program: ${args.program_url}`);
  const findings = args.findings_summary || [];
  lines.push(`\n## Findings (${findings.length})`);
  for (const f of findings) lines.push(`- ${f.id} [${(f.severity || "").toUpperCase()}]: ${f.title}`);
  lines.push("\n## Explored");
  for (const e of args.explored_with_results || []) lines.push(`- ${e}`);
  lines.push("\n## Dead Ends");
  for (const d of args.dead_ends || []) lines.push(`- ${d}`);
  lines.push("\n## Unexplored");
  for (const u of args.unexplored || []) lines.push(`- ${u}`);
  lines.push("\n## Must Do Next");
  for (const m of args.must_do_next || []) lines.push(`- [${m.priority}] ${m.description}`);
  lines.push("\n## Promising Leads");
  for (const p of args.promising_leads || []) lines.push(`- ${p}`);

  const handoffPath = path.join(dir, `SESSION_HANDOFF.md`);
  writeFileAtomic(handoffPath, lines.join("\n") + "\n");
  return JSON.stringify({ written: handoffPath });
}

function logDeadEnds(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const wave = parseWaveId(args.wave);
  const agent = parseAgentId(args.agent);
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");

  const deadEnds = normalizeStringArray(args.dead_ends, "dead_ends");
  const wafBlocked = normalizeStringArray(args.waf_blocked_endpoints, "waf_blocked_endpoints");

  if (deadEnds.length === 0 && wafBlocked.length === 0) {
    return JSON.stringify({ appended: 0, message: "Nothing to log" });
  }

  return withSessionLock(domain, () => {
    validateAssignedWaveAgentSurface(domain, wave, agent, surfaceId);

    const logPath = liveDeadEndsJsonlPath(domain, wave, agent);
    const record = {
      ts: new Date().toISOString(),
      surface_id: surfaceId,
      dead_ends: deadEnds,
      waf_blocked_endpoints: wafBlocked,
    };
    appendJsonlLine(logPath, record);

    return JSON.stringify({
      appended: deadEnds.length + wafBlocked.length,
      dead_ends: deadEnds.length,
      waf_blocked_endpoints: wafBlocked.length,
      log_path: logPath,
    });
  });
}

// Reserved for future paths that need to consult attack_surface.json directly.
// The smart_contract completion gate does NOT use this — it reads from the
// MCP-owned, tamper-resistant assignment file (captured at start_wave time
// in mcp/lib/waves.js startWave). Reading from attack_surface.json would
// allow a hunter with Bash access to mutate the file and disable enforcement.
function lookupSurfaceType(domain, surfaceId) {
  const attackSurface = readAttackSurfaceStrict(domain);
  const surface = (attackSurface.document.surfaces || []).find((entry) => entry && entry.id === surfaceId);
  if (!surface) return null;
  if (typeof surface.surface_type === "string" && surface.surface_type.trim() !== "") {
    return surface.surface_type.trim();
  }
  return null;
}

function writeWaveHandoff(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const wave = parseWaveId(args.wave);
  const agent = parseAgentId(args.agent);
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  const surfaceStatus = parseSurfaceStatus(args.surface_status);
  const summary = normalizeHandoffSummary(args, { requireStructuredSummary: true });
  const chainNotes = normalizeChainNotes(args.chain_notes);
  const blockedHarnessRuns = normalizeBlockedHarnessRuns(args.blocked_harness_runs);
  const blockedPrereqs = normalizeBlockedPrereqs(args.blocked_prereqs);

  if (typeof args.content !== "string") {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "content must be a string");
  }
  if (args.content.length > WAVE_HANDOFF_CONTENT_MAX_CHARS) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `content must be at most ${WAVE_HANDOFF_CONTENT_MAX_CHARS} characters`,
    );
  }

  return withSessionLock(domain, () => {
    const assignment = validateAssignedWaveAgentSurface(domain, wave, agent, surfaceId);
    // Session state may be missing in narrow test paths that only seed
    // assignments + attack surface. Default to legacy mode in that case;
    // production callers always have an initialized session here.
    let requireProvenance = false;
    try {
      const { state } = readSessionStateStrict(domain);
      requireProvenance = state.handoff_provenance_required === true;
    } catch {
      requireProvenance = false;
    }
    const provenance = validateHandoffToken(assignment, args.handoff_token, { requireProvenance });

    // Read surface_type from the immutable, MCP-owned assignment file (captured
    // at start_wave time). Reading from agent-writable attack_surface.json would
    // let a hunter disable the smart_contract gate via Bash mutation.
    const surfaceType = assignment.surface_type || null;
    const findingsForRun = readFindingsFromJsonl(domain).filter((finding) => (
      finding.wave === wave &&
      finding.agent === agent &&
      finding.surface_id === surfaceId
    ));
    const findingIdSet = new Set(findingsForRun.map((finding) => finding.id));
    const bypassAttempts = normalizeBypassAttempts(args.bypass_attempts, { findingIds: findingIdSet });
    assertBlockedHarnessConsistency(surfaceStatus, blockedHarnessRuns);
    assertBlockedPrereqConsistency(surfaceStatus, blockedPrereqs);
    assertSmartContractCompletionEvidence({
      surfaceType,
      surfaceStatus,
      bypassAttempts,
      findingCount: findingsForRun.length,
    });
    const surfaceLeadResult = recordSurfaceLeadsForWaveHandoff(domain, Array.isArray(args.surface_leads) ? args.surface_leads : [], {
      source: "hunter_handoff",
      source_wave: wave,
      source_agent: agent,
      source_surface_id: surfaceId,
    });

    const handoff = {
      target_domain: domain,
      wave,
      agent,
      surface_id: surfaceId,
      surface_type: surfaceType,
      surface_status: surfaceStatus,
      provenance,
      summary,
      chain_notes: chainNotes,
      blocked_harness_runs: blockedHarnessRuns,
      blocked_prereqs: blockedPrereqs,
      bypass_attempts: bypassAttempts,
      dead_ends: normalizeStringArray(args.dead_ends, "dead_ends"),
      waf_blocked_endpoints: normalizeStringArray(args.waf_blocked_endpoints, "waf_blocked_endpoints"),
      lead_surface_ids: normalizeStringArray(args.lead_surface_ids, "lead_surface_ids"),
    };
    if (surfaceLeadResult.lead_ids.length > 0) {
      handoff.surface_lead_ids = surfaceLeadResult.lead_ids;
    }
    const persistedHandoff = provenance === "verified"
      ? signHandoffProvenance(handoff, ensureHandoffSigningKey(domain), { assignment })
      : handoff;

    const dir = sessionDir(domain);
    const markdownPath = path.join(dir, `handoff-${wave}-${agent}.md`);
    const jsonPath = path.join(dir, `handoff-${wave}-${agent}.json`);

    writeFileAtomic(markdownPath, args.content);
    writeFileAtomic(jsonPath, JSON.stringify(persistedHandoff, null, 2) + "\n");

    return JSON.stringify({
      written_md: markdownPath,
      written_json: jsonPath,
      provenance,
      provenance_model: persistedHandoff.provenance_model || null,
      surface_lead_ids: surfaceLeadResult.lead_ids,
    });
  });
}

module.exports = {
  applyWaveMerge,
  buildWaveHandoffsDocument,
  logDeadEnds,
  mergeWaveHandoffs,
  readWaveHandoffs,
  startNextWave,
  startWave,
  waveHandoffStatus,
  waveStatus,
  writeHandoff,
  writeWaveHandoff,
  WAVE_HANDOFF_CONTENT_MAX_CHARS,
};
