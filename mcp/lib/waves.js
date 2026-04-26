"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const {
  assertBoolean,
  assertNonEmptyString,
  compareAgentLabels,
  normalizeStringArray,
  parseAgentId,
  parseSurfaceStatus,
  parseWaveId,
  parseWaveNumber,
  pushUnique,
} = require("./validation.js");
const {
  sessionDir,
  waveAssignmentsPath,
} = require("./paths.js");
const {
  appendJsonlLine,
  readJsonFile,
  withSessionLock,
  writeFileAtomic,
} = require("./storage.js");
const {
  compactSessionState,
  readSessionStateStrict,
  writeSessionStateDocument,
} = require("./session-state.js");
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
  readFindingsFromJsonl,
  summarizeFindings,
} = require("./findings.js");
const { readScopeExclusions } = require("./scope.js");
const { rankAttackSurfaces } = require("./ranking.js");
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
} = require("./pipeline-analytics.js");

function listWaveHandoffFiles(dir, wave) {
  const handoffPrefix = `handoff-${wave}-`;
  // Readiness intentionally indexes only structured handoff JSON. Markdown handoffs are for humans/debugging.
  return fs.existsSync(dir)
    ? fs.readdirSync(dir)
        .filter((name) => name.startsWith(handoffPrefix) && name.endsWith(".json"))
        .sort()
    : [];
}

function buildWaveHandoffFileIndex(dir, wave, assignmentByAgent) {
  const handoffFiles = listWaveHandoffFiles(dir, wave);
  const handoffPathByAgent = new Map();
  const unexpectedAgentSet = new Set();

  for (const fileName of handoffFiles) {
    const rawAgent = fileName.slice(`handoff-${wave}-`.length, -".json".length);
    if (!assignmentByAgent.has(rawAgent)) {
      unexpectedAgentSet.add(rawAgent);
      continue;
    }
    handoffPathByAgent.set(rawAgent, path.join(dir, fileName));
  }

  return {
    handoffFiles,
    handoffPathByAgent,
    unexpectedAgents: Array.from(unexpectedAgentSet).sort(compareAgentLabels),
  };
}

function loadWaveArtifacts(domain, waveNumber) {
  const assignmentsInfo = loadWaveAssignments(domain, waveNumber);
  const handoffInfo = buildWaveHandoffFileIndex(
    assignmentsInfo.dir,
    assignmentsInfo.wave,
    assignmentsInfo.assignmentByAgent,
  );

  return {
    ...assignmentsInfo,
    ...handoffInfo,
  };
}

function buildWaveReadiness(artifacts) {
  const receivedAgents = [];
  const missingAgents = [];

  for (const assignment of artifacts.assignments) {
    if (artifacts.handoffPathByAgent.has(assignment.agent)) {
      receivedAgents.push(assignment.agent);
    } else {
      missingAgents.push(assignment.agent);
    }
  }

  return {
    assignments_total: artifacts.assignments.length,
    handoffs_total: artifacts.handoffFiles.length,
    received_agents: receivedAgents,
    missing_agents: missingAgents,
    unexpected_agents: artifacts.unexpectedAgents,
    is_complete: missingAgents.length === 0,
  };
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value), "utf8").digest("hex");
}

function generateHandoffToken() {
  return crypto.randomBytes(24).toString("base64url");
}

function assignmentRequiresToken(assignment) {
  return !!(assignment && assignment.handoff_token_sha256);
}

function validateHandoffToken(assignment, token) {
  if (!assignmentRequiresToken(assignment)) {
    return "legacy_unverified";
  }
  if (typeof token !== "string" || !token.trim()) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff_token is required for this wave assignment");
  }
  if (sha256Hex(token.trim()) !== assignment.handoff_token_sha256) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff_token does not match this wave assignment");
  }
  return "verified";
}

function validateHandoffProvenance(payload, assignment) {
  if (!assignmentRequiresToken(assignment)) {
    return "legacy_unverified";
  }
  if (payload.provenance !== "verified") {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff provenance is not verified for this tokenized assignment");
  }
  normalizeHandoffSummary(payload, { requireStructuredSummary: true });
  return "verified";
}

function normalizeHandoffSummary(payload, { requireStructuredSummary = false } = {}) {
  if (payload.summary == null && !requireStructuredSummary) {
    return null;
  }
  const summary = assertNonEmptyString(payload.summary, "summary");
  if (summary.length > 2000) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "summary must be at most 2000 characters");
  }
  return summary;
}

function normalizeChainNotes(value) {
  const notes = normalizeStringArray(value, "chain_notes");
  if (notes.length > 20) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "chain_notes must contain at most 20 entries");
  }
  for (const note of notes) {
    if (note.length > 300) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "chain_notes entries must be at most 300 characters");
    }
  }
  return notes;
}

function validateWaveHandoffPayload(payload, { targetDomain, wave, agent, surfaceId }) {
  if (payload == null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff payload must be an object");
  }

  if (payload.target_domain != null && assertNonEmptyString(payload.target_domain, "target_domain") !== targetDomain) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff target_domain does not match merge target");
  }

  const payloadWave = parseWaveId(payload.wave);
  const payloadAgent = parseAgentId(payload.agent);
  const payloadSurfaceId = assertNonEmptyString(payload.surface_id, "surface_id");
  const surfaceStatus = parseSurfaceStatus(payload.surface_status);

  if (payloadWave !== wave) throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff wave does not match assignment wave");
  if (payloadAgent !== agent) throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff agent does not match assignment");
  if (payloadSurfaceId !== surfaceId) throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff surface_id does not match assignment");

  return {
    summary: normalizeHandoffSummary(payload),
    chain_notes: normalizeChainNotes(payload.chain_notes),
    dead_ends: normalizeStringArray(payload.dead_ends, "dead_ends"),
    waf_blocked_endpoints: normalizeStringArray(payload.waf_blocked_endpoints, "waf_blocked_endpoints"),
    lead_surface_ids: normalizeStringArray(payload.lead_surface_ids, "lead_surface_ids"),
    surface_status: surfaceStatus,
  };
}

function mergeWaveHandoffsInternal(domain, waveNumber) {
  const artifacts = loadWaveArtifacts(domain, waveNumber);
  const readiness = buildWaveReadiness(artifacts);

  const receivedAgents = [];
  const invalidAgents = [];
  const completedSurfaceIds = [];
  const partialSurfaceIds = [];
  const missingSurfaceIds = [];
  const deadEnds = [];
  const wafBlockedEndpoints = [];
  const leadSurfaceIds = [];
  const provenance = {
    verified_agents: [],
    legacy_unverified_agents: [],
  };

  const deadEndSet = new Set();
  const wafSet = new Set();
  const leadSet = new Set();

  for (const assignment of artifacts.assignments) {
    const filePath = artifacts.handoffPathByAgent.get(assignment.agent);
    if (!filePath) {
      missingSurfaceIds.push(assignment.surface_id);
      continue;
    }

    try {
      const payload = validateWaveHandoffPayload(readJsonFile(filePath), {
        targetDomain: domain,
        wave: artifacts.wave,
        agent: assignment.agent,
        surfaceId: assignment.surface_id,
      });
      const provenanceStatus = validateHandoffProvenance(readJsonFile(filePath), assignment);

      receivedAgents.push(assignment.agent);
      if (provenanceStatus === "verified") {
        provenance.verified_agents.push(assignment.agent);
      } else {
        provenance.legacy_unverified_agents.push(assignment.agent);
      }
      if (payload.surface_status === "complete") {
        completedSurfaceIds.push(assignment.surface_id);
      } else {
        partialSurfaceIds.push(assignment.surface_id);
      }
      pushUnique(deadEnds, deadEndSet, payload.dead_ends);
      pushUnique(wafBlockedEndpoints, wafSet, payload.waf_blocked_endpoints);
      pushUnique(leadSurfaceIds, leadSet, payload.lead_surface_ids);
    } catch {
      invalidAgents.push(assignment.agent);
    }
  }

  for (const assignment of artifacts.assignments) {
    const logPath = path.join(artifacts.dir, `live-dead-ends-${artifacts.wave}-${assignment.agent}.jsonl`);
    if (!fs.existsSync(logPath)) continue;
    let raw;
    try {
      raw = fs.readFileSync(logPath, "utf8");
    } catch {
      continue;
    }
    const lines = raw.trim().split("\n");
    for (const line of lines) {
      if (!line) continue;
      try {
        const record = JSON.parse(line);
        if (record.surface_id !== assignment.surface_id) continue;
        pushUnique(deadEnds, deadEndSet, normalizeStringArray(record.dead_ends, "live_dead_ends"));
        pushUnique(wafBlockedEndpoints, wafSet, normalizeStringArray(record.waf_blocked_endpoints, "live_waf_blocked"));
      } catch {
        // Skip malformed line, keep processing remaining records
      }
    }
  }

  return {
    artifacts,
    readiness,
    merge: {
      received_agents: receivedAgents,
      invalid_agents: invalidAgents,
      unexpected_agents: readiness.unexpected_agents,
      completed_surface_ids: completedSurfaceIds,
      partial_surface_ids: partialSurfaceIds,
      missing_surface_ids: missingSurfaceIds,
      dead_ends: deadEnds,
      waf_blocked_endpoints: wafBlockedEndpoints,
      lead_surface_ids: leadSurfaceIds,
      provenance,
    },
  };
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

function waveStatus(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  let rankedAttackSurface = null;
  try { rankedAttackSurface = rankAttackSurfaces(domain, { write: false }); } catch {}
  const findings = readFindingsFromJsonl(domain);
  const summary = summarizeFindings(findings);

  // Compute surface coverage for deterministic wave decisions
  let coverage = null;
  try {
    const { state } = readSessionStateStrict(domain);
    const attackSurface = readAttackSurfaceStrict(domain);
    const surfaces = rankedAttackSurface?.surfaces || attackSurface.document.surfaces;
    const exploredSet = new Set(state.explored);
    const nonLowSurfaces = surfaces.filter(
      (s) => s.priority && s.priority.toUpperCase() !== "LOW",
    );
    const totalNonLow = nonLowSurfaces.length;
    const exploredNonLow = nonLowSurfaces.filter((s) => exploredSet.has(s.id)).length;
    coverage = {
      total_surfaces: surfaces.length,
      non_low_total: totalNonLow,
      non_low_explored: exploredNonLow,
      coverage_pct: totalNonLow > 0 ? Math.round((exploredNonLow / totalNonLow) * 100) : 100,
      unexplored_high: surfaces.filter(
        (s) => ["CRITICAL", "HIGH"].includes((s.priority || "").toUpperCase()) && !exploredSet.has(s.id),
      ).length,
    };
  } catch {}

  let auditSummary = null;
  let trafficSummary = null;
  let circuitBreakerSummary = null;
  try {
    const auditRecords = readHttpAuditRecordsFromJsonl(domain);
    auditSummary = summarizeHttpAuditRecords(auditRecords, { limit: 0 });
    circuitBreakerSummary = buildCircuitBreakerSummary(auditRecords);
  } catch {}
  try {
    trafficSummary = summarizeTrafficRecords(readTrafficRecordsFromJsonl(domain), { limit: 0 });
  } catch {}

  return JSON.stringify({
    ...summary,
    coverage,
    http_audit: auditSummary,
    traffic: trafficSummary,
    circuit_breaker: circuitBreakerSummary,
    findings_summary: findings.map((finding) => ({
      id: finding.id,
      severity: finding.severity,
      title: finding.title,
      endpoint: finding.endpoint,
      wave_agent: finding.wave || finding.agent ? `${finding.wave || "?"}/${finding.agent || "?"}` : null,
    })),
  });
}

function startWave(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  const assignments = normalizeWaveAssignmentsInput(args.assignments);

  return withSessionLock(domain, () => {
    const { raw, state } = readSessionStateStrict(domain);
    if (state.phase !== "HUNT" && state.phase !== "EXPLORE") {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Wave start requires phase HUNT or EXPLORE, found ${state.phase}`);
    }
    if (state.pending_wave != null) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Wave start requires pending_wave null, found ${state.pending_wave}`);
    }
    if (waveNumber !== state.hunt_wave + 1) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `wave_number must equal hunt_wave + 1 (${state.hunt_wave + 1})`);
    }

    const assignmentsPath = waveAssignmentsPath(domain, waveNumber);
    if (fs.existsSync(assignmentsPath)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Assignment file already exists: ${assignmentsPath}`);
    }

    const attackSurface = readAttackSurfaceStrict(domain);
    for (const assignment of assignments) {
      if (!attackSurface.surface_id_set.has(assignment.surface_id)) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `Unknown surface_id in assignments: ${assignment.surface_id}`);
      }
    }

    const persistedAssignments = assignments.map((assignment) => {
      const token = generateHandoffToken();
      return {
        ...assignment,
        handoff_token_sha256: sha256Hex(token),
        handoff_token: token,
      };
    });
    const assignmentsForDisk = persistedAssignments.map(({ handoff_token, ...assignment }) => assignment);

    writeFileAtomic(assignmentsPath, `${JSON.stringify({
      wave_number: waveNumber,
      assignments: assignmentsForDisk,
    }, null, 2)}\n`);

    const nextState = {
      ...state,
      pending_wave: waveNumber,
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
      source: "bounty_start_wave",
      counts: {
        assignments: assignments.length,
      },
    });

    return JSON.stringify({
      version: 1,
      started: true,
      wave_number: waveNumber,
      assignments: persistedAssignments.map((assignment) => ({
        agent: assignment.agent,
        surface_id: assignment.surface_id,
        handoff_token: assignment.handoff_token,
      })),
      assignments_path: assignmentsPath,
      state: compactSessionState(nextState),
    });
  });
}

function applyWaveMerge(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  const forceMerge = assertBoolean(args.force_merge, "force_merge");

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

    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, waveNumber));
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

    const attackSurface = readAttackSurfaceStrict(domain);
    const { artifacts, merge } = mergeWaveHandoffsInternal(domain, waveNumber);
    const coverageRecords = readCoverageRecordsFromJsonl(domain);
    const requeueSurfaceIds = computeRequeueSurfaceIds(artifacts, merge, coverageRecords);
    const requeueSurfaceIdSet = new Set(requeueSurfaceIds);
    const findings = summarizeFindings(readFindingsFromJsonl(domain));
    const scopeExclusions = [...state.scope_exclusions];
    pushUnique(scopeExclusions, new Set(scopeExclusions), readScopeExclusions(domain));

    const explored = [...state.explored];
    const deadEnds = [...state.dead_ends];
    const wafBlockedEndpoints = [...state.waf_blocked_endpoints];
    const leadSurfaceIds = [...state.lead_surface_ids];

    pushUnique(
      explored,
      new Set(explored),
      merge.completed_surface_ids.filter((surfaceId) => !requeueSurfaceIdSet.has(surfaceId)),
    );
    pushUnique(deadEnds, new Set(deadEnds), merge.dead_ends);
    pushUnique(wafBlockedEndpoints, new Set(wafBlockedEndpoints), merge.waf_blocked_endpoints);
    pushUnique(leadSurfaceIds, new Set(leadSurfaceIds), merge.lead_surface_ids);

    const filteredLeadSurfaceIds = leadSurfaceIds.filter(
      (surfaceId) => attackSurface.surface_id_set.has(surfaceId) && !explored.includes(surfaceId),
    );

    const nextState = {
      ...state,
      explored,
      dead_ends: deadEnds,
      waf_blocked_endpoints: wafBlockedEndpoints,
      lead_surface_ids: filteredLeadSurfaceIds,
      scope_exclusions: scopeExclusions,
      pending_wave: null,
      hunt_wave: waveNumber,
      total_findings: findings.total,
    };

    writeSessionStateDocument(domain, raw, nextState);
    safeAppendPipelineEventDirect(domain, "wave_merged", {
      phase: state.phase,
      wave_number: waveNumber,
      status: "merged",
      source: "bounty_apply_wave_merge",
      counts: {
        assignments: readiness.assignments_total,
        handoffs: readiness.handoffs_total,
        received_handoffs: merge.received_agents.length,
        invalid_handoffs: merge.invalid_agents.length,
        unexpected_handoffs: merge.unexpected_agents.length,
        missing_surfaces: merge.missing_surface_ids.length,
        requeue_surfaces: requeueSurfaceIds.length,
        findings: findings.total,
      },
    });
    return JSON.stringify({
      version: 1,
      status: "merged",
      wave_number: waveNumber,
      force_merge: forceMerge,
      readiness,
      merge: {
        received_agents: merge.received_agents,
        invalid_agents: merge.invalid_agents,
        unexpected_agents: merge.unexpected_agents,
        completed_surface_ids: merge.completed_surface_ids,
        partial_surface_ids: merge.partial_surface_ids,
        missing_surface_ids: merge.missing_surface_ids,
        requeue_surface_ids: requeueSurfaceIds,
        new_dead_ends_count: merge.dead_ends.length,
        new_waf_blocked_count: merge.waf_blocked_endpoints.length,
        lead_surface_ids: merge.lead_surface_ids,
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

  validateAssignedWaveAgentSurface(domain, wave, agent, surfaceId);

  const deadEnds = normalizeStringArray(args.dead_ends, "dead_ends");
  const wafBlocked = normalizeStringArray(args.waf_blocked_endpoints, "waf_blocked_endpoints");

  if (deadEnds.length === 0 && wafBlocked.length === 0) {
    return JSON.stringify({ appended: 0, message: "Nothing to log" });
  }

  const dir = sessionDir(domain);
  const logPath = path.join(dir, `live-dead-ends-${wave}-${agent}.jsonl`);
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
}

function writeWaveHandoff(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const wave = parseWaveId(args.wave);
  const agent = parseAgentId(args.agent);
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  const surfaceStatus = parseSurfaceStatus(args.surface_status);
  const summary = normalizeHandoffSummary(args, { requireStructuredSummary: true });
  const chainNotes = normalizeChainNotes(args.chain_notes);

  if (typeof args.content !== "string") {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "content must be a string");
  }

  const assignment = validateAssignedWaveAgentSurface(domain, wave, agent, surfaceId);
  const provenance = validateHandoffToken(assignment, args.handoff_token);

  const handoff = {
    target_domain: domain,
    wave,
    agent,
    surface_id: surfaceId,
    surface_status: surfaceStatus,
    provenance,
    summary,
    chain_notes: chainNotes,
    dead_ends: normalizeStringArray(args.dead_ends, "dead_ends"),
    waf_blocked_endpoints: normalizeStringArray(args.waf_blocked_endpoints, "waf_blocked_endpoints"),
    lead_surface_ids: normalizeStringArray(args.lead_surface_ids, "lead_surface_ids"),
  };

  const dir = sessionDir(domain);
  const markdownPath = path.join(dir, `handoff-${wave}-${agent}.md`);
  const jsonPath = path.join(dir, `handoff-${wave}-${agent}.json`);

  writeFileAtomic(markdownPath, args.content);
  writeFileAtomic(jsonPath, JSON.stringify(handoff, null, 2) + "\n");

  return JSON.stringify({
    written_md: markdownPath,
    written_json: jsonPath,
    provenance,
  });
}

function waveHandoffStatus(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  return JSON.stringify(buildWaveReadiness(loadWaveArtifacts(domain, waveNumber)));
}

function mergeWaveHandoffs(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  const { readiness, merge } = mergeWaveHandoffsInternal(domain, waveNumber);

  return JSON.stringify({
    assignments_total: readiness.assignments_total,
    handoffs_total: readiness.handoffs_total,
    received_agents: merge.received_agents,
    invalid_agents: merge.invalid_agents,
    unexpected_agents: merge.unexpected_agents,
    completed_surface_ids: merge.completed_surface_ids,
    partial_surface_ids: merge.partial_surface_ids,
    missing_surface_ids: merge.missing_surface_ids,
    dead_ends: merge.dead_ends,
    waf_blocked_endpoints: merge.waf_blocked_endpoints,
    lead_surface_ids: merge.lead_surface_ids,
    provenance: merge.provenance,
  });
}

function listWaveAssignmentNumbers(domain) {
  const dir = sessionDir(domain);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .map((fileName) => {
      const match = fileName.match(/^wave-([1-9][0-9]*)-assignments\.json$/);
      return match ? Number(match[1]) : null;
    })
    .filter((waveNumber) => Number.isInteger(waveNumber))
    .sort((a, b) => a - b);
}

function buildWaveHandoffsDocument(domain, waveNumbers) {
  const handoffs = [];
  const missingHandoffs = [];
  const invalidHandoffs = [];
  const unexpectedHandoffs = [];

  for (const waveNumber of waveNumbers) {
    const artifacts = loadWaveArtifacts(domain, waveNumber);
    for (const agent of artifacts.unexpectedAgents) {
      unexpectedHandoffs.push({ wave: artifacts.wave, agent });
    }

    for (const assignment of artifacts.assignments) {
      const filePath = artifacts.handoffPathByAgent.get(assignment.agent);
      if (!filePath) {
        missingHandoffs.push({
          wave: artifacts.wave,
          agent: assignment.agent,
          surface_id: assignment.surface_id,
        });
        continue;
      }

      try {
        const payload = validateWaveHandoffPayload(readJsonFile(filePath), {
          targetDomain: domain,
          wave: artifacts.wave,
          agent: assignment.agent,
          surfaceId: assignment.surface_id,
        });
        const provenance = validateHandoffProvenance(readJsonFile(filePath), assignment);
        handoffs.push({
          wave: artifacts.wave,
          agent: assignment.agent,
          surface_id: assignment.surface_id,
          surface_status: payload.surface_status,
          provenance,
          summary: payload.summary,
          chain_notes: payload.chain_notes,
          dead_ends: payload.dead_ends,
          waf_blocked_endpoints: payload.waf_blocked_endpoints,
          lead_surface_ids: payload.lead_surface_ids,
        });
      } catch (error) {
        invalidHandoffs.push({
          wave: artifacts.wave,
          agent: assignment.agent,
          surface_id: assignment.surface_id,
          error: error.message || String(error),
        });
      }
    }
  }

  return {
    version: 1,
    target_domain: domain,
    wave_numbers: waveNumbers,
    handoffs,
    missing_handoffs: missingHandoffs,
    invalid_handoffs: invalidHandoffs,
    unexpected_handoffs: unexpectedHandoffs,
  };
}

function readWaveHandoffs(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumbers = args.wave_number == null
    ? listWaveAssignmentNumbers(domain)
    : [parseWaveNumber(args.wave_number)];

  return JSON.stringify(buildWaveHandoffsDocument(domain, waveNumbers));
}

module.exports = {
  applyWaveMerge,
  buildWaveHandoffsDocument,
  logDeadEnds,
  mergeWaveHandoffs,
  readWaveHandoffs,
  startWave,
  waveHandoffStatus,
  waveStatus,
  writeHandoff,
  writeWaveHandoff,
};
