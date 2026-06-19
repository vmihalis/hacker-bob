"use strict";

const fs = require("fs");
const path = require("path");
const {
  assertNonEmptyString,
  normalizeStringArray,
  parseAgentId,
  parseSurfaceStatus,
  parseWaveId,
} = require("../validation.js");
const {
  liveDeadEndsJsonlPath,
  sessionDir,
  waveAssignmentsPath,
} = require("../paths.js");
const {
  appendJsonlLine,
  withSessionLock,
  writeFileAtomic,
} = require("../storage.js");
const { appendFrontierEvent } = require("../frontier-events.js");
const { scheduleMaterialization } = require("../frontier-materialize-debounce.js");
const {
  validateAssignedWaveAgentSurface,
} = require("../assignments.js");
const {
  routeSurfacesInternal,
} = require("../surface-router.js");
const {
  recordSurfaceLeadsForWaveHandoff,
} = require("../surface-leads.js");
const { readAttackSurfaceStrict } = require("../attack-surface.js");
const { currentSurfaces } = require("../frontier-projections.js");
const {
  findingPayloadsFromClaims,
} = require("../tools/record-candidate-claim.js");
const {
  ERROR_CODES,
  ToolError,
} = require("../envelope.js");
const {
  ensureHandoffSigningKey,
} = require("../handoff-signing-key.js");
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
} = require("../wave-handoff-contracts.js");

// Build the immutable wave assignment artifact. Returns { assignmentsPath,
// persistedAssignments, assignmentsDocument, attackSurface }. The caller
// (wave-scheduler) writes the file inside the session lock and owns the
// state-write rollback.
function prepareWaveAssignments({
  domain,
  waveNumber,
  assignments,
  attackSurfaceInfo,
  schedulerDecisionId,
  assignmentBatchId,
}) {
  const assignmentsPath = waveAssignmentsPath(domain, waveNumber);
  if (fs.existsSync(assignmentsPath)) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Assignment file already exists: ${assignmentsPath}`);
  }
  // Surface authority after Cycle D.3: surface-index.json (materialized
  // from frontier events) is the canonical surface set. currentSurfaces
  // returns a union view (materialized + legacy attack_surface.json) so
  // promotion-emitted surface.observed events and operator-seeded
  // baseline surfaces both reach the wave-start validator.
  let attackSurface = attackSurfaceInfo;
  if (!attackSurface) {
    const projection = currentSurfaces(domain);
    if (projection.source === "missing") {
      throw new Error(`Missing attack surface JSON: ${projection.path}`);
    }
    const surfaceIdSet = new Set();
    for (const surface of projection.surfaces || []) {
      if (surface && typeof surface.id === "string" && surface.id) {
        surfaceIdSet.add(surface.id);
      }
    }
    attackSurface = {
      path: projection.path,
      document: { surfaces: projection.surfaces || [] },
      surface_ids: Array.from(surfaceIdSet),
      surface_id_set: surfaceIdSet,
    };
  }
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
  // Capturing surface_type AT WAVE START into the immutable assignment file
  // makes the smart_contract completion gate tamper-resistant.
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
      evaluator_agent: route.evaluator_agent,
      brief_profile: route.brief_profile,
      context_budget: route.context_budget,
      task_lens: assignment.task_lens,
      budget: assignment.budget,
      handoff_token_required: true,
      handoff_token_sha256: sha256Hex(token),
      handoff_token: token,
    };
  });
  const assignmentsForDisk = persistedAssignments.map(({ handoff_token, ...assignment }) => assignment);
  ensureHandoffSigningKey(domain);
  const assignmentsDocument = {
    version: 1,
    handoff_tokens_required: true,
    handoff_provenance_model: HANDOFF_PROVENANCE_MODEL,
    wave_number: waveNumber,
    assignments: assignmentsForDisk,
  };
  if (schedulerDecisionId) assignmentsDocument.scheduler_decision_id = schedulerDecisionId;
  if (assignmentBatchId) assignmentsDocument.assignment_batch_id = assignmentBatchId;
  return {
    assignmentsPath,
    persistedAssignments,
    assignmentsDocument,
    attackSurface,
  };
}

function writeWaveAssignmentsDocument(assignmentsPath, assignmentsDocument) {
  writeFileAtomic(assignmentsPath, `${JSON.stringify(assignmentsDocument, null, 2)}\n`);
}

function removeWaveAssignmentsDocument(assignmentsPath) {
  try {
    fs.rmSync(assignmentsPath, { force: true });
    return true;
  } catch {
    return false;
  }
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
    const provenance = validateHandoffToken(assignment, args.handoff_token);

    // Read surface_type from the immutable assignment file (captured at
    // start_wave); reading attack_surface.json would let an evaluator disable
    // the smart_contract gate via Bash mutation.
    const surfaceType = assignment.surface_type || null;
    const findingsForRun = findingPayloadsFromClaims(domain).filter((finding) => (
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
      source: "evaluator_handoff",
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
    const persistedHandoff = signHandoffProvenance(handoff, ensureHandoffSigningKey(domain), { assignment });

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

    // Dual-write per Pact P2: dead ends and WAF blocks are blocker signals.
    try {
      appendFrontierEvent({
        target_domain: domain,
        kind: "blocker.asserted",
        surface_id: surfaceId,
        payload: {
          wave,
          agent,
          dead_ends: deadEnds,
          waf_blocked_endpoints: wafBlocked,
          dead_end_count: deadEnds.length,
          waf_blocked_count: wafBlocked.length,
        },
        source: { artifact: "live-dead-ends.jsonl", tool: "bob_log_dead_ends" },
      });
      scheduleMaterialization(domain);
    } catch {
      // Frontier ledger is dual-write best-effort.
    }

    return JSON.stringify({
      appended: deadEnds.length + wafBlocked.length,
      dead_ends: deadEnds.length,
      waf_blocked_endpoints: wafBlocked.length,
      log_path: logPath,
    });
  });
}

module.exports = {
  WAVE_HANDOFF_CONTENT_MAX_CHARS,
  logDeadEnds,
  prepareWaveAssignments,
  removeWaveAssignmentsDocument,
  writeHandoff,
  writeWaveHandoff,
  writeWaveAssignmentsDocument,
};
