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
  isUnroutableRoute,
} = require("../surface-router.js");
// The id-bearing detector is INJECTED here (as in the route-surfaces handler) so
// the durable surface-routes.json written at wave start preserves
// auth_differential_required — routeSurfacesInternal rewrites the file, and
// without the detector it would clobber the flag route_surfaces set to false.
const { surfaceExposesIdBearingCollection } = require("../offensive-idor-producer.js");
const { listAuthProfiles } = require("../auth.js");
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
  normalizeSpawnedChildren,
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
  let authProfileCount = 0;
  try {
    const authProfiles = JSON.parse(listAuthProfiles({ target_domain: domain }));
    // Count DISTINCT AUTHENTICATED principals (non-null MCP-owned fingerprints), not raw
    // profile names — so the auth-differential obligation fires exactly when >=2 real
    // tenants exist to run the cross-tenant test (aligning the flag with the completion
    // gate's clearance predicate; a single authed account + anon never over-flags).
    authProfileCount = Array.isArray(authProfiles.profiles)
      ? new Set(authProfiles.profiles.map((p) => p && p.principal_fingerprint).filter(Boolean)).size
      : 0;
  } catch {
    authProfileCount = 0;
  }
  const routedSurfaces = routeSurfacesInternal(domain, {
    attackSurfaceInfo: attackSurface,
    authProfileCount,
    idBearingDetector: surfaceExposesIdBearingCollection,
  });
  const routeBySurfaceId = new Map(
    routedSurfaces.document.routes.map((route) => [route.surface_id, route]),
  );
  for (const assignment of assignments) {
    if (!routeBySurfaceId.has(assignment.surface_id)) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `Missing route for surface_id in assignments: ${assignment.surface_id}`);
    }
  }
  // Partition on the route's disposition. A surface WITH a route classified
  // unroutable (unknown/unresolved chain_family → capability_pack:null) must
  // not be minted into an executable assignment: that would persist an
  // SC+null-pack row that normalizeAssignmentRouteMetadata throws on later
  // (at brief-read/handoff), halting the wave. Instead it is recorded as a
  // parked coverage gap so routable siblings proceed and the surface stays
  // visible (surfaced by bob_wave_status), never silently dropped. A surface
  // with NO route still errors at the "Missing route" guard above.
  //
  // SINGLE DURABLE SOURCE: routeSurfacesInternal above WROTE surface-routes.json,
  // so this in-memory partition IS the writer of that durable file — not a second,
  // divergent derivation of "unroutable". The planner (planNextWave) and
  // bob_wave_status both READ that same file through the shared
  // deriveUnroutableSurfacesFromRoutes helper, so all three agree by construction.
  // This partition operates on the just-written route doc; do not add a re-read
  // here or change these partition semantics.
  const routableAssignments = [];
  const unroutableSurfaces = [];
  for (const assignment of assignments) {
    const route = routeBySurfaceId.get(assignment.surface_id);
    if (isUnroutableRoute(route)) {
      unroutableSurfaces.push({
        surface_id: assignment.surface_id,
        agent: assignment.agent,
        surface_type: surfaceTypeById.get(assignment.surface_id) || route.surface_type || null,
        unroutable_reason: route.reason,
      });
      continue;
    }
    routableAssignments.push(assignment);
  }
  const persistedAssignments = routableAssignments.map((assignment) => {
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
      // Carry the route-derived (MCP-owned) auth-differential obligation onto the
      // immutable assignment so the per-run AD1 gate can read it; sourced ONLY from
      // route, never the agent-supplied assignment (no forgeability re-entry).
      auth_differential_required: route.auth_differential_required === true,
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
    unroutable_surfaces: unroutableSurfaces,
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

// The single brain-pinned spawn role a nesting child is dispatched as. A
// reported child of any other type is rejected by the allowlist leg below.
const SPAWN_CHILD_SUBAGENT_TYPE = "evaluator-fanout";

// The live detective backstop on actuated fan-out. The brain owns the per-surface
// fan-out budget (buildChildFanoutPlanForSurface); a worker self-reports the children
// it spawned in its handoff. Here, at the MCP-owned handoff-write site, cross-check
// the reported children against the budget the brain handed this surface so the
// "a leaf worker must not fan out" rule is mechanical, not prose.
//
// The budget is RE-DERIVED from the same brain function the dispatch used, so it
// matches what the agent was handed. The discriminator is remaining_depth, which is
// host/policy-derived (effectiveSpawnDepth minus one) and therefore stable between
// dispatch and handoff write — unlike max_children/children[], which the cell-floor
// dedup can only SHRINK as coverage advances. So:
//   - No plan, or remaining_depth <= 0  => a leaf worker (the default-off path, every
//     normal evaluator, and the new flat fan-outs: recon angles, per-finding
//     verifiers). Budget depth 0 / max_children 0 — ANY reported child is rejected.
//   - remaining_depth > 0               => the surface was handed a real fan-out plan
//     (the opt-in nested evaluator-fanout). Children up to the plan's count, of the
//     pinned spawn type, pass. The count leg uses the live plan's max_children; a
//     legitimate parent's reported count never exceeds the dispatch-time width
//     because the live recompute only shrinks, so an honest parent stays within
//     budget. The allowlist leg pins the child type.
//
// Best-effort recompute: if the plan cannot be derived (missing surface, transient
// read error), fall back to a depth-0 leaf budget so an unbudgeted child is still
// caught and a budgeted parent is never falsely rejected by a recompute failure —
// instead its width leg is skipped while the leaf leg stays on.
function spawnFanoutBudgetForSurface(domain, surfaceId, wave) {
  let plan = null;
  try {
    const { buildChildFanoutPlanForSurface } = require("../assignment-brief.js");
    const { buildCoverageSummaryForSurface, readCoverageRecordsFromJsonl } = require("../coverage.js");
    const surfaces = readAttackSurfaceStrict(domain).document.surfaces || [];
    const surfaceObj = surfaces.find((s) => s && s.id === surfaceId);
    if (surfaceObj) {
      const coverageRecords = readCoverageRecordsFromJsonl(domain);
      plan = buildChildFanoutPlanForSurface({
        domain,
        surfaceObj,
        surfaceId,
        coverageSummary: buildCoverageSummaryForSurface(coverageRecords, surfaceId),
        wave,
      });
    }
  } catch {
    plan = null;
  }
  if (plan && Number.isInteger(plan.remaining_depth) && plan.remaining_depth > 0) {
    return {
      remaining_depth: plan.remaining_depth,
      max_children: Number.isInteger(plan.max_children) ? plan.max_children : 0,
      child_type_allowlist: [SPAWN_CHILD_SUBAGENT_TYPE],
    };
  }
  return { remaining_depth: 0, max_children: 0 };
}

function assertSpawnFanoutWithinBudget(domain, wave, agent, surfaceId, spawnedChildren) {
  if (!Array.isArray(spawnedChildren) || spawnedChildren.length === 0) return;
  const { validateSpawnFanout } = require("../nested-spawn.js");
  const budget = spawnFanoutBudgetForSurface(domain, surfaceId, wave);
  const result = validateSpawnFanout(spawnedChildren, budget);
  if (!result.ok) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `${wave}/${agent} on ${surfaceId} reported a fan-out outside its spawn budget: ${result.violations.join("; ")}`,
    );
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
  const spawnedChildren = normalizeSpawnedChildren(args.spawned_children);
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
    assertSpawnFanoutWithinBudget(domain, wave, agent, surfaceId, spawnedChildren);
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
      spawned_children: spawnedChildren,
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
