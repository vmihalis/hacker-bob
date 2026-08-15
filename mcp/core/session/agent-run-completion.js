"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const {
  assertNonEmptyString,
  parseAgentId,
  parseWaveId,
} = require("../io/validation.js");
const {
  buildWaveHandoffsDocument,
} = require("../waves/wave-handoff-store.js");
const {
  loadWaveAssignments,
} = require("./assignments.js");
const {
  attackSurfacePath,
  sessionDir,
} = require("../io/paths.js");
const {
  readJsonFile,
} = require("../io/storage.js");
const {
  readResults: readAuthDifferentialResults,
} = require("../auth-differential-runner.js");
const {
  readFindingDifferentialVerifiedSummary,
} = require("../differential/index.js");
const {
  edgesFromAttackSurface,
} = require("../frontier/surface-graph-builder.js");
const { FANOUT_ROLE_REGISTRY } = require("./nested-spawn.js");

const EVIDENCE_MODE = "evidence";
const FANOUT_CHILD_MODE = "fanout_child";

function cleanString(value) {
  if (typeof value !== "string") return "";
  return value.trim();
}

function markerMode(marker) {
  return cleanString(marker && marker.mode);
}

function isEvidenceMarker(marker) {
  return markerMode(marker) === EVIDENCE_MODE;
}

// Validate the post-report evidence marker shape — distinct from wave-mode
// markers because evidence runs have no wave/agent context. The orchestrator
// permits these only after REPORT (or during EXPLORE) when an operator asks
// the evaluator to amplify a single finding's evidence.
function evidenceMarkerValidationError(marker) {
  if (!cleanString(marker && marker.target_domain)) {
    return {
      block_code: "malformed_marker",
      reason: "Post-report evidence marker is missing required field: target_domain",
    };
  }
  if (cleanString(marker.wave) || cleanString(marker.agent)) {
    return {
      block_code: "malformed_marker",
      reason: "Post-report evidence marker must not include wave or agent; use the normal wave marker for EXPLORE evaluators.",
    };
  }
  return null;
}

// Read state.phase from disk (not via MCP) because the hook process may not
// have the MCP server in scope at SubagentStop time. Phase must be REPORT or
// EXPLORE for evidence runs to be allowed; outside that window we block to
// prevent accidental evidence collection during EVALUATE/CHAIN/VERIFY/GRADE.
function evaluateEvidenceCompletion(marker) {
  const targetDomain = cleanString(marker && marker.target_domain);
  if (!targetDomain) {
    return {
      ok: false,
      block_code: "evidence_state_unreadable",
      reason: "Post-report evidence marker missing target_domain.",
    };
  }
  const home = os.homedir();
  if (!home) {
    return {
      ok: false,
      block_code: "evidence_state_unreadable",
      reason: "Post-report evidence marker could not resolve $HOME for session state read.",
    };
  }
  const statePath = path.join(sessionDir(targetDomain), "state.json");
  let state;
  try {
    state = readJsonFile(statePath, { label: "state.json" });
  } catch (error) {
    return {
      ok: false,
      block_code: "evidence_state_unreadable",
      reason: `Post-report evidence marker could not read session state: ${error.message || String(error)}`,
    };
  }
  // Post-report evidence runs are allowed only when the session has reached
  // REPORT (or re-entered OPEN_FRONTIER from REPORT — the legacy EXPLORE
  // window). The lifecycle vocabulary is lossy here: OPEN_FRONTIER covers both
  // active EVALUATE (block) and post-report EXPLORE (allow), so the legacy
  // phase remains the discriminator for that one ambiguous lifecycle state.
  //
  // Step 4: session-nucleus.json is the single source of truth for lifecycle
  // state; state.json is a projection of it. Source lifecycle_state from the
  // nucleus so a partially-written / drifted state.json can never gate this
  // hook against the authoritative lifecycle (the REPORT vs CLAIM_FREEZE drift
  // class). The nucleus read is best-effort: the hook process may not have the
  // MCP server in scope at SubagentStop time (and the session may predate the
  // nucleus), so on any read failure fall back to state.json's own copy.
  const allowedLifecycleStates = new Set(["REPORT", "OPEN_FRONTIER"]);
  const allowedLegacyPhases = new Set(["REPORT", "EXPLORE"]);
  let lifecycleState = state && state.lifecycle_state;
  const legacyPhase = state && state.phase;
  try {
    const { readSessionNucleus } = require("../governance/index.js");
    const nucleus = readSessionNucleus(targetDomain);
    if (nucleus && typeof nucleus.lifecycle_state === "string") {
      lifecycleState = nucleus.lifecycle_state;
    }
  } catch (_error) {
    // Nucleus unavailable (hook out of MCP scope, or legacy session without a
    // nucleus). Keep the state.json-derived lifecycle_state above.
  }
  // REPORT is unambiguous at the lifecycle level and is sourced from the
  // nucleus. OPEN_FRONTIER is ambiguous (EVALUATE vs EXPLORE), so it is only an
  // evidence window when the legacy phase confirms the EXPLORE re-entry. When
  // no lifecycle_state is available at all (legacy disk), fall back entirely to
  // the legacy phase.
  const lifecycleAllowed = lifecycleState === "REPORT"
    || (lifecycleState === "OPEN_FRONTIER" && legacyPhase && allowedLegacyPhases.has(legacyPhase));
  const legacyAllowed = !lifecycleState && legacyPhase && allowedLegacyPhases.has(legacyPhase);
  if (!state || (!lifecycleAllowed && !legacyAllowed)) {
    return {
      ok: false,
      block_code: "evidence_phase_mismatch",
      reason: `Post-report evidence marker is allowed only when lifecycle_state is REPORT or OPEN_FRONTIER (legacy phase REPORT or EXPLORE); current lifecycle_state is ${lifecycleState || "unknown"} / phase ${legacyPhase || "unknown"}.`,
    };
  }
  return {
    ok: true,
    handoff: {
      present: false,
      valid: true,
      provenance: "post_report_evidence",
      surface_status: "evidence",
      summary_present: cleanString(marker.summary) !== "",
      chain_notes_count: 0,
    },
  };
}

function evidenceTelemetryInput({
  marker,
  status,
  block_code = null,
  handoff = null,
  transcript_path = null,
  now = new Date(),
}) {
  return {
    ok: status === "allowed",
    runType: EVIDENCE_MODE,
    status,
    block_code,
    target_domain: cleanString(marker && marker.target_domain) || null,
    wave: null,
    agent: null,
    surface_id: cleanString(marker && marker.surface_id) || null,
    transcript_path,
    handoff,
    telemetry_source: "evaluator-evidence-stop",
    now,
  };
}
const {
  buildCoverageSummaryForSurface,
  latestCoverageRecordsByKey,
  readCoverageRecordsFromJsonl,
} = require("../frontier/coverage.js");
const {
  findingPayloadsFromClaims,
} = require("../claims/candidate-claim-recorder.js");
const {
  evaluateTechniqueAttemptRequirement,
} = require("../dispatch/technique-attempt-gate.js");
const {
  ERROR_CODES,
  ToolError,
} = require("../io/envelope.js");
const {
  safeRecordToolInvocationTelemetry,
} = require("../telemetry/tool-telemetry.js");
const {
  safeRecordEvaluatorStoppedPipelineEvent,
} = require("../telemetry/pipeline-events.js");
const {
  safeGovernanceContextForDomain,
} = require("../governance/index.js");

function handoffTelemetry(handoff, { present = true, valid = true } = {}) {
  return {
    present,
    valid,
    provenance: handoff && handoff.provenance ? handoff.provenance : null,
    surface_status: handoff && handoff.surface_status ? handoff.surface_status : null,
    summary_present: typeof (handoff && handoff.summary) === "string" && handoff.summary.trim() !== "",
    chain_notes_count: Array.isArray(handoff && handoff.chain_notes) ? handoff.chain_notes.length : 0,
  };
}

function summarizeCoverageForRun(marker) {
  const summary = { total: 0, by_status: {} };
  if (!marker) return summary;

  try {
    const records = readCoverageRecordsFromJsonl(marker.target_domain);
    for (const record of records) {
      if (
        record.wave !== marker.wave ||
        record.agent !== marker.agent ||
        record.surface_id !== marker.surface_id
      ) {
        continue;
      }
      summary.total += 1;
      summary.by_status[record.status] = (summary.by_status[record.status] || 0) + 1;
    }
  } catch {}
  return summary;
}

function summarizeFindingsForRun(marker) {
  const summary = { count: 0 };
  if (!marker) return summary;

  try {
    const findings = findingPayloadsFromClaims(marker.target_domain);
    summary.count = findings.filter((finding) => (
      finding.wave === marker.wave &&
      finding.agent === marker.agent &&
      finding.surface_id === marker.surface_id
    )).length;
  } catch {}
  return summary;
}

// NS-7 — evaluate the distinct nested-child stop attestation without touching
// the wave AgentRun. Claude's supported topology is wave-root teammate -> one
// anonymous synchronous child level. Every child deliberately reuses the root's
// (wave, agent, surface) authority for MCP writes, so bob_finalize_agent_run or
// a wave handoff from the child would race the root. The child instead emits an
// MCP-cell-bound marker. Reconstruct the ROOT plan from coverage with this
// run's rows removed (the plan as it existed before its children wrote), require
// an exact emitted (cell_key, planning_key), then require terminal coverage from
// the current run for that cell. This is attestation only: no handoff, no
// finalize, and no AgentRun settlement/terminal mutation.
function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function spawnPromptHasLine(prompt, label, value) {
  if (typeof prompt !== "string" || !prompt) return false;
  const pattern = new RegExp(
    `(?:^|\\n)\\s*${escapeRegExp(label)}\\s*:\\s*${escapeRegExp(value)}\\s*(?:\\n|$)`,
    "i",
  );
  return pattern.test(prompt);
}

function spawnPromptHasExactSingleLine(prompt, label, value) {
  if (typeof prompt !== "string" || !prompt) return false;
  const pattern = new RegExp(
    `(?:^|\\n)\\s*${escapeRegExp(label)}\\s*:\\s*([^\\n]*)`,
    "gi",
  );
  const values = [];
  let match;
  while ((match = pattern.exec(prompt)) !== null) values.push(match[1].trim());
  return values.length === 1 && values[0] === String(value);
}

// NS-7 — read-only pre-spawn attestation for the host PreToolUse boundary.
// A proposed leaf must be both (a) in the immutable dispatch-time plan rebuilt
// without this root run's coverage and (b) still present in the LIVE plan with
// current coverage. The intersection prevents an originally budget-pruned cell
// from sliding into a later slot and prevents a completed cell from spawning
// again. Exact single header lines reject conflicting duplicate fields.
function evaluateNestedChildSpawn(rootContext, spawnPrompt) {
  const targetDomain = cleanString(rootContext && rootContext.target_domain);
  const wave = cleanString(rootContext && rootContext.wave);
  const agent = cleanString(rootContext && rootContext.agent);
  if (!targetDomain || !/^w[1-9][0-9]*$/.test(wave) || !/^a[1-9][0-9]*$/.test(agent)) {
    return {
      ok: false,
      block_code: "child_root_context_mismatch",
      reason: "Fanout root Domain/Wave/Agent context is missing or malformed.",
    };
  }
  if (typeof spawnPrompt !== "string" || !spawnPrompt.trim()) {
    return {
      ok: false,
      block_code: "child_spawn_context_mismatch",
      reason: "Fanout child spawn prompt is missing.",
    };
  }
  if (/(?:^|\n)\s*Handoff token\s*:/i.test(spawnPrompt)) {
    return {
      ok: false,
      block_code: "child_handoff_token_leak",
      reason: "Fanout child spawn prompt must not contain the root Handoff token.",
    };
  }

  try {
    const waveNumber = Number(wave.slice(1));
    const assignments = loadWaveAssignments(targetDomain, waveNumber);
    const assignment = assignments.assignmentByAgent.get(agent) || null;
    if (!assignment || assignment.evaluator_agent !== FANOUT_ROLE_REGISTRY.root.subagent_type) {
      return {
        ok: false,
        block_code: "child_assignment_mismatch",
        reason: `Fanout child does not resolve to an ${FANOUT_ROLE_REGISTRY.root.subagent_type} root assignment.`,
      };
    }
    const { readAttackSurfaceStrict } = require("../frontier/attack-surface.js");
    const surface = (readAttackSurfaceStrict(targetDomain).document.surfaces || [])
      .find((entry) => entry && entry.id === assignment.surface_id) || null;
    if (!surface) {
      return {
        ok: false,
        block_code: "child_plan_unavailable",
        reason: "Fanout root assignment surface is absent from the attack-surface projection.",
      };
    }

    const allRecords = readCoverageRecordsFromJsonl(targetDomain);
    const baselineRecords = allRecords.filter((record) => !(
      record.wave === wave
      && record.agent === agent
      && record.surface_id === assignment.surface_id
    ));
    const { buildChildFanoutPlanForSurface } = require("./assignment-brief.js");
    const planFor = (records) => buildChildFanoutPlanForSurface({
      domain: targetDomain,
      surfaceObj: surface,
      surfaceId: assignment.surface_id,
      coverageSummary: buildCoverageSummaryForSurface(records, assignment.surface_id),
      wave,
    });
    const baselinePlan = planFor(baselineRecords);
    const livePlan = planFor(allRecords);
    const exactPromptFor = (child) => child
      && child.subagent_type === FANOUT_ROLE_REGISTRY.child.subagent_type
      && child.remaining_depth === FANOUT_ROLE_REGISTRY.child.remaining_depth
      && spawnPromptHasExactSingleLine(spawnPrompt, "Nested child", "true")
      && spawnPromptHasExactSingleLine(spawnPrompt, "Domain", targetDomain)
      && spawnPromptHasExactSingleLine(spawnPrompt, "Wave", wave)
      && spawnPromptHasExactSingleLine(spawnPrompt, "Agent", agent)
      && spawnPromptHasExactSingleLine(spawnPrompt, "surface_id", child.surface_id)
      && spawnPromptHasExactSingleLine(spawnPrompt, "cell_key", child.cell_key)
      && spawnPromptHasExactSingleLine(spawnPrompt, "planning_key", child.planning_key)
      && spawnPromptHasExactSingleLine(spawnPrompt, "bug_class", child.bug_class)
      && spawnPromptHasExactSingleLine(spawnPrompt, "auth_profile", child.auth_profile || '""')
      && spawnPromptHasExactSingleLine(spawnPrompt, "remaining_depth", "0");
    const baselineChild = baselinePlan && Array.isArray(baselinePlan.children)
      ? baselinePlan.children.find(exactPromptFor)
      : null;
    const liveChild = livePlan && Array.isArray(livePlan.children)
      ? livePlan.children.find((child) => baselineChild
        && child.cell_key === baselineChild.cell_key
        && child.planning_key === baselineChild.planning_key
        && exactPromptFor(child))
      : null;
    if (!baselineChild || !liveChild) {
      return {
        ok: false,
        block_code: "child_cell_not_live_issued",
        reason: "Fanout child prompt does not exactly match a cell present in both the dispatch and live MCP-issued plans.",
      };
    }
    return {
      ok: true,
      block_code: null,
      reason: `Fanout child ${liveChild.planning_key} is dispatch-issued and still live.`,
      child: liveChild,
    };
  } catch (error) {
    return {
      ok: false,
      block_code: "child_plan_unavailable",
      reason: `Fanout child plan could not be attested: ${error.message || String(error)}`,
    };
  }
}

function evaluateNestedChildCompletion(marker, options = {}) {
  const requiredStringFields = [
    "target_domain",
    "wave",
    "agent",
    "surface_id",
    "cell_key",
    "planning_key",
    "bug_class",
    "auth_profile",
    "coverage_status",
  ];
  const missing = requiredStringFields.filter((field) => typeof marker?.[field] !== "string");
  if (missing.length > 0) {
    return {
      ok: false,
      status: "blocked",
      block_code: "malformed_child_marker",
      reason: `Nested child marker is missing string field(s): ${missing.join(", ")}`,
      marker,
    };
  }
  if (!cleanString(marker.target_domain) || !cleanString(marker.surface_id)
      || !cleanString(marker.cell_key) || !cleanString(marker.planning_key)
      || !cleanString(marker.bug_class)) {
    return {
      ok: false,
      status: "blocked",
      block_code: "malformed_child_marker",
      reason: "Nested child marker contains an empty required identity field.",
      marker,
    };
  }
  if (!/^w[1-9][0-9]*$/.test(marker.wave) || !/^a[1-9][0-9]*$/.test(marker.agent)) {
    return {
      ok: false,
      status: "blocked",
      block_code: "malformed_child_marker",
      reason: "Nested child marker wave/agent must look like positive wN/aN.",
      marker,
    };
  }
  if (!new Set(["tested", "blocked"]).has(marker.coverage_status)) {
    return {
      ok: false,
      status: "blocked",
      block_code: "nonterminal_child_coverage",
      reason: "Nested child marker coverage_status must be terminal (tested or blocked).",
      marker,
    };
  }

  // Bind the self-reported marker to THIS subagent's host-owned transcript,
  // not merely to a valid cell in the wave. SubagentStop supplies
  // agent_transcript_path; its first user event is the immutable spawn prompt
  // that the root constructed from the MCP-issued child. Requiring every exact
  // tuple field plus remaining_depth:0 prevents a root echo, sibling marker, or
  // stale cell marker from taking the no-settlement child path.
  const spawnPrompt = typeof options.spawn_prompt === "string" ? options.spawn_prompt : "";
  const spawnContextFields = [
    ["Nested child", "true"],
    ["Domain", marker.target_domain],
    ["Wave", marker.wave],
    ["Agent", marker.agent],
    ["surface_id", marker.surface_id],
    ["cell_key", marker.cell_key],
    ["planning_key", marker.planning_key],
    ["bug_class", marker.bug_class],
    ["auth_profile", marker.auth_profile || '""'],
    ["remaining_depth", "0"],
  ];
  const missingSpawnFields = spawnContextFields
    .filter(([label, value]) => !spawnPromptHasLine(spawnPrompt, label, value))
    .map(([label]) => label);
  if (missingSpawnFields.length > 0) {
    return {
      ok: false,
      status: "blocked",
      block_code: "child_spawn_context_mismatch",
      reason: `Nested child marker is not bound to its SubagentStop spawn context: ${missingSpawnFields.join(", ")}`,
      marker,
    };
  }

  let assignment;
  let surface;
  let baselineRecords;
  let currentRecords;
  let plan;
  try {
    const waveNumber = Number(marker.wave.slice(1));
    const assignments = loadWaveAssignments(marker.target_domain, waveNumber);
    assignment = assignments.assignmentByAgent.get(marker.agent) || null;
    if (!assignment || assignment.surface_id !== marker.surface_id
        || assignment.evaluator_agent !== FANOUT_ROLE_REGISTRY.root.subagent_type) {
      return {
        ok: false,
        status: "blocked",
        block_code: "child_assignment_mismatch",
        reason: `Nested child marker does not resolve to an ${FANOUT_ROLE_REGISTRY.root.subagent_type} wave assignment.`,
        marker,
      };
    }
    const { readAttackSurfaceStrict } = require("../frontier/attack-surface.js");
    const surfaces = readAttackSurfaceStrict(marker.target_domain).document.surfaces || [];
    surface = surfaces.find((entry) => entry && entry.id === marker.surface_id) || null;
    if (!surface) {
      return {
        ok: false,
        status: "blocked",
        block_code: "child_plan_unavailable",
        reason: "Nested child marker surface is absent from the attack-surface projection.",
        marker,
      };
    }
    const allRecords = readCoverageRecordsFromJsonl(marker.target_domain);
    baselineRecords = allRecords.filter((record) => !(
      record.wave === marker.wave
      && record.agent === marker.agent
      && record.surface_id === marker.surface_id
    ));
    currentRecords = allRecords.filter((record) => (
      record.wave === marker.wave
      && record.agent === marker.agent
      && record.surface_id === marker.surface_id
    ));
    const { buildChildFanoutPlanForSurface } = require("./assignment-brief.js");
    plan = buildChildFanoutPlanForSurface({
      domain: marker.target_domain,
      surfaceObj: surface,
      surfaceId: marker.surface_id,
      coverageSummary: buildCoverageSummaryForSurface(baselineRecords, marker.surface_id),
      wave: marker.wave,
    });
  } catch (error) {
    return {
      ok: false,
      status: "blocked",
      block_code: "child_plan_unavailable",
      reason: `Nested child plan could not be reconstructed: ${error.message || String(error)}`,
      marker,
    };
  }

  const child = plan && Array.isArray(plan.children)
    ? plan.children.find((entry) => entry
      && entry.cell_key === marker.cell_key
      && entry.planning_key === marker.planning_key)
    : null;
  if (!child) {
    return {
      ok: false,
      status: "blocked",
      block_code: "child_cell_not_issued",
      reason: "Nested child marker does not match a cell emitted by the reconstructed root plan.",
      marker,
    };
  }
  // NS-7 — bind completion to the registry-issued leaf role. A root-role
  // marker is never accepted as a child even when every cell field matches.
  if (child.subagent_type !== FANOUT_ROLE_REGISTRY.child.subagent_type
      || child.surface_id !== marker.surface_id
      || child.bug_class !== marker.bug_class
      || (child.auth_profile || "") !== marker.auth_profile
      || child.remaining_depth !== 0) {
    return {
      ok: false,
      status: "blocked",
      block_code: "child_cell_identity_mismatch",
      reason: "Nested child marker fields do not match the MCP-issued leaf cell.",
      marker,
    };
  }

  const latest = Array.from(latestCoverageRecordsByKey(currentRecords).values());
  const matching = latest.filter((record) => (
    record.bug_class === child.bug_class.toLowerCase()
    && (record.auth_profile || "") === (child.auth_profile || "")
  ));
  const hasBlocked = matching.some((record) => record.status === "blocked");
  const hasUnfinished = matching.some((record) => ["promising", "needs_auth", "requeue"].includes(record.status));
  const hasTested = matching.some((record) => record.status === "tested");
  const terminalStatus = hasBlocked ? "blocked" : (hasTested && !hasUnfinished ? "tested" : null);
  if (!terminalStatus) {
    return {
      ok: false,
      status: "blocked",
      block_code: "missing_child_terminal_coverage",
      reason: "Nested child has no terminal current-run coverage for its issued bug_class/auth_profile cell.",
      marker,
      child,
    };
  }
  if (marker.coverage_status !== terminalStatus) {
    return {
      ok: false,
      status: "blocked",
      block_code: "child_coverage_status_mismatch",
      reason: `Nested child marker claims ${marker.coverage_status}, but durable coverage resolves to ${terminalStatus}.`,
      marker,
      child,
    };
  }
  return {
    ok: true,
    status: "allowed",
    block_code: null,
    reason: `Nested child cell ${marker.planning_key} accepted with terminal ${terminalStatus} coverage.`,
    marker,
    child,
    coverage: {
      total: matching.length,
      by_status: matching.reduce((counts, record) => {
        counts[record.status] = (counts[record.status] || 0) + 1;
        return counts;
      }, {}),
    },
  };
}

function nestedChildTelemetryInput(evaluation, {
  transcript_path: transcriptPath = null,
  now = new Date(),
} = {}) {
  const marker = evaluation && evaluation.marker ? evaluation.marker : null;
  return {
    runType: FANOUT_CHILD_MODE,
    status: evaluation && evaluation.ok ? "allowed" : "blocked",
    block_code: evaluation && evaluation.block_code ? evaluation.block_code : null,
    target_domain: marker && marker.target_domain,
    wave: marker && marker.wave,
    agent: marker && marker.agent,
    surface_id: marker && marker.surface_id,
    transcript_path: transcriptPath,
    handoff: {
      present: false,
      valid: true,
      provenance: "root_owned",
      surface_status: "child_cell",
      summary_present: false,
      chain_notes_count: 0,
    },
    coverage: evaluation && evaluation.coverage ? evaluation.coverage : { total: 0, by_status: {} },
    findings: { count: 0 },
    telemetry_source: "fanout-child-stop",
    now,
  };
}

function evaluateOssCompletionCoverage(marker, assignment, handoff) {
  if (!assignment || !assignment.capability_pack || !assignment.capability_pack.startsWith("oss_")) {
    return null;
  }
  if (!handoff || handoff.surface_status !== "complete") return null;

  const coverage = summarizeCoverageForRun(marker);
  const findings = summarizeFindingsForRun(marker);
  if (coverage.total > 0 || findings.count > 0) return null;

  return {
    ok: false,
    status: "blocked",
    block_code: "missing_oss_coverage",
    reason: `Evaluator ${marker.wave}/${marker.agent} cannot mark OSS surface ${marker.surface_id} complete with zero coverage rows and zero findings; log concrete repo checks/build attempts or set surface_status to partial with blockers.`,
    marker,
    handoff: null,
  };
}

function assignmentWithAuthDifferentialFlag(assignmentsInfo, marker) {
  const assignment = assignmentsInfo.assignmentByAgent.get(marker.agent);
  if (!assignment || assignment.auth_differential_required === true) return assignment;
  try {
    const raw = readJsonFile(assignmentsInfo.assignmentsPath, { label: "wave assignments" });
    const rawAssignments = raw && Array.isArray(raw.assignments) ? raw.assignments : [];
    const rawAssignment = rawAssignments.find((entry) => (
      entry
      && entry.agent === marker.agent
      && entry.surface_id === marker.surface_id
      && entry.auth_differential_required === true
    ));
    if (rawAssignment) return { ...assignment, auth_differential_required: true };
  } catch {}
  return assignment;
}

function frozenIdBearingEndpoints(assignment) {
  // The MCP-owned, route-FROZEN id-bearing endpoint set (already in {id}-template form),
  // carried onto the immutable wave assignment from surface-routes.json. NEVER re-derived
  // from agent-writable attack_surface.json, so a real cross-tenant flip cannot be
  // relabelled onto a foreign surface by editing scratch after the sweep.
  const eps = assignment && Array.isArray(assignment.id_bearing_endpoints) ? assignment.id_bearing_endpoints : [];
  return new Set(eps.filter((e) => typeof e === "string" && e));
}

// Mirrors claims.js exploitTargetHostInScope (the grade-time gate's B3 host check): the cited
// URL's host must be the target domain or a subdomain of it. An unparseable URL is out of scope
// (false). Kept in lockstep with the gate so finalize and grade agree on which effective_url a
// flip row was actually fetched under — never re-implement one without the other.
function finalizeHostInScope(targetUrl, domain) {
  let host;
  try {
    host = new URL(targetUrl).hostname.toLowerCase();
  } catch {
    return false;
  }
  const scope = String(domain).toLowerCase();
  return host === scope || host.endsWith(`.${scope}`);
}

function rowHasTwoProfileSweep(row) {
  // Executed cross-tenant coverage requires a per-endpoint FLIP (MCP-computed): one VALIDATED
  // principal ACCESSED the object (2xx) while a DISTINCT VALIDATED principal was DENIED it
  // (4xx) — the negative control flipped. Same-account-twice (both 2xx, no denial) and
  // [real, junk] (junk never validated) both fail to flip; a genuinely-secure surface
  // (owner-in/attacker-out) does flip and correctly earns completion.
  return !!(row && row.cross_tenant_flip === true);
}

function hasAuthDifferentialSweepForSurface(marker, assignment) {
  const endpoints = frozenIdBearingEndpoints(assignment);
  if (endpoints.size === 0) return false;
  const results = readAuthDifferentialResults(marker.target_domain);
  const rows = results && Array.isArray(results.per_endpoint) ? results.per_endpoint : [];
  const { templatizeIdBearingEndpoint } = require("../frontier/id-bearing-endpoints.js");
  // Cycle B keyed layer: resolve the row verifier ONCE (a disk key read), then require every
  // credited flip row to carry a VERIFYING row_mac under the auth-differential context. rowMacVerifies
  // wraps assertRowMac to a boolean (STRICT — an unsigned/tampered/forged/cross-context row throws
  // -> false), checked BEFORE rowHasTwoProfileSweep so a Bash-forged flip never clears the id-bearing
  // surface at finalize. Fail closed: a pre-keypair session's null verifier rejects any present row_mac.
  const { assertRowMac, AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT } = require("../ledger-integrity/index.js");
  const { resolveRowVerifierSafely } = require("../ledger-integrity/index.js");
  const rowVerifier = resolveRowVerifierSafely(marker.target_domain);
  const rowMacVerifies = (row) => {
    try {
      assertRowMac(AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT, row, rowVerifier);
      return true;
    } catch {
      return false;
    }
  };
  // B3 base_url-relabel defense (mirrors the grade-time gate in claims.js): the runner stamps
  // effective_url = joinUrl(base_url, endpoint) — the URL actually fetched — into the row_mac
  // preimage, so a MAC-verified row's effective_url is the real tested URL. The signed `endpoint`
  // alone templatizes to a frozen crown path even when the arm was fetched under a relabeled
  // base_url: an OFF-SCOPE host, or a benign PATH PREFIX that hid an easy same-host target. When
  // effective_url is present, additionally require it to resolve to an in-scope host AND to
  // templatize to one of THIS surface's frozen id-bearing endpoints; a mismatch is not credited
  // (fail closed). An ABSENT field is a legacy/pre-urlbind row: skip only this extra check
  // (back-compat) — the MAC, flip, surface_id-bind, and endpoint-template checks stand.
  const effectiveUrlResolves = (row) => {
    if (typeof row.effective_url !== "string" || !row.effective_url) return true;
    if (!finalizeHostInScope(row.effective_url, marker.target_domain)) return false;
    const effectiveTemplate = templatizeIdBearingEndpoint(row.effective_url);
    return effectiveTemplate !== null && endpoints.has(effectiveTemplate);
  };
  return rows.some((row) => (
    row
    && typeof row.endpoint === "string"
    // Bind by surface_id: the sweep must be stamped for THIS surface AND hit one of its
    // id-bearing endpoints (matched in TEMPLATE form) — no bleed from another surface.
    && row.surface_id === marker.surface_id
    && endpoints.has(templatizeIdBearingEndpoint(row.endpoint))
    && rowMacVerifies(row)
    && effectiveUrlResolves(row)
    && rowHasTwoProfileSweep(row)
  ));
}

// Mirrors claims.js ID_BEARING_ACCESS_CONTROL_CWES (the grade-time gate's B1 access-control set).
// An id-bearing crown's obligation is a CROSS-TENANT object-authorization test, so its clearing
// EXECUTED finding must be an access-control class. A same-surface executed SSRF/XSS proves impact
// but NOT that object-level authorization was ever probed, so it does not discharge the crown
// obligation (the auth-differential FLIP still does). bug_class is not persisted on the finding
// record; the CANONICAL CWE is (catalog-canonical on read-back), so class is resolved from the CWE
// alone. Only catalog CWEs reach here — a novel/non-catalog CWE degrades to null on read-back — so
// an unrecognized class HOLDS the surface as an honest partial, the SAFE (fail-toward-HOLD)
// direction. Kept in lockstep with the gate so finalize cannot settle a crown grade would hold.
const ID_BEARING_ACCESS_CONTROL_CWES = new Set([
  "CWE-639", // Authorization Bypass Through User-Controlled Key (IDOR)
  "CWE-284", // Improper Access Control
  "CWE-285", // Improper Authorization
  "CWE-862", // Missing Authorization
  "CWE-863", // Incorrect Authorization
]);

// The subset of recorded finding ids whose CANONICAL CWE is an access-control class, resolved from
// the persisted claims. Fails CLOSED: an unreadable claims ledger yields an empty set, so no
// finding-differential clears an id-bearing surface (the safe HOLD direction) — the auth-diff sweep
// path remains the independent, authoritative clearing lever.
function accessControlFindingIdsForDomain(domain) {
  const ids = new Set();
  try {
    for (const finding of findingPayloadsFromClaims(domain)) {
      if (!finding || !finding.id) continue;
      if (typeof finding.cwe === "string" && ID_BEARING_ACCESS_CONTROL_CWES.has(finding.cwe)) {
        ids.add(finding.id);
      }
    }
  } catch { /* unreadable claims — no finding-differential clears (safe HOLD direction) */ }
  return ids;
}

function hasVerifiedFindingDifferentialForSurface(marker) {
  const summary = readFindingDifferentialVerifiedSummary(marker.target_domain);
  const verified = summary && summary.verified_by_finding;
  if (verified == null || typeof verified !== "object" || Array.isArray(verified)) return false;
  // B1 mirror (id-bearing independence): a verified finding-differential clears an id-bearing
  // crown ONLY when the finding is an access-control class — a same-surface executed SSRF/XSS
  // never discharges the cross-tenant object-authorization obligation. verified_by_finding is keyed
  // by finding_id (the same id space as findingPayloadsFromClaims), so the class is looked up by
  // that key. Consistent with the grade-time gate's hasAccessControlExecuted.
  const accessControlFindingIds = accessControlFindingIdsForDomain(marker.target_domain);
  return Object.entries(verified).some(([findingId, entry]) => (
    entry
    && entry.surface_id === marker.surface_id
    && accessControlFindingIds.has(findingId)
  ));
}

function authDifferentialCompletionBlock(marker, { needsSecondPrincipal = false } = {}) {
  const reason = needsSecondPrincipal
    ? `Evaluator ${marker.wave}/${marker.agent} cannot mark id-bearing surface ${marker.surface_id} complete: this run has <2 distinct authenticated principals, so a cross-tenant flip is not runnable. Provision a 2nd account and run bob_run_auth_differential, OR mark the surface partial (an honest "needs a 2nd principal to test cross-tenant IDOR" block) — do NOT mark it complete. A coverage row / bypass_attempt narrative does NOT clear an id-bearing surface.`
    : `Evaluator ${marker.wave}/${marker.agent} cannot mark id-bearing surface ${marker.surface_id} complete without an executed auth-differential sweep (≥1 endpoint across ≥2 profiles) or a signed IDOR/finding-differential confirm bound to the surface. If the cross-tenant test cannot be run, mark the surface partial with a blocked_prereqs/blocked_harness_runs entry naming the un-run test — do NOT mark it complete.`;
  return {
    ok: false,
    status: "blocked",
    block_code: "missing_auth_differential",
    reason,
    marker,
    handoff: null,
  };
}

// FINALIZE/GRADE PARITY (routes integrity). The grade-time gate (claims.js
// completionDepthGapForCompleteSurfaces) re-establishes the id-bearing predicate from the
// MCP-owned surface-routes.json at GRADE time, and fails CLOSED whenever that document cannot
// speak for a surface. Three such states, all of which leave the surface with NO route row in the
// readable document:
//   1. the strict read THROWS — absent file, torn/corrupt write, dangling symlink, version drift;
//   2. this surface's own route was QUARANTINED into malformed_routes[] (cross-version field drift
//      on a resumed session, a duplicate row) — the resilient reader drops it from document.routes;
//   3. the document is readable but carries NO row for the surface (the totality anomaly: every
//      complete surface was assigned, and wave-assignment-store rejects a routeless assignment).
// In every one of those states grade clears the surface ONLY on executed access-control evidence
// or a re-verified cross-stack composition — never on the auth-differential flip, because the
// FROZEN id-bearing endpoint set the flip must bind to lives in that same unreadable document.
//
// Finalize reads a DIFFERENT document — the frozen wave-N assignment's id_bearing /
// id_bearing_endpoints — so without this mirror a run settles HERE on a MAC-verified flip and is
// then permanently held at GRADE with no artifact the agent can still add. That is a DEADLOCK, not
// a false clear, and it is why this condition is mirrored rather than left to grade.
//
// Deliberately NOT stricter than grade: an unattributable quarantine ELSEWHERE in the document (a
// malformed row that lost its surface_id) raises grade's GLOBAL routesUnverifiable flag, but a
// surface whose OWN route is intact and id_bearing still takes grade's id-bearing branch and
// clears on the flip. So verifiability keys on THIS surface's route row only.
function surfaceRouteVerifiability(domain, surfaceId, assignmentEndpoints = []) {
  let routesRead;
  try {
    const { readSurfaceRoutesStrict } = require("../frontier/surface-router.js");
    routesRead = readSurfaceRoutesStrict(domain);
  } catch (error) {
    return { verifiable: false, code: "routes_unreadable", detail: error.message || String(error) };
  }
  const routes = routesRead && routesRead.document && Array.isArray(routesRead.document.routes)
    ? routesRead.document.routes
    : [];
  const route = routes.find((entry) => entry && entry.surface_id === surfaceId);
  if (route) {
    // A row existing is not enough. Grade credits the flip only through the ROUTE's frozen
    // id_bearing_endpoints (claims.js surfaceEndpointValues -> endpoints.has(rowTemplate)), and
    // surface-router.js rewrites that set from agent-writable attack_surface.json on every route
    // pass — the never-downgrade guard restores prior endpoints only when the fresh derivation is
    // id_bearing===false. So a readable, validator-clean row whose endpoint set drifted away from
    // the endpoints this wave was assigned cannot credit the sweep at grade; settling on it here
    // is exactly the settle-then-deadlock this function exists to prevent.
    //
    // Only checked while the route is still id_bearing: when it is not, grade does not require a
    // flip at all and clears on ordinary evidence, so blocking here would be STRICTER than grade
    // and would trade the deadlock for a false block. The goal is agreement, not severity.
    if (route.id_bearing === true) {
      const routeEndpoints = new Set(
        (Array.isArray(route.id_bearing_endpoints) ? route.id_bearing_endpoints : [])
          .filter((endpoint) => typeof endpoint === "string" && endpoint),
      );
      const dropped = (Array.isArray(assignmentEndpoints) ? assignmentEndpoints : [])
        .filter((endpoint) => typeof endpoint === "string" && endpoint && !routeEndpoints.has(endpoint));
      if (dropped.length > 0) {
        return {
          verifiable: false,
          code: "route_endpoints_drifted",
          detail: `surface-routes.json no longer lists the id-bearing endpoint(s) this wave was assigned (${dropped.join(", ")}), so a sweep against them cannot be credited at grade`,
        };
      }
    }
    return { verifiable: true, code: null, detail: null };
  }
  const quarantined = (Array.isArray(routesRead.malformed_routes) ? routesRead.malformed_routes : [])
    .find((bad) => bad && bad.surface_id === surfaceId);
  if (quarantined) {
    return {
      verifiable: false,
      code: "route_quarantined",
      detail: quarantined.reason || "route metadata was quarantined",
    };
  }
  return {
    verifiable: false,
    code: "route_absent",
    detail: `surface-routes.json carries no route row for ${surfaceId}`,
  };
}

// Mirrors the grade-time gate's cross-stack composition arm (claims.js
// compositionExecutedSurfaces). verified_cross_stack_path_surface_refs is re-derived at read time
// from rows whose bind leaves MAC-resolve and re-adjudicate, and the `offensive:` prefix originates
// from the MAC-verified offensive row's surface_id — never a hand-written field. Used ONLY as an
// escape from the routes-unverifiable block below (grade's fail-closed branch clears on it), never
// as a standalone clearing lever for an id-bearing surface. Fails CLOSED on an unreadable ledger.
function hasVerifiedCrossStackCompositionForSurface(domain, surfaceId) {
  try {
    const { readCompositionVerifiedSummary } = require("../differential/index.js");
    const refsByHash = readCompositionVerifiedSummary(domain).verified_cross_stack_path_surface_refs || {};
    for (const refs of Object.values(refsByHash)) {
      if (Array.isArray(refs) && refs.includes(`offensive:${surfaceId}`)) return true;
    }
  } catch { /* missing/unreadable composition-verified contributes nothing */ }
  return false;
}

function routesUnverifiableCompletionBlock(marker, verifiability) {
  return {
    ok: false,
    status: "blocked",
    block_code: "unverifiable_surface_route",
    reason: `Evaluator ${marker.wave}/${marker.agent} cannot mark id-bearing surface ${marker.surface_id} complete: its MCP-owned route in surface-routes.json cannot be re-read (${verifiability.code}: ${verifiability.detail}). A cross-tenant flip clears the grade-time completion gate only through the ROUTE-frozen id-bearing endpoints, so settling this surface now would deadlock the run at GRADE, which holds the same surface for the same reason. Re-run bob_route_surfaces to regenerate surface-routes.json and re-run bob_run_auth_differential, OR mark the surface partial with a blocked_prereqs entry naming the un-re-verifiable route — do NOT mark it complete.`,
    marker,
    handoff: null,
  };
}

function evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff) {
  if (!assignment) return null;
  // Fire on id_bearing (detector result), NOT only auth_differential_required, so a
  // single-account (<2-principal) id-bearing surface is caught HERE at finalize with the
  // correct 'mark partial' guidance — consistent with the grade gate (which also keys on
  // id_bearing). Otherwise finalize permits it and only grade rejects it, late and confusing.
  const authDiffRequired = assignment.auth_differential_required === true;
  const isIdBearing = assignment.id_bearing === true || authDiffRequired;
  if (!isIdBearing) return null;
  if (!handoff || handoff.surface_status !== "complete") return null;

  let ledgerReadFailed = false;
  let hasSweepEvidence = false;
  let hasFindingDifferential = false;

  try {
    hasSweepEvidence = hasAuthDifferentialSweepForSurface(marker, assignment);
  } catch {
    ledgerReadFailed = true;
  }
  try {
    hasFindingDifferential = hasVerifiedFindingDifferentialForSurface(marker);
  } catch {
    ledgerReadFailed = true;
  }

  // AD1: an id-bearing surface earns complete ONLY on executed ledger evidence (a
  // distinct-principal sweep or a signed finding-differential). A genuinely-blocked
  // surface must be recorded PARTIAL — the grade-time gate rejects a complete surface
  // backed only by a blocker, so accepting it here would deadlock the run at grade.
  if (!ledgerReadFailed && (hasSweepEvidence || hasFindingDifferential)) {
    // ROUTES-INTEGRITY PARITY (see surfaceRouteVerifiability): the SWEEP is a clearing basis at
    // grade only through the route-frozen endpoint set, so when this surface's route cannot be
    // re-read the flip does not clear there. Accept exactly what grade's fail-closed branch
    // accepts — an executed access-control finding-differential, or a re-verified cross-stack
    // composition — so finalize never blocks a run grade would clear, and never settles one grade
    // would hold. The MAC-verified-flip requirement, the effective_url/host binds, and the
    // honest-partial fallback below are untouched: this only refuses to SETTLE on a flip whose
    // route-frozen basis is unreadable.
    if (hasFindingDifferential) return null;
    const verifiability = surfaceRouteVerifiability(
      marker.target_domain,
      marker.surface_id,
      Array.isArray(assignment.id_bearing_endpoints) ? assignment.id_bearing_endpoints : [],
    );
    if (verifiability.verifiable) return null;
    if (hasVerifiedCrossStackCompositionForSurface(marker.target_domain, marker.surface_id)) return null;
    return routesUnverifiableCompletionBlock(marker, verifiability);
  }
  // With <2 distinct principals a cross-tenant flip is not runnable — guide to partial.
  return authDifferentialCompletionBlock(marker, { needsSecondPrincipal: isIdBearing && !authDiffRequired });
}

function normalizeFinalizeArgs(args) {
  const targetDomain = assertNonEmptyString(args.target_domain, "target_domain");
  const wave = parseWaveId(args.wave);
  const agent = parseAgentId(args.agent);
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  return {
    target_domain: targetDomain,
    wave,
    agent,
    surface_id: surfaceId,
  };
}

function evaluateAgentCompletion(args) {
  const marker = normalizeFinalizeArgs(args);
  const waveNumber = Number(marker.wave.slice(1));
  let waveAssignments;
  try {
    waveAssignments = loadWaveAssignments(marker.target_domain, waveNumber);
  } catch (error) {
    return {
      ok: false,
      status: "blocked",
      block_code: "unreadable_wave_assignments",
      reason: `Evaluator ${marker.wave}/${marker.agent} could not read wave assignments: ${error.message || String(error)}`,
      marker,
      handoff: handoffTelemetry(null, { present: false, valid: false }),
    };
  }

  let handoffs;
  try {
    handoffs = buildWaveHandoffsDocument(marker.target_domain, [waveNumber]);
  } catch (error) {
    return {
      ok: false,
      status: "blocked",
      block_code: "unreadable_wave_assignments",
      reason: `Evaluator ${marker.wave}/${marker.agent} could not evaluate wave assignments: ${error.message || String(error)}`,
      marker,
      handoff: handoffTelemetry(null, { present: false, valid: false }),
    };
  }

  const missing = (handoffs.missing_handoffs || []).find((item) => item.agent === marker.agent);
  if (missing) {
    return {
      ok: false,
      status: "blocked",
      block_code: "missing_handoff",
      reason: `Evaluator ${marker.wave}/${marker.agent} must call bob_write_wave_handoff before finalizing.`,
      marker,
      handoff: handoffTelemetry(null, { present: false, valid: false }),
    };
  }

  const invalid = (handoffs.invalid_handoffs || []).find((item) => item.agent === marker.agent);
  if (invalid) {
    return {
      ok: false,
      status: "blocked",
      block_code: "invalid_handoff",
      reason: `Evaluator ${marker.wave}/${marker.agent} wrote an invalid handoff: ${invalid.error || "validation failed"}`,
      marker,
      handoff: handoffTelemetry(null, { present: true, valid: false }),
    };
  }

  const handoff = (handoffs.handoffs || []).find((item) => item.agent === marker.agent);
  if (!handoff) {
    return {
      ok: false,
      status: "blocked",
      block_code: "missing_handoff",
      reason: `Evaluator ${marker.wave}/${marker.agent} handoff was not found in structured wave handoffs.`,
      marker,
      handoff: handoffTelemetry(null, { present: false, valid: false }),
    };
  }

  if (handoff.wave !== marker.wave || handoff.surface_id !== marker.surface_id) {
    return {
      ok: false,
      status: "blocked",
      block_code: "handoff_mismatch",
      reason: `Evaluator finalization does not match structured handoff for ${marker.wave}/${marker.agent}.`,
      marker,
      handoff: handoffTelemetry(handoff),
    };
  }

  const assignment = assignmentWithAuthDifferentialFlag(waveAssignments, marker);
  const techniqueAttemptBlock = evaluateTechniqueAttemptRequirement(marker, assignment);
  if (techniqueAttemptBlock) {
    return {
      ...techniqueAttemptBlock,
      handoff: handoffTelemetry(handoff),
    };
  }

  const ossCoverageBlock = evaluateOssCompletionCoverage(marker, assignment, handoff);
  if (ossCoverageBlock) {
    return {
      ...ossCoverageBlock,
      handoff: handoffTelemetry(handoff),
    };
  }

  const authDiffBlock = evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff);
  if (authDiffBlock) {
    return {
      ...authDiffBlock,
      handoff: handoffTelemetry(handoff),
    };
  }

  return {
    ok: true,
    status: "allowed",
    block_code: null,
    reason: "handoff valid",
    marker,
    handoff: handoffTelemetry(handoff),
  };
}

function telemetryInput(evaluation, {
  transcript_path: transcriptPath = null,
  telemetry_source: telemetrySource = "bob_finalize_agent_run",
  now = new Date(),
} = {}) {
  const marker = evaluation && evaluation.marker ? evaluation.marker : null;
  return {
    runType: "evaluator",
    status: evaluation.status,
    blockCode: evaluation.block_code,
    target_domain: marker && marker.target_domain,
    wave: marker && marker.wave,
    agent: marker && marker.agent,
    surface_id: marker && marker.surface_id,
    transcript_path: transcriptPath,
    handoff: evaluation.handoff,
    coverage: summarizeCoverageForRun(marker),
    findings: summarizeFindingsForRun(marker),
    telemetry_source: telemetrySource,
    now,
  };
}

function recordAgentCompletionTelemetry(evaluation, options = {}) {
  // Evidence-mode input is already a fully-formed telemetry record (the hook
  // builds it directly because evidence runs have no wave/agent and skip the
  // structured-handoff evaluation path). Detect that shape by the runType
  // field and pass it through to the recorders unchanged.
  if (evaluation && evaluation.runType === FANOUT_CHILD_MODE) {
    // A child completion is recorded as tool-invocation telemetry only. Do not
    // emit evaluator_stopped: that pipeline event denotes the wave root and
    // would make an accepted child look like premature root settlement.
    safeRecordToolInvocationTelemetry(evaluation);
    return evaluation;
  }
  if (evaluation && evaluation.runType === "evidence") {
    safeRecordToolInvocationTelemetry(evaluation);
    safeRecordEvaluatorStoppedPipelineEvent(
      evaluation,
      safeGovernanceContextForDomain(evaluation.target_domain),
    );
    return evaluation;
  }
  const input = telemetryInput(evaluation, options);
  safeRecordToolInvocationTelemetry(input);
  safeRecordEvaluatorStoppedPipelineEvent(
    input,
    safeGovernanceContextForDomain(input.target_domain),
  );
  return input;
}

function finalizeAgentCompletion(args, options = {}) {
  const evaluation = evaluateAgentCompletion(args);
  recordAgentCompletionTelemetry(evaluation, options);
  return evaluation;
}

function finalizeAgentRun(args) {
  const evaluation = finalizeAgentCompletion(args, {
    telemetry_source: "bob_finalize_agent_run",
  });
  if (!evaluation.ok) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, evaluation.reason, {
      block_code: evaluation.block_code,
      target_domain: evaluation.marker.target_domain,
      wave: evaluation.marker.wave,
      agent: evaluation.marker.agent,
      surface_id: evaluation.marker.surface_id,
      handoff: evaluation.handoff,
    });
  }

  return JSON.stringify({
    version: 1,
    status: evaluation.status,
    target_domain: evaluation.marker.target_domain,
    wave: evaluation.marker.wave,
    agent: evaluation.marker.agent,
    surface_id: evaluation.marker.surface_id,
    message: evaluation.reason,
    handoff: evaluation.handoff,
  });
}

module.exports = {
  EVIDENCE_MODE,
  FANOUT_CHILD_MODE,
  evaluateEvidenceCompletion,
  evaluateAgentCompletion,
  evaluateAuthDifferentialCompletionCoverage,
  evaluateTechniqueAttemptRequirement,
  evidenceMarkerValidationError,
  evidenceTelemetryInput,
  evaluateNestedChildCompletion,
  evaluateNestedChildSpawn,
  finalizeAgentCompletion,
  finalizeAgentRun,
  handoffTelemetry,
  isEvidenceMarker,
  markerMode,
  nestedChildTelemetryInput,
  recordAgentCompletionTelemetry,
  summarizeCoverageForRun,
  summarizeFindingsForRun,
  telemetryInput,
};
