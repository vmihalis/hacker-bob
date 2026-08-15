"use strict";

const fs = require("fs");
const path = require("path");
const {
  assertNonEmptyString,
  compareAgentLabels,
  normalizeStringArray,
  parseWaveNumber,
  pushUnique,
} = require("../io/validation.js");
const {
  liveDeadEndsJsonlPath,
  sessionDir,
} = require("../io/paths.js");
const {
  readFileUtf8,
  readJsonFile,
} = require("../io/storage.js");

const {
  loadWaveAssignments,
} = require("../session/assignments.js");
const {
  findingPayloadsFromClaims,
} = require("../../tools/record-candidate-claim.js");
const {
  readHandoffSigningKey,
} = require("../ledger-integrity/handoff-signing-key.js");
const {
  assignmentRequiresToken,
  attachHandoffOrigin,
  computeUnconsumedPivots,
  groupBlockedHarnessRuns,
  groupBlockedPrereqs,
  groupBypassAttempts,
  pivotEdgeKey,
  validateHandoffProvenance,
  validateWaveHandoffPayload,
} = require("./wave-handoff-contracts.js");
const {
  readTransitionProposals,
} = require("./task-graph-events.js");
const {
  readSurfaceLeadsDocument,
} = require("../frontier/surface-leads.js");
const {
  latestAgentRunForWaveAgent,
} = require("../session/agent-runs.js");
const {
  evaluateTechniqueAttemptRequirement,
} = require("../dispatch/technique-attempt-gate.js");

// Drive the merge gate from the AgentRun lifecycle rather than handoff-file
// presence. The lifecycle is recorded non-forgeably from real subagent activity:
// universal MCP-side start-recording marks `running` on the agent's first
// surface-scoped tool call (bob_read_assignment_brief), and the SubagentStart
// hook marks it even earlier at spawn on adapters that wire it. Each row maps to
// a gate verdict:
//
//   settled              -> handoff authoritative; accept on the row.
//   failed | abandoned   -> stop-hook terminal-non-settled; refuse (subject to
//                           the recoverable-block relaxation below, which
//                           re-validates a provenance-valid handoff on disk).
//                           This path carries the merge-time teeth of the
//                           stop-hook finalize controls (e.g. attempt_log_required
//                           on ordinary surface-* runs is NON-recoverable, so a
//                           valid handoff cannot merge over it) and is unchanged.
//   running              -> the agent provably started; the work product (the
//                           handoff) is the authority, so DEFER to full on-disk
//                           validation (validateWaveHandoffPayload +
//                           validateHandoffProvenance) instead of refusing on the
//                           bare status. A started run with a provenance-valid
//                           handoff is received; with an absent/invalid handoff
//                           it is missing (the genuine died-mid-flight case).
//   assigned | completed | null
//                        -> no lifecycle progress recorded (an agent that never
//                           read its brief, or a lost best-effort start write).
//                           This is the documented degraded path: validate the
//                           handoff on disk. A provenance-valid handoff is a
//                           permanent fail-safe — never regressed to missing —
//                           even when its `running` start-record was lost.
//
// A `gate` of "settled" closes the merge gate in favor of the AgentRun row.
// A `gate` of "closed_terminal_non_settled" closes it against the agent.
// A `gate` of "started" and a `gate` of "fallback" both defer to full on-disk
// handoff validation at the call site — the existence boolean is no longer the
// decider; the started lifecycle plus payload+provenance validation are.
function agentRunGateForAssignment(domain, wave, assignment) {
  let run = null;
  try {
    run = latestAgentRunForWaveAgent(domain, {
      wave,
      agent: assignment.agent,
      surfaceId: assignment.surface_id,
    });
  } catch {
    run = null;
  }
  const status = run ? run.status : null;
  // Surface the terminal row's block_code so the relaxation below can tell a
  // recoverable runaway-loop artifact (missing/invalid handoff, promoted-lead
  // technique-log gap) from a genuinely non-recoverable blocker
  // (e.g. missing_oss_coverage) that must keep the surface gated closed even
  // when a handoff file happens to be on disk.
  const blockCode = run && typeof run.block_code === "string" ? run.block_code : null;
  if (status === "settled") {
    return { status, gate: "settled", blockCode };
  }
  if (status === "failed" || status === "abandoned") {
    return { status, gate: "closed_terminal_non_settled", blockCode };
  }
  if (status === "running") {
    return { status, gate: "started", blockCode };
  }
  return { status, gate: "fallback", blockCode };
}

// Only a stop-hook-written terminal status (`failed`/`abandoned`) is eligible
// for the verified-handoff relaxation below. A `running` row is NOT terminal —
// it routes through the "started" gate, which already defers to full on-disk
// handoff validation, so it needs no relaxation here. The relaxation exists
// solely to undo the runaway loop's `failed`-row poisoning of a settleable run.
function gateStatusIsHookTerminal(status) {
  return status === "failed" || status === "abandoned";
}

// Step 2b: which terminal block_codes the verified-handoff relaxation may
// override. This MUST mirror agent-run-stop.js isRecoverableBlock so the merge
// gate and the stop hook agree on what "recoverable" means:
//   * missing_technique_attempt_log — recoverable ONLY for promoted-lead
//     surfaces (surface_id "lead-*"); for ordinary "surface-*" assignments the
//     registry's attempt_log_required control is terminal, so a valid handoff
//     must NOT let it merge (that would re-open the bypass the stop-hook scoping
//     closes).
//   * missing_handoff / invalid_handoff — the runaway loop poisoned a row whose
//     handoff is nonetheless provenance-valid on disk (the on-disk re-validation
//     is enforced separately at each call site).
// Any other block_code (missing_oss_coverage, handoff_mismatch, evidence_*,
// malformed_marker, unreadable_wave_assignments, …) is NON-recoverable and stays
// gated closed even with a handoff file on disk.
function isRecoverableBlockCode(blockCode, surfaceId) {
  if (!blockCode) return false;
  if (blockCode === "missing_technique_attempt_log") {
    return typeof surfaceId === "string" && surfaceId.startsWith("lead-");
  }
  if (blockCode === "missing_auth_differential") {
    return typeof surfaceId === "string" && surfaceId.startsWith("lead-");
  }
  return blockCode === "missing_handoff" || blockCode === "invalid_handoff";
}

// Branch-uniform technique-attempt requirement for the merge/readiness
// HANDOFF-ACCEPTANCE gates. The finalize/SubagentStop gate
// (agent-run-completion.js evaluateAgentCompletion) only runs when the agent
// reaches SubagentStop; a run whose handoff is accepted on a non-settled
// branch — started (running), fallback (assigned/completed/null), or a recovered
// terminal row whose handoff re-validates on disk — never reaches that gate, so a
// technique-log-less handoff would otherwise merge over the
// `attempt_log_required` control on whichever branch it took. Re-run the SAME
// shared evaluateTechniqueAttemptRequirement at the merge gate so the merge gate
// and the finalize gate never diverge: a surface whose route metadata sets
// context_budget.attempt_log_required (web/OSS) must carry a completion-status
// technique attempt before its handoff is honored. attempt_log_required=false
// (smart_contract) returns null inside the shared check, so SC handoffs are not
// gated here — the independent SC completion-substance depth gate inside
// validateWaveHandoffPayload still runs first. The predicate is branch-agnostic;
// the CALLER restricts it to the non-settled acceptance branches (a settled run
// already cleared the finalize technique gate) and invokes it only after payload
// + provenance validation succeed. The lead-* relaxation is composed via the
// SAME isRecoverableBlockCode predicate the closed-terminal path uses: a
// missing_technique_attempt_log on a "lead-*" surface is relaxed (merges); on an
// ordinary "surface-*" it is refused. invalid_technique_attempt_log (an
// unreadable log) is never relaxed and always fails closed. The check keys on the
// handoff surface_id + the on-disk technique-attempts.jsonl + attempt_log_required,
// all independent of the lifecycle ledger, so a lost AgentRun row does not
// over-gate beyond what attempt_log_required already dictates.
function handoffMissingRequiredTechniqueAttempt(domain, assignment, wave, handoff = null) {
  const block = evaluateTechniqueAttemptRequirement(
    {
      target_domain: domain,
      wave,
      agent: assignment.agent,
      surface_id: assignment.surface_id,
    },
    assignment,
  );
  if (block && !isRecoverableBlockCode(block.block_code, assignment.surface_id)) return true;
  if (!handoff) return false;

  const {
    evaluateAuthDifferentialCompletionCoverage,
  } = require("../session/agent-run-completion.js");
  const authDiffBlock = evaluateAuthDifferentialCompletionCoverage(
    {
      target_domain: domain,
      wave,
      agent: assignment.agent,
      surface_id: assignment.surface_id,
    },
    assignment,
    handoff,
  );
  // AD1
  if (!authDiffBlock) return false;
  return !isRecoverableBlockCode(authDiffBlock.block_code, assignment.surface_id);
}

// Step 2b: a `failed`/`abandoned` AgentRun row drives the gate to
// "closed_terminal_non_settled". But the stop-hook's runaway loop (RCA [3])
// could append a `failed` row for an agent that DID write a cryptographically
// valid handoff (e.g. a tooling gap on a promoted-lead surface that the agent
// could not log a technique attempt for). Before treating such an agent as
// missing, re-read the on-disk handoff and verify FULL HMAC provenance
// (validateWaveHandoffPayload + validateHandoffProvenance, timingSafeEqual).
// Only a handoff that passes both is honored — a forged/unsigned/absent
// handoff is never accepted, so a genuinely-dead agent stays gated closed.
function verifiedHandoffOnDiskForAssignment(domain, artifacts, assignment, {
  signingKey = null,
  signingKeyError = null,
} = {}) {
  const filePath = artifacts.handoffPathByAgent.get(assignment.agent);
  if (!filePath) return false;
  try {
    if (assignmentRequiresToken(assignment) && signingKeyError) {
      throw signingKeyError;
    }
    const handoffJson = readJsonFile(filePath);
    // Validate against the run's recorded findings (same set the merge uses), so
    // a finding-bearing handoff recovered on the runaway-loop path is not falsely
    // rejected by an empty finding set — the Y-D-style readiness deadlock again.
    const findingsForRun = findingPayloadsFromClaims(domain).filter(
      (finding) => finding.wave === artifacts.wave
        && finding.agent === assignment.agent
        && finding.surface_id === assignment.surface_id,
    );
    validateWaveHandoffPayload(handoffJson, {
      targetDomain: domain,
      wave: artifacts.wave,
      agent: assignment.agent,
      surfaceId: assignment.surface_id,
      effectiveSurfaceType: assignment.surface_type || null,
      findingsForRun,
    });
    validateHandoffProvenance(handoffJson, assignment, { signingKey });
    return true;
  } catch {
    return false;
  }
}

const WAVE_ARTIFACT_KEYS = Object.freeze([
  "dir",
  "wave",
  "assignmentsPath",
  "assignments",
  "assignmentByAgent",
  "handoffFiles",
  "handoffPathByAgent",
  "unexpectedAgents",
]);

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
  let assignmentsInfo = loadWaveAssignments(domain, waveNumber);
  assignmentsInfo = attachAuthDifferentialFlags(assignmentsInfo);
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

function attachAuthDifferentialFlags(assignmentsInfo) {
  let rawAssignments = [];
  try {
    const raw = readJsonFile(assignmentsInfo.assignmentsPath, { label: "wave assignments" });
    rawAssignments = raw && Array.isArray(raw.assignments) ? raw.assignments : [];
  } catch {
    return assignmentsInfo;
  }
  const required = new Set(rawAssignments
    .filter((entry) => entry && entry.auth_differential_required === true)
    .map((entry) => `${entry.agent}\u0000${entry.surface_id}`));
  if (required.size === 0) return assignmentsInfo;
  const assignments = assignmentsInfo.assignments.map((assignment) => (
    required.has(`${assignment.agent}\u0000${assignment.surface_id}`)
      ? { ...assignment, auth_differential_required: true }
      : assignment
  ));
  const assignmentByAgent = new Map(assignments.map((assignment) => [assignment.agent, assignment]));
  return {
    ...assignmentsInfo,
    assignments,
    assignmentByAgent,
  };
}

function readSigningKeyForArtifacts(domain, artifacts) {
  return artifacts.assignments.some((assignment) => assignmentRequiresToken(assignment))
    ? readHandoffSigningKey(domain)
    : null;
}

function buildWaveReadiness(artifacts, { domain = null } = {}) {
  const receivedAgents = [];
  const missingAgents = [];
  const invalidAgents = [];

  // When a `domain` is provided, also validate each present handoff's signature
  // and metadata so the readiness gate at apply_wave_merge can refuse to merge
  // when invalid handoffs would silently drop surfaces from completed/partial/
  // missing tracking (R1-HIGH-#2). Without validation, the file-presence-only
  // readiness lies to the caller about wave health.
  let signingKey = null;
  let signingKeyError = null;
  // Load the run's recorded findings so each handoff's bypass_attempts[].finding_id
  // is validated against the SAME finding set the merge uses (mergeWaveHandoffsInternal).
  // Without this, a handoff that legitimately cites a recorded finding is forced into
  // invalid_agents while the real merge accepts it, deadlocking apply_wave_merge.
  const findingsByRun = new Map();
  if (domain) {
    try {
      signingKey = readSigningKeyForArtifacts(domain, artifacts);
    } catch (error) {
      signingKeyError = error;
    }
    for (const finding of findingPayloadsFromClaims(domain)) {
      if (finding.wave !== artifacts.wave) continue;
      const runKey = `${finding.wave}\u0000${finding.agent}\u0000${finding.surface_id}`;
      if (!findingsByRun.has(runKey)) findingsByRun.set(runKey, []);
      findingsByRun.get(runKey).push(finding);
    }
  }

  for (const assignment of artifacts.assignments) {
    // Drive readiness from the AgentRun lifecycle; a "started" or "fallback"
    // gate defers to the on-disk handoff validation below. Without a `domain`
    // there is no ledger to consult, so the only signal is file-presence
    // (the principled degraded path).
    const handoffPresent = artifacts.handoffPathByAgent.has(assignment.agent);
    const gate = domain
      ? agentRunGateForAssignment(domain, artifacts.wave, assignment)
      : { status: null, gate: "fallback" };
    if (gate.gate === "closed_terminal_non_settled") {
      // A stop-hook `failed`/`abandoned` row from the runaway loop must NOT mask
      // a cryptographically verified handoff. Only fall through to "received"
      // when the row is hook-terminal AND the block_code is a recoverable one
      // (runaway-loop handoff poisoning, or a promoted-lead technique-log gap)
      // AND full HMAC provenance validates on disk. A non-recoverable blocker
      // (e.g. missing_oss_coverage) and a forged/absent handoff stay gated
      // closed. (A `running` row never reaches here — it routes through the
      // "started" gate above.)
      if (domain
        && gateStatusIsHookTerminal(gate.status)
        && isRecoverableBlockCode(gate.blockCode, assignment.surface_id)
        && verifiedHandoffOnDiskForAssignment(domain, artifacts, assignment, { signingKey, signingKeyError })) {
        // The recovered terminal row accepts its on-disk handoff; apply the same
        // branch-uniform technique-attempt requirement the started/fallback
        // branch below uses so a recovered web/OSS handoff with no attempt is
        // refused (lead-* relaxed, SC unaffected). Depth + provenance already
        // ran inside verifiedHandoffOnDiskForAssignment.
        let recoveredHandoff = null;
        try {
          recoveredHandoff = readJsonFile(artifacts.handoffPathByAgent.get(assignment.agent));
        } catch {}
        if (!recoveredHandoff
          || handoffMissingRequiredTechniqueAttempt(domain, assignment, artifacts.wave, recoveredHandoff)) {
          missingAgents.push(assignment.agent);
          continue;
        }
        receivedAgents.push(assignment.agent);
        continue;
      }
      missingAgents.push(assignment.agent);
      continue;
    }
    if ((gate.gate === "started" || gate.gate === "fallback") && !handoffPresent) {
      // A started run with no handoff on disk is the genuine died-mid-flight
      // case; a fallback run with no handoff never produced one. Both are
      // missing. A started/fallback run WITH a handoff falls through to the full
      // payload + provenance validation below.
      missingAgents.push(assignment.agent);
      continue;
    }
    if (gate.gate === "settled" && !handoffPresent) {
      missingAgents.push(assignment.agent);
      continue;
    }
    if (!domain) {
      receivedAgents.push(assignment.agent);
      continue;
    }
    try {
      if (assignmentRequiresToken(assignment) && signingKeyError) {
        throw signingKeyError;
      }
      const filePath = artifacts.handoffPathByAgent.get(assignment.agent);
      const handoffJson = readJsonFile(filePath);
      // Only validate provenance + payload shape here; the full business-logic
      // validation runs inside mergeWaveHandoffsInternal. Catching both here
      // ensures the gate also reflects business-rule failures so merge can't
      // silently drop surfaces with invalid handoffs.
      const runKey = `${artifacts.wave}\u0000${assignment.agent}\u0000${assignment.surface_id}`;
      const payload = validateWaveHandoffPayload(handoffJson, {
        targetDomain: domain,
        wave: artifacts.wave,
        agent: assignment.agent,
        surfaceId: assignment.surface_id,
        effectiveSurfaceType: assignment.surface_type || null,
        findingsForRun: findingsByRun.get(runKey) || [],
      });
      void payload;
      validateHandoffProvenance(handoffJson, assignment, { signingKey });
      // Branch-uniform technique-attempt requirement on the non-settled
      // acceptance branches (started ∪ fallback here; recovery is handled
      // inline above). A settled run already cleared the finalize technique
      // gate, so it is not re-checked.
      if (gate.gate !== "settled"
        && handoffMissingRequiredTechniqueAttempt(domain, assignment, artifacts.wave, payload)) {
        missingAgents.push(assignment.agent);
      } else {
        receivedAgents.push(assignment.agent);
      }
    } catch {
      invalidAgents.push(assignment.agent);
    }
  }

  return {
    assignments_total: artifacts.assignments.length,
    handoffs_total: artifacts.handoffFiles.length,
    received_agents: receivedAgents,
    missing_agents: missingAgents,
    invalid_agents: invalidAgents,
    unexpected_agents: artifacts.unexpectedAgents,
    is_complete: missingAgents.length === 0 && invalidAgents.length === 0,
  };
}

// Build the consumption context the advisory unconsumed-pivots surfacing
// checks merged discovered_pivots[] against. Both reads are best-effort and
// fail-open: a missing/corrupt frontier ledger or surface-leads doc yields
// empty sets, so the surfacing degrades to "treat every pivot as unconsumed"
// (still advisory — it gates nothing) rather than breaking the merge. Off the
// nesting path there are no pivots, so this context is never consulted.
function buildPivotConsumptionContext(domain) {
  const proposedEdges = new Set();
  try {
    for (const event of readTransitionProposals(domain)) {
      const payload = event && event.payload;
      if (!payload || typeof payload !== "object") continue;
      const fromSurface = typeof payload.from_surface === "string" ? payload.from_surface : "";
      const toSurface = typeof payload.to_surface === "string" ? payload.to_surface : "";
      if (fromSurface && toSurface) proposedEdges.add(pivotEdgeKey(fromSurface, toSurface));
    }
  } catch {
    // Fail-open: no transition edges known.
  }
  const leadReferenceStrings = new Set();
  try {
    const doc = readSurfaceLeadsDocument(domain);
    for (const lead of (doc && Array.isArray(doc.leads) ? doc.leads : [])) {
      if (!lead || typeof lead !== "object") continue;
      for (const field of ["title", "source_surface_id", "contract_address", "promoted_surface_id"]) {
        const value = lead[field];
        if (typeof value === "string" && value) leadReferenceStrings.add(value);
      }
    }
  } catch {
    // Fail-open: no lead references known.
  }
  return { proposedEdges, leadReferenceStrings };
}

function mergeWaveHandoffsInternal(domain, waveNumber) {
  const artifacts = loadWaveArtifacts(domain, waveNumber);
  const readiness = buildWaveReadiness(artifacts, { domain });

  const receivedAgents = [];
  const runContexts = [];
  const invalidAgents = [];
  const invalidHandoffs = [];
  const completedSurfaceIds = [];
  const partialSurfaceIds = [];
  const missingSurfaceIds = [];
  const deadEnds = [];
  const wafBlockedEndpoints = [];
  const leadSurfaceIds = [];
  const blockedHarnessRuns = [];
  const blockedPrereqs = [];
  const bypassAttempts = [];
  const discoveredPivots = [];
  const provenance = {
    verified_agents: [],
  };

  const deadEndSet = new Set();
  const wafSet = new Set();
  const leadSet = new Set();

  const allFindings = findingPayloadsFromClaims(domain);
  const findingsByRun = new Map();
  for (const finding of allFindings) {
    if (finding.wave === artifacts.wave) {
      const runKey = `${finding.wave}\u0000${finding.agent}\u0000${finding.surface_id}`;
      if (!findingsByRun.has(runKey)) findingsByRun.set(runKey, []);
      findingsByRun.get(runKey).push(finding);
    }
  }

  const signingKey = readSigningKeyForArtifacts(domain, artifacts);

  for (const assignment of artifacts.assignments) {
    const filePath = artifacts.handoffPathByAgent.get(assignment.agent);
    // Drive the merge gate from the AgentRun lifecycle. A "started" or
    // "fallback" gate defers to the on-disk handoff validation below; the
    // existence check only buckets a started/fallback run with no handoff as
    // missing.
    const gate = agentRunGateForAssignment(domain, artifacts.wave, assignment);
    if (gate.gate === "closed_terminal_non_settled"
      && !(gateStatusIsHookTerminal(gate.status)
        && isRecoverableBlockCode(gate.blockCode, assignment.surface_id)
        && verifiedHandoffOnDiskForAssignment(domain, artifacts, assignment, { signingKey }))) {
      // A stop-hook `failed`/`abandoned` row gates the surface closed UNLESS the
      // block_code is recoverable (runaway-loop handoff poisoning, or a
      // promoted-lead technique-log gap) AND a cryptographically verified handoff
      // is present on disk — only then is it the runaway loop poisoning a
      // settleable run, so re-validate and let it fall through to the normal
      // merge bucketing below. A non-recoverable blocker (e.g.
      // missing_oss_coverage) stays closed regardless. (A `running` row never
      // reaches here — it routes through the "started" gate.)
      // Best-effort pivot durability on the terminal-non-settled path too: an abandoned fanout
      // agent that wrote a handoff still has its cross-surface discovered_pivots on disk — surface
      // them to the orchestrator's requeue path rather than dropping them with the surface.
      if (filePath) {
        try {
          const rawHandoff = readJsonFile(filePath);
          if (rawHandoff && Array.isArray(rawHandoff.discovered_pivots) && rawHandoff.discovered_pivots.length > 0) {
            discoveredPivots.push(...attachHandoffOrigin(rawHandoff.discovered_pivots, {
              agent: assignment.agent,
              surfaceId: assignment.surface_id,
            }));
          }
        } catch { /* raw unreadable -> nothing to salvage */ }
      }
      missingSurfaceIds.push(assignment.surface_id);
      continue;
    }
    if ((gate.gate === "started" || gate.gate === "fallback") && !filePath) {
      missingSurfaceIds.push(assignment.surface_id);
      continue;
    }
    if (!filePath) {
      // AgentRun says settled but the handoff file is absent — dual-write
      // mismatch. Treat as missing so the merge gate refuses to advance
      // until both ledger and on-disk evidence agree.
      missingSurfaceIds.push(assignment.surface_id);
      continue;
    }

    try {
      const handoffJson = readJsonFile(filePath);
      const runKey = `${artifacts.wave}\u0000${assignment.agent}\u0000${assignment.surface_id}`;
      const findingsForRun = findingsByRun.get(runKey) || [];
      const effectiveSurfaceType = assignment.surface_type || null;
      const payload = validateWaveHandoffPayload(handoffJson, {
        targetDomain: domain,
        wave: artifacts.wave,
        agent: assignment.agent,
        surfaceId: assignment.surface_id,
        effectiveSurfaceType,
        findingsForRun,
      });
      validateHandoffProvenance(handoffJson, assignment, { signingKey });

      // A run accepted on a non-settled branch never reached the finalize gate;
      // refuse its technique-log-less handoff here (the same requirement, lead-*
      // relaxed, SC unaffected) so the residual cannot merge. One guard covers
      // started + fallback + the recovered terminal row (which falls through to
      // this try-block, gate "closed_terminal_non_settled" !== "settled"); a
      // settled run already cleared the finalize technique gate, so it is skipped.
      if (gate.gate !== "settled"
        && handoffMissingRequiredTechniqueAttempt(domain, assignment, artifacts.wave, payload)) {
        // Pivot durability: this handoff is VALID (payload validated) but gated on a missing
        // technique attempt — still surface its cross-surface discovered_pivots (advisory,
        // independent of the surface's completion gate) rather than dropping them with the surface.
        if (Array.isArray(payload.discovered_pivots) && payload.discovered_pivots.length > 0) {
          discoveredPivots.push(...attachHandoffOrigin(payload.discovered_pivots, {
            agent: assignment.agent,
            surfaceId: assignment.surface_id,
          }));
        }
        missingSurfaceIds.push(assignment.surface_id);
        continue;
      }

      receivedAgents.push(assignment.agent);
      provenance.verified_agents.push(assignment.agent);
      runContexts.push({
        // run_id/node_id: the validated payload may omit them; fall back to the
        // SAME deterministic run key the findings loop uses at the runKey above.
        run_id: payload.run_id
          || `${artifacts.wave}\u0000${assignment.agent}\u0000${assignment.surface_id}`,
        node_id: payload.node_id || assignment.surface_id,
        // RAW handoff JSON — carries ranked_leads[] for handoff_ledger_diff.
        // NOT the validated `payload` (its summary is a flattened string).
        handoff_summary: handoffJson,
      });
      if (payload.surface_status === "complete") {
        completedSurfaceIds.push(assignment.surface_id);
      } else {
        partialSurfaceIds.push(assignment.surface_id);
      }
      pushUnique(deadEnds, deadEndSet, payload.dead_ends);
      pushUnique(wafBlockedEndpoints, wafSet, payload.waf_blocked_endpoints);
      pushUnique(leadSurfaceIds, leadSet, payload.lead_surface_ids);
      blockedHarnessRuns.push(...attachHandoffOrigin(payload.blocked_harness_runs || [], {
        agent: assignment.agent,
        surfaceId: assignment.surface_id,
      }));
      blockedPrereqs.push(...attachHandoffOrigin(payload.blocked_prereqs || [], {
        agent: assignment.agent,
        surfaceId: assignment.surface_id,
      }));
      bypassAttempts.push(...attachHandoffOrigin(payload.bypass_attempts || [], {
        agent: assignment.agent,
        surfaceId: assignment.surface_id,
      }));
      discoveredPivots.push(...attachHandoffOrigin(payload.discovered_pivots || [], {
        agent: assignment.agent,
        surfaceId: assignment.surface_id,
      }));
    } catch (error) {
      invalidAgents.push(assignment.agent);
      invalidHandoffs.push({
        agent: assignment.agent,
        surface_id: assignment.surface_id,
        error: error.message || String(error),
      });
      // Pivot durability: even for an INVALID handoff, best-effort preserve discovered_pivots[]
      // so a transition-blind evaluator-fanout's cross-surface pivots are not lost on a handoff
      // validation failure (e.g. a secret-scanner trip on Set-Cookie/UUID evidence) — a flat
      // evaluator's inline bob_propose_transition persists independent of handoff outcome. Pivots
      // are ADVISORY/non-gating (orchestrator hints), so salvaging from an unvalidated handoff
      // adds a lead to investigate, never a security gate.
      try {
        const rawHandoff = readJsonFile(filePath);
        if (rawHandoff && Array.isArray(rawHandoff.discovered_pivots) && rawHandoff.discovered_pivots.length > 0) {
          discoveredPivots.push(...attachHandoffOrigin(rawHandoff.discovered_pivots, {
            agent: assignment.agent,
            surfaceId: assignment.surface_id,
          }));
        }
      } catch { /* raw unreadable -> nothing to salvage */ }
      // Surface the invalid handoff's surface_id via missing_surface_ids so it
      // reaches the orchestrator's requeue path. Without this, R1-HIGH-#2:
      // the surface is silently dropped from completed/partial/missing buckets
      // while the wave appears merged.
      if (!missingSurfaceIds.includes(assignment.surface_id)) {
        missingSurfaceIds.push(assignment.surface_id);
      }
    }
  }

  for (const assignment of artifacts.assignments) {
    const logPath = liveDeadEndsJsonlPath(domain, artifacts.wave, assignment.agent);
    if (!fs.existsSync(logPath)) continue;
    let raw;
    try {
      raw = readFileUtf8(logPath, { label: path.basename(logPath) });
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
        // Skip malformed line, keep processing remaining records.
      }
    }
  }

  // Advisory: flag discovered_pivots[] with no corresponding consumption
  // (no proposed transition edge AND no recorded surface lead for the
  // to_surface). Empty/no-op off the nesting path. Non-gating; reported only.
  const pivotConsumption = discoveredPivots.length > 0
    ? buildPivotConsumptionContext(domain)
    : { proposedEdges: new Set(), leadReferenceStrings: new Set() };
  const unconsumedPivots = computeUnconsumedPivots(discoveredPivots, pivotConsumption);

  return {
    artifacts,
    readiness,
    merge: {
      received_agents: receivedAgents,
      invalid_agents: invalidAgents,
      invalid_handoffs: invalidHandoffs,
      unexpected_agents: readiness.unexpected_agents,
      completed_surface_ids: completedSurfaceIds,
      partial_surface_ids: partialSurfaceIds,
      missing_surface_ids: missingSurfaceIds,
      dead_ends: deadEnds,
      waf_blocked_endpoints: wafBlockedEndpoints,
      lead_surface_ids: leadSurfaceIds,
      blocked_harness_runs: blockedHarnessRuns,
      blocked_harness_runs_grouped: groupBlockedHarnessRuns(blockedHarnessRuns),
      blocked_prereqs: blockedPrereqs,
      blocked_prereqs_grouped: groupBlockedPrereqs(blockedPrereqs),
      bypass_attempts: bypassAttempts,
      bypass_attempts_grouped: groupBypassAttempts(bypassAttempts),
      discovered_pivots: discoveredPivots,
      unconsumed_pivots: unconsumedPivots,
      provenance,
      // CR-3/I4: per-run coordinates the server-side friction mechanization
      // needs (run_id/node_id + the RAW handoff JSON, which carries ranked_leads).
      run_contexts: runContexts,
    },
  };
}

// Y.10 (Y-P12) — merge-snapshot persistence so the runtime gate at
// bob_advance_session(OPEN_FRONTIER -> CLAIM_FREEZE) can read the latest
// merged wave's partial_surface_ids without re-running mergeWaveHandoffsInternal.
// Snapshot lives at <sessionDir>/wave-handoffs/wave-<N>-merge-snapshot.json and
// is append-only (each successful merge writes a new snapshot file; older
// snapshots are retained for audit). The wave-handoffs/ directory is already
// in AUDIT_GRADED_RELATIVE_DIRS (mcp/lib/paths.js) so the snapshot is
// MCP-owned audit-graded artifact content (Y-P13).
function waveHandoffsSnapshotDir(domain) {
  return path.join(sessionDir(domain), "wave-handoffs");
}

function waveMergeSnapshotPath(domain, waveNumber) {
  return path.join(waveHandoffsSnapshotDir(domain), `wave-${waveNumber}-merge-snapshot.json`);
}

function writeWaveMergeSnapshot(domain, waveNumber, snapshot) {
  const dir = waveHandoffsSnapshotDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  const filePath = waveMergeSnapshotPath(domain, waveNumber);
  const body = `${JSON.stringify(snapshot, null, 2)}\n`;
  fs.writeFileSync(filePath, body);
}

// Returns the partial_surface_ids of the highest-numbered merge snapshot for
// the target's session; empty array if no merges have happened or the
// snapshot directory is missing. Used by the Y-P12 runtime gate in
// mcp/lib/tools/advance-session.js and by mcp/lib/scheduler-preconditions.js.
function getLatestMergedWavePartialSurfaceIds(targetDomain) {
  const domain = assertNonEmptyString(targetDomain, "target_domain");
  const dir = waveHandoffsSnapshotDir(domain);
  if (!fs.existsSync(dir)) return [];
  let entries;
  try {
    entries = fs.readdirSync(dir);
  } catch {
    return [];
  }
  const snapshotPattern = /^wave-([1-9][0-9]*)-merge-snapshot\.json$/;
  const numbers = [];
  for (const entry of entries) {
    const match = entry.match(snapshotPattern);
    if (match) numbers.push(Number(match[1]));
  }
  if (numbers.length === 0) return [];
  const highest = Math.max.apply(null, numbers);
  let parsed;
  try {
    parsed = readJsonFile(waveMergeSnapshotPath(domain, highest));
  } catch {
    return [];
  }
  if (!parsed || typeof parsed !== "object") return [];
  const partial = parsed.partial_surface_ids;
  if (!Array.isArray(partial)) return [];
  return partial.filter((id) => typeof id === "string" && id.length > 0);
}

function mergeWaveHandoffs(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  const { readiness, merge } = mergeWaveHandoffsInternal(domain, waveNumber);

  // Y.10 (Y-P12) — persist a merge snapshot so the partial-surface runtime
  // gate at bob_advance_session can consult the latest merged wave without
  // recomputing. Failures here do NOT block the merge itself (the merge
  // result is the primary contract); the gate falls back to "no partial
  // surfaces known" when the snapshot is missing, which is the safer default.
  try {
    writeWaveMergeSnapshot(domain, waveNumber, {
      wave_number: waveNumber,
      merged_at_iso: new Date().toISOString(),
      partial_surface_ids: merge.partial_surface_ids.slice(),
      completed_surface_ids: merge.completed_surface_ids.slice(),
      missing_surface_ids: merge.missing_surface_ids.slice(),
    });
  } catch {
    // Intentionally swallow — snapshot persistence is best-effort.
  }

  return JSON.stringify({
    assignments_total: readiness.assignments_total,
    handoffs_total: readiness.handoffs_total,
    received_agents: merge.received_agents,
    invalid_agents: merge.invalid_agents,
    invalid_handoffs: merge.invalid_handoffs,
    unexpected_agents: merge.unexpected_agents,
    completed_surface_ids: merge.completed_surface_ids,
    partial_surface_ids: merge.partial_surface_ids,
    missing_surface_ids: merge.missing_surface_ids,
    dead_ends: merge.dead_ends,
    waf_blocked_endpoints: merge.waf_blocked_endpoints,
    lead_surface_ids: merge.lead_surface_ids,
    blocked_harness_runs: merge.blocked_harness_runs,
    blocked_harness_runs_grouped: merge.blocked_harness_runs_grouped,
    blocked_prereqs: merge.blocked_prereqs,
    blocked_prereqs_grouped: merge.blocked_prereqs_grouped,
    bypass_attempts: merge.bypass_attempts,
    bypass_attempts_grouped: merge.bypass_attempts_grouped,
    unconsumed_pivots: merge.unconsumed_pivots,
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

  const allFindings = findingPayloadsFromClaims(domain);
  const findingsByRun = new Map();
  for (const finding of allFindings) {
    const runKey = `${finding.wave} ${finding.agent} ${finding.surface_id}`;
    if (!findingsByRun.has(runKey)) findingsByRun.set(runKey, []);
    findingsByRun.get(runKey).push(finding);
  }

  for (const waveNumber of waveNumbers) {
    const artifacts = loadWaveArtifacts(domain, waveNumber);
    let signingKey = null;
    let signingKeyError = null;
    try {
      signingKey = readSigningKeyForArtifacts(domain, artifacts);
    } catch (error) {
      signingKeyError = error;
    }
    for (const agent of artifacts.unexpectedAgents) {
      unexpectedHandoffs.push({ wave: artifacts.wave, agent });
    }

    for (const assignment of artifacts.assignments) {
      const filePath = artifacts.handoffPathByAgent.get(assignment.agent);
      // Drive the readout from the AgentRun lifecycle. A "started" or "fallback"
      // gate defers to the on-disk handoff validation below; only a
      // started/fallback run with no handoff on disk is reported missing.
      const gate = agentRunGateForAssignment(domain, artifacts.wave, assignment);
      if (gate.gate === "closed_terminal_non_settled"
        && !(gateStatusIsHookTerminal(gate.status)
          && isRecoverableBlockCode(gate.blockCode, assignment.surface_id)
          && verifiedHandoffOnDiskForAssignment(domain, artifacts, assignment, { signingKey, signingKeyError }))) {
        // Don't let a stop-hook `failed`/`abandoned` row force this agent into
        // missing_handoffs (RCA gate self-poison flip) when the block_code is
        // recoverable (runaway-loop handoff poisoning, or a promoted-lead
        // technique-log gap) and a cryptographically verified handoff sits on
        // disk. Only fall through when full HMAC provenance passes; a
        // non-recoverable blocker (e.g. missing_oss_coverage) or a forged/absent
        // handoff stays missing. (A `running` row routes through the "started"
        // gate, not here.)
        missingHandoffs.push({
          wave: artifacts.wave,
          agent: assignment.agent,
          surface_id: assignment.surface_id,
        });
        continue;
      }
      if ((gate.gate === "started" || gate.gate === "fallback") && !filePath) {
        missingHandoffs.push({
          wave: artifacts.wave,
          agent: assignment.agent,
          surface_id: assignment.surface_id,
        });
        continue;
      }
      if (gate.gate === "settled" && !filePath) {
        missingHandoffs.push({
          wave: artifacts.wave,
          agent: assignment.agent,
          surface_id: assignment.surface_id,
        });
        continue;
      }

      try {
        if (assignmentRequiresToken(assignment) && signingKeyError) {
          throw signingKeyError;
        }
        const handoffJson = readJsonFile(filePath);
        const runKey = `${artifacts.wave} ${assignment.agent} ${assignment.surface_id}`;
        const findingsForRun = findingsByRun.get(runKey) || [];
        const effectiveSurfaceType = assignment.surface_type || null;
        const payload = validateWaveHandoffPayload(handoffJson, {
          targetDomain: domain,
          wave: artifacts.wave,
          agent: assignment.agent,
          surfaceId: assignment.surface_id,
          effectiveSurfaceType,
          findingsForRun,
        });
        const provenance = validateHandoffProvenance(handoffJson, assignment, { signingKey });
        // The merge-side technique-attempt check (handoffMissingRequiredTechniqueAttempt)
        // is deliberately NOT applied here. This document is consumed by the
        // finalize gate (agent-run-completion.js evaluateAgentCompletion), which
        // calls evaluateTechniqueAttemptRequirement itself and must keep
        // producing block_code missing_technique_attempt_log (terminal on an
        // ordinary surface). Refusing the handoff here would relabel that block
        // as missing_handoff (which is recoverable + verified-handoff-relaxed at
        // merge), reopening the attempt_log_required bypass. The technique-log
        // residual is closed at the authoritative merge gate
        // (mergeWaveHandoffsInternal) and the readiness gate (buildWaveReadiness)
        // that apply_wave_merge consults; this readout intentionally still
        // surfaces the on-disk handoff.
        const handoff = {
          wave: artifacts.wave,
          agent: assignment.agent,
          surface_id: assignment.surface_id,
          surface_type: payload.surface_type,
          surface_status: payload.surface_status,
          provenance,
          summary: payload.summary,
          chain_notes: payload.chain_notes,
          discovered_pivots: payload.discovered_pivots,
          spawned_children: payload.spawned_children,
          blocked_harness_runs: payload.blocked_harness_runs,
          blocked_prereqs: payload.blocked_prereqs,
          bypass_attempts: payload.bypass_attempts,
          dead_ends: payload.dead_ends,
          waf_blocked_endpoints: payload.waf_blocked_endpoints,
          lead_surface_ids: payload.lead_surface_ids,
        };
        if (payload.surface_lead_ids.length > 0) {
          handoff.surface_lead_ids = payload.surface_lead_ids;
        }
        handoffs.push(handoff);
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

function waveHandoffStatus(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  return JSON.stringify(buildWaveReadiness(loadWaveArtifacts(domain, waveNumber), { domain }));
}

module.exports = {
  WAVE_ARTIFACT_KEYS,
  buildWaveHandoffFileIndex,
  buildWaveHandoffsDocument,
  buildWaveReadiness,
  getLatestMergedWavePartialSurfaceIds,
  listWaveAssignmentNumbers,
  listWaveHandoffFiles,
  loadWaveArtifacts,
  mergeWaveHandoffs,
  mergeWaveHandoffsInternal,
  readSigningKeyForArtifacts,
  readWaveHandoffs,
  verifiedHandoffOnDiskForAssignment,
  waveHandoffStatus,
  waveMergeSnapshotPath,
  waveHandoffsSnapshotDir,
};
