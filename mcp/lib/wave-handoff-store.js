"use strict";

const fs = require("fs");
const path = require("path");
const {
  assertNonEmptyString,
  compareAgentLabels,
  normalizeStringArray,
  parseWaveNumber,
  pushUnique,
} = require("./validation.js");
const {
  liveDeadEndsJsonlPath,
  sessionDir,
} = require("./paths.js");
const {
  readFileUtf8,
  readJsonFile,
} = require("./storage.js");

const {
  loadWaveAssignments,
} = require("./assignments.js");
const {
  findingPayloadsFromClaims,
} = require("./tools/record-candidate-claim.js");
const {
  readHandoffSigningKey,
} = require("./handoff-signing-key.js");
const {
  assignmentRequiresToken,
  attachHandoffOrigin,
  groupBlockedHarnessRuns,
  groupBlockedPrereqs,
  groupBypassAttempts,
  validateHandoffProvenance,
  validateWaveHandoffPayload,
} = require("./wave-handoff-contracts.js");
const {
  latestAgentRunForWaveAgent,
} = require("./agent-runs.js");

// Cycle S.5: drive the merge gate from AgentRun.state instead of the
// handoff-file presence on disk. Pact P2 keeps file-presence as the fallback
// during the deprecation window: until the SubagentStart hook lands in every
// adapter, freshly-started agents may have only an `assigned` row when the
// merge gate inspects them. Treat the three signals as follows:
//
//   settled                       -> handoff authoritative, no fallback.
//   failed | abandoned            -> explicit terminal-non-settled, refuse.
//   running                       -> agent observed running but never settled;
//                                    the SubagentStop hook should have fired
//                                    to either settle or mark terminal, so a
//                                    stuck `running` row means the agent died
//                                    mid-flight — refuse.
//   assigned | completed | null   -> not enough state-machine signal yet; fall
//                                    back to handoff-file presence so the
//                                    dual-write window keeps producing valid
//                                    merges for legacy callers and adapters
//                                    that have not wired the SubagentStart
//                                    hook yet.
//
// A `gate` of "settled" closes the merge gate in favor of the AgentRun row.
// A `gate` of "closed_terminal_non_settled" closes it against the agent.
// A `gate` of "fallback" defers to file-presence checks at the call site.
const AGENT_RUN_GATE_FALLBACK_STATUSES = new Set([null, "assigned", "completed"]);

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
  if (status === "failed" || status === "abandoned" || status === "running") {
    return { status, gate: "closed_terminal_non_settled", blockCode };
  }
  return { status, gate: "fallback", blockCode };
}

// Step 2b: only a stop-hook-written terminal status (`failed`/`abandoned`) is
// eligible for the verified-handoff relaxation below. A stuck `running` row
// means the agent died mid-flight without ever cleanly settling — that stays
// gated closed even if a handoff file is on disk (Cycle S.5 semantics), so we
// do NOT relax it. The relaxation exists solely to undo the runaway loop's
// `failed`-row poisoning of a settleable run.
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
  return blockCode === "missing_handoff" || blockCode === "invalid_handoff";
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
    // Cycle S.5: drive readiness from AgentRun.state with file-presence as
    // the deprecation-window fallback (Pact P2).
    const handoffPresent = artifacts.handoffPathByAgent.has(assignment.agent);
    const gate = domain
      ? agentRunGateForAssignment(domain, artifacts.wave, assignment)
      : { status: null, gate: "fallback" };
    if (gate.gate === "closed_terminal_non_settled") {
      // Step 2b: a stop-hook `failed`/`abandoned` row from the runaway loop
      // must NOT mask a cryptographically verified handoff. Only fall through
      // to "received" when the row is hook-terminal AND the block_code is a
      // recoverable one (runaway-loop handoff poisoning, or a promoted-lead
      // technique-log gap) AND full HMAC provenance validates on disk. A
      // non-recoverable blocker (e.g. missing_oss_coverage), a stuck `running`
      // row (agent died mid-flight), and a forged/absent handoff all stay gated
      // closed.
      if (domain
        && gateStatusIsHookTerminal(gate.status)
        && isRecoverableBlockCode(gate.blockCode, assignment.surface_id)
        && verifiedHandoffOnDiskForAssignment(domain, artifacts, assignment, { signingKey, signingKeyError })) {
        receivedAgents.push(assignment.agent);
        continue;
      }
      missingAgents.push(assignment.agent);
      continue;
    }
    if (gate.gate === "fallback" && !handoffPresent) {
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
      receivedAgents.push(assignment.agent);
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

// sc_complete_with_zero_evidence is a NON-BLOCKING human-review suspicion flag,
// not a gate. The only structured substance signal on a bypass_attempt is the
// outcome (partial_evidence/finding_recorded, handled by the early return in
// bypassAttemptHasSubstance) plus finding_id; for a no_finding/blocked disproof
// the sole field-local signal left is how much the agent actually wrote. These
// length floors are 2x the schema storage floors (condition >= 4,
// attempt_summary >= 30 in wave-handoff-contracts.js) — a deliberately coarse
// heuristic. They suppress the flag for a disproof that both cites a condition
// and describes the exercised mechanism, while still flagging a floor-hugging
// one-line attestation. Length is gameable in both directions; this narrows the
// false positives that fired on thoroughly-tested-clean surfaces, it does not
// prove substance. A stronger semantic check (condition must appear in the
// surface's trust_assumptions[*].bypass_conditions) is a follow-up.
const SUBSTANTIVE_BYPASS_CONDITION_MIN_CHARS = 8;
const SUBSTANTIVE_BYPASS_SUMMARY_MIN_CHARS = 60;

function bypassAttemptHasSubstance(attempt) {
  // A recorded/partial finding is substance on its own.
  if (attempt.outcome === "partial_evidence" || attempt.outcome === "finding_recorded") {
    return true;
  }
  // A no_finding / blocked disproof counts only when it both cites a real
  // bypass condition and documents the concrete mechanism it exercised.
  const condition = typeof attempt.condition === "string" ? attempt.condition.trim() : "";
  const summary = typeof attempt.attempt_summary === "string" ? attempt.attempt_summary.trim() : "";
  return (
    condition.length >= SUBSTANTIVE_BYPASS_CONDITION_MIN_CHARS
    && summary.length >= SUBSTANTIVE_BYPASS_SUMMARY_MIN_CHARS
  );
}

function buildSuspicionFlags({ smartContractCompletedSurfaceIds, bypassAttemptsForCompletedSurfaces, recordedFindingsBySurface }) {
  const flags = [];
  for (const surfaceId of smartContractCompletedSurfaceIds) {
    const findings = recordedFindingsBySurface.get(surfaceId) || [];
    const attempts = bypassAttemptsForCompletedSurfaces.get(surfaceId) || [];
    if (findings.length > 0) continue;
    if (attempts.length === 0) continue;
    if (attempts.some(bypassAttemptHasSubstance)) continue;
    flags.push({
      flag: "sc_complete_with_zero_evidence",
      surface_id: surfaceId,
      reason: "smart_contract surface marked complete with no recorded finding and no bypass_attempts entry shows substance (a cited bypass condition plus a concrete attempt_summary describing the exercised mechanism, or a partial_evidence/finding_recorded outcome); review for low-effort attestation",
    });
  }
  return flags;
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
  const provenance = {
    verified_agents: [],
  };

  const deadEndSet = new Set();
  const wafSet = new Set();
  const leadSet = new Set();

  const allFindings = findingPayloadsFromClaims(domain);
  const findingsByRun = new Map();
  const recordedFindingsBySurface = new Map();
  for (const finding of allFindings) {
    if (finding.wave === artifacts.wave) {
      const runKey = `${finding.wave}\u0000${finding.agent}\u0000${finding.surface_id}`;
      if (!findingsByRun.has(runKey)) findingsByRun.set(runKey, []);
      findingsByRun.get(runKey).push(finding);
      if (!recordedFindingsBySurface.has(finding.surface_id)) recordedFindingsBySurface.set(finding.surface_id, []);
      recordedFindingsBySurface.get(finding.surface_id).push(finding);
    }
  }

  const smartContractCompletedSurfaceIds = [];
  const bypassAttemptsForCompletedSurfaces = new Map();
  const signingKey = readSigningKeyForArtifacts(domain, artifacts);

  for (const assignment of artifacts.assignments) {
    const filePath = artifacts.handoffPathByAgent.get(assignment.agent);
    // Cycle S.5: drive the merge gate from AgentRun.state. The file-presence
    // check stays as a fallback when no AgentRun row exists yet (legacy
    // session, pre-S.5 wave, or hook write failure) per Pact P2.
    const gate = agentRunGateForAssignment(domain, artifacts.wave, assignment);
    if (gate.gate === "closed_terminal_non_settled"
      && !(gateStatusIsHookTerminal(gate.status)
        && isRecoverableBlockCode(gate.blockCode, assignment.surface_id)
        && verifiedHandoffOnDiskForAssignment(domain, artifacts, assignment, { signingKey }))) {
      // Step 2b: a stop-hook `failed`/`abandoned` row gates the surface closed
      // UNLESS the block_code is recoverable (runaway-loop handoff poisoning, or
      // a promoted-lead technique-log gap) AND a cryptographically verified
      // handoff is present on disk — only then is it the runaway loop poisoning
      // a settleable run, so re-validate and let it fall through to the normal
      // merge bucketing below. A non-recoverable blocker (e.g.
      // missing_oss_coverage) and a stuck `running` row stay closed regardless.
      missingSurfaceIds.push(assignment.surface_id);
      continue;
    }
    if (gate.gate === "fallback" && !filePath) {
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
        if (effectiveSurfaceType === "smart_contract") {
          smartContractCompletedSurfaceIds.push(assignment.surface_id);
          bypassAttemptsForCompletedSurfaces.set(assignment.surface_id, payload.bypass_attempts || []);
        }
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
    } catch (error) {
      invalidAgents.push(assignment.agent);
      invalidHandoffs.push({
        agent: assignment.agent,
        surface_id: assignment.surface_id,
        error: error.message || String(error),
      });
      // Surface the invalid handoff's surface_id via missing_surface_ids so it
      // reaches the orchestrator's requeue path. Without this, R1-HIGH-#2:
      // the surface is silently dropped from completed/partial/missing buckets
      // while the wave appears merged.
      if (!missingSurfaceIds.includes(assignment.surface_id)) {
        missingSurfaceIds.push(assignment.surface_id);
      }
    }
  }

  const suspicionFlags = buildSuspicionFlags({
    smartContractCompletedSurfaceIds,
    bypassAttemptsForCompletedSurfaces,
    recordedFindingsBySurface,
  });

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
      suspicion_flags: suspicionFlags,
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
    suspicion_flags: merge.suspicion_flags,
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
      // Cycle S.5: drive the readout from AgentRun.state with file-presence as
      // the deprecation-window fallback (Pact P2).
      const gate = agentRunGateForAssignment(domain, artifacts.wave, assignment);
      if (gate.gate === "closed_terminal_non_settled"
        && !(gateStatusIsHookTerminal(gate.status)
          && isRecoverableBlockCode(gate.blockCode, assignment.surface_id)
          && verifiedHandoffOnDiskForAssignment(domain, artifacts, assignment, { signingKey, signingKeyError }))) {
        // Step 2b: don't let a stop-hook `failed`/`abandoned` row force this
        // agent into missing_handoffs (RCA gate self-poison flip) when the
        // block_code is recoverable (runaway-loop handoff poisoning, or a
        // promoted-lead technique-log gap) and a cryptographically verified
        // handoff sits on disk. Only fall through when full HMAC provenance
        // passes; a non-recoverable blocker (e.g. missing_oss_coverage), a
        // forged/absent handoff, or a stuck `running` row stays missing.
        missingHandoffs.push({
          wave: artifacts.wave,
          agent: assignment.agent,
          surface_id: assignment.surface_id,
        });
        continue;
      }
      if (gate.gate === "fallback" && !filePath) {
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
  buildSuspicionFlags,
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
