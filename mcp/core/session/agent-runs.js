"use strict";

const {
  assertEnumValue,
  normalizeOptionalText,
} = require("../io/validation.js");
const {
  assertSafeDomain,
  agentRunsJsonlPath,
} = require("../io/paths.js");
const {
  appendJsonlLine,
  withSessionLock,
} = require("../io/storage.js");
const {
  hashCanonicalJson,
} = require("../verification/verification-contracts.js");
const {
  validateHandoffProvenance,
} = require("../waves/wave-handoff-contracts.js");
const {
  normalizeId,
  normalizeIsoTimestamp,
  normalizeOptionalId,
  normalizeOptionalObject,
  normalizeReferenceArray,
} = require("../io/validation.js");
const {
  readJsonlStrict,
} = require("../io/storage.js");
const {
  withDocumentHash,
} = require("../verification/document-hash.js");

const AGENT_RUN_VERSION = 1;
const AGENT_RUN_STATUSES = Object.freeze(["assigned", "running", "completed", "failed", "abandoned", "settled"]);
const AGENT_RUN_TERMINAL_STATUSES = Object.freeze(["completed", "failed", "abandoned", "settled"]);
const AGENT_RUNS_MAX_RECORDS = 20000;

function generatedAgentRunId(fields) {
  return `AR-${hashCanonicalJson(fields).slice(0, 24)}`;
}

// Synthesize a task_id from wave coordinates for wave assignments that lack
// one. During the dual-write window many wave assignments come from
// planNextWave (not scheduler decisions) and have no task_id. The synthetic id
// is deterministic per (domain, wave, agent, surface_id) so subsequent state
// rows (running, settled) resolve to the same task lineage. Real scheduler
// decisions still supply assignment.task_id, which takes precedence at the
// call site.
function syntheticTaskIdForWaveAssignment({ targetDomain, wave, agent, surfaceId }) {
  return `WT-${hashCanonicalJson({
    target_domain: targetDomain,
    wave,
    agent,
    surface_id: surfaceId,
  }).slice(0, 24)}`;
}

function normalizeAgentRun(input, { targetDomain = null, now = new Date() } = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("agent run must be an object");
  }
  const domain = assertSafeDomain(input.target_domain || targetDomain);
  const status = assertEnumValue(input.status || "assigned", AGENT_RUN_STATUSES, "status");
  const taskId = normalizeId(input.task_id, "task_id");
  const agentId = normalizeId(input.agent_id || input.agent, "agent_id");
  const startedAt = normalizeIsoTimestamp(input.started_at || input.ts, "started_at", now);
  const base = {
    version: AGENT_RUN_VERSION,
    target_domain: domain,
    task_id: taskId,
    agent_id: agentId,
    status,
    started_at: startedAt,
  };

  const endedAt = input.ended_at == null ? null : normalizeIsoTimestamp(input.ended_at, "ended_at", null);
  const assignmentId = normalizeOptionalId(input.assignment_id, "assignment_id");
  const contextSliceHash = normalizeOptionalText(input.context_slice_hash, "context_slice_hash");
  const summary = normalizeOptionalText(input.summary, "summary");
  const failureReason = normalizeOptionalText(input.failure_reason, "failure_reason");
  // Step 2b: structured failure classification so the merge gate / audit can
  // distinguish a recoverable tooling gap (e.g. a promoted-lead surface whose
  // technique-attempt row could not be logged) from a genuine failure.
  const blockCode = normalizeOptionalText(input.block_code, "block_code");
  const failureKind = normalizeOptionalText(input.failure_kind, "failure_kind");
  const inputRefs = normalizeReferenceArray(input.input_refs, "input_refs");
  const outputRefs = normalizeReferenceArray(input.output_refs, "output_refs");
  const handoffRefs = normalizeReferenceArray(input.handoff_refs, "handoff_refs");
  const metrics = normalizeOptionalObject(input.metrics, "metrics");

  if (endedAt) base.ended_at = endedAt;
  if (assignmentId) base.assignment_id = assignmentId;
  if (contextSliceHash) base.context_slice_hash = contextSliceHash;
  if (summary) base.summary = summary;
  if (failureReason) base.failure_reason = failureReason;
  if (blockCode) base.block_code = blockCode;
  if (failureKind) base.failure_kind = failureKind;
  if (inputRefs.length > 0) base.input_refs = inputRefs;
  if (outputRefs.length > 0) base.output_refs = outputRefs;
  if (handoffRefs.length > 0) base.handoff_refs = handoffRefs;
  if (metrics) base.metrics = metrics;

  const runId = normalizeOptionalId(input.agent_run_id, "agent_run_id") || generatedAgentRunId(base);
  return withDocumentHash({
    agent_run_id: runId,
    ...base,
  }, "agent_run_hash");
}

function appendAgentRun(input, options = {}) {
  const run = normalizeAgentRun(input, options);
  return withSessionLock(run.target_domain, () => {
    appendJsonlLine(agentRunsJsonlPath(run.target_domain), run, {
      maxRecords: options.maxRecords == null ? AGENT_RUNS_MAX_RECORDS : options.maxRecords,
    });
    return run;
  });
}

function readAgentRuns(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  return readJsonlStrict(
    agentRunsJsonlPath(domain),
    "agent-runs.jsonl",
    (record) => normalizeAgentRun(record, { targetDomain: domain, now: null }),
  );
}

// Latest row per (task_id, agent_id). The JSONL is append-only, so the merge
// gate needs the row that reflects the run's final fate. Prefer the row with
// the greatest ended_at (terminal/settled rows carry ended_at) and fall back to
// append order only when neither candidate is dated (e.g. two assigned/running
// rows). This makes the reader idempotent under duplicate settled rows AND
// order-insensitive, so a `failed` row appended after a `settled` row by a
// later stop attempt cannot flip the gate closed for a run that did settle.
function latestAgentRunByTaskAndAgent(targetDomain) {
  const runs = readAgentRuns(targetDomain);
  const index = new Map();
  for (const run of runs) {
    if (!run || typeof run.task_id !== "string" || typeof run.agent_id !== "string") continue;
    const key = `${run.task_id}\u0000${run.agent_id}`;
    const existing = index.get(key);
    if (!existing) {
      index.set(key, run);
      continue;
    }
    const existingEnded = typeof existing.ended_at === "string" ? existing.ended_at : null;
    const candidateEnded = typeof run.ended_at === "string" ? run.ended_at : null;
    if (candidateEnded && existingEnded) {
      // Both dated: keep the later-ended row; ties keep the later-appended one.
      if (candidateEnded >= existingEnded) index.set(key, run);
    } else if (candidateEnded && !existingEnded) {
      // A dated terminal/settled row supersedes an undated assigned/running row.
      index.set(key, run);
    } else if (!candidateEnded && !existingEnded) {
      // Neither dated: fall back to append order (later wins).
      index.set(key, run);
    }
    // candidate undated but existing dated: keep the dated existing row.
  }
  return index;
}

// Resolve the current AgentRun for a wave-context tuple. Used by the merge
// gate (wave-handoff-store.js) to decide whether an agent has settled.
// Returns null when no row exists yet (e.g., legacy session pre-S.5).
function latestAgentRunForWaveAgent(targetDomain, { wave, agent, surfaceId }) {
  const taskId = syntheticTaskIdForWaveAssignment({
    targetDomain: assertSafeDomain(targetDomain),
    wave,
    agent,
    surfaceId,
  });
  const index = latestAgentRunByTaskAndAgent(targetDomain);
  return index.get(`${taskId}\u0000${agent}`) || null;
}

// Append an `assigned` row for a wave assignment. Called from the
// assignment-emission path (waves.js startWaveLocked) so every spawned agent
// has a ledger row before the SubagentStart hook fires. Idempotent within a
// run: a duplicate call produces a duplicate row (the JSONL is the ledger),
// but the merge gate uses the latest row, so re-emission is safe.
function appendWaveAssignmentAgentRun({
  targetDomain,
  wave,
  agent,
  surfaceId,
  assignmentId = null,
  taskId = null,
  contextSliceHash = null,
  startedAt = null,
  now = new Date(),
} = {}) {
  const domain = assertSafeDomain(targetDomain);
  const resolvedTaskId = taskId || syntheticTaskIdForWaveAssignment({
    targetDomain: domain,
    wave,
    agent,
    surfaceId,
  });
  return appendAgentRun({
    target_domain: domain,
    task_id: resolvedTaskId,
    agent_id: agent,
    assignment_id: assignmentId,
    status: "assigned",
    started_at: startedAt || now.toISOString(),
    context_slice_hash: contextSliceHash,
    input_refs: surfaceId
      ? [{ kind: "wave_surface", wave, surface_id: surfaceId }]
      : [],
  });
}

// Append a `running` row for a previously-`assigned` agent. Called by the
// SubagentStart hook. If no `assigned` row exists yet (legacy session, or hook
// fired before assignment emission), we still emit the row so the ledger
// reflects observed activity — the merge gate treats absent rows as
// not-settled, which is the safe behavior.
function markAgentRunRunning({
  targetDomain,
  wave,
  agent,
  surfaceId,
  taskId = null,
  startedAt = null,
  now = new Date(),
} = {}) {
  const domain = assertSafeDomain(targetDomain);
  const resolvedTaskId = taskId || syntheticTaskIdForWaveAssignment({
    targetDomain: domain,
    wave,
    agent,
    surfaceId,
  });
  return appendAgentRun({
    target_domain: domain,
    task_id: resolvedTaskId,
    agent_id: agent,
    status: "running",
    started_at: startedAt || now.toISOString(),
    input_refs: surfaceId
      ? [{ kind: "wave_surface", wave, surface_id: surfaceId }]
      : [],
  });
}

// Universal MCP-side start-recording. Transition a wave assignment's run from
// `assigned` to `running` the first time a real subagent tool call reaches the
// server (the natural universal entry is bob_read_assignment_brief — every
// evaluator reads its brief first), so the merge gate observes a real `running`
// lifecycle WITHOUT depending on any adapter wiring a SubagentStart hook. The
// SubagentStart hook stays as the early-recording optimization (it marks
// `running` at spawn, before the first tool call); this is the universal
// backstop that fires on every adapter.
//
// Idempotent / first-transition-only: a `running` row is appended ONLY when the
// latest row for this run is absent or still `assigned`. A re-call, or a run
// already `running`/`completed`/`failed`/`abandoned`/`settled`, is a no-op. The
// read-then-append is intentionally not wrapped in an outer lock: the worst case
// is a duplicate `running` row (e.g. the start hook and this path both firing),
// which the latest-row reader collapses and which a later dated `settled`/`failed`
// row supersedes — so correctness does not depend on exactly-once.
//
// Non-forgeable + correctly attributed: the start is recorded from the FACT of
// the server-side tool call, and keyed by (target_domain, wave, agent, surface_id)
// where surface_id is resolved by the caller from the on-disk assignment, never
// from an agent-asserted field. The `agent` label disambiguates a surface that a
// wave assigns to more than one agent.
function markAgentRunStartedIdempotent({
  targetDomain,
  wave,
  agent,
  surfaceId,
  taskId = null,
  now = new Date(),
} = {}) {
  const domain = assertSafeDomain(targetDomain);
  let latest = null;
  try {
    latest = latestAgentRunForWaveAgent(domain, { wave, agent, surfaceId });
  } catch {
    latest = null;
  }
  const status = latest ? latest.status : null;
  if (status !== null && status !== "assigned") {
    return null;
  }
  return markAgentRunRunning({
    targetDomain: domain,
    wave,
    agent,
    surfaceId,
    taskId,
    now,
  });
}

// Append a non-settled terminal row (failed / abandoned). Used by the
// SubagentStop hook when the agent stopped without writing a valid handoff —
// the merge gate keeps the gate closed until either a settled or an explicit
// terminal row reflects the run's fate. `started_at` is required by the
// schema; callers typically pass the original assigned-row timestamp.
function markAgentRunTerminal({
  targetDomain,
  wave,
  agent,
  surfaceId,
  status,
  taskId = null,
  startedAt = null,
  endedAt = null,
  failureReason = null,
  blockCode = null,
  failureKind = null,
  now = new Date(),
} = {}) {
  if (status !== "failed" && status !== "abandoned" && status !== "completed") {
    throw new Error(`markAgentRunTerminal: status must be failed|abandoned|completed, got ${status}`);
  }
  const domain = assertSafeDomain(targetDomain);
  const resolvedTaskId = taskId || syntheticTaskIdForWaveAssignment({
    targetDomain: domain,
    wave,
    agent,
    surfaceId,
  });
  return appendAgentRun({
    target_domain: domain,
    task_id: resolvedTaskId,
    agent_id: agent,
    status,
    started_at: startedAt || now.toISOString(),
    ended_at: endedAt || now.toISOString(),
    failure_reason: failureReason,
    block_code: blockCode,
    failure_kind: failureKind,
    input_refs: surfaceId
      ? [{ kind: "wave_surface", wave, surface_id: surfaceId }]
      : [],
  });
}

function signedHandoffReference(handoff, provenance) {
  const signature = handoff && handoff.provenance_signature;
  return {
    kind: "signed_handoff",
    provenance,
    provenance_model: handoff.provenance_model,
    provenance_assignment_hash: handoff.provenance_assignment_hash,
    signature_digest: signature && typeof signature.digest === "string" ? signature.digest : null,
  };
}

function settleAgentRunFromHandoff(input, options = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("settled agent run input must be an object");
  }
  const assignment = input.assignment;
  const handoff = input.handoff;
  const provenance = validateHandoffProvenance(handoff, assignment, {
    signingKey: input.signing_key || input.signingKey || null,
    requireProvenance: true,
  });
  const targetDomain = input.target_domain || (handoff && handoff.target_domain);
  const agentId = input.agent_id || input.agent || (assignment && assignment.agent);
  const surfaceId = input.surface_id
    || (handoff && handoff.surface_id)
    || (assignment && assignment.surface_id);
  const wave = input.wave || (handoff && handoff.wave);
  // Use the assignment/input task_id when present; otherwise synthesize from
  // wave coordinates so the settle row resolves to the same lineage as the
  // assigned/running rows from S.5's wave-emission path.
  const taskId = input.task_id
    || (assignment && assignment.task_id)
    || (targetDomain && wave && agentId && surfaceId
      ? syntheticTaskIdForWaveAssignment({
          targetDomain: assertSafeDomain(targetDomain),
          wave,
          agent: agentId,
          surfaceId,
        })
      : null);
  const run = normalizeAgentRun({
    target_domain: targetDomain,
    task_id: taskId,
    agent_id: agentId,
    assignment_id: input.assignment_id || (assignment && assignment.assignment_id),
    status: "settled",
    started_at: input.started_at || input.ts,
    ended_at: input.ended_at || new Date().toISOString(),
    summary: input.summary || (handoff && handoff.summary),
    handoff_refs: [signedHandoffReference(handoff, provenance)],
    metrics: input.metrics,
  }, options);
  if (options.write) {
    return appendAgentRun(run, options);
  }
  return run;
}

module.exports = {
  AGENT_RUNS_MAX_RECORDS,
  AGENT_RUN_STATUSES,
  AGENT_RUN_TERMINAL_STATUSES,
  AGENT_RUN_VERSION,
  appendAgentRun,
  appendWaveAssignmentAgentRun,
  generatedAgentRunId,
  latestAgentRunByTaskAndAgent,
  latestAgentRunForWaveAgent,
  markAgentRunRunning,
  markAgentRunStartedIdempotent,
  markAgentRunTerminal,
  normalizeAgentRun,
  readAgentRuns,
  settleAgentRunFromHandoff,
  syntheticTaskIdForWaveAssignment,
};
