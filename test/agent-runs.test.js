const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendAgentRun,
  appendWaveAssignmentAgentRun,
  latestAgentRunForWaveAgent,
  markAgentRunStartedIdempotent,
  markAgentRunTerminal,
  readAgentRuns,
  settleAgentRunFromHandoff,
  syntheticTaskIdForWaveAssignment,
} = require("../mcp/lib/agent-runs.js");
const {
  signHandoffProvenance,
} = require("../mcp/lib/wave-handoff-contracts.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-agent-runs-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function signedInput() {
  const signingKey = Buffer.from("0123456789abcdef0123456789abcdef");
  const assignment = {
    assignment_id: "A-alpha",
    task_id: "T-alpha",
    agent: "a1",
    surface_id: "surface:alpha",
    task_lens: "control_check",
    budget: { max_steps: 4, max_context_tokens: 12000 },
    handoff_token_required: true,
    handoff_token_sha256: "0".repeat(64),
  };
  const handoff = signHandoffProvenance({
    target_domain: "runs.example.com",
    wave: "w1",
    agent: "a1",
    surface_id: "surface:alpha",
    surface_status: "complete",
    provenance: "verified",
    summary: "Completed the assigned boundary check.",
  }, signingKey, { assignment });
  return { assignment, handoff, signingKey };
}

test("agent runs settle only through signed handoff provenance", () => {
  withTempHome(() => {
    const { assignment, handoff, signingKey } = signedInput();
    const run = settleAgentRunFromHandoff({
      target_domain: "runs.example.com",
      assignment,
      handoff,
      signing_key: signingKey,
      started_at: "2026-05-26T05:00:00.000Z",
      ended_at: "2026-05-26T05:05:00.000Z",
      write: true,
    }, { write: true });

    assert.equal(run.status, "settled");
    assert.equal(run.task_id, "T-alpha");
    assert.equal(run.assignment_id, "A-alpha");
    assert.equal(run.handoff_refs[0].provenance, "verified");
    assert.match(run.agent_run_hash, /^[0-9a-f]{64}$/);
    assert.equal(readAgentRuns("runs.example.com")[0].agent_run_id, run.agent_run_id);
  });
});

test("agent run settlement rejects unsigned handoff payloads", () => {
  const { assignment, handoff } = signedInput();
  assert.throws(
    () => settleAgentRunFromHandoff({
      target_domain: "runs.example.com",
      assignment,
      handoff: { ...handoff, provenance_signature: null },
      signing_key: Buffer.from("0123456789abcdef0123456789abcdef"),
      started_at: "2026-05-26T05:00:00.000Z",
    }),
    /signature is required/,
  );
});

test("duplicate settled rows are idempotent at the reader and a later failed row cannot unsettle them", () => {
  withTempHome(() => {
    const targetDomain = "dedupe.example.com";
    const wave = "w1";
    const agent = "a4";
    const surfaceId = "surface:money";
    const taskId = syntheticTaskIdForWaveAssignment({
      targetDomain,
      wave,
      agent,
      surfaceId,
    });
    const base = {
      target_domain: targetDomain,
      task_id: taskId,
      agent_id: agent,
      input_refs: [{ kind: "wave_surface", wave, surface_id: surfaceId }],
    };
    // Four settled rows from a re-finalize loop, with monotonically increasing
    // ended_at (each settle defaults ended_at to now()).
    appendAgentRun({ ...base, status: "settled", started_at: "2026-05-26T05:00:00.000Z", ended_at: "2026-05-26T05:05:00.000Z" });
    appendAgentRun({ ...base, status: "settled", started_at: "2026-05-26T05:00:00.000Z", ended_at: "2026-05-26T05:06:00.000Z" });
    appendAgentRun({ ...base, status: "settled", started_at: "2026-05-26T05:00:00.000Z", ended_at: "2026-05-26T05:07:00.000Z" });
    appendAgentRun({ ...base, status: "settled", started_at: "2026-05-26T05:00:00.000Z", ended_at: "2026-05-26T05:08:00.000Z" });

    // Duplicate settled rows must resolve to settled (count-insensitive).
    const afterSettled = latestAgentRunForWaveAgent(targetDomain, { wave, agent, surfaceId });
    assert.equal(afterSettled.status, "settled");

    // A later stop attempt that fails finalization appends a `failed` row whose
    // ended_at is EARLIER than the winning settled row (the settle already
    // happened). latest-by-ended_at must keep the run settled; latest-by-append
    // order would wrongly flip it to failed.
    appendAgentRun({ ...base, status: "failed", started_at: "2026-05-26T05:00:00.000Z", ended_at: "2026-05-26T05:07:30.000Z", failure_reason: "runaway stop loop" });

    const afterLateFailed = latestAgentRunForWaveAgent(targetDomain, { wave, agent, surfaceId });
    assert.equal(afterLateFailed.status, "settled");
  });
});

// markAgentRunStartedIdempotent — the universal MCP-side start recorder. It
// transitions assigned -> running exactly once, keyed by
// (target_domain, wave, agent, surface_id), and is a no-op on any further call
// or on a run that has already moved past `assigned`.
function runningCount(domain, agent) {
  return readAgentRuns(domain).filter((r) => r.agent_id === agent && r.status === "running").length;
}

test("markAgentRunStartedIdempotent appends running only when latest is absent or assigned", () => {
  withTempHome(() => {
    const domain = "started-idem.example.com";
    const surfaceId = "surface:m";

    // null latest -> appends running (the degraded path where the assigned
    // write was lost still records start, keyed to the caller-supplied tuple).
    let row = markAgentRunStartedIdempotent({ targetDomain: domain, wave: "w1", agent: "a1", surfaceId });
    assert.ok(row && row.status === "running");
    assert.equal(latestAgentRunForWaveAgent(domain, { wave: "w1", agent: "a1", surfaceId }).status, "running");
    assert.equal(runningCount(domain, "a1"), 1);

    // already running -> no-op.
    assert.equal(markAgentRunStartedIdempotent({ targetDomain: domain, wave: "w1", agent: "a1", surfaceId }), null);
    assert.equal(runningCount(domain, "a1"), 1);

    // assigned latest -> appends running.
    appendWaveAssignmentAgentRun({ targetDomain: domain, wave: "w1", agent: "a2", surfaceId });
    assert.equal(latestAgentRunForWaveAgent(domain, { wave: "w1", agent: "a2", surfaceId }).status, "assigned");
    row = markAgentRunStartedIdempotent({ targetDomain: domain, wave: "w1", agent: "a2", surfaceId });
    assert.ok(row && row.status === "running");
    assert.equal(latestAgentRunForWaveAgent(domain, { wave: "w1", agent: "a2", surfaceId }).status, "running");
  });
});

test("markAgentRunStartedIdempotent is a no-op for completed/failed/abandoned/settled runs", () => {
  withTempHome(() => {
    const domain = "started-idem-terminal.example.com";
    for (const [agent, status] of [["a1", "completed"], ["a2", "failed"], ["a3", "abandoned"]]) {
      const surfaceId = `surface:${agent}`;
      markAgentRunTerminal({ targetDomain: domain, wave: "w1", agent, surfaceId, status });
      assert.equal(markAgentRunStartedIdempotent({ targetDomain: domain, wave: "w1", agent, surfaceId }), null);
      assert.equal(latestAgentRunForWaveAgent(domain, { wave: "w1", agent, surfaceId }).status, status);
      assert.equal(runningCount(domain, agent), 0);
    }

    // settled run: a stray start record must not unsettle or add a running row.
    const settledAgent = "a4";
    const settledSurface = "surface:a4";
    const { assignment, handoff, signingKey } = signedInput();
    settleAgentRunFromHandoff({
      target_domain: domain,
      wave: "w1",
      agent: settledAgent,
      surface_id: settledSurface,
      task_id: syntheticTaskIdForWaveAssignment({ targetDomain: domain, wave: "w1", agent: settledAgent, surfaceId: settledSurface }),
      assignment: { ...assignment, agent: settledAgent, surface_id: settledSurface },
      handoff: signHandoffProvenance({
        target_domain: domain,
        wave: "w1",
        agent: settledAgent,
        surface_id: settledSurface,
        surface_status: "complete",
        provenance: "verified",
        summary: "Completed the assigned boundary check.",
      }, signingKey, { assignment: { ...assignment, agent: settledAgent, surface_id: settledSurface } }),
      signing_key: signingKey,
    }, { write: true });
    assert.equal(latestAgentRunForWaveAgent(domain, { wave: "w1", agent: settledAgent, surfaceId: settledSurface }).status, "settled");
    assert.equal(markAgentRunStartedIdempotent({ targetDomain: domain, wave: "w1", agent: settledAgent, surfaceId: settledSurface }), null);
    assert.equal(latestAgentRunForWaveAgent(domain, { wave: "w1", agent: settledAgent, surfaceId: settledSurface }).status, "settled");
    assert.equal(runningCount(domain, settledAgent), 0);
  });
});

test("markAgentRunStartedIdempotent disambiguates two agents on the SAME surface_id", () => {
  withTempHome(() => {
    const domain = "started-idem-multi.example.com";
    const surfaceId = "surface:shared";
    // Two agents share a surface (e.g. a nested-spawn fan-out). The `agent`
    // label keys the run, so each gets its own running row; neither is
    // mis-attributed to the other.
    appendWaveAssignmentAgentRun({ targetDomain: domain, wave: "w1", agent: "a1", surfaceId });
    appendWaveAssignmentAgentRun({ targetDomain: domain, wave: "w1", agent: "a2", surfaceId });

    markAgentRunStartedIdempotent({ targetDomain: domain, wave: "w1", agent: "a1", surfaceId });
    // a1 running; a2 untouched (still assigned).
    assert.equal(latestAgentRunForWaveAgent(domain, { wave: "w1", agent: "a1", surfaceId }).status, "running");
    assert.equal(latestAgentRunForWaveAgent(domain, { wave: "w1", agent: "a2", surfaceId }).status, "assigned");

    markAgentRunStartedIdempotent({ targetDomain: domain, wave: "w1", agent: "a2", surfaceId });
    assert.equal(latestAgentRunForWaveAgent(domain, { wave: "w1", agent: "a2", surfaceId }).status, "running");

    const a1 = readAgentRuns(domain).filter((r) => r.agent_id === "a1" && r.status === "running");
    const a2 = readAgentRuns(domain).filter((r) => r.agent_id === "a2" && r.status === "running");
    assert.equal(a1.length, 1);
    assert.equal(a2.length, 1);
    assert.notEqual(a1[0].task_id, a2[0].task_id);
  });
});
