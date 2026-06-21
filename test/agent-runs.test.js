const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendAgentRun,
  latestAgentRunForWaveAgent,
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
