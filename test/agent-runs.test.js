const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  readAgentRuns,
  settleAgentRunFromHandoff,
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
