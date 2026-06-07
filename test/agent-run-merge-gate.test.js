"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  agentRunsJsonlPath,
  attackSurfacePath,
  sessionDir,
} = require("../mcp/lib/paths.js");
const {
  readAgentRuns,
  appendWaveAssignmentAgentRun,
  markAgentRunTerminal,
  settleAgentRunFromHandoff,
  syntheticTaskIdForWaveAssignment,
} = require("../mcp/lib/agent-runs.js");
const {
  buildWaveReadiness,
  loadWaveArtifacts,
  mergeWaveHandoffsInternal,
} = require("../mcp/lib/wave-handoff-store.js");
const {
  startWave,
  applyWaveMerge,
  writeWaveHandoff,
} = require("../mcp/lib/waves.js");
const {
  initSession,
  advanceSession,
} = require("../mcp/lib/session-state.js");
const {
  writeFileAtomic,
} = require("../mcp/lib/storage.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-agent-merge-gate-"));
  process.env.HOME = tempHome;
  try {
    return fn(tempHome);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

function seedAttackSurfaces(domain, surfaces) {
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
}

// Drive a real wave through startWave so the assignment-emission path appends
// the assigned AgentRun rows. Returns the parsed start payload (including
// handoff_token for each agent so subsequent handoff writes succeed).
function driveWaveStart(domain, surfaceIds) {
  // init the session first (refuses on a non-empty session dir), then seed
  // attack surfaces, then advance into OPEN_FRONTIER so wave scheduling can run.
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
  seedAttackSurfaces(
    domain,
    surfaceIds.map((id) => ({ id, hosts: [`https://${domain}`], priority: "HIGH" })),
  );
  JSON.parse(advanceSession({
    target_domain: domain,
    to_state: "OPEN_FRONTIER",
  }));
  return JSON.parse(startWave({
    target_domain: domain,
    wave_number: 1,
    assignments: surfaceIds.map((surfaceId, index) => ({
      agent: `a${index + 1}`,
      surface_id: surfaceId,
    })),
  }));
}

test("startWave appends an AgentRun row in 'assigned' state for each agent slot", () => {
  withTempHome(() => {
    const domain = "agent-runs-assigned.example.com";
    driveWaveStart(domain, ["surface-a", "surface-b", "surface-c"]);
    const runs = readAgentRuns(domain);
    assert.equal(runs.length, 3);
    for (const run of runs) {
      assert.equal(run.status, "assigned");
      assert.ok(/^a[1-3]$/.test(run.agent_id));
      assert.ok(typeof run.task_id === "string" && run.task_id.length > 0);
      assert.match(run.agent_run_hash, /^[0-9a-f]{64}$/);
    }
    // Task ids must be deterministic per (domain, wave, agent, surface_id).
    const expectedTaskIdForA1 = syntheticTaskIdForWaveAssignment({
      targetDomain: domain,
      wave: "w1",
      agent: "a1",
      surfaceId: "surface-a",
    });
    assert.ok(runs.some((run) => run.agent_id === "a1" && run.task_id === expectedTaskIdForA1));
  });
});

test("SubagentStop with valid handoff settles the AgentRun row through the merge gate", () => {
  withTempHome(() => {
    const domain = "agent-runs-settle.example.com";
    const start = driveWaveStart(domain, ["surface-a"]);
    const assignmentToken = start.assignments[0].handoff_token;

    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: assignmentToken,
      summary: "surface fully covered",
      chain_notes: ["nothing else worth pivoting to"],
      content: "# Handoff\n\nFinal handoff body",
    }));

    // Simulate the SubagentStop hook's settle path: it reads the assignment +
    // handoff JSON, calls settleAgentRunFromHandoff, which validates signed
    // provenance and appends a `settled` row.
    const { loadWaveAssignments } = require("../mcp/lib/assignments.js");
    const { readHandoffSigningKey } = require("../mcp/lib/handoff-signing-key.js");
    const assignments = loadWaveAssignments(domain, 1);
    const assignment = assignments.assignmentByAgent.get("a1");
    const handoffJsonPath = path.join(sessionDir(domain), "handoff-w1-a1.json");
    const handoffJson = JSON.parse(fs.readFileSync(handoffJsonPath, "utf8"));
    const signingKey = readHandoffSigningKey(domain);

    settleAgentRunFromHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      assignment,
      handoff: handoffJson,
      signing_key: signingKey,
    }, { write: true });

    const runs = readAgentRuns(domain);
    const settled = runs.filter((run) => run.agent_id === "a1" && run.status === "settled");
    assert.equal(settled.length, 1);
    assert.equal(settled[0].handoff_refs[0].provenance, "verified");

    // The merge gate now reflects the settled row: readiness is complete and
    // the merge advances without falling back to file-presence quirks.
    const artifacts = loadWaveArtifacts(domain, 1);
    const readiness = buildWaveReadiness(artifacts, { domain });
    assert.equal(readiness.is_complete, true);
    assert.equal(readiness.missing_agents.length, 0);
    assert.equal(readiness.received_agents[0], "a1");

    const mergeResult = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));
    assert.equal(mergeResult.status, "merged");
    assert.deepEqual(mergeResult.merge.completed_surface_ids, ["surface-a"]);
  });
});

test("killed agent (running, no settle) keeps merge gate closed on the in-flight agent", () => {
  withTempHome(() => {
    const domain = "agent-runs-killed.example.com";
    const start = driveWaveStart(domain, ["surface-a", "surface-b"]);
    const assignmentTokenA = start.assignments[0].handoff_token;
    const { markAgentRunRunning } = require("../mcp/lib/agent-runs.js");

    // Agent a1 fired SubagentStart (state = running) and wrote its handoff,
    // but the SubagentStop hook never settled. The stuck `running` row is
    // the dead-agent signal the merge gate now refuses to advance through.
    markAgentRunRunning({
      targetDomain: domain,
      wave: "w1",
      agent: "a1",
      surfaceId: "surface-a",
    });
    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: assignmentTokenA,
      summary: "surface mostly covered",
      content: "# Handoff\n\nWrote handoff but died before settle",
    }));

    const runsBeforeMerge = readAgentRuns(domain);
    const latestA1 = [...runsBeforeMerge].reverse().find((run) => run.agent_id === "a1");
    assert.equal(latestA1.status, "running");

    const artifacts = loadWaveArtifacts(domain, 1);
    const readiness = buildWaveReadiness(artifacts, { domain });
    assert.equal(readiness.is_complete, false);
    // a1 is gated closed by the running-without-settle row.
    assert.ok(readiness.missing_agents.includes("a1"));
    // a2 is gated by the file-presence fallback (no handoff file on disk).
    assert.ok(readiness.missing_agents.includes("a2"));

    // mergeWaveHandoffsInternal puts the un-settled surfaces into
    // missing_surface_ids, so apply_wave_merge would refuse without force.
    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.ok(merge.missing_surface_ids.includes("surface-a"));
    assert.ok(merge.missing_surface_ids.includes("surface-b"));
    assert.equal(merge.completed_surface_ids.length, 0);
  });
});

test("assigned-only row (no SubagentStart hook) falls back to file-presence per Pact P2", () => {
  withTempHome(() => {
    const domain = "agent-runs-assigned-fallback.example.com";
    const start = driveWaveStart(domain, ["surface-a"]);
    const assignmentToken = start.assignments[0].handoff_token;

    // Wave start emitted an `assigned` row. The SubagentStart hook never
    // fired (legacy adapter, hook miss). The agent did write a handoff. The
    // gate falls back to file-presence and accepts the merge so deprecation-
    // window callers keep functioning.
    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: assignmentToken,
      summary: "legacy adapter, no start hook",
      content: "# Handoff\n\nlegacy body",
    }));
    const runs = readAgentRuns(domain);
    assert.equal(runs[runs.length - 1].status, "assigned");

    const artifacts = loadWaveArtifacts(domain, 1);
    const readiness = buildWaveReadiness(artifacts, { domain });
    assert.equal(readiness.is_complete, true);
    assert.deepEqual(readiness.received_agents, ["a1"]);
  });
});

test("AgentRun row in 'failed' state likewise keeps the merge gate closed", () => {
  withTempHome(() => {
    const domain = "agent-runs-failed.example.com";
    const start = driveWaveStart(domain, ["surface-a"]);
    const assignmentToken = start.assignments[0].handoff_token;

    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: assignmentToken,
      summary: "wrote handoff then failed before finalizing",
      content: "# Handoff\n\nbody",
    }));

    // Simulate the SubagentStop hook's failure path (e.g., missing technique
    // attempt log): markAgentRunTerminal appends a `failed` row. The latest
    // state row for (w1, a1, surface-a) is now `failed`, not `settled`.
    markAgentRunTerminal({
      targetDomain: domain,
      wave: "w1",
      agent: "a1",
      surfaceId: "surface-a",
      status: "failed",
      failureReason: "missing technique attempt log",
    });

    const runs = readAgentRuns(domain);
    const latest = runs[runs.length - 1];
    assert.equal(latest.status, "failed");
    assert.equal(latest.failure_reason, "missing technique attempt log");

    const artifacts = loadWaveArtifacts(domain, 1);
    const readiness = buildWaveReadiness(artifacts, { domain });
    assert.equal(readiness.is_complete, false);
    assert.deepEqual(readiness.missing_agents, ["a1"]);
  });
});

test("a fully driven wave yields N settled rows in agent-runs.jsonl", () => {
  withTempHome(() => {
    const domain = "agent-runs-full-wave.example.com";
    const surfaces = ["surface-a", "surface-b", "surface-c", "surface-d"];
    const start = driveWaveStart(domain, surfaces);

    const { loadWaveAssignments } = require("../mcp/lib/assignments.js");
    const { readHandoffSigningKey } = require("../mcp/lib/handoff-signing-key.js");
    const assignmentsInfo = loadWaveAssignments(domain, 1);
    const signingKey = readHandoffSigningKey(domain);

    for (let index = 0; index < surfaces.length; index += 1) {
      const surfaceId = surfaces[index];
      const agentLabel = `a${index + 1}`;
      const token = start.assignments[index].handoff_token;
      JSON.parse(writeWaveHandoff({
        target_domain: domain,
        wave: "w1",
        agent: agentLabel,
        surface_id: surfaceId,
        surface_status: "complete",
        handoff_token: token,
        summary: `surface ${surfaceId} covered`,
        chain_notes: [],
        content: `# Handoff ${agentLabel}\n\nbody`,
      }));
      const assignment = assignmentsInfo.assignmentByAgent.get(agentLabel);
      const handoffJson = JSON.parse(fs.readFileSync(
        path.join(sessionDir(domain), `handoff-w1-${agentLabel}.json`),
        "utf8",
      ));
      settleAgentRunFromHandoff({
        target_domain: domain,
        wave: "w1",
        agent: agentLabel,
        surface_id: surfaceId,
        assignment,
        handoff: handoffJson,
        signing_key: signingKey,
      }, { write: true });
    }

    const runs = readAgentRuns(domain);
    const settledRows = runs.filter((run) => run.status === "settled");
    assert.equal(settledRows.length, surfaces.length);
    const settledAgents = new Set(settledRows.map((run) => run.agent_id));
    for (let index = 0; index < surfaces.length; index += 1) {
      assert.ok(settledAgents.has(`a${index + 1}`), `agent a${index + 1} should be settled`);
    }

    // Sanity: each `settled` row links its handoff via signed_handoff metadata.
    for (const row of settledRows) {
      assert.equal(row.handoff_refs.length, 1);
      assert.equal(row.handoff_refs[0].kind, "signed_handoff");
      assert.equal(row.handoff_refs[0].provenance, "verified");
    }

    // The merge gate is fully open: applyWaveMerge produces a `merged` result.
    const mergeResult = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));
    assert.equal(mergeResult.status, "merged");
    assert.equal(mergeResult.merge.completed_surface_ids.length, surfaces.length);

    // agent-runs.jsonl on disk reflects every appended row.
    const jsonlPath = agentRunsJsonlPath(domain);
    const content = fs.readFileSync(jsonlPath, "utf8");
    const lines = content.split("\n").filter((line) => line.trim());
    assert.equal(lines.length, runs.length);
    assert.ok(runs.length >= surfaces.length * 2, "expect at least one assigned + one settled row per agent");
  });
});

test("missing AgentRun row falls back to file-presence per dual-write Pact P2", () => {
  withTempHome(() => {
    const domain = "agent-runs-dual-write-fallback.example.com";

    // Construct a wave through the normal path, then erase the AgentRun ledger
    // so the gate must rely on the file-presence fallback. This mirrors legacy
    // sessions and the rollout window when the ledger is empty.
    const started = driveWaveStart(domain, ["surface-a"]);
    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: started.assignments[0].handoff_token,
      summary: "legacy-session handoff",
      content: "# Handoff\n\nlegacy body",
    }));

    // Erase agent-runs.jsonl to simulate a legacy session with no ledger.
    const ledgerPath = agentRunsJsonlPath(domain);
    if (fs.existsSync(ledgerPath)) fs.rmSync(ledgerPath);

    const artifacts = loadWaveArtifacts(domain, 1);
    const readiness = buildWaveReadiness(artifacts, { domain });
    // File-presence fallback path: the handoff file is on disk, so readiness
    // reports the surface as received even without a `settled` ledger row.
    assert.equal(readiness.is_complete, true);
    assert.deepEqual(readiness.received_agents, ["a1"]);
  });
});

test("appendWaveAssignmentAgentRun stamps surface_id into input_refs for traceability", () => {
  withTempHome(() => {
    const domain = "agent-runs-traceability.example.com";
    appendWaveAssignmentAgentRun({
      targetDomain: domain,
      wave: "w1",
      agent: "a1",
      surfaceId: "surface-deep",
    });
    const runs = readAgentRuns(domain);
    assert.equal(runs.length, 1);
    assert.equal(runs[0].status, "assigned");
    assert.deepEqual(runs[0].input_refs, [{
      kind: "wave_surface",
      wave: "w1",
      surface_id: "surface-deep",
    }]);
  });
});
