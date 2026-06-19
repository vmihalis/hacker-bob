"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

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
  buildWaveHandoffsDocument,
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

test("AgentRun row in 'failed' state keeps the merge gate closed ONLY when no provenance-verified handoff exists on disk", () => {
  withTempHome(() => {
    const domain = "agent-runs-failed.example.com";
    driveWaveStart(domain, ["surface-a"]);

    // True-missing case: the agent died WITHOUT leaving a verified handoff on
    // disk (no writeWaveHandoff call here). The SubagentStop hook's failure
    // path appends a `failed` row. Since there is no settleable handoff, the
    // gate must stay closed — this is the genuine-failure behavior Step 2b
    // preserves (it only relaxes the gate when a verified handoff IS present).
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

// Step 2b — Test D (gate fallback): a stop-hook `failed` row written on top of a
// provenance-verified handoff must NOT poison the gate into reporting the agent
// as missing. buildWaveHandoffsDocument is the exact reader whose self-poison
// flip (RCA [3]) forced every subsequent finalize to block on missing_handoff.
test("Test D: provenance-verified handoff is honored even after a `failed` row, not pushed into missing_handoffs", () => {
  withTempHome(() => {
    const domain = "agent-runs-failed-but-verified.example.com";
    const start = driveWaveStart(domain, ["surface-a"]);
    const assignmentToken = start.assignments[0].handoff_token;

    // The agent DID write a cryptographically valid handoff.
    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: assignmentToken,
      summary: "fully covered, but the stop hook then wrote failed rows",
      content: "# Handoff\n\nbody",
    }));

    // The runaway stop-hook loop appended a `failed` row tagged
    // `missing_handoff` — the RCA [3] gate self-poison: finalize flipped to
    // missing_handoff even though a cryptographically valid handoff is on disk.
    // missing_handoff is a recoverable block (surface-agnostic) precisely
    // BECAUSE the on-disk HMAC re-validation below proves the run is settleable.
    markAgentRunTerminal({
      targetDomain: domain,
      wave: "w1",
      agent: "a1",
      surfaceId: "surface-a",
      status: "failed",
      blockCode: "missing_handoff",
      failureReason: "gate self-poisoned to missing_handoff despite a valid handoff on disk",
    });

    const latest = readAgentRuns(domain).slice(-1)[0];
    assert.equal(latest.status, "failed");

    // The gate must fall back to the verified handoff on disk: a1 is NOT in
    // missing_handoffs, and the structured handoff is surfaced instead.
    const doc = buildWaveHandoffsDocument(domain, [1]);
    assert.equal(doc.missing_handoffs.length, 0, "verified handoff must not be reported missing");
    assert.ok(doc.handoffs.some((h) => h.agent === "a1" && h.surface_id === "surface-a"));

    // Readiness and merge agree: the wave is complete and the surface merges.
    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.equal(readiness.is_complete, true);
    assert.deepEqual(readiness.received_agents, ["a1"]);
    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.deepEqual(merge.completed_surface_ids, ["surface-a"]);
    assert.equal(merge.missing_surface_ids.length, 0);
  });
});

// Step 2b negative control: a `failed` row with NO handoff on disk (the agent
// genuinely died) and a `failed` row with a FORGED handoff both stay gated
// closed. The verified-handoff relaxation must never accept unsigned/forged
// evidence.
test("Test D negative: a `failed` row with an unsigned/forged handoff stays in missing_handoffs", () => {
  withTempHome(() => {
    const domain = "agent-runs-failed-forged.example.com";
    driveWaveStart(domain, ["surface-a"]);

    // Write a handoff JSON that lacks valid HMAC provenance (forged).
    writeFileAtomic(
      path.join(sessionDir(domain), "handoff-w1-a1.json"),
      `${JSON.stringify({
        version: 1,
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        surface_status: "complete",
        provenance: "verified",
        summary: "forged handoff with no real signature",
      }, null, 2)}\n`,
    );

    markAgentRunTerminal({
      targetDomain: domain,
      wave: "w1",
      agent: "a1",
      surfaceId: "surface-a",
      status: "failed",
      failureReason: "agent died",
    });

    const doc = buildWaveHandoffsDocument(domain, [1]);
    assert.ok(
      doc.missing_handoffs.some((m) => m.agent === "a1"),
      "forged handoff must NOT be accepted by the verified-handoff fallback",
    );
    assert.ok(!doc.handoffs.some((h) => h.agent === "a1"));
  });
});

// Step 2a — Test E (bounded escape): the stop hook must not loop forever
// appending `failed` rows on a recoverable block. After TERMINAL_RETRY_CAP (3)
// prior `failed` rows, the next stop appends exactly one labelled `abandoned`
// row and exits 0 — no 4th `failed` row, no exit-2 loop.
function runStopHook({ domain, tempHome, marker }) {
  const hookPath = path.join(__dirname, "..", ".claude", "hooks", "agent-run-stop.js");
  const stdin = JSON.stringify({
    last_assistant_message: `Done.\n\nBOB_AGENT_RUN_DONE ${JSON.stringify(marker)}\n`,
  });
  return spawnSync(process.execPath, [hookPath], {
    input: stdin,
    encoding: "utf8",
    env: {
      ...process.env,
      HOME: tempHome,
      BOB_PROJECT_DIR: path.join(__dirname, ".."),
    },
  });
}

test("Test E: stop hook escapes a recoverable block after the retry cap with one `abandoned` row, not a 4th `failed`", () => {
  withTempHome((tempHome) => {
    const domain = "agent-runs-bounded-escape.example.com";
    const start = driveWaveStart(domain, ["lead-a"]);
    const assignmentToken = start.assignments[0].handoff_token;
    const marker = {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "lead-a",
    };

    // The agent wrote a valid handoff but never logged a technique attempt
    // (attempt_log_required defaults to true), so finalize returns
    // `missing_technique_attempt_log`. This is recoverable ONLY because the
    // surface is a promoted-lead surface (id "lead-*"), where the genuine
    // tooling gap lives. An ordinary "surface-*" assignment with the same block
    // stays terminal — see the ordinary-surface control below.
    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "lead-a",
      surface_status: "complete",
      handoff_token: assignmentToken,
      summary: "covered but could not log a technique attempt on this surface",
      content: "# Handoff\n\nbody",
    }));

    // Seed exactly TERMINAL_RETRY_CAP (3) prior `failed` rows for this run, as
    // the runaway loop would have produced.
    for (let i = 0; i < 3; i += 1) {
      markAgentRunTerminal({
        targetDomain: domain,
        wave: "w1",
        agent: "a1",
        surfaceId: "lead-a",
        status: "failed",
        blockCode: "missing_technique_attempt_log",
        failureKind: "recoverable_tooling_gap",
        failureReason: "missing technique attempt log",
      });
    }
    const failedBefore = readAgentRuns(domain).filter((r) => r.agent_id === "a1" && r.status === "failed").length;
    assert.equal(failedBefore, 3);

    const result = runStopHook({ domain, tempHome, marker });

    // Clean terminal: exit 0, not the exit-2 retry loop.
    assert.equal(result.status, 0, `hook stdout=${result.stdout} stderr=${result.stderr}`);

    const runsAfter = readAgentRuns(domain);
    const failedAfter = runsAfter.filter((r) => r.agent_id === "a1" && r.status === "failed").length;
    const abandonedAfter = runsAfter.filter((r) => r.agent_id === "a1" && r.status === "abandoned");

    // No 4th `failed` row was appended.
    assert.equal(failedAfter, 3, "hook must not append a 4th failed row past the cap");
    // Exactly one labelled `abandoned` row terminates the run.
    assert.equal(abandonedAfter.length, 1);
    assert.equal(abandonedAfter[0].block_code, "missing_technique_attempt_log");
    assert.equal(abandonedAfter[0].failure_kind, "recoverable_tooling_gap");
  });
});

test("Test E control: below the cap the stop hook still writes a `failed` row and exits non-zero", () => {
  withTempHome((tempHome) => {
    const domain = "agent-runs-below-cap.example.com";
    const start = driveWaveStart(domain, ["lead-a"]);
    const assignmentToken = start.assignments[0].handoff_token;
    const marker = {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "lead-a",
    };

    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "lead-a",
      surface_status: "complete",
      handoff_token: assignmentToken,
      summary: "covered but could not log a technique attempt on this surface",
      content: "# Handoff\n\nbody",
    }));

    // No prior failed rows: the first recoverable block still records a failed
    // row (so the merge gate sees a terminal state) and exits 2.
    const result = runStopHook({ domain, tempHome, marker });
    assert.equal(result.status, 2, `expected exit 2, stdout=${result.stdout} stderr=${result.stderr}`);

    const runsAfter = readAgentRuns(domain);
    const failed = runsAfter.filter((r) => r.agent_id === "a1" && r.status === "failed");
    assert.equal(failed.length, 1);
    // The failed row is tagged so the retry counter / audit can classify it.
    assert.equal(failed[0].block_code, "missing_technique_attempt_log");
    assert.equal(failed[0].failure_kind, "recoverable_tooling_gap");
    assert.equal(runsAfter.filter((r) => r.agent_id === "a1" && r.status === "abandoned").length, 0);
  });
});

// Step 2b — surface-scoping control: a `missing_technique_attempt_log` terminal
// row is relaxed by a verified handoff ONLY for a promoted-lead ("lead-*")
// surface, where the genuine tooling gap lives. The SAME block on an ordinary
// "surface-*" assignment must stay gated closed even with a provenance-valid
// handoff on disk — otherwise an evaluator could skip the registry-enforced
// attempt_log_required control and still merge via the abandoned +
// verified-handoff path. This pins the merge-gate half of the bypass closure
// (the security-critical path); the stop-hook half is scoped in
// agent-run-stop.js isRecoverableBlock.
test("Test E2: missing_technique_attempt_log is relaxed for lead-* but NOT for an ordinary surface", () => {
  withTempHome(() => {
    const domain = "agent-runs-technique-scope.example.com";
    const start = driveWaveStart(domain, ["surface-a", "lead-b"]);
    const tokenBySurface = new Map(start.assignments.map((a) => [a.surface_id, a.handoff_token]));

    // Both agents wrote a cryptographically valid handoff, then a stop-hook
    // `abandoned` row tagged missing_technique_attempt_log was appended.
    for (const [agent, surfaceId] of [["a1", "surface-a"], ["a2", "lead-b"]]) {
      JSON.parse(writeWaveHandoff({
        target_domain: domain,
        wave: "w1",
        agent,
        surface_id: surfaceId,
        surface_status: "complete",
        handoff_token: tokenBySurface.get(surfaceId),
        summary: "covered but the technique-attempt log was not written",
        content: "# Handoff\n\nbody",
      }));
      markAgentRunTerminal({
        targetDomain: domain,
        wave: "w1",
        agent,
        surfaceId,
        status: "abandoned",
        blockCode: "missing_technique_attempt_log",
        failureKind: "recoverable_tooling_gap",
        failureReason: "missing technique attempt log",
      });
    }

    const doc = buildWaveHandoffsDocument(domain, [1]);
    // Ordinary surface stays missing (control enforced); lead surface is honored.
    assert.ok(
      doc.missing_handoffs.some((m) => m.agent === "a1" && m.surface_id === "surface-a"),
      "ordinary surface must stay missing (attempt_log_required not bypassed)",
    );
    assert.ok(
      doc.handoffs.some((h) => h.agent === "a2" && h.surface_id === "lead-b"),
      "promoted-lead surface's verified handoff must be honored",
    );
    assert.ok(!doc.handoffs.some((h) => h.agent === "a1"));

    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.ok(merge.missing_surface_ids.includes("surface-a"));
    assert.ok(merge.completed_surface_ids.includes("lead-b"));
  });
});

// Step 2b — scoping control: the verified-handoff relaxation overrides ONLY
// recoverable block_codes. A non-recoverable blocker such as
// `missing_oss_coverage` (an OSS surface marked complete with no coverage) must
// keep the surface gated closed even when a provenance-valid handoff sits on
// disk — otherwise a terminal finalize failure no longer prevents the merge.
test("Test F: a non-recoverable missing_oss_coverage failure is NOT relaxed by a verified handoff", () => {
  withTempHome(() => {
    const domain = "agent-runs-nonrecoverable-blocker.example.com";
    const start = driveWaveStart(domain, ["surface-a"]);
    const assignmentToken = start.assignments[0].handoff_token;

    // A cryptographically valid handoff IS on disk.
    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: assignmentToken,
      summary: "claims complete but no coverage rows or findings were recorded",
      content: "# Handoff\n\nbody",
    }));

    // The finalize gate recorded a terminal, non-recoverable blocker.
    markAgentRunTerminal({
      targetDomain: domain,
      wave: "w1",
      agent: "a1",
      surfaceId: "surface-a",
      status: "failed",
      blockCode: "missing_oss_coverage",
      failureReason: "OSS surface marked complete with zero coverage and zero findings",
    });

    // The verified handoff must NOT relax a non-recoverable blocker: the agent
    // stays in missing_handoffs and the surface does not merge.
    const doc = buildWaveHandoffsDocument(domain, [1]);
    assert.ok(
      doc.missing_handoffs.some((m) => m.agent === "a1" && m.surface_id === "surface-a"),
      "missing_oss_coverage must keep the agent in missing_handoffs despite a valid handoff",
    );
    assert.ok(!doc.handoffs.some((h) => h.agent === "a1"));

    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.equal(readiness.is_complete, false);
    assert.ok(!readiness.received_agents.includes("a1"));

    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.ok(merge.missing_surface_ids.includes("surface-a"));
    assert.equal(merge.completed_surface_ids.length, 0);
  });
});
