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
} = require("../mcp/core/io/paths.js");
const {
  readAgentRuns,
  appendWaveAssignmentAgentRun,
  markAgentRunTerminal,
  settleAgentRunFromHandoff,
  syntheticTaskIdForWaveAssignment,
} = require("../mcp/core/session/agent-runs.js");
const {
  buildWaveHandoffsDocument,
  buildWaveReadiness,
  loadWaveArtifacts,
  mergeWaveHandoffsInternal,
} = require("../mcp/core/waves/wave-handoff-store.js");
const {
  startWave,
  applyWaveMerge,
  writeWaveHandoff,
} = require("../mcp/core/waves/waves.js");
const {
  initSession,
  advanceSession,
} = require("../mcp/core/session/session-state.js");
const {
  writeFileAtomic,
} = require("../mcp/core/io/storage.js");
const {
  logTechniqueAttempt,
} = require("../mcp/core/dispatch/technique-packs.js");
const {
  evaluateAgentCompletion,
} = require("../mcp/core/session/agent-run-completion.js");

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
    const { loadWaveAssignments } = require("../mcp/core/session/assignments.js");
    const { readHandoffSigningKey } = require("../mcp/core/ledger-integrity/handoff-signing-key.js");
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

test("a started (running) agent with a provenance-valid handoff merges via the lifecycle gate, not file-presence", () => {
  withTempHome(() => {
    const domain = "agent-runs-started-merges.example.com";
    const start = driveWaveStart(domain, ["surface-a", "surface-b"]);
    const assignmentTokenA = start.assignments[0].handoff_token;
    const { markAgentRunRunning } = require("../mcp/core/session/agent-runs.js");

    // Agent a1's first surface-scoped tool call recorded `running` (universal
    // MCP-side start-recording, or the SubagentStart hook), and it wrote a
    // provenance-valid handoff. No `settled` row exists (e.g. an adapter with no
    // stop hook). The merge gate accepts a1 on the started lifecycle PLUS full
    // on-disk payload+provenance validation — the existence boolean is no longer
    // the decider.
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
      summary: "surface fully covered; started but never settled",
      content: "# Handoff\n\nWrote handoff, no stop hook fired",
    }));
    // The started run logged a real technique attempt, so its handoff carries
    // the attempt_log_required evidence the merge gate requires.
    JSON.parse(logTechniqueAttempt({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      pack_id: "generic-rest-api",
      status: "attempted",
      outcome: "no_finding",
      evidence: "probed REST authz across two accounts on surface-a; no IDOR observed",
    }));

    const runsBeforeMerge = readAgentRuns(domain);
    const latestA1 = [...runsBeforeMerge].reverse().find((run) => run.agent_id === "a1");
    assert.equal(latestA1.status, "running");

    const artifacts = loadWaveArtifacts(domain, 1);
    const readiness = buildWaveReadiness(artifacts, { domain });
    // a1 is RECEIVED on the started lifecycle (no settled row required).
    assert.ok(readiness.received_agents.includes("a1"));
    assert.ok(!readiness.missing_agents.includes("a1"));
    // a2 only ever got its `assigned` row and wrote no handoff -> missing.
    assert.ok(readiness.missing_agents.includes("a2"));
    assert.equal(readiness.is_complete, false);

    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.ok(merge.completed_surface_ids.includes("surface-a"));
    assert.ok(merge.missing_surface_ids.includes("surface-b"));
  });
});

test("a started (running) agent with NO handoff on disk stays missing (genuine died-mid-flight)", () => {
  withTempHome(() => {
    const domain = "agent-runs-started-no-handoff.example.com";
    driveWaveStart(domain, ["surface-a"]);
    const { markAgentRunRunning } = require("../mcp/core/session/agent-runs.js");

    // a1 started but died before writing any handoff. The started lifecycle is
    // present, but with no handoff to validate the surface stays missing.
    markAgentRunRunning({ targetDomain: domain, wave: "w1", agent: "a1", surfaceId: "surface-a" });

    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.equal(readiness.is_complete, false);
    assert.deepEqual(readiness.missing_agents, ["a1"]);
    assert.ok(!readiness.received_agents.includes("a1"));

    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.ok(merge.missing_surface_ids.includes("surface-a"));
    assert.equal(merge.completed_surface_ids.length, 0);
  });
});

test("a started (running) agent with a forged/unsigned handoff stays out of received (validation, not presence)", () => {
  withTempHome(() => {
    const domain = "agent-runs-started-forged.example.com";
    driveWaveStart(domain, ["surface-a"]);
    const { markAgentRunRunning } = require("../mcp/core/session/agent-runs.js");
    markAgentRunRunning({ targetDomain: domain, wave: "w1", agent: "a1", surfaceId: "surface-a" });

    // A handoff JSON with no valid HMAC provenance is on disk. The started
    // lifecycle does NOT wave it through — full provenance validation rejects it.
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

    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.ok(!readiness.received_agents.includes("a1"));
    assert.ok(readiness.invalid_agents.includes("a1"));
    assert.equal(readiness.is_complete, false);

    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.ok(merge.missing_surface_ids.includes("surface-a"));
    assert.equal(merge.completed_surface_ids.length, 0);
  });
});

// The assigned-only (fallback) acceptance branch is subject to the same
// branch-uniform technique-attempt requirement as the started branch. An
// assigned-only run that wrote a provenance-valid handoff AND logged a matching
// completion-status technique attempt still merges — the on-disk-handoff
// fail-safe is preserved for a compliant handoff even when the start record was
// lost.
test("assigned-only row with a valid handoff AND a matching technique attempt merges (fail-safe preserved)", () => {
  withTempHome(() => {
    const domain = "agent-runs-assigned-fallback-attempt.example.com";
    const start = driveWaveStart(domain, ["surface-a"]);
    const assignmentToken = start.assignments[0].handoff_token;

    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: assignmentToken,
      summary: "assigned-only run, start never recorded, attempt logged",
      content: "# Handoff\n\nassigned-only body",
    }));
    JSON.parse(logTechniqueAttempt({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      pack_id: "generic-rest-api",
      status: "attempted",
      outcome: "no_finding",
      evidence: "probed REST authz across two accounts on surface-a; no IDOR observed",
    }));
    const runs = readAgentRuns(domain);
    assert.equal(runs[runs.length - 1].status, "assigned");

    const artifacts = loadWaveArtifacts(domain, 1);
    const readiness = buildWaveReadiness(artifacts, { domain });
    assert.equal(readiness.is_complete, true);
    assert.deepEqual(readiness.received_agents, ["a1"]);

    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.ok(merge.completed_surface_ids.includes("surface-a"));
    assert.equal(merge.missing_surface_ids.length, 0);
  });
});

// The changed permanent-fail-safe semantics: an assigned-only (fallback) run on
// an attempt-log-required (web) surface that wrote a provenance-valid handoff but
// logged NO technique attempt is now REFUSED at readiness and merge. The
// fallback branch no longer waves a lazy no-attempt handoff through — it is
// branch-uniform with the started branch.
test("assigned-only row with a valid handoff but NO technique attempt is refused at merge (web surface)", () => {
  withTempHome(() => {
    const domain = "agent-runs-assigned-fallback-no-attempt.example.com";
    const start = driveWaveStart(domain, ["surface-a"]);
    const assignmentToken = start.assignments[0].handoff_token;

    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: assignmentToken,
      summary: "assigned-only run, start never recorded, no attempt logged",
      content: "# Handoff\n\nassigned-only body",
    }));
    const runs = readAgentRuns(domain);
    assert.equal(runs[runs.length - 1].status, "assigned");

    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.ok(!readiness.received_agents.includes("a1"));
    assert.ok(readiness.missing_agents.includes("a1"));
    assert.equal(readiness.is_complete, false);

    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.ok(merge.missing_surface_ids.includes("surface-a"));
    assert.equal(merge.completed_surface_ids.length, 0);
  });
});

// SC surfaces carry attempt_log_required=false, so the merge-side technique-log
// requirement does not apply: an assigned-only (fallback) SC run with a valid
// handoff and NO technique attempt still merges. The independent SC
// completion-substance depth gate is unaffected (partial here needs no
// substance).
test("assigned-only SC surface with a valid handoff and NO technique attempt merges (attempt_log_required=false)", () => {
  withTempHome(() => {
    const domain = "agent-runs-assigned-fallback-sc.example.com";
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
    seedAttackSurfaces(domain, [{
      id: "surface-sc",
      surface_type: "smart_contract",
      chain_family: "evm",
      hosts: [`https://${domain}`],
      priority: "HIGH",
    }]);
    JSON.parse(advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER" }));
    const start = JSON.parse(startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-sc" }],
    }));

    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-sc",
      surface_status: "partial",
      handoff_token: start.assignments[0].handoff_token,
      summary: "SC surface assigned-only, partial coverage, no attempt logged",
      content: "# Handoff\n\nsc body",
      blocked_harness_runs: [{
        kind: "foundry_fork",
        harness: "forge test --fork-url <archive-rpc>",
        reason: "no archive RPC available to fork mainnet for the redeem-path invariant",
      }],
    }));
    const runs = readAgentRuns(domain);
    assert.equal(runs[runs.length - 1].status, "assigned");

    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.ok(readiness.received_agents.includes("a1"));
    assert.equal(readiness.is_complete, true);

    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.ok(merge.partial_surface_ids.includes("surface-sc"));
    assert.equal(merge.missing_surface_ids.length, 0);
  });
});

// A promoted-lead ("lead-*") surface is relaxed on the fallback branch the same
// way it is on the started and recovery branches: an assigned-only lead-* run
// with a valid handoff and NO technique attempt merges (the genuine tooling gap
// where an attempt cannot always be logged).
test("assigned-only lead-* surface with a valid handoff and NO technique attempt merges (relaxed)", () => {
  withTempHome(() => {
    const domain = "agent-runs-assigned-fallback-lead.example.com";
    const start = driveWaveStart(domain, ["lead-a"]);

    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "lead-a",
      surface_status: "complete",
      handoff_token: start.assignments[0].handoff_token,
      summary: "promoted-lead surface, assigned-only, no technique attempt loggable",
      content: "# Handoff\n\nlead body",
    }));
    const runs = readAgentRuns(domain);
    assert.equal(runs[runs.length - 1].status, "assigned");

    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.ok(readiness.received_agents.includes("a1"));
    assert.equal(readiness.is_complete, true);

    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.ok(merge.completed_surface_ids.includes("lead-a"));
    assert.equal(merge.missing_surface_ids.length, 0);
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

    const { loadWaveAssignments } = require("../mcp/core/session/assignments.js");
    const { readHandoffSigningKey } = require("../mcp/core/ledger-integrity/handoff-signing-key.js");
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

test("a missing AgentRun row defers to on-disk handoff validation (permanent fail-safe)", () => {
  withTempHome(() => {
    const domain = "agent-runs-dual-write-fallback.example.com";

    // Construct a wave through the normal path, then erase the AgentRun ledger
    // so the gate must rely on the on-disk handoff. This mirrors a session whose
    // ledger is absent (an empty/lost ledger).
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
    // The merge-side technique-log check keys on the handoff surface_id + the
    // on-disk technique-attempts.jsonl, both independent of the agent-runs
    // ledger. A real handoff for a require-attempts surface that logged a real
    // attempt still merges even after the ledger is lost — the null-ledger case
    // does not over-gate beyond what attempt_log_required dictates.
    JSON.parse(logTechniqueAttempt({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      pack_id: "generic-rest-api",
      status: "attempted",
      outcome: "no_finding",
      evidence: "probed REST authz across two accounts on surface-a; no IDOR observed",
    }));

    // Erase agent-runs.jsonl to simulate a legacy session with no ledger.
    const ledgerPath = agentRunsJsonlPath(domain);
    if (fs.existsSync(ledgerPath)) fs.rmSync(ledgerPath);

    const artifacts = loadWaveArtifacts(domain, 1);
    const readiness = buildWaveReadiness(artifacts, { domain });
    // Degraded path: with no ledger the gate validates the on-disk handoff, so
    // readiness reports the surface as received even without a `settled` row.
    assert.equal(readiness.is_complete, true);
    assert.deepEqual(readiness.received_agents, ["a1"]);
  });
});

// Depth-gate composition. The smart_contract completion-substance gate lives in
// validateWaveHandoffPayload, which fires at MERGE for every accept-eligible
// run. A `started` (running) run is NOT exempt: it still flows through that
// validation, so an SC handoff that claims `complete` without a finding or a
// substantive bypass_attempt is rejected at merge even though the agent provably
// started. This pins that universal start-recording did NOT weaken the depth
// gate. The handoff is crafted + re-signed directly because bob_write_wave_handoff
// refuses an SC-complete-no-substance handoff at WRITE time (the same gate's
// other enforcement point), so it can never reach disk through the tool.
test("depth gate: a started run's SC handoff lacking completion-substance is rejected at merge", () => {
  withTempHome(() => {
    const domain = "agent-runs-started-sc-depth.example.com";
    // Seed a smart_contract surface so the assignment file captures
    // surface_type=smart_contract (the gate's tamper-resistant input).
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
    seedAttackSurfaces(domain, [{
      id: "surface-sc",
      surface_type: "smart_contract",
      chain_family: "evm",
      hosts: [`https://${domain}`],
      priority: "HIGH",
    }]);
    JSON.parse(advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER" }));
    const start = JSON.parse(startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-sc" }],
    }));

    const { markAgentRunRunning } = require("../mcp/core/session/agent-runs.js");
    const { signHandoffProvenance } = require("../mcp/core/waves/wave-handoff-contracts.js");
    const { loadWaveAssignments } = require("../mcp/core/session/assignments.js");
    const { readHandoffSigningKey } = require("../mcp/core/ledger-integrity/handoff-signing-key.js");

    markAgentRunRunning({ targetDomain: domain, wave: "w1", agent: "a1", surfaceId: "surface-sc" });

    // First write a VALID SC-complete handoff (with a substantive bypass_attempt)
    // through the tool to obtain a correctly-shaped, signed handoff, then strip
    // the substance and re-sign so a SIGNED but substance-free SC-complete
    // handoff sits on disk.
    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-sc",
      surface_status: "complete",
      handoff_token: start.assignments[0].handoff_token,
      summary: "exercised the redeem path against the collateral invariant",
      content: "# Handoff\n\nbody",
      bypass_attempts: [{
        condition: "permissionless collateral redemption bypasses the solvency check",
        attempt_summary: "Forked mainnet and called redeem() with a crafted oracle update to break the solvency invariant; reverted, no break.",
        outcome: "no_finding",
      }],
    }));

    const assignment = loadWaveAssignments(domain, 1).assignmentByAgent.get("a1");
    const signingKey = readHandoffSigningKey(domain);
    const handoffPath = path.join(sessionDir(domain), "handoff-w1-a1.json");
    const signed = JSON.parse(fs.readFileSync(handoffPath, "utf8"));
    // Strip the substance and the existing provenance fields, then re-sign.
    delete signed.bypass_attempts;
    delete signed.provenance_model;
    delete signed.provenance_signature;
    delete signed.provenance_assignment_hash;
    const reSigned = signHandoffProvenance(signed, signingKey, { assignment });
    writeFileAtomic(handoffPath, `${JSON.stringify(reSigned, null, 2)}\n`);

    // The re-signed handoff is SC-complete with no finding and no substantive
    // bypass: the merge-time depth gate rejects it even for a started run.
    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.ok(!readiness.received_agents.includes("a1"));
    assert.ok(readiness.invalid_agents.includes("a1"));

    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.ok(merge.missing_surface_ids.includes("surface-sc"));
    assert.equal(merge.completed_surface_ids.length, 0);
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
    // A compliant handoff also logged its technique attempt, so the recovery
    // branch's branch-uniform technique-log requirement is satisfied and the
    // surface merges (the recovery is about the runaway-loop missing_handoff
    // poisoning, not a technique-log gap).
    JSON.parse(logTechniqueAttempt({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      pack_id: "generic-rest-api",
      status: "attempted",
      outcome: "no_finding",
      evidence: "probed REST authz across two accounts on surface-a; no IDOR observed",
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

// Test D + recorded finding: the verified-handoff recovery path must validate a
// FINDING-BEARING handoff against the run's actual recorded findings, not an
// empty set. Before the fix, verifiedHandoffOnDiskForAssignment passed
// findingsForRun:[] so a bypass_attempts entry citing a recorded finding_id
// threw "does not match any recorded finding", the recovery returned false, and
// the agent that found the bug was wrongly pushed into missing — the same
// readiness deadlock, on the recovery path.
test("Test D + finding: a finding-bearing handoff is honored on the recovery path", () => {
  withTempHome(() => {
    const recordCandidateClaimTool = require("../mcp/tools/record-candidate-claim.js");
    const domain = "agent-runs-failed-but-verified-finding.example.com";
    const start = driveWaveStart(domain, ["surface-a"]);
    const assignmentToken = start.assignments[0].handoff_token;

    const recorded = JSON.parse(recordCandidateClaimTool.handler({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      title: "Reward accounting lets a donor skew the split",
      severity: "high",
      cwe: "CWE-682",
      endpoint: "onchain://ethereum-mainnet/0xDf1AC1AC255d91F5f4B1E3B4Aef57c5350F64C7A",
      description: "Donating to the distributor before distribution swings the pool share.",
      proof_of_concept: "Mainnet-fork test donates aUSDC, then distributeRewards redirects emissions.",
      response_evidence: "Fork run shows the USDC pool jump from ~1.2% to ~98.4% of the daily window.",
      impact: "Permissionless redirection of ~2864 MOR/day from honest depositors.",
      validated: true,
      auth_profile: "attacker-1",
      cvss_inputs: { attack_vector: "network", privileges_required: "none", confidentiality: "none", integrity: "high" },
    }));
    assert.match(recorded.finding_id, /^F-[1-9][0-9]*$/);

    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: assignmentToken,
      summary: "found a reward-split manipulation; recorded as a finding",
      content: "# Handoff\n\nbody",
      bypass_attempts: [{
        condition: "permissionless reward-split manipulation via pre-distribution donation",
        attempt_summary: "Mainnet-fork PoC donates aUSDC before distributeRewards and confirms the emission redirect.",
        outcome: "finding_recorded",
        finding_id: recorded.finding_id,
      }],
    }));
    // A recorded finding does NOT satisfy the technique-attempt requirement (the
    // merge-side check reads technique-attempts.jsonl, not findings); the
    // compliant run also logged a technique attempt, so the recovery branch's
    // branch-uniform technique-log requirement is met.
    JSON.parse(logTechniqueAttempt({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      pack_id: "generic-rest-api",
      status: "validated",
      outcome: "finding_recorded",
      evidence: "Mainnet-fork PoC redirected the reward split; recorded as a finding.",
    }));

    markAgentRunTerminal({
      targetDomain: domain,
      wave: "w1",
      agent: "a1",
      surfaceId: "surface-a",
      status: "failed",
      blockCode: "missing_handoff",
      failureReason: "gate self-poisoned despite a valid finding-bearing handoff on disk",
    });

    const doc = buildWaveHandoffsDocument(domain, [1]);
    assert.equal(doc.missing_handoffs.length, 0, "finding-bearing verified handoff must not be reported missing");
    assert.ok(doc.handoffs.some((h) => h.agent === "a1" && h.surface_id === "surface-a"));

    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.equal(readiness.is_complete, true);
    assert.deepEqual(readiness.received_agents, ["a1"]);
    assert.deepEqual(readiness.invalid_agents, []);
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

// Recovery-branch parity: a recovered terminal row (failed + recoverable
// missing_handoff + a provenance-verified handoff on disk) on an
// attempt-log-required (web) surface is subject to the same branch-uniform
// technique-attempt requirement as the started and fallback branches. With NO
// technique attempt logged, the surface is REFUSED at readiness and merge — the
// runaway-loop missing_handoff poisoning would otherwise be recovered, but a
// lazy no-attempt handoff is not honored. buildWaveHandoffsDocument still
// surfaces the on-disk handoff (its readout is consumed by the finalize gate,
// which applies the technique check itself); the refusal lives at the
// authoritative readiness + merge gates that apply_wave_merge consults.
test("recovery branch refuses a web-surface handoff with NO technique attempt", () => {
  withTempHome(() => {
    const domain = "agent-runs-recovery-no-attempt.example.com";
    const start = driveWaveStart(domain, ["surface-a"]);
    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: start.assignments[0].handoff_token,
      summary: "recovered terminal row, valid handoff, no technique attempt",
      content: "# Handoff\n\nbody",
    }));
    markAgentRunTerminal({
      targetDomain: domain,
      wave: "w1",
      agent: "a1",
      surfaceId: "surface-a",
      status: "failed",
      blockCode: "missing_handoff",
      failureReason: "runaway loop poisoned the row to missing_handoff",
    });

    // The document readout is unchanged: it still surfaces the on-disk handoff.
    const doc = buildWaveHandoffsDocument(domain, [1]);
    assert.ok(doc.handoffs.some((h) => h.agent === "a1" && h.surface_id === "surface-a"));

    // The authoritative gates refuse the no-attempt handoff on the recovery branch.
    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.ok(!readiness.received_agents.includes("a1"));
    assert.ok(readiness.missing_agents.includes("a1"));
    assert.equal(readiness.is_complete, false);

    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.ok(merge.missing_surface_ids.includes("surface-a"));
    assert.equal(merge.completed_surface_ids.length, 0);
  });
});

// Recovery-branch lead-* relaxation: a recovered terminal row on a promoted-lead
// ("lead-*") surface with a valid handoff and NO technique attempt MERGES — the
// same lead-* relaxation the fallback and started branches apply, composed via
// the shared isRecoverableBlockCode predicate.
test("recovery branch relaxes a lead-* surface handoff with NO technique attempt", () => {
  withTempHome(() => {
    const domain = "agent-runs-recovery-lead.example.com";
    const start = driveWaveStart(domain, ["lead-a"]);
    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "lead-a",
      surface_status: "complete",
      handoff_token: start.assignments[0].handoff_token,
      summary: "promoted-lead surface, recovered terminal row, no attempt loggable",
      content: "# Handoff\n\nlead body",
    }));
    markAgentRunTerminal({
      targetDomain: domain,
      wave: "w1",
      agent: "a1",
      surfaceId: "lead-a",
      status: "abandoned",
      blockCode: "missing_technique_attempt_log",
      failureKind: "recoverable_tooling_gap",
      failureReason: "missing technique attempt log",
    });

    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.ok(readiness.received_agents.includes("a1"));
    assert.equal(readiness.is_complete, true);

    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.ok(merge.completed_surface_ids.includes("lead-a"));
    assert.equal(merge.missing_surface_ids.length, 0);
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

// The crash window: a started (running) run wrote a provenance-valid handoff but
// died before SubagentStop, so the finalize gate's attempt_log_required control
// never ran. On an ordinary surface-* with no matching technique attempt, the
// merge + readiness gates now refuse the handoff (the residual the finalize gate
// alone could not close — it never executed for this run).
test("crash window: a started run's valid handoff with NO technique attempt is refused at merge (ordinary surface)", () => {
  withTempHome(() => {
    const domain = "agent-runs-crash-window-refused.example.com";
    const start = driveWaveStart(domain, ["surface-a"]);
    const { markAgentRunRunning } = require("../mcp/core/session/agent-runs.js");

    // a1 started (running) and wrote a valid handoff, but logged no technique
    // attempt and never reached SubagentStop (no terminal row).
    markAgentRunRunning({ targetDomain: domain, wave: "w1", agent: "a1", surfaceId: "surface-a" });
    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: start.assignments[0].handoff_token,
      summary: "started, handoff written, crashed before any technique attempt was logged",
      content: "# Handoff\n\ncrash-window body",
    }));
    assert.equal(readAgentRuns(domain).slice(-1)[0].status, "running");

    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.ok(!readiness.received_agents.includes("a1"));
    assert.ok(readiness.missing_agents.includes("a1"));
    assert.equal(readiness.is_complete, false);

    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.ok(merge.missing_surface_ids.includes("surface-a"));
    assert.equal(merge.completed_surface_ids.length, 0);
  });
});

// The same crash window on a promoted-lead surface (id "lead-*") is RELAXED: a
// promoted lead cannot always log a technique attempt, so the merge gate honors
// its provenance-valid handoff. This is the exact lead-* relaxation the
// closed-terminal path uses (isRecoverableBlockCode), composed on the started
// branch so the two gates agree.
test("crash window: a started run's valid handoff with NO technique attempt MERGES for a lead-* surface (relaxed)", () => {
  withTempHome(() => {
    const domain = "agent-runs-crash-window-lead.example.com";
    const start = driveWaveStart(domain, ["lead-a"]);
    const { markAgentRunRunning } = require("../mcp/core/session/agent-runs.js");

    markAgentRunRunning({ targetDomain: domain, wave: "w1", agent: "a1", surfaceId: "lead-a" });
    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "lead-a",
      surface_status: "complete",
      handoff_token: start.assignments[0].handoff_token,
      summary: "promoted-lead surface, started, handoff written, no technique attempt loggable",
      content: "# Handoff\n\nlead crash-window body",
    }));

    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.ok(readiness.received_agents.includes("a1"));
    assert.ok(!readiness.missing_agents.includes("a1"));
    assert.equal(readiness.is_complete, true);

    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.ok(merge.completed_surface_ids.includes("lead-a"));
    assert.equal(merge.missing_surface_ids.length, 0);
  });
});

// A started run with a matching completion-status technique attempt merges: the
// requirement is satisfied, not bypassed. Pins that the new check refuses only
// the genuinely technique-log-less crash, never a real evaluated surface.
test("crash window: a started run with a matching technique attempt MERGES (ordinary surface)", () => {
  withTempHome(() => {
    const domain = "agent-runs-crash-window-attempt.example.com";
    const start = driveWaveStart(domain, ["surface-a"]);
    const { markAgentRunRunning } = require("../mcp/core/session/agent-runs.js");

    markAgentRunRunning({ targetDomain: domain, wave: "w1", agent: "a1", surfaceId: "surface-a" });
    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: start.assignments[0].handoff_token,
      summary: "started, handoff written, technique attempt logged",
      content: "# Handoff\n\nattempt-present body",
    }));
    JSON.parse(logTechniqueAttempt({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      pack_id: "generic-rest-api",
      status: "attempted",
      outcome: "no_finding",
      evidence: "probed REST authz across two accounts on surface-a; no IDOR observed",
    }));

    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.ok(readiness.received_agents.includes("a1"));
    assert.equal(readiness.is_complete, true);

    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.ok(merge.completed_surface_ids.includes("surface-a"));
    assert.equal(merge.missing_surface_ids.length, 0);
  });
});

// The finalize gate and the merge gate agree: both consult the SAME shared
// evaluateTechniqueAttemptRequirement. An ordinary started run with no attempt
// blocks finalize with block_code missing_technique_attempt_log AND is bucketed
// missing at merge; logging a matching attempt flips both to pass. This also
// pins that the finalize gate keeps its own block_code (it is NOT relabeled to
// missing_handoff by the merge-side check).
test("the finalize gate and the merge gate agree on the technique-attempt requirement", () => {
  withTempHome(() => {
    const domain = "agent-runs-gates-agree.example.com";
    const start = driveWaveStart(domain, ["surface-a"]);
    const { markAgentRunRunning } = require("../mcp/core/session/agent-runs.js");

    markAgentRunRunning({ targetDomain: domain, wave: "w1", agent: "a1", surfaceId: "surface-a" });
    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: start.assignments[0].handoff_token,
      summary: "started, valid handoff, attempt deferred",
      content: "# Handoff\n\ngates-agree body",
    }));

    // Before the attempt: finalize blocks on missing_technique_attempt_log
    // (NOT missing_handoff) and the merge buckets the surface missing.
    const beforeFinalize = evaluateAgentCompletion({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    assert.equal(beforeFinalize.ok, false);
    assert.equal(beforeFinalize.block_code, "missing_technique_attempt_log");
    const beforeMerge = mergeWaveHandoffsInternal(domain, 1).merge;
    assert.ok(beforeMerge.missing_surface_ids.includes("surface-a"));
    assert.equal(beforeMerge.completed_surface_ids.length, 0);

    // After a matching attempt: both gates flip to pass.
    JSON.parse(logTechniqueAttempt({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      pack_id: "generic-rest-api",
      status: "attempted",
      outcome: "no_finding",
      evidence: "probed REST authz across two accounts on surface-a; no IDOR observed",
    }));
    const afterFinalize = evaluateAgentCompletion({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    assert.equal(afterFinalize.ok, true);
    const afterMerge = mergeWaveHandoffsInternal(domain, 1).merge;
    assert.ok(afterMerge.completed_surface_ids.includes("surface-a"));
    assert.equal(afterMerge.missing_surface_ids.length, 0);
  });
});
