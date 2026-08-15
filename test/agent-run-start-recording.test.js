"use strict";

// Universal MCP-side start-recording. bob_read_assignment_brief is every
// evaluator's documented first action, so the MCP transitions the
// (target_domain, wave, agent, surface_id) agent-run assigned -> running on that
// call, WITHOUT depending on any adapter wiring a SubagentStart hook. The merge
// gate then drives off the started lifecycle plus on-disk handoff validation,
// not bare file-presence. These tests prove the recording is non-forgeable
// (surface_id is resolved from the on-disk assignment, never an agent-asserted
// field), idempotent (first-transition-only), correctly attributed across
// multiple agents on the same surface, and reachable on the degraded path where
// the wave-emission `assigned` write was lost.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  agentRunsJsonlPath,
  attackSurfacePath,
  sessionDir,
  statePath,
} = require("../mcp/core/io/paths.js");
const {
  readAgentRuns,
  latestAgentRunForWaveAgent,
  settleAgentRunFromHandoff,
  syntheticTaskIdForWaveAssignment,
} = require("../mcp/core/session/agent-runs.js");
const {
  startWave,
  writeWaveHandoff,
} = require("../mcp/core/waves/waves.js");
const {
  buildWaveReadiness,
  loadWaveArtifacts,
  mergeWaveHandoffsInternal,
} = require("../mcp/core/waves/wave-handoff-store.js");
const { readAssignmentBrief } = require("../mcp/core/session/assignment-brief.js");
const { logTechniqueAttempt } = require("../mcp/core/dispatch/technique-packs.js");
const { writeFileAtomic } = require("../mcp/core/io/storage.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-start-recording-"));
  process.env.HOME = tempHome;
  try {
    return fn(tempHome);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

function seedSessionState(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  writeFileAtomic(statePath(domain), `${JSON.stringify({
    target: domain,
    target_url: `https://${domain}`,
    deep_mode: false,
    phase: "EVALUATE",
    evaluation_wave: 0,
    pending_wave: null,
    total_findings: 0,
    explored: [],
    terminally_blocked: [],
    prereq_registry_snapshots: [],
    blocked_prereq_history: [],
    terminal_block_clear_history: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
    scope_exclusions: [],
    hold_count: 0,
    auth_status: "pending",
    operator_note: null,
    verification_schema_version: null,
    verification_attempt_id: null,
    verification_snapshot_hash: null,
    verification_entered_at: null,
  }, null, 2)}\n`);
}

function seedSurfaces(domain, surfaces) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
}

function webSurface(id, host) {
  return {
    id,
    surface_type: "api",
    hosts: [host],
    title: "User and billing API",
    tech_stack: ["Express"],
    endpoints: ["/api/users"],
  };
}

function callBrief(domain, agent) {
  return JSON.parse(readAssignmentBrief({
    target_domain: domain,
    wave: "w1",
    agent,
    egress_profile: "default",
    block_internal_hosts: false,
  }));
}

function latestStatus(domain, agent, surfaceId) {
  const run = latestAgentRunForWaveAgent(domain, { wave: "w1", agent, surfaceId });
  return run ? run.status : null;
}

function runningRowsFor(domain, agent) {
  return readAgentRuns(domain).filter((r) => r.agent_id === agent && r.status === "running");
}

test("reading the assignment brief transitions assigned -> running without any SubagentStart hook", () => {
  withTempHome(() => {
    const domain = "start-rec-brief.example.com";
    const surfaceId = "surface-a";
    seedSessionState(domain);
    seedSurfaces(domain, [webSurface(surfaceId, `https://api.${domain}`)]);
    startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: surfaceId }],
    });

    // Wave start left exactly an `assigned` row; no hook has fired.
    assert.equal(latestStatus(domain, "a1", surfaceId), "assigned");

    callBrief(domain, "a1");

    // The brief recorded `running`, keyed to the surface from the assignment
    // file (input_refs), not an agent-asserted field.
    const running = runningRowsFor(domain, "a1");
    assert.equal(running.length, 1);
    assert.deepEqual(running[0].input_refs, [{ kind: "wave_surface", wave: "w1", surface_id: surfaceId }]);
    const expectedTaskId = syntheticTaskIdForWaveAssignment({
      targetDomain: domain, wave: "w1", agent: "a1", surfaceId,
    });
    assert.equal(running[0].task_id, expectedTaskId);
    assert.equal(latestStatus(domain, "a1", surfaceId), "running");
  });
});

test("the started lifecycle drives the merge gate (no settle row, no hook, not file-presence)", () => {
  withTempHome(() => {
    const domain = "start-rec-merge.example.com";
    const surfaceId = "surface-a";
    seedSessionState(domain);
    seedSurfaces(domain, [webSurface(surfaceId, `https://api.${domain}`)]);
    const start = JSON.parse(startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: surfaceId }],
    }));

    // First surface-scoped tool call records `running`.
    callBrief(domain, "a1");

    // The agent wrote a provenance-valid handoff and then stopped without any
    // SubagentStop settle (e.g. an adapter with no stop hook).
    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: surfaceId,
      surface_status: "complete",
      handoff_token: start.assignments[0].handoff_token,
      summary: "surface fully covered; started, handoff written, never settled",
      content: "# Handoff\n\nstarted run, no stop hook",
    }));
    // The started run logged a real technique attempt, so its handoff carries
    // the attempt_log_required evidence the merge gate requires.
    JSON.parse(logTechniqueAttempt({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: surfaceId,
      pack_id: "generic-rest-api",
      status: "attempted",
      outcome: "no_finding",
      evidence: "probed REST authz across two accounts on the surface; no IDOR observed",
    }));

    // The merge gate accepts a1 on the started lifecycle PLUS on-disk
    // payload+provenance validation — no `settled` row exists.
    assert.equal(latestStatus(domain, "a1", surfaceId), "running");
    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.equal(readiness.is_complete, true);
    assert.deepEqual(readiness.received_agents, ["a1"]);

    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.deepEqual(merge.completed_surface_ids, [surfaceId]);
    assert.equal(merge.missing_surface_ids.length, 0);
  });
});

test("start-recording is idempotent: re-reading the brief is a no-op", () => {
  withTempHome(() => {
    const domain = "start-rec-idempotent.example.com";
    const surfaceId = "surface-a";
    seedSessionState(domain);
    seedSurfaces(domain, [webSurface(surfaceId, `https://api.${domain}`)]);
    startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: surfaceId }],
    });

    callBrief(domain, "a1");
    callBrief(domain, "a1");
    callBrief(domain, "a1");

    // Three brief reads, exactly one `running` row: the latest is already
    // `running` on the 2nd/3rd call, so the transition is a no-op.
    assert.equal(runningRowsFor(domain, "a1").length, 1);
    assert.equal(latestStatus(domain, "a1", surfaceId), "running");
  });
});

test("start-recording on an already-settled run is a no-op (does not resurrect running)", () => {
  withTempHome(() => {
    const domain = "start-rec-settled.example.com";
    const surfaceId = "surface-a";
    seedSessionState(domain);
    seedSurfaces(domain, [webSurface(surfaceId, `https://api.${domain}`)]);
    const start = JSON.parse(startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: surfaceId }],
    }));

    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: surfaceId,
      surface_status: "complete",
      handoff_token: start.assignments[0].handoff_token,
      summary: "covered and settled",
      content: "# Handoff\n\nbody",
    }));

    const { loadWaveAssignments } = require("../mcp/core/session/assignments.js");
    const { readHandoffSigningKey } = require("../mcp/core/ledger-integrity/index.js");
    const assignment = loadWaveAssignments(domain, 1).assignmentByAgent.get("a1");
    const handoffJson = JSON.parse(fs.readFileSync(
      path.join(sessionDir(domain), "handoff-w1-a1.json"), "utf8",
    ));
    settleAgentRunFromHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: surfaceId,
      assignment,
      handoff: handoffJson,
      signing_key: readHandoffSigningKey(domain),
    }, { write: true });
    assert.equal(latestStatus(domain, "a1", surfaceId), "settled");

    // A late brief read (e.g. a resumed agent) must NOT append a `running` row
    // over a settled run.
    callBrief(domain, "a1");
    assert.equal(runningRowsFor(domain, "a1").length, 0);
    assert.equal(latestStatus(domain, "a1", surfaceId), "settled");
  });
});

// Per-wave emission forbids two agents on one surface_id (assignments.js
// normalizeWaveAssignmentsInput rejects a duplicate surface_id), so a surface
// gets exactly one agent per wave and the (domain, wave, surface_id) tuple is
// never ambiguous through the brief path. This test proves the per-agent
// disambiguation across the wave: a1's brief records ONLY a1's run, never
// spilling onto a2. The same-surface, two-agent disambiguation (keyed by the
// `agent` label) is pinned at the unit level in agent-runs.test.js.
test("each agent's brief records only its own run, never mis-attributed to another agent", () => {
  withTempHome(() => {
    const domain = "start-rec-multi.example.com";
    seedSessionState(domain);
    seedSurfaces(domain, [
      webSurface("surface-a", `https://api.${domain}`),
      webSurface("surface-b", `https://other.${domain}`),
    ]);
    startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
      ],
    });

    callBrief(domain, "a1");
    // After a1's brief, only a1 is running; a2 is still assigned (no spillover).
    assert.equal(latestStatus(domain, "a1", "surface-a"), "running");
    assert.equal(latestStatus(domain, "a2", "surface-b"), "assigned");
    assert.equal(runningRowsFor(domain, "a2").length, 0);

    callBrief(domain, "a2");
    assert.equal(latestStatus(domain, "a2", "surface-b"), "running");

    const a1Running = runningRowsFor(domain, "a1");
    const a2Running = runningRowsFor(domain, "a2");
    assert.equal(a1Running.length, 1);
    assert.equal(a2Running.length, 1);
    assert.notEqual(a1Running[0].task_id, a2Running[0].task_id);
    assert.equal(a1Running[0].task_id, syntheticTaskIdForWaveAssignment({
      targetDomain: domain, wave: "w1", agent: "a1", surfaceId: "surface-a",
    }));
    assert.equal(a2Running[0].task_id, syntheticTaskIdForWaveAssignment({
      targetDomain: domain, wave: "w1", agent: "a2", surfaceId: "surface-b",
    }));
  });
});

test("degraded path: the brief still records start when the wave-emission `assigned` write was lost", () => {
  withTempHome(() => {
    const domain = "start-rec-degraded.example.com";
    const surfaceId = "surface-a";
    seedSessionState(domain);
    seedSurfaces(domain, [webSurface(surfaceId, `https://api.${domain}`)]);
    startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: surfaceId }],
    });

    // Simulate the best-effort `assigned` write being lost: erase the ledger.
    // The on-disk assignment file (the source of surface_id) is untouched.
    const ledger = agentRunsJsonlPath(domain);
    if (fs.existsSync(ledger)) fs.rmSync(ledger);

    callBrief(domain, "a1");

    // The brief records `running` keyed to the REAL on-disk assignment surface,
    // even with no prior `assigned` row.
    const running = runningRowsFor(domain, "a1");
    assert.equal(running.length, 1);
    assert.deepEqual(running[0].input_refs, [{ kind: "wave_surface", wave: "w1", surface_id: surfaceId }]);
    assert.equal(latestStatus(domain, "a1", surfaceId), "running");
  });
});
