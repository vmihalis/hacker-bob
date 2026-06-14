"use strict";

// Y.10 — scheduler-preconditions registry shape + paired safety test.
//
// Asserts:
//   1. SCHEDULER_PRECONDITION_VALUES is Object.freeze'd and non-empty.
//   2. Every value in SCHEDULER_PRECONDITION_VALUES has a backing check
//      function in PRECONDITION_CHECKS (paired safety per Y.10 Do step 9).
//   3. partial_surfaces_drained returns {satisfied, blocked_surface_ids}
//      shape with semantics tied to mergeWaveHandoffs snapshot state.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  SCHEDULER_PRECONDITION_VALUES,
  PRECONDITION_CHECKS,
  evaluateSchedulerPrecondition,
} = require("../mcp/lib/scheduler-preconditions.js");
const {
  waveMergeSnapshotPath,
  waveHandoffsSnapshotDir,
} = require("../mcp/lib/wave-handoff-store.js");
const recordCandidateClaimTool = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  writeChainAttempt,
} = require("../mcp/lib/chain-attempts.js");
const {
  initSession,
  advanceSession,
} = require("../mcp/lib/session-state.js");
const {
  startWave,
  writeWaveHandoff,
} = require("../mcp/lib/waves.js");
const {
  attackSurfacePath,
} = require("../mcp/lib/paths.js");
const {
  writeFileAtomic,
} = require("../mcp/lib/storage.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sched-pre-"));
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

// Record a reportable candidate claim through the canonical producer so the
// session-artifact summary projects a finding (findings.total). Two of these
// drive chain_work_required via the findings.total >= 2 arm.
function recordFinding(domain, index) {
  return JSON.parse(recordCandidateClaimTool.handler({
    target_domain: domain,
    title: `IDOR exposes record ${index}`,
    severity: "high",
    cwe: "CWE-639",
    endpoint: `https://${domain}/api/records/${index}`,
    description: `Changing record ${index} identifier returns another tenant payload.`,
    proof_of_concept: `GET /api/records/${index} as the attacker tenant returns private fields.`,
    response_evidence: `Response leaked tenant identifier and email for record ${index}.`,
    impact: `Cross-tenant record ${index} disclosure.`,
    validated: true,
    auth_profile: `attacker-${index}`,
    surface_id: `surface:record-${index}`,
    cvss_inputs: {
      attack_vector: "network",
      privileges_required: "low",
      confidentiality: "high",
    },
  }));
}

// Seed one validated structured wave handoff carrying a chain_note through the
// real assignment + handoff_token path so summarizeStructuredHandoffChainNotes
// counts it. This drives chain_work_required via the chain_notes_count > 0 arm
// independent of any finding.
function recordHandoffChainNote(domain, surfaceId) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
  writeFileAtomic(
    attackSurfacePath(domain),
    `${JSON.stringify({ surfaces: [{ id: surfaceId, hosts: [`https://${domain}`], priority: "HIGH" }] }, null, 2)}\n`,
  );
  JSON.parse(advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER" }));
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
    summary: "surface covered; one pivot lead worth correlating",
    chain_notes: ["pivot from this surface into the account-takeover flow"],
    content: "# Handoff\n\nFinal handoff body",
  }));
}

// Write a terminal structured chain attempt (not_applicable is terminal) with
// no finding/surface references so the seed stays self-contained.
function recordTerminalChainAttempt(domain) {
  JSON.parse(writeChainAttempt({
    target_domain: domain,
    finding_ids: [],
    surface_ids: [],
    hypothesis: "Recorded chain work resolves to no credible cross-surface pivot.",
    steps: ["Replay the recorded leads; none pivot into a higher-severity outcome."],
    outcome: "not_applicable",
    evidence_summary: "Terminal chain outcome for the recorded chain work.",
  }));
}

test("SCHEDULER_PRECONDITION_VALUES is frozen and includes partial_surfaces_drained", () => {
  assert.equal(Object.isFrozen(SCHEDULER_PRECONDITION_VALUES), true);
  assert.ok(SCHEDULER_PRECONDITION_VALUES.length >= 1);
  assert.ok(SCHEDULER_PRECONDITION_VALUES.includes("partial_surfaces_drained"));
});

test("PRECONDITION_CHECKS is frozen and covers every value in SCHEDULER_PRECONDITION_VALUES (paired safety)", () => {
  assert.equal(Object.isFrozen(PRECONDITION_CHECKS), true);
  for (const name of SCHEDULER_PRECONDITION_VALUES) {
    assert.equal(typeof PRECONDITION_CHECKS[name], "function", `${name} has no check function`);
  }
});

test("evaluateSchedulerPrecondition rejects unknown precondition names", () => {
  assert.throws(
    () => evaluateSchedulerPrecondition("not_a_real_precondition", { target_domain: "x.com" }),
    /unknown scheduler precondition/,
  );
});

test("partial_surfaces_drained returns satisfied=true when no merge snapshot exists", () => {
  withTempHome(() => {
    const domain = "no-merges-yet.com";
    const result = evaluateSchedulerPrecondition("partial_surfaces_drained", { target_domain: domain });
    assert.equal(result.satisfied, true);
    assert.deepEqual(result.blocked_surface_ids, []);
  });
});

test("partial_surfaces_drained returns satisfied=false with blocked_surface_ids from snapshot", () => {
  withTempHome(() => {
    const domain = "has-partials.com";
    fs.mkdirSync(waveHandoffsSnapshotDir(domain), { recursive: true });
    fs.writeFileSync(waveMergeSnapshotPath(domain, 1), JSON.stringify({
      wave_number: 1,
      partial_surface_ids: ["surface-partial-a", "surface-partial-b"],
    }));
    const result = evaluateSchedulerPrecondition("partial_surfaces_drained", { target_domain: domain });
    assert.equal(result.satisfied, false);
    assert.deepEqual(result.blocked_surface_ids, ["surface-partial-a", "surface-partial-b"]);
  });
});

test("partial_surfaces_drained returns satisfied=true when all partials drained in highest snapshot", () => {
  withTempHome(() => {
    const domain = "drained-in-latest.com";
    fs.mkdirSync(waveHandoffsSnapshotDir(domain), { recursive: true });
    fs.writeFileSync(waveMergeSnapshotPath(domain, 1), JSON.stringify({
      wave_number: 1,
      partial_surface_ids: ["surface-partial-a"],
    }));
    fs.writeFileSync(waveMergeSnapshotPath(domain, 2), JSON.stringify({
      wave_number: 2,
      partial_surface_ids: [],
    }));
    const result = evaluateSchedulerPrecondition("partial_surfaces_drained", { target_domain: domain });
    assert.equal(result.satisfied, true);
    assert.deepEqual(result.blocked_surface_ids, []);
  });
});

test("partial_surfaces_drained requires target_domain", () => {
  assert.throws(
    () => evaluateSchedulerPrecondition("partial_surfaces_drained", {}),
    /target_domain/,
  );
});

test("SCHEDULER_PRECONDITION_VALUES includes chain_work_terminal with a paired check (covered by paired-safety iteration)", () => {
  assert.ok(SCHEDULER_PRECONDITION_VALUES.includes("chain_work_terminal"));
  assert.equal(typeof PRECONDITION_CHECKS.chain_work_terminal, "function");
});

test("chain_work_terminal returns satisfied=true when no chain work is required", () => {
  withTempHome(() => {
    const domain = "no-chain-work-yet.com";
    const result = evaluateSchedulerPrecondition("chain_work_terminal", { target_domain: domain });
    assert.equal(result.chain_work_required, false);
    assert.equal(result.findings_total, 0);
    assert.equal(result.chain_notes_count, 0);
    assert.equal(result.satisfied, true);
  });
});

test("chain_work_terminal returns satisfied=false when >=2 findings exist without a terminal chain attempt", () => {
  withTempHome(() => {
    const domain = "two-findings-no-terminal.com";
    recordFinding(domain, 1);
    recordFinding(domain, 2);
    const result = evaluateSchedulerPrecondition("chain_work_terminal", { target_domain: domain });
    assert.equal(result.chain_work_required, true);
    assert.equal(result.findings_total, 2);
    assert.equal(result.terminal_total, 0);
    assert.equal(result.satisfied, false);
  });
});

test("chain_work_terminal returns satisfied=false when a handoff chain-note exists without a terminal chain attempt", () => {
  withTempHome(() => {
    const domain = "chain-note-no-terminal.com";
    recordHandoffChainNote(domain, "surface:chain-seed");
    const result = evaluateSchedulerPrecondition("chain_work_terminal", { target_domain: domain });
    assert.equal(result.chain_work_required, true);
    assert.ok(result.chain_notes_count > 0);
    assert.equal(result.terminal_total, 0);
    assert.equal(result.satisfied, false);
  });
});

test("chain_work_terminal returns satisfied=true when required chain work has a terminal chain attempt", () => {
  withTempHome(() => {
    const domain = "chain-work-with-terminal.com";
    recordFinding(domain, 1);
    recordFinding(domain, 2);
    recordTerminalChainAttempt(domain);
    const result = evaluateSchedulerPrecondition("chain_work_terminal", { target_domain: domain });
    assert.equal(result.chain_work_required, true);
    assert.equal(result.findings_total, 2);
    assert.ok(result.terminal_total > 0);
    assert.equal(result.satisfied, true);
  });
});

test("chain_work_terminal requires target_domain", () => {
  assert.throws(
    () => evaluateSchedulerPrecondition("chain_work_terminal", {}),
    /target_domain/,
  );
});
