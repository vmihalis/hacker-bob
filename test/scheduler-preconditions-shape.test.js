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
  httpAuditJsonlPath,
  statePath,
} = require("../mcp/lib/paths.js");
const {
  writeFileAtomic,
} = require("../mcp/lib/storage.js");
const {
  recordProducerRun,
} = require("../mcp/lib/producer-run-ledger.js");
const {
  authStore,
} = require("../mcp/lib/auth.js");
const {
  BLOCKED_PREREQ_KIND_CAPABILITY,
  computeCapabilityClearedPremiseSurfaceIds,
  computeRequeueSurfaceIds,
  detectTerminalPromotions,
} = require("../mcp/lib/waves/wave-promotion-detector.js");
const {
  capabilityToolMapFromRegistry,
} = require("../mcp/lib/tool-registry.js");
const producerFloorTool = require("../mcp/lib/tools/materialize-producer-floor.js");
const initContractSessionTool = require("../mcp/lib/tools/init-contract-session.js");
const {
  materializeFrontier,
} = require("../mcp/lib/frontier-materializer.js");

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

function patchSessionState(domain, patch) {
  const filePath = statePath(domain);
  const doc = JSON.parse(fs.readFileSync(filePath, "utf8"));
  fs.writeFileSync(filePath, `${JSON.stringify({ ...doc, ...patch }, null, 2)}\n`);
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

test("SCHEDULER_PRECONDITION_VALUES includes unscanned_bodies_drained with a paired check", () => {
  assert.ok(SCHEDULER_PRECONDITION_VALUES.includes("unscanned_bodies_drained"));
  assert.equal(typeof PRECONDITION_CHECKS.unscanned_bodies_drained, "function");
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

test("blocked_prereq capability table covers every kind with registered capability ids", () => {
  const capabilityMap = capabilityToolMapFromRegistry();
  assert.deepEqual(Object.keys(BLOCKED_PREREQ_KIND_CAPABILITY).sort(), [
    "auth_missing",
    "egress_unreachable",
    "external_credential_missing",
    "funded_wallet_missing",
    "key_material_missing",
  ].sort());
  for (const config of Object.values(BLOCKED_PREREQ_KIND_CAPABILITY)) {
    assert.ok(Object.prototype.hasOwnProperty.call(capabilityMap, config.required_capability_id));
  }
});

test("computeCapabilityClearedPremiseSurfaceIds reads live auth profiles for auth blockers", () => {
  withTempHome(() => {
    const domain = "cap-clear-auth.example.com";
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
    const blockers = new Map([
      ["surface-auth", [{ kind: "auth_missing", identifier_hint: "attacker" }]],
    ]);
    assert.deepEqual(
      Array.from(computeCapabilityClearedPremiseSurfaceIds({
        currentWaveBlockersBySurface: blockers,
        target_domain: domain,
      })),
      [],
    );
    JSON.parse(authStore({
      target_domain: domain,
      profile_name: "attacker",
      headers: { Authorization: "Bearer test-token" },
    }));
    assert.deepEqual(
      Array.from(computeCapabilityClearedPremiseSurfaceIds({
        currentWaveBlockersBySurface: blockers,
        target_domain: domain,
      })),
      ["surface-auth"],
    );
  });
});

test("computeCapabilityClearedPremiseSurfaceIds reads producer terminal set for artifact blockers", () => {
  withTempHome(() => {
    const domain = "cap-clear-producer.example.com";
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
    const blockers = new Map([
      ["surface-key", [{ kind: "key_material_missing", identifier_hint: "signer" }]],
    ]);
    assert.deepEqual(
      Array.from(computeCapabilityClearedPremiseSurfaceIds({
        currentWaveBlockersBySurface: blockers,
        target_domain: domain,
      })),
      [],
    );
    recordProducerRun(domain, { producer_key: "I7_chain_state_tree", status: "produced" });
    assert.deepEqual(
      Array.from(computeCapabilityClearedPremiseSurfaceIds({
        currentWaveBlockersBySurface: blockers,
        target_domain: domain,
      })),
      ["surface-key"],
    );
  });
});

test("computeRequeueSurfaceIds unions capability-cleared surfaces through the existing path", () => {
  const requeue = computeRequeueSurfaceIds(
    {
      wave: 1,
      assignments: [{ agent: "bad-agent", surface_id: "surface-invalid" }],
      assignmentByAgent: new Map([["bad-agent", { surface_id: "surface-invalid" }]]),
    },
    {
      partial_surface_ids: ["surface-partial"],
      missing_surface_ids: ["surface-cap"],
      invalid_agents: ["bad-agent"],
    },
    [],
    new Set(["surface-cap", "surface-auth"]),
  );
  assert.deepEqual(requeue, ["surface-partial", "surface-cap", "surface-invalid", "surface-auth"]);
});

test("detectTerminalPromotions leaves unrelated recurring blockers on a capability-cleared surface", () => {
  withTempHome(() => {
    const domain = "cap-clear-mixed.example.com";
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
    JSON.parse(authStore({
      target_domain: domain,
      profile_name: "attacker",
      headers: { Authorization: "Bearer test-token" },
    }));
    const historyBySurface = new Map([
      ["surface-mixed", [
        { wave: 1, surface_id: "surface-mixed", kind: "auth_missing", identifier_hint: "attacker" },
        { wave: 1, surface_id: "surface-mixed", kind: "funded_wallet_missing", identifier_hint: "sepolia" },
        { wave: 2, surface_id: "surface-mixed", kind: "auth_missing", identifier_hint: "attacker" },
        { wave: 2, surface_id: "surface-mixed", kind: "funded_wallet_missing", identifier_hint: "sepolia" },
      ]],
    ]);
    const currentWaveBlockersBySurface = new Map([
      ["surface-mixed", [
        { kind: "auth_missing", identifier_hint: "attacker" },
        { kind: "funded_wallet_missing", identifier_hint: "sepolia" },
      ]],
    ]);
    const capabilityClearedSurfaceIds = computeCapabilityClearedPremiseSurfaceIds({
      historyBySurface,
      currentWaveBlockersBySurface,
      currentWave: 2,
      target_domain: domain,
    });
    const promotions = detectTerminalPromotions({
      currentWaveBlockersBySurface,
      historyBySurface,
      prereqRegistrySnapshots: [],
      clearHistoryBySurface: new Map(),
      currentWave: 2,
      capabilityClearedSurfaceIds,
    });
    assert.equal(promotions.length, 1);
    assert.deepEqual(promotions[0].blockers.map((b) => b.kind), ["funded_wallet_missing"]);
  });
});

test("blocked_prereqs_capability_clear is vacuous without current-wave blockers and blocks when auth clears one", () => {
  withTempHome(() => {
    const domain = "cap-clear-gate.example.com";
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
    assert.ok(SCHEDULER_PRECONDITION_VALUES.includes("blocked_prereqs_capability_clear"));
    assert.equal(typeof PRECONDITION_CHECKS.blocked_prereqs_capability_clear, "function");
    let result = evaluateSchedulerPrecondition("blocked_prereqs_capability_clear", { target_domain: domain });
    assert.equal(result.satisfied, true);
    assert.equal(result.capability_clear_active, false);

    patchSessionState(domain, {
      lifecycle_state: "OPEN_FRONTIER",
      phase: "EVALUATE",
      evaluation_wave: 1,
      blocked_prereq_history: [
        { wave: 1, surface_id: "surface-auth", kind: "auth_missing", identifier_hint: "attacker" },
      ],
    });
    JSON.parse(authStore({
      target_domain: domain,
      profile_name: "attacker",
      headers: { Authorization: "Bearer test-token" },
    }));
    result = evaluateSchedulerPrecondition("blocked_prereqs_capability_clear", { target_domain: domain });
    assert.equal(result.satisfied, false);
    assert.equal(result.capability_clear_active, true);
    assert.deepEqual(result.blocked_surface_ids, ["surface-auth"]);

    patchSessionState(domain, {
      evaluation_wave: 2,
      blocked_prereq_history: [
        { wave: 1, surface_id: "surface-auth", kind: "auth_missing", identifier_hint: "attacker" },
      ],
    });
    result = evaluateSchedulerPrecondition("blocked_prereqs_capability_clear", { target_domain: domain });
    assert.equal(result.satisfied, true);
    assert.equal(result.capability_clear_active, false);
  });
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

// Bootstrap a pure-SC session through the contract front door, flush the seeded
// depth-1 smart_contract surface into the surface-index, and record the two
// bootstrap producers (sc_chain_root + the bare sc_address_expander) terminal so
// the only thing keeping the floor off its fixpoint is the per-instance expander
// the live depth-1 surface re-proposes at depth 2. Returns the derived domain and
// the depth-2 per-instance expander key.
function bootstrapPureScFloor(address) {
  const init = JSON.parse(initContractSessionTool.handler({
    contracts: [{ chain_family: "evm", chain_id: "1", address }],
  }));
  const domain = init.target_domain;
  // FORCE synchronous surface-index materialization so the seeded depth-1
  // smart_contract surface is visible to readScExpanderSurfaces.
  materializeFrontier(domain, { write: true });
  recordProducerRun(domain, { producer_key: "sc_chain_root", status: "produced" });
  recordProducerRun(domain, { producer_key: "sc_address_expander", status: "produced" });
  const instanceKey = `sc_address_expander:evm:1:${address.toLowerCase()}`;
  return { domain, instanceKey };
}

test("seed_producers_drained is NOT satisfied while a pending depth-2 sc-expander instance remains", () => {
  withTempHome(() => {
    const address = "0xaaa1000000000000000000000000000000000000";
    const { domain } = bootstrapPureScFloor(address);

    // Dispatch the floor: ready is empty (both bootstrap producers terminal, no
    // web 'target' seed), but the live depth-1 surface re-proposes the depth-2
    // per-instance expander, so the handler stamps producer_floor_at_fixpoint=false
    // and materializes a producer node (the floor is now active).
    const floor = JSON.parse(producerFloorTool.handler({ target_domain: domain }));
    assert.equal(floor.tier1_producers_emitted, 0,
      "no ready non-advisory producer — both bootstrap producers are terminal and there is no web target");
    assert.equal(floor.producer_floor_at_fixpoint, false,
      "the handler is NOT at fixpoint while the depth-2 per-instance expander is pending");

    const result = evaluateSchedulerPrecondition("seed_producers_drained", { target_domain: domain });
    assert.equal(result.producer_floor_active, true);
    assert.equal(result.ready_count, 0,
      "plan.ready is empty — a verdict derived from plan.ready alone would wrongly read DRAINED here");
    assert.equal(result.sc_expander_instance_count, 1,
      "the pending depth-2 per-instance expander is surfaced in the verdict");
    assert.equal(result.satisfied, false,
      "the gate and the dispatcher agree: a pending sc-expander keeps the floor undrained");
  });
});

test("seed_producers_drained IS satisfied once every per-instance sc-expander is terminal", () => {
  withTempHome(() => {
    const address = "0xaaa2000000000000000000000000000000000000";
    const { domain, instanceKey } = bootstrapPureScFloor(address);

    // First dispatch materializes the producer node and proposes the depth-2
    // instance (floor active, not yet drained).
    const firstFloor = JSON.parse(producerFloorTool.handler({ target_domain: domain }));
    assert.equal(firstFloor.producer_floor_at_fixpoint, false);

    // Record the per-instance expander terminal — the dedup path now suppresses it,
    // so the floor reaches its genuine fixpoint with the producer node still present.
    recordProducerRun(domain, { producer_key: instanceKey, status: "produced" });

    const secondFloor = JSON.parse(producerFloorTool.handler({ target_domain: domain }));
    assert.equal(secondFloor.tier1_producers_emitted, 0);
    assert.equal(secondFloor.producer_floor_at_fixpoint, true,
      "the handler is at fixpoint once the per-instance expander is terminal");

    const result = evaluateSchedulerPrecondition("seed_producers_drained", { target_domain: domain });
    assert.equal(result.producer_floor_active, true,
      "the producer floor is still active — the terminal producer node persists in the graph");
    assert.equal(result.ready_count, 0);
    assert.equal(result.sc_expander_instance_count, 0,
      "no per-instance expander remains pending");
    assert.equal(result.satisfied, true,
      "the genuinely-drained floor satisfies the precondition");
  });
});

test("seed_producers_drained matches the dispatch handler at a non-default linked_contract_depth (single-sourced caps, no drift)", () => {
  withTempHome(() => {
    // bootstrapPureScFloor initializes at the default linked_contract_depth (3),
    // where the handler's depth cap and the gate BOTH admit the depth-2 expander, so
    // it cannot expose a caps divergence. Bootstrap inline at linked_contract_depth=1
    // instead: the depth-2 per-instance expander the live depth-1 surface re-proposes
    // is depth-CAPPED (proposed_depth 2 > 1), so the dispatcher permanently declines
    // to propose it. A gate that rebuilt the plan WITHOUT the persisted cap would fall
    // back to the hardcoded depthCap default of 3, still count that expander pending,
    // and wait forever for an instance the dispatcher can never emit — freezing the
    // frontier. This test drives sc_chain_root (not the capped depth-2 instance) to
    // materialize the producer node, so the gate is non-vacuous at the capped depth.
    const address = "0xaaa3000000000000000000000000000000000000";
    const init = JSON.parse(initContractSessionTool.handler({
      contracts: [{ chain_family: "evm", chain_id: "1", address }],
      linked_contract_depth: 1,
    }));
    const domain = init.target_domain;
    // FORCE synchronous surface-index materialization so the seeded depth-1
    // smart_contract surface is visible to readScExpanderSurfaces.
    materializeFrontier(domain, { write: true });

    // Pass 1 proposes sc_chain_root (a ready chain root) and materializes it as a
    // producer node, so the drain gate is non-vacuous on the next pass. The depth-2
    // expander is depth-capped at 1, so the handler emits no per-instance node.
    JSON.parse(producerFloorTool.handler({ target_domain: domain }));
    recordProducerRun(domain, { producer_key: "sc_chain_root", status: "produced" });
    recordProducerRun(domain, { producer_key: "sc_address_expander", status: "produced" });

    // Pass 2 is the live handler verdict: with sc_chain_root terminal and the depth-2
    // expander capped, the floor is at its fixpoint, and the capped expander is
    // REPORTED (RANK != BOUND), never silently dropped.
    const floor = JSON.parse(producerFloorTool.handler({ target_domain: domain }));
    assert.equal(floor.producer_floor_at_fixpoint, true,
      "at linked_contract_depth=1 the depth-2 expander is capped, so the handler is at its fixpoint");
    assert.ok(
      floor.sc_recursion_gaps.some((g) => g.kind === "linked_contract_depth_capped"),
      "the depth-capped expander is reported by name, not silently dropped");

    // The gate MUST agree, reading the SAME persisted linked_contract_depth=1 cap the
    // handler used — not a hardcoded depthCap default of 3. Pre-fix, a cap-free gate
    // reported sc_expander_instance_count=1 / satisfied=false here while the handler
    // stamped producer_floor_at_fixpoint=true — an OPEN_FRONTIER that never advances.
    const result = evaluateSchedulerPrecondition("seed_producers_drained", { target_domain: domain });
    assert.equal(result.producer_floor_active, true,
      "the sc_chain_root producer node persists, so the gate is non-vacuous");
    assert.equal(result.sc_expander_instance_count, 0,
      "the gate honors linked_contract_depth=1: the depth-2 expander is capped, not pending");
    assert.equal(result.satisfied, floor.producer_floor_at_fixpoint,
      "single-sourced caps: the gate's verdict equals the dispatcher's fixpoint stamp (no drift)");
    assert.equal(result.satisfied, true,
      "the depth-capped floor is genuinely drained ⇒ OPEN_FRONTIER can advance");
  });
});

test("unscanned_bodies_drained is vacuous before a producer floor is materialized", () => {
  withTempHome(() => {
    const domain = "unscanned-vacuous.example.com";
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));

    const result = evaluateSchedulerPrecondition("unscanned_bodies_drained", { target_domain: domain });
    assert.equal(result.satisfied, true);
    assert.equal(result.obligation_active, false);
    assert.equal(result.unscanned_body_present, false);
  });
});

test("unscanned_bodies_drained blocks when a materialized http body corpus leaves web_onchain_ref ready", () => {
  withTempHome(() => {
    const domain = "unscanned-blocking.example.com";
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));

    JSON.parse(producerFloorTool.handler({ target_domain: domain }));
    const auditPath = httpAuditJsonlPath(domain);
    fs.mkdirSync(path.dirname(auditPath), { recursive: true });
    fs.writeFileSync(
      auditPath,
      `${JSON.stringify({ body: "see contract 0x0000000000000000000000000000000000000abc on chain" })}\n`,
    );

    const result = evaluateSchedulerPrecondition("unscanned_bodies_drained", { target_domain: domain });
    assert.equal(result.satisfied, false);
    assert.equal(result.unscanned_body_present, true);
    assert.equal(result.obligation_active, true);
    assert.ok(result.ready_web_onchain_ref_count >= 1);

    const lifecycleGates = require("../mcp/lib/lifecycle-gates.js");
    const gate = lifecycleGates.gateOpenFrontierToClaimFreeze
      || lifecycleGates.TRANSITION_GATES["OPEN_FRONTIER->CLAIM_FREEZE"];
    if (typeof gate === "function") {
      const blockers = gate({ target_domain: domain });
      const blocker = blockers.find((b) => b.code === "unscanned_bodies_undrained");
      assert.ok(blocker);
      assert.ok(blocker.remediation);
    }
  });
});

test("unscanned_bodies_drained is satisfied once web_onchain_ref has a terminal producer_run", () => {
  withTempHome(() => {
    const domain = "unscanned-drained.example.com";
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));

    JSON.parse(producerFloorTool.handler({ target_domain: domain }));
    const auditPath = httpAuditJsonlPath(domain);
    fs.mkdirSync(path.dirname(auditPath), { recursive: true });
    fs.writeFileSync(
      auditPath,
      `${JSON.stringify({ body: "see contract 0x0000000000000000000000000000000000000abc on chain" })}\n`,
    );

    const blocked = evaluateSchedulerPrecondition("unscanned_bodies_drained", { target_domain: domain });
    assert.equal(blocked.satisfied, false);

    recordProducerRun(domain, { producer_key: "web_onchain_ref", status: "produced" });
    const result = evaluateSchedulerPrecondition("unscanned_bodies_drained", { target_domain: domain });
    assert.equal(result.satisfied, true);
    assert.equal(result.unscanned_body_present, false);
  });
});

test("unscanned_bodies_drained requires target_domain", () => {
  assert.throws(
    () => evaluateSchedulerPrecondition("unscanned_bodies_drained", {}),
    /target_domain/,
  );
});
