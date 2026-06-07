"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  advanceSession,
  initSession,
} = require("../mcp/lib/session-state.js");
const {
  readSessionNucleus,
} = require("../mcp/lib/governance-store.js");
const {
  repoInventoryPath,
  sessionEventsJsonlPath,
  statePath,
} = require("../mcp/lib/paths.js");
const {
  readSessionEvents,
} = require("../mcp/lib/session-events.js");
const {
  allowedTargetsFor,
  evaluateLifecycleTransition,
} = require("../mcp/lib/lifecycle-gates.js");
const {
  appendCandidateClaim,
} = require("../mcp/lib/claims.js");
const {
  buildClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  writeEvidencePacks,
} = require("../mcp/lib/evidence.js");
const {
  buildRepoInventory,
  initRepoSession,
} = require("../mcp/lib/repo-target.js");
const {
  writeVerificationRound,
} = require("../mcp/lib/verification-round-store.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-lifecycle-advance-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function bootstrapDomain(domain) {
  initSession({ target_domain: domain, target_url: `https://${domain}/` });
}

function writeRepoFile(root, relativePath, content) {
  const filePath = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content, "utf8");
}

function verificationResult(findingId = "F-1", overrides = {}) {
  return {
    finding_id: findingId,
    disposition: "confirmed",
    severity: "high",
    reportable: true,
    reasoning: "Fresh replay confirmed the finding against the current target state.",
    ...overrides,
  };
}

function evidencePack(findingId = "F-1") {
  return {
    finding_id: findingId,
    sample_type: "repo replay",
    sample_count: 1,
    aggregate_counts: { affected_objects_sampled: 1 },
    representative_samples: [{
      request_ref: "repo-check:1",
      endpoint: "src/parser.c",
      auth_profile: "repo",
      status: 0,
      observed_fields: ["asan"],
      redacted_object_id: "local-input",
    }],
    sensitive_clusters: ["none"],
    replay_summary: "Verification replay confirmed the native finding.",
    redaction_notes: "No secrets captured.",
    report_snippet: "A crafted input triggers a native parser crash.",
  };
}

function seedRepoVerification(home, {
  targetDomain,
  surfaceId,
  surfaceIds = null,
  finalSeverity = "high",
  runInventory = true,
} = {}) {
  const repo = path.join(home, targetDomain);
  fs.mkdirSync(repo, { recursive: true });
  writeRepoFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(lifecycle_gate C)\n");
  writeRepoFile(repo, "src/parser.c", "int parse_packet(const char *buf, int len){ return len > 0 ? buf[0] : 0; }\n");
  const init = initRepoSession({ repo_path: repo, target_domain: targetDomain });
  if (runInventory) {
    buildRepoInventory({ target_domain: init.target_domain });
  }
  appendCandidateClaim({
    target_domain: init.target_domain,
    title: "Native parser over-read",
    summary: "Parser reads past the available buffer.",
    severity: "medium",
    status: "candidate",
    surface_ids: surfaceIds || [surfaceId],
    evidence_refs: [{
      kind: "finding",
      finding_id: "F-1",
      content_hash: "0".repeat(64),
    }],
    impact: "Parser crash on crafted local input.",
  });
  buildClaimFreeze(init.target_domain, {
    write: true,
    now: new Date("2026-05-27T01:00:00.000Z"),
  });
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: init.target_domain,
      round,
      notes: null,
      results: [verificationResult("F-1", { severity: finalSeverity })],
    });
  }
  writeEvidencePacks({ target_domain: init.target_domain, packs: [evidencePack("F-1")] });
  return init.target_domain;
}

function lifecycleAdvancedEvents(domain) {
  return readSessionEvents(domain).filter((event) => event.kind === "governance.lifecycle.advanced");
}

function lifecycleOverrideEvents(domain) {
  return readSessionEvents(domain).filter((event) => event.kind === "governance.lifecycle.override");
}

const TOPOLOGY_ONLY_FORCEABLE_GATES = Object.freeze(new Map([
  ["VERIFY->GRADE", { blocked_by: "verification_stale", code: "verification_chain_incomplete" }],
  ["GRADE->REPORT", { blocked_by: "evidence_incomplete", code: "evidence_packs_invalid" }],
]));

function advanceTopology(domain, toState) {
  try {
    return JSON.parse(advanceSession({ target_domain: domain, to_state: toState }));
  } catch (error) {
    if (!error || error.code !== "STATE_CONFLICT") throw error;
    const details = error.details || {};
    const gate = TOPOLOGY_ONLY_FORCEABLE_GATES.get(`${details.from}->${details.to}`);
    if (!gate || details.blocked_by !== gate.blocked_by || details.code !== gate.code) {
      throw error;
    }
    return JSON.parse(advanceSession({
      target_domain: domain,
      to_state: toState,
      override: "operator_force",
      override_reason: "topology-only lifecycle test bypasses external artifact gates",
    }));
  }
}

test("bob_advance_session rejects an unreachable target with a structured no_transition blocker", () => {
  withTempHome(() => {
    const domain = "block.example.com";
    bootstrapDomain(domain);

    let captured = null;
    try {
      advanceSession({ target_domain: domain, to_state: "VERIFY" });
    } catch (error) {
      captured = error;
    }

    assert.ok(captured, "forced VERIFY from SETUP must throw");
    assert.equal(captured.code, "STATE_CONFLICT", `expected STATE_CONFLICT, got ${captured.code}`);
    assert.ok(captured.details, "structured blocker payload must be attached");
    assert.equal(captured.details.blocked_by, "no_transition");
    assert.equal(captured.details.from, "SETUP");
    assert.equal(captured.details.to, "VERIFY");
    assert.deepEqual(captured.details.allowed, allowedTargetsFor("SETUP"));
    assert.ok(Array.isArray(captured.details.blockers));
    assert.equal(captured.details.blockers[0].blocked_by, "no_transition");

    // No advance event should have been written by the rejected call.
    assert.equal(lifecycleAdvancedEvents(domain).length, 0);
    assert.equal(lifecycleOverrideEvents(domain).length, 0);

    // Nucleus must still be SETUP.
    const nucleus = readSessionNucleus(domain);
    assert.equal(nucleus.lifecycle_state, "SETUP");
  });
});

test("bob_advance_session drives SETUP -> OPEN_FRONTIER -> CLAIM_FREEZE -> VERIFY -> GRADE -> REPORT with distinct hashes", () => {
  withTempHome(() => {
    const domain = "sequence.example.com";
    bootstrapDomain(domain);

    const initialNucleus = readSessionNucleus(domain);
    assert.equal(initialNucleus.lifecycle_state, "SETUP");
    const observedHashes = new Set([initialNucleus.nucleus_hash]);

    // The hypergraph review gate calls for six distinct nucleus_hash values
    // and six governance.lifecycle.advanced events. The canonical SETUP ->
    // OPEN_FRONTIER -> CLAIM_FREEZE -> VERIFY -> GRADE -> REPORT walk is
    // 5 forward edges (5 advances). Combined with the initial SETUP nucleus
    // that lands six distinct lifecycle_state values, six distinct
    // nucleus_hash values, and five lifecycle.advanced events. The sixth
    // event comes from the D3 re-entry REPORT -> OPEN_FRONTIER, which lands
    // a sixth lifecycle.advanced event even though it returns to a previously
    // observed OPEN_FRONTIER lifecycle_state.
    const sequence = [
      "OPEN_FRONTIER",
      "CLAIM_FREEZE",
      "VERIFY",
      "GRADE",
      "REPORT",
      "OPEN_FRONTIER",
    ];

    let priorHash = initialNucleus.nucleus_hash;
    for (const target of sequence) {
      const result = advanceTopology(domain, target);
      assert.equal(result.advanced, true);
      assert.equal(result.to_state, target);
      assert.equal(result.prior_nucleus_hash, priorHash);
      assert.match(result.nucleus_hash, /^[0-9a-f]{64}$/);
      observedHashes.add(result.nucleus_hash);
      const persisted = readSessionNucleus(domain);
      assert.equal(persisted.lifecycle_state, target);
      assert.equal(persisted.nucleus_hash, result.nucleus_hash);
      priorHash = result.nucleus_hash;
    }

    // Six distinct nucleus_hash values: SETUP, OPEN_FRONTIER, CLAIM_FREEZE,
    // VERIFY, GRADE, REPORT. The seventh advance (REPORT -> OPEN_FRONTIER)
    // returns to the previously observed OPEN_FRONTIER hash, which is correct
    // because the nucleus is deterministically content-hashed and the
    // post-states are identical.
    assert.equal(observedHashes.size, 6, "six distinct nucleus_hash values must be observed across SETUP..REPORT");

    const events = lifecycleAdvancedEvents(domain);
    assert.equal(events.length, 6, `expected 6 lifecycle.advanced events, got ${events.length}`);
    const orderedTransitions = events.map((event) => [event.payload.from_state, event.payload.to_state]);
    assert.deepEqual(orderedTransitions, [
      ["SETUP", "OPEN_FRONTIER"],
      ["OPEN_FRONTIER", "CLAIM_FREEZE"],
      ["CLAIM_FREEZE", "VERIFY"],
      ["VERIFY", "GRADE"],
      ["GRADE", "REPORT"],
      ["REPORT", "OPEN_FRONTIER"],
    ]);

    // Every advance event must carry the nucleus_hash for the post-state and
    // the prior_nucleus_hash for the pre-state.
    for (const event of events) {
      assert.match(event.payload.nucleus_hash, /^[0-9a-f]{64}$/);
      assert.match(event.payload.prior_nucleus_hash, /^[0-9a-f]{64}$/);
      assert.notEqual(event.payload.nucleus_hash, event.payload.prior_nucleus_hash);
      assert.equal(event.nucleus_hash, event.payload.nucleus_hash);
    }
  });
});

test("bob_advance_session with override: operator_force advances despite a no_transition blocker and writes a lifecycle.override event", () => {
  withTempHome(() => {
    const domain = "override.example.com";
    bootstrapDomain(domain);

    const priorNucleus = readSessionNucleus(domain);
    assert.equal(priorNucleus.lifecycle_state, "SETUP");

    const result = JSON.parse(advanceSession({
      target_domain: domain,
      to_state: "VERIFY",
      override: "operator_force",
      override_reason: "operator forced verify for cycle test",
    }));
    assert.equal(result.advanced, true);
    assert.equal(result.from_state, "SETUP");
    assert.equal(result.to_state, "VERIFY");
    assert.equal(result.override, "operator_force");

    const persisted = readSessionNucleus(domain);
    assert.equal(persisted.lifecycle_state, "VERIFY");
    assert.equal(persisted.nucleus_hash, result.nucleus_hash);

    const overrides = lifecycleOverrideEvents(domain);
    assert.equal(overrides.length, 1, "exactly one governance.lifecycle.override event after forced advance");
    const [overrideEvent] = overrides;
    assert.equal(overrideEvent.payload.from_state, "SETUP");
    assert.equal(overrideEvent.payload.to_state, "VERIFY");
    assert.equal(overrideEvent.payload.override, "operator_force");
    assert.equal(overrideEvent.payload.override_reason, "operator forced verify for cycle test");
    assert.equal(overrideEvent.payload.prior_nucleus_hash, priorNucleus.nucleus_hash);
    assert.ok(Array.isArray(overrideEvent.payload.blockers));
    assert.equal(overrideEvent.payload.blockers[0].blocked_by, "no_transition");

    const advances = lifecycleAdvancedEvents(domain);
    assert.equal(advances.length, 1, "override path still emits the lifecycle.advanced event");
    assert.equal(advances[0].payload.from_state, "SETUP");
    assert.equal(advances[0].payload.to_state, "VERIFY");
  });
});

test("VERIFY -> GRADE blocks repo sessions when I9 exists but a reportable finding has no reachability stamp", () => {
  withTempHome((home) => {
    const domain = seedRepoVerification(home, {
      targetDomain: "reachability-missing-gate",
      surfaceId: "repo:module:missing-surface.c",
      runInventory: true,
    });

    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "VERIFY",
      to_state: "GRADE",
    });

    assert.equal(evaluation.blockers.length, 1);
    assert.equal(evaluation.blockers[0].code, "reachability_stamp_missing");
    assert.equal(evaluation.blockers[0].blocked_by, "reachability_absent");
    assert.deepEqual(evaluation.blockers[0].missing_finding_ids, ["F-1"]);
  });
});

test("VERIFY -> GRADE treats malformed I9 reachability as present but unresolved", () => {
  withTempHome((home) => {
    const domain = seedRepoVerification(home, {
      targetDomain: "reachability-malformed-gate",
      surfaceId: "repo:module:src-parser.c",
      runInventory: true,
    });
    const inventoryPath = repoInventoryPath(domain);
    const inventory = JSON.parse(fs.readFileSync(inventoryPath, "utf8"));
    inventory.reachability = {
      max_credible_severity_ceiling: "medium",
      network_reachable: false,
    };
    fs.writeFileSync(inventoryPath, JSON.stringify(inventory), "utf8");

    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "VERIFY",
      to_state: "GRADE",
    });

    assert.equal(evaluation.blockers.length, 1);
    assert.equal(evaluation.blockers[0].code, "reachability_stamp_missing");
    assert.deepEqual(evaluation.blockers[0].missing_finding_ids, ["F-1"]);
  });
});

test("VERIFY -> GRADE blocks when a frozen repo module surface is missing from partial I9 inventory", () => {
  withTempHome((home) => {
    const domain = seedRepoVerification(home, {
      targetDomain: "reachability-partial-gate",
      surfaceId: "repo:module:src-parser.c",
      surfaceIds: ["repo:module:src-parser.c", "repo:module:missing-surface.c"],
      runInventory: true,
    });

    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "VERIFY",
      to_state: "GRADE",
    });

    assert.equal(evaluation.blockers.length, 1);
    assert.equal(evaluation.blockers[0].code, "reachability_stamp_missing");
    assert.deepEqual(evaluation.blockers[0].missing_finding_ids, ["F-1"]);
  });
});

test("VERIFY -> GRADE reachability gate ignores repo surfaces I9 does not stamp", () => {
  withTempHome((home) => {
    const domain = seedRepoVerification(home, {
      targetDomain: "reachability-non-native-noop",
      surfaceId: "repo:manifest:package.json",
      runInventory: true,
    });

    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "VERIFY",
      to_state: "GRADE",
    });

    assert.deepEqual(evaluation.blockers, []);
  });
});

test("VERIFY -> GRADE reachability gate fails closed when session state is malformed", () => {
  withTempHome((home) => {
    const domain = seedRepoVerification(home, {
      targetDomain: "reachability-state-malformed",
      surfaceId: "repo:module:src-parser.c",
      runInventory: true,
    });
    fs.writeFileSync(statePath(domain), "{", "utf8");

    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "VERIFY",
      to_state: "GRADE",
    });

    assert.equal(evaluation.blockers.length, 1);
    assert.equal(evaluation.blockers[0].code, "reachability_stamp_missing");
    assert.equal(evaluation.blockers[0].blocked_by, "reachability_absent");
    assert.match(evaluation.blockers[0].message, /session state unavailable/);
  });
});

test("VERIFY -> GRADE reachability gate fails closed for repo sessions before I9 inventory exists", () => {
  withTempHome((home) => {
    const domain = seedRepoVerification(home, {
      targetDomain: "reachability-absent-block",
      surfaceId: "repo:module:src-parser.c",
      runInventory: false,
    });

    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "VERIFY",
      to_state: "GRADE",
    });

    assert.equal(evaluation.blockers.length, 1);
    assert.equal(evaluation.blockers[0].code, "reachability_stamp_missing");
    assert.equal(evaluation.blockers[0].blocked_by, "reachability_absent");
    assert.deepEqual(evaluation.blockers[0].missing_finding_ids, ["F-1"]);
    assert.match(evaluation.blockers[0].message, /no reachability inventory/);
    assert.match(evaluation.blockers[0].message, /without an I9 ceiling/);
  });
});

test("VERIFY -> GRADE reachability gate no-ops without inventory when no medium repo module finding is reportable", () => {
  withTempHome((home) => {
    const domain = seedRepoVerification(home, {
      targetDomain: "reachability-absent-low-noop",
      surfaceId: "repo:module:src-parser.c",
      finalSeverity: "low",
      runInventory: false,
    });

    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "VERIFY",
      to_state: "GRADE",
    });

    assert.deepEqual(evaluation.blockers, []);
  });
});

test("bob_advance_session honors D3 bidirectional edges (CLAIM_FREEZE <-> OPEN_FRONTIER and REPORT -> OPEN_FRONTIER)", () => {
  withTempHome(() => {
    const domain = "bidir.example.com";
    bootstrapDomain(domain);

    // SETUP -> OPEN_FRONTIER -> CLAIM_FREEZE -> OPEN_FRONTIER (D3).
    advanceTopology(domain, "OPEN_FRONTIER");
    advanceTopology(domain, "CLAIM_FREEZE");
    const reopened = advanceTopology(domain, "OPEN_FRONTIER");
    assert.equal(reopened.from_state, "CLAIM_FREEZE");
    assert.equal(reopened.to_state, "OPEN_FRONTIER");
    assert.equal(readSessionNucleus(domain).lifecycle_state, "OPEN_FRONTIER");

    // Walk forward to REPORT and then re-enter OPEN_FRONTIER.
    advanceTopology(domain, "CLAIM_FREEZE");
    advanceTopology(domain, "VERIFY");
    advanceTopology(domain, "GRADE");
    advanceTopology(domain, "REPORT");
    const reentry = advanceTopology(domain, "OPEN_FRONTIER");
    assert.equal(reentry.from_state, "REPORT");
    assert.equal(reentry.to_state, "OPEN_FRONTIER");
    assert.equal(readSessionNucleus(domain).lifecycle_state, "OPEN_FRONTIER");

    const advances = lifecycleAdvancedEvents(domain);
    const orderedTransitions = advances.map((event) => [event.payload.from_state, event.payload.to_state]);
    assert.deepEqual(orderedTransitions, [
      ["SETUP", "OPEN_FRONTIER"],
      ["OPEN_FRONTIER", "CLAIM_FREEZE"],
      ["CLAIM_FREEZE", "OPEN_FRONTIER"],
      ["OPEN_FRONTIER", "CLAIM_FREEZE"],
      ["CLAIM_FREEZE", "VERIFY"],
      ["VERIFY", "GRADE"],
      ["GRADE", "REPORT"],
      ["REPORT", "OPEN_FRONTIER"],
    ]);
    assert.ok(fs.existsSync(sessionEventsJsonlPath(domain)));
  });
});
