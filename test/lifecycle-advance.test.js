"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  advanceSession,
  deriveAdvanceAuthContext,
  initSession,
} = require("../mcp/core/session/session-state.js");
const {
  authStore,
} = require("../mcp/core/auth/index.js");
const {
  buildSessionNucleus,
  readSessionNucleus,
} = require("../mcp/core/governance/index.js");
const {
  readSessionStateStrict,
  writeSessionStateDocument,
} = require("../mcp/core/session/session-state-store.js");
const {
  gradeArtifactPaths,
  repoInventoryPath,
  sessionEventsJsonlPath,
  sessionNucleusPath,
  statePath,
  verificationAttemptsDir,
  verificationSnapshotPath,
} = require("../mcp/core/io/paths.js");
const verificationModule = require("../mcp/core/verification/verification.js");
const {
  readSessionEvents,
} = require("../mcp/core/session/session-events.js");
const {
  loadGradeVerdictHash,
} = require("../mcp/core/report-finalize.js");
const {
  writeFileAtomic,
} = require("../mcp/core/io/storage.js");
const {
  allowedTargetsFor,
  evaluateLifecycleTransition,
} = require("../mcp/core/session/lifecycle-gates.js");
const {
  _setApprovalBackendForTest,
  _setApprovalHmacKeyForTest,
} = require("../mcp/core/approval-store.js");
const { withIsolatedSigner } = require("./helpers/sandbox-isolated-signer.js");
const {
  appendCandidateClaim,
} = require("../mcp/core/claims/claims.js");
const recordCandidateClaimTool = require("../mcp/tools/record-candidate-claim.js");
const {
  writeChainAttempt,
} = require("../mcp/core/chain-attempts.js");
const {
  waveMergeSnapshotPath,
  waveHandoffsSnapshotDir,
} = require("../mcp/core/waves/wave-handoff-store.js");
const {
  buildClaimFreeze,
} = require("../mcp/core/claims/claim-freeze.js");
const {
  writeEvidencePacks,
} = require("../mcp/core/evidence.js");
const {
  buildRepoInventory,
  initRepoSession,
} = require("../mcp/domains/repo/repo-target.js");
const {
  writeVerificationRound,
} = require("../mcp/core/verification/verification-round-store.js");
const {
  evaluateEvidenceCompletion,
} = require("../mcp/core/session/agent-run-completion.js");

// fx-hmac-content test helper: the same HMAC-SHA256(`${target_domain}|${grade_verdict_hash}`,
// key) content-bound scheme mcp/lib/approval-store.js's verifyApprovalArtifact (and the
// S3-backed production VerifierGateFunction in template.yaml, and the sibling Python hook)
// use. Producing a syntactically-valid-but-wrong-signature artifact (a different key, or a
// tampered hmac hex string) exercises the "existence is not enough" defense-in-depth path; a
// STALE gradeVerdictHash (signed for a grade verdict that has since been amended) exercises the
// content-binding path this node adds.
const APPROVAL_TEST_HMAC_KEY = "test-only-approval-hmac-key-do-not-use-in-prod";
const APPROVAL_FREEZE_BODY_SHA256 = "b".repeat(64);
const APPROVAL_FREEZE_VERSION_ID = "lifecycle-test-freeze-version-1";

function signedApprovalArtifact(targetDomain, gradeVerdictHash, key = APPROVAL_TEST_HMAC_KEY) {
  const profile = targetDomain === "libheif-cve-2026-49271"
    ? "libheif-cve-2026-49271"
    : "smoke";
  const hmac = crypto.createHmac("sha256", key)
    .update(JSON.stringify([
      profile,
      targetDomain,
      gradeVerdictHash,
      APPROVAL_FREEZE_BODY_SHA256,
      APPROVAL_FREEZE_VERSION_ID,
    ]), "utf8")
    .digest("hex");
  return JSON.stringify({
    schema_version: 2,
    binding_version: "grade-freeze-v2",
    profile,
    target_domain: targetDomain,
    grade_verdict_hash: gradeVerdictHash,
    grade_freeze_bundle_sha256: APPROVAL_FREEZE_BODY_SHA256,
    grade_freeze_version_id: APPROVAL_FREEZE_VERSION_ID,
    hmac,
  });
}

// fx-hmac-content test helper: gradeToReportApprovalBlocker binds the approval to
// loadGradeVerdictHash(domain) -- the sha256-over-canonical-JSON of grade.json
// (mcp/lib/report-finalize.js / mcp/lib/verification-contracts.js hashCanonicalJson). Writing
// grade.json DIRECTLY (rather than through mcp/lib/grade-verdict-store.js's writeGradeVerdict)
// deliberately bypasses that module's grading business-rule gates (O-P4 native-code repro
// proof, standalone finding-differential proof, sandbox-isolation, reachability stamps, etc.)
// -- none of which this suite exercises; those are covered exhaustively by
// test/grade-from-frozen-payload.test.js and test/report-snapshot-binding.test.js. This suite
// only needs a real, readable grade.json at the canonical path so the CONTENT-BINDING plumbing
// under test (loadGradeVerdictHash -> verifyApprovalArtifact -> gradeToReportApprovalBlocker) is
// exercised against real production code, not a mock.
function writeTestGradeVerdict(domain, { findingId = "F-1", totalScore = 75, verdict = "SUBMIT", feedback = "Clear, reproducible, and reportable." } = {}) {
  const document = {
    version: 1,
    target_domain: domain,
    verdict,
    total_score: totalScore,
    findings: [{
      finding_id: findingId,
      impact: 25,
      proof_quality: 20,
      severity_accuracy: 10,
      chain_potential: 10,
      report_quality: 10,
      total_score: totalScore,
      feedback,
    }],
    graded_at: "2026-05-27T02:00:00.000Z",
  };
  writeFileAtomic(gradeArtifactPaths(domain).json, `${JSON.stringify(document, null, 2)}\n`);
  return loadGradeVerdictHash(domain);
}

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
  reachabilityAssertion = null,
} = {}) {
  const repo = path.join(home, targetDomain);
  fs.mkdirSync(repo, { recursive: true });
  writeRepoFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(lifecycle_gate C)\n");
  writeRepoFile(repo, "src/parser.c", "int parse_packet(const char *buf, int len){ return len > 0 ? buf[0] : 0; }\n");
  const init = initRepoSession({ repo_path: repo, target_domain: targetDomain });
  if (runInventory) {
    buildRepoInventory({ target_domain: init.target_domain });
  }
  const claim = {
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
  };
  if (reachabilityAssertion) {
    claim.payload = {
      finding: {
        id: "F-1",
        capability_pack: "oss_native_code",
        reachability_assertion: reachabilityAssertion,
      },
    };
  }
  appendCandidateClaim(claim);
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

// Record two reportable candidate claims through the canonical producer so the
// session-artifact summary projects findings.total >= 2 — the signal that
// recorded chain work must yield a terminal structured chain attempt before
// CLAIM_FREEZE.
function recordChainWorkFindings(domain) {
  for (const index of [1, 2]) {
    JSON.parse(recordCandidateClaimTool.handler({
      target_domain: domain,
      title: `IDOR exposes record ${index}`,
      severity: "high",
      cwe: "CWE-639",
      endpoint: `https://${domain}/api/records/${index}`,
      request_method: "GET",
      injection_point: "path:record_id",
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

// Persist a merged-wave snapshot carrying an undrained partial surface so the
// partial_surfaces_drained precondition reports it as remaining.
function seedUndrainedPartialSurface(domain, surfaceId) {
  fs.mkdirSync(waveHandoffsSnapshotDir(domain), { recursive: true });
  fs.writeFileSync(waveMergeSnapshotPath(domain, 1), JSON.stringify({
    wave_number: 1,
    partial_surface_ids: [surfaceId],
  }));
}

function authContextReplacedEvents(domain) {
  return readSessionEvents(domain).filter((event) => event.kind === "governance.auth_context.replaced");
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

test("REPORT -> OPEN_FRONTIER re-entry lands a hash-bound lifecycle.advanced event so the post-report evidence gate admits it", () => {
  withTempHome(() => {
    const domain = "evidence-reentry.example.com";
    bootstrapDomain(domain);

    // Walk to REPORT, then re-enter OPEN_FRONTIER — the post-report
    // evidence-amplification / re-mine window the evidence-completion gate is
    // designed to admit.
    for (const target of ["OPEN_FRONTIER", "CLAIM_FREEZE", "VERIFY", "GRADE", "REPORT"]) {
      advanceTopology(domain, target);
    }
    const reentry = advanceTopology(domain, "OPEN_FRONTIER");
    assert.equal(reentry.from_state, "REPORT");
    assert.equal(reentry.to_state, "OPEN_FRONTIER");

    // phase is migration-only: the re-entry writes the canonical pre-image of
    // OPEN_FRONTIER (EVALUATE), never a history-dependent override.
    const state = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    assert.equal(state.phase, "EVALUATE", "phase must stay the canonical pre-image, not a re-entry-specific override");
    assert.equal(readSessionNucleus(domain).lifecycle_state, "OPEN_FRONTIER");

    // The evidence-completion gate is driven by the event ledger, not phase:
    // the latest governance.lifecycle.advanced event binds the current nucleus
    // hash and records a REPORT -> OPEN_FRONTIER re-entry, so the gate admits
    // the run (it would block a SETUP -> OPEN_FRONTIER active-evaluation event
    // as a mismatch).
    const events = lifecycleAdvancedEvents(domain);
    const latest = events[events.length - 1];
    assert.equal(latest.payload.from_state, "REPORT");
    assert.equal(latest.payload.to_state, "OPEN_FRONTIER");
    assert.equal(latest.nucleus_hash, reentry.nucleus_hash);
    assert.equal(latest.payload.nucleus_hash, reentry.nucleus_hash);

    const gate = evaluateEvidenceCompletion({ target_domain: domain });
    assert.equal(gate.ok, true, "post-report OPEN_FRONTIER re-entry must admit an evidence run");
    assert.equal(gate.handoff.provenance, "post_report_evidence");
  });
});

test("bob_advance_session with override: operator_force advances despite a no_transition blocker and folds override/blockers into the ONE canonical lifecycle.advanced event", () => {
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

    // A2/A7: exactly ONE governance event per advance. The override is folded
    // into the canonical governance.lifecycle.advanced event rather than a
    // separate governance.lifecycle.override event.
    assert.equal(
      lifecycleOverrideEvents(domain).length, 0,
      "override is folded into the canonical advanced event, not a separate event",
    );
    const advances = lifecycleAdvancedEvents(domain);
    assert.equal(advances.length, 1, "override path emits exactly one lifecycle.advanced event");
    const [advanceEvent] = advances;
    assert.equal(advanceEvent.payload.from_state, "SETUP");
    assert.equal(advanceEvent.payload.to_state, "VERIFY");
    assert.equal(advanceEvent.payload.override, "operator_force");
    assert.equal(advanceEvent.payload.override_reason, "operator forced verify for cycle test");
    assert.equal(advanceEvent.payload.prior_nucleus_hash, priorNucleus.nucleus_hash);
    assert.ok(Array.isArray(advanceEvent.payload.blockers));
    assert.equal(advanceEvent.payload.blockers[0].blocked_by, "no_transition");
  });
});

test("bob_advance_session rejects operator_force without a non-empty override_reason before writing state", () => {
  withTempHome(() => {
    const domain = "override-reason-required.example.com";
    bootstrapDomain(domain);
    const priorNucleus = readSessionNucleus(domain);

    for (const overrideReason of [undefined, "", "   ", null, 42]) {
      assert.throws(
        () => advanceSession({
          target_domain: domain,
          to_state: "VERIFY",
          override: "operator_force",
          ...(overrideReason === undefined ? {} : { override_reason: overrideReason }),
        }),
        (error) => {
          assert.equal(error.code, "INVALID_ARGUMENTS");
          assert.match(error.message, /override_reason must be a non-empty string/);
          return true;
        },
      );
    }

    const persisted = readSessionNucleus(domain);
    assert.equal(persisted.lifecycle_state, "SETUP");
    assert.equal(persisted.nucleus_hash, priorNucleus.nucleus_hash);
    assert.equal(lifecycleOverrideEvents(domain).length, 0);
    assert.equal(lifecycleAdvancedEvents(domain).length, 0);
  });
});

test("VERIFY -> GRADE blocks repo sessions when I9 exists but a reportable finding has no reachability stamp", () => {
  withTempHome((home) => {
    const domain = seedRepoVerification(home, {
      targetDomain: "reachability-missing-gate",
      surfaceId: "repo:module:missing-surface.c",
      runInventory: true,
    });

    const evaluation = withIsolatedSigner(() => evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "VERIFY",
      to_state: "GRADE",
    }));

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

    const evaluation = withIsolatedSigner(() => evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "VERIFY",
      to_state: "GRADE",
    }));

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

    const evaluation = withIsolatedSigner(() => evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "VERIFY",
      to_state: "GRADE",
    }));

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

    const evaluation = withIsolatedSigner(() => evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "VERIFY",
      to_state: "GRADE",
    }));

    assert.equal(evaluation.blockers.length, 1);
    assert.equal(evaluation.blockers[0].code, "reachability_stamp_missing");
    assert.equal(evaluation.blockers[0].blocked_by, "reachability_absent");
    assert.deepEqual(evaluation.blockers[0].missing_finding_ids, ["F-1"]);
    assert.match(evaluation.blockers[0].message, /no reachability inventory/);
    assert.match(evaluation.blockers[0].message, /without an I9 ceiling/);
  });
});

test("VERIFY -> GRADE reachability gate accepts cited assertion before I9 inventory exists", () => {
  withTempHome((home) => {
    const domain = seedRepoVerification(home, {
      targetDomain: "reachability-absent-asserted-ok",
      surfaceId: "repo:module:src-parser.c",
      runInventory: false,
      reachabilityAssertion: {
        attack_vector: "local",
        network_reachable: false,
        call_path: "local file input -> parse_packet -> buffer read",
        justification: "The finding is reached through local file parsing, not a network listener.",
      },
    });

    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "VERIFY",
      to_state: "GRADE",
    });

    assert.deepEqual(evaluation.blockers, []);
  });
});

test("VERIFY -> GRADE reachability gate accepts cited assertion when stamped heuristic is unresolved", () => {
  withTempHome((home) => {
    const domain = seedRepoVerification(home, {
      targetDomain: "reachability-malformed-asserted-ok",
      surfaceId: "repo:module:src-parser.c",
      runInventory: true,
      reachabilityAssertion: {
        attack_vector: "network",
        network_reachable: true,
        call_path: "UDP listener -> parse_packet -> buffer read",
        justification: "The evaluator traced attacker-controlled network input to the sink.",
      },
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

    assert.deepEqual(evaluation.blockers, []);
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

test("GRADE -> REPORT approval gate is inert when BOB_AGENTCORE is unset", () => {
  withTempHome((home) => {
    const domain = seedRepoVerification(home, {
      targetDomain: "approval-gate-inert",
      surfaceId: "repo:module:src-parser.c",
      runInventory: true,
    });

    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "GRADE",
      to_state: "REPORT",
    });

    assert.deepEqual(evaluation.blockers, []);
  });
});

test("GRADE -> REPORT blocks with external_approval_pending under BOB_AGENTCORE=1 when the approval artifact is absent", () => {
  withTempHome((home) => {
    const domain = seedRepoVerification(home, {
      targetDomain: "approval-gate-blocked",
      surfaceId: "repo:module:src-parser.c",
      runInventory: true,
    });

    const previousAgentcore = process.env.BOB_AGENTCORE;
    process.env.BOB_AGENTCORE = "1";
    try {
      const evaluation = evaluateLifecycleTransition({
        target_domain: domain,
        from_state: "GRADE",
        to_state: "REPORT",
      });

      assert.equal(evaluation.blockers.length, 1);
      assert.equal(evaluation.blockers[0].code, "external_approval_pending");
      assert.equal(evaluation.blockers[0].blocked_by, "external_approval_pending");
    } finally {
      if (previousAgentcore === undefined) {
        delete process.env.BOB_AGENTCORE;
      } else {
        process.env.BOB_AGENTCORE = previousAgentcore;
      }
    }
  });
});

test("GRADE -> REPORT approval gate admits the transition once the HMAC-verified, content-bound S3-shaped artifact exists", () => {
  withTempHome((home) => {
    const domain = seedRepoVerification(home, {
      targetDomain: "approval-gate-admitted",
      surfaceId: "repo:module:src-parser.c",
      runInventory: true,
    });
    const gradeVerdictHash = writeTestGradeVerdict(domain);

    const previousAgentcore = process.env.BOB_AGENTCORE;
    process.env.BOB_AGENTCORE = "1";
    // Injects the S3-backend seam directly (mcp/lib/approval-store.js's
    // _setApprovalBackendForTest, mirroring the awsClientFactoriesForTest pattern already
    // established in mcp/lib/tools/export-security-hub-finding.js) rather than a bare
    // fs.writeFileSync stand-in -- this exercises the fetch+verify contract the real
    // S3 GetObject path also goes through, not merely "a file exists".
    _setApprovalBackendForTest((targetDomain, currentGradeVerdictHash) => {
      assert.equal(targetDomain, domain, "backend must be queried by the exact target_domain");
      assert.equal(currentGradeVerdictHash, loadGradeVerdictHash(domain));
      return signedApprovalArtifact(domain, gradeVerdictHash);
    });
    _setApprovalHmacKeyForTest(APPROVAL_TEST_HMAC_KEY);
    try {
      const evaluation = evaluateLifecycleTransition({
        target_domain: domain,
        from_state: "GRADE",
        to_state: "REPORT",
      });

      assert.deepEqual(evaluation.blockers, []);

      // fx-hmac-content: amend + re-grade (simulating a post-approval report edit) changes
      // grade_verdict_hash. The SAME previously-valid, unmodified artifact must no longer
      // verify -- the amend-and-reexport gap this node closes.
      const amendedHash = writeTestGradeVerdict(domain, { totalScore: 40, feedback: "Downgraded on re-review." });
      assert.notEqual(amendedHash, gradeVerdictHash, "amending the grade verdict must change its hash");

      const reevaluation = evaluateLifecycleTransition({
        target_domain: domain,
        from_state: "GRADE",
        to_state: "REPORT",
      });
      assert.equal(reevaluation.blockers.length, 1, "amended content must invalidate the stale artifact");
      assert.equal(reevaluation.blockers[0].code, "external_approval_pending");
      assert.equal(reevaluation.blockers[0].blocked_by, "external_approval_pending");
    } finally {
      if (previousAgentcore === undefined) {
        delete process.env.BOB_AGENTCORE;
      } else {
        process.env.BOB_AGENTCORE = previousAgentcore;
      }
      _setApprovalBackendForTest(null);
      _setApprovalHmacKeyForTest(null);
    }
  });
});

test("GRADE -> REPORT approval gate blocks when the artifact exists but its HMAC is wrong (tampered/wrong-signature)", () => {
  withTempHome((home) => {
    const domain = seedRepoVerification(home, {
      targetDomain: "approval-gate-tampered",
      surfaceId: "repo:module:src-parser.c",
      runInventory: true,
    });
    const gradeVerdictHash = writeTestGradeVerdict(domain);

    const previousAgentcore = process.env.BOB_AGENTCORE;
    process.env.BOB_AGENTCORE = "1";
    // The artifact is well-formed JSON with an `hmac` field and a grade_verdict_hash that
    // MATCHES the current grade (mere existence, or even a matching content-binding, would
    // have satisfied the old raw-existence check this hardening replaces) but was signed with
    // a DIFFERENT key than the one the gate resolves -- fx-gate-hardening's defense-in-depth
    // HMAC check must still block. IAM deny-write is the PRIMARY enforcement in production;
    // this test exercises the secondary check independently of that IAM boundary.
    _setApprovalBackendForTest(() => signedApprovalArtifact(domain, gradeVerdictHash, "a-different-attacker-controlled-key"));
    _setApprovalHmacKeyForTest(APPROVAL_TEST_HMAC_KEY);
    try {
      const evaluation = evaluateLifecycleTransition({
        target_domain: domain,
        from_state: "GRADE",
        to_state: "REPORT",
      });

      assert.equal(evaluation.blockers.length, 1);
      assert.equal(evaluation.blockers[0].code, "external_approval_pending");
      assert.equal(evaluation.blockers[0].blocked_by, "external_approval_pending");
    } finally {
      if (previousAgentcore === undefined) {
        delete process.env.BOB_AGENTCORE;
      } else {
        process.env.BOB_AGENTCORE = previousAgentcore;
      }
      _setApprovalBackendForTest(null);
      _setApprovalHmacKeyForTest(null);
    }
  });
});

test("GRADE -> REPORT approval gate blocks on malformed artifact content (not JSON, missing hmac field, or missing/stale grade_verdict_hash)", () => {
  withTempHome((home) => {
    const domain = seedRepoVerification(home, {
      targetDomain: "approval-gate-malformed",
      surfaceId: "repo:module:src-parser.c",
      runInventory: true,
    });
    const gradeVerdictHash = writeTestGradeVerdict(domain);
    const correctHmac = JSON.parse(signedApprovalArtifact(domain, gradeVerdictHash)).hmac;
    const validV2Artifact = JSON.parse(signedApprovalArtifact(domain, gradeVerdictHash));

    const previousAgentcore = process.env.BOB_AGENTCORE;
    process.env.BOB_AGENTCORE = "1";
    _setApprovalHmacKeyForTest(APPROVAL_TEST_HMAC_KEY);
    try {
      const malformedCases = [
        "not json",
        "{}",
        JSON.stringify({ hmac: "" }),
        JSON.stringify({ hmac: 12345 }),
        // Well-formed, correctly-signed hmac field but NO grade_verdict_hash at all.
        JSON.stringify({ hmac: correctHmac }),
        // grade_verdict_hash present but blank/non-string.
        JSON.stringify({ hmac: correctHmac, grade_verdict_hash: "" }),
        JSON.stringify({ hmac: correctHmac, grade_verdict_hash: 12345 }),
        JSON.stringify({ ...validV2Artifact, schema_version: 1 }),
        JSON.stringify({ ...validV2Artifact, binding_version: "legacy" }),
        JSON.stringify({ ...validV2Artifact, profile: "libheif-cve-2026-49271" }),
        JSON.stringify({ ...validV2Artifact, target_domain: "other-target" }),
        JSON.stringify({ ...validV2Artifact, grade_freeze_bundle_sha256: "" }),
        JSON.stringify({ ...validV2Artifact, grade_freeze_version_id: "bad\nversion" }),
        // grade_verdict_hash present and well-formed-looking, but STALE (does not equal the
        // current grade.json hash) -- the hmac itself was computed over a DIFFERENT stale
        // hash, so this also exercises "hmac recomputed over the wrong input" fails closed.
        signedApprovalArtifact(domain, "f".repeat(64)),
      ];
      for (const raw of malformedCases) {
        _setApprovalBackendForTest(() => raw);
        const evaluation = evaluateLifecycleTransition({
          target_domain: domain,
          from_state: "GRADE",
          to_state: "REPORT",
        });
        assert.equal(evaluation.blockers.length, 1, `expected a block for artifact content ${JSON.stringify(raw)}`);
        assert.equal(evaluation.blockers[0].code, "external_approval_pending");
      }
    } finally {
      if (previousAgentcore === undefined) {
        delete process.env.BOB_AGENTCORE;
      } else {
        process.env.BOB_AGENTCORE = previousAgentcore;
      }
      _setApprovalBackendForTest(null);
      _setApprovalHmacKeyForTest(null);
    }
  });
});

test("bob_advance_session: operator_force does NOT bypass external_approval_pending on GRADE -> REPORT under BOB_AGENTCORE=1", () => {
  withTempHome(() => {
    const domain = "operator-force-nonbypass.example.com";
    bootstrapDomain(domain);
    advanceTopology(domain, "OPEN_FRONTIER");
    advanceTopology(domain, "CLAIM_FREEZE");
    advanceTopology(domain, "VERIFY");
    advanceTopology(domain, "GRADE");
    assert.equal(readSessionNucleus(domain).lifecycle_state, "GRADE");

    const overridesBefore = lifecycleOverrideEvents(domain).length;
    const advancesBefore = lifecycleAdvancedEvents(domain).length;

    const previousAgentcore = process.env.BOB_AGENTCORE;
    process.env.BOB_AGENTCORE = "1";
    try {
      let captured = null;
      try {
        // No approval artifact backend is configured (no BOB_APPROVAL_ARTIFACT_DIR,
        // BOB_APPROVAL_BUCKET, or test-injected backend) — the headless AgentCore deploy's
        // sole caller (the model) must not be able to self-approve GRADE -> REPORT by
        // simply passing operator_force.
        advanceSession({
          target_domain: domain,
          to_state: "REPORT",
          override: "operator_force",
          override_reason: "attempt to self-approve GRADE -> REPORT under AgentCore",
        });
      } catch (error) {
        captured = error;
      }

      assert.ok(captured, "operator_force must NOT bypass external_approval_pending under BOB_AGENTCORE=1");
      assert.equal(captured.code, "STATE_CONFLICT", `expected STATE_CONFLICT, got ${captured.code}`);
      assert.ok(captured.details, "structured blocker payload must be attached");
      assert.equal(captured.details.blocked_by, "external_approval_pending");
      assert.equal(captured.details.code, "external_approval_pending");
      assert.equal(captured.details.from, "GRADE");
      assert.equal(captured.details.to, "REPORT");

      // The blocked attempt must write NOTHING: no override event, no advance
      // event, and the nucleus (and state.json mirror) stay at GRADE.
      assert.equal(lifecycleOverrideEvents(domain).length, overridesBefore);
      assert.equal(lifecycleAdvancedEvents(domain).length, advancesBefore);
      assert.equal(readSessionNucleus(domain).lifecycle_state, "GRADE");
      assert.equal(JSON.parse(fs.readFileSync(statePath(domain), "utf8")).lifecycle_state, "GRADE");
    } finally {
      if (previousAgentcore === undefined) {
        delete process.env.BOB_AGENTCORE;
      } else {
        process.env.BOB_AGENTCORE = previousAgentcore;
      }
    }
  });
});

test("bob_advance_session: operator_force still bypasses GRADE -> REPORT blockers when BOB_AGENTCORE is unset (guard is inert off the AWS branch)", () => {
  withTempHome(() => {
    const domain = "operator-force-inert.example.com";
    bootstrapDomain(domain);
    advanceTopology(domain, "OPEN_FRONTIER");
    advanceTopology(domain, "CLAIM_FREEZE");
    advanceTopology(domain, "VERIFY");
    advanceTopology(domain, "GRADE");
    assert.equal(readSessionNucleus(domain).lifecycle_state, "GRADE");

    const previousAgentcore = process.env.BOB_AGENTCORE;
    delete process.env.BOB_AGENTCORE;
    try {
      // Off the AWS branch, gradeToReportApprovalBlocker contributes no blocker at all, so
      // operator_force bypassing whatever remains (e.g. evidence_packs_invalid) is unchanged
      // pre-existing behavior — proving this guard adds zero effect here.
      const result = JSON.parse(advanceSession({
        target_domain: domain,
        to_state: "REPORT",
        override: "operator_force",
        override_reason: "topology-only lifecycle test bypasses the evidence-pack gate",
      }));
      assert.equal(result.advanced, true);
      assert.equal(result.to_state, "REPORT");
      assert.equal(readSessionNucleus(domain).lifecycle_state, "REPORT");
    } finally {
      if (previousAgentcore === undefined) {
        delete process.env.BOB_AGENTCORE;
      } else {
        process.env.BOB_AGENTCORE = previousAgentcore;
      }
    }
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

test("OPEN_FRONTIER -> CLAIM_FREEZE blocks recorded chain work with no terminal chain attempt even when partial surfaces are drained", () => {
  withTempHome(() => {
    const domain = "chain-work-blocked.example.com";
    bootstrapDomain(domain);
    recordChainWorkFindings(domain);

    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
    });

    const codes = evaluation.blockers.map((blocker) => blocker.code);
    assert.ok(codes.includes("chain_work_terminal_required"), `expected chain_work_terminal_required, got ${codes.join(", ")}`);
    assert.ok(!codes.includes("partial_surfaces_remaining"), "drained frontier must not raise partial_surfaces_remaining");
    const chainBlocker = evaluation.blockers.find((blocker) => blocker.code === "chain_work_terminal_required");
    assert.equal(chainBlocker.findings, 2);
    assert.equal(chainBlocker.chain_attempts_terminal, 0);
  });
});

test("OPEN_FRONTIER -> CLAIM_FREEZE allows recorded chain work once a terminal chain attempt exists", () => {
  withTempHome(() => {
    const domain = "chain-work-allowed.example.com";
    bootstrapDomain(domain);
    recordChainWorkFindings(domain);
    recordTerminalChainAttempt(domain);

    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
    });

    const codes = evaluation.blockers.map((blocker) => blocker.code);
    assert.ok(!codes.includes("chain_work_terminal_required"), `terminal chain attempt must clear the chain gate, got ${codes.join(", ")}`);
    assert.deepEqual(evaluation.blockers, []);
  });
});

test("OPEN_FRONTIER -> CLAIM_FREEZE accumulates chain-work and partial-surface blockers together", () => {
  withTempHome(() => {
    const domain = "chain-work-and-partials.example.com";
    bootstrapDomain(domain);
    recordChainWorkFindings(domain);
    seedUndrainedPartialSurface(domain, "surface-partial-open");

    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
    });

    const codes = evaluation.blockers.map((blocker) => blocker.code);
    assert.ok(codes.includes("chain_work_terminal_required"), `expected chain_work_terminal_required, got ${codes.join(", ")}`);
    assert.ok(codes.includes("partial_surfaces_remaining"), `expected partial_surfaces_remaining, got ${codes.join(", ")}`);
    const partialBlocker = evaluation.blockers.find((blocker) => blocker.code === "partial_surfaces_remaining");
    assert.deepEqual(partialBlocker.surfaces, ["surface-partial-open"]);
  });
});

test("OPEN_FRONTIER -> CLAIM_FREEZE is unblocked with no chain work and no partial surfaces", () => {
  withTempHome(() => {
    const domain = "chain-work-clean.example.com";
    bootstrapDomain(domain);

    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
    });

    assert.deepEqual(evaluation.blockers, []);
  });
});

test("auth_status derives to 'authenticated' on advance when a usable profile is stored (Option C)", () => {
  withTempHome(() => {
    const domain = "auth-derive.example.test";
    bootstrapDomain(domain);
    assert.equal(readSessionNucleus(domain).auth_context.auth_status, "pending");
    authStore({ target_domain: domain, profile_name: "attacker", cookies: { sess: "abc123" } });
    advanceTopology(domain, "OPEN_FRONTIER");
    assert.equal(readSessionNucleus(domain).auth_context.auth_status, "authenticated");
    // state.json mirrors the nucleus auth_status (the two lifecycle stores stay in lockstep).
    assert.equal(JSON.parse(fs.readFileSync(statePath(domain), "utf8")).auth_status, "authenticated");
  });
});

test("auth_status carries forward (stays pending) on advance when no profile is stored", () => {
  withTempHome(() => {
    const domain = "auth-none.example.test";
    bootstrapDomain(domain);
    advanceTopology(domain, "OPEN_FRONTIER");
    assert.equal(readSessionNucleus(domain).auth_context.auth_status, "pending");
  });
});

test("advanceSession honors an explicit auth_status arg over profile presence", () => {
  withTempHome(() => {
    const domain = "auth-explicit.example.test";
    bootstrapDomain(domain);
    authStore({ target_domain: domain, profile_name: "attacker", cookies: { sess: "abc123" } });
    // explicit "unauthenticated" wins even though a usable profile is stored
    advanceSession({
      target_domain: domain,
      to_state: "OPEN_FRONTIER",
      auth_status: "unauthenticated",
      override: "operator_force",
      override_reason: "auth-status precedence test",
    });
    assert.equal(readSessionNucleus(domain).auth_context.auth_status, "unauthenticated");
  });
});

test("auth_status stays 'pending' when the stored profile carries no credential material", () => {
  withTempHome(() => {
    const domain = "auth-empty-profile.example.test";
    bootstrapDomain(domain);
    // bob_auth_store with only a profile_name — no headers/cookies/storage = an empty profile
    // with no actual auth material, so it must NOT count as authenticated.
    authStore({ target_domain: domain, profile_name: "attacker" });
    advanceTopology(domain, "OPEN_FRONTIER");
    assert.equal(readSessionNucleus(domain).auth_context.auth_status, "pending");
  });
});

test("auth_status stays 'pending' when the stored profile carries ONLY a non-credential header (positive-inclusion)", () => {
  withTempHome(() => {
    const domain = "auth-noncred-header.example.test";
    bootstrapDomain(domain);
    // A profile with a header that is NOT a session credential (X-Debug) must not promote the
    // session — hasUsableAuthProfile is a positive allowlist (Authorization/Cookie), not "any key
    // that isn't known metadata", so an unrecognized header cannot silently auth the session.
    authStore({ target_domain: domain, profile_name: "attacker", headers: { "X-Debug": "true" } });
    advanceTopology(domain, "OPEN_FRONTIER");
    assert.equal(readSessionNucleus(domain).auth_context.auth_status, "pending");
  });
});

test("auth_status: a prior explicit 'unauthenticated' is carried forward across a later advance even when a profile exists", () => {
  withTempHome(() => {
    const domain = "auth-noauth-sticky.example.test";
    bootstrapDomain(domain);
    // A usable profile is captured, but the operator ran --no-auth (explicit unauthenticated).
    authStore({ target_domain: domain, profile_name: "attacker", cookies: { sess: "abc123" } });
    advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER", auth_status: "unauthenticated" });
    assert.equal(readSessionNucleus(domain).auth_context.auth_status, "unauthenticated");
    // A LATER advance that omits auth_status must NOT silently flip it back to "authenticated"
    // just because a profile is on disk — the operator-asserted negative is sticky.
    advanceSession({
      target_domain: domain,
      to_state: "CLAIM_FREEZE",
      override: "operator_force",
      override_reason: "auth-status carry-forward test bypasses the freeze content gate",
    });
    assert.equal(readSessionNucleus(domain).auth_context.auth_status, "unauthenticated");
    assert.equal(JSON.parse(fs.readFileSync(statePath(domain), "utf8")).auth_status, "unauthenticated");
  });
});

test("auth_status: an explicit 'authenticated' with NO stored profile and NO operator_force is NOT honored (no forged provenance)", () => {
  withTempHome(() => {
    const domain = "auth-forge-guard.example.test";
    bootstrapDomain(domain);
    // No profile is stored. A plain caller asserting "authenticated" must not be able to forge
    // credential provenance — the unbacked positive claim is ignored and derivation keeps it pending.
    advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER", auth_status: "authenticated" });
    assert.equal(readSessionNucleus(domain).auth_context.auth_status, "pending");
  });
});

test("auth_status: an explicit 'authenticated' under operator_force IS honored (operator authority)", () => {
  withTempHome(() => {
    const domain = "auth-force-authed.example.test";
    bootstrapDomain(domain);
    // operator_force is the deliberate operator-authority path — an explicit "authenticated" is
    // honored even with no profile (the operator vouches for the credential context).
    advanceSession({
      target_domain: domain,
      to_state: "OPEN_FRONTIER",
      auth_status: "authenticated",
      override: "operator_force",
      override_reason: "operator vouches for an out-of-band authenticated context",
    });
    assert.equal(readSessionNucleus(domain).auth_context.auth_status, "authenticated");
  });
});

test("auth_status: a blank auth_status arg is treated as omitted and does NOT split-brain the nucleus vs state.json", () => {
  withTempHome(() => {
    const domain = "auth-blank-arg.example.test";
    bootstrapDomain(domain);
    // The canonical schema rejects a blank enum value, but a direct in-process caller could pass
    // one. It must be treated as OMITTED (derive), and — the headline of the round — the nucleus
    // and its state.json mirror must AGREE on the normalized value, not split-brain ("pending" vs "").
    advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER", auth_status: "" });
    const nucleusStatus = readSessionNucleus(domain).auth_context.auth_status;
    const stateStatus = JSON.parse(fs.readFileSync(statePath(domain), "utf8")).auth_status;
    assert.equal(nucleusStatus, "pending");
    assert.equal(stateStatus, "pending");
    assert.equal(nucleusStatus, stateStatus);
  });
});

test("deriveAdvanceAuthContext precedence table: operator authority > sticky --no-auth > forge-guarded explicit > derive", () => {
  const D = (prior, explicit, hasProfile, op) =>
    deriveAdvanceAuthContext({ auth_status: prior }, explicit, hasProfile, op).auth_status;
  // (1) operator_force is authority — an explicit value (incl. unbacked "authenticated") is honored.
  assert.equal(D("unauthenticated", "authenticated", false, true), "authenticated");
  assert.equal(D("authenticated", "unauthenticated", true, true), "unauthenticated");
  // (2) sticky --no-auth: a prior "unauthenticated" survives an omitted auth_status AND an
  //     UNPRIVILEGED explicit "authenticated" — even with a usable profile present. THE HEADLINE FIX.
  assert.equal(D("unauthenticated", null, true, false), "unauthenticated");
  assert.equal(D("unauthenticated", "authenticated", true, false), "unauthenticated");
  // (3) unprivileged explicit: negative/neutral always honored; positive only when backed by a profile.
  assert.equal(D("pending", "unauthenticated", false, false), "unauthenticated");
  assert.equal(D("pending", "authenticated", false, false), "pending");   // forge guard: unbacked → ignored
  assert.equal(D("pending", "authenticated", true, false), "authenticated"); // backed → honored
  // (3) no-regress: an explicit "pending" (the "unknown" state) must NOT downgrade an established
  //     milestone — even without operator_force and with no profile, an authenticated session stays
  //     authenticated (falls through to carry-forward). The forge guard blocks the reverse; this
  //     blocks the regress-to-unknown direction Codex+Claude flagged.
  assert.equal(D("authenticated", "pending", false, false), "authenticated"); // explicit "pending" cannot regress
  assert.equal(D("authenticated", "pending", true, false), "authenticated");  // (profile would derive authed anyway)
  assert.equal(D("pending", "pending", false, false), "pending");             // pending->pending is a no-op, allowed
  // (4)/(5) no explicit: derive from profile presence, else carry forward.
  assert.equal(D("pending", null, true, false), "authenticated");
  assert.equal(D("pending", null, false, false), "pending");
  assert.equal(D("authenticated", null, false, false), "authenticated");   // never auto-downgrade
});

test("deriveAdvanceAuthContext self-guards an invalid explicit value (exported fn, no call-boundary)", () => {
  // The function is exported and callable in-process WITHOUT advanceSession's boundary validation.
  // A non-blank value outside AUTH_STATUS_VALUES must throw a clear INVALID_ARGUMENTS here, not
  // propagate silently into a deep normalizeAuthContext throw at nucleus-build time.
  assert.throws(
    () => deriveAdvanceAuthContext({ auth_status: "pending" }, "bogus", false, false),
    (err) => err && err.code === "INVALID_ARGUMENTS" && /auth_status must be one of/.test(err.message),
  );
  // A NON-STRING (non-null) value is rejected outright (fail-closed, matching advanceSession's
  // boundary) rather than silently treated as omitted.
  assert.throws(
    () => deriveAdvanceAuthContext({ auth_status: "pending" }, 42, false, false),
    (err) => err && err.code === "INVALID_ARGUMENTS" && /auth_status must be a string/.test(err.message),
  );
  // A blank/whitespace explicit value is still allowed (treated as omitted → derive); so is null/omitted.
  assert.equal(deriveAdvanceAuthContext({ auth_status: "pending" }, "   ", true, false).auth_status, "authenticated");
  assert.equal(deriveAdvanceAuthContext({ auth_status: "pending" }, null, true, false).auth_status, "authenticated");
});

test("advanceSession folds the auth_context delta into the ONE canonical lifecycle.advanced event, with auth_status_changed accurate on every advance", () => {
  withTempHome(() => {
    const domain = "auth-audit-event.example.test";
    bootstrapDomain(domain);
    // A usable profile is stored, so the first advance moves auth_status pending -> authenticated.
    authStore({ target_domain: domain, profile_name: "attacker", cookies: { sess: "abc123" } });
    advanceTopology(domain, "OPEN_FRONTIER");
    // A2/A7: no separate governance.auth_context.replaced event — the auth delta
    // rides atomically on the SAME canonical event as the lifecycle move.
    assert.equal(
      authContextReplacedEvents(domain).length, 0,
      "auth delta is folded into the canonical advanced event, not a separate event",
    );
    const advanced = lifecycleAdvancedEvents(domain);
    const changedAdvance = advanced.find((e) => e.payload.auth_status_changed === true);
    assert.ok(changedAdvance, "the advance that changed auth_status carries it on the canonical event");
    assert.equal(changedAdvance.payload.from_auth_status, "pending");
    assert.equal(changedAdvance.payload.to_auth_status, "authenticated");
    assert.equal(changedAdvance.payload.had_usable_profile, true);
    assert.equal(changedAdvance.payload.explicit_auth_status_supplied, false);

    // A LATER advance that does not change auth_status (still authenticated) marks
    // auth_status_changed=false on ITS OWN canonical event rather than emitting a
    // second change-audit event.
    advanceSession({
      target_domain: domain,
      to_state: "CLAIM_FREEZE",
      override: "operator_force",
      override_reason: "auth-audit no-change test bypasses the freeze content gate",
    });
    assert.equal(readSessionNucleus(domain).auth_context.auth_status, "authenticated");
    const noChangeAdvance = lifecycleAdvancedEvents(domain).find((e) => e.payload.to_state === "CLAIM_FREEZE");
    assert.ok(noChangeAdvance, "the CLAIM_FREEZE advance still emits a canonical lifecycle.advanced event");
    assert.equal(noChangeAdvance.payload.auth_status_changed, false);
    assert.equal(noChangeAdvance.payload.from_auth_status, "authenticated");
    assert.equal(noChangeAdvance.payload.to_auth_status, "authenticated");
    assert.equal(
      authContextReplacedEvents(domain).length, 0,
      "still no separate auth_context.replaced event",
    );
  });
});

test("advanceSession rejects an invalid (non-blank) auth_status at the call boundary", () => {
  withTempHome(() => {
    const domain = "auth-invalid-arg.example.test";
    bootstrapDomain(domain);
    assert.throws(
      () => advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER", auth_status: "bogus" }),
      (err) => err && err.code === "INVALID_ARGUMENTS" && /auth_status must be one of/.test(err.message),
    );
    // The rejected call must not have advanced the nucleus.
    assert.equal(readSessionNucleus(domain).lifecycle_state, "SETUP");
  });
});

test("advanceSession trims a padded auth_status (honored, not thrown deep, and the stores agree)", () => {
  withTempHome(() => {
    const domain = "auth-padded.example.test";
    bootstrapDomain(domain);
    // A padded "  authenticated  " passes the trim-based call-boundary check; it must also be
    // TRIMMED before derivation so it is honored as "authenticated" (with a backing profile) rather
    // than passed raw and throwing on the padded enum value deep in normalizeAuthContext.
    authStore({ target_domain: domain, profile_name: "attacker", cookies: { sess: "abc123" } });
    advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER", auth_status: "  authenticated  " });
    assert.equal(readSessionNucleus(domain).auth_context.auth_status, "authenticated");
    assert.equal(JSON.parse(fs.readFileSync(statePath(domain), "utf8")).auth_status, "authenticated");
  });
});

// Seed an existing v2 verification attempt directly onto disk (bypassing a full
// lifecycle traversal) so a SUBSEQUENT VERIFY bootstrap has a real prior attempt
// to archive when it runs — exercising commitVerificationEntry's archive-dir
// write (and therefore its undo receipt) for real, not vacuously against an
// empty archives directory.
function seedPriorV2VerificationAttempt(domain) {
  const { raw, state } = readSessionStateStrict(domain);
  const priorAttemptId = "va-prior-seed-00000001";
  const priorSnapshot = {
    version: 1,
    schema_version: 2,
    target_domain: domain,
    verification_attempt_id: priorAttemptId,
    created_at: "2026-01-01T00:00:00.000Z",
    claim_freeze_id: null,
    claim_ids: [],
    finding_ids: [],
    input_hashes: {},
    snapshot_hash: "0".repeat(64),
  };
  fs.mkdirSync(path.dirname(verificationSnapshotPath(domain)), { recursive: true });
  fs.writeFileSync(verificationSnapshotPath(domain), `${JSON.stringify(priorSnapshot, null, 2)}\n`);
  writeSessionStateDocument(domain, raw, {
    ...state,
    verification_schema_version: 2,
    verification_attempt_id: priorAttemptId,
    verification_snapshot_hash: priorSnapshot.snapshot_hash,
    verification_entered_at: priorSnapshot.created_at,
  });
  return priorSnapshot;
}

test("advanceSession -> VERIFY: a throw in the widened window between commitVerificationEntry and commitSessionAuthority invokes the verification undo receipt", () => {
  withTempHome(() => {
    const domain = "verify-undo-widened-window.example.com";
    bootstrapDomain(domain);
    advanceTopology(domain, "OPEN_FRONTIER");
    advanceTopology(domain, "CLAIM_FREEZE");
    const priorSnapshot = seedPriorV2VerificationAttempt(domain);

    const statePreBytes = fs.readFileSync(statePath(domain));
    const nucleusPreBytes = fs.readFileSync(sessionNucleusPath(domain));
    const eventsPreBytes = fs.readFileSync(sessionEventsJsonlPath(domain));

    const originalCommit = verificationModule.commitVerificationEntry;
    verificationModule.commitVerificationEntry = (targetDomain, built) => {
      // Perform the REAL write (the new attempt's archive dir + snapshot land on
      // disk for real, archiving priorSnapshot), then fail from the WIDENED
      // window (advanceSession's own state/event computation, reached via
      // accessing .state_fields) rather than from commitSessionAuthority's CAS
      // call — proving the undo receipt covers more than just a CAS throw.
      const real = originalCommit(targetDomain, built);
      return {
        ...real,
        get state_fields() {
          throw new Error("simulated failure inside the widened rollback window (pre-CAS)");
        },
      };
    };

    let captured = null;
    try {
      advanceSession({ target_domain: domain, to_state: "VERIFY" });
    } catch (error) {
      captured = error;
    } finally {
      verificationModule.commitVerificationEntry = originalCommit;
    }

    assert.ok(captured, "advanceSession -> VERIFY must throw when the widened window throws");
    assert.match(captured.message, /simulated failure inside the widened rollback window/);

    // The verification undo receipt must have reversed the REAL archive-dir
    // write commitVerificationEntry performed before the throw.
    const archiveDirs = fs.existsSync(verificationAttemptsDir(domain))
      ? fs.readdirSync(verificationAttemptsDir(domain))
      : [];
    assert.deepEqual(archiveDirs, [], "the archive dir created by commitVerificationEntry must be removed by undo()");
    assert.deepEqual(
      JSON.parse(fs.readFileSync(verificationSnapshotPath(domain), "utf8")),
      priorSnapshot,
      "verification-snapshot.json must be restored to its exact pre-advance bytes",
    );

    // The throw happened before commitSessionAuthority was ever called, so the
    // three lifecycle-authority stores must be byte-identical to their pre-call
    // snapshots.
    assert.deepEqual(fs.readFileSync(statePath(domain)), statePreBytes);
    assert.deepEqual(fs.readFileSync(sessionNucleusPath(domain)), nucleusPreBytes);
    assert.deepEqual(fs.readFileSync(sessionEventsJsonlPath(domain)), eventsPreBytes);
    assert.equal(readSessionNucleus(domain).lifecycle_state, "CLAIM_FREEZE");
  });
});

test("advanceSession -> VERIFY: a nucleus CAS mismatch reached THROUGH advanceSession invokes the verification undo receipt and leaves state.json/session-events.jsonl untouched", () => {
  withTempHome(() => {
    const domain = "verify-cas-mismatch-through-advance.example.com";
    bootstrapDomain(domain);
    advanceTopology(domain, "OPEN_FRONTIER");
    advanceTopology(domain, "CLAIM_FREEZE");
    const priorSnapshot = seedPriorV2VerificationAttempt(domain);

    const statePreBytes = fs.readFileSync(statePath(domain));
    const eventsPreBytes = fs.readFileSync(sessionEventsJsonlPath(domain));
    const preNucleus = readSessionNucleus(domain);

    // A self-consistent nucleus with a DIFFERENT nucleus_hash, simulating a
    // concurrent writer that mutated session-nucleus.json between advanceSession's
    // verified read (at the top of the call, before this stub runs) and its CAS
    // commit (which pinned expectedNucleusHash to the value read at that top).
    const concurrentNucleus = buildSessionNucleus({
      ...preNucleus,
      operator_constraint: { ...preNucleus.operator_constraint, operator_note: "concurrent external mutation" },
    });
    assert.notEqual(concurrentNucleus.nucleus_hash, preNucleus.nucleus_hash);

    const originalCommit = verificationModule.commitVerificationEntry;
    verificationModule.commitVerificationEntry = (targetDomain, built) => {
      const real = originalCommit(targetDomain, built);
      fs.writeFileSync(sessionNucleusPath(domain), `${JSON.stringify(concurrentNucleus, null, 2)}\n`);
      return real;
    };

    let captured = null;
    try {
      advanceSession({ target_domain: domain, to_state: "VERIFY" });
    } catch (error) {
      captured = error;
    } finally {
      verificationModule.commitVerificationEntry = originalCommit;
    }

    assert.ok(captured, "advanceSession -> VERIFY must throw on a nucleus CAS mismatch");
    assert.match(captured.message, /CAS mismatch/);

    // The verification undo receipt still fires on a CAS-call throw (not just a
    // throw in the widened window before the CAS call).
    const archiveDirs = fs.existsSync(verificationAttemptsDir(domain))
      ? fs.readdirSync(verificationAttemptsDir(domain))
      : [];
    assert.deepEqual(archiveDirs, [], "the archive dir created by commitVerificationEntry must be removed by undo()");
    assert.deepEqual(
      JSON.parse(fs.readFileSync(verificationSnapshotPath(domain), "utf8")),
      priorSnapshot,
      "verification-snapshot.json must be restored to its exact pre-advance bytes",
    );

    // advanceSession's OWN write never landed: state.json and session-events.jsonl
    // (which only advanceSession's failed transaction could have touched) are
    // byte-identical to their pre-call snapshots.
    assert.deepEqual(fs.readFileSync(statePath(domain)), statePreBytes);
    assert.deepEqual(fs.readFileSync(sessionEventsJsonlPath(domain)), eventsPreBytes);
    // session-nucleus.json reflects the concurrent writer's data, NOT
    // advanceSession's own (correctly rejected) attempted overwrite — the CAS
    // mismatch protects the concurrent writer rather than silently clobbering it.
    assert.deepEqual(
      JSON.parse(fs.readFileSync(sessionNucleusPath(domain), "utf8")),
      concurrentNucleus,
    );
  });
});
