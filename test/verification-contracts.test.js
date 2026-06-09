const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  computeAdjudicationPlanHash,
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");
const recordCandidateClaimTool = require("../mcp/lib/tools/record-candidate-claim.js");
const recordFinding = recordCandidateClaimTool.handler;
const {
  readGradeVerdict,
  writeGradeVerdict,
} = require("../mcp/lib/grade-verdict-store.js");
const {
  gradeArtifactPaths,
  sessionDir,
  statePath,
  verificationAttemptsDir,
  verificationRoundPaths,
} = require("../mcp/lib/paths.js");
const {
  readSessionArtifactSummary,
} = require("../mcp/lib/pipeline-session-artifacts.js");
const {
  artifactDivergence,
  buildVerificationAdjudication,
  prepareVerificationEntry,
  readVerificationContext,
} = require("../mcp/lib/verification.js");
const {
  listArchivedVerificationAttempts,
  summarizeVerificationRoundArtifact,
} = require("../mcp/lib/verification-status-contracts.js");
const {
  readVerificationRound,
  writeVerificationRound,
} = require("../mcp/lib/verification-round-store.js");
const {
  writeEvidencePacks,
} = require("../mcp/lib/evidence.js");
const {
  acquireSessionLock,
  writeFileAtomic,
} = require("../mcp/lib/storage.js");
const {
  normalizeSessionStateDocument,
} = require("../mcp/lib/session-state-contracts.js");
const {
  readSessionStateStrict,
} = require("../mcp/lib/session-state-store.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-verification-contracts-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

test("session state contract normalizes and reads the shared state shape", () => {
  withTempHome(() => {
    const domain = "state-contract.example";
    // Cycle D.3 removed state.explored / state.terminally_blocked /
    // state.lead_surface_ids from the session-state contract; the legacy
    // disjointness invariant is gone because the frontier projection is
    // self-disjoint (latest surface-state event wins).
    const raw = {
      target: domain,
      target_url: `https://${domain}`,
      phase: "EVALUATE",
    };
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    writeFileAtomic(statePath(domain), `${JSON.stringify(raw, null, 2)}\n`);

    const normalized = normalizeSessionStateDocument(raw, domain);
    const read = readSessionStateStrict(domain);

    assert.equal(read.state.target, domain);
    assert.deepEqual(read.state, normalized);
    assert.equal(read.state.checkpoint_mode, "normal");
    assert.equal(read.state.block_internal_hosts, false);
    assert.equal(read.state.block_internal_hosts_source, "legacy_default");
    assert.equal(read.state.egress_profile, "default");
    assert.equal(read.state.verification_schema_version, null);
    // The deleted projection fields no longer appear on the normalized state.
    assert.ok(!Object.prototype.hasOwnProperty.call(read.state, "explored"));
    assert.ok(!Object.prototype.hasOwnProperty.call(read.state, "terminally_blocked"));
    assert.ok(!Object.prototype.hasOwnProperty.call(read.state, "lead_surface_ids"));
  });
});

function findingInput(domain, overrides = {}) {
  return {
    target_domain: domain,
    title: "IDOR exposes billing profile",
    severity: "high",
    cwe: "CWE-639",
    endpoint: "https://victim.example/api/billing/123",
    description: "Changing the billing profile identifier returns another tenant's billing metadata.",
    proof_of_concept: "GET /api/billing/123 as a different tenant returns private billing fields.",
    response_evidence: "Response included another tenant billing_profile_id and billing email.",
    impact: "Cross-tenant billing metadata disclosure.",
    validated: true,
    auth_profile: "attacker",
    ...overrides,
  };
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

function v2VerificationResult(findingId = "F-1", overrides = {}) {
  return {
    ...verificationResult(findingId),
    confidence: "high",
    confidence_reasons: ["fresh_replay_passed"],
    state_sensitive: false,
    artifact_hashes: {},
    ...overrides,
  };
}

function evidencePack(findingId = "F-1", overrides = {}) {
  return {
    finding_id: findingId,
    sample_type: "cross-account replay",
    sample_count: 1,
    aggregate_counts: { affected_objects_sampled: 1 },
    representative_samples: [{
      request_ref: "http-audit:1",
      endpoint: "/api/billing/123",
      auth_profile: "attacker",
      status: 200,
      observed_fields: ["billing_profile_id", "email"],
      redacted_object_id: "acct_...002",
    }],
    sensitive_clusters: ["billing metadata"],
    replay_summary: "Fresh replay returned another tenant's private billing metadata.",
    redaction_notes: "Object IDs and personal values redacted; auth material omitted.",
    report_snippet: "An attacker can retrieve another tenant's private billing metadata by changing the billing profile ID.",
    ...overrides,
  };
}

function seedFinding(domain) {
  return JSON.parse(recordFinding(findingInput(domain))).finding_id;
}

function seedFinalVerification(domain) {
  seedFinding(domain);
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain,
      round,
      notes: null,
      results: [verificationResult("F-1")],
    });
  }
}

function writeVerifyState(domain, stateFields, overrides = {}) {
  writeFileAtomic(statePath(domain), `${JSON.stringify({
    target: domain,
    target_url: `https://${domain}`,
    deep_mode: false,
    phase: "VERIFY",
    evaluation_wave: 0,
    pending_wave: null,
    total_findings: 1,
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
    auth_status: "unauthenticated",
    operator_note: null,
    ...stateFields,
    ...overrides,
  }, null, 2)}\n`);
}

function gradeFinding(findingId = "F-1", overrides = {}) {
  return {
    finding_id: findingId,
    impact: 25,
    proof_quality: 20,
    severity_accuracy: 10,
    chain_potential: 10,
    report_quality: 10,
    total_score: 75,
    feedback: "Clear, reproducible, and reportable.",
    ...overrides,
  };
}

test("hashCanonicalJson is stable across object key ordering", () => {
  assert.equal(
    hashCanonicalJson({ b: 2, a: { d: 4, c: 3 } }),
    hashCanonicalJson({ a: { c: 3, d: 4 }, b: 2 }),
  );
});

test("computeAdjudicationPlanHash ignores volatile adjudication metadata", () => {
  const base = {
    target_domain: "example.com",
    input_round_hashes: { brutalist: "a", balanced: "b" },
    replay_required: [],
  };
  assert.equal(
    computeAdjudicationPlanHash({
      ...base,
      adjudication_plan_hash: "old",
      built_at: "2026-05-15T00:00:00.000Z",
    }),
    computeAdjudicationPlanHash({
      ...base,
      adjudication_plan_hash: "new",
      built_at: "2026-05-16T00:00:00.000Z",
    }),
  );
});

test("artifactDivergence is deterministic and only flags both-replayed artifact divergence", () => {
  const replayed = (artifactHashes, overrides = {}) => v2VerificationResult("F-1", {
    artifact_hashes: artifactHashes,
    ...overrides,
  });

  assert.equal(
    artifactDivergence(
      replayed({ sqli_response: "1".repeat(64) }),
      replayed({ xss_response: "2".repeat(64) }),
    ),
    "artifact_key_divergence",
  );
  assert.equal(
    artifactDivergence(
      replayed({ shared_response: "1".repeat(64) }),
      replayed({ shared_response: "2".repeat(64) }),
    ),
    "artifact_hash_divergence",
  );
  assert.equal(
    artifactDivergence(
      replayed({ sqli_response: "1".repeat(64) }),
      replayed(
        { xss_response: "2".repeat(64) },
        { confidence_reasons: ["agreement_not_replayed"] },
      ),
    ),
    "none",
  );
  assert.equal(
    artifactDivergence(
      replayed({}),
      replayed({ xss_response: "2".repeat(64) }),
    ),
    "none",
  );
  assert.equal(
    artifactDivergence(
      undefined,
      replayed({ xss_response: "2".repeat(64) }),
    ),
    "none",
  );
  assert.equal(
    artifactDivergence(
      replayed(
        { sqli_response: "1".repeat(64) },
        { confidence_reasons: "fresh_replay_passed" },
      ),
      replayed({ xss_response: "2".repeat(64) }),
    ),
    "none",
  );
  assert.equal(
    artifactDivergence(
      replayed({
        z_response: "1".repeat(64),
        a_response: "2".repeat(64),
      }),
      replayed({
        a_response: "2".repeat(64),
        z_response: "1".repeat(64),
      }),
    ),
    "none",
  );
});

test("verification round store writes, reads, mirrors markdown, and enforces prior-round coverage", () => {
  withTempHome(() => {
    const domain = "verification-round-store.example.com";
    seedFinding(domain);

    const brutalist = JSON.parse(writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: "independent review",
      results: [verificationResult("F-1")],
    }));
    assert.equal(brutalist.round, "brutalist");
    assert.equal(brutalist.schema_version, 1);

    assert.throws(
      () => writeVerificationRound({
        target_domain: domain,
        round: "balanced",
        notes: null,
        results: [],
      }),
      /balanced round is missing 1 finding\(s\) from brutalist round: F-1/,
    );

    writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: null,
      results: [verificationResult("F-1")],
    });
    const read = JSON.parse(readVerificationRound({ target_domain: domain, round: "balanced" }));
    assert.deepEqual(read.results.map((result) => result.finding_id), ["F-1"]);

    const markdown = fs.readFileSync(verificationRoundPaths(domain, "balanced").markdown, "utf8");
    assert.match(markdown, /Verification Round: balanced/);
    assert.match(markdown, /## F-1/);
  });
});

test("grade verdict store requires final verification and valid evidence before read/write", () => {
  withTempHome(() => {
    const missingFinalDomain = "grade-missing-final.example.com";
    seedFinding(missingFinalDomain);
    assert.throws(
      () => writeGradeVerdict({
        target_domain: missingFinalDomain,
        verdict: "SUBMIT",
        total_score: 75,
        findings: [gradeFinding("F-1")],
      }),
      /Final verification must exist and be valid before grading/,
    );

    const missingEvidenceDomain = "grade-missing-evidence.example.com";
    seedFinalVerification(missingEvidenceDomain);
    assert.throws(
      () => writeGradeVerdict({
        target_domain: missingEvidenceDomain,
        verdict: "SUBMIT",
        total_score: 75,
        findings: [gradeFinding("F-1")],
      }),
      /Evidence packs are required/,
    );

    const domain = "grade-store.example.com";
    seedFinalVerification(domain);
    writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
    const written = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    }));
    assert.equal(written.verdict, "SUBMIT");
    assert.equal(fs.existsSync(gradeArtifactPaths(domain).markdown), true);

    const evidencePath = path.join(sessionDir(domain), "evidence-packs.json");
    const evidence = JSON.parse(fs.readFileSync(evidencePath, "utf8"));
    writeFileAtomic(evidencePath, `${JSON.stringify({ ...evidence, target_domain: "stale.example.com" }, null, 2)}\n`);
    assert.throws(
      () => readGradeVerdict({ target_domain: domain }),
      /Evidence packs are required/,
    );
    const analytics = readSessionArtifactSummary(domain);
    assert.equal(analytics.grade.valid, false);
    assert.match(analytics.grade.error, /Evidence packs are required/);
  });
});

test("verification status contract keeps verification context and analytics aligned for current and archived attempts", () => {
  withTempHome(() => {
    const domain = "verification-status.example.com";
    seedFinalVerification(domain);

    const archiveDir = path.join(verificationAttemptsDir(domain), "attempt-old-1");
    fs.mkdirSync(archiveDir, { recursive: true });
    writeFileAtomic(path.join(archiveDir, "manifest.json"), `${JSON.stringify({
      attempt_id: "old-1",
      archived_at: "2026-05-15T00:00:00.000Z",
      snapshot_hash: "abc123",
      adjudication_plan_hash: "plan123",
      final_verification_hash: "final123",
      files: { "verification-final.json": "hash" },
      missing_files: [],
    }, null, 2)}\n`);

    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const analytics = readSessionArtifactSummary(domain);
    assert.deepEqual(context.archived_attempts, analytics.verification.archived_attempts);

    for (const round of ["brutalist", "balanced", "final"]) {
      assert.equal(context.round_status[round].results_count, analytics.verification.rounds[round].results_count);
      assert.equal(context.round_status[round].reportable_count, analytics.verification.rounds[round].reportable_count);
      assert.equal(context.round_status[round].current, analytics.verification.rounds[round].current);
    }

    const finalDocument = JSON.parse(fs.readFileSync(verificationRoundPaths(domain, "final").json, "utf8"));
    const direct = summarizeVerificationRoundArtifact({
      targetDomain: domain,
      round: "final",
      exists: true,
      document: finalDocument,
    });
    assert.deepEqual(direct.final_reportable_ids, analytics.verification.final_reportable_ids);
    assert.deepEqual(listArchivedVerificationAttempts(domain), analytics.verification.archived_attempts);
  });
});

test("writeVerificationRound uses the session lock before mutating artifacts", () => {
  withTempHome(() => {
    const domain = "verification-lock.example.com";
    const release = acquireSessionLock(domain);
    try {
      assert.throws(
        () => writeVerificationRound({
          target_domain: domain,
          round: "balanced",
          notes: null,
          results: [],
        }),
        /Session lock busy/,
      );
    } finally {
      release();
    }
  });
});

test("verification adjudication and grade writers use the session lock before mutating artifacts", () => {
  withTempHome(() => {
    const domain = "verification-lock-more.example.com";
    const release = acquireSessionLock(domain);
    try {
      assert.throws(
        () => buildVerificationAdjudication({ target_domain: domain }),
        /Session lock busy/,
      );
      assert.throws(
        () => writeGradeVerdict({
          target_domain: domain,
          verdict: "HOLD",
          total_score: 0,
          findings: [],
          feedback: null,
        }),
        /Session lock busy/,
      );
    } finally {
      release();
    }
  });
});

test("verification status contract reports frozen-payload rounds as current even after findings.jsonl mutation", () => {
  // Cycle C.4: the verification snapshot is sourced from the immutable
  // claim-freeze.json, so a brutalist round that covers the frozen
  // CandidateClaim set must continue to read as `current: true` even when a
  // new finding is appended to findings.jsonl after the snapshot. The freeze
  // hash is the integrity check; the live findings ledger is no longer
  // re-scanned on every status read.
  withTempHome(() => {
    const domain = "verification-status-v2.example.com";
    seedFinding(domain);
    const entry = prepareVerificationEntry(domain, {
      phase: "CHAIN",
      verification_schema_version: null,
      verification_attempt_id: null,
      verification_snapshot_hash: null,
    }, { now: new Date("2026-05-15T00:00:00.000Z") });
    writeVerifyState(domain, entry.state_fields);

    writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: "v2 current before findings.jsonl mutation",
      verification_attempt_id: entry.state_fields.verification_attempt_id,
      verification_snapshot_hash: entry.state_fields.verification_snapshot_hash,
      round_profile: "brutalist",
      results: [v2VerificationResult("F-1")],
    });

    recordFinding(findingInput(domain, {
      title: "New post-snapshot reportable finding",
      endpoint: "https://victim.example/api/billing/456",
      proof_of_concept: "GET /api/billing/456 after the snapshot returns another tenant's private billing fields.",
      response_evidence: "Post-snapshot response included another tenant billing_profile_id.",
      force_record: true,
    }));

    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const analytics = readSessionArtifactSummary(domain);
    assert.equal(context.round_status.brutalist.current, true);
    assert.equal(analytics.verification.rounds.brutalist.current, true);
    assert.equal(context.round_status.brutalist.stale, false);
    assert.equal(analytics.verification.rounds.brutalist.stale, false);
    assert.equal(
      analytics.verification.rounds.brutalist.blocker_reason,
      context.round_status.brutalist.blocker_reason,
    );
    assert.equal(context.round_status.brutalist.blocker_reason, null);
  });
});

test("verification status contract keeps malformed round errors aligned between context and analytics", () => {
  withTempHome(() => {
    const domain = "verification-status-malformed.example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    writeFileAtomic(verificationRoundPaths(domain, "brutalist").json, "{bad json");

    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const analytics = readSessionArtifactSummary(domain);
    assert.equal(
      analytics.verification.rounds.brutalist.blocker_reason,
      context.round_status.brutalist.blocker_reason,
    );
    assert.match(context.round_status.brutalist.blocker_reason, /Malformed brutalist verification round JSON/);
  });
});
