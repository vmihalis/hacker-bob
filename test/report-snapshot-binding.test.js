"use strict";

// Cycle C.7 invariant: bob_finalize_report appends a ReportSnapshot row to
// report-snapshots.jsonl that binds five hashes:
//
//   - claim_freeze_hash       (claim-freeze.json freeze_hash)
//   - final_verification_hash (V2 final verification round)
//   - evidence_hash           (sha256 of canonical packs[] manifest)
//   - grade_verdict_hash      (sha256 of canonical grade.json)
//   - report_content_hash     (sha256 of report.md content)
//
// The five-hash binding is the realization of the C.7 ReportSnapshot ledger:
// a downstream consumer can read one snapshot row, hash the on-disk artifacts,
// and prove the report was finalized over an exact CLAIM_FREEZE → VERIFY →
// GRADE → REPORT chain. Re-running finalize after a report.md mutation
// produces a new row with a different report_content_hash; a missing
// upstream (no freeze / no final verification / no grade verdict / no
// evidence pack) refuses finalization.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const finalizeReportTool = require("../mcp/lib/tools/finalize-report.js");
const recordFindingTool = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  _setApprovalBackendForTest,
  _setApprovalHmacKeyForTest,
} = require("../mcp/lib/approval-store.js");
const {
  buildClaimFreeze,
  readCurrentClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  writeEvidencePacks,
} = require("../mcp/lib/evidence.js");
const {
  writeGradeVerdict,
} = require("../mcp/lib/grade-verdict-store.js");
const {
  loadGradeVerdictHash,
} = require("../mcp/lib/report-finalize.js");
const {
  normalizeProofBundlesDocument,
} = require("../mcp/lib/proof-bundle.js");
const {
  verifyReproReproduction,
} = require("../mcp/lib/repro-replay-verifier.js");
const {
  writeVerificationRound,
} = require("../mcp/lib/verification-round-store.js");
const {
  readReportSnapshots,
} = require("../mcp/lib/report-snapshots.js");
const {
  readFrontierEvents,
} = require("../mcp/lib/frontier-events.js");
const {
  evidencePackPaths,
  gradeArtifactPaths,
  proofBundlePaths,
  repoCommandRunsJsonlPath,
  repoRunsDir,
  reportMarkdownPath,
  sessionDir,
  statePath,
  verificationRoundPaths,
  claimFreezePath,
  findingDifferentialVerifiedJsonlPath,
} = require("../mcp/lib/paths.js");
const {
  finalVerificationHash,
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");
const {
  appendJsonlLine,
  writeFileAtomic,
} = require("../mcp/lib/storage.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");
const {
  persistingRunner,
} = require("./helpers/repro-run-pair.js");
const { withIsolatedSigner } = require("./helpers/sandbox-isolated-signer.js");

const HASH_HEX_RE = /^[a-f0-9]{64}$/;

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-report-snapshot-binding-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previousHome;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// Seed a genuine, re-derivable finding-differential verified_pass arm: a real MAC-signed
// exploited_safely positive + blocked_by_defense control (high demonstrated severity, same
// surface, distinct command_hash) + the verdict line binding them. Post-A1 the grade gate
// re-resolves the verdict against these MAC-covered rows, so a bare ledger line no longer
// suffices.
function seedFindingDifferentialArm(domain, findingId = "F-1", surfaceId = "surface:billing-profile") {
  const { canonicalizeExploitTarget } = require("../mcp/lib/claims.js");
  const { ensureHandoffSigningKey } = require("../mcp/lib/handoff-signing-key.js");
  const { signOffensiveRunRow } = require("../mcp/lib/offensive-row-mac.js");
  const { offensiveRowHash } = require("../mcp/lib/finding-differential-verifier.js");
  const { offensiveRunsJsonlPath } = require("../mcp/lib/paths.js");
  const mkRow = (suffix, outcome, ch) => {
    const row = {
      version: 1, target_domain: domain, run_id: `${findingId}-${suffix}`, tool_id: "bob_http_idor_confirm",
      target: canonicalizeExploitTarget(`https://${domain}/api/billing/1`),
      offensive_outcome: outcome, dry_run: false, timed_out: false,
      command_hash: ch, exit_code: 0, stdout_hash: "b".repeat(64), stderr_hash: "c".repeat(64),
      demonstrated_severity: "high", surface_id: surfaceId,
    };
    signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
    return row;
  };
  const positive = mkRow("pos", "exploited_safely", "1".repeat(64));
  const control = mkRow("ctl", "blocked_by_defense", "2".repeat(64));
  appendJsonlLine(findingDifferentialVerifiedJsonlPath(domain), {
    version: 1, target_domain: domain, finding_id: findingId, result: "verified_pass",
    reason: "executed_finding_differential_flip", surface_id: surfaceId, source: "offensive_runs",
    positive_run_id: `${findingId}-pos`, positive_row_hash: offensiveRowHash(positive),
    control_run_id: `${findingId}-ctl`, control_row_hash: offensiveRowHash(control),
  });
}

// Mirror of the seedSessionState helper used by mcp-server.test.js. The
// verification-write path requires a baseline state document so its
// schema-version probe selects V1 (no verification-input-snapshot.json on
// disk yet, no V2 marker in state).
function seedSessionState(domain, overrides = {}) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  const state = {
    target: domain,
    target_url: `https://${domain}`,
    deep_mode: false,
    checkpoint_mode: "normal",
    block_internal_hosts: false,
    block_internal_hosts_source: "legacy_default",
    phase: "REPORT",
    evaluation_wave: 1,
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
    auth_status: "authenticated",
    egress_profile: "default",
    egress_region: null,
    proxy_configured: false,
    egress_profile_identity_hash: null,
    egress_profile_identity_version: null,
    egress_profile_identity_bound_at: null,
    egress_profile_identity_bind_source: null,
    operator_note: null,
    verification_schema_version: null,
    verification_attempt_id: null,
    verification_snapshot_hash: null,
    verification_entered_at: null,
    ...overrides,
  };
  writeFileAtomic(statePath(domain), `${JSON.stringify(state, null, 2)}\n`);
  return state;
}

function recordFinding(domain, overrides = {}) {
  return JSON.parse(recordFindingTool.handler({
    target_domain: domain,
    title: overrides.title || "IDOR on billing profile",
    severity: overrides.severity || "high",
    cwe: overrides.cwe || "CWE-639",
    endpoint: overrides.endpoint || "https://victim.example/api/billing/1",
    description: overrides.description || "Tenant boundary allows cross-account view",
    proof_of_concept: overrides.poc || "GET /api/billing/1 returns another tenant payload",
    response_evidence: overrides.response_evidence || "Cross-tenant billing payload",
    impact: overrides.impact || "Cross-tenant billing disclosure",
    validated: true,
    auth_profile: overrides.auth_profile || "attacker",
    surface_id: overrides.surface_id || "surface:billing-profile",
    // Cross-tenant IDOR disclosure: network-reachable, low-privilege attacker
    // tenant, confidentiality impact.
    cvss_inputs: overrides.cvss_inputs || {
      attack_vector: "network",
      privileges_required: "low",
      confidentiality: "high",
    },
  }));
}

function evidencePackInput(findingId = "F-1", overrides = {}) {
  return {
    finding_id: findingId,
    sample_type: "cross-account replay",
    sample_count: 1,
    aggregate_counts: { affected_objects_sampled: 1 },
    representative_samples: [{
      request_ref: "http-audit:1",
      endpoint: "/api/billing/1",
      auth_profile: "attacker",
      status: 200,
      observed_fields: ["billing_profile_id"],
      redacted_object_id: "acct_...002",
    }],
    sensitive_clusters: ["billing metadata"],
    replay_summary: "Fresh replay returned another tenant's private billing metadata.",
    redaction_notes: "Object IDs and personal values redacted; auth material omitted.",
    report_snippet: "An attacker can retrieve another tenant's private billing metadata by changing the billing profile ID.",
    ...overrides,
  };
}

function gradeFindingInput(findingId = "F-1", overrides = {}) {
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

// Drive the entire pipeline up to (but not including) finalize. Writes a
// freeze, a V1 verification chain through final, evidence packs, a grade
// verdict, then upgrades the V1 final round document on disk to a V2 shape
// with a freeze-bound verification_snapshot_hash + final_verification_hash
// stamp so the C.7 bob_finalize_report resolver finds the four-hash chain.
// Finally writes report.md. Returns nothing; tests read the on-disk state
// via the public resolvers.
function drivePipelineToReportWritten(domain) {
  seedSessionState(domain);
  recordFinding(domain);
  buildClaimFreeze(domain, { write: true, now: new Date("2026-05-27T01:00:00.000Z") });

  // V1 verification chain (brutalist + balanced + final). The
  // selectVerificationWriteSchemaVersion probe selects V1 here because no
  // verification-input-snapshot.json is on disk and state has no V2 marker.
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain,
      round,
      notes: null,
      results: [{
        finding_id: "F-1",
        disposition: "confirmed",
        severity: "high",
        reportable: true,
        reasoning: "Fresh replay confirmed the finding against the current target state.",
      }],
    });
  }

  // V1 evidence-pack write is allowed because the final round is V1 at this
  // point. (The C.5 path is V1-aware when there is no V2 attempt.)
  writeEvidencePacks({
    target_domain: domain,
    packs: [evidencePackInput("F-1")],
  });
  // The web IDOR finding is a standalone executable-flip class; seed its
  // finding-differential verified_pass arm so the grade-time standalone gate is
  // satisfied (it stays reportable, NO amputation). Post-A1 the gate re-resolves the
  // verdict against MAC-covered offensive-runs rows + re-adjudicates the flip, so seed
  // a real MAC-signed exploited_safely positive + blocked_by_defense control (high
  // demonstrated severity), then the verdict line binding them.
  seedFindingDifferentialArm(domain, "F-1", "surface:billing-profile");
  // The shared pipeline driver grades a verdict-ledger-backed reportable finding
  // to reach report.md; this helper exercises the snapshot-binding cascade, not
  // the sandbox posture, so the grade runs under an isolated signer (inert gate).
  withIsolatedSigner(() => writeGradeVerdict({
    target_domain: domain,
    verdict: "SUBMIT",
    total_score: 75,
    findings: [gradeFindingInput("F-1")],
  }));

  // C.7 requires a V2-shape final round bound to the claim freeze (the
  // final_verification_hash field is only stamped on V2 final rounds). We
  // upgrade the V1 final round in-place on disk: same results, V2 envelope,
  // freeze-derived snapshot binding. The bob_finalize_report resolver only
  // reads final_verification_hash from the document; nothing else in the
  // post-write pipeline reads this artifact between now and finalize.
  const finalPath = verificationRoundPaths(domain, "final").json;
  const v1FinalDocument = JSON.parse(fs.readFileSync(finalPath, "utf8"));
  const freeze = readCurrentClaimFreeze(domain);
  const v2FinalDocument = {
    version: 2,
    target_domain: domain,
    round: "final",
    notes: null,
    verification_attempt_id: `attempt-${freeze.freeze_id}`,
    verification_snapshot_hash: freeze.freeze_hash,
    round_profile: "final",
    adjudication_plan_hash: crypto.createHash("sha256")
      .update(`adjudication:${freeze.freeze_id}`)
      .digest("hex"),
    results: v1FinalDocument.results,
  };
  v2FinalDocument.final_verification_hash = finalVerificationHash(v2FinalDocument);
  fs.writeFileSync(finalPath, JSON.stringify(v2FinalDocument, null, 2) + "\n");

  fs.writeFileSync(reportMarkdownPath(domain), "# Bob Report\n\n## Findings\n\n- F-1: IDOR\n");
}

function sha256OfFile(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

async function appendRepoRunFixture(domain) {
  const runId = "run-proof";
  const replayCommand = ["sh", "-lc", "./repro.sh"];
  const stdout = "proof reproduced\n";
  const stderr = "";
  const replayCommandHash = crypto.createHash("sha256").update(JSON.stringify(replayCommand)).digest("hex");
  fs.mkdirSync(repoRunsDir(domain), { recursive: true });
  fs.writeFileSync(path.join(repoRunsDir(domain), `${runId}.stdout`), stdout);
  fs.writeFileSync(path.join(repoRunsDir(domain), `${runId}.stderr`), stderr);
  appendJsonlLine(repoCommandRunsJsonlPath(domain), {
    version: 1,
    target_domain: domain,
    run_id: runId,
    dry_run: false,
    command_hash: replayCommandHash,
    replay_command_hash: replayCommandHash,
    argv_hash: crypto.createHash("sha256").update(JSON.stringify(["run", "--network", "none"])).digest("hex"),
    network_mode: "none",
    mount_mode: "read_only",
    work_mount_mode: "read_write",
    replay_context: { finding_id: "F-1" },
    image_tag: `bob-oss-${domain}:stable`,
    timeout_ms: 300000,
    exit_code: 1,
    signal: null,
    timed_out: false,
    stdout_hash: crypto.createHash("sha256").update(stdout).digest("hex"),
    stderr_hash: crypto.createHash("sha256").update(stderr).digest("hex"),
    stdout_size_bytes: Buffer.byteLength(stdout),
    stderr_size_bytes: Buffer.byteLength(stderr),
    stdout_truncated: false,
    stderr_truncated: false,
  });
  // REFUTING-ARM (universal): a replay_script proof bundle now requires a
  // VERIFIED_PASS differential in repro-verified.jsonl, keyed by finding_id AND the
  // replayed command. Seed it with the real verifier: an attributable /src ASAN
  // crash on the vuln tree, clean exit 0 on the upstream-fix tree → a real flip.
  let n = 0;
  const repoDockerRunFn = async ({ checkout }) => {
    n += 1;
    if (checkout) return { run_id: `repro-control-${n}`, exit_code: 0, stdout_text: "", stderr_text: "All tests passed\n" };
    return {
      run_id: `repro-vuln-${n}`,
      exit_code: 1,
      stdout_text: "",
      stderr_text: "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x511\n    #0 0x4f1c2a in parse() /src/parser.c:1242:10\nSUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:1242:10",
    };
  };
  await verifyReproReproduction(
    { target_domain: domain, finding_id: "F-1", command: replayCommand, control_ref: "322716256d60e316c9a3b905a387be36d4e47368" },
    { repoDockerRunFn: persistingRunner(domain, repoDockerRunFn) },
  );
  return { runId, replayCommand };
}

async function writeProofBundleDocument(domain) {
  const finalRound = JSON.parse(fs.readFileSync(verificationRoundPaths(domain, "final").json, "utf8"));
  const binding = {
    verification_attempt_id: finalRound.verification_attempt_id,
    verification_snapshot_hash: finalRound.verification_snapshot_hash,
    final_verification_hash: finalRound.final_verification_hash,
  };
  const { runId, replayCommand } = await appendRepoRunFixture(domain);
  const document = normalizeProofBundlesDocument({
    version: 1,
    target_domain: domain,
    ...binding,
    packs: [{
      finding_id: "F-1",
      bundle_kind: "replay_script",
      artifacts: [{
        run_id: runId,
        replay_command: replayCommand,
        replay_summary: "Offline proof replay reproduces F-1.",
      }],
    }],
  }, {
    expectedDomain: domain,
    findingIdSet: new Set(["F-1"]),
    finalReportableIdSet: new Set(["F-1"]),
    verificationBinding: binding,
  });
  const paths = proofBundlePaths(domain);
  fs.writeFileSync(paths.json, `${JSON.stringify(document, null, 2)}\n`);
  return document;
}

test("bob_finalize_report appends a five-hash ReportSnapshot row after a full pipeline", async () => {
  await withTempHome(async () => {
    const domain = "bind.example.com";
    drivePipelineToReportWritten(domain);

    const response = JSON.parse(finalizeReportTool.handler({ target_domain: domain }));
    assert.equal(response.finalized, true);
    assert.equal(response.target_domain, domain);
    assert.match(response.snapshot_hash, HASH_HEX_RE);
    assert.match(response.claim_freeze_hash, HASH_HEX_RE);
    assert.match(response.final_verification_hash, HASH_HEX_RE);
    assert.match(response.evidence_hash, HASH_HEX_RE);
    assert.match(response.grade_verdict_hash, HASH_HEX_RE);
    assert.match(response.report_content_hash, HASH_HEX_RE);

    const snapshots = readReportSnapshots(domain);
    assert.equal(snapshots.length, 1, "report-snapshots.jsonl must hold exactly one row after a single finalize");
    const row = snapshots[0];
    assert.match(row.claim_freeze_hash, HASH_HEX_RE);
    assert.match(row.final_verification_hash, HASH_HEX_RE);
    assert.match(row.evidence_hash, HASH_HEX_RE);
    assert.match(row.grade_verdict_hash, HASH_HEX_RE);
    assert.match(row.report_content_hash, HASH_HEX_RE);
    assert.equal(row.claim_freeze_hash, response.claim_freeze_hash);
    assert.equal(row.final_verification_hash, response.final_verification_hash);
    assert.equal(row.evidence_hash, response.evidence_hash);
    assert.equal(row.grade_verdict_hash, response.grade_verdict_hash);
    assert.equal(row.report_content_hash, response.report_content_hash);

    // The report content hash on the snapshot row must match a fresh sha256
    // of the report.md file on disk.
    assert.equal(
      row.report_content_hash,
      sha256OfFile(reportMarkdownPath(domain)),
      "snapshot report_content_hash must match sha256(report.md)",
    );

    // A claim.report_snapshot.appended frontier event must accompany the row.
    const events = readFrontierEvents(domain)
      .filter((event) => event.kind === "claim.report_snapshot.appended");
    assert.equal(events.length, 1, "exactly one claim.report_snapshot.appended event must be emitted per finalize");
    assert.equal(events[0].payload.snapshot_id, row.snapshot_id);
    assert.equal(events[0].payload.report_content_hash, row.report_content_hash);
  });
});

// fx-gate-hardening (P1-3): bob_finalize_report must apply the SAME GRADE -> REPORT
// human-approval blocker gateGradeToReport enforces at the bob_advance_session transition --
// a defense-in-depth re-check for the append-only/re-finalizable nature of this tool (its own
// description: "subsequent calls produce a new row ... re-finalize after a report.md edit").
// Both branches (blocked when BOB_AGENTCORE=1 with no valid artifact; a complete no-op when
// BOB_AGENTCORE is unset) are asserted here against the exact same drivePipelineToReportWritten
// pipeline the unguarded test above already proved succeeds.
test("bob_finalize_report is blocked by the GRADE -> REPORT approval gate under BOB_AGENTCORE=1 with no valid artifact", async () => {
  await withTempHome(async () => {
    const domain = "finalize-approval-blocked.example.com";
    drivePipelineToReportWritten(domain);

    const previousAgentcore = process.env.BOB_AGENTCORE;
    process.env.BOB_AGENTCORE = "1";
    try {
      let captured = null;
      try {
        finalizeReportTool.handler({ target_domain: domain });
      } catch (error) {
        captured = error;
      }
      assert.ok(captured, "bob_finalize_report must throw when BOB_AGENTCORE=1 and no approval artifact exists");
      assert.equal(captured.code, "STATE_CONFLICT");
      assert.equal(captured.details.blocked_by, "external_approval_pending");
      assert.equal(captured.details.target_domain, domain);
      // Nothing must have been written -- a blocked finalize is not a partial finalize.
      assert.equal(readReportSnapshots(domain).length, 0);
    } finally {
      if (previousAgentcore === undefined) delete process.env.BOB_AGENTCORE;
      else process.env.BOB_AGENTCORE = previousAgentcore;
    }
  });
});

test("bob_finalize_report succeeds under BOB_AGENTCORE=1 once a valid, content-bound HMAC-verified artifact exists", async () => {
  await withTempHome(async () => {
    const domain = "finalize-approval-admitted.example.com";
    drivePipelineToReportWritten(domain);

    const previousAgentcore = process.env.BOB_AGENTCORE;
    process.env.BOB_AGENTCORE = "1";
    _setApprovalHmacKeyForTest("finalize-approval-test-key");
    // fx-hmac-content: the artifact must be bound to the CURRENT grade_verdict_hash
    // (drivePipelineToReportWritten already wrote a real grade.json via writeGradeVerdict), not
    // just target_domain -- mirrors the production ApprovalWriterFunction's signing scheme.
    _setApprovalBackendForTest((targetDomain) => {
      const gradeVerdictHash = loadGradeVerdictHash(targetDomain);
      const hmac = crypto.createHmac("sha256", "finalize-approval-test-key")
        .update(`${targetDomain}|${gradeVerdictHash}`, "utf8").digest("hex");
      return JSON.stringify({ hmac, grade_verdict_hash: gradeVerdictHash });
    });
    try {
      const response = JSON.parse(finalizeReportTool.handler({ target_domain: domain }));
      assert.equal(response.finalized, true);
      assert.equal(readReportSnapshots(domain).length, 1);
    } finally {
      if (previousAgentcore === undefined) delete process.env.BOB_AGENTCORE;
      else process.env.BOB_AGENTCORE = previousAgentcore;
      _setApprovalBackendForTest(null);
      _setApprovalHmacKeyForTest(null);
    }
  });
});

test("bob_finalize_report approval gate is a complete no-op when BOB_AGENTCORE is unset", async () => {
  await withTempHome(async () => {
    const domain = "finalize-approval-inert.example.com";
    drivePipelineToReportWritten(domain);

    const previousAgentcore = process.env.BOB_AGENTCORE;
    delete process.env.BOB_AGENTCORE;
    try {
      const response = JSON.parse(finalizeReportTool.handler({ target_domain: domain }));
      assert.equal(response.finalized, true);
    } finally {
      if (previousAgentcore === undefined) delete process.env.BOB_AGENTCORE;
      else process.env.BOB_AGENTCORE = previousAgentcore;
    }
  });
});

test("bob_finalize_report binds proof bundles when report cites proof_bundle refs", async () => {
  await withTempHome(async () => {
    const domain = "bind-proof.example.com";
    drivePipelineToReportWritten(domain);
    const proofDocument = await writeProofBundleDocument(domain);
    fs.writeFileSync(
      reportMarkdownPath(domain),
      "# Bob Report\n\n## Proof Bundle\n\nEvidence:\n- `proof_bundle:F-1`\n",
    );

    const response = JSON.parse(finalizeReportTool.handler({ target_domain: domain }));
    const expectedProofHash = hashCanonicalJson(proofDocument);
    assert.equal(response.proof_bundle_hash, expectedProofHash);

    const snapshots = readReportSnapshots(domain);
    assert.equal(snapshots.length, 1);
    const row = snapshots[0];
    assert.equal(row.proof_bundle_hash, expectedProofHash);
    assert.deepEqual(row.artifact_refs.find((ref) => ref.kind === "proof_bundle"), {
      kind: "proof_bundle",
      path: "proof-bundles.json",
      content_hash: expectedProofHash,
    });
  });
});

test("bob_finalize_report refuses proof bundle files with unnormalized fields", async () => {
  await withTempHome(async () => {
    const domain = "proof-extra-field.example.com";
    drivePipelineToReportWritten(domain);
    const proofDocument = await writeProofBundleDocument(domain);
    proofDocument.packs[0].artifacts[0].local_debug_path = "/Users/operator/harness/test/BobInvariant.t.sol";
    fs.writeFileSync(proofBundlePaths(domain).json, `${JSON.stringify(proofDocument, null, 2)}\n`);
    fs.writeFileSync(
      reportMarkdownPath(domain),
      "# Bob Report\n\n## Proof Bundle\n\nEvidence:\n- `proof_bundle:F-1`\n",
    );

    assert.throws(
      () => finalizeReportTool.handler({ target_domain: domain }),
      /do not match the normalized proof bundle artifact/,
    );
    assert.equal(readReportSnapshots(domain).length, 0, "finalization must not append a snapshot for mutated proof bundles");
  });
});

test("bob_finalize_report refuses proof_bundle refs without proof-bundles.json", async () => {
  await withTempHome(async () => {
    const domain = "missing-proof.example.com";
    drivePipelineToReportWritten(domain);
    fs.writeFileSync(
      reportMarkdownPath(domain),
      "# Bob Report\n\n## Proof Bundle\n\nEvidence:\n- `proof_bundle:F-1`\n",
    );

    assert.throws(
      () => finalizeReportTool.handler({ target_domain: domain }),
      /proof bundles are not present/,
    );
  });
});

test("bob_finalize_report ignores prose proof_bundle mentions without F-N refs", async () => {
  await withTempHome(async () => {
    const domain = "loose-proof-prose.example.com";
    drivePipelineToReportWritten(domain);
    fs.writeFileSync(
      reportMarkdownPath(domain),
      "# Bob Report\n\n## Notes\n\nThe proof_bundle: field is documented for future evidence refs.\n",
    );

    const response = JSON.parse(finalizeReportTool.handler({ target_domain: domain }));
    assert.equal(response.finalized, true);
    assert.equal(response.proof_bundle_hash, undefined);
    assert.equal(readReportSnapshots(domain).length, 1);
  });
});

test("bob_finalize_report refuses proof_bundle refs after proof bundle replacement", async () => {
  await withTempHome(async () => {
    const domain = "replaced-proof.example.com";
    drivePipelineToReportWritten(domain);
    const finalRound = JSON.parse(fs.readFileSync(verificationRoundPaths(domain, "final").json, "utf8"));
    fs.writeFileSync(
      reportMarkdownPath(domain),
      "# Bob Report\n\n## Proof Bundle\n\nEvidence:\n- `proof_bundle:F-1`\n",
    );
    fs.writeFileSync(proofBundlePaths(domain).json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      verification_attempt_id: finalRound.verification_attempt_id,
      verification_snapshot_hash: finalRound.verification_snapshot_hash,
      final_verification_hash: finalRound.final_verification_hash,
      packs: [],
    }, null, 2)}\n`);

    assert.throws(
      () => finalizeReportTool.handler({ target_domain: domain }),
      /proof_bundle:F-1 does not resolve/,
    );
    assert.equal(readReportSnapshots(domain).length, 0, "finalization must not append a snapshot for stale proof refs");
  });
});

test("bob_finalize_report refuses proof bundles stale against current final verification", async () => {
  await withTempHome(async () => {
    const domain = "stale-proof-finalize.example.com";
    drivePipelineToReportWritten(domain);
    fs.writeFileSync(
      reportMarkdownPath(domain),
      "# Bob Report\n\n## Proof Bundle\n\nEvidence:\n- `proof_bundle:F-1`\n",
    );
    fs.writeFileSync(proofBundlePaths(domain).json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      verification_attempt_id: "old-attempt",
      verification_snapshot_hash: "a".repeat(64),
      final_verification_hash: "b".repeat(64),
      packs: [],
    }, null, 2)}\n`);

    assert.throws(
      () => finalizeReportTool.handler({ target_domain: domain }),
      /do not validate against the current final verification/,
    );
    assert.equal(readReportSnapshots(domain).length, 0, "finalization must not append a snapshot for stale proof bindings");
  });
});

test("re-finalize after mutating report.md produces a new row with a different report_content_hash", async () => {
  await withTempHome(async () => {
    const domain = "remutate.example.com";
    drivePipelineToReportWritten(domain);

    const firstResponse = JSON.parse(finalizeReportTool.handler({ target_domain: domain }));
    const firstRow = readReportSnapshots(domain)[0];
    assert.equal(firstRow.report_content_hash, firstResponse.report_content_hash);

    // Manually poke report.md (overwrite with new content).
    fs.writeFileSync(reportMarkdownPath(domain), "# Bob Report — revised\n\nSecond pass.\n");

    const secondResponse = JSON.parse(finalizeReportTool.handler({ target_domain: domain }));
    const rows = readReportSnapshots(domain);
    assert.equal(rows.length, 2, "re-finalize must append a second snapshot row");
    const secondRow = rows[1];

    assert.notEqual(
      secondRow.report_content_hash,
      firstRow.report_content_hash,
      "re-finalize after report.md mutation must change report_content_hash",
    );
    assert.equal(
      secondRow.report_content_hash,
      sha256OfFile(reportMarkdownPath(domain)),
      "the new row must bind to the new report.md content",
    );

    // The upstream four hashes are stable across the re-finalize because no
    // upstream artifact changed; only the report content moved.
    assert.equal(secondRow.claim_freeze_hash, firstRow.claim_freeze_hash);
    assert.equal(secondRow.final_verification_hash, firstRow.final_verification_hash);
    assert.equal(secondRow.evidence_hash, firstRow.evidence_hash);
    assert.equal(secondRow.grade_verdict_hash, firstRow.grade_verdict_hash);

    assert.equal(secondResponse.report_content_hash, secondRow.report_content_hash);
  });
});

test("bob_finalize_report refuses when claim-freeze.json is missing", async () => {
  await withTempHome(async () => {
    const domain = "no-freeze.example.com";
    drivePipelineToReportWritten(domain);
    // Remove the claim freeze file but leave every other artifact intact.
    fs.rmSync(claimFreezePath(domain));
    assert.throws(
      () => finalizeReportTool.handler({ target_domain: domain }),
      /no claim-freeze.json/,
      "missing claim freeze must refuse finalization",
    );
    // Snapshot ledger must not be created.
    assert.equal(readReportSnapshots(domain).length, 0);
  });
});

test("bob_finalize_report refuses when the final verification round is missing", async () => {
  await withTempHome(async () => {
    const domain = "no-final.example.com";
    drivePipelineToReportWritten(domain);
    // Remove the final verification round.
    fs.rmSync(verificationRoundPaths(domain, "final").json);
    assert.throws(
      () => finalizeReportTool.handler({ target_domain: domain }),
      /final verification round is not present/,
      "missing final verification round must refuse finalization",
    );
    assert.equal(readReportSnapshots(domain).length, 0);
  });
});

test("bob_finalize_report refuses when the grade verdict is missing", async () => {
  await withTempHome(async () => {
    const domain = "no-grade.example.com";
    drivePipelineToReportWritten(domain);
    fs.rmSync(gradeArtifactPaths(domain).json);
    assert.throws(
      () => finalizeReportTool.handler({ target_domain: domain }),
      /grade verdict is not present/,
      "missing grade verdict must refuse finalization",
    );
    assert.equal(readReportSnapshots(domain).length, 0);
  });
});

test("bob_finalize_report refuses when evidence packs are missing", async () => {
  await withTempHome(async () => {
    const domain = "no-evidence.example.com";
    drivePipelineToReportWritten(domain);
    fs.rmSync(evidencePackPaths(domain).json);
    assert.throws(
      () => finalizeReportTool.handler({ target_domain: domain }),
      /evidence packs are not present/,
      "missing evidence packs must refuse finalization",
    );
    assert.equal(readReportSnapshots(domain).length, 0);
  });
});

test("bob_finalize_report refuses when report.md is missing", async () => {
  await withTempHome(async () => {
    const domain = "no-report.example.com";
    drivePipelineToReportWritten(domain);
    fs.rmSync(reportMarkdownPath(domain));
    assert.throws(
      () => finalizeReportTool.handler({ target_domain: domain }),
      /report\.md is not present/,
      "missing report.md must refuse finalization",
    );
    assert.equal(readReportSnapshots(domain).length, 0);
  });
});

test("bob_finalize_report descriptor binds to the reporter role bundle", async () => {
  assert.equal(finalizeReportTool.name, "bob_finalize_report");
  assert.deepEqual(
    finalizeReportTool.role_bundles,
    ["reporter"],
    "bob_finalize_report must be reporter-only per Cycle C.7",
  );
  assert.equal(finalizeReportTool.mutating, true);
  assert.ok(finalizeReportTool.session_artifacts_written.includes("report-snapshots.jsonl"));
});
