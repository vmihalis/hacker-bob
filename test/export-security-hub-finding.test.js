"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const exportSecurityHubTool = require("../mcp/lib/tools/export-security-hub-finding.js");
const finalizeReportTool = require("../mcp/lib/tools/finalize-report.js");
const recordFindingTool = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  buildClaimFreeze,
  readCurrentClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  writeEvidencePacks,
} = require("../mcp/lib/evidence.js");
const {
  readGradeVerdict,
  writeGradeVerdict,
} = require("../mcp/lib/grade-verdict-store.js");
const {
  loadGradeVerdictHash,
  resolveReportFinalizationHashes,
} = require("../mcp/lib/report-finalize.js");
const {
  _setApprovalBackendForTest,
  _setApprovalHmacKeyForTest,
} = require("../mcp/lib/approval-store.js");
const {
  gradeFreezeS3Key,
  _setSyncPutObjectForTest,
} = require("../mcp/lib/grade-freeze-store.js");
const {
  readReportSnapshots,
} = require("../mcp/lib/report-snapshots.js");
const {
  findingPayloadsFromClaims,
} = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  proofBundlePaths,
  repoCommandRunsJsonlPath,
  repoRunsDir,
  reportMarkdownPath,
  sessionDir,
  statePath,
  verificationRoundPaths,
  findingDifferentialVerifiedJsonlPath,
} = require("../mcp/lib/paths.js");
const {
  appendJsonlLine,
  writeFileAtomic,
} = require("../mcp/lib/storage.js");
const {
  finalVerificationHash,
} = require("../mcp/lib/verification-contracts.js");
const {
  writeVerificationRound,
} = require("../mcp/lib/verification-round-store.js");
const {
  deriveCvss31,
} = require("../mcp/lib/cvss31.js");
const {
  normalizeProofBundlesDocument,
} = require("../mcp/lib/proof-bundle.js");
const {
  verifyReproReproduction,
} = require("../mcp/lib/repro-replay-verifier.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");
const {
  persistingRunner,
} = require("./helpers/repro-run-pair.js");
const { withIsolatedSigner } = require("./helpers/sandbox-isolated-signer.js");

const PRODUCT_ARN = "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default";
const EVIDENCE_BUCKET = "bob-evidence-test";

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const previousProductArn = process.env.AWS_SECURITY_HUB_PRODUCT_ARN;
  const previousBucket = process.env.AWS_SECURITY_HUB_EVIDENCE_BUCKET;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-security-hub-export-"));
  process.env.HOME = home;
  process.env.AWS_SECURITY_HUB_PRODUCT_ARN = PRODUCT_ARN;
  process.env.AWS_SECURITY_HUB_EVIDENCE_BUCKET = EVIDENCE_BUCKET;
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previousHome;
    if (previousProductArn == null) delete process.env.AWS_SECURITY_HUB_PRODUCT_ARN;
    else process.env.AWS_SECURITY_HUB_PRODUCT_ARN = previousProductArn;
    if (previousBucket == null) delete process.env.AWS_SECURITY_HUB_EVIDENCE_BUCKET;
    else process.env.AWS_SECURITY_HUB_EVIDENCE_BUCKET = previousBucket;
    exportSecurityHubTool._setAwsClientFactoriesForTest(null);
    _setApprovalBackendForTest(null);
    _setApprovalHmacKeyForTest(null);
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// fx-gate-bypass defense 3 — installs a valid, HMAC-bound approval artifact
// for `domain` bound to its CURRENT grade_verdict_hash, via the same test
// injection seams (_setApprovalBackendForTest / _setApprovalHmacKeyForTest)
// mcp/lib/approval-store.js already exposes and lifecycle-gates.js's own
// tests already use. Call this AFTER the pipeline has written grade.json
// (i.e. after drivePipelineToFinalizedReport) so the bound hash matches what
// bob_export_security_hub_finding's chokepoint will independently recompute.
const APPROVAL_HMAC_KEY_TEST = "test-approval-hmac-key";
const APPROVAL_FREEZE_BODY_SHA256 = "b".repeat(64);
const APPROVAL_FREEZE_VERSION_ID = "export-tool-test-freeze-version-1";

function approvalArtifact(domain, gradeVerdictHash, key = APPROVAL_HMAC_KEY_TEST) {
  const profile = domain === "libheif-cve-2026-49271" ? domain : "smoke";
  const hmac = crypto.createHmac("sha256", key)
    .update(JSON.stringify([
      profile,
      domain,
      gradeVerdictHash,
      APPROVAL_FREEZE_BODY_SHA256,
      APPROVAL_FREEZE_VERSION_ID,
    ]), "utf8")
    .digest("hex");
  return JSON.stringify({
    schema_version: 2,
    binding_version: "grade-freeze-v2",
    profile,
    target_domain: domain,
    grade_verdict_hash: gradeVerdictHash,
    grade_freeze_bundle_sha256: APPROVAL_FREEZE_BODY_SHA256,
    grade_freeze_version_id: APPROVAL_FREEZE_VERSION_ID,
    hmac,
  });
}

function installApprovalArtifact(domain) {
  const gradeVerdictHash = loadGradeVerdictHash(domain);
  _setApprovalHmacKeyForTest(APPROVAL_HMAC_KEY_TEST);
  _setApprovalBackendForTest((targetDomain) => {
    if (targetDomain !== domain) return null;
    return approvalArtifact(domain, gradeVerdictHash);
  });
}

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

function seedSessionState(domain, overrides = {}) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  writeFileAtomic(statePath(domain), `${JSON.stringify({
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
  }, null, 2)}\n`);
}

function recordFinding(domain) {
  return JSON.parse(recordFindingTool.handler({
    target_domain: domain,
    title: "IDOR on billing profile",
    severity: "high",
    cwe: "CWE-639",
    endpoint: `https://${domain}/api/billing/1`,
    description: "Tenant boundary allows cross-account view",
    proof_of_concept: "GET /api/billing/1 returns another tenant payload",
    response_evidence: "Cross-tenant billing payload",
    impact: "Cross-tenant billing disclosure",
    validated: true,
    auth_profile: "attacker",
    surface_id: "surface:billing-profile",
    cvss_inputs: {
      attack_vector: "network",
      privileges_required: "low",
      confidentiality: "high",
    },
  }));
}

function recordSecondaryFinding(domain, { severity = "low" } = {}) {
  return JSON.parse(recordFindingTool.handler({
    target_domain: domain,
    title: "Verbose stack trace on password reset",
    severity,
    endpoint: `https://${domain}/api/password-reset`,
    description: "Malformed password-reset request echoes an internal stack trace",
    proof_of_concept: "POST /api/password-reset with a malformed body returns a stack trace",
    response_evidence: "Stack trace disclosing internal file paths",
    impact: "Minor information disclosure with no direct exploitation path",
    validated: true,
    auth_profile: "attacker",
    surface_id: "surface:password-reset",
  }));
}

function evidencePackInput(findingId = "F-1") {
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
  };
}

function gradeFindingInput(findingId = "F-1", totalScore = 75) {
  return {
    finding_id: findingId,
    impact: totalScore === 75 ? 25 : 5,
    proof_quality: totalScore === 75 ? 20 : 5,
    severity_accuracy: totalScore === 75 ? 10 : 5,
    chain_potential: totalScore === 75 ? 10 : 5,
    report_quality: totalScore === 75 ? 10 : 5,
    total_score: totalScore,
    feedback: "Clear, reproducible, and reportable.",
  };
}

// Ported from test/report-snapshot-binding.test.js: seed a real, re-derivable
// replay_script proof-bundle fixture (a repo-command-run row + a MAC-free
// repro-verified.jsonl VERIFIED_PASS differential) so proof-bundle.js's
// normalizeProofBundlesDocument accepts the bundle written by
// writeProofBundleDocument() below.
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

// Ported from test/report-snapshot-binding.test.js: write a validly-normalized
// proof-bundles.json bound to the final round's stamped
// verification_attempt_id/verification_snapshot_hash/final_verification_hash
// fields. `replaySummary` lets callers rewrite the document (without
// re-running bob_finalize_report) to a different-hash-but-still-valid
// document, mirroring how the report.md-amendment test mutates report.md
// directly.
async function writeProofBundleDocument(domain, { replaySummary = "Offline proof replay reproduces F-1." } = {}) {
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
        replay_summary: replaySummary,
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

async function drivePipelineToFinalizedReport(domain, { verdict = "SUBMIT", totalScore = 75, proofBundle = false, beforeFinalize = null, secondFinding = null } = {}) {
  seedSessionState(domain);
  recordFinding(domain);
  if (secondFinding) {
    recordSecondaryFinding(domain, secondFinding);
  }
  buildClaimFreeze(domain, { write: true, now: new Date("2026-05-27T01:00:00.000Z") });

  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain,
      round,
      notes: null,
      results: [
        {
          finding_id: "F-1",
          disposition: "confirmed",
          severity: "high",
          reportable: true,
          reasoning: "Fresh replay confirmed the finding against the current target state.",
        },
        ...(secondFinding ? [{
          finding_id: "F-2",
          disposition: "downgraded",
          severity: secondFinding.severity || "low",
          reportable: false,
          reasoning: "Fresh replay confirmed only a low-severity, non-reportable observation.",
        }] : []),
      ],
    });
  }

  writeEvidencePacks({
    target_domain: domain,
    packs: [evidencePackInput("F-1")],
  });
  seedFindingDifferentialArm(domain, "F-1", "surface:billing-profile");
  withIsolatedSigner(() => writeGradeVerdict({
    target_domain: domain,
    verdict,
    total_score: totalScore,
    findings: [
      gradeFindingInput("F-1", totalScore),
      ...(secondFinding ? [gradeFindingInput("F-2", secondFinding.totalScore || 25)] : []),
    ],
  }));

  const finalPath = verificationRoundPaths(domain, "final").json;
  const v1FinalDocument = JSON.parse(fs.readFileSync(finalPath, "utf8"));
  const freeze = readCurrentClaimFreeze(domain);
  const hashStampedFinalDocument = {
    ...v1FinalDocument,
    verification_attempt_id: `attempt-${freeze.freeze_id}`,
    verification_snapshot_hash: freeze.freeze_hash,
    adjudication_plan_hash: crypto.createHash("sha256")
      .update(`adjudication:${freeze.freeze_id}`)
      .digest("hex"),
  };
  hashStampedFinalDocument.final_verification_hash = finalVerificationHash(hashStampedFinalDocument);
  fs.writeFileSync(finalPath, `${JSON.stringify(hashStampedFinalDocument, null, 2)}\n`);

  if (proofBundle) {
    await writeProofBundleDocument(domain);
  }

  const reportBody = proofBundle
    ? "# Bob Report\n\n## Findings\n\n- F-1: IDOR\n\n## Proof Bundle\n\nEvidence:\n- `proof_bundle:F-1`\n"
    : "# Bob Report\n\n## Findings\n\n- F-1: IDOR\n";

  if (typeof beforeFinalize === "function") {
    await beforeFinalize({ domain });
  }

  fs.writeFileSync(reportMarkdownPath(domain), reportBody);

  return JSON.parse(finalizeReportTool.handler({ target_domain: domain }));
}

function installAwsFakes({ securityHubResponse = { FailedCount: 0, SuccessCount: 1 } } = {}) {
  const securityHubCalls = [];
  const s3Calls = [];
  class BatchImportFindingsCommand {
    constructor(input) {
      this.input = input;
    }
  }
  class PutObjectCommand {
    constructor(input) {
      this.input = input;
    }
  }
  exportSecurityHubTool._setAwsClientFactoriesForTest({
    securityHub: () => ({
      BatchImportFindingsCommand,
      client: {
        send: async (command) => {
          securityHubCalls.push(command);
          return securityHubResponse;
        },
      },
    }),
    s3: () => ({
      PutObjectCommand,
      client: {
        send: async (command) => {
          s3Calls.push(command);
          return { VersionId: "v1" };
        },
      },
    }),
  });
  return { securityHubCalls, s3Calls };
}

test("bob_export_security_hub_finding exports one SUBMIT MEDIUM+ finding as ASFF and ledger row", async () => {
  await withTempHome(async () => {
    const domain = "asff-submit.example.com";
    await drivePipelineToFinalizedReport(domain);
    installApprovalArtifact(domain);
    const { securityHubCalls, s3Calls } = installAwsFakes();

    const response = JSON.parse(await exportSecurityHubTool.handler({ target_domain: domain }));

    assert.equal(securityHubCalls.length, 1);
    assert.equal(s3Calls.length, 1);
    assert.equal(response.exported.length, 1);

    const asff = securityHubCalls[0].input.Findings[0];
    const putObject = s3Calls[0].input;
    const hashes = resolveReportFinalizationHashes(domain);
    const snapshot = readReportSnapshots(domain)[0];
    const grade = JSON.parse(readGradeVerdict({ target_domain: domain }));
    const gradeFinding = grade.findings[0];
    const payload = findingPayloadsFromClaims(domain).find((finding) => finding.id === "F-1");
    const cvss = deriveCvss31(payload.cvss_inputs);
    const expectedS3Uri = `s3://${EVIDENCE_BUCKET}/hacker-bob/security-hub-evidence/${snapshot.snapshot_hash}.json`;

    assert.equal(asff.Id, `hacker-bob/${domain}/F-1/${hashes.report_content_hash.slice(0, 16)}`);
    assert.equal(asff.ProductArn, PRODUCT_ARN);
    assert.equal(asff.Severity.Label, gradeFinding.graded_severity.toUpperCase());
    assert.deepEqual(asff.Cvss, [{
      Version: "3.1",
      BaseScore: cvss.base_score,
      BaseVector: cvss.vector,
    }]);
    assert.deepEqual(asff.ProductFields, {
      "hacker_bob/claim_freeze_hash": hashes.claim_freeze_hash,
      "hacker_bob/final_verification_hash": hashes.final_verification_hash,
      "hacker_bob/evidence_hash": hashes.evidence_hash,
      "hacker_bob/grade_verdict_hash": hashes.grade_verdict_hash,
      "hacker_bob/report_content_hash": hashes.report_content_hash,
      "hacker_bob/s3_uri": expectedS3Uri,
    });
    assert.equal(putObject.Bucket, EVIDENCE_BUCKET);
    assert.equal(putObject.Key, `hacker-bob/security-hub-evidence/${snapshot.snapshot_hash}.json`);
    assert.equal(JSON.parse(putObject.Body).snapshot.snapshot_hash, snapshot.snapshot_hash);

    const ledgerPath = path.join(sessionDir(domain), "aws-security-hub-export.jsonl");
    const rows = fs.readFileSync(ledgerPath, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    assert.equal(rows.length, 1);
    assert.equal(rows[0].finding_id, "F-1");
    assert.equal(rows[0].asff_id, asff.Id);
    assert.equal(rows[0].s3_uri, expectedS3Uri);
  });
});

test("bob_export_security_hub_finding refuses (fail closed) when no valid human-approval artifact exists for the target domain, and never calls BatchImportFindings/PutObject", async () => {
  await withTempHome(async () => {
    const domain = "asff-no-approval.example.com";
    await drivePipelineToFinalizedReport(domain);
    // Deliberately NO installApprovalArtifact(domain) call: no backend is
    // injected, so approval-store.js's verifyApprovalArtifact fails closed
    // (fetchRawArtifact returns null with no BOB_APPROVAL_ARTIFACT_DIR /
    // BOB_APPROVAL_BUCKET / test backend configured).
    const { securityHubCalls, s3Calls } = installAwsFakes();

    await assert.rejects(
      () => exportSecurityHubTool.handler({ target_domain: domain }),
      /human.approval|human_approval_required/i,
    );

    assert.equal(securityHubCalls.length, 0, "BatchImportFindings must never be called without a valid approval artifact");
    assert.equal(s3Calls.length, 0, "S3 PutObject must never be called without a valid approval artifact");
    assert.equal(fs.existsSync(path.join(sessionDir(domain), "aws-security-hub-export.jsonl")), false);
  });
});

test("bob_export_security_hub_finding refuses when an injected approval backend returns a mismatched grade_verdict_hash (post-approval amend+re-grade)", async () => {
  await withTempHome(async () => {
    const domain = "asff-stale-approval.example.com";
    await drivePipelineToFinalizedReport(domain);
    // A validly-HMAC-signed artifact, but bound to a DIFFERENT (stale)
    // grade_verdict_hash than the one currently on disk -- the
    // amend-and-reexport gap fx-hmac-content already closes for the other
    // two approval layers must hold here too.
    const staleHash = "0".repeat(64);
    _setApprovalHmacKeyForTest(APPROVAL_HMAC_KEY_TEST);
    _setApprovalBackendForTest((targetDomain) => (
      targetDomain === domain
        ? approvalArtifact(domain, staleHash)
        : null
    ));
    const { securityHubCalls, s3Calls } = installAwsFakes();

    await assert.rejects(
      () => exportSecurityHubTool.handler({ target_domain: domain }),
      /human.approval|human_approval_required/i,
    );

    assert.equal(securityHubCalls.length, 0);
    assert.equal(s3Calls.length, 0);
  });
});

test("bob_export_security_hub_finding no-ops HOLD verdict without AWS calls", async () => {
  await withTempHome(async () => {
    const domain = "asff-hold.example.com";
    await drivePipelineToFinalizedReport(domain, { verdict: "HOLD", totalScore: 25 });
    const { securityHubCalls, s3Calls } = installAwsFakes();

    const response = JSON.parse(await exportSecurityHubTool.handler({ target_domain: domain }));

    assert.equal(response.verdict, "HOLD");
    assert.deepEqual(response.exported, []);
    assert.equal(securityHubCalls.length, 0);
    assert.equal(s3Calls.length, 0);
    assert.equal(fs.existsSync(path.join(sessionDir(domain), "aws-security-hub-export.jsonl")), false);
  });
});

test("bob_export_security_hub_finding refuses when AWS Security Hub rejects the finding (partial-failure response, no ledger row)", async () => {
  await withTempHome(async () => {
    const domain = "asff-rejected.example.com";
    await drivePipelineToFinalizedReport(domain);
    installApprovalArtifact(domain);
    const { securityHubCalls, s3Calls } = installAwsFakes({
      securityHubResponse: {
        FailedCount: 1,
        SuccessCount: 0,
        FailedFindings: [{
          Id: "hacker-bob/asff-rejected.example.com/F-1/deadbeef",
          ErrorCode: "InvalidInput",
          ErrorMessage: "Severity.Label is not a valid enum value",
        }],
      },
    });

    await assert.rejects(
      () => exportSecurityHubTool.handler({ target_domain: domain }),
      /InvalidInput|Severity\.Label/,
    );

    // BatchImportFindings was actually called (a real, non-2xx-but-partial-failure
    // AWS response), but the finding was rejected — no ledger row must be written.
    assert.equal(securityHubCalls.length, 1);
    assert.equal(s3Calls.length, 1);
    assert.equal(fs.existsSync(path.join(sessionDir(domain), "aws-security-hub-export.jsonl")), false);
  });
});

test("bob_export_security_hub_finding exports only the MEDIUM+ finding when a LOW/non-reportable finding is also present", async () => {
  await withTempHome(async () => {
    const domain = "asff-mixed-severity.example.com";
    await drivePipelineToFinalizedReport(domain, {
      secondFinding: { severity: "low", totalScore: 25 },
    });
    installApprovalArtifact(domain);
    const { securityHubCalls, s3Calls } = installAwsFakes();

    const response = JSON.parse(await exportSecurityHubTool.handler({ target_domain: domain }));

    // Exactly one BatchImportFindings call / one ledger row: the MEDIUM+ (F-1)
    // finding only. The LOW/non-reportable F-2 finding is graded and present in
    // grade.json, but must not be exported.
    assert.equal(securityHubCalls.length, 1);
    assert.equal(s3Calls.length, 1);
    assert.equal(response.exported.length, 1);
    assert.equal(response.exported[0].finding_id, "F-1");
    assert.equal(securityHubCalls[0].input.Findings.length, 1);
    assert.equal(securityHubCalls[0].input.Findings[0].Id.includes("/F-1/"), true);

    const ledgerPath = path.join(sessionDir(domain), "aws-security-hub-export.jsonl");
    const rows = fs.readFileSync(ledgerPath, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    assert.equal(rows.length, 1);
    assert.equal(rows[0].finding_id, "F-1");
  });
});

test("bob_export_security_hub_finding refuses to export when report.md was amended after finalize", async () => {
  await withTempHome(async () => {
    const domain = "asff-stale-snapshot.example.com";
    await drivePipelineToFinalizedReport(domain);

    // Amend report.md directly on disk WITHOUT re-invoking bob_finalize_report,
    // so the latest report-snapshots.jsonl row is now stale relative to the
    // live report content hash.
    fs.writeFileSync(reportMarkdownPath(domain), "# Bob Report amended\n\n## Findings\n\n- F-1: IDOR\n");

    const { securityHubCalls, s3Calls } = installAwsFakes();

    await assert.rejects(
      () => exportSecurityHubTool.handler({ target_domain: domain }),
      /report_content_hash|stale|does not match/,
    );

    assert.equal(securityHubCalls.length, 0);
    assert.equal(s3Calls.length, 0);
    assert.equal(fs.existsSync(path.join(sessionDir(domain), "aws-security-hub-export.jsonl")), false);
  });
});

test("bob_export_security_hub_finding refuses to export when the proof bundle was amended after finalize (stale proof_bundle_hash)", async () => {
  await withTempHome(async () => {
    const domain = "asff-stale-proof-bundle.example.com";
    await drivePipelineToFinalizedReport(domain, { proofBundle: true });

    // Rewrite proof-bundles.json directly on disk to a validly-normalized but
    // different-hash document WITHOUT re-invoking bob_finalize_report, so the
    // proof_bundle_hash bound onto the latest report-snapshots.jsonl row is
    // now stale relative to the live proof-bundles.json content hash. Mirrors
    // how the report.md-amendment test above mutates report.md directly.
    await writeProofBundleDocument(domain, { replaySummary: "Offline proof replay reproduces F-1 (amended)." });

    const { securityHubCalls, s3Calls } = installAwsFakes();

    await assert.rejects(
      () => exportSecurityHubTool.handler({ target_domain: domain }),
      /proof_bundle_hash|stale|does not match/,
    );

    assert.equal(securityHubCalls.length, 0);
    assert.equal(s3Calls.length, 0);
    assert.equal(fs.existsSync(path.join(sessionDir(domain), "aws-security-hub-export.jsonl")), false);
  });
});

test("export-security-hub-finding loads without AWS SDK packages at require time", () => {
  const script = `
    const Module = require("module");
    const originalLoad = Module._load;
    Module._load = function(request, parent, isMain) {
      if (request.startsWith("@aws-sdk/")) {
        throw new Error("AWS SDK required at module load: " + request);
      }
      return originalLoad.apply(this, arguments);
    };
    const tool = require("./mcp/lib/tools/export-security-hub-finding.js");
    if (tool.name !== "bob_export_security_hub_finding") process.exit(2);
  `;
  const result = spawnSync(process.execPath, ["-e", script], {
    cwd: path.join(__dirname, ".."),
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
});

test("bob_export_security_hub_finding descriptor is reporter mutating without audit-graded flag", () => {
  assert.equal(exportSecurityHubTool.name, "bob_export_security_hub_finding");
  assert.deepEqual(exportSecurityHubTool.role_bundles, ["reporter"]);
  assert.equal(exportSecurityHubTool.mutating, true);
  assert.equal(exportSecurityHubTool.writes_audit_graded, false);
  // fx-gate-bypass defense 6: this tool makes real AWS network calls (S3
  // PutObject, Security Hub BatchImportFindings) and was mislabeled false.
  assert.equal(exportSecurityHubTool.network_access, true);
});

// ARCHITECTURAL FIX (Eric-approved) end-to-end wiring check: writeGradeVerdict
// (the REAL engine call, exercised here via the same full pipeline every other
// test in this file drives) performs the additive GRADE-time WORM freeze write
// when BOB_GRADE_FREEZE_BUCKET is configured, keyed by the SAME
// grade_verdict_hash bob_export_security_hub_finding / loadGradeVerdictHash
// independently recompute later. See test/grade-freeze-store.test.js for the
// module's own unit coverage; this test only asserts the wiring seam fires.
test("bob_write_grade_verdict triggers the GRADE-time WORM freeze write when BOB_GRADE_FREEZE_BUCKET is configured", async () => {
  await withTempHome(async () => {
    const domain = "grade-freeze-wiring.example.com";
    const previousFreezeBucket = process.env.BOB_GRADE_FREEZE_BUCKET;
    process.env.BOB_GRADE_FREEZE_BUCKET = "hacker-bob-evidence-test";
    const calls = [];
    _setSyncPutObjectForTest((args) => { calls.push(args); });
    try {
      await drivePipelineToFinalizedReport(domain);

      const gradeVerdictHash = loadGradeVerdictHash(domain);
      assert.equal(calls.length, 1, "exactly one grade write happened in the pipeline");
      assert.equal(calls[0].bucket, "hacker-bob-evidence-test");
      assert.equal(calls[0].key, gradeFreezeS3Key(domain, gradeVerdictHash));
      const bundle = JSON.parse(calls[0].bodyString);
      assert.equal(bundle.grade_verdict_hash, gradeVerdictHash);
      assert.equal(bundle.target_domain, domain);
      assert.deepEqual(bundle.reportable_finding_ids, ["F-1"]);
      assert.ok(bundle.findings.some((f) => f.id === "F-1"));
    } finally {
      _setSyncPutObjectForTest(null);
      if (previousFreezeBucket == null) delete process.env.BOB_GRADE_FREEZE_BUCKET;
      else process.env.BOB_GRADE_FREEZE_BUCKET = previousFreezeBucket;
    }
  });
});
