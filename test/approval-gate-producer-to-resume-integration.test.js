"use strict";

// Integration test (f1-approval-wiring / fx-gate-hardening): drives ARTIFACT -> BOTH-CONSUMERS
// as one continuous flow, exercising the actual shared coupling point (the approval artifact's
// content + HMAC scheme) rather than re-running the two halves' existing unit tests in
// isolation.
//
// fx-gate-hardening REMOVED the model-writable-artifact PRODUCER that used to live inside
// infra/runner/agentcore-entrypoint.py's run_invocation (see test/agentcore_entrypoint_test.py's
// dedicated regression test confirming that removal). The real production producer is now the
// out-of-band VerifierGateFunction Lambda declared in
// infra/aws/hacker-bob-stack/template.yaml -- not unit-testable via node --test without live AWS
// (that Lambda's own inline Python source is syntax/structure-checked by
// test/hacker-bob-template-approval-env.test.js instead).
//
// What THIS test still verifies end-to-end, without either consumer diverging:
//   1. Both consumers (mcp/lib/lifecycle-gates.js's gradeToReportApprovalBlocker, the
//      .claude/hooks/bob-approval-gate-impl.py PreToolUse hook) start BLOCKED for a
//      target_domain with no artifact.
//   2. Writing ONE artifact -- {"hmac": HMAC-SHA256(`${target_domain}|${grade_verdict_hash}`,
//      key), "grade_verdict_hash": <hash>} (fx-hmac-content: content-bound to the grade the
//      human reviewed) -- to the SAME local backend stand-in (BOB_APPROVAL_ARTIFACT_DIR /
//      BOB_APPROVAL_HMAC_KEY, the identical seam both consumers' production
//      S3+SecretsManager backends swap in for) flips BOTH consumers to ALLOW, with no
//      naming/keying divergence between them.
//   3. A tampered/wrong-signature artifact leaves BOTH consumers BLOCKED (existence alone is
//      never enough).
//   4. fx-hmac-content: amending + re-grading (a post-approval report edit) leaves the SAME
//      previously-valid artifact rejected by BOTH consumers -- the amend-and-reexport gap this
//      node closes, verified end-to-end (not just per-consumer in isolation).
//   5. BOB_AGENTCORE unset leaves BOTH consumers ALLOW/abstain regardless of artifact state
//      (inert-by-default end-to-end).

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.join(__dirname, "..");
const HOOK_PATH = path.join(ROOT, ".claude", "hooks", "bob-approval-gate-impl.py");

const { gradeToReportApprovalBlocker } = require("../mcp/core/session/lifecycle-gates.js");
const { _setApprovalBackendForTest, _setApprovalHmacKeyForTest } = require("../mcp/core/approval-store.js");
const { gradeArtifactPaths } = require("../mcp/core/io/paths.js");
const { writeFileAtomic } = require("../mcp/core/io/storage.js");
const { loadGradeVerdictHash } = require("../mcp/core/report-finalize.js");

const TARGET_DOMAIN = "10.0.0.42"; // the port-stripped form both consumers key by
const HMAC_KEY = "integration-test-only-hmac-key-do-not-use-in-prod";
const FREEZE_BODY_SHA256 = "b".repeat(64);
const FREEZE_VERSION_ID = "integration-freeze-version-1";

// fx-hmac-content: the artifact is bound to `${target_domain}|${grade_verdict_hash}`, not just
// target_domain -- mirrors the production VerifierGateFunction's signing scheme AND both
// consumers' recompute-and-compare (mcp/lib/approval-store.js, bob-approval-gate-impl.py).
function signedArtifact(targetDomain, gradeVerdictHash, key = HMAC_KEY) {
  const profile = targetDomain === "libheif-cve-2026-49271"
    ? "libheif-cve-2026-49271"
    : "smoke";
  const hmac = crypto.createHmac("sha256", key)
    .update(JSON.stringify([
      profile,
      targetDomain,
      gradeVerdictHash,
      FREEZE_BODY_SHA256,
      FREEZE_VERSION_ID,
    ]), "utf8")
    .digest("hex");
  return JSON.stringify({
    schema_version: 2,
    binding_version: "grade-freeze-v2",
    profile,
    target_domain: targetDomain,
    grade_verdict_hash: gradeVerdictHash,
    grade_freeze_bundle_sha256: FREEZE_BODY_SHA256,
    grade_freeze_version_id: FREEZE_VERSION_ID,
    hmac,
  });
}

function writeApprovalArtifact(artifactDir, targetDomain, gradeVerdictHash, body) {
  const targetDir = path.join(artifactDir, targetDomain);
  fs.mkdirSync(targetDir, { recursive: true });
  fs.writeFileSync(path.join(targetDir, `${gradeVerdictHash}.approved`), body);
}

// fx-hmac-content: both consumers resolve their own "current" grade_verdict_hash from
// HOME/hacker-bob-sessions/<target_domain>/grade.json — the JS gate via
// mcp/lib/paths.js's gradeArtifactPaths (os.homedir() -> process.env.HOME), the Python hook via
// its own identical ~/hacker-bob-sessions/<engagement_id>/grade.json path. Writing the fixture
// directly (rather than through mcp/lib/grade-verdict-store.js's writeGradeVerdict) deliberately
// bypasses that module's grading business-rule gates, which this integration test does not
// exercise -- see the identical rationale in test/lifecycle-advance.test.js's
// writeTestGradeVerdict.
function writeTestGradeVerdict(home, targetDomain, { totalScore = 75 } = {}) {
  const previousHome = process.env.HOME;
  process.env.HOME = home;
  try {
    const document = {
      version: 1,
      target_domain: targetDomain,
      verdict: "SUBMIT",
      total_score: totalScore,
      findings: [{
        finding_id: "F-1",
        impact: 25,
        proof_quality: 20,
        severity_accuracy: 10,
        chain_potential: 10,
        report_quality: 10,
        total_score: totalScore,
        feedback: "Clear, reproducible, and reportable.",
      }],
      graded_at: "2026-05-27T02:00:00.000Z",
    };
    writeFileAtomic(gradeArtifactPaths(targetDomain).json, `${JSON.stringify(document, null, 2)}\n`);
    return loadGradeVerdictHash(targetDomain);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
  }
}

function runHook({ home, artifactDir, agentcoreEnabled }) {
  const env = { ...process.env };
  delete env.BOB_AGENTCORE;
  delete env.BOB_APPROVAL_ARTIFACT_DIR;
  delete env.BOB_APPROVAL_HMAC_KEY;
  if (agentcoreEnabled) env.BOB_AGENTCORE = "1";
  if (artifactDir) env.BOB_APPROVAL_ARTIFACT_DIR = artifactDir;
  // fx-hmac-content: the Python hook resolves its OWN current grade_verdict_hash from
  // HOME/hacker-bob-sessions/<target_domain>/grade.json, so it must see the SAME HOME the JS
  // gate/test fixture wrote grade.json under -- otherwise the hook can never agree with the JS
  // gate on the current hash (a naming/keying divergence this test exists to rule out).
  if (home) env.HOME = home;
  env.BOB_APPROVAL_HMAC_KEY = HMAC_KEY;
  const payload = JSON.stringify({
    tool_name: "mcp__hacker-bob__bob_advance_session",
    tool_input: { target_domain: TARGET_DOMAIN, to_state: "REPORT" },
  });
  return spawnSync("python3", [HOOK_PATH], { input: payload, env, encoding: "utf8" });
}

test("both consumers block before the artifact exists, allow after a single valid write, and BOTH re-block after amend (no naming/keying divergence)", () => {
  const artifactDir = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-integration-artifacts-"));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-integration-home-"));
  const previousAgentcore = process.env.BOB_AGENTCORE;
  const previousArtifactDir = process.env.BOB_APPROVAL_ARTIFACT_DIR;
  const previousHome = process.env.HOME;
  process.env.BOB_AGENTCORE = "1";
  process.env.BOB_APPROVAL_ARTIFACT_DIR = artifactDir;
  process.env.HOME = home;
  _setApprovalHmacKeyForTest(HMAC_KEY);
  try {
    // (1) BEFORE: no artifact yet (and no grade.json yet either) -> both consumers block.
    const before = gradeToReportApprovalBlocker({ target_domain: TARGET_DOMAIN });
    assert.equal(before.length, 1, "lifecycle-gates.js must block before the artifact exists");
    assert.equal(before[0].code, "external_approval_pending");

    const hookBefore = runHook({ home, artifactDir, agentcoreEnabled: true });
    assert.equal(hookBefore.status, 2, `hook must block before the artifact exists; stdout=${hookBefore.stdout}`);

    // (2) Seed the grade the human is approving, then ONE write -- the same artifact content an
    //     ApprovalWriter Lambda would produce in production, content-bound to that grade's
    //     hash -- satisfies BOTH consumers via the identical BOB_APPROVAL_ARTIFACT_DIR
    //     local-backend seam (mcp/lib/approval-store.js's readLocalArtifact,
    //     bob-approval-gate-impl.py's _fetch_approval_artifact_bytes) AND the identical HOME
    //     both resolve grade.json under.
    const gradeVerdictHash = writeTestGradeVerdict(home, TARGET_DOMAIN);
    writeApprovalArtifact(
      artifactDir,
      TARGET_DOMAIN,
      gradeVerdictHash,
      signedArtifact(TARGET_DOMAIN, gradeVerdictHash),
    );

    // (3) AFTER: gate now allows -- same artifact dir, same target_domain key, same HOME, no
    //     divergence.
    const after = gradeToReportApprovalBlocker({ target_domain: TARGET_DOMAIN });
    assert.deepEqual(after, [], "lifecycle-gates.js must allow once the artifact exists and HMAC-verifies");

    const hookAfter = runHook({ home, artifactDir, agentcoreEnabled: true });
    assert.equal(hookAfter.status, 0, `hook must allow once the artifact exists; stdout=${hookAfter.stdout}`);

    // (4) fx-hmac-content: amend + re-grade (simulating a post-approval report edit). The SAME
    //     unmodified artifact must now be rejected by BOTH consumers -- the amend-and-reexport
    //     gap this node closes, checked end-to-end against both.
    const amendedHash = writeTestGradeVerdict(home, TARGET_DOMAIN, { totalScore: 10 });
    assert.notEqual(amendedHash, gradeVerdictHash, "amending the grade verdict must change its hash");

    const afterAmend = gradeToReportApprovalBlocker({ target_domain: TARGET_DOMAIN });
    assert.equal(afterAmend.length, 1, "lifecycle-gates.js must re-block the SAME artifact after amend");
    assert.equal(afterAmend[0].code, "external_approval_pending");

    const hookAfterAmend = runHook({ home, artifactDir, agentcoreEnabled: true });
    assert.equal(
      hookAfterAmend.status, 2,
      `hook must re-block the SAME artifact after amend; stdout=${hookAfterAmend.stdout}`,
    );
  } finally {
    if (previousAgentcore === undefined) delete process.env.BOB_AGENTCORE;
    else process.env.BOB_AGENTCORE = previousAgentcore;
    if (previousArtifactDir === undefined) delete process.env.BOB_APPROVAL_ARTIFACT_DIR;
    else process.env.BOB_APPROVAL_ARTIFACT_DIR = previousArtifactDir;
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    _setApprovalHmacKeyForTest(null);
    _setApprovalBackendForTest(null);
    fs.rmSync(artifactDir, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("both consumers stay blocked on a tampered/wrong-signature artifact (existence alone is not enough)", () => {
  const artifactDir = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-integration-tampered-"));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-integration-tampered-home-"));
  const previousAgentcore = process.env.BOB_AGENTCORE;
  const previousArtifactDir = process.env.BOB_APPROVAL_ARTIFACT_DIR;
  const previousHome = process.env.HOME;
  process.env.BOB_AGENTCORE = "1";
  process.env.BOB_APPROVAL_ARTIFACT_DIR = artifactDir;
  process.env.HOME = home;
  _setApprovalHmacKeyForTest(HMAC_KEY);
  try {
    const gradeVerdictHash = writeTestGradeVerdict(home, TARGET_DOMAIN);
    // Well-formed {"hmac": "...", "grade_verdict_hash": "..."} JSON, content-bound to the
    // CURRENT grade (mere existence, or even a matching content-binding, would have allowed
    // this under the old raw-existence check this hardening replaces) -- but signed with a
    // DIFFERENT key.
    writeApprovalArtifact(
      artifactDir,
      TARGET_DOMAIN,
      gradeVerdictHash,
      signedArtifact(TARGET_DOMAIN, gradeVerdictHash, "a-different-attacker-controlled-key"),
    );

    const gateResult = gradeToReportApprovalBlocker({ target_domain: TARGET_DOMAIN });
    assert.equal(gateResult.length, 1, "lifecycle-gates.js must block a tampered/wrong-signature artifact");
    assert.equal(gateResult[0].code, "external_approval_pending");

    const hookResult = runHook({ home, artifactDir, agentcoreEnabled: true });
    assert.equal(hookResult.status, 2, `hook must block a tampered/wrong-signature artifact; stdout=${hookResult.stdout}`);
  } finally {
    if (previousAgentcore === undefined) delete process.env.BOB_AGENTCORE;
    else process.env.BOB_AGENTCORE = previousAgentcore;
    if (previousArtifactDir === undefined) delete process.env.BOB_APPROVAL_ARTIFACT_DIR;
    else process.env.BOB_APPROVAL_ARTIFACT_DIR = previousArtifactDir;
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    _setApprovalHmacKeyForTest(null);
    _setApprovalBackendForTest(null);
    fs.rmSync(artifactDir, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("both consumers allow/abstain when BOB_AGENTCORE != \"1\", regardless of artifact state (inert-by-default end-to-end)", () => {
  const artifactDir = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-integration-inert-"));
  try {
    // Even a VALID (content-bound) artifact present must not matter off the AWS branch -- the
    // gate itself must not fire at all (BOB_AGENTCORE !== "1" is gradeToReportApprovalBlocker's
    // own first check), so the grade_verdict_hash value here is arbitrary -- inert either way.
    writeApprovalArtifact(
      artifactDir,
      TARGET_DOMAIN,
      "0".repeat(64),
      signedArtifact(TARGET_DOMAIN, "0".repeat(64)),
    );

    delete process.env.BOB_AGENTCORE;
    delete process.env.BOB_APPROVAL_ARTIFACT_DIR;
    _setApprovalBackendForTest(null);
    _setApprovalHmacKeyForTest(null);
    assert.deepEqual(gradeToReportApprovalBlocker({ target_domain: TARGET_DOMAIN }), []);

    const hookResult = runHook({ artifactDir, agentcoreEnabled: false });
    assert.equal(hookResult.status, 0, "hook must allow (abstain) when BOB_AGENTCORE != \"1\"");
  } finally {
    fs.rmSync(artifactDir, { recursive: true, force: true });
  }
});

test("Node production approval backend resolves Secrets Manager through image-owned Python+boto3, never an absent AWS CLI", () => {
  const source = fs.readFileSync(path.join(ROOT, "mcp", "core", "approval-store.js"), "utf8");
  const dockerfile = fs.readFileSync(path.join(ROOT, "infra", "runner", "Dockerfile"), "utf8");
  assert.match(source, /execFileSync\(\s*"python3"/);
  assert.match(source, /boto3\.client\('secretsmanager'\)/);
  assert.doesNotMatch(source, /execFileSync\(\s*"aws"/);
  assert.match(source, /approvals\/\$\{targetDomain\}\/\$\{currentGradeVerdictHash\}\.approved/);
  assert.match(dockerfile, /boto3==1\.43\.46/);
  assert.match(dockerfile, /ENV PATH=\/opt\/agentcore-venv\/bin:\$PATH/);
});
