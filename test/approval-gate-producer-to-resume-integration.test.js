"use strict";

// Integration test (f1-approval-wiring / fx-gate-hardening): drives ARTIFACT -> BOTH-CONSUMERS
// as one continuous flow, exercising the actual shared coupling point (the approval artifact's
// content + HMAC scheme) rather than re-running the two halves' existing unit tests in
// isolation.
//
// fx-gate-hardening REMOVED the model-writable-artifact PRODUCER that used to live inside
// infra/runner/agentcore-entrypoint.py's run_invocation (see test/agentcore_entrypoint_test.py's
// dedicated regression test confirming that removal). The real production producer is now the
// out-of-band ApprovalWriterFunction Lambda declared in
// infra/aws/glassbox-stack/template.yaml -- not unit-testable via node --test without live AWS
// (that Lambda's own inline Python source is syntax/structure-checked by
// test/glassbox-template-approval-env.test.js instead).
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

const { gradeToReportApprovalBlocker } = require("../mcp/lib/lifecycle-gates.js");
const { _setApprovalBackendForTest, _setApprovalHmacKeyForTest } = require("../mcp/lib/approval-store.js");
const { gradeArtifactPaths } = require("../mcp/lib/paths.js");
const { writeFileAtomic } = require("../mcp/lib/storage.js");
const { loadGradeVerdictHash } = require("../mcp/lib/report-finalize.js");

const TARGET_DOMAIN = "10.0.0.42"; // the port-stripped form both consumers key by
const HMAC_KEY = "integration-test-only-hmac-key-do-not-use-in-prod";

// fx-hmac-content: the artifact is bound to `${target_domain}|${grade_verdict_hash}`, not just
// target_domain -- mirrors the production ApprovalWriterFunction's signing scheme AND both
// consumers' recompute-and-compare (mcp/lib/approval-store.js, bob-approval-gate-impl.py).
function signedArtifact(targetDomain, gradeVerdictHash, key = HMAC_KEY) {
  const hmac = crypto.createHmac("sha256", key)
    .update(`${targetDomain}|${gradeVerdictHash}`, "utf8")
    .digest("hex");
  return JSON.stringify({ hmac, grade_verdict_hash: gradeVerdictHash });
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
  const artifactDir = fs.mkdtempSync(path.join(os.tmpdir(), "glassbox-integration-artifacts-"));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "glassbox-integration-home-"));
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
    fs.writeFileSync(
      path.join(artifactDir, `${TARGET_DOMAIN}.approved`),
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
  const artifactDir = fs.mkdtempSync(path.join(os.tmpdir(), "glassbox-integration-tampered-"));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "glassbox-integration-tampered-home-"));
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
    fs.writeFileSync(
      path.join(artifactDir, `${TARGET_DOMAIN}.approved`),
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
  const artifactDir = fs.mkdtempSync(path.join(os.tmpdir(), "glassbox-integration-inert-"));
  try {
    // Even a VALID (content-bound) artifact present must not matter off the AWS branch -- the
    // gate itself must not fire at all (BOB_AGENTCORE !== "1" is gradeToReportApprovalBlocker's
    // own first check), so the grade_verdict_hash value here is arbitrary -- inert either way.
    fs.writeFileSync(
      path.join(artifactDir, `${TARGET_DOMAIN}.approved`),
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
