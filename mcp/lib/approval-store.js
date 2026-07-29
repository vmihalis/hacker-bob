"use strict";

// approval-store.js — GRADE -> REPORT human-approval artifact store (AgentCore rail-b,
// fx-gate-hardening / f1-approval-wiring hardening pass).
//
// Replaces the old "does <target_domain>.approved exist under a model-writable EFS dir"
// check (forgeable: a headless --dangerously-skip-permissions model runs AS
// HackerBobAgentRuntimeExecutionRole and could `touch` that file itself) with:
//   (1) PRIMARY enforcement: the artifact lives under an S3 `approvals/` prefix the
//       model's role can only s3:GetObject on, never s3:PutObject (see template.yaml
//       HackerBobAgentRuntimeExecutionRole's GetApprovalArtifacts Sid). Only the SFN/
//       Lambda role (ApprovalWriterRole) can write there.
//   (2) Defense-in-depth: the schema-v2 artifact is stored at
//       approvals/<target_domain>/<grade_verdict_hash>.approved and carries an
//       HMAC-SHA256 over compact UTF-8 JSON
//       [profile,target_domain,grade_verdict_hash,grade_freeze_bundle_sha256,
//       grade_freeze_version_id], computed by the named-human writer
//       with a key that ONLY the SFN/Lambda role and (read-only)
//       HackerBobAgentRuntimeExecutionRole can read from Secrets Manager. This module
//       recomputes and compares it — a write that somehow lands in the bucket without going
//       through the real ApprovalWriter Lambda (e.g. a misconfigured bucket policy elsewhere
//       in the account) still fails closed here.
//   (3) fx-hmac-content: the artifact is bound to the EXACT grade the human reviewed, not
//       just the target_domain. verifyApprovalArtifact takes the CURRENT grade_verdict_hash
//       (resolved by the caller via mcp/lib/report-finalize.js's loadGradeVerdictHash) and
//       requires it to equal the artifact's own stored grade_verdict_hash before the HMAC is
//       even checked. A post-approval amend+re-grade changes the current hash, so the SAME
//       previously-valid artifact no longer verifies — closing the "one approval permanently
//       pre-authorizes unlimited amend+re-export" gap.
//
// Consumed by mcp/lib/lifecycle-gates.js's gradeToReportApprovalBlocker AND (P1-3)
// mcp/lib/tools/finalize-report.js. This module owns ONLY the fetch + verify decision
// (verifyApprovalArtifact -> boolean); callers own their own blocker/ToolError shape.
//
// SYNCHRONOUS BY DESIGN: gradeToReportApprovalBlocker is invoked deep inside
// evaluateLifecycleTransition -> advanceSession's synchronous, session-locked call chain,
// which dozens of existing callers/tests invoke synchronously today. Making that chain
// async is out of this node's remit ("engine changes additive-only" — it would change the
// calling contract for every non-AWS-branch caller too). The AWS SDK v3 clients are
// Promise-only, so the real S3/Secrets-Manager reads below are bridged through a
// short-lived child process this function blocks on (execFileSync) rather than making
// this module's own exported surface async. Neither production fetch path is exercised by
// the test suite: tests always inject a backend via _setApprovalBackendForTest / point
// BOB_APPROVAL_ARTIFACT_DIR + BOB_APPROVAL_HMAC_KEY at local fixtures.
//
// Runbook: aabw-2026/projects/06-aws-hacker-bob/AGENTCORE-BRANCH-PLAN.md

const crypto = require("crypto");

let backendForTest = null;
let hmacKeyForTest = null;

function isSafeTargetDomain(value) {
  return typeof value === "string"
    && /^[A-Za-z0-9._:-]{1,255}$/.test(value)
    && !value.startsWith(".")
    && !value.includes("..");
}

// Test-only injection points, mirroring the awsClientFactoriesForTest pattern already
// established in mcp/lib/tools/export-security-hub-finding.js. Never read in production.
function _setApprovalBackendForTest(fn) {
  backendForTest = typeof fn === "function" ? fn : null;
}

function _setApprovalHmacKeyForTest(key) {
  hmacKeyForTest = typeof key === "string" && key ? key : null;
}

// Local-filesystem stand-in seam (dev/test only). Post-fx-gate-hardening, template.yaml's
// AgentCoreRuntime provisioner no longer sets BOB_APPROVAL_ARTIFACT_DIR in production —
// that writable-EFS artifact path was exactly the forgeable design this hardening removes.
// It is only ever set by a human/test harness pointing at a tmp dir, mirroring the
// "local-filesystem stand-in seam" language already used by
// .claude/hooks/bob-approval-gate-impl.py's own docstring.
function readLocalArtifact(targetDomain, currentGradeVerdictHash) {
  const dir = process.env.BOB_APPROVAL_ARTIFACT_DIR;
  if (!dir) return null;
  const fs = require("fs");
  const path = require("path");
  try {
    return fs.readFileSync(
      path.join(dir, targetDomain, `${currentGradeVerdictHash}.approved`),
      "utf8",
    );
  } catch {
    return null;
  }
}

// Real production backend: S3 GetObject on the un-writable-by-the-model approvals/
// prefix. See the module header for why this is bridged through a child process rather
// than making verifyApprovalArtifact async. Any failure (missing object, network error,
// timeout, malformed response) returns null — the caller treats null as "not approved".
function readS3Artifact(targetDomain, currentGradeVerdictHash) {
  const bucket = process.env.BOB_APPROVAL_BUCKET;
  if (!bucket) return null;
  const { execFileSync } = require("child_process");
  const key = `approvals/${targetDomain}/${currentGradeVerdictHash}.approved`;
  const script = [
    "const { S3Client, GetObjectCommand } = require(\"@aws-sdk/client-s3\");",
    "(async () => {",
    "  const client = new S3Client({});",
    "  const resp = await client.send(new GetObjectCommand({ Bucket: process.argv[2], Key: process.argv[3] }));",
    "  const chunks = [];",
    "  for await (const chunk of resp.Body) chunks.push(Buffer.from(chunk));",
    "  process.stdout.write(Buffer.concat(chunks).toString(\"utf8\"));",
    "})().catch((err) => { process.stderr.write(String((err && err.message) || err)); process.exit(1); });",
  ].join("\n");
  try {
    return execFileSync(process.execPath, ["-e", script, bucket, key], {
      encoding: "utf8",
      timeout: 5000,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch {
    return null;
  }
}

function fetchRawArtifact(targetDomain, currentGradeVerdictHash) {
  if (backendForTest) return backendForTest(targetDomain, currentGradeVerdictHash);
  const local = readLocalArtifact(targetDomain, currentGradeVerdictHash);
  if (local != null) return local;
  return readS3Artifact(targetDomain, currentGradeVerdictHash);
}

// Real production Secrets Manager fetch. This synchronous module already bridges its
// async S3 read through a short-lived process. Use the image's Python+boto3 runtime for
// Secrets Manager too: the final AgentCore image intentionally does not ship the AWS CLI.
function readSecretFromSecretsManager(secretId) {
  const { execFileSync } = require("child_process");
  const script = [
    "import boto3, sys",
    "response = boto3.client('secretsmanager').get_secret_value(SecretId=sys.argv[1])",
    "secret = response.get('SecretString')",
    "if not isinstance(secret, str) or not secret:",
    "    raise RuntimeError('approval HMAC secret has no SecretString')",
    "sys.stdout.write(secret)",
  ].join("\n");
  try {
    return execFileSync(
      "python3",
      ["-c", script, secretId],
      { encoding: "utf8", timeout: 5000, stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch {
    return null;
  }
}

function resolveHmacKey() {
  if (hmacKeyForTest) return hmacKeyForTest;
  // Local/dev/test stand-in (never set in production — see readLocalArtifact above for
  // the identical rationale applied to the artifact fetch).
  if (process.env.BOB_APPROVAL_HMAC_KEY) return process.env.BOB_APPROVAL_HMAC_KEY;
  const secretId = process.env.BOB_APPROVAL_HMAC_SECRET_ID;
  if (!secretId) return null;
  const secret = readSecretFromSecretsManager(secretId);
  return typeof secret === "string" && secret.trim() ? secret.trim() : null;
}

// Recomputes the schema-v2 compact-JSON-array HMAC and compares it (constant-time)
// against the artifact's `hmac` field, AND confirms the artifact's
// own stored `grade_verdict_hash` equals the CALLER-SUPPLIED currentGradeVerdictHash (the hash
// of the grade the human is being asked to approve RIGHT NOW, resolved by the caller via
// mcp/lib/report-finalize.js's loadGradeVerdictHash). Binding the HMAC input to the graded
// content -- not just target_domain -- closes the amend-and-reexport gap: a single approval no
// longer permanently pre-authorizes unlimited amend+re-finalize+re-export against that domain,
// because a post-approval change to grade.json changes currentGradeVerdictHash, which no longer
// matches the signed artifact.
//
// Fails CLOSED (returns false) on every ambiguity: unreadable artifact, malformed JSON,
// missing/non-string hmac field, missing/non-string currentGradeVerdictHash argument,
// missing/invalid schema-v2 profile, target, body hash, VersionId, or grade hash, a grade hash
// MISMATCH (the amend-and-reexport case), unresolvable key, or a length mismatch that would otherwise
// make timingSafeEqual throw.
function verifyApprovalArtifact(targetDomain, currentGradeVerdictHash) {
  if (!isSafeTargetDomain(targetDomain)) return false;
  if (!/^[0-9a-f]{64}$/.test(currentGradeVerdictHash || "")) return false;
  let raw;
  try {
    raw = fetchRawArtifact(targetDomain, currentGradeVerdictHash);
  } catch {
    raw = null;
  }
  if (typeof raw !== "string" || !raw) return false;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return false;
  }
  if (
    !parsed
    || typeof parsed !== "object"
    || parsed.schema_version !== 2
    || parsed.binding_version !== "grade-freeze-v2"
    || !/^[0-9a-f]{64}$/.test(parsed.hmac || "")
  ) {
    return false;
  }
  if (!/^[0-9a-f]{64}$/.test(parsed.grade_verdict_hash || "")) {
    return false;
  }
  // Content binding: the artifact was signed over a SPECIFIC grade_verdict_hash. If the current
  // grade verdict has since changed (amend/re-grade), this comparison fails and the transition
  // blocks -- even though the artifact itself is still a validly-HMAC-signed object for the hash
  // it WAS signed over.
  if (parsed.grade_verdict_hash !== currentGradeVerdictHash) {
    return false;
  }
  if (parsed.target_domain !== targetDomain) return false;
  const expectedProfile = targetDomain === "libheif-cve-2026-49271"
    ? "libheif-cve-2026-49271"
    : "smoke";
  if (parsed.profile !== expectedProfile) return false;
  if (!/^[0-9a-f]{64}$/.test(parsed.grade_freeze_bundle_sha256 || "")) return false;
  if (
    typeof parsed.grade_freeze_version_id !== "string"
    || !parsed.grade_freeze_version_id
    || parsed.grade_freeze_version_id.length > 1024
    || /[\u0000-\u001f\u007f]/.test(parsed.grade_freeze_version_id)
  ) return false;
  const key = resolveHmacKey();
  if (!key) return false;
  let expected;
  let provided;
  try {
    expected = crypto.createHmac("sha256", key)
      .update(JSON.stringify([
        parsed.profile,
        targetDomain,
        parsed.grade_verdict_hash,
        parsed.grade_freeze_bundle_sha256,
        parsed.grade_freeze_version_id,
      ]), "utf8")
      .digest();
    provided = Buffer.from(parsed.hmac, "hex");
  } catch {
    return false;
  }
  if (!Buffer.isBuffer(provided) || provided.length !== expected.length) return false;
  try {
    return crypto.timingSafeEqual(provided, expected);
  } catch {
    return false;
  }
}

module.exports = {
  verifyApprovalArtifact,
  _setApprovalBackendForTest,
  _setApprovalHmacKeyForTest,
};
