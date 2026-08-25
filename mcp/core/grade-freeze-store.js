"use strict";

// grade-freeze-store.js — ARCHITECTURAL FIX (Eric-approved): additive,
// best-effort WORM (S3 Object Lock COMPLIANCE) capture of the graded
// finding set, taken AT GRADE TIME (inside writeGradeVerdict, BEFORE any
// human approval exists), content-addressed by grade_verdict_hash.
//
// This is the durable object the downstream ExportSecurityHubFunction
// Lambda reads from -- never live session state, never claims.jsonl, never
// a re-run bob_finalize_report snapshot -- so a rogue in-process model
// cannot change what an already-approved grade exports by mutating
// claims.jsonl or report.md AFTER a human has approved a given
// grade_verdict_hash: any such mutation either (a) lands under a DIFFERENT
// hash-keyed WORM object, unreachable without a fresh, matching approval, or
// (b) is refused outright because the object at the approved key is
// retained under Object Lock COMPLIANCE and cannot be overwritten.
//
// INTEGRITY ARGUMENT (why the model's role having PutObject on this prefix is SAFE — it cannot
// change what gets exported, reviewed 2026-07-10): the downstream ExportSecurityHub Lambda reads
// ONLY the object keyed by the SFN-approved grade_verdict_hash (`$.gradeResult.grade_verdict_hash`
// from the legit GRADE invocation — a value the model's process can never inject into the SFN
// approval flow) and RE-VERIFIES the object's content hashes to that key. Combined with Object Lock
// COMPLIANCE (a legit freeze is immutable first-write; a rogue cannot overwrite it) and content-
// hash-keying (a rogue cannot place fake content at a real hash's key — hash preimage resistance),
// a rogue engine cannot alter the finding that is exported. Least-privilege build-day refinement:
// move this write to a trusted GRADE-time step outside the model process (documented in the
// aabw-2026 HARDENING-CHECKLIST); also make the write retry-not-silently-noop so a legit finding
// reliably freezes (a transient S3 error currently fails the export CLOSED, safe but a demo gap).
//
// SYNCHRONOUS BY DESIGN, mirroring mcp/core/approval-store.js's own module
// header: writeGradeVerdict (grade-verdict-store.js) is invoked deep inside
// dozens of existing synchronous, session-locked call chains, and making
// that chain async is out of this node's "engine changes additive-only"
// remit. The AWS SDK v3 S3 client is Promise-only, so the real PutObject
// call is bridged through a short-lived child process this function blocks
// on (execFileSync) -- the SAME pattern approval-store.js's readS3Artifact
// already established for this codebase, not a new async-bridging idiom.
//
// Best-effort / additive / NEVER throws: if no bucket is configured
// (BOB_GRADE_FREEZE_BUCKET -- deliberately its OWN, single env var, not
// sharing export-security-hub-finding.js's AWS_SECURITY_HUB_EVIDENCE_BUCKET
// fallback chain, so that unrelated tests/sessions which set the legacy
// export tool's bucket var never accidentally activate this freeze write
// too. In production template.yaml sets BOB_GRADE_FREEZE_BUCKET to the SAME
// EvidenceBucket name, under its own key prefix -- see
// gradeFreezeS3Key -- so operationally there is still only one bucket to
// provision), this is a silent no-op. Every non-AWS-branch local/CI/
// interactive session (the overwhelming majority) writes grade.json exactly
// as before, byte-identical. On the AWS branch it is NOT merely decorative:
// the architecture depends on this object existing by the time a human is
// asked to approve the grade.
//
// Runbook: aabw-2026/projects/06-aws-hacker-bob/AGENTCORE-BRANCH-PLAN.md

const {
  hashCanonicalJson,
} = require("./verification/verification-contracts.js");

let syncPutObjectForTest = null;

// Test-only injection point, mirroring the _setAwsClientFactoriesForTest /
// _setApprovalBackendForTest pattern already established in
// export-security-hub-finding.js / approval-store.js. Never read in
// production. fn receives ({ bucket, key, bodyString, retainUntilIso }) and
// may throw to simulate a failed PutObject.
function _setSyncPutObjectForTest(fn) {
  syncPutObjectForTest = typeof fn === "function" ? fn : null;
}

function resolveBucket() {
  const value = process.env.BOB_GRADE_FREEZE_BUCKET;
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function gradeFreezeS3Key(domain, gradeVerdictHash) {
  return `hacker-bob/grade-freeze/${domain}/${gradeVerdictHash}.json`;
}

// Pure: builds the exact bundle that gets written to WORM. Exported
// separately so a test can assert its shape without touching S3/child
// processes at all.
function buildGradeFreezeBundle({ domain, document, findingPayloads, reportableFindingIds }) {
  const gradeVerdictHash = hashCanonicalJson(document);
  const gradedFindingIds = new Set((document.findings || []).map((finding) => finding.finding_id));
  return {
    version: 1,
    target_domain: domain,
    grade_verdict_hash: gradeVerdictHash,
    grade: document,
    // Only the finding payloads for finding_ids actually bound into THIS
    // grade verdict -- never the full live claims.jsonl -- so a claim
    // appended or rewritten AFTER this freeze cannot ride along under the
    // SAME grade_verdict_hash key. The Lambda builds ASFF Title/Description/
    // cvss_inputs/cwe straight from these frozen payloads, never from a
    // live claims.jsonl read.
    findings: (findingPayloads || []).filter((finding) => finding && gradedFindingIds.has(finding.id)),
    // Persisted so the downstream Lambda can reconstruct the medium+
    // reportable set WITHOUT reading verification-round-final.json off local
    // session disk -- requireFinalReportableSeveritySet (grade-verdict-store.js)
    // is local-session-fs-bound and cannot run inside the Lambda.
    reportable_finding_ids: Array.from(reportableFindingIds || []).sort(),
    frozen_at: new Date().toISOString(),
  };
}

// Bridges a synchronous S3 PutObject through a short-lived child process,
// mirroring approval-store.js's readS3Artifact. The stack-owned bucket's
// default Object Lock rule applies COMPLIANCE retention; omitting per-request
// retention headers keeps this writer at s3:PutObject-only privilege.
// The body is written to a temp file first (rather than passed as a CLI
// argv value) so an arbitrarily large grade-freeze bundle never risks
// hitting an OS argv-length limit.
function putObjectSync({ bucket, key, bodyString }) {
  if (syncPutObjectForTest) {
    syncPutObjectForTest({ bucket, key, bodyString });
    return;
  }
  const fs = require("fs");
  const os = require("os");
  const path = require("path");
  const { execFileSync } = require("child_process");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-grade-freeze-"));
  const tmpFile = path.join(tmpDir, "bundle.json");
  try {
    fs.writeFileSync(tmpFile, bodyString);
    const script = [
      "const fs = require(\"fs\");",
      "const { S3Client, PutObjectCommand } = require(\"@aws-sdk/client-s3\");",
      "(async () => {",
      "  const client = new S3Client({});",
      "  const body = fs.readFileSync(process.argv[4]);",
      "  await client.send(new PutObjectCommand({",
      "    Bucket: process.argv[2],",
      "    Key: process.argv[3],",
      "    Body: body,",
      "    ContentType: \"application/json\",",
      "  }));",
      "})().catch((err) => { process.stderr.write(String((err && err.message) || err)); process.exit(1); });",
    ].join("\n");
    execFileSync(process.execPath, ["-e", script, bucket, key, tmpFile], {
      encoding: "utf8",
      timeout: 10000,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
  }
}

// Additive, best-effort, synchronous, NEVER throws -- a freeze-write
// failure must not block bob_write_grade_verdict; the local grade.json
// write remains the sole authoritative engine-state write. Returns
// {skipped:true, reason} when not configured/failed, or {skipped:false,
// bucket, key, grade_verdict_hash} on a successful PutObject.
function writeGradeFreezeBundleSync({ domain, document, findingPayloads, reportableFindingIds }) {
  const bucket = resolveBucket();
  if (!bucket) return { skipped: true, reason: "no_bucket_configured" };

  const bundle = buildGradeFreezeBundle({ domain, document, findingPayloads, reportableFindingIds });
  const key = gradeFreezeS3Key(domain, bundle.grade_verdict_hash);
  try {
    putObjectSync({
      bucket,
      key,
      bodyString: `${JSON.stringify(bundle, null, 2)}\n`,
    });
    return { skipped: false, bucket, key, grade_verdict_hash: bundle.grade_verdict_hash };
  } catch (error) {
    // Fail-soft by design (see module header): surfaced to stderr for
    // operator visibility but never thrown.
    try {
      process.stderr.write(
        `grade-freeze-store: WORM freeze write failed for ${domain} (${key}): ${(error && error.message) || error}\n`,
      );
    } catch {}
    return { skipped: true, reason: "put_object_failed", error: (error && error.message) || String(error) };
  }
}

module.exports = {
  buildGradeFreezeBundle,
  gradeFreezeS3Key,
  resolveBucket,
  writeGradeFreezeBundleSync,
  _setSyncPutObjectForTest,
};
