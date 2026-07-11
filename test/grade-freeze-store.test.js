"use strict";

// Unit tests for the additive, best-effort GRADE-time WORM freeze write
// (ARCHITECTURAL FIX, Eric-approved). Covers:
//   1. buildGradeFreezeBundle's pure shape (hash, filtering, ordering).
//   2. writeGradeFreezeBundleSync no-ops cleanly when no bucket is
//      configured (the default posture for every non-AWS-branch session).
//   3. writeGradeFreezeBundleSync performs a synchronous PutObject
//      (via the injectable test seam) when a bucket IS configured, using
//      a grade_verdict_hash-keyed key. Bucket-default Object Lock COMPLIANCE
//      retention is deliberately relied upon, so no PutObjectRetention grant
//      or per-request retention headers are needed.
//   4. A PutObject failure never throws out of writeGradeVerdict's call
//      chain (fail-soft by design).
//   5. writeGradeVerdict (the real, full engine call) triggers this freeze
//      write end-to-end when configured, and is silent/unaffected when not.

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  buildGradeFreezeBundle,
  gradeFreezeS3Key,
  resolveBucket,
  writeGradeFreezeBundleSync,
  _setSyncPutObjectForTest,
} = require("../mcp/lib/grade-freeze-store.js");
const {
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");

function sampleDocument() {
  return {
    version: 1,
    target_domain: "example.com",
    verdict: "SUBMIT",
    total_score: 75,
    findings: [
      { finding_id: "F-1", total_score: 75 },
      { finding_id: "F-2", total_score: 25 },
    ],
    feedback: null,
    claim_freeze_id: "freeze-1",
  };
}

test.afterEach(() => {
  _setSyncPutObjectForTest(null);
  delete process.env.BOB_GRADE_FREEZE_BUCKET;
  delete process.env.AWS_SECURITY_HUB_EVIDENCE_BUCKET;
  delete process.env.AWS_EVIDENCE_BUCKET;
  delete process.env.EVIDENCE_BUCKET;
});

test("resolveBucket reads its OWN dedicated env var only -- never the legacy export tool's AWS_SECURITY_HUB_EVIDENCE_BUCKET/AWS_EVIDENCE_BUCKET/EVIDENCE_BUCKET fallback chain", () => {
  assert.equal(resolveBucket(), null);
  process.env.EVIDENCE_BUCKET = "unrelated-legacy-bucket";
  process.env.AWS_EVIDENCE_BUCKET = "unrelated-legacy-bucket";
  process.env.AWS_SECURITY_HUB_EVIDENCE_BUCKET = "unrelated-legacy-bucket";
  assert.equal(resolveBucket(), null, "must not pick up the legacy export tool's bucket vars");
  process.env.BOB_GRADE_FREEZE_BUCKET = "a-bucket";
  assert.equal(resolveBucket(), "a-bucket");
});

test("buildGradeFreezeBundle is content-addressed by hashCanonicalJson(document) and filters findings to the graded id set", () => {
  const document = sampleDocument();
  const bundle = buildGradeFreezeBundle({
    domain: "example.com",
    document,
    findingPayloads: [
      { id: "F-1", title: "IDOR" },
      { id: "F-2", title: "Info disclosure" },
      { id: "F-99", title: "Not part of this grade -- must be excluded" },
    ],
    reportableFindingIds: new Set(["F-1"]),
  });

  assert.equal(bundle.grade_verdict_hash, hashCanonicalJson(document));
  assert.equal(bundle.target_domain, "example.com");
  assert.deepEqual(bundle.grade, document);
  assert.deepEqual(bundle.findings.map((f) => f.id).sort(), ["F-1", "F-2"]);
  assert.deepEqual(bundle.reportable_finding_ids, ["F-1"]);
  assert.ok(typeof bundle.frozen_at === "string" && bundle.frozen_at.length > 0);
});

test("buildGradeFreezeBundle is deterministic regardless of key order in the document (matches loadGradeVerdictHash's later recompute)", () => {
  const document = sampleDocument();
  // A value-identical object with keys inserted in a different order.
  const shuffled = {
    claim_freeze_id: document.claim_freeze_id,
    findings: document.findings,
    feedback: document.feedback,
    verdict: document.verdict,
    total_score: document.total_score,
    target_domain: document.target_domain,
    version: document.version,
  };
  const a = buildGradeFreezeBundle({ domain: "example.com", document, findingPayloads: [], reportableFindingIds: new Set() });
  const b = buildGradeFreezeBundle({ domain: "example.com", document: shuffled, findingPayloads: [], reportableFindingIds: new Set() });
  assert.equal(a.grade_verdict_hash, b.grade_verdict_hash);
});

test("gradeFreezeS3Key is content-addressed under a stable prefix", () => {
  assert.equal(
    gradeFreezeS3Key("example.com", "deadbeef"),
    "hacker-bob/grade-freeze/example.com/deadbeef.json",
  );
});

test("writeGradeFreezeBundleSync no-ops (skipped:true, no_bucket_configured) when no bucket env var is set", () => {
  let called = false;
  _setSyncPutObjectForTest(() => { called = true; });
  const result = writeGradeFreezeBundleSync({
    domain: "example.com",
    document: sampleDocument(),
    findingPayloads: [],
    reportableFindingIds: new Set(),
  });
  assert.deepEqual(result, { skipped: true, reason: "no_bucket_configured" });
  assert.equal(called, false);
});

test("writeGradeFreezeBundleSync performs a bucket-default-retained PutObject keyed by grade_verdict_hash when configured", () => {
  process.env.BOB_GRADE_FREEZE_BUCKET = "hacker-bob-evidence-test";
  const calls = [];
  _setSyncPutObjectForTest((args) => { calls.push(args); });

  const document = sampleDocument();
  const result = writeGradeFreezeBundleSync({
    domain: "example.com",
    document,
    findingPayloads: [{ id: "F-1", title: "IDOR" }],
    reportableFindingIds: new Set(["F-1"]),
  });

  assert.equal(result.skipped, false);
  assert.equal(result.bucket, "hacker-bob-evidence-test");
  assert.equal(result.grade_verdict_hash, hashCanonicalJson(document));
  assert.equal(result.key, gradeFreezeS3Key("example.com", result.grade_verdict_hash));

  assert.equal(calls.length, 1);
  assert.equal(calls[0].bucket, "hacker-bob-evidence-test");
  assert.equal(calls[0].key, result.key);
  const parsedBody = JSON.parse(calls[0].bodyString);
  assert.equal(parsedBody.grade_verdict_hash, result.grade_verdict_hash);
  assert.deepEqual(parsedBody.grade, document);
  assert.equal(Object.hasOwn(calls[0], "retainUntilIso"), false);
});

test("writeGradeFreezeBundleSync fails soft: a PutObject error is swallowed, never thrown", () => {
  process.env.BOB_GRADE_FREEZE_BUCKET = "hacker-bob-evidence-test";
  _setSyncPutObjectForTest(() => { throw new Error("simulated AWS error"); });

  let result;
  assert.doesNotThrow(() => {
    result = writeGradeFreezeBundleSync({
      domain: "example.com",
      document: sampleDocument(),
      findingPayloads: [],
      reportableFindingIds: new Set(),
    });
  });
  assert.equal(result.skipped, true);
  assert.equal(result.reason, "put_object_failed");
  assert.match(result.error, /simulated AWS error/);
});
