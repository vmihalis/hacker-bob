"use strict";

// Unit tests for the PURE, AWS/fs-free ASFF-building layer extracted out of
// mcp/lib/tools/export-security-hub-finding.js so it can be shared verbatim
// by the downstream ExportSecurityHubFunction Lambda
// (infra/aws/glassbox-stack/functions/export-security-hub/index.js).
//
// These tests deliberately never touch fs/network/session-state -- they
// only exercise the module's exported pure functions -- so they double as
// the "identical ASFF vs the old tool's output on a fixture" regression test
// requested for this refactor: test/export-security-hub-finding.test.js
// still exercises the SAME buildAsffRecord (re-exported, not reimplemented)
// end-to-end through the legacy tool, so any divergence between the two
// call sites would show up as a failure in ONE of these two suites without
// the other moving.

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  ASFF_SCHEMA_VERSION,
  PRODUCT_FIELD_PREFIX,
  TITLE_MAX,
  DESCRIPTION_MAX,
  SNAPSHOT_BINDING_FIELDS,
  truncateText,
  resolvedFindingSeverity,
  isMediumOrHigher,
  workflowStatusForDisposition,
  productFieldsFor,
  buildAsffRecord,
  assertSnapshotBindsCurrentReport,
  assertProofBundleBindsCurrentReport,
  s3UriFor,
  s3KeyFromUri,
} = require("../mcp/lib/asff-builder.js");

const PRODUCT_ARN = "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default";

function fiveHashSet(overrides = {}) {
  return {
    target_domain: "example.com",
    claim_freeze_hash: "a".repeat(64),
    final_verification_hash: "b".repeat(64),
    evidence_hash: "c".repeat(64),
    grade_verdict_hash: "d".repeat(64),
    report_content_hash: "e".repeat(64),
    ...overrides,
  };
}

test("asff-builder loads without fs/AWS SDK/session-path modules at require time", () => {
  const { spawnSync } = require("child_process");
  const path = require("path");
  const script = `
    const Module = require("module");
    const originalLoad = Module._load;
    const forbidden = ["@aws-sdk/", "./storage.js", "./paths.js", "fs"];
    Module._load = function(request, parent, isMain) {
      if (forbidden.some((p) => request === p || request.startsWith(p))) {
        throw new Error("forbidden dependency required at module load: " + request);
      }
      return originalLoad.apply(this, arguments);
    };
    const lib = require("./mcp/lib/asff-builder.js");
    if (typeof lib.buildAsffRecord !== "function") process.exit(2);
  `;
  const result = spawnSync(process.execPath, ["-e", script], {
    cwd: path.join(__dirname, ".."),
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
});

test("truncateText truncates only when over the limit", () => {
  assert.equal(truncateText("short", 10), "short");
  assert.equal(truncateText("a".repeat(20), 10), "a".repeat(10));
  assert.equal(truncateText(null, 10), "");
  assert.equal(truncateText(undefined, 10), "");
});

test("resolvedFindingSeverity prefers reachability.graded_severity over top-level graded_severity", () => {
  assert.equal(resolvedFindingSeverity({ reachability: { graded_severity: "HIGH" }, graded_severity: "low" }), "high");
  assert.equal(resolvedFindingSeverity({ graded_severity: "Medium" }), "medium");
  assert.equal(resolvedFindingSeverity({}), null);
  assert.equal(resolvedFindingSeverity(null), null);
});

test("isMediumOrHigher classifies severity bands", () => {
  assert.equal(isMediumOrHigher("critical"), true);
  assert.equal(isMediumOrHigher("high"), true);
  assert.equal(isMediumOrHigher("medium"), true);
  assert.equal(isMediumOrHigher("low"), false);
  assert.equal(isMediumOrHigher("info"), false);
  assert.equal(isMediumOrHigher(null), false);
});

test("workflowStatusForDisposition maps defender dispositions to ASFF Workflow.Status", () => {
  assert.equal(workflowStatusForDisposition("fix_now"), "NEW");
  assert.equal(workflowStatusForDisposition("worth_fixing"), "NEW");
  assert.equal(workflowStatusForDisposition("watch"), "NOTIFIED");
  assert.equal(workflowStatusForDisposition("held"), "NOTIFIED");
  assert.equal(workflowStatusForDisposition(undefined), "NEW");
});

test("productFieldsFor emits only present hash fields, all under the hacker_bob/ prefix", () => {
  const fields = productFieldsFor({ hashes: fiveHashSet(), s3Uri: "s3://bucket/key.json" });
  assert.deepEqual(fields, {
    [`${PRODUCT_FIELD_PREFIX}claim_freeze_hash`]: "a".repeat(64),
    [`${PRODUCT_FIELD_PREFIX}final_verification_hash`]: "b".repeat(64),
    [`${PRODUCT_FIELD_PREFIX}evidence_hash`]: "c".repeat(64),
    [`${PRODUCT_FIELD_PREFIX}grade_verdict_hash`]: "d".repeat(64),
    [`${PRODUCT_FIELD_PREFIX}report_content_hash`]: "e".repeat(64),
    [`${PRODUCT_FIELD_PREFIX}s3_uri`]: "s3://bucket/key.json",
  });

  // A partial hash set (the new grade-freeze-bound flow, which has no
  // report_content_hash yet) omits the missing fields rather than emitting
  // "undefined" keys.
  const partial = productFieldsFor({
    hashes: { grade_verdict_hash: "d".repeat(64) },
    s3Uri: "s3://bucket/grade-freeze.json",
  });
  assert.deepEqual(partial, {
    [`${PRODUCT_FIELD_PREFIX}grade_verdict_hash`]: "d".repeat(64),
    [`${PRODUCT_FIELD_PREFIX}s3_uri`]: "s3://bucket/grade-freeze.json",
  });
});

test("buildAsffRecord shapes a full ASFF record from a graded finding + claim payload", () => {
  const now = new Date("2026-07-08T00:00:00.000Z");
  const hashes = fiveHashSet();
  const record = buildAsffRecord({
    targetDomain: "example.com",
    gradeFinding: {
      finding_id: "F-1",
      graded_severity: "high",
      defender_disposition: "fix_now",
    },
    findingPayload: {
      id: "F-1",
      title: "IDOR on billing profile",
      description: "Tenant boundary allows cross-account view",
      cwe: "CWE-639",
      cvss_inputs: {
        attack_vector: "network",
        privileges_required: "low",
        confidentiality: "high",
      },
    },
    hashes,
    snapshot: { snapshot_hash: "f".repeat(64) },
    productArn: PRODUCT_ARN,
    s3Uri: "s3://bucket/evidence.json",
    now,
  });

  assert.equal(record.SchemaVersion, ASFF_SCHEMA_VERSION);
  assert.equal(record.Id, `hacker-bob/example.com/F-1/${hashes.report_content_hash.slice(0, 16)}`);
  assert.equal(record.ProductArn, PRODUCT_ARN);
  assert.equal(record.AwsAccountId, "123456789012");
  assert.equal(record.Severity.Label, "HIGH");
  assert.equal(record.Title, "IDOR on billing profile");
  assert.equal(record.Description, "Tenant boundary allows cross-account view");
  assert.equal(record.Workflow.Status, "NEW");
  assert.equal(record.UserDefinedFields.report_snapshot_hash, "f".repeat(64));
  assert.ok(record.Remediation.Recommendation.Text.includes("CWE-639"));
  assert.ok(Array.isArray(record.Cvss) && record.Cvss.length === 1);
  assert.equal(record.Cvss[0].Version, "3.1");
  assert.deepEqual(record.ProductFields, productFieldsFor({ hashes, s3Uri: "s3://bucket/evidence.json" }));
});

test("buildAsffRecord truncates Title/Description at the ASFF field limits", () => {
  const record = buildAsffRecord({
    targetDomain: "example.com",
    gradeFinding: { finding_id: "F-1", graded_severity: "medium" },
    findingPayload: {
      title: "T".repeat(TITLE_MAX + 50),
      description: "D".repeat(DESCRIPTION_MAX + 50),
    },
    hashes: fiveHashSet(),
    productArn: PRODUCT_ARN,
    s3Uri: "s3://bucket/evidence.json",
  });
  assert.equal(record.Title.length, TITLE_MAX);
  assert.equal(record.Description.length, DESCRIPTION_MAX);
});

test("buildAsffRecord falls back to finding_id / default description when no claim payload exists", () => {
  const record = buildAsffRecord({
    targetDomain: "example.com",
    gradeFinding: { finding_id: "F-9", graded_severity: "critical" },
    findingPayload: null,
    hashes: fiveHashSet(),
    productArn: PRODUCT_ARN,
    s3Uri: "s3://bucket/evidence.json",
  });
  assert.equal(record.Title, "F-9");
  assert.equal(record.Description, "Hacker Bob finalized report finding.");
  assert.equal(record.Remediation, undefined);
  assert.equal(record.Cvss, undefined);
});

test("buildAsffRecord refuses without a productArn", () => {
  assert.throws(
    () => buildAsffRecord({
      targetDomain: "example.com",
      gradeFinding: { finding_id: "F-1", graded_severity: "high" },
      findingPayload: null,
      hashes: fiveHashSet(),
      productArn: null,
      s3Uri: "s3://bucket/evidence.json",
    }),
    /product ARN/,
  );
});

test("assertSnapshotBindsCurrentReport passes when all five fields match and throws on any mismatch", () => {
  const hashes = fiveHashSet();
  assert.doesNotThrow(() => assertSnapshotBindsCurrentReport({ snapshot: hashes, hashes }));

  for (const field of SNAPSHOT_BINDING_FIELDS) {
    const staleSnapshot = { ...hashes, [field]: "0".repeat(64) };
    assert.throws(
      () => assertSnapshotBindsCurrentReport({ snapshot: staleSnapshot, hashes }),
      new RegExp(`${field} does not match`),
      `expected a throw for a stale ${field}`,
    );
  }
});

test("assertProofBundleBindsCurrentReport is a no-op when neither side carries proof_bundle_hash", () => {
  assert.doesNotThrow(() => assertProofBundleBindsCurrentReport({ snapshot: {}, hashes: {} }));
});

test("assertProofBundleBindsCurrentReport throws on a one-sided or mismatched proof_bundle_hash", () => {
  assert.throws(
    () => assertProofBundleBindsCurrentReport({
      snapshot: { proof_bundle_hash: "a".repeat(64) },
      hashes: {},
    }),
    /proof_bundle_hash/,
  );
  assert.throws(
    () => assertProofBundleBindsCurrentReport({
      snapshot: { proof_bundle_hash: "a".repeat(64) },
      hashes: { proof_bundle_hash: "b".repeat(64) },
    }),
    /proof_bundle_hash/,
  );
  assert.doesNotThrow(() => assertProofBundleBindsCurrentReport({
    snapshot: { proof_bundle_hash: "a".repeat(64) },
    hashes: { proof_bundle_hash: "a".repeat(64) },
  }));
});

test("s3UriFor / s3KeyFromUri round-trip", () => {
  const uri = s3UriFor({ bucket: "my-bucket", key: "hacker-bob/grade-freeze/example.com/deadbeef.json" });
  assert.equal(uri, "s3://my-bucket/hacker-bob/grade-freeze/example.com/deadbeef.json");
  assert.equal(s3KeyFromUri(uri), "hacker-bob/grade-freeze/example.com/deadbeef.json");
});
