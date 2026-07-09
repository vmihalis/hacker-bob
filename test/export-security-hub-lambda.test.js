"use strict";

// Unit tests for the downstream ExportSecurityHubFunction Lambda handler
// (infra/aws/glassbox-stack/functions/export-security-hub/index.js). No
// live AWS calls: every AWS SDK client is injected via
// _setAwsClientFactoriesForTest, mirroring the SAME test-injection idiom
// already established for the legacy MCP tool
// (mcp/lib/tools/export-security-hub-finding.js's
// _setAwsClientFactoriesForTest).
//
// Covers the properties the ARCHITECTURAL FIX depends on:
//   - exports ONLY the finding set frozen under the event's approved
//     grade_verdict_hash (a WORM-finding fixture);
//   - refuses (never calls BatchImportFindings) when the fetched bundle's
//     OWN grade_verdict_hash or target_domain disagrees with the event, or
//     when the WORM object does not exist at all;
//   - filters to medium+/reportable findings only, sourced entirely from
//     the frozen bundle (never a live claims.jsonl read -- there is none
//     available inside a Lambda);
//   - surfaces AWS Security Hub's partial-failure response (FailedFindings)
//     as a thrown error so Step Functions marks the Task failed.

const test = require("node:test");
const assert = require("node:assert/strict");

const lambda = require("../infra/aws/glassbox-stack/functions/export-security-hub/index.js");

const PRODUCT_ARN = "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default";
const BUCKET = "glassbox-evidence-test";

test.afterEach(() => {
  lambda._setAwsClientFactoriesForTest(null);
  delete process.env.GRADE_FREEZE_BUCKET;
  delete process.env.SECURITY_HUB_PRODUCT_ARN;
});

function sampleBundle({ domain = "example.com", gradeVerdictHash = "d".repeat(64), verdict = "SUBMIT" } = {}) {
  return {
    version: 1,
    target_domain: domain,
    grade_verdict_hash: gradeVerdictHash,
    grade: {
      version: 1,
      target_domain: domain,
      verdict,
      total_score: 75,
      findings: [
        { finding_id: "F-1", graded_severity: "high", defender_disposition: "fix_now", total_score: 75 },
        { finding_id: "F-2", graded_severity: "low", defender_disposition: "watch", total_score: 25 },
        { finding_id: "F-3", graded_severity: "critical", defender_disposition: "fix_now", total_score: 80 },
      ],
    },
    findings: [
      { id: "F-1", title: "IDOR on billing profile", description: "Cross-tenant billing disclosure", cwe: "CWE-639" },
      { id: "F-2", title: "Verbose stack trace", description: "Info disclosure" },
      { id: "F-3", title: "SSRF via webhook URL", description: "Internal metadata endpoint reachable" },
    ],
    // F-2 is excluded: low severity. F-3 is excluded here deliberately to
    // exercise the "graded but NOT reportable" path distinctly from the
    // severity filter (see the dedicated test below).
    reportable_finding_ids: ["F-1"],
    frozen_at: "2026-07-08T00:00:00.000Z",
  };
}

function installAwsFakes({ getObjectBody = null, securityHubResponse = { FailedCount: 0, SuccessCount: 1 } } = {}) {
  const s3Calls = [];
  const securityHubCalls = [];
  class GetObjectCommand {
    constructor(input) { this.input = input; }
  }
  class BatchImportFindingsCommand {
    constructor(input) { this.input = input; }
  }
  lambda._setAwsClientFactoriesForTest({
    s3: () => ({
      GetObjectCommand,
      client: {
        send: async (command) => {
          s3Calls.push(command);
          if (getObjectBody == null) {
            const error = new Error("NoSuchKey");
            error.name = "NoSuchKey";
            throw error;
          }
          const bodyString = typeof getObjectBody === "string" ? getObjectBody : JSON.stringify(getObjectBody);
          return {
            Body: (async function* () { yield Buffer.from(bodyString, "utf8"); })(),
          };
        },
      },
    }),
    securityHub: () => ({
      BatchImportFindingsCommand,
      client: {
        send: async (command) => {
          securityHubCalls.push(command);
          return securityHubResponse;
        },
      },
    }),
  });
  return { s3Calls, securityHubCalls };
}

function withEnv(fn) {
  process.env.GRADE_FREEZE_BUCKET = BUCKET;
  process.env.SECURITY_HUB_PRODUCT_ARN = PRODUCT_ARN;
  return fn();
}

test("handler exports exactly the reportable medium+ finding(s) frozen under the approved grade_verdict_hash", async () => {
  await withEnv(async () => {
    const bundle = sampleBundle();
    const { s3Calls, securityHubCalls } = installAwsFakes({ getObjectBody: bundle });

    const result = await lambda.handler({ target: "example.com", gradeVerdictHash: "d".repeat(64) });

    assert.equal(s3Calls.length, 1);
    assert.equal(s3Calls[0].input.Bucket, BUCKET);
    assert.equal(s3Calls[0].input.Key, lambda.gradeFreezeKey("example.com", "d".repeat(64)));

    assert.equal(securityHubCalls.length, 1);
    assert.equal(securityHubCalls[0].input.Findings.length, 1, "only F-1 is reportable");
    const record = securityHubCalls[0].input.Findings[0];
    assert.equal(record.Title, "IDOR on billing profile");
    assert.equal(record.Severity.Label, "HIGH");
    assert.equal(record.ProductArn, PRODUCT_ARN);
    assert.equal(
      record.ProductFields["hacker_bob/grade_verdict_hash"],
      "d".repeat(64),
    );
    assert.equal(
      record.ProductFields["hacker_bob/s3_uri"],
      `s3://${BUCKET}/${lambda.gradeFreezeKey("example.com", "d".repeat(64))}`,
    );
    // The new grade-freeze-bound flow has no report.md yet -- no
    // report_content_hash/claim_freeze_hash should be present.
    assert.equal(record.ProductFields["hacker_bob/report_content_hash"], undefined);

    assert.equal(result.exported.length, 1);
    assert.equal(result.exported[0].finding_id, "F-1");
    assert.equal(result.exported[0].asff_id, record.Id);
    assert.equal(result.verdict, "SUBMIT");
  });
});

test("handler excludes a graded-but-non-reportable finding even if its severity is medium+", async () => {
  await withEnv(async () => {
    const bundle = sampleBundle();
    // F-3 is critical but NOT in reportable_finding_ids.
    const { securityHubCalls } = installAwsFakes({ getObjectBody: bundle });
    const result = await lambda.handler({ target: "example.com", gradeVerdictHash: "d".repeat(64) });
    assert.equal(result.exported.length, 1);
    assert.ok(!result.exported.some((e) => e.finding_id === "F-3"));
    assert.equal(securityHubCalls[0].input.Findings.length, 1);
  });
});

test("handler no-ops (never calls BatchImportFindings) when no finding is both medium+ and reportable", async () => {
  await withEnv(async () => {
    const bundle = sampleBundle();
    bundle.reportable_finding_ids = [];
    const { securityHubCalls } = installAwsFakes({ getObjectBody: bundle });
    const result = await lambda.handler({ target: "example.com", gradeVerdictHash: "d".repeat(64) });
    assert.deepEqual(result.exported, []);
    assert.equal(securityHubCalls.length, 0);
  });
});

test("handler refuses when the WORM grade-freeze object does not exist, and never calls BatchImportFindings", async () => {
  await withEnv(async () => {
    const { securityHubCalls } = installAwsFakes({ getObjectBody: null });
    await assert.rejects(
      () => lambda.handler({ target: "example.com", gradeVerdictHash: "d".repeat(64) }),
      /no grade-freeze WORM object/,
    );
    assert.equal(securityHubCalls.length, 0);
  });
});

test("handler refuses when the fetched bundle's own grade_verdict_hash disagrees with the approved hash (bucket/key mixup or corruption)", async () => {
  await withEnv(async () => {
    const bundle = sampleBundle({ gradeVerdictHash: "0".repeat(64) });
    const { securityHubCalls } = installAwsFakes({ getObjectBody: bundle });
    await assert.rejects(
      () => lambda.handler({ target: "example.com", gradeVerdictHash: "d".repeat(64) }),
      /grade_verdict_hash=0{64}, expected d{64}/,
    );
    assert.equal(securityHubCalls.length, 0);
  });
});

test("handler refuses when the fetched bundle's target_domain disagrees with the event's target", async () => {
  await withEnv(async () => {
    const bundle = sampleBundle({ domain: "other.example.com" });
    const { securityHubCalls } = installAwsFakes({ getObjectBody: bundle });
    await assert.rejects(
      () => lambda.handler({ target: "example.com", gradeVerdictHash: "d".repeat(64) }),
      /target_domain=other\.example\.com, expected example\.com/,
    );
    assert.equal(securityHubCalls.length, 0);
  });
});

test("handler surfaces a Security Hub partial-failure response (FailedFindings) as a thrown error", async () => {
  await withEnv(async () => {
    const bundle = sampleBundle();
    installAwsFakes({
      getObjectBody: bundle,
      securityHubResponse: {
        FailedCount: 1,
        SuccessCount: 0,
        FailedFindings: [{
          Id: "some-id-mismatch-is-fine-for-this-test",
          ErrorCode: "InvalidInput",
          ErrorMessage: "Severity.Label is not a valid enum value",
        }],
      },
    });
    await assert.rejects(
      () => lambda.handler({ target: "example.com", gradeVerdictHash: "d".repeat(64) }),
      /rejected 1 of 1 finding/,
    );
  });
});

test("handler requires GRADE_FREEZE_BUCKET and SECURITY_HUB_PRODUCT_ARN to be set", async () => {
  delete process.env.GRADE_FREEZE_BUCKET;
  delete process.env.SECURITY_HUB_PRODUCT_ARN;
  await assert.rejects(
    () => lambda.handler({ target: "example.com", gradeVerdictHash: "d".repeat(64) }),
    /GRADE_FREEZE_BUCKET/,
  );
});

test("handler requires event.target and event.gradeVerdictHash", async () => {
  await withEnv(async () => {
    await assert.rejects(() => lambda.handler({}), /event\.target/);
    await assert.rejects(() => lambda.handler({ target: "example.com" }), /event\.gradeVerdictHash/);
  });
});
