"use strict";

// ExportSecurityHubFunction — the DOWNSTREAM Security Hub export Lambda.
//
// ARCHITECTURAL FIX (Eric-approved): the un-forgeable "human approval before
// external notification" property cannot be enforced by an in-process gate
// under `claude --dangerously-skip-permissions` -- the model controls its
// own env/Bash, so every in-process gate leaks. The robust fix moves the
// ASFF Security Hub export OUT of the model-reachable MCP tools entirely and
// makes it a Step Functions Task invoked ONLY after the human's
// SendTaskSuccess (see statemachine/glassbox-engagement.asl.json's
// ExportToSecurityHub state, wired directly after AwaitHumanApproval). The
// model's own process can never reach this Lambda: it runs under its OWN
// dedicated IAM role (ExportSecurityHubRole, template.yaml), which the
// model's GlassboxAgentRuntimeExecutionRole neither assumes nor shares --
// and GlassboxAgentRuntimeExecutionRole itself no longer holds
// securityhub:BatchImportFindings at all (that Sid was removed).
//
// What gets exported is the exact human-APPROVED finding set, captured
// IMMUTABLY (S3 Object Lock COMPLIANCE / WORM) at GRADE time -- BEFORE any
// approval exists -- by mcp/lib/grade-freeze-store.js's
// writeGradeFreezeBundleSync (called from mcp/lib/grade-verdict-store.js's
// writeGradeVerdict, right after the local grade.json write), keyed by
// content-derived grade_verdict_hash. This Lambda reads ONLY that
// grade-freeze WORM object -- NEVER live EFS session state, NEVER
// claims.jsonl, NEVER a re-run bob_finalize_report snapshot -- so even a
// rogue in-process model that appends a forged claims.jsonl row or rewrites
// report.md AFTER a human approves a given grade_verdict_hash cannot change
// what this Lambda exports for that hash: any such mutation either (a)
// lands under a DIFFERENT hash-keyed WORM object the human never approved,
// or (b) is refused outright because the object at the approved key is
// retained under Object Lock COMPLIANCE and cannot be overwritten.
//
// Step Functions topology IS the enforcement here (this Task only runs
// after AwaitHumanApproval resolves, which only happens after
// ApprovalWriterFunction writes the HMAC-signed approval artifact bound to
// the SAME grade_verdict_hash threaded through $.gradeResult) -- this
// handler does not re-verify the HMAC approval artifact itself. It DOES
// independently re-check that the fetched WORM bundle's own
// grade_verdict_hash/target_domain match the event it was invoked with, so
// a bucket-key mixup or a corrupted object fails closed rather than
// silently exporting the wrong finding set.
//
// Reuses mcp/lib/asff-builder.js (a pure, AWS/fs-free module) verbatim for
// ASFF record shaping -- the SAME module the (now-deregistered)
// mcp/lib/tools/export-security-hub-finding.js library imports, so this
// Lambda and that legacy code path can never silently diverge in how an
// ASFF record is built.
//
// Best-effort / buildable-not-deployed: no live AWS call was made while
// authoring this file (mirrors template.yaml's own header convention). Unit
// tests inject fake AWS SDK clients via _setAwsClientFactoriesForTest --
// see test/export-security-hub-lambda.test.js.
//
// Runbook: aabw-2026/projects/06-aws-glassbox/AGENTCORE-BRANCH-PLAN.md

const path = require("path");

const {
  buildAsffRecord,
  resolvedFindingSeverity,
  isMediumOrHigher,
  s3UriFor,
} = require(path.join(__dirname, "..", "..", "..", "..", "..", "mcp", "lib", "asff-builder.js"));

let awsClientFactoriesForTest = null;

function s3ClientFactory() {
  const {
    S3Client,
    GetObjectCommand,
  } = require("@aws-sdk/client-s3");
  return {
    client: new S3Client({}),
    GetObjectCommand,
  };
}

function securityHubClientFactory() {
  const {
    SecurityHubClient,
    BatchImportFindingsCommand,
  } = require("@aws-sdk/client-securityhub");
  return {
    client: new SecurityHubClient({}),
    BatchImportFindingsCommand,
  };
}

function _setAwsClientFactoriesForTest(factories) {
  awsClientFactoriesForTest = factories || null;
}

function awsFactories() {
  return awsClientFactoriesForTest || {
    s3: s3ClientFactory,
    securityHub: securityHubClientFactory,
  };
}

function requiredEnv(name) {
  const value = process.env[name];
  if (typeof value === "string" && value.trim()) return value.trim();
  throw new Error(`${name} must be set for the ExportSecurityHubFunction Lambda`);
}

// Mirrors mcp/lib/grade-freeze-store.js's gradeFreezeS3Key exactly. Not
// require()'d from there directly: that module also carries the (fs/
// child_process-bound) synchronous PutObject writer, which has no business
// existing inside this Lambda's bundle. Duplicating this one pure string
// formatter is cheaper and safer than importing a module with an
// irrelevant, heavier surface -- and any divergence would be caught
// immediately by every WORM read in this Lambda 404ing.
function gradeFreezeKey(domain, gradeVerdictHash) {
  return `hacker-bob/grade-freeze/${domain}/${gradeVerdictHash}.json`;
}

async function streamToString(body) {
  const chunks = [];
  for await (const chunk of body) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

// Fetches and validates the grade-freeze WORM bundle. Throws (fails the
// Step Functions Task, visible to the operator) on any of: object missing,
// malformed JSON, or a bundle whose OWN grade_verdict_hash/target_domain
// disagree with what this Lambda was invoked with -- refusing to export a
// mislabeled or corrupted bundle.
async function readGradeFreezeBundle({ s3, bucket, domain, gradeVerdictHash }) {
  const key = gradeFreezeKey(domain, gradeVerdictHash);
  let response;
  try {
    response = await s3.client.send(new s3.GetObjectCommand({ Bucket: bucket, Key: key }));
  } catch (error) {
    throw new Error(
      `no grade-freeze WORM object at s3://${bucket}/${key} for ${domain} / ${gradeVerdictHash}: ` +
        `${(error && error.message) || error}`,
    );
  }
  let bundle;
  try {
    bundle = JSON.parse(await streamToString(response.Body));
  } catch (error) {
    throw new Error(`grade-freeze WORM object at s3://${bucket}/${key} is not valid JSON: ${(error && error.message) || error}`);
  }
  if (!bundle || bundle.grade_verdict_hash !== gradeVerdictHash) {
    throw new Error(
      `grade-freeze bundle at s3://${bucket}/${key} carries grade_verdict_hash=` +
        `${bundle && bundle.grade_verdict_hash}, expected ${gradeVerdictHash}; refusing to export`,
    );
  }
  if (bundle.target_domain !== domain) {
    throw new Error(
      `grade-freeze bundle at s3://${bucket}/${key} carries target_domain=${bundle.target_domain}, ` +
        `expected ${domain}; refusing to export`,
    );
  }
  return { bundle, key };
}

// The SAME medium+/reportable filter the legacy MCP tool applied
// (export-security-hub-finding.js's handler loop), but sourced entirely
// from the frozen bundle: bundle.reportable_finding_ids (persisted at grade
// time, since requireFinalReportableSeveritySet is local-session-fs-bound
// and cannot run inside this Lambda) and bundle.findings (the frozen claim
// payloads, filtered at freeze time to the graded finding_id set).
function findingsToExport(bundle) {
  const reportableSet = new Set(Array.isArray(bundle.reportable_finding_ids) ? bundle.reportable_finding_ids : []);
  const payloadsById = new Map((bundle.findings || []).map((finding) => [finding.id, finding]));
  const gradedFindings = bundle.grade && Array.isArray(bundle.grade.findings) ? bundle.grade.findings : [];
  return gradedFindings
    .filter((finding) => {
      const severity = resolvedFindingSeverity(finding);
      return isMediumOrHigher(severity) && reportableSet.has(finding.finding_id);
    })
    .map((finding) => ({ finding, payload: payloadsById.get(finding.finding_id) || null }));
}

async function handler(event) {
  const domain = event && event.target;
  const gradeVerdictHash = event && event.gradeVerdictHash;
  if (typeof domain !== "string" || !domain) {
    throw new Error("event.target (target_domain) is required");
  }
  if (typeof gradeVerdictHash !== "string" || !gradeVerdictHash) {
    throw new Error("event.gradeVerdictHash is required");
  }

  const bucket = requiredEnv("GRADE_FREEZE_BUCKET");
  const productArn = requiredEnv("SECURITY_HUB_PRODUCT_ARN");

  const factories = awsFactories();
  const s3 = factories.s3();
  const securityHub = factories.securityHub();

  const { bundle, key } = await readGradeFreezeBundle({ s3, bucket, domain, gradeVerdictHash });
  const toExport = findingsToExport(bundle);

  if (toExport.length === 0) {
    return {
      version: 1,
      target_domain: domain,
      grade_verdict_hash: gradeVerdictHash,
      verdict: bundle.grade && bundle.grade.verdict != null ? bundle.grade.verdict : null,
      exported: [],
    };
  }

  const s3Uri = s3UriFor({ bucket, key });
  const records = toExport.map(({ finding, payload }) => buildAsffRecord({
    targetDomain: domain,
    gradeFinding: finding,
    findingPayload: payload,
    // The new grade-freeze-bound flow runs BEFORE report.md is composed
    // (this Task is wired directly after AwaitHumanApproval, ahead of the
    // REPORT-stage runtime invocation), so only grade_verdict_hash is
    // available here -- there is no report_content_hash/claim_freeze_hash/
    // evidence_hash/final_verification_hash to bind yet. buildAsffRecord's
    // productFieldsFor tolerates a partial hash object and simply omits the
    // fields that don't exist (see asff-builder.js).
    hashes: { grade_verdict_hash: bundle.grade_verdict_hash },
    productArn,
    s3Uri,
  }));

  const response = await securityHub.client.send(new securityHub.BatchImportFindingsCommand({
    Findings: records,
  }));

  // ASFF honesty: BatchImportFindings can return 200 OK while still
  // rejecting individual findings (FailedCount > 0 / FailedFindings
  // populated) -- a partial-failure response, not a thrown SDK error.
  // Mirrors the identical check in the legacy tool's sendAwsExport().
  const failedFindings = response && Array.isArray(response.FailedFindings) ? response.FailedFindings : [];
  const failedCount = response && typeof response.FailedCount === "number" ? response.FailedCount : failedFindings.length;
  const failedIds = new Set(failedFindings.map((f) => f.Id));

  const exported = [];
  for (let i = 0; i < records.length; i += 1) {
    const record = records[i];
    if (failedIds.has(record.Id)) continue;
    exported.push({
      asff_id: record.Id,
      finding_id: toExport[i].finding.finding_id,
      severity_label: record.Severity.Label,
    });
  }

  const result = {
    version: 1,
    target_domain: domain,
    grade_verdict_hash: gradeVerdictHash,
    verdict: bundle.grade && bundle.grade.verdict != null ? bundle.grade.verdict : null,
    exported,
    failed: failedFindings.map((f) => ({
      asff_id: f.Id,
      error_code: f.ErrorCode || null,
      error_message: f.ErrorMessage || null,
    })),
  };

  if (failedCount > 0 || failedFindings.length > 0) {
    // Surface a partial/total failure as a thrown error so Step Functions
    // marks this Task FAILED (operator-visible via CloudTrail/console) even
    // though some findings may have exported successfully.
    const error = new Error(
      `AWS Security Hub rejected ${failedFindings.length} of ${records.length} finding(s) for ` +
        `${domain} / ${gradeVerdictHash}`,
    );
    error.result = result;
    throw error;
  }

  return result;
}

module.exports = {
  handler,
  gradeFreezeKey,
  readGradeFreezeBundle,
  findingsToExport,
  _setAwsClientFactoriesForTest,
};
