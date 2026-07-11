// export-security-hub-finding.js — a `reporter`-role MCP write tool that publishes
// finalized SUBMIT/MEDIUM+ findings to AWS Security Hub (ASFF) and writes the evidence
// bundle to S3 Object Lock (WORM). Runs strictly AFTER bob_finalize_report. This is a
// findings-EXPORT / compliance sink: it reads the existing hash-chained pipeline and
// emits an audit/compliance record. It performs no scanning and adds no offensive capability.
//
// Runbook: aabw-2026/projects/06-aws-hacker-bob/AGENTCORE-BRANCH-PLAN.md
'use strict';

const path = require("path");

const {
  loadGradeVerdictHash,
  resolveReportFinalizationHashes,
} = require("../report-finalize.js");
const {
  verifyApprovalArtifact,
} = require("../approval-store.js");
const {
  readReportSnapshots,
} = require("../report-snapshots.js");
const {
  readGradeVerdict,
  requireFinalReportableSeveritySet,
} = require("../grade-verdict-store.js");
const {
  ERROR_CODES,
  ToolError,
} = require("../envelope.js");
const {
  evidencePackPaths,
  gradeArtifactPaths,
  reportMarkdownPath,
  sessionDir,
} = require("../paths.js");
const {
  appendJsonlLine,
  readFileUtf8,
  readJsonFile,
  withSessionLock,
} = require("../storage.js");
const {
  findingPayloadsFromClaims,
} = require("./record-candidate-claim.js");
const { wrapWriteTool } = require("./_write-base.js");
const {
  buildAsffRecord,
  resolvedFindingSeverity,
  isMediumOrHigher,
  assertSnapshotBindsCurrentReport,
  assertProofBundleBindsCurrentReport,
  s3UriFor,
  s3KeyFromUri,
} = require("../asff-builder.js");

const EXPORT_LEDGER_BASENAME = "aws-security-hub-export.jsonl";
const EXPORT_LEDGER_MAX_RECORDS = 10000;

let awsClientFactoriesForTest = null;

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

function s3ClientFactory() {
  const {
    S3Client,
    PutObjectCommand,
  } = require("@aws-sdk/client-s3");
  return {
    client: new S3Client({}),
    PutObjectCommand,
  };
}

function _setAwsClientFactoriesForTest(factories) {
  awsClientFactoriesForTest = factories || null;
}

function awsFactories() {
  return awsClientFactoriesForTest || {
    securityHub: securityHubClientFactory,
    s3: s3ClientFactory,
  };
}

function requiredEnv(name, alternates = []) {
  for (const key of [name, ...alternates]) {
    const value = process.env[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  throw new ToolError(
    ERROR_CODES.STATE_CONFLICT,
    `${name} must be set before exporting findings to AWS Security Hub`,
    { missing_env: name },
  );
}

// truncateText / resolvedFindingSeverity / isMediumOrHigher /
// workflowStatusForDisposition / productFieldsFor / buildAsffRecord all
// moved to ../asff-builder.js (a pure, AWS/fs-free module importable by both
// this tool and the downstream ExportSecurityHubFunction Lambda) and are
// required at the top of this file. Keeping a single implementation means
// the legacy export path here and the new grade-freeze-bound Lambda path
// can never silently diverge in how an ASFF record is shaped.

function latestReportSnapshot(domain) {
  const snapshots = readReportSnapshots(domain);
  if (!Array.isArray(snapshots) || snapshots.length === 0) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `report-snapshots.jsonl has no rows for ${domain}; call bob_finalize_report before exporting to AWS Security Hub`,
      { missing_artifact: "report-snapshots.jsonl" },
      { remediation: "call bob_finalize_report after the report is composed, then re-invoke bob_export_security_hub_finding" },
    );
  }
  return snapshots[snapshots.length - 1];
}

// SNAPSHOT_BINDING_FIELDS / assertSnapshotBindsCurrentReport /
// assertProofBundleBindsCurrentReport moved to ../asff-builder.js; required
// at the top of this file.

function evidenceBundleFor(domain, snapshot, hashes) {
  return {
    version: 1,
    target_domain: domain,
    snapshot,
    hashes,
    artifacts: {
      "evidence-packs.json": readJsonFile(evidencePackPaths(domain).json, { label: "evidence-packs.json" }),
      "report.md": readFileUtf8(reportMarkdownPath(domain), { label: "report.md" }),
      "grade.json": readJsonFile(gradeArtifactPaths(domain).json, { label: "grade.json" }),
    },
  };
}

function legacyEvidenceS3Uri({ bucket, snapshot }) {
  return s3UriFor({ bucket, key: `hacker-bob/security-hub-evidence/${snapshot.snapshot_hash}.json` });
}

function exportLedgerPath(domain) {
  return path.join(sessionDir(domain), EXPORT_LEDGER_BASENAME);
}

async function sendAwsExport({ asffRecord, evidenceBundle, s3Uri }) {
  const factories = awsFactories();
  const securityHub = factories.securityHub();
  const s3 = factories.s3();
  const s3Bucket = s3Uri.slice("s3://".length).split("/")[0];
  const s3Key = s3KeyFromUri(s3Uri);

  await s3.client.send(new s3.PutObjectCommand({
    Bucket: s3Bucket,
    Key: s3Key,
    Body: `${JSON.stringify(evidenceBundle, null, 2)}\n`,
    ContentType: "application/json",
    ObjectLockMode: "COMPLIANCE",
    ObjectLockRetainUntilDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
  }));

  const response = await securityHub.client.send(new securityHub.BatchImportFindingsCommand({
    Findings: [asffRecord],
  }));

  // ASFF honesty: BatchImportFindings can return 200 OK while still rejecting
  // individual findings (FailedCount > 0 / FailedFindings populated) — a
  // partial-failure response, not a thrown error. Inspect it BEFORE returning
  // so the caller (handler(), which appends the ledger row only after this
  // resolves) never records a finding AWS Security Hub actually refused.
  const failedFindings = response && Array.isArray(response.FailedFindings) ? response.FailedFindings : [];
  const failedCount = response && typeof response.FailedCount === "number" ? response.FailedCount : failedFindings.length;
  if (failedCount > 0 || failedFindings.length > 0) {
    const first = failedFindings[0] || {};
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `AWS Security Hub rejected finding ${asffRecord.Id}: ` +
        `${first.ErrorCode || "unknown_error_code"} ${first.ErrorMessage || "no error message returned"}`,
      {
        asff_id: asffRecord.Id,
        failed_count: failedCount,
        error_code: first.ErrorCode || null,
        error_message: first.ErrorMessage || null,
      },
      { remediation: "Inspect the returned ErrorCode/ErrorMessage, fix the ASFF record, and re-invoke bob_export_security_hub_finding; no ledger row is written for a rejected finding." },
    );
  }
}

async function handler(args) {
  const hashes = resolveReportFinalizationHashes(args && args.target_domain);
  const domain = hashes.target_domain;
  const snapshot = latestReportSnapshot(domain);
  assertSnapshotBindsCurrentReport({ snapshot, hashes });
  assertProofBundleBindsCurrentReport({ snapshot, hashes });
  const gradeDocument = JSON.parse(readGradeVerdict({ target_domain: domain }));
  if (gradeDocument.verdict !== "SUBMIT") {
    return JSON.stringify({
      version: 1,
      target_domain: domain,
      verdict: gradeDocument.verdict,
      exported: [],
    });
  }

  // fx-gate-bypass defense 3 — the INDEPENDENT, un-forgeable chokepoint. This
  // check is deliberately UNCONDITIONAL (never gated on BOB_AGENTCORE, unlike
  // lifecycle-gates.js's gradeToReportApprovalBlocker and
  // finalize-report.js's own approval check): a rogue SECOND engine instance
  // spawned outside the AWS branch (e.g. `env -u BOB_AGENTCORE node
  // .../mcp/server.js`) controls its own subprocess env and can trivially
  // make BOB_AGENTCORE-keyed gates inert, but it CANNOT fabricate a valid
  // approval artifact -- the root of trust is the IAM PutObject boundary
  // (only ApprovalWriterRole may write approvals/*.approved; see
  // mcp/lib/approval-store.js's module header), which no engine-side env var
  // can bypass. Reuses verifyApprovalArtifact/loadGradeVerdictHash EXACTLY as
  // lifecycle-gates.js's gradeToReportApprovalBlocker does, so the artifact
  // must be bound (via HMAC over target_domain + grade_verdict_hash) to the
  // CURRENT grade -- a post-approval amend+re-grade fails this identically to
  // how it already fails that gate. Placed here (before productArn/evidence
  // env resolution and before the export loop) so it fails closed before ANY
  // BatchImportFindingsCommand -- or S3 PutObjectCommand -- is ever sent.
  const currentGradeVerdictHash = loadGradeVerdictHash(domain);
  if (!verifyApprovalArtifact(domain, currentGradeVerdictHash)) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `bob_export_security_hub_finding blocked: no valid human-approval artifact for ${domain} `
        + "bound to the current grade verdict",
      { blocked_by: "human_approval_required", target_domain: domain },
      {
        remediation: "a named human approves via the Step Functions task token (SendTaskSuccess "
          + "through the ApprovalWriter Lambda), which writes and HMAC-signs the S3 "
          + "approvals/<target_domain>.approved artifact this chokepoint verifies; the export step "
          + "is withheld until that artifact exists, its HMAC checks out, and its bound "
          + "grade_verdict_hash matches the CURRENT grade verdict",
      },
    );
  }

  const productArn = requiredEnv("AWS_SECURITY_HUB_PRODUCT_ARN", ["SECURITY_HUB_PRODUCT_ARN"]);
  const evidenceBucket = requiredEnv("AWS_SECURITY_HUB_EVIDENCE_BUCKET", ["AWS_EVIDENCE_BUCKET", "EVIDENCE_BUCKET"]);
  const s3Uri = legacyEvidenceS3Uri({ bucket: evidenceBucket, snapshot });
  const findingIds = new Set(gradeDocument.findings.map((finding) => finding.finding_id));
  const reportableSet = requireFinalReportableSeveritySet(domain, findingIds);
  const findingPayloads = new Map(
    findingPayloadsFromClaims(domain).map((finding) => [finding.id, finding]),
  );
  const evidenceBundle = evidenceBundleFor(domain, snapshot, hashes);
  const exported = [];

  for (const finding of gradeDocument.findings) {
    const severity = resolvedFindingSeverity(finding);
    if (
      !isMediumOrHigher(severity) ||
      !reportableSet.has(finding.finding_id)
    ) {
      continue;
    }
    const findingPayload = findingPayloads.get(finding.finding_id) || null;
    const asffRecord = buildAsffRecord({
      targetDomain: domain,
      gradeFinding: finding,
      findingPayload,
      hashes,
      snapshot,
      productArn,
      s3Uri,
    });
    await sendAwsExport({ asffRecord, evidenceBundle, s3Uri });
    const row = {
      version: 1,
      target_domain: domain,
      finding_id: finding.finding_id,
      asff_id: asffRecord.Id,
      severity_label: asffRecord.Severity.Label,
      security_hub_product_arn: productArn,
      s3_uri: s3Uri,
      snapshot_hash: snapshot.snapshot_hash,
      report_content_hash: hashes.report_content_hash,
      exported_at: new Date().toISOString(),
    };
    withSessionLock(domain, () => {
      appendJsonlLine(exportLedgerPath(domain), row, { maxRecords: EXPORT_LEDGER_MAX_RECORDS });
    });
    exported.push(row);
  }

  return JSON.stringify({
    version: 1,
    target_domain: domain,
    verdict: gradeDocument.verdict,
    exported,
  });
}

module.exports = {
  ...wrapWriteTool({
    name: "bob_export_security_hub_finding",
    description:
      "Export finalized SUBMIT/MEDIUM+ Hacker Bob findings to AWS Security Hub " +
      "as ASFF records, write the hash-bound evidence bundle to S3 Object Lock, " +
      "and append aws-security-hub-export.jsonl. Requires an existing " +
      "ReportSnapshot row from bob_finalize_report.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: {
          type: "string",
        },
      },
      required: ["target_domain"],
    },
    handler,
    role_bundles: ["reporter"],
    mutating: true,
    global_preapproval: false,
    // Makes real AWS network calls (S3 PutObject, Security Hub
    // BatchImportFindings) -- see sendAwsExport() above. Was mislabeled
    // false; fx-gate-bypass corrects it (label-only, no behavior change).
    network_access: true,
    browser_access: false,
    scope_required: false,
    sensitive_output: false,
    session_artifacts_written: [
      EXPORT_LEDGER_BASENAME,
    ],
  }),
  _setAwsClientFactoriesForTest,
  buildAsffRecord,
};
