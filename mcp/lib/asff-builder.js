"use strict";

// asff-builder.js — the PURE ASFF (AWS Security Finding Format)-building layer,
// extracted out of mcp/lib/tools/export-security-hub-finding.js so it can be
// required unmodified by BOTH:
//   (1) the downstream ExportSecurityHubFunction Lambda
//       (infra/aws/hacker-bob-stack/functions/export-security-hub/index.js),
//       which runs under its OWN dedicated IAM role, invoked by Step
//       Functions strictly AFTER the human's SendTaskSuccess — the model's
//       process can never reach it; and
//   (2) any local test harness (test/asff-builder.test.js).
//
// Everything in this file is deterministic and side-effect-free: no fs, no
// AWS SDK, no session-path resolution, no network. It only transforms
// in-memory data and may throw ToolError (itself a dependency-free type).
// This is a hard invariant — do not import mcp/lib/storage.js, mcp/lib/
// paths.js, or any AWS SDK client from this file.
//
// Runbook: aabw-2026/projects/06-aws-hacker-bob/AGENTCORE-BRANCH-PLAN.md

const {
  deriveCvss31,
} = require("./cvss31.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");

const ASFF_SCHEMA_VERSION = "2018-10-08";
const PRODUCT_FIELD_PREFIX = "hacker_bob/";
const TITLE_MAX = 256;
const DESCRIPTION_MAX = 1024;

function truncateText(value, maxLength) {
  const text = typeof value === "string" ? value : "";
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength);
}

function resolvedFindingSeverity(finding) {
  const severity = finding && finding.reachability
    ? finding.reachability.graded_severity
    : finding && finding.graded_severity;
  return typeof severity === "string" ? severity.toLowerCase() : null;
}

const isMediumOrHigher = (severity) => ["medium", "high", "critical"].includes(severity);

function workflowStatusForDisposition(disposition) {
  if (disposition === "fix_now" || disposition === "worth_fixing") return "NEW";
  if (disposition === "watch" || disposition === "held") return "NOTIFIED";
  return "NEW";
}

// productFieldsFor is intentionally tolerant of a partial `hashes` object:
// the old (report-finalize-bound) 5/6-hash chain and the new
// (grade-freeze-bound) caller both funnel through here. Any field absent
// from `hashes` is simply omitted from ProductFields rather than emitted as
// "undefined" — JSON.stringify would drop an `undefined` value anyway, but
// building the object this way keeps callers from needing to know which
// hash set they have in hand.
function productFieldsFor({ hashes = {}, s3Uri }) {
  const fields = {};
  const maybeSet = (key, value) => {
    if (value != null) fields[`${PRODUCT_FIELD_PREFIX}${key}`] = value;
  };
  maybeSet("claim_freeze_hash", hashes.claim_freeze_hash);
  maybeSet("final_verification_hash", hashes.final_verification_hash);
  maybeSet("evidence_hash", hashes.evidence_hash);
  maybeSet("grade_verdict_hash", hashes.grade_verdict_hash);
  maybeSet("grade_freeze_version_id", hashes.grade_freeze_version_id);
  maybeSet("grade_freeze_bundle_sha256", hashes.grade_freeze_bundle_sha256);
  maybeSet("report_content_hash", hashes.report_content_hash);
  maybeSet("proof_bundle_hash", hashes.proof_bundle_hash);
  maybeSet("s3_uri", s3Uri);
  return fields;
}

// Stable ASFF Id suffix: prefers report_content_hash (the legacy 5-hash
// chain, still emitted by the pre-approval-export flow via
// export-security-hub-finding.js's own resolveReportFinalizationHashes
// caller), falling back to grade_verdict_hash (the new grade-freeze-bound
// flow, which runs before report.md is composed and therefore has no
// report_content_hash yet).
function asffIdSuffix(hashes) {
  const source = (hashes && hashes.report_content_hash) || (hashes && hashes.grade_verdict_hash);
  return typeof source === "string" && source.length >= 16 ? source.slice(0, 16) : "unbound";
}

function buildAsffRecord({
  targetDomain,
  gradeFinding,
  findingPayload,
  hashes,
  snapshot,
  productArn,
  s3Uri,
  now = new Date(),
}) {
  if (!productArn || typeof productArn !== "string") {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      "AWS Security Hub product ARN must be provided before building ASFF",
      { missing_env: "AWS_SECURITY_HUB_PRODUCT_ARN" },
    );
  }
  const findingId = gradeFinding.finding_id;
  const severity = resolvedFindingSeverity(gradeFinding);
  const derivedCvss = deriveCvss31(findingPayload && findingPayload.cvss_inputs);
  const record = {
    SchemaVersion: ASFF_SCHEMA_VERSION,
    Id: `hacker-bob/${targetDomain}/${findingId}/${asffIdSuffix(hashes)}`,
    ProductArn: productArn,
    GeneratorId: "hacker-bob",
    AwsAccountId: productArn.split(":")[4] || undefined,
    Types: ["Software and Configuration Checks/Vulnerabilities/CVE"],
    CreatedAt: now.toISOString(),
    UpdatedAt: now.toISOString(),
    Severity: {
      Label: severity.toUpperCase(),
    },
    Title: truncateText(
      findingPayload && findingPayload.title ? findingPayload.title : findingId,
      TITLE_MAX,
    ),
    Description: truncateText(
      findingPayload && findingPayload.description ? findingPayload.description : "Hacker Bob finalized report finding.",
      DESCRIPTION_MAX,
    ),
    Resources: [{
      Type: "Other",
      Id: targetDomain,
      Details: {
        Other: {
          target_domain: targetDomain,
        },
      },
    }],
    Workflow: {
      Status: workflowStatusForDisposition(gradeFinding.defender_disposition),
    },
    ProductFields: productFieldsFor({ hashes, s3Uri }),
  };
  if (findingPayload && findingPayload.cwe) {
    record.Remediation = {
      Recommendation: {
        Text: `Review and remediate ${findingPayload.cwe} evidence in the linked Hacker Bob report bundle.`,
      },
    };
  }
  if (snapshot && snapshot.snapshot_hash) {
    record.UserDefinedFields = {
      report_snapshot_hash: snapshot.snapshot_hash,
    };
  }
  if (!derivedCvss.insufficient) {
    record.Cvss = [{
      Version: derivedCvss.version,
      BaseScore: derivedCvss.base_score,
      BaseVector: derivedCvss.vector,
    }];
  }
  return record;
}

// The upstream-binding fields that tie a ReportSnapshot row to the live
// claim-freeze/verification/evidence/grade/report-content chain (the LEGACY
// post-finalize export flow). Mirrors the idiom in evidence.js
// (normalizeEvidencePacksDocument) and proof-bundle.js
// (normalizeProofBundlesDocument): "${field} does not match current final
// verification".
//
// proof_bundle_hash is deliberately NOT in this list and is checked
// separately by assertProofBundleBindsCurrentReport(): it is an optional
// sixth field, present on the snapshot/hashes only when report.md cites a
// `proof_bundle:F-N` ref, so it cannot be looped over uniformly with the
// five mandatory fields without breaking exports for reports that never
// cite a proof bundle.
const SNAPSHOT_BINDING_FIELDS = [
  "claim_freeze_hash",
  "final_verification_hash",
  "evidence_hash",
  "grade_verdict_hash",
  "report_content_hash",
];

// Guard against exporting a finding whose ReportSnapshot was finalized over a
// report.md / claim-freeze / verification / evidence / grade state that has
// since been superseded (e.g. report.md was amended without re-running
// bob_finalize_report). Pure comparison; the caller resolves both `snapshot`
// and `hashes` from whatever store it has access to (local session state for
// the legacy flow, or is simply not called at all by the grade-freeze flow,
// which has no ReportSnapshot to bind against).
function assertSnapshotBindsCurrentReport({ snapshot, hashes }) {
  for (const field of SNAPSHOT_BINDING_FIELDS) {
    const snapshotValue = snapshot ? snapshot[field] : undefined;
    const currentValue = hashes ? hashes[field] : undefined;
    if (!snapshotValue || snapshotValue !== currentValue) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `${field} does not match current final verification; report-snapshots.jsonl ` +
          `row ${snapshot && snapshot.snapshot_id} is stale for ${hashes && hashes.target_domain} ` +
          `(snapshot ${field}=${snapshotValue || "missing"}, current ${field}=${currentValue}); ` +
          "re-run bob_finalize_report before exporting to AWS Security Hub",
        {
          mismatched_field: field,
          snapshot_id: snapshot && snapshot.snapshot_id,
          snapshot_value: snapshotValue || null,
          current_value: currentValue,
        },
        { remediation: "call bob_finalize_report to append a fresh ReportSnapshot bound to the current report.md, then re-invoke bob_export_security_hub_finding" },
      );
    }
  }
}

// Guard the sixth, optional binding field: proof_bundle_hash. Unlike the five
// SNAPSHOT_BINDING_FIELDS above, this field is only populated when report.md
// cites a `proof_bundle:F-N` ref. When neither side carries a
// proof_bundle_hash, no proof bundle is involved in this report and the check
// is a no-op. When either side is missing it (but not both) or the two
// values differ, the proof bundle was amended (or a binding was dropped)
// after bob_finalize_report last ran, so the export must refuse for the same
// reason a stale five-hash field refuses it.
function assertProofBundleBindsCurrentReport({ snapshot, hashes }) {
  const snapshotValue = snapshot ? snapshot.proof_bundle_hash : undefined;
  const currentValue = hashes ? hashes.proof_bundle_hash : undefined;
  if (!snapshotValue && !currentValue) return;
  if (!snapshotValue || !currentValue || snapshotValue !== currentValue) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `proof_bundle_hash does not match current final verification; report-snapshots.jsonl ` +
        `row ${snapshot && snapshot.snapshot_id} is stale for ${hashes && hashes.target_domain} ` +
        `(snapshot proof_bundle_hash=${snapshotValue || "missing"}, current proof_bundle_hash=${currentValue || "missing"}); ` +
        "re-run bob_finalize_report before exporting to AWS Security Hub",
      {
        mismatched_field: "proof_bundle_hash",
        snapshot_id: snapshot && snapshot.snapshot_id,
        snapshot_value: snapshotValue || null,
        current_value: currentValue || null,
      },
      { remediation: "call bob_finalize_report to append a fresh ReportSnapshot bound to the current report.md and proof bundle, then re-invoke bob_export_security_hub_finding" },
    );
  }
}

function s3UriFor({ bucket, key }) {
  return `s3://${bucket}/${key}`;
}

function s3KeyFromUri(s3Uri) {
  const withoutScheme = s3Uri.slice("s3://".length);
  return withoutScheme.slice(withoutScheme.indexOf("/") + 1);
}

module.exports = {
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
};
