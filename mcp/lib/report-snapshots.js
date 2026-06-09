"use strict";

const {
  assertEnumValue,
  normalizeOptionalText,
} = require("./validation.js");
const {
  assertSafeDomain,
  reportSnapshotsJsonlPath,
} = require("./paths.js");
const {
  appendJsonlLine,
  withSessionLock,
} = require("./storage.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  normalizeId,
  normalizeIsoTimestamp,
  normalizeOptionalId,
  normalizeOptionalTextArray,
  normalizeReferenceArray,
  readJsonlStrict,
  withDocumentHash,
} = require("./fabric-common.js");

const REPORT_SNAPSHOT_VERSION = 1;
const REPORT_SNAPSHOTS_MAX_RECORDS = 10000;
const REPORT_SNAPSHOT_STATUSES = Object.freeze(["draft", "ready", "published", "superseded"]);
const HASH_HEX_RE = /^[0-9a-f]{64}$/i;

function generatedReportSnapshotId(fields) {
  return `RS-${hashCanonicalJson(fields).slice(0, 24)}`;
}

function normalizeHash(value, fieldName) {
  const normalized = normalizeId(value, fieldName).toLowerCase();
  if (!HASH_HEX_RE.test(normalized)) {
    throw new Error(`${fieldName} must be a 64-character hex hash`);
  }
  return normalized;
}

function normalizeReportSnapshot(input, { targetDomain = null, now = new Date() } = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("report snapshot must be an object");
  }
  const domain = assertSafeDomain(input.target_domain || targetDomain);
  const createdAt = normalizeIsoTimestamp(input.created_at || input.ts, "created_at", now);
  const status = assertEnumValue(input.status || "draft", REPORT_SNAPSHOT_STATUSES, "status");
  const claimFreezeHash = normalizeHash(input.claim_freeze_hash, "claim_freeze_hash");
  const verificationHash = normalizeHash(input.final_verification_hash, "final_verification_hash");
  const evidenceHash = normalizeHash(input.evidence_hash || input.evidence_pack_hash, "evidence_hash");
  const proofBundleHash = input.proof_bundle_hash == null
    ? null
    : normalizeHash(input.proof_bundle_hash, "proof_bundle_hash");
  const gradeVerdictHash = normalizeHash(input.grade_verdict_hash, "grade_verdict_hash");
  const base = {
    version: REPORT_SNAPSHOT_VERSION,
    target_domain: domain,
    status,
    created_at: createdAt,
    claim_freeze_hash: claimFreezeHash,
    final_verification_hash: verificationHash,
    evidence_hash: evidenceHash,
    grade_verdict_hash: gradeVerdictHash,
  };
  if (proofBundleHash) base.proof_bundle_hash = proofBundleHash;

  const claimIds = normalizeOptionalTextArray(input.claim_ids, "claim_ids");
  const artifactRefs = normalizeReferenceArray(input.artifact_refs, "artifact_refs");
  const reportPath = normalizeOptionalText(input.report_path, "report_path");
  const summary = normalizeOptionalText(input.summary, "summary");
  const verificationSnapshotHash = input.verification_snapshot_hash == null
    ? null
    : normalizeHash(input.verification_snapshot_hash, "verification_snapshot_hash");
  // Cycle C.7: bind the snapshot to the on-disk report.md content. The
  // ReportSnapshot now carries five hashes (claim_freeze + final_verification +
  // evidence + grade_verdict + report content) so a later consumer can prove
  // the snapshot was finalized over an exact report.md file.
  const reportContentHash = input.report_content_hash == null
    ? null
    : normalizeHash(input.report_content_hash, "report_content_hash");

  if (claimIds.length > 0) base.claim_ids = claimIds;
  if (artifactRefs.length > 0) base.artifact_refs = artifactRefs;
  if (reportPath) base.report_path = reportPath;
  if (summary) base.summary = summary;
  if (verificationSnapshotHash) base.verification_snapshot_hash = verificationSnapshotHash;
  if (reportContentHash) base.report_content_hash = reportContentHash;

  const snapshotId = normalizeOptionalId(input.snapshot_id, "snapshot_id") || generatedReportSnapshotId(base);
  return withDocumentHash({
    snapshot_id: snapshotId,
    ...base,
  }, "snapshot_hash");
}

function appendReportSnapshot(input, options = {}) {
  const snapshot = normalizeReportSnapshot(input, options);
  return withSessionLock(snapshot.target_domain, () => {
    appendJsonlLine(reportSnapshotsJsonlPath(snapshot.target_domain), snapshot, {
      maxRecords: options.maxRecords == null ? REPORT_SNAPSHOTS_MAX_RECORDS : options.maxRecords,
    });
    return snapshot;
  });
}

function readReportSnapshots(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  return readJsonlStrict(
    reportSnapshotsJsonlPath(domain),
    "report-snapshots.jsonl",
    (record) => normalizeReportSnapshot(record, { targetDomain: domain, now: null }),
  );
}

module.exports = {
  REPORT_SNAPSHOTS_MAX_RECORDS,
  REPORT_SNAPSHOT_STATUSES,
  REPORT_SNAPSHOT_VERSION,
  appendReportSnapshot,
  generatedReportSnapshotId,
  normalizeHash,
  normalizeReportSnapshot,
  readReportSnapshots,
};
