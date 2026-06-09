"use strict";

// Cycle C.7: bob_finalize_report is the hash-bound replacement for
// bounty_report_written. Both tools coexist during the deprecation window
// (Pact P2 — dual-write before deletion); both append a ReportSnapshot row
// when all four upstream hashes resolve. The new tool refuses to finalize
// unless every upstream hash is present so the ReportSnapshot ledger never
// admits an orphan row.

const {
  appendFrontierEvent,
} = require("../frontier-events.js");
const {
  appendReportSnapshot,
} = require("../report-snapshots.js");
const {
  resolveReportFinalizationHashes,
} = require("../report-finalize.js");
const {
  safeAppendPipelineEventDirect,
} = require("../pipeline-events.js");
const {
  safeGovernanceContextForDomain,
} = require("../governance-context.js");
const { wrapWriteTool } = require("./_write-base.js");

function artifactRefsForBundle(bundle) {
  const refs = [
    { kind: "markdown", path: "report.md", content_hash: bundle.report_content_hash },
  ];
  if (bundle.proof_bundle_hash) {
    refs.push({ kind: "proof_bundle", path: "proof-bundles.json", content_hash: bundle.proof_bundle_hash });
  }
  return refs;
}

function handler(args) {
  // Resolve the four upstream hashes + report content hash. Each missing
  // upstream raises a structured ToolError with a precise pointer so the
  // caller can advance the missing stage and re-finalize.
  const bundle = resolveReportFinalizationHashes(args && args.target_domain);

  // Append a ReportSnapshot row binding all five hashes. The snapshot is
  // hash-bound (snapshot_hash) and append-only (REPORT_SNAPSHOTS_MAX_RECORDS
  // cap inside appendReportSnapshot).
  const snapshot = appendReportSnapshot({
    target_domain: bundle.target_domain,
    status: "ready",
    claim_freeze_hash: bundle.claim_freeze_hash,
    final_verification_hash: bundle.final_verification_hash,
    evidence_hash: bundle.evidence_hash,
    proof_bundle_hash: bundle.proof_bundle_hash,
    grade_verdict_hash: bundle.grade_verdict_hash,
    report_content_hash: bundle.report_content_hash,
    claim_ids: bundle.claim_ids,
    artifact_refs: artifactRefsForBundle(bundle),
    report_path: "report.md",
  });

  // Emit a frontier event so the materialized claim-plane projections see the
  // snapshot row. The event carries the snapshot_id and report_snapshot_id
  // identity so consumers can dereference back to the ledger entry.
  try {
    appendFrontierEvent({
      target_domain: bundle.target_domain,
      kind: "claim.report_snapshot.appended",
      payload: {
        snapshot_id: snapshot.snapshot_id,
        snapshot_hash: snapshot.snapshot_hash,
        claim_freeze_hash: bundle.claim_freeze_hash,
        final_verification_hash: bundle.final_verification_hash,
        evidence_hash: bundle.evidence_hash,
        ...(bundle.proof_bundle_hash ? { proof_bundle_hash: bundle.proof_bundle_hash } : {}),
        grade_verdict_hash: bundle.grade_verdict_hash,
        report_content_hash: bundle.report_content_hash,
        report_size_bytes: bundle.report_size_bytes,
      },
      source: { artifact: "report-snapshots.jsonl", tool: "bob_finalize_report" },
    });
  } catch {
    // The ReportSnapshot row is the authoritative record; the frontier event
    // is observational. A producer regression must not block the snapshot
    // append.
  }

  // Dual-write per Pact P2: keep the legacy report_written pipeline event so
  // analytics and pipeline-analytics bottleneck detection continue to see the
  // canonical signal even when callers migrate to bob_finalize_report.
  try {
    safeAppendPipelineEventDirect(bundle.target_domain, "report_written", {
      status: "written",
      source: "bob_finalize_report",
      counts: {
        report_size_bytes: bundle.report_size_bytes,
      },
    }, safeGovernanceContextForDomain(bundle.target_domain));
  } catch {
    // Best-effort; the pipeline-event emission must never regress the
    // ReportSnapshot append.
  }

  return JSON.stringify({
    version: 1,
    finalized: true,
    target_domain: bundle.target_domain,
    snapshot_id: snapshot.snapshot_id,
    snapshot_hash: snapshot.snapshot_hash,
    claim_freeze_hash: bundle.claim_freeze_hash,
    final_verification_hash: bundle.final_verification_hash,
    evidence_hash: bundle.evidence_hash,
    ...(bundle.proof_bundle_hash ? { proof_bundle_hash: bundle.proof_bundle_hash } : {}),
    grade_verdict_hash: bundle.grade_verdict_hash,
    report_content_hash: bundle.report_content_hash,
    report_path: bundle.report_path,
    report_size_bytes: bundle.report_size_bytes,
  });
}

module.exports = wrapWriteTool({
  name: "bob_finalize_report",
  description:
    "Finalize the canonical session report.md by appending a hash-bound " +
    "ReportSnapshot row to report-snapshots.jsonl. Resolves four upstream " +
    "hashes (claim_freeze_hash, final_verification_hash, evidence_hash, " +
    "grade_verdict_hash) plus the report.md content hash, and when report.md " +
    "cites proof_bundle refs it also binds proof-bundles.json. Refuses if any " +
    "required upstream artifact is missing. Append-only; subsequent calls produce a " +
    "new row with the current report content hash so re-finalize after a " +
    "report.md edit is detectable in the ledger.",
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
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [
    "report-snapshots.jsonl",
    "frontier-events.jsonl",
    "pipeline-events.jsonl",
  ],
});
