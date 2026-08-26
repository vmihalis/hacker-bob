"use strict";

// bob_finalize_report is the hash-bound report completion tool. It emits the
// report_written pipeline event and appends a ReportSnapshot row only when all
// four upstream hashes resolve, refusing to finalize unless every upstream hash
// is present so the ReportSnapshot ledger never admits an orphan row.

const crypto = require("crypto");
const {
  appendFrontierEvent,
} = require("../core/frontier/frontier-events.js");
const {
  appendReportSnapshot,
  normalizeReportSnapshot,
  readReportSnapshots,
} = require("../core/report-snapshots.js");
const {
  resolveReportFinalizationHashes,
} = require("../core/report-finalize.js");
const {
  safeAppendPipelineEventDirect,
} = require("../core/telemetry/pipeline-events.js");
const {
  safeGovernanceContextForDomain,
} = require("../core/governance/index.js");
const {
  ERROR_CODES,
  ToolError,
} = require("../core/io/envelope.js");
const {
  gradeToReportApprovalBlocker,
} = require("../core/session/lifecycle-gates.js");
const { wrapWriteTool } = require("./_write-base.js");
const {
  writeFindingArtifact,
} = require("../finding-artifact.js");
const {
  readFinalizationReceipt,
  writeFinalizationReceipt,
} = require("../finalization-receipt.js");

function artifactRefsForBundle(bundle) {
  const refs = [
    { kind: "markdown", path: "report.md", content_hash: bundle.report_content_hash },
  ];
  if (bundle.proof_bundle_hash) {
    refs.push({ kind: "proof_bundle", path: "proof-bundles.json", content_hash: bundle.proof_bundle_hash });
  }
  return refs;
}

function reportSnapshotInput(bundle) {
  return {
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
  };
}

function resolveReportSnapshot(bundle) {
  const input = reportSnapshotInput(bundle);
  const snapshots = readReportSnapshots(bundle.target_domain);
  for (let index = snapshots.length - 1; index >= 0; index -= 1) {
    const candidate = snapshots[index];
    const expected = normalizeReportSnapshot({
      ...input,
      created_at: candidate.created_at,
      snapshot_id: candidate.snapshot_id,
    });
    if (JSON.stringify(candidate) === JSON.stringify(expected)) {
      return { snapshot: candidate, appended: false };
    }
  }
  return { snapshot: appendReportSnapshot(input), appended: true };
}

function finalizationIdentity(bundle) {
  const configuredRunSlug = typeof process.env.BOB_RUN_SLUG === "string"
    ? process.env.BOB_RUN_SLUG.trim()
    : "";
  const runSlug = configuredRunSlug || `local-${crypto
    .createHash("sha256")
    .update(bundle.target_domain)
    .digest("hex")
    .slice(0, 20)}`;
  const reportSlug = `${runSlug}-report`;
  const configuredReportSlug = typeof process.env.BOB_REPORT_SLUG === "string"
    ? process.env.BOB_REPORT_SLUG.trim()
    : "";
  if (configuredReportSlug && configuredReportSlug !== reportSlug) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      "configured report slug does not match the deterministic run report slug",
      { code: "report_slug_mismatch", run_slug: runSlug },
    );
  }
  return { projectionRequired: false, runSlug, reportSlug };
}

function assertExistingReceiptIdentity(existing, bundle, identity) {
  const receipt = existing.receipt;
  const expected = {
    runSlug: identity.runSlug,
    targetDomain: bundle.target_domain,
    reportSlug: identity.reportSlug,
    freezeHash: bundle.claim_freeze_hash,
    snapshotHash: bundle.final_verification_hash,
    evidenceHash: bundle.evidence_hash,
    reportContentHash: bundle.report_content_hash,
  };
  const mismatched = Object.keys(expected).filter((key) => receipt[key] !== expected[key]);
  if (receipt.projection.required !== identity.projectionRequired) {
    mismatched.push("projection.required");
  }
  if (mismatched.length > 0) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `completed finalization receipt conflicts with current identity: ${mismatched.join(", ")}`,
      { code: "finalization_receipt_conflict", mismatched_fields: mismatched },
    );
  }
}

function replayResponse(existing) {
  const receipt = existing.receipt;
  return JSON.stringify({
    version: 1,
    finalized: true,
    replayed: true,
    target_domain: receipt.targetDomain,
    claim_freeze_hash: receipt.freezeHash,
    final_verification_hash: receipt.snapshotHash,
    evidence_hash: receipt.evidenceHash,
    artifact: receipt.artifact,
    projection: receipt.projection,
    finalization_receipt: receipt,
    finalization_receipt_sha256: existing.sha256,
  });
}

function handler(args) {
  // Resolve the four upstream hashes + report content hash. Each missing
  // upstream raises a structured ToolError with a precise pointer so the
  // caller can advance the missing stage and re-finalize.
  const bundle = resolveReportFinalizationHashes(args && args.target_domain);
  const identity = finalizationIdentity(bundle);
  const existingReceipt = readFinalizationReceipt(bundle.target_domain, { required: false });
  if (existingReceipt) {
    assertExistingReceiptIdentity(existingReceipt, bundle, identity);
    return replayResponse(existingReceipt);
  }

  // AgentCore rail-b (P1-3): the same GRADE -> REPORT human-approval blocker
  // gateGradeToReport enforces at the bob_advance_session(to_state=REPORT) transition
  // must also cover bob_finalize_report directly -- a session can reach REPORT and then
  // have bob_finalize_report re-invoked later (e.g. after a report.md edit; this tool is
  // explicitly append-only/re-finalizable, see its description below), a point in time the
  // transition-time gate never re-checks. Inert unless BOB_AGENTCORE==="1"
  // (gradeToReportApprovalBlocker's own first check); fails CLOSED with the identical
  // structured blocker shape bob_advance_session surfaces.
  const approvalBlockers = gradeToReportApprovalBlocker({ target_domain: bundle.target_domain });
  if (approvalBlockers.length > 0) {
    const first = approvalBlockers[0];
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `bob_finalize_report blocked: ${first.message || first.code}`,
      {
        blocked_by: first.blocked_by || first.code,
        code: first.code || first.blocked_by,
        target_domain: bundle.target_domain,
      },
      { remediation: typeof first.remediation === "string" ? first.remediation : null },
    );
  }

  // Append a ReportSnapshot row binding all five hashes. The snapshot is
  // hash-bound (snapshot_hash) and append-only (REPORT_SNAPSHOTS_MAX_RECORDS
  // cap inside appendReportSnapshot).
  const snapshotResolution = resolveReportSnapshot(bundle);
  const snapshot = snapshotResolution.snapshot;

  if (snapshotResolution.appended) {
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

  // Emit the report_written pipeline event so analytics and pipeline-analytics
  // bottleneck detection see the canonical report-completion signal.
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
  }
  // Emit the canonical structured finding artifact. Hosted projection is
  // deliberately owned by the trusted runner parent after Codex exits; this
  // MCP process never receives the control-plane credential or performs
  // network I/O.
  let artifactSummary;
  try {
    artifactSummary = writeFindingArtifact(bundle.target_domain);
  } catch (error) {
    if (error instanceof ToolError) throw error;
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `finding artifact emission failed: ${error.message || String(error)}`,
      { artifact: "finding-artifact.json" },
    );
  }
  const projectionReceipt = {
    required: false,
    succeeded: false,
    duplicate: false,
    projected: 0,
    reopened: 0,
    closed: 0,
  };
  const consoleReport = {
    schemaVersion: 1,
    domain: bundle.target_domain,
    findings: [],
  };

  const receiptWrite = writeFinalizationReceipt(bundle.target_domain, {
    schemaVersion: 1,
    runSlug: identity.runSlug,
    targetDomain: bundle.target_domain,
    reportSlug: identity.reportSlug,
    completedAt: new Date().toISOString(),
    freezeHash: bundle.claim_freeze_hash,
    snapshotHash: bundle.final_verification_hash,
    evidenceHash: bundle.evidence_hash,
    reportContentHash: bundle.report_content_hash,
    artifact: {
      emitted: artifactSummary.emitted,
      sha256: artifactSummary.emitted ? artifactSummary.content_hash : null,
      findingCount: artifactSummary.reportableCount,
    },
    projection: projectionReceipt,
    consoleReport,
  });


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
    artifact: artifactSummary.emitted
      ? {
        written_json: artifactSummary.written_json,
        content_hash: artifactSummary.content_hash,
        findings_count: artifactSummary.reportableCount,
      }
      : { emitted: false, reason: artifactSummary.reason },
    projection: receiptWrite.receipt.projection,
    finalization_receipt: receiptWrite.receipt,
    finalization_receipt_sha256: receiptWrite.sha256,
  });
}

const finalizeReportTool = wrapWriteTool({
  name: "bob_finalize_report",
  writes_audit_graded: true,
  description:
    "Finalize the canonical session report.md by appending a hash-bound " +
    "ReportSnapshot row to report-snapshots.jsonl. Resolves four upstream " +
    "hashes (claim_freeze_hash, final_verification_hash, evidence_hash, " +
    "grade_verdict_hash) plus the report.md content hash, and when report.md " +
    "cites proof_bundle refs it also binds proof-bundles.json. Refuses if any " +
    "required upstream artifact is missing. Completion is immutable once the " +
    "hash-verified finalization receipt is written; identical redelivery returns " +
    "that receipt without appending another snapshot. Hosted projection is " +
    "performed by the trusted runner parent after this tool completes.",
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
    "finding-artifact.json",
    "finding-artifact.sha256",
    "finalization-receipt.json",
    "finalization-receipt.sha256",
  ],
});

module.exports = Object.freeze({ ...finalizeReportTool });
