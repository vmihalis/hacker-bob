"use strict";

// bob_finalize_report is the hash-bound report completion tool. It emits the
// report_written pipeline event and appends a ReportSnapshot row only when all
// four upstream hashes resolve, refusing to finalize unless every upstream hash
// is present so the ReportSnapshot ledger never admits an orphan row.

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
const {
  ERROR_CODES,
  ToolError,
} = require("../envelope.js");
const {
  gradeToReportApprovalBlocker,
} = require("../lifecycle-gates.js");
const { wrapWriteTool } = require("./_write-base.js");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");
const {
  writeFindingArtifact,
} = require("../finding-artifact.js");
const {
  buildProjectionPayload,
} = require("../projection-payload.js");

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
  // runner-wiring: emit the canonical structured finding artifact and
  // project the sealed findings into the retained console ledger. The
  // artifact write is unconditional (sealed evidence); projection runs only
  // when the runner dispatched this run (BOB_PROJECTION_URL set) and fails
  // closed — an unprojected dispatched run must not complete.
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
  let projectionSummary = { skipped: true, reason: "no_projection_url" };
  if (process.env.BOB_PROJECTION_URL) {
    const runSlug = process.env.BOB_RUN_SLUG;
    const projectionKey = process.env.BOB_PROJECTION_KEY;
    if (!runSlug || !projectionKey) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        "projection URL is set but the run slug or projection key is missing",
        { code: "projection_env_incomplete" },
      );
    }
    const { payload } = buildProjectionPayload(bundle.target_domain, {
      runSlug,
      projectionKey,
      reportSlug: process.env.BOB_REPORT_SLUG || null,
      kind: process.env.BOB_RUN_KIND === "retest" ? "retest" : "assessment",
      retestOf: process.env.BOB_RETEST_OF
        ? process.env.BOB_RETEST_OF.split(",").map((value) => value.trim()).filter(Boolean)
        : [],
    });
    const payloadFile = path.join(
      os.tmpdir(),
      `bob-projection-${runSlug}-${Date.now()}.json`,
    );
    fs.writeFileSync(payloadFile, JSON.stringify(payload), { encoding: "utf8", mode: 0o600 });
    try {
      const stdout = execFileSync(
        process.execPath,
        [path.join(__dirname, "../../../scripts/project-findings.js"), payloadFile],
        { encoding: "utf8", timeout: 180000, env: { ...process.env } },
      );
      const lastLine = String(stdout).trim().split("\n").pop();
      projectionSummary = JSON.parse(lastLine || "{}");
    } catch (error) {
      let detail = null;
      if (error && error.stdout) {
        try {
          detail = JSON.parse(String(error.stdout).trim().split("\n").pop());
        } catch {
          detail = null;
        }
      }
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `projection failed: ${detail && detail.error ? detail.error : detail && detail.message ? detail.message : error.message || String(error)}`,
        { code: "projection_failed", detail },
      );
    } finally {
      try { fs.unlinkSync(payloadFile); } catch { /* best-effort */ }
    }
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
    artifact: artifactSummary.emitted
      ? {
        written_json: artifactSummary.written_json,
        content_hash: artifactSummary.content_hash,
        findings_count: artifactSummary.reportableCount,
      }
      : { emitted: false, reason: artifactSummary.reason },
    projection: projectionSummary,
  });
}

module.exports = wrapWriteTool({
  name: "bob_finalize_report",
  writes_audit_graded: true,
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
