"use strict";

// Legacy bounty_report_written tool. Deprecated as of Cycle C.7 of the
// frontier-topology realization hypergraph. The supported replacement is
// bob_finalize_report (finalize-report.js), which appends a hash-bound
// ReportSnapshot row to report-snapshots.jsonl after resolving four
// upstream hashes.
//
// This wrapper stays registered so existing callers do not break. Every
// invocation:
//   1. delegates to the original reportWritten handler so the
//      report.md-present check and the legacy report_written pipeline event
//      keep flowing (analytics and pipeline-analytics bottleneck detection
//      depend on the legacy event signal during the dual-write window).
//   2. opportunistically appends a ReportSnapshot row when all four upstream
//      hashes resolve. If any upstream is missing the dual-write is silently
//      skipped so the legacy contract (event-only, no hash binding) is
//      preserved for callers that have not yet advanced through the
//      CLAIM_FREEZE → VERIFY → GRADE chain.

const { reportWritten } = require("../session-state.js");
const {
  appendFrontierEvent,
} = require("../frontier-events.js");
const {
  appendReportSnapshot,
} = require("../report-snapshots.js");
const {
  tryResolveReportFinalizationHashes,
} = require("../report-finalize.js");

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
  const response = reportWritten(args);
  const bundle = tryResolveReportFinalizationHashes(args && args.target_domain);
  if (bundle == null) {
    return response;
  }
  // Dual-write per Pact P2: the new tool is bob_finalize_report; until that
  // tool is the only entry point we mirror the ReportSnapshot append so any
  // caller hitting the legacy path still produces a hash-bound row.
  try {
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
          via_legacy_tool: true,
        },
        source: { artifact: "report-snapshots.jsonl", tool: "bounty_report_written" },
      });
    } catch {
      // Frontier event is observational; do not regress the legacy response.
    }
  } catch {
    // Snapshot dual-write must never regress the legacy event-only contract.
    // The bob_finalize_report path is the authoritative way to require a
    // snapshot; the legacy tool is best-effort here by design.
  }
  return response;
}

module.exports = Object.freeze({
  name: "bounty_report_written",
  description:
    "Deprecated: mark report.md as written for this session and emit a " +
    "report_written pipeline event. Prefer bob_finalize_report; this shim " +
    "preserves the legacy event-only contract and opportunistically appends " +
    "a hash-bound ReportSnapshot row when all four upstream hashes resolve.",
  deprecated: true,
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
    },
    "required": ["target_domain"],
  },
  handler,
  role_bundles: ["reporter", "orchestrator"],
  // Appends a row to pipeline-events.jsonl; the dual-write path also appends
  // to report-snapshots.jsonl and frontier-events.jsonl when the four
  // upstream hashes resolve. mutating: true keeps the audit envelope honest.
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [
    "pipeline-events.jsonl",
    "report-snapshots.jsonl",
    "frontier-events.jsonl",
  ],
});
