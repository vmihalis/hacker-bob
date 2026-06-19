"use strict";

const { ingestAuditReport } = require("../audit-report-parser.js");

function ingestAuditReportHandler(args) {
  return ingestAuditReport({
    target_domain: args.target_domain,
    raw_markdown: args.raw_markdown,
    source_uri: args.source_uri,
  });
}

module.exports = Object.freeze({
  name: "bob_ingest_audit_report",
  aliases: ["bounty_ingest_audit_report"],
  description:
    "Parse a markdown audit report into structured findings and persist them to audit-reports.jsonl. Idempotent by source_doc_hash; later ingestion of the same report is a no-op for unchanged content. Each finding gains a vulnerability_class label (reentrancy, access_control, arithmetic_overflow, oracle_manipulation, ...) so I5's invariant template corpus can suggest matching Foundry harnesses.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      raw_markdown: {
        type: "string",
        description: "Raw markdown audit report. H1 is the title; H2 sections are findings; severity comes from H2 inline `(Severity: ...)` or a `**Severity:**` body line.",
      },
      source_uri: {
        type: "string",
        description: "Optional URL or file path the report was fetched from.",
      },
    },
    required: ["target_domain", "raw_markdown"],
  },
  handler: ingestAuditReportHandler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["audit-reports.jsonl"],
});
