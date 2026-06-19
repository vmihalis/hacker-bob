"use strict";

const { queryAuditReports } = require("../audit-report-parser.js");

function queryAuditReportsHandler(args) {
  return queryAuditReports({
    target_domain: args.target_domain,
    severity_filter: args.severity_filter,
    vulnerability_class_filter: args.vulnerability_class_filter,
    limit: args.limit,
  });
}

module.exports = Object.freeze({
  name: "bob_query_audit_reports",
  aliases: ["bounty_query_audit_reports"],
  description:
    "Query the persisted audit-report corpus for a target. Filters by severity (critical/high/medium/low/informational/info) and vulnerability_class (reentrancy, access_control, arithmetic_overflow, etc.). Use to enumerate audit findings before generating invariants for a Foundry harness.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      severity_filter: { type: "string" },
      vulnerability_class_filter: { type: "string" },
      limit: { type: "integer", minimum: 1, maximum: 200 },
    },
    required: ["target_domain"],
  },
  handler: queryAuditReportsHandler,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
