"use strict";

const { readResults } = require("../doc-delta-runner.js");
const { assertSafeDomain } = require("../paths.js");

function readDocDeltaResultsHandler(args) {
  const domain = assertSafeDomain(args.target_domain);
  const payload = readResults(domain);
  if (payload == null) {
    return {
      schema_version: 1,
      target_domain: domain,
      exists: false,
      results_path: "doc-delta-results.json",
    };
  }
  if (args.summary_only === true) {
    return {
      schema_version: payload.schema_version,
      target_domain: domain,
      exists: true,
      summary: payload.summary,
      results_hash: payload.results_hash,
      results_path: "doc-delta-results.json",
    };
  }
  return {
    schema_version: payload.schema_version,
    target_domain: domain,
    exists: true,
    summary: payload.summary,
    per_contract: payload.per_contract,
    results_hash: payload.results_hash,
    results_path: "doc-delta-results.json",
  };
}

module.exports = Object.freeze({
  name: "bob_read_doc_delta_results",
  aliases: ["bounty_read_doc_delta_results"],
  capability_id: "C2_doc_vs_behavior",
  description:
    "Read the persisted doc-delta-results.json for a target. Pass summary_only: true to skip the per-contract array when only the divergence tally is needed.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      summary_only: { type: "boolean", description: "Omit per_contract from the response when true." },
    },
    required: ["target_domain"],
  },
  handler: readDocDeltaResultsHandler,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
