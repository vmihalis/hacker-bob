"use strict";

const { readResults } = require("../auth-differential-runner.js");
const { assertSafeDomain } = require("../paths.js");

function readAuthDifferentialResultsHandler(args) {
  const domain = assertSafeDomain(args.target_domain);
  const payload = readResults(domain);
  if (payload == null) {
    return {
      schema_version: 1,
      target_domain: domain,
      exists: false,
      results_path: "auth-differential-results.json",
    };
  }
  if (args.summary_only === true) {
    return {
      schema_version: payload.schema_version,
      target_domain: domain,
      exists: true,
      summary: payload.summary,
      results_hash: payload.results_hash,
      results_path: "auth-differential-results.json",
    };
  }
  return {
    schema_version: payload.schema_version,
    target_domain: domain,
    exists: true,
    summary: payload.summary,
    per_endpoint: payload.per_endpoint,
    results_hash: payload.results_hash,
    results_path: "auth-differential-results.json",
  };
}

module.exports = Object.freeze({
  name: "bob_read_auth_differential_results",
  aliases: ["bounty_read_auth_differential_results"],
  capability_id: "C4_multi_account_differential",
  description:
    "Read the persisted auth-differential-results.json for a target. Pass summary_only: true to skip the per-endpoint array when only the divergence tally is needed.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      summary_only: { type: "boolean", description: "Omit per_endpoint from the response when true." },
    },
    required: ["target_domain"],
  },
  handler: readAuthDifferentialResultsHandler,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
