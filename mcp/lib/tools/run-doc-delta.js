"use strict";

const { httpScan } = require("../http-scan.js");
const { runDocDelta } = require("../doc-delta-runner.js");
const { makeHttpScanFetcher } = require("../http-scan-adapter.js");

async function runDocDeltaToolHandler(args) {
  const fetch_fn = makeHttpScanFetcher({
    httpScanFn: httpScan,
    target_domain: args.target_domain,
    auth_profile: args.auth_profile,
    block_internal_hosts: args.block_internal_hosts,
    egress_profile: args.egress_profile,
  });
  const result = await runDocDelta({
    target_domain: args.target_domain,
    base_url: args.base_url,
    fetch_fn,
    endpoint_pattern: args.endpoint_pattern,
    method: args.method,
    limit: args.limit,
    run_id: args.run_id,
  });
  return {
    schema_version: result.schema_version,
    summary: result.summary,
    results_hash: result.results_hash,
    results_path: "doc-delta-results.json",
  };
}

module.exports = Object.freeze({
  name: "bob_run_doc_delta",
  aliases: ["bounty_run_doc_delta"],
  capability_id: "C2_doc_vs_behavior",
  description:
    "Run a doc-vs-behavior differential against the persisted schema-contract corpus. For each contract, issues a request via bob_http_scan, classifies divergences, and writes doc-delta-results.json. Use after seeding the corpus with bob_ingest_schema_doc.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      base_url: {
        type: "string",
        description: "Base URL the contract endpoints are joined onto. Combined with each contract.endpoint to form the request URL.",
      },
      auth_profile: {
        type: "string",
        description: "Optional auth profile name to inject. When set, sent_with_auth flag is true for divergence classification.",
      },
      endpoint_pattern: {
        type: "string",
        description: "Optional substring filter on contract endpoints.",
      },
      method: {
        type: "string",
        description: "Optional HTTP method filter. Case-insensitive.",
      },
      limit: {
        type: "integer",
        minimum: 1,
        maximum: 1000,
        description: "Max contracts to test in this run. Defaults to the runner's internal cap.",
      },
      run_id: {
        type: "string",
        description: "Optional opaque identifier captured in the result summary for cross-run correlation.",
      },
      block_internal_hosts: {
        type: "boolean",
        description: "Forwarded to bob_http_scan. When omitted, the session's persisted effective policy is used by bob_http_scan.",
      },
      egress_profile: {
        type: "string",
        pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        description: "Forwarded to bob_http_scan when set.",
      },
    },
    required: ["target_domain", "base_url"],
  },
  handler: runDocDeltaToolHandler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: true,
  browser_access: false,
  scope_required: true,
  scope_url_fields: ["base_url"],
  sensitive_output: true,
  session_artifacts_written: ["doc-delta-results.json"],
});
