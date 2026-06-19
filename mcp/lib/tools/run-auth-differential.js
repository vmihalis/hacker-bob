"use strict";

const { httpScan } = require("../http-scan.js");
const { runAuthDifferential } = require("../auth-differential-runner.js");
const { makePerCallHttpScanFetcher } = require("../http-scan-adapter.js");

const UNAUTH_PROFILE_NAMES = new Set([
  "anon",
  "anonymous",
  "guest",
  "noauth",
  "no-auth",
  "public",
  "unauth",
  "unauthenticated",
]);

function deriveDefaultProfileMetadata(authProfiles) {
  const metadata = {};
  for (const profile of authProfiles) {
    const lower = typeof profile === "string" ? profile.toLowerCase() : "";
    metadata[profile] = {
      sent_with_auth: !UNAUTH_PROFILE_NAMES.has(lower),
    };
  }
  return metadata;
}

async function runAuthDifferentialToolHandler(args) {
  const fetch_fn = makePerCallHttpScanFetcher({
    httpScanFn: httpScan,
    target_domain: args.target_domain,
    block_internal_hosts: args.block_internal_hosts,
    egress_profile: args.egress_profile,
  });
  const profileMetadata = args.profile_metadata && typeof args.profile_metadata === "object"
    ? args.profile_metadata
    : deriveDefaultProfileMetadata(args.auth_profiles);
  const result = await runAuthDifferential({
    target_domain: args.target_domain,
    base_url: args.base_url,
    endpoints: args.endpoints,
    auth_profiles: args.auth_profiles,
    fetch_fn,
    profile_metadata: profileMetadata,
    run_id: args.run_id,
    limit: args.limit,
  });
  return {
    schema_version: result.schema_version,
    summary: result.summary,
    results_hash: result.results_hash,
    results_path: "auth-differential-results.json",
  };
}

module.exports = Object.freeze({
  name: "bob_run_auth_differential",
  aliases: ["bounty_run_auth_differential"],
  capability_id: "C4_multi_account_differential",
  description:
    "Run a multi-account differential across the supplied endpoints. For each endpoint, issues a request via bob_http_scan once per auth_profile, classifies divergences (status, response class, body shape, body length, sensitive-field count, unauth-success-with-auth-blocked), and writes auth-differential-results.json. Provide profile_metadata to flag genuine auth bypass; otherwise the tool auto-derives sent_with_auth: false for profile names matching guest/anon/noauth/etc.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      base_url: {
        type: "string",
        description: "Base URL the endpoint paths are joined onto.",
      },
      endpoints: {
        type: "array",
        items: {
          oneOf: [
            { type: "string" },
            {
              type: "object",
              properties: {
                endpoint: { type: "string" },
                method: { type: "string" },
              },
              required: ["endpoint"],
            },
          ],
        },
        description: "Endpoints to differential-test. Each entry is either a path string (defaults to GET) or {endpoint, method}.",
      },
      auth_profiles: {
        type: "array",
        items: { type: "string" },
        minItems: 2,
        description: "Two or more auth profile names to compare. Names like guest/anon/noauth auto-flag sent_with_auth: false unless profile_metadata overrides.",
      },
      profile_metadata: {
        type: "object",
        description: "Optional per-profile metadata. Keyed by profile name; supports sent_with_auth boolean and role string.",
      },
      run_id: {
        type: "string",
        description: "Optional opaque identifier captured in the result summary.",
      },
      limit: {
        type: "integer",
        minimum: 1,
        maximum: 1000,
        description: "Max endpoints to test in this run. Defaults to the runner's internal cap.",
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
    required: ["target_domain", "base_url", "endpoints", "auth_profiles"],
  },
  handler: runAuthDifferentialToolHandler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: true,
  browser_access: false,
  scope_required: true,
  scope_url_fields: ["base_url"],
  sensitive_output: true,
  session_artifacts_written: ["auth-differential-results.json"],
});
