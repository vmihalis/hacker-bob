"use strict";

const { httpScan } = require("../http-scan.js");
const { verifyCompositionPath } = require("../composition-live-verifier.js");

async function verifyCompositionPathToolHandler(args) {
  const result = await verifyCompositionPath(
    {
      target_domain: args.target_domain,
      base_url: args.base_url,
      path: args.path,
      block_internal_hosts: args.block_internal_hosts,
      egress_profile: args.egress_profile,
    },
    { httpScanFn: httpScan },
  );
  return result;
}

const REQUEST_SCHEMA = {
  type: "object",
  properties: {
    method: { type: "string" },
    url: { type: "string", description: "Request path joined onto base_url, or an absolute in-scope URL." },
    auth_profile: { type: "string", description: "Auth profile name; omit for an anonymous (no-auth) request." },
  },
  required: ["url"],
};

module.exports = Object.freeze({
  name: "bob_verify_composition_path",
  description:
    "LIVE-verify a composition path for SC1's confirm-half (object-auth/HTTP guard edges). " +
    "For each guard leaf, re-executes the CB-D1 7-control battery live (attacker/victim/no-auth/" +
    "nonexistent/public/stale/cache-nonce as (auth_profile, url) probes), re-derives the deterministic " +
    "object-auth differential verdict, and mints a verified_pass ONLY when every guard leaf's flip " +
    "reproduces and agrees with its offline claim. A self-consistent counterfeit observation that passes " +
    "the offline shape gate is refuted on re-execution. Non-guard / non-HTTP edges return inconclusive " +
    "(K=1: object-auth only). The verified_pass is written to the MCP-owned, audit-graded " +
    "composition-verified.jsonl ledger that SC1 grades on; no frontier event is emitted.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      base_url: {
        type: "string",
        description: "Base URL each leaf request path is joined onto. Scope-enforced.",
      },
      path: {
        type: "array",
        minItems: 1,
        description:
          "Ordered composition path. Each leaf binds an offline observation (evidence_ref) and carries the live " +
          "re-execution inputs for a guard edge: the primary attack request plus the control_plan probe set.",
        items: {
          type: "object",
          properties: {
            evidence_ref: { type: "string", description: "frontier_event:<event_id> of the leaf's offline observation.recorded." },
            edge_id: { type: "string" },
            primary: {
              ...REQUEST_SCHEMA,
              description: "The attack request: attacker principal reaching the victim object.",
            },
            control_plan: {
              type: "array",
              description:
                "Per-control probe requests. Each: {control, method, url, auth_profile?}. control is one of " +
                "attacker_owned_control, victim_auth_same_object, no_auth_same_object, nonexistent_object, " +
                "public_object_check, stale_session_check, cache_nonce_check.",
              items: {
                type: "object",
                properties: {
                  control: { type: "string" },
                  method: { type: "string" },
                  url: { type: "string" },
                  auth_profile: { type: "string" },
                  evidence_ref: { type: "string" },
                },
                required: ["control", "url"],
              },
            },
          },
          required: ["evidence_ref"],
        },
      },
      block_internal_hosts: {
        type: "boolean",
        description: "Forwarded to bob_http_scan. When omitted, the session's persisted effective policy is used.",
      },
      egress_profile: {
        type: "string",
        pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        description: "Forwarded to bob_http_scan when set.",
      },
    },
    required: ["target_domain", "base_url", "path"],
  },
  handler: verifyCompositionPathToolHandler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: true,
  browser_access: false,
  scope_required: true,
  scope_url_fields: ["base_url"],
  sensitive_output: true,
  session_artifacts_written: ["composition-verified.jsonl", "composition-results.jsonl"],
});
