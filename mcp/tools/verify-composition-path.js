"use strict";

const { httpScan } = require("../core/http-scan.js");
const { verifyCompositionPath } = require("../core/differential/composition-live-verifier.js");

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

// A cross-stack BIND ref: an ALREADY-EXECUTED MAC-signed row in an executed-row ledger.
// The bind resolver table is the real authority; the ledger enum here is a shape
// convenience. row_id is the ledger-native key (offensive_runs run_id, invariant_runs
// run_hash).
const RUN_REF_SCHEMA = {
  type: "object",
  properties: {
    ledger: {
      type: "string",
      enum: ["offensive_runs", "invariant_runs"],
      description: "Which executed-row ledger the row lives in (offensive_runs=web HTTP, invariant_runs=EVM/SC-FV).",
    },
    row_id: { type: "string", description: "Ledger-native key: offensive_runs run_id, invariant_runs run_hash." },
  },
  required: ["ledger", "row_id"],
};

module.exports = Object.freeze({
  name: "bob_verify_composition_path",
  description:
    "LIVE-verify a composition path for SC1's confirm-half. TWO leaf kinds: " +
    "(1) a GUARD leaf is RE-EXECUTED — re-runs the CB-D1 7-control object-auth battery " +
    "(attacker/victim/no-auth/nonexistent/public/stale/cache-nonce as (auth_profile, url) probes), " +
    "re-derives the deterministic object-auth differential verdict, and verifies ONLY when its flip " +
    "reproduces and agrees with its offline claim (a counterfeit observation that passes the offline " +
    "shape gate is refuted on re-execution). " +
    "(2) a cross-stack BIND leaf (positive_run_ref + control_run_ref) BINDS two already-executed " +
    "MAC-signed rows — offensive_runs (web) and/or invariant_runs (EVM/SC-FV), possibly on DIFFERENT " +
    "surfaces/stacks — and confirms the executed flip (positive demonstrates, control flips to a " +
    "blocked/held disposition, distinct row-hashes) WITHOUT re-executing; its open-vocab edge_type is " +
    "shape-validated only. A single run, a hash-identical control, a non-flipping control, or a MAC-" +
    "tampered row is refused. Both kinds mint a verified_pass to the same MCP-owned, audit-graded " +
    "composition-verified.jsonl ledger keyed by path_hash (no frontier event); the object-auth guard " +
    "re-execution path is unchanged.",
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
          "Ordered composition path. A GUARD leaf binds an offline observation (evidence_ref) and carries the " +
          "live re-execution inputs (primary attack request + control_plan probe set). A cross-stack BIND leaf " +
          "carries positive_run_ref + control_run_ref (already-executed MAC-signed rows) and an open-vocab " +
          "edge_type; it binds, it does not re-execute. A leaf is a bind leaf iff BOTH run refs are present.",
        items: {
          type: "object",
          properties: {
            evidence_ref: { type: "string", description: "Guard leaf: frontier_event:<event_id> of the leaf's offline observation.recorded." },
            edge_id: { type: "string" },
            primary: {
              ...REQUEST_SCHEMA,
              description: "Guard leaf: the attack request — attacker principal reaching the victim object.",
            },
            control_plan: {
              type: "array",
              description:
                "Guard leaf per-control probe requests. Each: {control, method, url, auth_profile?}. control is one of " +
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
            positive_run_ref: {
              ...RUN_REF_SCHEMA,
              description:
                "Cross-stack bind: the ALREADY-EXECUTED MAC-signed row that DEMONSTRATES the mechanism " +
                "(offensive_runs: exploited_safely / invariant_runs: violated). Binds, does not re-execute.",
            },
            control_run_ref: {
              ...RUN_REF_SCHEMA,
              description:
                "Cross-stack bind: the NEGATIVE CONTROL row that MUST FLIP (different executed outcome AND a " +
                "blocked/held disposition; offensive_runs: blocked_by_defense / invariant_runs: held), distinct " +
                "row-hash, MAC-verified.",
            },
            cause_run_ref: {
              ...RUN_REF_SCHEMA,
              description:
                "Cross-stack bind: the offensive_runs row (exploited_safely) that PRODUCED the effect — the " +
                "stack-A CAUSE the violated arm consumed. The violated arm's MAC-covered cause_run_id NAMES it " +
                "and its MAC-covered consumed_artifact_hash equals the cause's (proven-not-named). REQUIRED on a " +
                "cross-stack bind leaf.",
            },
            decoy_run_ref: {
              ...RUN_REF_SCHEMA,
              description:
                "Cross-stack bind: the invariant_runs row that ran the SAME test on the SAME tree with the random " +
                "SHAPE-MATCHED decoy bytes — must HOLD (the artifact-relevance arm). REQUIRED on a cross-stack " +
                "bind leaf.",
            },
            decoy_cause_run_ref: {
              ...RUN_REF_SCHEMA,
              description:
                "Cross-stack bind: the offensive_runs is_decoy:true capture (a DISTINCT shape-matched random-bytes " +
                "capture, same length+encoding-class as the cause, the decoy arm consumes). REQUIRED on a cross-" +
                "stack bind leaf.",
            },
            edge_type: {
              type: "string",
              description:
                "Cross-stack bind leaf: open-vocab mechanism label. SHAPE-validated only (any non-empty string); " +
                "annotates the bind, never gates it.",
            },
          },
          // evidence_ref is OPTIONAL: a GUARD leaf binds an offline observation (its
          // evidence_ref is required functionally downstream — a guard leaf without it is
          // offline-refused by runPathCompositionExperiment), but a cross-stack BIND leaf has
          // no offline observation (it binds already-executed signed rows), so requiring
          // evidence_ref at the schema would reject every bind leaf before the handler runs.
          // additionalProperties stays at its default false, so a genuinely-unknown key is
          // still rejected now that all five run-ref fields are declared.
          required: [],
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
  required_session_axes: ["url"],
});
