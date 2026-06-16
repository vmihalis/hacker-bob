"use strict";

const {
  idorConfirm,
  ORACLE_KIND_VALUES,
  READ_ONLY_METHODS,
} = require("../offensive-idor-producer.js");
const { REPLAY_CONTEXT_SCHEMA } = require("./replay-context-schema.js");

module.exports = Object.freeze({
  name: "bob_http_idor_confirm",
  description:
    "Second-test-identity IDOR signed-row PRODUCER. Provisions a producer-created synthetic object per identity, writes a 256-bit crypto canary into identity B's own object, and proves identity A (a different tenant) reads B's object across the tenant boundary by observing B's exact canary at the same parsed leaf field (never a substring, never whole-body equality). A signed offensive-runs row is minted ONLY when ALL mint conditions hold (7-probe P0-P6 differential: P4/P4-id auth-challenged, P5 a true cross-tenant deny, P6 directional partition, own-scope private, tenant discriminator differs, no shared-cache signal, canary survives a fresh URL, synthetic-only bytes); any miss writes nothing. demonstrated_severity is a HARD MEDIUM by construction (the leaked bytes are attacker-owned synthetic objects). " +
    "INTEGRITY BOUNDARY (honest, NOT closed here): the row MAC defends against an agent confined to the MCP + guarded-Bash surface; it does NOT defend against an agent running arbitrary in-process code (a same-UID node -e that reads the 0600 signing key and hand-MACs a row) — absolute un-fakeability requires the deferred offensive-SANDBOX (UID/container) PR, the same assumption Bob's wave-handoff signing makes. " +
    "v1 SCOPE: direct path-segment-id resource reads only ({id} must terminate the path), single-endpoint single-host surfaces only; AC-2 binds path_template (and thus row.target) to the surface's RECORDED endpoint via resolveBaselineFromSurface — an off-route template is rejected before any probe — and #111 ties the signed proof to the claimed surface_id. No URL, body, headers, severity, object id, tenant, or canary are accepted as input — every value is server-derived from surface_id + path_template + the producer's own create/readback.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      surface_id: { type: "string" },
      oracle_kind: { type: "string", enum: [...ORACLE_KIND_VALUES] },
      path_template: {
        type: "string",
        description: "Absolute path template under the routed surface's single recorded endpoint origin, containing exactly one server-substituted {id} path slot that must terminate the final path segment, for example /api/accounts/{id}. No URL, finding_id, request body, object id, severity, tenant, canary, or arbitrary headers are accepted.",
      },
      method: { type: "string", enum: [...READ_ONLY_METHODS] },
      identity_a_profile: { type: "string" },
      identity_b_profile: { type: "string" },
      identity_c_profile: { type: "string" },
      // A verifier/evidence agent passes its replay_context during VERIFY so the
      // tool's live probes are governed by the same replay lease as bob_http_scan.
      replay_context: REPLAY_CONTEXT_SCHEMA,
    },
    required: [
      "target_domain",
      "surface_id",
      "oracle_kind",
      "path_template",
      "method",
      "identity_a_profile",
      "identity_b_profile",
      "identity_c_profile",
    ],
    additionalProperties: false,
  },
  handler: idorConfirm,
  // Narrow on purpose: check:authority-inventory asserts no read-only/verifier/
  // evidence role inherits this signed-row producer. DO NOT widen to the
  // ["verifier","evaluator-web","evidence"] set bob_http_confirm uses.
  role_bundles: ["evaluator-web"],
  // Mints un-fakeable proof AND CREATEs objects, so the per-call operator prompt
  // is defensible. DO NOT copy bob_http_confirm's global_preapproval:true.
  global_preapproval: false,
  mutating: true,
  network_access: true,
  browser_access: false,
  scope_required: true,
  sensitive_output: true,
  session_artifacts_written: ["offensive-runs.jsonl", "offensive-runs/", "http-audit.jsonl"],
});
