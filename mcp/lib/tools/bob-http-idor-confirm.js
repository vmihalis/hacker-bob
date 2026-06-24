"use strict";

const {
  idorConfirm,
  ORACLE_KIND_VALUES,
  READ_ONLY_METHODS,
} = require("../offensive-idor-producer.js");

module.exports = Object.freeze({
  name: "bob_http_idor_confirm",
  description:
    "OPERATOR-ARMED LIVE ARM: live object-creation (a WRITE to the target) is INERT unless the operator sets env BOB_IDOR_PROVISION_AUTHORIZED=<target_domain> (target-bound, never a bare 1); unarmed, every call returns blocked_by_design WITHOUT contacting the target. global_preapproval:false means each call also requires per-call operator approval. " +
    "Second-test-identity IDOR signed-row PRODUCER. When armed, it PROVISIONS a synthetic object per identity (POST to the create endpoint DERIVED from path_template by dropping the trailing /{id} — structurally on-route, no off-route write), writes a 256-bit crypto canary into each object, captures the server-minted ids, and proves identity A (a different tenant) reads B's object across the tenant boundary by observing B's exact canary at the same parsed leaf field (never a substring, never whole-body equality). A signed offensive-runs row is minted ONLY when ALL mint conditions hold (P0-P8 differential: P4/P4-id auth-challenged, P5 a true cross-tenant deny, P6 directional partition, P7/P8 prove C authenticates, own-scope private, no shared-cache signal, canary survives a fresh URL, synthetic-only bytes); any miss writes nothing. demonstrated_severity has a MEDIUM ceiling by construction (the leaked bytes are attacker-owned synthetic objects) and DOWNSHIFTS to LOW via confidence_signals when cross-tenant attribution is unprovable from the bodies (own-scope key absent / no comparable tenant discriminator — cap-not-kill, never inflated). " +
    "INTEGRITY BOUNDARY (honest, NOT closed here): the row MAC defends against an agent confined to the MCP + guarded-Bash surface; it does NOT defend against an agent running arbitrary in-process code (a same-UID node -e that reads the 0600 signing key and hand-MACs a row) — absolute un-fakeability requires the deferred offensive-SANDBOX (UID/container) PR, the same assumption Bob's wave-handoff signing makes. " +
    "v1 SCOPE: direct path-segment-id resource reads only ({id} must terminate the path), single-endpoint single-host surfaces only; AC-2 binds path_template (and thus row.target) to the surface's RECORDED endpoint via resolveBaselineFromSurface — an off-route template is rejected before any probe — and #111 ties the signed proof to the claimed surface_id. The object id, tenant, and canary VALUE are NEVER accepted as input (server-minted/captured); only the create-CONTRACT metadata (canary_field / id_field / a PII-screened synthetic create_body skeleton) is, and the create_body is screened for operator PII before any write.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      surface_id: { type: "string" },
      oracle_kind: { type: "string", enum: [...ORACLE_KIND_VALUES] },
      path_template: {
        type: "string",
        description: "Absolute path template under the routed surface's single recorded endpoint origin, containing exactly one server-substituted {id} path slot that must terminate the final path segment, for example /api/accounts/{id}. The create endpoint is derived by dropping the trailing /{id}. No URL, finding_id, object id, severity, tenant, or canary VALUE is accepted.",
      },
      method: { type: "string", enum: [...READ_ONLY_METHODS] },
      identity_a_profile: { type: "string" },
      identity_b_profile: { type: "string" },
      identity_c_profile: { type: "string" },
      canary_field: {
        type: "string",
        description: "The object field NAME the producer writes its server-minted 256-bit canary into at create time (e.g. \"note\"). A field NAME only — never the canary VALUE (server-minted).",
      },
      id_field: {
        type: "string",
        description: "The field in the create response that carries the server-minted object id (default \"id\").",
      },
      create_body: {
        type: "object",
        description: "Optional SYNTHETIC create-body skeleton for any required non-canary fields (no PII — screened before any write); the producer always overrides canary_field with its own minted canary.",
      },
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
  // The live arm requires per-call operator approval (it mints proof AND CREATEs objects):
  // global_preapproval:false keeps it off the auto-approve list. DO NOT copy
  // bob_http_confirm's global_preapproval:true.
  //
  // OPERATOR CHECKPOINT (PR-D, the live arm): the MCP dispatcher calls idorConfirm(args) with NO
  // `provision`. The handler self-provisions live ONLY when the operator has ARMED this target
  // (env BOB_IDOR_PROVISION_AUTHORIZED === target_domain, target-bound); otherwise it returns
  // blocked_by_design:object_not_self_provisioned BEFORE any network/signing — DEFAULT-OFF dormancy.
  // The create POSTs are the only writes; they are scope-validated + audited. Two independent gates
  // (per-call approval AND the target-bound arming env) must both hold for a live write — and the
  // #18 provenance gate still requires all three identities to be synthetic Bob-minted accounts.
  global_preapproval: false,
  mutating: true,
  network_access: true,
  browser_access: false,
  scope_required: true,
  sensitive_output: true,
  session_artifacts_written: ["offensive-runs.jsonl", "offensive-runs/", "http-audit.jsonl"],
});
