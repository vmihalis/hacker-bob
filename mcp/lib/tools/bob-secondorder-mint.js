"use strict";

const {
  secondorderMint,
  ORACLE_KIND_VALUES,
  SECONDORDER_METHODS,
} = require("../offensive-secondorder-producer.js");

module.exports = Object.freeze({
  name: "bob_secondorder_mint",
  description:
    "SECOND-ORDER / stored-effect canary ALLOCATOR — the NON-signing half of the second-order re-read producer (mirrors bob_oob_mint's mint/reread split). It server-mints a high-entropy 256-bit canary plus a DISTINCT silent DECOY canary, binds an in-scope INJECTION endpoint and a DISTINCT in-scope OBSERVATION endpoint resolved from surface_id by endpoint locus (single-host guarded), and writes the audit-graded canary->surface binding. It returns ONLY the benign canary_payload for you to inject into the TARGET's injection endpoint via a target-facing tool; the DECOY is server-secret and is NEVER returned (it must stay silent to serve as the un-injectable negative control). This tool NEVER fires a request at the target and NEVER signs a row — bob_secondorder_reread re-reads the bound observation endpoint (a channel Bob controls, safeFetch) and signs the proof. " +
    "INTEGRITY BOUNDARY (honest, NOT closed here; the SAME assumption Bob's wave-handoff signing and the other offensive producers make): proof is minted by bob_secondorder_reread, not this tool. The eventual row MAC is TAMPER-EVIDENT against an agent confined to the MCP + guarded-Bash surface; it is NOT cryptographically un-forgeable — a same-UID agent running arbitrary in-process code (a node -e that reads the 0600 signing key) can forge a row. Closed only by the deferred offensive-SANDBOX (UID/network-separation) work; do NOT advertise un-fakeability. " +
    "LOCUS SAFETY: the canary + decoy are server-minted, the bound endpoints are the surface's OWN in-scope endpoints resolved from surface_id by integer locus — no host, token, canary, decoy, payload, endpoint, or severity is accepted (additionalProperties:false plus a forbidden-extras allowlist).",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      surface_id: { type: "string" },
      oracle_kind: { type: "string", enum: [...ORACLE_KIND_VALUES] },
      method: {
        type: "string",
        enum: [...SECONDORDER_METHODS],
        description: "Optional read-only method LABEL for the re-read (default GET). The re-read never mutates; GET/HEAD only.",
      },
      injection_locus: {
        type: "integer",
        minimum: 0,
        description: "Optional non-negative integer index (default 0) into the surface's server-recorded endpoint list selecting the INJECTION endpoint. A server-bounded selector, NOT a raw URL. Must resolve DISTINCT from observation_locus.",
      },
      observation_locus: {
        type: "integer",
        minimum: 0,
        description: "Optional non-negative integer index (default 1) into the surface's server-recorded endpoint list selecting the DISTINCT OBSERVATION endpoint Bob re-reads. A server-bounded selector, NOT a raw URL.",
      },
    },
    required: ["target_domain", "surface_id", "oracle_kind"],
    additionalProperties: false,
  },
  handler: secondorderMint,
  // Narrow on purpose: granted ONLY to the web evaluator, never to
  // read-only/verifier/evidence roles (mirrors the other offensive producers).
  // check:authority-inventory asserts the narrow grant.
  role_bundles: ["evaluator-web"],
  // Writes the audit-graded secondorder-tokens.jsonl binding (a durable session-state
  // mutation), so mutating:true. It issues NO network request of its own.
  mutating: true,
  global_preapproval: false,
  // Stateless allocator: NO network. The single re-read egress is bob_secondorder_reread.
  network_access: false,
  browser_access: false,
  scope_required: true,
  // The returned canary is a Bob nonce returned BY DESIGN so the agent can inject
  // it — not target-sensitive, so sensitive_output:false.
  sensitive_output: false,
  session_artifacts_written: ["secondorder-tokens.jsonl"],
});
