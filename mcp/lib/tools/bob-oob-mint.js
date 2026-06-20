"use strict";

const {
  oobMint,
  ORACLE_KIND_VALUES,
  OOB_METHODS,
} = require("../oob-collector.js");

module.exports = Object.freeze({
  name: "bob_oob_mint",
  description:
    "OOB (out-of-band) token ALLOCATOR for blind-vuln discovery (PR6) — the NON-signing half of the OOB collector. It mints a high-entropy token bound to a CONSTANT, server-owned OOB host and returns the benign, token-only payload forms (payload_dns = token.<host>, payload_http = https://<host>/<token>) for you to inject into the TARGET via a target-facing tool (e.g. an SSRF/SSTI/blind-injection sink). It resolves the IN-SCOPE injection endpoint server-side from surface_id + path_template (NEVER the OOB host) and writes an audit-graded token->surface binding; bob_oob_poll later reads that binding to stamp the signed proof. This tool NEVER fires a request at the target and NEVER signs a row. " +
    "INERT-UNTIL-PROVISIONED: when the OOB sink is not configured in the MCP launch env (BOB_OOB_HOST / BOB_OOB_POLL_URL), mint returns blocked_by_infra:oob_sink_not_configured and writes nothing — the tool ships dormant and activates only on operator provisioning. " +
    "INTEGRITY BOUNDARY (honest, NOT closed here): proof is minted by bob_oob_poll, not this tool. The eventual row MAC is TAMPER-EVIDENT against an agent confined to the MCP + guarded-Bash surface; it is NOT cryptographically un-forgeable — a same-UID agent running arbitrary in-process code (a node -e that reads the 0600 signing key) can forge a row, the SAME assumption Bob's wave-handoff signing makes. PR6 also adds an AGENT SELF-HIT arm: the token is returned to you by design, so on the wide-open net it can be self-fetched to fabricate a callback (bounded to a MEDIUM in-scope finding). Both close only with the deferred offensive-SANDBOX (UID/network-separation) PR; do NOT advertise un-fakeability. " +
    "LOCUS SAFETY: the OOB host is server-constant (never a tool arg), the token is server-minted, and the bound proof target is the in-scope endpoint resolved from surface_id + path_template — no host, token, payload, or sink URL is accepted.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      surface_id: { type: "string" },
      oracle_kind: { type: "string", enum: [...ORACLE_KIND_VALUES] },
      method: {
        type: "string",
        enum: [...OOB_METHODS],
        description: "Optional method LABEL for the proof (default GET). mint/poll never fire a request at the target, so this only labels the signed row's command_hash.",
      },
    },
    required: ["target_domain", "surface_id", "oracle_kind"],
    additionalProperties: false,
  },
  handler: oobMint,
  // Narrow on purpose: granted ONLY to the web evaluator, never to
  // read-only/verifier/evidence roles (mirrors the other offensive producers).
  // check:authority-inventory asserts the narrow grant.
  role_bundles: ["evaluator-web"],
  // Writes the audit-graded oob-tokens.jsonl binding (a durable session-state
  // mutation), so mutating:true. It issues NO network request of its own.
  mutating: true,
  global_preapproval: false,
  // Stateless allocator: NO network. The single OOB egress point is bob_oob_poll.
  network_access: false,
  browser_access: false,
  scope_required: true,
  // The returned token is a Bob nonce returned BY DESIGN so the agent can inject
  // it — not target-sensitive, so sensitive_output:false.
  sensitive_output: false,
  session_artifacts_written: ["oob-tokens.jsonl"],
});
