"use strict";

const {
  corsConfirm,
} = require("../offensive-cors-producer.js");

module.exports = Object.freeze({
  name: "bob_http_cors_confirm",
  description:
    "CORS-misconfiguration signed-row PRODUCER (in-process, live). It PROVES that a routed in-scope endpoint PERMITS credentialed cross-origin reads from an ARBITRARY origin (Access-Control-Allow-Origin reflects the request Origin + Access-Control-Allow-Credentials: true on a 2xx response) — the cross-origin-read misconfiguration. It server-mints TWO distinct, structurally-dissimilar unguessable origins (different reserved TLD + label, e.g. https://bob-cors-<32hex>.example and https://<32hex>-bobcanary.test, so a single-suffix/prefix allowlist cannot match both), sends a GET probe carrying each as the Origin header ALONG WITH the browser cross-origin fetch metadata (Sec-Fetch-Site: cross-site / -Mode: cors / -Dest: empty, a faithful emulation of a credentialed cross-site fetch), and mints a signed offensive-runs row ONLY when BOTH responses are a browser-readable 2xx, echo their OWN distinct origin in Access-Control-Allow-Origin, AND set Access-Control-Allow-Credentials: true. A server cannot guess two unguessable origins, so echoing each is a SOUND deterministic witness of arbitrary-origin reflection (the reflected-canary soundness class; NOT the server-noise trap). A wildcard '*' ACAO, a static ACAO, no reflection, or reflection without credentials writes NOTHING. demonstrated_severity is a HARD MEDIUM by construction: the misconfiguration is proven; the full cross-origin data-theft impact is additionally gated on the endpoint returning sensitive data AND the session cookie being cross-site-sendable (SameSite=None / unset) — state those gates in the report, they are not signed. " +
    "INTEGRITY BOUNDARY (honest, NOT closed here): the row MAC is TAMPER-EVIDENT against an agent confined to the MCP + guarded-Bash surface but is NOT cryptographically un-forgeable by a same-UID in-process actor — the SAME assumption Bob's wave-handoff signing makes; full un-forgeability requires the deferred offensive-SANDBOX (UID/container) work, tracked in #131. Do NOT advertise un-fakeability. Blast radius is bounded to a fabricated MEDIUM by the frozen per-tool ceiling. " +
    "EGRESS RESIDUAL: block_internal_hosts defaults OFF (the producer refuses proxy-backed egress while it is on). INPUT SAFETY: no URL, origin, header value, marker, severity, or finding id is accepted — the probe endpoint is server-derived from a RECORDED endpoint of the routed surface, the two Origin markers are server-minted, and the endpoint is re-validated for scope + read-only path before any probe. v1 SCOPE: single recorded in-scope endpoint, GET-only; signs only the CREDENTIALED (ACAC:true) reflected-origin case.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      surface_id: { type: "string" },
    },
    required: ["target_domain", "surface_id"],
    additionalProperties: false,
  },
  handler: corsConfirm,
  // Narrow on purpose: this signed-row producer is granted ONLY to the web evaluator, never
  // to read-only/verifier/evidence roles (mirrors bob_http_idor_confirm / bob_http_xss_reflect).
  // check:authority-inventory asserts the narrow grant.
  role_bundles: ["evaluator-web"],
  // It writes the AUDIT-GRADED offensive-runs.jsonl ledger + captures (a durable session-state
  // mutation), so mutating:true — matching its siblings. It remains GET-only and read-only
  // against the TARGET (it sends only a benign Origin header; no target state changes); the
  // session-artifact writes are declared in session_artifacts_written.
  mutating: true,
  // No global blanket pre-approval: it fires LIVE requests and writes durable signed proof, so
  // it is granted only via the evaluator-web role bundle (the same posture as
  // bob_http_idor_confirm / bob_http_xss_reflect).
  global_preapproval: false,
  network_access: true,
  browser_access: false,
  scope_required: true,
  sensitive_output: true,
 session_artifacts_written: ["offensive-runs.jsonl", "offensive-runs/", "http-audit.jsonl"],
  required_session_axes: ["url"],
});
