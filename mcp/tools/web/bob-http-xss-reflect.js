"use strict";

const {
  reflectXss,
  ORACLE_KIND_VALUES,
} = require("../../domains/web/offensive-reflect-producer.js");

module.exports = Object.freeze({
  name: "bob_http_xss_reflect",
  description:
    "Reflected-canary XSS FINDER (find-axis MVP) — the FIRST attack-to-FIND signed-row PRODUCER. It DISCOVERS a previously-unknown reflected-injection sink by attacking with a benign, inert payload: it server-mints a high-entropy nonce + the inert metachar sentinel '\"<> (never a working payload), then runs a CONTROL fetch (nonce only, locates the sink + content-type) and a PROBE fetch (nonce + sentinel, bounded by a random end-marker) GET-only against ONE recorded query param of the routed surface. A signed offensive-runs row is minted ONLY when the raw metacharacters survive UNESCAPED into an HTML-EXECUTABLE context (a text node or an unquoted-attribute / tag-break) on a text/html response, proven by a conservative, fail-closed, context-aware classifier (a mini HTML tokenizer; NEVER a substring/adjacency check); every encoded / escaped / quoted-attribute / JS-string / comment / CDATA / non-HTML / WAF / no-reflection case writes nothing. demonstrated_severity is a HARD MEDIUM by construction (reflection-context survival, NOT proven script execution; the browser-execution confirm that proves HIGH is a deferred follow-up). " +
    "INTEGRITY BOUNDARY (honest, NOT closed here): this MVP is the FIRST production tool that writes LIVE signed exploited_safely rows, so the #108 in-process-key boundary becomes load-bearing for the first time. The row MAC is TAMPER-EVIDENT against an agent confined to the MCP + guarded-Bash surface; it is NOT cryptographically un-forgeable — a same-UID agent running arbitrary in-process code (a node -e that reads the 0600 signing key and hand-MACs a row) can forge a row around the gates, the SAME assumption Bob's wave-handoff signing makes. Absolute un-fakeability requires the deferred offensive-SANDBOX (UID/container) PR; blast radius is bounded to a fabricated MEDIUM by the frozen per-tool ceiling. " +
    "EGRESS RESIDUAL: block_internal_hosts defaults OFF (the producer refuses proxy-backed egress while it is on). LOCUS SAFETY: no URL, param name, value, nonce, sentinel, severity, or finding id is accepted — the injection param is server-derived from a RECORDED query param of the surface (param_locus is only an ordinal selector), the canary value is server-minted, and the FINAL injected URL is re-validated for scope + read-only path/query before any probe. v1 SCOPE: single-host single recorded query-bearing endpoint, GET-only, text/html only (MIME-sniff deferred).",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      surface_id: { type: "string" },
      param_locus: {
        type: "string",
        description: "A non-negative integer ordinal (e.g. \"0\") selecting WHICH of the routed surface's deterministically-sorted RECORDED query params to test. It is a selector only — never a raw URL, param name, or value. The param name is server-derived from the surface record and the injected canary value is server-minted.",
      },
      oracle_kind: { type: "string", enum: [...ORACLE_KIND_VALUES] },
    },
    required: ["target_domain", "surface_id", "param_locus", "oracle_kind"],
    additionalProperties: false,
  },
  handler: reflectXss,
  // Narrow on purpose: this signed-row producer is granted ONLY to the web
  // evaluator, never to read-only/verifier/evidence roles (mirrors
  // bob_http_idor_confirm). check:authority-inventory asserts the narrow grant.
  role_bundles: ["evaluator-web"],
  // It writes the AUDIT-GRADED offensive-runs.jsonl ledger + captures (a durable
  // session-state mutation), so mutating:true — matching its siblings
  // bob_http_idor_confirm / bob_http_confirm. It remains GET-only and read-only
  // against the TARGET (it injects only a benign inert canary; no target state
  // changes); the session-artifact writes are declared in session_artifacts_written.
  mutating: true,
  // No global blanket pre-approval: it fires LIVE requests and writes durable
  // signed proof, so it is granted only via the evaluator-web role bundle (the
  // same posture as bob_http_idor_confirm; do NOT copy bob_http_confirm's
  // global_preapproval:true).
  global_preapproval: false,
  network_access: true,
  browser_access: false,
  scope_required: true,
  sensitive_output: true,
 session_artifacts_written: ["offensive-runs.jsonl", "offensive-runs/", "http-audit.jsonl"],
  required_session_axes: ["url"],
});
