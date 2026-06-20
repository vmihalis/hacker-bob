"use strict";

const {
  confirmXssExecution,
  ORACLE_KIND_VALUES,
} = require("../offensive-xss-exec-producer.js");

module.exports = Object.freeze({
  name: "bob_http_xss_confirm",
  description:
    "Browser-EXECUTION reflected-XSS CONFIRM (the FIRST HIGH-ceiling signed-row PRODUCER). It proves a reflected injection actually EXECUTES as script in a real browser engine — lifting a reflected-XSS finding from reflection-context survival (the MEDIUM bob_http_xss_reflect proves) to proven script execution (HIGH). It server-mints a high-entropy nonce and drives Bob's OWN headless browser through two GET navigations against ONE recorded query param of the routed surface: a CONTROL (inert nonce text — the nonce-keyed window marker must be ABSENT) and a PROBE (a benign, NETWORK-FREE executing payload \"><svg onload=…> whose only effect, IF it runs, is to set that nonce-keyed global to the nonce string). A signed offensive-runs row is minted ONLY on the deterministic differential: marker ABSENT on the control page AND marker === the server-minted nonce on the probe page (proven execution). Every other outcome (marker absent on the probe → escaped / encoded / sanitized / non-executable context / CSP-blocked, WAF, navigation error, no browser) writes nothing. demonstrated_severity is a HARD HIGH by construction. " +
    "INTEGRITY BOUNDARY (honest, NOT closed here): this is the FIRST tool that signs a HIGH offensive-runs row, so the #108 in-process-key boundary is now load-bearing at HIGH. The row MAC is TAMPER-EVIDENT against an agent confined to the MCP + guarded-Bash surface; it is NOT cryptographically un-forgeable — a same-UID agent running arbitrary in-process code (a node -e that reads the 0600 signing key and hand-MACs a row) can forge a row around the gates, the SAME assumption Bob's wave-handoff signing makes. A HIGH ceiling raises the residual blast radius from a fabricated MEDIUM (reflect) to a fabricated HIGH. Absolute un-fakeability requires the deferred offensive-SANDBOX (UID/container) PR; do NOT advertise un-fakeability. " +
    "ARCHITECTURE: drives the established bob_browser_* subsystem (subprocess-backed) — not the pure-safeFetch reflect path. SSRF RESIDUAL: the headless driver navigates with blockInternalHosts:false, so this producer REFUSES to run when the session's block_internal_hosts policy is on (fails closed). LOCUS SAFETY: no URL, param name, value, nonce, payload, severity, or finding id is accepted — the injection param is server-derived from a RECORDED query param (param_locus is only an ordinal selector), the canary value is server-minted, and the FINAL injected URL is re-validated for scope + read-only path/query before any navigation. v1 SCOPE: single-host single recorded query-bearing endpoint, GET-only. v1 CONTEXT COVERAGE: the executing probe breaks out of text-node, double-quoted-attribute, and unquoted-attribute contexts; a parameter reflected inside a SINGLE-quoted attribute (e.g. value='REFLECTED') returns blocked_by_defense/script_did_not_execute even when the endpoint is genuinely exploitable via that context — do NOT mark the surface closed on that result alone (it is a v1 false negative, not proof the sink is safe).",
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
  handler: confirmXssExecution,
  // Narrow on purpose: this signed-row producer is granted ONLY to the web
  // evaluator, never to read-only/verifier/evidence roles (mirrors
  // bob_http_xss_reflect / bob_http_idor_confirm). check:authority-inventory
  // asserts the narrow grant.
  role_bundles: ["evaluator-web"],
  // It writes the AUDIT-GRADED offensive-runs.jsonl ledger + captures (a durable
  // session-state mutation), so mutating:true. It remains GET-only and read-only
  // against the TARGET (it injects only a benign, network-free executing marker
  // into Bob's own headless browser; no target state changes).
  mutating: true,
  // No global blanket pre-approval: it fires LIVE navigations and writes durable
  // signed HIGH proof, so it is granted only via the evaluator-web role bundle.
  global_preapproval: false,
  network_access: true,
  // browser_access:true is a truthful capability CLASSIFICATION (the handler drives
  // a real browser session); it does NOT grant reachability — role_bundles does.
  browser_access: true,
  scope_required: true,
  sensitive_output: true,
  session_artifacts_written: ["offensive-runs.jsonl", "offensive-runs/", "http-audit.jsonl"],
});
