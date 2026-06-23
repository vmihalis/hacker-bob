"use strict";

const {
  massreadConfirm,
} = require("../offensive-massread-producer.js");

module.exports = Object.freeze({
  name: "bob_http_massread_confirm",
  description:
    "Broken-authorization / BFLA MASS-READ signed-row PRODUCER (browser transport, live). It PROVES that an UNDER-AUTHORIZED caller can bulk-read a sensitive collection it should not, by an attacker-vs-control DIFFERENTIAL through the real-Chrome authed_fetch transport (which beats Cloudflare's bare-Node 403): (1) an ATTACKER arm carrying the under-authorized identity's cookies — read SERVER-SIDE from a stored auth profile, injected over stdin, never the env, never an agent — and (2) a fresh UNCREDENTIALED CONTROL arm. From each response it derives a MASKED summary in memory (record_count + the SET of known-sensitive field-name buckets present + PII value-shape booleans), then DISCARDS the raw body. It mints a signed offensive-runs row ONLY on the differential: attacker 2xx with record_count >= 2 AND >= 1 sensitive field present, AND the control DENIED (401/403, or a 2xx with 0 records / no sensitive shapes). A control that ALSO reads the bulk collection is a PUBLIC endpoint, not an authorization break, and writes NOTHING. demonstrated_severity is a HARD HIGH by construction, stamped from the registry (NEVER agent-supplied): the producer proves the bulk-read IMPACT; the underlying vuln (hardcoded/guessable credential, missing object/function-level authz) is the finding. " +
    "WITNESS / PII: the SIGNED rail carries ONLY the masked summary (counts + field-name buckets + booleans + differential statuses), screened by sensitiveShapesPresent and fail-closed — it NEVER carries raw PII (the same tool runs against third-party bug-bounty targets where harvesting strangers' data is forbidden). A FULL raw capture is written ONLY under the operator env gate BOB_MASSREAD_OWNER_AUTHORIZED=1, to a session-local massread-evidence/ file OUTSIDE the signed rail that the operator deletes after the engagement — it is NOT an agent argument, so the agent can never enable PII capture. " +
    "ARCHITECTURE: drives the established bob_browser_* subsystem + the trusted authed_fetch command (cookie auth only; authed_fetch REJECTS Authorization/Cookie headers). SSRF RESIDUAL: the headless driver navigates with blockInternalHosts:false, so this producer REFUSES to run when the session's block_internal_hosts policy is on (fails closed). INPUT SAFETY: no URL, endpoint, cookie/token/credential, header, body, record, severity, or owner_authorized flag is accepted — the listing endpoint is server-derived from the routed surface, the attacker cookies are read server-side from the named profile, and the endpoint is re-validated for scope + read-only path before any read. v1 SCOPE: single recorded in-scope endpoint, GET-only, COOKIE-expressible identity (POST-body listing and bearer-token identities are the documented v2). OPERATOR CONTRACT: auth_profile must carry the LEAKED / UNDER-PRIVILEGED / guessable credential — a fully-authorized credential is operator misuse → false positive; the authed-vs-UNAUTHENTICATED differential proves only that a credentialed caller bulk-reads PII an unauthenticated client is denied, NOT that the credential is under-privileged (true cross-tenant BFLA, with a second AUTHENTICATED victim identity denied while the attacker reads its data, is the v2 oracle). INTEGRITY BOUNDARY (honest, NOT closed here): the row MAC is tamper-evident against an MCP/guarded-Bash-confined agent but NOT cryptographically un-forgeable by a same-UID actor (the #131 boundary, bounded to a fabricated HIGH by the frozen ceiling); the authed-vs-control differential is target-distinguishable, so a single capture is evidence, not proof — the operator corroborates for integrity-sensitive use.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      surface_id: { type: "string" },
      // Optional SELECTOR naming a stored auth profile (a registry handle, NOT raw credential
      // material — the cookie values are read server-side). Defaults to "attacker".
      auth_profile: { type: "string" },
    },
    required: ["target_domain", "surface_id"],
    additionalProperties: false,
  },
  handler: massreadConfirm,
  // Narrow on purpose: this signed-row producer is granted ONLY to the web evaluator, never to
  // read-only/verifier/evidence roles (mirrors bob_http_idor_confirm / bob_http_xss_confirm).
  // check:authority-inventory asserts the narrow grant.
  role_bundles: ["evaluator-web"],
  // It writes the AUDIT-GRADED offensive-runs.jsonl ledger + (opt-in) the massread-evidence capture
  // — durable session-state mutations — so mutating:true. It remains GET-only and read-only against
  // the TARGET (it only reads a listing endpoint); the writes are declared in session_artifacts_written.
  mutating: true,
  // No global blanket pre-approval: it fires LIVE credentialed reads and writes durable signed proof,
  // so it is granted only via the evaluator-web role bundle.
  global_preapproval: false,
  network_access: true,
  // browser_access:true is a truthful capability CLASSIFICATION (the handler drives a real browser
  // session via the authed_fetch transport); it does NOT grant reachability — role_bundles does.
  browser_access: true,
  scope_required: true,
  sensitive_output: true,
  session_artifacts_written: ["offensive-runs.jsonl", "offensive-runs/", "http-audit.jsonl", "massread-evidence/"],
});
