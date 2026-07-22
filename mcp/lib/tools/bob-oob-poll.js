"use strict";

const {
  oobPoll,
} = require("../oob-collector.js");

module.exports = Object.freeze({
  name: "bob_oob_poll",
  description:
    "OOB (out-of-band) interaction CONFIRM (PR6) — the SIGNING half of the OOB collector and a MEDIUM-ceiling signed-row PRODUCER. Given a token_handle from bob_oob_mint, it polls Bob's OWN sink for an interaction carrying the EXACT minted token. A hit proves the TARGET backend made a server-side outbound request to Bob's sink = blind SSRF / SSTI / RCE-callback reachability — a SOUND positive (a server that never saw the unguessable 128-bit nonce cannot fabricate it; the agent only READS the poll API, never writes the sink). On a hit it mints a signed offensive-runs row whose target is the IN-SCOPE injection endpoint bound at mint (NEVER the OOB host); an empty poll, a non-minted token, or sink noise writes NOTHING (the never-sign-noise discipline). A second poll of the same hit is idempotent (returns the already-signed run_id, no second row). " +
    "SEVERITY: demonstrated_severity is a HARD MEDIUM by construction — an OOB hit proves server-side egress reachability, NOT data exfiltration, internal-network reach, or command output (\"SSRF-to-OOB = limited confidentiality, not RCE\"). Even an RCE-suspected DNS callback caps at MEDIUM (a callback fired; retrievable output was not shown). " +
    "HONEST CLAIM + RESIDUALS (stated, NOT advertised away): (1) INTERMEDIARY ATTRIBUTION — an unfurler / proxy / SIEM-scanner in the target's request path that fetches the token also satisfies the oracle, so the demonstrated claim is \"server-side egress reachability triggered by the injection, NOT isolated to the bound surface\"; the RCE/internal-reach upside belongs only in the inferred impact_potential narrative, never in demonstrated_severity. (2) AGENT SELF-HIT — the token is held by the agent by design, so on the wide-open net a self-fetch can fabricate a callback this tool would sign (NORMAL network capability, STRICTLY WEAKER than the in-process key-read; bounded to MEDIUM-in-scope; partial HTTP-only same-egress-IP withhold). (3) TRUSTED REPORTER — the gate never inspects capture content, so a compromised/buggy sink that fabricates a token-matched interaction induces a false signed row. (4) IN-PROCESS-KEY (#108) — a same-UID node -e can read the 0600 signing key and hand-MAC a row, the SAME assumption wave-handoff signing makes. All close only with the deferred offensive-SANDBOX (UID/network-separation) PR; do NOT advertise un-fakeability. " +
    "AIM-EXEMPTION + INERT: poll fetches the constant Bob-owned sink directly (no targetDomain so the first-party scope check is skipped) but with blockInternalHosts:true + followRedirects:false + NO session egress proxy. When the sink is not configured in the MCP launch env (BOB_OOB_HOST / BOB_OOB_POLL_URL), it returns blocked_by_infra and signs nothing (ships dormant). LOCUS SAFETY: accepts ONLY target_domain + token_handle + an expect arm selector — no surface_id, URL, host, token value, or severity; the surface + in-scope target are read from the mint binding (the tightest anti-retarget shape). The expect=silence CONTROL arm signs a blocked_by_defense decoy-silent row (a token the agent did not inject, confirmed silent against a reachable sink) so an OOB finding earns a finding-differential verified_pass (a real flip: injected-and-fired positive vs decoy-silent control) instead of capping to advisory on a single uncontrolled callback. The control closes the ambient-noise/promiscuous-sink false positive; the intermediary-attribution residual above is unchanged.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      token_handle: {
        type: "string",
        description: "The opaque handle returned by bob_oob_mint. The token value, OOB host, surface_id, and in-scope target are all resolved server-side from the binding — never passed here.",
      },
      expect: {
        type: "string",
        enum: ["interaction", "silence"],
        description: "Arm selector (default \"interaction\"). \"interaction\" requires a matching callback and signs the exploited_safely POSITIVE. \"silence\" is the NEGATIVE CONTROL: poll a DECOY token you did NOT inject — a reachable sink with NO interaction for it signs a blocked_by_defense control row to pair with the positive via bob_verify_finding_differential (the FLIP that lets an OOB finding earn a reportable verified_pass instead of capping to advisory). A decoy that interacted is refused (invalid control). An arm selector, NOT a target input.",
      },
    },
    required: ["target_domain", "token_handle"],
    additionalProperties: false,
  },
  handler: oobPoll,
  // Narrow on purpose: this signed-row producer is granted ONLY to the web
  // evaluator, never to read-only/verifier/evidence roles. check:authority-inventory
  // asserts the narrow grant.
  role_bundles: ["evaluator-web"],
  // Writes the audit-graded offensive-runs.jsonl ledger + captures + the
  // oob-tokens.jsonl consume record on a hit, so mutating:true.
  mutating: true,
  global_preapproval: false,
  // The one aim-exempt egress: a direct fetch to the constant Bob-owned sink.
  network_access: true,
  browser_access: false,
  scope_required: true,
  sensitive_output: true,
  // Deliberately NOT http-audit.jsonl — the sink is Bob's own host, not the target,
  // so OOB polling stays out of target telemetry / circuit-breaker accounting.
 session_artifacts_written: ["offensive-runs.jsonl", "offensive-runs/"],
  required_session_axes: ["url"],
});
