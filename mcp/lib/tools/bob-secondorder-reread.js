"use strict";

const {
  secondorderReread,
} = require("../offensive-secondorder-producer.js");

module.exports = Object.freeze({
  name: "bob_secondorder_reread",
  description:
    "SECOND-ORDER / stored-effect re-read CONFIRM — the SIGNING half of the second-order producer and a MEDIUM-ceiling signed-row PRODUCER (mirrors bob_oob_poll's mint/reread split). Given a token_handle from bob_secondorder_mint, it RE-READS the bound in-scope OBSERVATION endpoint via safeFetch (a channel Bob controls, not the agent) and applies the exact-parsed-leaf oracle. A POSITIVE (expect:interaction) requires the EXACT server-minted canary present as a parsed LEAF value (never a substring, never whole-body equality) AND the DECOY absent — proving the surfaced value is specifically the injected canary, not an ambient echo. On a hit it mints a signed offensive-runs row whose target is the IN-SCOPE observation endpoint bound at mint (re-derived live, never a stored target); a missing canary, a surfaced decoy, an unreachable endpoint, or sink noise writes NOTHING (never-sign-noise). A second re-read of the same hit is idempotent (returns the already-signed run_id). " +
    "SEVERITY: demonstrated_severity is a HARD MEDIUM by construction (SECONDORDER_ORACLE_DEMONSTRATED_CEILING) — a stored-effect surfacing is a MEDIUM-at-most LEAD unless the effect itself is the impact. It is ALWAYS stamped server-side (requireExplicitSeverity), NEVER agent-supplied, NEVER content-derived. Because the re-read channel is Bob-controlled (safeFetch), there is no OOB agent-self-hit attribution weakness; but a single positive is NOT self-closing (oracle_kind second_order_reread is non-self-contained), so it must EARN a finding-differential verified_pass by flipping against the decoy-silent control. " +
    "CONTROL ARM: expect=silence signs a blocked_by_defense decoy-silent row — the server-minted DECOY (never returned, never injectable) confirmed ABSENT against a REACHABLE endpoint, proving the endpoint does not ambient-echo an arbitrary server-minted nonce. Pair the injected-and-surfaced positive with this control via bob_verify_finding_differential (the real flip that earns a reportable verified_pass instead of capping to advisory). " +
    "INTEGRITY BOUNDARY (honest, NOT closed here): the row MAC is TAMPER-EVIDENT against an agent confined to the MCP + guarded-Bash surface; a same-UID node -e that reads the 0600 signing key can forge a row — the SAME assumption Bob's wave-handoff signing makes, closed only by the deferred offensive-SANDBOX PR; do NOT advertise un-fakeability. LOCUS SAFETY: accepts ONLY target_domain + token_handle + an expect arm selector — no surface_id, URL, host, canary, decoy, or severity; the surface, in-scope target, canary, and decoy are all resolved server-side from the mint binding.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      token_handle: {
        type: "string",
        description: "The opaque handle returned by bob_secondorder_mint. The canary, decoy, bound endpoints, surface_id, and in-scope target are all resolved server-side from the binding — never passed here.",
      },
      expect: {
        type: "string",
        enum: ["interaction", "silence"],
        description: "Arm selector (default \"interaction\"). \"interaction\" requires the exact minted canary present at a parsed leaf + the decoy absent and signs the exploited_safely POSITIVE. \"silence\" is the NEGATIVE CONTROL: mint a SEPARATE binding you did NOT inject — a reachable endpoint with the un-injected DECOY absent signs a blocked_by_defense control row to pair with the positive via bob_verify_finding_differential (the FLIP that lets a second-order finding earn a reportable verified_pass instead of capping to advisory). A decoy that surfaced is refused (invalid control). An arm selector, NOT a target input.",
      },
    },
    required: ["target_domain", "token_handle"],
    additionalProperties: false,
  },
  handler: secondorderReread,
  // Narrow on purpose: this signed-row producer is granted ONLY to the web
  // evaluator, never to read-only/verifier/evidence roles. check:authority-inventory
  // asserts the narrow grant.
  role_bundles: ["evaluator-web"],
  // Writes the audit-graded offensive-runs.jsonl ledger + captures + the
  // secondorder-tokens.jsonl consume record on a hit, so mutating:true.
  mutating: true,
  global_preapproval: false,
  // The one egress: a scope-validated safeFetch re-read of the in-scope observation
  // endpoint bound at mint (Bob-controlled channel, never an agent self-hit).
  network_access: true,
  browser_access: false,
  scope_required: true,
  sensitive_output: true,
  session_artifacts_written: ["offensive-runs.jsonl", "offensive-runs/", "secondorder-tokens.jsonl"],
  required_session_axes: ["url"],
});
