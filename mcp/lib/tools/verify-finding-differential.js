"use strict";

const { verifyFindingDifferential } = require("../finding-differential-verifier.js");

// bob_verify_finding_differential — the web-standalone sibling of
// bob_verify_repro_reproduction / bob_verify_invariant_differential. It does NOT
// re-execute (the web standalone classes have no two-tree docker model); it BINDS two
// already-executed, MAC-signed offensive-runs.jsonl rows for ONE finding_id and mints a
// verified_pass ONLY on a genuine flip (positive exploited the issue, control was
// blocked, on the SAME surface). A single declared row, a hash-identical control, or a
// non-discriminating control is REFUSED. The verdict is written only to the MCP-write-
// only, audit-graded finding-differential-verified.jsonl the grade-time gate grades on.
async function verifyFindingDifferentialToolHandler(args) {
  return verifyFindingDifferential({
    target_domain: args.target_domain,
    finding_id: args.finding_id,
    surface_id: args.surface_id,
    positive_run_ref: args.positive_run_ref,
    control_run_ref: args.control_run_ref,
  });
}

const RUN_REF_SCHEMA = Object.freeze({
  type: "object",
  properties: {
    ledger: {
      type: "string",
      enum: ["offensive_runs"],
      description: "The executed ledger the row lives in. Only offensive_runs (the MAC-signed, audit-graded HTTP run ledger) is supported.",
    },
    row_id: {
      type: "string",
      description: "The executed offensive-runs run_id (the row the runner produced).",
    },
  },
  required: ["ledger", "row_id"],
  additionalProperties: false,
});

module.exports = Object.freeze({
  name: "bob_verify_finding_differential",
  description:
    "Execution-graded finding-differential verifier for STANDALONE non-oracle findings " +
    "(auth-bypass-not-via-IDOR, manual IDOR, SSRF, business-logic, info-disclosure, races) — the " +
    "web sibling of bob_verify_repro_reproduction (native) and bob_verify_invariant_differential (FV). " +
    "It does NOT re-execute; it BINDS two already-executed, MAC-signed offensive-runs.jsonl rows for ONE " +
    "finding_id. Provide the finding's single surface_id, a positive_run_ref (an exploited_safely row that " +
    "demonstrates the issue), and a control_run_ref (the same surface's authorized/safe-variant row that must " +
    "be blocked_by_defense/blocked_by_infra). Mints a verified_pass (executed_finding_differential_flip) ONLY on " +
    "a genuine flip: the positive demonstrates the issue and the control is blocked, on the SAME surface, with " +
    "distinct executed identities. A single declared row, a hash-identical control, a non-discriminating control " +
    "(same outcome), or a cross-surface row is REFUSED. verified_pass is written only to the MCP-write-only, " +
    "audit-graded finding-differential-verified.jsonl the grade-time standalone-finding gate requires.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string", description: "The in-scope session domain." },
      finding_id: { type: "string", description: "The finding the differential attests (e.g. F-2)." },
      surface_id: {
        type: "string",
        description: "The finding's single bound surface_id; BOTH rows must bind to it (#111 surface binding).",
      },
      positive_run_ref: {
        ...RUN_REF_SCHEMA,
        description: "The executed POSITIVE row: an exploited_safely offensive-runs row on the finding's surface that demonstrates the issue.",
      },
      control_run_ref: {
        ...RUN_REF_SCHEMA,
        description: "The executed CONTROL row: the SAME surface's authorized/safe-variant offensive-runs row that must be blocked (the flip).",
      },
    },
    required: ["target_domain", "finding_id", "surface_id", "positive_run_ref", "control_run_ref"],
  },
  handler: verifyFindingDifferentialToolHandler,
  // Same placement + classification as bob_verify_oracle_differential: a VERIFICATION
  // activity (binding executed rows to confirm a flip), outside evaluator-shared.
  // Minting the audit-graded finding-differential-verified.jsonl is an MCP-owned write;
  // the audit-grade blocks only the agent Write tool. scope_required: it reads in-scope
  // HTTP rows. network_access: false (binds existing rows, never fetches).
  role_bundles: ["verifier", "evidence"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: true,
  sensitive_output: true,
  session_artifacts_written: ["finding-differential-verified.jsonl"],
});
