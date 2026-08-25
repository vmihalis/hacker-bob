"use strict";

const { verifyInvariantDifferential } = require("../../core/invariant-runner.js");

// The FV-confirm gate. The two arms are already-executed invariant runs
// persisted to invariant-runs.jsonl by bob_run_invariant_for_finding: the POSITIVE
// arm is the SAME generated test run against the REAL target (the invariant must
// FAIL there → a counterexample), the CONTROL arm is that test run against a
// control tree where the invariant SHOULD hold (it must NOT fail). This tool loads
// both rows, re-validates their hash-binding exactly as the proof-bundle gate does,
// adjudicates the FLIP (reusing the OSS repro gate's verdict vocabulary), and mints
// a verdict to the MCP-write-only, audit-graded invariant-verified.jsonl keyed by
// finding_id. A bare single-run pass (no control arm) is INCONCLUSIVE by
// construction; a non-flipping pair is REFUTED. Only a real flip mints verified.
async function verifyInvariantDifferentialToolHandler(args) {
  return verifyInvariantDifferential({
    target_domain: args.target_domain,
    finding_id: args.finding_id,
    positive_run_hash: args.positive_run_hash,
    control_run_hash: args.control_run_hash,
  });
}

module.exports = Object.freeze({
  name: "bob_verify_invariant_differential",
  description:
    "REFUTING-control gate for Foundry/halmos (FV) findings — the SC sibling of " +
    "bob_verify_repro_reproduction. An FV finding asserts an invariant is VIOLATED on the " +
    "real target. This adjudicates a TWO-ARM differential over two already-executed invariant " +
    "runs (recorded by bob_run_invariant_for_finding): the POSITIVE arm runs the generated test " +
    "against the real target — the safe-assertion must FAIL (a counterexample) — and the CONTROL " +
    "arm runs the SAME test (same template/contract/function/slots/execution-context, differing " +
    "ONLY in tree_ref/checkout) against a fixed/safe control tree where the invariant must HOLD. " +
    "It re-validates each row's hash-binding, then mints a verified_pass ONLY on a genuine flip " +
    "(violated on the target, holds on the control). A bare single-run pass with no control arm is " +
    "INCONCLUSIVE; a non-flipping pair (the test also fails on the known-safe baseline → a " +
    "harness/template artifact) is REFUTED; a degraded arm (fork_blocked/forge_missing) is " +
    "INCONCLUSIVE. The verdict is written only to the MCP-write-only, audit-graded " +
    "invariant-verified.jsonl the proof-bundle invariant gate grades on; a bare passing " +
    "agent-authored test can no longer mint a verified finding.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string", description: "The session domain." },
      finding_id: { type: "string", pattern: "^F-[0-9]+$", description: "The finding the invariant attests (e.g. F-3)." },
      positive_run_hash: {
        type: "string",
        pattern: "^[0-9a-f]{64}$",
        description: "run_hash of the invariant run on the REAL target (the invariant must FAIL there → outcome test_failed).",
      },
      control_run_hash: {
        type: "string",
        pattern: "^[0-9a-f]{64}$",
        description: "run_hash of the SAME test on a control tree where the invariant must HOLD (outcome test_passed). Omitting it yields an INCONCLUSIVE verdict — there is nothing to flip against.",
      },
    },
    required: ["target_domain", "finding_id", "positive_run_hash"],
  },
  handler: verifyInvariantDifferentialToolHandler,
  // FV confirmation is a VERIFICATION activity (independent adjudication of an
  // executed flip), mirroring verify-repro-reproduction's placement. Writing the
  // audit-graded ledger is an MCP-owned write; the audit-grade blocks only the
  // agent Write tool.
  role_bundles: ["verifier", "evidence"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: true,
  session_artifacts_written: ["invariant-verified.jsonl"],
});
