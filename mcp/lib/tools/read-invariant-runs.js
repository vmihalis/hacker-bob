"use strict";

const { readInvariantRuns } = require("../invariant-runner.js");

function readInvariantRunsHandler(args) {
  return readInvariantRuns({
    target_domain: args.target_domain,
    outcome_filter: args.outcome_filter,
    template_id_filter: args.template_id_filter,
    limit: args.limit,
  });
}

module.exports = Object.freeze({
  name: "bob_read_invariant_runs",
  aliases: ["bounty_read_invariant_runs"],
  description:
    "Read the per-target invariant-runs.jsonl corpus. Reads reject symlinked or hard-linked corpus files, and use descriptor-bound no-follow reads where the platform exposes O_NOFOLLOW; without O_NOFOLLOW, static symlinks are rejected before open but malicious same-UID concurrent final-entry replacement and in-place regular-file mutation outside Bob's cooperative session lock remain unsupported. Each record carries finding_hash, template_id, slot_values, contract_name, function_name, test_path, outcome (test_passed, test_failed, fork_blocked, forge_missing, no_template, unknown), and the captured Foundry result. Filter by outcome (e.g. test_failed for counterexamples that need follow-up) or template_id.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      outcome_filter: { type: "string" },
      template_id_filter: { type: "string" },
      limit: { type: "integer", minimum: 1, maximum: 200 },
    },
    required: ["target_domain"],
  },
  handler: readInvariantRunsHandler,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
