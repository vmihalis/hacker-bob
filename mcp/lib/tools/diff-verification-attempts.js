"use strict";

const { diffVerificationAttempts } = require("../verification-attempt-diff.js");

function diffVerificationAttemptsHandler(args) {
  return diffVerificationAttempts(args.target_domain, args.attempt_a, args.attempt_b);
}

module.exports = Object.freeze({
  name: "bob_diff_verification_attempts",
  aliases: ["bounty_diff_verification_attempts"],
  capability_id: "X2_verification_attempt_diff",
  description:
    "Compare two verification attempts for the same target. Each attempt_id is either an archive id from bob_read_verification_context.archived_attempts[*].attempt_id, or the literal string \"current\" for the live attempt. Returns hash matches (snapshot, adjudication plan, final verification) plus a per-file diff (which files exist in only one side, which differ in content).",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      attempt_a: {
        type: "string",
        description: "Earlier attempt id, or \"current\" to compare against the live attempt.",
      },
      attempt_b: {
        type: "string",
        description: "Later attempt id, or \"current\" to compare against the live attempt.",
      },
    },
    required: ["target_domain", "attempt_a", "attempt_b"],
  },
  handler: diffVerificationAttemptsHandler,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
