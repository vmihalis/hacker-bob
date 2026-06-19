"use strict";

const { readChainAttempts } = require("../chain-attempts.js");

module.exports = Object.freeze({
  name: "bob_read_chain_attempts",
  aliases: ["bounty_read_chain_attempts"],
  description:
    "Read structured CHAIN-phase impact proof-chain attempts and outcome counts from MCP-owned chain-attempts.jsonl.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
    },
    required: ["target_domain"],
  },
  handler: readChainAttempts,
  role_bundles: ["chain", "verifier", "grader", "reporter", "orchestrator"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
