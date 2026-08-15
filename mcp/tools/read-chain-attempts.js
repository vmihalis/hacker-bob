"use strict";

const { defineReadTool } = require("./_archetypes.js");

const { readChainAttempts } = require("../core/chain-attempts.js");

module.exports = defineReadTool({
  name: "bob_read_chain_attempts",
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
});
