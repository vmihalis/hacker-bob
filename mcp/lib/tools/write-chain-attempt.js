"use strict";

const { writeChainAttempt } = require("../chain-attempts.js");

module.exports = Object.freeze({
  name: "bounty_write_chain_attempt",
  description:
    "Append one structured CHAIN-phase exploit-chain attempt to MCP-owned chain-attempts.jsonl.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      finding_ids: {
        type: "array",
        items: { type: "string", pattern: "^F-[1-9][0-9]*$" },
      },
      surface_ids: {
        type: "array",
        items: { type: "string", minLength: 1 },
      },
      hypothesis: { type: "string", minLength: 1, maxLength: 2000 },
      steps: {
        type: "array",
        minItems: 1,
        maxItems: 50,
        items: { type: "string", minLength: 1, maxLength: 1000 },
      },
      outcome: {
        type: "string",
        enum: ["confirmed", "denied", "blocked", "inconclusive", "not_applicable"],
      },
      evidence_summary: { type: "string", minLength: 1, maxLength: 4000 },
      request_refs: {
        type: "array",
        maxItems: 100,
        items: { type: "string", minLength: 1, maxLength: 300 },
      },
      auth_profiles: {
        type: "array",
        maxItems: 20,
        items: { type: "string", minLength: 1, maxLength: 120 },
      },
    },
    required: [
      "target_domain",
      "finding_ids",
      "surface_ids",
      "hypothesis",
      "steps",
      "outcome",
      "evidence_summary",
    ],
  },
  handler: writeChainAttempt,
  role_bundles: ["chain"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["chain-attempts.jsonl"],
  hook_required: false,
});
