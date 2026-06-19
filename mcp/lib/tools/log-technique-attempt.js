"use strict";

const { logTechniqueAttempt } = require("../technique-packs.js");
const {
  TECHNIQUE_ATTEMPT_STATUS_VALUES,
} = require("../constants.js");

module.exports = Object.freeze({
  name: "bob_log_technique_attempt",
  aliases: ["bounty_log_technique_attempt"],
  description:
    "Append one validated technique-pack selection, attempt, skip, or outcome record to MCP-owned technique-attempts.jsonl.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      wave: { type: "string", pattern: "^w[1-9][0-9]*$" },
      agent: { type: "string", pattern: "^a[1-9][0-9]*$" },
      surface_id: { type: "string" },
      pack_id: { type: "string" },
      status: { type: "string", enum: TECHNIQUE_ATTEMPT_STATUS_VALUES },
      outcome: { type: "string" },
      evidence: { type: "string", minLength: 1 },
    },
    required: ["target_domain", "surface_id", "pack_id", "status", "evidence"],
  },
  handler: logTechniqueAttempt,
  role_bundles: ["evaluator-web", "orchestrator"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["technique-attempts.jsonl"],
});
