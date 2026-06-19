"use strict";

const { readTechniquePackForTool } = require("../technique-packs.js");

function readTechniquePackTool(args) {
  return readTechniquePackForTool(args);
}

module.exports = Object.freeze({
  name: "bob_read_technique_pack",
  aliases: ["bounty_read_technique_pack"],
  description: "Read one technique pack in summary or full bounded mode. Full mode requires target_domain, wave, agent, and surface_id so full_pack_read_limit can be enforced for the assignment.",
  inputSchema: {
    type: "object",
    properties: {
      pack_id: { type: "string" },
      mode: { type: "string", enum: ["summary", "full"] },
      target_domain: { type: "string", description: "Required when mode is full." },
      wave: { type: "string", pattern: "^w[1-9][0-9]*$", description: "Required when mode is full." },
      agent: { type: "string", pattern: "^a[1-9][0-9]*$", description: "Required when mode is full." },
      surface_id: { type: "string", description: "Required when mode is full." },
    },
    required: ["pack_id"],
  },
  handler: readTechniquePackTool,
  role_bundles: ["evaluator-web", "orchestrator"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["technique-pack-reads.jsonl"],
});
