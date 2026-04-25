"use strict";

const { readHunterBrief } = require("../hunter-brief.js");

module.exports = Object.freeze({
  name: "bounty_read_hunter_brief",
  description:
    "Return everything a hunter needs to start testing: assigned surface, exclusions, valid surface IDs, bypass table, bounded curated technique guidance, and capped traffic/audit/intel/static-scan hints. Hunters call this once on startup instead of receiving everything via spawn prompt.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "wave": {
        "type": "string",
        "pattern": "^w[1-9][0-9]*$"
      },
      "agent": {
        "type": "string",
        "pattern": "^a[1-9][0-9]*$"
      }
    },
    "required": [
      "target_domain",
      "wave",
      "agent"
    ]
  },
  handler: readHunterBrief,
  role_bundles: ["hunter"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
  hook_required: false,
});
