"use strict";

const { logDeadEnds } = require("../waves.js");

module.exports = Object.freeze({
  name: "bounty_log_dead_ends",
  description:
    "Append dead ends and WAF-blocked endpoints discovered so far. Call periodically (~every 30 turns) so terrain survives if the hunter hits maxTurns. Validated against wave assignments.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "wave": {
        "type": "string",
        "pattern": "^w[0-9]+$"
      },
      "agent": {
        "type": "string",
        "pattern": "^a[0-9]+$"
      },
      "surface_id": {
        "type": "string"
      },
      "dead_ends": {
        "type": "array",
        "items": {
          "type": "string"
        }
      },
      "waf_blocked_endpoints": {
        "type": "array",
        "items": {
          "type": "string"
        }
      }
    },
    "required": [
      "target_domain",
      "wave",
      "agent",
      "surface_id"
    ]
  },
  handler: logDeadEnds,
  role_bundles: ["hunter"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["live-dead-ends-wN-aN.jsonl"],
  hook_required: false,
});
