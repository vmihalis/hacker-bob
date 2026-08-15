"use strict";

const { defineLogTool } = require("./_archetypes.js");

const { logDeadEnds } = require("../core/waves/waves.js");

module.exports = defineLogTool({
  name: "bob_log_dead_ends",
  description:
    "Append dead ends and WAF-blocked endpoints discovered so far. Call periodically (~every 30 turns) so terrain survives if the evaluator hits maxTurns. Validated against wave assignments.",
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
  role_bundles: ["evaluator-shared"],
  session_artifacts_written: ["live-dead-ends-wN-aN.jsonl"],
});
