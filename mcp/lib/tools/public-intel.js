"use strict";

const { bountyPublicIntel: bountyPublicIntelTool } = require("../public-intel.js");
const { rankAttackSurfaces } = require("../ranking.js");

async function bountyPublicIntel(args) {
  return bountyPublicIntelTool(args, { rankAttackSurfaces });
}

module.exports = Object.freeze({
  name: "bounty_public_intel",
  description:
    "Fetch optional public bug bounty intel: HackerOne-style program policy summary, stats, structured scopes, and disclosed report hints. Network/API failures degrade to empty results with errors.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "program": {
        "type": "string",
        "description": "Optional HackerOne handle or program URL."
      },
      "keywords": {
        "oneOf": [
          {
            "type": "array",
            "items": {
              "type": "string"
            }
          },
          {
            "type": "string"
          }
        ],
        "description": "Optional disclosed-report search keywords. Defaults to the target domain."
      },
      "limit": {
        "type": "number"
      }
    },
    "required": [
      "target_domain"
    ]
  },
  handler: bountyPublicIntel,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: true,
  browser_access: false,
  scope_required: true,
  sensitive_output: false,
  session_artifacts_written: ["public-intel.json"],
  hook_required: false,
  bountyPublicIntel,
});
