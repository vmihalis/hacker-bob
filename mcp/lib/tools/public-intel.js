"use strict";

const { bountyPublicIntel: bountyPublicIntelTool } = require("../public-intel.js");

async function bountyPublicIntel(args) {
  return bountyPublicIntelTool(args);
}

module.exports = Object.freeze({
  name: "bounty_public_intel",
  description:
    "Fetch optional public bug bounty intel: HackerOne-style program policy summary, stats, structured scopes, disclosed report hints, and operator-provided NVD/CVE JSON matched against the current attack surface. Network/API failures degrade to empty results with errors.",
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
      },
      "cve_feed_json": {
        "type": "string",
        "maxLength": 300000,
        "description": "Optional operator-provided NVD 2.0/1.x JSON or a single CVE JSON record. Bob does not fetch this URL; pass the feed content directly."
      },
      "cve_source_uri": {
        "type": "string",
        "description": "Optional display-only source label for cve_feed_json."
      },
      "cve_limit": {
        "type": "number",
        "description": "Maximum matched CVE records to retain, capped at the public intel item limit."
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
  bountyPublicIntel,
});
