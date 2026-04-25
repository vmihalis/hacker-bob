"use strict";

const { staticScan } = require("../static-artifacts.js");

module.exports = Object.freeze({
  name: "bounty_static_scan",
  description:
    "Run a deterministic token-contract static scan on a previously imported session-owned artifact. Results are stored as redacted structured JSON in static-scan-results.jsonl and summarized in hunter briefs.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "artifact_id": {
        "type": "string",
        "pattern": "^SA-[1-9][0-9]*$"
      },
      "scan_type": {
        "type": "string",
        "enum": [
          "token_contract"
        ],
        "description": "Defaults to token_contract."
      },
      "limit": {
        "type": "number",
        "description": "Max findings to return in the immediate response. Stored results remain capped by Bob."
      }
    },
    "required": [
      "target_domain",
      "artifact_id"
    ]
  },
  handler: staticScan,
  role_bundles: ["hunter"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["static-scan-results.jsonl"],
  hook_required: false,
  staticScan,
});
