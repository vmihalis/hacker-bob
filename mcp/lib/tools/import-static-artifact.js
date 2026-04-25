"use strict";

const { importStaticArtifact } = require("../static-artifacts.js");

module.exports = Object.freeze({
  name: "bounty_import_static_artifact",
  description:
    "Import a token contract source artifact into session-owned static-imports for later safe static scanning. Accepts content only; filesystem path imports are rejected. Stored content is redacted and capped.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "artifact_type": {
        "type": "string",
        "enum": [
          "evm_token_contract",
          "solana_token_contract"
        ]
      },
      "content": {
        "type": "string",
        "maxLength": 200000
      },
      "label": {
        "type": "string",
        "description": "Optional short display label for the artifact."
      },
      "source_name": {
        "type": "string",
        "description": "Optional source filename/display name. Used as a label only; no file is read."
      },
      "surface_id": {
        "type": "string",
        "description": "Optional attack_surface.json surface ID to scope hunter brief hints."
      }
    },
    "required": [
      "target_domain",
      "artifact_type",
      "content"
    ]
  },
  handler: importStaticArtifact,
  role_bundles: ["hunter"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["static-imports","static-artifacts.jsonl"],
  hook_required: false,
  importStaticArtifact,
});
