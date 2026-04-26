"use strict";

const {
  importHttpTraffic: importHttpTrafficRecords,
} = require("../http-records.js");

function importHttpTraffic(args) {
  return importHttpTrafficRecords(args);
}

module.exports = Object.freeze({
  name: "bounty_import_http_traffic",
  description:
    "Import Burp/HAR-style request history into session-owned traffic.jsonl. Entries are validated, capped, deduped, and limited to the target's first-party hosts.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "source": {
        "type": "string",
        "description": "Traffic source label such as burp, har, browser, proxy, or manual."
      },
      "block_internal_hosts": {
        "type": "boolean",
        "description": "When true, reject imported localhost, private/link-local IP ranges, .internal/.local names, and cloud metadata hosts. Defaults to false."
      },
      "entries": {
        "oneOf": [
          {
            "type": "array",
            "items": {
              "type": "object",
              "additionalProperties": true
            }
          },
          {
            "type": "object",
            "additionalProperties": true
          },
          {
            "type": "string"
          }
        ],
        "description": "Array of HAR log.entries items, a HAR object with log.entries, a JSON string containing either shape, or simplified {method,url,status,headers,ts} records."
      }
    },
    "required": [
      "target_domain",
      "source"
    ]
  },
  handler: importHttpTraffic,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: true,
  sensitive_output: false,
  session_artifacts_written: ["traffic.jsonl"],
  hook_required: false,
  importHttpTraffic,
});
