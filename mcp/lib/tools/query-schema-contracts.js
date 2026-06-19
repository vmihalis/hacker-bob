"use strict";

const { querySchemaContracts } = require("../schema-contracts-store.js");

module.exports = Object.freeze({
  name: "bob_query_schema_contracts",
  aliases: ["bounty_query_schema_contracts"],
  capability_id: "C2_doc_vs_behavior",
  description:
    "Query the schema-contract corpus for a target. Filters by endpoint substring and HTTP method. Use to discover documented contracts before differential testing or to enumerate the documented attack surface.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
      "endpoint_pattern": {
        "type": "string",
        "description": "Substring filter applied to contract endpoints. Matches when the contract's endpoint string contains this substring.",
      },
      "method": {
        "type": "string",
        "description": "HTTP method filter. Case-insensitive; canonicalized to uppercase before matching.",
      },
      "limit": {
        "type": "integer",
        "minimum": 1,
        "maximum": 1000,
        "description": "Maximum number of contracts to return. Defaults to all matched.",
      },
    },
    "required": ["target_domain"],
  },
  handler: querySchemaContracts,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
