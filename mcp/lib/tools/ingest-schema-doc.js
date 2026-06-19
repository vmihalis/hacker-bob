"use strict";

const { ingestSchemaDoc } = require("../schema-contracts-store.js");

module.exports = Object.freeze({
  name: "bob_ingest_schema_doc",
  aliases: ["bounty_ingest_schema_doc"],
  capability_id: "C2_doc_vs_behavior",
  description:
    "Parse and persist an OpenAPI / GraphQL / Postman document into the per-target schema-contract corpus. Contracts are deduplicated by contract_hash; later ingestion of the same source doc is a no-op for unchanged contracts. Use to seed doc-vs-behavior differential testing.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
      "raw_doc": {
        "type": "string",
        "description": "Raw schema document as a JSON string. OpenAPI 3 is supported in the current slice; GraphQL SDL and Postman collections are recognized in subsequent slices.",
      },
      "source_uri": {
        "type": "string",
        "description": "Optional URL or file path the doc was fetched from. Recorded on every contract for provenance tracking.",
      },
    },
    "required": ["target_domain", "raw_doc"],
  },
  handler: ingestSchemaDoc,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["schema-contracts.jsonl"],
});
