"use strict";

const { defineReadTool } = require("./_archetypes.js");

const {
  readHttpAudit: readHttpAuditRecordsTool,
} = require("../core/io/http-records.js");
const { readAttackSurfaceStrict } = require("../core/frontier/attack-surface.js");

function readHttpAudit(args) {
  return readHttpAuditRecordsTool(args, { readAttackSurfaceStrict });
}

module.exports = defineReadTool({
  name: "bob_read_http_audit",
  description:
    "Read a capped HTTP request audit summary from session-owned http-audit.jsonl, optionally filtered to one attack surface.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      surface_id: { type: "string" },
      limit: { type: "number", description: "Maximum recent records to return; clamped server-side to the audit summary cap." },
    },
    required: ["target_domain"],
  },
  handler: readHttpAudit,
  role_bundles: ["evaluator-web", "verifier", "chain", "evidence"],
  readHttpAudit,
});
