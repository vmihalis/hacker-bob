"use strict";

const { defineReadTool } = require("./_archetypes.js");

const { readEvidencePacks } = require("../core/evidence.js");

module.exports = defineReadTool({
  name: "bob_read_evidence_packs",
  description:
    "Read and validate the evidence packs document for final reportable findings.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
    },
    required: ["target_domain"],
  },
  handler: readEvidencePacks,
  role_bundles: ["evidence", "grader", "reporter", "orchestrator"],
});
