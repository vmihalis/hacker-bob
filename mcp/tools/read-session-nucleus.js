"use strict";

const { defineReadTool } = require("./_archetypes.js");

const {
  assertNonEmptyString,
} = require("../core/io/validation.js");
const {
  readSessionNucleusProjection,
} = require("../core/governance/index.js");

function handler(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const { nucleus, verified } = readSessionNucleusProjection(domain);
  return JSON.stringify({
    version: 1,
    nucleus,
    verified,
  });
}

module.exports = defineReadTool({
  name: "bob_read_session_nucleus",
  description: "Read the persisted SessionNucleus for a target_domain.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      }
    },
    "required": [
      "target_domain"
    ]
  },
  handler,
  role_bundles: ["orchestrator", "evaluator-shared", "evaluator-physical", "reporter"],
});
