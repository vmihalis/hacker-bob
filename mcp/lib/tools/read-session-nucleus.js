"use strict";

const {
  assertNonEmptyString,
} = require("../validation.js");
const {
  readSessionNucleus,
} = require("../governance-store.js");

function handler(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const nucleus = readSessionNucleus(domain);
  return JSON.stringify({
    version: 1,
    nucleus,
  });
}

module.exports = Object.freeze({
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
  role_bundles: ["orchestrator", "evaluator-shared", "reporter"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
