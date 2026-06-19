"use strict";

const { readGradeVerdict } = require("../grade-verdict-store.js");

module.exports = Object.freeze({
  name: "bob_read_grade_verdict",
  aliases: ["bounty_read_grade_verdict"],
  description:
    "Read the authoritative grade verdict JSON document.",
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
  handler: readGradeVerdict,
  role_bundles: ["grader","reporter","orchestrator"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
