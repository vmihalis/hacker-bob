"use strict";

const { defineReadTool } = require("./_archetypes.js");

const { readGradeVerdict } = require("../core/grade-verdict-store.js");

module.exports = defineReadTool({
  name: "bob_read_grade_verdict",
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
});
