"use strict";

const { defineWriteTool } = require("./_archetypes.js");

const { writeGradeVerdict } = require("../core/grade-verdict-store.js");
const { wrapWriteTool } = require("./_write-base.js");

module.exports = wrapWriteTool(defineWriteTool({
  name: "bob_write_grade_verdict",
  writes_audit_graded: true,
  description:
    "Write the authoritative grading verdict JSON plus a markdown mirror.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "verdict": {
        "type": "string",
        "enum": [
          "SUBMIT",
          "HOLD",
          "SKIP"
        ]
      },
      "total_score": {
        "type": "number"
      },
      "findings": {
        "type": "array",
        "items": {
          "type": "object",
          "properties": {
            "finding_id": {
              "type": "string"
            },
            "impact": {
              "type": "number"
            },
            "proof_quality": {
              "type": "number"
            },
            "severity_accuracy": {
              "type": "number"
            },
            "chain_potential": {
              "type": "number"
            },
            "report_quality": {
              "type": "number"
            },
            "total_score": {
              "type": "number"
            },
            "feedback": {
              "type": [
                "string",
                "null"
              ]
            }
          },
          "required": [
            "finding_id",
            "impact",
            "proof_quality",
            "severity_accuracy",
            "chain_potential",
            "report_quality",
            "total_score",
            "feedback"
          ]
        }
      },
      "feedback": {
        "type": [
          "string",
          "null"
        ]
      }
    },
    "required": [
      "target_domain",
      "verdict",
      "total_score",
      "findings",
      "feedback"
    ]
  },
  handler: writeGradeVerdict,
  role_bundles: ["grader"],
  session_artifacts_written: ["grade.json","grade.md"],
}));
