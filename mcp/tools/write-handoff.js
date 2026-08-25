"use strict";

const { defineWriteTool } = require("./_archetypes.js");

const { writeHandoff } = require("../core/waves/waves.js");

module.exports = defineWriteTool({
  name: "bob_write_handoff",
  description:
    "Write session handoff for context rotation.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "session_number": {
        "type": "number"
      },
      "target_url": {
        "type": "string"
      },
      "program_url": {
        "type": "string"
      },
      "findings_summary": {
        "type": "array",
        "items": {
          "type": "object",
          "properties": {
            "id": {
              "type": "string"
            },
            "severity": {
              "type": "string"
            },
            "title": {
              "type": "string"
            }
          }
        }
      },
      "attack_surface_map": {
        "type": "array",
        "items": {
          "type": "string"
        }
      },
      "explored_with_results": {
        "type": "array",
        "items": {
          "type": "string"
        }
      },
      "dead_ends": {
        "type": "array",
        "items": {
          "type": "string"
        }
      },
      "blockers": {
        "type": "array",
        "items": {
          "type": "string"
        }
      },
      "unexplored": {
        "type": "array",
        "items": {
          "type": "string"
        }
      },
      "must_do_next": {
        "type": "array",
        "items": {
          "type": "object",
          "properties": {
            "priority": {
              "type": "string"
            },
            "description": {
              "type": "string"
            }
          }
        }
      },
      "promising_leads": {
        "type": "array",
        "items": {
          "type": "string"
        }
      }
    },
    "required": [
      "target_domain",
      "session_number",
      "target_url",
      "explored_with_results",
      "must_do_next"
    ]
  },
  handler: writeHandoff,
  role_bundles: ["orchestrator"],
  global_preapproval: false,
  session_artifacts_written: ["SESSION_HANDOFF.md"],
});
