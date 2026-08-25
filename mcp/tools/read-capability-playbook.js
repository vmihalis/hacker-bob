"use strict";

const { defineReadTool } = require("./_archetypes.js");

const {
  readCapabilityPlaybook,
} = require("../core/capability/capability-playbooks.js");

function readCapabilityPlaybookHandler(args) {
  return readCapabilityPlaybook(args && args.capability_id);
}

module.exports = defineReadTool({
  name: "bob_read_capability_playbook",
  description:
    "Read an externalized orchestrator capability playbook from prompts/playbooks/<capability_id>.md. Returns the markdown guidance for a registered capability without exposing unrelated prompt bodies.",
  inputSchema: {
    type: "object",
    properties: {
      capability_id: {
        type: "string",
        pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
      },
    },
    required: ["capability_id"],
  },
  handler: readCapabilityPlaybookHandler,
  role_bundles: ["orchestrator"],
  readCapabilityPlaybook,
});
