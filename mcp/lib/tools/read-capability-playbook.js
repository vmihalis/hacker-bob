"use strict";

const {
  readCapabilityPlaybook,
} = require("../capability-playbooks.js");

function readCapabilityPlaybookHandler(args) {
  return readCapabilityPlaybook(args && args.capability_id);
}

module.exports = Object.freeze({
  name: "bob_read_capability_playbook",
  aliases: ["bounty_read_capability_playbook"],
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
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
  readCapabilityPlaybook,
});
