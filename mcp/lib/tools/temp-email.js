"use strict";

const { tempEmail } = require("../temp-email.js");

module.exports = Object.freeze({
  name: "bounty_temp_email",
  description:
    "Manage temporary email addresses for automated account registration. Operations: create (new mailbox), poll (check inbox), extract (parse verification code/link from message).",
  inputSchema: {
    "type": "object",
    "properties": {
      "operation": {
        "type": "string",
        "enum": [
          "create",
          "poll",
          "extract"
        ]
      },
      "provider": {
        "type": "string",
        "enum": [
          "mail.tm",
          "guerrillamail"
        ]
      },
      "email_address": {
        "type": "string"
      },
      "message_id": {
        "type": "string"
      },
      "from_filter": {
        "type": "string"
      }
    },
    "required": [
      "operation"
    ]
  },
  handler: tempEmail,
  role_bundles: ["auth"],
  mutating: true,
  global_preapproval: true,
  network_access: true,
  browser_access: false,
  scope_required: false,
  sensitive_output: true,
  session_artifacts_written: [],
  hook_required: false,
});
