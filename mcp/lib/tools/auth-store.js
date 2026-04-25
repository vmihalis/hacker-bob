"use strict";

const { authStore } = require("../auth.js");

module.exports = Object.freeze({
  name: "bounty_auth_store",
  description:
    "Store an authentication profile by profile_name. Names such as attacker, victim, admin, and tenant_b are caller-defined auth profiles.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "profile_name": {
        "type": "string"
      },
      "cookies": {
        "type": "object",
        "additionalProperties": {
          "type": "string"
        }
      },
      "headers": {
        "type": "object",
        "additionalProperties": {
          "type": "string"
        }
      },
      "local_storage": {
        "type": "object",
        "additionalProperties": {
          "type": "string"
        }
      },
      "credentials": {
        "type": "object",
        "properties": {
          "email": {
            "type": "string"
          },
          "password": {
            "type": "string"
          }
        }
      }
    },
    "required": [
      "target_domain",
      "profile_name"
    ]
  },
  handler: authStore,
  role_bundles: ["auth"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: true,
  session_artifacts_written: ["auth.json"],
  hook_required: false,
});
