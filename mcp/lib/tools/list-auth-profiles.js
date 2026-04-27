"use strict";

const { listAuthProfiles } = require("../auth.js");

module.exports = Object.freeze({
  name: "bounty_list_auth_profiles",
  description:
    "Return redacted auth profile status for a target. Shows profile names, header/cookie key names, credential presence, and expiry/staleness hints without token, cookie, localStorage, or password values.",
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
  handler: listAuthProfiles,
  role_bundles: ["auth","hunter","verifier","orchestrator","chain"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
  hook_required: false,
});
