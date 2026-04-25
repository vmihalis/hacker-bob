"use strict";

const { signupDetect } = require("../signup.js");

module.exports = Object.freeze({
  name: "bounty_signup_detect",
  description:
    "Probe a target for registration/signup endpoints and analyze form requirements. Returns detected endpoints, form fields, CAPTCHA presence, and signup feasibility.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "target_url": {
        "type": "string"
      }
    },
    "required": [
      "target_domain",
      "target_url"
    ]
  },
  handler: signupDetect,
  role_bundles: ["auth"],
  mutating: false,
  global_preapproval: true,
  network_access: true,
  browser_access: false,
  scope_required: true,
  sensitive_output: false,
  session_artifacts_written: [],
  hook_required: true,
});
