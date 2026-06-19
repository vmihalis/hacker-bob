"use strict";

const { signupDetect } = require("../signup.js");

module.exports = Object.freeze({
  name: "bob_signup_detect",
  aliases: ["bounty_signup_detect"],
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
      },
      "block_internal_hosts": {
        "type": "boolean",
        "description": "When true, block localhost, private/link-local IP ranges, .internal/.local names, cloud metadata hosts, and public hostnames that resolve to those addresses on direct egress. When omitted, Bob uses the session's persisted effective policy: normal/yolo/legacy false, paranoid true unless allow_internal_hosts was set at init. Proxy-backed egress rejects this mode because Bob cannot verify proxy-side DNS/routing."
      },
      "egress_profile": {
        "type": "string",
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        "description": "Optional named egress profile from .claude/bob/egress-profiles.json. Defaults to direct local egress."
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
  scope_url_fields: ["target_url"],
  sensitive_output: false,
  session_artifacts_written: [],
});
