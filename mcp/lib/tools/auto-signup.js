"use strict";

const { autoSignup } = require("../signup.js");

module.exports = Object.freeze({
  name: "bob_auto_signup",
  aliases: ["bounty_auto_signup"],
  description:
    "Automated browser-based account registration using Patchright (stealth Playwright fork) with CAPTCHA solving. Fills signup forms with human-like interaction, solves reCAPTCHA/hCaptcha/Turnstile via CapSolver, and returns extracted auth tokens. Requires patchright to be installed (optional dep). Set CAPSOLVER_API_KEY env var for CAPTCHA solving.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "signup_url": {
        "type": "string"
      },
      "email": {
        "type": "string"
      },
      "password": {
        "type": "string"
      },
      "name": {
        "type": "string"
      },
      "profile_name": {
        "type": "string",
        "default": "attacker"
      },
      "egress_profile": {
        "type": "string",
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        "description": "Optional named egress profile from .claude/bob/egress-profiles.json. Defaults to direct local egress."
      },
      "headless": {
        "type": "boolean"
      },
      "timeout_ms": {
        "type": "number"
      },
      "block_internal_hosts": {
        "type": "boolean",
        "description": "When true or when the session's effective policy is true, this browser tool refuses with SCOPE_BLOCKED/manual fallback because Chromium cannot be DNS-pinned by Bob's safeFetch transport; use manual signup or direct MCP HTTP tools."
      }
    },
    "required": [
      "target_domain",
      "signup_url",
      "email",
      "password"
    ]
  },
  handler: autoSignup,
  role_bundles: ["auth"],
  mutating: true,
  global_preapproval: true,
  network_access: true,
  browser_access: true,
  scope_required: true,
  scope_url_fields: ["signup_url"],
  sensitive_output: true,
  session_artifacts_written: ["auth.json"],
});
