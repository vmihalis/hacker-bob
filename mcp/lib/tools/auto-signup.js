"use strict";

const { autoSignup } = require("../signup.js");

module.exports = Object.freeze({
  name: "bounty_auto_signup",
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
      "proxy": {
        "type": "string"
      },
      "headless": {
        "type": "boolean"
      },
      "timeout_ms": {
        "type": "number"
      },
      "block_internal_hosts": {
        "type": "boolean",
        "description": "When true, block localhost, private/link-local IP ranges, .internal/.local names, cloud metadata hosts, and public hostnames that resolve to those addresses. Defaults to false."
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
  sensitive_output: true,
  session_artifacts_written: ["auth.json"],
  hook_required: true,
});
