"use strict";

const { httpScan } = require("../http-scan.js");

module.exports = Object.freeze({
  name: "bounty_http_scan",
  description:
    "Make an HTTP request and auto-analyze for security issues. Returns status, headers, body, plus detected tech stack, leaked secrets, misconfigs, and endpoints.",
  inputSchema: {
    type: "object",
    properties: {
      method: { type: "string", enum: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"] },
      url: { type: "string" },
      headers: { type: "object", additionalProperties: { type: "string" } },
      body: { type: "string" },
      follow_redirects: { type: "boolean" },
      timeout_ms: { type: "number" },
      auth_profile: { type: "string" },
      target_domain: { type: "string", description: "Session domain for scope resolution when scanning cross-domain URLs (e.g. third-party APIs discovered on the target)." },
      wave: { type: "string", pattern: "^w[0-9]+$", description: "Optional wave ID for request audit correlation." },
      agent: { type: "string", pattern: "^a[0-9]+$", description: "Optional agent ID for request audit correlation." },
      surface_id: { type: "string", description: "Optional assigned surface ID for request audit correlation." },
      response_mode: {
        type: "string",
        enum: ["full", "status_only", "headers_only", "body_truncate"],
        description: "Control response size. 'full' (default): complete response. 'status_only': status code + redirect info only (~100 tokens). 'headers_only': status + headers, no body. 'body_truncate': status + headers + first body_limit chars of body.",
      },
      body_limit: { type: "number", description: "Max body chars when response_mode is 'body_truncate'. Default 2000." },
    },
    required: ["method", "url"],
  },
  handler: httpScan,
  role_bundles: ["hunter", "verifier", "auth"],
  mutating: true,
  global_preapproval: true,
  network_access: true,
  browser_access: false,
  scope_required: true,
  sensitive_output: true,
  session_artifacts_written: ["http-audit.jsonl"],
  hook_required: true,
});
