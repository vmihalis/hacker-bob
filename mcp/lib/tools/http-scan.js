"use strict";

const { httpScan } = require("../http-scan.js");
const { REPLAY_CONTEXT_SCHEMA } = require("./replay-context-schema.js");

module.exports = Object.freeze({
  name: "bob_http_scan",
  aliases: ["bounty_http_scan"],
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
      block_internal_hosts: {
        type: "boolean",
        description: "When true, block localhost, private/link-local IP ranges, .internal/.local names, cloud metadata hosts, and public hostnames that resolve to those addresses on direct egress. When omitted, Bob uses the session's persisted effective policy: normal/yolo/legacy false, paranoid true unless allow_internal_hosts was set at init. Proxy-backed egress rejects this mode because Bob cannot verify proxy-side DNS/routing.",
      },
      timeout_ms: { type: "number" },
      auth_profile: { type: "string" },
      egress_profile: {
        type: "string",
        pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        description: "Optional named egress profile from .claude/bob/egress-profiles.json. Defaults to direct local egress.",
      },
      target_domain: { type: "string", description: "Required session domain for scope ownership, audit ownership, and allowed-host resolution." },
      wave: { type: "string", pattern: "^w[1-9][0-9]*$", description: "Optional wave ID for request audit correlation." },
      agent: { type: "string", pattern: "^a[1-9][0-9]*$", description: "Optional agent ID for request audit correlation." },
      surface_id: { type: "string", description: "Optional assigned surface ID for request audit correlation." },
      response_mode: {
        type: "string",
        enum: ["full", "status_only", "headers_only", "body_truncate"],
        description: "Control response size. 'full' (default): complete response. 'status_only': status code + redirect info only (~100 tokens). 'headers_only': status + headers, no body. 'body_truncate': status + headers + first body_limit chars of body.",
      },
      body_limit: { type: "number", description: "Max body chars when response_mode is 'body_truncate'. Default 2000." },
      replay_context: REPLAY_CONTEXT_SCHEMA,
    },
    required: ["method", "url", "target_domain"],
  },
  handler: httpScan,
  role_bundles: ["evaluator-web", "verifier", "auth", "chain", "evidence"],
  mutating: true,
  global_preapproval: true,
  network_access: true,
  browser_access: false,
  scope_required: true,
  sensitive_output: true,
  session_artifacts_written: ["http-audit.jsonl"],
});
