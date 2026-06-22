"use strict";

const { wsProbe } = require("../ws-probe.js");

module.exports = Object.freeze({
  name: "bob_ws_probe",
  aliases: [],
  description:
    "Probe a WebSocket endpoint for security issues. Modes: json_rpc_enumerate (discover enabled/disabled JSON-RPC methods including admin/debug); cswsh_probe (test Cross-Site WebSocket Hijacking by connecting with a foreign Origin); subscription_probe (send subscribe messages and collect responses); raw (send raw frames and collect responses). Scope-gated and audit-logged.",
  inputSchema: {
    type: "object",
    properties: {
      url: { type: "string", description: "ws:// or wss:// endpoint URL." },
      target_domain: { type: "string", description: "Required session domain for scope ownership and audit." },
      mode: {
        type: "string",
        enum: ["json_rpc_enumerate", "cswsh_probe", "subscription_probe", "raw"],
        description: "Probe mode. Default: json_rpc_enumerate.",
      },
      messages: {
        type: "array",
        items: { type: "string" },
        description: "Message frames to send. Used in subscription_probe and raw modes.",
      },
      origin: {
        type: "string",
        description: "Custom Origin header for cswsh_probe. Default: https://evil.example.com.",
      },
      auth_profile: { type: "string", description: "Optional auth profile name." },
      egress_profile: {
        type: "string",
        pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        description: "Optional named egress profile. Defaults to direct local egress.",
      },
      timeout_ms: { type: "number", description: "Connection and operation timeout in milliseconds. Default: 10000." },
      max_messages: { type: "number", description: "Max messages to collect in subscription_probe or raw mode. Default: 5." },
      wave: { type: "string", pattern: "^w[1-9][0-9]*$", description: "Optional wave ID for audit correlation." },
      agent: { type: "string", pattern: "^a[1-9][0-9]*$", description: "Optional agent ID for audit correlation." },
      surface_id: { type: "string", description: "Optional assigned surface ID for audit correlation." },
      block_internal_hosts: {
        type: "boolean",
        description: "When true, block private/internal hosts. Inherits session policy when omitted.",
      },
    },
    required: ["url", "target_domain"],
  },
  handler: wsProbe,
  role_bundles: ["evaluator-web", "verifier", "auth", "chain", "evidence"],
  mutating: false,
  global_preapproval: true,
  network_access: true,
  browser_access: false,
  scope_required: true,
  sensitive_output: true,
  session_artifacts_written: ["http-audit.jsonl"],
});
