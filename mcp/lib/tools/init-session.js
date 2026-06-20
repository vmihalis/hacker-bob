"use strict";

const { initSession } = require("../session-state.js");
const { ERROR_CODES, ToolError } = require("../envelope.js");

// Cycle O.1: web-mode init_session refuses target_repo with a structured
// pointer to bob_init_repo_session. Cross-mode sessions are opt-in via a
// separate companion-binding tool (out of scope for O.1).
function handler(args) {
  if (args && args.target_repo != null) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "bob_init_session is the web-mode entrypoint; call bob_init_repo_session to bind a repo target",
      { redirect_to_tool: "bob_init_repo_session" },
    );
  }
  return initSession(args);
}

module.exports = Object.freeze({
  name: "bob_init_session",
  aliases: ["bounty_init_session"],
  description:
    "Initialize a new session state.json for a target domain.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "target_url": {
        "type": "string"
      },
      "deep_mode": {
        "type": "boolean"
      },
      "target_kind": {
        "type": "string",
        "enum": ["web", "repo"],
        "description": "Defaults to web. Repo sessions should normally use bounty_init_repo_session."
      },
      "repo": {
        "type": "object",
        "description": "Repo metadata for target_kind=repo.",
        "properties": {
          "root_path": { "type": "string" },
          "source_url": { "type": "string" },
          "branch": { "type": "string" },
          "commit": { "type": "string" },
          "default_branch": { "type": "string" }
        },
        "required": ["root_path"]
      },
      "checkpoint_mode": {
        "type": "string",
        "enum": ["normal", "paranoid", "yolo"],
        "description": "Selected checkpoint mode. normal/yolo keep internal-host blocking opt-in; paranoid defaults block_internal_hosts to true on direct/default egress."
      },
      "block_internal_hosts": {
        "type": "boolean",
        "description": "Force strict direct-egress DNS/private/internal-host blocking for this session."
      },
      "allow_internal_hosts": {
        "type": "boolean",
        "description": "Disable paranoid's default internal-host blocking for explicitly authorized internal/lab programs. Cannot be combined with block_internal_hosts."
      },
      "egress_profile": {
        "type": "string",
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        "description": "Egress profile to bind to this session. Defaults to default."
      },
      "lab_authorization": {
        "type": "object",
        "description": "OFF BY DEFAULT. Declares intent to scope this session to a private host (IPv4 loopback 127.0.0.0/8 or RFC1918: 10/8, 172.16/12, 192.168/16) that the OPERATOR owns and is authorized to test. This declaration ALONE does NOT grant the escape: the operator must ALSO set the BOB_LAB_TARGET_ACK environment variable on the MCP server (an operator-only control the agent cannot supply). Without both, the public-DNS gate rejects non-public targets. Cloud-metadata, link-local, IPv6, and .internal/.local hosts are never eligible. Recorded as an audit-graded artifact and implies allow_internal_hosts for this session; cannot be combined with block_internal_hosts.",
        "properties": {
          "private_targets": {
            "type": "boolean",
            "description": "Must be true to declare a private-target session. Authorization is granted out-of-band by the operator via the BOB_LAB_TARGET_ACK server environment variable, not by any value in this call."
          }
        },
        "required": ["private_targets"],
        "additionalProperties": false
      }
    },
    "required": [
      "target_domain",
      "target_url"
    ]
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["state.json", "lab-authorization.json"],
});
