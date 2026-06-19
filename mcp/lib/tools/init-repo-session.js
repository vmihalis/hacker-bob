"use strict";

const { initRepoSession } = require("../repo-target.js");

function handler(args) {
  const result = initRepoSession({
    repo_path: args.repo_path,
    target_domain: args.target_domain,
    source_url: args.source_url,
    branch: args.branch,
    commit: args.commit,
    deep_mode: args.deep_mode,
    egress_profile: args.egress_profile,
  });
  return JSON.stringify({
    version: 1,
    ...result,
  });
}

module.exports = Object.freeze({
  name: "bob_init_repo_session",
  description:
    "Initialize a new session bound to a locally-checked-out repo (Plane O OSS axis). target_domain is derived from the absolute repo path; the session writes target_repo + repo_hash into state.json instead of target_url.",
  inputSchema: {
    "type": "object",
    "properties": {
      "repo_path": {
        "type": "string",
        "description": "Absolute path to a locally-checked-out repository. Plane O O-P1 forbids remote clones; the path must already exist as a directory."
      },
      "target_domain": {
        "type": "string",
        "description": "Optional custom safe-slug override for the derived repo target_domain (supports --target-id stability across path changes). When omitted, the slug is derived from the canonical repo path."
      },
      "source_url": {
        "type": "string",
        "description": "Optional upstream URL (e.g. https://github.com/org/repo). Stored for provenance; never used to clone."
      },
      "branch": {
        "type": "string",
        "description": "Optional branch name for provenance."
      },
      "commit": {
        "type": "string",
        "description": "Optional 7-64 character hex commit id. When present, pinned as repo_hash so the docker image tag stays stable across the session lifetime."
      },
      "deep_mode": {
        "type": "boolean"
      },
      "egress_profile": {
        "type": "string",
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        "description": "Egress profile to bind to this session. Defaults to default."
      }
    },
    "required": [
      "repo_path"
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
  session_artifacts_written: ["state.json", "session-nucleus.json"],
});
