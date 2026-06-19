"use strict";

const { repoCheck } = require("../repo-target.js");

function handler(args) {
  const result = repoCheck({
    target_domain: args.target_domain,
    check_type: args.check_type,
    file_path: args.file_path,
    pattern: args.pattern,
    regex: args.regex,
    replay_context: args.replay_context,
  });
  return JSON.stringify({
    version: 1,
    ...result,
  });
}

module.exports = Object.freeze({
  name: "bob_repo_check",
  description:
    "Read-only evidence probe against a file under the bound Plane O repo session. " +
    "Supports file_exists, file_contains (literal substring), and regex_match (per-line regex). " +
    "Caps file reads at 4 MB; rejects paths that escape the bound repo root. " +
    "Binary files probe-detect and do NOT have their bytes excerpted. " +
    "Every appended matched_lines[].excerpt is redacted via redactTextSensitiveValues before persistence " +
    "so .env-shaped secrets (API_KEY=..., Authorization: Bearer ...) never land in repo-checks.jsonl (O-P7).",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
        description: "Repo session target_domain derived by bob_init_repo_session.",
      },
      check_type: {
        type: "string",
        enum: ["file_exists", "file_contains", "regex_match"],
        description:
          "Probe shape. Defaults to file_exists when no pattern/regex is supplied; " +
          "regex_match when regex is supplied; file_contains when pattern is supplied.",
      },
      file_path: {
        type: "string",
        description:
          "Relative path under the bound repo root. Absolute paths and `..` segments " +
          "that escape the repo root are rejected with structured errors (O-P1).",
      },
      pattern: {
        type: "string",
        description: "Literal substring to look for. Used by file_contains.",
      },
      regex: {
        type: "string",
        description:
          "Regex body or `/body/flags` form. The `m` flag is forced so matched_lines " +
          "are scanned per line. Used by regex_match.",
      },
      replay_context: {
        type: "object",
        description:
          "Optional dispatch context (wave, agent, surface_id, task_lens, technique_pack_id, " +
          "purpose, operator_note) recorded with the check for evaluator correlation.",
      },
    },
    required: ["target_domain", "file_path"],
  },
  handler,
  // Per O.5 §4: broad reach matching MVP — evaluator-shared, verifier,
  // evidence, grader, reporter all need read-only repo probes during their
  // respective lifecycle phases.
  role_bundles: ["evaluator-shared", "verifier", "evidence", "grader", "reporter"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [
    "repo-checks.jsonl",
  ],
});
