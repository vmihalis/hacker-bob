"use strict";

const { buildRepoInventory } = require("../repo-target.js");

function handler(args) {
  const result = buildRepoInventory({
    target_domain: args.target_domain,
    repo_path: args.repo_path,
  });
  return JSON.stringify({
    version: 1,
    ...result,
  });
}

module.exports = Object.freeze({
  name: "bob_repo_inventory",
  description:
    "Walk a bound repo session and materialize repo-inventory.json plus frontier surface.observed events " +
    "for every enumerated artefact (code modules, manifests, dependencies, entry points, CI pipelines, configs). " +
    "Honors .gitignore + default heavy excludes, halts on symlink loops, and caps the walk at 50k files. " +
    "Does not read file contents; payloads carry paths + structural metadata only.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
        description: "Repo session target_domain derived by bob_init_repo_session.",
      },
      repo_path: {
        type: "string",
        description:
          "Optional sub-tree override. Defaults to the session's bound target_repo.root_path. " +
          "Operators use this for repos that exceed REPO_WALK_MAX_FILES (50k).",
      },
    },
    required: ["target_domain"],
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [
    "repo-inventory.json",
    "frontier-events.jsonl",
    "surface-index.json",
    "task-queue.json",
  ],
});
