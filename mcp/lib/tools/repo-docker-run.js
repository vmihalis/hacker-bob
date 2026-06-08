"use strict";

const { repoDockerRun } = require("../repo-env.js");

async function handler(args) {
  const result = await repoDockerRun({
    target_domain: args.target_domain,
    command: args.command,
    checkout: args.checkout,
    dry_run: args.dry_run,
    allow_network: args.allow_network,
    repo_mount_mode: args.repo_mount_mode,
    image_tag: args.image_tag,
    timeout_ms: args.timeout_ms,
    replay_context: args.replay_context,
    blocked_harness_run_id: args.blocked_harness_run_id,
    egress_profile: args.egress_profile,
  });
  return JSON.stringify({
    version: 1,
    ...result,
  });
}

module.exports = Object.freeze({
  name: "bob_repo_docker_run",
  description:
    "Run an operator-vetted command inside the per-session Plane O docker sandbox. " +
    "Every constructed argv carries the full O-P3 flag set (--cap-drop ALL, --no-new-privileges, " +
    "--user 1000:1000, --cpus 2, --memory 4g, --pids-limit 1024, --read-only-tmpfs, " +
    "--tmpfs /tmp:size=512m, and --network none by default). The bound repo is mounted read-only " +
    "at /src; /work is the session-writable scratch area. Defaults to dry_run: true. " +
    "Stdout/stderr stream to <session>/repo-runs/<run_id>.{stdout,stderr} capped at 16 MB each; " +
    "the JSONL ledger entry carries paths + sha256 hashes only — never raw bytes. " +
    "Refuses image_tag values that don't match the session-derived tag (O-D6).",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
        description: "Repo session target_domain derived by bob_init_repo_session.",
      },
      command: {
        type: "array",
        items: { type: "string" },
        description: "Command to execute inside the container, as a token array (e.g. [\"sh\", \"-lc\", \"...\"]). 1-64 tokens; each <= 2048 chars. When checkout is provided Bob materializes the checkout first and runs this command from that checkout.",
      },
      checkout: {
        type: "object",
        properties: {
          ref: {
            type: "string",
            description: "Local git ref or 7-64 hex object prefix already present in the bound repo history.",
          },
          kind: {
            type: "string",
            enum: ["upstream_fix", "pre_introduction", "self_patch"],
            description: "Differential checkout kind to materialize under a run-scoped /work checkout.",
          },
        },
        required: ["ref", "kind"],
        additionalProperties: false,
        description: "Optional S14 differential checkout provenance. Refuses shallow or absent local history before docker argv construction.",
      },
      dry_run: {
        type: "boolean",
        description: "When true (default), records the planned argv to repo-command-runs.jsonl without invoking docker.",
      },
      allow_network: {
        type: "boolean",
        description: "When true, attaches --network bridge + --dns 1.1.1.1 and threads HTTP(S)_PROXY via --env. Defaults to false (--network none).",
      },
      repo_mount_mode: {
        type: "string",
        enum: ["read_only", "read_write"],
        description: "How /src is mounted. Defaults to read_only. Differential checkout runs require read_only.",
      },
      image_tag: {
        type: "string",
        description: "Optional explicit image tag. Must match the session's derived bob-oss-<target_domain>:<repo_hash> tag (O-D6).",
      },
      timeout_ms: {
        type: "integer",
        minimum: 1000,
        maximum: 600000,
        description: "docker run timeout in milliseconds. Defaults to 300000 (5m); max 600000 (10m).",
      },
      replay_context: {
        type: "object",
        description: "Optional dispatch context (wave, agent, surface_id, task_lens, technique_pack_id, purpose, operator_note) recorded with the run for evaluator correlation.",
      },
      blocked_harness_run_id: {
        type: "string",
        description: "Optional cross-reference to a wave handoff blocked_harness_runs[] entry being resolved by this run.",
      },
      egress_profile: {
        type: "string",
        description: "Optional egress profile name override. Defaults to the session's bound profile.",
      },
    },
    required: ["target_domain", "command"],
  },
  handler,
  // Per O.4 §9: evaluator-shared, verifier, evidence. Orchestrator
  // dispatches but does NOT execute docker.
  role_bundles: ["evaluator-shared", "verifier", "evidence"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [
    "repo-command-runs.jsonl",
    "repo-runs/",
    "repo-work/",
    "repo-checkouts/",
  ],
});
