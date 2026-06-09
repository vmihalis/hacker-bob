"use strict";

const { runInvariantForFinding } = require("../invariant-runner.js");
const { runFoundryTest, DEFAULT_TIMEOUT_MS } = require("../foundry-runner.js");

async function adapter(args) {
  const result = await runFoundryTest({
    workdir: args.harness_path,
    matchTest: args.match_test || null,
    matchContract: args.match_contract || null,
    chainId: args.chain_id || null,
    forkBlock: args.fork_block || null,
    forkUrls: Array.isArray(args.fork_urls) ? args.fork_urls : null,
    extraArgs: Array.isArray(args.extra_args) ? args.extra_args : [],
    timeoutMs: args.timeout_ms || DEFAULT_TIMEOUT_MS,
  });
  return result;
}

async function runInvariantForFindingHandler(args) {
  return runInvariantForFinding({
    target_domain: args.target_domain,
    finding: args.finding,
    template_id: args.template_id,
    slot_values: args.slot_values,
    harness_path: args.harness_path,
    foundry_run: adapter,
    chain_id: args.chain_id,
    fork_block: args.fork_block,
    fork_urls: args.fork_urls,
    extra_args: args.extra_args,
    timeout_ms: args.timeout_ms,
    run_id: args.run_id,
    dry_run: args.dry_run,
  });
}

module.exports = Object.freeze({
  name: "bob_run_invariant_for_finding",
  aliases: ["bounty_run_invariant_for_finding"],
  description:
    "Generate a single-function Foundry invariant test from an audit finding's vulnerability_class, write it into the supplied harness, run forge against it, and persist the result to invariant-runs.jsonl. The harness root, test/ directory, and test/bob-invariants output directory are resolved through realpath containment before writing; generated tests use an exclusive same-directory temp file plus atomic rename so pre-existing final-file symlinks are replaced, not followed. Result persistence rejects symlinked per-domain session directories under the resolved sessions root and replaces pre-existing symlinked or hard-linked invariant-runs.jsonl files without importing their target records. The corpus is bounded by the artifact read cap; if valid accumulated records would exceed it, newest records are retained and the response reports invariant_runs_retention. This is honest-harness/resolved-session-root containment and final-file symlink safety, not a guarantee against a malicious same-UID process replacing validated parent directories or final path entries during path-based read/write operations, or mutating already-open regular files outside Bob's cooperative session lock. Fork RPC inherits bob_foundry_run's direct public HTTPS policy: DNS-private/private/localnet endpoints and egress_profile proxy routing are unsupported by default, and endpoint evidence is redacted. Pass dry_run: true to preview the generated test without writing or running. Use after bob_query_audit_reports + bob_suggest_invariants when you want the runner to commit a specific template against a real harness.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      finding: {
        type: "object",
        description: "An audit-report finding enriched with the current Bob finding_id. Must include finding_id and vulnerability_class.",
        properties: {
          finding_id: { type: "string", pattern: "^F-[0-9]+$" },
          finding_hash: { type: "string" },
          title: { type: "string" },
          vulnerability_class: { type: "string" },
          description: { type: "string" },
        },
        required: ["finding_id", "vulnerability_class"],
        additionalProperties: true,
      },
      template_id: { type: "string", description: "Optional. Pin a specific template id; default is the first suggestion for the class." },
      slot_values: { type: "object", description: "Map of parameter_slot -> value (target_contract, vulnerable_function, etc.)." },
      harness_path: { type: "string", description: "Foundry harness root under the user home directory. The root, test/, and test/bob-invariants paths are realpath-validated to stay inside the harness before writing." },
      chain_id: { type: "integer", minimum: 1 },
      fork_block: {
        oneOf: [
          { type: "integer", minimum: 0 },
          { type: "string", pattern: "^[0-9]+$|^0x[0-9a-fA-F]+$" },
        ],
      },
      fork_urls: { type: "array", items: { type: "string", format: "uri" }, maxItems: 8 },
      extra_args: { type: "array", items: { type: "string", minLength: 1, maxLength: 200 }, maxItems: 12 },
      timeout_ms: { type: "integer", minimum: 5000, maximum: 300000 },
      run_id: { type: "string" },
      dry_run: { type: "boolean", description: "When true, returns the planned test source without writing files or invoking forge." },
    },
    required: ["target_domain", "finding", "harness_path"],
  },
  handler: runInvariantForFindingHandler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: true,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["invariant-runs.jsonl"],
});
