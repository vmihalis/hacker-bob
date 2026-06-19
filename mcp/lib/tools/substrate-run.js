"use strict";

const { runSubstrateTest, DEFAULT_TIMEOUT_MS } = require("../substrate-runner.js");
const { REPLAY_CONTEXT_SCHEMA } = require("./replay-context-schema.js");

async function handler(args) {
  const result = await runSubstrateTest({
    workdir: args.harness_path,
    matchTest: args.match_test || null,
    network: args.network || null,
    forkBlock: args.fork_block != null ? args.fork_block : null,
    forkUrls: Array.isArray(args.fork_urls) ? args.fork_urls : null,
    extraArgs: Array.isArray(args.extra_args) ? args.extra_args : [],
    timeoutMs: args.timeout_ms || DEFAULT_TIMEOUT_MS,
  });
  return JSON.stringify(result);
}

module.exports = Object.freeze({
  name: "bob_substrate_run",
  aliases: ["bounty_substrate_run"],
  description: "Run `cargo test --exact <match_test>` on a local ink! contract harness, optionally pinned to a substrate network for harnesses that opt into mainnet-clone fixtures via BOB_SUBSTRATE_FORK_URL (e.g., chopsticks-fork or substrate-contracts-node replicas). Forks use direct public HTTPS RPC endpoints from explicit fork_urls, env overrides, or the supplied network ladder; DNS-private/private endpoints and egress_profile proxy routing are unsupported by default, and localnet RPC has no default endpoint. Endpoint filtering is preflight-only handoff; Bob does not DNS-pin the downstream cargo/harness socket. On RPC failure the result reports reason: rpc_unreachable or a no_fork_endpoints* reason plus redacted fork_attempts[]/rpc_policy_rejections[] so the evaluator can record blocked_harness_runs[] and set surface_status: partial. Returns structured per-test pass/fail parsed from cargo test output (test ... ok|FAILED|ignored). Requires `cargo` in PATH on the user's machine; if absent, returns reason: substrate_not_in_path. Subprocess hard-killed at timeout (default 90s, max 600s).",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
      "harness_path": { "type": "string", "minLength": 1 },
      "match_test": { "type": "string", "minLength": 1, "maxLength": 200 },
      "network": { "type": "string", "enum": ["polkadot", "kusama", "astar", "shiden", "rococo", "westend", "localnet"] },
      "fork_block": { "type": "integer", "minimum": 0 },
      "fork_urls": { "type": "array", "items": { "type": "string", "format": "uri" }, "maxItems": 8 },
      "extra_args": { "type": "array", "items": { "type": "string", "minLength": 1, "maxLength": 200 }, "maxItems": 12 },
      "timeout_ms": { "type": "integer", "minimum": 5000, "maximum": 600000 },
      "replay_context": REPLAY_CONTEXT_SCHEMA
    },
    "required": ["target_domain", "harness_path", "match_test"]
  },
  handler,
  role_bundles: ["evaluator-substrate", "verifier", "evidence"],
  mutating: false,
  global_preapproval: false,
  network_access: true,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
