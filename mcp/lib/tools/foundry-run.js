"use strict";

const { runFoundryTest, MAX_TIMEOUT_MS, DEFAULT_TIMEOUT_MS } = require("../foundry-runner.js");
const { REPLAY_CONTEXT_SCHEMA } = require("./replay-context-schema.js");

async function handler(args) {
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
  return JSON.stringify(result);
}

module.exports = Object.freeze({
  name: "bob_foundry_run",
  aliases: ["bounty_foundry_run"],
  description: "Run forge test on a local Foundry harness, optionally pinned to a fork-url and fork-block-number. Forks use direct public HTTPS RPC endpoints from explicit fork_urls, env overrides, or the supplied chain_id ladder; DNS-private/private/localnet endpoints and egress_profile proxy routing are unsupported by default. Endpoint filtering is preflight-only handoff; Bob does not DNS-pin the downstream forge socket. On RPC failure the result reports reason: rpc_unreachable or a no_fork_endpoints* reason plus redacted fork_attempts[]/rpc_policy_rejections[] so the evaluator can record blocked_harness_runs[] and set surface_status: partial. Returns structured per-test pass/fail with gas, reason, and counterexamples (truncated). Requires `forge` in PATH on the user's machine; if absent, returns reason: forge_not_in_path. Subprocess hard-killed at timeout (default 60s, max 300s).",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
      "harness_path": { "type": "string", "minLength": 1 },
      "match_test": { "type": "string", "minLength": 1, "maxLength": 200 },
      "match_contract": { "type": "string", "minLength": 1, "maxLength": 200 },
      "chain_id": { "type": "integer", "minimum": 1 },
      "fork_block": {
        "oneOf": [
          { "type": "integer", "minimum": 0 },
          { "type": "string", "pattern": "^[0-9]+$|^0x[0-9a-fA-F]+$" }
        ]
      },
      "fork_urls": { "type": "array", "items": { "type": "string", "format": "uri" }, "maxItems": 8 },
      "extra_args": { "type": "array", "items": { "type": "string", "minLength": 1, "maxLength": 200 }, "maxItems": 12 },
      "timeout_ms": { "type": "integer", "minimum": 5000, "maximum": 300000 },
      "replay_context": REPLAY_CONTEXT_SCHEMA
    },
    "required": ["target_domain", "harness_path"]
  },
  handler,
  role_bundles: ["evaluator-evm", "verifier", "evidence"],
  mutating: false,
  global_preapproval: false,
  network_access: true,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
