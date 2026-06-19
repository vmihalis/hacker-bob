"use strict";

const { runAptosTest, DEFAULT_TIMEOUT_MS } = require("../aptos-runner.js");
const { REPLAY_CONTEXT_SCHEMA } = require("./replay-context-schema.js");

async function handler(args) {
  const result = await runAptosTest({
    workdir: args.harness_path,
    matchTest: args.match_test || null,
    network: args.network || null,
    forkVersion: args.fork_version != null ? args.fork_version : (args.fork_block != null ? args.fork_block : null),
    forkUrls: Array.isArray(args.fork_urls) ? args.fork_urls : null,
    extraArgs: Array.isArray(args.extra_args) ? args.extra_args : [],
    timeoutMs: args.timeout_ms || DEFAULT_TIMEOUT_MS,
  });
  return JSON.stringify(result);
}

module.exports = Object.freeze({
  name: "bob_aptos_run",
  aliases: ["bounty_aptos_run"],
  description: "Run aptos move test on a local Aptos Move package, optionally pinned to an Aptos network for harnesses that opt into mainnet-clone fixtures via BOB_APTOS_FORK_URL. Forks use direct public HTTPS REST endpoints from explicit fork_urls, env overrides, or the supplied network ladder; DNS-private/private endpoints and egress_profile proxy routing are unsupported by default. Endpoint filtering is preflight-only handoff; Bob does not DNS-pin the downstream Aptos CLI socket. On REST failure the result reports reason: rpc_unreachable or a no_fork_endpoints* reason plus redacted fork_attempts[]/rpc_policy_rejections[] so the evaluator can record blocked_harness_runs[] and set surface_status: partial. Returns structured per-test pass/fail parsed from the Move unit test output ([ PASS ]/[ FAIL ]/[ TIMEOUT ]). Requires `aptos` CLI in PATH on the user's machine; if absent, returns reason: aptos_not_in_path. Subprocess hard-killed at timeout (default 90s, max 600s).",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
      "harness_path": { "type": "string", "minLength": 1 },
      "match_test": { "type": "string", "minLength": 1, "maxLength": 200 },
      "network": { "type": "string", "enum": ["mainnet", "testnet", "devnet"] },
      "fork_version": { "type": "integer", "minimum": 0 },
      "fork_block": { "type": "integer", "minimum": 0, "description": "Alias for fork_version — accepted for symmetry with bob_foundry_run / bob_anchor_run." },
      "fork_urls": { "type": "array", "items": { "type": "string", "format": "uri" }, "maxItems": 8 },
      "extra_args": { "type": "array", "items": { "type": "string", "minLength": 1, "maxLength": 200 }, "maxItems": 12 },
      "timeout_ms": { "type": "integer", "minimum": 5000, "maximum": 600000 },
      "replay_context": REPLAY_CONTEXT_SCHEMA
    },
    "required": ["target_domain", "harness_path", "match_test"]
  },
  handler,
  role_bundles: ["evaluator-move", "verifier", "evidence"],
  mutating: false,
  global_preapproval: false,
  network_access: true,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
