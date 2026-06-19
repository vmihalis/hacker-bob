"use strict";

const { runHalmos, DEFAULT_TIMEOUT_MS } = require("../halmos-runner.js");

async function handler(args) {
  const result = await runHalmos({
    workdir: args.harness_path,
    matchTest: args.match_test || null,
    matchContract: args.match_contract || null,
    extraArgs: Array.isArray(args.extra_args) ? args.extra_args : [],
    timeoutMs: args.timeout_ms || DEFAULT_TIMEOUT_MS,
  });
  return JSON.stringify(result);
}

module.exports = Object.freeze({
  name: "bob_halmos_run",
  aliases: ["bounty_halmos_run"],
  description: "Run halmos symbolic execution over a Foundry-shape test function. Halmos explores all reachable states up to a bounded depth, surfacing counterexamples that concrete fuzzing misses (signature replay variants, oracle staleness boundaries, donation/rounding edge cases). Halmos is a downstream subprocess; Bob scrubs inherited proxy/RPC/secret env but does not DNS-pin any socket it opens. Requires `halmos` in PATH (Python tool: pip install halmos). Subprocess hard-killed at timeout (default 120s, max 600s). extra_args allowlisted to safe halmos flags only — no FFI, no solver-command override.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
      "harness_path": { "type": "string", "minLength": 1 },
      "match_test": { "type": "string", "minLength": 1, "maxLength": 200 },
      "match_contract": { "type": "string", "minLength": 1, "maxLength": 200 },
      "extra_args": { "type": "array", "items": { "type": "string", "minLength": 1, "maxLength": 200 }, "maxItems": 12 },
      "timeout_ms": { "type": "integer", "minimum": 5000, "maximum": 600000 }
    },
    "required": ["target_domain", "harness_path"]
  },
  handler,
  role_bundles: ["evaluator-evm", "verifier", "evidence"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
