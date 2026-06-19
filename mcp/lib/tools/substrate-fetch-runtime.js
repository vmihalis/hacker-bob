"use strict";

const { getRuntimeVersion, getSystemChain, getHeader } = require("../substrate-client.js");

async function handler(args) {
  // Pull runtime spec + chain name + head height in parallel; verifier prompts
  // use spec_version to confirm a recorded bug still applies under the current
  // runtime, and use system_chain as the cross-check that the RPC endpoint
  // serves the network the evaluator claimed (catches chain_id misroutes).
  const [runtimeRes, chainRes, headerRes] = await Promise.allSettled([
    getRuntimeVersion({ network: args.network, blockHash: args.block_hash || null, endpoints: args.endpoints }),
    getSystemChain({ network: args.network, endpoints: args.endpoints }),
    getHeader({ network: args.network, blockHash: null, endpoints: args.endpoints }),
  ]);

  let blockUsed = null;
  if (headerRes.status === "fulfilled" && headerRes.value && headerRes.value.result) {
    const numHex = headerRes.value.result.number;
    if (typeof numHex === "string" && numHex.startsWith("0x")) {
      const n = parseInt(numHex.slice(2), 16);
      if (Number.isFinite(n)) blockUsed = n;
    }
  }

  return JSON.stringify({
    network: args.network,
    runtime: runtimeRes.status === "fulfilled" ? (runtimeRes.value && runtimeRes.value.result) : null,
    runtime_error: runtimeRes.status === "rejected" ? String(runtimeRes.reason && runtimeRes.reason.message || runtimeRes.reason) : null,
    chain: chainRes.status === "fulfilled" ? (chainRes.value && chainRes.value.result) : null,
    chain_error: chainRes.status === "rejected" ? String(chainRes.reason && chainRes.reason.message || chainRes.reason) : null,
    block_used: blockUsed,
    endpoint_used: runtimeRes.status === "fulfilled" ? runtimeRes.value.endpoint : (chainRes.status === "fulfilled" ? chainRes.value.endpoint : null),
  });
}

module.exports = Object.freeze({
  name: "bob_substrate_fetch_runtime",
  aliases: ["bounty_substrate_fetch_runtime"],
  description: "Read-only state_getRuntimeVersion + system_chain + chain_getHeader against the DNS-pinned direct public HTTPS substrate JSON-RPC fallback ladder. DNS-private/private endpoints and egress_profile proxy routing are unsupported by default; localnet RPC has no default endpoint and endpoint_used is redacted. Returns spec_name, spec_version, transaction_version, the runtime API list, the chain identity string, and the current head block number. Verifiers use this as a sanity check before re-running a fresh-fork harness — a runtime upgrade since the evaluator recorded the bug means the verifier may be looking at a different runtime API than the harness was written against.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
      "network": { "type": "string", "enum": ["polkadot", "kusama", "astar", "shiden", "rococo", "westend", "localnet"] },
      "block_hash": { "type": "string", "pattern": "^0x[a-fA-F0-9]{64}$", "description": "Optional block hash to read runtime version at; omit for current head." },
      "endpoints": { "type": "array", "items": { "type": "string", "format": "uri" }, "maxItems": 8 }
    },
    "required": ["target_domain", "network"]
  },
  handler,
  role_bundles: ["evaluator-substrate", "verifier", "evidence"],
  mutating: false,
  global_preapproval: true,
  network_access: true,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
