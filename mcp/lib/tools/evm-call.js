"use strict";

const { ethBlockNumber, ethCall } = require("../evm-client.js");

async function handler(args) {
  const result = await ethCall({
    chainId: args.chain_id,
    to: args.to,
    data: args.data,
    block: args.block,
    from: args.from || null,
    endpoints: args.endpoints,
  });
  // Resolve "latest" to a concrete block when the caller did not pin one. The
  // verifier needs a stable on-chain reference for the report (`verified at
  // block N`), and final-verifier prompt promises the call carries this.
  let blockUsed = args.block != null && args.block !== "latest" ? args.block : null;
  if (blockUsed == null) {
    try {
      const hexBlock = await ethBlockNumber({ chainId: args.chain_id, endpoints: args.endpoints });
      if (typeof hexBlock === "string" && /^0x[0-9a-fA-F]+$/.test(hexBlock)) {
        blockUsed = Number(BigInt(hexBlock));
      }
    } catch {
      // Best-effort: a follow-up RPC failure should not invalidate a
      // successful eth_call. Verifier prompt accepts blockUsed=null and
      // reasons "no stable block reference."
    }
  }
  return JSON.stringify({
    chain_id: Number(args.chain_id),
    to: args.to,
    data_length: typeof args.data === "string" ? args.data.length : 0,
    block: args.block || "latest",
    block_used: blockUsed,
    endpoint_used: result.endpoint,
    result: result.result,
  });
}

module.exports = Object.freeze({
  name: "bob_evm_call",
  aliases: ["bounty_evm_call"],
  description: "Read-only EVM eth_call against a contract through the DNS-pinned direct public HTTPS RPC fallback ladder. DNS-private/private endpoints and egress_profile proxy routing are unsupported by default; endpoint_used is redacted. Used by EVM evaluators to read on-chain state (role membership, configuration, oracle prices) before constructing impact hypotheses.",
  inputSchema: {
    "type": "object",
    "properties": {
      "chain_id": { "type": "integer", "minimum": 1 },
      "to": { "type": "string", "pattern": "^0x[0-9a-fA-F]{40}$" },
      "data": { "type": "string", "pattern": "^0x[0-9a-fA-F]*$" },
      "block": {
        "oneOf": [
          { "type": "integer", "minimum": 0 },
          { "type": "string" }
        ]
      },
      "from": { "type": "string", "pattern": "^0x[0-9a-fA-F]{40}$" },
      "endpoints": { "type": "array", "items": { "type": "string", "format": "uri" }, "maxItems": 8 }
    },
    "required": ["chain_id", "to", "data"]
  },
  handler,
  role_bundles: ["evaluator-evm", "verifier", "evidence"],
  mutating: false,
  global_preapproval: true,
  network_access: true,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
