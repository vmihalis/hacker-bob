"use strict";

const { ethGetStorageAt } = require("../evm-client.js");

async function handler(args) {
  const result = await ethGetStorageAt({
    chainId: args.chain_id,
    address: args.address,
    slot: args.slot,
    block: args.block,
    endpoints: args.endpoints,
  });
  return JSON.stringify({
    chain_id: Number(args.chain_id),
    address: args.address,
    slot: args.slot,
    block: args.block || "latest",
    endpoint_used: result.endpoint,
    value: result.result,
  });
}

module.exports = Object.freeze({
  name: "bob_evm_storage_read",
  aliases: ["bounty_evm_storage_read"],
  description: "Read a storage slot at a contract address (eth_getStorageAt) through the DNS-pinned direct public HTTPS RPC fallback ladder. DNS-private/private endpoints and egress_profile proxy routing are unsupported by default; endpoint_used is redacted. Used to inspect implementation slots, role mappings, paused flags, and other state that isn't exposed through ABI getters.",
  inputSchema: {
    "type": "object",
    "properties": {
      "chain_id": { "type": "integer", "minimum": 1 },
      "address": { "type": "string", "pattern": "^0x[0-9a-fA-F]{40}$" },
      "slot": { "type": "string", "pattern": "^0x[0-9a-fA-F]{1,64}$" },
      "block": {
        "oneOf": [
          { "type": "integer", "minimum": 0 },
          { "type": "string" }
        ]
      },
      "endpoints": { "type": "array", "items": { "type": "string", "format": "uri" }, "maxItems": 8 }
    },
    "required": ["chain_id", "address", "slot"]
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
