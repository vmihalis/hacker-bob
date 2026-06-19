"use strict";

const { querySmart, getLatestBlock } = require("../cosmwasm-client.js");

async function handler(args) {
  // CosmWasm smart queries take a base64-encoded JSON message. We accept
  // either a JSON object (encoded server-side) or a pre-encoded base64
  // string. Evaluators/verifiers usually pass the JSON form for clarity.
  const queryMsg = args.query_msg != null ? args.query_msg
    : (typeof args.query_msg_base64 === "string" ? args.query_msg_base64 : null);
  if (queryMsg == null) {
    throw new Error("Either query_msg (object) or query_msg_base64 (string) is required");
  }
  const result = await querySmart({
    network: args.network,
    address: args.address,
    queryMsg,
    endpoints: args.endpoints,
  });

  let blockUsed = null;
  if (typeof result.block_height_used === "string" && result.block_height_used) {
    const parsed = Number(result.block_height_used);
    if (Number.isFinite(parsed)) blockUsed = parsed;
  }
  if (blockUsed == null) {
    try {
      const latest = await getLatestBlock({ network: args.network, endpoints: args.endpoints });
      const heightStr = latest.result && latest.result.block && latest.result.block.header && latest.result.block.header.height;
      if (typeof heightStr === "string") {
        const parsed = Number(heightStr);
        if (Number.isFinite(parsed)) blockUsed = parsed;
      }
    } catch {
      // ignore — opportunistic
    }
  }

  // Smart query response shape: { data: <base64-or-json> }
  const data = result.result && result.result.data !== undefined ? result.result.data : null;
  return JSON.stringify({
    network: args.network,
    address: args.address,
    block_used: blockUsed,
    endpoint_used: result.endpoint,
    data,
  });
}

module.exports = Object.freeze({
  name: "bob_cosmwasm_smart_query",
  aliases: ["bounty_cosmwasm_smart_query"],
  description: "Read-only CosmWasm smart query GET /cosmwasm/wasm/v1/contract/{address}/smart/{base64-msg} through the DNS-pinned direct public HTTPS REST fallback ladder. DNS-private/private endpoints and egress_profile proxy routing are unsupported by default; localnet REST has no default endpoint and endpoint_used is redacted. Evaluators and verifiers use this to inspect contract-defined query entrypoints (admin, balance, config, owner, etc.) at current state without re-running the harness. Verifiers query the same balance / authority / nonce slots before and after a fresh-fork run to confirm the bug actually moved value rather than a runtime panic / view-only.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
      "network": { "type": "string", "enum": ["osmosis", "juno", "neutron", "archway", "sei", "stargaze", "terra", "kava", "localnet"] },
      "address": { "type": "string", "minLength": 8, "maxLength": 90 },
      "query_msg": { "type": "object", "description": "Smart query message as a JSON object (e.g., {\"balance\":{\"address\":\"osmo1...\"}}). Encoded to base64 server-side." },
      "query_msg_base64": { "type": "string", "minLength": 1, "maxLength": 8192, "description": "Pre-encoded base64 query message. Use when the JSON form is awkward." },
      "endpoints": { "type": "array", "items": { "type": "string", "format": "uri" }, "maxItems": 8 }
    },
    "required": ["target_domain", "network", "address"]
  },
  handler,
  role_bundles: ["evaluator-cosmwasm", "verifier", "evidence"],
  mutating: false,
  global_preapproval: true,
  network_access: true,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
