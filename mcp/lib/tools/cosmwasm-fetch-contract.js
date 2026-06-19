"use strict";

const { getContractInfo, getLatestBlock } = require("../cosmwasm-client.js");

async function handler(args) {
  const result = await getContractInfo({
    network: args.network,
    address: args.address,
    endpoints: args.endpoints,
  });
  // Best-effort head-block lookup so the verifier can record "verified at
  // block N on chain X" without a follow-up. The cosmwasm REST endpoint
  // populates Grpc-Metadata-X-Cosmos-Block-Height when available; fall back
  // to /blocks/latest if not.
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
      // ignore — block reference is opportunistic
    }
  }

  // The /cosmwasm/wasm/v1/contract/{address} response shape:
  //   { address, contract_info: { code_id, creator, admin, label, created, ibc_port_id, extension } }
  const contractInfo = result.result && result.result.contract_info ? result.result.contract_info : null;
  return JSON.stringify({
    network: args.network,
    address: args.address,
    block_used: blockUsed,
    endpoint_used: result.endpoint,
    contract: contractInfo ? {
      code_id: contractInfo.code_id != null ? Number(contractInfo.code_id) : null,
      creator: typeof contractInfo.creator === "string" ? contractInfo.creator : null,
      admin: typeof contractInfo.admin === "string" ? contractInfo.admin : null,
      label: typeof contractInfo.label === "string" ? contractInfo.label : null,
      ibc_port_id: typeof contractInfo.ibc_port_id === "string" ? contractInfo.ibc_port_id : null,
    } : null,
  });
}

module.exports = Object.freeze({
  name: "bob_cosmwasm_fetch_contract",
  aliases: ["bounty_cosmwasm_fetch_contract"],
  description: "Read-only GET /cosmwasm/wasm/v1/contract/{address} through the DNS-pinned direct public HTTPS CosmWasm REST fallback ladder. DNS-private/private endpoints and egress_profile proxy routing are unsupported by default; localnet REST has no default endpoint and endpoint_used is redacted. Returns the contract's code_id, creator, admin, and label, plus the head block height for the verified-at reference line. Evaluators use this to identify the admin (migration-key holder) and code_id (WASM blob hash); verifiers use admin + code_id to confirm the contract hasn't been migrated since the evaluator recorded the bug. A 404 from this endpoint is the chain_id/chain_family disambiguation gate — if the bech32 address doesn't resolve on the claimed network, the verifier denies the finding.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
      "network": { "type": "string", "enum": ["osmosis", "juno", "neutron", "archway", "sei", "stargaze", "terra", "kava", "localnet"] },
      "address": { "type": "string", "minLength": 8, "maxLength": 90, "description": "bech32-encoded contract address (e.g., osmo1..., juno1...). Validated via the public CosmWasm REST API." },
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
