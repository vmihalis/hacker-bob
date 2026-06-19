"use strict";

const { getStorage, getHeader } = require("../substrate-client.js");

async function handler(args) {
  const result = await getStorage({
    network: args.network,
    storageKey: args.storage_key,
    blockHash: args.block_hash || null,
    endpoints: args.endpoints,
  });
  // Best-effort header lookup so the verifier can record "verified at block N"
  // without a follow-up call. Substrate doesn't expose a "block-of-the-read"
  // header on the storage RPC response itself, so we fetch the header
  // separately at "current head" granularity.
  let blockUsed = null;
  let parentHash = null;
  try {
    const header = await getHeader({ network: args.network, blockHash: null, endpoints: args.endpoints });
    if (header.result && typeof header.result === "object") {
      const numHex = header.result.number;
      if (typeof numHex === "string" && numHex.startsWith("0x")) {
        const n = parseInt(numHex.slice(2), 16);
        if (Number.isFinite(n)) blockUsed = n;
      }
      parentHash = typeof header.result.parentHash === "string" ? header.result.parentHash : null;
    }
  } catch {
    // ignore — block reference is opportunistic
  }
  return JSON.stringify({
    network: args.network,
    storage_key: args.storage_key,
    block_used: blockUsed,
    parent_hash: parentHash,
    endpoint_used: result.endpoint,
    storage_value: result.result,
  });
}

module.exports = Object.freeze({
  name: "bob_substrate_fetch_storage",
  aliases: ["bounty_substrate_fetch_storage"],
  description: "Read-only state_getStorage(key, blockHash?) call against the DNS-pinned direct public HTTPS substrate JSON-RPC fallback ladder. DNS-private/private endpoints and egress_profile proxy routing are unsupported by default; localnet RPC has no default endpoint and endpoint_used is redacted. Returns the raw SCALE-encoded storage value at the supplied key, plus the head block number for the verified-at reference line. Evaluators and verifiers use this to confirm pallet_contracts.ContractInfoOf entries (owner, code_hash, storage deposit) and validator/governance capability state without re-running the full harness.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
      "network": { "type": "string", "enum": ["polkadot", "kusama", "astar", "shiden", "rococo", "westend", "localnet"] },
      "storage_key": { "type": "string", "pattern": "^0x[a-fA-F0-9]+$", "minLength": 4, "maxLength": 256, "description": "0x-prefixed hex storage key (Twox128(pallet) + Twox128(item) + optional Twox64Concat(account_id) etc.)" },
      "block_hash": { "type": "string", "pattern": "^0x[a-fA-F0-9]{64}$", "description": "Optional block hash to read at; omit for current head." },
      "endpoints": { "type": "array", "items": { "type": "string", "format": "uri" }, "maxItems": 8 }
    },
    "required": ["target_domain", "network", "storage_key"]
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
