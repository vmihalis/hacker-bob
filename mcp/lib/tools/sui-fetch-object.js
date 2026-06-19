"use strict";

const { getObject, getLatestCheckpointSequenceNumber } = require("../sui-client.js");

async function handler(args) {
  const result = await getObject({
    network: args.network,
    objectId: args.object_id,
    options: args.options,
    endpoints: args.endpoints,
  });
  // sui_getObject returns { data: { objectId, version, digest, type, owner, content, ...} }
  let blockUsed = null;
  try {
    const checkpoint = await getLatestCheckpointSequenceNumber({ network: args.network, endpoints: args.endpoints });
    if (typeof checkpoint.result === "string" && checkpoint.result) {
      const parsed = Number(checkpoint.result);
      if (Number.isFinite(parsed)) blockUsed = parsed;
    } else if (typeof checkpoint.result === "number" && Number.isFinite(checkpoint.result)) {
      blockUsed = checkpoint.result;
    }
  } catch {
    // ignore — checkpoint reference is opportunistic
  }

  const data = result.result && result.result.data ? result.result.data : null;
  // Owner may be a string ("Immutable", "Shared") or an object ({ AddressOwner, ObjectOwner }).
  // Type is fully-qualified Move type, e.g. "0x2::coin::Coin<0x2::sui::SUI>".
  return JSON.stringify({
    network: args.network,
    object_id: args.object_id,
    block_used: blockUsed,
    endpoint_used: result.endpoint,
    object: data ? {
      object_id: typeof data.objectId === "string" ? data.objectId : null,
      version: typeof data.version === "string" ? data.version : null,
      digest: typeof data.digest === "string" ? data.digest : null,
      type: typeof data.type === "string" ? data.type : null,
      owner: data.owner !== undefined ? data.owner : null,
      content: data.content !== undefined ? data.content : null,
      previous_transaction: typeof data.previousTransaction === "string" ? data.previousTransaction : null,
      storage_rebate: typeof data.storageRebate === "string" ? data.storageRebate : null,
    } : null,
  });
}

module.exports = Object.freeze({
  name: "bob_sui_fetch_object",
  aliases: ["bounty_sui_fetch_object"],
  description: "Read-only Sui sui_getObject through the DNS-pinned direct public HTTPS RPC fallback ladder. DNS-private/private endpoints and egress_profile proxy routing are unsupported by default; localnet RPC has no default endpoint and endpoint_used is redacted. Returns the object's owner (Immutable / Shared / AddressOwner / ObjectOwner), Move type, content fields, and previous transaction digest, plus the latest checkpoint sequence the read is anchored against. Used by Sui evaluators to detect object_ownership_violation, capability_leakage, and dynamic-field unauthorized access before constructing impact hypotheses.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
      "network": { "type": "string", "enum": ["mainnet", "testnet", "devnet", "localnet"] },
      "object_id": { "type": "string", "pattern": "^0x[a-fA-F0-9]{1,64}$" },
      "options": {
        "type": "object",
        "description": "Optional sui_getObject options. Defaults: {showType, showOwner, showPreviousTransaction, showContent, showStorageRebate}=true; {showDisplay, showBcs}=false."
      },
      "endpoints": { "type": "array", "items": { "type": "string", "format": "uri" }, "maxItems": 8 }
    },
    "required": ["target_domain", "network", "object_id"]
  },
  handler,
  role_bundles: ["evaluator-move", "verifier", "evidence"],
  mutating: false,
  global_preapproval: true,
  network_access: true,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
