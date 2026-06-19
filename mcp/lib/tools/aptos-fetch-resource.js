"use strict";

const { getAccountResource, getLedgerInfo } = require("../aptos-client.js");

async function handler(args) {
  const result = await getAccountResource({
    network: args.network,
    address: args.address,
    resourceType: args.resource_type,
    endpoints: args.endpoints,
    ledgerVersion: args.ledger_version != null ? args.ledger_version : null,
  });
  // Resolve a current ledger version reference for the verified-at line.
  // Best-effort; the GET /<base> root response carries ledger_version too.
  let blockUsed = null;
  if (typeof result.ledger_version_used === "string" && result.ledger_version_used) {
    const parsed = Number(result.ledger_version_used);
    if (Number.isFinite(parsed)) blockUsed = parsed;
  }
  if (blockUsed == null) {
    try {
      const ledger = await getLedgerInfo({ network: args.network, endpoints: args.endpoints });
      const ledgerVersionStr = ledger.result && ledger.result.ledger_version;
      if (typeof ledgerVersionStr === "string") {
        const parsed = Number(ledgerVersionStr);
        if (Number.isFinite(parsed)) blockUsed = parsed;
      }
    } catch {
      // ignore — version reference is opportunistic
    }
  }

  // Aptos REST returns a Resource object: { type: "0x1::module::Struct<...>", data: { ... } }
  const resource = result.result;
  return JSON.stringify({
    network: args.network,
    address: args.address,
    resource_type: args.resource_type,
    block_used: blockUsed,
    endpoint_used: result.endpoint,
    resource: resource && typeof resource === "object" ? {
      type: typeof resource.type === "string" ? resource.type : null,
      data: resource.data === undefined ? null : resource.data,
    } : null,
  });
}

module.exports = Object.freeze({
  name: "bob_aptos_fetch_resource",
  aliases: ["bounty_aptos_fetch_resource"],
  description: "Read-only Aptos REST GET /accounts/{address}/resource/{resource_type} through the DNS-pinned direct public HTTPS REST fallback ladder. DNS-private/private endpoints and egress_profile proxy routing are unsupported by default; endpoint_used is redacted. Returns the deserialized Move resource value plus the ledger_version the read was anchored at. Used by Aptos evaluators to inspect on-chain capability tokens, ownership records, treasury balances, and module config before constructing impact hypotheses.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
      "network": { "type": "string", "enum": ["mainnet", "testnet", "devnet"] },
      "address": { "type": "string", "pattern": "^0x[a-fA-F0-9]{1,64}$" },
      "resource_type": { "type": "string", "minLength": 1, "maxLength": 512 },
      "ledger_version": { "type": "integer", "minimum": 0 },
      "endpoints": { "type": "array", "items": { "type": "string", "format": "uri" }, "maxItems": 8 }
    },
    "required": ["target_domain", "network", "address", "resource_type"]
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
