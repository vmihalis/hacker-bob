"use strict";

const { getAccountModule, getLedgerInfo } = require("../aptos-client.js");

async function handler(args) {
  const result = await getAccountModule({
    network: args.network,
    address: args.address,
    moduleName: args.module_name,
    endpoints: args.endpoints,
    ledgerVersion: args.ledger_version != null ? args.ledger_version : null,
  });
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
      // ignore
    }
  }

  // Aptos REST module response: { bytecode: "0x...", abi: { address, name, friends, exposed_functions, structs } }
  const moduleResp = result.result;
  return JSON.stringify({
    network: args.network,
    address: args.address,
    module_name: args.module_name,
    block_used: blockUsed,
    endpoint_used: result.endpoint,
    module: moduleResp && typeof moduleResp === "object" ? {
      bytecode_length: typeof moduleResp.bytecode === "string"
        ? Math.max(0, (moduleResp.bytecode.length - 2) / 2)
        : null,
      abi: moduleResp.abi === undefined ? null : moduleResp.abi,
    } : null,
  });
}

module.exports = Object.freeze({
  name: "bob_aptos_fetch_module",
  aliases: ["bounty_aptos_fetch_module"],
  description: "Read-only Aptos REST GET /accounts/{address}/module/{module_name} through the DNS-pinned direct public HTTPS REST fallback ladder. DNS-private/private endpoints and egress_profile proxy routing are unsupported by default; endpoint_used is redacted. Returns the module's ABI (functions, structs, friends) and bytecode length plus the ledger_version the read was anchored at. Used by Aptos evaluators to enumerate exposed entry functions, capability types, and friend relationships before constructing impact hypotheses.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
      "network": { "type": "string", "enum": ["mainnet", "testnet", "devnet"] },
      "address": { "type": "string", "pattern": "^0x[a-fA-F0-9]{1,64}$" },
      "module_name": { "type": "string", "minLength": 1, "maxLength": 200 },
      "ledger_version": { "type": "integer", "minimum": 0 },
      "endpoints": { "type": "array", "items": { "type": "string", "format": "uri" }, "maxItems": 8 }
    },
    "required": ["target_domain", "network", "address", "module_name"]
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
