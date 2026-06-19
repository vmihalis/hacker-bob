"use strict";

const { getNormalizedMoveModulesByPackage, getLatestCheckpointSequenceNumber } = require("../sui-client.js");

async function handler(args) {
  const result = await getNormalizedMoveModulesByPackage({
    network: args.network,
    packageId: args.package_id,
    endpoints: args.endpoints,
  });
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
    // ignore
  }

  // sui_getNormalizedMoveModulesByPackage returns { <module_name>: { fileFormatVersion, address, name, friends, structs, exposedFunctions } }
  const modules = result.result && typeof result.result === "object" ? result.result : null;
  const moduleNames = modules ? Object.keys(modules) : [];
  const moduleSummaries = moduleNames.slice(0, 100).map((name) => {
    const mod = modules[name];
    return {
      name,
      friends_count: Array.isArray(mod && mod.friends) ? mod.friends.length : 0,
      structs_count: mod && mod.structs && typeof mod.structs === "object" ? Object.keys(mod.structs).length : 0,
      exposed_functions_count: mod && mod.exposedFunctions && typeof mod.exposedFunctions === "object" ? Object.keys(mod.exposedFunctions).length : 0,
      // Function signatures are useful for entry-function enumeration. Cap to
      // the first 30 names to keep the brief bounded.
      exposed_function_names: mod && mod.exposedFunctions && typeof mod.exposedFunctions === "object"
        ? Object.keys(mod.exposedFunctions).slice(0, 30)
        : [],
    };
  });

  return JSON.stringify({
    network: args.network,
    package_id: args.package_id,
    block_used: blockUsed,
    endpoint_used: result.endpoint,
    modules_count: moduleNames.length,
    modules_truncated: moduleNames.length > moduleSummaries.length,
    modules: moduleSummaries,
  });
}

module.exports = Object.freeze({
  name: "bob_sui_fetch_package",
  aliases: ["bounty_sui_fetch_package"],
  description: "Read-only Sui sui_getNormalizedMoveModulesByPackage through the DNS-pinned direct public HTTPS RPC fallback ladder. DNS-private/private endpoints and egress_profile proxy routing are unsupported by default; localnet RPC has no default endpoint and endpoint_used is redacted. Returns a per-module ABI summary (friends, structs, exposed functions) for the package, plus the latest checkpoint sequence the read is anchored against. Used by Sui evaluators to enumerate entry functions, capability types, and friend relationships before constructing impact hypotheses.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
      "network": { "type": "string", "enum": ["mainnet", "testnet", "devnet", "localnet"] },
      "package_id": { "type": "string", "pattern": "^0x[a-fA-F0-9]{1,64}$" },
      "endpoints": { "type": "array", "items": { "type": "string", "format": "uri" }, "maxItems": 8 }
    },
    "required": ["target_domain", "network", "package_id"]
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
