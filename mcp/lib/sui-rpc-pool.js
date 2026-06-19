"use strict";

const {
  isHttpsUrl,
  isPrivateHost,
  isPublicHttpsUrl,
  normalizeRpcEndpointList,
  redactRpcEndpoint,
  splitRpcEndpointEnv,
} = require("./sc-egress-policy.js");

// Public Sui JSON-RPC fallback ladder per network.
//
// Override per network via env: BOB_SUI_RPCS_<NETWORK>=url1,url2
// Override globally via env: BOB_SUI_RPCS_DEFAULT=url1,url2
const DEFAULT_PUBLIC_RPC_LADDER = Object.freeze({
  "mainnet": Object.freeze([
    "https://fullnode.mainnet.sui.io:443",
    "https://sui-mainnet.public.blastapi.io",
    "https://sui-mainnet-rpc.publicnode.com",
  ]),
  "testnet": Object.freeze([
    "https://fullnode.testnet.sui.io:443",
    "https://sui-testnet.public.blastapi.io",
  ]),
  "devnet": Object.freeze([
    "https://fullnode.devnet.sui.io:443",
  ]),
  // localnet has no public default; private/localnet RPC is unsupported by
  // default policy until a per-family opt-in policy exists.
  "localnet": Object.freeze([]),
});

function envKeyForNetwork(network) {
  return `BOB_SUI_RPCS_${String(network).toUpperCase().replace(/-/g, "_")}`;
}

function envOverride(network) {
  if (String(network).trim() === "localnet") return [];
  const key = envKeyForNetwork(network);
  return splitRpcEndpointEnv(process.env[key]);
}

function defaultOverride() {
  return splitRpcEndpointEnv(process.env.BOB_SUI_RPCS_DEFAULT);
}

function resolveSuiRpcEndpoints(network) {
  if (typeof network !== "string" || !network.trim()) {
    throw new Error(`network must be a non-empty string, received: ${network}`);
  }
  const normalizedNetwork = network.trim();
  if (normalizedNetwork === "localnet") return [];
  const fromEnv = envOverride(normalizedNetwork);
  const defaults = DEFAULT_PUBLIC_RPC_LADDER[normalizedNetwork] || [];
  const fromDefaultEnv = defaultOverride();

  return normalizeRpcEndpointList([...fromEnv, ...defaults, ...fromDefaultEnv]).endpoints;
}

function summarizeSuiPoolForBrief(network) {
  const normalizedNetwork = typeof network === "string" ? network.trim() : null;
  if (!normalizedNetwork) {
    return { chain_family: "sui", network: null, endpoints: [], note: "Set chain_id (network) on the surface for a populated RPC pool." };
  }
  let endpoints;
  try {
    endpoints = resolveSuiRpcEndpoints(normalizedNetwork);
  } catch {
    endpoints = [];
  }
  const trimmed = endpoints.slice(0, 6).map(redactRpcEndpoint);
  const note = endpoints.length === 0
    ? `No default RPC ladder for network ${normalizedNetwork}. Evaluators must pass 'endpoints' explicitly to bob_sui_* tools and 'fork_urls' to bob_sui_run. Operators can set ${envKeyForNetwork(normalizedNetwork)}=url1,url2 in the MCP server env (before launch) for a default.`
    : null;
  return {
    chain_family: "sui",
    network: normalizedNetwork,
    endpoints: trimmed,
    truncated: endpoints.length > trimmed.length,
    note,
  };
}

module.exports = {
  DEFAULT_PUBLIC_RPC_LADDER,
  envKeyForNetwork,
  isPrivateHost,
  isHttpsUrl,
  isPublicHttpsUrl,
  resolveSuiRpcEndpoints,
  summarizeSuiPoolForBrief,
};
