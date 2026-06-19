"use strict";

const {
  isHttpsUrl,
  isPrivateHost,
  isPublicHttpsUrl,
  normalizeRpcEndpointList,
  redactRpcEndpoint,
  splitRpcEndpointEnv,
} = require("./sc-egress-policy.js");

// Public Aptos REST API fallback ladder per network.
//
// Override per network via env: BOB_APTOS_RPCS_<NETWORK>=url1,url2
//   - <NETWORK> is uppercased. e.g. mainnet → BOB_APTOS_RPCS_MAINNET.
// Override globally via env: BOB_APTOS_RPCS_DEFAULT=url1,url2 (appended after
//                            network-specific overrides if no network match)
//
// NOTE: Aptos uses a REST API, not JSON-RPC. The endpoint URLs include the
// /v1 path prefix already because every Aptos REST request begins with /v1.
const DEFAULT_PUBLIC_RPC_LADDER = Object.freeze({
  // Aptos mainnet (chain_id=1, but we key by network name)
  "mainnet": Object.freeze([
    "https://api.mainnet.aptoslabs.com/v1",
    "https://fullnode.mainnet.aptoslabs.com/v1",
  ]),
  // Aptos testnet (chain_id=2)
  "testnet": Object.freeze([
    "https://api.testnet.aptoslabs.com/v1",
    "https://fullnode.testnet.aptoslabs.com/v1",
  ]),
  // Aptos devnet (chain_id rotates daily — operators must point a network
  // override at the current daily endpoint when verifying devnet bugs.)
  "devnet": Object.freeze([
    "https://api.devnet.aptoslabs.com/v1",
    "https://fullnode.devnet.aptoslabs.com/v1",
  ]),
});

function envKeyForNetwork(network) {
  return `BOB_APTOS_RPCS_${String(network).toUpperCase().replace(/-/g, "_")}`;
}

function envOverride(network) {
  if (String(network).trim() === "localnet") return [];
  const key = envKeyForNetwork(network);
  return splitRpcEndpointEnv(process.env[key]);
}

function defaultOverride() {
  return splitRpcEndpointEnv(process.env.BOB_APTOS_RPCS_DEFAULT);
}

function resolveAptosRpcEndpoints(network) {
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

function summarizeAptosPoolForBrief(network) {
  const normalizedNetwork = typeof network === "string" ? network.trim() : null;
  if (!normalizedNetwork) {
    return { chain_family: "aptos", network: null, endpoints: [], note: "Set chain_id (network) on the surface for a populated RPC pool." };
  }
  let endpoints;
  try {
    endpoints = resolveAptosRpcEndpoints(normalizedNetwork);
  } catch {
    endpoints = [];
  }
  const trimmed = endpoints.slice(0, 6).map(redactRpcEndpoint);
  const note = endpoints.length === 0
    ? `No default RPC ladder for network ${normalizedNetwork}. Evaluators must pass 'endpoints' explicitly to bob_aptos_* tools and 'fork_urls' to bob_aptos_run. Operators can set ${envKeyForNetwork(normalizedNetwork)}=url1,url2 in the MCP server env (before launch) for a default.`
    : null;
  return {
    chain_family: "aptos",
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
  resolveAptosRpcEndpoints,
  summarizeAptosPoolForBrief,
};
