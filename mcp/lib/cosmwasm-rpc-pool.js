"use strict";

const {
  isHttpsUrl,
  isPrivateHost,
  isPublicHttpsUrl,
  normalizeRpcEndpointList,
  redactRpcEndpoint,
  splitRpcEndpointEnv,
} = require("./sc-egress-policy.js");

// Public CosmWasm REST API fallback ladder per network.
//
// Each Cosmos SDK chain hosts:
//   - Tendermint RPC (port 26657 by convention) for chain-level queries
//   - REST/LCD API (port 1317) for high-level queries including
//     /cosmwasm/wasm/v1/contract/{address} and /cosmwasm/wasm/v1/contract/{address}/smart/{base64-msg}
//
// Bob's cosmwasm read tools and runner use the REST API because that's where
// CosmWasm-specific queries live. The endpoint URL is the LCD/REST root —
// the client appends "/cosmwasm/wasm/v1/..." paths.
//
// Override per network via env: BOB_COSMWASM_RPCS_<NETWORK>=url1,url2
// Override globally via env: BOB_COSMWASM_RPCS_DEFAULT=url1,url2
const DEFAULT_PUBLIC_RPC_LADDER = Object.freeze({
  "osmosis": Object.freeze([
    "https://lcd.osmosis.zone",
    "https://osmosis-rest.publicnode.com",
    "https://osmosis-api.polkachu.com",
  ]),
  "juno": Object.freeze([
    "https://juno-api.polkachu.com",
    "https://lcd.juno.basementnodes.ca",
  ]),
  "neutron": Object.freeze([
    "https://rest-kralum.neutron-1.neutron.org",
    "https://neutron-api.polkachu.com",
  ]),
  "archway": Object.freeze([
    "https://api.mainnet.archway.io",
    "https://archway-api.polkachu.com",
  ]),
  "sei": Object.freeze([
    "https://sei-rest.brocha.in",
    "https://rest.sei-apis.com",
  ]),
  "stargaze": Object.freeze([
    "https://rest.stargaze-apis.com",
    "https://stargaze-api.polkachu.com",
  ]),
  "terra": Object.freeze([
    "https://phoenix-lcd.terra.dev",
    "https://terra-api.polkachu.com",
  ]),
  "kava": Object.freeze([
    "https://api.data.kava.io",
    "https://kava-api.polkachu.com",
  ]),
  // localnet has no public default; private/localnet RPC is unsupported by
  // default policy until a per-family opt-in policy exists.
  "localnet": Object.freeze([]),
});

function envKeyForNetwork(network) {
  return `BOB_COSMWASM_RPCS_${String(network).toUpperCase().replace(/-/g, "_")}`;
}

function envOverride(network) {
  if (String(network).trim() === "localnet") return [];
  const key = envKeyForNetwork(network);
  return splitRpcEndpointEnv(process.env[key]);
}

function defaultOverride() {
  return splitRpcEndpointEnv(process.env.BOB_COSMWASM_RPCS_DEFAULT);
}

function resolveCosmwasmRpcEndpoints(network) {
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

function summarizeCosmwasmPoolForBrief(network) {
  const normalizedNetwork = typeof network === "string" ? network.trim() : null;
  if (!normalizedNetwork) {
    return { chain_family: "cosmwasm", network: null, endpoints: [], note: "Set chain_id (network) on the surface for a populated RPC pool." };
  }
  let endpoints;
  try {
    endpoints = resolveCosmwasmRpcEndpoints(normalizedNetwork);
  } catch {
    endpoints = [];
  }
  const trimmed = endpoints.slice(0, 6).map(redactRpcEndpoint);
  const note = endpoints.length === 0
    ? `No default REST ladder for network ${normalizedNetwork}. Evaluators must pass 'endpoints' explicitly to bob_cosmwasm_* tools and 'fork_urls' to bob_cosmwasm_run. Operators can set ${envKeyForNetwork(normalizedNetwork)}=url1,url2 in the MCP server env (before launch) for a default.`
    : null;
  return {
    chain_family: "cosmwasm",
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
  resolveCosmwasmRpcEndpoints,
  summarizeCosmwasmPoolForBrief,
};
