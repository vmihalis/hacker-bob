"use strict";

const {
  isHttpsUrl,
  isPrivateHost,
  isPublicHttpsUrl,
  normalizeRpcEndpointList,
  redactRpcEndpoint,
  splitRpcEndpointEnv,
} = require("./sc-egress-policy.js");

// Public Substrate JSON-RPC fallback ladder per network.
//
// Substrate nodes accept JSON-RPC over WebSocket primarily; HTTP is supported
// on most public infrastructure for read-only methods (state_getStorage,
// chain_getBlock, system_chain). Bob's substrate read tools and runner use
// HTTP because subprocesses don't share a WS lifecycle. Operators with
// WS-only deployments must run a local proxy or set BOB_SUBSTRATE_RPCS_<NET>
// to an HTTP-reachable upstream.
//
// Override per network via env: BOB_SUBSTRATE_RPCS_<NETWORK>=url1,url2
// Override globally via env: BOB_SUBSTRATE_RPCS_DEFAULT=url1,url2
const DEFAULT_PUBLIC_RPC_LADDER = Object.freeze({
  "polkadot": Object.freeze([
    "https://rpc.polkadot.io",
    "https://polkadot-rpc.dwellir.com",
    "https://polkadot.api.onfinality.io/public",
  ]),
  "kusama": Object.freeze([
    "https://kusama-rpc.polkadot.io",
    "https://kusama-rpc.dwellir.com",
    "https://kusama.api.onfinality.io/public",
  ]),
  "astar": Object.freeze([
    "https://astar.api.onfinality.io/public",
    "https://astar-rpc.dwellir.com",
  ]),
  "shiden": Object.freeze([
    "https://shiden.api.onfinality.io/public",
    "https://shiden-rpc.dwellir.com",
  ]),
  "rococo": Object.freeze([
    "https://rococo-rpc.polkadot.io",
  ]),
  "westend": Object.freeze([
    "https://westend-rpc.polkadot.io",
  ]),
  // localnet has no public default; private/localnet RPC is unsupported by
  // default policy until a per-family opt-in policy exists.
  "localnet": Object.freeze([]),
});

function envKeyForNetwork(network) {
  return `BOB_SUBSTRATE_RPCS_${String(network).toUpperCase().replace(/-/g, "_")}`;
}

function envOverride(network) {
  if (String(network).trim() === "localnet") return [];
  const key = envKeyForNetwork(network);
  return splitRpcEndpointEnv(process.env[key]);
}

function defaultOverride() {
  return splitRpcEndpointEnv(process.env.BOB_SUBSTRATE_RPCS_DEFAULT);
}

function resolveSubstrateRpcEndpoints(network) {
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

function summarizeSubstratePoolForBrief(network) {
  const normalizedNetwork = typeof network === "string" ? network.trim() : null;
  if (!normalizedNetwork) {
    return { chain_family: "substrate", network: null, endpoints: [], note: "Set chain_id (network) on the surface for a populated RPC pool." };
  }
  let endpoints;
  try {
    endpoints = resolveSubstrateRpcEndpoints(normalizedNetwork);
  } catch {
    endpoints = [];
  }
  const trimmed = endpoints.slice(0, 6).map(redactRpcEndpoint);
  const note = endpoints.length === 0
    ? `No default RPC ladder for network ${normalizedNetwork}. Evaluators must pass 'endpoints' explicitly to bob_substrate_* tools and 'fork_urls' to bob_substrate_run. Operators can set ${envKeyForNetwork(normalizedNetwork)}=url1,url2 in the MCP server env (before launch) for a default.`
    : null;
  return {
    chain_family: "substrate",
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
  resolveSubstrateRpcEndpoints,
  summarizeSubstratePoolForBrief,
};
