"use strict";

const {
  isHttpsUrl,
  isPrivateHost,
  isPublicHttpsUrl,
  normalizeRpcEndpointList,
  redactRpcEndpoint,
  splitRpcEndpointEnv,
} = require("./sc-egress-policy.js");

// Public Solana JSON-RPC fallback ladder per cluster.
// Order matters — earlier endpoints are tried first.
//
// Override per cluster via env: BOB_SVM_RPCS_<CLUSTER>=url1,url2
//   - <CLUSTER> is uppercased and `-` is replaced with `_`. e.g. mainnet-beta
//     becomes BOB_SVM_RPCS_MAINNET_BETA.
// Override globally via env: BOB_SVM_RPCS_DEFAULT=url1,url2 (appended after
//                            cluster-specific overrides if no cluster match)
const DEFAULT_PUBLIC_RPC_LADDER = Object.freeze({
  // Solana mainnet-beta
  "mainnet-beta": Object.freeze([
    "https://solana-rpc.publicnode.com",
    "https://api.mainnet-beta.solana.com",
    "https://solana.drpc.org",
  ]),
  // Solana devnet
  "devnet": Object.freeze([
    "https://api.devnet.solana.com",
    "https://solana-devnet-rpc.publicnode.com",
  ]),
  // Solana testnet
  "testnet": Object.freeze([
    "https://api.testnet.solana.com",
  ]),
});

function envKeyForCluster(cluster) {
  // mainnet-beta → MAINNET_BETA
  return `BOB_SVM_RPCS_${String(cluster).toUpperCase().replace(/-/g, "_")}`;
}

function envOverride(cluster) {
  if (String(cluster).trim() === "localnet") return [];
  const key = envKeyForCluster(cluster);
  return splitRpcEndpointEnv(process.env[key]);
}

function defaultOverride() {
  return splitRpcEndpointEnv(process.env.BOB_SVM_RPCS_DEFAULT);
}

function resolveSvmRpcEndpoints(cluster) {
  if (typeof cluster !== "string" || !cluster.trim()) {
    throw new Error(`cluster must be a non-empty string, received: ${cluster}`);
  }
  const normalizedCluster = cluster.trim();
  if (normalizedCluster === "localnet") return [];
  const fromEnv = envOverride(normalizedCluster);
  const defaults = DEFAULT_PUBLIC_RPC_LADDER[normalizedCluster] || [];
  const fromDefaultEnv = defaultOverride();

  // Priority: cluster-specific env > shipped defaults > global env fallback.
  return normalizeRpcEndpointList([...fromEnv, ...defaults, ...fromDefaultEnv]).endpoints;
}

function summarizeSvmPoolForBrief(cluster) {
  const normalizedCluster = typeof cluster === "string" ? cluster.trim() : null;
  if (!normalizedCluster) {
    return { chain_family: "svm", cluster: null, endpoints: [], note: "Set chain_id (cluster) on the surface for a populated RPC pool." };
  }
  let endpoints;
  try {
    endpoints = resolveSvmRpcEndpoints(normalizedCluster);
  } catch {
    endpoints = [];
  }
  // Cap the brief view at 6 endpoints (matches ASSIGNMENT_BRIEF_SURFACE_ARRAY_LIMITS.fork_rpc_pool).
  const trimmed = endpoints.slice(0, 6).map(redactRpcEndpoint);
  const note = endpoints.length === 0
    ? `No default RPC ladder for cluster ${normalizedCluster}. Evaluators must pass 'endpoints' explicitly to bob_svm_* tools and 'fork_urls' to bob_anchor_run. Operators can set ${envKeyForCluster(normalizedCluster)}=url1,url2 in the MCP server env (before launch) for a default.`
    : null;
  return {
    chain_family: "svm",
    cluster: normalizedCluster,
    endpoints: trimmed,
    truncated: endpoints.length > trimmed.length,
    note,
  };
}

module.exports = {
  DEFAULT_PUBLIC_RPC_LADDER,
  envKeyForCluster,
  isPrivateHost,
  isHttpsUrl,
  isPublicHttpsUrl,
  resolveSvmRpcEndpoints,
  summarizeSvmPoolForBrief,
};
