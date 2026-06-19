"use strict";

const {
  isHttpsUrl,
  isPrivateHost,
  isPublicHttpsUrl,
  normalizeRpcEndpointList,
  redactRpcEndpoint,
  splitRpcEndpointEnv,
} = require("./sc-egress-policy.js");

// Public archive RPC fallback ladder per major EVM chain.
// Order matters — earlier endpoints are tried first. All entries are full
// archive nodes that support eth_call at historical blocks.
//
// Override per chain via env: BOB_EVM_RPCS_<CHAIN_ID>=url1,url2
// Override globally via env: BOB_EVM_RPCS_DEFAULT=url1,url2 (appended after
//                            chain-specific overrides if no chain match)
const DEFAULT_PUBLIC_RPC_LADDER = Object.freeze({
  // Ethereum
  1: Object.freeze([
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://1rpc.io/eth",
  ]),
  // Optimism
  10: Object.freeze([
    "https://optimism-rpc.publicnode.com",
    "https://op.llamarpc.com",
    "https://1rpc.io/op",
  ]),
  // BNB Smart Chain
  56: Object.freeze([
    "https://bsc-rpc.publicnode.com",
    "https://bsc-dataseed.binance.org",
  ]),
  // Polygon
  137: Object.freeze([
    "https://polygon-bor-rpc.publicnode.com",
    "https://polygon-rpc.com",
  ]),
  // zkSync Era
  324: Object.freeze([
    "https://zksync-mainnet.zksync.io",
    "https://1rpc.io/zksync2-era",
  ]),
  // Base
  8453: Object.freeze([
    "https://base-rpc.publicnode.com",
    "https://base.llamarpc.com",
    "https://1rpc.io/base",
  ]),
  // Arbitrum One
  42161: Object.freeze([
    "https://arbitrum-one-rpc.publicnode.com",
    "https://arb1.arbitrum.io/rpc",
    "https://1rpc.io/arb",
  ]),
  // Avalanche C-chain
  43114: Object.freeze([
    "https://avalanche-c-chain-rpc.publicnode.com",
    "https://1rpc.io/avax/c",
  ]),
  // Linea
  59144: Object.freeze([
    "https://linea-rpc.publicnode.com",
    "https://1rpc.io/linea",
  ]),
  // Scroll
  534352: Object.freeze([
    "https://scroll-rpc.publicnode.com",
    "https://1rpc.io/scroll",
  ]),
});

function envOverride(chainId) {
  const key = `BOB_EVM_RPCS_${chainId}`;
  return splitRpcEndpointEnv(process.env[key]);
}

function defaultOverride() {
  return splitRpcEndpointEnv(process.env.BOB_EVM_RPCS_DEFAULT);
}

function resolveEvmRpcEndpoints(chainId) {
  const numericChainId = Number(chainId);
  if (!Number.isInteger(numericChainId) || numericChainId <= 0) {
    throw new Error(`chainId must be a positive integer, received: ${chainId}`);
  }
  const fromEnv = envOverride(numericChainId);
  const defaults = DEFAULT_PUBLIC_RPC_LADDER[numericChainId] || [];
  const fromDefaultEnv = defaultOverride();

  // Priority: chain-specific env > shipped defaults > global env fallback.
  return normalizeRpcEndpointList([...fromEnv, ...defaults, ...fromDefaultEnv]).endpoints;
}

function summarizeRpcPoolForBrief(chainFamily, chainId) {
  // Dispatch by chain_family so SVM/Aptos/Sui/Substrate/CosmWasm evaluators
  // receive their proper RPC ladders rather than the legacy evm-only
  // placeholder. Lazy-require family pools to avoid circular import
  // (svm-rpc-pool depends on this module's isPublicHttpsUrl helper indirectly
  // via shared patterns).
  if (chainFamily === "svm") {
    const { summarizeSvmPoolForBrief } = require("./svm-rpc-pool.js");
    return summarizeSvmPoolForBrief(chainId);
  }
  if (chainFamily === "aptos") {
    const { summarizeAptosPoolForBrief } = require("./aptos-rpc-pool.js");
    return summarizeAptosPoolForBrief(chainId);
  }
  if (chainFamily === "sui") {
    const { summarizeSuiPoolForBrief } = require("./sui-rpc-pool.js");
    return summarizeSuiPoolForBrief(chainId);
  }
  if (chainFamily === "substrate") {
    const { summarizeSubstratePoolForBrief } = require("./substrate-rpc-pool.js");
    return summarizeSubstratePoolForBrief(chainId);
  }
  if (chainFamily === "cosmwasm") {
    const { summarizeCosmwasmPoolForBrief } = require("./cosmwasm-rpc-pool.js");
    return summarizeCosmwasmPoolForBrief(chainId);
  }
  if (chainFamily !== "evm") {
    return { chain_family: chainFamily || null, endpoints: [], note: "RPC pool is currently provided for chain_family: evm, svm, aptos, sui, substrate, cosmwasm only." };
  }
  const numericChainId = Number(chainId);
  if (!Number.isInteger(numericChainId) || numericChainId <= 0) {
    return { chain_family: chainFamily, chain_id: chainId || null, endpoints: [], note: "Set chain_id on the surface for a populated RPC pool." };
  }
  let endpoints;
  try {
    endpoints = resolveEvmRpcEndpoints(numericChainId);
  } catch {
    endpoints = [];
  }
  // Cap the brief view at 6 endpoints (matches ASSIGNMENT_BRIEF_SURFACE_ARRAY_LIMITS.fork_rpc_pool).
  const trimmed = endpoints.slice(0, 6).map(redactRpcEndpoint);
  const note = endpoints.length === 0
    ? `No default RPC ladder for chain_id ${numericChainId}. Evaluators must pass 'endpoints' explicitly to bob_evm_* tools and 'fork_urls' to bob_foundry_run. Operators can set BOB_EVM_RPCS_${numericChainId}=url1,url2 in the MCP server env (before launch) for a default.`
    : null;
  return {
    chain_family: chainFamily,
    chain_id: numericChainId,
    endpoints: trimmed,
    truncated: endpoints.length > trimmed.length,
    note,
  };
}

module.exports = {
  DEFAULT_PUBLIC_RPC_LADDER,
  isPrivateHost,
  isHttpsUrl,
  isPublicHttpsUrl,
  resolveEvmRpcEndpoints,
  summarizeRpcPoolForBrief,
};
