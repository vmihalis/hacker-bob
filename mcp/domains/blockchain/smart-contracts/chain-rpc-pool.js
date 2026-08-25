"use strict";

const {
  isHttpsUrl,
  isPrivateHost,
  isPublicHttpsUrl,
  normalizeRpcEndpointList,
  redactRpcEndpoint,
  splitRpcEndpointEnv,
} = require("./sc-egress-policy.js");

function frozenLadder(entries) {
  return Object.freeze(Object.fromEntries(
    Object.entries(entries).map(([selector, endpoints]) => [selector, Object.freeze(endpoints)]),
  ));
}

function makeChainRpcPool({
  chainFamily,
  selectorKey,
  selectorLabel,
  defaultPublicRpcLadder,
  envPrefix,
  normalizeSelector,
  summarySelector = normalizeSelector,
  missingSelectorValue = () => null,
  disabledSelectors = [],
  emptyNote,
  missingNote,
}) {
  const disabled = new Set(disabledSelectors);
  const supportedSelectors = Object.freeze(Object.keys(defaultPublicRpcLadder));

  function envKeyForSelector(selector) {
    return `${envPrefix}_${String(selector).toUpperCase().replace(/-/g, "_")}`;
  }

  function resolveEndpoints(rawSelector) {
    const selector = normalizeSelector(rawSelector);
    if (disabled.has(String(selector))) return [];
    const fromEnv = splitRpcEndpointEnv(process.env[envKeyForSelector(selector)]);
    const defaults = defaultPublicRpcLadder[selector] || [];
    const fromDefaultEnv = splitRpcEndpointEnv(process.env[`${envPrefix}_DEFAULT`]);
    return normalizeRpcEndpointList([...fromEnv, ...defaults, ...fromDefaultEnv]).endpoints;
  }

  function summarizeForBrief(rawSelector) {
    const selector = summarySelector(rawSelector);
    if (selector == null) {
      return {
        chain_family: chainFamily,
        [selectorKey]: missingSelectorValue(rawSelector),
        endpoints: [],
        note: missingNote,
      };
    }
    let endpoints;
    try {
      endpoints = resolveEndpoints(selector);
    } catch {
      endpoints = [];
    }
    const trimmed = endpoints.slice(0, 6).map(redactRpcEndpoint);
    return {
      chain_family: chainFamily,
      [selectorKey]: selector,
      endpoints: trimmed,
      truncated: endpoints.length > trimmed.length,
      note: endpoints.length === 0 ? emptyNote(selector, envKeyForSelector(selector)) : null,
    };
  }

  return Object.freeze({
    chainFamily,
    defaultPublicRpcLadder,
    envKeyForSelector,
    resolveEndpoints,
    selectorKey,
    selectorLabel,
    summarizeForBrief,
    supportedSelectors,
  });
}

const EVM_DEFAULTS = frozenLadder({
  1: [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://1rpc.io/eth",
  ],
  10: [
    "https://optimism-rpc.publicnode.com",
    "https://op.llamarpc.com",
    "https://1rpc.io/op",
  ],
  56: [
    "https://bsc-rpc.publicnode.com",
    "https://bsc-dataseed.binance.org",
  ],
  137: [
    "https://polygon-bor-rpc.publicnode.com",
    "https://polygon-rpc.com",
  ],
  324: [
    "https://zksync-mainnet.zksync.io",
    "https://1rpc.io/zksync2-era",
  ],
  8453: [
    "https://base-rpc.publicnode.com",
    "https://base.llamarpc.com",
    "https://1rpc.io/base",
  ],
  42161: [
    "https://arbitrum-one-rpc.publicnode.com",
    "https://arb1.arbitrum.io/rpc",
    "https://1rpc.io/arb",
  ],
  43114: [
    "https://avalanche-c-chain-rpc.publicnode.com",
    "https://1rpc.io/avax/c",
  ],
  59144: [
    "https://linea-rpc.publicnode.com",
    "https://1rpc.io/linea",
  ],
  534352: [
    "https://scroll-rpc.publicnode.com",
    "https://1rpc.io/scroll",
  ],
});

const SVM_DEFAULTS = frozenLadder({
  "mainnet-beta": [
    "https://solana-rpc.publicnode.com",
    "https://api.mainnet-beta.solana.com",
    "https://solana.drpc.org",
  ],
  devnet: [
    "https://api.devnet.solana.com",
    "https://solana-devnet-rpc.publicnode.com",
  ],
  testnet: ["https://api.testnet.solana.com"],
});

const SUI_DEFAULTS = frozenLadder({
  mainnet: [
    "https://fullnode.mainnet.sui.io:443",
    "https://sui-mainnet.public.blastapi.io",
    "https://sui-mainnet-rpc.publicnode.com",
  ],
  testnet: [
    "https://fullnode.testnet.sui.io:443",
    "https://sui-testnet.public.blastapi.io",
  ],
  devnet: ["https://fullnode.devnet.sui.io:443"],
  localnet: [],
});

const APTOS_DEFAULTS = frozenLadder({
  mainnet: [
    "https://api.mainnet.aptoslabs.com/v1",
    "https://fullnode.mainnet.aptoslabs.com/v1",
  ],
  testnet: [
    "https://api.testnet.aptoslabs.com/v1",
    "https://fullnode.testnet.aptoslabs.com/v1",
  ],
  devnet: [
    "https://api.devnet.aptoslabs.com/v1",
    "https://fullnode.devnet.aptoslabs.com/v1",
  ],
});

const COSMWASM_DEFAULTS = frozenLadder({
  osmosis: [
    "https://lcd.osmosis.zone",
    "https://osmosis-rest.publicnode.com",
    "https://osmosis-api.polkachu.com",
  ],
  juno: [
    "https://juno-api.polkachu.com",
    "https://lcd.juno.basementnodes.ca",
  ],
  neutron: [
    "https://rest-kralum.neutron-1.neutron.org",
    "https://neutron-api.polkachu.com",
  ],
  archway: [
    "https://api.mainnet.archway.io",
    "https://archway-api.polkachu.com",
  ],
  sei: [
    "https://sei-rest.brocha.in",
    "https://rest.sei-apis.com",
  ],
  stargaze: [
    "https://rest.stargaze-apis.com",
    "https://stargaze-api.polkachu.com",
  ],
  terra: [
    "https://phoenix-lcd.terra.dev",
    "https://terra-api.polkachu.com",
  ],
  kava: [
    "https://api.data.kava.io",
    "https://kava-api.polkachu.com",
  ],
  localnet: [],
});

const SUBSTRATE_DEFAULTS = frozenLadder({
  polkadot: [
    "https://rpc.polkadot.io",
    "https://polkadot-rpc.dwellir.com",
    "https://polkadot.api.onfinality.io/public",
  ],
  kusama: [
    "https://kusama-rpc.polkadot.io",
    "https://kusama-rpc.dwellir.com",
    "https://kusama.api.onfinality.io/public",
  ],
  astar: [
    "https://astar.api.onfinality.io/public",
    "https://astar-rpc.dwellir.com",
  ],
  shiden: [
    "https://shiden.api.onfinality.io/public",
    "https://shiden-rpc.dwellir.com",
  ],
  rococo: ["https://rococo-rpc.polkadot.io"],
  westend: ["https://westend-rpc.polkadot.io"],
  localnet: [],
});

function normalizeNetwork(value, label) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${label} must be a non-empty string, received: ${value}`);
  }
  return value.trim();
}

function summaryNetwork(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

const CHAIN_RPC_POOLS = Object.freeze({
  evm: makeChainRpcPool({
    chainFamily: "evm",
    selectorKey: "chain_id",
    selectorLabel: "chain_id",
    defaultPublicRpcLadder: EVM_DEFAULTS,
    envPrefix: "BOB_EVM_RPCS",
    normalizeSelector(value) {
      const numeric = Number(value);
      if (!Number.isInteger(numeric) || numeric <= 0) {
        throw new Error(`chainId must be a positive integer, received: ${value}`);
      }
      return numeric;
    },
    summarySelector(value) {
      const numeric = Number(value);
      return Number.isInteger(numeric) && numeric > 0 ? numeric : null;
    },
    missingSelectorValue: (value) => value || null,
    missingNote: "Set chain_id on the surface for a populated RPC pool.",
    emptyNote: (chainId) => `No default RPC ladder for chain_id ${chainId}. Evaluators must pass 'endpoints' explicitly to bob_evm_* tools and 'fork_urls' to bob_foundry_run. Operators can set BOB_EVM_RPCS_${chainId}=url1,url2 in the MCP server env (before launch) for a default.`,
  }),
  svm: makeChainRpcPool({
    chainFamily: "svm",
    selectorKey: "cluster",
    selectorLabel: "cluster",
    defaultPublicRpcLadder: SVM_DEFAULTS,
    envPrefix: "BOB_SVM_RPCS",
    normalizeSelector: (value) => normalizeNetwork(value, "cluster"),
    summarySelector: summaryNetwork,
    disabledSelectors: ["localnet"],
    missingNote: "Set chain_id (cluster) on the surface for a populated RPC pool.",
    emptyNote: (cluster, envKey) => `No default RPC ladder for cluster ${cluster}. Evaluators must pass 'endpoints' explicitly to bob_svm_* tools and 'fork_urls' to bob_anchor_run. Operators can set ${envKey}=url1,url2 in the MCP server env (before launch) for a default.`,
  }),
  aptos: makeChainRpcPool({
    chainFamily: "aptos",
    selectorKey: "network",
    selectorLabel: "network",
    defaultPublicRpcLadder: APTOS_DEFAULTS,
    envPrefix: "BOB_APTOS_RPCS",
    normalizeSelector: (value) => normalizeNetwork(value, "network"),
    summarySelector: summaryNetwork,
    disabledSelectors: ["localnet"],
    missingNote: "Set chain_id (network) on the surface for a populated RPC pool.",
    emptyNote: (network, envKey) => `No default RPC ladder for network ${network}. Evaluators must pass 'endpoints' explicitly to bob_aptos_* tools and 'fork_urls' to bob_aptos_run. Operators can set ${envKey}=url1,url2 in the MCP server env (before launch) for a default.`,
  }),
  sui: makeChainRpcPool({
    chainFamily: "sui",
    selectorKey: "network",
    selectorLabel: "network",
    defaultPublicRpcLadder: SUI_DEFAULTS,
    envPrefix: "BOB_SUI_RPCS",
    normalizeSelector: (value) => normalizeNetwork(value, "network"),
    summarySelector: summaryNetwork,
    disabledSelectors: ["localnet"],
    missingNote: "Set chain_id (network) on the surface for a populated RPC pool.",
    emptyNote: (network, envKey) => `No default RPC ladder for network ${network}. Evaluators must pass 'endpoints' explicitly to bob_sui_* tools and 'fork_urls' to bob_sui_run. Operators can set ${envKey}=url1,url2 in the MCP server env (before launch) for a default.`,
  }),
  substrate: makeChainRpcPool({
    chainFamily: "substrate",
    selectorKey: "network",
    selectorLabel: "network",
    defaultPublicRpcLadder: SUBSTRATE_DEFAULTS,
    envPrefix: "BOB_SUBSTRATE_RPCS",
    normalizeSelector: (value) => normalizeNetwork(value, "network"),
    summarySelector: summaryNetwork,
    disabledSelectors: ["localnet"],
    missingNote: "Set chain_id (network) on the surface for a populated RPC pool.",
    emptyNote: (network, envKey) => `No default RPC ladder for network ${network}. Evaluators must pass 'endpoints' explicitly to bob_substrate_* tools and 'fork_urls' to bob_substrate_run. Operators can set ${envKey}=url1,url2 in the MCP server env (before launch) for a default.`,
  }),
  cosmwasm: makeChainRpcPool({
    chainFamily: "cosmwasm",
    selectorKey: "network",
    selectorLabel: "network",
    defaultPublicRpcLadder: COSMWASM_DEFAULTS,
    envPrefix: "BOB_COSMWASM_RPCS",
    normalizeSelector: (value) => normalizeNetwork(value, "network"),
    summarySelector: summaryNetwork,
    disabledSelectors: ["localnet"],
    missingNote: "Set chain_id (network) on the surface for a populated RPC pool.",
    emptyNote: (network, envKey) => `No default REST ladder for network ${network}. Evaluators must pass 'endpoints' explicitly to bob_cosmwasm_* tools and 'fork_urls' to bob_cosmwasm_run. Operators can set ${envKey}=url1,url2 in the MCP server env (before launch) for a default.`,
  }),
});

function summarizeChainRpcPoolForBrief(chainFamily, selector) {
  const pool = CHAIN_RPC_POOLS[chainFamily];
  if (!pool) {
    return {
      chain_family: chainFamily || null,
      endpoints: [],
      note: "RPC pool is currently provided for chain_family: evm, svm, aptos, sui, substrate, cosmwasm only.",
    };
  }
  return pool.summarizeForBrief(selector);
}

module.exports = {
  CHAIN_RPC_POOLS,
  isHttpsUrl,
  isPrivateHost,
  isPublicHttpsUrl,
  makeChainRpcPool,
  summarizeChainRpcPoolForBrief,
};
