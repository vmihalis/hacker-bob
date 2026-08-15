"use strict";

const { CHAIN_RPC_POOLS, isHttpsUrl, isPrivateHost, isPublicHttpsUrl } = require("./chain-rpc-pool.js");

const pool = CHAIN_RPC_POOLS.sui;

module.exports = {
  DEFAULT_PUBLIC_RPC_LADDER: pool.defaultPublicRpcLadder,
  envKeyForNetwork: pool.envKeyForSelector,
  isPrivateHost,
  isHttpsUrl,
  isPublicHttpsUrl,
  resolveSuiRpcEndpoints: pool.resolveEndpoints,
  summarizeSuiPoolForBrief: pool.summarizeForBrief,
};
