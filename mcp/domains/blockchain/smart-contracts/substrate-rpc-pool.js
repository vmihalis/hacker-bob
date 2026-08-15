"use strict";

const { CHAIN_RPC_POOLS, isHttpsUrl, isPrivateHost, isPublicHttpsUrl } = require("./chain-rpc-pool.js");

const pool = CHAIN_RPC_POOLS.substrate;

module.exports = {
  DEFAULT_PUBLIC_RPC_LADDER: pool.defaultPublicRpcLadder,
  envKeyForNetwork: pool.envKeyForSelector,
  isPrivateHost,
  isHttpsUrl,
  isPublicHttpsUrl,
  resolveSubstrateRpcEndpoints: pool.resolveEndpoints,
  summarizeSubstratePoolForBrief: pool.summarizeForBrief,
};
