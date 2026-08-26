"use strict";

const { CHAIN_RPC_POOLS, isHttpsUrl, isPrivateHost, isPublicHttpsUrl } = require("./chain-rpc-pool.js");

const pool = CHAIN_RPC_POOLS.svm;

module.exports = {
  DEFAULT_PUBLIC_RPC_LADDER: pool.defaultPublicRpcLadder,
  envKeyForCluster: pool.envKeyForSelector,
  isPrivateHost,
  isHttpsUrl,
  isPublicHttpsUrl,
  resolveSvmRpcEndpoints: pool.resolveEndpoints,
  summarizeSvmPoolForBrief: pool.summarizeForBrief,
};
