"use strict";

const { CHAIN_RPC_POOLS, isHttpsUrl, isPrivateHost, isPublicHttpsUrl } = require("./chain-rpc-pool.js");

const pool = CHAIN_RPC_POOLS.cosmwasm;

module.exports = {
  DEFAULT_PUBLIC_RPC_LADDER: pool.defaultPublicRpcLadder,
  envKeyForNetwork: pool.envKeyForSelector,
  isPrivateHost,
  isHttpsUrl,
  isPublicHttpsUrl,
  resolveCosmwasmRpcEndpoints: pool.resolveEndpoints,
  summarizeCosmwasmPoolForBrief: pool.summarizeForBrief,
};
