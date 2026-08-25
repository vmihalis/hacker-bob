"use strict";

const {
  CHAIN_RPC_POOLS,
  isHttpsUrl,
  isPrivateHost,
  isPublicHttpsUrl,
  summarizeChainRpcPoolForBrief,
} = require("./chain-rpc-pool.js");

const pool = CHAIN_RPC_POOLS.evm;

module.exports = {
  CHAIN_RPC_POOLS,
  DEFAULT_PUBLIC_RPC_LADDER: pool.defaultPublicRpcLadder,
  isPrivateHost,
  isHttpsUrl,
  isPublicHttpsUrl,
  resolveEvmRpcEndpoints: pool.resolveEndpoints,
  summarizeRpcPoolForBrief: summarizeChainRpcPoolForBrief,
};
