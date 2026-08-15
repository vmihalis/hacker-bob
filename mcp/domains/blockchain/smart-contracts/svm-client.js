"use strict";

const { resolveSvmRpcEndpoints } = require("./svm-rpc-pool.js");
const { makeJsonRpcClient } = require("./json-rpc-transport.js");

const DEFAULT_MAX_RESULT_BYTES = 64 * 1024;

const SVM_PUBKEY_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

function isPubkey(value) {
  return typeof value === "string" && SVM_PUBKEY_RE.test(value);
}

// Solana RPC has a stronger rate-limit reputation than EVM public RPCs. The
// caller-supplied endpoints + per-cluster ladder lets verifiers/evaluators fail
// over without re-spawning the MCP server.
const { rpcRequest } = makeJsonRpcClient({
  resolveEndpoints: resolveSvmRpcEndpoints,
  selectorKey: "cluster",
  selectorLabel: "cluster",
  envHint: (cluster) => `BOB_SVM_RPCS_${String(cluster).toUpperCase().replace(/-/g, "_")}`,
});

async function getAccountInfo({ cluster, pubkey, encoding = "base64", endpoints }) {
  if (!isPubkey(pubkey)) {
    throw new Error(`pubkey must be a base58 32-44 char Solana program/account id, received: ${pubkey}`);
  }
  // commitment: "confirmed" balances tradeoff between freshness and finality.
  // For audit work "confirmed" is more useful than "finalized" because slot
  // is recent enough to reflect bug-pattern state without waiting for full
  // finality (32 slots / ~12s).
  return rpcRequest({
    cluster,
    method: "getAccountInfo",
    params: [pubkey, { encoding, commitment: "confirmed" }],
    endpoints,
    maxResponseBytes: 1024 * 1024, // up to 1 MiB for executables and large data accounts
  });
}

async function getMultipleAccounts({ cluster, pubkeys, encoding = "base64", endpoints }) {
  if (!Array.isArray(pubkeys) || pubkeys.length === 0) {
    throw new Error("pubkeys must be a non-empty array");
  }
  for (const pk of pubkeys) {
    if (!isPubkey(pk)) {
      throw new Error(`pubkey must be a base58 32-44 char Solana program/account id, received: ${pk}`);
    }
  }
  if (pubkeys.length > 100) {
    throw new Error("getMultipleAccounts caps requests at 100 pubkeys per call");
  }
  return rpcRequest({
    cluster,
    method: "getMultipleAccounts",
    params: [pubkeys, { encoding, commitment: "confirmed" }],
    endpoints,
    maxResponseBytes: 4 * 1024 * 1024,
  });
}

async function getSlot({ cluster, endpoints }) {
  return rpcRequest({
    cluster,
    method: "getSlot",
    params: [{ commitment: "confirmed" }],
    endpoints,
    maxResponseBytes: 1024,
  });
}

async function getEpochInfo({ cluster, endpoints }) {
  return rpcRequest({
    cluster,
    method: "getEpochInfo",
    params: [{ commitment: "confirmed" }],
    endpoints,
    maxResponseBytes: 4096,
  });
}

module.exports = {
  DEFAULT_MAX_RESULT_BYTES,
  SVM_PUBKEY_RE,
  getAccountInfo,
  getEpochInfo,
  getMultipleAccounts,
  getSlot,
  isPubkey,
  rpcRequest,
};
