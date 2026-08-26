"use strict";

// Sui JSON-RPC client. Mirrors svm-client.js for reuse semantics.

const { resolveSuiRpcEndpoints } = require("./sui-rpc-pool.js");
const { makeJsonRpcClient } = require("./json-rpc-transport.js");

const DEFAULT_MAX_RESULT_BYTES = 64 * 1024;

const MOVE_ADDRESS_RE = /^0x[a-fA-F0-9]{1,64}$/;

function isMoveAddress(value) {
  return typeof value === "string" && MOVE_ADDRESS_RE.test(value);
}

function normalizeMoveAddress(value) {
  if (!isMoveAddress(value)) return null;
  const hex = value.slice(2).toLowerCase();
  return `0x${hex.padStart(64, "0")}`;
}

const { rpcRequest } = makeJsonRpcClient({
  resolveEndpoints: resolveSuiRpcEndpoints,
  selectorKey: "network",
  selectorLabel: "network",
  envHint: (network) => `BOB_SUI_RPCS_${String(network).toUpperCase()}`,
});

async function getObject({ network, objectId, options, endpoints }) {
  if (!isMoveAddress(objectId)) {
    throw new Error(`objectId must be a 0x-prefixed hex Sui object id, received: ${objectId}`);
  }
  // Sui's sui_getObject takes (id, options). options controls whether the
  // response includes content/type/owner/previousTransaction. We always show
  // owner + type because verifier prompts use both for object_ownership_*
  // pattern matching.
  const opts = {
    showType: true,
    showOwner: true,
    showPreviousTransaction: true,
    showDisplay: false,
    showContent: true,
    showBcs: false,
    showStorageRebate: true,
    ...(options || {}),
  };
  const normalized = normalizeMoveAddress(objectId);
  return rpcRequest({
    network,
    method: "sui_getObject",
    params: [normalized, opts],
    endpoints,
    maxResponseBytes: 1024 * 1024,
  });
}

async function getNormalizedMoveModulesByPackage({ network, packageId, endpoints }) {
  if (!isMoveAddress(packageId)) {
    throw new Error(`packageId must be a 0x-prefixed hex Sui package id, received: ${packageId}`);
  }
  const normalized = normalizeMoveAddress(packageId);
  return rpcRequest({
    network,
    method: "sui_getNormalizedMoveModulesByPackage",
    params: [normalized],
    endpoints,
    maxResponseBytes: 4 * 1024 * 1024,
  });
}

async function getLatestCheckpointSequenceNumber({ network, endpoints }) {
  return rpcRequest({
    network,
    method: "sui_getLatestCheckpointSequenceNumber",
    params: [],
    endpoints,
    maxResponseBytes: 1024,
  });
}

module.exports = {
  DEFAULT_MAX_RESULT_BYTES,
  MOVE_ADDRESS_RE,
  getLatestCheckpointSequenceNumber,
  getNormalizedMoveModulesByPackage,
  getObject,
  isMoveAddress,
  normalizeMoveAddress,
  rpcRequest,
};
