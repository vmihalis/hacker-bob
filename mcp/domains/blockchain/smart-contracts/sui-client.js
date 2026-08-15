"use strict";

// Sui JSON-RPC client. Mirrors svm-client.js for reuse semantics.

const { resolveSuiRpcEndpoints } = require("./sui-rpc-pool.js");
const {
  filterResolvedPublicRpcEndpoints,
  redactRpcEndpoint,
  redactRpcEndpointText,
  summarizeRpcPolicyRejections,
} = require("./sc-egress-policy.js");
const { requestPublicHttpsText } = require("./sc-http-client.js");

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024;
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

async function rpcRequestOnce(url, method, params, { timeoutMs = DEFAULT_TIMEOUT_MS, maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES, lookup } = {}) {
  const displayUrl = redactRpcEndpoint(url);
  const resp = await requestPublicHttpsText(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", method, params, id: 1 }),
    timeoutMs,
    maxBytes: maxResponseBytes,
    lookup,
  });
  const text = resp.text;
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status} from ${displayUrl}: ${redactRpcEndpointText(text).slice(0, 200)}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`malformed JSON-RPC response from ${displayUrl}: ${error.message || String(error)}`);
  }
  if (parsed && parsed.error) {
    const message = typeof parsed.error.message === "string" ? parsed.error.message : JSON.stringify(parsed.error);
    const err = new Error(`JSON-RPC error from ${displayUrl}: ${redactRpcEndpointText(message)}`);
    err.rpcError = parsed.error;
    throw err;
  }
  return parsed && parsed.result;
}

async function rpcRequest({
  network,
  method,
  params,
  endpoints,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
  lookup,
} = {}) {
  const rawEndpointList = Array.isArray(endpoints) && endpoints.length > 0
    ? endpoints
    : resolveSuiRpcEndpoints(network);
  const { endpoints: endpointList, rejected } = await filterResolvedPublicRpcEndpoints(rawEndpointList, { lookup });
  if (endpointList.length === 0) {
    const err = new Error(`no public HTTPS RPC endpoints available for network ${network}; set BOB_SUI_RPCS_${String(network).toUpperCase()}=url1,url2 to override`);
    err.rpc_policy_rejections = summarizeRpcPolicyRejections(rejected);
    err.details = { rpc_policy_rejections: err.rpc_policy_rejections };
    throw err;
  }

  const errors = [];
  for (const endpoint of endpointList) {
    try {
      const result = await rpcRequestOnce(endpoint, method, params, { timeoutMs, maxResponseBytes, lookup });
      return { result, endpoint: redactRpcEndpoint(endpoint) };
    } catch (error) {
      errors.push({
        endpoint: redactRpcEndpoint(endpoint),
        message: redactRpcEndpointText(error.message || String(error)),
      });
    }
  }
  const summary = errors.map((e) => `${e.endpoint}: ${e.message}`).join("; ");
  const err = new Error(`all RPC endpoints failed for ${method} on network ${network}: ${summary}`);
  err.attempts = errors;
  throw err;
}

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
