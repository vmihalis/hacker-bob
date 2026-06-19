"use strict";

const { resolveSvmRpcEndpoints } = require("./svm-rpc-pool.js");
const {
  filterResolvedPublicRpcEndpoints,
  redactRpcEndpoint,
  redactRpcEndpointText,
  summarizeRpcPolicyRejections,
} = require("./sc-egress-policy.js");
const { requestPublicHttpsText } = require("./sc-http-client.js");

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024; // 256 KiB
const DEFAULT_MAX_RESULT_BYTES = 64 * 1024;

const SVM_PUBKEY_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

function isPubkey(value) {
  return typeof value === "string" && SVM_PUBKEY_RE.test(value);
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

// Solana RPC has a stronger rate-limit reputation than EVM public RPCs. The
// caller-supplied endpoints + per-cluster ladder lets verifiers/evaluators fail
// over without re-spawning the MCP server.
async function rpcRequest({
  cluster,
  method,
  params,
  endpoints,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
  lookup,
} = {}) {
  const rawEndpointList = Array.isArray(endpoints) && endpoints.length > 0
    ? endpoints
    : resolveSvmRpcEndpoints(cluster);
  const { endpoints: endpointList, rejected } = await filterResolvedPublicRpcEndpoints(rawEndpointList, { lookup });
  if (endpointList.length === 0) {
    const err = new Error(`no public HTTPS RPC endpoints available for cluster ${cluster}; set BOB_SVM_RPCS_${String(cluster).toUpperCase().replace(/-/g, "_")}=url1,url2 to override`);
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
  const err = new Error(`all RPC endpoints failed for ${method} on cluster ${cluster}: ${summary}`);
  err.attempts = errors;
  throw err;
}

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
