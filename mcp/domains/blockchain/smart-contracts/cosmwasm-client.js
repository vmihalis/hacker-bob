"use strict";

// CosmWasm REST client. Cosmos SDK chains expose CosmWasm-specific REST
// endpoints under /cosmwasm/wasm/v1/...:
//   - GET /cosmwasm/wasm/v1/contract/{address}              → contract info
//   - GET /cosmwasm/wasm/v1/contract/{address}/raw/{key}    → raw storage at key (hex)
//   - GET /cosmwasm/wasm/v1/contract/{address}/smart/{msg}  → smart query (msg is base64)
//   - GET /cosmwasm/wasm/v1/contract/{address}/history      → migration history
//   - GET /cosmwasm/wasm/v1/code/{code_id}                  → uploaded WASM info
//
// Chain info via the cosmos-sdk side:
//   - GET /cosmos/base/tendermint/v1beta1/blocks/latest     → latest block
//   - GET /cosmos/base/tendermint/v1beta1/node_info         → chain_id sanity check
//
// Bech32 addresses are case-insensitive but we always lower-case before
// querying so two findings against "Osmo1..." and "osmo1..." dedupe.

const { resolveCosmwasmRpcEndpoints } = require("./cosmwasm-rpc-pool.js");
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

const BECH32_RE = /^[a-z0-9]{1,83}1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{6,87}$/;

function isBech32Address(value) {
  return typeof value === "string" && BECH32_RE.test(value.toLowerCase());
}

function normalizeBech32(value) {
  if (!isBech32Address(value)) return null;
  return value.toLowerCase();
}

function redactJsonBody(value) {
  if (!value || typeof value !== "object") return value;
  try {
    return JSON.parse(redactRpcEndpointText(JSON.stringify(value)));
  } catch {
    return value;
  }
}

function buildRestUrl(baseUrl, path) {
  const parsed = new URL(baseUrl);
  const basePath = parsed.pathname.replace(/\/+$/, "");
  const trimmedPath = String(path || "").replace(/^\/+/, "");
  parsed.pathname = trimmedPath ? `${basePath || ""}/${trimmedPath}` : (basePath || "/");
  return parsed.toString();
}

async function restGetOnce(baseUrl, path, { timeoutMs = DEFAULT_TIMEOUT_MS, maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES, lookup } = {}) {
  const url = buildRestUrl(baseUrl, path);
  const displayUrl = redactRpcEndpoint(url);
  const resp = await requestPublicHttpsText(url, {
    method: "GET",
    headers: { Accept: "application/json" },
    timeoutMs,
    maxBytes: maxResponseBytes,
    lookup,
  });
  const text = resp.text;
  if (!resp.ok) {
    // CosmWasm REST returns 404 for "no such contract" with a JSON body
    // shaped {code, message, details}. Surface the JSON body so callers
    // can distinguish "not found" from "endpoint broken".
    let parsed = null;
    try { parsed = JSON.parse(text); } catch {}
    const msg = redactRpcEndpointText(parsed && parsed.message ? parsed.message : text).slice(0, 200);
    const err = new Error(`HTTP ${resp.status} from ${displayUrl}: ${msg}`);
    err.status = resp.status;
    err.body = parsed ? redactJsonBody(parsed) : redactRpcEndpointText(text);
    throw err;
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`malformed JSON response from ${displayUrl}: ${error.message || String(error)}`);
  }
  // Cosmos SDK populates "Grpc-Metadata-X-Cosmos-Block-Height" with the block
  // height the read was served from. Surface it so verifier prompts can
  // record "verified at block N" without an extra round-trip.
  const blockHeight = resp.headers && typeof resp.headers.get === "function"
    ? resp.headers.get("Grpc-Metadata-X-Cosmos-Block-Height") || resp.headers.get("grpc-metadata-x-cosmos-block-height")
    : null;
  return { result: parsed, block_height_used: blockHeight };
}

async function restGet({ network, path, endpoints, timeoutMs = DEFAULT_TIMEOUT_MS, maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES, lookup } = {}) {
  const rawEndpointList = Array.isArray(endpoints) && endpoints.length > 0
    ? endpoints
    : resolveCosmwasmRpcEndpoints(network);
  const { endpoints: endpointList, rejected } = await filterResolvedPublicRpcEndpoints(rawEndpointList, { lookup });
  if (endpointList.length === 0) {
    const err = new Error(`no public HTTPS REST endpoints available for network ${network}; set BOB_COSMWASM_RPCS_${String(network).toUpperCase()}=url1,url2 to override`);
    err.rpc_policy_rejections = summarizeRpcPolicyRejections(rejected);
    err.details = { rpc_policy_rejections: err.rpc_policy_rejections };
    throw err;
  }

  const errors = [];
  for (const endpoint of endpointList) {
    try {
      const { result, block_height_used } = await restGetOnce(endpoint, path, { timeoutMs, maxResponseBytes, lookup });
      return { result, endpoint: redactRpcEndpoint(endpoint), block_height_used };
    } catch (error) {
      // 404 is a real "no such resource" answer — bubble it up rather than
      // failing over (the next endpoint would return the same 404).
      if (error.status === 404) {
        const err = new Error(error.message);
        err.status = 404;
        err.body = error.body;
        err.endpoint = redactRpcEndpoint(endpoint);
        throw err;
      }
      errors.push({
        endpoint: redactRpcEndpoint(endpoint),
        message: redactRpcEndpointText(error.message || String(error)),
      });
    }
  }
  const summary = errors.map((e) => `${e.endpoint}: ${e.message}`).join("; ");
  const err = new Error(`all REST endpoints failed for ${path} on network ${network}: ${summary}`);
  err.attempts = errors;
  throw err;
}

async function getContractInfo({ network, address, endpoints }) {
  if (!isBech32Address(address)) {
    throw new Error(`address must be a bech32-encoded contract address, received: ${address}`);
  }
  const normalized = normalizeBech32(address);
  return restGet({
    network,
    path: `cosmwasm/wasm/v1/contract/${encodeURIComponent(normalized)}`,
    endpoints,
    maxResponseBytes: 64 * 1024,
  });
}

async function querySmart({ network, address, queryMsg, endpoints }) {
  if (!isBech32Address(address)) {
    throw new Error(`address must be a bech32-encoded contract address, received: ${address}`);
  }
  if (queryMsg == null || (typeof queryMsg !== "object" && typeof queryMsg !== "string")) {
    throw new Error("queryMsg must be a JSON object or pre-encoded base64 string");
  }
  const normalized = normalizeBech32(address);
  // CosmWasm smart queries take a base64-encoded JSON message in the URL path.
  // We accept either a JSON-serializable object (we encode it) or a string
  // already encoded by the caller.
  const encoded = typeof queryMsg === "string"
    ? queryMsg
    : Buffer.from(JSON.stringify(queryMsg), "utf8").toString("base64");
  return restGet({
    network,
    path: `cosmwasm/wasm/v1/contract/${encodeURIComponent(normalized)}/smart/${encodeURIComponent(encoded)}`,
    endpoints,
    maxResponseBytes: 256 * 1024,
  });
}

async function getCodeInfo({ network, codeId, endpoints }) {
  if (!Number.isInteger(codeId) || codeId < 1) {
    throw new Error("codeId must be a positive integer");
  }
  return restGet({
    network,
    path: `cosmwasm/wasm/v1/code/${codeId}`,
    endpoints,
    maxResponseBytes: 16 * 1024,
  });
}

async function getLatestBlock({ network, endpoints }) {
  return restGet({
    network,
    path: "cosmos/base/tendermint/v1beta1/blocks/latest",
    endpoints,
    maxResponseBytes: 64 * 1024,
  });
}

async function getNodeInfo({ network, endpoints }) {
  // node_info returns the chain's network id (e.g., "osmosis-1", "neutron-1").
  // Verifier prompts compare this against the claimed chain_id to catch a
  // evaluator mis-routing an address from one chain to another.
  return restGet({
    network,
    path: "cosmos/base/tendermint/v1beta1/node_info",
    endpoints,
    maxResponseBytes: 16 * 1024,
  });
}

module.exports = {
  BECH32_RE,
  DEFAULT_MAX_RESULT_BYTES,
  getCodeInfo,
  getContractInfo,
  getLatestBlock,
  getNodeInfo,
  isBech32Address,
  normalizeBech32,
  querySmart,
  restGet,
};
