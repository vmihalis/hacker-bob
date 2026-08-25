"use strict";

// Aptos REST client. Aptos uses a plain REST API (not JSON-RPC). Endpoints
// follow the shape <base>/v1/<resource> where base already includes the /v1
// suffix per aptos-rpc-pool ladder. We therefore strip a leading slash from
// the path argument and append it directly to the endpoint URL.

const { resolveAptosRpcEndpoints } = require("./aptos-rpc-pool.js");
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

// Move addresses on Aptos: 0x + 1..64 hex chars. The validator below mirrors
// findings.js MOVE_ADDRESS_RE so callers see the same constraints regardless
// of whether they're recording a finding or fetching state.
const MOVE_ADDRESS_RE = /^0x[a-fA-F0-9]{1,64}$/;

function isMoveAddress(value) {
  return typeof value === "string" && MOVE_ADDRESS_RE.test(value);
}

function normalizeMoveAddress(value) {
  if (!isMoveAddress(value)) return null;
  const hex = value.slice(2).toLowerCase();
  return `0x${hex.padStart(64, "0")}`;
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

async function restGetOnce(baseUrl, path, { timeoutMs = DEFAULT_TIMEOUT_MS, maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES, ledgerVersion = null, lookup } = {}) {
  let url = buildRestUrl(baseUrl, path);
  // Aptos accepts ?ledger_version=N to read at a specific version. This is the
  // analog of EVM block-pinning, but verifiers always run against fresh state
  // (no pin) — only diagnostic tooling passes ledgerVersion.
  if (ledgerVersion != null) {
    const sep = url.includes("?") ? "&" : "?";
    url = `${url}${sep}ledger_version=${encodeURIComponent(ledgerVersion)}`;
  }
  const displayUrl = redactRpcEndpoint(url);
  const resp = await requestPublicHttpsText(url, {
    method: "GET",
    headers: { Accept: "application/json" },
    timeoutMs,
    maxBytes: maxResponseBytes,
    lookup,
  });
  const text = resp.text;
  // Aptos REST returns 4xx with a JSON body shaped {message, error_code, vm_error_code}.
  // Treat 200 as success, otherwise surface the body as the error so callers
  // can distinguish "no such resource" (404) from RPC trouble (5xx).
  if (!resp.ok) {
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
  // Aptos populates X-Aptos-Ledger-Version on responses; the verifier uses
  // this for the verified-at version reference.
  const ledgerVersionUsed = resp.headers && typeof resp.headers.get === "function"
    ? resp.headers.get("X-Aptos-Ledger-Version") || resp.headers.get("x-aptos-ledger-version")
    : null;
  return { result: parsed, ledger_version_used: ledgerVersionUsed };
}

async function restGet({ network, path, endpoints, timeoutMs = DEFAULT_TIMEOUT_MS, maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES, ledgerVersion = null, lookup } = {}) {
  const rawEndpointList = Array.isArray(endpoints) && endpoints.length > 0
    ? endpoints
    : resolveAptosRpcEndpoints(network);
  const { endpoints: endpointList, rejected } = await filterResolvedPublicRpcEndpoints(rawEndpointList, { lookup });
  if (endpointList.length === 0) {
    const err = new Error(`no public HTTPS REST endpoints available for network ${network}; set BOB_APTOS_RPCS_${String(network).toUpperCase()}=url1,url2 to override`);
    err.rpc_policy_rejections = summarizeRpcPolicyRejections(rejected);
    err.details = { rpc_policy_rejections: err.rpc_policy_rejections };
    throw err;
  }

  const errors = [];
  for (const endpoint of endpointList) {
    try {
      const { result, ledger_version_used } = await restGetOnce(endpoint, path, { timeoutMs, maxResponseBytes, ledgerVersion, lookup });
      return { result, endpoint: redactRpcEndpoint(endpoint), ledger_version_used };
    } catch (error) {
      // 404 is a real "no such resource" answer — bubble it up rather than
      // failing over to other endpoints (they would return the same 404).
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

async function getAccountResource({ network, address, resourceType, endpoints, ledgerVersion = null }) {
  if (!isMoveAddress(address)) {
    throw new Error(`address must be a 0x-prefixed hex Move address (1-64 hex chars), received: ${address}`);
  }
  if (typeof resourceType !== "string" || !resourceType.trim()) {
    throw new Error("resourceType is required (e.g., 0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>)");
  }
  const normalized = normalizeMoveAddress(address);
  return restGet({
    network,
    // The resource_type may contain ":<", ">", and "::" — encode the segment.
    path: `accounts/${normalized}/resource/${encodeURIComponent(resourceType)}`,
    endpoints,
    ledgerVersion,
    maxResponseBytes: 1024 * 1024,
  });
}

async function getAccountModule({ network, address, moduleName, endpoints, ledgerVersion = null }) {
  if (!isMoveAddress(address)) {
    throw new Error(`address must be a 0x-prefixed hex Move address (1-64 hex chars), received: ${address}`);
  }
  if (typeof moduleName !== "string" || !moduleName.trim()) {
    throw new Error("moduleName is required");
  }
  const normalized = normalizeMoveAddress(address);
  return restGet({
    network,
    path: `accounts/${normalized}/module/${encodeURIComponent(moduleName)}`,
    endpoints,
    ledgerVersion,
    maxResponseBytes: 4 * 1024 * 1024,
  });
}

async function getLedgerInfo({ network, endpoints }) {
  return restGet({
    network,
    path: "",
    endpoints,
    maxResponseBytes: 4096,
  });
}

module.exports = {
  DEFAULT_MAX_RESULT_BYTES,
  MOVE_ADDRESS_RE,
  getAccountModule,
  getAccountResource,
  getLedgerInfo,
  isMoveAddress,
  normalizeMoveAddress,
  restGet,
};
