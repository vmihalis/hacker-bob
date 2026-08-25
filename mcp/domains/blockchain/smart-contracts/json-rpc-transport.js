"use strict";

const {
  filterResolvedPublicRpcEndpoints,
  redactRpcEndpoint,
  redactRpcEndpointText,
  summarizeRpcPolicyRejections,
} = require("./sc-egress-policy.js");
const { requestPublicHttpsText } = require("./sc-http-client.js");

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024;

function makeJsonRpcClient({
  resolveEndpoints,
  selectorKey,
  selectorLabel,
  availabilitySelectorLabel = selectorLabel,
  envHint,
}) {
  if (typeof resolveEndpoints !== "function") throw new TypeError("resolveEndpoints must be a function");
  if (typeof selectorKey !== "string" || !selectorKey) throw new TypeError("selectorKey must be a non-empty string");
  if (typeof selectorLabel !== "string" || !selectorLabel) throw new TypeError("selectorLabel must be a non-empty string");
  if (typeof envHint !== "function") throw new TypeError("envHint must be a function");

  async function rpcRequestOnce(url, method, params, {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
    lookup,
  } = {}) {
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

  async function rpcRequest(options = {}) {
    const {
      method,
      params,
      endpoints,
      timeoutMs = DEFAULT_TIMEOUT_MS,
      maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
      lookup,
    } = options;
    const selector = options[selectorKey];
    const rawEndpointList = Array.isArray(endpoints) && endpoints.length > 0
      ? endpoints
      : resolveEndpoints(selector);
    const { endpoints: endpointList, rejected } = await filterResolvedPublicRpcEndpoints(rawEndpointList, { lookup });
    if (endpointList.length === 0) {
      const err = new Error(`no public HTTPS RPC endpoints available for ${availabilitySelectorLabel} ${selector}; set ${envHint(selector)}=url1,url2 to override`);
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
    const err = new Error(`all RPC endpoints failed for ${method} on ${selectorLabel} ${selector}: ${summary}`);
    err.attempts = errors;
    throw err;
  }

  return Object.freeze({ rpcRequest, rpcRequestOnce });
}

module.exports = {
  DEFAULT_MAX_RESPONSE_BYTES,
  DEFAULT_TIMEOUT_MS,
  makeJsonRpcClient,
};
