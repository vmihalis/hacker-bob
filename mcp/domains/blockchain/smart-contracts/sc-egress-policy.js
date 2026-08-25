"use strict";

const dns = require("dns");
const net = require("net");
const { redactTextSensitiveValues, redactUrlSensitiveValues } = require("../../../redaction.js");
const { isBlockedInternalHost } = require("../../../core/url-surface.js");

const SC_EGRESS_POLICY = Object.freeze({
  transport: "direct",
  protocol: "https",
  block_internal_hosts: true,
  dns_lookup_timeout_ms: 3_000,
  proxy_supported: false,
  private_localnet_default: "unsupported",
});

const SC_PROXY_ENV_KEYS = Object.freeze([
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "all_proxy",
  "no_proxy",
  "npm_config_proxy",
  "npm_config_https_proxy",
  "npm_config_noproxy",
  "YARN_PROXY",
  "YARN_HTTPS_PROXY",
]);

const SC_SECRET_ENV_KEY_RE = /(?:^|[_-])(?:api[_-]?key|auth(?:orization)?|auth[_-]?token|credential|jwt|mnemonic|pass(?:word|wd)?|private[_-]?key|refresh[_-]?token|secret|seed|session|token)(?:$|[_-])/i;
const SC_RPC_ENV_KEY_RE = /(?:^BOB_[A-Z0-9_]*(?:_RPCS?|_FORK_URL)(?:_|$)|(?:^|[_-])(?:URL|RPCS?|RPC_URL|RPC_URI|RPC_ENDPOINT|FORK_URL|FORK_URI|FORK_ENDPOINT|ENDPOINTS?|ENDPOINT_URL|PROVIDER_URL|NODE_URL|FULLNODE_URL|FULL_NODE_URL|REST_URL)(?:$|[_-]))/i;
const SC_CONTROLLED_SUBPROCESS_ENV_KEYS = Object.freeze(new Set([
  "BOB_SVM_FORK_URL",
  "BOB_APTOS_FORK_URL",
  "BOB_SUI_FORK_URL",
  "BOB_SUBSTRATE_FORK_URL",
  "BOB_COSMWASM_FORK_URL",
]));

// The cross-stack consumable-artifact env var the foundry runner injects on a violated
// arm (hex-encoded captured bytes). It is a CONTROLLED, Bob-injected value, never an
// inherited secret/RPC, so it must pass through to the subprocess intact. It matches
// neither SC_SECRET_ENV_KEY_RE nor SC_RPC_ENV_KEY_RE today; this explicit pass-through
// allowlist keeps it delivered even if the secret regex is later tightened to catch an
// "ARTIFACT"-adjacent token, so a future hardening cannot silently break the consume path.
const SC_CONTROLLED_ARTIFACT_ENV_KEYS = Object.freeze(new Set([
  "BOB_CONSUMED_ARTIFACT",
]));

let testLookupOverride = null;

function setSmartContractRpcLookupForTesting(lookupFn) {
  testLookupOverride = typeof lookupFn === "function" ? lookupFn : null;
}

function activeLookup() {
  return testLookupOverride || dns.lookup;
}

function redactRpcEndpoint(value) {
  return redactUrlSensitiveValues(value);
}

function redactRpcEndpointText(value) {
  if (typeof value !== "string") return value;
  return redactTextSensitiveValues(value);
}

function redactRpcEndpointArgs(args) {
  return (Array.isArray(args) ? args : []).map((arg) => (
    typeof arg === "string" ? redactRpcEndpointText(arg) : arg
  ));
}

// Foundry config-DISCOVERY-REDIRECT env. FOUNDRY_CONFIG points config discovery at an arbitrary
// alternate foundry.toml and FOUNDRY_PROFILE selects a non-default profile — either can override the
// runner-pinned project foundry.toml (e.g. the sealed cross-stack project's ffi-off / pinned-solc
// config). Strip both from every SC subprocess so the on-disk project config is authoritative.
// (Bounded defense-in-depth: an agent cannot set the MCP process env — this hardens the same-uid /
// operator-env residual. Other FOUNDRY_* are config VALUES, not redirects, and are left alone.)
const SC_FOUNDRY_CONFIG_REDIRECT_ENV_RE = /^(FOUNDRY_CONFIG|FOUNDRY_PROFILE)$/;
function shouldStripInheritedSmartContractEnvKey(key) {
  return SC_PROXY_ENV_KEYS.includes(key)
    || SC_SECRET_ENV_KEY_RE.test(key)
    || SC_RPC_ENV_KEY_RE.test(key)
    || SC_FOUNDRY_CONFIG_REDIRECT_ENV_RE.test(key);
}

function shouldStripControlledSmartContractEnvKey(key) {
  // An explicitly controlled, Bob-injected artifact var is ALWAYS passed through, even
  // ahead of the secret/proxy checks, so a future secret-regex tightening cannot strip it.
  if (SC_CONTROLLED_ARTIFACT_ENV_KEYS.has(key)) return false;
  if (SC_PROXY_ENV_KEYS.includes(key) || SC_SECRET_ENV_KEY_RE.test(key)) return true;
  return SC_RPC_ENV_KEY_RE.test(key) && !SC_CONTROLLED_SUBPROCESS_ENV_KEYS.has(key);
}

function directSmartContractSubprocessEnv(extraEnv = {}) {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!shouldStripInheritedSmartContractEnvKey(key)) {
      env[key] = value;
    }
  }
  if (extraEnv && typeof extraEnv === "object") {
    for (const [key, value] of Object.entries(extraEnv)) {
      if (!shouldStripControlledSmartContractEnvKey(key)) {
        env[key] = value;
      }
    }
  }
  return env;
}

function parseRpcUrl(value) {
  if (typeof value !== "string" || !value.trim()) return null;
  try {
    return new URL(value.trim());
  } catch {
    return null;
  }
}

function isPrivateHost(hostname) {
  return isBlockedInternalHost(hostname);
}

function isHttpsUrl(value) {
  const parsed = parseRpcUrl(value);
  return !!parsed && parsed.protocol === "https:";
}

function rpcUrlPolicyDecision(value) {
  const parsed = parseRpcUrl(value);
  if (!parsed) {
    return { ok: false, reason: "invalid_url", redacted_endpoint: redactRpcEndpoint(value) };
  }
  if (parsed.protocol !== "https:") {
    return {
      ok: false,
      reason: "unsupported_protocol",
      protocol: parsed.protocol,
      redacted_endpoint: redactRpcEndpoint(parsed.toString()),
    };
  }
  if (isPrivateHost(parsed.hostname)) {
    return {
      ok: false,
      reason: "blocked_internal_host",
      host: parsed.hostname,
      redacted_endpoint: redactRpcEndpoint(parsed.toString()),
    };
  }
  return {
    ok: true,
    endpoint: parsed.toString(),
    redacted_endpoint: redactRpcEndpoint(parsed.toString()),
    host: parsed.hostname,
  };
}

function isPublicHttpsUrl(value) {
  return rpcUrlPolicyDecision(value).ok;
}

function normalizeRpcEndpointList(values) {
  const input = Array.isArray(values) ? values : [values];
  const endpoints = [];
  const rejected = [];
  const seen = new Set();
  for (const value of input) {
    const decision = rpcUrlPolicyDecision(value);
    if (!decision.ok) {
      rejected.push(decision);
      continue;
    }
    if (seen.has(decision.endpoint)) continue;
    seen.add(decision.endpoint);
    endpoints.push(decision.endpoint);
  }
  return { endpoints, rejected };
}

function splitRpcEndpointEnv(raw) {
  if (typeof raw !== "string" || !raw.trim()) return [];
  const values = raw.split(",").map((url) => url.trim()).filter(Boolean);
  return normalizeRpcEndpointList(values).endpoints;
}

// Session-bound RPC override selection. A session MAY carry an
// `rpc_endpoints` array of operator-supplied {chain_family, chain_id, url}
// entries (parsed from `--rpc` by target-intake.parseRpcFlag). This selector
// projects that array onto a single (chain_family, chain_id) pool request and
// returns the matching override URLs.
//
// Additive and fail-closed by construction:
//   - The hard public-HTTPS-only rule is PRESERVED, not re-implemented: every
//     matched url is re-run through normalizeRpcEndpointList (→ rpcUrlPolicyDecision),
//     so a non-https url or a literal private/localnet host is REJECTED here even
//     if it was somehow stored on the session (the stored shape is never trusted).
//   - Absent / empty / non-array `rpc_endpoints`, or a missing selector key,
//     yields {endpoints: [], rejected: []} — no override, so callers fall back to
//     their existing env/default ladder. The fail-closed default is unchanged.
//   - Matching is string-equality on trimmed chain_family and String()-coerced,
//     trimmed chain_id (mirrors contract-target / chain-authority normalization),
//     so a numeric `1` and the string `"1"` fold to one chain. Entries for other
//     chains are simply not applicable (filtered, not "rejected").
// The DNS-private layer is applied downstream by every SC client via
// filterResolvedPublicRpcEndpoints; filterResolvedSessionRpcOverrides below
// bundles that layer for callers that want the full DNS-aware gate inline.
function normalizeSelectorChainId(value) {
  return value == null ? "" : String(value).trim();
}

function selectSessionRpcOverrides(rpcEndpoints, selector = {}) {
  const family = selector && typeof selector.chain_family === "string"
    ? selector.chain_family.trim()
    : "";
  const chainId = normalizeSelectorChainId(selector && selector.chain_id);
  if (!family || !chainId || !Array.isArray(rpcEndpoints) || rpcEndpoints.length === 0) {
    return { endpoints: [], rejected: [] };
  }
  const matched = [];
  for (const entry of rpcEndpoints) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
    const entryFamily = typeof entry.chain_family === "string" ? entry.chain_family.trim() : "";
    const entryChainId = normalizeSelectorChainId(entry.chain_id);
    if (entryFamily !== family || entryChainId !== chainId) continue;
    // Push the raw url unconditionally — normalizeRpcEndpointList is the single
    // policy gate, so a non-string/non-https/private url is rejected (and
    // redacted), never silently passed through.
    matched.push(entry.url);
  }
  return normalizeRpcEndpointList(matched);
}

// DNS-aware variant: selects the session override URLs for a pool request and
// then applies the SAME DNS-private gate every SC client uses, so the full
// "reject non-https, private/localnet, DNS-private" rule is enforced inline.
// Sync-policy rejections and DNS-layer rejections are merged into one redacted
// `rejected` list; the fail-closed empty default is preserved end-to-end.
async function filterResolvedSessionRpcOverrides(rpcEndpoints, selector = {}, { lookup, dnsTimeoutMs } = {}) {
  const selected = selectSessionRpcOverrides(rpcEndpoints, selector);
  if (selected.endpoints.length === 0) {
    return { endpoints: [], rejected: selected.rejected };
  }
  const resolved = await filterResolvedPublicRpcEndpoints(selected.endpoints, { lookup, dnsTimeoutMs });
  return {
    endpoints: resolved.endpoints,
    rejected: [...selected.rejected, ...resolved.rejected],
  };
}

function dnsLookupAll(hostname, lookup = activeLookup(), timeoutMs = SC_EGRESS_POLICY.dns_lookup_timeout_ms) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      finish(new Error(`SC RPC DNS lookup timed out for ${hostname}`));
    }, Math.max(1, Number(timeoutMs) || SC_EGRESS_POLICY.dns_lookup_timeout_ms));
    const finish = (error, addresses, family) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) {
        reject(error);
        return;
      }
      if (Array.isArray(addresses)) {
        resolve(addresses);
        return;
      }
      if (addresses && typeof addresses === "object") {
        resolve([addresses]);
        return;
      }
      if (typeof addresses === "string") {
        resolve([{ address: addresses, family }]);
        return;
      }
      resolve([]);
    };
    try {
      const maybePromise = lookup(hostname, { all: true }, finish);
      if (maybePromise && typeof maybePromise.then === "function") {
        maybePromise.then((addresses) => finish(null, addresses)).catch(finish);
      }
    } catch (error) {
      finish(error);
    }
  });
}

function normalizeAddressRecords(addresses) {
  return (Array.isArray(addresses) ? addresses : [])
    .map((item) => {
      if (typeof item === "string") return { address: item, family: net.isIP(item) || null };
      if (!item || typeof item.address !== "string") return null;
      return { address: item.address, family: item.family || net.isIP(item.address) || null };
    })
    .filter((item) => item && item.address);
}

async function assertResolvedPublicRpcEndpoint(endpoint, { lookup, dnsTimeoutMs } = {}) {
  const decision = rpcUrlPolicyDecision(endpoint);
  if (!decision.ok) {
    const error = new Error(`SC RPC endpoint rejected by policy: ${decision.reason}`);
    error.rpc_policy_rejection = decision;
    throw error;
  }
  const hostForLookup = decision.host.replace(/^\[|\]$/g, "");
  const literalFamily = net.isIP(hostForLookup);
  const addresses = literalFamily
    ? [{ address: hostForLookup, family: literalFamily }]
    : normalizeAddressRecords(await dnsLookupAll(hostForLookup, lookup, dnsTimeoutMs));
  if (addresses.length === 0) {
    const error = new Error(`DNS lookup returned no addresses for ${decision.redacted_endpoint}`);
    error.rpc_policy_rejection = {
      reason: "dns_no_addresses",
      host: decision.host,
      redacted_endpoint: decision.redacted_endpoint,
    };
    throw error;
  }
  for (const item of addresses) {
    if (isBlockedInternalHost(item.address)) {
      const error = new Error(`Blocked internal/private DNS address for SC RPC host ${decision.host}: ${item.address}`);
      error.scope_decision = "blocked";
      error.rpc_policy_rejection = {
        reason: "blocked_internal_dns_address",
        host: decision.host,
        address: item.address,
        redacted_endpoint: decision.redacted_endpoint,
      };
      throw error;
    }
  }
  return {
    endpoint: decision.endpoint,
    redacted_endpoint: decision.redacted_endpoint,
    host: decision.host,
    addresses,
  };
}

async function filterResolvedPublicRpcEndpoints(values, { lookup, dnsTimeoutMs } = {}) {
  const normalized = normalizeRpcEndpointList(values);
  const endpoints = [];
  const rejected = normalized.rejected.slice();
  for (const endpoint of normalized.endpoints) {
    try {
      await assertResolvedPublicRpcEndpoint(endpoint, { lookup, dnsTimeoutMs });
      endpoints.push(endpoint);
    } catch (error) {
      rejected.push(error.rpc_policy_rejection || {
        reason: "dns_lookup_failed",
        redacted_endpoint: redactRpcEndpoint(endpoint),
        message: redactRpcEndpointText(error.message || String(error)),
      });
    }
  }
  return { endpoints, rejected };
}

function summarizeRpcPolicyRejections(rejected) {
  return (Array.isArray(rejected) ? rejected : []).map((item) => ({
    reason: item && item.reason ? item.reason : "unknown",
    endpoint: item && item.redacted_endpoint ? item.redacted_endpoint : null,
    host: item && item.host ? item.host : null,
    address: item && item.address ? item.address : null,
  }));
}

module.exports = {
  SC_EGRESS_POLICY,
  SC_PROXY_ENV_KEYS,
  SC_RPC_ENV_KEY_RE,
  SC_SECRET_ENV_KEY_RE,
  SC_CONTROLLED_ARTIFACT_ENV_KEYS,
  assertResolvedPublicRpcEndpoint,
  directSmartContractSubprocessEnv,
  filterResolvedPublicRpcEndpoints,
  filterResolvedSessionRpcOverrides,
  isHttpsUrl,
  isPrivateHost,
  isPublicHttpsUrl,
  normalizeRpcEndpointList,
  redactRpcEndpoint,
  redactRpcEndpointArgs,
  redactRpcEndpointText,
  rpcUrlPolicyDecision,
  selectSessionRpcOverrides,
  setSmartContractRpcLookupForTesting,
  splitRpcEndpointEnv,
  summarizeRpcPolicyRejections,
};
