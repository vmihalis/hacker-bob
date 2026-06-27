"use strict";

const dns = require("dns");
const http = require("http");
const https = require("https");
const net = require("net");
const {
  isBlockedInternalHost,
  isFirstPartyHost,
  shouldBlockInternalHosts,
  validateScanUrl,
} = require("./url-surface.js");
const {
  validateHttpScanScope,
} = require("./scope.js");

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_REDIRECTS = 10;
const DEFAULT_MAX_RESPONSE_BYTES = 1_000_000;

function isRedirectStatus(status) {
  return [301, 302, 303, 307, 308].includes(status);
}

function normalizeRedirectMethod(status, method, body) {
  const upperMethod = String(method || "GET").toUpperCase();
  if (status === 303 || ((status === 301 || status === 302) && !["GET", "HEAD"].includes(upperMethod))) {
    return { method: "GET", body: undefined };
  }
  return { method: upperMethod, body };
}

function makeScopeBlockedError(message) {
  const error = new Error(message);
  error.scope_decision = "blocked";
  return error;
}

const SAFE_REDIRECT_HEADERS = new Set(["user-agent", "accept", "accept-language", "accept-encoding"]);

// On a cross-SITE or protocol-DOWNGRADE redirect (a roamed host, or https→http), reduce request headers to
// a minimal non-credential ALLOWLIST so NO target-bound credential — Cookie, Authorization,
// Proxy-Authorization, or a custom auth header (X-Api-Key, X-Auth-Token, …) the caller/auth_profile set —
// is replayed to the new origin. An allowlist, not a Cookie/Authorization denylist, so an arbitrary custom
// auth header can't slip through (round-2: a Cookie/Authorization-only strip was insufficient).
function stripCredentialHeaders(headers) {
  if (!headers || typeof headers !== "object") return headers;
  const cleaned = {};
  for (const [name, value] of Object.entries(headers)) {
    if (SAFE_REDIRECT_HEADERS.has(String(name).toLowerCase())) cleaned[name] = value;
  }
  return cleaned;
}

function assertSafeRequestUrl(url, targetDomain, options = {}) {
  try {
    validateScanUrl(url, options);
    let scopeDecision = null;
    if (targetDomain) {
      scopeDecision = validateHttpScanScope(url, targetDomain);
    }
    return scopeDecision;
  } catch (error) {
    if (!error.scope_decision) {
      error.scope_decision = "blocked";
    }
    throw error;
  }
}

function normalizeHeaders(headers) {
  const normalized = {};
  for (const [name, value] of Object.entries(headers || {})) {
    if (Array.isArray(value)) {
      normalized[name.toLowerCase()] = value.join(", ");
    } else if (value != null) {
      normalized[name.toLowerCase()] = String(value);
    }
  }
  return normalized;
}

class SafeFetchHeaders {
  constructor(headers) {
    this.map = normalizeHeaders(headers);
  }

  get(name) {
    return this.map[String(name || "").toLowerCase()] || null;
  }

  forEach(callback) {
    for (const [name, value] of Object.entries(this.map)) {
      callback(value, name);
    }
  }

  toJSON() {
    return { ...this.map };
  }
}

function lookupAll(hostname) {
  return new Promise((resolve, reject) => {
    dns.lookup(hostname, { all: true }, (error, addresses) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(addresses || []);
    });
  });
}

function normalizeResolverHostname(hostname) {
  const value = String(hostname || "");
  if (value.startsWith("[") && value.endsWith("]")) {
    return value.slice(1, -1);
  }
  return value;
}

async function resolveSafeAddress(hostname, options = {}) {
  const blockInternalHosts = shouldBlockInternalHosts(options);
  const lookupHostname = normalizeResolverHostname(hostname);
  const literalVersion = net.isIP(lookupHostname);
  if (literalVersion) {
    if (blockInternalHosts && isBlockedInternalHost(lookupHostname)) {
      throw makeScopeBlockedError(`Blocked internal/private DNS address for ${hostname}: ${lookupHostname}`);
    }
    return { address: lookupHostname, family: literalVersion };
  }

  const addresses = await lookupAll(lookupHostname);
  if (!addresses.length) {
    throw new Error(`DNS lookup returned no addresses for ${hostname}`);
  }

  if (blockInternalHosts) {
    for (const item of addresses) {
      if (isBlockedInternalHost(item.address)) {
        throw makeScopeBlockedError(`Blocked internal/private DNS address for ${hostname}: ${item.address}`);
      }
    }
  }

  return addresses[0];
}

async function assertSafeResolvedRequestUrl(url, targetDomain, options = {}) {
  const scopeDecision = assertSafeRequestUrl(url, targetDomain, options);
  // A roamed (operator_armed_roam) request ALWAYS resolves and blocks internal IPs, even when the caller
  // disabled blockInternalHosts (the browser navigate path does) — so a public name that RESOLVES to an
  // internal/metadata IP cannot become an SSRF via roam (DNS rebinding). (Round-2 CRITICAL.)
  const enforceInternalBlock = !!(scopeDecision && scopeDecision.enforce_internal_block);
  if (!enforceInternalBlock && !shouldBlockInternalHosts(options)) {
    return;
  }

  const parsed = new URL(url);
  await resolveSafeAddress(parsed.hostname, { ...options, blockInternalHosts: true });
}

function makeTimeoutError(timeoutMs) {
  const error = new Error(`timeout after ${timeoutMs}ms`);
  error.name = "AbortError";
  return error;
}

function bodyToBuffer(body) {
  if (body == null) return undefined;
  if (Buffer.isBuffer(body)) return body;
  if (body instanceof Uint8Array) return Buffer.from(body);
  return Buffer.from(String(body));
}

async function requestOnce(url, options) {
  const parsed = new URL(url);
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  const maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  const hasAgent = options.agent != null;
  const selectedAddress = hasAgent && !shouldBlockInternalHosts(options)
    ? null
    : await resolveSafeAddress(parsed.hostname, options);
  const requestModule = parsed.protocol === "https:" ? https : http;
  const bodyBuffer = bodyToBuffer(options.body);

  return new Promise((resolve, reject) => {
    let settled = false;
    let deadlineTimer = null;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      if (deadlineTimer) {
        clearTimeout(deadlineTimer);
        deadlineTimer = null;
      }
      callback(value);
    };

    const requestOptions = {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port || undefined,
      path: `${parsed.pathname}${parsed.search}`,
      method: options.method || "GET",
      headers: options.headers || {},
    };
    if (options.agent) {
      requestOptions.agent = options.agent;
    }
    if (selectedAddress) {
      requestOptions.lookup = (_hostname, lookupOptions, callback) => {
        const cb = typeof lookupOptions === "function" ? lookupOptions : callback;
        if (lookupOptions && lookupOptions.all) {
          cb(null, [{ address: selectedAddress.address, family: selectedAddress.family }]);
          return;
        }
        cb(null, selectedAddress.address, selectedAddress.family);
      };
    }

    const req = requestModule.request(requestOptions, (res) => {
      const chunks = [];
      let receivedBytes = 0;
      let truncated = false;

      res.on("data", (chunk) => {
        if (settled) return;
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        const remaining = maxResponseBytes - receivedBytes;
        if (remaining > 0) {
          chunks.push(buffer.length > remaining ? buffer.subarray(0, remaining) : buffer);
        }
        receivedBytes += buffer.length;
        if (receivedBytes > maxResponseBytes) {
          truncated = true;
          finish(resolve, buildSafeFetchResponse({
            res,
            url,
            body: Buffer.concat(chunks),
            receivedBytes,
            truncated,
            redirected: options.redirected,
            redirectCount: options.redirectCount,
          }));
          res.destroy();
        }
      });

      res.on("end", () => {
        finish(resolve, buildSafeFetchResponse({
          res,
          url,
          body: Buffer.concat(chunks),
          receivedBytes,
          truncated,
          redirected: options.redirected,
          redirectCount: options.redirectCount,
        }));
      });

      res.on("error", (error) => {
        if (!settled) finish(reject, error);
      });
    });

    // A WebSocket handshake is an HTTP request: GET + Connection/Upgrade
    // headers, answered with `101 Switching Protocols`. Node's http client
    // routes 101 to the 'upgrade' event, NOT the 'response' callback above, so
    // without this handler the request promise never settles and the caller
    // wedges forever on any WS-upgrade endpoint. Resolve with the 101 handshake
    // (status + Sec-WebSocket-Accept and any bytes already buffered after the
    // headers), then release the upgraded socket — this is a one-shot scan, not
    // a live WS client.
    req.on("upgrade", (res, socket, head) => {
      const headBuffer = Buffer.isBuffer(head) ? head : Buffer.alloc(0);
      const capped = headBuffer.length > maxResponseBytes
        ? headBuffer.subarray(0, maxResponseBytes)
        : headBuffer;
      try { socket.destroy(); } catch { /* socket already gone */ }
      finish(resolve, buildSafeFetchResponse({
        res,
        url,
        body: capped,
        receivedBytes: headBuffer.length,
        truncated: headBuffer.length > maxResponseBytes,
        redirected: options.redirected,
        redirectCount: options.redirectCount,
      }));
    });

    req.on("error", (error) => {
      if (!settled) finish(reject, error);
    });

    // The connection can close before the response stream ends (peer reset,
    // premature half-close after a botched upgrade). Without this the promise
    // would never settle. Resolve/reject paths above all run before req 'close'
    // (response 'end' precedes it), so this only fires on a genuine unsettled
    // close.
    req.on("close", () => {
      if (!settled) {
        finish(reject, new Error("connection closed before response completed"));
      }
    });

    // req.setTimeout is a socket-INACTIVITY timeout: a server that holds the
    // connection open or trickles bytes (WS hold, slowloris, chunked keepalive)
    // keeps resetting it, so it can never fire. Arm an absolute wall-clock
    // deadline as the guaranteed backstop.
    req.setTimeout(timeoutMs, () => {
      const error = makeTimeoutError(timeoutMs);
      req.destroy(error);
      finish(reject, error);
    });

    deadlineTimer = setTimeout(() => {
      const error = makeTimeoutError(timeoutMs);
      req.destroy(error);
      finish(reject, error);
    }, timeoutMs);

    if (bodyBuffer) {
      req.write(bodyBuffer);
    }
    req.end();
  });
}

function buildSafeFetchResponse({ res, url, body, receivedBytes, truncated, redirected, redirectCount }) {
  const headers = new SafeFetchHeaders(res.headers || {});
  const bodyBytes = body || Buffer.alloc(0);
  return {
    status: res.statusCode || 0,
    statusText: res.statusMessage || "",
    headers,
    url,
    redirected: !!redirected,
    redirectCount: redirectCount || 0,
    bodyBytes,
    bodyByteLength: receivedBytes || bodyBytes.length,
    bodyTruncated: !!truncated,
    async text() {
      return bodyBytes.toString("utf8");
    },
    async arrayBuffer() {
      return bodyBytes.buffer.slice(bodyBytes.byteOffset, bodyBytes.byteOffset + bodyBytes.byteLength);
    },
  };
}

async function safeFetch(url, options = {}) {
  const followRedirects = options.followRedirects ?? false;
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const targetDomain = options.targetDomain || null;
  const blockInternalHosts = shouldBlockInternalHosts(options);
  let currentUrl = String(url);
  let currentMethod = String(options.method || "GET").toUpperCase();
  let currentBody = options.body;
  let currentHeaders = options.headers;
  let redirects = 0;

  while (true) {
    const scopeDecision = assertSafeRequestUrl(currentUrl, targetDomain, { blockInternalHosts });
    // A roamed hop ALWAYS resolves + blocks internal IPs, even if the caller disabled blockInternalHosts —
    // a public name that resolves to an internal IP cannot become a roam SSRF (DNS rebinding). (CRITICAL.)
    const hopBlockInternal = blockInternalHosts || !!(scopeDecision && scopeDecision.enforce_internal_block);
    const response = await requestOnce(currentUrl, {
      ...options,
      headers: currentHeaders,
      blockInternalHosts: hopBlockInternal,
      method: currentMethod,
      body: currentBody,
      redirected: redirects > 0,
      redirectCount: redirects,
    });
    // Carry THIS hop's scope reason on the response so the caller can audit the FINAL hop — in particular a
    // first-party request that REDIRECTS into a roamed host audits operator_armed_roam, not the initial
    // first-party decision (round-2 CodeRabbit/Codex). The returned response is the final hop's.
    response.scopeReason = scopeDecision && scopeDecision.reason ? scopeDecision.reason : null;

    if (!followRedirects || !isRedirectStatus(response.status)) {
      return response;
    }

    const location = response.headers.get("location");
    if (!location) {
      return response;
    }
    if (redirects >= maxRedirects) {
      throw new Error(`too many redirects (${maxRedirects})`);
    }

    const nextUrl = new URL(location, currentUrl).toString();
    assertSafeRequestUrl(nextUrl, targetDomain, { blockInternalHosts });
    // Reduce headers to the safe allowlist + drop the body on a CROSS-SITE (roamed) or protocol-DOWNGRADE
    // (https→http) redirect, so the target's credentials and request body are never replayed to a different
    // origin — including a 307/308 that would otherwise preserve them. A same-site, same-scheme redirect
    // keeps them. (Round-2: custom auth headers, proxy creds, body, and downgrade — not just Cookie/Auth.)
    let crossOrigin = false;
    try {
      const from = new URL(currentUrl);
      const to = new URL(nextUrl);
      const crossSite = targetDomain
        ? !isFirstPartyHost(to.hostname, targetDomain)
        : to.host !== from.host;
      const downgrade = from.protocol === "https:" && to.protocol === "http:";
      crossOrigin = crossSite || downgrade;
    } catch {
      crossOrigin = true;
    }
    if (crossOrigin) {
      currentHeaders = stripCredentialHeaders(currentHeaders);
      currentBody = undefined;
    }
    redirects += 1;
    const normalized = normalizeRedirectMethod(response.status, currentMethod, currentBody);
    currentMethod = normalized.method;
    currentBody = normalized.body;
    currentUrl = nextUrl;
  }
}

module.exports = {
  DEFAULT_MAX_REDIRECTS,
  DEFAULT_MAX_RESPONSE_BYTES,
  DEFAULT_TIMEOUT_MS,
  SafeFetchHeaders,
  assertSafeResolvedRequestUrl,
  assertSafeRequestUrl,
  resolveSafeAddress,
  isRedirectStatus,
  normalizeRedirectMethod,
  safeFetch,
  stripCredentialHeaders,
};
