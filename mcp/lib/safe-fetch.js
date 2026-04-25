"use strict";

const dns = require("dns");
const http = require("http");
const https = require("https");
const net = require("net");
const {
  isBlockedInternalHost,
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

function assertSafeRequestUrl(url, targetDomain) {
  try {
    validateScanUrl(url);
    if (targetDomain) {
      validateHttpScanScope(url, targetDomain);
    }
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

async function resolveSafeAddress(hostname) {
  const literalVersion = net.isIP(hostname);
  if (literalVersion) {
    if (isBlockedInternalHost(hostname)) {
      throw makeScopeBlockedError(`Blocked internal/private DNS address for ${hostname}: ${hostname}`);
    }
    return { address: hostname, family: literalVersion };
  }

  const addresses = await lookupAll(hostname);
  if (!addresses.length) {
    throw new Error(`DNS lookup returned no addresses for ${hostname}`);
  }

  for (const item of addresses) {
    if (isBlockedInternalHost(item.address)) {
      throw makeScopeBlockedError(`Blocked internal/private DNS address for ${hostname}: ${item.address}`);
    }
  }

  return addresses[0];
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
  const selectedAddress = await resolveSafeAddress(parsed.hostname);
  const requestModule = parsed.protocol === "https:" ? https : http;
  const bodyBuffer = bodyToBuffer(options.body);

  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      callback(value);
    };

    const req = requestModule.request({
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port || undefined,
      path: `${parsed.pathname}${parsed.search}`,
      method: options.method || "GET",
      headers: options.headers || {},
      lookup: (_hostname, lookupOptions, callback) => {
        const cb = typeof lookupOptions === "function" ? lookupOptions : callback;
        if (lookupOptions && lookupOptions.all) {
          cb(null, [{ address: selectedAddress.address, family: selectedAddress.family }]);
          return;
        }
        cb(null, selectedAddress.address, selectedAddress.family);
      },
    }, (res) => {
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

    req.on("error", (error) => {
      if (!settled) finish(reject, error);
    });

    req.setTimeout(timeoutMs, () => {
      const error = makeTimeoutError(timeoutMs);
      req.destroy(error);
      finish(reject, error);
    });

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
  let currentUrl = String(url);
  let currentMethod = String(options.method || "GET").toUpperCase();
  let currentBody = options.body;
  let redirects = 0;

  while (true) {
    assertSafeRequestUrl(currentUrl, targetDomain);
    const response = await requestOnce(currentUrl, {
      ...options,
      method: currentMethod,
      body: currentBody,
      redirected: redirects > 0,
      redirectCount: redirects,
    });

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
    assertSafeRequestUrl(nextUrl, targetDomain);
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
  assertSafeRequestUrl,
  isRedirectStatus,
  normalizeRedirectMethod,
  safeFetch,
};
