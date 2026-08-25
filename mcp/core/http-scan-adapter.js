"use strict";

function findContentType(headers) {
  if (headers == null || typeof headers !== "object") return null;
  for (const [key, value] of Object.entries(headers)) {
    if (typeof key !== "string") continue;
    if (key.toLowerCase() !== "content-type") continue;
    if (typeof value !== "string") return null;
    const segment = value.split(";")[0].trim();
    return segment.length > 0 ? segment : null;
  }
  return null;
}

function tryParseJson(value) {
  if (typeof value !== "string" || value.length === 0) return value;
  try {
    return JSON.parse(value);
  } catch (_err) {
    return value;
  }
}

function parseHttpScanResult(rawResult, sent_with_auth) {
  let parsed;
  if (typeof rawResult === "string") {
    try {
      parsed = JSON.parse(rawResult);
    } catch (err) {
      throw new Error(`http-scan result was not JSON: ${err.message || String(err)}`);
    }
  } else if (rawResult != null && typeof rawResult === "object") {
    parsed = rawResult;
  } else {
    throw new Error("http-scan result must be an object or JSON string");
  }
  if (typeof parsed.error === "string" && typeof parsed.status !== "number") {
    return {
      status: null,
      content_type: null,
      body: null,
      sent_with_auth: sent_with_auth === true,
      fetch_error: parsed.error,
      scope_decision: typeof parsed.scope_decision === "string" ? parsed.scope_decision : null,
    };
  }
  const status = typeof parsed.status === "number" ? parsed.status : null;
  const contentType = findContentType(parsed.headers);
  let body = parsed.body;
  if (contentType && contentType.toLowerCase().includes("json")) {
    body = tryParseJson(body);
  }
  return {
    status,
    content_type: contentType,
    body,
    sent_with_auth: sent_with_auth === true,
  };
}

function makeHttpScanFetcher({
  httpScanFn,
  target_domain,
  auth_profile,
  block_internal_hosts,
  egress_profile,
}) {
  if (typeof httpScanFn !== "function") {
    throw new Error("httpScanFn must be a function");
  }
  if (typeof target_domain !== "string" || target_domain.length === 0) {
    throw new Error("target_domain must be a non-empty string");
  }
  const sentWithAuth = typeof auth_profile === "string" && auth_profile.length > 0;
  return async function fetch_fn({ url, method }) {
    const args = {
      method,
      url,
      target_domain,
      response_mode: "full",
      block_internal_hosts: block_internal_hosts === true,
    };
    if (sentWithAuth) args.auth_profile = auth_profile;
    if (typeof egress_profile === "string" && egress_profile.length > 0) {
      args.egress_profile = egress_profile;
    }
    const rawResult = await httpScanFn(args);
    return parseHttpScanResult(rawResult, sentWithAuth);
  };
}

function makePerCallHttpScanFetcher({
  httpScanFn,
  target_domain,
  block_internal_hosts,
  egress_profile,
  freshness,
}) {
  if (typeof httpScanFn !== "function") {
    throw new Error("httpScanFn must be a function");
  }
  if (typeof target_domain !== "string" || target_domain.length === 0) {
    throw new Error("target_domain must be a non-empty string");
  }
  // Opt-in per-arm transport freshness (the auth-differential sweep opts in; the composition
  // live-verifier and the belief object-auth probe leave it OFF and are byte-identical to today).
  // When on, each call carries request cache-control so a cached/stale response can never stand
  // in for a live cross-tenant arm. These directives ride httpScan's existing args.headers
  // pathway (http-scan.js:190) and survive applyAuthProfileHeaders (preserved by presence,
  // auth.js:81) so an auth profile cannot overwrite them. Request headers never enter the
  // response signature or the row preimage, so results_hash / row_mac stay deterministic.
  const freshnessOn = freshness === true;
  return async function fetch_fn({ url, method, auth_profile }) {
    const sentWithAuth = typeof auth_profile === "string" && auth_profile.length > 0;
    const args = {
      method,
      url,
      target_domain,
      response_mode: "full",
      block_internal_hosts: block_internal_hosts === true,
    };
    if (freshnessOn) {
      args.headers = { "Cache-Control": "no-cache, no-store", "Pragma": "no-cache" };
    }
    if (sentWithAuth) args.auth_profile = auth_profile;
    if (typeof egress_profile === "string" && egress_profile.length > 0) {
      args.egress_profile = egress_profile;
    }
    const rawResult = await httpScanFn(args);
    return parseHttpScanResult(rawResult, sentWithAuth);
  };
}

module.exports = {
  parseHttpScanResult,
  makeHttpScanFetcher,
  makePerCallHttpScanFetcher,
};
