"use strict";

const crypto = require("crypto");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  blockInternalHostsPolicyFields,
} = require("./session-state-contracts.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");
const {
  createProxyAgent,
} = require("./egress-profiles.js");
const {
  resolveAndAssertSessionEgressIdentity,
} = require("./session-state.js");
const {
  assertSafeRequestUrl,
  safeFetch,
} = require("./safe-fetch.js");
const {
  assertEnumValue,
  assertNonEmptyString,
  assertRequiredText,
} = require("./validation.js");
// Shared HTTP/surface primitives (extracted in PR-B so the forthcoming
// bob_http_idor_confirm producer reuses the same security-reviewed logic). The
// confirmer passes its own TOOL_ID to the parameterized assertNoForbiddenInputs
// + auditConfirmRequest so its behavior is byte-identical to before the move.
const {
  rejectInvalidArguments,
  assertReadOnlyPath,
  normalizePathTemplate,
  pathTemplateMatchesEndpoint,
  findRoutedSurface,
  resolveBaselineFromSurface,
  isAuthChallenge,
  isLoginRedirect,
  isResourceShapedResponse,
  auditConfirmRequest,
  assertNoForbiddenInputs,
  SCOPE_VALIDATION_OPTS,
} = require("./offensive-http-common.js");

const TOOL_ID = "bob_http_confirm";
const READ_ONLY_METHODS = Object.freeze(["GET", "HEAD", "OPTIONS"]);
const ORACLE_KIND_VALUES = Object.freeze(["differential_response"]);
const DEFAULT_TIMEOUT_MS = 10_000;
const HEADER_SUBSET = Object.freeze({
  accept: "application/json, text/plain;q=0.9, */*;q=0.1",
  "user-agent": "HackerBob-readonly-confirmer/1",
});

function syntheticResourceId() {
  return `bob-synthetic-nonexistent-${crypto.randomUUID()}`;
}

function normalizeMethod(value) {
  const method = value == null ? "GET" : assertRequiredText(value, "method").toUpperCase();
  return assertEnumValue(method, READ_ONLY_METHODS, "method");
}

function normalizeOracleKind(value) {
  return assertEnumValue(assertRequiredText(value, "oracle_kind"), ORACLE_KIND_VALUES, "oracle_kind");
}

function resolveConfirmSurface({ domain, surfaceId, pathTemplate, state }) {
  const { route, surface } = findRoutedSurface(domain, surfaceId);
  const baselineUrl = resolveBaselineFromSurface({
    domain,
    surface,
    pathTemplate,
    state,
  });

  assertReadOnlyPath(baselineUrl.toString());
  if (!pathTemplateMatchesEndpoint(pathTemplate.split("?")[0], baselineUrl.pathname)) {
    rejectInvalidArguments("path_template path shape does not match the surface's recorded endpoint path");
  }

  const syntheticId = syntheticResourceId();
  const resolvedTemplate = pathTemplate.replace("{id}", encodeURIComponent(syntheticId));
  const targetUrl = new URL(resolvedTemplate, baselineUrl.origin);
  assertSafeRequestUrl(targetUrl.toString(), domain, SCOPE_VALIDATION_OPTS);
  assertReadOnlyPath(targetUrl.toString());
  if (targetUrl.origin !== baselineUrl.origin) {
    rejectInvalidArguments("path_template must resolve under the surface endpoint origin");
  }

  return {
    route,
    surface,
    synthetic_id: syntheticId,
    baseline_url: baselineUrl.toString(),
    target_url: targetUrl.toString(),
  };
}

// Read-only differential REPORTER (negative-only). It classifies what the
// same-endpoint unauth differential observed but NEVER mints a signed row.
// Rationale: a resource-shaped 200 on a `bob-synthetic-nonexistent-<uuid>` id is,
// by construction, a catch-all / server-variance signal — NOT proof that one
// specific object's data leaked (a deterministic per-object store 404s an unknown
// id; only non-determinism could make two equivalent synthetic ids differ, and
// that is not an authorization exposure). Soundly proving missing object-auth
// needs a real second-identity IDOR oracle, which is a follow-up. Until then this
// confirmer only DISPROVES leads and surfaces diagnostics — it has no positive
// (write_row) path, so the un-fakeable offensive-runs ledger never signs noise.
function classifyDifferential({ baselineResponse, targetResponse }) {
  if (!isAuthChallenge(baselineResponse)) {
    return { outcome: "blocked_by_infra", exploited: false, reason: "baseline_not_auth_challenge" };
  }
  if (isAuthChallenge(targetResponse)) {
    return { outcome: "blocked_by_defense", exploited: false, reason: "target_auth_challenge" };
  }
  if (targetResponse && targetResponse.status === 404) {
    return { outcome: "blocked_by_defense", exploited: false, reason: "target_not_found_secure_response" };
  }
  if (isLoginRedirect(targetResponse)) {
    return { outcome: "blocked_by_defense", exploited: false, reason: "target_login_redirect" };
  }
  if (targetResponse && [429, 503].includes(targetResponse.status)) {
    return { outcome: "blocked_by_defense", exploited: false, reason: "target_waf_or_rate_limit" };
  }
  if (isResourceShapedResponse(targetResponse)) {
    // Resource-shaped 200 on a synthetic non-existent id == catch-all / variance,
    // not a sound per-object exposure. Reported as a diagnostic negative; minting
    // a signed row here is exactly the unsound positive this tool must not make.
    return { outcome: "blocked_by_infra", exploited: false, reason: "synthetic_id_resource_shape_not_provable" };
  }
  return { outcome: "blocked_by_infra", exploited: false, reason: "target_response_not_resource_shaped" };
}

async function fetchConfirmRequest(url, {
  method,
  headers,
  domain,
  blockInternalHosts,
  agent,
}) {
  return safeFetch(url, {
    method,
    headers,
    body: undefined,
    followRedirects: false,
    timeoutMs: DEFAULT_TIMEOUT_MS,
    targetDomain: domain,
    blockInternalHosts,
    agent,
  });
}

async function httpConfirm(args = {}) {
  assertNoForbiddenInputs(args, TOOL_ID);
  const startedAt = Date.now();
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  const oracleKind = normalizeOracleKind(args.oracle_kind);
  const method = normalizeMethod(args.method);
  const pathTemplate = normalizePathTemplate(args.path_template);
  const { state } = readSessionStateStrict(domain);
  const internalHostPolicy = blockInternalHostsPolicyFields(state);
  const blockInternalHosts = internalHostPolicy.block_internal_hosts === true;
  const surface = resolveConfirmSurface({
    domain,
    surfaceId,
    pathTemplate,
    state,
  });
  // Headers are server-controlled (the immutable HEADER_SUBSET); assertNoForbiddenInputs
  // already blocks any caller-supplied `headers` arg, so no allowlist check is needed.
  const headers = { ...HEADER_SUBSET };

  // Use the session's BOUND egress profile (not a hardcoded "default"), so a
  // session initialized with a regional/proxy profile can use the confirmer
  // instead of being rejected as profile drift.
  const requestedEgressProfile = typeof state.egress_profile === "string" && state.egress_profile.trim()
    ? state.egress_profile
    : "default";
  const { profile, identity } = resolveAndAssertSessionEgressIdentity(domain, requestedEgressProfile, {
    source: TOOL_ID,
  });
  if (blockInternalHosts && profile && profile.proxy_url) {
    throw new ToolError(
      ERROR_CODES.SCOPE_BLOCKED,
      "block_internal_hosts cannot be verified with proxy-backed egress for bob_http_confirm",
      {
        scope_decision: "blocked",
        egress_profile: identity.egress_profile,
      },
    );
  }
  const egressAgent = createProxyAgent(profile.proxy_url);
  const egressProfileName = identity.egress_profile || requestedEgressProfile;
  let baselineResponse;
  let targetResponse;
  // Track which probe is in flight so a fetch failure is audited against the URL
  // that actually failed (baseline vs target), not always the target.
  let inFlightUrl = surface.baseline_url;
  try {
    baselineResponse = await fetchConfirmRequest(surface.baseline_url, {
      method,
      headers,
      domain,
      blockInternalHosts,
      agent: egressAgent,
    });
    auditConfirmRequest({
      domain, surfaceId, method, url: surface.baseline_url,
      egressProfile: egressProfileName, status: baselineResponse.status, startedAt,
      toolId: TOOL_ID,
    });
    inFlightUrl = surface.target_url;
    targetResponse = await fetchConfirmRequest(surface.target_url, {
      method,
      headers,
      domain,
      blockInternalHosts,
      agent: egressAgent,
    });
    auditConfirmRequest({
      domain, surfaceId, method, url: surface.target_url,
      egressProfile: egressProfileName, status: targetResponse.status, startedAt,
      toolId: TOOL_ID,
    });
  } catch (error) {
    const scopeBlocked = error && error.scope_decision === "blocked";
    auditConfirmRequest({
      domain, surfaceId, method, url: inFlightUrl,
      egressProfile: egressProfileName, status: null,
      scopeDecision: scopeBlocked ? "blocked" : null,
      error: error.message || String(error), startedAt,
      toolId: TOOL_ID,
    });
    // NOTE: `failure_reason`, NOT `error` — executeTool treats any returned
    // object with an `error` string as an MCP error, which would surface this
    // intended `blocked_by_infra` negative confirmation as ok:false/INTERNAL_ERROR.
    return {
      confirmed: false,
      target_domain: domain,
      surface_id: surfaceId,
      oracle_kind: oracleKind,
      offensive_outcome: "blocked_by_infra",
      reason: scopeBlocked ? "scope_blocked" : "transport_error",
      failure_reason: error.message || String(error),
      row_written: false,
      ...identity,
      ...internalHostPolicy,
    };
  }

  const classification = classifyDifferential({
    baselineResponse,
    targetResponse,
  });
  // Negative-only confirmer: a synthetic non-existent id has no sound positive
  // signal (see classifyDifferential), so this tool NEVER mints a signed
  // offensive-runs row. It reports the differential outcome as a diagnostic and
  // leaves the signed-row producer path to a real second-identity IDOR oracle
  // (a follow-up). The #108 proof contract is exercised by the seed-based unit
  // tests in test/offensive-proof-contract.test.js + test/severity-rise-guard.test.js.
  return {
    confirmed: false,
    target_domain: domain,
    surface_id: surfaceId,
    oracle_kind: oracleKind,
    offensive_outcome: classification.outcome,
    reason: classification.reason,
    baseline_status: baselineResponse.status,
    target_status: targetResponse.status,
    row_written: false,
    ...identity,
    ...internalHostPolicy,
  };
}

module.exports = {
  HEADER_SUBSET,
  ORACLE_KIND_VALUES,
  READ_ONLY_METHODS,
  TOOL_ID,
  assertReadOnlyPath,
  classifyDifferential,
  httpConfirm,
  isResourceShapedResponse,
  normalizePathTemplate,
};
