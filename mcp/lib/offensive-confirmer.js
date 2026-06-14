"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const {
  OFFENSIVE_OUTCOME_VALUES,
  SEVERITY_VALUES,
} = require("./constants.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  ensureHandoffSigningKey,
} = require("./handoff-signing-key.js");
const {
  blockInternalHostsPolicyFields,
} = require("./session-state-contracts.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");
const {
  readSurfaceRoutesStrict,
} = require("./surface-router.js");
const {
  currentSurfaces,
} = require("./frontier-projections.js");
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
  canonicalizeExploitTarget,
} = require("./claims.js");
const {
  offensiveRunsDir,
  offensiveRunsJsonlPath,
} = require("./paths.js");
const {
  signOffensiveRunRow,
} = require("./offensive-row-mac.js");
const {
  appendJsonlLine,
  withSessionLock,
} = require("./storage.js");
const {
  validateNoSensitiveMaterial,
} = require("./sensitive-material.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  assertEnumValue,
  assertNonEmptyString,
  assertRequiredText,
} = require("./validation.js");

const TOOL_ID = "bob_http_confirm";
const OFFENSIVE_CONFIRM_VERSION = 1;
const READ_ONLY_METHODS = Object.freeze(["GET", "HEAD", "OPTIONS"]);
const ORACLE_KIND_VALUES = Object.freeze(["differential_response"]);
const DEMONSTRATED_SEVERITY_BY_ORACLE = Object.freeze({
  differential_response: "low",
});
const DEFAULT_TIMEOUT_MS = 10_000;
const EMPTY_HASH = crypto.createHash("sha256").update(Buffer.alloc(0)).digest("hex");
const HEADER_SUBSET = Object.freeze({
  accept: "application/json, text/plain;q=0.9, */*;q=0.1",
  "user-agent": "HackerBob-readonly-confirmer/1",
});
const METHOD_OVERRIDE_HEADERS = Object.freeze([
  "x-http-method-override",
  "x-method-override",
  "x-http-method",
  "x-method",
  "_method",
]);
// The REAL safety boundary against "confirm emits a state-changing GET against
// the real recorded id" is STRUCTURAL: {id} must be the final path segment
// (normalizePathTemplate), so no action segment (`/{id}/capture`, `/{id}/transfer`)
// can follow it. A verb denylist can NEVER enumerate the open-ended mutation
// surface (capture/settle/promote/enable/...), so this list is kept deliberately
// NARROW — only unambiguous destructive verbs that are almost never legitimate
// resource-collection nouns — and is best-effort defense-in-depth ONLY, to catch
// a verb-named collection BEFORE the id (`/delete/{id}`). It must NOT include
// ambiguous nouns (order/charge/transfer/block/run) or it would wrongly reject
// legitimate single-resource reads like /api/order/{id}.
const STATE_CHANGE_PATH_SEGMENT_RE = /(?:^|\/)(?:delete|logout|remove|destroy|deactivate|disable|revoke|reset|unsubscribe|terminate|purge|wipe)(?:\/|$)/i;
const VERB_LIKE_TOKEN_RE = /^(?:delete|remove|destroy|logout|create|update|patch|put|post|submit|send|transfer|refund|reset|revoke|disable|enable|drop|truncate|mutation)$/i;

// Recursively percent-decode each path segment until stable (defeats double /
// multi encoding like %2564elete) so the deny-list sees the real verb.
function decodePathSegments(pathname) {
  return pathname
    .split("/")
    .map((seg) => {
      let decoded = seg;
      for (let i = 0; i < 3; i += 1) {
        let next;
        try {
          next = decodeURIComponent(decoded);
        } catch {
          break;
        }
        if (next === decoded) break;
        decoded = next;
      }
      return decoded;
    })
    .join("/");
}

function sha256Buffer(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function generateOffensiveRunId() {
  const stamp = Date.now().toString(16).padStart(12, "0");
  const noise = crypto.randomBytes(4).toString("hex");
  return `oconf-${stamp}-${noise}`;
}

function syntheticResourceId() {
  return `bob-synthetic-nonexistent-${crypto.randomUUID()}`;
}

function rejectInvalidArguments(message, details = null) {
  throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, message, details);
}

function normalizeMethod(value) {
  const method = value == null ? "GET" : assertRequiredText(value, "method").toUpperCase();
  return assertEnumValue(method, READ_ONLY_METHODS, "method");
}

function normalizeOracleKind(value) {
  return assertEnumValue(assertRequiredText(value, "oracle_kind"), ORACLE_KIND_VALUES, "oracle_kind");
}

function assertNoForbiddenInputs(args) {
  for (const field of ["url", "body", "headers", "severity", "demonstrated_severity", "finding_id", "resource_id", "id"]) {
    if (Object.prototype.hasOwnProperty.call(args || {}, field)) {
      rejectInvalidArguments(`bob_http_confirm does not accept ${field}; the request is derived server-side from surface_id and path_template`);
    }
  }
}

function sortedHeaderSubset(headers) {
  return Object.fromEntries(Object.entries(headers).sort(([a], [b]) => a.localeCompare(b)));
}

function assertAllowedRequestHeaders(headers) {
  const allowed = new Set(Object.keys(HEADER_SUBSET));
  for (const name of Object.keys(headers || {})) {
    const lower = name.toLowerCase();
    if (!allowed.has(lower) || METHOD_OVERRIDE_HEADERS.includes(lower)) {
      rejectInvalidArguments(`request header ${name} is not allowed for bob_http_confirm`);
    }
  }
}

function assertReadOnlyPath(url) {
  const parsed = new URL(url);
  const pathAndQuery = `${parsed.pathname}${parsed.search}`;
  const decodedPath = decodePathSegments(parsed.pathname);
  if (STATE_CHANGE_PATH_SEGMENT_RE.test(parsed.pathname) || STATE_CHANGE_PATH_SEGMENT_RE.test(decodedPath)) {
    rejectInvalidArguments(
      "path_template resolves to a state-changing path segment; bob_http_confirm only shrinks, not eliminates, GET-side-effect risk and rejects mutation-shaped paths",
      { path: parsed.pathname },
    );
  }
  const params = new URLSearchParams(parsed.search);
  for (const [rawKey, rawValue] of params.entries()) {
    const key = String(rawKey || "").trim();
    const value = String(rawValue || "").trim();
    if (/^action$/i.test(key) || /^_method$/i.test(key)) {
      rejectInvalidArguments(`query parameter ${key} is not allowed for bob_http_confirm`);
    }
    if (VERB_LIKE_TOKEN_RE.test(key) || VERB_LIKE_TOKEN_RE.test(value)) {
      rejectInvalidArguments(`query parameter ${key} carries a mutation-shaped token`);
    }
    if (/graphql|query/i.test(key) && /\bmutation\b/i.test(value)) {
      rejectInvalidArguments("GraphQL mutation-shaped query is not allowed for bob_http_confirm");
    }
  }
  if (/\bmutation\b/i.test(pathAndQuery)) {
    rejectInvalidArguments("mutation-shaped path or query is not allowed for bob_http_confirm");
  }
}

function normalizePathTemplate(rawTemplate) {
  const template = assertRequiredText(rawTemplate, "path_template");
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(template)) {
    rejectInvalidArguments("path_template must be a path, not an absolute URL");
  }
  if (!template.startsWith("/")) {
    rejectInvalidArguments("path_template must start with /");
  }
  if (template.includes("#")) {
    rejectInvalidArguments("path_template must not include a fragment");
  }
  // No query string: the oracle reads a resource by id, and the baseline (real
  // id) request is built from the recorded endpoint WITHOUT the template query,
  // so a template-only query would make the differential turn on the query
  // rather than on id/auth. Forbid it so baseline and target are symmetric.
  if (template.includes("?")) {
    rejectInvalidArguments("path_template must not include a query string");
  }
  const slotMatches = template.match(/\{id\}/g) || [];
  if (slotMatches.length !== 1) {
    rejectInvalidArguments("path_template must contain exactly one {id} slot");
  }
  const slotIndex = template.indexOf("{id}");
  const queryIndex = template.indexOf("?");
  if (queryIndex !== -1 && slotIndex > queryIndex) {
    rejectInvalidArguments("path_template {id} slot must be in the path, not the query string");
  }
  // STRUCTURAL read-only boundary: {id} must be the FINAL path segment. The
  // baseline request hits the REAL recorded id, so any segment after {id}
  // (`/accounts/{id}/transfer`, `/payments/{id}/capture`) would emit an unauth
  // state-changing GET against a real resource — the incident class this tool
  // exists to prevent — and a verb denylist can never enumerate that surface.
  // Forbidding a trailing segment closes it outright. (Consequence: PR3's oracle
  // confirms only DIRECT resource reads, not sub-resource/action endpoints; a
  // sub-resource read oracle that synthesizes its own baseline is deferred.)
  const pathPart = queryIndex === -1 ? template : template.slice(0, queryIndex);
  const afterSlot = pathPart.slice(pathPart.indexOf("{id}") + "{id}".length);
  if (afterSlot.includes("/")) {
    rejectInvalidArguments("path_template {id} must be the final path segment; bob_http_confirm confirms only direct resource reads, so no path segment may follow {id}");
  }
  return template;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function pathTemplateMatchesEndpoint(templatePathname, endpointPathname) {
  const parts = templatePathname.split("{id}");
  if (parts.length !== 2) return false;
  const pattern = `^${escapeRegExp(parts[0])}[^/]+${escapeRegExp(parts[1])}$`;
  return new RegExp(pattern).test(endpointPathname);
}

function originFromState(domain, state) {
  const targetUrl = state && state.target_url;
  if (typeof targetUrl !== "string" || !targetUrl.trim()) {
    rejectInvalidArguments("bob_http_confirm requires a web session with target_url");
  }
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    rejectInvalidArguments("session target_url is not a valid URL");
  }
  assertSafeRequestUrl(parsed.toString(), domain, { blockInternalHosts: false });
  return parsed.origin;
}

function urlFromEndpoint(endpoint, origin, fieldName) {
  const raw = assertRequiredText(endpoint, fieldName);
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) return new URL(raw);
    if (raw.startsWith("/")) return new URL(raw, origin);
  } catch {
    rejectInvalidArguments(`${fieldName} could not be resolved as a URL`);
  }
  rejectInvalidArguments(`${fieldName} must be an absolute http(s) URL or an absolute path`);
}

function findRoutedSurface(domain, surfaceId) {
  const routed = readSurfaceRoutesStrict(domain);
  const route = routed.document.routes.find((entry) => entry.surface_id === surfaceId) || null;
  if (!route) {
    rejectInvalidArguments(`unknown or unrouted surface_id ${surfaceId}`);
  }
  const surfaces = currentSurfaces(domain);
  const surface = (surfaces.surfaces || []).find((entry) => entry && entry.id === surfaceId) || null;
  if (!surface) {
    rejectInvalidArguments(`surface_id ${surfaceId} is routed but not present in current surfaces`);
  }
  return { route, surface };
}

function candidateSurfaceEndpoints(surface) {
  const candidates = [];
  if (surface && typeof surface.uri === "string" && surface.uri.trim()) {
    candidates.push({ value: surface.uri, field: "surface.uri" });
  }
  if (surface && Array.isArray(surface.endpoints)) {
    for (let index = 0; index < surface.endpoints.length; index += 1) {
      const endpoint = surface.endpoints[index];
      if (typeof endpoint === "string" && endpoint.trim()) {
        candidates.push({ value: endpoint, field: `surface.endpoints[${index}]` });
      }
    }
  }
  return candidates;
}

function resolveSurfaceOrigins(surface, stateOrigin) {
  const origins = new Set([stateOrigin]);
  for (const { value } of candidateSurfaceEndpoints(surface)) {
    try {
      const parsed = new URL(value);
      if (parsed.protocol === "http:" || parsed.protocol === "https:") origins.add(parsed.origin);
    } catch {}
  }
  if (surface && Array.isArray(surface.hosts)) {
    let protocol = "https:";
    try {
      protocol = new URL(stateOrigin).protocol;
    } catch {}
    for (const host of surface.hosts) {
      if (typeof host !== "string" || !host.trim()) continue;
      try {
        origins.add(new URL(`${protocol}//${host.trim().replace(/^https?:\/\//i, "")}`).origin);
      } catch {}
    }
  }
  return Array.from(origins);
}

function resolveBaselineFromSurface({ domain, surface, pathTemplate, state }) {
  const stateOrigin = originFromState(domain, state);
  const origins = resolveSurfaceOrigins(surface, stateOrigin);
  for (const endpoint of candidateSurfaceEndpoints(surface)) {
    for (const origin of origins) {
      let candidate;
      try {
        candidate = urlFromEndpoint(endpoint.value, origin, endpoint.field);
      } catch {
        continue;
      }
      try {
        assertSafeRequestUrl(candidate.toString(), domain, { blockInternalHosts: false });
      } catch {
        continue;
      }
      if (pathTemplateMatchesEndpoint(pathTemplate.split("?")[0], candidate.pathname)) {
        return candidate;
      }
    }
  }
  rejectInvalidArguments("path_template path shape does not match any recorded endpoint for surface_id");
}

function resolveConfirmSurface({ domain, surfaceId, pathTemplate, state }) {
  const { route, surface } = findRoutedSurface(domain, surfaceId);
  const baselineUrl = resolveBaselineFromSurface({
    domain,
    surface,
    pathTemplate,
    state,
  });

  const syntheticId = syntheticResourceId();
  const encodedSyntheticId = encodeURIComponent(syntheticId);
  const resolvedTemplate = pathTemplate.replace("{id}", encodedSyntheticId);
  const targetUrl = new URL(resolvedTemplate, baselineUrl.origin);
  assertSafeRequestUrl(targetUrl.toString(), domain, { blockInternalHosts: false });
  assertReadOnlyPath(targetUrl.toString());
  assertReadOnlyPath(baselineUrl.toString());

  if (targetUrl.origin !== baselineUrl.origin) {
    rejectInvalidArguments("path_template must resolve under the surface endpoint origin");
  }
  if (!pathTemplateMatchesEndpoint(pathTemplate.split("?")[0], baselineUrl.pathname)) {
    rejectInvalidArguments("path_template path shape does not match the surface's recorded endpoint path");
  }

  return {
    route,
    surface,
    synthetic_id: syntheticId,
    baseline_url: baselineUrl.toString(),
    target_url: targetUrl.toString(),
    canonical_target: canonicalizeExploitTarget(targetUrl.toString()),
  };
}

function responseHeadersObject(headers) {
  const out = {};
  if (headers && typeof headers.forEach === "function") {
    headers.forEach((value, key) => {
      out[key] = value;
    });
  }
  return out;
}

function isAuthChallenge(response) {
  return response && (response.status === 401 || response.status === 403);
}

function isLoginRedirect(response) {
  if (!response) return false;
  if (![301, 302, 303, 307, 308].includes(response.status)) return false;
  const location = response.headers && response.headers.get ? response.headers.get("location") : "";
  return /login|signin|auth|sso/i.test(String(location || ""));
}

function responseLooksLikeLoginPage(response) {
  if (!response || !Buffer.isBuffer(response.bodyBytes)) return false;
  const contentType = response.headers && response.headers.get ? String(response.headers.get("content-type") || "") : "";
  if (!/html|text/i.test(contentType)) return false;
  const text = response.bodyBytes.toString("utf8", 0, Math.min(response.bodyBytes.length, 8192));
  return /<form\b/i.test(text) && /\b(password|login|sign\s*in|signin|csrf)\b/i.test(text);
}

// Soft-404 / "no such resource" markers: a 200 carrying these is an existence
// oracle, not a leaked resource — must NOT mint a proof row.
const NON_RESOURCE_TEXT_RE = /not[ _-]?found|no such (?:record|resource|user|object|item|account|entity|row)|does(?:n['’]?t| not) exist|invalid (?:id|identifier|resource)|unknown (?:id|identifier|resource)|"(?:exists|found|present)"\s*:\s*false/i;
// Keys that, alone, mark a response as an error/status envelope rather than a
// resource. (Deliberately excludes "ok"/"id"/"data-payload" keys.)
const ERROR_ENVELOPE_KEYS = new Set(["error", "errors", "message", "detail", "details", "title", "code", "status", "reason"]);
const DATA_WRAPPER_KEYS = Object.freeze(["data", "result", "results", "items", "records", "rows", "entries"]);
// Pagination/listing metadata that is never itself the leaked payload — so an
// object whose only non-envelope keys are an EMPTY data-wrapper plus these
// (e.g. {items:[],total:0,page:1}) is an empty collection, not a resource.
const PAGINATION_METADATA_KEYS = new Set([
  "total", "count", "page", "pages", "per_page", "perpage", "page_size", "pagesize",
  "limit", "offset", "has_more", "hasmore", "has_next", "next", "prev", "previous",
  "cursor", "size", "start", "end", "links", "meta", "pagination",
]);

function contentTypeOf(response) {
  return response && response.headers && response.headers.get
    ? String(response.headers.get("content-type") || "")
    : "";
}

// Read the FULL body (bounded only by safe-fetch's 1 MB response cap) — a fixed
// sub-body window would window-truncate a large genuine JSON resource into
// invalid JSON and fail it closed, silently dropping real missing-auth findings.
function bodyTextOf(response, limit = 1_048_576) {
  if (!response || !Buffer.isBuffer(response.bodyBytes) || response.bodyBytes.length === 0) return "";
  return response.bodyBytes.toString("utf8", 0, Math.min(response.bodyBytes.length, limit));
}

// For a JSON body that did not parse: distinguish a malformed/non-resource body
// (fail closed) from a genuine resource truncated at safe-fetch's 1 MB cap. A
// large structured resource has multiple "key": value pairs; a catch-all ("OK",
// a banner) does not.
function looksStructurallyLikeJsonResource(text) {
  return (text.match(/"[^"\\]+"\s*:/g) || []).length >= 2;
}

function jsonIsGenuineResource(parsed) {
  if (Array.isArray(parsed)) return parsed.length > 0;
  if (parsed == null || typeof parsed !== "object") return false;
  const keys = Object.keys(parsed);
  if (keys.length === 0) return false;
  const isEmptyValue = (value) => value == null
    || (Array.isArray(value) && value.length === 0)
    || (typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0);
  // The leaked PAYLOAD is any key that is not an error/status envelope key, not
  // pagination/listing metadata, and not an EMPTY data-wrapper. An object with
  // no such key — {error:..}, {data:null}, {results:[]}, OR an empty paginated
  // list like {items:[],total:0,page:1} (metadata siblings included) — exposed
  // nothing and is not a resource.
  const payloadKeys = keys.filter((key) => {
    const lower = key.toLowerCase();
    if (ERROR_ENVELOPE_KEYS.has(lower)) return false;
    if (PAGINATION_METADATA_KEYS.has(lower)) return false;
    if (DATA_WRAPPER_KEYS.includes(lower) && isEmptyValue(parsed[key])) return false;
    return true;
  });
  return payloadKeys.length > 0;
}

// Affirmative resource-shape check (fixes the false-positive class: soft-404 /
// generic-200 JSON, empty collections, and SPA/app-shell HTML). We only mint a
// signed "exploited_safely" row when the target genuinely returned resource-like
// content — never on "not 401/403" alone, and never on HEAD/OPTIONS (no body to
// inspect). Ambiguous/unparseable bodies fail CLOSED (no row).
function isResourceShapedResponse(response) {
  if (!response || response.status < 200 || response.status >= 300) return false;
  if (isLoginRedirect(response)) return false;
  if (response.headers && response.headers.get && response.headers.get("www-authenticate")) return false;
  if (!Buffer.isBuffer(response.bodyBytes) || response.bodyBytes.length === 0) return false;
  if (responseLooksLikeLoginPage(response)) return false;
  const text = bodyTextOf(response);
  if (!text.trim()) return false;
  if (NON_RESOURCE_TEXT_RE.test(text)) return false;
  const contentType = contentTypeOf(response);
  const trimmed = text.trim();
  const looksJson = /json/i.test(contentType) || trimmed.startsWith("{") || trimmed.startsWith("[");
  if (looksJson) {
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      // Unparseable JSON is malformed (fail closed) UNLESS the body was
      // truncated at safe-fetch's 1 MB cap — a genuine large resource — which we
      // keep via a structural key:value heuristic so the finding is not dropped.
      return response.bodyTruncated === true && looksStructurallyLikeJsonResource(trimmed);
    }
    return jsonIsGenuineResource(parsed);
  }
  if (/xml/i.test(contentType)) {
    // Genuine XML resource: count DATA leaf elements (<tag>text</tag>) that are
    // NOT status/error envelope tags. >=1 data leaf (e.g. <account><balance>5000
    // </balance></account>) is a resource; a pure status/error envelope
    // (<response><status>ok</status><code>0</code></response>) has 0.
    const leaves = trimmed.match(/<([a-z][\w-]*)\b[^>]*>[^<]+<\/\1\s*>/gi) || [];
    const dataLeaves = leaves.filter((leaf) => {
      const tag = (leaf.match(/^<([a-z][\w-]*)/i) || [])[1] || "";
      return !/^(?:status|code|error|errors|message|msg|reason|detail|title|success|fault|result)$/i.test(tag);
    });
    return dataLeaves.length >= 1;
  }
  if (/html|text/i.test(contentType)) {
    const stripped = text.replace(/<[^>]*>/g, "").replace(/\s+/g, " ").trim();
    if (/<(?:div|main|app-root)[^>]*\bid=["']?(?:root|app|__next)["']?/i.test(text) && stripped.length < 200) {
      return false;
    }
    return stripped.length >= 64;
  }
  // Unrecognized / missing content-type: fail CLOSED. A 200 with no content-type
  // (catch-all / health / default handler) is a manufacture vector, not proof of
  // a leaked resource; genuine binary/download resources are a deferred oracle.
  return false;
}

function classifyDifferential({ baselineResponse, targetResponse, method }) {
  if (!isAuthChallenge(baselineResponse)) {
    return {
      outcome: "blocked_by_infra",
      exploited: false,
      reason: "baseline_not_auth_challenge",
      write_row: false,
    };
  }
  if (isAuthChallenge(targetResponse)) {
    return {
      outcome: "blocked_by_defense",
      exploited: false,
      reason: "target_auth_challenge",
      write_row: false,
    };
  }
  if (targetResponse && targetResponse.status === 404) {
    return {
      outcome: "blocked_by_defense",
      exploited: false,
      reason: "target_not_found_secure_response",
      write_row: false,
    };
  }
  if (isLoginRedirect(targetResponse)) {
    return {
      outcome: "blocked_by_defense",
      exploited: false,
      reason: "target_login_redirect",
      write_row: false,
    };
  }
  if (targetResponse && [429, 503].includes(targetResponse.status)) {
    return {
      outcome: "blocked_by_defense",
      exploited: false,
      reason: "target_waf_or_rate_limit",
      write_row: false,
    };
  }
  if (isResourceShapedResponse(targetResponse)) {
    return {
      outcome: "exploited_safely",
      exploited: true,
      reason: "baseline_auth_challenge_target_resource_shaped",
      write_row: true,
    };
  }
  return {
    outcome: "blocked_by_infra",
    exploited: false,
    reason: "target_response_not_resource_shaped",
    write_row: false,
  };
}

function requestDescriptor({ method, url, headers }) {
  return {
    method,
    url_full_with_query_and_synthetic_id: url,
    sorted_header_subset: sortedHeaderSubset(headers),
    body: null,
  };
}

function captureRequestBytes({ runId, method, targetUrl, baselineUrl, headers, syntheticId, oracleKind }) {
  return Buffer.from(`${JSON.stringify({
    version: 1,
    run_id: runId,
    oracle_kind: oracleKind,
    synthetic_id: syntheticId,
    baseline_request: {
      method,
      url: baselineUrl,
      headers: sortedHeaderSubset(headers),
      body: null,
    },
    target_request: {
      method,
      url: targetUrl,
      headers: sortedHeaderSubset(headers),
      body: null,
    },
    note: "bob_http_confirm uses read-only method/header/path allowlists that shrink, not eliminate, GET-side-effect risk.",
  }, null, 2)}\n`, "utf8");
}

function capturePocBytes({ baselineResponse, targetResponse, classification }) {
  return Buffer.from(`${JSON.stringify({
    version: 1,
    oracle: "differential_response",
    classification,
    baseline_response: {
      status: baselineResponse.status,
      headers: responseHeadersObject(baselineResponse.headers),
      body_sha256: sha256Buffer(baselineResponse.bodyBytes || Buffer.alloc(0)),
      body_bytes: baselineResponse.bodyByteLength || 0,
      body_truncated: baselineResponse.bodyTruncated === true,
    },
    target_response: {
      status: targetResponse.status,
      headers: responseHeadersObject(targetResponse.headers),
      body_sha256: sha256Buffer(targetResponse.bodyBytes || Buffer.alloc(0)),
      body_bytes: targetResponse.bodyByteLength || 0,
      body_truncated: targetResponse.bodyTruncated === true,
    },
  }, null, 2)}\n`, "utf8");
}

function replayFieldsFromArgs(args) {
  const context = args && args.replay_context && typeof args.replay_context === "object"
    ? args.replay_context
    : null;
  if (!context || context.active !== true) {
    return {
      verification_attempt_id: null,
      verification_snapshot_hash: null,
    };
  }
  return {
    verification_attempt_id: typeof context.verification_attempt_id === "string" ? context.verification_attempt_id : null,
    verification_snapshot_hash: typeof context.verification_snapshot_hash === "string" ? context.verification_snapshot_hash : null,
  };
}

function buildSignedOffensiveRunRow({
  domain,
  surfaceId,
  oracleKind,
  runId,
  targetUrl,
  commandHash,
  stdoutHash,
  requestPath,
  responsePath,
  pocPath,
  targetResponse,
  egressContext,
  replayFields,
  classification,
}) {
  // The row label is derived from (and asserted against) the scored
  // classification so a future caller or a new write_row branch can never mint
  // a MAC-signed row whose offensive_outcome diverges from what was proven.
  if (!classification || classification.write_row !== true || classification.outcome !== "exploited_safely") {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "buildSignedOffensiveRunRow requires a classification with write_row=true and outcome=exploited_safely",
      { code: "offensive_row_outcome_mismatch" },
    );
  }
  const demonstratedSeverity = DEMONSTRATED_SEVERITY_BY_ORACLE[oracleKind];
  assertEnumValue(demonstratedSeverity, SEVERITY_VALUES, "demonstrated_severity");
  const row = {
    version: OFFENSIVE_CONFIRM_VERSION,
    target_domain: domain,
    run_id: runId,
    tool_id: TOOL_ID,
    target: canonicalizeExploitTarget(targetUrl),
    offensive_outcome: assertEnumValue(classification.outcome, OFFENSIVE_OUTCOME_VALUES, "offensive_outcome"),
    dry_run: false,
    timed_out: false,
    command_hash: commandHash,
    stdout_hash: stdoutHash,
    stderr_hash: EMPTY_HASH,
    exit_code: 0,
    demonstrated_severity: demonstratedSeverity,
    surface_id: surfaceId,
    verification_attempt_id: replayFields.verification_attempt_id,
    verification_snapshot_hash: replayFields.verification_snapshot_hash,
    confirmed_at: new Date().toISOString(),
    oracle_kind: oracleKind,
    request_path: requestPath,
    response_path: responsePath,
    poc_path: pocPath,
    stdout_bytes: targetResponse.bodyByteLength || 0,
    body_truncated: targetResponse.bodyTruncated === true,
    egress_profile: {
      egress_profile: egressContext.egress_profile || "default",
      egress_region: egressContext.egress_region || null,
      proxy_configured: egressContext.proxy_configured === true,
      egress_profile_identity_hash: egressContext.egress_profile_identity_hash || null,
      egress_profile_identity_version: egressContext.egress_profile_identity_version || null,
    },
  };
  validateNoSensitiveMaterial(row, "offensive_runs");
  return signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
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
  assertNoForbiddenInputs(args);
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
  const headers = { ...HEADER_SUBSET };
  assertAllowedRequestHeaders(headers);
  const commandHash = hashCanonicalJson(requestDescriptor({
    method,
    url: surface.target_url,
    headers,
  }));

  const { profile, identity } = resolveAndAssertSessionEgressIdentity(domain, "default", {
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
  let baselineResponse;
  let targetResponse;
  try {
    baselineResponse = await fetchConfirmRequest(surface.baseline_url, {
      method,
      headers,
      domain,
      blockInternalHosts,
      agent: egressAgent,
    });
    targetResponse = await fetchConfirmRequest(surface.target_url, {
      method,
      headers,
      domain,
      blockInternalHosts,
      agent: egressAgent,
    });
  } catch (error) {
    return {
      confirmed: false,
      target_domain: domain,
      surface_id: surfaceId,
      oracle_kind: oracleKind,
      offensive_outcome: "blocked_by_infra",
      reason: error && error.scope_decision === "blocked" ? "scope_blocked" : "transport_error",
      error: error.message || String(error),
      row_written: false,
      ...identity,
      ...internalHostPolicy,
    };
  }

  const classification = classifyDifferential({
    baselineResponse,
    targetResponse,
    method,
  });
  if (!classification.write_row) {
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

  const runId = generateOffensiveRunId();
  const runsDir = offensiveRunsDir(domain);
  const requestPath = path.join(runsDir, `${runId}.request`);
  const responsePath = path.join(runsDir, `${runId}.response`);
  const pocPath = path.join(runsDir, `${runId}.poc.json`);
  const requestBytes = captureRequestBytes({
    runId,
    method,
    targetUrl: surface.target_url,
    baselineUrl: surface.baseline_url,
    headers,
    syntheticId: surface.synthetic_id,
    oracleKind,
  });
  const responseBytes = Buffer.isBuffer(targetResponse.bodyBytes)
    ? targetResponse.bodyBytes
    : Buffer.alloc(0);
  const pocBytes = capturePocBytes({
    baselineResponse,
    targetResponse,
    classification,
  });
  const stdoutHash = sha256Buffer(responseBytes);
  const signedRow = buildSignedOffensiveRunRow({
    domain,
    surfaceId,
    oracleKind,
    runId,
    targetUrl: surface.target_url,
    commandHash,
    stdoutHash,
    requestPath,
    responsePath,
    pocPath,
    targetResponse,
    egressContext: identity,
    replayFields: replayFieldsFromArgs(args),
    classification,
  });
  withSessionLock(domain, () => {
    fs.mkdirSync(runsDir, { recursive: true });
    fs.writeFileSync(requestPath, requestBytes);
    fs.writeFileSync(responsePath, responseBytes);
    fs.writeFileSync(pocPath, pocBytes);
    appendJsonlLine(offensiveRunsJsonlPath(domain), signedRow);
  });

  const exploitRunRef = {
    kind: "exploit_run",
    run_id: runId,
    tool_id: TOOL_ID,
    target: signedRow.target,
    offensive_outcome: signedRow.offensive_outcome,
    command_hash: signedRow.command_hash,
    exit_code: signedRow.exit_code,
    stdout_hash: signedRow.stdout_hash,
    stderr_hash: signedRow.stderr_hash,
  };

  return {
    confirmed: true,
    target_domain: domain,
    surface_id: surfaceId,
    oracle_kind: oracleKind,
    offensive_outcome: signedRow.offensive_outcome,
    demonstrated_severity: signedRow.demonstrated_severity,
    run_id: runId,
    target: signedRow.target,
    command_hash: signedRow.command_hash,
    stdout_hash: signedRow.stdout_hash,
    stderr_hash: signedRow.stderr_hash,
    exit_code: signedRow.exit_code,
    request_path: requestPath,
    response_path: responsePath,
    poc_path: pocPath,
    row_written: true,
    exploit_run: exploitRunRef,
    baseline_status: baselineResponse.status,
    target_status: targetResponse.status,
    ...identity,
    ...internalHostPolicy,
  };
}

module.exports = {
  DEMONSTRATED_SEVERITY_BY_ORACLE,
  HEADER_SUBSET,
  ORACLE_KIND_VALUES,
  READ_ONLY_METHODS,
  TOOL_ID,
  assertReadOnlyPath,
  buildSignedOffensiveRunRow,
  classifyDifferential,
  generateOffensiveRunId,
  httpConfirm,
  isResourceShapedResponse,
  normalizePathTemplate,
  requestDescriptor,
};
