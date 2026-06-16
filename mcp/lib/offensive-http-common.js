"use strict";

// Shared HTTP/surface primitives for the offensive confirmer family
// (bob_http_confirm and the forthcoming bob_http_idor_confirm producer).
// Everything here is extracted VERBATIM from offensive-confirmer.js so the
// negative-only confirmer behaves byte-identically; the only parameterized
// surfaces are assertNoForbiddenInputs (toolName + extraFields) and
// auditConfirmRequest (toolId), so a second offensive tool can reuse them
// without forking the security-reviewed logic.

const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  readSurfaceRoutesStrict,
} = require("./surface-router.js");
const {
  currentSurfaces,
} = require("./frontier-projections.js");
const {
  assertSafeRequestUrl,
} = require("./safe-fetch.js");
const {
  assertRequiredText,
} = require("./validation.js");
const {
  appendHttpAuditRecord,
} = require("./http-records.js");
const { redactUrlSensitiveValues } = require("../redaction.js");

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
// The verb may be followed by `/`, end-of-path, OR a format/matrix suffix
// (`.json`, `;v=1`) that many routers strip before dispatch — so /api/delete.json/{id}
// and /api/reset;v=1/{id} are caught too.
const STATE_CHANGE_PATH_SEGMENT_RE = /(?:^|\/)(?:delete|logout|remove|destroy|deactivate|disable|revoke|reset|unsubscribe|terminate|purge|wipe)(?:[./;,]|\/|$)/i;
const VERB_LIKE_TOKEN_RE = /^(?:delete|remove|destroy|logout|create|update|patch|put|post|submit|send|transfer|refund|reset|revoke|disable|enable|drop|truncate|mutation)$/i;

// An encoded path separator at ANY encoding depth: %2F / %5C, %252F, %2525252F,
// etc. (`(25)*` absorbs each extra `%25` layer). Layer-count-independent, so it
// does not depend on how many times decodePathSegments iterates.
const ENCODED_SEPARATOR_RE = /%(?:25)*(?:2f|5c)/i;
// The ONLY suffix allowed after {id}: an inert data/serialization file extension.
// Deliberately a closed allowlist (NOT `\.\w+`) so a verb-shaped dot suffix like
// `{id}.capture` / `{id}.delete` — which routes to an action on the real id — is
// rejected, while `{id}.json` / `{id}.xml` direct reads pass.
const INERT_EXTENSION_RE = /^\.(?:json|xml|csv|tsv|txt|yaml|yml|html?|pdf|md|ndjson|geojson)$/i;
// Pre-fetch URL validation hardcodes blockInternalHosts:false ON PURPOSE — these
// are domain-scope/URL-shape range checks; the session's real SSRF policy
// (block_internal_hosts) is enforced at FETCH time in safeFetch. The named
// constant signals the `false` is intentional, not a dropped policy, so a future
// refactor of the validation layer can't silently strip SSRF enforcement.
const SCOPE_VALIDATION_OPTS = Object.freeze({ blockInternalHosts: false });

function rejectInvalidArguments(message, details = null) {
  throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, message, details);
}

// Recursively percent-decode each path segment until stable (defeats double /
// multi encoding like %2564elete) so the deny-list sees the real verb.
function decodePathSegments(pathname) {
  return pathname
    .split("/")
    .map((seg) => {
      let decoded = seg;
      for (let i = 0; i < 8; i += 1) {
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

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// The recorded baseline id segment must be a CLEAN single resource id. The unauth
// baseline GET hits this REAL recorded id, so anything that can route to a
// sub-resource/action must be rejected, whether it lives in the surface record
// (which normalizePathTemplate never sees) or is supplied raw:
//  - a path separator, literal OR encoded at any depth (%2F, %252F, %25%32%46),
//  - action/matrix punctuation (: ; ,), literal OR percent-escaped (%3A…).
// Decode each segment to a FIXED POINT so multi-layer / split-hex encodings are
// seen, and fail closed on a remnant escape that 8 passes could not resolve.
// KNOWN RESIDUAL: a dot-action suffix in a RECORDED id (e.g. /payments/pay_123.capture
// captured via template /payments/{id}) is NOT rejected here, because real ids
// legitimately contain dots (user.name, 1.2.3, file.bin) and there is no rule that
// separates an action suffix from a dotted id without false-rejecting legit reads.
// Accepted as a conservative-scope limitation: the unreached cases require the
// surface record to already contain an action-shaped path, and the request is a
// read-only GET the scanner would also issue. The template side ({id}.capture) IS
// closed by the inert-extension allowlist in normalizePathTemplate.
function capturedIdSegmentIsSafe(idSegment) {
  if (!idSegment || idSegment.includes("/") || idSegment.includes("\\")) return false;
  if (/[:;,]/.test(idSegment)) return false;
  if (ENCODED_SEPARATOR_RE.test(idSegment)) return false;
  const decoded = decodePathSegments(idSegment);
  if (decoded.includes("/") || decoded.includes("\\")) return false;
  if (/[:;,]/.test(decoded)) return false;
  if (/%[0-9a-f]{2}/i.test(decoded)) return false;
  return true;
}

function pathTemplateMatchesEndpoint(templatePathname, endpointPathname) {
  const parts = templatePathname.split("{id}");
  if (parts.length !== 2) return false;
  const pattern = new RegExp(`^${escapeRegExp(parts[0])}([^/]+)${escapeRegExp(parts[1])}$`);
  const match = pattern.exec(endpointPathname);
  if (!match) return false;
  return capturedIdSegmentIsSafe(match[1]);
}

// `toolName` defaults to "bob_http_confirm" so the negative-only confirmer's
// error strings stay byte-identical after the PR-B extraction; the IDOR producer
// passes its own tool id so its rejection messages name it correctly.
function assertReadOnlyPath(url, toolName = "bob_http_confirm") {
  const parsed = new URL(url);
  const pathAndQuery = `${parsed.pathname}${parsed.search}`;
  const decodedPath = decodePathSegments(parsed.pathname);
  if (STATE_CHANGE_PATH_SEGMENT_RE.test(parsed.pathname) || STATE_CHANGE_PATH_SEGMENT_RE.test(decodedPath)) {
    rejectInvalidArguments(
      `path_template resolves to a state-changing path segment; ${toolName} only shrinks, not eliminates, GET-side-effect risk and rejects mutation-shaped paths`,
      { path: parsed.pathname },
    );
  }
  const params = new URLSearchParams(parsed.search);
  for (const [rawKey, rawValue] of params.entries()) {
    const key = String(rawKey || "").trim();
    const value = String(rawValue || "").trim();
    if (/^action$/i.test(key) || /^_method$/i.test(key)) {
      rejectInvalidArguments(`query parameter ${key} is not allowed for ${toolName}`);
    }
    if (VERB_LIKE_TOKEN_RE.test(key) || VERB_LIKE_TOKEN_RE.test(value)) {
      rejectInvalidArguments(`query parameter ${key} carries a mutation-shaped token`);
    }
    if (/graphql|query/i.test(key) && /\bmutation\b/i.test(value)) {
      rejectInvalidArguments(`GraphQL mutation-shaped query is not allowed for ${toolName}`);
    }
  }
  // Check the raw AND the recursively-decoded path so an encoded `mutation`
  // segment (e.g. /api/%6Dutation/{id}) that routers decode before dispatch is
  // also rejected, not just the literal form.
  if (/\bmutation\b/i.test(pathAndQuery) || /\bmutation\b/i.test(decodedPath)) {
    rejectInvalidArguments(`mutation-shaped path or query is not allowed for ${toolName}`);
  }
}

function normalizePathTemplate(rawTemplate, toolName = "bob_http_confirm") {
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
  // {id} must TERMINATE the final path segment: nothing may follow it except an
  // inert file extension (.json/.xml). This single allowlist rejects, in one rule,
  //  - a following path segment (/accounts/{id}/transfer),
  //  - an encoded separator at ANY depth (/payments/{id}%2Fcapture, %252F...),
  //  - a same-segment action / matrix suffix (/payments/{id}:capture, {id};delete),
  // each of which would make the unauth baseline GET (which hits the REAL recorded
  // id) reach a sub-resource/action — the incident class this tool exists to
  // prevent. A verb denylist can never enumerate that surface; an allowlist closes
  // it structurally. (Consequence: PR3's oracle confirms only DIRECT resource
  // reads; a sub-resource read oracle that synthesizes its own baseline is deferred.)
  if (afterSlot !== "" && !INERT_EXTENSION_RE.test(afterSlot)) {
    rejectInvalidArguments(`path_template {id} must terminate the final path segment (optionally followed by an inert file extension like .json); ${toolName} confirms only direct resource reads, so nothing else may follow {id}`);
  }
  return template;
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

function originFromState(domain, state, toolName = "bob_http_confirm") {
  const targetUrl = state && state.target_url;
  if (typeof targetUrl !== "string" || !targetUrl.trim()) {
    rejectInvalidArguments(`${toolName} requires a web session with target_url`);
  }
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    rejectInvalidArguments("session target_url is not a valid URL");
  }
  assertSafeRequestUrl(parsed.toString(), domain, SCOPE_VALIDATION_OPTS);
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

function resolveBaselineFromSurface({ domain, surface, pathTemplate, state, toolName = "bob_http_confirm" }) {
  const stateOrigin = originFromState(domain, state, toolName);
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
        assertSafeRequestUrl(candidate.toString(), domain, SCOPE_VALIDATION_OPTS);
      } catch {
        continue;
      }
      if (pathTemplateMatchesEndpoint(pathTemplate.split("?")[0], candidate.pathname)) {
        // Drop any query the recorded endpoint carried: the target is built from
        // the (query-free) template, so a baseline query would make the
        // differential turn on query params rather than the id/auth gate.
        // KNOWN RESIDUAL (safe false-negative): a query-ROUTED endpoint
        // (/api/items?format=json, /report?type=summary) whose required param is
        // dropped may 400/404 on the baseline, so classifyDifferential returns
        // baseline_not_auth_challenge instead of testing the gate. The confirmer
        // simply does not cover query-routed endpoints; it never mis-confirms one.
        candidate.search = "";
        return candidate;
      }
    }
  }
  rejectInvalidArguments("path_template path shape does not match any recorded endpoint for surface_id");
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
// oracle, not a leaked resource — must NOT classify as resource-shaped.
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
// Status/health/infra keys that are never themselves a leaked resource — so a
// generic 200 like {ok:true}, {success:false}, or {service:"api",region:"us"}
// from a catch-all/health endpoint is not "resource-shaped". (Canonical resource
// fields like id/name/email are deliberately NOT here.)
const STATUS_HEALTH_KEYS = new Set([
  "ok", "success", "healthy", "alive", "ready", "up", "pong", "ping", "state",
  "version", "service", "uptime", "build", "commit", "hostname", "region",
  "environment", "env", "mode", "timestamp", "time",
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
    if (STATUS_HEALTH_KEYS.has(lower)) return false;
    if (DATA_WRAPPER_KEYS.includes(lower) && isEmptyValue(parsed[key])) return false;
    return true;
  });
  return payloadKeys.length > 0;
}

// Affirmative resource-shape check (rejects the false-positive class: soft-404 /
// generic-200 JSON, empty collections, and SPA/app-shell HTML). Returns true only
// when the target genuinely returned resource-like content — never on "not
// 401/403" alone, and never on HEAD/OPTIONS (no body to inspect). Ambiguous /
// unparseable bodies fail CLOSED (return false). Used purely as a diagnostic by
// the negative-only classifyDifferential; it never gates a signed row.
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

// Cache-cross-fill discriminator for the IDOR producer (PR-C §3.4). A
// cross-tenant read that is actually an edge/CDN cache cross-fill — not an
// origin BOLA — leaves cache-status fingerprints on the response. This flags a
// response that a SHARED cache could have served:
//   - Age > 0                              (the response sat in a shared cache)
//   - X-Cache / CF-Cache-Status / X-Served-By contains HIT
//   - Cache-Control public | s-maxage WITHOUT a Vary: Authorization|Cookie
//     (a shared cache is allowed to serve this object to a different principal)
// A Vary on Authorization/Cookie means the cache keys on the credential, so a
// `public`/`s-maxage` response that varies by credential is NOT a cross-principal
// cache hazard and is not flagged. The producer trips on a true here for P2/P2′
// → `blocked_by_infra:cache_shared_response`, signing nothing. Read-only header
// inspection; never used to gate a signed row positively.
function responseIsSharedCacheable(response) {
  if (!response || !response.headers || typeof response.headers.get !== "function") {
    return false;
  }
  const get = (name) => String(response.headers.get(name) || "");
  const ageRaw = get("age").trim();
  if (ageRaw !== "" && /^\d+$/.test(ageRaw) && Number(ageRaw) > 0) {
    return true;
  }
  const cacheStatusHeaders = ["x-cache", "cf-cache-status", "x-served-by"];
  for (const headerName of cacheStatusHeaders) {
    if (/\bhit\b/i.test(get(headerName))) {
      return true;
    }
  }
  const cacheControl = get("cache-control").toLowerCase();
  // no-store / private take precedence over public / s-maxage — a shared cache
  // must not serve such a response to a different principal, so it is not a
  // cross-principal cache hazard (avoids a false-positive that would reject a
  // legitimate finding as cache_shared_response).
  if (/\bno-store\b/.test(cacheControl) || /\bprivate\b/.test(cacheControl)) {
    return false;
  }
  const sharedDirective = /\bpublic\b/.test(cacheControl) || /\bs-maxage\b/.test(cacheControl);
  if (sharedDirective) {
    const vary = get("vary").toLowerCase();
    const variesByCredential = /\bauthorization\b/.test(vary) || /\bcookie\b/.test(vary);
    if (!variesByCredential) {
      return true;
    }
  }
  return false;
}

// Record each offensive probe in http-audit.jsonl so the session request budget
// and circuit-breaker summary (built from http-audit records) count the live
// traffic — an offensive tool makes multiple live requests per call and must not
// be invisible to the breaker. `toolId` is parameterized so each offensive tool
// (bob_http_confirm, bob_http_idor_confirm) is attributed correctly in the audit
// record's `tool` field; the confirmer passes its own TOOL_ID for byte-identical
// behavior.
function auditConfirmRequest({ domain, surfaceId, method, url, egressProfile, status, scopeDecision, error, startedAt, toolId }) {
  if (!domain) return;
  let parsed = null;
  try {
    parsed = new URL(url);
  } catch {}
  const auditUrl = redactUrlSensitiveValues(url);
  let auditParsed = parsed;
  try {
    auditParsed = new URL(auditUrl);
  } catch {}
  try {
    appendHttpAuditRecord({
      version: 1,
      ts: new Date().toISOString(),
      target_domain: domain,
      method,
      url: auditUrl,
      host: parsed ? parsed.hostname.toLowerCase() : null,
      path: auditParsed ? `${auditParsed.pathname}${auditParsed.search}` : null,
      surface_id: surfaceId || null,
      tool: toolId,
      egress_profile: egressProfile || null,
      status: status == null ? null : status,
      // normalizeHttpAuditRecord REQUIRES a non-empty scope_decision; a null here
      // throws and is swallowed by the catch below, dropping the record entirely
      // (and with it the circuit-breaker/budget visibility). Default a normal
      // probe to "allowed" and a non-scope transport failure to "request_error",
      // matching bob_http_scan's audit convention.
      scope_decision: scopeDecision || (error ? "request_error" : "allowed"),
      error: error || null,
      duration_ms: startedAt ? Date.now() - startedAt : null,
    });
  } catch (auditError) {
    // A swallowed audit-write failure makes this probe invisible to the circuit
    // breaker / request budget — a control-plane gap. We still must not let an
    // audit failure abort the confirm, but surface it to stderr so it is
    // detectable outside the control plane.
    try {
      process.stderr.write(`${toolId}: http-audit write failed: ${auditError && auditError.message ? auditError.message : String(auditError)}\n`);
    } catch {}
  }
}

// The base set of fields no offensive confirmer accepts as caller input: the
// request is derived server-side from surface_id + path_template, never from a
// raw URL/body/headers or an asserted severity/finding id. `extraFields` lets a
// specific tool forbid additional inputs (e.g. the IDOR producer also forbids the
// server-minted object ids and canary). `toolName` is interpolated into the
// rejection message so each tool reports under its own id.
const FORBIDDEN_INPUT_FIELDS = Object.freeze([
  "url", "body", "headers", "severity", "demonstrated_severity", "finding_id", "resource_id", "id",
]);

function assertNoForbiddenInputs(args, toolName, extraFields = []) {
  // Fail fast on a mis-wired caller: a non-array extraFields (e.g. the string
  // "object_id" instead of ["object_id"]) would spread into single characters
  // and silently DROP the intended extra forbidden field — weakening the guard.
  // Throw loudly rather than degrade security quietly.
  if (!Array.isArray(extraFields)) {
    rejectInvalidArguments(`${toolName} forbidden-input guard misconfigured: extraFields must be an array of field names`);
  }
  for (const field of [...FORBIDDEN_INPUT_FIELDS, ...extraFields]) {
    if (Object.prototype.hasOwnProperty.call(args || {}, field)) {
      rejectInvalidArguments(`${toolName} does not accept ${field}; the request is derived server-side from surface_id and path_template`);
    }
  }
}

module.exports = {
  rejectInvalidArguments,
  decodePathSegments,
  escapeRegExp,
  capturedIdSegmentIsSafe,
  pathTemplateMatchesEndpoint,
  assertReadOnlyPath,
  normalizePathTemplate,
  findRoutedSurface,
  candidateSurfaceEndpoints,
  resolveSurfaceOrigins,
  originFromState,
  urlFromEndpoint,
  resolveBaselineFromSurface,
  isAuthChallenge,
  isLoginRedirect,
  responseLooksLikeLoginPage,
  isResourceShapedResponse,
  responseIsSharedCacheable,
  auditConfirmRequest,
  assertNoForbiddenInputs,
  SCOPE_VALIDATION_OPTS,
};
