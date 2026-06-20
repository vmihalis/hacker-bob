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
const {
  detectPiiShapes,
} = require("./pii-detector.js");
const {
  canonicalJson,
} = require("./verification-contracts.js");
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
  // A `.` / `..` segment is a relative path traversal, never a real resource id:
  // /api/items/.. resolves to the parent collection, /api/items/. to the collection
  // itself. Reject literal AND percent-encoded (%2e) forms (no legit id is . or ..).
  if (idSegment === "." || idSegment === "..") return false;
  if (/[:;,]/.test(idSegment)) return false;
  if (ENCODED_SEPARATOR_RE.test(idSegment)) return false;
  const decoded = decodePathSegments(idSegment);
  if (decoded === "." || decoded === "..") return false;
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
  // Reject path traversal: a `.` or `..` segment, literal OR percent-encoded at any
  // depth (e.g. /api/%252e%252e/admin), that a server may decode would route the
  // request to a DIFFERENT resource than the recorded endpoint. decodePathSegments
  // resolves each segment to a fixed point, so a double-encoded traversal is seen
  // here. No legitimate resource path contains a bare `.`/`..` segment.
  for (const segment of decodedPath.split("/")) {
    if (segment === "." || segment === "..") {
      rejectInvalidArguments(
        `path_template resolves to a path-traversal (. or ..) segment; ${toolName} rejects traversal paths`,
        { path: parsed.pathname },
      );
    }
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
  // A leading `//` is a network-path reference (protocol-relative URL): new URL("//host/x",
  // origin) resolves to a DIFFERENT host, taking the probe off the bound surface origin.
  // It passes the absolute-URL scheme check (no `scheme://`) but is not a path.
  if (template.startsWith("//")) {
    rejectInvalidArguments("path_template must be an absolute path, not a // network-path reference (it resolves to a different host)");
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
  // Check quarantined routes for THIS surface FIRST — BEFORE accepting a route — so a corrupt file
  // (even one with a valid-first occurrence AND a malformed duplicate for the same surface_id) is
  // rejected here exactly as getContextBudget rejects it. Otherwise live offensive probes would
  // trust a file the budget system considers corrupt (split routing authority over one artifact).
  // The reader quarantines instead of bricking; a targeted probe surfaces the repairable reason.
  if (Array.isArray(routed.malformed_routes)) {
    const malformed = routed.malformed_routes.find((entry) => entry.surface_id === surfaceId);
    if (malformed) {
      rejectInvalidArguments(`surface_id ${surfaceId} has a malformed route (re-run bob_route_surfaces): ${malformed.reason}`);
    }
  }
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

// Origins the SURFACE itself declares — parsed from its absolute endpoints and its hosts[] —
// WITHOUT the unconditional session-apex seed that resolveSurfaceOrigins adds. Used to bind a
// RELATIVE endpoint to a host the surface actually names (so api.example.com's "/v1/data" is not
// silently resolved against the session apex example.com).
function surfaceDeclaredOrigins(surface, stateOrigin) {
  const origins = new Set();
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

// Apex-seeded origin list (session origin FIRST, then the surface's declared origins). Identical
// output to the previous inline form; unchanged callers (resolveBaselineFromSurface) keep their
// apex-first preference.
function resolveSurfaceOrigins(surface, stateOrigin) {
  return Array.from(new Set([stateOrigin, ...surfaceDeclaredOrigins(surface, stateOrigin)]));
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
    // A path-absolute reference is a single "/" + path. A leading "//" is a network-path
    // (protocol-relative) reference: new URL("//host/x", origin) resolves to a DIFFERENT host,
    // escaping the surface-host binding and signing a row for the wrong asset. Mirror the
    // normalizePathTemplate guard and reject it here (it falls through to the reject below).
    if (raw.startsWith("/") && !raw.startsWith("//")) return new URL(raw, origin);
  } catch {
    rejectInvalidArguments(`${fieldName} could not be resolved as a URL`);
  }
  rejectInvalidArguments(`${fieldName} must be an absolute http(s) URL or an absolute path (not a // network-path reference)`);
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

// Resolve a representative, scope-validated endpoint URL for a surface — for header-policy
// provers (e.g. bob_http_cors_confirm) that probe an endpoint's RESPONSE policy and need no
// {id}/query path template. Returns the first recorded endpoint that resolves + passes scope,
// with query + fragment stripped (a CORS/header policy is keyed on origin+path, not query).
// Fails closed (no in-scope endpoint) rather than invent an agent-supplied path.
function resolveSurfaceEndpoint({ domain, surface, state, toolName = "bob_http_confirm" }) {
  const stateOrigin = originFromState(domain, state, toolName);
  // A RELATIVE endpoint binds to the surface's OWN declared host(s) — never the session apex (P1):
  // a surface for api.example.com with "/v1/data" must be probed against (and signed for)
  // api.example.com, not example.com, or the MAC-backed row mis-attributes the misconfiguration.
  // A relative endpoint that resolves in-scope against MORE THAN ONE declared host is AMBIGUOUS —
  // silently picking one risks signing the wrong asset, so we fail closed. An ABSOLUTE endpoint
  // carries its own host (unambiguous). With no declared host, a relative endpoint is the apex.
  const declaredOrigins = surfaceDeclaredOrigins(surface, stateOrigin);
  const stripped = (url) => { url.search = ""; url.hash = ""; return url; };
  let sawAmbiguousRelative = false;

  for (const endpoint of candidateSurfaceEndpoints(surface)) {
    const isAbsolute = /^[a-z][a-z0-9+.-]*:\/\//i.test(String(endpoint.value || "").trim());

    if (isAbsolute) {
      let candidate;
      // The origin arg is ignored by urlFromEndpoint for an absolute URL (host is in the value).
      try {
        candidate = urlFromEndpoint(endpoint.value, stateOrigin, endpoint.field);
      } catch {
        continue;
      }
      try {
        assertSafeRequestUrl(candidate.toString(), domain, SCOPE_VALIDATION_OPTS);
      } catch {
        continue;
      }
      return stripped(candidate);
    }

    // Relative endpoint: resolve against each declared host (or the apex if none declared) and
    // collect the in-scope candidates by distinct origin.
    const relHosts = declaredOrigins.length ? declaredOrigins : [stateOrigin];
    const inScopeByOrigin = new Map();
    for (const origin of relHosts) {
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
      if (!inScopeByOrigin.has(candidate.origin)) inScopeByOrigin.set(candidate.origin, stripped(candidate));
    }
    if (inScopeByOrigin.size === 1) return inScopeByOrigin.values().next().value;
    if (inScopeByOrigin.size > 1) { sawAmbiguousRelative = true; continue; }
    // size 0 → try the next candidate endpoint
  }

  if (sawAmbiguousRelative) {
    rejectInvalidArguments(`relative endpoint is ambiguous across multiple in-scope declared hosts for surface_id (${toolName}); record an absolute endpoint to disambiguate`);
  }
  rejectInvalidArguments(`no in-scope recorded endpoint resolves for surface_id (${toolName})`);
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

// The cache-STATUS headers a reverse proxy / CDN sets to report hit-vs-miss for
// THIS response (so their presence proves a cache handled it, and a HIT/MISS token
// inside them is the disposition). Beyond X-Cache / CF-Cache-Status / RFC 9211
// Cache-Status this MUST include the canonical vendor variants — nginx
// X-Cache-Status ($upstream_cache_status), X-Proxy-Cache / X-Nginx-Cache, Google
// Cloud CDN x-goog-cache-status, Akamai X-Cache-Remote (TCP_HIT), EdgeCast/Verizon
// X-EC-Cache, Varnish X-Varnish-Cache/X-VCache — or a path-keyed shared cache that
// labels only one of these (with no Age) would cross-fill undetected. Deliberately
// EXCLUDES Via, X-Served-By, CDN-Cache-Control (set on every response / origin-
// authored — they do not prove a cache HIT) and x-iinfo (an Incapsula WAF marker).
const CACHE_STATUS_HEADERS = Object.freeze([
  "x-cache", "cf-cache-status", "cache-status",
  "x-cache-status", "x-proxy-cache", "x-nginx-cache",
  "x-goog-cache-status", "x-cache-remote", "x-ec-cache",
  "x-varnish-cache", "x-vcache",
]);

// Does the response carry an affirmative cache-HIT signal (a cache demonstrably
// SERVED this body)? Age>0, any cache-status header with a \bhit\b token (underscore-
// normalized so TCP_HIT is seen), or a positive numeric X-Cache-Hits.
function cacheReportsHit(get) {
  const ageRaw = get("age").trim();
  if (/^\d+$/.test(ageRaw) && Number(ageRaw) > 0) return true;
  for (const headerName of CACHE_STATUS_HEADERS) {
    if (/\bhit\b/i.test(get(headerName).replace(/_/g, " "))) return true;
  }
  const hits = get("x-cache-hits").trim();
  return /^\d+$/.test(hits) && Number(hits) > 0;
}

// Does the response carry an affirmative cache-MISS signal (a cache demonstrably
// FETCHED this body from origin)? ONLY an explicit miss/dynamic/bypass cache-status
// token (NOT updating/revalidated/stale — those serve a stale cached body, and NOT a
// numeric X-Cache-Hits:0, which is weaker / cross-CDN-ambiguous).
function cacheReportsMiss(get) {
  // ONLY an explicit cache-status MISS token proves a fresh origin fetch. X-Cache-Hits:0
  // is deliberately NOT a proven miss — a numeric "0 hits" is weaker / cross-CDN-ambiguous
  // and could mask a cross-principal hit, so a response carrying only X-Cache-Hits:0 is
  // NOT trusted as origin and falls through to fail closed (cacheDetectablyInPath).
  const combined = CACHE_STATUS_HEADERS.map((h) => get(h)).join(" ").replace(/_/g, " ");
  return /\b(miss|dynamic|bypass)\b/i.test(combined);
}

// Is a shared cache detectably in the request path at all (regardless of hit/miss)?
// Age (cache-generated per RFC 7234), a numeric X-Cache-Hits, or any cache-status
// header. Deliberately EXCLUDES Via / X-Served-By / CDN-Cache-Control (set on every
// response / origin-authored) and x-iinfo (an Incapsula WAF marker).
function cacheDetectablyInPath(get) {
  return get("age").trim() !== ""
    || get("x-cache-hits").trim() !== ""
    || CACHE_STATUS_HEADERS.some((h) => get(h).trim() !== "");
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
  // A DEFINITIVE cache HIT (Age>0 / explicit HIT token / positive X-Cache-Hits) is the
  // ONLY signal that proves THIS response was served from a shared cache to (potentially)
  // a different principal, so it is the cross-principal hazard. It fires REGARDLESS of
  // Cache-Control — a no-store/private header does not negate an observed hit.
  //
  // A bare Cache-Control directive (public / s-maxage) is the ORIGIN's cacheability HINT,
  // NOT evidence a cache acted on THIS response. Flagging it without a detectable cache in
  // path false-negatives every legit IDOR on an origin that merely marks a resource
  // cacheable. The "cache detectably in path but no proven miss" case (the real residual
  // cross-fill risk) is handled, fail-closed, by cacheInPathWithoutProvenMiss (#15b) — so
  // this function is just the definitive-hit signal and does not speculate on directives.
  return cacheReportsHit(get);
}

// AFFIRMATIVE-ORIGIN gate for the IDOR producer's cross-principal proof bodies
// (PR-C §3.4 hardening). responseIsSharedCacheable only flags a DEFINITIVE hazard
// (Age>0 / explicit HIT); a misconfigured query-string-ignoring shared cache that
// stored a `private`/`no-store` body and emits Age:0 / an unlabeled cache-status
// header leaves no definitive HIT, so canary-survival on a cross-principal read
// could be a downstream cache CROSS-FILL rather than an origin object-authorization
// break. This returns true when a shared cache is DETECTABLY in the request path
// (per cacheDetectablyInPath — Age, a numeric X-Cache-Hits, or any cache-STATUS
// header; NOT Via / X-Served-By / CDN-Cache-Control, which are not cache-hit evidence)
// but does NOT affirmatively prove a fresh origin fetch (no explicit MISS cache
// status). The producer fails CLOSED on true. A direct origin read (NO cache header at
// all) returns false and is trusted; a CDN that labels its MISS returns false and is
// trusted. RESIDUAL: a truly fingerprint-less shared cache is indistinguishable from
// origin here — closed only by a live path-segment cache-buster (PR-D), since a
// query-key cache-buster cannot defeat a path-keyed cache and {id} must stay final.
function cacheInPathWithoutProvenMiss(response) {
  if (!response || !response.headers || typeof response.headers.get !== "function") {
    return false;
  }
  const get = (name) => String(response.headers.get(name) || "");
  // A HIT signal anywhere means a cache SERVED this body — fail closed even if another
  // cache layer also annotates a miss (one layer's miss must NOT override another's hit).
  if (cacheReportsHit(get)) return true;
  // An affirmative miss (and no hit) proves a fresh origin fetch — trust it as origin.
  // ONLY the unambiguous origin-fetch statuses count (miss/dynamic/bypass, X-Cache-Hits:0);
  // updating/revalidated/stale are stale-cache serves and are deliberately not misses.
  if (cacheReportsMiss(get)) return false;
  // A cache is detectably in path but proved no miss → cannot confirm an ORIGIN read,
  // so fail closed. RESIDUAL: a truly fingerprint-less shared cache (no cache header at
  // all) is indistinguishable from origin here — closed only by a live path-segment
  // cache-buster in PR-D (a query-key buster cannot defeat a path-keyed cache, and {id}
  // must stay the final segment).
  return cacheDetectablyInPath(get);
}

// Record each offensive probe in http-audit.jsonl so the session request budget
// and circuit-breaker summary (built from http-audit records) count the live
// traffic — an offensive tool makes multiple live requests per call and must not
// be invisible to the breaker. `toolId` is parameterized so each offensive tool
// (bob_http_confirm, bob_http_idor_confirm) is attributed correctly in the audit
// record's `tool` field; the confirmer passes its own TOOL_ID for byte-identical
// behavior.
// Returns true if the audit record was persisted, false if the write was swallowed
// (so a signing producer can fail closed rather than mint a row for an unrecorded probe).
// The negative-only confirmer ignores the return value, so its behavior is unchanged.
function auditConfirmRequest({ domain, surfaceId, method, url, egressProfile, status, scopeDecision, error, startedAt, toolId }) {
  if (!domain) return false;
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
    return true;
  } catch (auditError) {
    // A swallowed audit-write failure makes this probe invisible to the circuit
    // breaker / request budget — a control-plane gap. We still must not let an
    // audit failure abort the confirm, but surface it to stderr so it is
    // detectable outside the control plane, and report false so a signing producer
    // can fail closed.
    try {
      process.stderr.write(`${toolId}: http-audit write failed: ${auditError && auditError.message ? auditError.message : String(auditError)}\n`);
    } catch {}
    return false;
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

// Resolve the in-scope recorded endpoint(s) of the surface that carry a query string —
// the SERVER-DERIVED injection-locus source for the reflected-XSS family (bob_http_xss_reflect
// proves one param; bob_offensive_dalfox finds across the endpoint's params). Returns an
// array of candidate URL objects (callers refuse 0 = no locus, >1 = ambiguous host).
// NEVER derives a locus from agent input: candidates come from the surface record only. A
// RELATIVE endpoint binds to the surface's OWN host(s), never the session apex (which would
// drift row.target from surface_id). `toolId` is only for the originFromState attribution.
function resolveQueryLocusEndpoint(domain, surface, state, toolId) {
  const stateOrigin = originFromState(domain, state, toolId);
  const allOrigins = resolveSurfaceOrigins(surface, stateOrigin);
  const ownOrigins = allOrigins.filter((origin) => origin !== stateOrigin);
  const relativeOrigins = ownOrigins.length > 0 ? ownOrigins : [stateOrigin];
  const seen = new Set();
  const matches = [];
  for (const endpoint of candidateSurfaceEndpoints(surface)) {
    const isAbsolute = /^[a-z][a-z0-9+.-]*:\/\//i.test(String(endpoint.value).trim());
    const originsForEndpoint = isAbsolute ? [stateOrigin] : relativeOrigins;
    for (const origin of originsForEndpoint) {
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
      if ([...candidate.searchParams.keys()].length === 0) continue;
      const key = candidate.toString();
      if (seen.has(key)) continue;
      seen.add(key);
      matches.push(candidate);
    }
  }
  return matches;
}

// The deterministically sorted, de-duplicated recorded query-param NAMES of the endpoint.
// An ordinal (param_locus) indexes into this stable list — the reflected-XSS PROVER and the
// dalfox FINDER MUST share this derivation so a finder lead's ordinal means the same param
// to the prover.
function recordedQueryParamNames(url) {
  const names = [];
  const seen = new Set();
  for (const name of url.searchParams.keys()) {
    if (seen.has(name)) continue;
    seen.add(name);
    names.push(name);
  }
  return names.sort();
}

// ── shared PII / credential screening for the signed-row producers ───────────
// Extracted VERBATIM from offensive-reflect-producer.js so every signed-row
// producer (reflect + the browser-execution XSS confirm) screens the durable
// row target + captures with byte-identical logic — security screening must not
// drift between two copies. The hex nonce/end-marker tokens the producers mint
// match NONE of these shapes; the screen guards a recorded PATH segment that a
// surface might carry into the durable row target.
const SECRET_SHAPE_RES = Object.freeze([
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/, // jwt
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,                                // aws access key
  /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/,                     // pem
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,                               // github token
  /\bgithub_pat_[A-Za-z0-9_]{30,}/,                               // github fine-grained PAT
  /\bglpat-[A-Za-z0-9_-]{15,}/,                                   // gitlab
  /\bAIza[0-9A-Za-z_-]{35}\b/,                                    // google api key
  /\b[rs]k_live_[A-Za-z0-9]{16,}/,                                // stripe
  /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/,                            // openai
  /\bxox[baprs]-[A-Za-z0-9-]{10,}/,                               // slack
]);

// Percent-decode to a fixed point so a percent-encoded secret / PII shape in a
// PATH segment cannot slip past the literal-ASCII regexes below. Per-triplet
// decode (a whole-string decodeURIComponent throws on a stray `%`); bounded
// iterations catch double-encoding.
function percentDecodeToFixedPoint(value) {
  let current = String(value);
  for (let i = 0; i < 4; i += 1) {
    const next = current.replace(/%[0-9a-fA-F]{2}/g, (m) => {
      try { return decodeURIComponent(m); } catch { return m; }
    });
    if (next === current) break;
    current = next;
  }
  return current;
}

function sensitiveShapesPresent(text) {
  const raw = typeof text === "string" ? text : canonicalJson(text);
  // Screen the raw form AND its percent-decoded form: a recorded path segment
  // can carry a secret / PII shape percent-encoded (e.g. /u/alice%40corp.com or
  // /reset/sk%2Dlive_…) that the literal regexes would otherwise miss before the
  // value persists into the durable signed row target.
  const decoded = percentDecodeToFixedPoint(raw);
  const s = decoded === raw ? raw : `${raw}\n${decoded}`;
  if (detectPiiShapes(s).length > 0) return true;
  return SECRET_SHAPE_RES.some((re) => re.test(s));
}

module.exports = {
  rejectInvalidArguments,
  resolveQueryLocusEndpoint,
  recordedQueryParamNames,
  sensitiveShapesPresent,
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
  resolveSurfaceEndpoint,
  isAuthChallenge,
  isLoginRedirect,
  responseLooksLikeLoginPage,
  isResourceShapedResponse,
  contentTypeOf,
  responseIsSharedCacheable,
  cacheInPathWithoutProvenMiss,
  auditConfirmRequest,
  assertNoForbiddenInputs,
  SCOPE_VALIDATION_OPTS,
};
