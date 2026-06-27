"use strict";

// bob_http_idor_confirm — the second-test-identity IDOR signed-row PRODUCER.
//
// This is the FIRST production writer of `offensive-runs.jsonl` rows + per-run
// capture files. The oracle: identity B writes a producer-minted 256-bit crypto
// canary into B's OWN object O_B at create time; the positive is identity A (a
// different tenant) reading O_B by its id and the response carrying B's exact
// canary AT THE SAME PARSED LEAF. A deterministic/reflective server cannot
// fabricate a 256-bit nonce it never saw — so the witness (canary-FIELD presence
// at a parsed leaf, NEVER a substring, NEVER whole-body equality) is the
// categorical escape from #110's non-existent-id trap.
//
// THREAT-MODEL BOUNDARY (honest, stated verbatim, NOT closed by this file): the
// signed-row MAC defends against an agent confined to the MCP tool surface and
// the guarded Bash surface. It does NOT defend against an agent that executes
// arbitrary in-process code (a same-UID `node -e` that require()s the 0600
// handoff signing key and hand-MACs a row around every gate below). This is the
// SAME assumption Bob's wave-handoff signing already makes; absolute
// un-fakeability requires the deferred offensive-SANDBOX (UID/container) PR. The
// second handler parameter ({ fetch_fn, provision }) — the seam tests use to drive
// the oracle without a live target — is WITHIN this same in-process boundary: a
// same-UID caller that can pass it can already read the signing key and forge a row
// directly, so the seam does not widen the trust boundary the sandbox PR closes. The
// MCP dispatcher always calls idorConfirm(args) with NO second argument.
//
// CACHE-CROSS-FILL RESIDUAL (honest): the canary witness proves identity A obtained
// B's private object, but #15/#15b/#16 distinguish an ORIGIN object-authorization
// break from a downstream shared-cache cross-fill by requiring an affirmative-origin
// signal (no cache in path, or a labeled cache MISS) and failing closed when a cache
// is detectably present without one. A truly FINGERPRINT-LESS query-string-ignoring
// shared cache (no Age/Via/X-Cache and ignores the no-cache request header) is
// indistinguishable from origin here, so it could still mislabel a cache cross-fill
// as an origin IDOR (the cross-tenant READ is real either way, same MEDIUM impact).
// Closed only by a live PATH-segment cache-buster in PR-D — a query-key buster
// cannot defeat a path-keyed cache and {id} must stay the final segment.
//
// INERT AT HEAD: the provenance refuse-to-sign gate (every resolved profile must
// carry synthetic:true + email_origin:"temp_email" + provisioned_via:
// "bob_auto_signup") can never be satisfied pre-PR-PROV — nothing stamps those
// flags and summarizeAuthProfile does not surface them — so the only positive
// (write_row) path is structurally dormant on the merged transport.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");
const {
  blockInternalHostsPolicyFields,
} = require("./session-state-contracts.js");
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
const {
  findRoutedSurface,
  candidateSurfaceEndpoints,
  pathTemplateMatchesEndpoint,
  resolveBaselineFromSurface,
  normalizePathTemplate,
  assertReadOnlyPath,
  assertCreateCollectionShapeSafe,
  capturedIdSegmentIsSafe,
  originFromState,
  isResourceShapedResponse,
  isAuthChallenge,
  isLoginRedirect,
  responseLooksLikeLoginPage,
  responseIsSharedCacheable,
  cacheInPathWithoutProvenMiss,
  auditConfirmRequest,
  assertNoForbiddenInputs,
  SCOPE_VALIDATION_OPTS,
} = require("./offensive-http-common.js");
const {
  canonicalizeExploitTarget,
} = require("./claims.js");
const {
  buildAndSignOffensiveRow,
} = require("./offensive-capture-writer.js");
const {
  resolveAuthProfile,
  buildHeaderProfile,
  PROFILE_METADATA_KEYS,
} = require("./auth.js");
const {
  withSessionLock,
} = require("./storage.js");
const {
  canonicalJson,
} = require("./verification-contracts.js");
const {
  detectPiiShapes,
  MAX_MATCHES: PII_MAX_MATCHES,
} = require("./pii-detector.js");

const TOOL_ID = "bob_http_idor_confirm";
const READ_ONLY_METHODS = Object.freeze(["GET", "HEAD"]);
// The create body is a tiny synthetic skeleton (a few non-canary fields) + a 64-hex canary. safeFetch
// caps RESPONSES, never request bodies, so an oversized create_body would otherwise be POSTed whole to
// the target before the oracle could block (Codex P2). Cap the serialized create_body well above any
// legitimate skeleton; the canary the producer adds is fixed-size and screened separately.
const MAX_CREATE_BODY_BYTES = 8192;
// __proto__/constructor/prototype as a JSON create-body key are prototype-pollution payload shapes on
// many handlers; refused as canary_field / id_field / any create_body key before any write (Codex P2).
const RESERVED_PROTO_KEYS = new Set(["__proto__", "constructor", "prototype"]);
// Body-level method / action dispatch keys: a target honoring `{"_method":"DELETE"}` or `{"action":"run"}`
// could execute a mutation even though the path action-guard passed, so they are refused in create_body
// at any depth before any write (Codex P2).
// Method/action dispatch keys, stored NORMALIZED (so _method / method-override / methodOverride / X-HTTP-
// Method-Override-style body keys all match via normalizeFieldName, not an exact lowercase spelling, Codex P1).
const CREATE_BODY_OVERRIDE_KEYS = new Set([
  "method", "action", "op", "operation", "cmd", "command", "do",
  "methodoverride", "httpmethod", "httpmethodoverride", "xhttpmethodoverride",
]);
// Canonicalize a field NAME so camelCase / snake_case / kebab-case / spacing aliases collapse to one form
// (tenantId / tenant_id / tenant-id -> "tenantid", _id -> "id"). Lets the create-contract guards reject a
// scope-key or id alias on APIs that normalize JSON field names, not just the exact snake_case spelling
// (Codex P1). Returns "" for a non-string so a bogus key can never silently pass.
function normalizeFieldName(name) {
  return typeof name === "string" ? name.toLowerCase().replace(/[^a-z0-9]/g, "") : "";
}
// Request-side client-id aliases (normalized): a create/upsert API honoring any of these would let an
// agent pick the object id, breaking the server-minted-id invariant. The configured id_field is checked
// separately (its normalized form), so this set covers the common aliases beyond it (Codex P1).
const ID_ALIAS_KEYS = new Set(["id", "objectid", "resourceid", "recordid", "entityid", "uuid", "guid", "uid"]);
// Reserved prototype key check that also splits a deep-setter path (dotted / bracketed) — so a JSON
// endpoint expanding `constructor.prototype.x` / `__proto__[x]` into a prototype write is caught for BOTH
// create_body keys AND the canary_field / id_field NAMEs (Codex P1). Raw, case-sensitive segments — the
// JS-meaningful spellings (normalizeFieldName would strip the underscores).
function keyHasReservedSegment(key) {
  return String(key).split(/[.[\]]/).some((seg) => RESERVED_PROTO_KEYS.has(seg));
}
// Client-id alias check that ALSO splits a deep-setter path (dotted / bracketed), mirroring
// keyHasReservedSegment — so a create_body key like `id.uuid` / `uid[value]` (which a JSON endpoint may
// expand into an id object, letting the caller choose/upsert the object id before the server-minted-id
// invariant can be enforced) is caught alongside the whole-name normalized check that only sees the
// collapsed `iduuid`/`uidvalue` (Codex P1). Each split segment is normalized before matching the alias set
// or the configured id_field. Used for create_body keys AND the canary_field NAME.
function keyHasIdAliasSegment(key, normIdField) {
  return String(key).split(/[.[\]]/).some((seg) => {
    const n = normalizeFieldName(seg);
    return n !== "" && (ID_ALIAS_KEYS.has(n) || (normIdField && n === normIdField));
  });
}
// Ownership / scope SELECTOR fields, matched by BASE NOUN rather than an enumerated alias list: a create
// API honoring one would steer the synthetic object into a caller-chosen real tenant/principal, breaking
// the synthetic-owned boundary (the object must belong to the creating synthetic identity, inferred from
// its auth). `baseNoun` normalizes then strips a trailing "id"/"by" (twice), so the BARE form (tenant,
// user, team), the _id form (tenant_id, user_id), and the _by[_id] form (created_by, created_by_id) all
// collapse to one base — closing the alias/suffix tail rather than enumerating it (Codex P1).
const SCOPE_BASE_NOUNS = new Set(["tenant", "org", "organization", "workspace", "ownerscope", "namespace", "realm", "company", "enterprise", "business"]);
// Clear ownership SELECTORS only — content-ambiguous nouns (created/creator/author, which appear in benign
// created_at / author-name fields) are deliberately excluded; the actor pattern *_by (created_by/updated_by)
// is caught by the "by" token rule in fieldIsOwnerSelector instead.
const OWNER_BASE_NOUNS = new Set(["user", "owner", "account", "customer", "member", "team", "group", "project", "principal", "assignee"]);
function baseNoun(normName) {
  let s = String(normName);
  // Strip trailing key-suffixes iteratively so tenant_uuid / workspaceGuid / owner_uid / tenant_ids /
  // user_ids / created_by_id / teams all collapse to the base noun (tenant, workspace, owner, user,
  // created, team) — closing the suffix tail rather than enumerating it (Codex P1). Longest suffix first;
  // length guards keep a BARE "uid"/"uuid"/"guid"/"id" intact (those are caught as id aliases instead).
  for (let i = 0; i < 5; i += 1) {
    if (s.length > 4 && (s.endsWith("uuid") || s.endsWith("guid"))) s = s.slice(0, -4);
    else if (s.length > 3 && (s.endsWith("ids") || s.endsWith("bys") || s.endsWith("uid"))) s = s.slice(0, -3);
    else if (s.length > 2 && (s.endsWith("id") || s.endsWith("by"))) s = s.slice(0, -2);
    else if (s.length > 3 && s.endsWith("s")) s = s.slice(0, -1);
    else break;
  }
  return s;
}
// TOKENIZE a field name into lowercase word tokens (split on non-alnum AND camelCase/Pascal boundaries).
// Matching ANY token against the scope/owner sets — instead of normalizing the WHOLE name — catches a
// PREFIXED selector (victim_tenant_id), a COMPOSITE one (owner_user_id), and an alternative-suffix one
// (tenant_slug, workspaceKey, org_code) that whole-name base-noun matching misses (brutalist / Codex P1).
function fieldNameTokens(name) {
  return String(name)
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}
const inSet = (set, t) => set.has(t) || set.has(baseNoun(t));
function fieldIsScopeSelector(name) {
  // Whole-name match catches a JOINED noun (owner_scope -> "ownerscope"); token match catches a prefixed /
  // composite / alt-suffix one (victim_tenant_id, tenant_slug).
  if (inSet(SCOPE_BASE_NOUNS, normalizeFieldName(name))) return true;
  return fieldNameTokens(name).some((t) => inSet(SCOPE_BASE_NOUNS, t));
}
function fieldIsOwnerSelector(name) {
  if (inSet(OWNER_BASE_NOUNS, normalizeFieldName(name))) return true;
  const tokens = fieldNameTokens(name);
  // A trailing-actor field (created_by / updated_by / modified_by / deleted_by) assigns the principal —
  // detected by a standalone "by" token, so created_at / updated_at (timestamps) are NOT caught.
  if (tokens.includes("by")) return true;
  return tokens.some((t) => inSet(OWNER_BASE_NOUNS, t));
}
// Privilege / authorization-assignment SELECTOR tokens: a create API honoring one would let the
// operator-armed write mint an ELEVATED synthetic object (an admin/role/permission-bearing account)
// instead of a plain canary-bearing resource — a confined agent using the operator's write-authorization
// for privilege escalation rather than the intended cross-tenant READ proof (Codex P1). Matched by TOKEN
// (like the scope/owner selectors) so role / roles / is_admin / isAdmin / user_role / permission_ids /
// granted_scopes all trip. Deliberately omits over-generic tokens (root/staff/access/level) that collide
// with benign fields (root_cause, staff_name); kept to unambiguous privilege markers.
const PRIVILEGE_BASE_TOKENS = new Set([
  "role", "roles", "admin", "isadmin", "superuser", "superadmin", "sudo",
  "privilege", "privileges", "permission", "permissions", "perm", "perms",
  "grant", "grants", "acl", "scope", "scopes", "capability", "capabilities",
  "authority", "authorities", "entitlement", "entitlements",
]);
function fieldIsPrivilegeSelector(name) {
  if (PRIVILEGE_BASE_TOKENS.has(normalizeFieldName(name))) return true;
  return fieldNameTokens(name).some((t) => PRIVILEGE_BASE_TOKENS.has(t) || PRIVILEGE_BASE_TOKENS.has(baseNoun(t)));
}
// Credential / secret-bearing field NAMES: screenCreateBody screens value SHAPES (URL / GraphQL) and the
// write-byte scan catches narrowly-shaped tokens (AWS / JWT / PEM), but a `{password:"weak"}` /
// `{api_key:"local-test"}` whose VALUE matches no token regex would be POSTed verbatim — contradicting the
// "every written byte secret-screened" contract (brutalist / Codex P1). Refuse the field by NAME, fail-closed,
// regardless of value shape. Matched as a whole normalized name OR a joined-token match (apiKey -> "apikey",
// client_secret -> "clientsecret") so camel/snake/kebab spellings all trip.
const CREDENTIAL_WHOLE_NAMES = new Set([
  "password", "passwd", "pwd", "secret", "apikey", "apisecret", "token", "accesstoken", "refreshtoken",
  "clientsecret", "privatekey", "secretkey", "authorization", "credential", "credentials", "passphrase",
  "sessiontoken", "bearertoken",
]);
// STRONG markers safe to match as a BARE token inside a compound name (user_password, account_apikey) without
// false-positiving on benign fields — UNLIKE the generic `secret` / `token` / `authorization`, which match
// ONLY as a whole name, so secret_note / csrf_token / authorization_status stay clean and still mint.
const CREDENTIAL_STRONG_TOKENS = new Set([
  "password", "passwd", "pwd", "apikey", "apisecret", "clientsecret", "privatekey", "secretkey", "passphrase",
  "accesstoken", "refreshtoken", "sessiontoken", "bearertoken",
]);
function fieldIsCredentialSelector(name) {
  if (CREDENTIAL_WHOLE_NAMES.has(normalizeFieldName(name))) return true;
  const tokens = fieldNameTokens(name);
  if (tokens.some((t) => CREDENTIAL_STRONG_TOKENS.has(t))) return true;
  // Join adjacent tokens so api_key/apiKey -> "apikey", client_secret -> "clientsecret", access_token ->
  // "accesstoken" all match the joined credential names even when split into two tokens.
  for (let i = 0; i < tokens.length - 1; i += 1) {
    if (CREDENTIAL_WHOLE_NAMES.has(tokens[i] + tokens[i + 1])) return true;
  }
  return false;
}
// True when a create_body string VALUE is a fetch/connection URL (brutalist / Codex P1). SCHEME-AGNOSTIC,
// not an enumerated allowlist — any authority-bearing URI can drive a server-side fetch/connection (SSRF):
//  - protocol-relative `//host` / `\\host` (either slash direction);
//  - ANY `scheme://authority` (http/https/ftp/file/gopher/ldap/ssh/sftp/redis/mongodb/jdbc:mysql://…);
//  - a known fetch scheme with NO `//` then ANY authority char (incl. IPv6 `[`, userinfo `@`, alnum) — so
//    http:host / http:[::1] / http:@h (WHATWG-normalized to absolute URLs) are caught;
//  - a WHATWG parse that yields a non-empty HOST (any scheme), catching anything the regexes miss.
// "file: report" / "note: hi" / "ratio 3:1" (no `//`, no authority char, unparseable) are NOT URLs.
function valueLooksLikeUrl(value) {
  const s = String(value).trim();
  if (/^[\\/]{2}/.test(s)) return true;
  if (/:\/\//.test(s)) return true;
  if (/^(?:https?|ftp|file|gopher|wss?|dict|ldaps?|sftp|ssh|redis|mongodb|jar):[\\/]*[^\s/\\]/i.test(s)) return true;
  try { if (new URL(s).host) return true; } catch { /* not URL-parseable */ }
  return false;
}
// True when a create_body string value carries a GraphQL OPERATION document — query, mutation, OR
// subscription (brutalist / Codex P1: the mutation-only screen let a `{"query":"query {...}"}` body + a
// derived POST /graphql become an arbitrary authenticated GraphQL surface, where even a read query can
// exfiltrate data the tool then carries in-process). An operation keyword + a `{` (a selection set must
// follow) closes the whole grammar tail — directives (@x), comments (#…), commas, named/anonymous ops — in
// one rule. A benign "mutation rate: 0.5" / "query the manual" (no `{`) is not matched; the derived
// /graphql COLLECTION itself is independently refused by the action-verb guard (graphql ∈ WRITE_ACTION_VERBS).
function valueLooksLikeGraphqlOperation(value) {
  const s = String(value);
  // Named/keyworded operation: query|mutation|subscription + a selection set.
  if (/\b(?:query|mutation|subscription)\b/i.test(s) && s.includes("{")) return true;
  // ANONYMOUS query shorthand (brutalist / Codex P1): `{ viewer { email } }` is a valid GraphQL query
  // document with NO operation keyword, so it slips the keyword check and — on a GraphQL endpoint mounted
  // at /api or /gql (not literally /graphql, so the action-verb collection guard misses it) — a
  // `create_body:{query:"{ ... }"}` becomes an authenticated GraphQL READ on the first POST. A brace-wrapped
  // value that is NOT valid JSON (GraphQL field selections have no quoted keys / colons, unlike a JSON
  // object) is treated as a GraphQL document and refused. A benign JSON-object string still parses and passes.
  const t = s.trim();
  if (t.startsWith("{") && t.includes("}")) {
    try { JSON.parse(t); } catch { return true; }
  }
  return false;
}
// Recursively screen the agent-supplied create_body skeleton BEFORE any write. The body is spread
// unchanged into the POST (only canary_field is overwritten), so a hostile/buggy skeleton can subvert
// the target or the oracle. Walk every key at every depth (objects + arrays) and fail closed on:
//  - a reserved prototype key (nested prototype-pollution shape);
//  - a method/action-dispatch key (body-level method override);
//  - a client-id key — the configured id_field OR a known id alias (object_id/resource_id/uuid/...),
//    normalized, at ANY depth: the object id must NEVER be agent-supplied (Codex P1);
//  - an owning-scope key (owner_scope/tenant_id/org_id/workspace_id and their aliases), normalized, at
//    ANY depth: a {tenant_id:"victim-org"} body would make the live write drift into a caller-chosen
//    tenant/workspace before the oracle blocks (Codex P1);
//  - an owner-ASSIGNMENT key (user_id/owner_id/account_id/created_by/…), normalized, at ANY depth: a
//    create API honoring it would assign the synthetic object to a caller-chosen real principal (Codex P1);
//  - a URL-shaped string VALUE at ANY depth, in objects OR arrays (avatar_url/callback_url/["http://…"]):
//    a target that fetches body URLs would turn the canary create into an SSRF / off-target callback;
//  - a GraphQL mutation/subscription OPERATION string at ANY depth: on a GraphQL-compatible derived
//    collection it would execute an arbitrary mutation rather than create a synthetic object (Codex P1).
// Returns a blocked() reason string, or null when the body is clean. depth-bounded to fail closed.
function screenCreateBody(value, idField, depth = 0) {
  if (depth > 8) return "create_body_too_deep";
  // STRING values are screened at the top so the same checks cover BOTH object-property values AND array
  // elements (a URL/GraphQL string hidden in {callbacks:["http://…"]} must not slip the property-only loop,
  // Codex P1). A URL-shaped value would be fetched by some targets (SSRF/callback); a GraphQL mutation
  // operation would execute on a GraphQL-compatible derived collection.
  if (typeof value === "string") {
    // Screen the raw value AND its fully-decoded form: a target that percent-/unicode-decodes a JSON
    // string before using it as a callback/import URL or GraphQL document would otherwise be reached by
    // an encoded `http%3a%2f%2f…` / `mutation%20{` the raw check misses (Codex P1).
    for (const probe of [value, decodeAllEncodingLayers(value)]) {
      if (valueLooksLikeUrl(probe)) return "create_body_url_value";
      if (valueLooksLikeGraphqlOperation(probe)) return "create_body_graphql_operation";
    }
    return null;
  }
  if (Array.isArray(value)) {
    for (const el of value) { const r = screenCreateBody(el, idField, depth + 1); if (r) return r; }
    return null;
  }
  if (!value || typeof value !== "object") return null;
  const normIdField = normalizeFieldName(idField);
  for (const key of Object.keys(value)) {
    const k = String(key);
    if (keyHasReservedSegment(k)) return "reserved_field_name"; // incl. dotted/bracketed deep-setter paths
    const norm = normalizeFieldName(k);
    if (CREATE_BODY_OVERRIDE_KEYS.has(norm)) return "create_body_action_override";
    if (fieldIsScopeSelector(k)) return "create_body_scope_field";
    // The configured id_field / a generic id alias is the most precise reason (client-supplied object id);
    // check it BEFORE the broader owner selector so e.g. id_field:"account_id" reports client_supplied_id,
    // while a non-id owner field (user_id / created_by with the default id_field) reports owner_field. The
    // dotted/bracketed deep-setter form (id.uuid / uid[value]) is caught by keyHasIdAliasSegment, mirroring
    // keyHasReservedSegment — the whole-name normalize collapses it to a non-alias `iduuid` (Codex P1).
    if (ID_ALIAS_KEYS.has(norm) || (normIdField && norm === normIdField) || keyHasIdAliasSegment(k, normIdField)) {
      return "create_body_client_supplied_id";
    }
    if (fieldIsOwnerSelector(k)) return "create_body_owner_field";
    // A privilege/authorization-assignment key (role / is_admin / permissions / granted_scopes) would mint
    // an ELEVATED synthetic object via the operator-armed write — refuse before the recursive descent (Codex P1).
    if (fieldIsPrivilegeSelector(k)) return "create_body_privilege_field";
    // A credential-NAMED key (password / api_key / token / client_secret) would write a secret to the target
    // verbatim even when its VALUE matches no token-shape regex — refuse by name, fail-closed (Codex P1).
    if (fieldIsCredentialSelector(k)) return "create_body_credential_field";
    const r = screenCreateBody(value[key], idField, depth + 1); // string values hit the top URL/GraphQL screen
    if (r) return r;
  }
  return null;
}
const ORACLE_KIND_VALUES = Object.freeze(["differential_response"]);
const DEFAULT_TIMEOUT_MS = 10_000;

// AC-3 HARD MEDIUM: a safe cross-tenant READ of attacker-owned SYNTHETIC objects
// caps at MEDIUM by construction (the leaked bytes do not reflect a real victim).
// Frozen + "use strict" means an in-process actor's `MAP.x = "critical"` THROWS.
// demonstrated_severity is stamped from here, NEVER agent-supplied, NEVER content-derived.
const IDOR_ORACLE_DEMONSTRATED_CEILING = Object.freeze({ differential_response: "medium" });

// Bytes well under safe-fetch's 1 MB response cap; mint condition #3.
const SAFE_OBJECT_CAP = 256 * 1024;
// P2 must be the same object class as P1 — body length within this factor either
// way (mint condition #7). A fragment/error envelope is rejected.
const P2_LENGTH_TOLERANCE = 4;

// AC-5: the EXACT-MATCH synthetic-identifier allowlist. piiScan admits ONLY the
// actual provisioned synthetic mailboxes (passed per-run as allowedEmails) — never
// a prefix, which would admit a REAL target user whose address merely starts with
// it (e.g. eval_uator@victim.com) and defeat the synthetic-only guarantee.
// "pentest_user" and "Evaluator Test" are the autoSignup synthetic name defaults.
// NOTHING else is admitted.
const SYNTHETIC_NAME_ALLOWLIST = Object.freeze(["pentest_user", "Evaluator Test"]);

// Provenance flags every resolved auth profile MUST carry before this producer
// will sign (mint condition #18 — the INERT invariant). Nothing stamps these at
// HEAD, so the positive path is dormant until PR-PROV.
const REQUIRED_PROVENANCE = Object.freeze({
  synthetic: true,
  email_origin: "temp_email",
  provisioned_via: "bob_auto_signup",
});

// An auth profile object co-mingles real HTTP headers (Authorization, Cookie, X-*) with
// Bob-LOCAL metadata: credentials/storage PLUS the PR-PROV provenance flags this producer
// requires (synthetic/email_origin/provisioned_via) and the synthetic mailbox (email) +
// expiry hints. buildHeaderProfile Object.assigns its first arg verbatim into the outbound
// header map, so the full profile must NEVER be passed as headers — that would leak
// Bob-local provenance and the synthetic mailbox to the TARGET. These keys are stripped
// (resolveIdentity, below) before building outbound headers. The strip set is the canonical
// PROFILE_METADATA_KEYS imported from auth.js — shared with bob_http_scan's outbound merge
// and the bob_list_auth_profiles summary so no reader can drift and leak a future key.

// Outbound HEADER names (lowercased) that must NEVER be sent on a read probe even if a
// stored/imported auth profile carries them: method/verb overrides turn the producer's
// GET into a server-side mutation (DELETE/PUT/...), defeating the read-only guarantee.
const FORBIDDEN_OUTBOUND_HEADERS = Object.freeze(new Set([
  // Method/verb overrides turn the GET into a server-side mutation.
  "x-http-method-override", "x-http-method", "x-method-override", "x-method",
  // Host overrides the vhost (routing/cache-key confusion); the body-framing headers
  // enable request smuggling. safe-fetch derives all of these from the URL itself.
  "host", "content-length", "transfer-encoding",
]));

// ── small helpers ──────────────────────────────────────────────────────────

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

// Full UTF-8 body bounded by the object cap; mint conditions read the parsed leaf,
// never a substring of this string.
function bodyTextOf(response, limit = SAFE_OBJECT_CAP) {
  if (!response || !Buffer.isBuffer(response.bodyBytes) || response.bodyBytes.length === 0) return "";
  return response.bodyBytes.toString("utf8", 0, Math.min(response.bodyBytes.length, limit));
}

function parseJsonBody(response) {
  const text = bodyTextOf(response);
  if (!text.trim()) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

// Scan the ENTIRE response body (bounded only by safe-fetch's 1 MB response cap,
// NOT the 256 KB object cap bodyTextOf applies) for an exact canary occurrence.
// Used for deny/leak bodies (P4/P4id/P5/P6) where a canary hidden past the object
// cap would otherwise be missed and a leak read as a clean deny. A body truncated
// at the 1 MB fetch cap is rejected separately by the per-probe truncation gates,
// so anything beyond 1 MB is never silently trusted.
// Resolve JSON \uXXXX escapes in RAW text WITHOUT parsing, so duplicate/shadowed keys
// are preserved (JSON.parse would drop a shadowed key). Lets a substring scan catch a
// value that is BOTH \u-escaped AND hidden in a shadowed duplicate key.
function decodeJsonUnicodeEscapes(text) {
  return typeof text === "string"
    ? text.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    : "";
}

// Decode ALL common reflected-input encoding layers to a fixed point: JSON \u escapes
// AND percent-encoding, composed and iterated, so a value that LAYERS encodings (e.g.
// percent-of-\u, \u-of-percent, %2562) is fully resolved before a substring scan. Used
// by every canary/PII/secret scan so no single decoder gap lets a leak through.
function decodeAllEncodingLayers(text) {
  let decoded = String(text);
  for (let i = 0; i < 12; i += 1) {
    const next = decodePercentToFixedPoint(decodeJsonUnicodeEscapes(decoded));
    if (next === decoded) break;
    decoded = next;
  }
  return decoded;
}

// Percent-decode a value to a FIXED POINT (defeats single + multi-layer encoding like
// %62 / %2562). Decodes each valid %XX triplet INDEPENDENTLY so an unrelated literal `%`
// elsewhere in the body (e.g. "100%", "50% off") does NOT abort the whole decode — a
// whole-string decodeURIComponent would throw on the stray `%` and leave a percent-
// encoded canary/PII undecoded, defeating the scan. Bounded iterations.
function decodePercentToFixedPoint(value) {
  let decoded = String(value);
  for (let i = 0; i < 8; i += 1) {
    const next = decoded.replace(/%[0-9a-fA-F]{2}/g, (m) => {
      try {
        return decodeURIComponent(m);
      } catch {
        return m;
      }
    });
    if (next === decoded) break;
    decoded = next;
  }
  return decoded;
}

function bodyLeaksCanary(response, canary) {
  if (!response || !Buffer.isBuffer(response.bodyBytes) || typeof canary !== "string" || !canary) {
    return false;
  }
  const raw = response.bodyBytes.toString("utf8");
  if (raw.includes(canary)) return true;
  // A deny/error body can hide the canary by \u-escaping it ("bb..."), PERCENT-encoding
  // it ("%62%62..."), LAYERING both, and/or placing it in a shadowed duplicate key.
  // decodeAllEncodingLayers resolves every layer over the RAW text (dup keys preserved).
  const decoded = decodeAllEncodingLayers(raw);
  return decoded !== raw && decoded.includes(canary);
}

// Focused secret-shape detector for the SIGNED proof body (AC-5 #17b). detectPiiShapes
// covers email/phone/ssn/credit-card; this catches high-confidence CREDENTIAL shapes a
// server could inject into the cross-tenant read (expanded-record leak). O_B is
// self-provisioned synthetic, so any of these in the proof body is non-synthetic. The
// 256-bit hex canary matches NONE of these patterns, so it never false-positives.
const SECRET_SHAPE_RES = Object.freeze([
  ["jwt", /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/],
  ["aws_access_key", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ["pem_private_key", /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/],
  ["github_token", /\bgh[pousr]_[A-Za-z0-9]{20,}\b/],
  ["github_fine_grained_pat", /\bgithub_pat_[A-Za-z0-9_]{30,}/],
  ["gitlab_token", /\bglpat-[A-Za-z0-9_-]{15,}/],
  ["google_api_key", /\bAIza[0-9A-Za-z_-]{35}\b/],
  ["stripe_secret_key", /\b[rs]k_live_[A-Za-z0-9]{16,}/],
  ["openai_key", /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/],
  ["slack_token", /\bxox[baprs]-[A-Za-z0-9-]{10,}/],
]);

function secretShapesIn(parsedBodyOrText) {
  const scan = typeof parsedBodyOrText === "string" ? parsedBodyOrText : canonicalJson(parsedBodyOrText);
  const found = [];
  for (const [label, re] of SECRET_SHAPE_RES) {
    if (re.test(scan)) found.push(label);
  }
  return found;
}

// Replace the producer's OWN minted canaries with a neutral token before a FOREIGN-PII/secret scan. The
// canaries are 256-bit nonces the producer generated — known-safe, definitionally not foreign data — but a
// CHANCE 16+-digit run inside a 64-hex canary can false-positive as a credit card (Luhn) and block a clean
// mint (~0.4% per canary). Stripping the EXACT 64-char run cannot hide adjacent real PII (only the canary
// itself is removed, never a neighbouring value), so this is precision-only. Returns a STRING so callers
// canonicalize a parsed body first. Applied to every body that BOTH reflects a canary AND is foreign-scanned:
// the create responses (#4), the owner readback (#24), and the signed proof bodies (#17/#17b).
function neutralizeCanaries(textOrParsed, canaries) {
  let s = typeof textOrParsed === "string" ? textOrParsed : canonicalJson(textOrParsed);
  for (const c of canaries) {
    if (typeof c === "string" && c) s = s.split(c).join("CANARY");
  }
  return s;
}

// Walk a parsed body to a fixed FIELD_PATH (array of string keys) and return the
// leaf value. NEVER a substring search; the path is DISCOVERED from the owner
// readback (D11b) and the comparison is exact string equality to the 256-bit hex
// canary. Absent path / non-leaf / non-parsing → null (fails closed).
function canaryAt(parsedBody, fieldPath) {
  if (parsedBody == null || typeof parsedBody !== "object") return null;
  if (!Array.isArray(fieldPath) || fieldPath.length === 0) return null;
  let node = parsedBody;
  for (const key of fieldPath) {
    if (node == null || typeof node !== "object" || Array.isArray(node)) return null;
    if (!Object.prototype.hasOwnProperty.call(node, key)) return null;
    node = node[key];
  }
  return typeof node === "string" ? node : null;
}

// Discover the FIELD_PATH at which `canary` appears as an exact leaf value in the
// owner readback. Returns the FIRST such path (BFS, stable order) or null. The
// canary is a 256-bit nonce, so a match is the field the server reflected it into.
function discoverCanaryFieldPath(parsedBody, canary, maxDepth = 8) {
  if (parsedBody == null || typeof parsedBody !== "object" || typeof canary !== "string" || !canary) {
    return null;
  }
  const queue = [{ node: parsedBody, path: [] }];
  while (queue.length > 0) {
    const { node, path: nodePath } = queue.shift();
    if (nodePath.length > maxDepth) continue;
    if (node == null || typeof node !== "object" || Array.isArray(node)) continue;
    for (const key of Object.keys(node)) {
      const value = node[key];
      const childPath = [...nodePath, key];
      if (typeof value === "string") {
        if (value === canary) return childPath;
      } else if (value != null && typeof value === "object" && !Array.isArray(value)) {
        queue.push({ node: value, path: childPath });
      }
    }
  }
  return null;
}

// Capture the object's OWNING scope from B's self-read at a fixed well-known key.
// Used for the cross-tenant scope proof (mint condition #13) and the tenant
// discriminator (mint condition #14). Returns a trimmed string or null.
// Tenant/owner-scope keys ONLY. `account_id` is deliberately EXCLUDED: in many APIs it
// is the record's OWN id (per-resource), not a tenant — so two different records would
// carry different account_ids even within the SAME tenant, which would FALSELY satisfy
// the cross-tenant discriminator (#14). These keys are unambiguously tenant/owner-level.
const OWNING_SCOPE_KEYS = Object.freeze(["owner_scope", "tenant_id", "org_id", "workspace_id"]);
const SHARED_SCOPE_VALUES = Object.freeze(["shared", "default", "demo", "sandbox", "public", "global"]);

// Common single-object envelope wrappers: many REST APIs nest the resource under one of these keys
// (e.g. {data:{org_id:..}}, {result:{owner_scope:..}}), and JSON:API nests it TWO levels under
// {data:{attributes:{..}}}. Owning-scope detection scans the TOP-LEVEL body, ONE level into these
// wrappers, AND a SECOND level via the same wrappers (so JSON:API data.attributes is reached) — so a
// nested tenant/owner scope is not invisible, which after #13/#14 were demoted to soft-gates would let
// a nested-envelope SAME-tenant body soft-mint at LOW (Codex PR#136). Bounded to two levels, descending
// ONLY through these well-known keys; the direction is precision-safe (more scope detected = more
// same-tenant/shared/unusable HARD blocks, never a new mint). Top-level root is scanned first, so flat
// bodies are unchanged.
const SCOPE_ENVELOPE_KEYS = Object.freeze(["data", "result", "item", "record", "attributes", "payload", "resource"]);

function scopeSearchRoots(parsedBody) {
  if (parsedBody == null || typeof parsedBody !== "object" || Array.isArray(parsedBody)) return [];
  const roots = [parsedBody];
  const addEnvelopeChildren = (obj) => {
    for (const key of SCOPE_ENVELOPE_KEYS) {
      const nested = obj[key];
      if (nested != null && typeof nested === "object" && !Array.isArray(nested) && !roots.includes(nested)) {
        roots.push(nested);
      }
    }
  };
  addEnvelopeChildren(parsedBody);            // level 1: {data:{...}}, {result:{...}}, ...
  for (const root of roots.slice(1)) {        // level 2: JSON:API {data:{attributes:{...}}}
    addEnvelopeChildren(root);
  }
  return roots;
}

// Coerce an owning-scope field to its canonical string form: a non-empty trimmed string, OR a SAFE
// integer stringified. Integer org_id/tenant_id values are common in real REST APIs; without this a
// numeric tenant id is typeof "number", silently escapes the string-only scope reads, and a
// same-tenant BOLA (A and B both org_id:42) would be mislabeled a cross-tenant IDOR. Only
// Number.isSafeInteger values are coerced: a 64-bit id above 2^53 already lost precision in
// JSON.parse (9007199254740993 -> ...992), so its String() form is unreliable for tenant comparison
// and could COLLIDE two distinct tenants — reject it (-> null = no usable scope value, the
// conservative direction: the read soft-gates rather than risk a precision-wrong same-tenant
// verdict). A float (42.5) is likewise not a tenant id. Anything else (null, boolean, object,
// NaN/Infinity, unsafe-magnitude number) is also not a usable scope value.
function scopeValueString(value) {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed ? trimmed : null;
  }
  if (typeof value === "number" && Number.isSafeInteger(value)) return String(value);
  return null;
}

function ownScopeOf(parsedBody) {
  for (const root of scopeSearchRoots(parsedBody)) {
    for (const key of OWNING_SCOPE_KEYS) {
      const value = scopeValueString(root[key]);
      if (value != null) return value;
    }
  }
  return null;
}

// A B-private scope must NOT be a shared/default/demo/sandbox heuristic match
// (mint condition #13). Returns true only when a concrete, non-shared scope is present.
function ownScopeIsPrivate(scope) {
  if (typeof scope !== "string" || !scope.trim()) return false;
  return !SHARED_SCOPE_VALUES.includes(scope.trim().toLowerCase());
}

// The tenant discriminator at a FIXED well-known key (mint condition #14). The
// first present owning-scope key is the discriminator; both identities must carry
// one at the SAME key and they must differ.
function tenantDiscriminator(parsedBody) {
  for (const root of scopeSearchRoots(parsedBody)) {
    for (const key of OWNING_SCOPE_KEYS) {
      const value = scopeValueString(root[key]);
      if (value != null) return { key, value };
    }
  }
  return null;
}

// All owning-scope VALUES present in a body across EVERY OWNING_SCOPE_KEYS alias (not just the
// first-matched one). Lets the same-tenant guard detect a shared tenant value even when A and
// B label it under different alias keys, or carry it under a SECONDARY key (e.g. A
// owner_scope:"x" + tenant_id:"acme" vs B org_id:"acme"). Lowercased for a case-robust match.
function owningScopeValues(parsedBody) {
  const values = [];
  for (const root of scopeSearchRoots(parsedBody)) {
    for (const key of OWNING_SCOPE_KEYS) {
      const value = scopeValueString(root[key]);
      if (value != null) values.push(value.toLowerCase());
    }
  }
  return values;
}

// True iff a body carries an EXPLICIT shared/default/public owning-scope label at ANY alias
// (mint condition #13). Scans EVERY OWNING_SCOPE_KEYS alias, not just the first ownScopeOf match,
// so a {owner_scope:"tenant-B", workspace_id:"public"} body cannot hide a shared label behind a
// private primary alias. Positive evidence the object is shared → HARD refutation.
function hasExplicitSharedScope(parsedBody) {
  return owningScopeValues(parsedBody).some((value) => SHARED_SCOPE_VALUES.includes(value));
}

// True iff a body carries an owning-scope key whose value is PRESENT but UNUSABLE for tenant
// comparison — specifically a NUMBER that is not a safe integer (a 64-bit id above 2^53 already
// lost precision in JSON.parse, or a float). scopeValueString() drops these to null, which the
// same-tenant guard would otherwise read as "scope ABSENT" and could then soft-mint two SAME-tenant
// objects (both org_id:9007199254740993) as cross-tenant. A present-but-unsafe discriminator means
// we cannot prove the two identities are in DIFFERENT tenants, so it is positive evidence AGAINST a
// provable cross-tenant break → HARD refutation (fail closed), NOT a soft "missing scope" signal.
// (Booleans/objects as a tenant id are nonsensical and cannot precision-collide, so they stay
// scopeValueString→null/absent; only the realistic numeric-id precision risk hard-blocks here.)
function hasUnusableOwningScope(parsedBody) {
  for (const root of scopeSearchRoots(parsedBody)) {
    for (const key of OWNING_SCOPE_KEYS) {
      const value = root[key];
      if (typeof value === "number" && !Number.isSafeInteger(value)) return true;
    }
  }
  return false;
}

// AC-5 PII tripwire (mint condition #17). Scan a body for PII shapes; any shape
// that is not an exact-allowlisted synthetic identifier aborts the sign. Wires
// detectPiiShapes (previously unwired). Returns the offending shapes (empty = ok).
function piiScan(parsedBodyOrText, allowedEmails) {
  const text = typeof parsedBodyOrText === "string"
    ? parsedBodyOrText
    : canonicalJson(parsedBodyOrText);
  // detectPiiShapes only matches a CONTIGUOUS card run and an email whose domain does
  // not end in a root-label dot. Also scan a NORMALIZED copy so the human-readable
  // display forms are seen: (1) join intra-digit separators — actual whitespace/dot/dash
  // AND JSON-escaped whitespace (\n \t \r) — so a grouped PAN ("4111 1111", "4111\n1111")
  // becomes a contiguous Luhn-checkable run; (2) drop a boundary trailing dot so an
  // absolute-FQDN email (victim@corp.com.) is matched.
  const normalized = text
    .replace(/(?<=\d)(?:[\s.\-]|\\[ntrf])+(?=\d)/g, "")
    .replace(/\.(?=["'\s,}\])]|$)/g, "");
  const scans = normalized !== text
    ? [detectPiiShapes(text), detectPiiShapes(normalized)]
    : [detectPiiShapes(text)];
  const allowed = new Set((Array.isArray(allowedEmails) ? allowedEmails : []).map((e) => String(e).toLowerCase()));
  const offending = [];
  for (const shape of scans.flat()) {
    if (shape.type === "email") {
      const lower = String(shape.value).toLowerCase();
      // EXACT-MATCH only against the actual provisioned synthetic mailboxes — a
      // prefix match would admit a real target user whose address merely starts
      // with the prefix, defeating the synthetic-only AC-5 guarantee.
      if (allowed.has(lower)) continue;
      offending.push(shape);
    } else {
      // phone / ssn / credit_card / any non-email shape is never allowlisted.
      offending.push(shape);
    }
  }
  // FAIL CLOSED on a truncated scan: detectPiiShapes stops at MAX_MATCHES, so a body
  // padded with that many allowlisted synthetic matches could hide a real foreign PII
  // shape past the cap. If any scan hit the cap, surface a sentinel so the caller blocks.
  if (scans.some((s) => s.length >= PII_MAX_MATCHES)) {
    offending.push({ type: "scan_truncated", value: "pii_match_cap_reached" });
  }
  // Name shapes are not produced by detectPiiShapes; the server-templated CREATE
  // body only carries the synthetic names, asserted disjoint from operator
  // identifiers by autoSignup (PR-PROV) — out of this producer's path.
  void SYNTHETIC_NAME_ALLOWLIST;
  return offending;
}

// Resolve a profile NAME → header profile + the profile object (for provenance).
function resolveIdentity(profileName, url, domain, label) {
  const name = assertNonEmptyString(profileName, label);
  const profile = resolveAuthProfile(name, url, domain);
  if (!profile || typeof profile !== "object") {
    return { name, profile: null, headers: null };
  }
  // Build outbound HTTP headers from ONLY the profile's header fields. Strip the
  // Bob-local metadata (provenance flags, synthetic mailbox, credentials, storage,
  // expiry hints) so buildHeaderProfile's Object.assign cannot emit them as
  // outbound headers to the target. The JWT-in-storage promotion still runs from
  // the storage arg below.
  const headerFields = {};
  for (const [key, value] of Object.entries(profile)) {
    if (PROFILE_METADATA_KEYS.has(key)) continue;
    if (FORBIDDEN_OUTBOUND_HEADERS.has(String(key).toLowerCase())) continue;
    headerFields[key] = value;
  }
  const headers = buildHeaderProfile(
    headerFields,
    {},
    profile.local_storage && typeof profile.local_storage === "object" ? profile.local_storage : {},
  );
  return { name, profile, headers };
}

// Mint condition #18 (the INERT gate): every resolved profile must carry the
// synthetic+temp-email+autoSignup provenance flags. Nothing stamps these at HEAD,
// so this can never be satisfied on the merged transport.
function profileHasProvenance(profile) {
  if (!profile || typeof profile !== "object") return false;
  // SECURITY-LOAD-BEARING: STRICT === against the frozen literals, and `synthetic` must be
  // boolean true. Auth-profile HEADER values are schema-coerced to strings, so an agent
  // that injects a header literally named `synthetic` (value "true") via bob_auth_store
  // yields "true" !== true and the gate stays closed. Do NOT relax to ==/truthy or accept
  // string "true" — that would open a forge onto a real (non-synthetic) identity.
  // A non-empty `email` (the synthetic mailbox) is required so the gate matches the full
  // four-field stamp authStore writes AND so mint condition #17 (allowedEmails, :NNN) always
  // has this identity's mailbox for the piiScan allowlist — a 3-marker profile lacking email
  // must not pass, or the allowlist would be silently short an entry.
  return profile.synthetic === REQUIRED_PROVENANCE.synthetic
    && profile.email_origin === REQUIRED_PROVENANCE.email_origin
    && profile.provisioned_via === REQUIRED_PROVENANCE.provisioned_via
    && typeof profile.email === "string" && profile.email.length > 0;
}

// ── AC-2 cardinality + scan-trail provenance ─────────────────────────────────

// GAP A (relaxed to ONE-RESOURCE multi-endpoint surfaces): v1 confirms single-HOST surfaces. A surface
// may record MULTIPLE endpoints (real discovery records a route pattern, sampled concrete instances, and
// the collection — e.g. the lab's ["/api/users/:id", "/api/users/1"]), but they must ALL resolve to ONE
// origin AND describe ONE resource: only path_template's item-route forms (the collection segments + an
// id segment, concrete OR a ":id"/"{id}" pattern) plus that route's collection are allowed. Any OTHER
// endpoint — a sub-resource, an unrelated resource, or a query-routed sibling — fails closed, because the
// downstream proof gate binds a row to a finding by surface_id ONLY, so a second resource on the surface
// could launder an item proof onto a different finding (the intra-surface laundering the old
// single-endpoint guard prevented; Codex P1). The bound target is a server-RECORDED item endpoint (the
// same route resolveBaselineFromSurface selects), never agent free-text. See the classification below.
function assertSingleHostBoundEndpoint(surface, stateOrigin, pathTemplate) {
  const endpoints = candidateSurfaceEndpoints(surface);
  if (endpoints.length === 0) {
    rejectInvalidArguments(
      "bob_http_idor_confirm requires a surface with at least one recorded endpoint.",
      { code: "idor_producer_surface_no_endpoint", endpoint_count: 0 },
    );
  }
  // Resolve an endpoint to its URL: absolute → its OWN origin (may be an in-scope subdomain), a
  // path-absolute "/x" → the session origin. Reject a "//host" network-path ref (it resolves to a
  // FOREIGN origin, escaping the surface-host binding) exactly as urlFromEndpoint does. null = skip.
  const resolveUrl = (value) => {
    if (typeof value !== "string") return null;
    try {
      if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
        const u = new URL(value);
        return (u.protocol === "http:" || u.protocol === "https:") ? u : null;
      }
      if (value.startsWith("/") && !value.startsWith("//")) {
        const u = new URL(value, stateOrigin);
        return (u.protocol === "http:" || u.protocol === "https:") ? u : null;
      }
    } catch {}
    return null;
  };
  // SINGLE HOST: every endpoint PLUS any surface.hosts must collapse to ONE origin — so a relative
  // endpoint and a DIFFERENT declared host can never split the target across origins. Do NOT seed the
  // bare session origin the way resolveSurfaceOrigins does, or an endpoint on an in-scope subdomain
  // would falsely count as two.
  const origins = new Set();
  for (const { value } of endpoints) {
    const u = resolveUrl(value);
    if (u) origins.add(u.origin);
  }
  if (Array.isArray(surface.hosts)) {
    let protocol = "https:";
    try { protocol = new URL(stateOrigin).protocol; } catch {}
    for (const host of surface.hosts) {
      if (typeof host !== "string" || !host.trim()) continue;
      try { origins.add(new URL(`${protocol}//${host.trim().replace(/^https?:\/\//i, "")}`).origin); } catch {}
    }
  }
  if (origins.size !== 1) {
    rejectInvalidArguments(
      "bob_http_idor_confirm v1 only confirms single-host surfaces; this surface resolves to more than one origin.",
      { code: "idor_producer_surface_not_single_host", origin_count: origins.size },
    );
  }
  // Classify every recorded endpoint STRUCTURALLY against path_template's shape. path_template has a
  // single, trailing {id} slot, so the route is COLLECTION-segments + one id segment. An endpoint is an
  // ITEM FORM of the route iff it has the same segment count AND its non-final segments equal the
  // collection — the final segment is the id in ANY recorded form (a concrete value OR a ":id"/"{id}"
  // route-pattern marker). Multiple item forms are the SAME route (a pattern + sampled instances), NOT
  // distinct targets. The only OTHER endpoint allowed is the route's COLLECTION itself. Everything else
  // fails closed, because the downstream proof gate binds a row to a finding by surface_id ONLY, so any
  // OTHER resource sharing the surface could be laundered:
  //   - a sub-resource (/api/accounts/{id}/settings) — a DIFFERENT, often higher-sensitivity resource;
  //   - an unrelated resource (/api/users/{id} under /api/accounts/{id});
  //   - a query-routed sibling (/api/items?type=invoice) — selects different data than its bare path and
  //     would make the derived create-collection POST to a broader/different collection than recorded.
  const templatePath = String(pathTemplate).split("?")[0];
  const templateSegments = templatePath.split("/").filter(Boolean);
  const collectionSegments = templateSegments.slice(0, -1);
  const isItemForm = (segs) => segs.length === templateSegments.length
    && collectionSegments.every((seg, index) => segs[index] === seg);
  const isCollection = (segs) => segs.length === collectionSegments.length
    && collectionSegments.every((seg, index) => segs[index] === seg);
  const items = [];
  const others = [];
  for (const ep of endpoints) {
    const u = resolveUrl(ep.value);
    if (!u) {
      rejectInvalidArguments(
        "bob_http_idor_confirm: a recorded endpoint could not be resolved to an in-scope http(s) URL.",
        { code: "idor_producer_surface_unresolvable_endpoint" },
      );
    }
    const segs = u.pathname.split("/").filter(Boolean);
    const entry = { ep, search: u.search, pathname: u.pathname, segs };
    if (isItemForm(segs)) items.push(entry);
    else others.push(entry);
  }
  // No item form at all → path_template is off-route for this surface (the AC-2 message, mirroring
  // resolveBaselineFromSurface which rejects the same case right after).
  if (items.length === 0) {
    rejectInvalidArguments(
      "bob_http_idor_confirm: path_template path shape does not match any recorded endpoint on this single-host surface.",
      { code: "idor_producer_surface_no_matched_endpoint", match_count: 0 },
    );
  }
  // With ≥1 item form, every OTHER endpoint MUST be exactly the route's collection — a sub-resource or
  // unrelated resource means the surface aggregates more than one resource and is rejected (Codex P1).
  for (const other of others) {
    if (!isCollection(other.segs)) {
      rejectInvalidArguments(
        "bob_http_idor_confirm: this surface records an endpoint that is neither path_template's item route nor its collection; it aggregates a different resource (intra-surface laundering risk).",
        { code: "idor_producer_surface_aggregates_unrelated_endpoints" },
      );
    }
  }
  // Bind to a CONCRETE item form (one resolveBaselineFromSurface will also match via
  // pathTemplateMatchesEndpoint) so row.target is a real recorded instance; fall back to the first item
  // form if only a route pattern was recorded (resolveBaselineFromSurface then rejects for no concrete).
  const boundEntry = items.find((item) => pathTemplateMatchesEndpoint(templatePath, item.pathname)) || items[0];
  // Every NON-bound recorded endpoint must be clean path-routed. The BOUND endpoint's own query, if any,
  // is caught downstream by the create-collection ?-guard (which returns a blocked result, reason
  // create_collection_query_routed_endpoint — see PR-D r14). But a query-routed SIBLING (e.g. a
  // query-routed collection) escapes that guard and could let the derived POST hit a broader/different
  // collection than recorded — so reject it here (Codex).
  for (const entry of [...items, ...others]) {
    if (entry !== boundEntry && entry.search) {
      rejectInvalidArguments(
        "bob_http_idor_confirm: a non-bound recorded endpoint is query-routed; v1 confirms only clean path-routed sibling endpoints.",
        { code: "idor_producer_surface_query_routed_endpoint" },
      );
    }
  }
  const boundEndpoint = boundEntry.ep;
  return { endpoint: boundEndpoint, origin: [...origins][0] };
}

// ── the P0–P6 canary runner ──────────────────────────────────────────────────

// A blocked outcome — write NOTHING, sign nothing.
function blocked(outcome, reason, extra = {}) {
  return {
    confirmed: false,
    target_domain: null,
    tool_id: TOOL_ID,
    offensive_outcome: outcome,
    reason,
    row_written: false,
    ...extra,
    // A blocked outcome NEVER carries confidence signals — kept authoritative (after ...extra) so a
    // caller's extra cannot accidentally attach a soft-gate signal to a hard block.
    confidence_signals: [],
  };
}

// Run a single probe via the injectable fetch_fn (seeded tests) or safeFetch.
// Audits every probe so the AC-2 scan-trail cross-check sees the producer's own
// traffic and the circuit breaker counts the live requests.
async function runProbe({
  fetchFn,
  url,
  method,
  headers,
  domain,
  surfaceId,
  egressProfile,
  blockInternalHosts,
  agent,
  startedAt,
}) {
  let response;
  let error;
  try {
    if (typeof fetchFn === "function") {
      response = await fetchFn({ url, method, headers });
    } else {
      response = await safeFetch(url, {
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
  } catch (e) {
    error = e;
  }
  const auditOk = auditConfirmRequest({
    domain,
    surfaceId,
    method,
    url,
    egressProfile,
    status: response ? response.status : null,
    scopeDecision: error && error.scope_decision === "blocked" ? "blocked" : null,
    error: error ? (error.message || String(error)) : null,
    startedAt,
    toolId: TOOL_ID,
  });
  // A swallowed audit-write failure means this live probe is invisible to the circuit
  // breaker / request budget. The producer signs a durable proof row, so it must NOT
  // proceed — ABORT immediately rather than keep firing un-audited live probes.
  if (auditOk === false) {
    const auditErr = new ToolError(ERROR_CODES.STATE_CONFLICT, "probe http-audit write failed");
    auditErr.probe_audit_failed = true;
    throw auditErr;
  }
  if (error) throw error;
  return response;
}

// Resolve the canonical P2 target URL for a probe id under the single endpoint.
function buildTargetUrl(pathTemplate, objectId, origin) {
  const resolved = pathTemplate.replace("{id}", encodeURIComponent(objectId));
  return new URL(resolved, origin);
}

// ── PR-D live self-provisioning (the operator-armed write arm) ───────────────────
// The OPERATOR CHECKPOINT for live object creation (a WRITE to the target): INERT unless the
// operator explicitly arms it for THIS target via the env, target-BOUND (=== domain, never a bare
// "1"), mirroring the mass-read owner-authorization gate. Default-off keeps the tool dormant.
const IDOR_PROVISION_ENV = "BOB_IDOR_PROVISION_AUTHORIZED";
function idorProvisionAuthorizedFor(domain) {
  const v = process.env[IDOR_PROVISION_ENV];
  return typeof v === "string" && v.trim().length > 0 && v.trim() === String(domain);
}

// A 256-bit canary as 64 lowercase hex chars (mint condition #19).
function mintCanary() {
  return crypto.randomBytes(32).toString("hex");
}

// A path segment shaped like a concrete resource INSTANCE (a numeric id, a uuid, or an id-bearing slug
// like `proj-123` / `tenant_42`) — as opposed to a static route word (`api`, `v1`, `orgs`, `accounts`).
// Version tags (`v1`, `v2`) and acronym-with-digit route words (`oauth2`, `s3`) are NOT instances: they
// carry no SEPARATED id portion. Used by pathHasConcreteParentInstance for the #5 nested-container guard.
const UUID_INSTANCE_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function segmentLooksLikeResourceInstance(seg) {
  const s = String(seg);
  if (/^\d+$/.test(s)) return true;       // 123
  if (UUID_INSTANCE_RE.test(s)) return true; // 550e8400-e29b-41d4-a716-446655440000
  if (/[-_.]\d+$/.test(s)) return true;   // proj-123, tenant_42, org-1   (separated trailing id, incl. 1 digit)
  if (/^\d+[-_.]/.test(s)) return true;   // 42-acme, 7_widgets           (separated leading id, incl. 1 digit)
  return false;
}
// True when a derived create-collection's PARENT path (the ancestors of the collection segment) contains a
// concrete resource INSTANCE — i.e. the collection is nested inside a FIXED real container like
// /api/orgs/acme-corp/projects/proj-123/accounts, where the armed POST would write a synthetic object into
// a real tenant/project rather than a synthetic-owned collection (#5, brutalist). Inspects only the
// ANCESTOR segments; the collection itself (last segment) is allowed to be any noun.
// Percent-encoding is decoded to a fixed point BEFORE splitting (mirroring assertCreateCollectionShapeSafe's
// decoder): an encoded id-bearing parent (%34%32 -> 42, proj%2d123 -> proj-123) must be seen as the instance
// a router decodes it to, and an encoded separator (%2f -> /) re-splits into the real segments — the raw
// check was parser-inconsistent with the action-verb guard (brutalist / Codex P1). A residual percent-escape
// in any ancestor fails CLOSED (could decode further at the router to an untested id-bearing segment).
// RESIDUAL: a pure-alpha tenant slug (`acme-corp`, no id portion) is indistinguishable from a static route
// word and is NOT caught here — but A/B/C then share that container and the downstream same-tenant guard
// (identities_collided_same_tenant / own_scope_missing) hard-blocks or downgrades the cross-tenant claim, so
// cross-tenant SOUNDNESS stays backstopped even when this write-side defense-in-depth does not fire. A fully
// known-synthetic (operator-seeded) parent contract is the deferred robust closure (ties to canary-injection).
function pathHasConcreteParentInstance(parentPath) {
  const decoded = decodePercentToFixedPoint(String(parentPath));
  const segs = decoded.split(/[/\\]/).filter(Boolean);
  const ancestors = segs.slice(0, -1);
  if (ancestors.some((s) => /%/.test(s))) return true; // residual encoding → fail closed
  return ancestors.some(segmentLooksLikeResourceInstance);
}

// CREATE one synthetic object as `identity` via POST to the derived collection endpoint, the canary
// written into `canaryField` of a server-templated synthetic body (the producer mints the canary;
// the body skeleton is PII-screened upstream). Returns the server-minted id (from `idField`) + the
// parsed response. The create is the ONE intentional WRITE: scope-validated + audited (circuit
// breaker) but NEVER read-only-guarded. Mirrors runProbe's audit-or-abort discipline.
async function createObject({ createUrl, headers, canaryField, canary, idField, createBody, probeBase }) {
  const body = JSON.stringify({
    ...(createBody && typeof createBody === "object" ? createBody : {}),
    [canaryField]: canary, // server-minted canary ALWAYS wins over any skeleton value
  });
  const startedAt = Date.now();
  const reqHeaders = { ...(headers || {}), "Content-Type": "application/json" };
  // PRE-FLIGHT the audit BEFORE the mutating POST (Codex P1): a create is a target WRITE, so it must
  // never fire if it cannot be recorded in http-audit.jsonl (the circuit-breaker / request-budget trail).
  // Reserve a request-initiated record (status null); if the audit log is unwritable, ABORT before any
  // POST so no unaudited mutation escapes the control plane. The completion record (with the real status)
  // is appended after the POST below; the reserved record stands as the trail entry even if that fails.
  const reserveOk = auditConfirmRequest({
    domain: probeBase.domain, surfaceId: probeBase.surfaceId, method: "POST", url: createUrl,
    egressProfile: probeBase.egressProfile, status: null, scopeDecision: "allowed", startedAt, toolId: TOOL_ID,
  });
  if (reserveOk === false) {
    const e = new ToolError(ERROR_CODES.STATE_CONFLICT, "create http-audit preflight write failed");
    e.probe_audit_failed = true;
    throw e;
  }
  let response;
  let error;
  try {
    if (typeof probeBase.fetchFn === "function") {
      response = await probeBase.fetchFn({ url: createUrl, method: "POST", headers: reqHeaders, body });
    } else {
      response = await safeFetch(createUrl, {
        method: "POST",
        headers: reqHeaders,
        body,
        followRedirects: false,
        timeoutMs: DEFAULT_TIMEOUT_MS,
        targetDomain: probeBase.domain,
        blockInternalHosts: probeBase.blockInternalHosts,
        agent: probeBase.agent,
      });
    }
  } catch (e) {
    error = e;
  }
  const auditOk = auditConfirmRequest({
    domain: probeBase.domain,
    surfaceId: probeBase.surfaceId,
    method: "POST",
    url: createUrl,
    egressProfile: probeBase.egressProfile,
    status: response ? response.status : null,
    scopeDecision: error && error.scope_decision === "blocked" ? "blocked" : null,
    error: error ? (error.message || String(error)) : null,
    startedAt,
    toolId: TOOL_ID,
  });
  if (auditOk === false) {
    const e = new ToolError(ERROR_CODES.STATE_CONFLICT, "create http-audit write failed");
    e.probe_audit_failed = true;
    throw e;
  }
  if (error) throw error;
  const parsed = parseJsonBody(response);
  // Only a SUCCESSFUL create supplies a server id (a 4xx/5xx error envelope that happens to carry an
  // `id`/request-id must NOT be treated as a created object, Codex P2). The id must be the response's
  // OWN scalar field (hasOwnProperty + string/number) — a missing/inherited key like `toString` /
  // `constructor` resolves to a prototype function, which must read as "no id captured", not a value.
  const is2xx = response && typeof response.status === "number" && response.status >= 200 && response.status < 300;
  const own = is2xx && parsed && typeof parsed === "object" && !Array.isArray(parsed)
    && Object.prototype.hasOwnProperty.call(parsed, idField) ? parsed[idField] : undefined;
  // A numeric id outside the safe-integer range (common for 64-bit ids) was ALREADY rounded by
  // JSON.parse, so stringifying it into the readback / probe URL would address a DIFFERENT resource
  // than the one just created — a credentialed read of an unrelated object and invalid evidence. Accept
  // a number only when it round-trips exactly (Number.isSafeInteger); require string ids otherwise
  // (Codex P2). A non-string/non-safe-int value reads as "no id captured" → caller fail-fasts.
  const id = typeof own === "string" ? own
    : (typeof own === "number" && Number.isSafeInteger(own)) ? own
      : undefined;
  return { id, response, parsed };
}

// Live self-provision O_A/O_B/O_C IN ORDER + owner-readback of B. Minting 3 distinct 256-bit
// canaries and creating one object per identity in A→B→C order lets a creation-order-dependent
// broken read-grant land the A→B cross-tenant break. Captures the server-minted ids and reads B's
// object back AS B (for the oracle's canary-leaf discovery + #24 create-time PII screen). Returns
// the `provision` shape idorConfirm's oracle consumes; throws on transport / audit failure.
// Exported + injectable `fetchFn` so unit tests drive it without a live target.
async function liveProvision({ idA, idB, idC, createUrl, canaryField, idField, createBody, pathTemplate, origin, allowedEmails, probeBase }) {
  const canary_a = mintCanary();
  const canary_b = mintCanary();
  const canary_c = mintCanary();
  const base = { object_a: null, object_b: null, object_c: null, canary_a, canary_b, canary_c, owner_readback_b: null };
  // A captured id is interpolated into the readback / probe URLs, so it must be a SAFE single resource
  // segment carrying no operator PII/secret BEFORE it is dispatched. idorConfirm re-checks the ids after
  // this returns, but the owner-readback GET below fires inside here — so validate the id at capture
  // (Codex P1: a bad contract returning `foo/transfer` must not produce a credentialed GET to a
  // sub-resource before the run blocks). Decoded, mirroring the id screen in idorConfirm.
  const idCaptureSafe = (id) => {
    if (id == null) return false;
    const s = String(id);
    if (!capturedIdSegmentIsSafe(s)) return false;
    for (const probe of [s, decodeAllEncodingLayers(s)]) {
      if (piiScan(probe, allowedEmails).length > 0 || secretShapesIn(probe).length > 0) return false;
    }
    return true;
  };
  // #4 (brutalist): the A/B/C CREATE responses themselves must be screened for foreign PII / secret shapes
  // BEFORE the next create POST fires or the proof continues — a create endpoint that echoes another tenant's
  // PII / a credential in its create response would otherwise leak that data into the tool process while the
  // later readback/proof bodies still pass. Mirrors the owner-readback gate (#24): scan the RAW response bytes
  // (raw + all decoded layers) and fail CLOSED via a tagged error idorConfirm maps to a precise blocked reason.
  const assertCreateRespClean = (created) => {
    const resp = created && created.response;
    // FAIL CLOSED on a TRUNCATED create response (Codex P1): a body capped by safe-fetch is only screened over
    // the retained prefix, so foreign PII/secret PAST the cap goes unseen while the prefix still yields a usable
    // id — the tool would proceed to B/C creates + probes after ingesting unscreened non-synthetic data. Mirror
    // the owner-readback / proof-body truncation gates and refuse before using the captured id.
    if (resp && resp.bodyTruncated === true) {
      const e = new ToolError(ERROR_CODES.STATE_CONFLICT, "create response truncated; cannot fully screen");
      e.create_response_truncated = true;
      throw e;
    }
    const raw = resp && Buffer.isBuffer(resp.bodyBytes) ? resp.bodyBytes.toString("utf8") : "";
    if (!raw) return; // a 201-no-body / empty create response carries nothing to leak
    for (const probe of [raw, decodeAllEncodingLayers(raw)]) {
      // Neutralize the producer's OWN minted canaries before the FOREIGN-data scan: each is a 256-bit nonce
      // we generated (known-safe, definitionally not foreign data), but a chance 16-digit run inside a hex
      // canary can false-positive as a credit card and block a clean mint. Exact 64-char replacement cannot
      // hide adjacent real PII — only the canary run itself is removed — so this is precision-only.
      const scan = neutralizeCanaries(probe, [canary_a, canary_b, canary_c]);
      if (piiScan(scan, allowedEmails).length > 0 || secretShapesIn(scan).length > 0) {
        const e = new ToolError(ERROR_CODES.STATE_CONFLICT, "create response carried foreign PII / secret");
        e.create_response_contaminated = true;
        throw e;
      }
    }
  };
  // FAIL FAST: a bad create contract / wrong id_field / unsafe id on the FIRST object must not trigger
  // the later B/C writes or the readback (Codex P1/P2). Validate the captured id after each create, and
  // screen each create RESPONSE for foreign data before the next write (#4).
  const a = await createObject({ createUrl, headers: idA.headers, canaryField, canary: canary_a, idField, createBody, probeBase });
  assertCreateRespClean(a);
  if (!idCaptureSafe(a.id)) return base;
  base.object_a = String(a.id);
  const b = await createObject({ createUrl, headers: idB.headers, canaryField, canary: canary_b, idField, createBody, probeBase });
  assertCreateRespClean(b);
  if (!idCaptureSafe(b.id)) return base;
  base.object_b = String(b.id);
  const c = await createObject({ createUrl, headers: idC.headers, canaryField, canary: canary_c, idField, createBody, probeBase });
  assertCreateRespClean(c);
  if (!idCaptureSafe(c.id)) return base;
  base.object_c = String(c.id);
  // All three created → read B's object back AS B (canary-leaf discovery + #24 create-time PII screen).
  const readbackUrl = buildTargetUrl(pathTemplate, String(b.id), origin).toString();
  assertSafeRequestUrl(readbackUrl, probeBase.domain, SCOPE_VALIDATION_OPTS);
  assertReadOnlyPath(readbackUrl, TOOL_ID);
  const rb = await runProbe({ ...probeBase, url: readbackUrl, method: "GET", headers: idB.headers });
  base.owner_readback_b = parseJsonBody(rb);
  // Preserve the RAW readback bytes for the #24 foreign-PII gate: PII present only in bytes JSON.parse
  // discards/normalizes (a shadowed duplicate key before the final value) would slip a parsed-only scan
  // (Codex P2). Captured here so idorConfirm can scan the raw body, not just the parsed object.
  base.owner_readback_b_raw = (rb && Buffer.isBuffer(rb.bodyBytes)) ? rb.bodyBytes.toString("utf8") : null;
  // A TRUNCATED readback is trusted for neither canary discovery nor the #24 PII/secret screen: foreign
  // PII/secret past the response cap would go unscreened while a parseable prefix still reflects the
  // canary. Capture the flag so idorConfirm fails closed, mirroring the proof-body non-truncation gate
  // (Codex P2).
  base.owner_readback_b_truncated = rb ? rb.bodyTruncated : null;
  return base;
}

// The full oracle. `fetch_fn` is injectable so seeded tests need no live target.
// `provision` supplies the producer-created object ids + canaries + the
// owner-readbacks (PR-D drives these live; PR-C tests seed them). All identity
// resolution + provenance + AC-2 + capture writing happens here, BEFORE signing.
async function idorConfirm(args = {}, { fetch_fn = null, provision = null } = {}) {
  // AC-3 input denylist: the producer's request is server-derived. Reject the
  // base forbidden set PLUS the server-minted-only object ids + canary.
  assertNoForbiddenInputs(args, TOOL_ID, ["object_id", "o_a", "o_b", "o_c", "tenant", "sensitivity", "canary"]);

  const startedAt = Date.now();
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  const oracleKind = normalizeOracleKind(args.oracle_kind);
  const method = normalizeMethod(args.method);
  // HEAD has no response body, so the canary differential can never read B's canary back and the oracle
  // can never mint — but an armed HEAD call would still self-provision A/B/C (live WRITEs) before the
  // body-less probes block (Codex P1). Refuse GET-only BEFORE any provisioning. The tool schema also
  // narrows `method` to GET; this handler guard is the authoritative enforcement.
  if (method !== "GET") {
    rejectInvalidArguments(
      "bob_http_idor_confirm requires method GET; HEAD has no response body for the canary differential and must not reach live object provisioning",
      { method },
    );
  }
  // GAP E: {id}-final clean path segment, no query (mint condition #23).
  const pathTemplate = normalizePathTemplate(args.path_template, TOOL_ID);

  const { state } = readSessionStateStrict(domain);
  const internalHostPolicy = blockInternalHostsPolicyFields(state);
  const blockInternalHosts = internalHostPolicy.block_internal_hosts === true;

  // Resolve + route the surface; AC-2 cardinality (GAP A, mint condition #22).
  const { surface } = findRoutedSurface(domain, surfaceId);
  const stateOrigin = originFromState(domain, state, TOOL_ID);
  // The surface's ONE validated origin (an in-scope subdomain or the apex). assertSingleHostBoundEndpoint
  // rejects a surface that resolves to >1 origin (so a relative endpoint + a DIFFERENT declared host can
  // never reach here) and binds boundEndpoint to the ONE recorded endpoint that path_template matches
  // (rejecting an ambiguous >1-match). We capture the single origin and bind the live create + probes to
  // it explicitly below — so even a future change to resolveBaselineFromSurface's origin ordering can't
  // point a WRITE at the session apex instead of the surface-declared host (Codex P1, defense-in-depth).
  const { origin: surfaceOrigin, endpoint: boundEndpoint } = assertSingleHostBoundEndpoint(surface, stateOrigin, pathTemplate);
  // AC-2 (operator-locked, NON-circular): bind the agent-supplied path_template to
  // the surface's RECORDED endpoint. resolveBaselineFromSurface throws
  // "path_template path shape does not match any recorded endpoint" unless the
  // template matches an endpoint the routed surface actually records — the SAME
  // binding the sibling read-only confirmer uses (offensive-confirmer.js). This,
  // not a ledger/scan-trail membership check, is what stops an agent pointing the
  // producer at an off-route target; with #111 (claim.surface_id === row.surface_id)
  // it ties the signed proof to the routed surface. The probe targets below are
  // built from this bound origin, so row.target is routed by construction.
  const baselineUrl = resolveBaselineFromSurface({ domain, surface, pathTemplate, state, toolName: TOOL_ID });
  // Bind the baseline (and thus the derived create URL + every probe, which all use baselineUrl.origin) to
  // the surface's single validated origin. Fail closed (structural, like the off-route guards below) on any
  // mismatch so a WRITE is never sent to the session apex instead of the assigned subdomain host (Codex P1).
  if (baselineUrl.origin !== surfaceOrigin) {
    rejectInvalidArguments(
      "bob_http_idor_confirm: resolved baseline origin does not match the surface's single declared host; refusing to bind a live create/probe to a different origin",
      { baseline_origin: baselineUrl.origin, surface_origin: surfaceOrigin },
    );
  }
  // Reject a mutation-shaped recorded endpoint BEFORE any probe — normalizePathTemplate
  // already forces {id} to be the FINAL segment, but a verb-NAMED collection before
  // the id (/api/reset/{id}, /delete/{id}) still resolves here, so apply the same
  // read-only guard the sibling confirmer runs on its baseline (offensive-confirmer.js).
  assertReadOnlyPath(baselineUrl.toString(), TOOL_ID);

  // Egress identity (mirrors bob_http_confirm).
  const requestedEgressProfile = typeof state.egress_profile === "string" && state.egress_profile.trim()
    ? state.egress_profile
    : "default";
  const { profile: egressProfile, identity } = resolveAndAssertSessionEgressIdentity(domain, requestedEgressProfile, {
    source: TOOL_ID,
  });
  if (blockInternalHosts && egressProfile && egressProfile.proxy_url) {
    throw new ToolError(
      ERROR_CODES.SCOPE_BLOCKED,
      "block_internal_hosts cannot be verified with proxy-backed egress for bob_http_idor_confirm",
      { scope_decision: "blocked", egress_profile: identity.egress_profile },
    );
  }
  const egressAgent = createProxyAgent(egressProfile.proxy_url);
  const egressProfileName = identity.egress_profile || requestedEgressProfile;

  // Resolve the three pure-consumer identities (AC-5: producer NEVER signs up).
  const probeUrl = `https://${domain}/`;
  const idA = resolveIdentity(args.identity_a_profile, probeUrl, domain, "identity_a_profile");
  const idB = resolveIdentity(args.identity_b_profile, probeUrl, domain, "identity_b_profile");
  const idC = resolveIdentity(args.identity_c_profile, probeUrl, domain, "identity_c_profile");

  // Mint condition #18 — provenance refuse-to-sign gate (INERT at HEAD). All three
  // resolved profiles must carry synthetic+temp-email+autoSignup provenance.
  if (!profileHasProvenance(idA.profile) || !profileHasProvenance(idB.profile) || !profileHasProvenance(idC.profile)) {
    return blocked("blocked_by_design", "identity_provenance_not_synthetic", {
      target_domain: domain,
      surface_id: surfaceId,
      oracle_kind: oracleKind,
      ...identity,
      ...internalHostPolicy,
    });
  }

  // The synthetic mailbox addresses for the piiScan allowlist (mint condition #17).
  const allowedEmails = [idA.profile, idB.profile, idC.profile]
    .map((p) => (p && typeof p.email === "string" ? p.email : null))
    .filter(Boolean);

  // ── Provision O_A/O_B/O_C (PR-D live; PR-C tests seed via `provision`). ──
  // The producer CREATEs each object itself with a server-templated body
  // containing ONLY the 256-bit canary + synthetic fields (AC-5). The object id
  // is captured from the producer's OWN create/readback, NEVER an agent arg.
  if (!provision || typeof provision !== "object") {
    // PR-D LIVE self-provisioning. STRUCTURAL DORMANCY: live object-creation is INERT unless the
    // operator has ARMED this target (idorProvisionAuthorizedFor — target-bound env). Unarmed →
    // blocked_by_design, the HEAD default. (The internal create/readback use the same injectable
    // fetch_fn as the probes, so an armed unit test drives the full path with a mock and a real run
    // — fetch_fn null — uses safeFetch; the live WRITE therefore only happens armed AND fetch_fn-null.)
    if (!idorProvisionAuthorizedFor(domain)) {
      return blocked("blocked_by_design", "object_not_self_provisioned", {
        target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
        ...identity, ...internalHostPolicy,
      });
    }
    // Create-contract (metadata only; AC-3 still forbids the canary VALUE + object ids). The create
    // endpoint is DERIVED from the AC-2-bound path_template (strip the trailing /{id} → the
    // collection), so the write target is structurally on-route — no new off-route write surface.
    const canaryField = assertNonEmptyString(args.canary_field, "canary_field");
    const idField = typeof args.id_field === "string" && args.id_field.trim() ? args.id_field.trim() : "id";
    const createBody = (args.create_body && typeof args.create_body === "object" && !Array.isArray(args.create_body))
      ? args.create_body : {};
    // canary_field / id_field NAMES must not be reserved prototype keys (they become JSON body keys).
    // canary_field / id_field NAMES become JSON keys in the create body, so reject a reserved prototype
    // name INCLUDING a dotted/bracketed deep-setter path (constructor.prototype.x, __proto__[x]) — same
    // segment check the create_body keys use (Codex P1).
    if (keyHasReservedSegment(canaryField) || keyHasReservedSegment(idField)) {
      return blocked("blocked_by_design", "reserved_field_name", {
        target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
        ...identity, ...internalHostPolicy,
      });
    }
    // canary_field must not overlap an owning-scope discriminator (tenant/org/workspace, any prefix/
    // composite/suffix form): the producer writes a DISTINCT minted canary into that field per identity,
    // and the oracle reads those keys as the private tenant discriminator (#13/#14). On an API that
    // normalizes such a create field into the stored/readback object, an unblocked alias would forge
    // "provably distinct tenants" from attacker-chosen values and strip the confidence downgrade — signing
    // an inflated cross-tenant proof. Refuse via the tokenized scope-selector match (Codex P1).
    if (fieldIsScopeSelector(canaryField)) {
      return blocked("blocked_by_design", "canary_field_overlaps_scope_key", {
        target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
        ...identity, ...internalHostPolicy,
      });
    }
    // canary_field must not alias id_field OR any client-id alias (id/object_id/resourceId/uuid/…, in any
    // camel/snake/kebab/case form): createObject writes the minted canary into canary_field AFTER this
    // screen, so an id-aliasing canary_field places the (server-minted) canary into the OBJECT-ID slot of
    // the create body — on a create/upsert API that honors/normalizes client ids that POSTs an object with
    // a client-supplied id, violating the server-minted-id invariant before the post-write
    // canary_reflected_in_object_id guard can fire (Codex P1). The configured id is the most precise reason,
    // so check it BEFORE the broader owner selector. Refuse the (normalized) alias before any write.
    const normCanaryField = normalizeFieldName(canaryField);
    const normIdFieldForCanary = normalizeFieldName(idField);
    if (ID_ALIAS_KEYS.has(normCanaryField) || (normCanaryField && normCanaryField === normIdFieldForCanary)
      || keyHasIdAliasSegment(canaryField, normIdFieldForCanary)) {
      return blocked("blocked_by_design", "canary_field_aliases_id_field", {
        target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
        ...identity, ...internalHostPolicy,
      });
    }
    // canary_field must not be an OWNER selector either (user_id/owner_id/createdBy/…): createObject POSTs
    // { [canaryField]: canary }, so an owner-named canary_field writes the minted canary into an ownership
    // slot, and an API honoring it would assign the synthetic object to a caller-chosen real principal
    // before any readback gate (brutalist / Codex P1).
    if (fieldIsOwnerSelector(canaryField)) {
      return blocked("blocked_by_design", "canary_field_overlaps_owner_field", {
        target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
        ...identity, ...internalHostPolicy,
      });
    }
    // canary_field must not be a PRIVILEGE selector (role/is_admin/scopes/…): the same POST-into-an-ownership-
    // -slot logic applies — an elevation-named canary_field would write the minted canary into a privilege
    // slot, minting an elevated synthetic object on an API that honors it (Codex P1).
    if (fieldIsPrivilegeSelector(canaryField)) {
      return blocked("blocked_by_design", "canary_field_overlaps_privilege_field", {
        target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
        ...identity, ...internalHostPolicy,
      });
    }
    // canary_field must not be a CREDENTIAL-named field either (password/api_key/token/…): writing the minted
    // canary into a credential slot is nonsensical and an API honoring it could set a guessable secret (Codex P1).
    if (fieldIsCredentialSelector(canaryField)) {
      return blocked("blocked_by_design", "canary_field_overlaps_credential_field", {
        target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
        ...identity, ...internalHostPolicy,
      });
    }
    // Recursively screen create_body content (nested reserved/proto keys, method/action-dispatch keys,
    // a top-level client-supplied id) BEFORE any write — the body is spread unchanged into the POST so a
    // hostile skeleton must not subvert the target or the server-minted-id invariant (Codex P2).
    const createBodyReason = screenCreateBody(createBody, idField);
    if (createBodyReason) {
      return blocked("blocked_by_design", createBodyReason, {
        target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
        ...identity, ...internalHostPolicy,
      });
    }
    // Cap the FINAL serialized create body BEFORE any write — the POST body is createBody PLUS the
    // canary_field key + its 64-hex value, so the cap must include the (caller-supplied) canary_field
    // NAME, not just createBody. safeFetch caps responses, never request bodies (Codex P2).
    const finalBodyBytes = Buffer.byteLength(JSON.stringify({ ...createBody, [canaryField]: "c".repeat(64) }), "utf8");
    if (finalBodyBytes > MAX_CREATE_BODY_BYTES) {
      return blocked("blocked_by_design", "create_body_too_large", {
        target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
        ...identity, ...internalHostPolicy,
      });
    }
    // The "drop trailing /{id}" derivation is only valid when {id} is its OWN final segment. normalizePathTemplate
    // forbids anything AFTER {id} (except an inert extension) but NOT a prefix BEFORE it in the same segment,
    // so /api/account-{id} or /api/v1/accounts.{id} would pass there yet strip to /api or /api/v1 — a broader /
    // off-route POST target. Require the final segment to be exactly {id} (optionally {id}.ext) before deriving
    // the collection, else fail closed (Codex P1).
    // A query-qualified recorded endpoint (/api/items/123?type=invoice) is query-ROUTED: resolveBaselineFromSurface
    // strips the query, so the derived create collection /api/items may be a broader/different collection than
    // the one actually recorded + bound. Refuse to derive a create target from a query-routed endpoint (Codex P1).
    if (String(boundEndpoint.value).includes("?")) {
      return blocked("blocked_by_design", "create_collection_query_routed_endpoint", {
        target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
        ...identity, ...internalHostPolicy,
      });
    }
    const finalSegment = pathTemplate.slice(pathTemplate.lastIndexOf("/") + 1);
    if (!/^\{id\}(?:\.[a-z0-9]+)?$/i.test(finalSegment)) {
      return blocked("blocked_by_design", "create_collection_not_id_terminated", {
        target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
        ...identity, ...internalHostPolicy,
      });
    }
    // The create endpoint = the COLLECTION: strip the FINAL path segment (now proven to be exactly {id}[.ext]).
    // Robust to inert-suffix templates (`/api/accounts/{id}.json` → `/api/accounts`) — never POST a malformed
    // `%7Bid%7D` URL. Structurally on-route (derived from the AC-2-bound template), never an agent free-text write.
    const createPath = pathTemplate.replace(/\/[^/]*$/, "");
    // A read template like /{id} strips to an EMPTY collection → POST / (the site root, often routed to
    // login/contact/search), not a collection-specific create endpoint and with no segment for the
    // action-shape guard to inspect. Refuse a root-level derived create endpoint (Codex P2).
    if (!createPath) {
      return blocked("blocked_by_design", "create_collection_is_root", {
        target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
        ...identity, ...internalHostPolicy,
      });
    }
    // #5 nested-container guard: route-binding proves the READ is on-surface, but the stripped PARENT path
    // is not proven to be a synthetic-owned collection. A concrete resource-INSTANCE ancestor (numeric id /
    // uuid / `proj-123`) means the derived POST would create the synthetic object INSIDE a real fixed
    // tenant/project container (/api/orgs/acme-corp/projects/proj-123/accounts), so refuse rather than write
    // there (brutalist). Pure-alpha tenant slugs are a documented residual backstopped by the downstream
    // same-tenant guard (see pathHasConcreteParentInstance).
    if (pathHasConcreteParentInstance(createPath)) {
      return blocked("blocked_by_design", "create_collection_nested_in_real_container", {
        target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
        ...identity, ...internalHostPolicy,
      });
    }
    const createUrl = new URL(createPath, baselineUrl.origin).toString();
    // The read template passed assertReadOnlyPath, but that guard intentionally allows action-NOUNS like
    // `transfer`/`refund` for a GET-by-id; the DERIVED collection POST /api/transfer would EXECUTE the
    // action (real mutation). Hold the create collection to the stricter fail-closed action-verb guard
    // BEFORE any write (Codex P1) — an action-shaped create path is refused, never POSTed to.
    assertCreateCollectionShapeSafe(createUrl, TOOL_ID);
    // EVERY byte WRITTEN to the target — the create URL, the serialized body, AND the canary FIELD NAME —
    // is screened for operator PII / secrets BEFORE any write, with LAYERED DECODING (percent / unicode,
    // to a fixed point), mirroring the proof-body gates so an encoded `victim%40example.test` or token can't
    // slip through. The hard rule: never submit operator identifiers to a target. (The canary VALUE is a
    // server-minted 256-bit hex nonce — safe — and is not agent-supplied, so it is not part of this scan.)
    const writeBytes = `${createUrl}\n${JSON.stringify(createBody)}\n${canaryField}`;
    for (const probe of [writeBytes, decodeAllEncodingLayers(writeBytes)]) {
      if (piiScan(probe, allowedEmails).length > 0 || secretShapesIn(probe).length > 0) {
        return blocked("blocked_operator_pii", "create_inputs_contain_sensitive_value", {
          target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
          ...identity, ...internalHostPolicy,
        });
      }
    }
    assertSafeRequestUrl(createUrl, domain, SCOPE_VALIDATION_OPTS); // the ONE allowed write; NOT read-only-guarded
    const provisionProbeBase = {
      fetchFn: fetch_fn, method: "GET", domain, surfaceId, egressProfile: egressProfileName,
      blockInternalHosts, agent: egressAgent, startedAt,
    };
    try {
      provision = await liveProvision({
        idA, idB, idC, createUrl, canaryField, idField, createBody,
        pathTemplate, origin: baselineUrl.origin, allowedEmails, probeBase: provisionProbeBase,
      });
    } catch (e) {
      if (e && e.probe_audit_failed) {
        return blocked("blocked_by_infra", "provision_audit_failed", {
          target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
          ...identity, ...internalHostPolicy,
        });
      }
      // #4 (brutalist): a create response that echoed foreign PII / a secret fails CLOSED with a precise
      // reason — the tool received non-synthetic data, so sign nothing (parity with the readback #24 gate).
      if (e && e.create_response_contaminated) {
        return blocked("blocked_by_design", "create_response_contains_foreign_data", {
          target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
          ...identity, ...internalHostPolicy,
        });
      }
      // A truncated create response cannot be fully foreign-screened — fail closed (Codex P1).
      if (e && e.create_response_truncated) {
        return blocked("blocked_by_design", "create_response_truncated", {
          target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
          ...identity, ...internalHostPolicy,
        });
      }
      return blocked("blocked_by_infra", "provision_transport_error", {
        target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
        failure_reason: e.message || String(e), ...identity, ...internalHostPolicy,
      });
    }
  }
  const { object_a, object_b, object_c, canary_a, canary_b, canary_c, owner_readback_b } = provision;
  // Self-provisioned ids must come from the producer's own create response.
  if (!object_a || !object_b || !object_c
    || typeof canary_a !== "string" || typeof canary_b !== "string" || typeof canary_c !== "string") {
    return blocked("blocked_by_design", "object_not_self_provisioned", {
      target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
      ...identity, ...internalHostPolicy,
    });
  }
  // Canaries pairwise-distinct (mint condition #19) + each a 256-bit hex nonce.
  const HEX256 = /^[0-9a-f]{64}$/;
  if (!HEX256.test(canary_b) || !HEX256.test(canary_a) || !HEX256.test(canary_c)
    || canary_a === canary_b || canary_b === canary_c || canary_a === canary_c) {
    return blocked("blocked_by_design", "canary_not_distinct_256bit", {
      target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
      ...identity, ...internalHostPolicy,
    });
  }
  // Canary disjoint from O_B's id/slug/URL path/query (mint condition #19). Compare
  // BOTH the raw id AND its percent-decoded form (to a fixed point) against the canary:
  // a server-minted id that is a percent-encoded canary (e.g. %62%62... = "bb...")
  // would slip past a raw includes() yet decode to the canary at the server, making the
  // canary-at-leaf a trivial id reflection rather than a cross-tenant read.
  // Apply the disjointness to EVERY object/canary pair: O_A and O_C are the tenant
  // discriminator (P3) and the C-authentication proof (P7), so an id that is (an encoding
  // of) its own canary would make those legs a trivial id reflection too.
  const canaryReflectedInId = (objectId, canary) => {
    const id = String(objectId);
    return id.includes(canary) || decodePercentToFixedPoint(id).includes(canary);
  };
  const objBId = String(object_b);
  if (canaryReflectedInId(object_b, canary_b)
    || canaryReflectedInId(object_a, canary_a)
    || canaryReflectedInId(object_c, canary_c)) {
    return blocked("blocked_by_design", "canary_reflected_in_object_id", {
      target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
      ...identity, ...internalHostPolicy,
    });
  }
  // Each self-provisioned id is interpolated into the {id} slot of the probe URL
  // (encodeURIComponent only encodes — it does not REJECT). A server-minted id
  // carrying a path separator (literal/encoded at any depth) or action/matrix
  // punctuation could route the read to a sub-resource/action once decoded, so
  // every id must be a CLEAN single resource segment — the same guard the
  // read-only confirmer applies to a recorded baseline id (capturedIdSegmentIsSafe).
  if (!capturedIdSegmentIsSafe(objBId)
    || !capturedIdSegmentIsSafe(String(object_a))
    || !capturedIdSegmentIsSafe(String(object_c))) {
    return blocked("blocked_by_design", "object_id_unsafe_segment", {
      target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
      ...identity, ...internalHostPolicy,
    });
  }
  // A self-provisioned id is interpolated into the probe URL AND persisted into the
  // signed row's `target` (canonicalizeExploitTarget). A sensitive id — an email-as-id
  // account (/api/accounts/victim@gmail.com) or a token-shaped id — would leak into the
  // durable proof. Screen every id for non-synthetic PII / credential shapes.
  for (const rawId of [objBId, String(object_a), String(object_c)]) {
    for (const id of [rawId, decodeAllEncodingLayers(rawId)]) {
      if (piiScan(id, allowedEmails).length > 0 || secretShapesIn(id).length > 0) {
        return blocked("blocked_operator_pii", "object_id_contains_sensitive_value", {
          target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
          ...identity, ...internalHostPolicy,
        });
      }
    }
  }

  // FAIL CLOSED on a TRUNCATED owner readback (Codex P2): a readback larger than the response cap is
  // trusted for neither canary discovery nor the #24 PII/secret screen — foreign PII/secret past the cap
  // would go unscreened while a parseable prefix still reflects the canary. The live arm stamps
  // owner_readback_b_truncated (boolean); seeded provisions omit it (undefined → trusted by construction).
  if (provision.owner_readback_b_truncated === true) {
    return blocked("blocked_by_design", "owner_readback_truncated", {
      target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
      ...identity, ...internalHostPolicy,
    });
  }

  // CANARY-REFLECTED + FIELD_PATH discovery (mint condition #20, D11b): discover
  // FIELD_PATH from the owner readback; if the canary is not reflected, abort.
  const readbackBody = owner_readback_b != null
    ? owner_readback_b
    : (provision.owner_readback_b_parsed || null);
  const parsedReadback = readbackBody && typeof readbackBody === "object" ? readbackBody : null;
  const fieldPath = parsedReadback ? discoverCanaryFieldPath(parsedReadback, canary_b) : null;
  if (!fieldPath) {
    return blocked("blocked_by_design", "canary_not_reflected", {
      target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
      ...identity, ...internalHostPolicy,
    });
  }

  // CREATE-TIME FOREIGN-PII (mint condition #24): the fresh owner readback must
  // carry the canary AND no foreign PII shape — else a shared object store.
  // The producer's own canaries are neutralized first (neutralizeCanaries) so a chance card-shaped digit
  // run inside a hex canary does not false-positive — the readback legitimately reflects canary_b.
  const ownCanaries = [canary_a, canary_b, canary_c];
  const readbackPii = piiScan(neutralizeCanaries(parsedReadback, ownCanaries), allowedEmails);
  if (readbackPii.length > 0) {
    return blocked("blocked_by_design", "shared_object_store", {
      target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
      ...identity, ...internalHostPolicy,
    });
  }
  // Also scan the RAW readback bytes for foreign PII AND secret shapes, with layered decoding — mirroring
  // the proof-body / write-byte gates (Codex P2). Foreign data present only in bytes JSON.parse
  // discards/normalizes (a shadowed duplicate key) or in an encoded form (a `victim%40corp.test` / an
  // `sk-...` token) would otherwise slip the parsed-only PII scan, letting a contaminated / shared object
  // store through after the tool already received non-synthetic data. The live arm captures
  // owner_readback_b_raw; seeded provisions omit it.
  const rawReadback = typeof provision.owner_readback_b_raw === "string" ? provision.owner_readback_b_raw : null;
  if (rawReadback) {
    for (const probe of [rawReadback, decodeAllEncodingLayers(rawReadback)]) {
      const scan = neutralizeCanaries(probe, ownCanaries);
      if (piiScan(scan, allowedEmails).length > 0 || secretShapesIn(scan).length > 0) {
        return blocked("blocked_by_design", "shared_object_store", {
          target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
          ...identity, ...internalHostPolicy,
        });
      }
    }
  }

  // Build the canonical P2 target from the surface-bound origin (AC-2).
  const p2TargetUrl = buildTargetUrl(pathTemplate, objBId, baselineUrl.origin);
  // Reject any probe URL that contains the canary (defeats id-echo reflection).
  if (p2TargetUrl.toString().includes(canary_b)) {
    return blocked("blocked_by_design", "canary_in_probe_url", {
      target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
      ...identity, ...internalHostPolicy,
    });
  }
  assertSafeRequestUrl(p2TargetUrl.toString(), domain, SCOPE_VALIDATION_OPTS);
  assertReadOnlyPath(p2TargetUrl.toString(), TOOL_ID);

  const probeBase = {
    fetchFn: fetch_fn,
    method,
    domain,
    surfaceId,
    egressProfile: egressProfileName,
    blockInternalHosts,
    agent: egressAgent,
    startedAt,
  };

  // P4 cold-first so any edge cache is cold during authed reads.
  const oBUrl = p2TargetUrl.toString();
  // O_A (A's own object, for the tenant discriminator + partition symmetry) and
  // O_C (C's own object, to PROVE C authenticates) are also dynamically built, so
  // they must clear the SAME scope + read-only guards as oBUrl — never dispatch a
  // URL that has not passed assertSafeRequestUrl.
  const oAUrl = buildTargetUrl(pathTemplate, String(object_a), baselineUrl.origin).toString();
  assertSafeRequestUrl(oAUrl, domain, SCOPE_VALIDATION_OPTS);
  assertReadOnlyPath(oAUrl, TOOL_ID);
  const oCUrl = buildTargetUrl(pathTemplate, String(object_c), baselineUrl.origin).toString();
  assertSafeRequestUrl(oCUrl, domain, SCOPE_VALIDATION_OPTS);
  assertReadOnlyPath(oCUrl, TOOL_ID);

  let P0a; let P0b; let P1; let P2; let P2prime; let P3; let P4; let P4id; let P5; let P6; let P7; let P8;
  try {
    // P4 + P4id are both ANON reads of O_B by its real server-assigned id, run
    // cold-first so any edge cache is cold during the authed reads. They are
    // intentionally identical here (the object is addressed only by its one real
    // id; there is no separate "synthetic id" axis as in #110), so P4id is an anon
    // consistency re-read — both must 401/403 (mint condition #10). A distinct
    // private-vs-unlisted-by-id discriminator is a PR-D oracle refinement.
    P4 = await runProbe({ ...probeBase, url: oBUrl, headers: {} }); // anon baseline (cold-first)
    P4id = await runProbe({ ...probeBase, url: oBUrl, headers: {} }); // anon consistency re-read
    P0a = await runProbe({ ...probeBase, url: oBUrl, headers: idB.headers });
    P0b = await runProbe({ ...probeBase, url: oBUrl, headers: idB.headers });
    P1 = await runProbe({ ...probeBase, url: oBUrl, headers: idB.headers });
    P2 = await runProbe({ ...probeBase, url: oBUrl, headers: idA.headers });
    // P2′ on a fresh never-before-requested URL variant + server-added no-cache.
    const p2primeUrl = new URL(oBUrl);
    p2primeUrl.searchParams.set("_bobcb", crypto.randomBytes(8).toString("hex"));
    // Re-validate scope on the cache-bust variant (defense-in-depth: same host as
    // the validated oBUrl, but never dispatch a URL that has not passed scope).
    assertSafeRequestUrl(p2primeUrl.toString(), domain, SCOPE_VALIDATION_OPTS);
    assertReadOnlyPath(p2primeUrl.toString(), TOOL_ID);
    P2prime = await runProbe({
      ...probeBase,
      url: p2primeUrl.toString(),
      headers: { ...idA.headers, "Cache-Control": "no-cache" },
    });
    P3 = await runProbe({ ...probeBase, url: oAUrl, headers: idA.headers });
    P5 = await runProbe({ ...probeBase, url: oBUrl, headers: idC.headers });
    P6 = await runProbe({ ...probeBase, url: oAUrl, headers: idB.headers });
    P7 = await runProbe({ ...probeBase, url: oCUrl, headers: idC.headers }); // C reads its OWN object
    P8 = await runProbe({ ...probeBase, url: oCUrl, headers: {} }); // ANON reads O_C (proves O_C is auth-gated)
  } catch (error) {
    // A probe whose http-audit write failed aborts the whole run (control-plane gap):
    // the producer must not sign a durable proof row for an unrecorded live probe.
    if (error && error.probe_audit_failed) {
      return blocked("blocked_by_infra", "probe_audit_failed", {
        target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
        ...identity, ...internalHostPolicy,
      });
    }
    return blocked("blocked_by_infra", "transport_error", {
      target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
      failure_reason: error.message || String(error),
      ...identity, ...internalHostPolicy,
    });
  }

  // ── Evaluate the mint conditions (any miss → blocked, sign nothing). ──
  const fail = (outcome, reason) => blocked(outcome, reason, {
    target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
    ...identity, ...internalHostPolicy,
  });

  // #1 NON-TRUNCATION (P1/P2/P2′/P5). A truncated proof body could hide the canary
  // or foreign PII past the fetch cap, so every signing-relevant body must be whole.
  if (P1.bodyTruncated !== false || P2.bodyTruncated !== false
    || P2prime.bodyTruncated !== false || P5.bodyTruncated !== false) {
    return fail("blocked_by_design", "body_truncated");
  }
  // #2 PARSE (P1/P2).
  const p1Parsed = parseJsonBody(P1);
  const p2Parsed = parseJsonBody(P2);
  const p2primeParsed = parseJsonBody(P2prime);
  if (p1Parsed == null || p2Parsed == null) {
    return fail("blocked_by_design", "body_not_parseable");
  }
  // #3 SIZE (P1/P2/P2′).
  if ((P1.bodyByteLength || 0) >= SAFE_OBJECT_CAP
    || (P2.bodyByteLength || 0) >= SAFE_OBJECT_CAP
    || (P2prime.bodyByteLength || 0) >= SAFE_OBJECT_CAP) {
    return fail("blocked_by_design", "object_too_large");
  }
  // #4 STABILITY P0 — two B-as-B reads byte-identical after canonicalJson.
  const p0aParsed = parseJsonBody(P0a);
  const p0bParsed = parseJsonBody(P0b);
  if (p0aParsed == null || p0bParsed == null || canonicalJson(p0aParsed) !== canonicalJson(p0bParsed)) {
    return fail("blocked_by_design", "volatile_object");
  }
  // #6 RESOURCE SHAPE P1.
  if (isResourceShapedResponse(P1) !== true) {
    return fail("blocked_by_design", "p1_not_resource_shaped");
  }
  // #7 P2 structural-shape + body-length within tolerance of P1.
  const p1Len = P1.bodyByteLength || 0;
  const p2Len = P2.bodyByteLength || 0;
  if (p1Len === 0 || p2Len === 0
    || p2Len > p1Len * P2_LENGTH_TOLERANCE || p1Len > p2Len * P2_LENGTH_TOLERANCE) {
    return fail("blocked_by_design", "p2_shape_out_of_tolerance");
  }
  // #7b RESOURCE SHAPE P2/P2′ — the cross-tenant reads must be genuine 2xx RESOURCE
  // responses, not a 401/403 error envelope that merely echoes B's id/canary at the
  // field path. "A READ B's object" requires a real resource body; an error body that
  // reflects the canary is not a read. (P1 is already shape-checked at #6.)
  if (isResourceShapedResponse(P2) !== true || isResourceShapedResponse(P2prime) !== true) {
    return fail("blocked_by_design", "p2_not_resource_shaped");
  }
  // #8 PRIMARY WITNESS — exact leaf equality on P1 AND P2. Checked BEFORE the
  // P2′ persistence leg so "A never read B's object" is the surfaced reason for a
  // proper deny, not the downstream cache-persistence check.
  if (canaryAt(p1Parsed, fieldPath) !== canary_b) {
    return fail("blocked_by_design", "canary_absent_p1");
  }
  if (canaryAt(p2Parsed, fieldPath) !== canary_b) {
    // The categorical signal: A did not read B's specific object.
    return fail("blocked_by_defense", "canary_absent_p2_no_cross_tenant_read");
  }
  // #16 cache origin-proof: canary survives P2′'s never-before-requested URL.
  if (p2primeParsed == null || canaryAt(p2primeParsed, fieldPath) !== canary_b) {
    return fail("blocked_by_infra", "canary_did_not_survive_fresh_url");
  }
  // #9 OBJECT-SCOPING — P3 (A's own object) must NOT carry O_B's canary; canary
  // absent from anon bodies (P4/P4-id). A truncated P3 could hide B's canary past the
  // fetch cap, so reject truncation before trusting the leak scan (symmetric with
  // P4/P4id/P5/P6).
  if (P3.bodyTruncated !== false) {
    return fail("blocked_by_design", "p3_body_truncated");
  }
  const p3Parsed = parseJsonBody(P3);
  // PROVE P3 IS IDENTITY A's OWN OBJECT: A must successfully read O_A carrying A's
  // OWN canary. The tenant discriminator (#14) for identity A is derived from P3;
  // without a positive self-read, P3 could be a stray/error/empty body that merely
  // happens to carry an owning-scope key, making the cross-tenant distinctness
  // unsound. A 200 resource body reflecting canary_a is the categorical proof.
  if (p3Parsed == null || !isResourceShapedResponse(P3) || discoverCanaryFieldPath(p3Parsed, canary_a) == null) {
    return fail("blocked_by_design", "p3_not_identity_a_object");
  }
  // Scan ALL of P3 for B's canary (not just the discovered field path): B's canary
  // appearing ANYWHERE in A's own-object response is cross-contamination / a shared
  // store, so use the full-body leak scan (raw + \u-decoded), same as P4/P5/P6.
  if (bodyLeaksCanary(P3, canary_b)) {
    return fail("blocked_by_design", "canary_viewer_echoed_p3");
  }
  // The anon P4/P4id bodies are trusted to prove the unauthenticated read does NOT
  // leak the canary; a truncated anon body could hide the canary past the fetch cap,
  // so reject truncation before the leak scan.
  if (P4.bodyTruncated !== false || P4id.bodyTruncated !== false) {
    return fail("blocked_by_design", "p4_body_truncated");
  }
  if (bodyLeaksCanary(P4, canary_b) || bodyLeaksCanary(P4id, canary_b)) {
    return fail("blocked_by_design", "canary_leaked_unauthenticated");
  }
  // #10 ACCESS CONTROL — P4 and P4-id both 401/403.
  if (!isAuthChallenge(P4) || !isAuthChallenge(P4id)) {
    return fail("blocked_by_defense", "object_not_access_controlled");
  }
  // Login-page-as-200 exclusion (defense in depth on P4).
  if (responseLooksLikeLoginPage(P2) || isLoginRedirect(P2)) {
    return fail("blocked_by_defense", "p2_login_page");
  }
  // #11 AUTHENTICATED-BUT-SHARED EXCLUSION — a DIFFERENT authenticated identity C
  // is denied O_B. This only excludes "shared to all authenticated users" if C is
  // GENUINELY authenticated: a 401/403 from stale/invalid C creds is just "C not
  // logged in" (indistinguishable from anon P4) and proves nothing. So PROVE C
  // authenticates first. Two legs are required, because C reading O_C is only proof
  // of authentication if O_C is NOT publicly readable:
  //   (a) O_C is access-controlled — an ANON read (P8) is denied and does not leak
  //       canary_c. If O_C were public, a stale/empty C would read it too.
  //   (b) C passes that gate — C's read (P7) is a 200 resource reflecting canary_c.
  if (P8.bodyTruncated !== false) {
    return fail("blocked_by_design", "p8_body_truncated");
  }
  if (bodyLeaksCanary(P8, canary_c)) {
    return fail("blocked_by_design", "o_c_public_canary_leaked");
  }
  if (!isAuthChallenge(P8)) {
    return fail("blocked_by_design", "o_c_not_access_controlled");
  }
  if (P7.bodyTruncated !== false) {
    return fail("blocked_by_design", "p7_body_truncated");
  }
  const p7Parsed = parseJsonBody(P7);
  if (p7Parsed == null || !isResourceShapedResponse(P7) || discoverCanaryFieldPath(p7Parsed, canary_c) == null) {
    return fail("blocked_by_design", "identity_c_not_authenticated");
  }
  // P5 must be a TRUE deny (401/403 ONLY) whose body does NOT carry B's canary.
  if (P5.bodyTruncated !== false) {
    return fail("blocked_by_design", "p5_body_truncated");
  }
  if (isAuthChallenge(P5)) {
    // A 401/403 whose body STILL leaks B's canary is NOT a true deny — identity C
    // actually received B's object inside the error envelope, so the access-control
    // leg would be unsound. Scan the FULL deny body (bodyLeaksCanary), so a canary
    // hidden past the object cap in a large error envelope is not missed.
    if (bodyLeaksCanary(P5, canary_b)) {
      return fail("blocked_by_design", "p5_canary_in_deny_body");
    }
  } else {
    // P5 200-without-canary → p5_ambiguous (D11a HARD block). P5 404 / canary
    // present are equally non-deny and also block here.
    if (P5.status === 404) {
      return fail("blocked_by_design", "p5_not_found_ambiguous");
    }
    const p5Parsed = parseJsonBody(P5);
    if (p5Parsed != null && canaryAt(p5Parsed, fieldPath) === canary_b) {
      return fail("blocked_by_design", "p5_authenticated_shared");
    }
    return fail("blocked_by_design", "p5_ambiguous");
  }
  // #12 TENANT PARTITION SYMMETRY — P6 (B→O_A) challenged OR 404, AND its body does
  // NOT leak A's canary. A truncated P6 could hide canary_a past the fetch cap; a
  // 401/403/404 whose body STILL carries canary_a means B actually read A's object
  // (the partition is false) — both block. Symmetric to the P5 deny-body scan.
  if (P6.bodyTruncated !== false) {
    return fail("blocked_by_design", "p6_body_truncated");
  }
  if (!(isAuthChallenge(P6) || P6.status === 404)) {
    return fail("blocked_by_design", "p6_not_partitioned");
  }
  if (bodyLeaksCanary(P6, canary_a)) {
    return fail("blocked_by_design", "p6_canary_in_deny_body");
  }
  // #13/#14 are DEMOTED from hard refutations to non-blocking CONFIDENCE SIGNALS
  // (measure-idor-oracle.js read-out: they killed real A-only IDORs, holding recall at
  // 16.7%). The canary witness already proved A read B's specific private object (P2/P2′)
  // while anon (P4/P4id) AND a third authenticated tenant C (P5) are denied — a categorical
  // cross-principal break. #13/#14 only STRENGTHEN the labeling of that break as
  // cross-TENANT; their absence weakens tenant attribution but does NOT refute the IDOR, so
  // record the weakness and continue to the mint. (C1/C2 controls trip DIFFERENT, upstream
  // gates — canary_leaked_unauthenticated / p5_authenticated_shared — which are NOT demoted.)
  const confidenceSignals = [];
  // #13 CROSS-TENANT SCOPE PROOF — is O_B's OWN scope private, or an EXPLICIT shared label?
  // An EXPLICIT shared/default/public value at ANY owning-scope alias is positive evidence O_B is
  // SHARED (not B-private) → HARD refutation. Scan it across EVERY body that should reflect O_B's
  // scope, each at EVERY alias (hasExplicitSharedScope, not just the first ownScopeOf match):
  //   - p1Parsed     — the live P1 cross-principal read;
  //   - parsedReadback — B's OWN owner readback (already trusted for #20 canary discovery + #24
  //     create-time PII screening, so its shared label is authoritative even when P1 omits it);
  //   - p2Parsed/p2primeParsed — the successful A→B proof reads whose canary signs the row; the
  //     signed proof body itself must not say "public"/"default"/"shared".
  // Only a scope MISSING from the P1 body across ALL aliases is "unprovable" and demotes to a
  // confidence signal (the read still mints, at a LOWER severity). Asymmetric by the
  // absence-vs-positive rule: positive shared evidence on ANY of these bodies STRENGTHENS the
  // block; a readback/proof body that merely carries a PRIVATE scope does NOT clear the P1-side
  // soft-gate (the soft-gate reflects what the P1 proof body demonstrates to a reviewer).
  for (const proofBody of [p1Parsed, parsedReadback, p2Parsed, p2primeParsed]) {
    if (hasExplicitSharedScope(proofBody)) {
      return fail("blocked_by_design", "own_scope_explicitly_shared");
    }
  }
  // A PRESENT-but-unusable owning-scope value (an unsafe-magnitude / float number that
  // scopeValueString drops to null) would make the same-tenant guard below read the scope as
  // ABSENT and could soft-mint two SAME-tenant objects (both carrying the same unsafe numeric
  // org_id) as cross-tenant. We cannot prove the identities are in DIFFERENT tenants when a
  // discriminator is present but unsafe to compare, so fail closed across EVERY body that feeds
  // the tenant guard — the B side (p1/readback/p2/p2′) AND the A side (p3). (Codex PR#136 P1.)
  for (const proofBody of [p1Parsed, parsedReadback, p2Parsed, p2primeParsed, p3Parsed]) {
    if (hasUnusableOwningScope(proofBody)) {
      return fail("blocked_by_design", "own_scope_unusable_numeric");
    }
  }
  const p1Scope = ownScopeOf(p1Parsed);
  const ownScopePrivate = ownScopeIsPrivate(p1Scope);
  if (p1Scope == null) {
    confidenceSignals.push({
      gate: "own_scope_missing",
      reason: "P1 echoed NO owning-scope key, so B-private ownership cannot be shown from the body; cross-tenant attribution is unproven.",
    });
  }
  // #14 TENANT DISCRIMINATOR — A and B present at a fixed key AND differ?
  const tenantB = tenantDiscriminator(p1Parsed);
  const tenantA = tenantDiscriminator(p3Parsed);
  // PROVABLY SAME tenant: A and B share ANY owning-scope VALUE, across EVERY alias key (not
  // just the first-matched discriminator, and not just at the SAME key) — e.g. B `org_id:"acme"`
  // vs A `tenant_id:"acme"`, or a match under a SECONDARY key. That is positive evidence AGAINST
  // a cross-tenant break, so it stays a HARD refutation. A genuine same-tenant user-level BOLA
  // would need a different proof; minting it here would mislabel it as THIS producer's
  // cross-TENANT IDOR. B's scope values fold in the OWNER READBACK too (same absence-vs-positive
  // rule as #13): when the live P1 body omits owning-scope keys, the trusted readback's B-scope
  // still hard-refutes a same-tenant collision with A. (It can only ADD a refutation; differing
  // values do NOT clear the P1-side distinctness soft-gate below, which stays on the live bodies.)
  // B's scope values ALSO fold in the signed A→B proof bodies (p2/p2′): those are the reads whose
  // canary signs the row and are already trusted for the explicit-shared hard block above, so if
  // the proof body itself reveals O_B sits in A's tenant (same owning-scope value as A), that is
  // positive same-tenant evidence and must hard-refute too — even when P1/readback omit the key
  // (Codex PR#136 P1). Folding proof bodies can only ADD a refutation: a real cross-tenant proof
  // body carries B's tenant value (≠ A), so it never creates a false same-tenant collision.
  const bScopeValues = [...new Set([
    ...owningScopeValues(p1Parsed),
    ...owningScopeValues(parsedReadback),
    ...owningScopeValues(p2Parsed),
    ...owningScopeValues(p2primeParsed),
  ])];
  const aScopeValues = owningScopeValues(p3Parsed);
  const tenantsProvablySame = aScopeValues.some((v) => bScopeValues.includes(v));
  if (tenantsProvablySame) {
    return fail("blocked_by_design", "identities_collided_same_tenant");
  }
  // PROVABLY DISTINCT: both present at the SAME key with DIFFERENT values. Compared
  // case-INSENSITIVELY to stay consistent with the same-tenant HARD block above (owningScopeValues
  // lowercases): a case-only difference ("Acme" vs "acme") must NOT read as "provably distinct" here
  // while the same-tenant guard already treats it as one tenant — that asymmetry would otherwise be a
  // false-negative dead-zone. Case-insensitive is the SAFE direction (prefer same-tenant → no mint).
  const tenantsProvablyDistinct = !!(tenantA && tenantB
    && tenantA.key === tenantB.key && tenantA.value.toLowerCase() !== tenantB.value.toLowerCase());
  // The remainder — a missing discriminator on either side, or different alias keys carrying
  // different values — is UNPROVABLE (not disproven): demote to a confidence signal.
  if (!tenantsProvablyDistinct) {
    confidenceSignals.push({
      gate: "identities_collided_not_provable",
      reason: "A and B carry no comparable tenant discriminator (missing on one side, or different alias keys with different values); cross-tenant distinctness is not provable from the bodies.",
    });
  }
  // #15 CACHE ORIGIN-PROOF — no DEFINITIVE shared-cache hazard signal on P2/P2′.
  if (responseIsSharedCacheable(P2) || responseIsSharedCacheable(P2prime)) {
    return fail("blocked_by_infra", "cache_shared_response");
  }
  // #15b AFFIRMATIVE-ORIGIN — the cross-principal proof bodies must be ORIGIN reads,
  // not a downstream cache cross-fill. responseIsSharedCacheable only catches a
  // DEFINITIVE hazard (Age>0 / explicit HIT); a query-string-ignoring shared cache
  // that stored a `private`/`no-store` body and emits Age:0 / Via / an unlabeled
  // cache header would serve B's body to A for BOTH P2 and the ?_bobcb P2′ (same
  // path → same cache key), defeating #16's fresh-URL leg. So when a shared cache is
  // DETECTABLY in the request path without an affirmative MISS, fail closed rather
  // than mint a row that mislabels a cache cross-fill as an origin authorization
  // break. A direct origin read (no cache header) and a labeled-MISS CDN both pass.
  if (cacheInPathWithoutProvenMiss(P2) || cacheInPathWithoutProvenMiss(P2prime)) {
    return fail("blocked_by_infra", "cannot_prove_origin_read_through_cache");
  }
  // #17 SYNTHETIC-ONLY (AC-5) — piiScan P1, P2, AND the cache-bust P2′ find only
  // allowlisted synthetics. P2′ is another successful A→B proof body whose canary
  // is required before signing (#16), so it must clear the same PII tripwire — a
  // fresh-URL fetch can return an expanded payload the cached P2 did not. Scan BOTH
  // the parsed body (canonicalJson resolves \u escapes) AND the RAW body text — a
  // JSON response with DUPLICATE keys keeps only the last value after JSON.parse, so
  // foreign PII in a shadowed duplicate key would evade a parsed-only scan.
  // Each proof body is screened in three forms so neither a duplicate (shadowed) key
  // nor a \u-escaped value can smuggle foreign PII past the synthetic-only gate: the
  // parsed object (canonicalJson resolves escapes but drops shadowed keys), the raw
  // text (keeps shadowed keys but not escapes), and the raw text with \u escapes
  // decoded (keeps shadowed keys AND resolves escapes).
  // The producer's own canaries are neutralized in every proof-scan form (neutralizeCanaries) so a chance
  // card-shaped digit run inside a hex canary cannot false-positive — the proof bodies legitimately reflect
  // canary_b. Exact 64-char replacement leaves any adjacent injected PII/secret intact for the scan.
  const proofParsedScan = [p1Parsed, p2Parsed, p2primeParsed].map((p) => neutralizeCanaries(p, ownCanaries));
  const proofScanTexts = [P1, P2, P2prime].flatMap((r) => {
    const raw = bodyTextOf(r);
    // raw + ALL decoded layers (\u / percent / layered) — a sensitive value encoded in
    // the body survives JSON.parse + canonicalJson but decodes server-side.
    return [neutralizeCanaries(raw, ownCanaries), neutralizeCanaries(decodeAllEncodingLayers(raw), ownCanaries)];
  });
  if (proofParsedScan.some((t) => piiScan(t, allowedEmails).length > 0)
    || proofScanTexts.some((t) => piiScan(t, allowedEmails).length > 0)) {
    return fail("blocked_operator_pii", "non_synthetic_pii_in_response");
  }
  // #17b SYNTHETIC-ONLY (secrets) — the signed proof body must not carry injected
  // credential-shaped data (JWT / AWS key / PEM / prefixed tokens). O_B is
  // self-provisioned synthetic, so a secret here is a server-injected expanded-record
  // leak. Same parsed + raw + \u-decoded screening as the PII tripwire.
  if (proofParsedScan.some((t) => secretShapesIn(t).length > 0)
    || proofScanTexts.some((t) => secretShapesIn(t).length > 0)) {
    return fail("blocked_operator_pii", "non_synthetic_secret_in_response");
  }

  // ── All mint conditions hold. Build the canonical target. ──
  // AC-2 was enforced UP-FRONT by resolveBaselineFromSurface (path_template is
  // bound to the surface's recorded endpoint) and every probe target was built
  // from that bound origin, so canonicalTarget is the routed target by
  // construction — no ledger/scan-trail membership check is needed, and a
  // redacted-http-audit check would add no soundness over this in-memory identity.
  const canonicalTarget = canonicalizeExploitTarget(oBUrl);

  // The canonical target is PERSISTED into the signed row. Its fixed path segments come
  // from the agent-supplied path_template, so screen the whole target (raw + all decoded
  // layers) for non-synthetic PII / credential shapes — an email/token in a fixed
  // segment (/api/users/victim@x.com/{id}) must not leak into the durable proof.
  for (const form of [canonicalTarget, decodeAllEncodingLayers(canonicalTarget)]) {
    if (piiScan(form, allowedEmails).length > 0 || secretShapesIn(form).length > 0) {
      return fail("blocked_operator_pii", "proof_target_contains_sensitive_value");
    }
  }

  // Deterministic captures: the P2 cross-tenant body (canonical-normalized,
  // synthetic+canary bytes only) is the ONLY file re-hashed at freeze.
  const p2BodyForCapture = canonicalJson(p2Parsed);
  const relationBooleans = {
    p0_stable: true,
    p2_prime_stable: true,
    p4_challenged: true,
    p4_id_challenged: true,
    p5_denied: true,
    p6_partitioned: true,
    c_authenticated: true,
    o_c_access_controlled: true,
    tenants_distinct: tenantsProvablyDistinct,
    own_scope_private: ownScopePrivate,
    no_cache_signal: true,
  };
  const diagnosticBundle = canonicalJson({
    probe_statuses: {
      p0a: P0a.status, p0b: P0b.status, p1: P1.status, p2: P2.status,
      p2prime: P2prime.status, p3: P3.status, p4: P4.status, p4id: P4id.status,
      p5: P5.status, p6: P6.status, p7: P7.status, p8: P8.status,
    },
    relation: relationBooleans,
    field_path: fieldPath,
    canary_present: { p1: true, p2: true, p2prime: true },
    tenant_key: tenantB ? tenantB.key : null,
    confidence_signals: confidenceSignals,
  });

  const row = withSessionLock(domain, () => buildAndSignOffensiveRow(domain, {
    runIdPrefix: "idor",
    toolId: TOOL_ID,
    method, canonicalTarget, surfaceId,
    identityTag: "B-as-A",
    stdoutContent: p2BodyForCapture,
    stderrContent: diagnosticBundle,
    relationBooleans,
    // A soft-gated fire (any confidence signal) caps the signed row at LOW: the unproven
    // cross-tenant attribution must be claim-visible, and severity is the only field the
    // claim/grade path carries. A fully-proven fire keeps the registry MEDIUM ceiling.
    demonstratedSeverityOverride: confidenceSignals.length > 0 ? "low" : undefined,
  }));

  // Masked three-hash return (sensitive_output:true) — NEVER raw response bytes.
  return {
    confirmed: true,
    target_domain: domain,
    surface_id: surfaceId,
    oracle_kind: oracleKind,
    offensive_outcome: "exploited_safely",
    row_written: true,
    // The values the evaluator copies verbatim into the bob_record_candidate_claim
    // exploit_run ref so offensiveRunRowSatisfiesEvidence binds row↔ref.
    run_id: row.run_id,
    tool_id: row.tool_id,
    target: row.target,
    command_hash: row.command_hash,
    stdout_hash: row.stdout_hash,
    stderr_hash: row.stderr_hash,
    exit_code: row.exit_code,
    demonstrated_severity: row.demonstrated_severity,
    // Non-blocking provability signals (#13/#14): EMPTY on a fully-proven fire, populated
    // when tenant attribution is weaker. Hash-bound via stderr_hash (diagnosticBundle) and
    // surfaced here so the evaluator/grader can corroborate or discount the attribution.
    // Each consumer-facing slot gets an INDEPENDENT array (.slice()) so a caller mutating one
    // return field can never silently mutate the other (top-level vs masked_oracle).
    confidence_signals: confidenceSignals.slice(),
    // The agent passes this surface_id to BOTH the producer and the record call
    // so the #111 strict-equality gate passes.
    masked_oracle: {
      relation: relationBooleans,
      canary_present: { p1: true, p2: true, p2prime: true },
      confidence_signals: confidenceSignals.slice(),
      body_hash: row.stdout_hash,
    },
    ...identity,
    ...internalHostPolicy,
  };
}

module.exports = {
  TOOL_ID,
  ORACLE_KIND_VALUES,
  READ_ONLY_METHODS,
  IDOR_ORACLE_DEMONSTRATED_CEILING,
  idorConfirm,
  // Exported for unit tests (seeded, no live target).
  canaryAt,
  discoverCanaryFieldPath,
  ownScopeOf,
  ownScopeIsPrivate,
  tenantDiscriminator,
  piiScan,
  profileHasProvenance,
  // PR-D live-arm internals (injectable fetchFn so unit tests drive create/readback without a live target).
  liveProvision,
  createObject,
  idorProvisionAuthorizedFor,
  mintCanary,
  pathHasConcreteParentInstance,
  IDOR_PROVISION_ENV,
  // NOTE: buildAndSignOffensiveRow (in offensive-capture-writer.js) + assertSingleHostBoundEndpoint
  // are NOT re-exported here. buildAndSignOffensiveRow signs+writes a row WITHOUT running the
  // mint-condition gates (those live in idorConfirm), so re-exporting it would give an
  // internal caller a gate-bypassing signed-row path. Keep the row builder private to the
  // tool layer; tests drive the full oracle through idorConfirm.
};
