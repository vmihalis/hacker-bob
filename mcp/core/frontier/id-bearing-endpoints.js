"use strict";

const RESERVED_PROTO_KEYS = new Set(["__proto__", "constructor", "prototype"]);

// An encoded path separator at ANY encoding depth: %2F / %5C, %252F, %2525252F,
// etc. (`(25)*` absorbs each extra `%25` layer).
const ENCODED_SEPARATOR_RE = /%(?:25)*(?:2f|5c)/i;

// Recursively percent-decode each path segment until stable.
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

function capturedIdSegmentIsSafe(idSegment) {
  if (!idSegment || idSegment.includes("/") || idSegment.includes("\\")) return false;
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

function isRouteParamMarker(seg) {
  return /^:[^/]+$/.test(seg)
    || /^\{[^/]+\}$/.test(seg)
    || /^%7b[^/]+%7d$/i.test(seg);
}

function candidateEndpointPathname(value) {
  if (typeof value !== "string" || value.trim() === "") return null;
  try {
    return new URL(value, "https://bob.invalid").pathname;
  } catch {
    return null;
  }
}

// S1 id-bearing collection detector — DEFINED as the templatizer's total: a value is
// id-bearing iff templatizeIdBearingEndpoint can freeze a canonical {id}-template for it.
// Single-sourcing the detector THROUGH the templatizer (never a parallel segment scan that
// could drift) makes route.id_bearing <=> route.id_bearing_endpoints non-empty by construction,
// and matches the runner (auth-differential-runner.js:402) and grade gate (claims.js:2001), which
// both bind coverage by templatizing the swept endpoint. An id-bearing value is one whose path
// carries a per-object id segment (:id / {id} / %7b..%7d / numeric / uuid / hex-0x) OR whose query
// carries an object-scoping key (?teamId=/?userId=/?id=) — the query-param BOLA shape. A benign
// sibling (/me, /api/users, ?page=2) templatizes to null, so it never launders coverage.
function endpointValueIsIdBearing(value) {
  return templatizeIdBearingEndpoint(value) !== null;
}

// One path segment is id-bearing iff it is a route-param marker (:id / {id} / %7b..%7d) or a
// concrete id-signalling segment (a real identifier, not a bare-punctuation fixed-route word).
function segmentIsIdBearing(seg) {
  // A route-param marker (:id / {id} / %7b..%7d) is always id-bearing. For a CONCRETE segment,
  // reuse the file's existing resource-instance classifier (segmentLooksLikeResourceInstance:
  // pure-numeric / uuid / separated slug like proj-123) and EXCLUDE API-structural words
  // (isStaticApiAncestor: v1/v2/oauth2/graphql/... via VERSION_SEGMENT_RE + STATIC_API_ANCESTOR_WORDS).
  // A digit-anywhere rule falsely flagged ubiquitous versioned routes (/api/v1/users), freezing
  // an unsatisfiable cross-tenant obligation onto a fixed collection route. The extra classifiers
  // (isUlid / isPrefixedOpaqueSlug / isHighEntropyOpaqueKey) close common object-identifier shapes
  // segmentLooksLikeResourceInstance misses — a gated crown carrying an ord_KxPq9Z / ULID / base58
  // key would otherwise route id_bearing:false and never earn a cross-tenant test. All new terms sit
  // INSIDE the !isStaticApiAncestor && capturedIdSegmentIsSafe guard, so a version tag / structural
  // word / traversal segment is still never id-bearing.
  return isRouteParamMarker(seg)
    || (!isStaticApiAncestor(seg) && capturedIdSegmentIsSafe(seg)
      && (segmentLooksLikeResourceInstance(seg)
        || isHexIdToken(seg)
        || isUlid(seg)
        || isPrefixedOpaqueSlug(seg)
        || isHighEntropyOpaqueKey(seg)));
}

// A long hex/hash token or 0x address (>=16 hex chars) — a per-object identifier (content
// hash, tx hash, on-chain address) that segmentLooksLikeResourceInstance does not cover. The
// >=16 length keeps short version/acronym segments (v1, s3, api2) excluded.
function isHexIdToken(seg) {
  return /^(0x)?[0-9a-f]{16,}$/i.test(String(seg));
}

// A ULID (26 Crockford-base32 chars: 0-9 A-Z minus I/L/O/U, leading timestamp char 0-7). A common
// per-object id (Stripe-adjacent stacks, event stores) that carries base32 letters beyond hex, so
// isHexIdToken never catches it. The exact 26-length + Crockford alphabet make a collision with a
// path WORD implausible (no 26-char English word, and I/L/O/U are excluded).
const ULID_RE = /^[0-7][0-9ABCDEFGHJKMNPQRSTVWXYZ]{25}$/i;
function isUlid(seg) {
  return ULID_RE.test(String(seg));
}

// A PREFIXED opaque slug: a short lowercase word + "_" + a mixed high-entropy token (ord_KxPq9Z,
// user_abc123, sub_9fKQ2p). The token must be >=6 chars AND genuinely mixed — a digit-with-letter
// or a mixed-case run — so a plain two-word segment (reset_password, access_token, user_profile)
// carries no id signal and is NOT tagged. This is the ubiquitous Stripe/Twilio-style object-id shape
// that segmentLooksLikeResourceInstance (which needs a SEPARATED trailing/leading digit run) misses.
function isPrefixedOpaqueSlug(seg) {
  const m = /^([a-z]{2,10})_([A-Za-z0-9]{6,})$/.exec(String(seg));
  if (!m) return false;
  const token = m[2];
  const hasDigit = /[0-9]/.test(token);
  const hasLower = /[a-z]/.test(token);
  const hasUpper = /[A-Z]/.test(token);
  return (hasDigit && (hasLower || hasUpper)) || (hasUpper && hasLower);
}

// A single high-entropy opaque object key (base58 / base64url): a >=16-char run over the base58 /
// base64url charset that is a genuine ALNUM token (has BOTH a letter and a digit) — the per-object
// key discovery captured verbatim (Bitcoin-style base58, nanoid, base64url handles). Requiring a
// digit AND a letter keeps a readable long word (internationalization) or a camelCase RPC method
// (getAccountBalanceById) out; a `-`/`_`-delimited multi-word slug that merely happens to carry a
// stray digit (q3-2024-financial-report) is dropped by the readable-slug guard, so precision holds.
function isHighEntropyOpaqueKey(seg) {
  const s = String(seg);
  if (s.length < 16) return false;
  if (!/^[A-Za-z0-9_-]+$/.test(s)) return false;
  if (!/[0-9]/.test(s) || !/[A-Za-z]/.test(s)) return false;
  const parts = s.split(/[-_]/).filter(Boolean);
  if (parts.length >= 2) {
    const wordParts = parts.filter((p) => /^[A-Za-z]{4,}$/.test(p));
    if (wordParts.length >= 2) return false; // readable multi-word slug, not an opaque key
  }
  return true;
}

// Plural collection nouns that precede a per-object INSTANCE segment (/users/<handle>, /orgs/<slug>,
// /teams/<slug>). Deliberately PLURAL-only: a singular namespace (/account/reset-password,
// /user/settings) is a singleton route, not a collection of objects, so it must NOT make the next
// segment an id — keeping ubiquitous singular action routes out of the id-bearing set.
const COLLECTION_NOUN_SEGMENTS = new Set([
  "users", "orgs", "organizations", "teams", "accounts", "projects", "groups",
  "members", "customers", "companies", "workspaces", "tenants", "clients",
  "repos", "repositories", "posts", "articles", "comments", "orders", "invoices",
  "documents", "events", "products", "subscriptions", "tickets", "issues", "tasks",
  "folders", "channels", "rooms", "messages", "devices", "apps", "applications", "services",
]);
function segmentIsCollectionNoun(seg) {
  return COLLECTION_NOUN_SEGMENTS.has(normalizeFieldName(seg));
}

// Reserved SUB-ROUTE words: a segment right after a collection noun that names an action / view /
// singleton, not an object instance (/users/settings, /orgs/new, /teams/search). Excluded from the
// handle-after-collection rule so /users/settings stays id_bearing:false (the named precision case).
const RESERVED_SUBROUTE_WORDS = new Set([
  "settings", "setting", "profile", "profiles", "me", "self", "current", "all",
  "new", "edit", "create", "update", "delete", "remove", "add", "search",
  "login", "logout", "signin", "signout", "signup", "register", "password",
  "admin", "dashboard", "home", "about", "help", "config", "configuration",
  "preferences", "notifications", "billing", "security", "privacy",
  "export", "import", "invite", "invites", "list", "count", "summary",
  "activity", "feed", "avatar", "photo", "photos", "image", "images",
  "verify", "confirm", "reset", "activate", "status", "health", "info",
  "details", "overview", "history", "logs", "stats", "metrics", "report",
  "reports", "recent", "latest", "popular", "featured", "trending", "public",
  "private", "shared", "archive", "archived", "trash", "drafts", "draft",
]);
function segmentIsReservedSubroute(seg) {
  return RESERVED_SUBROUTE_WORDS.has(normalizeFieldName(seg));
}

// Handle/username/slug shape: begins alnum, then alnum plus - _ . — a plausible per-object handle a
// path carries in the instance position (johndoe, acme-corp, team.alpha). Not by itself id-bearing;
// it only qualifies in the handle-AFTER-collection context below.
function segmentIsHandleShaped(seg) {
  return /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(String(seg));
}

// A camelCase / verb_snake RPC-method segment led by a data-access verb (getBalanceDetails, list_all,
// createOrder). Unlike an ambiguous handle (johndoe), a verb-led method is UNambiguously an action,
// not an object, so it is excluded from the handle-after-collection rule (/accounts/getBalanceDetails
// stays id_bearing:false). Only a camelCase (verb + uppercase) / snake (verb + "_") / bare-verb form
// trips; a hyphenated or all-lowercase slug (set-designer, deleter) is left as a handle.
const HANDLE_VERB_PREFIXES = new Set([
  "get", "set", "list", "create", "update", "delete", "fetch", "find", "search", "query",
  "add", "remove", "save", "load", "send", "post", "put", "patch", "exec", "run", "do",
  "validate", "verify", "generate", "refresh", "toggle", "enable", "disable",
  "upload", "download", "export", "import", "sync", "count", "check",
]);
function segmentLooksLikeVerbMethod(seg) {
  const m = /^([a-z]+)(?=[A-Z_]|$)/.exec(String(seg));
  return m !== null && HANDLE_VERB_PREFIXES.has(m[1]);
}

// True when `seg` sits immediately after a plural collection noun AND is a plausible handle/slug
// instance (not a reserved sub-route, not a nested collection, not a structural word). This is the
// context-sensitive BOLA shape (/users/johndoe, /orgs/acme-corp) that a context-free per-segment
// scan cannot see. Applied ONLY within templatizeIdBearingEndpoint (which has the predecessor); the
// same function drives the runner + grade binding, so the swept /users/johndoe and the frozen
// /users/{id} stay byte-identical.
function segmentIsHandleAfterCollection(prevSeg, seg) {
  if (!segmentIsCollectionNoun(prevSeg)) return false;
  if (isRouteParamMarker(seg)) return false;          // already handled as a marker
  if (isStaticApiAncestor(seg)) return false;
  if (!capturedIdSegmentIsSafe(seg)) return false;
  if (segmentIsReservedSubroute(seg)) return false;   // /users/settings, /orgs/new
  if (segmentIsCollectionNoun(seg)) return false;     // /users/orders is a nested collection, not an instance
  if (segmentLooksLikeVerbMethod(seg)) return false;  // /accounts/getBalanceDetails is a method, not an object
  return segmentIsHandleShaped(seg);
}

// An object-scoping SEARCH-param KEY: a query parameter that keys a PER-OBJECT resource
// (?teamId=/?userId=/?tenantId=/?id=/?uuid=) rather than paginating/sorting/searching a
// collection (?page=/?limit=/?offset=/?sort=/?q=/?filter=). Classified by KEY, REUSING the
// SAME create-body id/owner/scope predicates the id_field guards already use — so "an
// object-identifying field" stays single-sourced: an id alias (ID_ALIAS_KEYS /
// keyHasIdAliasSegment: id, uuid, guid, object_id, ...), an owner selector
// (fieldIsOwnerSelector: userId, teamId, projectId, account_id, ...), or a scope selector
// (fieldIsScopeSelector: tenantId, org_id, workspace_id, ...). Fails SAFE toward object-scoping
// on a genuine object key; pagination/sort/search keys match NONE of these, so a collection
// listing is never mistaken for a per-object BOLA surface (which would freeze an unsatisfiable
// cross-tenant obligation onto a non-BOLA route — the inverted 'bound-not-rank' harm).
// A query SORT/ORDER directive (sortBy, order_by, groupBy, ...) carries a "by" token that
// fieldIsOwnerSelector matches for create-BODY actor fields (created_by) — but as a query KEY it
// selects a sort COLUMN, not an object, so it must not scope a per-object BOLA obligation onto a
// collection listing (the inverted bound-not-rank harm). Owner FILTERS (created_by=<userId>) stay
// object-scoping; only the bare sort/order/group directives are excluded.
const SORT_DIRECTIVE_KEYS = new Set(["sort", "order", "group", "sortby", "orderby", "groupby"]);
function isQuerySortDirectiveKey(norm) {
  if (SORT_DIRECTIVE_KEYS.has(norm)) return true;
  const toks = fieldNameTokens(norm);
  return toks.length === 2 && toks[1] === "by"
    && (toks[0] === "sort" || toks[0] === "order" || toks[0] === "group");
}
function paramKeyIsObjectScoping(key) {
  if (typeof key !== "string" || key === "") return false;
  const norm = normalizeFieldName(key);
  if (ID_ALIAS_KEYS.has(norm)) return true;
  if (keyHasIdAliasSegment(key, "")) return true;
  if (fieldIsScopeSelector(key)) return true;
  if (!isQuerySortDirectiveKey(norm) && fieldIsOwnerSelector(key)) return true;
  return false;
}

// The object-scoping search-param keys (sorted, deduped) of a candidate endpoint VALUE. Parsed
// with the SAME WHATWG base (https://bob.invalid) candidateEndpointPathname uses, so a relative
// or an absolute value both resolve. Sorting makes the frozen suffix order-independent
// (?userId=&teamId= and ?teamId=&userId= collapse to ONE canonical form).
function objectScopingParamKeys(value) {
  if (typeof value !== "string" || value.trim() === "") return [];
  let url;
  try {
    url = new URL(value, "https://bob.invalid");
  } catch {
    return [];
  }
  const keys = new Set();
  for (const key of url.searchParams.keys()) {
    if (paramKeyIsObjectScoping(key)) keys.add(key);
  }
  return Array.from(keys).sort();
}

// Canonical id-bearing template with EVERY id PATH segment collapsed to {id} AND every
// object-scoping SEARCH param collapsed to key={id}, so a concrete sweep (/api/orders/123,
// /api/teams?teamId=<uuid>) matches the surface's stored TEMPLATE (/api/orders/{id},
// /api/teams?teamId={id}). Inspects ALL path segments — the most common BOLA shape carries the
// owner id in a NON-final segment (/users/{id}/orders), which a final-segment-only check would
// miss — AND the query keys (the query-param BOLA shape, /api/teams?teamId=<uuid>). Object-scoping
// params are sorted then collapsed to key={id}, so two concrete values differing only in the
// object-key VALUE (?teamId=<uuidA> vs <uuidB>) freeze to the SAME string the runner/grade gate
// re-derive from the swept endpoint. The `?...` suffix is appended ONLY when >=1 object-scoping
// param exists, so every path-only endpoint stays BYTE-IDENTICAL to before. Returns null when
// neither a path id nor an object-scoping query key is present (a benign collection/pagination
// route), so the detector above is exactly this function's total — they cannot disagree.
function templatizeIdBearingEndpoint(value) {
  const pathname = candidateEndpointPathname(value);
  if (!pathname) return null;
  const segments = pathname.split("/").filter(Boolean);
  let sawId = false;
  const templated = segments.map((seg, i) => {
    if (segmentIsIdBearing(seg)) {
      sawId = true;
      return "{id}";
    }
    // Context-sensitive: a handle/slug immediately after a plural collection noun (/users/johndoe,
    // /orgs/acme-corp) is a per-object instance even with no context-free id signal.
    if (i > 0 && segmentIsHandleAfterCollection(segments[i - 1], seg)) {
      sawId = true;
      return "{id}";
    }
    return seg;
  });
  const objectScopeKeys = objectScopingParamKeys(value);
  if (objectScopeKeys.length > 0) sawId = true;
  if (!sawId) return null;
  const templatedPath = `/${templated.join("/")}`;
  if (objectScopeKeys.length === 0) return templatedPath;
  return `${templatedPath}?${objectScopeKeys.map((k) => `${k}={id}`).join("&")}`;
}

// True when discovery's interesting_params[] names an object-identifying param (id / uuid / *_id /
// objectId / userId / tenantId ...). Reuses the SAME paramKeyIsObjectScoping predicate the query-param
// BOLA detector uses, so a sort/order/group directive key (sortBy, order_by) — which names a column,
// not an object — never trips the flag. Positive evidence the surface serves per-object reads even
// when discovery captured no concrete id-bearing endpoint URL.
function surfaceInterestingParamsIdBearing(surface) {
  const params = surface && Array.isArray(surface.interesting_params) ? surface.interesting_params : [];
  return params.some((p) => typeof p === "string" && p.trim() !== "" && paramKeyIsObjectScoping(p));
}

function surfaceExposesIdBearingCollection(surface) {
  try {
    for (const { value } of candidateSurfaceEndpoints(surface)) {
      if (endpointValueIsIdBearing(value)) return true;
    }
  } catch {
    return false;
  }
  // An id-like interesting_param raises the id_bearing FLAG even with no bindable endpoint. This is a
  // ONE-WAY, safe-direction relaxation of the flag<=>frozen-endpoints equality: surfaceIdBearingEndpoints
  // stays endpoint-derived (possibly empty), so the completion gate has nothing to bind and HOLDS toward
  // an honest partial (reason complete_idbearing_surface_no_differential) — it can NEVER false-clear a
  // surface purely because a param says "objects here". The crown gets a real cross-tenant test forced;
  // it just is not auto-satisfiable until the concrete id-bearing endpoint is discovered/recorded.
  try {
    if (surfaceInterestingParamsIdBearing(surface)) return true;
  } catch {
    return false;
  }
  return false;
}

// The surface's id-bearing endpoints in canonical {id}-template form, sorted+deduped. The
// router FREEZES this onto the MCP-owned route at route time (when attack_surface.json is
// fresh from discovery), so the completion gates bind coverage to endpoints the agent cannot
// later tamper — never re-reading agent-writable attack_surface.json at grade time.
function surfaceIdBearingEndpoints(surface) {
  const out = new Set();
  try {
    for (const { value } of candidateSurfaceEndpoints(surface)) {
      const t = templatizeIdBearingEndpoint(value);
      if (t) out.add(t);
    }
  } catch {
    return [];
  }
  return Array.from(out).sort();
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
// Path segments that are DEFINITIVELY API-structural — the versioned / gateway prefixes a REST route
// carries ABOVE its top-level collection, never a tenant/org/customer INSTANCE. Kept deliberately SMALL:
// the fail-closed direction prefers declining a legitimate-but-nested collection over ever POSTing a
// synthetic object into a real tenant container.
const STATIC_API_ANCESTOR_WORDS = new Set([
  "api", "apis", "rest", "restapi", "rpc", "jsonrpc", "graphql", "gql",
  "public", "internal", "external", "gateway", "app",
]);
// A version-tag ancestor (v1, v2, v1_2, v2.1) is structural, not an instance.
const VERSION_SEGMENT_RE = /^v\d+(?:[._-]\d+)*$/i;
function isStaticApiAncestor(seg) {
  const s = String(seg).toLowerCase();
  return STATIC_API_ANCESTOR_WORDS.has(s) || VERSION_SEGMENT_RE.test(s);
}

module.exports = {
  endpointValueIsIdBearing,
  templatizeIdBearingEndpoint,
  surfaceExposesIdBearingCollection,
  surfaceIdBearingEndpoints,
  normalizeFieldName,
  ID_ALIAS_KEYS,
  keyHasReservedSegment,
  keyHasIdAliasSegment,
  baseNoun,
  fieldNameTokens,
  fieldIsScopeSelector,
  fieldIsOwnerSelector,
  isRouteParamMarker,
  segmentLooksLikeResourceInstance,
  isStaticApiAncestor,
};
