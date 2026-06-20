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
  resolveBaselineFromSurface,
  normalizePathTemplate,
  assertReadOnlyPath,
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
  if (parsedBody == null || typeof parsedBody !== "object") return null;
  for (const key of OWNING_SCOPE_KEYS) {
    const value = scopeValueString(parsedBody[key]);
    if (value != null) return value;
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
  if (parsedBody == null || typeof parsedBody !== "object") return null;
  for (const key of OWNING_SCOPE_KEYS) {
    const value = scopeValueString(parsedBody[key]);
    if (value != null) return { key, value };
  }
  return null;
}

// All owning-scope VALUES present in a body across EVERY OWNING_SCOPE_KEYS alias (not just the
// first-matched one). Lets the same-tenant guard detect a shared tenant value even when A and
// B label it under different alias keys, or carry it under a SECONDARY key (e.g. A
// owner_scope:"x" + tenant_id:"acme" vs B org_id:"acme"). Lowercased for a case-robust match.
function owningScopeValues(parsedBody) {
  if (parsedBody == null || typeof parsedBody !== "object") return [];
  const values = [];
  for (const key of OWNING_SCOPE_KEYS) {
    const value = scopeValueString(parsedBody[key]);
    if (value != null) values.push(value.toLowerCase());
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

// GAP A: v1 is scoped to single-endpoint, single-host surfaces. row.target is
// pinned to that single endpoint, never agent free-text.
function assertSingleEndpointSingleHost(surface, stateOrigin) {
  const endpoints = candidateSurfaceEndpoints(surface);
  if (endpoints.length !== 1) {
    rejectInvalidArguments(
      "bob_http_idor_confirm v1 only confirms single-endpoint surfaces; this surface records more than one endpoint.",
      { code: "idor_producer_surface_not_single_endpoint", endpoint_count: endpoints.length },
    );
  }
  // Count the origin(s) the surface's endpoint actually LIVES on — an absolute
  // endpoint resolves to its OWN origin (which may be an in-scope subdomain of the
  // session base), a relative endpoint to the session origin — PLUS any surface.hosts.
  // Do NOT seed the bare session origin the way resolveSurfaceOrigins does, or a single
  // endpoint on a subdomain would falsely count as two hosts and be rejected.
  const origins = new Set();
  for (const { value } of endpoints) {
    try {
      const u = /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? new URL(value) : new URL(value, stateOrigin);
      if (u.protocol === "http:" || u.protocol === "https:") origins.add(u.origin);
    } catch {}
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
      { code: "idor_producer_surface_not_single_endpoint", origin_count: origins.size },
    );
  }
  return { endpoint: endpoints[0], origin: [...origins][0] };
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
  // GAP E: {id}-final clean path segment, no query (mint condition #23).
  const pathTemplate = normalizePathTemplate(args.path_template, TOOL_ID);

  const { state } = readSessionStateStrict(domain);
  const internalHostPolicy = blockInternalHostsPolicyFields(state);
  const blockInternalHosts = internalHostPolicy.block_internal_hosts === true;

  // Resolve + route the surface; AC-2 cardinality (GAP A, mint condition #22).
  const { surface } = findRoutedSurface(domain, surfaceId);
  const stateOrigin = originFromState(domain, state, TOOL_ID);
  assertSingleEndpointSingleHost(surface, stateOrigin);
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
    // INERT at HEAD: live self-provisioning lands in PR-D. With no provision and
    // no fetch_fn there is no object to create, so the producer mints nothing.
    return blocked("blocked_by_design", "object_not_self_provisioned", {
      target_domain: domain,
      surface_id: surfaceId,
      oracle_kind: oracleKind,
      ...identity,
      ...internalHostPolicy,
    });
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
  const readbackPii = piiScan(parsedReadback, allowedEmails);
  if (readbackPii.length > 0) {
    return blocked("blocked_by_design", "shared_object_store", {
      target_domain: domain, surface_id: surfaceId, oracle_kind: oracleKind,
      ...identity, ...internalHostPolicy,
    });
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
  const bScopeValues = [...new Set([
    ...owningScopeValues(p1Parsed),
    ...owningScopeValues(parsedReadback),
  ])];
  const aScopeValues = owningScopeValues(p3Parsed);
  const tenantsProvablySame = aScopeValues.some((v) => bScopeValues.includes(v));
  if (tenantsProvablySame) {
    return fail("blocked_by_design", "identities_collided_same_tenant");
  }
  // PROVABLY DISTINCT: both present at the SAME key with DIFFERENT values.
  const tenantsProvablyDistinct = !!(tenantA && tenantB
    && tenantA.key === tenantB.key && tenantA.value !== tenantB.value);
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
  const proofParsed = [p1Parsed, p2Parsed, p2primeParsed];
  const proofScanTexts = [P1, P2, P2prime].flatMap((r) => {
    const raw = bodyTextOf(r);
    // raw + ALL decoded layers (\u / percent / layered) — a sensitive value encoded in
    // the body survives JSON.parse + canonicalJson but decodes server-side.
    return [raw, decodeAllEncodingLayers(raw)];
  });
  if (proofParsed.some((p) => piiScan(p, allowedEmails).length > 0)
    || proofScanTexts.some((t) => piiScan(t, allowedEmails).length > 0)) {
    return fail("blocked_operator_pii", "non_synthetic_pii_in_response");
  }
  // #17b SYNTHETIC-ONLY (secrets) — the signed proof body must not carry injected
  // credential-shaped data (JWT / AWS key / PEM / prefixed tokens). O_B is
  // self-provisioned synthetic, so a secret here is a server-injected expanded-record
  // leak. Same parsed + raw + \u-decoded screening as the PII tripwire.
  if (proofParsed.some((p) => secretShapesIn(p).length > 0)
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
    confidence_signals: confidenceSignals,
    // The agent passes this surface_id to BOTH the producer and the record call
    // so the #111 strict-equality gate passes.
    masked_oracle: {
      relation: relationBooleans,
      canary_present: { p1: true, p2: true, p2prime: true },
      confidence_signals: confidenceSignals,
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
  // NOTE: buildAndSignOffensiveRow (in offensive-capture-writer.js) + assertSingleEndpointSingleHost
  // are NOT re-exported here. buildAndSignOffensiveRow signs+writes a row WITHOUT running the
  // mint-condition gates (those live in idorConfirm), so re-exporting it would give an
  // internal caller a gate-bypassing signed-row path. Keep the row builder private to the
  // tool layer; tests drive the full oracle through idorConfirm.
};
