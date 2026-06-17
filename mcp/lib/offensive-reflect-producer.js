"use strict";

// bob_http_xss_reflect — the reflected-canary XSS *finder* signed-row PRODUCER
// (find-axis MVP). This is the FIRST real attack-to-FIND capability: it DISCOVERS
// a previously-unknown reflected-injection sink by attacking with a benign,
// inert payload.
//
// THE ORACLE (sound, deterministic, re-hashable): server-mint a high-entropy
// nonce + an INERT metachar sentinel ('"<>, never a working payload). A CONTROL
// fetch (nonce only) proves the param reflects into a text/html body and locates
// the sink CONTEXT. A PROBE fetch (nonce + the sentinel, bounded by a second
// random end-marker) proves the raw metacharacters survive UNESCAPED at that sink
// in an HTML-EXECUTABLE context (a text node or an unquoted-attribute / tag-break).
// Because reflection-unescaped is a deterministic function of the producer-minted
// nonce, re-sending re-produces the same bytes — categorically escaping the #110
// synthetic-id noise trap that the negative-only confirmer cannot. demonstrated_
// severity is a HARD MEDIUM by construction (reflection-context survival, NOT
// proven script execution; the browser-execution confirm that proves HIGH is a
// deferred follow-up tool).
//
// INTEGRITY BOUNDARY (honest, stated verbatim, NOT closed by this file): this MVP
// is the FIRST production tool that writes LIVE signed `exploited_safely`
// offensive-runs rows — so the #108 in-process-key boundary becomes load-bearing
// for the first time. The signed-row MAC is TAMPER-EVIDENT against an agent
// confined to the MCP tool surface and the guarded Bash surface; it is NOT
// cryptographically un-forgeable. A same-UID actor that executes arbitrary
// in-process code (a `node -e` that require()s readHandoffSigningKey, reads the
// 0600 signing key via fs, and hand-MACs a row) can forge a row around every gate
// below — the SAME assumption Bob's wave-handoff signing already makes. Absolute
// un-fakeability requires the deferred offensive-SANDBOX (UID/container) PR; do NOT
// advertise un-fakeability. Blast radius is bounded to a fabricated MEDIUM by the
// frozen per-tool ceiling. The second handler parameter ({ fetch_fn }) — the seam
// tests use to drive the oracle without a live target — is WITHIN this same
// in-process boundary (a caller that can pass it can already read the key and
// forge a row directly), so it does not widen the trust boundary. The MCP
// dispatcher always calls reflectXss(args) with NO second argument (LIVE).
//
// EGRESS RESIDUAL (honest): block_internal_hosts defaults OFF, so unless the
// session opted in, safeFetch does not resolve+reject internal/private addresses.
// The producer refuses to run under proxy-backed egress while block_internal_hosts
// is on (it cannot verify the policy through a proxy), mirroring the confirmer.

const crypto = require("crypto");

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
  resolveSurfaceOrigins,
  originFromState,
  urlFromEndpoint,
  assertReadOnlyPath,
  auditConfirmRequest,
  assertNoForbiddenInputs,
  contentTypeOf,
  SCOPE_VALIDATION_OPTS,
} = require("./offensive-http-common.js");
const {
  canonicalizeExploitTarget,
} = require("./claims.js");
const {
  buildAndSignOffensiveRow,
} = require("./offensive-capture-writer.js");
const {
  withSessionLock,
} = require("./storage.js");
const {
  canonicalJson,
} = require("./verification-contracts.js");
const {
  detectPiiShapes,
} = require("./pii-detector.js");

const TOOL_ID = "bob_http_xss_reflect";
// GET-only by construction (idempotent, read-only-safe, re-hashable). POST/form
// reflection is a deferred oracle_kind.
const READ_ONLY_METHODS = Object.freeze(["GET"]);
const ORACLE_KIND_VALUES = Object.freeze(["reflected_context"]);
const DEFAULT_TIMEOUT_MS = 10_000;

// HARD MEDIUM by construction: reflected-CONTEXT survival is NOT proven script
// execution. Frozen + "use strict" means an in-process actor's `MAP.x = "high"`
// THROWS. demonstrated_severity is stamped from the registry in
// buildAndSignOffensiveRow (OFFENSIVE_TOOL_DEMONSTRATED_CEILING), NEVER from here
// and NEVER agent-supplied; this frozen map documents the intent + anchors a test.
const REFLECT_DEMONSTRATED_CEILING = Object.freeze({ reflected_context: "medium" });

// The INERT metachar sentinel: the four HTML/attribute breakout metacharacters.
// It is NOT a working payload (no script/handler/scheme) — only the raw chars an
// XSS would need to break out of its lexical context. Server-minted, never
// agent-supplied.
const REFLECTION_SENTINEL = "'\"<>";

// Cap on how far apart the start-nonce and end-marker may render. The producer
// sends `<nonce><sentinel><endMarker>` as ONE contiguous value; the server
// reflects it as a unit, so the sentinel rendering between the two markers is
// tiny (<= ~20 chars even fully HTML-escaped). A larger gap means the markers were
// SPLIT across the page (a `<` between them would be page markup, not our
// surviving sentinel), so we fail closed rather than read adjacent markup as a
// surviving metachar.
const MAX_REFLECTION_GAP = 64;

// param_locus is a non-negative ordinal selecting among the surface's recorded
// query params; bound it so a wild value cannot index unboundedly.
const MAX_PARAM_LOCUS = 256;

// Raw-text + RCDATA elements: inside these, a `<` does NOT start a tag, so a
// surviving `<>` is NOT a tag-injection sink. Reflections here fail closed.
// `template` (an inert document fragment — its contents are NOT executed unless
// separate page code clones it) and `plaintext` (everything after it is literal
// text) are NOT rawtext per spec, but their contents are likewise non-executable
// for this oracle, so they are grouped here to fail closed (codex).
const RAWTEXT_ELEMENTS = Object.freeze(new Set(["script", "style", "xmp", "iframe", "noembed", "noframes", "noscript", "template", "plaintext"]));
const RCDATA_ELEMENTS = Object.freeze(new Set(["title", "textarea"]));

// The reflection CONTEXTS in which a surviving raw `<>` is HTML-executable: a text
// node (inject a fresh `<script>`/tag) or inside a start tag while UNQUOTED (a raw
// `>` breaks the tag → tag-break). Every other / ambiguous context is non-positive
// and fails closed.
const POSITIVE_CONTEXTS = Object.freeze(new Set(["text_node", "unquoted_attr"]));

// Focused credential-shape detector for the SIGNED capture bytes (defense in
// depth; the captured fragment is the producer's own nonce+sentinel rendering, so
// this should never fire, but a recorded endpoint PATH segment persisted into the
// row target could carry one). The hex nonce/end-marker match NONE of these.
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

// param_locus is a SELECTOR ordinal (a non-negative integer as a string), NEVER a
// raw param name/value/URL. It picks WHICH of the surface's deterministically
// sorted recorded query params to test; the param NAME is server-derived from the
// surface record and the injected VALUE is server-minted.
function normalizeParamLocus(value) {
  const raw = assertRequiredText(value, "param_locus").trim();
  if (!/^\d+$/.test(raw)) {
    rejectInvalidArguments("param_locus must be a non-negative integer ordinal selecting a recorded query param (never a raw URL, param name, or value)");
  }
  const index = Number(raw);
  if (!Number.isInteger(index) || index < 0 || index > MAX_PARAM_LOCUS) {
    rejectInvalidArguments(`param_locus ordinal must be between 0 and ${MAX_PARAM_LOCUS}`);
  }
  return index;
}

function mintToken(prefix) {
  // prefix + 128 bits hex. Alphanumeric (no metacharacters), high-entropy, and
  // never an action verb / "1" / "true", so the only metacharacters at the sink
  // come from the sentinel.
  return `${prefix}${crypto.randomBytes(16).toString("hex")}`;
}

function bodyTextOf(response, limit = 1_048_576) {
  if (!response || !Buffer.isBuffer(response.bodyBytes) || response.bodyBytes.length === 0) return "";
  return response.bodyBytes.toString("utf8", 0, Math.min(response.bodyBytes.length, limit));
}

function contentTypeIsHtml(response) {
  // v1 restricts to a RENDERED text/html document (MIME-sniff is a deferred
  // oracle_kind). Parse the MIME essence (the token before the first ';'), trim +
  // lowercase, and require an EXACT "text/html" — a loose substring would
  // over-match non-rendered subtypes (text/htmlx, text/html-sandboxed). A missing
  // or other content-type fails closed.
  const essence = contentTypeOf(response).split(";")[0].trim().toLowerCase();
  return essence === "text/html";
}

// A response delivered as a download (Content-Disposition: attachment) is NOT
// rendered in an HTML browsing context — the browser saves it to disk — so a
// reflected metacharacter there is not an executable XSS sink (auditor F1). The
// disposition TYPE is the token before the first ';'; an "attachment" type fails
// closed even when the content-type is text/html. A missing or "inline"
// disposition renders normally and is allowed.
function isAttachmentDisposition(response) {
  const cd = response && response.headers && typeof response.headers.get === "function"
    ? String(response.headers.get("content-disposition") || "")
    : "";
  return cd.split(";")[0].trim().toLowerCase() === "attachment";
}

// Percent-decode to a fixed point so a percent-encoded secret / PII shape in a
// PATH segment cannot slip past the literal-ASCII regexes below. Per-triplet decode
// (a whole-string decodeURIComponent throws on a stray `%`); bounded iterations
// catch double-encoding.
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
  // Screen the raw form AND its percent-decoded form: a recorded path segment can
  // carry a secret / PII shape percent-encoded (e.g. /u/alice%40corp.com or
  // /reset/sk%2Dlive_…) that the literal regexes would otherwise miss before the
  // value persists into the durable signed row target (brutalist).
  const decoded = percentDecodeToFixedPoint(raw);
  const s = decoded === raw ? raw : `${raw}\n${decoded}`;
  if (detectPiiShapes(s).length > 0) return true;
  return SECRET_SHAPE_RES.some((re) => re.test(s));
}

// ── the conservative, fail-closed, context-aware HTML reflection classifier ──

// A mini HTML tokenizer that scans html[0, idx) and returns the parser CONTEXT at
// idx. The bytes BEFORE the first reflected nonce occurrence are pure server
// markup (the producer's value appears AT idx, never before its first
// occurrence), so the context it computes is unaffected by the injected
// metacharacters. Only `text_node` and `unquoted_attr` (a start tag with no open
// quote, where a raw `>` breaks the tag) are positive; comment / cdata /
// quoted-attribute / raw-text / rcdata / anything ambiguous fail closed.
function htmlContextAt(html, idx) {
  const limit = Math.min(idx, html.length);
  const startsWith = (needle, at) => html.startsWith(needle, at);
  let state = "text";
  let tagName = "";
  let tagIsClosing = false;
  let i = 0;
  const closeTagState = () => {
    if (!tagIsClosing && RAWTEXT_ELEMENTS.has(tagName)) return "rawtext";
    if (!tagIsClosing && RCDATA_ELEMENTS.has(tagName)) return "rcdata";
    return "text";
  };
  while (i < limit) {
    const c = html[i];
    if (state === "text") {
      if (c === "<") {
        if (startsWith("<!--", i)) { state = "comment"; i += 4; continue; }
        if (startsWith("<![CDATA[", i)) { state = "cdata"; i += 9; continue; }
        const m = /^<(\/?)([a-zA-Z][a-zA-Z0-9:_-]*)/.exec(html.slice(i, i + 64));
        if (m) {
          tagIsClosing = m[1] === "/";
          tagName = m[2].toLowerCase();
          state = "tag";
          i += m[0].length;
          continue;
        }
        // a lone "<" not starting a tag stays in text
      }
      i += 1;
      continue;
    }
    if (state === "comment") {
      if (startsWith("-->", i)) { state = "text"; i += 3; continue; }
      i += 1;
      continue;
    }
    if (state === "cdata") {
      if (startsWith("]]>", i)) { state = "text"; i += 3; continue; }
      i += 1;
      continue;
    }
    if (state === "tag") {
      if (c === ">") { state = closeTagState(); i += 1; continue; }
      if (c === "\"") { state = "attr_double"; i += 1; continue; }
      if (c === "'") { state = "attr_single"; i += 1; continue; }
      i += 1;
      continue;
    }
    if (state === "attr_double") {
      if (c === "\"") { state = "tag"; i += 1; continue; }
      i += 1;
      continue;
    }
    if (state === "attr_single") {
      if (c === "'") { state = "tag"; i += 1; continue; }
      i += 1;
      continue;
    }
    if (state === "rawtext" || state === "rcdata") {
      // Exit ONLY on a REAL matching end tag: </tagName followed by a valid
      // delimiter (whitespace, `/`, `>`, or EOF). A prefix-only match would exit
      // raw-text on `</scripture>` and mis-classify a reflection that is actually
      // still inside the block (a safe context) as an executable text node (codex).
      if (c === "<" && html.slice(i, i + 2 + tagName.length).toLowerCase() === `</${tagName}`) {
        const after = html[i + 2 + tagName.length];
        if (after === undefined || after === ">" || after === "/" || /\s/.test(after)) {
          state = "tag";
          tagIsClosing = true;
          i += 2 + tagName.length;
          continue;
        }
      }
      i += 1;
      continue;
    }
    i += 1;
  }
  switch (state) {
    case "text": return "text_node";
    case "tag": return "unquoted_attr";
    case "attr_double":
    case "attr_single": return "quoted_attr";
    case "comment": return "comment";
    case "cdata": return "cdata";
    case "rawtext": return "rawtext";
    case "rcdata": return "rcdata";
    default: return "unknown";
  }
}

// The bounded metachar-survival witness. The producer sent
// `<nonce><sentinel><endMarker>` as ONE value; in the response body the slice
// strictly BETWEEN the first nonce occurrence and the next end-marker is the
// server's rendering of the sentinel. The witness is the sentinel's RAW ADJACENT
// `<>` surviving inside that bounded slice (the tag-injection primitive): the
// sentinel's angle brackets are adjacent and the server never splits our one
// contiguous value, so requiring the adjacent pair rejects a stray `<`/`>` from page
// markup. An HTML-escaped reflection renders `&lt;&gt;` (no raw `<>`), a
// percent-left-encoded one renders `%3C%3E`, and a stripped one renders neither —
// all fail the witness. Returns { located, survived, between, contextKind } or a reason.
function classifyReflection(body, nonce, endMarker) {
  const startIdx = body.indexOf(nonce);
  if (startIdx === -1) return { located: false };
  const searchFrom = startIdx + nonce.length;
  const endIdx = body.indexOf(endMarker, searchFrom);
  if (endIdx === -1) return { located: true, survived: false, reason: "reflection_boundary_not_found" };
  if (endIdx - searchFrom > MAX_REFLECTION_GAP) {
    // The markers were SPLIT across the page; a `<` between them would be page
    // markup, not our surviving sentinel. Fail closed.
    return { located: true, survived: false, reason: "reflection_boundary_too_far" };
  }
  const between = body.slice(searchFrom, endIdx);
  // The sentinel's angle brackets are ADJACENT ('"<>) and the server never inserts
  // characters into our one contiguous value, so a genuine raw passthrough yields
  // "<>" ADJACENT in `between`. Requiring the adjacent pair (not merely some "<"
  // before some ">") is the precise tag-injection witness: a stray "<" and ">" from
  // page markup landing in the bounded window cannot satisfy it (the residual a loose
  // indexOf check leaves open), and no true positive is lost — an escaped / encoded /
  // stripped sentinel never renders a raw adjacent "<>".
  const survived = between.includes("<>");
  // Context is computed from the markup BEFORE the nonce (pure server bytes).
  const contextKind = htmlContextAt(body, startIdx);
  return { located: true, survived, between, contextKind };
}

// ── the probe runner ─────────────────────────────────────────────────────────

function blocked(outcome, reason, extra = {}) {
  return {
    confirmed: false,
    target_domain: null,
    tool_id: TOOL_ID,
    offensive_outcome: outcome,
    reason,
    row_written: false,
    ...extra,
  };
}

// Run a single probe via the injectable fetch_fn (seeded tests) or safeFetch.
// Audits every probe so the circuit breaker / request budget count the live
// traffic; a swallowed audit-write aborts (the producer signs a durable proof row,
// so it must not fire un-audited live probes).
async function runProbe({
  fetchFn, url, method, headers, domain, surfaceId, egressProfile, blockInternalHosts, agent, startedAt,
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
  if (auditOk === false) {
    const auditErr = new ToolError(ERROR_CODES.STATE_CONFLICT, "probe http-audit write failed");
    auditErr.probe_audit_failed = true;
    throw auditErr;
  }
  if (error) throw error;
  return response;
}

// Resolve the SINGLE in-scope recorded endpoint of the surface that carries a
// query string (the server-derived locus source). Returns { url } or null. NEVER
// derives a locus from agent-supplied data: the candidate endpoints come from the
// surface record (surface.uri + surface.endpoints[]), and the query params come
// from those recorded URLs.
function resolveQueryLocusEndpoint(domain, surface, state) {
  const stateOrigin = originFromState(domain, state, TOOL_ID);
  const allOrigins = resolveSurfaceOrigins(surface, stateOrigin);
  // Bind a RELATIVE endpoint to the surface's OWN host(s) — never the session apex,
  // which resolveSurfaceOrigins lists first. Resolving a subdomain surface's
  // relative endpoint against the apex would sign a row whose target host drifts
  // from surface_id (codex). The apex is used only when the surface declares no
  // host of its own. Collect ALL distinct query-bearing candidates (no break on the
  // first origin) so the single-endpoint guard below refuses host ambiguity instead
  // of silently picking one.
  const ownOrigins = allOrigins.filter((origin) => origin !== stateOrigin);
  const relativeOrigins = ownOrigins.length > 0 ? ownOrigins : [stateOrigin];
  const seen = new Set();
  const matches = [];
  for (const endpoint of candidateSurfaceEndpoints(surface)) {
    const isAbsolute = /^[a-z][a-z0-9+.-]*:\/\//i.test(String(endpoint.value).trim());
    // urlFromEndpoint ignores `origin` for an absolute endpoint (it carries its own
    // host); a relative endpoint binds to the surface's own host(s).
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

// The deterministically sorted, de-duplicated recorded query-param NAMES of the
// endpoint. The ordinal param_locus indexes into this stable list.
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

// The full oracle. `fetch_fn` is injectable so seeded tests need no live target;
// with no fetch_fn the MCP dispatcher drives the LIVE arm via safeFetch.
async function reflectXss(args = {}, { fetch_fn = null } = {}) {
  // The request is server-derived. Reject the base forbidden set PLUS every raw
  // locus-smuggling field — a caller may supply ONLY the ordinal param_locus, never
  // a raw URL, raw param name, raw value, nonce, sentinel, or payload (must-fix #1).
  assertNoForbiddenInputs(args, TOOL_ID, [
    "param", "param_name", "param_value", "value", "locus", "locus_url", "injection",
    "canary", "nonce", "sentinel", "payload",
  ]);

  const startedAt = Date.now();
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  const oracleKind = normalizeOracleKind(args.oracle_kind);
  const method = normalizeMethod(args.method);
  const paramLocus = normalizeParamLocus(args.param_locus);

  const { state } = readSessionStateStrict(domain);
  const internalHostPolicy = blockInternalHostsPolicyFields(state);
  const blockInternalHosts = internalHostPolicy.block_internal_hosts === true;

  const fail = (outcome, reason) => blocked(outcome, reason, {
    target_domain: domain,
    surface_id: surfaceId,
    oracle_kind: oracleKind,
    ...internalHostPolicy,
  });

  // Resolve + route the surface, then derive the injection locus SERVER-SIDE from
  // a recorded query param (never an agent-supplied URL/name).
  const { surface } = findRoutedSurface(domain, surfaceId);
  const locusEndpoints = resolveQueryLocusEndpoint(domain, surface, state);
  if (locusEndpoints.length === 0) {
    // The surface records no in-scope query-bearing endpoint, so there is no
    // server-derived locus. STOP — never invent an agent-supplied URL path.
    return fail("blocked_by_design", "no_recorded_query_param");
  }
  if (locusEndpoints.length > 1) {
    // More than one distinct query-bearing endpoint → row.target would be
    // ambiguous. Refuse rather than guess.
    return fail("blocked_by_design", "ambiguous_query_endpoint");
  }
  const baseUrl = locusEndpoints[0];
  // Read-only + scope guard on the RECORDED endpoint (catches a verb-named path
  // segment and an action-shaped recorded query param like ?action=/?_method=).
  assertReadOnlyPath(baseUrl.toString(), TOOL_ID);

  const paramNames = recordedQueryParamNames(baseUrl);
  if (paramLocus >= paramNames.length) {
    rejectInvalidArguments(
      `param_locus ordinal ${paramLocus} is out of range; the routed surface records ${paramNames.length} query param(s)`,
      { code: "reflect_param_locus_out_of_range", recorded_param_count: paramNames.length },
    );
  }
  const paramName = paramNames[paramLocus];

  // Egress identity (mirrors the confirmer / IDOR producer).
  const requestedEgressProfile = typeof state.egress_profile === "string" && state.egress_profile.trim()
    ? state.egress_profile
    : "default";
  const { profile: egressProfile, identity } = resolveAndAssertSessionEgressIdentity(domain, requestedEgressProfile, {
    source: TOOL_ID,
  });
  if (blockInternalHosts && egressProfile && egressProfile.proxy_url) {
    throw new ToolError(
      ERROR_CODES.SCOPE_BLOCKED,
      "block_internal_hosts cannot be verified with proxy-backed egress for bob_http_xss_reflect",
      { scope_decision: "blocked", egress_profile: identity.egress_profile },
    );
  }
  const egressAgent = createProxyAgent(egressProfile.proxy_url);
  const egressProfileName = identity.egress_profile || requestedEgressProfile;

  // Server-mint the canary tokens + the inert sentinel.
  const nonce = mintToken("bxr");
  const endMarker = mintToken("exr");
  const controlValue = nonce;
  const probeValue = `${nonce}${REFLECTION_SENTINEL}${endMarker}`;

  // Build the CONTROL + PROBE URLs by replacing ONLY the locus param's value;
  // every other recorded param keeps its recorded value.
  const controlUrl = new URL(baseUrl.toString());
  controlUrl.searchParams.set(paramName, controlValue);
  const probeUrl = new URL(baseUrl.toString());
  probeUrl.searchParams.set(paramName, probeValue);

  // Re-validate the FINAL injected URLs (path + query). The confirmer family
  // strips queries on purpose, so the injected query MUST be re-validated, not
  // just the recorded template, and the origin re-asserted (must-fix #1).
  for (const u of [controlUrl, probeUrl]) {
    assertSafeRequestUrl(u.toString(), domain, SCOPE_VALIDATION_OPTS);
    assertReadOnlyPath(u.toString(), TOOL_ID);
    if (u.origin !== baseUrl.origin) {
      rejectInvalidArguments("injected probe URL must resolve under the recorded surface endpoint origin");
    }
  }

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
  const headers = {
    accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "user-agent": "HackerBob-xss-reflect/1",
  };

  let controlResponse;
  let probeResponse;
  try {
    controlResponse = await runProbe({ ...probeBase, url: controlUrl.toString(), headers });
    probeResponse = await runProbe({ ...probeBase, url: probeUrl.toString(), headers });
  } catch (error) {
    if (error && error.probe_audit_failed) {
      return fail("blocked_by_infra", "probe_audit_failed");
    }
    return blocked("blocked_by_infra", "transport_error", {
      target_domain: domain,
      surface_id: surfaceId,
      oracle_kind: oracleKind,
      failure_reason: error.message || String(error),
      ...internalHostPolicy,
    });
  }

  // ── classify (fail-closed, sign nothing on any miss) ──
  // WAF / rate-limit and redirects are not rendered sinks.
  for (const r of [controlResponse, probeResponse]) {
    if (r && (r.status === 429 || r.status === 503)) {
      return fail("blocked_by_defense", "waf_or_rate_limit");
    }
    if (r && [301, 302, 303, 307, 308].includes(r.status)) {
      return fail("blocked_by_defense", "reflection_in_redirect");
    }
  }
  // v1: text/html only (defer MIME-sniff). Both probes must be HTML.
  if (!contentTypeIsHtml(controlResponse) || !contentTypeIsHtml(probeResponse)) {
    return fail("blocked_by_defense", "content_type_not_html");
  }
  // A download (Content-Disposition: attachment) is not rendered, so a reflection
  // there is not an executable sink — fail closed even though it is text/html.
  if (isAttachmentDisposition(controlResponse) || isAttachmentDisposition(probeResponse)) {
    return fail("blocked_by_defense", "content_disposition_attachment");
  }
  // Truncated bodies can hide the reflection boundary past the fetch cap.
  if (controlResponse.bodyTruncated !== false || probeResponse.bodyTruncated !== false) {
    return fail("blocked_by_infra", "body_truncated");
  }

  const controlBody = bodyTextOf(controlResponse);
  const probeBody = bodyTextOf(probeResponse);

  // CONTROL: the param must reflect into a POSITIVE (executable) context with a
  // clean nonce — this locates the sink before any metacharacter could alter the
  // parse.
  const controlIdx = controlBody.indexOf(nonce);
  if (controlIdx === -1) {
    return fail("blocked_by_defense", "nonce_not_reflected");
  }
  const controlContext = htmlContextAt(controlBody, controlIdx);
  if (!POSITIVE_CONTEXTS.has(controlContext)) {
    return fail("blocked_by_defense", "safe_context");
  }

  // PROBE: the raw metacharacters must survive UNESCAPED at the SAME positive
  // context kind.
  const probe = classifyReflection(probeBody, nonce, endMarker);
  if (!probe.located) {
    return fail("blocked_by_defense", "nonce_not_reflected");
  }
  if (!probe.survived) {
    // Sentinel was escaped / encoded / stripped / split — no unescaped breakout.
    return fail("blocked_by_defense", probe.reason || "metachars_escaped");
  }
  if (!POSITIVE_CONTEXTS.has(probe.contextKind)) {
    return fail("blocked_by_defense", "safe_context");
  }
  if (probe.contextKind !== controlContext) {
    // The clean reflection and the metachar reflection disagree on context → the
    // sink is not stable; fail closed rather than mint on an ambiguous parse.
    return fail("blocked_by_infra", "ambiguous_context");
  }

  // ── build the canonical proof (value-blind target, PII-screened) ──
  const canonicalTarget = canonicalizeExploitTarget(probeUrl.toString());
  // canonicalizeExploitTarget keeps origin+path (query stripped). A PII/secret
  // shape in a fixed PATH segment would persist into the durable row target.
  if (sensitiveShapesPresent(canonicalTarget)) {
    return fail("blocked_operator_pii", "proof_target_contains_sensitive_value");
  }

  // The captured fragment is the producer's own nonce + the surviving sentinel
  // rendering ONLY — never the surrounding page body (no PII capture by design).
  const reflectedFragment = `${nonce}${probe.between}`;
  const stdoutContent = canonicalJson({
    param: paramName,
    context: probe.contextKind,
    reflected_fragment: reflectedFragment,
  });
  const stderrContent = canonicalJson({
    control_status: controlResponse.status,
    probe_status: probeResponse.status,
    content_type_html: true,
    param: paramName,
    context: probe.contextKind,
    metachars_survived: true,
  });
  // Defense in depth: even the bounded capture must carry no PII / credential
  // shape. (Structurally impossible for nonce+sentinel, but screened anyway.)
  if (sensitiveShapesPresent(stdoutContent) || sensitiveShapesPresent(stderrContent)) {
    return fail("blocked_operator_pii", "capture_contains_sensitive_value");
  }

  const relationBooleans = {
    control_reflected: true,
    probe_metachars_survived: true,
    context_executable: true,
    content_type_html: true,
  };

  // demonstrated_severity is DERIVED from the per-tool registry inside
  // buildAndSignOffensiveRow (never passed from here). Capture FIRST, recompute
  // hashes from on-disk bytes, sign LAST, hardened append — under the session lock
  // (the run_id single-use guard is only race-safe there).
  const row = withSessionLock(domain, () => buildAndSignOffensiveRow(domain, {
    runIdPrefix: "reflect",
    toolId: TOOL_ID,
    method,
    canonicalTarget,
    surfaceId,
    identityTag: "unauth-reflect",
    stdoutContent,
    stderrContent,
    relationBooleans,
  }));

  // Masked oracle return (sensitive_output:true) — booleans + hashes + run_id,
  // NEVER raw response bytes.
  return {
    confirmed: true,
    target_domain: domain,
    surface_id: surfaceId,
    oracle_kind: oracleKind,
    offensive_outcome: "exploited_safely",
    row_written: true,
    run_id: row.run_id,
    tool_id: row.tool_id,
    target: row.target,
    command_hash: row.command_hash,
    stdout_hash: row.stdout_hash,
    stderr_hash: row.stderr_hash,
    exit_code: row.exit_code,
    demonstrated_severity: row.demonstrated_severity,
    masked_oracle: {
      param: paramName,
      context: probe.contextKind,
      relation: relationBooleans,
      fragment_hash: row.stdout_hash,
    },
    ...identity,
    ...internalHostPolicy,
  };
}

module.exports = {
  TOOL_ID,
  ORACLE_KIND_VALUES,
  READ_ONLY_METHODS,
  REFLECT_DEMONSTRATED_CEILING,
  REFLECTION_SENTINEL,
  reflectXss,
  // Exported for unit tests (seeded, no live target).
  htmlContextAt,
  classifyReflection,
  recordedQueryParamNames,
  // NOTE: buildAndSignOffensiveRow (offensive-capture-writer.js) is intentionally
  // NOT re-exported — it signs+writes a row WITHOUT running the classifier gates
  // above, so re-exporting it would give an internal caller a gate-bypassing
  // signed-row path. Tests drive the full oracle through reflectXss.
};
