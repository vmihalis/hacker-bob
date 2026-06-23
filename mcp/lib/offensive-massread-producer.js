"use strict";

// bob_http_massread_confirm — broken-authorization / BFLA MASS-READ signed-row PRODUCER
// (browser transport, LIVE).
//
// THE ORACLE (attacker-vs-control differential, safe_oracle.kind "differential_response"):
// the producer issues TWO credentialed-channel reads of a routed in-scope listing/search
// endpoint THROUGH THE WAF via the real-Chrome `authed_fetch` transport (PR1 / #155 —
// in-process safeFetch is Cloudflare-blind):
//   1. ATTACKER arm — a browser session carrying the under-authorized identity's cookies
//      (read SERVER-SIDE from a stored auth profile, injected over stdin via set_auth_cookies,
//      never the env, never an agent). Response A.
//   2. CONTROL arm — a fresh UNCREDENTIALED session (no cookies). Response C.
// From each response body it derives a MASKED summary in memory — record_count, the SET of
// known-sensitive field NAMES present (names only, never values), and PII value-shape booleans
// (the values are thrown away) — then DISCARDS the raw body. The POSITIVE is a DIFFERENTIAL:
//   - attacker: 2xx AND record_count >= MASSREAD_MIN_RECORDS AND >= 1 sensitive field shape
//     (bulk PII, not a single self-record), AND
//   - control: 401/403, OR a 2xx with 0 records / no sensitive shapes (the baseline is DENIED).
// i.e. the under-authorized caller reads bulk PII the control cannot — an authorization failure,
// not a merely-public endpoint. A control that ALSO reads the bulk data is a public endpoint, not
// a privilege break → fail closed (blocked_by_design).
//
// SEVERITY: HARD HIGH by construction, stamped from OFFENSIVE_TOOL_DEMONSTRATED_CEILING inside
// buildAndSignOffensiveRow (NEVER from here, NEVER agent-supplied). The producer proves the
// IMPACT (bulk read of sensitive records by an under-authorized caller); the underlying vuln
// (e.g. a hardcoded/guessable credential, missing object/function-level authz) is the finding.
//
// DUAL OUTPUT (operator decision):
//   1. SIGNED proof row (offensive-runs.jsonl) — ALWAYS masked: the hashed+signed capture carries
//      ONLY record_count + sensitive_field_names + pii_shape_present booleans + the differential
//      statuses. Screened by sensitiveShapesPresent; a sensitive VALUE shape in the capture fails
//      the run closed (blocked_operator_pii). Non-negotiable: the signed rail NEVER carries raw PII
//      (it is the tamper-evident rail re-used by third-party bug-bounty runs where harvesting
//      strangers' data is forbidden).
//   2. FULL raw capture (sessionDir/massread-evidence/<run_id>.json) — OPT-IN, OPERATOR-gated by the
//      env var BOB_MASSREAD_OWNER_AUTHORIZED=1 (NOT an agent argument — the agent can NEVER enable
//      PII capture, so the same tool stays safe on third-party targets). Written OUTSIDE the signed
//      rail; the operator deletes it at the end of the engagement. Keep this folder out of any
//      sync/backup path.
//
// INTEGRITY BOUNDARY (honest, NOT closed here): the row MAC is tamper-evident against an agent
// confined to the MCP + guarded-Bash surface; it is NOT cryptographically un-forgeable (a same-UID
// actor can read the 0600 key and hand-MAC a row — the #131 boundary, bounded to a fabricated HIGH
// by the frozen per-tool ceiling). The authed-vs-control differential is ALSO not tamper-proof — a
// hostile target can tell the credentialed arm from the control and could serve forged data — but a
// target forging a vuln against ITSELF gains nothing, and a single capture is evidence, not proof
// (the operator corroborates for integrity-sensitive use). The page-controlled-fetch residual is
// inherent to the transport (see #155 / the plan), mitigated by waitUntil:"commit" + the differential.
//
// V1 SCOPE (deliberate, documented):
//   - GET listing/search endpoints. The authed_fetch transport supports POST+body, but resolving a
//     recorded POST body value-blind (without leaking PII into the signed target) is the documented
//     v2 follow-up — even though the motivating finding was a POST listing.
//   - COOKIE-expressible under-authorized identity (set_auth_cookies is cookie-only; authed_fetch
//     REJECTS Authorization/Cookie headers). A profile whose ONLY credential is a bearer token has no
//     usable cookie → blocked_by_design (bearer support is v2).

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
  resolveAndAssertSessionEgressIdentity,
} = require("./session-state.js");
const {
  assertNonEmptyString,
} = require("./validation.js");
const {
  findRoutedSurface,
  resolveSurfaceEndpoint,
  assertReadOnlyPath,
  auditConfirmRequest,
  assertNoForbiddenInputs,
  sensitiveShapesPresent,
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
  browserSessions,
  callBrowser,
  parseProxyUrlForPlaywright,
} = require("./browser-tools-shared.js");
const {
  resolveAuthProfile,
} = require("./auth.js");
const {
  detectPiiShapes,
} = require("./pii-detector.js");
const {
  sessionDir,
  sessionsRoot,
  assertSafeDomain,
} = require("./paths.js");

const TOOL_ID = "bob_http_massread_confirm";
// v1: GET listing/search. POST-body listing is the documented v2 (the transport supports POST).
const HTTP_METHOD = "GET";
// Bulk = strictly more than one record; a single self-record is the authorized baseline, not a
// mass-read. Conservative floor; the report grades the leak by what actually leaked.
const MASSREAD_MIN_RECORDS = 2;
// Soft per-fetch page budget; the driver's COMMAND_TIMEOUT_MS is the hard ceiling.
const FETCH_TIMEOUT_MS = 20_000;
const DEFAULT_AUTH_PROFILE = "attacker";
// WAF / rate-limit statuses on the ATTACKER arm: the credentialed read did not actually run, so
// we cannot prove the read — fail closed rather than read a block page as "0 records".
const WAF_STATUSES = Object.freeze(new Set([429, 503]));
// Operator-only full-capture gate. NOT an agent argument by design.
const OWNER_AUTHORIZED_ENV = "BOB_MASSREAD_OWNER_AUTHORIZED";

// HARD HIGH by construction. Frozen + "use strict" → an in-process actor's `MAP.x = "critical"`
// THROWS. demonstrated_severity is stamped from the registry in buildAndSignOffensiveRow, NEVER
// here and NEVER agent-supplied; this frozen map documents the intent + anchors a test.
const MASSREAD_DEMONSTRATED_CEILING = Object.freeze({ bob_http_massread_confirm: "high" });

// Known-sensitive field NAMES (object keys) — used to label WHICH sensitive columns the collection
// exposes. Names only; values are never stored. Lowercased compare; substring so `user_email`,
// `billing_phone`, `id_card_number` match.
const SENSITIVE_FIELD_NAME_FRAGMENTS = Object.freeze([
  "email", "phone", "mobile", "msisdn", "iban", "bic", "swift", "account_number", "accountnumber",
  "ssn", "sin", "nino", "national_id", "passport", "tax_id", "vat_number", "dob", "date_of_birth",
  "birthdate", "credit_card", "card_number", "cardnumber", "pan", "cvv", "address", "postcode",
  "zipcode", "zip_code", "id_number", "license", "license_number", "drivers_license",
]);

// Canonical sensitive field-name BUCKETS reported (a stable, low-cardinality set so the signed
// summary never echoes a target-specific column name verbatim — only which class is present).
const SENSITIVE_FIELD_BUCKETS = Object.freeze([
  { bucket: "email", fragments: ["email", "e_mail", "mail"] },
  { bucket: "phone", fragments: ["phone", "mobile", "msisdn"] },
  { bucket: "financial", fragments: ["iban", "bic", "swift", "account_number", "accountnumber", "credit_card", "card_number", "cardnumber", "pan", "cvv"] },
  { bucket: "government_id", fragments: ["ssn", "sin", "nino", "national_id", "passport", "tax_id", "vat_number", "id_number", "license", "drivers_license"] },
  { bucket: "date_of_birth", fragments: ["dob", "date_of_birth", "birthdate"] },
  { bucket: "postal_address", fragments: ["address", "postcode", "zipcode", "zip_code", "street"] },
]);

// PII VALUE detection — the repo's battle-tested detectPiiShapes (email / phone / SSN / Luhn-valid
// credit-card) UNION an IBAN shape it does not cover. Run ONLY over a counted record's own VALUES
// (deriveMaskedSummary), so the mint gate binds the PII signal to the records it counts; only the
// shape BOOLEAN is kept, the value is discarded. Wider than the former email/phone/iban vocabulary
// (which silently dropped SSN / credit-card mass-reads) and no longer a whole-body scan (which let
// unrelated response metadata — a support/copyright email — forge the signal).
const PII_TYPE_TO_SHAPE = Object.freeze({
  email: "email", phone: "phone_intl", ssn: "ssn", credit_card: "credit_card",
});
// Cap the per-record value scan so a huge collection cannot blow the regex budget; record_count
// still counts every object record, but PII presence only needs ONE qualifying record.
const MASSREAD_PII_SCAN_RECORDS = 1000;
function emptyPiiShapes() {
  return { email: false, phone_intl: false, iban: false, ssn: false, credit_card: false };
}

// SUBJECT-IDENTIFIER shapes: the PII shapes that are (near-)UNIQUE per data subject within a single
// field, so distinct normalized values are a sound proxy for distinct SUBJECTS. Phone and postal
// address are deliberately EXCLUDED from the subject count (a single subject legitimately has several
// numbers/addresses, and phone country-code/format aliases over-count — bot-review #183/#313/#419);
// they are still LABELED in sensitive_field_names so the leak's columns are recorded, they just don't
// drive the >= MIN-distinct-subjects floor. This is a deliberate PRECISION-first v1 choice: a leak
// bearing ONLY phone/address (no email/SSN/card/IBAN) is recorded but does not mint a HIGH on its own.
// Priority order for choosing a record's ONE dominant identifier (most-unique first). Keying each
// record by its single highest-priority identifier — not the full set — means two records that SHARE
// that identifier are ONE subject even if one row carries an extra identifier (bot-review #432).
const SUBJECT_IDENTIFIER_PRIORITY = Object.freeze(["email", "ssn", "credit_card", "iban"]);
const SUBJECT_IDENTIFIER_SHAPES = Object.freeze(new Set(SUBJECT_IDENTIFIER_PRIORITY));

// A sensitive field's VALUE as text for shape-matching: a scalar verbatim, else compact JSON (so a
// nested { street, city } address or a list of values is still scanned). Empty for null/undefined.
function piiValueText(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try { return JSON.stringify(value); } catch { return ""; }
}

// Canonicalize a matched PII VALUE so case/format variants of ONE subject collapse to ONE key —
// otherwise `Alice@X.com` vs `alice@x.com`, or `(555) 123-4567` vs `555-123-4567`, would count as two
// distinct subjects (bot-review #394). Email lowercased; phone/ssn/card digits-only; IBAN
// upper+space-stripped; anything else lower+whitespace-collapsed.
function normalizePiiValue(shape, value) {
  const v = String(value);
  switch (shape) {
    case "email": return v.trim().toLowerCase();
    case "phone_intl": case "ssn": case "credit_card": return v.replace(/\D/g, "");
    case "iban": return v.toUpperCase().replace(/\s+/g, "");
    default: return v.trim().toLowerCase().replace(/\s+/g, " ");
  }
}

// IBAN detection — the repo's detectPiiShapes does NOT cover IBAN, so this producer adds it. Detect by
// DECODING percent-encoding, scanning case-INSENSITIVELY, and validating the mod-97 CHECKSUM — so a real
// IBAN is caught regardless of case/encoding (bot-review #650, e.g. `gb82west…` or `%47%42…`) WITHOUT
// false-positiving on arbitrary hex-ish id/path segments (a bare shape regex would, and since the target
// screen is fail-CLOSED, a false match would spuriously block a legit run). Returns canonical (decoded,
// uppercased, space-stripped) IBANs.
function ibanChecksumValid(iban) {
  if (iban.length < 5 || iban.length > 34) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    if (ch >= "A" && ch <= "Z") remainder = (remainder * 100 + (ch.charCodeAt(0) - 55)) % 97; // A=10..Z=35
    else if (ch >= "0" && ch <= "9") remainder = (remainder * 10 + (ch.charCodeAt(0) - 48)) % 97;
    else return false;
  }
  return remainder === 1;
}
function findIbans(text) {
  let decoded = String(text);
  try { decoded = decodeURIComponent(decoded); } catch { /* malformed % — scan the raw text */ }
  const out = [];
  const re = /\b[A-Za-z]{2}\d{2}[A-Za-z0-9]{10,30}\b/g;
  let m;
  while ((m = re.exec(decoded)) !== null) {
    const cand = m[0].toUpperCase();
    if (ibanChecksumValid(cand)) out.push(cand);
  }
  return out;
}

// PII value MATCHES in one field's value: the repo detectPiiShapes matches (mapped to our shape keys)
// UNION the IBAN shape it does not cover, each as { shape, norm } where `norm` is the CANONICAL value.
// Returns the EXTRACTED, NORMALIZED PII token(s) — NOT the whole serialized field value — so a
// structured field like `{ value: "a@x.com", label: "billing" }` contributes only `a@x.com`, and a
// varying non-PII sibling (`label`, a timestamp) can never inflate the distinct-subject count
// (bot-review #394 P1). The values are used ONLY for in-memory de-dup keys, then discarded.
function piiMatchesInValue(valueText) {
  const out = [];
  for (const m of detectPiiShapes(valueText)) {
    const shape = PII_TYPE_TO_SHAPE[m.type];
    if (shape && m.value != null) out.push({ shape, norm: normalizePiiValue(shape, m.value) });
  }
  for (const ib of findIbans(valueText)) out.push({ shape: "iban", norm: ib }); // already canonical
  return out;
}

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

function ownerAuthorized() {
  return process.env[OWNER_AUTHORIZED_ENV] === "1";
}

// A stored auth profile flattens cookies into a single "Cookie" HEADER string
// (auth.js#buildHeaderProfile); parse it back into the {name, value, url} cookie objects the
// set_auth_cookies transport requires. `url` binds each cookie to the exact endpoint origin (the
// driver scope-validates it against target_domain). A bearer-only profile has Authorization but no
// Cookie → returns [] (not cookie-expressible; bearer support is v2).
function cookieObjectsFromProfile(profile, urlForCookie) {
  // PREFER the STRUCTURED jar. auth.js#buildHeaderProfile now persists the original {name: value}
  // cookie map as `profile.cookie_jar` (a Bob-local metadata key, never emitted as a header). Using
  // it verbatim means a cookie VALUE that contains a `;` stays ONE cookie and can NEVER be re-split
  // into a FORGED extra cookie — the exact identity-mutation the flat-header re-parse below cannot
  // prevent (`sid=abc; role=admin` is indistinguishable from a legit two-cookie header once
  // flattened). So a forged elevated cookie can never silently widen the tested identity → no false
  // mint from a privilege the stored profile never had.
  if (profile && profile.cookie_jar && typeof profile.cookie_jar === "object"
      && !Array.isArray(profile.cookie_jar)) {
    const out = [];
    for (const [rawName, rawValue] of Object.entries(profile.cookie_jar)) {
      const name = String(rawName).trim();
      if (!name) continue;
      out.push({ name, value: String(rawValue), url: urlForCookie });
    }
    return out;
  }
  // LEGACY fallback: a profile stored before cookie_jar existed only has the flattened "Cookie"
  // header. Re-parse best-effort (the `eq <= 0` guard drops a name-less part → fail-closed to a
  // DROPPED cookie, which only weakens the attacker arm). Fresh per-engagement profiles always carry
  // cookie_jar, so this path is reached only for stale stored profiles.
  const header = typeof profile.Cookie === "string" ? profile.Cookie
    : (typeof profile.cookie === "string" ? profile.cookie : "");
  if (!header.trim()) return [];
  const out = [];
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    if (!name) continue;
    out.push({ name, value: part.slice(eq + 1).trim(), url: urlForCookie });
  }
  return out;
}

// The LIVE browser driver. massreadConfirm accepts an injectable `driver` so seeded tests need no
// Chromium; with no driver the dispatcher binds this one. callBrowser(command, sessionId, args)
// reorders to sendCommand(sessionId, command, args). Each returns the driver's RAW result and
// REJECTS with an Error (.code) on driver error.
const liveBrowserDriver = Object.freeze({
  isAvailable: () => browserSessions.isPatchrightAvailable(),
  start: (opts) => browserSessions.startSession(opts),
  authedFetch: (sessionId, fetchArgs) => callBrowser("authed_fetch", sessionId, fetchArgs),
  close: (sessionId, reason) => browserSessions.closeSession(sessionId, reason),
});

// Find the records array in a parsed listing response: a top-level array, or the largest array
// one level deep under a common collection key. Returns the OBJECT elements only — an array of
// scalars (strings/ids/facets) is NOT a record collection, so it can never inflate record_count or
// host the PII value the mint gate binds to those records. Returns [] when none qualifies.
const COLLECTION_KEYS = Object.freeze([
  "data", "results", "items", "records", "rows", "list", "hits", "docs", "entries", "content", "elements",
]);
function isPlainObject(x) {
  return !!x && typeof x === "object" && !Array.isArray(x);
}
// An array qualifies as a record collection iff a MAJORITY of its elements are plain objects (tolerate
// a few null/scalar holes). `{ data: ["a","b"] }` (strings) and `{ tags: [1,2,3] }` (ids) do NOT
// qualify; `{ results: [{...},{...}] }` does. The caller filters to the object elements for counting.
function recordObjects(arr) {
  if (!Array.isArray(arr) || arr.length === 0) return null;
  const objs = arr.filter(isPlainObject);
  if (objs.length >= 1 && objs.length * 2 >= arr.length) return objs;
  return null;
}
function extractRecords(parsed) {
  const top = recordObjects(parsed);
  if (top) return top;
  if (!isPlainObject(parsed)) return [];
  let best = [];
  for (const key of COLLECTION_KEYS) {
    const value = parsed[key];
    const objs = recordObjects(value);
    if (objs && objs.length > best.length) best = objs;
    // one more level: { data: { items: [...] } }
    if (isPlainObject(value)) {
      for (const inner of COLLECTION_KEYS) {
        const innerObjs = recordObjects(value[inner]);
        if (innerObjs && innerObjs.length > best.length) best = innerObjs;
      }
    }
  }
  return best;
}

// Tokenize a field key on camelCase + non-alphanumeric separators → lowercased tokens. So
// `emailVerified` / `email_verified` / `billing-email` all yield an `email` token, while
// `themailbox` does NOT (a bare-substring match would falsely fire on it).
function fieldTokens(rawName) {
  return String(rawName)
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[^A-Za-z0-9]+/g, " ")
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
}

// A fragment matches the field name iff its own tokens appear as a CONTIGUOUS subsequence of the
// field's tokens (word-boundary, not bare substring). Multi-word fragments (`date_of_birth`) and
// single tokens (`email`, `dob`) both work. NOTE: this is the WITNESS label only — the MINT gate
// additionally requires a real PII VALUE shape (pii_shape_present), so a field merely NAMED
// `email_verified` (a boolean) never lifts a row on its own.
function fragmentMatchesTokens(fragment, tokens) {
  const frag = fieldTokens(fragment);
  if (frag.length === 0) return false;
  for (let i = 0; i + frag.length <= tokens.length; i += 1) {
    let ok = true;
    for (let j = 0; j < frag.length; j += 1) { if (tokens[i + j] !== frag[j]) { ok = false; break; } }
    if (ok) return true;
  }
  return false;
}

function bucketForFieldName(rawName) {
  const tokens = fieldTokens(rawName);
  if (tokens.length === 0) return null;
  for (const { bucket, fragments } of SENSITIVE_FIELD_BUCKETS) {
    if (fragments.some((f) => fragmentMatchesTokens(f, tokens))) return bucket;
  }
  if (SENSITIVE_FIELD_NAME_FRAGMENTS.some((f) => fragmentMatchesTokens(f, tokens))) return "other_sensitive";
  return null;
}

// Derive the MASKED summary from a raw body, then the caller DISCARDS the raw body. On non-JSON or
// no recognizable collection, record_count is 0 (fail-closed: an ambiguous body cannot prove a
// mass-read). Returns booleans/counts/field-name BUCKETS only — never any value.
function deriveMaskedSummary(bodyText) {
  const summary = {
    record_count: 0,
    pii_bearing_count: 0,
    distinct_pii_count: 0,
    sensitive_field_names: [],
    pii_shape_present: emptyPiiShapes(),
    parse_ok: false,
  };
  if (typeof bodyText !== "string" || bodyText.length === 0) return summary;
  let parsed;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    return summary; // non-JSON (HTML block page, etc.) → not a countable collection
  }
  summary.parse_ok = true;
  const records = extractRecords(parsed); // plain-object records only (scalars excluded)
  summary.record_count = records.length;
  const buckets = new Set();
  const pii = summary.pii_shape_present;
  // A PII VALUE counts ONLY when it sits in a field whose NAME maps to a sensitive bucket — an email
  // VALUE in an `email`-named field, never a free-text `note` and never a boolean `email_verified`.
  // distinct_pii_count is the count of distinct SUBJECT KEYS across records. A record's subject key is
  // its single HIGHEST-PRIORITY normalized SUBJECT-IDENTIFIER value(s) (email > SSN > card > IBAN — the
  // shapes ~unique per subject); a record with no such identifier has no key and is not counted. This is
  // a robust lower bound on distinct subjects and converges the prior whack-a-mole rounds, because:
  //   • ONE record contributes at most ONE key, however many PII tokens it carries — so a field listing
  //     two values for one subject (`email: "a@x alt@x"`) is one key, not two (bot-review #419);
  //   • keying on the DOMINANT identifier (not the full set) means two rows that share it are ONE subject
  //     even if one row carries an extra identifier the other lacks (`{email}` vs `{email,ssn}`, #432);
  //   • same-bucket multi-field (`email` + `recovery_email`) and a promoted nested self-collection
  //     collapse to one key (#393/#313);
  //   • values are NORMALIZED + shape-extracted, so case/format variants and a structured field's
  //     varying non-PII siblings never split one subject into two (#394);
  //   • phone / postal address are EXCLUDED from the key (a subject has several), killing phone-format
  //     and address-multiplicity over-counts (#183) — they remain LABELED in sensitive_field_names.
  // So a self-record, constant boilerplate, and one subject's many PII fields ALL yield ONE key; only
  // >= MIN genuinely-distinct subjects clear the floor.
  const subjectKeys = new Set();
  let piiBearingRecords = 0;
  const scanLimit = Math.min(records.length, MASSREAD_PII_SCAN_RECORDS);
  for (let i = 0; i < scanLimit; i += 1) {
    const record = records[i];
    let recordHasSensitivePii = false;
    const idByShape = new Map(); // this record's normalized identifier values, grouped by shape
    for (const key of Object.keys(record)) {
      const bucket = bucketForFieldName(key);
      if (!bucket) continue;
      const valueText = piiValueText(record[key]);
      if (!valueText) continue;
      const matches = piiMatchesInValue(valueText); // [{ shape, norm }] — extracted + normalized
      if (matches.length === 0) continue;
      buckets.add(bucket);
      recordHasSensitivePii = true;
      for (const m of matches) {
        pii[m.shape] = true;
        if (!SUBJECT_IDENTIFIER_SHAPES.has(m.shape)) continue;
        let set = idByShape.get(m.shape);
        if (!set) { set = new Set(); idByShape.set(m.shape, set); }
        set.add(m.norm);
      }
    }
    if (recordHasSensitivePii) piiBearingRecords += 1;
    // ONE subject key per record: its HIGHEST-PRIORITY identifier shape's value(s). A single dominant
    // identifier (not the full set) means two rows sharing it are ONE subject even if one carries an
    // extra identifier (#432); a record with no subject identifier contributes no key.
    for (const shape of SUBJECT_IDENTIFIER_PRIORITY) {
      const set = idByShape.get(shape);
      if (set && set.size > 0) { subjectKeys.add(`${shape}:${Array.from(set).sort().join(",")}`); break; }
    }
  }
  summary.sensitive_field_names = Array.from(buckets).sort();
  summary.pii_bearing_count = piiBearingRecords;
  // distinct_pii_count := number of distinct SUBJECT KEYS (records with a distinct identifier set).
  summary.distinct_pii_count = subjectKeys.size;
  return summary;
}

// Run one credentialed-or-control arm: start a (pinned) session, authed_fetch the endpoint, audit,
// close. Returns { status, body, final_url, body_truncated } or throws (scope/driver error). The
// session targetUrl is the exact endpoint host so authed_fetch's required launch DNS-pin covers it.
async function runArm(drv, {
  domain, surfaceId, endpointUrl, authCookies, blockInternalHosts, egressProfileName, playwrightProxy, armTag,
}) {
  const startedAt = Date.now();
  let sessionId = null;
  let result;
  let error;
  let scopeBlocked = false;
  try {
    const started = await drv.start({
      targetDomain: domain,
      targetUrl: endpointUrl,
      headless: true,
      proxy: playwrightProxy,
      authCookies: authCookies || undefined,
    });
    sessionId = started && started.session_id ? started.session_id : null;
    if (!sessionId) {
      const e = new Error(`browser_session_start_failed (${armTag})`);
      e.code = "browser_session_start_failed";
      throw e;
    }
    result = await drv.authedFetch(sessionId, {
      url: endpointUrl,
      method: HTTP_METHOD,
      block_internal_hosts: blockInternalHosts,
      timeout_ms: FETCH_TIMEOUT_MS,
    });
  } catch (e) {
    error = e;
    if (e && (e.scope_decision === "blocked" || e.code === "scope_blocked")) scopeBlocked = true;
  } finally {
    if (sessionId) {
      try { await drv.close(sessionId, `massread-${armTag}-done`); } catch { /* best-effort */ }
    }
  }
  // Coerce to null any status outside the valid HTTP range [100,599] — notably authed_fetch's
  // status 0 for a manual-redirect / opaqueredirect (an unauthenticated redirect-to-login control).
  // The http-audit normalizer rejects out-of-range statuses, so passing 0 through would throw
  // probe_audit_failed and CRASH the run instead of letting the control fall to control_inconclusive
  // (fail-closed). (bot-review #448.)
  const status = result && Number.isInteger(result.status) && result.status >= 100 && result.status <= 599
    ? result.status : null;
  const auditOk = auditConfirmRequest({
    domain,
    surfaceId,
    method: HTTP_METHOD,
    url: endpointUrl,
    egressProfile: egressProfileName,
    status,
    scopeDecision: scopeBlocked ? "blocked" : null,
    // Never write a raw driver error (it can embed the URL/credential context) into the
    // agent-readable audit; a fixed redacted token is enough for telemetry.
    error: error ? `massread ${armTag} arm error (redacted)` : null,
    startedAt,
    toolId: TOOL_ID,
  });
  if (auditOk === false) {
    const auditErr = new ToolError(ERROR_CODES.STATE_CONFLICT, `${armTag} arm http-audit write failed`);
    auditErr.probe_audit_failed = true;
    if (error) auditErr.cause = error;
    throw auditErr;
  }
  if (error) throw error;
  // A driver that resolves null/undefined (no throw) must not be dereferenced into a crash; treat
  // it as a transport error the caller converts to a fail-closed negative.
  if (!result || typeof result !== "object") {
    const e = new Error(`authed_fetch returned no result (${armTag})`);
    e.code = "browser_transport_error";
    throw e;
  }
  if (result.__timeout === true) {
    const e = new Error(`authed_fetch timeout (${armTag})`);
    e.code = "authed_fetch_timeout";
    throw e;
  }
  return {
    status,
    body: typeof result.body === "string" ? result.body : "",
    final_url: typeof result.final_url === "string" ? result.final_url : null,
    body_truncated: result.body_truncated === true,
    parse_ok: typeof result.body === "string" && result.body.length > 0,
  };
}

// Persist the FULL raw capture OUTSIDE the signed rail, ONLY under the operator env gate. The folder
// is co-located with the session (not the repo); the operator deletes it after the engagement.
// ADAPTER LIMITATION (honest): the agent-read block on massread-evidence/ is enforced by the
// session-read-guard PreToolUse hook, which ships in the Claude + Kimi adapters but NOT the Codex
// adapter (Codex has no hook layer — a pre-existing gap for every session artifact, not just this
// one). So under a Codex install the raw capture's only control is the operator env gate itself
// (BOB_MASSREAD_OWNER_AUTHORIZED, which the agent cannot set and which operators enable ONLY for
// client-owned data they are already authorized to hold) plus prompt deletion. The PRIMARY guarantee
// — the signed rail never carries raw PII — holds on every adapter regardless.
function writeFullCapture(domain, runId, payload) {
  // SAME symlink discipline as the signed offensive-runs rail (offensive-capture-writer.js
  // resolveCaptureDirSecure): this is the raw-PII artifact, so a symlinked session dir / evidence dir
  // / leaf must never redirect it. ANCHOR to the real sessions root + safe domain — realpath(sessionDir)
  // ALONE would silently FOLLOW a symlinked session dir and plant the capture at the link target.
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  const realRoot = fs.realpathSync(sessionsRoot());
  const expectedParent = path.join(realRoot, assertSafeDomain(domain)); // the only trusted session dir
  const nominalParent = sessionDir(domain);
  // Create + verify the SESSION dir BEFORE creating massread-evidence/ under it: a recursive mkdir
  // would otherwise follow a symlinked session dir. Reject any mismatch against the expected parent.
  fs.mkdirSync(nominalParent, { recursive: true });
  if (fs.realpathSync(nominalParent) !== expectedParent) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `massread-evidence session dir must stay inside its session root without symlinks: ${nominalParent}`);
  }
  const nominalDir = path.join(expectedParent, "massread-evidence");
  // Refuse a pre-existing symlinked evidence dir BEFORE a recursive mkdir would follow it.
  try {
    if (fs.lstatSync(nominalDir).isSymbolicLink()) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `massread-evidence dir must not be a symlink: ${nominalDir}`);
    }
  } catch (e) { if (e && e.code !== "ENOENT") throw e; }
  fs.mkdirSync(nominalDir, { recursive: true, mode: 0o700 });
  // Post-mkdir: PIN the evidence dir by an O_NOFOLLOW directory fd, then assert its inode == the
  // realpath-resolved expected dir. O_DIRECTORY|O_NOFOLLOW FAILS CLOSED (ELOOP) if `massread-evidence`
  // was swapped to a symlink AFTER the lstat above — the TOCTOU window a plain realpath re-check leaves
  // open (realpath FOLLOWS the link and silently passes). fstat dev+ino binds the fd to the trusted
  // inode (a swap to a different real dir mismatches). PORTABLE-NODE RESIDUAL (honest): there is no
  // openat(2) in core fs, so the leaf is still opened by pathname below; the sub-microsecond window in
  // which a SAME-UID actor re-swaps the parent between this pin and the leaf open is the conceded #131
  // boundary (a same-UID actor already reads the 0600 signing key) and additionally requires the
  // operator gate BOB_MASSREAD_OWNER_AUTHORIZED enabled — so the residual is bounded, not open.
  const dirFd = fs.openSync(nominalDir, (fs.constants.O_DIRECTORY || 0) | noFollow);
  try {
    const dirStat = fs.fstatSync(dirFd);
    const trustedStat = fs.statSync(fs.realpathSync(path.join(expectedParent, "massread-evidence")));
    if (!dirStat.isDirectory() || dirStat.dev !== trustedStat.dev || dirStat.ino !== trustedStat.ino) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `massread-evidence dir failed the inode pin (symlink swap?): ${nominalDir}`);
    }
  } finally {
    fs.closeSync(dirFd);
  }
  const file = path.join(nominalDir, `${String(runId).replace(/[^a-zA-Z0-9_-]/g, "_")}.json`);
  try {
    if (fs.lstatSync(file).isSymbolicLink()) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `massread-evidence capture must not be a symlink: ${file}`);
    }
  } catch (e) { if (e && e.code !== "ENOENT") throw e; }
  // Exclusive create + O_NOFOLLOW: a fresh per-run path, never following/truncating a planted symlink.
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | noFollow, 0o600);
  try {
    fs.writeFileSync(fd, `${JSON.stringify(payload, null, 2)}\n`);
  } finally {
    fs.closeSync(fd);
  }
  return file;
}

// The full oracle. `driver` is injectable so seeded tests need no live browser; with no driver the
// dispatcher drives the LIVE arm via Patchright + the authed_fetch transport.
async function massreadConfirm(args = {}, { driver = null } = {}) {
  // Server-derived request. The caller may supply ONLY target_domain + surface_id + the auth_profile
  // NAME selector — never a raw URL, endpoint, cookie/token/credential, header, body, record, or
  // severity. owner_authorized is NOT accepted from the caller (operator env gate only).
  assertNoForbiddenInputs(args, TOOL_ID, [
    "endpoint", "cookie", "cookies", "token", "credential", "credentials",
    "record", "records", "owner_authorized", "auth_cookies", "set_auth_cookies",
  ]);

  const drv = driver || liveBrowserDriver;
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  const authProfileName = typeof args.auth_profile === "string" && args.auth_profile.trim()
    ? args.auth_profile.trim()
    : DEFAULT_AUTH_PROFILE;

  const { state } = readSessionStateStrict(domain);
  const internalHostPolicy = blockInternalHostsPolicyFields(state);
  const blockInternalHosts = internalHostPolicy.block_internal_hosts === true;

  const fail = (outcome, reason) => blocked(outcome, reason, {
    target_domain: domain,
    surface_id: surfaceId,
    auth_profile: authProfileName,
    ...internalHostPolicy,
  });

  // The browser transport navigates with the producer's block_internal_hosts policy but, like
  // bob_http_xss_confirm, the producer refuses to confirm through a channel that cannot fully
  // enforce the session SSRF policy. Fail closed when block_internal_hosts is on.
  if (blockInternalHosts) {
    return fail("blocked_by_design", "block_internal_hosts_unsupported_for_browser");
  }

  // Resolve + route the surface, derive the listing endpoint SERVER-SIDE (never an agent URL).
  const { surface } = findRoutedSurface(domain, surfaceId);
  const endpointUrlObj = resolveSurfaceEndpoint({ domain, surface, state, toolName: TOOL_ID });
  const endpointUrl = endpointUrlObj.toString();
  // v1 fetches the RESOLVED endpoint as-is (resolveSurfaceEndpoint strips the query). The fetched URL
  // and the signed canonicalTarget are therefore the SAME origin+path — the signed row faithfully
  // identifies what was read, with no query-variant divergence. Query-routed search surfaces (e.g.
  // a required `?q=*`) are deferred to v2 (resurrecting a recorded query made the fetched URL diverge
  // from the signed target and was ambiguous across same-path candidates — bot-review #553/#498).
  const fetchUrlObj = new URL(endpointUrl);
  // Read-only + scope guard on the fetch URL; catches a verb-named segment.
  assertReadOnlyPath(fetchUrlObj.toString(), TOOL_ID);
  // Value-blind durable target (origin+path, query stripped); a PII/secret shape in a fixed path
  // segment would persist into the signed row target.
  const canonicalTarget = canonicalizeExploitTarget(endpointUrl);
  // sensitiveShapesPresent covers detectPiiShapes (email/phone/ssn/card) but NOT the IBAN shape this
  // producer adds, so screen IBAN explicitly — an IBAN in a fixed path segment (e.g.
  // /accounts/GB82WEST.../transactions) would otherwise persist into the signed/audited target (#643).
  if (sensitiveShapesPresent(canonicalTarget) || findIbans(canonicalTarget).length > 0) {
    return fail("blocked_operator_pii", "proof_target_contains_sensitive_value");
  }

  // Egress identity (mirrors the reflect / xss producers); convert proxy_url into Patchright form.
  const requestedEgressProfile = typeof state.egress_profile === "string" && state.egress_profile.trim()
    ? state.egress_profile
    : "default";
  const { profile: egressProfile, identity } = resolveAndAssertSessionEgressIdentity(domain, requestedEgressProfile, {
    source: TOOL_ID,
  });
  let playwrightProxy = null;
  if (egressProfile && egressProfile.proxy_url) {
    try {
      playwrightProxy = parseProxyUrlForPlaywright(egressProfile.proxy_url);
    } catch {
      return fail("blocked_by_infra", "egress_unsupported_for_browser");
    }
  }
  const egressProfileName = identity.egress_profile || requestedEgressProfile;

  // The ATTACKER (under-authorized) identity's COOKIES, read SERVER-SIDE from the stored profile —
  // never agent-supplied. Bearer-only profiles have no usable cookie for the transport (v2).
  const profile = resolveAuthProfile(authProfileName, endpointUrl, domain);
  if (!profile) {
    return fail("blocked_by_design", "attacker_auth_profile_not_found");
  }
  const endpointOrigin = endpointUrlObj.origin;
  const authCookies = cookieObjectsFromProfile(profile, endpointOrigin);
  if (authCookies.length === 0) {
    return fail("blocked_by_design", "attacker_credential_not_cookie_expressible");
  }

  if (!drv.isAvailable()) {
    return fail("blocked_by_infra", "browser_unavailable");
  }

  // Distinct cache-buster per arm: a shared cache keyed on URL (ignoring the cookie) could otherwise
  // serve the attacker's cached bulk body to the control arm (or vice versa) and forge the differential.
  // A unique `_cb` per arm forces a distinct cache key, and the arm order is recorded in the bundle.
  const armUrl = () => {
    const u = new URL(fetchUrlObj.toString());
    u.searchParams.set("_cb", crypto.randomBytes(8).toString("hex"));
    return u.toString();
  };
  const attackerUrl = armUrl();
  const controlUrl = armUrl();
  const armOrder = ["attacker", "control"];

  const armBase = {
    domain, surfaceId, blockInternalHosts, egressProfileName, playwrightProxy,
  };

  let attacker;
  let control;
  try {
    attacker = await runArm(drv, { ...armBase, endpointUrl: attackerUrl, authCookies, armTag: "attacker" });
    control = await runArm(drv, { ...armBase, endpointUrl: controlUrl, authCookies: null, armTag: "control" });
  } catch (e) {
    if (e && e.probe_audit_failed) throw e; // audit-write failure must surface, not be swallowed
    if (e && (e.scope_decision === "blocked" || e.code === "scope_blocked")) {
      return fail("blocked_by_defense", "scope_blocked");
    }
    if (e && e.code === "authed_fetch_timeout") {
      return fail("blocked_by_infra", "authed_fetch_timeout");
    }
    if (e && (e.code === "browser_session_start_failed")) {
      return fail("blocked_by_infra", "browser_session_start_failed");
    }
    return fail("blocked_by_infra", "browser_transport_error");
  }

  // WAF / rate-limit on EITHER arm: the read never actually ran (a block page is not "0 records"), so
  // the differential cannot be scored. Fail closed — a throttled CONTROL must NOT count as "denied".
  if (attacker.status != null && WAF_STATUSES.has(attacker.status)) {
    return fail("blocked_by_defense", "waf_or_rate_limit");
  }
  if (control.status != null && WAF_STATUSES.has(control.status)) {
    return fail("blocked_by_defense", "control_waf_or_rate_limit");
  }
  // A truncated body mis-scores: a truncated CONTROL parses to fewer/0 records → false "denied" → a
  // false HIGH; a truncated ATTACKER → false negative. Either truncated → unreliable, fail closed.
  if (attacker.body_truncated || control.body_truncated) {
    return fail("blocked_by_infra", "response_truncated_unreliable");
  }

  // Derive masked summaries, then DISCARD raw bodies (full capture, if any, happens after the mint).
  const attackerSummary = deriveMaskedSummary(attacker.body);
  const controlSummary = deriveMaskedSummary(control.body);

  const attackerOk2xx = attacker.status != null && attacker.status >= 200 && attacker.status < 300;
  // A 2xx attacker body that does not parse to a countable collection cannot prove a mass-read.
  if (attackerOk2xx && !attackerSummary.parse_ok) {
    return fail("blocked_by_defense", "attacker_body_not_a_countable_collection");
  }
  // MINT GATE: >= MIN DISTINCT subjects' PII. deriveMaskedSummary counts a PII VALUE only when it sits
  // in a sensitively-NAMED field of a counted record, and distinct_pii_count is the number of distinct
  // SUBJECT KEYS — one key per record, built from its normalized subject-identifier values (email / SSN
  // / card / IBAN) — so a benign list + a stray metadata email, a field merely NAMED like PII
  // (`email_verified: true`), constant boilerplate, a single self-record, one subject's many PII fields
  // (incl. same-bucket email+recovery_email or a field listing two of its own values), case/format
  // variants, and a promoted self-collection ALL yield ONE key and fall below the floor. NECESSARY,
  // not sufficient: this proves the credentialed arm read >= MIN distinct identifier-bearing subjects an
  // unauthenticated arm cannot — the evaluator + grader (which see endpoint semantics + the credential's
  // provenance) certify the BFLA / under-privilege class; see the design notes at the head of the file.
  // Require BOTH >= MIN records that carry sensitive PII AND >= MIN distinct subject keys.
  const attackerBulk = attackerOk2xx
    && attackerSummary.pii_bearing_count >= MASSREAD_MIN_RECORDS
    && attackerSummary.distinct_pii_count >= MASSREAD_MIN_RECORDS;
  if (!attackerBulk) {
    return fail("blocked_by_defense", "attacker_did_not_read_bulk_pii");
  }

  // ── score the control arm ──
  // (a) The control READ the bulk collection if its body parses to >= MIN records — REGARDLESS of HTTP
  //     status. A 401/403 (or any status) that STILL returns the bulk JSON body was NOT actually denied
  //     (the client can read that body) → a PUBLIC / control-visible collection, not an authz break.
  //     (bot-review #669/#677 — a body that read the records is never "denied", whatever the status.)
  const controlReadBulk = controlSummary.parse_ok
    && controlSummary.record_count >= MASSREAD_MIN_RECORDS;
  if (controlReadBulk) {
    return fail("blocked_by_design", "control_also_reads_bulk_not_a_privilege_break");
  }
  // (a2) The control surfaced SOME subject PII (>= 1 distinct subject key), but below the bulk floor.
  //      That is NOT a clean denial — the unauthenticated client read a real subject's PII, so the
  //      "anon is denied PII" premise fails (a public teaser / partial-public endpoint, not a clean
  //      authz differential). Fall through to inconclusive rather than mint (bot-review #784).
  const controlReadAnySubjectPii = controlSummary.distinct_pii_count > 0;
  // (b) A CLEAN unauthenticated denial reads NO subject PII AND is an explicit 401, OR a 2xx that did NOT
  //     return the bulk collection — a PARSED body with FEWER than MIN records, OR an EMPTY 2xx (204 No
  //     Content / empty 200: the unauth client got NO records at all, bot-review #706). A 403 is AMBIGUOUS
  //     — a WAF / bot-challenge vs a real authz denial — so it is NEVER scored "denied" (parseability is
  //     not an auth-denial oracle, bot-review #675); likewise an unparseable NON-empty 2xx (HTML app shell
  //     / WAF interstitial) stays ambiguous. All fall through to control_inconclusive.
  const control2xx = control.status != null && control.status >= 200 && control.status < 300;
  const controlBodyEmpty = typeof control.body !== "string" || control.body.trim().length === 0;
  const controlOk2xx = control2xx && controlSummary.parse_ok;
  const controlDenied = !controlReadAnySubjectPii && (
    control.status === 401
    || (control2xx && controlBodyEmpty)
    || (controlOk2xx && controlSummary.record_count < MASSREAD_MIN_RECORDS)
  );
  if (!controlDenied) {
    // Ambiguous control (403, 5xx, 404, unparseable, timeout, OR a control that itself read subject PII):
    // cannot conclude the control was DENIED, so the differential is unproven. Fail closed rather than
    // mint a HIGH off an inconclusive baseline.
    return fail("blocked_by_infra", "control_inconclusive");
  }

  // ── build the canonical proof (MASKED, value-blind, PII-screened) ──
  const maskedSummary = {
    record_count: attackerSummary.record_count,
    pii_bearing_count: attackerSummary.pii_bearing_count,
    distinct_pii_count: attackerSummary.distinct_pii_count,
    sensitive_field_names: attackerSummary.sensitive_field_names,
    pii_shape_present: attackerSummary.pii_shape_present,
  };
  const stdoutContent = canonicalJson(maskedSummary);
  const stderrContent = canonicalJson({
    attacker_status: attacker.status,
    control_status: control.status,
    attacker_record_count: attackerSummary.record_count,
    attacker_pii_bearing_count: attackerSummary.pii_bearing_count,
    attacker_distinct_pii_count: attackerSummary.distinct_pii_count,
    control_record_count: controlSummary.record_count,
    arm_order: armOrder,
    credentialed_bulk_pii_read: true,
    unauthenticated_control_denied: true,
    pii_value_shapes_present: true,
  });
  // Fail-closed PII screen: the masked summary is field-NAME buckets + counts + booleans, so a value
  // shape here means something leaked; refuse to sign it.
  if (sensitiveShapesPresent(stdoutContent) || sensitiveShapesPresent(stderrContent)
    || findIbans(stdoutContent).length > 0 || findIbans(stderrContent).length > 0) {
    return fail("blocked_operator_pii", "capture_contains_sensitive_value");
  }

  // HONEST about what the authed-vs-UNAUTHENTICATED differential actually proves: "credential X
  // bulk-reads PII an unauthenticated client is denied". It does NOT prove X is UNDER-privileged — a
  // FULLY-AUTHORIZED user reading authorized data would also satisfy this. The operator contract (tool
  // description + evaluator prose) is that `auth_profile` carries the LEAKED / UNDER-PRIVILEGED /
  // guessable credential; using a fully-authorized credential is operator misuse → false positive. True
  // cross-tenant BFLA (a second AUTHENTICATED victim identity denied while the attacker reads ITS data)
  // is the v2 oracle. So the signed booleans assert ONLY what is established — never a bare
  // `bfla_proven` / `under_privileged`.
  const relationBooleans = {
    credentialed_bulk_pii_read: true,
    unauthenticated_control_denied: true,
    pii_value_shapes_present: true,
  };

  // demonstrated_severity DERIVED from the per-tool registry inside buildAndSignOffensiveRow (never
  // passed). Capture FIRST, recompute hashes from on-disk bytes, sign LAST — under the session lock.
  const row = withSessionLock(domain, () => buildAndSignOffensiveRow(domain, {
    runIdPrefix: "massread",
    toolId: TOOL_ID,
    method: HTTP_METHOD,
    canonicalTarget,
    surfaceId,
    identityTag: `massread-${authProfileName}`,
    stdoutContent,
    stderrContent,
    relationBooleans,
  }));

  // OPT-IN full capture — OPERATOR env gate only, OUTSIDE the signed rail. The raw bodies live in
  // memory only until here; for the default (masked-only) path they are never persisted.
  let ownerCaptureWritten = false;
  if (ownerAuthorized()) {
    try {
      writeFullCapture(domain, row.run_id, {
        tool_id: TOOL_ID,
        run_id: row.run_id,
        target: row.target,
        attacker_status: attacker.status,
        control_status: control.status,
        attacker_body: attacker.body,
        control_body: control.body,
        note: "operator-authorized full capture (BOB_MASSREAD_OWNER_AUTHORIZED). NOT in the signed rail. Delete after the engagement; keep out of any sync/backup path.",
      });
      ownerCaptureWritten = true;
    } catch {
      ownerCaptureWritten = false; // the signed (masked) row stands regardless of the opt-in capture
    }
  }

  // Masked oracle return — counts + field-name buckets + booleans + hashes, NEVER raw bytes.
  return {
    confirmed: true,
    target_domain: domain,
    surface_id: surfaceId,
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
    owner_authorized_capture: ownerCaptureWritten,
    masked_oracle: {
      relation: relationBooleans,
      record_count: maskedSummary.record_count,
      pii_bearing_count: maskedSummary.pii_bearing_count,
      distinct_pii_count: maskedSummary.distinct_pii_count,
      sensitive_field_names: maskedSummary.sensitive_field_names,
      pii_shape_present: maskedSummary.pii_shape_present,
      fragment_hash: row.stdout_hash,
    },
    ...internalHostPolicy,
  };
}

module.exports = {
  massreadConfirm,
  deriveMaskedSummary,
  extractRecords,
  bucketForFieldName,
  cookieObjectsFromProfile,
  MASSREAD_MIN_RECORDS,
  OWNER_AUTHORIZED_ENV,
  TOOL_ID,
  MASSREAD_DEMONSTRATED_CEILING,
};
