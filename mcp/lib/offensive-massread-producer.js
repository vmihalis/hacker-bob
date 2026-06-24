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
// SEVERITY: stamped from OFFENSIVE_TOOL_DEMONSTRATED_CEILING (registry "high" = the CEILING) inside
// buildAndSignOffensiveRow (NEVER agent-supplied), but the per-RUN value is decided HERE and passed as
// an ALWAYS-explicit demonstratedSeverityOverride (never undefined — that would fail OPEN to the high
// ceiling). Two tiers:
//   - MEDIUM (v1, the default): the attacker-vs-ANON differential proves a credentialed caller bulk-reads
//     PII an unauthenticated client is denied — a real exposure — but NOT that the credential is
//     under-privileged (a fully-authorized user reading authorized data also satisfies it) nor that the
//     surface is a cross-subject collection. Honestly a MEDIUM.
//   - HIGH (v2, the victim arm): a SECOND AUTHENTICATED VICTIM identity reads its OWN private scope (an
//     endpoint a fresh anon client is DENIED), the attacker's bulk read CONTAINS one of those exact
//     subject identifiers (overlap >= 1), and the two identities are distinct (distinct profile + cookie
//     jar). That is a categorical cross-PRINCIPAL break — the attacker read a subject that is provably in
//     a distinct authenticated principal's private scope — so the run stamps demonstrated_severity:"high".
// The override can only LOWER the ceiling (offensive-capture-writer.js), so a v1 run is MEDIUM on disk and
// the claim-vs-row cap bounds any claim citing it at MEDIUM; the registry "high" only PERMITS a proven
// victim-arm row to demonstrate high. The underlying vuln (hardcoded/guessable credential, missing
// object/function-level authz) is the finding; the evaluator + grader certify the class from endpoint +
// credential context, under the operator contract that attacker and victim are DIFFERENT principals.
//
// DUAL OUTPUT (operator decision):
//   1. SIGNED proof row (offensive-runs.jsonl) — ALWAYS masked: the hashed+signed capture carries
//      ONLY record_count + sensitive_field_names + pii_shape_present booleans + the differential
//      statuses. Screened by sensitiveShapesPresent; a sensitive VALUE shape in the capture fails
//      the run closed (blocked_operator_pii). Non-negotiable: the signed rail NEVER carries raw PII
//      (it is the tamper-evident rail re-used by third-party bug-bounty runs where harvesting
//      strangers' data is forbidden).
//   2. FULL raw capture (sessionDir/massread-evidence/<run_id>.json) — OPT-IN, OPERATOR-gated by the
//      env var BOB_MASSREAD_OWNER_AUTHORIZED=<target_domain> — BOUND to the authorized target (a CSV of
//      domains is allowed; a bare "1" is rejected so one engagement's authorization can't leak onto
//      another's data, #904). NOT an agent argument — the agent can NEVER enable PII capture, so the
//      same tool stays safe on third-party targets. Written OUTSIDE the signed rail; the operator
//      deletes it at the end of the engagement. Keep this folder out of any
//      sync/backup path.
//
// INTEGRITY BOUNDARY (honest, NOT closed here): the row MAC is tamper-evident against an agent
// confined to the MCP + guarded-Bash surface; it is NOT cryptographically un-forgeable (a same-UID
// actor can read the 0600 key and hand-MAC a row — the #131 boundary). With the v2 ceiling now HIGH the
// same-UID forge residual is bounded to a fabricated HIGH (raised from MEDIUM); closing it needs the
// deferred offensive-sandbox. The authed-vs-control differential is ALSO not tamper-proof — a
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
  normalizeEmailForComparison,
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
// v2 victim arm: the SECOND authenticated identity that reads its OWN private scope. Naming the
// victim's own-scope surface (victim_surface_id) opts a run into the HIGH cross-principal oracle;
// the victim profile name defaults to this when only the surface is given.
const DEFAULT_VICTIM_AUTH_PROFILE = "victim";
// WAF / rate-limit statuses on the ATTACKER arm: the credentialed read did not actually run, so
// we cannot prove the read — fail closed rather than read a block page as "0 records".
const WAF_STATUSES = Object.freeze(new Set([429, 503]));
// Operator-only full-capture gate. NOT an agent argument by design.
const OWNER_AUTHORIZED_ENV = "BOB_MASSREAD_OWNER_AUTHORIZED";

// The CEILING (max a row may demonstrate) is HIGH — but the per-run value is MEDIUM unless the v2
// victim arm proves a cross-principal break (see the SEVERITY note in the header). Frozen + "use strict"
// → an in-process actor's `MAP.x = "critical"` THROWS. This frozen map documents the ceiling + anchors a
// test that cross-checks it against the authoritative claims.js OFFENSIVE_TOOL_DEMONSTRATED_CEILING so the
// two sources can never drift; demonstrated_severity is stamped from that registry in
// buildAndSignOffensiveRow (NEVER here, NEVER agent-supplied).
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
// Bound the per-record tree walk so a deeply/widely nested record cannot blow the regex/CPU budget:
// recurse at most this deep, and scan at most this many fields per record (bot-review #512).
const MASSREAD_MAX_RECORD_DEPTH = 8;
const MASSREAD_MAX_NODES_PER_RECORD = 512;
function emptyPiiShapes() {
  return { email: false, phone_intl: false, iban: false, ssn: false, credit_card: false };
}

// SUBJECT-IDENTIFIER shapes: the PII shapes that are ~1:1 with a data subject, so distinct normalized
// values are a sound proxy for distinct SUBJECTS. ONLY email + SSN qualify. Phone, postal address,
// credit card, AND IBAN are deliberately EXCLUDED from the subject count: a single subject legitimately
// has SEVERAL of each (multiple cards / bank accounts / numbers / addresses), so two distinct card or
// IBAN values cannot distinguish "two subjects" from "one subject's two instruments" — a
// `/me/payment-methods`-style self-service list of one person's two cards would otherwise produce two
// components, clear the >= MIN-distinct floor, and false-mint (bot-review #183/#313/#419 + the
// credit_card/IBAN multiplicity review: cards/IBANs share the exact multiplicity property already used
// to exclude phone/address). They are still LABELED in sensitive_field_names and set their
// pii_shape_present boolean (the leak's columns + value shapes are recorded), they just don't FORM or
// merge subject keys. PRECISION-first v1 choice: a leak bearing ONLY card/IBAN/phone/address (no
// email/SSN) is recorded but does not mint on its own — under-counting, the SAFE direction (a genuine
// cross-subject financial leak almost always also carries a per-row email/SSN, which does drive the floor).
const SUBJECT_IDENTIFIER_SHAPES = Object.freeze(new Set(["email", "ssn"]));

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
    // Use the repo's Gmail-aware canonicalizer so dot/plus aliases of one mailbox
    // (`alice.smith+orders@gmail.com` == `alicesmith@gmail.com`) collapse to one subject under union-find
    // instead of inflating the count (bot-review #203). Falls back to trim+lowercase for non-strings.
    case "email": return normalizeEmailForComparison(v) || v.trim().toLowerCase();
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
  // Decode to a FIXED POINT (bounded): a double-encoded IBAN (`%2520` → `%20` → ` `) needs more than one
  // pass before the separators are real characters the strip below can remove (bot-review #224).
  let decoded = String(text);
  for (let pass = 0; pass < 5; pass += 1) {
    let next;
    try { next = decodeURIComponent(decoded); } catch { break; /* malformed % — scan what we have */ }
    if (next === decoded) break;
    decoded = next;
  }
  // Strip the conventional IBAN separators (spaces / hyphens) so a FORMATTED IBAN — e.g. a path with
  // `GB82%20WEST%201234%20…` that decodes to `GB82 WEST 1234 …` — becomes contiguous and matches; the
  // mod-97 checksum still guards against fusing unrelated tokens into a false positive (bot-review #230).
  // Path/query structure (`/`, `?`, `&`, `=`) is preserved, so distinct segments stay distinct.
  const compact = decoded.replace(/[\s-]/g, "");
  const out = [];
  const re = /\b[A-Za-z]{2}\d{2}[A-Za-z0-9]{10,30}\b/g;
  let m;
  while ((m = re.exec(compact)) !== null) {
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

// Operator env gate, BOUND TO TARGET (bot-review #904): the env value is the authorized domain — or a
// comma-separated list of domains — and raw capture happens ONLY when it names THIS target_domain
// (exact, case-insensitive). A bare legacy "1" is REJECTED: it would authorize raw-PII capture for EVERY
// target the same MCP server evaluates, leaking one engagement's authorization onto another's data.
function ownerAuthorized(domain) {
  const raw = process.env[OWNER_AUTHORIZED_ENV];
  if (typeof raw !== "string" || !raw.trim()) return false;
  const target = String(domain || "").trim().toLowerCase();
  if (!target) return false;
  return raw.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean).includes(target);
}

// Is raw capture permitted on THIS adapter? The PreToolUse hook that blocks an agent's own file tools
// from reading massread-evidence/ ships in the Claude (.claude/hooks/) and Kimi (.kimi/hooks/) adapters;
// Codex + generic-mcp have NO hook layer (bot-review #916). The opt-in raw capture is readable by the
// evaluator agent unless that guard actually FIRES, so raw capture is DEFAULT-DENIED and requires the
// operator to EXPLICITLY assert an enforced read-guard via BOB_READ_GUARD (1/true/yes/on). We DELIBERATELY
// do NOT auto-detect by looking for the hook FILE on disk: the framework package SHIPS that file
// unconditionally, so its mere presence (a Codex install whose tree still contains it, or a mixed / partial
// / hand-merged install where the file exists but is never REGISTERED as a PreToolUse matcher) does not
// prove the guard fires — a materially weaker proxy than an enforced hook (bot-review #916 round-2, Codex
// P1 + Claude). Operators set BOB_READ_GUARD=1 ONLY on an adapter that enforces the read-guard
// (Claude/Kimi); never on Codex/generic. Fails CLOSED: unset/empty/any-other-value → no capture (the
// signed masked row is unaffected). HONEST (like #131): even with the guard, raw capture is not safe
// against a same-UID agent running arbitrary code — that residual needs the deferred offensive-sandbox.
function readGuardActive() {
  const v = process.env.BOB_READ_GUARD;
  return typeof v === "string" && /^(1|true|yes|on)$/i.test(v.trim());
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
  // distinct_pii_count is the number of distinct SUBJECTS, computed by UNION-FIND over normalized
  // subject-identifier values (email / SSN — the shapes ~1:1 per subject): two records
  // that share ANY identifier value are the SAME subject. This is the principled definition and ends the
  // prior whack-a-mole, because every same-subject inflation reduces to "records sharing an identifier":
  //   • a field listing two values for one subject (`email: "a@x alt@x"`) unions both → one subject (#419);
  //   • two rows that share an identifier but one carries an extra one (`{email}` vs `{email,ssn}`, or
  //     `{email:"a"}` vs `{email:"a alt"}`) union on the shared value → one subject (#432/#473);
  //   • same-bucket multi-field (`email`+`recovery_email`) and a promoted nested self-collection union
  //     on the repeated value → one subject (#393/#313); constant boilerplate unions all rows → one;
  //   • values are NORMALIZED + shape-extracted, so case/format variants and a structured field's
  //     varying non-PII siblings never split one subject (#394);
  //   • phone / postal address / credit card / IBAN are EXCLUDED as identifiers (a subject has several
  //     of each — two card/IBAN values can't tell two subjects from one subject's two instruments) —
  //     still LABELED in sensitive_field_names + pii_shape_present, they just don't form/merge subjects (#183).
  // HONEST about the residual (bot-review #500): WITHIN a record, multiple identifiers union to one
  // subject; ACROSS records, two rows sharing no value are counted as TWO subjects. That is correct for a
  // normal cross-subject collection (one row per person), but an OVER-count for a per-row SELF-collection
  // of one subject's multiple identifiers (e.g. /me/linked-emails returning primary + recovery + work
  // emails as separate rows). The oracle is schema-blind: from the response alone it cannot tell "N
  // subjects" from "one subject's N instruments" for ANY value-based identifier — which is exactly why
  // this differential is NECESSARY, not sufficient. That residual is bounded by the MEDIUM ceiling + the
  // operator under-privilege contract + the human grader (which know the route's collection-vs-self
  // semantics), NOT by this counter. SSN is truly 1:1; email is the de-facto collection key (removing it
  // would gut the oracle), so both stay — card/IBAN/phone/address were dropped above because per-instrument
  // multiplicity is their COMMON case (a payment-methods list), not a rare one. Only >= MIN distinct
  // components clear the floor; the most common same-subject inflations (shared/repeated values) still
  // merge to one.
  const parent = new Map();
  const findRoot = (x) => { let r = x; while (parent.get(r) !== r) r = parent.get(r); let c = x; while (parent.get(c) !== r) { const n = parent.get(c); parent.set(c, r); c = n; } return r; };
  const ensure = (x) => { if (!parent.has(x)) parent.set(x, x); };
  const union = (a, b) => { ensure(a); ensure(b); const ra = findRoot(a); const rb = findRoot(b); if (ra !== rb) parent.set(ra, rb); };
  let piiBearingRecords = 0;
  const scanLimit = Math.min(records.length, MASSREAD_PII_SCAN_RECORDS);
  for (let i = 0; i < scanLimit; i += 1) {
    const record = records[i];
    let recordHasSensitivePii = false;
    const identifierValues = []; // this record's shape-prefixed normalized subject-identifier values
    // Walk the record tree (bounded): a PII VALUE counts when its FIELD NAME maps to a sensitive bucket at
    // ANY nesting depth — { user: { email } }, { customer: { contact: { ssn } } } — so ordinary nested API
    // record shapes are not missed (bot-review #512). The masked-rail invariant holds: only the bucket
    // label + shape boolean + a normalized de-dup key are kept, never the raw value. Re-finding the same
    // normalized value (a sensitive key whose object value is both serialized-scanned here AND recursed
    // into) is idempotent under the union-find / value sets, so it never inflates the count.
    let nodeBudget = MASSREAD_MAX_NODES_PER_RECORD;
    const visit = (node, depth) => {
      if (node == null || typeof node !== "object" || depth > MASSREAD_MAX_RECORD_DEPTH) return;
      if (Array.isArray(node)) {
        for (const item of node) { if (nodeBudget <= 0) return; visit(item, depth + 1); }
        return;
      }
      for (const key of Object.keys(node)) {
        if (nodeBudget <= 0) return;
        nodeBudget -= 1;
        const value = node[key];
        const bucket = bucketForFieldName(key);
        if (bucket) {
          const valueText = piiValueText(value);
          const matches = valueText ? piiMatchesInValue(valueText) : []; // [{ shape, norm }] extracted + normalized
          if (matches.length > 0) {
            buckets.add(bucket);
            recordHasSensitivePii = true;
            for (const m of matches) {
              pii[m.shape] = true;
              if (SUBJECT_IDENTIFIER_SHAPES.has(m.shape)) identifierValues.push(`${m.shape}:${m.norm}`);
            }
          }
        }
        // Recurse into nested objects/arrays to reach sensitively-NAMED keys deeper in the record.
        if (value && typeof value === "object") visit(value, depth + 1);
      }
    };
    visit(record, 0);
    if (recordHasSensitivePii) piiBearingRecords += 1;
    // Union all of this record's identifier values — they belong to ONE subject. Two records that share
    // any value thereby join the same component (= the same subject).
    if (identifierValues.length > 0) {
      ensure(identifierValues[0]);
      for (let k = 1; k < identifierValues.length; k += 1) union(identifierValues[0], identifierValues[k]);
    }
  }
  summary.sensitive_field_names = Array.from(buckets).sort();
  summary.pii_bearing_count = piiBearingRecords;
  // distinct_pii_count := number of distinct subject components (union-find roots over identifier values).
  const roots = new Set();
  for (const value of parent.keys()) roots.add(findRoot(value));
  summary.distinct_pii_count = roots.size;
  return summary;
}

// Does a CONTROL body expose any field-bound PII? Used only for the control-denial gate. Unlike
// deriveMaskedSummary's record counting, this ALSO treats a top-level singleton OBJECT as a record, so a
// non-array control response — `200 {"email":"teaser@x"}` or a 401 error object `{"error":..,"phone":..}`
// — counts as the anon client having read a subject's PII and is therefore NOT a clean denial (bot-review
// #821/#836). Field-bound (a sensitively-NAMED field with a real PII value shape), so a support email in a
// denial page's free-text does not trip it.
function controlBodyExposesPii(bodyText) {
  if (typeof bodyText !== "string" || bodyText.length === 0) return false;
  let parsed;
  try { parsed = JSON.parse(bodyText); } catch { return false; }
  const records = extractRecords(parsed);
  const scan = records.length > 0 ? records : (isPlainObject(parsed) ? [parsed] : []);
  for (const record of scan) {
    for (const key of Object.keys(record)) {
      if (!bucketForFieldName(key)) continue;
      const valueText = piiValueText(record[key]);
      if (valueText && piiMatchesInValue(valueText).length > 0) return true;
    }
  }
  return false;
}

// Distinct PII VALUES (ANY shape — email / SSN / phone / credit-card / IBAN) anywhere in a RAW text blob
// (NOT field-bound, NOT JSON). Used ONLY to reject a control "denial" that nonetheless shipped BULK PII in
// a body deriveMaskedSummary / controlBodyExposesPii cannot parse — a CSV / plaintext / HTML export at a
// 401 or empty-looking 2xx (bot-review #837/#581). It counts ALL PII shapes, NOT just subject identifiers:
// a control dump of bulk PHONE / CARD / IBAN values (no email/SSN) is still raw PII the anon client
// received, so it must force inconclusive even though those shapes are not subject KEYS (bot-review #581).
// Threshold is >= MIN (not >= 1) on purpose: a flat scan can't bind a value to a record, so a lone
// support/contact value in a real denial page (1 < MIN) does NOT trip it (preserves the round-10
// field-bound free-text robustness); structured single-subject PII is still caught field-bound by
// controlBodyExposesPii at >= 1. De-dup by normalized (shape,value) so a repeated value doesn't inflate.
// Conservative: more matches here only push the control toward inconclusive → no mint (the safe direction).
function distinctPiiValuesInText(text) {
  if (typeof text !== "string" || text.length === 0) return 0;
  const vals = new Set();
  for (const m of piiMatchesInValue(text)) vals.add(`${m.shape}:${m.norm}`);
  return vals.size;
}

// IN-MEMORY ONLY: the SET of normalized SUBJECT-identifier keys (`${shape}:${norm}`, email / SSN — the
// same shapes that form the distinct-subject count) a body exposes in sensitively-NAMED fields. Used
// ONLY for the v2 cross-principal OVERLAP (intersect the attacker's bulk read with the victim's own-scope
// read), then DISCARDED — never persisted, never in the signed row (only the overlap COUNT + a boolean
// survive). Same bounded tree-walk + field-name gate + subject-shape filter as deriveMaskedSummary, so
// the overlap is over the exact same identifier notion as the count. Treats a top-level singleton OBJECT
// as a record too (a victim's `/me` is one object, not a collection), like controlBodyExposesPii.
function subjectIdentifierSet(bodyText) {
  const out = new Set();
  if (typeof bodyText !== "string" || bodyText.length === 0) return out;
  let parsed;
  try { parsed = JSON.parse(bodyText); } catch { return out; }
  // Scan the ENTIRE body (top-level fields + nested objects + every collection element), NOT an
  // extractRecords-selected subset: a /me's OWN top-level identifier must be seen even when the body ALSO
  // embeds a recognized child collection (`{email, items:[...]}` — extractRecords would pick `items` and miss
  // the top-level email, bot-review #N), and a wrapper / object-map's nested subjects must all be counted
  // (#M / CodeRabbit). Used in the victim arm for the own-identity + anon-leak MEMBERSHIP tests only (does this
  // body contain victimKey); the single-subject COUNT and the attacker OVERLAP each use their own walk below.
  let nodeBudget = MASSREAD_MAX_NODES_PER_RECORD * MASSREAD_PII_SCAN_RECORDS; // whole-body, bounded
  const visit = (node, depth) => {
    if (node == null || typeof node !== "object" || depth > MASSREAD_MAX_RECORD_DEPTH || nodeBudget <= 0) return;
    if (Array.isArray(node)) {
      for (const item of node) { if (nodeBudget <= 0) return; visit(item, depth + 1); }
      return;
    }
    for (const key of Object.keys(node)) {
      if (nodeBudget <= 0) return;
      nodeBudget -= 1;
      const value = node[key];
      if (bucketForFieldName(key)) {
        const valueText = piiValueText(value);
        for (const m of (valueText ? piiMatchesInValue(valueText) : [])) {
          if (SUBJECT_IDENTIFIER_SHAPES.has(m.shape)) out.add(`${m.shape}:${m.norm}`);
        }
      }
      if (value && typeof value === "object") visit(value, depth + 1);
    }
  };
  visit(parsed, 0);
  return out;
}

// The field PROPERTY-KEY names under which victimKey appears in the victim's OWN /me — the victim's subject
// field(s). The /me is the victim reading ITSELF, so whatever key holds victimKey there IS the subject-identity
// key for this principal (`email`, or a nested `…email`). Used to bind the attacker overlap to the SAME kind of
// field, so a bulk row's RELATIONAL metadata under a DIFFERENT property key (`viewer_email`, `manager_email`,
// `requested_by_email`) cannot pose as the victim's record (Codex P1 711). Returns the bare leaf KEY names.
function victimSubjectLeafNames(victimBodyText, victimKey) {
  const out = new Set();
  if (typeof victimBodyText !== "string" || victimBodyText.length === 0) return out;
  let parsed;
  try { parsed = JSON.parse(victimBodyText); } catch { return out; }
  let nodeBudget = MASSREAD_MAX_NODES_PER_RECORD * MASSREAD_PII_SCAN_RECORDS;
  const visit = (node, depth) => {
    if (node == null || typeof node !== "object" || depth > MASSREAD_MAX_RECORD_DEPTH || nodeBudget <= 0) return;
    if (Array.isArray(node)) { for (const item of node) { if (nodeBudget <= 0) return; visit(item, depth + 1); } return; }
    for (const key of Object.keys(node)) {
      if (nodeBudget <= 0) return;
      nodeBudget -= 1;
      const value = node[key];
      if (bucketForFieldName(key)) {
        for (const m of piiMatchesInValue(piiValueText(value))) {
          if (SUBJECT_IDENTIFIER_SHAPES.has(m.shape) && `${m.shape}:${m.norm}` === victimKey) out.add(key);
        }
      }
      if (value && typeof value === "object") visit(value, depth + 1);
    }
  };
  visit(parsed, 0);
  return out;
}

// Did the attacker read the victim AS A RECORD'S OWN SUBJECT (the v2 OVERLAP)? Record-bound is not enough — it
// must be SUBJECT-bound (Codex P1 / CodeRabbit): a bulk row's sensitively-named fields include the row's own
// identity (`email`) AND relational METADATA naming OTHER principals (`viewer_email` = who is viewing,
// `requested_by_email` = who requested). Two independent guards bind to the row's OWN subject WITHOUT a
// field-name denylist:
//   (1) CROSS-RECORD VARIANCE, per FULL PATH — a path whose values VARY (>= 2 distinct) across records is a
//       SUBJECT field (it identifies each row's principal); a CONSTANT path is shared metadata stamped on every
//       row. Keying by full path (not bare leaf) keeps a nested metadata path `viewer.email` separate from the
//       row subject `email` (Codex P1 702).
//   (2) FIELD-CONSISTENCY with the victim's OWN /me — the matching path's leaf KEY must be one under which the
//       victim's own /me carried victimKey (victimSubjectLeafNames). So a metadata field under a DIFFERENT key
//       (`manager_email`, `referred_by_email`) that merely VARIES per row cannot pose as the subject (Codex P1
//       711), while the victim's genuine subject field (`email`, possibly nested differently in the listing
//       than in /me) still matches on its leaf key.
// The victim overlaps iff victimKey is a value of a VARYING path whose leaf key ∈ the victim's /me subject keys.
// The base gate already requires >= MIN DISTINCT subjects (the subject field necessarily varies), so a genuine
// victim-subject is caught; empty/non-collection body or unknown victim subject field → fail closed (no overlap).
function attackerReadVictimSubject(victimBodyText, attackerBodyText, victimKey) {
  const subjectLeaves = victimSubjectLeafNames(victimBodyText, victimKey);
  if (subjectLeaves.size === 0) return false; // victim's own subject field unknown → cannot bind → fail closed
  if (typeof attackerBodyText !== "string" || attackerBodyText.length === 0) return false;
  let parsed;
  try { parsed = JSON.parse(attackerBodyText); } catch { return false; }
  const records = extractRecords(parsed);
  let nodeBudget = MASSREAD_MAX_NODES_PER_RECORD * MASSREAD_PII_SCAN_RECORDS;
  const scanLimit = Math.min(records.length, MASSREAD_PII_SCAN_RECORDS);
  const byPath = new Map(); // full path → { leaf, values: Set of `${shape}:${norm}` across records }
  const visit = (node, depth, path) => {
    if (node == null || typeof node !== "object" || depth > MASSREAD_MAX_RECORD_DEPTH || nodeBudget <= 0) return;
    if (Array.isArray(node)) { for (const item of node) { if (nodeBudget <= 0) return; visit(item, depth + 1, path); } return; }
    for (const key of Object.keys(node)) {
      if (nodeBudget <= 0) return;
      nodeBudget -= 1;
      const value = node[key];
      const childPath = path ? `${path}.${key}` : key;
      if (bucketForFieldName(key)) {
        for (const m of piiMatchesInValue(piiValueText(value))) {
          if (SUBJECT_IDENTIFIER_SHAPES.has(m.shape)) {
            if (!byPath.has(childPath)) byPath.set(childPath, { leaf: key, values: new Set() });
            byPath.get(childPath).values.add(`${m.shape}:${m.norm}`);
          }
        }
      }
      if (value && typeof value === "object") visit(value, depth + 1, childPath);
    }
  };
  for (let i = 0; i < scanLimit; i += 1) visit(records[i], 0, "");
  for (const { leaf, values } of byPath.values()) {
    if (values.size >= 2 && subjectLeaves.has(leaf) && values.has(victimKey)) return true;
  }
  return false;
}

// Distinct-SUBJECT count for the v2 single-subject gate — the number of distinct PEOPLE a body exposes. Per
// OBJECT NODE, count the distinct normalized VALUES of each subject-identifier SHAPE (email / ssn) among that
// node's sensitively-named fields, and credit the node the MAX over shapes; SUM that across all nodes. Two
// principles combine:
//   • MAX-over-shape WITHIN a node — one person carries at most one of each shape, so `{email, ssn}` → max(1
//     email, 1 ssn) = 1 (the live-validation /me, HIGH), but two DISTINCT same-shape values in sibling fields
//     `{email:victim, teammate_email:other}` → 2 emails → 2 (Codex P1 752: a node can hold MULTIPLE people).
//   • SUM ACROSS nodes — each object node is its own subject scope: `[{email:a},{email:b}]` / `{members:[…]}`
//     (#M) / `{u1:{…},u2:{…}}` (object-map) → separate nodes → 2+; `{email, items:[{sku}…]}` (#N) → items carry
//     no identifier → 1; `{email:a}` and `{ssn:b}` in separate nodes → 2 (Codex P1 round-2).
// Object/array VALUES of a sensitive key ARE serialized-extracted (NOT skipped) so `{email:victim,
// secondary_email:[other]}` counts both (Codex P1 743); under max-per-shape this is SAFE — a multi-subject
// container reads as >= 2 (→ MEDIUM), never collapsing to a false-HIGH 1. Residual (documented, SAFE-leaning →
// at worst a missed HIGH that stays MEDIUM, never a false HIGH): one subject SPLIT across separate nested
// objects (`{email, profile:{ssn}}`) or carrying multiple distinct same-shape values (primary+recovery email)
// reads as 2 → falls back to the v1 MEDIUM. Two err-toward-HIGH residuals remain, both requiring the victim's
// OWN /me to embed ANOTHER REAL principal's identifier in a sibling field — impossible for the SYNTHETIC,
// freshly-minted victim (a brand-new account has no spouse / dependent / teammate data), and otherwise bounded
// by the operator pointing victim_surface_id at a real /me + 3-round verification + grader: (a) two DIFFERENT
// people's SAME shape is caught (max counts 2 emails), but two people's DIFFERENT shapes fused into one FLAT
// object (`{email:victim, spouse_ssn:other}` / `{email:alice, ssn:bobs}`) → max(1,1)=1 (Codex P1 760 — a bare
// `ssn` sibling is indistinguishable from the victim's OWN ssn without field-name semantics, which would be an
// incomplete denylist; the robust future upgrade is canary-injection like the IDOR producer). If the bounded
// node BUDGET is exhausted mid-walk, FAIL CLOSED (return >= 2) so an only-partially-scanned large scope is never
// accepted as single-subject (CodeRabbit).
function distinctSubjectCount(bodyText) {
  if (typeof bodyText !== "string" || bodyText.length === 0) return 0;
  let parsed;
  try { parsed = JSON.parse(bodyText); } catch { return 0; }
  let nodeBudget = MASSREAD_MAX_NODES_PER_RECORD * MASSREAD_PII_SCAN_RECORDS; // whole-body, bounded
  let budgetExhausted = false;
  let total = 0;
  const visit = (node, depth) => {
    if (node == null || typeof node !== "object" || depth > MASSREAD_MAX_RECORD_DEPTH) return;
    if (nodeBudget <= 0) { budgetExhausted = true; return; }
    if (Array.isArray(node)) { for (const item of node) { if (nodeBudget <= 0) { budgetExhausted = true; return; } visit(item, depth + 1); } return; }
    const perShape = new Map(); // shape → Set of this node's distinct normalized values for that shape
    for (const key of Object.keys(node)) {
      if (nodeBudget <= 0) { budgetExhausted = true; return; }
      nodeBudget -= 1;
      const value = node[key];
      if (bucketForFieldName(key)) {
        for (const m of piiMatchesInValue(piiValueText(value))) {
          if (SUBJECT_IDENTIFIER_SHAPES.has(m.shape)) {
            if (!perShape.has(m.shape)) perShape.set(m.shape, new Set());
            perShape.get(m.shape).add(m.norm);
          }
        }
      }
      if (value && typeof value === "object") visit(value, depth + 1); // children are their own nodes
    }
    let nodeMax = 0;
    for (const vals of perShape.values()) if (vals.size > nodeMax) nodeMax = vals.size;
    total += nodeMax;
  };
  visit(parsed, 0);
  if (budgetExhausted) return Math.max(total, 2); // fail closed: a partial walk must never read as single-subject
  return total;
}

// The control-denial PREDICATE, factored out so the v1 LISTING control AND the v2 anon-VICTIM control
// score denial through ONE battle-tested path (no drift between two copies of a security check). Split
// into the two questions the inline v1 block asks (kept byte-identical):
//   controlReadsAnyPii — did the anon arm receive ANY subject/PII data? (a 2xx OR a 401 that still ships
//     PII is not a denial). pii-bearing record, a top-level singleton object, OR an unparseable bulk
//     dump of >= MIN distinct PII values (bot-review #784/#819/#821/#837/#581).
function controlReadsAnyPii(summary, body) {
  return summary.pii_bearing_count > 0
    || controlBodyExposesPii(body)
    || distinctPiiValuesInText(body) >= MASSREAD_MIN_RECORDS;
}
//   controlIsCleanDenial — read NO PII AND did not receive the bulk collection (>= MIN records at ANY
//     status is not a denial, bot-review #669/#677) AND is an explicit 401, an EMPTY 2xx (204 / empty
//     200), or a parsed 2xx with FEWER than MIN records. A 403 / 5xx / 404 / unparseable-nonempty-2xx is
//     AMBIGUOUS (WAF/bot-challenge vs authz) and is NEVER scored denied. `readAnyPii` is passed in so the
//     caller can reuse its own computation (v1 needs it for the split fail reason).
function controlIsCleanDenial(summary, resp, readAnyPii) {
  if (readAnyPii) return false;
  if (summary.parse_ok && summary.record_count >= MASSREAD_MIN_RECORDS) return false;
  const is2xx = resp.status != null && resp.status >= 200 && resp.status < 300;
  const bodyEmpty = typeof resp.body !== "string" || resp.body.trim().length === 0;
  const ok2xx = is2xx && summary.parse_ok;
  return resp.status === 401
    || (is2xx && bodyEmpty)
    || (ok2xx && summary.record_count < MASSREAD_MIN_RECORDS);
}

// Do the two cookie jars SHARE A SESSION? If so the two profiles authenticate as (at least partly) the
// SAME session — NOT distinct principals — so the victim arm must decline (fail CLOSED). We decline when
// the jars share any session-token-shaped VALUE (length >= SESSION_TOKEN_MIN_LEN), compared by VALUE
// regardless of cookie NAME. This is robust to the two unsound predecessors: full-set equality (bot-review
// #A: `{sid=ABC}` vs `{sid=ABC, csrf=Z}` are "unequal" yet share the session cookie) and a name=value
// compare (bot-review #J: the SAME opaque token reused under a DIFFERENT cookie name across app stacks /
// subdomains would read as distinct). The length floor targets real session tokens (JWT / UUID / base64
// sids are long) while NOT over-declining on a shared SHORT benign cookie (`locale=en`, `consent=true`,
// `role=admin`) that two genuinely distinct accounts often carry — declining there would gut the feature,
// and a shared short value is not evidence of a shared session anyway. Residual (documented): an app using
// a SHORT (< 16-char, insecure) session id is not caught here; distinct session ≠ distinct human either —
// the synthetic-identity anchor (victimIdentityKey) + the same-human guard carry the rest.
const SESSION_TOKEN_MIN_LEN = 16;
function cookiesShareAnyValue(a, b) {
  const tokensB = new Set((b || []).map((c) => String(c.value)).filter((v) => v.length >= SESSION_TOKEN_MIN_LEN));
  return (a || []).some((c) => {
    const v = String(c.value);
    return v.length >= SESSION_TOKEN_MIN_LEN && tokensB.has(v);
  });
}

// The victim's KNOWN account identity, as a normalized `email:<norm>` key — available ONLY for a SYNTHETIC
// Bob-minted profile (auth.js stamps profile.email + synthetic provenance ONLY on the in-process
// bob_auto_signup path; an operator-pasted profile cannot). Anchoring victim OWNERSHIP to this KNOWN
// identity — NOT to whatever the victim response body happens to contain — is what makes the cross-principal
// HIGH sound (bot-review #B/#C/#D/#E): a multi-subject private listing, org/team view, replayed collection,
// or shared static boilerplate (support@) cannot forge ownership of an identifier Bob did not mint for THIS
// victim. Mirrors the IDOR producer's synthetic-only #18 gate. Returns null when no known identity exists.
function victimIdentityKey(profile) {
  if (!profile || typeof profile !== "object") return null;
  if (profile.synthetic !== true) return null;
  if (typeof profile.email !== "string" || !profile.email) return null;
  const norm = normalizePiiValue("email", profile.email);
  return norm ? `email:${norm}` : null;
}

// Subject-identifier keys (email / ssn) found ANYWHERE in a RAW text blob (not field-bound). Used to prove
// the victim's own identity is NOT anon-readable even when an anon denial ships it in UNSTRUCTURED text —
// e.g. a 401 body `login required for victim@x` that subjectIdentifierSet (field-bound) would miss
// (bot-review #F). Returns the normalized `${shape}:${norm}` keys for the SUBJECT shapes only.
function subjectIdentifiersInRawText(text) {
  const out = new Set();
  for (const m of piiMatchesInValue(typeof text === "string" ? text : "")) {
    if (SUBJECT_IDENTIFIER_SHAPES.has(m.shape)) out.add(`${m.shape}:${m.norm}`);
  }
  return out;
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
// ADAPTER GUARD (bot-review #916): the agent-read block on massread-evidence/ is enforced by the
// session-read-guard PreToolUse hook, which ships in the Claude + Kimi adapters but NOT the Codex /
// generic-mcp adapters (no hook layer). Writing raw PII where the evaluator agent's own file tools can
// read it would break the operator-only intent of the capture, so raw capture is now DEFAULT-DENIED on
// any adapter without a read-guard — the call site gates on readGuardActive() AND ownerAuthorized(), so
// BOTH the operator env gate and a read-guard in this install are required. The PRIMARY guarantee — the
// signed rail never carries raw PII — holds on every adapter regardless. HONEST (like #131): the
// read-guard is incidental-read protection, not a barrier against a same-UID agent running arbitrary code.
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
  // v2 victim arm (optional): naming victim_surface_id opts the run into the HIGH cross-principal oracle —
  // a SECOND authenticated identity reads its OWN private scope (a routed in-scope surface) and the
  // attacker's bulk read is checked for an overlap with it. victim_auth_profile defaults to "victim".
  // Both are NAME selectors (a routed surface id + a stored profile name), never raw endpoint/credential.
  const victimSurfaceId = typeof args.victim_surface_id === "string" && args.victim_surface_id.trim()
    ? args.victim_surface_id.trim()
    : null;
  const victimProfileName = typeof args.victim_auth_profile === "string" && args.victim_auth_profile.trim()
    ? args.victim_auth_profile.trim()
    : DEFAULT_VICTIM_AUTH_PROFILE;
  const victimRequested = victimSurfaceId != null;

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
  // false MEDIUM; a truncated ATTACKER → false negative. Either truncated → unreliable, fail closed.
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
  // — card/IBAN/phone/address are recorded but are NOT subject keys, since one person has several) — so a
  // benign list + a stray metadata email, a field merely NAMED like PII
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
  // Compute the control's PII signal FIRST: any pii-bearing record (INCLUDING phone/address, which are not
  // subject identifiers but are still real PII), a top-level singleton object via controlBodyExposesPii, OR
  // a non-JSON body (CSV / plaintext / HTML) that ships >= MIN distinct PII values of ANY shape that
  // deriveMaskedSummary cannot parse (bot-review #784/#819/#821/#837/#581; a lone support value stays below
  // the floor).
  const controlReadAnyPii = controlReadsAnyPii(controlSummary, control.body);
  // (a) The control RECEIVED the bulk COLLECTION if its body parses to >= MIN records — REGARDLESS of HTTP
  //     status (a 401/403 that STILL returns the bulk body did NOT deny the client the records; bot-review
  //     #669/#677). It is therefore NOT a clean denial and never mints. Split the reason honestly so we do
  //     not conflate "read records" with "read the sensitive data" (bot-review #914):
  if (controlSummary.parse_ok && controlSummary.record_count >= MASSREAD_MIN_RECORDS) {
    if (controlReadAnyPii) {
      // anon read the bulk PII too → a PUBLIC / control-visible PII endpoint, not an authz break.
      return fail("blocked_by_design", "control_also_reads_bulk_pii");
    }
    // anon read >= MIN REDACTED records (no PII shape); the attacker's PII read of a collection the anon
    // sees only REDACTED is a field-level differential (BFLA on PII columns) — a real candidate, but v1
    // cannot tell it from a deliberately-public redacted listing without route semantics, so it DECLINES
    // rather than mint (the redacted-vs-PII mint is the v2 oracle). No longer mislabeled "public" (#914).
    return fail("blocked_by_infra", "control_inconclusive_redacted_bulk");
  }
  // (b) A CLEAN unauthenticated denial reads NO subject PII AND did not receive the bulk collection — an
  //     explicit 401, an EMPTY 2xx (204 / empty 200, bot-review #706), or a parsed 2xx with FEWER than MIN
  //     records. A 403 / 5xx / 404 / unparseable-nonempty-2xx is AMBIGUOUS (WAF/bot-challenge vs authz,
  //     bot-review #675) and is NEVER scored denied. The same predicate scores the v2 anon-VICTIM control.
  if (!controlIsCleanDenial(controlSummary, control, controlReadAnyPii)) {
    // Ambiguous control (403, 5xx, 404, unparseable, timeout, OR a control that itself read subject PII):
    // cannot conclude the control was DENIED, so the differential is unproven. Fail closed rather than
    // mint a MEDIUM off an inconclusive baseline.
    return fail("blocked_by_infra", "control_inconclusive");
  }

  // ── v2 victim arm (optional, ELEVATING only): prove a cross-PRINCIPAL break to stamp HIGH ──
  // The v1 MEDIUM differential is now proven. If the caller named a victim own-scope surface, run a SECOND
  // authenticated identity against it plus a fresh anon control, and elevate to HIGH iff ALL hold:
  //   (1) the victim is a SYNTHETIC Bob-minted identity with a KNOWN account email (victimIdentityKey) — so
  //       "the victim's own subject" is anchored to an identity Bob minted, NOT inferred from the response
  //       (bot-review #B/#C/#D/#E: a multi-subject listing / org view / replayed collection / shared
  //       boilerplate cannot forge ownership of an identifier Bob did not mint for this victim);
  //   (2) attacker and victim are DISTINCT — distinct profile NAME, DISJOINT cookie jars (no shared session
  //       value, bot-review #A), and (when the attacker identity is also known) a different account email;
  //   (3) victim_surface_id differs from the bulk listing (an own-scope endpoint, not a replay, bot-review #C);
  //   (4) the victim arm 2xx-reads its OWN known identity from that scope (it really is the victim's /me);
  //   (5) a fresh anon client is DENIED that scope AND the victim's identity is NOT anon-readable even in
  //       unstructured denial text (bot-review #F), so the identity is genuinely private; and
  //   (6) the attacker's bulk read CONTAINS the victim's known identity (the anchored overlap).
  // The victim arm can ONLY elevate — any failure leaves the proven MEDIUM intact and records WHY in the
  // hash-bound diagnostic. It runs AFTER the base passes, so a failing base never pays for the extra arms.
  // The overlap is computed over normalized identity VALUES in memory; ONLY booleans + a count are recorded
  // (the masked rail never carries a raw value). Severity is ALWAYS an explicit override (medium unless all
  // hold), and the sign path additionally requireExplicitSeverity so the high ceiling can never fail open.
  let crossTenantProven = false;
  let victimElevation = victimRequested ? "attempted" : "not_requested";
  const victimDiag = {};
  let victimBodyForCapture = null;
  let anonVictimBodyForCapture = null;
  if (victimRequested) {
    try {
      // Resolve the victim profile's KNOWN identity up front (URL only binds cookies; .email/.synthetic are
      // URL-independent). attackerIdentityKey is the attacker's own known identity, when it too is synthetic.
      const victimProfile = resolveAuthProfile(victimProfileName, `https://${domain}/`, domain);
      const victimKey = victimIdentityKey(victimProfile);
      const attackerIdentityKey = victimIdentityKey(profile);
      if (victimProfileName === authProfileName) {
        victimElevation = "victim_profile_not_distinct";          // same profile name = same identity
      } else if (victimSurfaceId === surfaceId) {
        victimElevation = "victim_surface_equals_listing";        // #C: own-scope must differ from the listing
      } else if (!victimProfile) {
        victimElevation = "victim_auth_profile_not_found";
      } else if (!victimKey) {
        victimElevation = "victim_profile_no_synthetic_identity"; // #B: a KNOWN (synthetic Bob-minted) victim is required
      } else if (attackerIdentityKey && attackerIdentityKey === victimKey) {
        victimElevation = "victim_identity_equals_attacker";      // same account on both arms = same principal
      } else {
        const { surface: victimSurface } = findRoutedSurface(domain, victimSurfaceId);
        const victimEndpointObj = resolveSurfaceEndpoint({ domain, surface: victimSurface, state, toolName: TOOL_ID });
        const victimEndpointUrl = victimEndpointObj.toString();
        // Read-only + scope guard on the victim endpoint (catches a verb-named segment); resolveSurfaceEndpoint
        // / findRoutedSurface re-validate scope, so an out-of-scope victim surface throws and is caught below
        // (no out-of-scope fetch happens).
        assertReadOnlyPath(victimEndpointUrl, TOOL_ID);
        // Value-blind (origin+path, query stripped) victim target — used for the alias-replay guard and as
        // the MAC-covered audit anchor of the victim scope.
        const victimCanonicalTarget = canonicalizeExploitTarget(victimEndpointUrl);
        const victimCookies = cookieObjectsFromProfile(victimProfile, victimEndpointObj.origin);
        if (sensitiveShapesPresent(victimEndpointUrl) || findIbans(victimEndpointUrl).length > 0) {
          victimElevation = "victim_endpoint_contains_sensitive_value";
        } else if (victimCanonicalTarget === canonicalTarget) {
          // #H: a DIFFERENT surface id that RESOLVES to the same endpoint as the bulk listing is still a
          // replay (the surface-id check above only catches an identical id). Compare resolved targets.
          victimElevation = "victim_endpoint_equals_listing";
        } else if (victimCookies.length === 0) {
          victimElevation = "victim_credential_not_cookie_expressible";
        } else if (cookiesShareAnyValue(authCookies, victimCookies)) {
          victimElevation = "victim_session_not_distinct";        // #A/#J: a shared session = same principal
        } else {
          // Record the victim SCOPE into the hash-bound diagnostic so a HIGH row MAC-covers WHICH scope
          // established the cross-principal break (bot-review #I) — value-blind + already PII-screened above.
          victimDiag.victim_surface_id = victimSurfaceId;
          victimDiag.victim_canonical_target = victimCanonicalTarget;
          const victimArmUrl = () => {
            const u = new URL(victimEndpointUrl);
            u.searchParams.set("_cb", crypto.randomBytes(8).toString("hex"));
            return u.toString();
          };
          const victim = await runArm(drv, { ...armBase, surfaceId: victimSurfaceId, endpointUrl: victimArmUrl(), authCookies: victimCookies, armTag: "victim" });
          const anonVictim = await runArm(drv, { ...armBase, surfaceId: victimSurfaceId, endpointUrl: victimArmUrl(), authCookies: null, armTag: "control-victim" });
          armOrder.push("victim", "control-victim");
          victimBodyForCapture = victim.body;
          anonVictimBodyForCapture = anonVictim.body;
          if ((victim.status != null && WAF_STATUSES.has(victim.status))
            || (anonVictim.status != null && WAF_STATUSES.has(anonVictim.status))) {
            victimElevation = "victim_arm_waf_or_rate_limit";
          } else if (victim.body_truncated || anonVictim.body_truncated) {
            victimElevation = "victim_arm_response_truncated";
          } else {
            const victimOk2xx = victim.status != null && victim.status >= 200 && victim.status < 300;
            const victimSubjects = victimOk2xx ? subjectIdentifierSet(victim.body) : new Set();
            // The victim arm must read its OWN known identity from this scope.
            const victimReadsOwnIdentity = victimSubjects.has(victimKey);
            // …AND the scope must be SINGLE-SUBJECT (the victim's own /me), not a multi-subject team/org/
            // listing/map that merely INCLUDES the victim among others (bot-review #L/#M/#N). On a shared
            // multi-subject scope the victim does not OWN the other subjects' data, so "victim_read_own_
            // private_scope" would be untruthful. distinctSubjectCount === 1: exactly one subject (one person's
            // email, plus optionally their own ssn) — a multi-person array / object-map / wrapper carries 2+
            // distinct emails and is rejected; a /me with email+ssn or a self-owned child collection stays 1.
            const victimScopeSingleSubject = distinctSubjectCount(victim.body) === 1;
            const anonVictimSummary = deriveMaskedSummary(anonVictim.body);
            const anonVictimDenied = controlIsCleanDenial(
              anonVictimSummary, anonVictim, controlReadsAnyPii(anonVictimSummary, anonVictim.body),
            );
            // anon must not see the victim's identity in EITHER structured fields or RAW denial text (#F).
            const anonSeesVictimIdentity = subjectIdentifierSet(anonVictim.body).has(victimKey)
              || subjectIdentifiersInRawText(anonVictim.body).has(victimKey);
            // The anchored overlap: the attacker's bulk read contains the victim as a RECORD'S OWN SUBJECT —
            // SUBJECT-bound (not merely record-bound), so a victim identity echoed in row/top-level METADATA
            // (`requested_by_email` / `viewer_email` / `manager_email`) does NOT count. Bound by cross-record
            // VARIANCE (varying path = subject, constant = metadata) AND FIELD-CONSISTENCY with the victim's own
            // /me subject key (so a varying metadata field under a different key cannot pose as the subject).
            const attackerReadsVictim = attackerReadVictimSubject(victim.body, attacker.body, victimKey);
            const proven = victimReadsOwnIdentity && victimScopeSingleSubject
              && anonVictimDenied && !anonSeesVictimIdentity && attackerReadsVictim;
            victimDiag.victim_status = victim.status;
            victimDiag.anon_victim_status = anonVictim.status;
            victimDiag.victim_overlap_count = proven ? 1 : 0;
            // Ordered root-cause first; all but the last reason stay MEDIUM.
            if (!anonVictimDenied) {
              victimElevation = "victim_scope_anon_not_denied";
            } else if (anonSeesVictimIdentity) {
              victimElevation = "victim_identity_visible_to_anon";   // #F: identity leaked to anon → not private
            } else if (!victimReadsOwnIdentity) {
              victimElevation = "victim_did_not_read_own_identity";  // the scope is not the victim's own /me
            } else if (!victimScopeSingleSubject) {
              victimElevation = "victim_scope_multi_subject";        // #L: a shared multi-subject scope, not /me
            } else if (!attackerReadsVictim) {
              victimElevation = "attacker_did_not_read_victim_subject";
            } else {
              crossTenantProven = true;
              victimElevation = "cross_principal_break_proven";
            }
          }
        }
      }
    } catch (e) {
      // The optional elevation must NEVER fail the proven MEDIUM run (scope/route/transport error) — but an
      // audit-write failure is a real integrity fault and must surface, like the base arms.
      if (e && e.probe_audit_failed) throw e;
      crossTenantProven = false;
      victimElevation = "victim_arm_error";
    }
  }
  // ALWAYS explicit (never undefined → no fail-open to the high ceiling): high only on a proven break.
  const severityDecision = crossTenantProven ? "high" : "medium";

  // ── build the canonical proof (MASKED, value-blind, PII-screened) ──
  const maskedSummary = {
    record_count: attackerSummary.record_count,
    pii_bearing_count: attackerSummary.pii_bearing_count,
    distinct_pii_count: attackerSummary.distinct_pii_count,
    sensitive_field_names: attackerSummary.sensitive_field_names,
    pii_shape_present: attackerSummary.pii_shape_present,
  };
  const stdoutContent = canonicalJson(maskedSummary);
  const stderrBundle = {
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
  };
  // Fold the v2 victim-arm diagnostics into the hash-bound bundle ONLY when a victim arm was requested
  // (a pure v1 run's stderr stays byte-identical). victimDiag holds counts/statuses only — never a raw
  // value — and victim_elevation is a fixed reason code; the PII screen below still guards both.
  if (victimRequested) {
    stderrBundle.victim_elevation = victimElevation;
    Object.assign(stderrBundle, victimDiag);
    if (crossTenantProven) {
      stderrBundle.victim_read_own_private_scope = true;
      stderrBundle.victim_scope_anon_denied = true;
      stderrBundle.attacker_read_victim_subject = true;
      stderrBundle.victim_distinct_session = true;
    }
  }
  const stderrContent = canonicalJson(stderrBundle);
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
  // The v2 cross-principal legs are added ONLY on a proven HIGH mint, so a MEDIUM row (victim absent OR
  // requested-but-unproven) carries exactly the v1 three booleans — the proven victim arm asserts the
  // extra legs that justify the high severity (the why-not for an unproven attempt lives in stderr).
  const relationBooleans = {
    credentialed_bulk_pii_read: true,
    unauthenticated_control_denied: true,
    pii_value_shapes_present: true,
    ...(crossTenantProven ? {
      victim_read_own_private_scope: true,   // a distinct authed victim read these subjects as its OWN
      victim_scope_anon_denied: true,        // a fresh anon client is DENIED the victim's own scope (private)
      attacker_read_victim_subject: true,    // the attacker's bulk read overlapped the victim's private subjects
      victim_distinct_session: true,         // distinct profile name + distinct cookie jar
    } : {}),
  };

  // demonstrated_severity DERIVED from the per-tool registry inside buildAndSignOffensiveRow, clamped by
  // our ALWAYS-explicit override (medium for v1, high only on a proven victim-arm break — the override can
  // only LOWER the high ceiling, so this never fails open). Capture FIRST, recompute hashes from on-disk
  // bytes, sign LAST — under the session lock.
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
    demonstratedSeverityOverride: severityDecision,
    // The ceiling is HIGH and severity is per-run, so fail CLOSED if a future path ever omits the override
    // (bot-review #G) rather than silently signing the high ceiling.
    requireExplicitSeverity: true,
  }));

  // OPT-IN full capture — OPERATOR env gate only, OUTSIDE the signed rail. The raw bodies live in
  // memory only until here; for the default (masked-only) path they are never persisted.
  let ownerCaptureWritten = false;
  if (ownerAuthorized(domain) && readGuardActive()) {
    try {
      writeFullCapture(domain, row.run_id, {
        tool_id: TOOL_ID,
        run_id: row.run_id,
        target: row.target,
        attacker_status: attacker.status,
        control_status: control.status,
        attacker_body: attacker.body,
        control_body: control.body,
        // The victim arms' raw bodies (when the elevation arms ran) — held in memory only until here,
        // under the SAME owner+read-guard gate as the attacker/control bodies. Null when no victim arm ran.
        victim_elevation: victimRequested ? victimElevation : undefined,
        victim_body: victimBodyForCapture,
        anon_victim_body: anonVictimBodyForCapture,
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
    // v2 elevation outcome (so the evaluator/grader see WHY a run is HIGH or only MEDIUM). cross_tenant_proven
    // is the boolean gate; victim_elevation is the fixed reason code; victim_overlap_count is the count of
    // the attacker∩victim private-subject overlap (0 unless a victim arm ran AND scored an overlap).
    cross_tenant_proven: crossTenantProven,
    victim_elevation: victimElevation,
    masked_oracle: {
      relation: relationBooleans,
      record_count: maskedSummary.record_count,
      pii_bearing_count: maskedSummary.pii_bearing_count,
      distinct_pii_count: maskedSummary.distinct_pii_count,
      sensitive_field_names: maskedSummary.sensitive_field_names,
      pii_shape_present: maskedSummary.pii_shape_present,
      cross_tenant_proven: crossTenantProven,
      victim_elevation: victimElevation,
      victim_overlap_count: typeof victimDiag.victim_overlap_count === "number" ? victimDiag.victim_overlap_count : 0,
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
