"use strict";

// SERVER-SIDE CREDENTIAL INJECTION for outbound request BODIES.
//
// The problem: bob_list_auth_profiles redacts credential VALUES on purpose — an agent
// holding a plaintext password can leak it into its own context, a finding, a report, a
// log, or an off-target request. But a form/JSON login, an OAuth token exchange
// (grant_type=refresh_token / client_credentials), a session re-auth, and any test of the
// auth endpoints themselves all need that plaintext in the request BODY. Applying a
// profile as HEADERS only (applyAuthProfileHeaders) cannot express any of it, so Bob could
// replay a session but never obtain one — including the second-principal provisioning the
// id-bearing completion gate depends on.
//
// The contract: the agent writes a PLACEHOLDER naming a credential field. The MCP server
// substitutes the real value at request-BUILD time — after the agent's arguments are fixed
// and after the scope gate has passed — sends it, then redacts that value out of
// everything the agent or any artifact can observe.
//
//   bob_http_scan({ method: "POST", url: "https://target/api/login",
//     body: { email: "{{auth.victim.email}}", password: "{{auth.victim.password}}" } })
//
// The agent NAMES a secret; it never SEES one. Enforced properties:
//
//   SCOPE      — substitution runs only after bob_http_scan's scope gate has allowed the
//                URL (http-scan.js), and safeFetch re-validates every redirect hop, so a
//                credential can never be sent off-target.
//   ECHO-BACK  — EVERY response for the session's target domain is stripped of ALL of that
//                session's credential material — not merely of what the current request
//                substituted — before anything is returned to the agent: status line,
//                headers, body, truncation/binary summaries, and every derived analysis copy.
//                Two exfil paths are closed. (1) POST-then-GET laundering: writing a secret
//                into a bio/note/display-name and re-reading it with an ordinary,
//                placeholder-free request. Redaction is a property of the DOMAIN, resolved
//                from the auth STORE at request time, so it survives a process restart and
//                covers a credential a previous session stored. (2) Encoder evasion: matching
//                runs against the DECODED haystack (numeric HTML entities, \uXXXX, percent
//                encoding), so an encoder Bob never enumerated cannot slip past silently.
//                The partial tail left by a truncated body is covered too.
//   AUDIT      — the caller redacts the audit record through the same redactor and records
//                only the placeholder LABEL, never the value.
//   FAIL CLOSED— an unknown profile, unknown field, non-string or empty credential, a
//                placeholder outside the body, or a malformed placeholder REFUSES the
//                request. Bob never sends the literal placeholder text and never
//                substitutes an empty string.
//   BOUNDED    — values resolve ONLY from the named auth.json profile's credential and
//                stored-token material (auth.js resolveProfileCredentialValue). This is not
//                a file/env read primitive.

// {{auth.<profile>.<field>}} — optional inner whitespace. Profile and field are restricted
// to [A-Za-z0-9_-] so `auth.a.b.c` is unambiguous (and is REFUSED by the loose check below
// rather than silently sent as literal text).
const CREDENTIAL_PLACEHOLDER_SOURCE = "\\{\\{\\s*auth\\.([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]+)\\s*\\}\\}";

// Anything shaped like an auth placeholder. A body may legitimately carry other mustache
// tokens (a template-injection payload such as {{7*7}} is a real evaluator technique), so
// the refusal is narrowed to tokens that ADDRESS auth — a malformed auth placeholder is a
// typo that must fail loudly, never a literal secret-shaped string sent to the target.
const LOOSE_CREDENTIAL_PLACEHOLDER_SOURCE = "\\{\\{\\s*auth\\s*\\.[^}]*\\}\\}";

// A truncated response can cut a reflected secret mid-value, leaving a PREFIX that exact
// matching would miss. Tail prefixes at least this long are redacted too.
const REDACTION_MIN_TAIL_CHARS = 4;

const DECISION_UNRESOLVED = "credential_unresolved";
const DECISION_REJECTED = "credential_placeholder_rejected";

function strictPlaceholderRegex() {
  return new RegExp(CREDENTIAL_PLACEHOLDER_SOURCE, "g");
}

function loosePlaceholderRegex() {
  return new RegExp(LOOSE_CREDENTIAL_PLACEHOLDER_SOURCE, "g");
}

class CredentialPlaceholderError extends Error {
  constructor(message, decision) {
    super(message);
    this.name = "CredentialPlaceholderError";
    this.decision = decision || DECISION_REJECTED;
    this.credential_placeholder_error = true;
  }
}

function isCredentialPlaceholderError(error) {
  return !!(error && error.credential_placeholder_error === true);
}

function placeholderLabel(profile, field) {
  return `auth.${profile}.${field}`;
}

function redactionMarker(profile, field) {
  return `[REDACTED_CREDENTIAL:${placeholderLabel(profile, field)}]`;
}

function containsStrictPlaceholder(text) {
  return typeof text === "string" && strictPlaceholderRegex().test(text);
}

function containsLoosePlaceholder(text) {
  return typeof text === "string" && loosePlaceholderRegex().test(text);
}

function containsAnyPlaceholder(text) {
  return containsStrictPlaceholder(text) || containsLoosePlaceholder(text);
}

// ---------------------------------------------------------------------------
// Substitution
// ---------------------------------------------------------------------------

function identityEncoder(value) {
  return value;
}

function formEncoder(value) {
  return encodeURIComponent(value);
}

// Escape exactly as a JSON string interior so a credential containing a quote or a
// backslash cannot break out of the surrounding JSON literal.
function jsonStringEncoder(value) {
  const json = JSON.stringify(String(value));
  return json.slice(1, -1);
}

function substituteText(text, resolve, encode) {
  return String(text).replace(strictPlaceholderRegex(), (_match, profile, field) =>
    encode(resolve(profile, field)));
}

function substituteStructural(value, resolve) {
  if (typeof value === "string") return substituteText(value, resolve, identityEncoder);
  if (Array.isArray(value)) return value.map((item) => substituteStructural(item, resolve));
  if (value && typeof value === "object") {
    // Null-prototype: an agent probing prototype pollution sends a literal "__proto__" key,
    // and JSON.parse hands it over as an OWN property. Rebuilding into a plain {} would
    // silently swallow it and change the payload under the agent's feet.
    const out = Object.create(null);
    for (const [key, child] of Object.entries(value)) {
      out[substituteText(key, resolve, identityEncoder)] = substituteStructural(child, resolve);
    }
    return out;
  }
  return value;
}

function headerValue(headers, name) {
  const wanted = String(name).toLowerCase();
  for (const [key, value] of Object.entries(headers || {})) {
    if (String(key).toLowerCase() === wanted) return value;
  }
  return null;
}

function hasHeader(headers, name) {
  return headerValue(headers, name) != null;
}

// A caller-supplied Content-Length was measured against the TEMPLATE, not the substituted
// body. Leaving it stale would truncate or hang the request, which reads as a target-side
// failure rather than a Bob-side one. Rewrite it in place, preserving the caller's casing.
function withCorrectedContentLength(headers, bodyString) {
  if (!hasHeader(headers, "content-length")) return headers;
  const out = { ...(headers || {}) };
  for (const key of Object.keys(out)) {
    if (String(key).toLowerCase() === "content-length") {
      out[key] = String(Buffer.byteLength(bodyString));
    }
  }
  return out;
}

function looksFormEncoded(text) {
  return /^[^=&\s]+=[^&]*(?:&[^=&\s]*=[^&]*)*$/.test(String(text));
}

function parsedJsonContainer(text) {
  const trimmed = String(text).trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return null;
  try {
    const parsed = JSON.parse(trimmed);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

function assertNoPlaceholder(value, whereDescription) {
  if (!containsAnyPlaceholder(value)) return;
  throw new CredentialPlaceholderError(
    `credential placeholders are substituted in the request BODY only — found one in ${whereDescription}. `
    + "Move it into the body, or use auth_profile for header-borne session material.",
    DECISION_REJECTED,
  );
}

// Build the outbound body, substituting every {{auth.<profile>.<field>}} placeholder from
// the named profiles. Returns the serialized body, the (possibly content-type-augmented)
// headers, and the substituted secrets so the caller can build a redactor. Throws
// CredentialPlaceholderError on any refusal; the caller must NOT send the request.
//
// `resolveCredential(profile, field)` must return the plaintext value or throw. It is the
// ONLY source of secret material here.
function prepareRequestBody({ url, agentHeaders, headers, body, resolveCredential }) {
  const substituted = [];
  const seen = new Set();
  const cache = new Map();
  const resolve = (profile, field) => {
    const label = placeholderLabel(profile, field);
    if (!cache.has(label)) {
      const value = resolveCredential(profile, field);
      if (typeof value !== "string" || value.trim() === "") {
        // Defensive: the resolver is contracted to throw, never to return an empty value.
        // Substituting "" would be a silent auth failure the agent could not diagnose.
        throw new CredentialPlaceholderError(
          `credential ${label} resolved to an empty value — request was refused rather than sending an empty credential`,
          DECISION_UNRESOLVED,
        );
      }
      cache.set(label, value);
    }
    const resolved = cache.get(label);
    if (!seen.has(label)) {
      seen.add(label);
      substituted.push({ label, profile, field, value: resolved });
    }
    return resolved;
  };

  // Placeholders are a BODY primitive. Anywhere else they are refused rather than sent as
  // literal text (a URL-borne credential would also land in the audit URL and in the
  // target's access log).
  assertNoPlaceholder(url, "the request URL");
  for (const [name, value] of Object.entries(agentHeaders || {})) {
    assertNoPlaceholder(name, "a request header name");
    assertNoPlaceholder(value, `request header "${name}"`);
  }

  const isBuffer = typeof Buffer !== "undefined" && Buffer.isBuffer(body);
  const isContainer = !isBuffer && body != null && typeof body === "object";
  const isString = typeof body === "string";
  if (!isContainer && !isString) {
    return { body, headers, substituted: [] };
  }

  const contentType = String(headerValue(headers, "content-type") || "").toLowerCase();
  let nextHeaders = headers;
  let outBody;

  if (isContainer) {
    // An object body is always serialized as JSON; JSON.stringify performs the escaping, so
    // a credential containing quotes/backslashes/control characters can never deform it.
    outBody = JSON.stringify(substituteStructural(body, resolve));
    if (!hasHeader(headers, "content-type")) {
      nextHeaders = { ...(headers || {}), "Content-Type": "application/json" };
    }
  } else if (!containsAnyPlaceholder(body)) {
    // No placeholder: return the caller's bytes untouched. Every existing request shape is
    // byte-identical to before this feature.
    return { body, headers, substituted: [] };
  } else if (contentType.includes("x-www-form-urlencoded")) {
    outBody = substituteText(body, resolve, formEncoder);
  } else if (contentType.includes("json")) {
    const container = parsedJsonContainer(body);
    outBody = container
      ? JSON.stringify(substituteStructural(container, resolve))
      // A deliberately malformed JSON body (a parser-abuse payload) still gets the value
      // escaped as a JSON string interior — the safe direction for a json content type.
      : substituteText(body, resolve, jsonStringEncoder);
  } else if (!contentType) {
    const container = parsedJsonContainer(body);
    if (container) {
      outBody = JSON.stringify(substituteStructural(container, resolve));
    } else if (looksFormEncoded(body)) {
      outBody = substituteText(body, resolve, formEncoder);
    } else {
      outBody = substituteText(body, resolve, identityEncoder);
    }
  } else {
    // A declared non-JSON, non-form content type (XML, GraphQL, text): substitute verbatim.
    outBody = substituteText(body, resolve, identityEncoder);
  }

  if (containsLoosePlaceholder(outBody)) {
    throw new CredentialPlaceholderError(
      "malformed credential placeholder in the request body — expected {{auth.<profile>.<field>}} "
      + "with [A-Za-z0-9_-] profile and field names. Request was refused rather than sending the "
      + "literal placeholder text to the target.",
      DECISION_REJECTED,
    );
  }

  return {
    body: outBody,
    headers: withCorrectedContentLength(nextHeaders, outBody),
    substituted,
  };
}

// ---------------------------------------------------------------------------
// Echo-back / artifact redaction
// ---------------------------------------------------------------------------

function htmlEscape(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// The shapes a reflecting endpoint may echo a substituted value back in. All are exact
// strings, so redaction is a literal replace with no regex escaping hazard.
//
// This is a CHEAP FIRST PASS ONLY — it is deliberately NOT the security boundary. Enumerating
// encoder outputs cannot be complete: markupsafe/Jinja2/Flask emit &#34; where htmlEscape
// emits &quot;, Django emits &#x27; where it emits &#39;, and Python's json.dumps defaults to
// ensure_ascii=True and emits \uXXXX for anything non-ASCII. Any encoder not in this list is a
// SILENT bypass. normalizeEncodedText below is the actual guarantee: it decodes the haystack
// and matches the RAW secret, so a fifth encoder no one anticipated is covered too.
function secretVariants(value) {
  const variants = new Set([value]);
  try {
    const encoded = encodeURIComponent(value);
    variants.add(encoded);
    variants.add(encoded.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase()));
  } catch {}
  variants.add(jsonStringEncoder(value));
  variants.add(htmlEscape(value));
  return Array.from(variants).filter((variant) => typeof variant === "string" && variant.length > 0);
}

function replaceAllLiteral(text, needle, replacement) {
  if (!needle || !text.includes(needle)) return text;
  return text.split(needle).join(replacement);
}

// ---------------------------------------------------------------------------
// Normalize-then-scan
// ---------------------------------------------------------------------------

// The named HTML entities a template engine can emit for a character that appears in a
// credential. Numeric entities (&#34; / &#x27;, decimal AND hex, any code point) are handled
// generically below, so this list only has to cover the NAMED spellings.
const NAMED_ENTITIES = Object.freeze({
  amp: "&", quot: '"', apos: "'", lt: "<", gt: ">", nbsp: " ", sol: "/", equals: "=",
});

// JSON single-character escapes. \uXXXX (including surrogate pairs) is handled generically.
const JSON_ESCAPES = Object.freeze({
  '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t",
});

// Cheap gate: text carrying none of these sigils cannot hide an encoded secret, so the
// (allocating) normalization pass is skipped entirely for the common case.
const ENCODING_SIGIL_RE = /&#[0-9xX]|&[a-zA-Z]{2,6};|\\[u"\\/bfnrt]|%[0-9A-Fa-f]{2}/;

function isHexDigit(ch) {
  return (ch >= "0" && ch <= "9") || (ch >= "a" && ch <= "f") || (ch >= "A" && ch <= "F");
}

// Decode HTML entities, JSON escapes, and percent-encoding in ONE left-to-right pass, and
// return a map from each normalized character back to its ORIGINAL offset.
//
// Every decoder here consumes >= 1 source character per emitted character, so the normalized
// string is never longer than the source and the offset map fits a preallocated Int32Array.
// The source is consumed contiguously, so starts[i] is the offset of normalized char i and
// starts[j] is the END offset of the token that produced normalized char j-1 — which is what
// lets a match found in normalized space be mapped back to an exact span of the ORIGINAL text.
// Redaction then replaces that original span, so the emitted output stays byte-faithful apart
// from the redaction marker.
//
// Returns null when nothing decoded (the caller then has nothing new to scan).
function normalizeEncodedText(input) {
  const src = String(input);
  const len = src.length;
  if (len === 0 || !ENCODING_SIGIL_RE.test(src)) return null;

  const starts = new Int32Array(len + 1);
  const chunks = [];
  let normLength = 0;
  let literalFrom = 0;
  let decodedAny = false;
  let i = 0;

  const flushLiteral = (upto) => {
    if (upto <= literalFrom) return;
    chunks.push(src.slice(literalFrom, upto));
    for (let k = literalFrom; k < upto; k += 1) {
      starts[normLength] = k;
      normLength += 1;
    }
  };

  while (i < len) {
    const ch = src[i];
    let decoded = null;
    let next = i;

    if (ch === "&") {
      const semi = src.indexOf(";", i + 1);
      if (semi > i && semi - i <= 12) {
        const inner = src.slice(i + 1, semi);
        if (inner[0] === "#") {
          const isHex = inner[1] === "x" || inner[1] === "X";
          const digits = isHex ? inner.slice(2) : inner.slice(1);
          if (digits && (isHex ? /^[0-9A-Fa-f]+$/ : /^[0-9]+$/).test(digits)) {
            const code = Number.parseInt(digits, isHex ? 16 : 10);
            if (Number.isFinite(code) && code >= 0 && code <= 0x10ffff) {
              try {
                decoded = String.fromCodePoint(code);
                next = semi + 1;
              } catch {}
            }
          }
        } else {
          const named = NAMED_ENTITIES[inner.toLowerCase()];
          if (named != null) {
            decoded = named;
            next = semi + 1;
          }
        }
      }
    } else if (ch === "\\") {
      const following = src[i + 1];
      if (following === "u" && /^[0-9A-Fa-f]{4}$/.test(src.slice(i + 2, i + 6))) {
        const high = Number.parseInt(src.slice(i + 2, i + 6), 16);
        if (high >= 0xd800 && high <= 0xdbff
          && src.slice(i + 6, i + 8) === "\\u"
          && /^[0-9A-Fa-f]{4}$/.test(src.slice(i + 8, i + 12))) {
          const low = Number.parseInt(src.slice(i + 8, i + 12), 16);
          if (low >= 0xdc00 && low <= 0xdfff) {
            decoded = String.fromCharCode(high, low);
            next = i + 12;
          }
        }
        if (decoded == null) {
          decoded = String.fromCharCode(high);
          next = i + 6;
        }
      } else if (following != null && Object.prototype.hasOwnProperty.call(JSON_ESCAPES, following)) {
        // "\\" decodes to a single backslash and consumes BOTH characters, so a literal
        // "\\u0041" is not mis-read as a unicode escape.
        decoded = JSON_ESCAPES[following];
        next = i + 2;
      }
    } else if (ch === "%") {
      // Consume the maximal run of %XX triplets so a multi-byte UTF-8 sequence decodes as one
      // character rather than as mojibake that would no longer match the raw secret.
      let end = i;
      while (end + 3 <= len && src[end] === "%" && isHexDigit(src[end + 1]) && isHexDigit(src[end + 2])) {
        end += 3;
      }
      if (end > i) {
        const run = src.slice(i, end);
        try {
          decoded = decodeURIComponent(run);
        } catch {
          // Not valid UTF-8 (a partial sequence, or raw high bytes): fall back to byte-wise so
          // an ASCII credential inside the run still matches.
          decoded = run.replace(/%([0-9A-Fa-f]{2})/g, (_m, hex) => String.fromCharCode(Number.parseInt(hex, 16)));
        }
        next = end;
      }
    }

    if (decoded == null) {
      i += 1;
      continue;
    }
    flushLiteral(i);
    chunks.push(decoded);
    for (let k = 0; k < decoded.length; k += 1) {
      starts[normLength] = i;
      normLength += 1;
    }
    literalFrom = next;
    decodedAny = true;
    i = next;
  }

  if (!decodedAny) return null;
  flushLiteral(len);
  starts[normLength] = len;
  return { text: chunks.join(""), starts, length: normLength };
}

// A single pass leaves DOUBLE-encoded material intact (%2520 decodes to %20, not to a space;
// &amp;#34; decodes to &#34;), so decoding is repeated to a fixpoint under a hard bound and the
// offset maps are composed back to the ORIGINAL string.
const MAX_NORMALIZATION_PASSES = 3;

function normalizeEncodedTextDeep(input) {
  let current = normalizeEncodedText(input);
  if (!current) return null;
  for (let pass = 1; pass < MAX_NORMALIZATION_PASSES; pass += 1) {
    const next = normalizeEncodedText(current.text);
    if (!next) break;
    // composed[i] = original offset of normalized char i, by walking this pass's map through
    // the previous one. Valid because every starts[] value indexes the previous pass's text.
    const composed = new Int32Array(next.length + 1);
    for (let i = 0; i <= next.length; i += 1) composed[i] = current.starts[next.starts[i]];
    current = { text: next.text, starts: composed, length: next.length };
  }
  return current;
}

// Replace a set of [start, end) spans of `text` with their markers. Spans are taken
// longest-first at each position and overlaps are dropped, so two secrets that share a
// substring produce one well-formed marker rather than a marker spliced into a marker.
function applySpanRedactions(text, spans) {
  if (!spans.length) return text;
  spans.sort((a, b) => (a.start - b.start) || ((b.end - b.start) - (a.end - a.start)));
  const out = [];
  let cursor = 0;
  for (const span of spans) {
    if (span.start < cursor) continue;
    out.push(text.slice(cursor, span.start), span.marker);
    cursor = span.end;
  }
  out.push(text.slice(cursor));
  return out.join("");
}

const IDENTITY_REDACTOR = Object.freeze({
  active: false,
  labels: Object.freeze([]),
  text: (value) => value,
  deep: (value) => value,
  truncatedTail: (value) => value,
});

// Build a redactor over a set of credential MATERIAL entries ({ label, profile, field,
// value }). No minimum length: a short credential is redacted too, because over-redacting a
// response is loud and recoverable — the marker names the exact profile.field that collided,
// so the operator can see and fix it — while leaking the operator's secret is neither loud
// nor recoverable.
//
// The caller decides the BASIS. http-scan passes the whole session's credential material
// (auth.js sessionCredentialMaterial), not just what this request substituted: a basis
// scoped to one call is trivially laundered by a second, placeholder-free call.
function makeCredentialRedactor(material) {
  const entries = Array.isArray(material) ? material : [];
  const needles = [];
  const secrets = [];
  const labels = [];
  const seenSecret = new Set();
  for (const entry of entries) {
    if (!entry || typeof entry.value !== "string" || entry.value === "") continue;
    labels.push(entry.label);
    const marker = redactionMarker(entry.profile, entry.field);
    for (const variant of secretVariants(entry.value)) {
      needles.push({ needle: variant, marker });
    }
    // The normalized scan matches the RAW secret only; the encoded variants above collapse
    // back to it once the haystack is decoded.
    if (!seenSecret.has(entry.value)) {
      seenSecret.add(entry.value);
      secrets.push({ secret: entry.value, marker });
    }
  }
  if (!needles.length) return IDENTITY_REDACTOR;
  // Longest first: a value whose encoded form contains its raw form must not be
  // half-replaced into an unrecognizable remainder.
  needles.sort((a, b) => b.needle.length - a.needle.length);

  // Second pass over the DECODED haystack. This is what makes an encoder Bob has never seen
  // (a numeric HTML entity, an ensure_ascii=True \uXXXX escape, a double-decoded parameter)
  // non-silent: the raw secret is matched against normalized text and the hit is mapped back
  // to a span of the ORIGINAL string, so the marker still appears in the output.
  const redactNormalized = (value) => {
    const normalized = normalizeEncodedTextDeep(value);
    if (!normalized || !normalized.length) return value;
    const spans = [];
    for (const { secret, marker } of secrets) {
      if (!secret) continue;
      let from = 0;
      for (;;) {
        const at = normalized.text.indexOf(secret, from);
        if (at === -1) break;
        const start = normalized.starts[at];
        // One source token can decode to two normalized chars (an astral code point via
        // &#128512; or a 😀 pair). If the match ends inside such a token, walk past
        // the whole token so the span covers it rather than half of it.
        let after = at + secret.length;
        const lastTokenStart = normalized.starts[after - 1];
        while (after < normalized.length && normalized.starts[after] === lastTokenStart) after += 1;
        const end = Math.max(normalized.starts[after], start + 1);
        spans.push({ start, end, marker });
        from = at + secret.length;
      }
    }
    return applySpanRedactions(value, spans);
  };

  const redactText = (value) => {
    if (typeof value !== "string" || value === "") return value;
    let out = value;
    for (const { needle, marker } of needles) {
      out = replaceAllLiteral(out, needle, marker);
    }
    return redactNormalized(out);
  };

  // A response cut at the transport/body cap can end in a PARTIAL secret that exact
  // matching cannot see. Redact a trailing proper prefix of any variant.
  const redactTruncatedTail = (value) => {
    if (typeof value !== "string" || value === "") return value;
    let out = value;
    for (const { needle, marker } of needles) {
      const maxPrefix = Math.min(needle.length - 1, out.length);
      for (let length = maxPrefix; length >= REDACTION_MIN_TAIL_CHARS; length -= 1) {
        const prefix = needle.slice(0, length);
        if (out.endsWith(prefix)) {
          out = out.slice(0, out.length - length) + marker;
          break;
        }
      }
    }
    return out;
  };

  const redactDeep = (value) => {
    if (typeof value === "string") return redactText(value);
    if (Array.isArray(value)) return value.map(redactDeep);
    if (value && typeof value === "object") {
      const out = {};
      for (const [key, child] of Object.entries(value)) {
        out[redactText(key)] = redactDeep(child);
      }
      return out;
    }
    return value;
  };

  return Object.freeze({
    active: true,
    labels: Object.freeze(Array.from(new Set(labels))),
    text: redactText,
    deep: redactDeep,
    truncatedTail: redactTruncatedTail,
  });
}

module.exports = {
  CREDENTIAL_PLACEHOLDER_SOURCE,
  CredentialPlaceholderError,
  DECISION_REJECTED,
  DECISION_UNRESOLVED,
  IDENTITY_REDACTOR,
  containsAnyPlaceholder,
  containsLoosePlaceholder,
  containsStrictPlaceholder,
  isCredentialPlaceholderError,
  makeCredentialRedactor,
  placeholderLabel,
  prepareRequestBody,
  redactionMarker,
};
