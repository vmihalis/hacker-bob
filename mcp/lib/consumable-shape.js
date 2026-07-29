"use strict";

const crypto = require("crypto");

// The cross-stack decoy must be indistinguishable-AS-A-SHAPE from the real cause so the
// ONLY thing a gate can use to flip its outcome is validating the byte CONTENT. A gate
// that rejects "wrong length / not-JWT-shaped" must no longer be able to tell the decoy
// from the cause. This module is the SINGLE shared classifier + same-shape random
// generator used by BOTH the mint side (offensive-capture-writer.mintDecoyCapture's
// cross-stack path) AND the verify side (cross-stack-differential-verifier's decoy
// shape-parity binding). Factoring it here prevents a mint/verify classifier divergence —
// which would itself be a soundness gap, since the verifier would bind a shape the mint
// never produced.
//
// The encoding classes, in order of derivation (most-specific first):
//   jwt    — three base64url segments separated by dots (header.payload.signature).
//   json   — the UTF-8 decode JSON.parses to an OBJECT or ARRAY (the IDOR producer's
//            canonicalJson cause). A scalar (number/bool/null/string) is NOT 'json' here:
//            randomizeJsonLeaves can only build a same-shape decoy for a structure, so the
//            mint side raw-floors a scalar; classifying it 'json' would make the verify side
//            expect a 'json' decoy the mint never produces — the mint/verify divergence that
//            silently barred a scalar-token cause from EVER producing a verified_pass. A
//            scalar falls through to the byte-pattern classes so both sides agree.
//   hex    — even-length, all [0-9a-fA-F].
//   base64 — length % 4 === 0, all [A-Za-z0-9+/] with up to two trailing '='.
//   raw    — none of the above (the byte-length parity check is the binding).
// raw is the fail-open floor: when no structured class is derivable, byte-length parity
// is still asserted, so a length-distinguishing gate cannot pass.

const JWT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const HEX_RE = /^[0-9a-fA-F]+$/;
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
// base64 alphabet chars OUTSIDE the hex alphabet [0-9a-fA-F] — used to guarantee a base64
// decoy never re-classifies as 'hex' (hex is checked first and is a subset of base64).
const NON_HEX_BASE64_CHARS = "GHIJKLMNOPQRSTUVWXYZghijklmnopqrstuvwxyz+/";

// Classify the SHAPE of a Buffer of consumable bytes into one of the encoding classes
// above. Pure + deterministic: the same bytes always classify to the same class on both
// the mint and verify sides. Returns "raw" for empty input (no structure to bind beyond
// length, which is zero).
function classifyConsumableShape(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) return "raw";
  let text = null;
  try {
    text = bytes.toString("utf8");
  } catch {
    text = null;
  }
  if (text != null && JWT_RE.test(text)) return "jwt";
  if (text != null) {
    try {
      const parsed = JSON.parse(text);
      // Only STRUCTURED JSON (object/array) is the 'json' shape — a scalar has no leaves to
      // randomize, so the mint side raw-floors it and the verify side must agree by NOT calling
      // it 'json'. Fall through to the byte-pattern classes for scalars.
      if (parsed !== null && typeof parsed === "object") return "json";
    } catch {
      // not JSON — fall through to the byte-pattern classes.
    }
  }
  if (text != null && text.length % 2 === 0 && HEX_RE.test(text)) return "hex";
  if (text != null && text.length % 4 === 0 && text.length > 0 && BASE64_RE.test(text)) return "base64";
  return "raw";
}

// Replace every leaf string/number value in a parsed JSON structure with random content of
// a matching length class — these leaves are exactly the credential/identity-bearing fields,
// so a decoy keeps the cause's grammar (same keys, same nesting) while carrying NONE of its
// secret content. Arrays/objects recurse; booleans/null are kept (they carry no secret and
// flipping them would change the grammar a structure-checking gate sees).
function randomizeJsonLeaves(value) {
  if (Array.isArray(value)) return value.map((v) => randomizeJsonLeaves(v));
  if (value !== null && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value)) {
      out[key] = randomizeJsonLeaves(value[key]);
    }
    return out;
  }
  if (typeof value === "string") {
    // Same character length, random hex content (a valid JSON string of equal length so the
    // serialized byte length is preserved leaf-for-leaf).
    if (value.length === 0) return "";
    const half = Math.ceil(value.length / 2);
    return crypto.randomBytes(half).toString("hex").slice(0, value.length);
  }
  if (typeof value === "number") {
    // Random digits of the SAME serialized length as the original (a leading non-zero digit
    // so it stays the same digit-length and is valid JSON). This preserves the serialized
    // byte length leaf-for-leaf so the structure re-serializes to ~the same length, leaving
    // only a small residual the filler leaf reconciles. Non-integers fall back to a random
    // same-length integer (the exact value is not secret-bearing shape).
    const digits = String(value).replace(/[^0-9]/g, "");
    const len = Math.max(1, digits.length);
    let out = String(1 + Math.floor(Math.random() * 9));
    for (let i = 1; i < len; i += 1) out += String(Math.floor(Math.random() * 10));
    return Number(out);
  }
  return value;
}

// Find the path to the LONGEST string leaf in a parsed JSON structure (the one with the most
// slack to grow/shrink for length reconciliation). Returns { container, key, length } or null
// when no string leaf exists. A string leaf is byte-length-tunable one-for-one (ASCII hex
// content), so resizing it lands the serialized byte length exactly without changing the
// grammar (same keys/nesting).
function findLongestStringLeaf(value) {
  let best = null;
  const visit = (container, key, v) => {
    if (typeof v === "string") {
      if (best == null || v.length > best.length) best = { container, key, length: v.length };
    } else if (Array.isArray(v)) {
      v.forEach((item, i) => visit(v, i, item));
    } else if (v !== null && typeof v === "object") {
      for (const k of Object.keys(v)) visit(v, k, v[k]);
    }
  };
  if (Array.isArray(value)) value.forEach((item, i) => visit(value, i, item));
  else if (value !== null && typeof value === "object") for (const k of Object.keys(value)) visit(value, k, value[k]);
  return best;
}

// Reconcile a randomized JSON structure's serialized byte length to EXACTLY targetLen by
// resizing its LONGEST string leaf (random hex content, one byte per char). The decoy stays
// valid JSON of the SAME grammar (same keys/nesting); only the chosen leaf's length changes.
// Because randomizeJsonLeaves preserves each leaf's serialized length, the residual is small
// and usually zero (the randomized object already equals targetLen). Returns a Buffer at the
// exact length, or null (caller falls back to the raw same-length floor) when no string leaf
// can absorb the residual.
function reconcileJsonByteLength(parsed, targetLen) {
  if (parsed === null || typeof parsed !== "object") {
    return null;
  }
  const asIs = Buffer.from(JSON.stringify(parsed), "utf8");
  if (asIs.length === targetLen) return asIs;
  const leaf = findLongestStringLeaf(parsed);
  if (leaf == null) return null;
  // Resizing the leaf string by N chars changes the serialized length by exactly N bytes.
  const delta = targetLen - asIs.length;
  const newLeafLen = leaf.length + delta;
  if (newLeafLen < 0) return null; // cannot shrink past empty
  const newContent = newLeafLen === 0
    ? ""
    : crypto.randomBytes(Math.ceil(newLeafLen / 2)).toString("hex").slice(0, newLeafLen);
  leaf.container[leaf.key] = newContent;
  const out = Buffer.from(JSON.stringify(parsed), "utf8");
  return out.length === targetLen ? out : null;
}

// Generate a SHAPE-MATCHED random decoy from the cause bytes: SAME byte length, SAME
// encoding class, RANDOM content. The decoy differs from the cause EXCLUSIVELY in content,
// so a gate can only reject it by validating that content. Returns a Buffer. Guaranteed
// (by the caller's post-gen distinctness assertion) not to equal the cause bytes.
function mintShapeMatchedDecoyBytes(causeBytes) {
  if (!Buffer.isBuffer(causeBytes) || causeBytes.length === 0) {
    // Degenerate cause — a zero-length consumable has no shape to match. Mint a small
    // non-empty random blob; byte-length parity against an empty cause is meaningless, and
    // the caller fails closed on a null/empty cause before reaching here.
    return crypto.randomBytes(32);
  }
  const targetLen = causeBytes.length;
  const cls = classifyConsumableShape(causeBytes);
  if (cls === "json") {
    let parsed = null;
    try {
      parsed = JSON.parse(causeBytes.toString("utf8"));
    } catch {
      parsed = null;
    }
    if (parsed !== null && typeof parsed === "object") {
      const randomized = randomizeJsonLeaves(parsed);
      const reconciled = reconcileJsonByteLength(randomized, targetLen);
      if (reconciled != null && reconciled.length === targetLen) return reconciled;
    }
    // Fall through to the raw floor when the JSON cannot be length-reconciled while staying
    // valid JSON of the same grammar (still same byte length, different content).
    return crypto.randomBytes(targetLen);
  }
  if (cls === "jwt") {
    return mintJwtShapedDecoy(causeBytes.toString("utf8"));
  }
  if (cls === "hex") {
    // Same hex char-length, random nibbles.
    const text = causeBytes.toString("utf8");
    const hex = crypto.randomBytes(Math.ceil(text.length / 2)).toString("hex").slice(0, text.length);
    return Buffer.from(hex, "utf8");
  }
  if (cls === "base64") {
    // Same base64 string length, random content. Generate random bytes and re-encode, then
    // size to the exact char length (base64 alphabet, valid padding preserved by slicing on
    // a 4-char boundary which the cause already satisfied).
    const text = causeBytes.toString("utf8");
    const rawLen = Math.ceil((text.length * 3) / 4);
    let b64 = crypto.randomBytes(rawLen).toString("base64");
    if (b64.length < text.length) b64 = b64.padEnd(text.length, "A");
    b64 = b64.slice(0, text.length);
    // classifyConsumableShape checks hex BEFORE base64 and the hex alphabet [0-9a-fA-F] is a
    // SUBSET of base64's, so a base64 string that is coincidentally all-hex (likely for a short
    // cause) would re-classify as 'hex' — a mint/verify divergence against the base64 cause (a
    // cause that classified base64 always has a non-hex char, else it would have classified hex
    // itself). Force one guaranteed-non-hex base64 char so the decoy always re-classifies base64.
    if (HEX_RE.test(b64) && b64.length > 0) {
      const arr = b64.split("");
      arr[crypto.randomBytes(1)[0] % arr.length] = NON_HEX_BASE64_CHARS[
        crypto.randomBytes(1)[0] % NON_HEX_BASE64_CHARS.length
      ];
      b64 = arr.join("");
    }
    return Buffer.from(b64, "utf8");
  }
  // raw — same byte length, random bytes.
  return crypto.randomBytes(targetLen);
}

// Build a syntactically valid JWT-shaped decoy: three base64url segments
// (header.payload.signature), randomized content, serialized to the SAME total byte length
// as the cause JWT (a structure-checking gate sees an identical three-segment shape; only
// the content differs). The signature segment is the length-tunable part: base64url chars
// are one byte each and a longer/shorter signature keeps the valid 3-segment JWT shape.
//
// The header segment is REUSED from the cause VERBATIM (its real alg/typ), never a fixed
// HS256 header. The JWT header carries the signature algorithm; a content-blind gate that
// branches on it (e.g. "only accept RS256") would HOLD the decoy on an alg TELL rather than
// on credential validation — and a decoy that holds for a shape reason proves nothing about
// content-validation, defeating the decoy-relevance arm. The header is structural metadata,
// not the captured secret (which lives in the signature/claims that ARE randomized), so
// reusing it is safe and removes the tell: cause and decoy now differ only in credential
// content. The fixed HS256 header survives only as a fallback for a non-3-segment input,
// which classifyConsumableShape (cls === "jwt") already excludes.
function mintJwtShapedDecoy(causeText) {
  const targetLen = Buffer.byteLength(causeText, "utf8");
  const b64url = (buf) => Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const causeSegments = causeText.split(".");
  const HEADER = causeSegments.length === 3 && causeSegments[0]
    ? causeSegments[0]
    : b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  // A minimal randomized payload (real-shaped claims, random values). Keep it small so the
  // signature segment carries the length slack.
  const PAYLOAD = b64url(JSON.stringify({ sub: crypto.randomBytes(6).toString("hex"), iat: 1 }));
  // The fixed prefix "<header>.<payload>." plus at least a 1-char signature.
  const prefix = `${HEADER}.${PAYLOAD}.`;
  const prefixLen = Buffer.byteLength(prefix, "utf8");
  const sigLen = targetLen - prefixLen;
  if (sigLen < 1) {
    // The cause JWT is shorter than our minimal header.payload. — cannot keep a valid
    // 3-segment shape at this length; fall back to raw same-length (byte-length parity holds).
    return crypto.randomBytes(targetLen);
  }
  // base64url signature of exactly sigLen chars (random alphabet content).
  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let sig = "";
  const rnd = crypto.randomBytes(sigLen);
  for (let i = 0; i < sigLen; i += 1) sig += ALPHABET[rnd[i] % ALPHABET.length];
  return Buffer.from(`${prefix}${sig}`, "utf8");
}

module.exports = {
  classifyConsumableShape,
  mintShapeMatchedDecoyBytes,
};
