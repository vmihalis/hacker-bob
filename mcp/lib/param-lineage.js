"use strict";

// param-lineage — stateful parameter lineage as DUMB, PURE dataflow.
//
// Two exports, both pure functions of their inputs (no network, no state store,
// no belief/causal graph, no clock, no randomness, no I/O):
//
//   extractIds(responseBody, { contentType })
//     Harvest candidate id key->value pairs from profile A's real 2xx JSON body
//     (uuids, numeric ids, long opaque/hex ids echoed at id-shaped keys). The
//     values returned are LITERALLY present in the parsed body — never synthesized.
//
//   bindLineage(endpointTemplate, extracted)
//     Fill the `:id`/`{id}` slots of a route's id_bearing endpoint template with
//     values harvested by extractIds, so a profile-B differential reaches the auth
//     check instead of 404ing on a dead id. Unfillable slot -> empty (never a
//     partial or fabricated URL).
//
// HONESTY (the raison d'etre, mirroring offensive-idor-producer's canary rule):
// a value only ever appears in the output if it was literally present in the input
// body. No harvested value that fits a required slot -> empty result, never a
// guessed id. This is the same "no fabricated id" contract the id_bearing sweep
// depends on.
//
// REUSE-NOT-FORK: the canonical id-bearing template form (every id segment
// collapsed to `{id}`) is obtained SOLELY from the exported templatizeIdBearingEndpoint
// so the notion of "what counts as an id-bearing template" stays single-sourced with
// claims.js and agent-run-completion.js. This module never re-derives segment-collapse
// logic; it only consumes the canonical string that helper returns.

const { templatizeIdBearingEndpoint } = require("./offensive-idor-producer.js");

// Bounded tree-walk budgets — mirror the visit() pattern in
// offensive-massread-producer.js's subjectIdentifierSet so a hostile/huge body
// cannot drive unbounded work. Pure constants, no ambient state.
const MAX_DEPTH = 8;
const MAX_NODES = 512;
// Defensive ceiling on the number of concrete endpoints bindLineage emits, applied
// deterministically AFTER dedupe+sort so it can never non-deterministically drop a
// viable binding. In practice the harvested map and slot count are tiny; this only
// guards a pathological multi-slot cross product.
const MAX_BINDINGS = 256;

// Tokenize a key/segment name into lowercase word tokens, splitting on non-alnum AND
// camelCase/Pascal boundaries (userId -> ["user","id"], order_id -> ["order","id"]).
// Local to this module (a few-line lexical helper, not the segment-collapse logic that
// must stay single-sourced in offensive-idor-producer.js).
function tokenize(name) {
  return String(name)
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

// Generic (noun-less) id tokens — a key made up ONLY of these is a "generic id"
// usable as a fallback for any slot (id, uuid, guid, slug).
const GENERIC_ID_TOKENS = new Set(["id", "uuid", "guid", "slug"]);

// A KEY is id-shaped iff any of its tokens is an id token (id / uuid / guid / slug):
// catches `id`, `order_id`, `orderId`, `user_uuid`, `slug`. Token-based (not substring)
// so `grid` / `validity` / `video` do NOT match.
function keyIsIdShaped(name) {
  return tokenize(name).some((t) => GENERIC_ID_TOKENS.has(t));
}

// A key whose EVERY token is a generic id token (id / uuid / guid / slug) — no
// specific noun. Used as the fallback candidate set when a slot's preceding path noun
// matches nothing.
function keyIsGenericId(name) {
  const tokens = tokenize(name);
  return tokens.length > 0 && tokens.every((t) => GENERIC_ID_TOKENS.has(t));
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NUMERIC_ID_RE = /^[0-9]{1,19}$/;
const HEX_ID_RE = /^(?:0x)?[0-9a-f]{16,}$/i;
// A long opaque token (nanoid / base64url-ish / stripe-style), >= 16 chars, no spaces
// or path-breaking punctuation. The leading char is alnum so a lone separator run is
// rejected.
const OPAQUE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._~-]{15,}$/;

// Is `value` a usable, id-SHAPED value literally present in the body? Returns the
// harvested string form (never a synthesized value) or null. Accepts a safe-integer
// number, a canonical uuid, a pure-numeric string, a long hex/0x string, or a long
// opaque token. Everything else (floats, short slugs, words, objects) -> null.
function idShapedValue(value) {
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value >= 0 ? String(value) : null;
  }
  if (typeof value !== "string") return null;
  const s = value.trim();
  if (!s) return null;
  if (UUID_RE.test(s) || NUMERIC_ID_RE.test(s) || HEX_ID_RE.test(s) || OPAQUE_ID_RE.test(s)) {
    return s;
  }
  return null;
}

// True when contentType is present and clearly NOT JSON (fail closed on it). Absent /
// blank contentType is treated as unknown and does NOT gate (the body itself is still
// JSON.parsed and fails closed on a parse error).
function contentTypeIsNonJson(contentType) {
  if (typeof contentType !== "string" || contentType.trim() === "") return false;
  return !/json/i.test(contentType);
}

// extractIds(responseBody, { contentType }) -> deterministic map of harvested id
// key->value pairs. Accepts a JSON string OR an already-parsed object/array. Fails
// closed (returns {}) on a non-JSON contentType, an unparseable/empty string, or a
// non-object input — NEVER throws, NEVER synthesizes a value.
function extractIds(responseBody, { contentType } = {}) {
  if (contentTypeIsNonJson(contentType)) return {};

  let parsed;
  if (typeof responseBody === "string") {
    if (responseBody.trim() === "") return {};
    try {
      parsed = JSON.parse(responseBody);
    } catch {
      return {};
    }
  } else if (responseBody !== null && typeof responseBody === "object") {
    parsed = responseBody;
  } else {
    return {};
  }

  // Bounded tree-walk. First-seen-wins on a duplicate bare key name (the retained
  // VALUE is stable for a given input); emission order is canonicalized by sorting the
  // keys below, so the returned map is byte-identical regardless of source sibling order.
  const harvested = Object.create(null);
  let nodeBudget = MAX_NODES;
  const visit = (node, depth) => {
    if (node == null || typeof node !== "object" || depth > MAX_DEPTH || nodeBudget <= 0) return;
    if (Array.isArray(node)) {
      for (const item of node) {
        if (nodeBudget <= 0) return;
        visit(item, depth + 1);
      }
      return;
    }
    for (const key of Object.keys(node)) {
      if (nodeBudget <= 0) return;
      nodeBudget -= 1;
      const value = node[key];
      if (keyIsIdShaped(key) && !Object.prototype.hasOwnProperty.call(harvested, key)) {
        const idValue = idShapedValue(value);
        if (idValue != null) harvested[key] = idValue; // literal value, first-seen wins
      }
      if (value && typeof value === "object") visit(value, depth + 1);
    }
  };
  visit(parsed, 0);

  const out = {};
  for (const key of Object.keys(harvested).sort()) out[key] = harvested[key];
  return out;
}

// Deterministic, minimal singularizer for path-noun matching (orders -> order,
// categories -> category, addresses -> address). Pure string transform.
function singularize(noun) {
  const n = String(noun).toLowerCase();
  if (n.length > 3 && n.endsWith("ies")) return `${n.slice(0, -3)}y`;
  if (n.length > 3 && n.endsWith("ses")) return n.slice(0, -2);
  if (n.length > 2 && n.endsWith("s") && !n.endsWith("ss")) return n.slice(0, -1);
  return n;
}

// Does a harvested KEY name reference the slot's preceding path NOUN? (/orders/{id}
// <- order_id / orderId / order). Compares tokens against the noun and its singular
// form, both directions singularized, so plural/singular spellings line up.
function keyMatchesNoun(key, noun) {
  if (!noun) return false;
  const nounForms = new Set([noun.toLowerCase(), singularize(noun)]);
  return tokenize(key).some((t) => nounForms.has(t) || nounForms.has(singularize(t)));
}

// Coerce a harvested value into a single clean path segment, or null if it cannot be
// one. The value is used VERBATIM (no encoding that would alter the literal id); only
// values that are already safe single segments survive.
function toPathSegment(value) {
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value >= 0 ? String(value) : null;
  }
  if (typeof value !== "string") return null;
  const s = value.trim();
  if (s === "") return null;
  if (/[\s/\\?#%]/.test(s)) return null;
  return s;
}

// The sorted, deduped set of path-safe candidate values for one {id} slot. PREFER
// keys whose name matches the slot's preceding path noun; only if none match, FALL
// BACK to generic id keys. Returns [] when nothing viable -> the slot is unfillable.
function slotCandidateValues(extracted, precedingNoun) {
  const keys = Object.keys(extracted).sort();
  let picked = [];
  if (precedingNoun) {
    picked = keys.filter((k) => keyMatchesNoun(k, precedingNoun));
  }
  if (picked.length === 0) {
    picked = keys.filter((k) => keyIsGenericId(k));
  }
  const values = [];
  for (const k of picked) {
    const seg = toPathSegment(extracted[k]);
    if (seg != null) values.push(seg);
  }
  return Array.from(new Set(values)).sort();
}

// bindLineage(endpointTemplate, extracted) -> sorted, deduped array of concrete
// in-path endpoints with every id slot filled from `extracted`. Reuses
// templatizeIdBearingEndpoint to canonicalize BOTH `:id` and `{id}` spellings to the
// single `{id}` form (single source of truth). Every slot is resolved deterministically;
// an unfillable slot yields [] (never a partial or fabricated URL).
function bindLineage(endpointTemplate, extracted) {
  const canonical = templatizeIdBearingEndpoint(endpointTemplate);
  if (typeof canonical !== "string") return [];
  if (extracted === null || typeof extracted !== "object" || Array.isArray(extracted)) return [];

  const segments = canonical.split("/").filter(Boolean);
  const slotPositions = [];
  segments.forEach((seg, i) => {
    if (seg === "{id}") slotPositions.push(i);
  });
  if (slotPositions.length === 0) return [];

  const perSlotValues = slotPositions.map((pos) => {
    const prev = pos > 0 ? segments[pos - 1] : "";
    const precedingNoun = prev === "{id}" ? "" : prev; // adjacent slot is not a noun
    return slotCandidateValues(extracted, precedingNoun);
  });
  // Any slot with no viable value makes the WHOLE binding unfillable — honest empty,
  // never a partial URL with a dangling {id} or a mis-borrowed value.
  if (perSlotValues.some((vals) => vals.length === 0)) return [];

  // Deterministic cross product of per-slot candidate values (each list is sorted).
  let combos = [[]];
  for (const vals of perSlotValues) {
    const next = [];
    for (const combo of combos) {
      for (const v of vals) {
        next.push([...combo, v]);
        if (next.length >= MAX_BINDINGS) break;
      }
      if (next.length >= MAX_BINDINGS) break;
    }
    combos = next;
  }

  const endpoints = new Set();
  for (const combo of combos) {
    const filled = segments.slice();
    slotPositions.forEach((pos, k) => {
      filled[pos] = combo[k];
    });
    endpoints.add(`/${filled.join("/")}`);
  }
  return Array.from(endpoints).sort().slice(0, MAX_BINDINGS);
}

module.exports = {
  extractIds,
  bindLineage,
};
