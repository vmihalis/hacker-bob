"use strict";

// Pure, total, deterministic CVSS v3.1 base-score derivation. Given a set of
// structured impact facts (enums) it produces the canonical vector string, the
// base score, and the severity band. It never throws: insufficient or garbage
// facts yield an explicit insufficient marker instead.
//
// Banding thresholds are NOT duplicated here. The numeric cut points
// (>=9.0 critical, >=7.0 high, >=4.0 medium, >0 low, else bottom band) live in
// the dependency-free cvss-bands.js classifyCvss and are reused so every surface
// shares one definition and cannot drift. The only adaptation is the bottom-band
// label: the CVSS v3.1 spec names the 0.0 band "none", so classifyCvss's
// "informational" result is mapped to "none" here for severity_band parity with
// the spec's qualitative scale.

const { classifyCvss } = require("./cvss-bands.js");

// FIRST.org CVSS v3.1 base metric weights.
const AV_WEIGHTS = Object.freeze({ N: 0.85, A: 0.62, L: 0.55, P: 0.20 });
const AC_WEIGHTS = Object.freeze({ L: 0.77, H: 0.44 });
const UI_WEIGHTS = Object.freeze({ N: 0.85, R: 0.62 });
const CIA_WEIGHTS = Object.freeze({ H: 0.56, L: 0.22, N: 0.00 });
// Privileges Required is scope-sensitive: Low and High weigh more when the
// vulnerable component can affect resources beyond its security scope.
const PR_WEIGHTS = Object.freeze({
  N: Object.freeze({ U: 0.85, C: 0.85 }),
  L: Object.freeze({ U: 0.62, C: 0.68 }),
  H: Object.freeze({ U: 0.27, C: 0.50 }),
});

// Canonical single-letter code -> long enum name, for the derived_from trail.
const AV_NAMES = Object.freeze({ N: "network", A: "adjacent", L: "local", P: "physical" });
const AC_NAMES = Object.freeze({ L: "low", H: "high" });
const PR_NAMES = Object.freeze({ N: "none", L: "low", H: "high" });
const UI_NAMES = Object.freeze({ N: "none", R: "required" });
const SCOPE_NAMES = Object.freeze({ U: "unchanged", C: "changed" });
const CIA_NAMES = Object.freeze({ H: "high", L: "low", N: "none" });

// Alias tables map every accepted spelling (long name, single letter, common
// synonyms) to the canonical single-letter metric code.
const AV_ALIASES = buildAliases({
  N: ["n", "network"],
  A: ["a", "adjacent", "adjacentnetwork", "adjacent_network", "adjacent-network"],
  L: ["l", "local"],
  P: ["p", "physical"],
});
const AC_ALIASES = buildAliases({
  L: ["l", "low"],
  H: ["h", "high"],
});
const PR_ALIASES = buildAliases({
  N: ["n", "none"],
  L: ["l", "low"],
  H: ["h", "high"],
});
const UI_ALIASES = buildAliases({
  N: ["n", "none"],
  R: ["r", "required", "req"],
});
const SCOPE_ALIASES = buildAliases({
  U: ["u", "unchanged"],
  C: ["c", "changed"],
});
const CIA_ALIASES = buildAliases({
  H: ["h", "high"],
  L: ["l", "low"],
  N: ["n", "none"],
});

function buildAliases(spec) {
  const out = Object.create(null);
  for (const code of Object.keys(spec)) {
    for (const alias of spec[code]) {
      out[alias] = code;
    }
  }
  return Object.freeze(out);
}

function normalizeToken(value) {
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (typeof value !== "string") return null;
  const trimmed = value.trim().toLowerCase();
  return trimmed.length ? trimmed : null;
}

function resolveMetric(value, aliases) {
  const token = normalizeToken(value);
  if (token == null) return null;
  const code = aliases[token];
  return code || null;
}

// Defaults documented in the task: a caller may supply only AV/PR/C/I/A.
const DEFAULTS = Object.freeze({
  attack_complexity: "L",
  user_interaction: "N",
  scope: "U",
});

function insufficient(reason) {
  return Object.freeze({
    version: "3.1",
    insufficient: true,
    reason,
    derived_from: Object.freeze([]),
  });
}

// CVSS v3.1 spec roundup: smallest 1-decimal value >= input, computed via the
// integer method so floating-point representation cannot perturb the result.
function roundup(input) {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) {
    return intInput / 100000;
  }
  return (Math.floor(intInput / 10000) + 1) / 10;
}

function isInsufficientFacts(facts) {
  return facts == null || typeof facts !== "object" || Array.isArray(facts);
}

// deriveCvss31(facts) -> derived result | insufficient marker. Total: any input,
// including null/garbage, returns a frozen object and never throws.
function deriveCvss31(facts) {
  if (isInsufficientFacts(facts)) {
    return insufficient("facts must be an object of CVSS metric enums");
  }

  const av = resolveMetric(facts.attack_vector, AV_ALIASES);
  const ac = resolveMetric(facts.attack_complexity, AC_ALIASES) || DEFAULTS.attack_complexity;
  const pr = resolveMetric(facts.privileges_required, PR_ALIASES);
  const ui = resolveMetric(facts.user_interaction, UI_ALIASES) || DEFAULTS.user_interaction;
  const scope = resolveMetric(facts.scope, SCOPE_ALIASES) || DEFAULTS.scope;
  const c = resolveMetric(facts.confidentiality, CIA_ALIASES);
  const i = resolveMetric(facts.integrity, CIA_ALIASES);
  const a = resolveMetric(facts.availability, CIA_ALIASES);

  // Without an attack vector there is no exploitability signal to anchor.
  if (av == null) {
    return insufficient("no recognizable attack_vector signal");
  }
  // Privileges Required has no documented default; it is a core exploitability
  // input and must be evidence-derived.
  if (pr == null) {
    return insufficient("no recognizable privileges_required signal");
  }
  // At least one impact dimension must be present; all-absent impact cannot
  // produce a meaningful base vector.
  if (c == null && i == null && a == null) {
    return insufficient("no recognizable impact metrics (confidentiality/integrity/availability)");
  }

  // Absent-but-present-elsewhere impact dimensions default to None per the
  // partial-impact convention (a finding may demonstrate only C, only I, etc.).
  const cCode = c || "N";
  const iCode = i || "N";
  const aCode = a || "N";

  const cw = CIA_WEIGHTS[cCode];
  const iw = CIA_WEIGHTS[iCode];
  const aw = CIA_WEIGHTS[aCode];

  const iss = 1 - (1 - cw) * (1 - iw) * (1 - aw);
  const impact = scope === "U"
    ? 6.42 * iss
    : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);

  const exploitability = 8.22
    * AV_WEIGHTS[av]
    * AC_WEIGHTS[ac]
    * PR_WEIGHTS[pr][scope]
    * UI_WEIGHTS[ui];

  let baseScore;
  if (impact <= 0) {
    baseScore = 0.0;
  } else if (scope === "U") {
    baseScore = roundup(Math.min(impact + exploitability, 10));
  } else {
    baseScore = roundup(Math.min(1.08 * (impact + exploitability), 10));
  }

  const vector = `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${scope}/C:${cCode}/I:${iCode}/A:${aCode}`;

  return Object.freeze({
    version: "3.1",
    vector,
    base_score: baseScore,
    severity_band: severityBand(baseScore),
    derived_from: Object.freeze([
      `attack_vector=${AV_NAMES[av]}`,
      `attack_complexity=${AC_NAMES[ac]}`,
      `privileges_required=${PR_NAMES[pr]}`,
      `user_interaction=${UI_NAMES[ui]}`,
      `scope=${SCOPE_NAMES[scope]}`,
      `confidentiality=${CIA_NAMES[cCode]}`,
      `integrity=${CIA_NAMES[iCode]}`,
      `availability=${CIA_NAMES[aCode]}`,
    ]),
  });
}

// Maps a base score to a CVSS qualitative band. The numeric thresholds come from
// the shared classifyCvss (no duplicated literals); only the bottom-band label
// is adapted to the CVSS spec's "none".
function severityBand(score) {
  const band = classifyCvss(score);
  return band === "informational" ? "none" : band;
}

// The structured-input vocabulary: each cvss_inputs key maps to its alias table
// and the canonical-code -> long-name table. This is the single source of truth
// for what the claim schema accepts; the schema description and the normalizer
// both read it so they cannot drift. Persisted inputs store the canonical long
// name (e.g. "network", "high") so the hashed finding carries a stable,
// human-legible enum that deriveCvss31 re-resolves identically at report time.
const CVSS_INPUT_SPEC = Object.freeze({
  attack_vector: { aliases: AV_ALIASES, names: AV_NAMES },
  attack_complexity: { aliases: AC_ALIASES, names: AC_NAMES },
  privileges_required: { aliases: PR_ALIASES, names: PR_NAMES },
  user_interaction: { aliases: UI_ALIASES, names: UI_NAMES },
  scope: { aliases: SCOPE_ALIASES, names: SCOPE_NAMES },
  confidentiality: { aliases: CIA_ALIASES, names: CIA_NAMES },
  integrity: { aliases: CIA_ALIASES, names: CIA_NAMES },
  availability: { aliases: CIA_ALIASES, names: CIA_NAMES },
});

const CVSS_INPUT_KEYS = Object.freeze(Object.keys(CVSS_INPUT_SPEC));

// Accepted long-name enum values per key, for schema enums and operator docs.
const CVSS_INPUT_ENUMS = Object.freeze(
  CVSS_INPUT_KEYS.reduce((acc, key) => {
    const { names } = CVSS_INPUT_SPEC[key];
    acc[key] = Object.freeze(Object.values(names));
    return acc;
  }, Object.create(null)),
);

// normalizeCvssInputs(value) -> { canonical cvss_inputs object } | null.
// Validates each supplied key against its alias table and REJECTS (throws) on
// any unknown value so a malformed enum cannot be silently persisted. Returns
// null when nothing recognizable was supplied (an empty/absent object). Unknown
// top-level keys are rejected. The returned object stores canonical long-name
// strings only for keys the caller actually provided — deriveCvss31's own
// defaults (AC=low, UI=none, S=unchanged) stay implicit so we never invent
// facts the caller did not assert.
// strict (default, write path): reject (throw) on any unknown key or value so a
// malformed enum can never be persisted. strict=false (read-back projection):
// mirror assertCwe({ strictPresent:false }) — a present-but-unrecognized key or
// value is SKIPPED rather than thrown, so a persisted finding whose cvss_inputs
// predates or postdates the current CVSS_INPUT_SPEC (e.g. a metric key renamed
// or removed in a future schema) still projects with its recognizable metrics
// instead of being silently dropped from every read by a caller's catch.
function normalizeCvssInputs(value, fieldName = "cvss_inputs", { strict = true } = {}) {
  if (value == null) return null;
  if (typeof value !== "object" || Array.isArray(value)) {
    if (!strict) return null;
    throw new Error(`${fieldName} must be an object of CVSS v3.1 metric enums`);
  }
  const out = {};
  for (const key of Object.keys(value)) {
    if (value[key] == null) continue;
    const spec = CVSS_INPUT_SPEC[key];
    if (!spec) {
      if (!strict) continue;
      throw new Error(`${fieldName}.${key} is not a recognized CVSS v3.1 metric (allowed: ${CVSS_INPUT_KEYS.join(", ")})`);
    }
    const token = normalizeToken(value[key]);
    const code = token == null ? null : spec.aliases[token];
    if (!code) {
      if (!strict) continue;
      throw new Error(`${fieldName}.${key} ${JSON.stringify(value[key])} is not a valid value (allowed: ${CVSS_INPUT_ENUMS[key].join(", ")})`);
    }
    out[key] = spec.names[code];
  }
  return Object.keys(out).length ? out : null;
}

module.exports = {
  deriveCvss31,
  normalizeCvssInputs,
  roundup,
  severityBand,
  CVSS_INPUT_KEYS,
  CVSS_INPUT_ENUMS,
};
