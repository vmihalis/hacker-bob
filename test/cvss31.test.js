"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { deriveCvss31, roundup, severityBand, normalizeCvssInputs } = require("../mcp/lib/cvss31.js");
const { classifyCvss } = require("../mcp/lib/cve-feed-parser.js");
const fs = require("fs");
const path = require("path");

// FIRST.org CVSS v3.1 base-score reference vectors. Each must derive to the
// exact published score, qualitative band, and canonical vector string.
const REFERENCE = [
  {
    facts: { attack_vector: "N", attack_complexity: "L", privileges_required: "N", user_interaction: "N", scope: "U", confidentiality: "H", integrity: "H", availability: "H" },
    score: 9.8,
    band: "critical",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  },
  {
    facts: { attack_vector: "N", attack_complexity: "L", privileges_required: "N", user_interaction: "N", scope: "U", confidentiality: "H", integrity: "N", availability: "N" },
    score: 7.5,
    band: "high",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  },
  {
    facts: { attack_vector: "N", attack_complexity: "L", privileges_required: "N", user_interaction: "R", scope: "C", confidentiality: "L", integrity: "L", availability: "N" },
    score: 6.1,
    band: "medium",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
  },
  {
    facts: { attack_vector: "N", attack_complexity: "L", privileges_required: "L", user_interaction: "N", scope: "U", confidentiality: "H", integrity: "N", availability: "N" },
    score: 6.5,
    band: "medium",
    vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
  },
  {
    facts: { attack_vector: "N", attack_complexity: "L", privileges_required: "N", user_interaction: "N", scope: "C", confidentiality: "H", integrity: "H", availability: "H" },
    score: 10.0,
    band: "critical",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  },
  {
    facts: { attack_vector: "N", attack_complexity: "L", privileges_required: "N", user_interaction: "N", scope: "U", confidentiality: "N", integrity: "N", availability: "N" },
    score: 0.0,
    band: "none",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
  },
  {
    // Physical attack, high complexity, high privileges, scope unchanged, low integrity only.
    facts: { attack_vector: "P", attack_complexity: "H", privileges_required: "H", user_interaction: "R", scope: "U", confidentiality: "N", integrity: "L", availability: "N" },
    score: 1.6,
    band: "low",
    vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N",
  },
];

test("deriveCvss31 matches FIRST.org reference vectors exactly", () => {
  for (const ref of REFERENCE) {
    const r = deriveCvss31(ref.facts);
    assert.equal(r.insufficient, undefined, `${ref.vector} should derive a score`);
    assert.equal(r.version, "3.1");
    assert.equal(r.base_score, ref.score, `score for ${ref.vector}`);
    assert.equal(r.severity_band, ref.band, `band for ${ref.vector}`);
    assert.equal(r.vector, ref.vector);
  }
});

test("derived_from records all eight base metrics in long form", () => {
  const r = deriveCvss31(REFERENCE[0].facts);
  assert.equal(r.derived_from.length, 8);
  assert.ok(r.derived_from.includes("attack_vector=network"));
  assert.ok(r.derived_from.includes("privileges_required=none"));
  assert.ok(r.derived_from.includes("availability=high"));
});

test("roundup uses the spec integer method (smallest 1-decimal >= input)", () => {
  assert.equal(roundup(0.0), 0);
  assert.equal(roundup(4.0), 4);
  assert.equal(roundup(4.02), 4.1);
  assert.equal(roundup(6.43), 6.5);
  assert.equal(roundup(7.5), 7.5);
  // floating point that would mis-round under naive Math.round
  assert.equal(roundup(4.005), 4.1);
});

test("severity_band reuses classifyCvss thresholds, mapping informational -> none", () => {
  assert.equal(severityBand(9.0), "critical");
  assert.equal(severityBand(7.0), "high");
  assert.equal(severityBand(4.0), "medium");
  assert.equal(severityBand(0.1), "low");
  assert.equal(severityBand(0.0), "none");
  // parity with the shared classifier for every non-zero band
  for (const s of [9.8, 7.5, 6.1, 0.5]) {
    assert.equal(severityBand(s), classifyCvss(s));
  }
  // only the bottom band label is adapted
  assert.equal(classifyCvss(0.0), "informational");
  assert.equal(severityBand(0.0), "none");
});

test("metric enums accept long names, single letters, casing, and numeric AV", () => {
  const long = deriveCvss31({ attack_vector: "Network", attack_complexity: "low", privileges_required: "None", user_interaction: "none", scope: "Unchanged", confidentiality: "High", integrity: "high", availability: "HIGH" });
  assert.equal(long.vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  assert.equal(long.base_score, 9.8);
  const aliased = deriveCvss31({ attack_vector: "adjacent-network", attack_complexity: "h", privileges_required: "l", user_interaction: "req", scope: "c", confidentiality: "l", integrity: "n", availability: "n" });
  assert.equal(aliased.vector, "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N");
});

test("attack_complexity, user_interaction, and scope default when omitted", () => {
  const r = deriveCvss31({ attack_vector: "N", privileges_required: "N", confidentiality: "H", integrity: "H", availability: "H" });
  assert.equal(r.vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  assert.equal(r.base_score, 9.8);
});

test("partial impact: an absent impact dimension defaults to None when another is present", () => {
  const r = deriveCvss31({ attack_vector: "N", privileges_required: "N", confidentiality: "H" });
  assert.equal(r.vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  assert.equal(r.base_score, 7.5);
});

test("scope=changed raises the PR weight for Low and High privileges", () => {
  const unchanged = deriveCvss31({ attack_vector: "N", attack_complexity: "L", privileges_required: "L", user_interaction: "N", scope: "U", confidentiality: "H", integrity: "H", availability: "H" });
  const changed = deriveCvss31({ attack_vector: "N", attack_complexity: "L", privileges_required: "L", user_interaction: "N", scope: "C", confidentiality: "H", integrity: "H", availability: "H" });
  assert.ok(changed.base_score > unchanged.base_score, "scope change should raise the score");
});

test("deriveCvss31 is total: garbage and insufficient facts yield a marker, never a throw", () => {
  for (const bad of [null, undefined, "garbage", 42, [], { foo: "bar" }]) {
    const r = deriveCvss31(bad);
    assert.equal(r.insufficient, true, `marker for ${JSON.stringify(bad)}`);
    assert.equal(r.version, "3.1");
    assert.ok(typeof r.reason === "string" && r.reason.length > 0);
    assert.deepEqual(r.derived_from, []);
  }
});

test("missing attack_vector, privileges, or all impact returns an explicit marker", () => {
  assert.equal(deriveCvss31({ privileges_required: "N", confidentiality: "H" }).insufficient, true);
  assert.equal(deriveCvss31({ attack_vector: "N", confidentiality: "H" }).insufficient, true);
  assert.equal(deriveCvss31({ attack_vector: "N", privileges_required: "N" }).insufficient, true);
});

test("normalizeCvssInputs is strict on write (throws) but tolerant on read-back (skips unknown)", () => {
  // strict (default = write path): an unknown key or value throws so a malformed
  // enum can never be persisted.
  assert.throws(() => normalizeCvssInputs({ attack_vector: "network", bogus_metric: "x" }));
  assert.throws(() => normalizeCvssInputs({ attack_vector: "interplanetary" }));
  // tolerant (strict:false = read-back projection): an unknown key/value is
  // SKIPPED and the recognizable metrics still project, so a persisted finding
  // whose cvss_inputs predate/postdate the current spec is never silently dropped.
  assert.deepEqual(
    normalizeCvssInputs(
      { attack_vector: "network", privileges_required: "low", future_metric: "x" },
      "cvss_inputs",
      { strict: false },
    ),
    { attack_vector: "network", privileges_required: "low" },
  );
  // When nothing recognizable survives, tolerant returns null (not a throw).
  assert.equal(normalizeCvssInputs({ attack_vector: "garbage" }, "cvss_inputs", { strict: false }), null);
});

test("CVSS banding is shared so cvss31 does not depend on the CVE feed parser", () => {
  // Dependency-direction fix: both surfaces import classifyCvss from the
  // dependency-free cvss-bands.js; cvss31.js no longer requires cve-feed-parser.
  const bands = require("../mcp/lib/cvss-bands.js");
  assert.equal(bands.classifyCvss, classifyCvss, "cve-feed-parser must re-export the shared classifyCvss");
  const src = fs.readFileSync(path.join(__dirname, "..", "mcp", "lib", "cvss31.js"), "utf8");
  assert.match(src, /require\("\.\/cvss-bands\.js"\)/);
  assert.doesNotMatch(src, /require\("\.\/cve-feed-parser\.js"\)/);
});
