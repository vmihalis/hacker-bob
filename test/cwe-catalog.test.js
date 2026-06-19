"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const {
  CWE_CATALOG,
  SMART_CONTRACT_FAMILY_CWE,
  OSS_IMPACT_CLASS_CWE,
  canonicalizeCwe,
  isKnownCwe,
  assertValidCwe,
  cweTitle,
} = require("../mcp/lib/cwe-catalog.js");

test("canonicalizeCwe normalizes string, lowercase, bare-number, and numeric inputs", () => {
  assert.equal(canonicalizeCwe("CWE-79"), "CWE-79");
  assert.equal(canonicalizeCwe("cwe-79"), "CWE-79");
  assert.equal(canonicalizeCwe("79"), "CWE-79");
  assert.equal(canonicalizeCwe(79), "CWE-79");
  assert.equal(canonicalizeCwe(" CWE-79 "), "CWE-79");
  assert.equal(canonicalizeCwe("cwe_79"), "CWE-79");
});

test("canonicalizeCwe is idempotent on already-canonical input", () => {
  for (const id of Object.keys(CWE_CATALOG)) {
    assert.equal(canonicalizeCwe(id), id, `${id} must canonicalize to itself`);
    assert.equal(canonicalizeCwe(canonicalizeCwe(id)), id, `${id} double-canonicalization must be stable`);
  }
});

test("canonicalizeCwe returns null for unparseable input", () => {
  assert.equal(canonicalizeCwe(null), null);
  assert.equal(canonicalizeCwe(undefined), null);
  assert.equal(canonicalizeCwe(""), null);
  assert.equal(canonicalizeCwe("   "), null);
  assert.equal(canonicalizeCwe("not-a-cwe"), null);
  assert.equal(canonicalizeCwe("CWE-"), null);
  assert.equal(canonicalizeCwe("CWE-79x"), null);
  assert.equal(canonicalizeCwe({}), null);
  assert.equal(canonicalizeCwe(-1), null);
  assert.equal(canonicalizeCwe(1.5), null);
});

test("assertValidCwe accepts every seeded catalog id", () => {
  for (const id of Object.keys(CWE_CATALOG)) {
    assert.equal(assertValidCwe(id), id);
  }
});

test("assertValidCwe accepts non-canonical forms of seeded ids and returns canonical", () => {
  assert.equal(assertValidCwe("cwe-79"), "CWE-79");
  assert.equal(assertValidCwe("79"), "CWE-79");
  assert.equal(assertValidCwe(639), "CWE-639");
});

test("assertValidCwe rejects bad-format ids", () => {
  assert.throws(() => assertValidCwe("not-a-cwe"), /CWE identifier/);
  assert.throws(() => assertValidCwe("CWE-"), /CWE identifier/);
  assert.throws(() => assertValidCwe(null), /CWE identifier/);
  assert.throws(() => assertValidCwe(""), /CWE identifier/);
});

test("assertValidCwe rejects well-formed but unknown ids", () => {
  assert.equal(isKnownCwe("CWE-999999"), false);
  assert.throws(() => assertValidCwe("CWE-999999"), /not in the curated CWE catalog/);
  assert.throws(() => assertValidCwe("CWE-602"), /not in the curated CWE catalog/);
});

test("isKnownCwe tracks the catalog and tolerates non-canonical forms", () => {
  assert.equal(isKnownCwe("CWE-79"), true);
  assert.equal(isKnownCwe("cwe-79"), true);
  assert.equal(isKnownCwe(79), true);
  assert.equal(isKnownCwe("CWE-999999"), false);
  assert.equal(isKnownCwe("garbage"), false);
  assert.equal(isKnownCwe(null), false);
});

test("cweTitle returns a title for known ids and null otherwise", () => {
  assert.equal(typeof cweTitle("CWE-79"), "string");
  assert.equal(cweTitle("cwe-79"), CWE_CATALOG["CWE-79"]);
  assert.equal(cweTitle("CWE-999999"), null);
  assert.equal(cweTitle("garbage"), null);
});

// Intentional negative fixtures: ids referenced in tests precisely because they
// are NOT in the catalog (assertValidCwe / write-path rejection coverage). They
// must be excluded from the completeness sweep below.
// CWE-0 is not a real id: the /CWE-[0-9]+/ sweep matches the literal "CWE-0"
// inside the regex /^CWE-0?22$/ in static-analysis-index.test.js (an optional
// leading zero on CWE-22). Treat it as a scan artifact, not a seedable id.
const NEGATIVE_CWE_FIXTURES = new Set(["CWE-0", "CWE-602", "CWE-999999"]);

function collectReferencedCwes(dir) {
  const ids = new Set();
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        walk(full);
        continue;
      }
      if (!entry.isFile()) continue;
      const text = fs.readFileSync(full, "utf8");
      // Case-insensitive so lowercase/mixed-case references (e.g. "cwe-79") are
      // also caught and can't slip an unseeded id past this completeness gate;
      // canonicalize to upper-case for the catalog membership check.
      for (const match of text.match(/CWE-[0-9]+/gi) || []) {
        ids.add(match.toUpperCase());
      }
    }
  };
  walk(dir);
  return ids;
}

test("every CWE referenced in prompts/ and test/ is seeded in the catalog", () => {
  // Derived dynamically so a newly referenced id added to any prompt or fixture
  // fails this test automatically unless it is also seeded into the catalog.
  const root = path.join(__dirname, "..");
  const referenced = new Set([
    ...collectReferencedCwes(path.join(root, "prompts")),
    ...collectReferencedCwes(path.join(root, "test")),
  ]);
  for (const id of NEGATIVE_CWE_FIXTURES) referenced.delete(id);

  assert.ok(referenced.size > 0, "sweep must find at least one referenced CWE id");
  for (const id of referenced) {
    assert.equal(isKnownCwe(id), true, `${id} is referenced in prompts/ or test/ but not seeded in the catalog`);
  }
});

test("smart-contract family mapping references only catalog ids", () => {
  for (const [family, ids] of Object.entries(SMART_CONTRACT_FAMILY_CWE)) {
    assert.ok(Array.isArray(ids) && ids.length > 0, `${family} must map to at least one CWE`);
    for (const id of ids) {
      assert.equal(isKnownCwe(id), true, `${family} -> ${id} must be in the catalog`);
    }
  }
});

test("OSS impact-class mapping references only catalog ids", () => {
  for (const [klass, ids] of Object.entries(OSS_IMPACT_CLASS_CWE)) {
    assert.ok(Array.isArray(ids) && ids.length > 0, `${klass} must map to at least one CWE`);
    for (const id of ids) {
      assert.equal(isKnownCwe(id), true, `${klass} -> ${id} must be in the catalog`);
    }
  }
});
