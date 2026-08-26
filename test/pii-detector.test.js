"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  normalizeEmailForComparison,
  detectPiiShapes,
  emailMatchesOperatorDenylist,
} = require("../mcp/core/pii-detector.js");

function valuesByType(matches, type) {
  return matches
    .filter((match) => match.type === type)
    .map((match) => match.value);
}

// Built from parts (not a contiguous PAN literal) so secret/PII scanners don't
// flag this Luhn-valid test card; it is the canonical 4242… test value.
const TEST_CARD = ["4242", "4242", "4242", "4242"].join("");

test("normalizeEmailForComparison canonicalizes Gmail aliases and preserves non-Gmail dots", () => {
  const base = normalizeEmailForComparison("vmihalis.tmd@gmail.com");
  assert.equal(normalizeEmailForComparison("Vmihalis.TMD+anything@Gmail.com"), base);
  assert.equal(normalizeEmailForComparison("v.mihalis.tmd@googlemail.com"), base);
  assert.equal(base, "vmihalistmd@gmail.com");

  assert.equal(normalizeEmailForComparison("a.b+x@corp.com"), "a.b@corp.com");
  assert.equal(normalizeEmailForComparison("  Opaque-Identifier  "), "opaque-identifier");
  assert.equal(normalizeEmailForComparison(42), null);
  assert.equal(normalizeEmailForComparison("   "), null);
});

test("detectPiiShapes finds conservative PII shapes", () => {
  const matches = detectPiiShapes([
    "Contact security@example.com or +1-555-867-5309.",
    `SSN shape 123-45-6789 and card ${TEST_CARD}.`,
    "Duplicate security@example.com should be reported once.",
  ].join(" "));

  assert.deepEqual(valuesByType(matches, "email"), ["security@example.com"]);
  assert.deepEqual(valuesByType(matches, "phone"), ["+1-555-867-5309"]);
  assert.deepEqual(valuesByType(matches, "ssn"), ["123-45-6789"]);
  assert.deepEqual(valuesByType(matches, "credit_card"), [TEST_CARD]);
});

test("detectPiiShapes avoids known false-positive shapes", () => {
  const matches = detectPiiShapes([
    "Invalid card 1234567890123456.",
    "UUID 550e8400-e29b-41d4-a716-446655440000.",
    "Timestamp 2026-06-16T12:34:56Z.",
    "Long numeric id 12345678901234567890.",
  ].join(" "));

  assert.deepEqual(matches, []);
  assert.deepEqual(detectPiiShapes(""), []);
  assert.deepEqual(detectPiiShapes(null), []);
});

test("emailMatchesOperatorDenylist uses normalized email comparison", () => {
  assert.equal(
    emailMatchesOperatorDenylist(
      "v.mihalis.tmd+signup@googlemail.com",
      ["vmihalis.tmd@gmail.com"],
    ),
    true,
  );
  assert.equal(emailMatchesOperatorDenylist("eval_abc@temp.tld", ["vmihalis.tmd@gmail.com"]), false);
  assert.equal(emailMatchesOperatorDenylist("v.mihalis.tmd+signup@googlemail.com", []), false);
});
