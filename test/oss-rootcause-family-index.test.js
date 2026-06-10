"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
} = require("../mcp/lib/technique-packs.js");
const {
  OSS_ROOTCAUSE_FAMILIES,
  SUPPORTED_FAMILIES,
  getFamiliesForLens,
  suggestFamiliesForSurface,
} = require("../mcp/lib/oss-rootcause-family-corpus.js");

const OSS_LENSES = ["code_surface_scout", "taint_trace", "fuzz_run"];

function assertWitnessShape(witness) {
  assert.equal(typeof witness.project, "string");
  assert.ok(witness.project.length > 0);
  assert.equal(typeof witness.cve_or_commit, "string");
  assert.ok(witness.cve_or_commit.length > 0);
  assert.equal(typeof witness.file_symbol, "string");
  assert.ok(witness.file_symbol.length > 0);
  assert.ok(Array.isArray(witness.controlling_fields));
  assert.ok(witness.controlling_fields.length > 0);
  assert.equal(typeof witness.impact, "string");
  assert.ok(witness.impact.length > 0);
}

test("SUPPORTED_FAMILIES covers the OSS root-cause families, including the two absent from the old prose blob", () => {
  for (const family of [
    "bounds_check",
    "integer_truncation",
    "signedness_conversion",
    "allocation_size_math",
    "nul_path_handling",
    "state_machine_confusion",
    "lifetime_ownership",
    "double_free_use_after_free",
    "crypto_ordering",
    "validate_vs_consume",
  ]) {
    assert.ok(SUPPORTED_FAMILIES.includes(family), `${family} present`);
  }
  assert.deepEqual(SUPPORTED_FAMILIES, [...SUPPORTED_FAMILIES].sort());
});

test("OSS_ROOTCAUSE_FAMILIES every entry declares id, family, name, lens_affinity, source_sink_signature, and witness", () => {
  for (const family of OSS_ROOTCAUSE_FAMILIES) {
    assert.ok(typeof family.id === "string" && family.id.length > 0);
    assert.ok(typeof family.family === "string" && family.family.length > 0);
    assert.ok(typeof family.name === "string" && family.name.length > 0);
    assert.ok(typeof family.description === "string" && family.description.length > 0);
    assert.ok(Array.isArray(family.lens_affinity));
    assert.ok(family.lens_affinity.length > 0);
    assert.ok(Array.isArray(family.source_sink_signature));
    assert.ok(family.source_sink_signature.length > 0);
    assertWitnessShape(family.witness);
    if (Array.isArray(family.additional_witnesses)) {
      for (const witness of family.additional_witnesses) {
        assertWitnessShape(witness);
      }
    }
  }
});

test("OSS_ROOTCAUSE_FAMILIES is fully frozen at record and witness boundaries", () => {
  assert.equal(Object.isFrozen(OSS_ROOTCAUSE_FAMILIES), true);
  for (const family of OSS_ROOTCAUSE_FAMILIES) {
    assert.equal(Object.isFrozen(family), true, `${family.id} must be frozen`);
    assert.equal(Object.isFrozen(family.lens_affinity), true, `${family.id}.lens_affinity must be frozen`);
    assert.equal(Object.isFrozen(family.source_sink_signature), true, `${family.id}.source_sink_signature must be frozen`);
    assert.equal(Object.isFrozen(family.witness), true, `${family.id}.witness must be frozen`);
    assert.equal(Object.isFrozen(family.witness.controlling_fields), true, `${family.id}.witness.controlling_fields must be frozen`);
    if (Array.isArray(family.additional_witnesses)) {
      assert.equal(Object.isFrozen(family.additional_witnesses), true, `${family.id}.additional_witnesses must be frozen`);
      for (const witness of family.additional_witnesses) {
        assert.equal(Object.isFrozen(witness), true);
        assert.equal(Object.isFrozen(witness.controlling_fields), true);
      }
    }
  }
});

test("validate_vs_consume carries the four public witness rows named in the I12 spec", () => {
  const record = OSS_ROOTCAUSE_FAMILIES.find((family) => family.family === "validate_vs_consume");
  assert.ok(record, "validate_vs_consume record must exist");
  const witnesses = [record.witness, ...record.additional_witnesses];
  const witnessText = JSON.stringify(witnesses);
  for (const expected of [
    "rpcbind",
    "rpcbaddrlist",
    "netatalk afpd",
    "Spotlight RPC",
    "libtirpc",
    "__xdrrec_getrec",
    "LibreDWG",
    "read_literal_length",
  ]) {
    assert.match(witnessText, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.equal(witnesses.length, 4);
});

test("crypto_ordering is explicitly fixture-only until Bob has a portfolio witness", () => {
  const record = OSS_ROOTCAUSE_FAMILIES.find((family) => family.family === "crypto_ordering");
  assert.ok(record, "crypto_ordering record must exist");
  assert.equal(record.fixture_only, true);
  assert.match(record.portfolio_status, /zero crypto-ordering findings/);
  assert.match(record.witness.impact, /padding-oracle|plaintext/i);
});

test("family witness rows avoid credentials and operator personal identifiers", () => {
  const raw = JSON.stringify(OSS_ROOTCAUSE_FAMILIES);
  assert.doesNotMatch(raw, /@/);
  assert.doesNotMatch(raw, /bearer\s+/i);
  assert.doesNotMatch(raw, /api[_-]?key/i);
  assert.doesNotMatch(raw, /token/i);
});

test("getFamiliesForLens returns the families whose lens_affinity matches", () => {
  for (const lens of OSS_LENSES) {
    const families = getFamiliesForLens(lens);
    assert.ok(families.length >= 1, `${lens} must return at least one family`);
    assert.ok(families.every((family) => family.lens_affinity.includes(lens)));
  }
});

test("getFamiliesForLens returns an empty array for unknown lenses", () => {
  assert.deepEqual(getFamiliesForLens("nope"), []);
  assert.deepEqual(getFamiliesForLens(""), []);
  assert.deepEqual(getFamiliesForLens(null), []);
});

test("suggestFamiliesForSurface emits bounded brief suggestions when lens is supported", () => {
  const result = suggestFamiliesForSurface({
    task_lens: "taint_trace",
    file_path: "src/rpc.c",
    bug_class_hints: ["length_field", "consuming_op", "bound_check_site"],
  }, {
    limit: 3,
  });
  assert.equal(result.lens, "taint_trace");
  assert.equal(result.unmatched_lens, false);
  assert.equal(result.suggestions.length, 3);
  assert.ok(result.family_count >= result.suggestions.length);
  for (const suggestion of result.suggestions) {
    assert.ok(suggestion.brief.length <= TECHNIQUE_SUMMARY_ITEM_MAX_CHARS);
    assert.ok(suggestion.witness.length <= TECHNIQUE_SUMMARY_ITEM_MAX_CHARS);
  }
});

test("truncated family brief strings carry an observable marker while staying bounded", () => {
  const result = suggestFamiliesForSurface({
    task_lens: "taint_trace",
  }, {
    limit: 10,
  });
  const truncated = result.suggestions.filter((suggestion) => suggestion.brief.endsWith("..."));
  assert.ok(truncated.length > 0, "fixture corpus should exercise brief truncation");
  for (const suggestion of truncated) {
    assert.ok(suggestion.brief.length <= TECHNIQUE_SUMMARY_ITEM_MAX_CHARS);
  }
});

test("suggestFamiliesForSurface ranks signature matches before applying the limit", () => {
  const result = suggestFamiliesForSurface({
    task_lens: "taint_trace",
    bug_class_hints: ["entry_to_consumer_path"],
  }, {
    limit: 1,
  });
  assert.equal(result.suggestions.length, 1);
  assert.equal(result.suggestions[0].family, "validate_vs_consume");
  assert.deepEqual(result.suggestions[0].matched_signature, ["entry_to_consumer_path"]);
});

test("suggestFamiliesForSurface sets unmatched_lens for unsupported lenses", () => {
  const result = suggestFamiliesForSurface({ task_lens: "not_a_real_lens" });
  assert.equal(result.lens, "not_a_real_lens");
  assert.equal(result.family_count, 0);
  assert.deepEqual(result.suggestions, []);
  assert.equal(result.unmatched_lens, true);
  assert.deepEqual(result.summary_limits, {
    item_max_chars: TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
    limit: 0,
    returned: 0,
  });
});

test("suggestFamiliesForSurface rejects malformed surface input", () => {
  assert.throws(() => suggestFamiliesForSurface(null), /surface/);
  assert.throws(() => suggestFamiliesForSurface([]), /surface/);
});

test("root-cause family ids are unique", () => {
  const ids = new Set();
  for (const family of OSS_ROOTCAUSE_FAMILIES) {
    assert.equal(ids.has(family.id), false, `duplicate family id: ${family.id}`);
    ids.add(family.id);
  }
});
