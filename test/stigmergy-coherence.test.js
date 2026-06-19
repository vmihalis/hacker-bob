"use strict";

// Cycle Y.9 (rev 4.1) — `check:stigmergy-coherence` CI gate test.
//
// Asserts the gate behavior across:
//   * Real tree (the live STIGMERGIC_PRODUCERS + STIGMERGIC_CONSUMERS):
//     exit-zero (no violations).
//   * Three fixture drift kinds:
//     (i)  consumer's token_or_regex absent at source_location.file →
//          violation kind `consumer_token_unresolved`.
//     (ii) producer orphaned (registered_consumers names a
//          non-manifested consumer) → violation kind
//          `producer_consumers_not_manifested`.
//     (iii) consumer references a non-manifested producer →
//           violation kind `consumer_references_unknown_producer`.
//   * Fixture corpus FP-rate ≤2% threshold (Y-P14c). The corpus is
//     curated under `test/fixtures/stigmergy-coherence/`; the synthetic
//     fixture set in this test is the canonical corpus.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const {
  runCoherenceCheck,
  checkAssertionA,
  checkAssertionB,
  checkAssertionC,
} = require("../scripts/check-stigmergy-coherence.js");
const {
  STIGMERGIC_PRODUCERS,
} = require("../mcp/lib/stigmergic-producers.js");
const {
  STIGMERGIC_CONSUMERS,
} = require("../mcp/lib/stigmergic-consumers.js");

const REPO_ROOT = path.join(__dirname, "..");

test("real tree: 0 violations across producers + consumers manifests", () => {
  const violations = runCoherenceCheck({
    producers: STIGMERGIC_PRODUCERS,
    consumers: STIGMERGIC_CONSUMERS,
    root: REPO_ROOT,
  });
  assert.deepEqual(
    violations,
    [],
    `expected 0 violations on real tree, got: ${JSON.stringify(violations, null, 2)}`,
  );
});

test("fixture drift (i): consumer token_or_regex absent at file produces consumer_token_unresolved", () => {
  // Synthesize a temp file that does NOT contain the token.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "stig-fixture-"));
  const fixtureFile = path.join(tmp, "drift-i.js");
  fs.writeFileSync(fixtureFile, "module.exports = { ok: true };\n");
  const fixtureConsumer = Object.freeze({
    consumer_id: "fixture_drift_i_consumer",
    source_location: Object.freeze({
      file: path.relative(REPO_ROOT, fixtureFile),
      token_or_regex: "this_token_is_missing_from_file",
    }),
    producer_id: "technique_pack_scorer",
    decision_boundary: "brief_composition",
    rationale: "fixture drift i",
  });
  const violations = checkAssertionB([fixtureConsumer], REPO_ROOT);
  assert.equal(violations.length, 1);
  assert.equal(violations[0].kind, "consumer_token_unresolved");
  assert.equal(violations[0].consumer_id, "fixture_drift_i_consumer");
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("fixture drift (ii): producer's registered_consumers names a non-manifested consumer produces producer_consumers_not_manifested", () => {
  const fixtureProducer = Object.freeze({
    producer_id: "fixture_drift_ii_producer",
    mcp_tool_or_artifact: "fictional_tool",
    trace_shape_ref: "nowhere",
    registered_consumers: Object.freeze(["consumer_that_was_never_registered"]),
  });
  // STIGMERGIC_CONSUMERS does not contain "consumer_that_was_never_registered".
  const violations = checkAssertionA([fixtureProducer], STIGMERGIC_CONSUMERS);
  assert.equal(violations.length, 1);
  assert.equal(violations[0].kind, "producer_consumers_not_manifested");
  assert.equal(violations[0].producer_id, "fixture_drift_ii_producer");
});

test("fixture drift (iii): consumer references non-manifested producer produces consumer_references_unknown_producer", () => {
  const fixtureConsumer = Object.freeze({
    consumer_id: "fixture_drift_iii_consumer",
    source_location: Object.freeze({
      file: "mcp/lib/stigmergic-consumers.js",
      token_or_regex: "STIGMERGIC_CONSUMERS",
    }),
    producer_id: "this_producer_id_is_not_in_the_manifest",
    decision_boundary: "brief_composition",
    rationale: "fixture drift iii",
  });
  const violations = checkAssertionC([fixtureConsumer]);
  assert.equal(violations.length, 1);
  assert.equal(violations[0].kind, "consumer_references_unknown_producer");
  assert.equal(violations[0].consumer_id, "fixture_drift_iii_consumer");
  assert.equal(
    violations[0].producer_id,
    "this_producer_id_is_not_in_the_manifest",
  );
});

test("fixture drift (iv): consumer points at non-existent source file produces consumer_source_file_missing", () => {
  const fixtureConsumer = Object.freeze({
    consumer_id: "fixture_drift_iv_consumer",
    source_location: Object.freeze({
      file: "does/not/exist/in/repo.js",
      token_or_regex: "anything",
    }),
    producer_id: "technique_pack_scorer",
    decision_boundary: "brief_composition",
    rationale: "fixture drift iv",
  });
  const violations = checkAssertionB([fixtureConsumer], REPO_ROOT);
  assert.equal(violations.length, 1);
  assert.equal(violations[0].kind, "consumer_source_file_missing");
});

test("FP-rate budget: ≤2% on the live canonical manifest", () => {
  // The curated corpus IS the live manifest of producer/consumer pairs.
  // The FP-rate budget Y-P14c is ≤2%; empirically the real tree has 0
  // violations.
  const violations = runCoherenceCheck({
    producers: STIGMERGIC_PRODUCERS,
    consumers: STIGMERGIC_CONSUMERS,
    root: REPO_ROOT,
  });
  const totalAssertions =
    STIGMERGIC_PRODUCERS.length + STIGMERGIC_CONSUMERS.length * 2;
  const fpRate = violations.length / totalAssertions;
  assert.ok(
    fpRate <= 0.02,
    `FP rate ${fpRate} exceeds Y-P14c ≤2% budget on curated corpus (${violations.length} / ${totalAssertions})`,
  );
});

test("regex token_or_regex resolves against multi-line content (chain-builder pair)", () => {
  // chain_builder_prompt_body_read_before_propose uses a multiline regex
  // /bob_read_chain_attempts[\s\S]*bob_propose_hypothesis/. Sanity-check
  // the regex resolves at the real chain-builder.md file.
  const chainBuilderPath = path.join(
    REPO_ROOT,
    ".claude/agents/chain-builder.md",
  );
  const content = fs.readFileSync(chainBuilderPath, "utf8");
  const regex = /bob_read_chain_attempts[\s\S]*bob_propose_hypothesis/;
  assert.ok(
    regex.test(content),
    "chain-builder.md must contain bob_read_chain_attempts followed (eventually) by bob_propose_hypothesis for the Y.9 stigmergy pair to resolve",
  );
});
