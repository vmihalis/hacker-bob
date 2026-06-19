"use strict";

// Y.3 Stage c — re-assert that bob_write_verification_round accepts both md5
// (32 hex) and sha256 (64 hex) artifact_hashes entries AFTER the _write-base.js
// migration. Y.0 hotfix 2 landed the sha256 acceptance in the underlying
// inputSchema; this test catches any future refactor that re-narrows the
// regex through the wrapped schema path.

const test = require("node:test");
const assert = require("node:assert/strict");

const writeVerificationRoundTool = require("../mcp/lib/tools/write-verification-round.js");

function getArtifactHashesPattern() {
  const schema = writeVerificationRoundTool.inputSchema;
  assert.ok(schema, "tool must expose inputSchema");
  const results = schema.properties && schema.properties.results;
  assert.ok(results, "schema must declare results array");
  const item = results.items;
  assert.ok(item, "results must declare items");
  const props = item.properties;
  assert.ok(props && props.artifact_hashes, "results items must declare artifact_hashes");
  const additional = props.artifact_hashes.additionalProperties;
  assert.ok(additional && typeof additional.pattern === "string", "artifact_hashes value must declare a pattern");
  return new RegExp(additional.pattern);
}

test("artifact_hashes regex accepts md5 (32 lowercase hex)", () => {
  const re = getArtifactHashesPattern();
  const md5 = "0123456789abcdef0123456789abcdef";
  assert.equal(md5.length, 32);
  assert.ok(re.test(md5), "md5 (32 hex) must match the artifact_hashes pattern");
});

test("artifact_hashes regex accepts sha256 (64 lowercase hex)", () => {
  const re = getArtifactHashesPattern();
  const sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  assert.equal(sha256.length, 64);
  assert.ok(re.test(sha256), "sha256 (64 hex) must match the artifact_hashes pattern");
});

test("artifact_hashes regex rejects upper-case hex and non-hex lengths", () => {
  const re = getArtifactHashesPattern();
  assert.ok(!re.test("0123456789ABCDEF0123456789ABCDEF"), "upper-case hex must be rejected");
  assert.ok(!re.test("0123456789abcdef"), "too-short hex (16) must be rejected");
  assert.ok(!re.test("0123456789abcdef0123456789abcde"), "off-by-one md5 (31) must be rejected");
  assert.ok(!re.test("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"), "off-by-one sha256 (65) must be rejected");
  assert.ok(!re.test("gggggggggggggggggggggggggggggggg"), "non-hex characters must be rejected");
});

test("_write-base.js migration preserves sha256 acceptance — wrapped tool exposes the same schema regex", () => {
  // wrapWriteTool propagates inputSchema; the migration path MUST NOT replace
  // the artifact_hashes pattern with an md5-only version. This is the post-
  // migration regression assertion (Y.0 hotfix shipped the broadened regex;
  // Y.3 cycle gate re-asserts that the wrapped path still surfaces it).
  const re = getArtifactHashesPattern();
  assert.equal(
    re.source,
    "^(?:[a-f0-9]{32}|[a-f0-9]{64})$",
    "_write-base.js migration must surface the broadened md5|sha256 regex unchanged",
  );
});
