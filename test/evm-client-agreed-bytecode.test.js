"use strict";

// The pure quorum decision behind the cross-stack target-binding lookup (ethGetCodeAgreed).
// It defends the on-chain bytecode cross-check from first-endpoint-wins: a single non-archival
// endpoint returning "0x" must not produce a wrong hash that FALSELY refuses a genuine target,
// and a transient all-endpoint failure must be a RE-RUNNABLE "unavailable", not a forgery.

const test = require("node:test");
const assert = require("node:assert/strict");

const { decideAgreedBytecode } = require("../mcp/lib/evm-client.js");

const REAL = `0x${"60".repeat(64)}`; // a non-empty runtime bytecode
const OTHER = `0x${"61".repeat(64)}`; // a DIFFERENT non-empty bytecode

test("unanimous real-code responders RESOLVE to the agreed code", () => {
  const d = decideAgreedBytecode([REAL, REAL, REAL]);
  assert.equal(d.status, "resolved");
  assert.equal(d.code, REAL.replace(/^0x/, ""));
  assert.equal(d.corroboration, 3);
});

test("a non-archival '0x' miss is IGNORED when an archival endpoint returns real code (no false hash)", () => {
  // First-endpoint-wins would have computed the hash of "0x" and falsely refused; agreement
  // over the real-code responders resolves correctly.
  const d = decideAgreedBytecode(["0x", REAL, "0x"]);
  assert.equal(d.status, "resolved");
  assert.equal(d.code, REAL.replace(/^0x/, ""));
  assert.equal(d.corroboration, 1);
});

test("real-code responders that DISAGREE are UNAVAILABLE (no single value is trusted)", () => {
  const d = decideAgreedBytecode([REAL, OTHER]);
  assert.equal(d.status, "unavailable");
  assert.equal(d.reason, "endpoint_disagreement");
});

test("all endpoints empty/failed is UNAVAILABLE (retryable), never resolved", () => {
  assert.deepEqual(decideAgreedBytecode(["0x", "0x", null]).status, "unavailable");
  assert.equal(decideAgreedBytecode(["0x", "0x", null]).reason, "no_code_responses");
  assert.equal(decideAgreedBytecode([null, null]).reason, "no_code_responses");
  assert.equal(decideAgreedBytecode([]).reason, "no_code_responses");
});

test("normalization: 0x-prefix and case do not split agreement", () => {
  const d = decideAgreedBytecode([REAL.toUpperCase(), REAL.replace(/^0x/, ""), REAL]);
  assert.equal(d.status, "resolved");
  assert.equal(d.code, REAL.replace(/^0x/, ""));
  assert.equal(d.corroboration, 3);
});
