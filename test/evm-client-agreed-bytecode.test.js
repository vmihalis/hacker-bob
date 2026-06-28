"use strict";

// The pure quorum decision behind the cross-stack target-binding lookup (ethGetCodeAgreed).
// It defends the on-chain bytecode cross-check: a single non-archival endpoint returning "0x"
// must not produce a wrong hash that FALSELY refuses a genuine target; a transient all-endpoint
// failure must be a RE-RUNNABLE "unavailable", not a forgery; and a LONE responder (quorum-of-
// one) — whether the only answer or a single compromised trusted endpoint — must NOT decide the
// hash. The caller resolves the TRUSTED operator ladder for these inputs, never agent fork_urls.

const test = require("node:test");
const assert = require("node:assert/strict");

const { decideAgreedBytecode } = require("../mcp/lib/evm-client.js");

const REAL = `0x${"60".repeat(64)}`; // a non-empty runtime bytecode
const OTHER = `0x${"61".repeat(64)}`; // a DIFFERENT non-empty bytecode

test("unanimous real-code responders (>= quorum) RESOLVE to the agreed code", () => {
  const d = decideAgreedBytecode([REAL, REAL, REAL]);
  assert.equal(d.status, "resolved");
  assert.equal(d.code, REAL.replace(/^0x/, ""));
  assert.equal(d.corroboration, 3);
});

test("a non-archival '0x' miss is IGNORED when >= quorum archival endpoints return real code", () => {
  // The "0x" misses are dropped; the two agreeing real-code responders meet the default quorum.
  const d = decideAgreedBytecode(["0x", REAL, REAL]);
  assert.equal(d.status, "resolved");
  assert.equal(d.code, REAL.replace(/^0x/, ""));
  assert.equal(d.corroboration, 2);
});

test("QUORUM: a LONE real-code responder is INSUFFICIENT_CORROBORATION, never resolved (quorum-of-one closed)", () => {
  // Default quorum is 2: a single endpoint that "agrees with itself" cannot decide the on-chain
  // hash — the multiplier that would let one agent/compromised endpoint forge the cross-check.
  const d = decideAgreedBytecode(["0x", REAL, "0x"]);
  assert.equal(d.status, "unavailable");
  assert.equal(d.reason, "insufficient_corroboration");
  assert.equal(d.corroboration, 1);
  assert.equal(d.required, 2);
  // Explicit minCorroboration is honored (an operator with one trusted archival provider).
  const relaxed = decideAgreedBytecode([REAL], { minCorroboration: 1 });
  assert.equal(relaxed.status, "resolved");
  assert.equal(relaxed.corroboration, 1);
  // A higher bar than available responders also fails closed.
  assert.equal(decideAgreedBytecode([REAL, REAL], { minCorroboration: 3 }).reason, "insufficient_corroboration");
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
