"use strict";

// Cycle Y.2 EXTEND (rev 4.1 W1) — Friction prompt fragments shape test.
//
// Asserts:
//   * FRICTION_PROMPT_FRAGMENTS is Object.freeze'd (closed list)
//   * Every canonical Y-D19 (rev 4.1) fragment_id is present with a
//     non-empty string text body
//   * The vocabulary is EXACTLY the canonical 9-entry set (no orphan
//     additions, no missing additions)
//   * Every fragment text names at least one bob_* tool OR (for the
//     auto-emit advisory fragments) explicitly disclaims manual logging
//   * Cross-reference against mcp/lib/role-trace-expectations.js (Y.6):
//     when present, every role-referenced fragment_id MUST exist in
//     FRICTION_PROMPT_FRAGMENTS (no role consumer references a
//     non-manifested fragment) AND every fragment_id in
//     FRICTION_PROMPT_FRAGMENTS that is mapped to ANY role MUST appear in
//     at least one role's expectation list. The cross-reference activates
//     once Y.6 lands; until then it is a forward-compat no-op so Y.2 can
//     ship per dependency graph (Y.2 blocks Y.6).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const {
  FRICTION_PROMPT_FRAGMENTS,
  FRAGMENT_IDS,
  isKnownFragmentId,
  getFragmentText,
} = require("../mcp/lib/friction-prompt-fragments.js");

const CANONICAL_FRAGMENT_IDS = [
  "internal_error_retry",
  "invalid_arguments_retry",
  "bash_curl_on_target_detected",
  "setup_setup_rejection",
  "read_chain_attempts_before_propose",
  "propose_hypothesis_for_new_chain",
  "emit_structured_ranked_leads",
  "cite_verification_round_for_bob_verified",
  "log_friction_on_internal_error",
];

test("FRICTION_PROMPT_FRAGMENTS is Object.freeze'd", () => {
  assert.equal(Object.isFrozen(FRICTION_PROMPT_FRAGMENTS), true);
  assert.equal(Object.isFrozen(FRAGMENT_IDS), true);
});

test("FRICTION_PROMPT_FRAGMENTS vocabulary is exactly the canonical Y-D19 (rev 4.1) 9-entry set", () => {
  const actualIds = Object.keys(FRICTION_PROMPT_FRAGMENTS).sort();
  const expectedIds = [...CANONICAL_FRAGMENT_IDS].sort();
  assert.deepEqual(
    actualIds,
    expectedIds,
    "fragment_id set MUST match Y-D19 canonical vocabulary exactly",
  );
});

test("every fragment_id maps to a non-empty string text body", () => {
  for (const id of CANONICAL_FRAGMENT_IDS) {
    const text = FRICTION_PROMPT_FRAGMENTS[id];
    assert.equal(typeof text, "string", `${id} must be a string`);
    assert.ok(text.length > 0, `${id} must be non-empty`);
  }
});

test("every fragment text mechanically names at least one bob_* tool OR disclaims manual emission", () => {
  // The two auto-emit advisory fragments explicitly tell the agent NOT to
  // log manually because MCP auto-emits — they need not name a bob_* tool
  // to call, but they must reference the auto-emission contract.
  const autoEmitDisclaimerIds = new Set(["invalid_arguments_retry"]);
  for (const id of CANONICAL_FRAGMENT_IDS) {
    const text = FRICTION_PROMPT_FRAGMENTS[id];
    if (autoEmitDisclaimerIds.has(id)) {
      assert.match(
        text,
        /auto-emits|do not also log/,
        `${id} (auto-emit advisory) must reference the auto-emission contract`,
      );
    } else {
      assert.match(
        text,
        /\bbob_[a-z_]+\b/,
        `${id} must name at least one bob_* tool the agent should call`,
      );
    }
  }
});

test("isKnownFragmentId returns true for canonical ids and false for unknown", () => {
  for (const id of CANONICAL_FRAGMENT_IDS) {
    assert.equal(isKnownFragmentId(id), true, `${id} must be known`);
  }
  assert.equal(isKnownFragmentId("nope_not_a_fragment"), false);
  assert.equal(isKnownFragmentId(""), false);
});

test("getFragmentText returns the registered text for known ids and null otherwise", () => {
  assert.equal(
    getFragmentText("internal_error_retry"),
    FRICTION_PROMPT_FRAGMENTS.internal_error_retry,
  );
  assert.equal(getFragmentText("nope_not_a_fragment"), null);
});

// Cross-reference against role-trace-expectations.js (Y.6).
//
// The Y-D19 canonical vocabulary (rev 4.1) is 9 fragments = 4 rev-4
// originals injected at recognized friction points (NOT via the role
// registry) + 5 used by ROLE_TRACE_EXPECTATIONS in Y.6. So the only
// orphan check that survives the design is the role-side direction:
// every role-referenced fragment_id MUST exist in
// FRICTION_PROMPT_FRAGMENTS. The inverse (every fragment must appear in
// the role registry) is NOT a design invariant — the 4 originals
// (internal_error_retry, invalid_arguments_retry,
// bash_curl_on_target_detected, setup_setup_rejection) are injected at
// dispatch-layer friction points and have no per-role expectation entry.
test("cross-reference role-trace-expectations.js (Y.6) when present: role-referenced fragment_ids resolve mechanically", () => {
  const expectationsPath = path.resolve(
    __dirname,
    "..",
    "mcp",
    "lib",
    "role-trace-expectations.js",
  );
  if (!fs.existsSync(expectationsPath)) {
    // Y.6 has not landed yet; cross-reference will activate when it does.
    return;
  }
  // eslint-disable-next-line global-require
  const { ROLE_TRACE_EXPECTATIONS } = require(expectationsPath);
  assert.equal(
    typeof ROLE_TRACE_EXPECTATIONS,
    "object",
    "Y.6 must export ROLE_TRACE_EXPECTATIONS once it lands",
  );

  const referencedFragmentIds = new Set();
  for (const role of Object.keys(ROLE_TRACE_EXPECTATIONS)) {
    const entries = ROLE_TRACE_EXPECTATIONS[role];
    assert.ok(Array.isArray(entries), `${role} expectations must be an array`);
    for (const entry of entries) {
      assert.ok(
        entry && typeof entry.fragment_id === "string",
        `${role} entry missing fragment_id`,
      );
      referencedFragmentIds.add(entry.fragment_id);
    }
  }

  // Every role-referenced fragment_id MUST exist in
  // FRICTION_PROMPT_FRAGMENTS (no consumer references a non-manifested
  // producer fragment). This is the one direction the design enforces.
  for (const fragmentId of referencedFragmentIds) {
    assert.ok(
      isKnownFragmentId(fragmentId),
      `role-trace-expectations references fragment_id "${fragmentId}" that is NOT in FRICTION_PROMPT_FRAGMENTS`,
    );
  }

  // The 5 role-mapped fragments MUST be exactly the rev-4.1 canonical
  // mapping per Y-D19. The remaining 4 (rev-4 originals) live in the
  // dispatch-layer injection paths and are deliberately NOT in
  // ROLE_TRACE_EXPECTATIONS.
  const REV4_DISPATCH_LAYER_FRAGMENTS = new Set([
    "internal_error_retry",
    "invalid_arguments_retry",
    "bash_curl_on_target_detected",
    "setup_setup_rejection",
  ]);
  const expectedRoleMapped = new Set(
    Object.keys(FRICTION_PROMPT_FRAGMENTS).filter(
      (id) => !REV4_DISPATCH_LAYER_FRAGMENTS.has(id),
    ),
  );
  assert.deepEqual(
    [...referencedFragmentIds].sort(),
    [...expectedRoleMapped].sort(),
    "role-mapped fragment set must match the 5 Y-D19 role-mapped fragments (rev-4 dispatch-layer fragments stay unreferenced by roles)",
  );
});
