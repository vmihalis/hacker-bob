"use strict";

// Regression suite for auth-aware circuit-breaker semantics (harden/session-robustness):
// an unauthenticated 403 (auth challenge) must NOT permanently trip the "host is blocking us"
// breaker once a later AUTHENTICATED request to the same host+path succeeds — while a GENUINE
// block (429, timeout, or a 403 returned DESPITE auth) must STILL trip and stay tripped (no
// evasion, no auto-bypass of a live block).

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  buildCircuitBreakerSummary,
  isHardBlockFailure,
  isUnauthenticatedForbidden,
  isCircuitBreakerFailure,
} = require("../mcp/lib/http-records.js");

const T0 = "2026-06-20T10:00:00.000Z"; // unauthenticated phase (earlier)
const T1 = "2026-06-20T11:00:00.000Z"; // authenticated phase (later)

function rec(overrides) {
  return { host: "api.example.test", path: "/data", url: "https://api.example.test/data", ts: T0, ...overrides };
}
const unauth403 = (ts = T0) => rec({ status: 403, auth_profile: null, ts });
const authed200 = (ts = T1) => rec({ status: 200, auth_profile: "attacker", ts });
const summary = (records) => buildCircuitBreakerSummary(records, { surface: null });

test("HEAL: unauth 403s followed by a later authed success do NOT trip the breaker", () => {
  const s = summary([unauth403(T0), unauth403(T0), unauth403(T0), authed200(T1)]);
  assert.equal(s.tripped_count, 0);
  assert.equal(s.auth_challenge_403_count, 3);
  assert.equal(s.auth_challenge_hosts[0].host, "api.example.test");
});

test("SAFETY — real WAF wall: unauth 403s with NO later authed success STILL trip and stay tripped", () => {
  const s = summary([unauth403(T0), unauth403(T0), unauth403(T0)]);
  assert.equal(s.tripped_count, 1);
  assert.equal(s.tripped_hosts[0].host, "api.example.test");
  assert.equal(s.auth_challenge_403_count, 0);
});

test("SAFETY — 403 DESPITE an auth profile is a hard block; a same-endpoint authed 200 never excuses it", () => {
  const s = summary([
    rec({ status: 403, auth_profile: "attacker", ts: T1 }),
    rec({ status: 403, auth_profile: "attacker", ts: T1 }),
    rec({ status: 403, auth_profile: "attacker", ts: T1 }),
    authed200(T1),
  ]);
  assert.equal(s.tripped_count, 1);
});

test("SAFETY — 429 rate-limit is never reclassified, even with a later authed success", () => {
  const s = summary([
    rec({ status: 429, auth_profile: null, ts: T0 }),
    rec({ status: 429, auth_profile: null, ts: T0 }),
    rec({ status: 429, auth_profile: null, ts: T0 }),
    authed200(T1),
  ]);
  assert.equal(s.tripped_count, 1);
});

test("SAFETY — timeouts are never reclassified, even with a later authed success", () => {
  const to = (ts) => rec({ status: null, scope_decision: "request_error", error: "request timeout", auth_profile: null, ts });
  const s = summary([to(T0), to(T0), to(T0), authed200(T1)]);
  assert.equal(s.tripped_count, 1);
});

test("SAFETY — temporal: an authed success BEFORE the unauth 403s does NOT heal them", () => {
  const s = summary([authed200(T0), unauth403(T1), unauth403(T1), unauth403(T1)]);
  assert.equal(s.tripped_count, 1, "403s that came after the success are a fresh block, not healed");
  assert.equal(s.auth_challenge_403_count, 0);
});

test("SAFETY — method mismatch: an authed GET 2xx does not heal blocked unauth POSTs on the same path", () => {
  const post403 = (ts) => rec({ status: 403, auth_profile: null, method: "POST", ts });
  const s = summary([post403(T0), post403(T0), post403(T0), rec({ status: 200, auth_profile: "attacker", method: "GET", ts: T1 })]);
  assert.equal(s.tripped_count, 1, "GET success must not heal a POST block");
  assert.equal(s.auth_challenge_403_count, 0);
});

test("SAFETY — egress mismatch: a success on a different egress profile does not heal the block", () => {
  const def403 = (ts) => rec({ status: 403, auth_profile: null, egress_profile: "default", ts });
  const s = summary([def403(T0), def403(T0), def403(T0), rec({ status: 200, auth_profile: "attacker", egress_profile: "gr-residential", ts: T1 })]);
  assert.equal(s.tripped_count, 1, "a success via a different egress must not heal a per-egress block");
  assert.equal(s.auth_challenge_403_count, 0);
});

test("SAFETY — an offensive-confirmer 403 (tool stamped, auth_profile lost) is never healed", () => {
  // An authenticated offensive probe records auth_profile:null but stamps `tool`; its genuine block
  // must not be reclassified by a later bob_http_scan authed 2xx on the same key.
  const idor403 = (ts) => rec({ status: 403, auth_profile: null, tool: "bob_http_idor_confirm", ts });
  const s = summary([idor403(T0), idor403(T0), idor403(T0), authed200(T1)]);
  assert.equal(s.tripped_count, 1, "a tool-stamped confirmer 403 must stay a hard block");
  assert.equal(s.auth_challenge_403_count, 0);
});

test("classifier split: hard-block vs unauthenticated-forbidden (back-compat preserved)", () => {
  assert.equal(isHardBlockFailure({ status: 429 }), true);
  assert.equal(isHardBlockFailure({ status: 403, auth_profile: "x" }), true);
  assert.equal(isHardBlockFailure({ status: 403, auth_profile: null }), false);
  assert.equal(isUnauthenticatedForbidden({ status: 403, auth_profile: null }), true);
  assert.equal(isUnauthenticatedForbidden({ status: 403, auth_profile: "x" }), false);
  // Any prior "failure" is still a failure (the reclassification lives in the summary, not here).
  assert.equal(isCircuitBreakerFailure({ status: 403, auth_profile: null }), true);
  assert.equal(isCircuitBreakerFailure({ status: 403, auth_profile: "x" }), true);
  assert.equal(isCircuitBreakerFailure({ status: 200 }), false);
});
