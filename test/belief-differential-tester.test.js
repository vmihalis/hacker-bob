"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  evaluateObjectAuthDifferential,
  buildCausalSupport,
} = require("../mcp/lib/belief/differential-tester.js");

// A full control set whose observed effects are all "safe" -> confirmed IDOR.
function confirmedInput() {
  return {
    primary_effect: { reached: true },
    controls: {
      attacker_owned_control: { reached: true },
      victim_auth_same_object: { reached: true },
      no_auth_same_object: { reached: false },
      public_object_check: { reached: false },
      nonexistent_object: { reached: false },
      stale_session_check: { reached: false },
      cache_nonce_check: { reached: true },
    },
  };
}

test("full safe control set yields a confirmed verdict", () => {
  const v = evaluateObjectAuthDifferential(confirmedInput());
  assert.equal(v.disposition, "confirmed");
  assert.deepEqual(v.confounders_ruled_out, ["cache_bleed", "expired_auth", "public_object", "response_reflection"]);
  assert.equal(v.missing_controls.length, 0);
});

// THE GATE (decisive flip): flipping one discriminating control flips the verdict.
test("verdict flips to denied when the public-object control flips (decisive)", () => {
  const base = evaluateObjectAuthDifferential(confirmedInput());
  assert.equal(base.disposition, "confirmed");

  const flipped = confirmedInput();
  flipped.controls.no_auth_same_object.reached = true; // no-auth now reaches => public
  const v = evaluateObjectAuthDifferential(flipped);

  assert.equal(v.disposition, "denied");
  assert.match(v.reason, /public_object/);
  assert.notEqual(v.disposition, base.disposition); // a constant cannot pass both
});

test("verdict flips to denied on reflection control flip (decisive)", () => {
  const flipped = confirmedInput();
  flipped.controls.nonexistent_object.reached = true; // nonexistent reaches => reflection/always-ok
  const v = evaluateObjectAuthDifferential(flipped);
  assert.equal(v.disposition, "denied");
  assert.match(v.reason, /response_reflection/);
});

// THE GATE (irrelevant flip): a non-decision field must NOT move the verdict or hash.
test("verdict and hash are invariant to an irrelevant field", () => {
  const base = evaluateObjectAuthDifferential(confirmedInput());
  const withNoise = confirmedInput();
  withNoise.controls.no_auth_same_object.latency_ms = 1234; // not a decision input
  withNoise.controls.victim_auth_same_object.note = "irrelevant";
  const v = evaluateObjectAuthDifferential(withNoise);
  assert.equal(v.disposition, base.disposition);
  assert.equal(v.verdict_hash, base.verdict_hash);
});

test("deterministic: same input reproduces the same verdict hash", () => {
  const a = evaluateObjectAuthDifferential(confirmedInput());
  const b = evaluateObjectAuthDifferential(confirmedInput());
  assert.equal(a.verdict_hash, b.verdict_hash);
});

test("no primary effect yields denied", () => {
  const v = evaluateObjectAuthDifferential({ primary_effect: { reached: false }, controls: confirmedInput().controls });
  assert.equal(v.disposition, "denied");
  assert.match(v.reason, /did not reach/);
});

test("missing discriminating controls yield inconclusive, not confirmed", () => {
  const v = evaluateObjectAuthDifferential({
    primary_effect: { reached: true },
    controls: { attacker_owned_control: { reached: true }, victim_auth_same_object: { reached: true } },
  });
  assert.equal(v.disposition, "inconclusive");
  assert.ok(v.missing_controls.includes("no_auth_same_object"));
  assert.ok(v.unruled_confounders.includes("public_object"));
});

test("failed positive control yields inconclusive (invalid test setup)", () => {
  const broken = confirmedInput();
  broken.controls.attacker_owned_control.reached = false; // attacker cannot even reach its own object
  const v = evaluateObjectAuthDifferential(broken);
  assert.equal(v.disposition, "inconclusive");
  assert.match(v.reason, /positive control failed/);
});

test("buildCausalSupport emits CB-C2 shape only for confirmed verdicts", () => {
  const confirmed = evaluateObjectAuthDifferential(confirmedInput());
  const support = buildCausalSupport(confirmed, { mechanism_id: "CWE-639" });
  assert.equal(support.mechanism_id, "CWE-639");
  assert.equal(support.intervention, "principal_fixed_object_swap");
  assert.ok(Array.isArray(support.controls_run) && support.controls_run.length > 0);
  for (const entry of support.controls_run) {
    assert.equal(typeof entry.control, "string");
    assert.ok(["reached", "blocked"].includes(entry.observed_effect));
  }
  assert.ok(support.confounders_ruled_out.includes("public_object"));

  const denied = evaluateObjectAuthDifferential({ primary_effect: { reached: false }, controls: {} });
  assert.equal(buildCausalSupport(denied), null);
});
