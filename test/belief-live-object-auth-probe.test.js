"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  runObjectAuthControlProbe,
} = require("../mcp/lib/belief/live-object-auth-probe.js");
const {
  evaluateObjectAuthDifferential,
} = require("../mcp/lib/belief/differential-tester.js");

const VICTIM_URL = "/api/objects/victim";
const VICTIM_CACHEBUST_URL = "/api/objects/victim?cb=1";
const ATTACKER_OWN_URL = "/api/objects/attacker";
const PUBLIC_URL = "/api/objects/public";
const GHOST_URL = "/api/objects/ghost";

const VICTIM_BODY = { id: "victim-7", email: "victim@example.com", ssn: "111-22-3333" };
const ATTACKER_BODY = { id: "attacker-1", email: "attacker@example.com" };

function ok(body, auth_profile) {
  return { status: 200, body, sent_with_auth: Boolean(auth_profile) };
}
function blocked(auth_profile, status = 401) {
  return { status, body: { error: "unauthorized" }, sent_with_auth: Boolean(auth_profile) };
}

// A live target that IS a genuine IDOR: the attacker principal reads the victim's
// private object (byte-identical to what the victim sees); every discriminating
// control is correctly blocked. `overrides` lets a test inject a single divergent
// response keyed by `${auth_profile||'anon'} ${url}`.
function makeFakeFetcher(overrides = {}) {
  return async function fetch_fn({ url, auth_profile }) {
    const key = `${auth_profile || "anon"} ${url}`;
    if (Object.prototype.hasOwnProperty.call(overrides, key)) return overrides[key];
    if (url.startsWith(GHOST_URL)) return blocked(auth_profile, 404);
    if (url.startsWith(ATTACKER_OWN_URL)) {
      return auth_profile === "attacker" ? ok(ATTACKER_BODY, auth_profile) : blocked(auth_profile);
    }
    if (url.startsWith(PUBLIC_URL)) return blocked(auth_profile); // public_object_check: safe when blocked
    if (url.startsWith(VICTIM_URL)) {
      // The bug: attacker (and the victim) read the victim object; anon/stale blocked.
      if (auth_profile === "victim" || auth_profile === "attacker") return ok(VICTIM_BODY, auth_profile);
      return blocked(auth_profile);
    }
    return blocked(auth_profile);
  };
}

function controlPlan() {
  return [
    { control: "attacker_owned_control", method: "GET", url: ATTACKER_OWN_URL, auth_profile: "attacker" },
    { control: "victim_auth_same_object", method: "GET", url: VICTIM_URL, auth_profile: "victim" },
    { control: "no_auth_same_object", method: "GET", url: VICTIM_URL },
    { control: "public_object_check", method: "GET", url: PUBLIC_URL },
    { control: "nonexistent_object", method: "GET", url: GHOST_URL, auth_profile: "attacker" },
    { control: "stale_session_check", method: "GET", url: VICTIM_URL, auth_profile: "stale" },
    { control: "cache_nonce_check", method: "GET", url: VICTIM_CACHEBUST_URL, auth_profile: "attacker" },
  ];
}

function primaryAttack() {
  return { method: "GET", url: VICTIM_URL, auth_profile: "attacker" };
}

async function probeVerdict(fetch_fn) {
  const probe = await runObjectAuthControlProbe({
    target_domain: "example.com",
    fetch_fn,
    primary: primaryAttack(),
    control_plan: controlPlan(),
  });
  return { probe, verdict: evaluateObjectAuthDifferential({ primary_effect: probe.primary_effect, controls: probe.controls }) };
}

test("a genuine live IDOR battery yields a confirmed verdict from real reached booleans", async () => {
  const { probe, verdict } = await probeVerdict(makeFakeFetcher());
  assert.equal(probe.primary_effect.reached, true);
  assert.equal(probe.primary_effect.body_match, true); // attacker got byte-identical victim object
  assert.equal(verdict.disposition, "confirmed");
  assert.equal(verdict.missing_controls.length, 0);
});

test("DECISIVE FLIP: when the victim object is actually public, no_auth reaches => denied", async () => {
  // The object is public — anon reads it too. The verdict must flip to denied.
  const fetch_fn = makeFakeFetcher({ [`anon ${VICTIM_URL}`]: ok(VICTIM_BODY, null) });
  const { verdict } = await probeVerdict(fetch_fn);
  assert.equal(verdict.disposition, "denied");
  assert.ok(verdict.confounders_present.includes("public_object"));
});

test("NOISE-INVARIANT: a blocked->blocked status change (404->403) leaves the verdict_hash unchanged", async () => {
  const base = await probeVerdict(makeFakeFetcher());
  // Change the nonexistent-object response from 404 to 403 — still blocked, reach unchanged.
  const noisy = await probeVerdict(makeFakeFetcher({ [`attacker ${GHOST_URL}`]: blocked("attacker", 403) }));
  assert.equal(base.verdict.disposition, "confirmed");
  assert.equal(noisy.verdict.disposition, "confirmed");
  assert.equal(noisy.verdict.verdict_hash, base.verdict.verdict_hash);
});

test("NOT A RUBBER STAMP: a target that returns 200 for everything is denied (confounders present)", async () => {
  const everything200 = async ({ url, auth_profile }) => ok({ id: "anything", url }, auth_profile);
  const { verdict } = await probeVerdict(everything200);
  // no_auth / public / nonexistent / stale all reach => multiple confounders present.
  assert.equal(verdict.disposition, "denied");
});

test("DEGRADED => MISSING => inconclusive: a scope-blocked discriminating control is not silently reached=false", async () => {
  const fetch_fn = makeFakeFetcher({
    [`attacker ${GHOST_URL}`]: { status: null, body: null, fetch_error: "scope", scope_decision: "blocked", sent_with_auth: true },
  });
  const probe = await runObjectAuthControlProbe({
    target_domain: "example.com",
    fetch_fn,
    primary: primaryAttack(),
    control_plan: controlPlan(),
  });
  assert.ok(probe.degraded_controls.some((d) => d.control === "nonexistent_object"));
  assert.ok(!("nonexistent_object" in probe.controls));
  const verdict = evaluateObjectAuthDifferential({ primary_effect: probe.primary_effect, controls: probe.controls });
  assert.equal(verdict.disposition, "inconclusive");
  assert.ok(verdict.missing_controls.includes("nonexistent_object"));
});

test("TRUNCATION DEGRADED: a body carrying httpScan's [TRUNCATED] marker is not trusted for the object match", async () => {
  // The attacker response is truncated (shares only the 12 KB prefix with the
  // victim). It must NOT mint a clean body_match — primary degrades to inconclusive.
  const truncated = `${JSON.stringify(VICTIM_BODY)}\n[TRUNCATED — 524288 bytes exceeded transport cap]`;
  const fetch_fn = makeFakeFetcher({
    [`attacker ${VICTIM_URL}`]: { status: 200, body: truncated, sent_with_auth: true },
  });
  const probe = await runObjectAuthControlProbe({
    target_domain: "example.com",
    fetch_fn,
    primary: primaryAttack(),
    control_plan: controlPlan(),
  });
  assert.equal(probe.primary_effect.reached, false);
  assert.equal(probe.primary_effect.degraded, "truncated_body");
});

test("BINARY DEGRADED: a [Binary: ...] summary body is not trusted for the object match", async () => {
  // Two distinct private binaries of the same size+type collapse to the same
  // httpScan summary string — it must not mint body_match.
  const binarySummary = "[Binary: 2097152 bytes (truncated from 5242880), type: application/pdf]";
  const fetch_fn = makeFakeFetcher({
    [`attacker ${VICTIM_URL}`]: { status: 200, body: binarySummary, sent_with_auth: true },
  });
  const probe = await runObjectAuthControlProbe({
    target_domain: "example.com",
    fetch_fn,
    primary: primaryAttack(),
    control_plan: controlPlan(),
  });
  assert.equal(probe.primary_effect.reached, false);
  assert.equal(probe.primary_effect.degraded, "binary_body");
});

test("ANTI-ECHO: a 200 that does NOT return the victim's object bytes is not 'reached' => denied", async () => {
  // An echo/debug endpoint returns 200 but reflects the request rather than the
  // victim object — the attacker did not actually obtain the private object.
  const fetch_fn = makeFakeFetcher({ [`attacker ${VICTIM_URL}`]: ok({ echo: "attacker-supplied" }, "attacker") });
  const probe = await runObjectAuthControlProbe({
    target_domain: "example.com",
    fetch_fn,
    primary: primaryAttack(),
    control_plan: controlPlan(),
  });
  assert.equal(probe.primary_effect.reached, false);
  assert.equal(probe.primary_effect.body_match, false);
  const verdict = evaluateObjectAuthDifferential({ primary_effect: probe.primary_effect, controls: probe.controls });
  assert.equal(verdict.disposition, "denied");
});
