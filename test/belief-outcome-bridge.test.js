"use strict";

// Outcome-bridge — the one-way executed-reality -> belief edge.
//
// A live composition verified_pass is ground truth that the attacker-principal
// request reached the SAME victim object the victim authorized request reaches. The
// bridge turns that audit-graded outcome into ONE advisory belief signal that
// sharpens exactly the matching request_equivalence latent toward `equivalent`. The
// invariants under test: NO GATING (belief never alters composition-verified.jsonl),
// KEYING (a verified_pass moves the matching latent and ONLY it; a non-pass emits
// nothing), and COMPLETENESS (no latent dropped — only a posterior sharpened).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendFrontierEvent } = require("../mcp/lib/frontier-events.js");
const { hashCanonicalJson } = require("../mcp/lib/verification-contracts.js");
const { compositionVerifiedJsonlPath } = require("../mcp/lib/paths.js");
const {
  verifyCompositionPath,
  RESULT_VERIFIED_PASS,
  RESULT_REFUTED,
  RESULT_INCONCLUSIVE,
} = require("../mcp/lib/composition-live-verifier.js");
const {
  buildBeliefWindow,
  stableId,
  requestEquivalenceScope,
} = require("../mcp/lib/belief/belief-window.js");
const {
  queryBeliefSignals,
  writeBeliefSignalScratch,
  _internals,
} = require("../mcp/lib/belief/authority.js");

const DOMAIN = "example.com";
const BASE_URL = "https://example.com";

const VICTIM_BODY = { id: "victim-7", email: "victim@example.com", ssn: "111-22-3333" };
const ATTACKER_BODY = { id: "attacker-1", email: "attacker@example.com" };

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-outcome-bridge-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// Shannon entropy in bits — the EIG of a discriminating test is bounded by this.
function entropyBits(distribution) {
  let result = 0;
  for (const value of Object.values(distribution || {})) {
    const p = Number(value) || 0;
    if (p > 0) result -= p * Math.log2(p);
  }
  return result;
}

// Seed the offline observation.recorded a guard leaf binds to (mirrors the live
// verifier's own fixtures): edge_type guard, claimed confirmed, a verdict-flipping
// negative control, and a recomputing replay_hash, so the offline gate accepts it.
function seedGuardObservation(domain, edgeType = "guard", victimUrl = "/api/objects/victim") {
  const request = { method: "GET", url: victimUrl, principal: "attacker" };
  const response = { status: 200, body: "victim-object" };
  const negative_control = {
    request: { ...request, principal: "owner" },
    response: { status: 403, body: "forbidden" },
    verdict: "denied",
  };
  const decisive = { edge_type: edgeType, request, response, verdict: "confirmed", negative_control };
  const payload = { ...decisive, replay_hash: hashCanonicalJson(decisive) };
  const event = appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    ts: "2026-06-01T00:00:00.000Z",
    surface_id: `surface:${edgeType}`,
    payload,
  });
  return { event_id: event.event_id, payload };
}

function ok(body) { return { status: 200, body }; }
function blocked(status = 401) { return { status, body: { error: "unauthorized" } }; }

// A live httpScan whose target IS a genuine IDOR (attacker reads the victim's object).
function makeFakeHttpScan(overrides = {}) {
  return async function httpScanFn(args) {
    const url = args.url;
    const ap = args.auth_profile || "anon";
    const key = `${ap} ${url}`;
    if (Object.prototype.hasOwnProperty.call(overrides, key)) return overrides[key];
    if (url.includes("/objects/ghost")) return blocked(404);
    if (url.includes("/objects/attacker")) return ap === "attacker" ? ok(ATTACKER_BODY) : blocked();
    if (url.includes("/objects/public")) return blocked();
    if (url.includes("/objects/victim")) return (ap === "victim" || ap === "attacker") ? ok(VICTIM_BODY) : blocked();
    return blocked();
  };
}

function guardLeaf(eventId) {
  return {
    evidence_ref: `frontier_event:${eventId}`,
    edge_id: "e-guard",
    primary: { method: "GET", url: "/api/objects/victim", auth_profile: "attacker" },
    control_plan: [
      { control: "attacker_owned_control", method: "GET", url: "/api/objects/attacker", auth_profile: "attacker" },
      { control: "victim_auth_same_object", method: "GET", url: "/api/objects/victim", auth_profile: "victim" },
      { control: "no_auth_same_object", method: "GET", url: "/api/objects/victim" },
      { control: "public_object_check", method: "GET", url: "/api/objects/public" },
      { control: "nonexistent_object", method: "GET", url: "/api/objects/ghost", auth_profile: "attacker" },
      { control: "stale_session_check", method: "GET", url: "/api/objects/victim", auth_profile: "stale" },
      { control: "cache_nonce_check", method: "GET", url: "/api/objects/victim?cb=1", auth_profile: "attacker" },
    ],
  };
}

function readVerifiedLedger(domain) {
  const filePath = compositionVerifiedJsonlPath(domain);
  if (!fs.existsSync(filePath)) return [];
  return fs.readFileSync(filePath, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
}

// The exact variable_id the window mints (and the producer recomputes) for an
// observation's request_equivalence latent.
function expectedVariableId(observationPayload, eventId, baseUrl = BASE_URL) {
  const scope = requestEquivalenceScope(observationPayload, eventId, baseUrl);
  return { scope, variable_id: stableId("BV", { type: "request_equivalence", scope }) };
}

test("PRODUCER: a verified_pass emits exactly one verified_intervention signal keyed to the leaf's request_equivalence latent", async () => {
  await withTempHome(async () => {
    const { event_id, payload } = seedGuardObservation(DOMAIN);
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(event_id)] },
      { httpScanFn: makeFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_VERIFIED_PASS);

    const signals = queryBeliefSignals({
      target_domain: DOMAIN,
      provenance: "verified_intervention",
      role: "evidence",
    }).signals;
    assert.equal(signals.length, 1, "exactly one belief signal");

    const sig = signals[0];
    assert.equal(sig.provenance, "verified_intervention");
    assert.equal(sig.role, "evidence");
    assert.equal(sig.payload.dispatch_authority, false);
    assert.equal(sig.payload.type, "request_equivalence");
    assert.equal(sig.payload.verified_state, "equivalent");

    const { scope, variable_id } = expectedVariableId(payload, event_id);
    assert.equal(sig.payload.latent_id, variable_id, "latent_id == window variable_id by construction");
    // scope.source_event_id == the leaf evidence_ref event id; endpoint/method match
    // the offline request after belief-window-style normalization.
    assert.equal(sig.payload.scope.source_event_id, event_id);
    assert.equal(sig.payload.scope.endpoint, scope.endpoint);
    assert.equal(sig.payload.scope.endpoint, "/api/objects/victim");
    assert.equal(sig.payload.scope.method, "GET");
    // artifact_ref binds to THIS verified row's results_hash.
    assert.equal(sig.artifact_ref, `composition_verified:${out.results_hash}`);
    assert.equal(sig.payload.results_hash, out.results_hash);
  });
});

test("CONSUMER: buildBeliefWindow sharpens the matching latent to ~0.9 equivalent, prior_source verified_intervention, lower entropy", async () => {
  await withTempHome(async () => {
    const { event_id, payload } = seedGuardObservation(DOMAIN);
    const { variable_id } = expectedVariableId(payload, event_id);

    // Pre-emit: the latent exists in the window at the uniform prior (1.585 bits).
    const before = buildBeliefWindow({ target_domain: DOMAIN, base_url: BASE_URL });
    const reqBefore = before.variables.find((v) => v.variable_id === variable_id);
    assert.ok(reqBefore, "request_equivalence latent present before the verified_pass");
    assert.equal(reqBefore.prior_source, "uniform");
    const entropyBefore = entropyBits(reqBefore.posterior);
    assert.ok(Math.abs(entropyBefore - 1.585) < 0.01, "uniform over 3 states ~ 1.585 bits");

    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(event_id)] },
      { httpScanFn: makeFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_VERIFIED_PASS);

    const after = buildBeliefWindow({ target_domain: DOMAIN, base_url: BASE_URL });
    const reqAfter = after.variables.find((v) => v.variable_id === variable_id);
    assert.ok(reqAfter, "latent still present — COMPLETENESS, nothing dropped");
    assert.equal(reqAfter.prior_source, "verified_intervention");
    assert.ok(Math.abs(reqAfter.posterior.equivalent - 0.9) < 1e-9);
    assert.ok(reqAfter.posterior.distinct < 0.2 && reqAfter.posterior.unknown < 0.2);
    const entropyAfter = entropyBits(reqAfter.posterior);
    assert.ok(entropyAfter < entropyBefore, "entropy strictly drops vs the pre-emit uniform");
    // EIG of any candidate keyed on this latent = entropy(posterior), so it drops too.
    assert.ok(entropyAfter < 1.585);
  });
});

test("KEYING: only the matching latent moves; every other window variable is byte-identical to the no-signal run", async () => {
  await withTempHome(async () => {
    const { event_id, payload } = seedGuardObservation(DOMAIN);
    const { variable_id } = expectedVariableId(payload, event_id);

    const before = buildBeliefWindow({ target_domain: DOMAIN, base_url: BASE_URL });
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(event_id)] },
      { httpScanFn: makeFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_VERIFIED_PASS);
    const after = buildBeliefWindow({ target_domain: DOMAIN, base_url: BASE_URL });

    const byId = (w) => new Map(w.variables.map((v) => [v.variable_id, v]));
    const beforeById = byId(before);
    const afterById = byId(after);
    // Same set of latents (no add/drop).
    assert.deepEqual(
      [...afterById.keys()].sort(),
      [...beforeById.keys()].sort(),
      "no latent added or dropped",
    );
    for (const [id, varAfter] of afterById) {
      const varBefore = beforeById.get(id);
      if (id === variable_id) {
        assert.notDeepEqual(varAfter.posterior, varBefore.posterior, "matching latent sharpened");
        continue;
      }
      assert.deepEqual(varAfter, varBefore, `non-matching latent ${id} is byte-identical`);
    }
  });
});

test("KEYING: a verified leaf whose reconstructed variable_id matches NO window variable is a no-op (nothing sharpens)", async () => {
  await withTempHome(async () => {
    const { event_id } = seedGuardObservation(DOMAIN);
    // Snapshot the window with NO verified signals.
    const baseline = buildBeliefWindow({ target_domain: DOMAIN, base_url: BASE_URL });

    // Inject a verified_intervention signal whose latent_id matches no window variable.
    writeBeliefSignalScratch({
      target_domain: DOMAIN,
      kind: "belief_signal",
      source: "composition-live-verifier",
      provenance: "verified_intervention",
      role: "evidence",
      artifact_ref: "composition_verified:deadbeef",
      payload: {
        latent_id: "BV-does-not-exist-000000000000",
        type: "request_equivalence",
        scope: { endpoint: "/nope", method: "GET", source_event_id: "no-such-event" },
        verified_state: "equivalent",
        distribution: { equivalent: 0.9, distinct: 0.05, unknown: 0.05 },
        dispatch_authority: false,
      },
    });

    const after = buildBeliefWindow({ target_domain: DOMAIN, base_url: BASE_URL });
    // The orphan signal sharpens nothing: every variable is byte-identical.
    assert.equal(after.window_hash, baseline.window_hash, "orphan verified signal is a no-op");
    assert.ok(event_id);
  });
});

test("NON-PASS: a refuted path emits ZERO verified_intervention signals", async () => {
  await withTempHome(async () => {
    const { event_id } = seedGuardObservation(DOMAIN);
    // The live target is patched: the attacker is blocked on the victim object.
    const patched = makeFakeHttpScan({ "attacker https://example.com/api/objects/victim": blocked(403) });
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(event_id)] },
      { httpScanFn: patched },
    );
    assert.equal(out.result, RESULT_REFUTED);
    const signals = queryBeliefSignals({
      target_domain: DOMAIN,
      provenance: "verified_intervention",
      role: "evidence",
    }).signals;
    assert.equal(signals.length, 0);
  });
});

test("NON-PASS: an inconclusive (K=1 non-guard) path emits ZERO verified_intervention signals", async () => {
  await withTempHome(async () => {
    const { event_id } = seedGuardObservation(DOMAIN, "sink"); // shape-valid sink => inconclusive
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(event_id)] },
      { httpScanFn: makeFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_INCONCLUSIVE);
    const signals = queryBeliefSignals({
      target_domain: DOMAIN,
      provenance: "verified_intervention",
      role: "evidence",
    }).signals;
    assert.equal(signals.length, 0);
  });
});

test("NO GATING: the audit-graded composition-verified.jsonl row is byte-identical whether or not the belief emit succeeds", async () => {
  // Run 1: belief emit succeeds normally.
  const recordA = await withTempHome(async () => {
    const { event_id } = seedGuardObservation(DOMAIN);
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(event_id)] },
      { httpScanFn: makeFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_VERIFIED_PASS);
    const ledger = readVerifiedLedger(DOMAIN);
    assert.equal(ledger.length, 1);
    return ledger[0];
  });

  // Run 2: force the belief write to throw — the verified row must be identical.
  const authority = require("../mcp/lib/belief/authority.js");
  const original = authority.writeBeliefSignalScratch;
  const recordB = await withTempHome(async () => {
    authority.writeBeliefSignalScratch = () => { throw new Error("forced belief write failure"); };
    try {
      const { event_id } = seedGuardObservation(DOMAIN);
      const out = await verifyCompositionPath(
        { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(event_id)] },
        { httpScanFn: makeFakeHttpScan() },
      );
      assert.equal(out.result, RESULT_VERIFIED_PASS, "belief failure does not change result");
      const ledger = readVerifiedLedger(DOMAIN);
      assert.equal(ledger.length, 1);
      // The forced failure means NO belief signal landed.
      const signals = queryBeliefSignals({
        target_domain: DOMAIN,
        provenance: "verified_intervention",
        role: "evidence",
      }).signals;
      assert.equal(signals.length, 0, "no signal on forced failure");
      return ledger[0];
    } finally {
      authority.writeBeliefSignalScratch = original;
    }
  });

  // The audit-graded row's belief-INDEPENDENT content is identical whether the belief
  // emit succeeds or is forced to throw. (`ts`/`results_hash` are wall-clock derived,
  // not belief derived, so they legitimately differ across the two separate runs; the
  // point is that NOTHING the belief edge does feeds back into the verified record.)
  assert.equal(recordA.result, recordB.result);
  assert.equal(recordA.path_hash, recordB.path_hash);
  assert.equal(recordA.leaf_count, recordB.leaf_count);
  assert.equal(recordA.verified_leaf_count, recordB.verified_leaf_count);
  assert.deepEqual(recordA.leaves, recordB.leaves);
  // The verified record carries NO belief-derived field at all.
  assert.equal(Object.prototype.hasOwnProperty.call(recordA, "belief"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(recordA, "belief_signal"), false);
});

test("AUTHORITY: provenance=verified_intervention with role=evidence is accepted by normalizeSignal (not deny-railed)", () => {
  const signal = _internals.normalizeSignal({
    kind: "belief_signal",
    source: "composition-live-verifier",
    provenance: "verified_intervention",
    role: "evidence",
    artifact_ref: "composition_verified:abc",
    payload: {
      latent_id: "BV-xyz",
      type: "request_equivalence",
      distribution: { equivalent: 0.9, distinct: 0.05, unknown: 0.05 },
      dispatch_authority: false,
    },
  });
  assert.equal(signal.provenance, "verified_intervention");
  assert.equal(signal.role, "evidence");
  assert.equal(signal.advisory, true);
  assert.equal(signal.derived, true);
  assert.equal(signal.scratch, true);
});
