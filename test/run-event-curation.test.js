"use strict";

// Lock the pure witness-event projection. curate(rawEvent) -> WitnessEvent | null
// selects the DRAMATIC, NON-SENSITIVE subset of bob's raw ledgers and shapes it to
// the Witness Panel vocabulary (kind/phase/register/weight/signal). The live
// consumer (the hosted-bob runner -> Convex) is external; these tests pin the
// contract that consumer depends on: what is witnessed, in what shape, and the
// fail-closed drop of anything non-dramatic, unrecognized, or sensitive.

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  curate,
  DISPOSITION,
  PHASE,
  projectDisposition,
  severityBand,
} = require("../mcp/lib/run-event-curation.js");

// ---- routing + fail-closed drops -----------------------------------------

test("curate drops anything that is not a plain object", () => {
  assert.equal(curate(null), null);
  assert.equal(curate(undefined), null);
  assert.equal(curate("nope"), null);
  assert.equal(curate(42), null);
  assert.equal(curate([{ plane: "frontier", kind: "session.seeded" }]), null);
});

test("curate returns null for an unrecognized record (no source hint, no sniffable shape)", () => {
  assert.equal(curate({ something: "else" }), null);
});

// ---- frontier curator -----------------------------------------------------

test("frontier session.seeded opens the field as body/wire, no gold", () => {
  const e = curate({ plane: "frontier", kind: "session.seeded", event_hash: "abc123", payload: {} });
  assert.equal(e.kind, "wire");
  assert.equal(e.phase, PHASE.SETUP);
  assert.equal(e.register, "body");
  assert.equal(e.signal, false);
  assert.equal(e.event_hash, "abc123");
  assert.match(e.payload.caption, /I have the scope/);
});

test("frontier surface.observed is accreting breath, never gold, with a bounded route count", () => {
  const e = curate({
    _source: "frontier",
    kind: "surface.observed",
    payload: { surface_type: "api", title: "Admin API", endpoints: ["/a", "/b", "/c"] },
  });
  assert.equal(e.kind, "wire");
  assert.equal(e.phase, PHASE.FRONTIER);
  assert.equal(e.register, "breath");
  assert.equal(e.signal, false);
  assert.equal(e.payload.routes, 3);
  assert.match(e.payload.caption, /I see an API/);
});

test("frontier closure.recorded witnesses tried doors; an empty closure is not dramatic (null)", () => {
  const e = curate({ plane: "frontier", kind: "closure.recorded", surface_id: "s1", payload: { tested: 4, promising: 1 } });
  assert.equal(e.kind, "attempts");
  assert.equal(e.weight, "lit"); // a promising door leans lit
  assert.ok(Array.isArray(e.payload.items) && e.payload.items.length === 2);

  assert.equal(curate({ plane: "frontier", kind: "closure.recorded", payload: {} }), null);
});

test("a non-witnessed frontier kind is dropped (the visitor sees the search, not the scheduler)", () => {
  // REAL FRONTIER_EVENT_KINDS members that are deliberately NOT witnessed — these
  // exercise the WITNESSED_FRONTIER_KINDS filter (the 2nd guard), not the
  // unknown-kind path. Widening that filter to admit one would flip these to
  // non-null, so this genuinely locks the "search, not scheduler" boundary.
  assert.equal(curate({ plane: "frontier", kind: "node.transitioned", payload: {} }), null);
  assert.equal(curate({ plane: "frontier", kind: "frontier.enqueued", payload: {} }), null);
});

// ---- coverage curator -----------------------------------------------------

test("coverage promising lead is lit breath in the matrix face", () => {
  const e = curate({
    _source: "coverage",
    status: "promising",
    endpoint: "/api/users/1",
    bug_class: "idor",
    evidence_summary: "sequential id returns another user",
  });
  assert.equal(e.kind, "matrix");
  assert.equal(e.phase, PHASE.FRONTIER);
  assert.equal(e.weight, "lit");
  assert.equal(e.payload.cols[0].open, true);
});

test("a bare tested coverage record with no summary is dropped (log, not search)", () => {
  assert.equal(curate({ status: "tested", endpoint: "/x", bug_class: "xss" }), null);
  // ...but a tested record that carries bob's own evidence is witnessed honestly.
  const e = curate({ status: "tested", endpoint: "/x", bug_class: "xss", evidence_summary: "reflected but sanitized" });
  assert.equal(e.kind, "matrix");
  assert.equal(e.weight, "dim");
});

// ---- pipeline curator -----------------------------------------------------

test("pipeline session_started + egress_identity_bound are body/wire disclosure, never gold", () => {
  const started = curate({ _source: "pipeline", type: "session_started" });
  assert.equal(started.register, "body");
  assert.equal(started.phase, PHASE.SETUP);
  assert.equal(started.signal, false);

  const egress = curate({ type: "egress_identity_bound", egress_profile: "residential", egress_region: "us-east", egress_profile_identity_hash: "deadbeefcafe1234" });
  assert.equal(egress.kind, "wire");
  assert.equal(egress.register, "body");
  assert.match(egress.payload.caption, /who I am on the wire/);
  assert.equal(egress.signal, false);
});

test("pipeline finding_recorded is the one strike-eligible claim; report_written is the sealing strike", () => {
  const claim = curate({ type: "finding_recorded", identifier_hint: "F-1" });
  assert.equal(claim.kind, "pivot");
  assert.equal(claim.phase, PHASE.CLAIM);
  assert.equal(claim.register, "strike");
  assert.equal(claim.signal, false); // gold rides the disposition at grade, not first sighting

  const sealed = curate({ type: "report_written" });
  assert.equal(sealed.kind, "verdict");
  assert.equal(sealed.phase, PHASE.SEAL);
  assert.equal(sealed.register, "strike");
  assert.equal(sealed.signal, false);
});

test("a non-witnessed pipeline type is dropped", () => {
  assert.equal(curate({ _source: "pipeline", type: "wave_merged" }), null);
});

// ---- grade finding curator (the disposition relens) -----------------------

test("grade finding at fix_now cuts in as a gold strike", () => {
  const e = curate({ _source: "grade", finding_id: "F-9", total_score: 55, reachability: { graded_severity: "high", network_reachable: true, disposition: "unchanged" } });
  assert.equal(e.kind, "verdict");
  assert.equal(e.phase, PHASE.GRADE);
  assert.equal(e.payload.verdict, DISPOSITION.FIX_NOW);
  assert.equal(e.register, "strike");
  assert.equal(e.signal, true); // gold only at fix_now
});

test("a reachability-capped finding is watched, not fix_now, and never gold", () => {
  const e = curate({ finding_id: "F-3", total_score: 55, reachability: { graded_severity: "high", network_reachable: false, disposition: "capped" } });
  assert.notEqual(e.payload.verdict, DISPOSITION.FIX_NOW);
  assert.equal(e.signal, false);
  assert.equal(e.register, "breath");
  assert.match(e.payload.meta, /not reachable/);
});

test("a low-scoring grade finding is held", () => {
  const e = curate({ _source: "grade", finding_id: "F-2", total_score: 10 });
  assert.equal(e.payload.verdict, DISPOSITION.HELD);
  assert.equal(e.signal, false);
});

test("a grade finding with no score is dropped", () => {
  assert.equal(curate({ _source: "grade", finding_id: "F-0" }), null);
});

// ---- fail-closed on sensitive material ------------------------------------

test("a curated event that would leak a secret is dropped (fail closed at the last boundary)", () => {
  // The evidence_summary would land in the matrix `confirm` field; the final
  // validateNoSensitiveMaterial gate throws and curate() catches -> null.
  assert.equal(curate({
    status: "promising",
    endpoint: "/login",
    bug_class: "auth",
    evidence_summary: "Cookie: session=deadbeef; Authorization: Bearer sk-live-1234567890",
  }), null);
});

// ---- exported pure helpers ------------------------------------------------

test("projectDisposition and severityBand are pure and consistent with the four words", () => {
  assert.equal(projectDisposition({ score: 50, band: "high", reportable: true, reachable: true }), DISPOSITION.FIX_NOW);
  assert.equal(projectDisposition({ score: 50, band: "high", reportable: true, reachable: false }), DISPOSITION.WORTH_FIXING);
  assert.equal(projectDisposition({ score: 25, band: "medium", reportable: true, reachable: true }), DISPOSITION.WATCH);
  assert.equal(projectDisposition({ score: 5, band: "low", reportable: false, reachable: true }), DISPOSITION.HELD);
  assert.equal(severityBand(95, "bob"), "critical");
  assert.equal(severityBand(9.5, "cvss"), "critical");
  assert.equal(severityBand(10, "bob"), "low");
});
