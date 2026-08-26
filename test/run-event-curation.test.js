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
  DEFENDER_DISPOSITION_VALUES,
  PHASE,
} = require("../mcp/core/telemetry/run-event-curation.js");

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

// ---- grade finding curator (consumes the verdict's stamped word) ----------

test("grade finding: the stamped fix_now word is consumed verbatim as a gold strike (live == sealed)", () => {
  // A real grade.json finding carries the verdict's stamped defender_disposition.
  const e = curate({ _source: "grade", finding_id: "F-9", total_score: 55, defender_disposition: "fix_now", reachability: { graded_severity: "high", network_reachable: true, disposition: "unchanged" } });
  assert.equal(e.kind, "verdict");
  assert.equal(e.phase, PHASE.GRADE);
  assert.equal(e.payload.verdict, "fix_now"); // canonical snake_case, identical to grade.json
  assert.equal(e.register, "strike");
  assert.equal(e.signal, true); // gold only at fix_now
});

test("grade finding: a capped worth_fixing is streamed as-stamped, never gold, and reads not-reachable", () => {
  // The verdict already resolved the capped finding to worth_fixing; curate does not
  // second-guess it. Reachability drives only the display band/meta, not the word.
  const e = curate({ finding_id: "F-3", total_score: 55, defender_disposition: "worth_fixing", reachability: { graded_severity: "high", network_reachable: false, disposition: "capped" } });
  assert.equal(e.payload.verdict, "worth_fixing");
  assert.notEqual(e.payload.verdict, "fix_now");
  assert.equal(e.signal, false);
  assert.equal(e.register, "breath");
  assert.match(e.payload.meta, /not reachable/);
});

test("grade finding: a stamped held word is consumed as held", () => {
  const e = curate({ _source: "grade", finding_id: "F-2", total_score: 10, defender_disposition: "held" });
  assert.equal(e.payload.verdict, "held");
  assert.equal(e.signal, false);
});

test("grade finding: an unstamped finding streams conservatively as held (never re-derived / over-stated)", () => {
  // No defender_disposition (legacy/malformed grade.json). curate must NOT re-derive
  // a word from the rubric score — a high score with no stamp still reads held, so a
  // fail-open sniff can never promote a held finding to worth-fixing on the surface.
  const e = curate({ _source: "grade", finding_id: "F-7", total_score: 95 });
  assert.equal(e.payload.verdict, "held");
  assert.equal(e.signal, false);
  assert.equal(e.register, "breath");
});

test("grade finding: the witness word is drawn from the same canonical vocabulary the verdict stamps", () => {
  for (const word of DEFENDER_DISPOSITION_VALUES) {
    const e = curate({ _source: "grade", finding_id: "F-1", total_score: 50, defender_disposition: word });
    assert.equal(e.payload.verdict, word, `witness word must equal the sealed word ${word}`);
  }
});

test("a grade finding with no score is dropped", () => {
  assert.equal(curate({ _source: "grade", finding_id: "F-0", defender_disposition: "fix_now" }), null);
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

test("the witness vocabulary is exactly the canonical defender vocabulary (single source, snake_case)", () => {
  assert.deepEqual(DEFENDER_DISPOSITION_VALUES, ["fix_now", "worth_fixing", "watch", "held"]);
});

test("grade finding: the display band is the graded SEVERITY, never the 0-100 rubric score", () => {
  // A high rubric score with NO severity of any kind must NOT be lit — the rubric
  // score is not a severity. No graded severity => no band, dim weight.
  const e = curate({ _source: "grade", finding_id: "F-hi", total_score: 95, defender_disposition: "held" });
  assert.equal(e.payload.total, "", "no severity => no fabricated band");
  assert.equal(e.weight, "dim");
  // With a reachability graded severity, the band IS that severity.
  const g = curate({ _source: "grade", finding_id: "F-g", total_score: 30, defender_disposition: "worth_fixing", reachability: { graded_severity: "high", network_reachable: true, disposition: "unchanged" } });
  assert.equal(g.payload.total, "high");
  assert.equal(g.weight, "lit");
});

test("grade finding: a severe LIVE-TARGET finding (no reachability stamp, top-level graded_severity) still lights", () => {
  // Web/SC targets have unknown reachability, so grade-verdict-store carries the
  // graded severity top-level. The witness must read it and light a severe finding —
  // not render it dim/unlit (the bug that would ship every web/SC high as breath).
  const e = curate({ _source: "grade", finding_id: "F-web", total_score: 60, defender_disposition: "fix_now", graded_severity: "critical" });
  assert.equal(e.payload.total, "critical");
  assert.equal(e.weight, "lit");
  assert.equal(e.signal, true);
  const h = curate({ _source: "grade", finding_id: "F-web2", total_score: 55, defender_disposition: "fix_now", graded_severity: "high" });
  assert.equal(h.payload.total, "high");
  assert.equal(h.weight, "lit");
});

test("grade finding: unknown reachability makes no claim — the customer is never told 'reachable' on absence", () => {
  const e = curate({ _source: "grade", finding_id: "F-u", total_score: 50, defender_disposition: "worth_fixing" });
  assert.equal(e.payload.meta, "", "no reachability stamp => no reachable/not-reachable claim");
});

test("coverage: a query string / fragment is stripped from the witnessed endpoint (no path-embedded token/PII leak)", () => {
  const e = curate({
    status: "promising",
    endpoint: "/account/reset?token=super-secret-value&uid=alice",
    bug_class: "auth",
    evidence_summary: "reset flow accepts a replayed token",
  });
  // Only the path is witnessed; the query (with the token) is gone from every field.
  assert.equal(e.payload.cols[0].name, "/account/reset");
  assert.match(e.payload.caption, /I test \/account\/reset\./);
  assert.ok(!JSON.stringify(e).includes("super-secret-value"), "the query token must not appear anywhere in the event");
});
