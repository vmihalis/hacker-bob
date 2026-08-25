"use strict";

// A6L + L1 coverage: the post-report evidence-completion gate
// (evaluateEvidenceCompletion) sources lifecycle_state authoritatively from a
// VERIFIED session-nucleus.json (so neither a drifted state.json NOR an
// unverifiable/tampered/absent nucleus can mis-gate it) and admits an
// evidence run only inside the post-report window.
//
// Allowed:  lifecycle_state REPORT (the evidence-amplification window), or
//           OPEN_FRONTIER when the latest governance.lifecycle.advanced event
//           binds the current nucleus hash (top+payload) and records a
//           REPORT/GRADE -> OPEN_FRONTIER re-entry.
// Blocked:  CLAIM_FREEZE / VERIFY / GRADE; OPEN_FRONTIER with no advance
//           event, an advance event that does not bind the current nucleus
//           hash, an advance event that is not a REPORT/GRADE re-entry (e.g.
//           the initial SETUP -> OPEN_FRONTIER move, which is active
//           evaluation, not an evidence window), and an OPEN_FRONTIER whose
//           latest advance event is a later non-qualifying transition even
//           when an earlier, now-stale, qualifying event exists in the same
//           ledger. Also blocked: any session whose nucleus is absent or
//           fails verification (A6L) — the gate never falls back to
//           state.json's own lifecycle_state, and it never reads state.json
//           at all.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { evaluateEvidenceCompletion } = require("../mcp/core/session/agent-run-completion.js");
const { appendSessionEvent, readSessionEvents } = require("../mcp/core/session/session-events.js");
const { sessionDir, statePath, sessionEventsJsonlPath, sessionNucleusPath } = require("../mcp/core/io/paths.js");
const { buildSessionNucleus } = require("../mcp/core/governance/index.js");
const { deriveBlockInternalHostsPolicy } = require("../mcp/core/session/session-state-contracts.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-evidence-gate-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// Write an explicit (state.json, session-nucleus.json) pair so the gate reads
// exactly the lifecycle_state we want (no synthesis fallback). The nucleus,
// when present, is a genuine canonically-hashed SessionNucleus so it passes
// readVerifiedSessionNucleus's verification. Returns the nucleus's
// nucleus_hash (or null when no nucleus was written) so callers can bind
// session-events.jsonl records to it.
function seedSession(domain, { stateLifecycle, nucleusLifecycle } = {}) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  const state = {};
  if (stateLifecycle !== undefined) state.lifecycle_state = stateLifecycle;
  fs.writeFileSync(statePath(domain), `${JSON.stringify(state, null, 2)}\n`, "utf8");
  if (nucleusLifecycle === undefined) return null;
  const nucleus = buildSessionNucleus({
    target_domain: domain,
    target_url: `https://${domain}`,
    lifecycle_state: nucleusLifecycle,
    scope_policy: deriveBlockInternalHostsPolicy({ legacyDefault: true }),
  });
  fs.writeFileSync(sessionNucleusPath(domain), `${JSON.stringify(nucleus, null, 2)}\n`, "utf8");
  return nucleus.nucleus_hash;
}

// Append a genuine, correctly-hashed governance.lifecycle.advanced event.
// boundNucleusHash controls whether the event's (top-level + payload)
// nucleus_hash binds the given hash, or an unrelated one, for the
// "does not bind the current nucleus hash" negative case.
function writeAdvanceEvent(domain, { fromState, toState, boundNucleusHash, actualNucleusHash }) {
  const hash = boundNucleusHash === false
    ? "f".repeat(64)
    : actualNucleusHash;
  appendSessionEvent({
    target_domain: domain,
    kind: "governance.lifecycle.advanced",
    nucleus_hash: hash,
    payload: {
      from_state: fromState,
      to_state: toState,
      nucleus_hash: hash,
    },
  });
}

function evaluate(domain) {
  return evaluateEvidenceCompletion({ target_domain: domain });
}

test("ALLOW: REPORT lifecycle_state admits a post-report evidence run", () => {
  withTempHome(() => {
    const domain = "evi-report.example.com";
    seedSession(domain, { stateLifecycle: "REPORT", nucleusLifecycle: "REPORT" });
    const r = evaluate(domain);
    assert.equal(r.ok, true, "REPORT must allow evidence");
    assert.equal(r.handoff.provenance, "post_report_evidence");
  });
});

test("ALLOW DRIFT: nucleus=REPORT overrides a stale state.json=CLAIM_FREEZE (nucleus is authoritative)", () => {
  withTempHome(() => {
    const domain = "evi-drift-allow.example.com";
    // The exact drift class the nucleus-only gate exists to close: state.json
    // lagging behind the nucleus. The nucleus (REPORT) must decide, not the
    // stale state.json (CLAIM_FREEZE) — and the gate never even reads state.json.
    seedSession(domain, { stateLifecycle: "CLAIM_FREEZE", nucleusLifecycle: "REPORT" });
    assert.equal(evaluate(domain).ok, true, "nucleus=REPORT must win over a drifted state.json=CLAIM_FREEZE");
  });
});

test("ALLOW: OPEN_FRONTIER whose latest advance event binds the current nucleus hash and records REPORT -> OPEN_FRONTIER", () => {
  withTempHome(() => {
    const domain = "evi-reentry-report.example.com";
    const nucleusHash = seedSession(domain, { stateLifecycle: "OPEN_FRONTIER", nucleusLifecycle: "OPEN_FRONTIER" });
    writeAdvanceEvent(domain, { fromState: "REPORT", toState: "OPEN_FRONTIER", actualNucleusHash: nucleusHash });
    const r = evaluate(domain);
    assert.equal(r.ok, true, "a hash-bound REPORT -> OPEN_FRONTIER advance event must admit evidence");
    assert.equal(r.handoff.provenance, "post_report_evidence");
  });
});

test("ALLOW: OPEN_FRONTIER whose latest advance event binds the current nucleus hash and records GRADE -> OPEN_FRONTIER", () => {
  withTempHome(() => {
    const domain = "evi-reentry-grade.example.com";
    const nucleusHash = seedSession(domain, { stateLifecycle: "OPEN_FRONTIER", nucleusLifecycle: "OPEN_FRONTIER" });
    writeAdvanceEvent(domain, { fromState: "GRADE", toState: "OPEN_FRONTIER", actualNucleusHash: nucleusHash });
    assert.equal(evaluate(domain).ok, true, "a hash-bound GRADE -> OPEN_FRONTIER advance event must admit evidence");
  });
});

test("BLOCK: OPEN_FRONTIER with no lifecycle.advanced event in the ledger admits nothing", () => {
  withTempHome(() => {
    const domain = "evi-no-advance.example.com";
    seedSession(domain, { stateLifecycle: "OPEN_FRONTIER", nucleusLifecycle: "OPEN_FRONTIER" });
    assert.equal(fs.existsSync(sessionEventsJsonlPath(domain)), false);
    const r = evaluate(domain);
    assert.equal(r.ok, false, "a missing advance ledger must never grant evidence eligibility");
    assert.equal(r.block_code, "evidence_phase_mismatch");
  });
});

test("BLOCK: OPEN_FRONTIER latest advance event does not bind the current nucleus hash", () => {
  withTempHome(() => {
    const domain = "evi-unbound-advance.example.com";
    const nucleusHash = seedSession(domain, { stateLifecycle: "OPEN_FRONTIER", nucleusLifecycle: "OPEN_FRONTIER" });
    writeAdvanceEvent(domain, {
      fromState: "REPORT",
      toState: "OPEN_FRONTIER",
      actualNucleusHash: nucleusHash,
      boundNucleusHash: false,
    });
    const r = evaluate(domain);
    assert.equal(r.ok, false, "an advance event bound to a different nucleus hash must never grant evidence eligibility");
    assert.equal(r.block_code, "evidence_phase_mismatch");
  });
});

test("BLOCK: OPEN_FRONTIER latest advance event is active evaluation (SETUP -> OPEN_FRONTIER), not a re-entry", () => {
  withTempHome(() => {
    const domain = "evi-active-eval.example.com";
    // Every first-time frontier pass lands exactly this event; it must stay
    // blocked or an active evaluator run would be admitted as an evidence run.
    const nucleusHash = seedSession(domain, { stateLifecycle: "OPEN_FRONTIER", nucleusLifecycle: "OPEN_FRONTIER" });
    writeAdvanceEvent(domain, { fromState: "SETUP", toState: "OPEN_FRONTIER", actualNucleusHash: nucleusHash });
    const r = evaluate(domain);
    assert.equal(r.ok, false, "SETUP -> OPEN_FRONTIER (active evaluation) must block evidence");
    assert.equal(r.block_code, "evidence_phase_mismatch");
  });
});

test("BLOCK: an earlier, now-stale REPORT -> OPEN_FRONTIER event grants nothing once a later non-qualifying advance is the latest", () => {
  withTempHome(() => {
    const domain = "evi-stale-advance.example.com";
    const nucleusHash = seedSession(domain, { stateLifecycle: "OPEN_FRONTIER", nucleusLifecycle: "OPEN_FRONTIER" });
    // A genuine qualifying re-entry happened once...
    writeAdvanceEvent(domain, { fromState: "REPORT", toState: "OPEN_FRONTIER", actualNucleusHash: nucleusHash });
    // ...but the session moved on and came back to OPEN_FRONTIER a second time
    // through a non-qualifying edge (the CLAIM_FREEZE <-> OPEN_FRONTIER back-edge).
    // Only the LATEST advance event may decide; the earlier qualifying record
    // must not be picked up from history.
    writeAdvanceEvent(domain, { fromState: "CLAIM_FREEZE", toState: "OPEN_FRONTIER", actualNucleusHash: nucleusHash });
    const events = readSessionEvents(domain).filter((event) => event.kind === "governance.lifecycle.advanced");
    assert.equal(events.length, 2);
    const r = evaluate(domain);
    assert.equal(r.ok, false, "the latest advance event governs; a stale earlier qualifying record must grant nothing");
    assert.equal(r.block_code, "evidence_phase_mismatch");
  });
});

test("BLOCK: VERIFY lifecycle_state rejects an evidence run", () => {
  withTempHome(() => {
    const domain = "evi-verify.example.com";
    seedSession(domain, { stateLifecycle: "VERIFY", nucleusLifecycle: "VERIFY" });
    assert.equal(evaluate(domain).ok, false, "VERIFY must block evidence");
  });
});

test("BLOCK: CLAIM_FREEZE lifecycle_state rejects an evidence run (no drift)", () => {
  withTempHome(() => {
    const domain = "evi-claimfreeze.example.com";
    seedSession(domain, { stateLifecycle: "CLAIM_FREEZE", nucleusLifecycle: "CLAIM_FREEZE" });
    assert.equal(evaluate(domain).ok, false, "CLAIM_FREEZE must block evidence");
  });
});

test("BLOCK DRIFT: nucleus=VERIFY overrides a stale state.json=REPORT (nucleus authoritative both ways)", () => {
  withTempHome(() => {
    const domain = "evi-drift-block.example.com";
    // state.json is MORE permissive (REPORT) but the nucleus says VERIFY — the
    // gate must trust the nucleus and BLOCK, proving authority is not one-sided.
    seedSession(domain, { stateLifecycle: "REPORT", nucleusLifecycle: "VERIFY" });
    assert.equal(evaluate(domain).ok, false, "nucleus=VERIFY must override a stale state.json=REPORT");
  });
});

test("BLOCK: absent session-nucleus.json fails closed instead of trusting a permissive state.json (A6L)", () => {
  withTempHome(() => {
    const domain = "evi-no-nucleus.example.com";
    // No nucleusLifecycle supplied: state.json exists but session-nucleus.json
    // does not. The gate must never synthesize a nucleus from state.json here.
    seedSession(domain, { stateLifecycle: "REPORT" });
    const r = evaluate(domain);
    assert.equal(r.ok, false, "an unverifiable/absent nucleus must never silently grant evidence eligibility");
    assert.equal(r.block_code, "evidence_nucleus_unverified");
  });
});

test("BLOCK: tampered session-nucleus.json (hash does not match content) fails closed (A6L)", () => {
  withTempHome(() => {
    const domain = "evi-tampered-nucleus.example.com";
    seedSession(domain, { stateLifecycle: "REPORT", nucleusLifecycle: "REPORT" });
    // Corrupt the nucleus in place: flip lifecycle_state without recomputing
    // nucleus_hash, so readVerifiedSessionNucleus's tamper check must reject it.
    const nucleus = JSON.parse(fs.readFileSync(sessionNucleusPath(domain), "utf8"));
    nucleus.lifecycle_state = "VERIFY";
    fs.writeFileSync(sessionNucleusPath(domain), `${JSON.stringify(nucleus, null, 2)}\n`, "utf8");
    const r = evaluate(domain);
    assert.equal(r.ok, false, "a tampered nucleus must never be trusted for evidence eligibility");
    assert.equal(r.block_code, "evidence_nucleus_unverified");
  });
});
