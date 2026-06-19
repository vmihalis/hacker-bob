"use strict";

// Step 4 coverage: the post-report evidence-completion gate
// (evaluateEvidenceCompletion) sources lifecycle_state authoritatively from
// session-nucleus.json (so a drifted state.json cannot mis-gate it) and admits
// an evidence run only inside the post-report window.
//
// Allowed:  lifecycle_state REPORT (the evidence-amplification window), or
//           OPEN_FRONTIER when the legacy phase confirms an explicit EXPLORE
//           re-entry. advanceSession stamps phase EXPLORE when OPEN_FRONTIER is
//           re-entered from REPORT/GRADE, so the post-report evidence/re-mine
//           window is admitted (see test/lifecycle-advance.test.js
//           "REPORT -> OPEN_FRONTIER re-entry stamps legacy phase EXPLORE").
// Blocked:  CLAIM_FREEZE / VERIFY / GRADE, and — critically — OPEN_FRONTIER with
//           phase EVALUATE, which is ACTIVE evaluation (a first-time frontier
//           pass, NOT a post-report re-entry). The nucleus read SYNTHESIZES
//           OPEN_FRONTIER from a legacy phase=EVALUATE session, so the phase
//           discriminator is what keeps active evaluation blocked while still
//           admitting the EXPLORE re-entry. Dropping the discriminator would
//           newly admit evidence during active evaluation — see
//           test/mcp-server.test.js "blocks evidence markers before REPORT or
//           EXPLORE".
//
// The gate reads state.json directly and the nucleus via readSessionNucleus,
// which synthesizes a nucleus from state.json when no nucleus file exists — so
// each case writes an explicit session-nucleus.json to control lifecycle_state.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { evaluateEvidenceCompletion } = require("../mcp/lib/agent-run-completion.js");
const { sessionDir, statePath } = require("../mcp/lib/paths.js");

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
// exactly the lifecycle_state/phase we want (no synthesis fallback).
function seedSession(domain, { stateLifecycle, statePhase, nucleusLifecycle }) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  const state = {};
  if (stateLifecycle !== undefined) state.lifecycle_state = stateLifecycle;
  if (statePhase !== undefined) state.phase = statePhase;
  fs.writeFileSync(statePath(domain), `${JSON.stringify(state, null, 2)}\n`, "utf8");
  if (nucleusLifecycle !== undefined) {
    fs.writeFileSync(
      path.join(dir, "session-nucleus.json"),
      `${JSON.stringify({ lifecycle_state: nucleusLifecycle }, null, 2)}\n`,
      "utf8",
    );
  }
}

function evaluate(domain) {
  return evaluateEvidenceCompletion({ target_domain: domain });
}

test("ALLOW: REPORT lifecycle_state admits a post-report evidence run", () => {
  withTempHome(() => {
    const domain = "evi-report.example.com";
    seedSession(domain, { stateLifecycle: "REPORT", statePhase: "REPORT", nucleusLifecycle: "REPORT" });
    const r = evaluate(domain);
    assert.equal(r.ok, true, "REPORT must allow evidence");
    assert.equal(r.handoff.provenance, "post_report_evidence");
  });
});

test("ALLOW DRIFT: nucleus=REPORT overrides a stale state.json=CLAIM_FREEZE (nucleus is authoritative)", () => {
  withTempHome(() => {
    const domain = "evi-drift-allow.example.com";
    // The exact Step-4 drift class: state.json lagging behind the nucleus.
    // The nucleus (REPORT) must decide, not the stale state.json (CLAIM_FREEZE).
    seedSession(domain, { stateLifecycle: "CLAIM_FREEZE", statePhase: "CHAIN", nucleusLifecycle: "REPORT" });
    assert.equal(evaluate(domain).ok, true, "nucleus=REPORT must win over a drifted state.json=CLAIM_FREEZE");
  });
});

test("ALLOW: OPEN_FRONTIER with explicit legacy phase EXPLORE is the legacy re-entry window", () => {
  withTempHome(() => {
    const domain = "evi-explore.example.com";
    seedSession(domain, { stateLifecycle: "OPEN_FRONTIER", statePhase: "EXPLORE", nucleusLifecycle: "OPEN_FRONTIER" });
    assert.equal(evaluate(domain).ok, true, "OPEN_FRONTIER + phase EXPLORE must allow evidence");
  });
});

test("BLOCK: OPEN_FRONTIER with phase EVALUATE stays blocked (active evaluate / re-eval, not an evidence window)", () => {
  withTempHome(() => {
    const domain = "evi-evaluate.example.com";
    // advanceSession stamps every OPEN_FRONTIER as phase EVALUATE; the phase
    // discriminator must keep this blocked (dropping it would admit evidence
    // during active evaluation).
    seedSession(domain, { stateLifecycle: "OPEN_FRONTIER", statePhase: "EVALUATE", nucleusLifecycle: "OPEN_FRONTIER" });
    const r = evaluate(domain);
    assert.equal(r.ok, false, "OPEN_FRONTIER + phase EVALUATE must block evidence");
    assert.equal(r.block_code, "evidence_phase_mismatch");
  });
});

test("BLOCK: VERIFY lifecycle_state rejects an evidence run", () => {
  withTempHome(() => {
    const domain = "evi-verify.example.com";
    seedSession(domain, { stateLifecycle: "VERIFY", statePhase: "VERIFY", nucleusLifecycle: "VERIFY" });
    assert.equal(evaluate(domain).ok, false, "VERIFY must block evidence");
  });
});

test("BLOCK: CLAIM_FREEZE lifecycle_state rejects an evidence run (no drift)", () => {
  withTempHome(() => {
    const domain = "evi-claimfreeze.example.com";
    seedSession(domain, { stateLifecycle: "CLAIM_FREEZE", statePhase: "CHAIN", nucleusLifecycle: "CLAIM_FREEZE" });
    assert.equal(evaluate(domain).ok, false, "CLAIM_FREEZE must block evidence");
  });
});

test("BLOCK DRIFT: nucleus=VERIFY overrides a stale state.json=REPORT (nucleus authoritative both ways)", () => {
  withTempHome(() => {
    const domain = "evi-drift-block.example.com";
    // state.json is MORE permissive (REPORT) but the nucleus says VERIFY — the
    // gate must trust the nucleus and BLOCK, proving authority is not one-sided.
    seedSession(domain, { stateLifecycle: "REPORT", statePhase: "REPORT", nucleusLifecycle: "VERIFY" });
    assert.equal(evaluate(domain).ok, false, "nucleus=VERIFY must override a stale state.json=REPORT");
  });
});
