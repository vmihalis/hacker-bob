"use strict";

// Shared test helper: run a body with the verdict-level sandbox-isolation gate
// forced INERT (decision:allow), then restore the real gate function.
//
// Most tests in the suite build a verdict-ledger-backed reportable medium+
// finding to exercise an UNRELATED invariant (executed-flip, CVSS/CWE,
// proof-bundle, reachability, finding-differential, grade math). They are not
// testing the sandbox posture, so the box's same-uid isolation state must not
// change their outcome. Under enforce the real gate would THROW/BLOCK for those
// (signer_not_isolated on a same-uid box); under degrade it would downgrade
// bob_verified -> advisory. Either would corrupt the unrelated assertion. The
// correct stance for an isolation-AGNOSTIC test is "treat the box as isolated":
// the gate is inert and the test passes identically under enforce AND degrade.
//
// Two load-bearing reasons this stubs the GATE FUNCTION rather than the key
// probe:
//   * A probe-isolated-only stub is INSUFFICIENT: seed helpers mint offensive
//     rows via signOffensiveRunRow (v1-HMAC envelope). The gate's
//     has_legacy_or_v1 leg forces decision:"block" EVEN when isolated:true. To
//     make the gate inert regardless of the backing row class, decision must be
//     forced to "allow".
//   * Both verdict seams resolve the gate fresh from the cached module export
//     (require(".../sandbox-isolation-gate.js").evaluateVerdictSandboxGate) at
//     call time — tools/compose-report.js and the bob_write_grade_verdict door —
//     so swapping the property on the cached module object is seen by both.
//
// The real gate's probe/decision logic is exercised by the dedicated sandbox
// tests (compose-report-sandbox-gate, sandbox-isolation-legacy-block,
// sandbox-isolation-live-reprobe, write-grade-verdict-sandbox-gate) instead.

const gateModule = require("../../mcp/core/ledger-integrity/index.js");

function inertDecision() {
  return Object.freeze({
    applies: false,
    mode: "enforce",
    mode_defaulted: false,
    isolated: true,
    attested: true,
    has_legacy_or_v1: false,
    reportable_finding_ids: [],
    decision: "allow",
    reason: "test_isolated_signer",
    probe: null,
  });
}

// SAME-UID MONKEYPATCH — proves the in-process gate is NOT same-uid-tamper-
// resistant. This helper swaps evaluateVerdictSandboxGate on the cached module
// object from WITHIN THE SAME PROCESS at the SAME uid. That it can do so at all is
// the constructive proof that a same-uid actor can rewrite the gate; the gate's
// real security boundary is therefore NOT in-process integrity but the DISTINCT
// AGENT UID under Mechanism A (an agent at a different uid cannot inject into the
// server process). On a same-uid box the live probe returns isolated:false and the
// gate fail-closes anyway, so nothing here is relied on for trust — it only makes
// isolation-agnostic tests deterministic.
//
// The stub is restored in a finally so a thrown body (assert.throws inside the
// wrap) never leaks the stub across tests.
//
// LEAK-SAFE CONTRACT: the restore runs in a finally, scoped to a single call, so
// the stub is gone before the next test. fn MUST be SYNCHRONOUS — if fn returned
// a promise the finally would restore the real gate before the async body ran,
// re-arming the real gate mid-test. All callers pass sync bodies; keep it that
// way (use a per-test inline stub with its own finally for any async need).
function withIsolatedSigner(fn) {
  const realGate = gateModule.evaluateVerdictSandboxGate;
  gateModule.evaluateVerdictSandboxGate = function stubbedIsolatedGate() {
    return inertDecision();
  };
  try {
    return fn();
  } finally {
    gateModule.evaluateVerdictSandboxGate = realGate;
  }
}

module.exports = { withIsolatedSigner };
