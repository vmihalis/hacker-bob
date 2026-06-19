"use strict";

// Step 4 regression: single-source-of-truth lifecycle state. advanceSession
// must never leave session-nucleus.json and state.json disagreeing, even when
// the fallible VERIFY-bootstrap work throws mid-transition.
//
// The historical ordering wrote the nucleus FIRST and unconditionally, then ran
// prepareVerificationEntry; a throw there advanced the nucleus to VERIFY while
// state.json stayed at CLAIM_FREEZE — a permanent split-brain. The fix runs all
// fallible work before any durable lifecycle write and writes the nucleus LAST,
// with a symmetric rollback of BOTH stores on any throw after the first write.
//
// Test G: stub prepareVerificationEntry to throw -> advanceSession->VERIFY
//         throws AND both stores still AGREE at CLAIM_FREEZE.
// Test H: stub refreshVerificationManifest to throw -> both stores roll back.
// Test I (happy path): no stub -> both stores reach VERIFY and the snapshot
//         exists.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  advanceSession,
  initSession,
} = require("../mcp/lib/session-state.js");
const {
  readSessionNucleus,
} = require("../mcp/lib/governance-store.js");
const {
  statePath,
  verificationSnapshotPath,
} = require("../mcp/lib/paths.js");
const verificationModule = require("../mcp/lib/verification.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-lifecycle-drift-"));
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

function driveToClaimFreeze(domain) {
  initSession({ target_domain: domain, target_url: `https://${domain}/` });
  JSON.parse(advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER" }));
  JSON.parse(advanceSession({ target_domain: domain, to_state: "CLAIM_FREEZE" }));
}

function readStateJson(domain) {
  return JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
}

// Assert the two lifecycle stores agree on the given lifecycle_state. state.json
// is a projection of nucleus.lifecycle_state, so both must report the same
// canonical lifecycle and the derived legacy phase.
function assertStoresAgree(domain, expectedLifecycleState) {
  const nucleus = readSessionNucleus(domain);
  const state = readStateJson(domain);
  assert.equal(
    nucleus.lifecycle_state,
    expectedLifecycleState,
    `nucleus.lifecycle_state must be ${expectedLifecycleState}, got ${nucleus.lifecycle_state}`,
  );
  assert.equal(
    state.lifecycle_state,
    expectedLifecycleState,
    `state.json lifecycle_state must agree at ${expectedLifecycleState}, got ${state.lifecycle_state}`,
  );
  assert.equal(
    nucleus.lifecycle_state,
    state.lifecycle_state,
    "session-nucleus.json and state.json must NOT drift",
  );
}

test("Test G: prepareVerificationEntry throwing leaves both lifecycle stores at CLAIM_FREEZE (no drift)", () => {
  withTempHome(() => {
    const domain = "drift-g.example.com";
    driveToClaimFreeze(domain);
    assertStoresAgree(domain, "CLAIM_FREEZE");

    const original = verificationModule.prepareVerificationEntry;
    verificationModule.prepareVerificationEntry = () => {
      throw new Error("simulated verification snapshot failure");
    };

    let captured = null;
    try {
      advanceSession({ target_domain: domain, to_state: "VERIFY" });
    } catch (error) {
      captured = error;
    } finally {
      verificationModule.prepareVerificationEntry = original;
    }

    assert.ok(captured, "advanceSession -> VERIFY must throw when prepareVerificationEntry throws");
    // The throw must NOT advance either store: both still agree at CLAIM_FREEZE.
    // (On the pre-fix nucleus-first ordering this fails — the nucleus would
    // already read VERIFY while state.json stayed at CLAIM_FREEZE.)
    assertStoresAgree(domain, "CLAIM_FREEZE");
  });
});

test("Test H: refreshVerificationManifest throwing rolls back both lifecycle stores to CLAIM_FREEZE", () => {
  withTempHome(() => {
    const domain = "drift-h.example.com";
    driveToClaimFreeze(domain);
    assertStoresAgree(domain, "CLAIM_FREEZE");

    const original = verificationModule.refreshVerificationManifest;
    verificationModule.refreshVerificationManifest = () => {
      throw new Error("simulated verification manifest failure");
    };

    let captured = null;
    try {
      advanceSession({ target_domain: domain, to_state: "VERIFY" });
    } catch (error) {
      captured = error;
    } finally {
      verificationModule.refreshVerificationManifest = original;
    }

    assert.ok(captured, "advanceSession -> VERIFY must throw when refreshVerificationManifest throws");
    // The post-nucleus manifest failure must roll back BOTH stores (the
    // historical handler restored only state.json, leaving the nucleus at
    // VERIFY). Both must agree at CLAIM_FREEZE.
    assertStoresAgree(domain, "CLAIM_FREEZE");
  });
});

test("Test I (happy path): advanceSession -> VERIFY advances both stores to VERIFY and writes the snapshot", () => {
  withTempHome(() => {
    const domain = "drift-i.example.com";
    driveToClaimFreeze(domain);
    assertStoresAgree(domain, "CLAIM_FREEZE");

    const result = JSON.parse(advanceSession({ target_domain: domain, to_state: "VERIFY" }));
    assert.equal(result.advanced, true);
    assert.equal(result.to_state, "VERIFY");

    assertStoresAgree(domain, "VERIFY");
    assert.ok(
      fs.existsSync(verificationSnapshotPath(domain)),
      "the VERIFY bootstrap must write the verification snapshot",
    );
  });
});
