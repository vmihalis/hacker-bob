"use strict";

// Step 4 regression: single-source-of-truth lifecycle state. advanceSession
// must never leave session-nucleus.json and state.json disagreeing, even when
// the fallible VERIFY-bootstrap work throws mid-transition.
//
// The historical ordering wrote the nucleus FIRST and unconditionally, then ran
// the fallible VERIFY bootstrap; a throw there advanced the nucleus to VERIFY
// while state.json stayed at CLAIM_FREEZE — a permanent split-brain. A7 routes
// the whole advance through ONE commitSessionAuthority CAS transaction: all
// fallible work (buildVerificationEntry) runs BEFORE any durable write, and
// commitVerificationEntry's undo() receipt protects the archive+snapshot write
// through the CAS commit.
//
// Test G: stub buildVerificationEntry (the pure build step) to throw ->
//         advanceSession->VERIFY throws AND both stores still AGREE at
//         CLAIM_FREEZE (zero I/O had happened yet).
// Test H: refreshVerificationManifest is now strictly postcommit and
//         best-effort (Agent-Prompt: "no prune/manifest/pipeline precommit") —
//         a throw there must NOT roll back an already-committed advance.
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
} = require("../mcp/core/session/session-state.js");
const {
  readSessionNucleus,
} = require("../mcp/core/governance/index.js");
const {
  sessionEventsJsonlPath,
  statePath,
  verificationSnapshotPath,
} = require("../mcp/core/io/paths.js");
const verificationModule = require("../mcp/core/verification/verification.js");
const {
  readSessionEvents,
} = require("../mcp/core/session/session-events.js");

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

test("Test G: buildVerificationEntry throwing (pure build, before any write) leaves both lifecycle stores at CLAIM_FREEZE (no drift)", () => {
  withTempHome(() => {
    const domain = "drift-g.example.com";
    driveToClaimFreeze(domain);
    assertStoresAgree(domain, "CLAIM_FREEZE");

    const original = verificationModule.buildVerificationEntry;
    verificationModule.buildVerificationEntry = () => {
      throw new Error("simulated verification build failure");
    };

    let captured = null;
    try {
      advanceSession({ target_domain: domain, to_state: "VERIFY" });
    } catch (error) {
      captured = error;
    } finally {
      verificationModule.buildVerificationEntry = original;
    }

    assert.ok(captured, "advanceSession -> VERIFY must throw when buildVerificationEntry throws");
    // The throw must NOT advance either store: both still agree at CLAIM_FREEZE.
    // buildVerificationEntry is pure (no I/O), so this proves a throw before any
    // write leaves zero drift — commitVerificationEntry/commitSessionAuthority
    // are never even reached.
    assertStoresAgree(domain, "CLAIM_FREEZE");
    assert.ok(!fs.existsSync(verificationSnapshotPath(domain)), "no verification snapshot must be written");
  });
});

test("Test H: refreshVerificationManifest is postcommit best-effort — a throw there does NOT roll back an already-committed VERIFY advance", () => {
  withTempHome(() => {
    const domain = "drift-h.example.com";
    driveToClaimFreeze(domain);
    assertStoresAgree(domain, "CLAIM_FREEZE");

    const original = verificationModule.refreshVerificationManifest;
    verificationModule.refreshVerificationManifest = () => {
      throw new Error("simulated verification manifest failure");
    };

    let captured = null;
    let result = null;
    try {
      result = JSON.parse(advanceSession({ target_domain: domain, to_state: "VERIFY" }));
    } catch (error) {
      captured = error;
    } finally {
      verificationModule.refreshVerificationManifest = original;
    }

    // Agent-Prompt: "no prune/manifest/pipeline precommit" — manifest refresh
    // runs strictly AFTER commitSessionAuthority has already durably committed
    // the advance, so a throw there must not surface as a tool error and must
    // not roll back the already-committed lifecycle move.
    assert.equal(captured, null, "a postcommit manifest failure must not fail advanceSession");
    assert.ok(result && result.advanced === true);
    assertStoresAgree(domain, "VERIFY");
    assert.ok(fs.existsSync(verificationSnapshotPath(domain)), "the VERIFY bootstrap must still write the verification snapshot");
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

test("readSessionEvents rejects a stored record whose event_hash is absent, instead of silently minting one", () => {
  withTempHome(() => {
    const domain = "drift-hash-absent.example.com";
    driveToClaimFreeze(domain);

    const eventsFile = sessionEventsJsonlPath(domain);
    const lines = fs.readFileSync(eventsFile, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    assert.ok(lines.length > 0);
    delete lines[0].event_hash;
    fs.writeFileSync(eventsFile, `${lines.map((line) => JSON.stringify(line)).join("\n")}\n`, "utf8");

    assert.throws(
      () => readSessionEvents(domain),
      /missing event_hash/,
    );
  });
});

test("readSessionEvents rejects a stored record whose event_hash does not match its canonical content, instead of silently recomputing it", () => {
  withTempHome(() => {
    const domain = "drift-hash-mismatch.example.com";
    driveToClaimFreeze(domain);

    const eventsFile = sessionEventsJsonlPath(domain);
    const lines = fs.readFileSync(eventsFile, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    assert.ok(lines.length > 0);
    // Corrupt the payload without recomputing event_hash — a forged/tampered
    // record, not merely an absent one.
    lines[0].payload = { ...lines[0].payload, forged: true };
    fs.writeFileSync(eventsFile, `${lines.map((line) => JSON.stringify(line)).join("\n")}\n`, "utf8");

    assert.throws(
      () => readSessionEvents(domain),
      /event_hash does not match its canonical content/,
    );
  });
});
