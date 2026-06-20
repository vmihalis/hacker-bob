"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { initSession } = require("../mcp/lib/session-state.js");
const {
  readSessionStateStrict,
  writeSessionStateDocument,
} = require("../mcp/lib/session-state-store.js");
const {
  evaluateLifecycleTransition,
  isTransitionAllowed,
} = require("../mcp/lib/lifecycle-gates.js");
const { verificationSnapshotPath, sessionDir } = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-reopen-gate-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function setState(domain, patch) {
  const { raw, state } = readSessionStateStrict(domain);
  writeSessionStateDocument(domain, raw, { ...state, ...patch });
}

test("VERIFY -> OPEN_FRONTIER is gated while a verification attempt is in flight; GRADE/REPORT re-mine stay open", () => {
  withTempHome(() => {
    const domain = "reopen-gate.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}/` });

    // I6: the back-edges must remain allowed (reopenability is preserved).
    assert.equal(isTransitionAllowed("VERIFY", "OPEN_FRONTIER"), true);
    assert.equal(isTransitionAllowed("GRADE", "OPEN_FRONTIER"), true);

    // No in-flight attempt -> VERIFY reopen passes (clean frontier re-entry).
    setState(domain, {
      lifecycle_state: "VERIFY",
      verification_schema_version: 2,
      verification_attempt_id: null,
      verification_snapshot_hash: null,
    });
    const cleanVerify = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "VERIFY",
      to_state: "OPEN_FRONTIER",
    });
    assert.equal(cleanVerify.blockers.length, 0, "no-attempt VERIFY reopen must not be blocked");

    // In-flight attempt -> the mid-verification requeue bounce from VERIFY is refused.
    setState(domain, {
      lifecycle_state: "VERIFY",
      verification_schema_version: 2,
      verification_attempt_id: "va-20260621-0001",
      verification_snapshot_hash: "deadbeef".repeat(8),
    });
    const blockedVerify = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "VERIFY",
      to_state: "OPEN_FRONTIER",
    });
    assert.equal(blockedVerify.blockers.length, 1);
    assert.equal(blockedVerify.blockers[0].code, "verification_attempt_in_flight");
    assert.equal(blockedVerify.blockers[0].verification_attempt_id, "va-20260621-0001");

    // GRADE -> OPEN_FRONTIER is the canonical grader-HOLD re-mine: verification
    // already COMPLETED to reach GRADE, so archiving + re-freezing is intended,
    // not an accidental bounce. It must stay open even with a live attempt id.
    setState(domain, { lifecycle_state: "GRADE" });
    const holdRemine = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "GRADE",
      to_state: "OPEN_FRONTIER",
    });
    assert.equal(holdRemine.blockers.length, 0, "grader-HOLD re-mine from GRADE must stay open without override");

    // REPORT -> OPEN_FRONTIER (post-report re-mine) stays open regardless.
    setState(domain, { lifecycle_state: "REPORT" });
    const remine = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "REPORT",
      to_state: "OPEN_FRONTIER",
    });
    assert.equal(remine.blockers.length, 0, "post-report re-mine must stay open");
  });
});

test("VERIFY -> OPEN_FRONTIER is gated even when state.json lost verification_attempt_id but v2 files remain", () => {
  withTempHome(() => {
    const domain = "reopen-gate-fieldloss.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}/` });

    // Simulate the documented field-loss: state.json no longer carries the
    // attempt id, but the on-disk v2 snapshot still records an in-flight attempt.
    setState(domain, {
      lifecycle_state: "VERIFY",
      verification_schema_version: 2,
      verification_attempt_id: null,
      verification_snapshot_hash: null,
    });
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    fs.writeFileSync(
      verificationSnapshotPath(domain),
      `${JSON.stringify({ verification_attempt_id: "va-orphaned-0007", finding_ids: [] }, null, 2)}\n`,
    );

    const blocked = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "VERIFY",
      to_state: "OPEN_FRONTIER",
    });
    assert.equal(blocked.blockers.length, 1, "field-loss must still block via on-disk v2 files");
    assert.equal(blocked.blockers[0].code, "verification_attempt_in_flight");
    assert.equal(blocked.blockers[0].verification_attempt_id, "va-orphaned-0007");
  });
});
