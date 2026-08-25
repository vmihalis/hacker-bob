"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  buildSessionNucleus,
  readVerifiedSessionNucleus,
  sessionNucleusFromState,
} = require("../mcp/core/governance/index.js");
const {
  sessionDir,
  sessionEventsJsonlPath,
  sessionNucleusPath,
  statePath,
} = require("../mcp/core/io/paths.js");
const {
  writeFileAtomic,
} = require("../mcp/core/io/storage.js");
const {
  readSessionEvents,
} = require("../mcp/core/session/session-events.js");
const {
  commitSessionAuthority,
} = require("../mcp/core/session/session-authority-unit-of-work.js");
const {
  buildInitialSessionState,
} = require("../mcp/core/session/session-state-contracts.js");
const {
  readSessionStateStrict,
} = require("../mcp/core/session/session-state-store.js");

const DEFAULT_EGRESS_PROFILE = Object.freeze({
  name: "default",
  region: null,
  proxy_configured: false,
  egress_profile_identity_hash: null,
  egress_profile_identity_version: null,
  egress_profile_identity_source: null,
});

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-session-authority-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function initialState(domain, overrides = {}) {
  return {
    ...buildInitialSessionState(domain, `https://${domain}`, {
      egressProfile: DEFAULT_EGRESS_PROFILE,
    }),
    ...overrides,
  };
}

function governanceEvent(kind, payload = {}) {
  return {
    kind,
    payload,
    source: {
      component: "session-authority-unit-of-work.test",
    },
  };
}

function commitState(domain, state, {
  expectedNucleusHash,
  rawDocument = {},
  event = governanceEvent("governance.session.initialized"),
} = {}) {
  const nextNucleus = sessionNucleusFromState(state);
  return commitSessionAuthority({
    targetDomain: domain,
    nextNucleus,
    stateProjection: {
      rawDocument,
      nextState: state,
    },
    event,
    expectedNucleusHash,
  });
}

function snapshotPaths(domain) {
  return [statePath(domain), sessionNucleusPath(domain), sessionEventsJsonlPath(domain)]
    .reduce((snapshots, filePath) => {
      snapshots[filePath] = fs.existsSync(filePath)
        ? { exists: true, bytes: fs.readFileSync(filePath) }
        : { exists: false, bytes: null };
      return snapshots;
    }, {});
}

function assertSnapshotsEqual(domain, expected) {
  for (const [filePath, snapshot] of Object.entries(expected)) {
    assert.equal(fs.existsSync(filePath), snapshot.exists, `${path.basename(filePath)} existence must match`);
    if (snapshot.exists) {
      assert.equal(
        Buffer.compare(fs.readFileSync(filePath), snapshot.bytes),
        0,
        `${path.basename(filePath)} bytes must match`,
      );
    }
  }
}

function assertAuthorityFilesAbsent(domain) {
  assert.equal(fs.existsSync(statePath(domain)), false);
  assert.equal(fs.existsSync(sessionNucleusPath(domain)), false);
  assert.equal(fs.existsSync(sessionEventsJsonlPath(domain)), false);
}

function assertNoAuthorityTemps(domain) {
  const files = [statePath(domain), sessionNucleusPath(domain), sessionEventsJsonlPath(domain)];
  const directories = new Set(files.map((filePath) => path.dirname(filePath)));
  for (const directory of directories) {
    if (!fs.existsSync(directory)) continue;
    const names = fs.readdirSync(directory);
    for (const filePath of files) {
      const prefix = `.${path.basename(filePath)}.`;
      assert.equal(
        names.some((name) => name.startsWith(prefix) && name.endsWith(".tmp")),
        false,
        `${path.basename(filePath)} temp residue must be absent`,
      );
    }
  }
}

function assertRetryCreatesAuthorityFiles(domain) {
  const state = initialState(domain);
  const expectedNucleus = sessionNucleusFromState(state);
  const result = commitState(domain, state, { expectedNucleusHash: null });

  assert.equal(result.target_domain, domain);
  assert.equal(result.nucleus_hash, expectedNucleus.nucleus_hash);
  assert.deepEqual(readVerifiedSessionNucleus(domain), expectedNucleus);
  assert.equal(readSessionEvents(domain).length, 1);
  assert.equal(readSessionStateStrict(domain).state.target, domain);
}

function isTempFor(target, candidate) {
  return path.dirname(candidate) === path.dirname(target)
    && path.basename(candidate).startsWith(`.${path.basename(target)}.`);
}

function assertFreshCommitLinkFirstProbeFaultRollback(domain, failedFile) {
  const realLinkSync = fs.linkSync;
  const realLstatSync = fs.lstatSync;
  const linkFailure = new Error(`injected ${path.basename(failedFile)} link failure after publish`);
  linkFailure.code = "EIO";
  const probeFailure = new Error(`injected ${path.basename(failedFile)} first final probe failure`);
  let injected = false;
  let probeThrown = false;
  let stagedTemp = null;
  let thrown = null;

  fs.linkSync = function injectedLink(source, destination) {
    if (!injected && path.resolve(destination) === path.resolve(failedFile)) {
      injected = true;
      stagedTemp = source;
      realLinkSync(source, destination);
      throw linkFailure;
    }
    return realLinkSync(source, destination);
  };
  fs.lstatSync = function injectedLstat(target) {
    if (
      injected
      && !probeThrown
      && path.resolve(target) === path.resolve(failedFile)
    ) {
      probeThrown = true;
      throw probeFailure;
    }
    return realLstatSync(target);
  };
  try {
    commitState(domain, initialState(domain), { expectedNucleusHash: null });
  } catch (error) {
    thrown = error;
  } finally {
    fs.linkSync = realLinkSync;
    fs.lstatSync = realLstatSync;
  }

  assert.equal(thrown, linkFailure);
  assert.equal(thrown.code, "EIO");
  assert.equal(thrown.probe_error, probeFailure.message);
  assert.equal(thrown.cleanup_error, undefined);
  assert.equal(thrown.rollback_error, undefined);
  assert.equal(thrown.exclusive_receipt.phase, "link");
  assert.equal(thrown.exclusive_receipt.status, "failed");
  assert.equal(thrown.exclusive_receipt.finalCandidate, null);
  assert.equal(thrown.exclusive_receipt.tempCandidate.owned, true);
  assert.equal(injected, true);
  assert.equal(probeThrown, true);
  assert.ok(stagedTemp);
  assert.equal(fs.existsSync(stagedTemp), false);
  assertAuthorityFilesAbsent(domain);
  assertNoAuthorityTemps(domain);
  assertRetryCreatesAuthorityFiles(domain);
  fs.rmSync(sessionDir(domain), { recursive: true, force: true });
}

function assertFreshCommitLinkReprobeRollback(domain, failedFile) {
  const realLinkSync = fs.linkSync;
  const realLstatSync = fs.lstatSync;
  const linkFailure = new Error(`injected ${path.basename(failedFile)} link failure after publish`);
  linkFailure.code = "EIO";
  const probeFailure = new Error(`injected ${path.basename(failedFile)} post-cleanup probe failure`);
  let injected = false;
  let probeThrown = false;
  let finalProbeCount = 0;
  let stagedTemp = null;
  let thrown = null;

  fs.linkSync = function injectedLink(source, destination) {
    if (!injected && path.resolve(destination) === path.resolve(failedFile)) {
      injected = true;
      stagedTemp = source;
      realLinkSync(source, destination);
      throw linkFailure;
    }
    return realLinkSync(source, destination);
  };
  fs.lstatSync = function injectedLstat(target) {
    if (
      injected
      && !probeThrown
      && path.resolve(target) === path.resolve(failedFile)
    ) {
      finalProbeCount += 1;
      if (finalProbeCount === 2) {
        probeThrown = true;
        throw probeFailure;
      }
    }
    return realLstatSync(target);
  };
  try {
    commitState(domain, initialState(domain), { expectedNucleusHash: null });
  } catch (error) {
    thrown = error;
  } finally {
    fs.linkSync = realLinkSync;
    fs.lstatSync = realLstatSync;
  }

  assert.equal(thrown, linkFailure);
  assert.equal(thrown.code, "EIO");
  assert.equal(thrown.probe_error, probeFailure.message);
  assert.equal(thrown.cleanup_error, undefined);
  assert.equal(thrown.exclusive_receipt.phase, "link");
  assert.equal(thrown.exclusive_receipt.status, "failed");
  assert.equal(thrown.exclusive_receipt.finalCandidate.owned, true);
  assert.equal(injected, true);
  assert.equal(probeThrown, true);
  assert.ok(stagedTemp);
  assert.equal(fs.existsSync(stagedTemp), false);
  assertAuthorityFilesAbsent(domain);
  fs.rmSync(sessionDir(domain), { recursive: true, force: true });
}

function assertFreshCommitPostlinkProbeFaultRollback(domain, failedFile, proofErrorCode = null) {
  const realLinkSync = fs.linkSync;
  const realLstatSync = fs.lstatSync;
  const probeFailure = new Error(`injected ${path.basename(failedFile)} postlink proof failure`);
  if (proofErrorCode !== null) probeFailure.code = proofErrorCode;
  let linked = false;
  let probeThrown = false;
  let stagedTemp = null;
  let thrown = null;

  fs.linkSync = function injectedLink(source, destination) {
    const result = realLinkSync(source, destination);
    if (path.resolve(destination) === path.resolve(failedFile)) {
      linked = true;
      stagedTemp = source;
    }
    return result;
  };
  fs.lstatSync = function injectedLstat(target) {
    if (
      linked
      && !probeThrown
      && path.resolve(target) === path.resolve(failedFile)
    ) {
      probeThrown = true;
      throw probeFailure;
    }
    return realLstatSync(target);
  };
  try {
    commitState(domain, initialState(domain), { expectedNucleusHash: null });
  } catch (error) {
    thrown = error;
  } finally {
    fs.linkSync = realLinkSync;
    fs.lstatSync = realLstatSync;
  }

  assert.equal(thrown, probeFailure);
  if (proofErrorCode !== null) assert.equal(thrown.code, proofErrorCode);
  assert.equal(thrown.probe_error, undefined);
  assert.equal(thrown.cleanup_error, undefined);
  assert.equal(thrown.rollback_error, undefined);
  assert.equal(thrown.exclusive_receipt.phase, "postlink_proof");
  assert.equal(thrown.exclusive_receipt.status, "failed");
  assert.equal(thrown.exclusive_receipt.finalCandidate, null);
  assert.equal(thrown.exclusive_receipt.tempCandidate.owned, true);
  assert.equal(linked, true);
  assert.equal(probeThrown, true);
  assert.ok(stagedTemp);
  assert.equal(fs.existsSync(stagedTemp), false);
  assertAuthorityFilesAbsent(domain);
  assertNoAuthorityTemps(domain);
  assertRetryCreatesAuthorityFiles(domain);
  fs.rmSync(sessionDir(domain), { recursive: true, force: true });
}

function assertFreshCommitWrongSourceLinkPreserved(domain, failedFile) {
  const realLinkSync = fs.linkSync;
  const linkFailure = new Error(`injected ${path.basename(failedFile)} wrong-source link failure`);
  linkFailure.code = "EIO";
  const replacementBytes = "wrong source winner survives\n";
  let injected = false;
  let stagedTemp = null;
  let finalStats = null;
  let thrown = null;

  fs.linkSync = function injectedLink(source, destination) {
    if (!injected && path.resolve(destination) === path.resolve(failedFile)) {
      injected = true;
      stagedTemp = source;
      const wrongSource = path.join(path.dirname(destination), `.wrong-${path.basename(destination)}`);
      fs.writeFileSync(wrongSource, replacementBytes, "utf8");
      realLinkSync(wrongSource, destination);
      fs.unlinkSync(wrongSource);
      finalStats = fs.lstatSync(destination);
      throw linkFailure;
    }
    return realLinkSync(source, destination);
  };
  try {
    commitState(domain, initialState(domain), { expectedNucleusHash: null });
  } catch (error) {
    thrown = error;
  } finally {
    fs.linkSync = realLinkSync;
  }

  assert.equal(thrown, linkFailure);
  assert.equal(thrown.rollback_error, undefined);
  assert.equal(thrown.exclusive_receipt.phase, "link");
  assert.equal(thrown.exclusive_receipt.status, "failed");
  assert.equal(thrown.exclusive_receipt.finalCandidate, null);
  assert.equal(injected, true);
  assert.ok(stagedTemp);
  assert.equal(fs.existsSync(stagedTemp), false);
  assert.equal(fs.existsSync(statePath(domain)), false);
  assert.equal(fs.readFileSync(failedFile, "utf8"), replacementBytes);
  const currentStats = fs.lstatSync(failedFile);
  assert.equal(currentStats.dev, finalStats.dev);
  assert.equal(currentStats.ino, finalStats.ino);
  assert.equal(fs.existsSync(sessionEventsJsonlPath(domain)), false);
  assertNoAuthorityTemps(domain);
  fs.rmSync(sessionDir(domain), { recursive: true, force: true });
}

function assertFreshCommitFinalReplacementPreserved(domain, failedFile) {
  const realLinkSync = fs.linkSync;
  const realLstatSync = fs.lstatSync;
  const linkFailure = new Error(`injected ${path.basename(failedFile)} link failure after publish`);
  linkFailure.code = "EIO";
  const probeFailure = new Error(`injected ${path.basename(failedFile)} replacement probe failure`);
  const replacementBytes = "replacement final survives\n";
  let injected = false;
  let probeThrown = false;
  let stagedTemp = null;
  let replacementStats = null;
  let thrown = null;

  fs.linkSync = function injectedLink(source, destination) {
    if (!injected && path.resolve(destination) === path.resolve(failedFile)) {
      injected = true;
      stagedTemp = source;
      realLinkSync(source, destination);
      throw linkFailure;
    }
    return realLinkSync(source, destination);
  };
  fs.lstatSync = function injectedLstat(target) {
    if (
      injected
      && !probeThrown
      && path.resolve(target) === path.resolve(failedFile)
    ) {
      probeThrown = true;
      fs.unlinkSync(target);
      fs.writeFileSync(target, replacementBytes, "utf8");
      replacementStats = realLstatSync(target);
      throw probeFailure;
    }
    return realLstatSync(target);
  };
  try {
    commitState(domain, initialState(domain), { expectedNucleusHash: null });
  } catch (error) {
    thrown = error;
  } finally {
    fs.linkSync = realLinkSync;
    fs.lstatSync = realLstatSync;
  }

  assert.equal(thrown, linkFailure);
  assert.equal(thrown.probe_error, probeFailure.message);
  assert.equal(thrown.rollback_error, undefined);
  assert.equal(thrown.exclusive_receipt.phase, "link");
  assert.equal(thrown.exclusive_receipt.status, "failed");
  assert.equal(thrown.exclusive_receipt.finalCandidate, null);
  assert.equal(injected, true);
  assert.equal(probeThrown, true);
  assert.ok(stagedTemp);
  assert.equal(fs.existsSync(stagedTemp), false);
  assert.equal(fs.existsSync(statePath(domain)), false);
  assert.equal(fs.readFileSync(failedFile, "utf8"), replacementBytes);
  const currentStats = fs.lstatSync(failedFile);
  assert.equal(currentStats.dev, replacementStats.dev);
  assert.equal(currentStats.ino, replacementStats.ino);
  assert.equal(fs.existsSync(sessionEventsJsonlPath(domain)), false);
  assertNoAuthorityTemps(domain);
  fs.rmSync(sessionDir(domain), { recursive: true, force: true });
}

function assertFreshCommitCleanupFailureRollback(domain, failedFile) {
  const realLinkSync = fs.linkSync;
  const realUnlinkSync = fs.unlinkSync;
  const linkFailure = new Error(`injected ${path.basename(failedFile)} link failure after publish`);
  linkFailure.code = "EIO";
  const cleanupFailure = new Error(`injected ${path.basename(failedFile)} staged cleanup failure`);
  let injected = false;
  let cleanupInjected = false;
  let stagedTemp = null;
  let thrown = null;

  fs.linkSync = function injectedLink(source, destination) {
    if (!injected && path.resolve(destination) === path.resolve(failedFile)) {
      injected = true;
      stagedTemp = source;
      realLinkSync(source, destination);
      throw linkFailure;
    }
    return realLinkSync(source, destination);
  };
  fs.unlinkSync = function injectedUnlink(target) {
    if (
      stagedTemp
      && !cleanupInjected
      && path.resolve(target) === path.resolve(stagedTemp)
    ) {
      cleanupInjected = true;
      throw cleanupFailure;
    }
    return realUnlinkSync(target);
  };
  try {
    commitState(domain, initialState(domain), { expectedNucleusHash: null });
  } catch (error) {
    thrown = error;
  } finally {
    fs.linkSync = realLinkSync;
    fs.unlinkSync = realUnlinkSync;
  }

  assert.equal(thrown, linkFailure);
  assert.equal(thrown.code, "EIO");
  assert.equal(thrown.cleanup_error, cleanupFailure.message);
  assert.equal(thrown.probe_error, undefined);
  assert.equal(thrown.rollback_error, undefined);
  assert.equal(thrown.exclusive_receipt.phase, "link");
  assert.equal(thrown.exclusive_receipt.status, "failed");
  assert.equal(thrown.exclusive_receipt.finalCandidate.owned, true);
  assert.equal(thrown.exclusive_receipt.tempCandidate.owned, true);
  assert.equal(injected, true);
  assert.equal(cleanupInjected, true);
  assert.ok(stagedTemp);
  assert.equal(fs.existsSync(stagedTemp), false);
  assertAuthorityFilesAbsent(domain);
  fs.rmSync(sessionDir(domain), { recursive: true, force: true });
}

test("commitSessionAuthority create writes state, nucleus, and bound event", () => {
  withTempHome(() => {
    const domain = "authority-create.example.com";
    const state = initialState(domain);
    const expectedNucleus = sessionNucleusFromState(state);

    const result = commitState(domain, state, {
      expectedNucleusHash: null,
      rawDocument: { preserved_raw: "yes" },
    });

    assert.equal(result.target_domain, domain);
    assert.equal(result.nucleus_hash, expectedNucleus.nucleus_hash);
    assert.equal(result.state_written, true);
    assert.match(result.event_id, /^SE-/);
    assert.deepEqual(readVerifiedSessionNucleus(domain), expectedNucleus);
    assert.equal(readSessionStateStrict(domain).raw.preserved_raw, "yes");

    const events = readSessionEvents(domain);
    assert.equal(events.length, 1);
    assert.equal(events[0].target_domain, domain);
    assert.equal(events[0].nucleus_hash, expectedNucleus.nucleus_hash);
    assert.equal(events[0].payload.nucleus_hash, expectedNucleus.nucleus_hash);
  });
});

test("commitSessionAuthority update enforces verified nucleus CAS and rejects stale hashes", () => {
  withTempHome(() => {
    const domain = "authority-update.example.com";
    const firstState = initialState(domain);
    const first = commitState(domain, firstState, { expectedNucleusHash: null });
    const nextState = initialState(domain, {
      lifecycle_state: "OPEN_FRONTIER",
      phase: "EVALUATE",
    });

    const update = commitState(domain, nextState, {
      expectedNucleusHash: first.nucleus_hash,
      rawDocument: readSessionStateStrict(domain).raw,
      event: governanceEvent("governance.lifecycle.advanced", {
        from_state: "SETUP",
        to_state: "OPEN_FRONTIER",
      }),
    });

    assert.notEqual(update.nucleus_hash, first.nucleus_hash);
    assert.equal(readVerifiedSessionNucleus(domain).nucleus_hash, update.nucleus_hash);
    assert.equal(readSessionEvents(domain).length, 2);

    const beforeStale = snapshotPaths(domain);
    assert.throws(
      () => commitState(domain, initialState(domain, { lifecycle_state: "VERIFY", phase: "VERIFY" }), {
        expectedNucleusHash: first.nucleus_hash,
        rawDocument: readSessionStateStrict(domain).raw,
        event: governanceEvent("governance.lifecycle.advanced"),
      }),
      /CAS mismatch/,
    );
    assertSnapshotsEqual(domain, beforeStale);
  });
});

test("commitSessionAuthority null-state mode writes nucleus and event while preserving state bytes", () => {
  withTempHome(() => {
    const freshDomain = "authority-null-state-fresh.example.com";
    const freshNucleus = buildSessionNucleus({
      target_domain: freshDomain,
      target_url: `https://${freshDomain}`,
      scope_policy: {
        target_domain: freshDomain,
        target_url: `https://${freshDomain}`,
        checkpoint_mode: "normal",
        block_internal_hosts: false,
        block_internal_hosts_source: "mode_default",
      },
      egress_identity: { egress_profile: "default", proxy_configured: false },
      auth_context: { auth_status: "pending" },
      operator_constraint: { handoff_provenance_required: true },
    });

    const fresh = commitSessionAuthority({
      targetDomain: freshDomain,
      nextNucleus: freshNucleus,
      stateProjection: null,
      event: governanceEvent("governance.session.initialized"),
      expectedNucleusHash: null,
    });

    assert.equal(fresh.state_written, false);
    assert.equal(fs.existsSync(statePath(freshDomain)), false);
    assert.equal(readVerifiedSessionNucleus(freshDomain).nucleus_hash, fresh.nucleus_hash);
    assert.equal(readSessionEvents(freshDomain).length, 1);

    const domain = "authority-null-state-preserve.example.com";
    const state = initialState(domain);
    const first = commitState(domain, state, { expectedNucleusHash: null });
    const priorStateBytes = fs.readFileSync(statePath(domain));
    const priorNucleus = readVerifiedSessionNucleus(domain);
    const nextNucleus = buildSessionNucleus({
      ...priorNucleus,
      operator_constraint: {
        handoff_provenance_required: true,
        operator_note: "legacy nucleus-only commit",
      },
    });

    const update = commitSessionAuthority({
      targetDomain: domain,
      nextNucleus,
      stateProjection: null,
      event: governanceEvent("governance.operator_constraint.updated"),
      expectedNucleusHash: first.nucleus_hash,
    });

    assert.equal(update.state_written, false);
    assert.equal(Buffer.compare(fs.readFileSync(statePath(domain)), priorStateBytes), 0);
    assert.equal(readVerifiedSessionNucleus(domain).nucleus_hash, nextNucleus.nucleus_hash);
    assert.equal(readSessionEvents(domain).length, 2);
  });
});

test("commitSessionAuthority rejects binding drift and create/update CAS failures before writes", () => {
  withTempHome(() => {
    const missingDomain = "authority-missing-cas.example.com";
    const missingState = initialState(missingDomain);
    assert.throws(
      () => commitState(missingDomain, missingState, {
        expectedNucleusHash: "0".repeat(64),
      }),
      /verified session nucleus requires session-nucleus\.json/,
    );
    assertAuthorityFilesAbsent(missingDomain);

    for (const [suffix, event] of [
      ["target", { ...governanceEvent("governance.session.initialized"), target_domain: "other.example.com" }],
      ["top-hash", { ...governanceEvent("governance.session.initialized"), nucleus_hash: "bad" }],
      ["payload-hash", governanceEvent("governance.session.initialized", { nucleus_hash: "bad" })],
    ]) {
      const domain = `authority-drift-${suffix}.example.com`;
      assert.throws(
        () => commitState(domain, initialState(domain), {
          expectedNucleusHash: null,
          event,
        }),
        /does not match/,
      );
      assertAuthorityFilesAbsent(domain);
    }

    const projectionDomain = "authority-projection-drift.example.com";
    const state = initialState(projectionDomain);
    const differentNucleus = sessionNucleusFromState(initialState("different-projection.example.com"));
    assert.throws(
      () => commitSessionAuthority({
        targetDomain: projectionDomain,
        nextNucleus: differentNucleus,
        stateProjection: { rawDocument: {}, nextState: state },
        event: governanceEvent("governance.session.initialized"),
        expectedNucleusHash: null,
      }),
      /target_domain does not match targetDomain/,
    );
    assertAuthorityFilesAbsent(projectionDomain);
  });
});

test("commitSessionAuthority rejects a symlinked state preimage before mutation", () => {
  withTempHome((home) => {
    const domain = "authority-state-symlink.example.com";
    const externalTarget = path.join(home, "external-state-target.json");
    const externalBytes = Buffer.from("{\"external\":true}\n");
    fs.writeFileSync(externalTarget, externalBytes);
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    fs.symlinkSync(externalTarget, statePath(domain));
    const linkTarget = fs.readlinkSync(statePath(domain));

    assert.throws(
      () => commitState(domain, initialState(domain), { expectedNucleusHash: null }),
      /state\.json must not be a symbolic link/,
    );

    const stateStats = fs.lstatSync(statePath(domain));
    assert.equal(stateStats.isSymbolicLink(), true);
    assert.equal(fs.readlinkSync(statePath(domain)), linkTarget);
    assert.equal(Buffer.compare(fs.readFileSync(externalTarget), externalBytes), 0);
    assert.equal(fs.existsSync(sessionNucleusPath(domain)), false);
    assert.equal(fs.existsSync(sessionEventsJsonlPath(domain)), false);
  });
});

test("commitSessionAuthority rejects a symlinked events preimage before mutation", () => {
  withTempHome((home) => {
    const domain = "authority-events-symlink.example.com";
    const first = commitState(domain, initialState(domain), { expectedNucleusHash: null });
    const beforeState = fs.readFileSync(statePath(domain));
    const beforeNucleus = fs.readFileSync(sessionNucleusPath(domain));
    const externalTarget = path.join(home, "external-events-target.jsonl");
    const externalBytes = Buffer.from("external event bytes\n");
    fs.writeFileSync(externalTarget, externalBytes);
    fs.unlinkSync(sessionEventsJsonlPath(domain));
    fs.symlinkSync(externalTarget, sessionEventsJsonlPath(domain));
    const linkTarget = fs.readlinkSync(sessionEventsJsonlPath(domain));

    assert.throws(
      () => commitState(domain, initialState(domain, { lifecycle_state: "OPEN_FRONTIER", phase: "EVALUATE" }), {
        expectedNucleusHash: first.nucleus_hash,
        rawDocument: readSessionStateStrict(domain).raw,
        event: governanceEvent("governance.lifecycle.advanced"),
      }),
      /session-events\.jsonl must not be a symbolic link/,
    );

    const eventsStats = fs.lstatSync(sessionEventsJsonlPath(domain));
    assert.equal(eventsStats.isSymbolicLink(), true);
    assert.equal(fs.readlinkSync(sessionEventsJsonlPath(domain)), linkTarget);
    assert.equal(Buffer.compare(fs.readFileSync(externalTarget), externalBytes), 0);
    assert.equal(Buffer.compare(fs.readFileSync(statePath(domain)), beforeState), 0);
    assert.equal(Buffer.compare(fs.readFileSync(sessionNucleusPath(domain)), beforeNucleus), 0);
  });
});

test("commitSessionAuthority create CAS collision preserves authority bytes", () => {
  withTempHome(() => {
    const domain = "authority-create-collision.example.com";
    commitState(domain, initialState(domain), { expectedNucleusHash: null });
    const before = snapshotPaths(domain);

    assert.throws(
      () => commitState(domain, initialState(domain, { lifecycle_state: "OPEN_FRONTIER", phase: "EVALUATE" }), {
        expectedNucleusHash: null,
        rawDocument: readSessionStateStrict(domain).raw,
        event: governanceEvent("governance.lifecycle.advanced"),
      }),
      /session-nucleus\.json already exists/,
    );

    assertSnapshotsEqual(domain, before);
  });
});

test("commitSessionAuthority rolls back a newly-created state when nucleus write fails", () => {
  withTempHome(() => {
    const domain = "authority-create-nucleus-failure.example.com";
    const realLinkSync = fs.linkSync;
    let injected = false;
    fs.linkSync = function injectedLink(source, destination) {
      if (!injected && path.resolve(destination) === path.resolve(sessionNucleusPath(domain))) {
        injected = true;
        throw new Error("injected nucleus CAS publish failure");
      }
      return realLinkSync(source, destination);
    };
    try {
      assert.throws(
        () => commitState(domain, initialState(domain), { expectedNucleusHash: null }),
        /injected nucleus CAS publish failure/,
      );
    } finally {
      fs.linkSync = realLinkSync;
    }

    assert.equal(injected, true);
    assertAuthorityFilesAbsent(domain);
    fs.rmSync(sessionDir(domain), { recursive: true, force: true });
  });
});

test("commitSessionAuthority removes fresh files when event append partially writes then fails", () => {
  withTempHome(() => {
    const domain = "authority-fresh-event-partial-failure.example.com";
    const eventsFile = sessionEventsJsonlPath(domain);
    const realLinkSync = fs.linkSync;
    let injected = false;
    fs.linkSync = function injectedLink(source, destination) {
      if (!injected && path.resolve(destination) === path.resolve(eventsFile)) {
        injected = true;
        realLinkSync(source, destination);
        throw new Error("injected fresh event append failure");
      }
      return realLinkSync(source, destination);
    };
    try {
      assert.throws(
        () => commitState(domain, initialState(domain), { expectedNucleusHash: null }),
        /injected fresh event append failure/,
      );
    } finally {
      fs.linkSync = realLinkSync;
    }

    assert.equal(injected, true);
    assertAuthorityFilesAbsent(domain);
    fs.rmSync(sessionDir(domain), { recursive: true, force: true });
  });
});

test("commitSessionAuthority propagates temp-open EEXIST and leaves no fresh authority files", () => {
  withTempHome(() => {
    const domain = "authority-temp-open-eexist.example.com";
    const stateFile = statePath(domain);
    const realOpenSync = fs.openSync;
    const injected = new Error("injected temp-open collision");
    injected.code = "EEXIST";
    let blockedTemp = null;

    fs.openSync = function injectedOpen(target, flags, mode) {
      if (isTempFor(stateFile, target)) {
        blockedTemp = target;
        throw injected;
      }
      return realOpenSync(target, flags, mode);
    };
    try {
      assert.throws(
        () => commitState(domain, initialState(domain), { expectedNucleusHash: null }),
        (error) => error === injected
          && error.exclusive_receipt.phase === "temp_open"
          && error.exclusive_receipt.unresolvedTemp.reason === "temp_exists",
      );
    } finally {
      fs.openSync = realOpenSync;
    }

    assert.ok(blockedTemp);
    assert.equal(fs.existsSync(blockedTemp), false);
    assertAuthorityFilesAbsent(domain);
    fs.rmSync(sessionDir(domain), { recursive: true, force: true });
  });
});

test("commitSessionAuthority fresh rollback preserves an event final collision winner", () => {
  withTempHome(() => {
    const domain = "authority-event-final-collision.example.com";
    const eventsFile = sessionEventsJsonlPath(domain);
    const realLinkSync = fs.linkSync;
    const collision = new Error("injected event final collision");
    collision.code = "EEXIST";
    let injected = false;
    let winnerStats = null;
    let winnerBytes = null;
    let thrown = null;

    fs.linkSync = function injectedLink(source, destination) {
      if (!injected && path.resolve(destination) === path.resolve(eventsFile)) {
        injected = true;
        fs.writeFileSync(eventsFile, "legacy winner\n", "utf8");
        winnerStats = fs.lstatSync(eventsFile);
        winnerBytes = fs.readFileSync(eventsFile);
        assert.equal(winnerStats.isFile(), true);
        assert.equal(winnerStats.isSymbolicLink(), false);
        throw collision;
      }
      return realLinkSync(source, destination);
    };
    try {
      assert.throws(
        () => commitState(domain, initialState(domain), { expectedNucleusHash: null }),
        (error) => {
          thrown = error;
          assert.match(error.message, /session-events\.jsonl already exists/);
          return true;
        },
      );
    } finally {
      fs.linkSync = realLinkSync;
    }

    assert.equal(injected, true);
    assert.ok(thrown);
    assert.equal(thrown.exclusive_receipt.label, "session-events.jsonl");
    assert.equal(thrown.exclusive_receipt.status, "exists");
    assert.equal(thrown.exclusive_receipt.phase, "link");
    assert.equal(thrown.exclusive_receipt.path, eventsFile);
    const finalCandidate = thrown.exclusive_receipt.finalCandidate;
    assert.equal(finalCandidate.path, eventsFile);
    assert.equal(finalCandidate.dev, winnerStats.dev);
    assert.equal(finalCandidate.ino, winnerStats.ino);
    assert.equal(finalCandidate.owned, false);
    assert.notEqual(finalCandidate.source_matches_temp, true);
    assert.notEqual(finalCandidate.inferredFromTemp, true);
    assert.notEqual(finalCandidate.rollbackOwned, true);
    assert.equal(fs.existsSync(statePath(domain)), false);
    assert.equal(fs.existsSync(sessionNucleusPath(domain)), false);
    const afterWinnerStats = fs.lstatSync(eventsFile);
    assert.equal(afterWinnerStats.dev, winnerStats.dev);
    assert.equal(afterWinnerStats.ino, winnerStats.ino);
    assert.equal(Buffer.compare(fs.readFileSync(eventsFile), winnerBytes), 0);
    assertNoAuthorityTemps(domain);
    fs.rmSync(sessionDir(domain), { recursive: true, force: true });
  });
});

test("commitSessionAuthority fresh rollback removes owned final after temp replacement proof failure", () => {
  withTempHome(() => {
    const domain = "authority-temp-replacement-rollback.example.com";
    const nucleusFile = sessionNucleusPath(domain);
    const realLinkSync = fs.linkSync;
    let replacementTemp = null;

    fs.linkSync = function injectedLink(source, destination) {
      realLinkSync(source, destination);
      if (path.resolve(destination) === path.resolve(nucleusFile)) {
        replacementTemp = source;
        fs.unlinkSync(source);
        fs.writeFileSync(source, "replacement temp survives\n", "utf8");
      }
    };
    try {
      assert.throws(
        () => commitState(domain, initialState(domain), { expectedNucleusHash: null }),
        /exclusive final link count proof failed/,
      );
    } finally {
      fs.linkSync = realLinkSync;
    }

    assert.ok(replacementTemp);
    assert.equal(fs.existsSync(statePath(domain)), false);
    assert.equal(fs.existsSync(nucleusFile), false);
    assert.equal(fs.existsSync(sessionEventsJsonlPath(domain)), false);
    assert.equal(fs.readFileSync(replacementTemp, "utf8"), "replacement temp survives\n");
    fs.rmSync(sessionDir(domain), { recursive: true, force: true });
  });
});

test("commitSessionAuthority fresh rollback removes owned final after link throws post-publish", () => {
  withTempHome(() => {
    const domain = "authority-real-link-throw-rollback.example.com";
    const nucleusFile = sessionNucleusPath(domain);
    const realLinkSync = fs.linkSync;
    let injected = false;

    fs.linkSync = function injectedLink(source, destination) {
      realLinkSync(source, destination);
      if (!injected && path.resolve(destination) === path.resolve(nucleusFile)) {
        injected = true;
        throw new Error("injected real-link-then-throw");
      }
    };
    try {
      assert.throws(
        () => commitState(domain, initialState(domain), { expectedNucleusHash: null }),
        /injected real-link-then-throw/,
      );
    } finally {
      fs.linkSync = realLinkSync;
    }

    assert.equal(injected, true);
    assertAuthorityFilesAbsent(domain);
    fs.rmSync(sessionDir(domain), { recursive: true, force: true });
  });
});

for (const [member, fileFor] of [
  ["state", statePath],
  ["nucleus", sessionNucleusPath],
  ["event", sessionEventsJsonlPath],
]) {
  test(`commitSessionAuthority fresh rollback infers ${member} final after first link proof fault`, () => {
    withTempHome(() => {
      const domain = `authority-${member}-link-first-probe-rollback.example.com`;
      assertFreshCommitLinkFirstProbeFaultRollback(domain, fileFor(domain));
    });
  });
}

test("commitSessionAuthority fresh rollback keeps state link primary when re-probe fails", () => {
  withTempHome(() => {
    const domain = "authority-state-link-reprobe-rollback.example.com";
    assertFreshCommitLinkReprobeRollback(domain, statePath(domain));
  });
});

test("commitSessionAuthority fresh rollback keeps nucleus link primary when re-probe fails", () => {
  withTempHome(() => {
    const domain = "authority-nucleus-link-reprobe-rollback.example.com";
    assertFreshCommitLinkReprobeRollback(domain, sessionNucleusPath(domain));
  });
});

test("commitSessionAuthority fresh rollback keeps event link primary when re-probe fails", () => {
  withTempHome(() => {
    const domain = "authority-event-link-reprobe-rollback.example.com";
    assertFreshCommitLinkReprobeRollback(domain, sessionEventsJsonlPath(domain));
  });
});

for (const [member, fileFor] of [
  ["state", statePath],
  ["nucleus", sessionNucleusPath],
  ["event", sessionEventsJsonlPath],
]) {
  test(`commitSessionAuthority fresh rollback infers ${member} final after postlink proof fault`, () => {
    withTempHome(() => {
      const domain = `authority-${member}-postlink-proof-rollback.example.com`;
      assertFreshCommitPostlinkProbeFaultRollback(domain, fileFor(domain));
    });
  });
}

for (const [member, fileFor] of [
  ["state", statePath],
  ["nucleus", sessionNucleusPath],
  ["event", sessionEventsJsonlPath],
]) {
  test(`commitSessionAuthority fresh rollback infers ${member} final after EEXIST-coded postlink proof fault`, () => {
    withTempHome(() => {
      const domain = `authority-${member}-postlink-proof-eexist-rollback.example.com`;
      assertFreshCommitPostlinkProbeFaultRollback(domain, fileFor(domain), "EEXIST");
    });
  });
}

test("commitSessionAuthority inferred final rollback preserves a wrong-source link winner", () => {
  withTempHome(() => {
    const domain = "authority-wrong-source-link-preserve.example.com";
    assertFreshCommitWrongSourceLinkPreserved(domain, sessionNucleusPath(domain));
  });
});

test("commitSessionAuthority inferred final rollback preserves a replaced final", () => {
  withTempHome(() => {
    const domain = "authority-final-replacement-preserve.example.com";
    assertFreshCommitFinalReplacementPreserved(domain, sessionNucleusPath(domain));
  });
});

test("commitSessionAuthority fresh rollback removes state final and temp after cleanup failure", () => {
  withTempHome(() => {
    const domain = "authority-state-cleanup-failure-rollback.example.com";
    assertFreshCommitCleanupFailureRollback(domain, statePath(domain));
  });
});

test("commitSessionAuthority fresh rollback removes nucleus final and temp after cleanup failure", () => {
  withTempHome(() => {
    const domain = "authority-nucleus-cleanup-failure-rollback.example.com";
    assertFreshCommitCleanupFailureRollback(domain, sessionNucleusPath(domain));
  });
});

test("commitSessionAuthority fresh rollback removes event final and temp after cleanup failure", () => {
  withTempHome(() => {
    const domain = "authority-event-cleanup-failure-rollback.example.com";
    assertFreshCommitCleanupFailureRollback(domain, sessionEventsJsonlPath(domain));
  });
});

test("commitSessionAuthority fresh rollback preserves replaced temp after cleanup failure", () => {
  withTempHome(() => {
    const domain = "authority-cleanup-temp-replacement-rollback.example.com";
    const nucleusFile = sessionNucleusPath(domain);
    const realLinkSync = fs.linkSync;
    const realUnlinkSync = fs.unlinkSync;
    const linkFailure = new Error("injected nucleus link failure after publish");
    linkFailure.code = "EIO";
    const cleanupFailure = new Error("injected nucleus staged cleanup failure");
    let injected = false;
    let cleanupInjected = false;
    let replacementTemp = null;
    let thrown = null;

    fs.linkSync = function injectedLink(source, destination) {
      if (!injected && path.resolve(destination) === path.resolve(nucleusFile)) {
        injected = true;
        replacementTemp = source;
        realLinkSync(source, destination);
        throw linkFailure;
      }
      return realLinkSync(source, destination);
    };
    fs.unlinkSync = function injectedUnlink(target) {
      if (
        replacementTemp
        && !cleanupInjected
        && path.resolve(target) === path.resolve(replacementTemp)
      ) {
        cleanupInjected = true;
        realUnlinkSync(target);
        fs.writeFileSync(target, "replacement temp survives\n", "utf8");
        throw cleanupFailure;
      }
      return realUnlinkSync(target);
    };
    try {
      commitState(domain, initialState(domain), { expectedNucleusHash: null });
    } catch (error) {
      thrown = error;
    } finally {
      fs.linkSync = realLinkSync;
      fs.unlinkSync = realUnlinkSync;
    }

    assert.equal(thrown, linkFailure);
    assert.equal(thrown.cleanup_error, cleanupFailure.message);
    assert.equal(injected, true);
    assert.equal(cleanupInjected, true);
    assert.ok(replacementTemp);
    assert.equal(fs.existsSync(statePath(domain)), false);
    assert.equal(fs.existsSync(nucleusFile), false);
    assert.equal(fs.existsSync(sessionEventsJsonlPath(domain)), false);
    assert.equal(fs.readFileSync(replacementTemp, "utf8"), "replacement temp survives\n");
    fs.rmSync(sessionDir(domain), { recursive: true, force: true });
  });
});

test("commitSessionAuthority restores exact prior bytes when nucleus CAS publish fails after state write", () => {
  withTempHome(() => {
    const domain = "authority-update-nucleus-failure.example.com";
    const first = commitState(domain, initialState(domain), { expectedNucleusHash: null });
    const before = snapshotPaths(domain);
    const realLinkSync = fs.linkSync;
    let injected = false;
    fs.linkSync = function injectedLink(source, destination) {
      if (!injected && path.resolve(destination) === path.resolve(sessionNucleusPath(domain))) {
        injected = true;
        throw new Error("injected nucleus rename failure");
      }
      return realLinkSync(source, destination);
    };
    try {
      assert.throws(
        () => commitState(domain, initialState(domain, { lifecycle_state: "OPEN_FRONTIER", phase: "EVALUATE" }), {
          expectedNucleusHash: first.nucleus_hash,
          rawDocument: readSessionStateStrict(domain).raw,
          event: governanceEvent("governance.lifecycle.advanced"),
        }),
        /injected nucleus rename failure/,
      );
    } finally {
      fs.linkSync = realLinkSync;
    }

    assert.equal(injected, true);
    assertSnapshotsEqual(domain, before);
  });
});

test("commitSessionAuthority restores exact prior bytes when event CAS publish fails post-effect", () => {
  withTempHome(() => {
    const domain = "authority-event-failure.example.com";
    const first = commitState(domain, initialState(domain), { expectedNucleusHash: null });
    const before = snapshotPaths(domain);
    const eventsFile = sessionEventsJsonlPath(domain);
    const realLinkSync = fs.linkSync;
    let injected = false;
    fs.linkSync = function injectedLink(source, destination) {
      if (!injected && path.resolve(destination) === path.resolve(eventsFile)) {
        injected = true;
        realLinkSync(source, destination);
        throw new Error("injected event CAS publish failure");
      }
      return realLinkSync(source, destination);
    };
    try {
      assert.throws(
        () => commitState(domain, initialState(domain, { lifecycle_state: "OPEN_FRONTIER", phase: "EVALUATE" }), {
          expectedNucleusHash: first.nucleus_hash,
          rawDocument: readSessionStateStrict(domain).raw,
          event: governanceEvent("governance.lifecycle.advanced"),
        }),
        /injected event CAS publish failure/,
      );
    } finally {
      fs.linkSync = realLinkSync;
    }

    assert.equal(injected, true);
    assertSnapshotsEqual(domain, before);
  });
});

test("commitSessionAuthority uses verified nucleus CAS instead of state fallback", () => {
  withTempHome(() => {
    const domain = "authority-no-state-fallback.example.com";
    const state = initialState(domain);
    writeFileAtomic(statePath(domain), `${JSON.stringify(state, null, 2)}\n`);

    assert.throws(
      () => commitState(domain, initialState(domain, { lifecycle_state: "OPEN_FRONTIER", phase: "EVALUATE" }), {
        expectedNucleusHash: sessionNucleusFromState(state).nucleus_hash,
        rawDocument: {},
        event: governanceEvent("governance.lifecycle.advanced"),
      }),
      /verified session nucleus requires session-nucleus\.json/,
    );

    assert.equal(fs.existsSync(sessionNucleusPath(domain)), false);
    assert.equal(fs.existsSync(sessionEventsJsonlPath(domain)), false);
    assert.equal(JSON.parse(fs.readFileSync(statePath(domain), "utf8")).target, domain);
  });
});
