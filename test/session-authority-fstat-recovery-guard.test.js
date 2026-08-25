"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  sessionDir,
  sessionEventsJsonlPath,
  sessionNucleusPath,
  statePath,
} = require("../mcp/core/io/paths.js");
const {
  writeFileExclusiveAtomic,
  writeFileExclusiveAtomicReceipt,
} = require("../mcp/core/io/storage.js");
const {
  readVerifiedSessionNucleus,
  sessionNucleusFromState,
} = require("../mcp/core/governance/index.js");
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

function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fstat-recovery-"));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fstat-home-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function withPatchedFs(patchers, fn) {
  const originals = {};
  const names = Object.keys(patchers);
  for (const name of names) originals[name] = fs[name];
  try {
    for (const name of names) fs[name] = patchers[name](originals);
    return fn();
  } finally {
    for (const name of names.reverse()) fs[name] = originals[name];
  }
}

function eio(message, { frozen = false } = {}) {
  const error = new Error(message);
  error.code = "EIO";
  if (frozen) Object.freeze(error);
  return error;
}

function isTempFor(target, candidate) {
  return path.dirname(candidate) === path.dirname(target)
    && path.basename(candidate).startsWith(`.${path.basename(target)}.`)
    && path.basename(candidate).endsWith(".tmp");
}

function tempPathsFor(target) {
  const dir = path.dirname(target);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter((entry) => isTempFor(target, path.join(dir, entry)))
    .map((entry) => path.join(dir, entry))
    .sort();
}

function assertNoTempFor(target) {
  assert.deepEqual(tempPathsFor(target), [], `${path.basename(target)} temp residue must be absent`);
}

function assertOnlyZeroByteTemp(target, tempPath) {
  assert.deepEqual(tempPathsFor(target), [tempPath]);
  const stats = fs.lstatSync(tempPath);
  assert.equal(stats.isFile(), true);
  assert.equal(stats.isSymbolicLink(), false);
  assert.equal(stats.size, 0);
  return stats;
}

function assertExactRegularFixture(filePath, expectedStats, expectedBytes) {
  const stats = fs.lstatSync(filePath);
  assert.equal(stats.isFile(), true);
  assert.equal(stats.isSymbolicLink(), false);
  assert.equal(stats.dev, expectedStats.dev);
  assert.equal(stats.ino, expectedStats.ino);
  assert.equal(fs.readFileSync(filePath, "utf8"), expectedBytes);
  return stats;
}

function unlinkExactRegularFixture(filePath, expectedStats, expectedBytes = null) {
  const stats = fs.lstatSync(filePath);
  assert.equal(stats.isFile(), true);
  assert.equal(stats.isSymbolicLink(), false);
  assert.equal(stats.dev, expectedStats.dev);
  assert.equal(stats.ino, expectedStats.ino);
  if (expectedBytes !== null) assert.equal(fs.readFileSync(filePath, "utf8"), expectedBytes);
  fs.unlinkSync(filePath);
}

function runFstatFaultScenario({
  failedFile,
  publicationFiles = [failedFile],
  mode,
  freezeSecond = false,
  replaceDuringClose = false,
  operation,
}) {
  const state = {
    tempFd: null,
    tempPath: null,
    targetOpenActive: false,
    fstatCount: 0,
    writeCount: 0,
    closeCount: 0,
    linkCount: 0,
    unlinkCount: 0,
    publicationOpenCounts: new Map(publicationFiles.map((filePath) => [filePath, 0])),
    movedPath: null,
    movedStats: null,
    replacementStats: null,
    firstError: eio(`injected first fstat failure for ${path.basename(failedFile)}`),
    secondError: eio(`injected second fstat failure for ${path.basename(failedFile)}`, {
      frozen: freezeSecond,
    }),
  };

  let result;
  let thrown = null;

  const matchingPublication = (candidate) => publicationFiles
    .find((filePath) => isTempFor(filePath, candidate));

  try {
    result = withPatchedFs({
      openSync: (originals) => function patchedOpenSync(target, flags, openMode) {
        const descriptor = originals.openSync.call(fs, target, flags, openMode);
        const publication = matchingPublication(target);
        if (publication) {
          state.publicationOpenCounts.set(
            publication,
            state.publicationOpenCounts.get(publication) + 1,
          );
        }
        if (publication && path.resolve(publication) === path.resolve(failedFile)) {
          state.tempFd = descriptor;
          state.tempPath = target;
          state.targetOpenActive = true;
        }
        return descriptor;
      },
      fstatSync: (originals) => function patchedFstatSync(descriptor) {
        if (state.targetOpenActive && descriptor === state.tempFd) {
          state.fstatCount += 1;
          if (mode === "transient" && state.fstatCount === 1) throw state.firstError;
          if (mode === "persistent") {
            if (state.fstatCount === 1) throw state.firstError;
            if (state.fstatCount === 2) throw state.secondError;
          }
        }
        return originals.fstatSync.call(fs, descriptor);
      },
      writeFileSync: (originals) => function patchedWriteFileSync(target, content, options) {
        if (state.targetOpenActive && target === state.tempFd) state.writeCount += 1;
        return originals.writeFileSync.call(fs, target, content, options);
      },
      closeSync: (originals) => function patchedCloseSync(descriptor) {
        if (state.targetOpenActive && descriptor === state.tempFd) {
          state.closeCount += 1;
          if (replaceDuringClose) {
            state.movedPath = path.join(path.dirname(state.tempPath), `.moved-${path.basename(state.tempPath)}`);
            originals.renameSync.call(fs, state.tempPath, state.movedPath);
            originals.writeFileSync.call(fs, state.tempPath, "replacement sentinel\n", "utf8");
            state.movedStats = originals.lstatSync.call(fs, state.movedPath);
            state.replacementStats = originals.lstatSync.call(fs, state.tempPath);
          }
          state.targetOpenActive = false;
        }
        return originals.closeSync.call(fs, descriptor);
      },
      linkSync: (originals) => function patchedLinkSync(source, destination) {
        if (path.resolve(destination) === path.resolve(failedFile)) state.linkCount += 1;
        return originals.linkSync.call(fs, source, destination);
      },
      unlinkSync: (originals) => function patchedUnlinkSync(target) {
        if (state.tempPath && path.resolve(target) === path.resolve(state.tempPath)) {
          state.unlinkCount += 1;
        }
        return originals.unlinkSync.call(fs, target);
      },
      renameSync: (originals) => originals.renameSync.bind(fs),
      lstatSync: (originals) => originals.lstatSync.bind(fs),
    }, operation);
  } catch (error) {
    thrown = error;
  }

  return {
    ...state,
    result,
    thrown,
  };
}

function initialState(domain, overrides = {}) {
  return {
    ...buildInitialSessionState(domain, `https://${domain}`, {
      egressProfile: DEFAULT_EGRESS_PROFILE,
    }),
    ...overrides,
  };
}

function governanceEvent(kind = "governance.session.initialized") {
  return {
    kind,
    payload: {},
    source: {
      component: "session-authority-fstat-recovery-guard.test",
    },
  };
}

function commitState(domain, state) {
  const nextNucleus = sessionNucleusFromState(state);
  return commitSessionAuthority({
    targetDomain: domain,
    nextNucleus,
    stateProjection: {
      rawDocument: {},
      nextState: state,
    },
    event: governanceEvent(),
    expectedNucleusHash: null,
  });
}

function publicationTable(domain) {
  return [
    { key: "state", label: "state.json", filePath: statePath(domain) },
    { key: "nucleus", label: "session-nucleus.json", filePath: sessionNucleusPath(domain) },
    { key: "events", label: "session-events.jsonl", filePath: sessionEventsJsonlPath(domain) },
  ];
}

function assertAuthorityFilesAbsent(domain) {
  for (const { filePath } of publicationTable(domain)) {
    assert.equal(fs.existsSync(filePath), false, `${path.basename(filePath)} final must be absent`);
  }
}

function assertNoAuthorityTemps(domain) {
  for (const { filePath } of publicationTable(domain)) assertNoTempFor(filePath);
}

function authorityTempPaths(domain) {
  return publicationTable(domain)
    .flatMap(({ filePath }) => tempPathsFor(filePath))
    .sort();
}

function assertAuthorityTrioCreated(domain, expectedNucleus) {
  assert.deepEqual(readVerifiedSessionNucleus(domain), expectedNucleus);
  assert.equal(readSessionStateStrict(domain).state.target, domain);
  const events = readSessionEvents(domain);
  assert.equal(events.length, 1);
  assert.equal(events[0].target_domain, domain);
}

test("exclusive receipt and wrapper recover from transient post-open fstat failure", () => {
  withTempDir((dir) => {
    const receiptFile = path.join(dir, "receipt.txt");
    const receiptRun = runFstatFaultScenario({
      failedFile: receiptFile,
      mode: "transient",
      operation: () => writeFileExclusiveAtomicReceipt(receiptFile, "receipt bytes\n"),
    });

    assert.equal(receiptRun.thrown, null);
    assert.equal(receiptRun.fstatCount, 2);
    assert.equal(receiptRun.writeCount, 1);
    assert.equal(receiptRun.closeCount, 1);
    assert.equal(receiptRun.linkCount, 1);
    assert.equal(receiptRun.unlinkCount, 1);
    assert.equal(receiptRun.result.status, "created");
    assert.equal(receiptRun.result.phase, "complete");
    assert.equal(receiptRun.result.error, undefined);
    assert.equal(receiptRun.result.tempPath, receiptRun.tempPath);
    assert.equal(fs.readFileSync(receiptFile, "utf8"), "receipt bytes\n");
    assertNoTempFor(receiptFile);

    const wrapperFile = path.join(dir, "wrapper.txt");
    const wrapperRun = runFstatFaultScenario({
      failedFile: wrapperFile,
      mode: "transient",
      operation: () => writeFileExclusiveAtomic(wrapperFile, "wrapper bytes\n"),
    });

    assert.equal(wrapperRun.thrown, null);
    assert.equal(wrapperRun.result, true);
    assert.equal(wrapperRun.fstatCount, 2);
    assert.equal(wrapperRun.writeCount, 1);
    assert.equal(wrapperRun.closeCount, 1);
    assert.equal(wrapperRun.linkCount, 1);
    assert.equal(wrapperRun.unlinkCount, 1);
    assert.equal(fs.readFileSync(wrapperFile, "utf8"), "wrapper bytes\n");
    assertNoTempFor(wrapperFile);
  });
});

test("exclusive receipt and wrapper stage unresolved temp on persistent post-open fstat failure", () => {
  withTempDir((dir) => {
    const receiptFile = path.join(dir, "receipt-persistent.txt");
    const receiptRun = runFstatFaultScenario({
      failedFile: receiptFile,
      mode: "persistent",
      freezeSecond: true,
      operation: () => writeFileExclusiveAtomicReceipt(receiptFile, "must not write\n"),
    });

    assert.equal(receiptRun.thrown, null);
    assert.equal(receiptRun.fstatCount, 2);
    assert.equal(receiptRun.writeCount, 0);
    assert.equal(receiptRun.closeCount, 1);
    assert.equal(receiptRun.linkCount, 0);
    assert.equal(receiptRun.unlinkCount, 0);
    assert.equal(receiptRun.result.status, "failed");
    assert.equal(receiptRun.result.phase, "temp_identity");
    assert.equal(receiptRun.result.error, receiptRun.secondError);
    assert.equal(receiptRun.result.tempCandidate, null);
    assert.equal(receiptRun.result.finalCandidate, null);
    assert.deepEqual(receiptRun.result.unresolvedTemp, {
      path: receiptRun.tempPath,
      reason: "identity_unresolved",
    });
    assert.equal(fs.existsSync(receiptFile), false);
    assertOnlyZeroByteTemp(receiptFile, receiptRun.tempPath);

    const wrapperFile = path.join(dir, "wrapper-persistent.txt");
    const wrapperRun = runFstatFaultScenario({
      failedFile: wrapperFile,
      mode: "persistent",
      freezeSecond: true,
      operation: () => writeFileExclusiveAtomic(wrapperFile, "must not write\n"),
    });

    assert.equal(wrapperRun.thrown, wrapperRun.secondError);
    assert.equal(wrapperRun.fstatCount, 2);
    assert.equal(wrapperRun.writeCount, 0);
    assert.equal(wrapperRun.closeCount, 1);
    assert.equal(wrapperRun.linkCount, 0);
    assert.equal(wrapperRun.unlinkCount, 0);
    assert.equal(fs.existsSync(wrapperFile), false);
    assertOnlyZeroByteTemp(wrapperFile, wrapperRun.tempPath);
    if (Object.hasOwn(wrapperRun.thrown, "exclusiveReceipt")) {
      assert.equal(wrapperRun.thrown.exclusiveReceipt.phase, "temp_identity");
    }
  });
});

test("persistent fstat identity failure never unlinks an unproven temp replacement", () => {
  withTempDir((dir) => {
    const filePath = path.join(dir, "replacement-proof.txt");
    const run = runFstatFaultScenario({
      failedFile: filePath,
      mode: "persistent",
      freezeSecond: true,
      replaceDuringClose: true,
      operation: () => writeFileExclusiveAtomicReceipt(filePath, "must not write\n"),
    });

    assert.equal(run.thrown, null);
    assert.equal(run.result.status, "failed");
    assert.equal(run.result.phase, "temp_identity");
    assert.equal(run.result.error, run.secondError);
    assert.equal(run.result.tempCandidate, null);
    assert.equal(run.result.finalCandidate, null);
    assert.deepEqual(run.result.unresolvedTemp, {
      path: run.tempPath,
      reason: "identity_unresolved",
    });
    assert.equal(run.writeCount, 0);
    assert.equal(run.linkCount, 0);
    assert.equal(run.unlinkCount, 0);
    assert.equal(fs.existsSync(filePath), false);

    assertExactRegularFixture(run.movedPath, run.movedStats, "");
    assertExactRegularFixture(run.tempPath, run.replacementStats, "replacement sentinel\n");
    unlinkExactRegularFixture(run.movedPath, run.movedStats, "");
    unlinkExactRegularFixture(run.tempPath, run.replacementStats, "replacement sentinel\n");
  });
});

test("fresh session authority UOW recovers transient fstat failures for every publication", () => {
  withTempHome(() => {
    for (const publicationKey of ["state", "nucleus", "events"]) {
      const domain = `authority-fstat-transient-${publicationKey}.example.com`;
      const table = publicationTable(domain);
      const failed = table.find((entry) => entry.key === publicationKey);
      const state = initialState(domain);
      const expectedNucleus = sessionNucleusFromState(state);
      const run = runFstatFaultScenario({
        failedFile: failed.filePath,
        publicationFiles: table.map((entry) => entry.filePath),
        mode: "transient",
        operation: () => commitState(domain, state),
      });

      assert.equal(run.thrown, null, publicationKey);
      assert.equal(run.result.target_domain, domain, publicationKey);
      assert.equal(run.result.nucleus_hash, expectedNucleus.nucleus_hash, publicationKey);
      assert.equal(run.fstatCount, 2, publicationKey);
      assert.equal(run.writeCount, 1, publicationKey);
      assert.equal(run.closeCount, 1, publicationKey);
      assert.equal(run.linkCount, 1, publicationKey);
      assertAuthorityTrioCreated(domain, expectedNucleus);
      assertNoAuthorityTemps(domain);
      fs.rmSync(sessionDir(domain), { recursive: true, force: true });
    }
  });
});

test("fresh session authority UOW rolls back persistent fstat failures and retries cleanly", () => {
  withTempHome(() => {
    for (const publicationKey of ["state", "nucleus", "events"]) {
      const domain = `authority-fstat-persistent-${publicationKey}.example.com`;
      const table = publicationTable(domain);
      const failedIndex = table.findIndex((entry) => entry.key === publicationKey);
      const failed = table[failedIndex];
      const state = initialState(domain);
      const expectedNucleus = sessionNucleusFromState(state);
      const run = runFstatFaultScenario({
        failedFile: failed.filePath,
        publicationFiles: table.map((entry) => entry.filePath),
        mode: "persistent",
        operation: () => commitState(domain, state),
      });

      assert.equal(run.thrown, run.secondError, publicationKey);
      assert.equal(run.thrown.code, "EIO", publicationKey);
      assert.equal(run.thrown.exclusive_receipt.label, failed.label, publicationKey);
      assert.equal(run.thrown.exclusive_receipt.status, "failed", publicationKey);
      assert.equal(run.thrown.exclusive_receipt.phase, "temp_identity", publicationKey);
      assert.deepEqual(run.thrown.exclusive_receipt.unresolvedTemp, {
        path: run.tempPath,
        reason: "identity_unresolved",
      }, publicationKey);
      assert.equal(run.fstatCount, 2, publicationKey);
      assert.equal(run.writeCount, 0, publicationKey);
      assert.equal(run.closeCount, 1, publicationKey);
      assert.equal(run.linkCount, 0, publicationKey);
      assert.equal(run.unlinkCount, 0, publicationKey);

      for (let index = 0; index < table.length; index += 1) {
        const entry = table[index];
        assert.equal(fs.existsSync(entry.filePath), false, `${entry.key} final must not survive`);
        if (index > failedIndex) {
          assert.equal(
            run.publicationOpenCounts.get(entry.filePath),
            0,
            `${entry.key} successor must be skipped`,
          );
        }
        if (entry.filePath !== failed.filePath) assertNoTempFor(entry.filePath);
      }

      assertAuthorityFilesAbsent(domain);
      assert.deepEqual(authorityTempPaths(domain), [run.tempPath], publicationKey);
      const unresolvedStats = assertOnlyZeroByteTemp(failed.filePath, run.tempPath);
      unlinkExactRegularFixture(run.tempPath, unresolvedStats, "");
      assertNoAuthorityTemps(domain);

      const retryResult = commitState(domain, state);
      assert.equal(retryResult.target_domain, domain);
      assert.equal(retryResult.nucleus_hash, expectedNucleus.nucleus_hash);
      assertAuthorityTrioCreated(domain, expectedNucleus);
      assertNoAuthorityTemps(domain);
      fs.rmSync(sessionDir(domain), { recursive: true, force: true });
    }
  });
});
