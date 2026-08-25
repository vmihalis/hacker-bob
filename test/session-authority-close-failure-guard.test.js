"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  readVerifiedSessionNucleus,
  sessionNucleusFromState,
} = require("../mcp/core/governance/index.js");
const {
  sessionEventsJsonlPath,
  sessionNucleusPath,
  statePath,
} = require("../mcp/core/io/paths.js");
const {
  writeFileExclusiveAtomic,
  writeFileExclusiveAtomicReceipt,
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
  egress_profile_identity_source: Object.freeze({
    proxy_url_source: "none",
    proxy_env_var: null,
    proxy_url_redacted: null,
    resolved_proxy: null,
  }),
});

const MEMBERS = Object.freeze([
  { key: "state", label: "state.json", pathFor: statePath },
  { key: "nucleus", label: "session-nucleus.json", pathFor: sessionNucleusPath },
  { key: "events", label: "session-events.jsonl", pathFor: sessionEventsJsonlPath },
]);

function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-close-failure-"));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-authority-close-failure-"));
  process.env.HOME = home;
  try {
    return fn();
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function samePath(left, right) {
  return path.resolve(left) === path.resolve(right);
}

function isTempFor(finalPath, candidate) {
  return path.dirname(candidate) === path.dirname(finalPath)
    && path.basename(candidate).startsWith(`.${path.basename(finalPath)}.`)
    && path.basename(candidate).endsWith(".tmp");
}

function frozenEio(message) {
  const error = new Error(message);
  error.code = "EIO";
  return Object.freeze(error);
}

function assertExactFile(filePath, identity, bytes) {
  const stats = fs.lstatSync(filePath);
  assert.equal(stats.isFile() && !stats.isSymbolicLink(), true);
  assert.equal(stats.dev, identity.dev);
  assert.equal(stats.ino, identity.ino);
  assert.equal(Buffer.compare(fs.readFileSync(filePath), bytes), 0);
  return stats;
}

function removeExactFile(filePath, identity) {
  const stats = fs.lstatSync(filePath);
  assert.equal(stats.isFile() && !stats.isSymbolicLink(), true);
  assert.equal(stats.dev, identity.dev);
  assert.equal(stats.ino, identity.ino);
  fs.unlinkSync(filePath);
}

function tempPathsFor(finalPath) {
  const directory = path.dirname(finalPath);
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory)
    .map((name) => path.join(directory, name))
    .filter((candidate) => isTempFor(finalPath, candidate))
    .sort();
}

function initialState(domain) {
  return buildInitialSessionState(domain, `https://${domain}`, {
    egressProfile: DEFAULT_EGRESS_PROFILE,
  });
}

function commitState(domain) {
  const state = initialState(domain);
  return commitSessionAuthority({
    targetDomain: domain,
    nextNucleus: sessionNucleusFromState(state),
    stateProjection: { rawDocument: {}, nextState: state },
    event: {
      kind: "governance.session.initialized",
      payload: {},
      source: { component: "session-authority-close-failure-guard.test" },
    },
    expectedNucleusHash: null,
  });
}

function publications(domain) {
  return MEMBERS.map((member) => ({ ...member, path: member.pathFor(domain) }));
}

function authorityTemps(domain) {
  return [...new Set(publications(domain).flatMap(({ path: filePath }) => tempPathsFor(filePath)))].sort();
}

function assertAuthorityAbsent(domain) {
  for (const publication of publications(domain)) {
    assert.equal(fs.existsSync(publication.path), false, `${publication.label} must be absent`);
  }
}

function assertCoherentRetry(domain) {
  const result = commitState(domain);
  const state = readSessionStateStrict(domain).state;
  const nucleus = readVerifiedSessionNucleus(domain);
  const events = readSessionEvents(domain);
  assert.equal(result.target_domain, domain);
  assert.equal(result.nucleus_hash, nucleus.nucleus_hash);
  assert.deepEqual(sessionNucleusFromState(state), nucleus);
  assert.equal(events.length, 1);
  assert.equal(events[0].nucleus_hash, nucleus.nucleus_hash);
  assert.deepEqual(authorityTemps(domain), []);
}

function runCloseFault({
  failedFile,
  publicationFiles = [failedFile],
  cleanupSecondary = false,
  replaceTemp = false,
  content = "authority candidate\n",
  operation,
}) {
  const primary = frozenEio(`injected close failure for ${path.basename(failedFile)}`);
  const cleanupFailure = new Error(`injected cleanup failure for ${path.basename(failedFile)}`);
  cleanupFailure.code = "EIO";
  const sentinelBytes = Buffer.from(`replacement for ${path.basename(failedFile)}\n`, "utf8");
  const originals = {
    openSync: fs.openSync,
    fstatSync: fs.fstatSync,
    readFileSync: fs.readFileSync,
    writeFileSync: fs.writeFileSync,
    closeSync: fs.closeSync,
    renameSync: fs.renameSync,
    lstatSync: fs.lstatSync,
    linkSync: fs.linkSync,
    unlinkSync: fs.unlinkSync,
  };
  const publicationOpenCounts = new Map(publicationFiles.map((filePath) => [filePath, 0]));
  const fdGenerations = new Map();
  let nextFdGeneration = 0;
  let tempFd = null;
  let tempFdGeneration = null;
  let tempPath = null;
  let tempStats = null;
  let closeCount = 0;
  let linkCount = 0;
  let tempUnlinkCount = 0;
  let cleanupInjected = false;
  let movedPath = null;
  let movedBytes = null;
  let movedStats = null;
  let replacementStats = null;
  let result;
  let thrown = null;

  fs.openSync = function patchedOpen(target, flags, mode) {
    const descriptor = originals.openSync.call(fs, target, flags, mode);
    const generation = ++nextFdGeneration;
    fdGenerations.set(descriptor, generation);
    const publication = publicationFiles.find((filePath) => isTempFor(filePath, target));
    if (publication) {
      publicationOpenCounts.set(publication, publicationOpenCounts.get(publication) + 1);
    }
    if (tempFd === null && isTempFor(failedFile, target)) {
      tempFd = descriptor;
      tempFdGeneration = generation;
      tempPath = target;
      tempStats = originals.fstatSync.call(fs, descriptor);
    }
    return descriptor;
  };
  fs.closeSync = function patchedClose(descriptor) {
    const generation = fdGenerations.get(descriptor);
    if (descriptor === tempFd && generation === tempFdGeneration) {
      closeCount += 1;
      if (closeCount > 1) return undefined;
      originals.closeSync.call(fs, descriptor);
      if (replaceTemp) {
        movedBytes = originals.readFileSync.call(fs, tempPath);
        movedPath = path.join(path.dirname(tempPath), `.moved-${path.basename(tempPath)}`);
        originals.renameSync.call(fs, tempPath, movedPath);
        const replacementFd = originals.openSync.call(
          fs,
          tempPath,
          fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY,
          0o600,
        );
        try {
          originals.writeFileSync.call(fs, replacementFd, sentinelBytes);
        } finally {
          originals.closeSync.call(fs, replacementFd);
        }
        movedStats = originals.lstatSync.call(fs, movedPath);
        replacementStats = originals.lstatSync.call(fs, tempPath);
      }
      throw primary;
    }
    try {
      return originals.closeSync.call(fs, descriptor);
    } finally {
      if (fdGenerations.get(descriptor) === generation) fdGenerations.delete(descriptor);
    }
  };
  fs.linkSync = function patchedLink(source, destination) {
    if (samePath(destination, failedFile)) linkCount += 1;
    return originals.linkSync.call(fs, source, destination);
  };
  fs.unlinkSync = function patchedUnlink(target) {
    if (tempPath && samePath(target, tempPath)) {
      tempUnlinkCount += 1;
      if (cleanupSecondary && !cleanupInjected) {
        const current = originals.lstatSync.call(fs, target);
        assert.equal(current.dev, tempStats.dev);
        assert.equal(current.ino, tempStats.ino);
        cleanupInjected = true;
        throw cleanupFailure;
      }
    }
    return originals.unlinkSync.call(fs, target);
  };

  try {
    result = operation();
  } catch (error) {
    thrown = error;
  } finally {
    fs.openSync = originals.openSync;
    fs.closeSync = originals.closeSync;
    fs.linkSync = originals.linkSync;
    fs.unlinkSync = originals.unlinkSync;
  }

  return {
    result,
    thrown,
    primary,
    cleanupFailure,
    sentinelBytes,
    publicationOpenCounts,
    tempFd,
    tempPath,
    tempStats,
    closeCount,
    linkCount,
    tempUnlinkCount,
    cleanupInjected,
    movedPath,
    movedBytes,
    movedStats,
    replacementStats,
    content: Buffer.from(content),
  };
}

function runCompoundWriteCloseCleanupFault(filePath) {
  const writeError = frozenEio("injected write failure");
  const closeError = frozenEio("injected close failure during write cleanup");
  const cleanupError = frozenEio("injected temp cleanup failure");
  const originals = {
    openSync: fs.openSync,
    fstatSync: fs.fstatSync,
    writeFileSync: fs.writeFileSync,
    closeSync: fs.closeSync,
    linkSync: fs.linkSync,
    lstatSync: fs.lstatSync,
    unlinkSync: fs.unlinkSync,
  };
  let tempFd = null;
  let tempPath = null;
  let tempStats = null;
  let closeCount = 0;
  let linkCount = 0;
  let cleanupCount = 0;

  fs.openSync = function patchedOpen(target, flags, mode) {
    const descriptor = originals.openSync.call(fs, target, flags, mode);
    if (tempFd === null && isTempFor(filePath, target)) {
      tempFd = descriptor;
      tempPath = target;
      tempStats = originals.fstatSync.call(fs, descriptor);
    }
    return descriptor;
  };
  fs.writeFileSync = function patchedWrite(descriptor, ...args) {
    if (descriptor === tempFd) throw writeError;
    return originals.writeFileSync.call(fs, descriptor, ...args);
  };
  fs.closeSync = function patchedClose(descriptor) {
    if (descriptor === tempFd) {
      closeCount += 1;
      originals.closeSync.call(fs, descriptor);
      throw closeError;
    }
    return originals.closeSync.call(fs, descriptor);
  };
  fs.linkSync = function patchedLink(source, destination) {
    if (samePath(destination, filePath)) linkCount += 1;
    return originals.linkSync.call(fs, source, destination);
  };
  fs.unlinkSync = function patchedUnlink(target) {
    if (tempPath && samePath(target, tempPath)) {
      const current = originals.lstatSync.call(fs, target);
      assert.equal(current.dev, tempStats.dev);
      assert.equal(current.ino, tempStats.ino);
      cleanupCount += 1;
      throw cleanupError;
    }
    return originals.unlinkSync.call(fs, target);
  };

  let receipt;
  try {
    receipt = writeFileExclusiveAtomicReceipt(filePath, "never published\n");
  } finally {
    fs.openSync = originals.openSync;
    fs.writeFileSync = originals.writeFileSync;
    fs.closeSync = originals.closeSync;
    fs.linkSync = originals.linkSync;
    fs.unlinkSync = originals.unlinkSync;
  }
  return {
    receipt,
    writeError,
    closeError,
    cleanupError,
    tempFd,
    tempPath,
    tempStats,
    closeCount,
    linkCount,
    cleanupCount,
  };
}

function assertDescriptorClosed(descriptor) {
  assert.throws(
    () => fs.fstatSync(descriptor),
    (error) => error && error.code === "EBADF",
  );
}

function assertReceiptCloseFailure(run) {
  const receipt = run.result;
  assert.equal(run.thrown, null);
  assert.equal(receipt.status, "failed");
  assert.equal(receipt.phase, "close");
  assert.equal(receipt.error, run.primary);
  assert.equal(receipt.path != null, true);
  assert.equal(receipt.tempPath, run.tempPath);
  assert.equal(receipt.finalCandidate, null);
  assert.equal(receipt.closeError, undefined);
  assert.equal(receipt.tempCandidate.path, run.tempPath);
  assert.equal(receipt.tempCandidate.dev, run.tempStats.dev);
  assert.equal(receipt.tempCandidate.ino, run.tempStats.ino);
  assert.equal(receipt.tempCandidate.type, "file");
  assert.equal(receipt.tempCandidate.owned, true);
  assert.equal(run.closeCount, 1);
  assert.equal(run.linkCount, 0);
  assertDescriptorClosed(run.tempFd);
  assert.equal(fs.existsSync(receipt.path), false);
}

function assertPublicationProgress(run, table, failedIndex) {
  for (const [index, publication] of table.entries()) {
    const count = run.publicationOpenCounts.get(publication.path);
    if (index < failedIndex) assert.equal(count, 1, `${publication.label} predecessor`);
    else if (index === failedIndex) assert.equal(count >= 1, true, `${publication.label} attempted`);
    else assert.equal(count, 0, `${publication.label} successor`);
  }
}

test("close failures preserve primary and candidate ownership across storage and session authority", () => {
  withTempDir((dir) => {
    const receiptFile = path.join(dir, "receipt.txt");
    const receiptRun = runCloseFault({
      failedFile: receiptFile,
      operation: () => writeFileExclusiveAtomicReceipt(receiptFile, "receipt candidate\n"),
    });
    assertReceiptCloseFailure(receiptRun);
    assert.equal(receiptRun.result.cleanupError, undefined);
    assert.equal(receiptRun.tempUnlinkCount, 1);
    assert.deepEqual(tempPathsFor(receiptFile), []);

    const wrapperFile = path.join(dir, "wrapper.txt");
    const wrapperRun = runCloseFault({
      failedFile: wrapperFile,
      operation: () => writeFileExclusiveAtomic(wrapperFile, "wrapper candidate\n"),
    });
    assert.equal(wrapperRun.result, undefined);
    assert.equal(wrapperRun.thrown, wrapperRun.primary);
    assert.equal(wrapperRun.thrown.name, "Error");
    assert.equal(wrapperRun.thrown.code, "EIO");
    if (Object.hasOwn(wrapperRun.thrown, "exclusiveReceipt")) {
      assert.equal(wrapperRun.thrown.exclusiveReceipt.phase, "close");
    }
    assert.equal(wrapperRun.closeCount, 1);
    assert.equal(wrapperRun.linkCount, 0);
    assert.equal(wrapperRun.tempUnlinkCount, 1);
    assertDescriptorClosed(wrapperRun.tempFd);
    assert.equal(fs.existsSync(wrapperFile), false);
    assert.deepEqual(tempPathsFor(wrapperFile), []);

    const compoundFile = path.join(dir, "compound.txt");
    const compound = runCompoundWriteCloseCleanupFault(compoundFile);
    assert.equal(compound.receipt.status, "failed");
    assert.equal(compound.receipt.phase, "write");
    assert.equal(compound.receipt.error, compound.writeError);
    assert.equal(compound.receipt.closeError, compound.closeError);
    assert.equal(compound.receipt.cleanupError, compound.cleanupError);
    assert.equal(compound.receipt.tempCandidate.path, compound.tempPath);
    assert.equal(compound.receipt.tempCandidate.dev, compound.tempStats.dev);
    assert.equal(compound.receipt.tempCandidate.ino, compound.tempStats.ino);
    assert.equal(compound.closeCount, 1);
    assert.equal(compound.linkCount, 0);
    assert.equal(compound.cleanupCount, 1);
    assertDescriptorClosed(compound.tempFd);
    assert.equal(fs.existsSync(compoundFile), false);
    assertExactFile(compound.tempPath, compound.tempStats, Buffer.alloc(0));
    removeExactFile(compound.tempPath, compound.tempStats);

    const cleanupFile = path.join(dir, "cleanup-secondary.txt");
    const cleanupRun = runCloseFault({
      failedFile: cleanupFile,
      cleanupSecondary: true,
      content: "cleanup candidate\n",
      operation: () => writeFileExclusiveAtomicReceipt(cleanupFile, "cleanup candidate\n"),
    });
    assertReceiptCloseFailure(cleanupRun);
    assert.equal(cleanupRun.result.cleanupError, cleanupRun.cleanupFailure);
    assert.equal(cleanupRun.cleanupInjected, true);
    assert.equal(cleanupRun.tempUnlinkCount, 1);
    assertExactFile(cleanupRun.tempPath, cleanupRun.tempStats, cleanupRun.content);
    removeExactFile(cleanupRun.tempPath, cleanupRun.tempStats);
    assert.deepEqual(tempPathsFor(cleanupFile), []);

    const replacementFile = path.join(dir, "replacement.txt");
    const replacementRun = runCloseFault({
      failedFile: replacementFile,
      replaceTemp: true,
      content: "owned candidate\n",
      operation: () => writeFileExclusiveAtomicReceipt(replacementFile, "owned candidate\n"),
    });
    assertReceiptCloseFailure(replacementRun);
    assert.equal(replacementRun.result.cleanupError, undefined);
    assert.equal(replacementRun.tempUnlinkCount, 0);
    assert.notEqual(
      replacementRun.tempStats.dev === replacementRun.replacementStats.dev
        && replacementRun.tempStats.ino === replacementRun.replacementStats.ino,
      true,
    );
    assertExactFile(replacementRun.movedPath, replacementRun.tempStats, replacementRun.content);
    assert.equal(Buffer.compare(replacementRun.movedBytes, replacementRun.content), 0);
    assertExactFile(replacementRun.tempPath, replacementRun.replacementStats, replacementRun.sentinelBytes);
    removeExactFile(replacementRun.movedPath, replacementRun.tempStats);
    removeExactFile(replacementRun.tempPath, replacementRun.replacementStats);
    assert.deepEqual(tempPathsFor(replacementFile), []);
  });

  withTempHome(() => {
    for (const [failedIndex, member] of MEMBERS.entries()) {
      const domain = `a2k-${member.key}-cleanup.example.com`;
      const table = publications(domain);
      const failedFile = member.pathFor(domain);
      const run = runCloseFault({
        failedFile,
        publicationFiles: table.map((publication) => publication.path),
        cleanupSecondary: true,
        operation: () => commitState(domain),
      });

      assert.equal(run.thrown, run.primary);
      assert.equal(run.thrown.code, "EIO");
      assert.equal(run.cleanupInjected, true);
      assert.equal(run.closeCount, 1);
      assert.equal(run.linkCount, 0);
      assert.equal(run.tempUnlinkCount, 2);
      assertDescriptorClosed(run.tempFd);
      assertPublicationProgress(run, table, failedIndex);
      assertAuthorityAbsent(domain);
      assert.deepEqual(authorityTemps(domain), []);
      assertCoherentRetry(domain);
    }

    const domain = "a2k-nucleus-replacement.example.com";
    const table = publications(domain);
    const failedFile = sessionNucleusPath(domain);
    const run = runCloseFault({
      failedFile,
      publicationFiles: table.map((publication) => publication.path),
      replaceTemp: true,
      operation: () => commitState(domain),
    });

    assert.equal(run.thrown, run.primary);
    assert.equal(run.closeCount, 1);
    assert.equal(run.linkCount, 0);
    assert.equal(run.tempUnlinkCount, 0);
    assertDescriptorClosed(run.tempFd);
    assertPublicationProgress(run, table, 1);
    assertAuthorityAbsent(domain);
    assert.deepEqual(authorityTemps(domain), [run.tempPath]);
    assertExactFile(run.movedPath, run.tempStats, run.movedBytes);
    assertExactFile(run.tempPath, run.replacementStats, run.sentinelBytes);
    removeExactFile(run.movedPath, run.tempStats);
    removeExactFile(run.tempPath, run.replacementStats);
    assert.deepEqual(authorityTemps(domain), []);
    assertCoherentRetry(domain);
  });
});
