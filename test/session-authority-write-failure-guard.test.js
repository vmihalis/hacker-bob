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
const { readSessionEvents } = require("../mcp/core/session/session-events.js");
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-write-failure-"));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-authority-write-failure-"));
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
  return typeof candidate === "string"
    && path.dirname(candidate) === path.dirname(finalPath)
    && path.basename(candidate).startsWith(`.${path.basename(finalPath)}.`)
    && path.basename(candidate).endsWith(".tmp");
}

function tempPathsFor(finalPath) {
  const directory = path.dirname(finalPath);
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory)
    .map((name) => path.join(directory, name))
    .filter((candidate) => isTempFor(finalPath, candidate))
    .sort();
}

function frozenEio(message) {
  const error = new Error(message);
  error.code = "EIO";
  return Object.freeze(error);
}

function assertExactRegular(filePath, identity, bytes) {
  const stats = fs.lstatSync(filePath);
  assert.equal(stats.isFile() && !stats.isSymbolicLink(), true);
  assert.equal(stats.dev, identity.dev);
  assert.equal(stats.ino, identity.ino);
  assert.equal(Buffer.compare(fs.readFileSync(filePath), bytes), 0);
  return stats;
}

function removeExactRegular(filePath, identity) {
  assertExactRegular(filePath, identity, fs.readFileSync(filePath));
  const stats = fs.lstatSync(filePath);
  assert.equal(stats.dev, identity.dev);
  assert.equal(stats.ino, identity.ino);
  fs.unlinkSync(filePath);
}

function assertDescriptorClosed(descriptor) {
  assert.throws(
    () => fs.fstatSync(descriptor),
    (error) => error && error.code === "EBADF",
  );
}

function createFdTracker(originals, failedFile, { onOpen = null } = {}) {
  const generations = new Map();
  let nextGeneration = 0;
  const tracker = {
    selected: null,
    closeCount: 0,
    open(target, flags, mode) {
      const descriptor = originals.openSync.call(fs, target, flags, mode);
      const entry = { generation: ++nextGeneration, path: target };
      generations.set(descriptor, entry);
      if (onOpen) onOpen(target);
      if (tracker.selected === null && isTempFor(failedFile, target)) {
        tracker.selected = {
          descriptor,
          generation: entry.generation,
          path: target,
          stats: originals.fstatSync.call(fs, descriptor),
        };
      }
      return descriptor;
    },
    entry(descriptor) {
      return generations.get(descriptor) || null;
    },
    isSelected(descriptor) {
      const current = generations.get(descriptor);
      return tracker.selected !== null
        && descriptor === tracker.selected.descriptor
        && current !== undefined
        && current.generation === tracker.selected.generation;
    },
    close(descriptor) {
      const entry = generations.get(descriptor);
      if (tracker.isSelected(descriptor)) {
        tracker.closeCount += 1;
        if (tracker.closeCount > 1) return undefined;
        return originals.closeSync.call(fs, descriptor);
      }
      try {
        return originals.closeSync.call(fs, descriptor);
      } finally {
        if (generations.get(descriptor) === entry) generations.delete(descriptor);
      }
    },
  };
  return tracker;
}

function runBufferProgressControl(filePath, content) {
  const originals = {
    openSync: fs.openSync,
    fstatSync: fs.fstatSync,
    writeSync: fs.writeSync,
    closeSync: fs.closeSync,
    linkSync: fs.linkSync,
  };
  const tracker = createFdTracker(originals, filePath);
  const total = content.length;
  const prefixLength = Math.max(1, Math.floor(total / 3));
  const calls = [];
  const progress = [];
  let linkCount = 0;
  let receipt;

  fs.openSync = tracker.open;
  fs.closeSync = tracker.close;
  fs.writeSync = function patchedWrite(descriptor, buffer, offset, length, position) {
    if (!tracker.isSelected(descriptor)) {
      return originals.writeSync.call(fs, descriptor, buffer, offset, length, position);
    }
    calls.push([offset, length]);
    let written;
    if (calls.length === 1) written = 0;
    else if (calls.length === 2) {
      written = originals.writeSync.call(fs, descriptor, buffer, offset, prefixLength, position);
    } else {
      written = originals.writeSync.call(fs, descriptor, buffer, offset, length, position);
    }
    progress.push(written);
    return written;
  };
  fs.linkSync = function patchedLink(source, destination) {
    if (samePath(destination, filePath)) linkCount += 1;
    return originals.linkSync.call(fs, source, destination);
  };

  try {
    receipt = writeFileExclusiveAtomicReceipt(filePath, content);
  } finally {
    fs.openSync = originals.openSync;
    fs.writeSync = originals.writeSync;
    fs.closeSync = originals.closeSync;
    fs.linkSync = originals.linkSync;
  }
  return { receipt, tracker, total, prefixLength, calls, progress, linkCount };
}

function runStringWriteFault({
  failedFile,
  publicationFiles = [failedFile],
  phase,
  replaceTemp = false,
  operation,
}) {
  const primary = frozenEio(`injected ${phase} write failure for ${path.basename(failedFile)}`);
  const sentinelBytes = Buffer.from(`replacement for ${path.basename(failedFile)}\n`, "utf8");
  const originals = {
    openSync: fs.openSync,
    fstatSync: fs.fstatSync,
    writeFileSync: fs.writeFileSync,
    closeSync: fs.closeSync,
    renameSync: fs.renameSync,
    lstatSync: fs.lstatSync,
    linkSync: fs.linkSync,
  };
  const publicationOpenCounts = new Map(publicationFiles.map((filePath) => [filePath, 0]));
  const publicationWriteCounts = new Map(publicationFiles.map((filePath) => [filePath, 0]));
  const tracker = createFdTracker(originals, failedFile, {
    onOpen(target) {
      const publication = publicationFiles.find((filePath) => isTempFor(filePath, target));
      if (publication) {
        publicationOpenCounts.set(publication, publicationOpenCounts.get(publication) + 1);
      }
    },
  });
  let writeCount = 0;
  let failedLinkCount = 0;
  let prefixBytes = null;
  let prefixStats = null;
  let movedPath = null;
  let movedStats = null;
  let replacementStats = null;
  let result;
  let thrown = null;

  fs.openSync = tracker.open;
  fs.closeSync = tracker.close;
  fs.writeFileSync = function patchedWrite(descriptor, data, options) {
    const entry = tracker.entry(descriptor);
    const publication = entry && publicationFiles.find((filePath) => isTempFor(filePath, entry.path));
    if (publication) {
      publicationWriteCounts.set(publication, publicationWriteCounts.get(publication) + 1);
    }
    if (!tracker.isSelected(descriptor)) {
      return originals.writeFileSync.call(fs, descriptor, data, options);
    }
    writeCount += 1;
    if (writeCount > 1) throw primary;
    assert.equal(typeof data, "string");
    if (phase === "Wp") {
      const bytes = Buffer.from(data, "utf8");
      const prefixLength = Math.max(1, Math.min(17, Math.floor(bytes.length / 3)));
      prefixBytes = bytes.subarray(0, prefixLength);
      originals.writeFileSync.call(fs, descriptor, prefixBytes);
      prefixStats = originals.fstatSync.call(fs, descriptor);
      if (replaceTemp) {
        movedPath = path.join(
          path.dirname(tracker.selected.path),
          `.aside-${path.basename(tracker.selected.path)}`,
        );
        originals.renameSync.call(fs, tracker.selected.path, movedPath);
        const replacementFd = originals.openSync.call(
          fs,
          tracker.selected.path,
          fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY,
          0o600,
        );
        try {
          originals.writeFileSync.call(fs, replacementFd, sentinelBytes);
        } finally {
          originals.closeSync.call(fs, replacementFd);
        }
        movedStats = originals.lstatSync.call(fs, movedPath);
        replacementStats = originals.lstatSync.call(fs, tracker.selected.path);
      }
    }
    throw primary;
  };
  fs.linkSync = function patchedLink(source, destination) {
    if (samePath(destination, failedFile)) failedLinkCount += 1;
    return originals.linkSync.call(fs, source, destination);
  };

  try {
    result = operation();
  } catch (error) {
    thrown = error;
  } finally {
    fs.openSync = originals.openSync;
    fs.writeFileSync = originals.writeFileSync;
    fs.closeSync = originals.closeSync;
    fs.linkSync = originals.linkSync;
  }

  return {
    failedFile,
    result,
    thrown,
    primary,
    phase,
    sentinelBytes,
    tracker,
    publicationOpenCounts,
    publicationWriteCounts,
    writeCount,
    failedLinkCount,
    prefixBytes,
    prefixStats,
    movedPath,
    movedStats,
    replacementStats,
  };
}

function createWinner(filePath, label) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const bytes = Buffer.from(`winner ${label}\n`, "utf8");
  fs.writeFileSync(filePath, bytes);
  return { stats: fs.lstatSync(filePath), bytes };
}

function assertFailedWriteReceipt(run) {
  const receipt = run.result;
  assert.equal(run.thrown, null);
  assert.equal(receipt.status, "failed");
  assert.equal(receipt.phase, "write");
  assert.equal(receipt.error, run.primary);
  assert.equal(receipt.path, run.failedFile);
  assert.equal(receipt.tempPath, run.tracker.selected.path);
  assert.equal(receipt.finalCandidate, null);
  assert.equal(receipt.closeError, undefined);
  assert.equal(receipt.cleanupError, undefined);
  assert.equal(receipt.probeError, undefined);
  assert.equal(receipt.unresolvedTemp, undefined);
  assert.equal(receipt.tempCandidate.path, run.tracker.selected.path);
  assert.equal(receipt.tempCandidate.dev, run.tracker.selected.stats.dev);
  assert.equal(receipt.tempCandidate.ino, run.tracker.selected.stats.ino);
  assert.equal(receipt.tempCandidate.type, "file");
  assert.equal(receipt.tempCandidate.owned, true);
  assert.equal(receipt.tempCandidate.size, 0);
}

function assertStringFaultCommon(run) {
  assert.equal(run.writeCount, 1);
  assert.equal(run.tracker.closeCount, 1);
  assert.equal(run.failedLinkCount, 0);
  assertDescriptorClosed(run.tracker.selected.descriptor);
  if (run.phase === "Wp") {
    assert.equal(run.prefixStats.size, run.prefixBytes.length);
  } else {
    assert.equal(run.prefixStats, null);
  }
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
      source: { component: "session-authority-write-failure-guard.test" },
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

function assertPublicationProgress(run, table, failedIndex) {
  for (const [index, publication] of table.entries()) {
    const expected = index <= failedIndex ? 1 : 0;
    assert.equal(
      run.publicationOpenCounts.get(publication.path),
      expected,
      `${publication.label} open progress`,
    );
    assert.equal(
      run.publicationWriteCounts.get(publication.path),
      expected,
      `${publication.label} write progress`,
    );
  }
}

test("Buffer publication tolerates finite zero progress and completes short writes", () => {
  withTempDir((dir) => {
    const filePath = path.join(dir, "buffer.txt");
    const content = Buffer.from("finite-zero-progress-short-write-control\n", "utf8");
    const run = runBufferProgressControl(filePath, content);
    const receipt = run.receipt;

    assert.equal(receipt.status, "created");
    assert.equal(receipt.phase, "complete");
    assert.equal(receipt.path, filePath);
    assert.deepEqual(run.calls, [
      [0, run.total],
      [0, run.total],
      [run.prefixLength, run.total - run.prefixLength],
    ]);
    assert.deepEqual(run.progress, [0, run.prefixLength, run.total - run.prefixLength]);
    assert.equal(run.tracker.closeCount, 1);
    assert.equal(run.linkCount, 1);
    assertDescriptorClosed(run.tracker.selected.descriptor);
    assert.equal(receipt.tempCandidate.dev, run.tracker.selected.stats.dev);
    assert.equal(receipt.tempCandidate.ino, run.tracker.selected.stats.ino);
    assert.equal(receipt.finalCandidate.dev, run.tracker.selected.stats.dev);
    assert.equal(receipt.finalCandidate.ino, run.tracker.selected.stats.ino);
    assertExactRegular(filePath, receipt.finalCandidate, content);
    assert.deepEqual(tempPathsFor(filePath), []);
  });
});

test("string W0/Wp failures retain exact receipt and boolean ownership semantics", () => {
  withTempDir((dir) => {
    for (const api of ["receipt", "boolean"]) {
      for (const phase of ["W0", "Wp"]) {
        const filePath = path.join(dir, `${api}-${phase}.txt`);
        const winner = createWinner(filePath, `${api}-${phase}`);
        const content = `candidate ${api}-${phase}\n`;
        const run = runStringWriteFault({
          failedFile: filePath,
          phase,
          operation: api === "receipt"
            ? () => writeFileExclusiveAtomicReceipt(filePath, content)
            : () => writeFileExclusiveAtomic(filePath, content),
        });

        if (api === "receipt") {
          assertFailedWriteReceipt(run);
        } else {
          assert.equal(run.result, undefined);
          assert.equal(run.thrown, run.primary);
          assert.equal(run.thrown.name, "Error");
          assert.equal(run.thrown.code, "EIO");
          assert.notEqual(run.thrown instanceof TypeError, true);
          assert.equal(Object.hasOwn(run.thrown, "exclusiveReceipt"), false);
        }
        assertStringFaultCommon(run);
        assertExactRegular(filePath, winner.stats, winner.bytes);
        assert.deepEqual(tempPathsFor(filePath), []);
      }
    }
  });
});

test("Wp replacement preserves both the owned prefix inode and replacement temp", () => {
  withTempDir((dir) => {
    const filePath = path.join(dir, "replacement.txt");
    const run = runStringWriteFault({
      failedFile: filePath,
      phase: "Wp",
      replaceTemp: true,
      operation: () => writeFileExclusiveAtomicReceipt(filePath, "owned prefix then failure\n"),
    });

    assertFailedWriteReceipt(run);
    assertStringFaultCommon(run);
    assert.equal(fs.existsSync(filePath), false);
    assert.equal(run.movedStats.dev, run.tracker.selected.stats.dev);
    assert.equal(run.movedStats.ino, run.tracker.selected.stats.ino);
    assert.notEqual(
      run.replacementStats.dev === run.tracker.selected.stats.dev
        && run.replacementStats.ino === run.tracker.selected.stats.ino,
      true,
    );
    assertExactRegular(run.movedPath, run.tracker.selected.stats, run.prefixBytes);
    assertExactRegular(run.tracker.selected.path, run.replacementStats, run.sentinelBytes);
    assert.deepEqual(tempPathsFor(filePath), [run.tracker.selected.path]);
    removeExactRegular(run.movedPath, run.tracker.selected.stats);
    removeExactRegular(run.tracker.selected.path, run.replacementStats);
    assert.deepEqual(tempPathsFor(filePath), []);
  });
});

test("fresh authority W0/Wp failures roll back state, nucleus, and events", () => {
  withTempHome(() => {
    for (const phase of ["W0", "Wp"]) {
      for (const [failedIndex, member] of MEMBERS.entries()) {
        const domain = `a2w-${phase.toLowerCase()}-${member.key}.example.com`;
        const table = publications(domain);
        const run = runStringWriteFault({
          failedFile: member.pathFor(domain),
          publicationFiles: table.map((publication) => publication.path),
          phase,
          operation: () => commitState(domain),
        });

        assert.equal(run.result, undefined);
        assert.equal(run.thrown, run.primary);
        assert.equal(run.thrown.code, "EIO");
        assert.notEqual(run.thrown instanceof TypeError, true);
        assertStringFaultCommon(run);
        assertPublicationProgress(run, table, failedIndex);
        assertAuthorityAbsent(domain);
        assert.deepEqual(authorityTemps(domain), []);
        assertCoherentRetry(domain);
      }
    }
  });
});
