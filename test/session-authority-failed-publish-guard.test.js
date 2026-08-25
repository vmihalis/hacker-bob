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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-failed-publish-"));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-authority-failed-publish-"));
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

function frozenError(message, code) {
  const error = new Error(message);
  error.code = code;
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

function removeExactRegular(filePath, identity, bytes) {
  assertExactRegular(filePath, identity, bytes);
  fs.unlinkSync(filePath);
}

function plantExclusive(originals, filePath, bytes) {
  const descriptor = originals.openSync.call(
    fs,
    filePath,
    fs.constants.O_CREAT
      | fs.constants.O_EXCL
      | fs.constants.O_WRONLY
      | (fs.constants.O_NOFOLLOW || 0),
    0o600,
  );
  try {
    originals.writeFileSync.call(fs, descriptor, bytes);
  } finally {
    originals.closeSync.call(fs, descriptor);
  }
  return originals.lstatSync.call(fs, filePath);
}

function runCompoundFault({
  kind,
  failedFile,
  operation,
  publicationFiles = [failedFile],
  replaceTemp = false,
}) {
  const originals = {
    openSync: fs.openSync,
    closeSync: fs.closeSync,
    writeFileSync: fs.writeFileSync,
    readFileSync: fs.readFileSync,
    linkSync: fs.linkSync,
    lstatSync: fs.lstatSync,
    unlinkSync: fs.unlinkSync,
  };
  const primary = frozenError(
    `A2X ${kind} publish primary`,
    kind === "F" ? "EIO" : "EEXIST",
  );
  const probe = frozenError(`A2X ${kind} final probe`, "EIO");
  const cleanup = frozenError(`A2X ${kind} temp cleanup`, "EIO");
  const winnerBytes = Buffer.from(`A2X ${kind} collision winner\n`, "utf8");
  const replacementBytes = Buffer.from(`A2X ${kind} temp replacement\n`, "utf8");
  const linkCounts = new Map(publicationFiles.map((filePath) => [filePath, 0]));
  let armed = false;
  let probeCount = 0;
  let cleanupCount = 0;
  let stagedTemp = null;
  let stagedStats = null;
  let stagedBytes = null;
  let finalStats = null;
  let finalBytes = null;
  let winnerStats = null;
  let replacementStats = null;
  let failedFinalRollbackCount = 0;
  let failedTempRollbackCount = 0;
  let result;
  let thrown = null;

  fs.linkSync = function patchedLink(source, destination) {
    for (const publicationFile of publicationFiles) {
      if (samePath(destination, publicationFile)) {
        linkCounts.set(publicationFile, linkCounts.get(publicationFile) + 1);
      }
    }
    if (!armed && samePath(destination, failedFile)) {
      stagedTemp = source;
      stagedStats = originals.lstatSync.call(fs, source);
      stagedBytes = originals.readFileSync.call(fs, source);
      assert.equal(isTempFor(failedFile, source), true);
      assert.equal(stagedStats.isFile() && !stagedStats.isSymbolicLink(), true);
      if (kind === "F") {
        originals.linkSync.call(fs, source, destination);
        finalStats = originals.lstatSync.call(fs, destination);
        finalBytes = originals.readFileSync.call(fs, destination);
      } else {
        winnerStats = plantExclusive(originals, destination, winnerBytes);
      }
      armed = true;
      throw primary;
    }
    return originals.linkSync.call(fs, source, destination);
  };
  fs.lstatSync = function patchedLstat(target) {
    if (armed && probeCount === 0 && samePath(target, failedFile)) {
      const current = originals.lstatSync.call(fs, target);
      const expected = kind === "F" ? stagedStats : winnerStats;
      assert.equal(current.isFile() && !current.isSymbolicLink(), true);
      assert.equal(current.dev, expected.dev);
      assert.equal(current.ino, expected.ino);
      probeCount += 1;
      throw probe;
    }
    return originals.lstatSync.call(fs, target);
  };
  fs.unlinkSync = function patchedUnlink(target) {
    if (
      armed
      && probeCount === 1
      && cleanupCount === 0
      && stagedTemp !== null
      && samePath(target, stagedTemp)
    ) {
      const current = originals.lstatSync.call(fs, target);
      assert.equal(current.isFile() && !current.isSymbolicLink(), true);
      assert.equal(current.dev, stagedStats.dev);
      assert.equal(current.ino, stagedStats.ino);
      cleanupCount += 1;
      if (replaceTemp) {
        originals.unlinkSync.call(fs, target);
        replacementStats = plantExclusive(originals, target, replacementBytes);
        assert.notEqual(
          replacementStats.dev === stagedStats.dev && replacementStats.ino === stagedStats.ino,
          true,
        );
      }
      throw cleanup;
    }
    if (armed && cleanupCount === 1 && samePath(target, failedFile)) {
      const current = originals.lstatSync.call(fs, target);
      assert.equal(current.dev, stagedStats.dev);
      assert.equal(current.ino, stagedStats.ino);
      failedFinalRollbackCount += 1;
    }
    if (armed && cleanupCount === 1 && stagedTemp !== null && samePath(target, stagedTemp)) {
      const current = originals.lstatSync.call(fs, target);
      if (current.dev === stagedStats.dev && current.ino === stagedStats.ino) {
        failedTempRollbackCount += 1;
      }
    }
    return originals.unlinkSync.call(fs, target);
  };

  try {
    result = operation();
  } catch (error) {
    thrown = error;
  } finally {
    fs.linkSync = originals.linkSync;
    fs.lstatSync = originals.lstatSync;
    fs.unlinkSync = originals.unlinkSync;
  }

  return {
    kind,
    result,
    thrown,
    primary,
    probe,
    cleanup,
    linkCounts,
    armed,
    probeCount,
    cleanupCount,
    stagedTemp,
    stagedStats,
    stagedBytes,
    finalStats,
    finalBytes,
    winnerBytes,
    winnerStats,
    replacementBytes,
    replacementStats,
    failedFinalRollbackCount,
    failedTempRollbackCount,
  };
}

function assertReceiptTriple(run, receipt, failedFile) {
  assert.equal(run.armed, true);
  assert.equal(run.probeCount, 1);
  assert.equal(run.cleanupCount, 1);
  assert.equal(receipt.status, run.kind === "F" ? "failed" : "exists");
  assert.equal(receipt.phase, "link");
  assert.equal(receipt.path, failedFile);
  assert.equal(receipt.tempPath, run.stagedTemp);
  assert.equal(receipt.error, run.primary);
  assert.equal(receipt.probeError, run.probe);
  assert.equal(receipt.cleanupError, run.cleanup);
  assert.equal(receipt.finalCandidate, null);
  assert.equal(receipt.tempCandidate.path, run.stagedTemp);
  assert.equal(receipt.tempCandidate.dev, run.stagedStats.dev);
  assert.equal(receipt.tempCandidate.ino, run.stagedStats.ino);
  assert.equal(receipt.tempCandidate.type, "file");
  assert.equal(receipt.tempCandidate.owned, true);
  assert.equal(receipt.tempCandidate.nlink, run.stagedStats.nlink);
  assert.equal(receipt.tempCandidate.size, run.stagedStats.size);
  assert.equal(receipt.unresolvedTemp, undefined);
  assert.equal(receipt.closeError, undefined);
}

function assertAndRemovePrimitiveArtifacts(run, filePath, candidateBytes) {
  if (run.kind === "F") {
    assert.equal(run.finalStats.dev, run.stagedStats.dev);
    assert.equal(run.finalStats.ino, run.stagedStats.ino);
    assert.equal(run.finalStats.nlink, 2);
    assertExactRegular(filePath, run.finalStats, candidateBytes);
    assertExactRegular(run.stagedTemp, run.stagedStats, candidateBytes);
    removeExactRegular(filePath, run.finalStats, candidateBytes);
    removeExactRegular(run.stagedTemp, run.stagedStats, candidateBytes);
  } else {
    assert.notEqual(
      run.winnerStats.dev === run.stagedStats.dev && run.winnerStats.ino === run.stagedStats.ino,
      true,
    );
    assertExactRegular(filePath, run.winnerStats, run.winnerBytes);
    assertExactRegular(run.stagedTemp, run.stagedStats, candidateBytes);
    removeExactRegular(filePath, run.winnerStats, run.winnerBytes);
    removeExactRegular(run.stagedTemp, run.stagedStats, candidateBytes);
  }
  assert.deepEqual(tempPathsFor(filePath), []);
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
      source: { component: "session-authority-failed-publish-guard.test" },
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

function assertPublicationCounts(run, table, failedIndex) {
  for (const [index, publication] of table.entries()) {
    assert.equal(
      run.linkCounts.get(publication.path),
      index <= failedIndex ? 1 : 0,
      `${publication.label} link progress`,
    );
  }
}

test("exclusive receipt and boolean APIs preserve compound failure precedence", () => {
  withTempDir((dir) => {
    for (const api of ["receipt", "boolean"]) {
      for (const kind of ["F", "C"]) {
        const filePath = path.join(dir, `${api}-${kind}.txt`);
        const content = `A2X ${api} ${kind} candidate\n`;
        const candidateBytes = Buffer.from(content, "utf8");
        const run = runCompoundFault({
          kind,
          failedFile: filePath,
          operation: api === "receipt"
            ? () => writeFileExclusiveAtomicReceipt(filePath, content)
            : () => writeFileExclusiveAtomic(filePath, content),
        });

        assert.equal(run.linkCounts.get(filePath), 1);
        assert.equal(run.probeCount, 1);
        assert.equal(run.cleanupCount, 1);
        if (api === "receipt") {
          assert.equal(run.thrown, null);
          assertReceiptTriple(run, run.result, filePath);
        } else if (kind === "F") {
          assert.equal(run.result, undefined);
          assert.equal(run.thrown, run.primary);
          assert.equal(run.thrown.code, "EIO");
          assert.notEqual(run.thrown instanceof TypeError, true);
          assert.equal(Object.hasOwn(run.thrown, "exclusiveReceipt"), false);
          assert.equal(Object.hasOwn(run.thrown, "probeError"), false);
          assert.equal(Object.hasOwn(run.thrown, "cleanupError"), false);
        } else {
          assert.equal(run.thrown, null);
          assert.equal(run.result, false);
        }
        assertAndRemovePrimitiveArtifacts(run, filePath, candidateBytes);
      }
    }
  });
});

test("fresh authority F/C failures roll back or preserve all three publication members", () => {
  withTempHome(() => {
    for (const kind of ["F", "C"]) {
      for (const [failedIndex, member] of MEMBERS.entries()) {
        const domain = `a2x-${kind.toLowerCase()}-${member.key}.example.com`;
        const table = publications(domain);
        const run = runCompoundFault({
          kind,
          failedFile: member.pathFor(domain),
          publicationFiles: table.map((publication) => publication.path),
          operation: () => commitState(domain),
        });

        assertPublicationCounts(run, table, failedIndex);
        assert.equal(run.probeCount, 1);
        assert.equal(run.cleanupCount, 1);
        if (kind === "F") {
          assert.equal(run.thrown, run.primary);
          assert.equal(run.thrown.code, "EIO");
          assert.notEqual(run.thrown instanceof TypeError, true);
          assert.equal(run.thrown.rollback_error, undefined);
          assert.equal(run.finalStats.dev, run.stagedStats.dev);
          assert.equal(run.finalStats.ino, run.stagedStats.ino);
          assert.equal(run.finalStats.nlink, 2);
          assert.equal(Buffer.compare(run.finalBytes, run.stagedBytes), 0);
          assert.equal(run.failedFinalRollbackCount, 1);
          assert.equal(run.failedTempRollbackCount, 1);
          assertAuthorityAbsent(domain);
        } else {
          assert.ok(run.thrown);
          assert.notEqual(run.thrown, run.primary);
          assert.equal(run.thrown.message, `${member.label} already exists`);
          assert.equal(run.thrown.probe_error, run.probe.message);
          assert.equal(run.thrown.cleanup_error, run.cleanup.message);
          assert.equal(run.thrown.rollback_error, undefined);
          assert.equal(run.thrown.exclusive_receipt.label, member.label);
          assert.equal(run.thrown.exclusive_receipt.status, "exists");
          assert.equal(run.thrown.exclusive_receipt.phase, "link");
          assert.equal(run.thrown.exclusive_receipt.path, member.pathFor(domain));
          assert.equal(run.thrown.exclusive_receipt.tempPath, run.stagedTemp);
          assert.equal(run.thrown.exclusive_receipt.finalCandidate, null);
          assert.equal(run.thrown.exclusive_receipt.tempCandidate.dev, run.stagedStats.dev);
          assert.equal(run.thrown.exclusive_receipt.tempCandidate.ino, run.stagedStats.ino);
          assert.equal(run.failedFinalRollbackCount, 0);
          assert.equal(run.failedTempRollbackCount, 1);
          assertExactRegular(member.pathFor(domain), run.winnerStats, run.winnerBytes);
          for (const publication of table) {
            if (publication.path !== member.pathFor(domain)) {
              assert.equal(fs.existsSync(publication.path), false, `${publication.label} must be absent`);
            }
          }
        }
        assert.deepEqual(authorityTemps(domain), []);
        if (kind === "C") {
          removeExactRegular(member.pathFor(domain), run.winnerStats, run.winnerBytes);
          assertAuthorityAbsent(domain);
        }
        assertCoherentRetry(domain);
      }
    }
  });
});

test("F cleanup replacement removes the owned final but preserves the new temp inode", () => {
  withTempHome(() => {
    for (const [failedIndex, member] of MEMBERS.entries()) {
      const domain = `a2x-replacement-${member.key}.example.com`;
      const table = publications(domain);
      const run = runCompoundFault({
        kind: "F",
        failedFile: member.pathFor(domain),
        publicationFiles: table.map((publication) => publication.path),
        replaceTemp: true,
        operation: () => commitState(domain),
      });

      assert.equal(run.thrown, run.primary);
      assert.equal(run.thrown.rollback_error, undefined);
      assertPublicationCounts(run, table, failedIndex);
      assert.equal(run.probeCount, 1);
      assert.equal(run.cleanupCount, 1);
      assert.equal(run.failedFinalRollbackCount, 1);
      assert.equal(run.failedTempRollbackCount, 0);
      assert.equal(Buffer.compare(run.finalBytes, run.stagedBytes), 0);
      assertAuthorityAbsent(domain);
      assert.deepEqual(authorityTemps(domain), [run.stagedTemp]);
      assertExactRegular(run.stagedTemp, run.replacementStats, run.replacementBytes);
      removeExactRegular(run.stagedTemp, run.replacementStats, run.replacementBytes);
      assert.deepEqual(authorityTemps(domain), []);
      assertCoherentRetry(domain);
    }
  });
});
