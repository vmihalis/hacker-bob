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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-post-publish-"));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-authority-post-publish-"));
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

function removeExactRegular(filePath, identity, bytes) {
  assertExactRegular(filePath, identity, bytes);
  fs.unlinkSync(filePath);
}

function assertDescriptorClosed(descriptor) {
  assert.throws(
    () => fs.fstatSync(descriptor),
    (error) => error && error.code === "EBADF",
  );
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

function runPostPublishFault({
  fault,
  failedFile,
  operation,
  publicationFiles = [failedFile],
  replaceFinal = false,
}) {
  const originals = {
    openSync: fs.openSync,
    closeSync: fs.closeSync,
    fstatSync: fs.fstatSync,
    writeFileSync: fs.writeFileSync,
    readFileSync: fs.readFileSync,
    linkSync: fs.linkSync,
    lstatSync: fs.lstatSync,
    unlinkSync: fs.unlinkSync,
  };
  const primary = frozenEio(`A2G ${fault} primary`);
  const sentinelBytes = Buffer.from(`A2G ${fault} final replacement\n`, "utf8");
  const linkCounts = new Map(publicationFiles.map((filePath) => [filePath, 0]));
  const postLinkProbeCounts = new Map(publicationFiles.map((filePath) => [filePath, 0]));
  const activeFinals = new Set();
  let linked = false;
  let storageDone = false;
  let faultCount = 0;
  let finalProbeCount = 0;
  let tempUnlinkAttemptCount = 0;
  let tempUnlinkSuccessCount = 0;
  let stagedTemp = null;
  let stagedStats = null;
  let stagedBytes = null;
  let linkedFinalStats = null;
  let secondProofStats = null;
  let sentinelStats = null;
  let heldFinalDescriptor = null;
  let heldFinalStats = null;
  let heldFinalCloseCount = 0;
  let failedFinalUnlinkAttemptCount = 0;
  let ownedFinalUnlinkAttemptCount = 0;
  let outsiderFinalUnlinkAttemptCount = 0;
  let unresolvedFinalUnlinkAttemptCount = 0;
  const failedFinalUnlinkObservations = [];
  let failedTempRollbackCount = 0;
  let result;
  let thrown = null;

  fs.linkSync = function patchedLink(source, destination) {
    let matchedPublication = null;
    for (const candidate of publicationFiles) {
      if (samePath(destination, candidate)) {
        linkCounts.set(candidate, linkCounts.get(candidate) + 1);
        matchedPublication = candidate;
        break;
      }
    }
    if (!linked && samePath(destination, failedFile)) {
      stagedTemp = source;
      stagedStats = originals.lstatSync.call(fs, source);
      stagedBytes = originals.readFileSync.call(fs, source);
      assert.equal(isTempFor(failedFile, source), true);
      assert.equal(stagedStats.isFile() && !stagedStats.isSymbolicLink(), true);
      originals.linkSync.call(fs, source, destination);
      linkedFinalStats = originals.lstatSync.call(fs, destination);
      assert.equal(linkedFinalStats.dev, stagedStats.dev);
      assert.equal(linkedFinalStats.ino, stagedStats.ino);
      assert.equal(linkedFinalStats.nlink, 2);
      linked = true;
      activeFinals.add(failedFile);
      return undefined;
    }
    const result = originals.linkSync.call(fs, source, destination);
    if (matchedPublication !== null) activeFinals.add(matchedPublication);
    return result;
  };
  fs.lstatSync = function patchedLstat(target) {
    const activeFinal = [...activeFinals].find((filePath) => samePath(target, filePath));
    if (activeFinal !== undefined) {
      postLinkProbeCounts.set(activeFinal, postLinkProbeCounts.get(activeFinal) + 1);
    }
    if (activeFinal !== undefined && samePath(activeFinal, failedFile) && !storageDone) {
      finalProbeCount += 1;
      const current = originals.lstatSync.call(fs, target);
      assert.equal(current.isFile() && !current.isSymbolicLink(), true);
      assert.equal(current.dev, stagedStats.dev);
      assert.equal(current.ino, stagedStats.ino);
      if (finalProbeCount === 1) {
        assert.equal(current.nlink, 2);
        return current;
      }
      assert.equal(finalProbeCount, 2);
      assert.equal(fault, "final_proof");
      assert.equal(current.nlink, 1);
      secondProofStats = current;
      if (replaceFinal) {
        heldFinalDescriptor = originals.openSync.call(
          fs,
          target,
          fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
        );
        try {
          heldFinalStats = originals.fstatSync.call(fs, heldFinalDescriptor);
          assert.equal(heldFinalStats.dev, stagedStats.dev);
          assert.equal(heldFinalStats.ino, stagedStats.ino);
          originals.unlinkSync.call(fs, target);
          sentinelStats = plantExclusive(originals, target, sentinelBytes);
          assert.notEqual(
            sentinelStats.dev === stagedStats.dev && sentinelStats.ino === stagedStats.ino,
            true,
          );
          const heldAfterReplacement = originals.fstatSync.call(fs, heldFinalDescriptor);
          assert.equal(heldAfterReplacement.dev, stagedStats.dev);
          assert.equal(heldAfterReplacement.ino, stagedStats.ino);
        } finally {
          originals.closeSync.call(fs, heldFinalDescriptor);
          heldFinalCloseCount += 1;
        }
      }
      faultCount += 1;
      storageDone = true;
      activeFinals.delete(activeFinal);
      throw primary;
    }
    const current = originals.lstatSync.call(fs, target);
    if (activeFinal !== undefined && postLinkProbeCounts.get(activeFinal) === 2) {
      activeFinals.delete(activeFinal);
    }
    return current;
  };
  fs.unlinkSync = function patchedUnlink(target) {
    if (linked && !storageDone && stagedTemp !== null && samePath(target, stagedTemp)) {
      tempUnlinkAttemptCount += 1;
      const current = originals.lstatSync.call(fs, target);
      assert.equal(current.isFile() && !current.isSymbolicLink(), true);
      assert.equal(current.dev, stagedStats.dev);
      assert.equal(current.ino, stagedStats.ino);
      if (fault === "temp_cleanup") {
        assert.equal(tempUnlinkAttemptCount, 1);
        faultCount += 1;
        storageDone = true;
        activeFinals.delete(failedFile);
        throw primary;
      }
      const unlinked = originals.unlinkSync.call(fs, target);
      tempUnlinkSuccessCount += 1;
      return unlinked;
    }
    if (storageDone && samePath(target, failedFile)) {
      failedFinalUnlinkAttemptCount += 1;
      let current = null;
      try {
        current = originals.lstatSync.call(fs, target);
        failedFinalUnlinkObservations.push({
          dev: current.dev,
          ino: current.ino,
          type: current.isSymbolicLink()
            ? "symlink"
            : current.isFile()
              ? "file"
              : current.isDirectory()
                ? "directory"
                : "other",
        });
      } catch (error) {
        unresolvedFinalUnlinkAttemptCount += 1;
        failedFinalUnlinkObservations.push({ error });
      }
      if (current && current.dev === stagedStats.dev && current.ino === stagedStats.ino) {
        ownedFinalUnlinkAttemptCount += 1;
      } else if (current) {
        outsiderFinalUnlinkAttemptCount += 1;
      }
    }
    if (storageDone && stagedTemp !== null && samePath(target, stagedTemp)) {
      const current = originals.lstatSync.call(fs, target);
      assert.equal(current.dev, stagedStats.dev);
      assert.equal(current.ino, stagedStats.ino);
      failedTempRollbackCount += 1;
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
    fault,
    result,
    thrown,
    primary,
    sentinelBytes,
    sentinelStats,
    heldFinalDescriptor,
    heldFinalStats,
    heldFinalCloseCount,
    linkCounts,
    postLinkProbeCounts,
    linked,
    storageDone,
    faultCount,
    finalProbeCount,
    tempUnlinkAttemptCount,
    tempUnlinkSuccessCount,
    stagedTemp,
    stagedStats,
    stagedBytes,
    linkedFinalStats,
    secondProofStats,
    failedFinalUnlinkAttemptCount,
    ownedFinalUnlinkAttemptCount,
    outsiderFinalUnlinkAttemptCount,
    unresolvedFinalUnlinkAttemptCount,
    failedFinalUnlinkObservations,
    failedTempRollbackCount,
  };
}

function assertCandidate(candidate, expectedPath, identity, nlink) {
  assert.equal(candidate.path, expectedPath);
  assert.equal(candidate.dev, identity.dev);
  assert.equal(candidate.ino, identity.ino);
  assert.equal(candidate.type, "file");
  assert.equal(candidate.owned, true);
  assert.equal(candidate.nlink, nlink);
  assert.equal(candidate.size, identity.size);
}

function assertReceipt(run, filePath) {
  const receipt = run.result;
  assert.equal(run.thrown, null);
  assert.equal(run.linked, true);
  assert.equal(run.storageDone, true);
  assert.equal(run.faultCount, 1);
  assert.equal(receipt.status, "failed");
  assert.equal(receipt.phase, run.fault);
  assert.equal(receipt.path, filePath);
  assert.equal(receipt.tempPath, run.stagedTemp);
  assert.equal(receipt.error, run.primary);
  assertCandidate(receipt.tempCandidate, run.stagedTemp, run.stagedStats, 1);
  assertCandidate(receipt.finalCandidate, filePath, run.linkedFinalStats, 2);
  assert.equal(receipt.probeError, undefined);
  assert.equal(receipt.closeError, undefined);
  assert.equal(receipt.unresolvedTemp, undefined);
  if (run.fault === "temp_cleanup") {
    assert.equal(receipt.cleanupError, run.primary);
  } else {
    assert.equal(receipt.cleanupError, undefined);
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
      source: { component: "session-authority-post-publish-guard.test" },
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
    assert.equal(
      run.postLinkProbeCounts.get(publication.path),
      index < failedIndex ? 2 : index === failedIndex
        ? run.fault === "temp_cleanup" ? 1 : 2
        : 0,
      `${publication.label} post-link proof progress`,
    );
  }
}

test("exclusive receipts distinguish temp cleanup from the second final proof", () => {
  withTempDir((dir) => {
    for (const fault of ["temp_cleanup", "final_proof"]) {
      const filePath = path.join(dir, `${fault}.txt`);
      const content = `A2G ${fault} candidate\n`;
      const bytes = Buffer.from(content, "utf8");
      const run = runPostPublishFault({
        fault,
        failedFile: filePath,
        operation: () => writeFileExclusiveAtomicReceipt(filePath, content),
      });

      assert.equal(run.linkCounts.get(filePath), 1);
      assertReceipt(run, filePath);
      assert.equal(run.finalProbeCount, fault === "temp_cleanup" ? 1 : 2);
      assert.equal(run.postLinkProbeCounts.get(filePath), run.finalProbeCount);
      assert.equal(run.tempUnlinkAttemptCount, 1);
      assert.equal(Buffer.compare(run.stagedBytes, bytes), 0);
      assert.equal(Object.isFrozen(run.primary), true);
      if (fault === "temp_cleanup") {
        assert.equal(run.tempUnlinkSuccessCount, 0);
        const liveFinal = assertExactRegular(filePath, run.linkedFinalStats, bytes);
        const liveTemp = assertExactRegular(run.stagedTemp, run.stagedStats, bytes);
        assert.equal(liveFinal.nlink, 2);
        assert.equal(liveTemp.nlink, 2);
        removeExactRegular(filePath, run.linkedFinalStats, bytes);
        removeExactRegular(run.stagedTemp, run.stagedStats, bytes);
      } else {
        assert.equal(run.tempUnlinkSuccessCount, 1);
        assert.equal(run.secondProofStats.nlink, 1);
        assert.equal(fs.existsSync(run.stagedTemp), false);
        const liveFinal = assertExactRegular(filePath, run.linkedFinalStats, bytes);
        assert.equal(liveFinal.nlink, 1);
        removeExactRegular(filePath, run.linkedFinalStats, bytes);
      }
      assert.deepEqual(tempPathsFor(filePath), []);
    }
  });
});

test("fresh authority post-publish failures roll back all members and retry", () => {
  withTempHome(() => {
    for (const fault of ["temp_cleanup", "final_proof"]) {
      for (const [failedIndex, member] of MEMBERS.entries()) {
        const domain = `a2g-${fault.replace("_", "-")}-${member.key}.example.com`;
        const table = publications(domain);
        const run = runPostPublishFault({
          fault,
          failedFile: member.pathFor(domain),
          publicationFiles: table.map((publication) => publication.path),
          operation: () => commitState(domain),
        });

        assert.equal(run.thrown, run.primary);
        assert.equal(run.thrown.code, "EIO");
        assert.notEqual(run.thrown instanceof TypeError, true);
        assert.equal(run.thrown.rollback_error, undefined);
        assert.equal(Object.hasOwn(run.thrown, "exclusive_receipt"), false);
        assert.equal(Object.hasOwn(run.thrown, "cleanup_error"), false);
        assertPublicationCounts(run, table, failedIndex);
        assert.equal(run.faultCount, 1);
        assert.equal(run.finalProbeCount, fault === "temp_cleanup" ? 1 : 2);
        assert.equal(run.tempUnlinkAttemptCount, 1);
        assert.equal(run.failedFinalUnlinkAttemptCount, 1);
        assert.equal(run.ownedFinalUnlinkAttemptCount, 1);
        assert.equal(run.outsiderFinalUnlinkAttemptCount, 0);
        assert.equal(run.unresolvedFinalUnlinkAttemptCount, 0);
        assert.deepEqual(run.failedFinalUnlinkObservations, [{
          dev: run.stagedStats.dev,
          ino: run.stagedStats.ino,
          type: "file",
        }]);
        assert.equal(run.failedTempRollbackCount, fault === "temp_cleanup" ? 1 : 0);
        assertAuthorityAbsent(domain);
        assert.deepEqual(authorityTemps(domain), []);
        assertCoherentRetry(domain);
      }
    }
  });
});

test("second final proof replacement preserves an outsider at every member", () => {
  withTempHome(() => {
    for (const [failedIndex, member] of MEMBERS.entries()) {
      const domain = `a2g-final-replacement-${member.key}.example.com`;
      const table = publications(domain);
      const failedFile = member.pathFor(domain);
      const run = runPostPublishFault({
        fault: "final_proof",
        failedFile,
        publicationFiles: table.map((publication) => publication.path),
        replaceFinal: true,
        operation: () => commitState(domain),
      });

      assert.equal(run.thrown, run.primary);
      assert.equal(run.thrown.code, "EIO");
      assert.notEqual(run.thrown instanceof TypeError, true);
      assert.equal(run.thrown.rollback_error, undefined);
      assert.equal(Object.hasOwn(run.thrown, "exclusive_receipt"), false);
      assertPublicationCounts(run, table, failedIndex);
      assert.equal(run.faultCount, 1);
      assert.equal(run.finalProbeCount, 2);
      assert.equal(run.tempUnlinkAttemptCount, 1);
      assert.equal(run.tempUnlinkSuccessCount, 1);
      assert.equal(run.failedFinalUnlinkAttemptCount, 0);
      assert.equal(run.ownedFinalUnlinkAttemptCount, 0);
      assert.equal(run.outsiderFinalUnlinkAttemptCount, 0);
      assert.equal(run.unresolvedFinalUnlinkAttemptCount, 0);
      assert.deepEqual(run.failedFinalUnlinkObservations, []);
      assert.equal(run.failedTempRollbackCount, 0);
      assert.equal(run.heldFinalCloseCount, 1);
      assert.equal(run.heldFinalStats.dev, run.stagedStats.dev);
      assert.equal(run.heldFinalStats.ino, run.stagedStats.ino);
      assertDescriptorClosed(run.heldFinalDescriptor);
      const liveSentinel = assertExactRegular(failedFile, run.sentinelStats, run.sentinelBytes);
      assert.equal(liveSentinel.nlink, 1);
      for (const publication of table) {
        if (publication.path !== failedFile) {
          assert.equal(fs.existsSync(publication.path), false, `${publication.label} must be absent`);
        }
      }
      assert.deepEqual(authorityTemps(domain), []);
      removeExactRegular(failedFile, run.sentinelStats, run.sentinelBytes);
      assertAuthorityAbsent(domain);
      assertCoherentRetry(domain);
    }
  });
});
