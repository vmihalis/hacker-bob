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

const FAULTS = Object.freeze([
  { key: "mkdir", code: "EACCES", phase: "mkdir" },
  { key: "open-before", code: "EIO", phase: "temp_open" },
  { key: "open-after", code: "EIO", phase: "temp_open" },
]);

function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-exclusive-precondition-"));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-authority-precondition-"));
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

function frozenFailure(code, message) {
  const error = new Error(message);
  error.code = code;
  return Object.freeze(error);
}

function snapshot(filePath) {
  const stats = fs.lstatSync(filePath);
  assert.equal(stats.isFile() && !stats.isSymbolicLink(), true);
  return { path: filePath, stats, bytes: fs.readFileSync(filePath) };
}

function assertExactFile(filePath, identity, bytes) {
  const stats = fs.lstatSync(filePath);
  assert.equal(stats.isFile() && !stats.isSymbolicLink(), true);
  assert.equal(stats.dev, identity.dev);
  assert.equal(stats.ino, identity.ino);
  assert.equal(Buffer.compare(fs.readFileSync(filePath), bytes), 0);
  return stats;
}

function assertSnapshotPreserved(expected) {
  assertExactFile(expected.path, expected.stats, expected.bytes);
}

function removeExactFile(filePath, identity) {
  const stats = fs.lstatSync(filePath);
  assert.equal(stats.isFile() && !stats.isSymbolicLink(), true);
  assert.equal(stats.dev, identity.dev);
  assert.equal(stats.ino, identity.ino);
  fs.unlinkSync(filePath);
}

function storageTemps(finalPath) {
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
      source: { component: "storage-exclusive-precondition-guard.test" },
    },
    expectedNucleusHash: null,
  });
}

function authorityPublications(domain) {
  return MEMBERS.map((member) => ({ ...member, path: member.pathFor(domain) }));
}

function authorityTemps(domain) {
  const publications = authorityPublications(domain);
  const directories = new Set(publications.map((publication) => path.dirname(publication.path)));
  const temps = new Set();
  for (const directory of directories) {
    if (!fs.existsSync(directory)) continue;
    for (const name of fs.readdirSync(directory)) {
      const candidate = path.join(directory, name);
      if (publications.some((publication) => isTempFor(publication.path, candidate))) {
        temps.add(candidate);
      }
    }
  }
  return [...temps].sort();
}

function assertAuthorityAbsent(domain) {
  for (const publication of authorityPublications(domain)) {
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

function runPrimitiveCell(fault, api) {
  withTempDir((dir) => {
    const parent = path.join(dir, `${fault.key}-${api}`);
    const finalPath = path.join(parent, "authority.txt");
    fs.mkdirSync(parent);
    fs.writeFileSync(finalPath, "winner bytes\n", "utf8");
    const winner = snapshot(finalPath);
    const primary = frozenFailure(fault.code, `${fault.key} ${api} primary`);
    const originals = {};
    const methods = [
      "mkdirSync",
      "openSync",
      "fstatSync",
      "writeFileSync",
      "closeSync",
      "lstatSync",
      "linkSync",
      "unlinkSync",
      "renameSync",
    ];
    for (const method of methods) originals[method] = fs[method];
    const calls = {
      mkdir: 0,
      open: 0,
      fstat: 0,
      write: 0,
      close: 0,
      lstat: 0,
      link: 0,
      unlink: 0,
    };
    const sentinelBytes = Buffer.from(`${fault.key} unresolved replacement\n`, "utf8");
    let receipt = null;
    let thrown = null;
    let tempPath = null;
    let opened = null;
    let openedAside = null;
    let replacement = null;
    let openFlags = null;

    fs.mkdirSync = function patchedMkdir(target, options) {
      calls.mkdir += 1;
      if (fault.key === "mkdir" && samePath(target, parent)) throw primary;
      return originals.mkdirSync.call(fs, target, options);
    };
    fs.openSync = function patchedOpen(target, flags, mode) {
      calls.open += 1;
      if (fault.key !== "mkdir" && isTempFor(finalPath, target)) {
        tempPath = target;
        openFlags = flags;
        if (fault.key === "open-before") throw primary;
        const descriptor = originals.openSync.call(fs, target, flags, mode);
        opened = originals.fstatSync.call(fs, descriptor);
        originals.closeSync.call(fs, descriptor);
        openedAside = `${target}.opened`;
        originals.renameSync.call(fs, target, openedAside);
        const replacementDescriptor = originals.openSync.call(
          fs,
          target,
          fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY,
          0o600,
        );
        try {
          originals.writeFileSync.call(fs, replacementDescriptor, sentinelBytes);
        } finally {
          originals.closeSync.call(fs, replacementDescriptor);
        }
        replacement = originals.lstatSync.call(fs, target);
        throw primary;
      }
      return originals.openSync.call(fs, target, flags, mode);
    };
    for (const [method, key] of [
      ["fstatSync", "fstat"],
      ["writeFileSync", "write"],
      ["closeSync", "close"],
      ["lstatSync", "lstat"],
      ["linkSync", "link"],
      ["unlinkSync", "unlink"],
    ]) {
      fs[method] = function countedCall(...args) {
        calls[key] += 1;
        return originals[method].apply(fs, args);
      };
    }

    try {
      if (api === "receipt") {
        receipt = writeFileExclusiveAtomicReceipt(finalPath, "replacement");
      } else {
        try {
          writeFileExclusiveAtomic(finalPath, "replacement");
        } catch (error) {
          thrown = error;
        }
      }
    } finally {
      for (const method of methods) fs[method] = originals[method];
    }

    assert.equal(Object.isFrozen(primary), true);
    assert.equal(calls.mkdir, 1);
    assert.equal(calls.open, fault.key === "mkdir" ? 0 : 1, `${fault.key}/${api} open call count`);
    for (const key of ["fstat", "write", "close", "lstat", "link", "unlink"]) {
      assert.equal(calls[key], 0, `${fault.key}/${api} must make zero later ${key} calls`);
    }
    if (api === "receipt") {
      assert.equal(receipt.status, "failed");
      assert.equal(receipt.phase, fault.phase);
      assert.equal(receipt.error, primary);
      assert.equal(receipt.path, finalPath);
      assert.equal(receipt.tempCandidate, null);
      assert.equal(receipt.finalCandidate, null);
      if (fault.key === "mkdir") {
        assert.equal(receipt.tempPath, null);
        assert.equal(receipt.unresolvedTemp, undefined);
      } else {
        assert.equal(receipt.tempPath, tempPath);
        assert.deepEqual(receipt.unresolvedTemp, {
          path: tempPath,
          reason: "temp_open_failed",
        });
      }
    } else {
      assert.equal(thrown, primary);
      assert.equal(thrown.name, "Error");
      assert.equal(thrown.code, fault.code);
      assert.equal(thrown.exclusiveReceipt, undefined);
    }
    assertSnapshotPreserved(winner);

    if (fault.key === "mkdir") {
      assert.deepEqual(storageTemps(finalPath), []);
    } else {
      assert.ok(tempPath);
      assert.notEqual(openFlags & fs.constants.O_EXCL, 0);
      assert.equal(openFlags & fs.constants.O_CREAT, fs.constants.O_CREAT);
      if (fault.key === "open-before") {
        assert.equal(fs.existsSync(tempPath), false);
        assert.deepEqual(storageTemps(finalPath), []);
      } else {
        assert.equal(opened.isFile(), true);
        assert.equal(opened.nlink, 1);
        assert.equal(opened.size, 0);
        assert.notEqual(opened.dev === replacement.dev && opened.ino === replacement.ino, true);
        assertExactFile(openedAside, opened, Buffer.alloc(0));
        assertExactFile(tempPath, replacement, sentinelBytes);
        assert.deepEqual(storageTemps(finalPath), [tempPath]);
        removeExactFile(openedAside, opened);
        removeExactFile(tempPath, replacement);
      }
    }
    removeExactFile(finalPath, winner.stats);
    assert.deepEqual(storageTemps(finalPath), []);
  });
}

function runUowCell(member, fault) {
  withTempHome(() => {
    const domain = `a2d-${member.key}-${fault.key}.example.com`;
    const directory = sessionDir(domain);
    const failedPath = member.pathFor(domain);
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const primary = frozenFailure(fault.code, `${member.key} ${fault.key} primary`);
    const realMkdirSync = fs.mkdirSync;
    const realOpenSync = fs.openSync;
    const realFstatSync = fs.fstatSync;
    const realCloseSync = fs.closeSync;
    let publicationOrdinal = 0;
    let injected = false;
    let tempPath = null;
    let tempIdentity = null;
    let thrown = null;

    fs.mkdirSync = function injectedMkdir(target, options) {
      if (fault.key === "mkdir" && samePath(target, directory)) {
        publicationOrdinal += 1;
        if (publicationOrdinal === MEMBERS.indexOf(member) + 1) {
          injected = true;
          throw primary;
        }
      }
      return realMkdirSync.call(fs, target, options);
    };
    fs.openSync = function injectedOpen(target, flags, mode) {
      if (fault.key !== "mkdir" && isTempFor(failedPath, target)) {
        assert.notEqual(path.basename(target), ".session.lock");
        injected = true;
        tempPath = target;
        if (fault.key === "open-before") throw primary;
        const descriptor = realOpenSync.call(fs, target, flags, mode);
        tempIdentity = realFstatSync.call(fs, descriptor);
        realCloseSync.call(fs, descriptor);
        throw primary;
      }
      return realOpenSync.call(fs, target, flags, mode);
    };
    try {
      commitState(domain);
    } catch (error) {
      thrown = error;
    } finally {
      fs.mkdirSync = realMkdirSync;
      fs.openSync = realOpenSync;
    }

    assert.equal(injected, true);
    assert.equal(thrown, primary);
    assert.equal(thrown.code, fault.code);
    assert.equal(thrown.exclusive_receipt, undefined);
    if (fault.key === "mkdir") {
      assert.equal(publicationOrdinal, MEMBERS.indexOf(member) + 1);
      assert.equal(tempPath, null);
    } else {
      assert.ok(tempPath);
      assert.equal(isTempFor(failedPath, tempPath), true);
    }
    assertAuthorityAbsent(domain);
    if (fault.key === "open-after") {
      assert.equal(tempIdentity.isFile() && !tempIdentity.isSymbolicLink(), true);
      assert.equal(tempIdentity.nlink, 1);
      assert.equal(tempIdentity.size, 0);
      assertExactFile(tempPath, tempIdentity, Buffer.alloc(0));
      assert.deepEqual(authorityTemps(domain), [tempPath]);
      removeExactFile(tempPath, tempIdentity);
    } else {
      assert.deepEqual(authorityTemps(domain), []);
      if (tempPath) assert.equal(fs.existsSync(tempPath), false);
    }
    assertCoherentRetry(domain);
  });
}

test("exclusive pre-open failures return total receipts and preserve frozen wrapper primaries", () => {
  for (const fault of FAULTS) {
    for (const api of ["receipt", "wrapper"]) runPrimitiveCell(fault, api);
  }
});

test("commitSessionAuthority pre-open failures roll back every 3x3 publication cell and retry", () => {
  for (const fault of FAULTS) {
    for (const member of MEMBERS) runUowCell(member, fault);
  }
});
