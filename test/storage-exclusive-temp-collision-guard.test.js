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
} = require("../mcp/core/io/storage.js");
const {
  sessionNucleusFromState,
} = require("../mcp/core/governance/index.js");
const {
  commitSessionAuthority,
} = require("../mcp/core/session/session-authority-unit-of-work.js");
const {
  buildInitialSessionState,
} = require("../mcp/core/session/session-state-contracts.js");
const {
  readSessionEvents,
} = require("../mcp/core/session/session-events.js");
const {
  readVerifiedSessionNucleus,
} = require("../mcp/core/governance/index.js");
const {
  readSessionStateStrict,
} = require("../mcp/core/session/session-state-store.js");

const FIXED_NOW = 1900000000000;
const FIXED_RANDOM = 0.5;
const FIXED_RANDOM_FRAGMENT = FIXED_RANDOM.toString(16).slice(2);

const DEFAULT_EGRESS_PROFILE = Object.freeze({
  name: "default",
  region: null,
  proxy_configured: false,
  egress_profile_identity_hash: null,
  egress_profile_identity_version: null,
  egress_profile_identity_source: null,
});

function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-temp-collision-"));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-authority-temp-collision-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function withFixedSiblingTempNames(fn) {
  const realNow = Date.now;
  const realRandom = Math.random;
  Date.now = () => FIXED_NOW;
  Math.random = () => FIXED_RANDOM;
  try {
    return fn();
  } finally {
    Date.now = realNow;
    Math.random = realRandom;
  }
}

function fixedSiblingTempPath(filePath) {
  return path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.${process.pid}.${FIXED_NOW}.${FIXED_RANDOM_FRAGMENT}.tmp`,
  );
}

function isSamePath(left, right) {
  return path.resolve(left) === path.resolve(right);
}

function patchOpenCollision(tempPath, mutateError, fn) {
  const realOpenSync = fs.openSync;
  let primary = null;
  fs.openSync = function patchedOpenSync(target, flags, mode) {
    try {
      return realOpenSync.call(fs, target, flags, mode);
    } catch (error) {
      if (isSamePath(target, tempPath) && error && error.code === "EEXIST") {
        primary = mutateError(error);
        throw primary;
      }
      throw error;
    }
  };
  try {
    const result = fn(() => primary);
    return { primary, result };
  } finally {
    fs.openSync = realOpenSync;
  }
}

function plantSentinel(filePath, bytes = "sentinel winner\n") {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, bytes, "utf8");
  return {
    path: filePath,
    stats: fs.lstatSync(filePath),
    bytes: fs.readFileSync(filePath),
  };
}

function assertSentinelPreserved(sentinel) {
  const stats = fs.lstatSync(sentinel.path);
  assert.equal(stats.dev, sentinel.stats.dev);
  assert.equal(stats.ino, sentinel.stats.ino);
  assert.equal(Buffer.compare(fs.readFileSync(sentinel.path), sentinel.bytes), 0);
}

function assertNoStorageTemps(target, exceptPath = null) {
  const entries = fs.existsSync(path.dirname(target))
    ? fs.readdirSync(path.dirname(target))
    : [];
  const residue = entries
    .filter((entry) => entry.startsWith(`.${path.basename(target)}.`) && entry.endsWith(".tmp"))
    .map((entry) => path.join(path.dirname(target), entry))
    .filter((entryPath) => !exceptPath || !isSamePath(entryPath, exceptPath));
  assert.deepEqual(residue, []);
}

function makeSetterHostile(error) {
  Object.defineProperty(error, "exclusiveReceipt", {
    enumerable: true,
    configurable: false,
    get() {
      return undefined;
    },
    set() {
      throw new Error("exclusiveReceipt setter blocked");
    },
  });
  return error;
}

function makeProxyHostile(error) {
  return new Proxy(error, {
    set() {
      throw new Error("proxy set blocked");
    },
    defineProperty() {
      throw new Error("proxy define blocked");
    },
  });
}

function assertStorageTempOpenPrimaryPreserved(label, mutateError) {
  withTempDir((dir) => {
    const target = path.join(dir, `${label}.txt`);
    withFixedSiblingTempNames(() => {
      const tempPath = fixedSiblingTempPath(target);
      const sentinel = plantSentinel(tempPath);
      let expectedMessage = null;
      let expectedCode = null;
      let observed = null;

      patchOpenCollision(tempPath, (error) => {
        const primary = mutateError(error);
        expectedMessage = primary.message;
        expectedCode = primary.code;
        return primary;
      }, (getPrimary) => {
        assert.throws(
          () => writeFileExclusiveAtomic(target, "replacement"),
          (error) => {
            observed = error;
            assert.equal(error, getPrimary());
            assert.equal(error.code, expectedCode);
            assert.equal(error.message, expectedMessage);
            return true;
          },
        );
      });

      assert.ok(observed);
      assert.equal(fs.existsSync(target), false);
      assertSentinelPreserved(sentinel);
      assertNoStorageTemps(target, tempPath);
    });
  });
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
      component: "storage-exclusive-temp-collision-guard.test",
    },
  };
}

function commitState(domain, state) {
  return commitSessionAuthority({
    targetDomain: domain,
    nextNucleus: sessionNucleusFromState(state),
    stateProjection: {
      rawDocument: {},
      nextState: state,
    },
    event: governanceEvent("governance.session.initialized"),
    expectedNucleusHash: null,
  });
}

function assertAuthorityFilesAbsent(domain) {
  assert.equal(fs.existsSync(statePath(domain)), false);
  assert.equal(fs.existsSync(sessionNucleusPath(domain)), false);
  assert.equal(fs.existsSync(sessionEventsJsonlPath(domain)), false);
}

function assertNoAuthorityTemps(domain, exceptPath = null) {
  for (const filePath of [statePath(domain), sessionNucleusPath(domain), sessionEventsJsonlPath(domain)]) {
    assertNoStorageTemps(filePath, exceptPath);
  }
}

function assertRetryCreatesAuthorityFiles(domain) {
  const state = initialState(domain);
  const expectedNucleus = sessionNucleusFromState(state);
  const result = commitState(domain, state);
  assert.equal(result.target_domain, domain);
  assert.equal(result.nucleus_hash, expectedNucleus.nucleus_hash);
  assert.deepEqual(readVerifiedSessionNucleus(domain), expectedNucleus);
  assert.equal(readSessionStateStrict(domain).state.target, domain);
  assert.equal(readSessionEvents(domain).length, 1);
}

function assertUowTempOpenPrimaryPreserved({
  domain,
  failedFile,
  mutateError,
  expectDiagnostics,
}) {
  withFixedSiblingTempNames(() => {
    const tempPath = fixedSiblingTempPath(failedFile);
    const sentinel = plantSentinel(tempPath);
    let expectedMessage = null;
    let expectedCode = null;
    let observed = null;

    patchOpenCollision(tempPath, (error) => {
      const primary = mutateError(error);
      expectedMessage = primary.message;
      expectedCode = primary.code;
      return primary;
    }, (getPrimary) => {
      assert.throws(
        () => commitState(domain, initialState(domain)),
        (error) => {
          observed = error;
          assert.equal(error, getPrimary());
          assert.equal(error.code, expectedCode);
          assert.equal(error.message, expectedMessage);
          if (expectDiagnostics) {
            assert.equal(error.exclusive_receipt.status, "failed");
            assert.equal(error.exclusive_receipt.phase, "temp_open");
            assert.equal(error.exclusive_receipt.path, failedFile);
            assert.deepEqual(error.exclusive_receipt.unresolvedTemp, {
              path: tempPath,
              reason: "temp_exists",
            });
          } else {
            assert.equal(error.exclusive_receipt, undefined);
          }
          return true;
        },
      );
    });

    assert.ok(observed);
    assertAuthorityFilesAbsent(domain);
    assertSentinelPreserved(sentinel);
    assertNoAuthorityTemps(domain, tempPath);
    fs.unlinkSync(tempPath);
    assertNoAuthorityTemps(domain);
    assertRetryCreatesAuthorityFiles(domain);
  });
}

test("writeFileExclusiveAtomic preserves hostile temp-open EEXIST primaries", () => {
  assertStorageTempOpenPrimaryPreserved("frozen", (error) => Object.freeze(error));
  assertStorageTempOpenPrimaryPreserved("non-extensible", (error) => Object.preventExtensions(error));
  assertStorageTempOpenPrimaryPreserved("setter-hostile", makeSetterHostile);
  assertStorageTempOpenPrimaryPreserved("proxy-hostile", makeProxyHostile);
});

test("writeFileExclusiveAtomic keeps temp-open EEXIST diagnostics on extensible errors", () => {
  withTempDir((dir) => {
    const target = path.join(dir, "extensible.txt");
    withFixedSiblingTempNames(() => {
      const tempPath = fixedSiblingTempPath(target);
      const sentinel = plantSentinel(tempPath);
      let primary = null;

      patchOpenCollision(tempPath, (error) => error, (getPrimary) => {
        assert.throws(
          () => writeFileExclusiveAtomic(target, "replacement"),
          (error) => {
            primary = getPrimary();
            assert.equal(error, primary);
            assert.equal(error.code, "EEXIST");
            assert.equal(error.exclusiveReceipt.status, "failed");
            assert.equal(error.exclusiveReceipt.phase, "temp_open");
            assert.equal(error.exclusiveReceipt.path, target);
            assert.deepEqual(error.exclusiveReceipt.unresolvedTemp, {
              path: tempPath,
              reason: "temp_exists",
            });
            return true;
          },
        );
      });

      assert.ok(primary);
      assertSentinelPreserved(sentinel);
      assert.equal(fs.existsSync(target), false);
    });
  });
});

test("writeFileExclusiveAtomic returns false on final-link EEXIST without mutating winner", () => {
  withTempDir((dir) => {
    const target = path.join(dir, "final-winner.txt");
    fs.writeFileSync(target, "winner bytes\n", "utf8");
    const before = fs.lstatSync(target);
    const beforeBytes = fs.readFileSync(target);

    assert.equal(writeFileExclusiveAtomic(target, "replacement"), false);

    const after = fs.lstatSync(target);
    assert.equal(after.dev, before.dev);
    assert.equal(after.ino, before.ino);
    assert.equal(Buffer.compare(fs.readFileSync(target), beforeBytes), 0);
    assertNoStorageTemps(target);
  });
});

test("commitSessionAuthority fresh temp-open collisions preserve hostile primaries and retry", () => {
  withTempHome(() => {
    for (const [suffix, fileFor, mutateError] of [
      ["state-frozen", statePath, (error) => Object.freeze(error)],
      ["nucleus-non-extensible", sessionNucleusPath, (error) => Object.preventExtensions(error)],
      ["event-frozen", sessionEventsJsonlPath, (error) => Object.freeze(error)],
    ]) {
      const domain = `authority-temp-open-${suffix}.example.com`;
      assertUowTempOpenPrimaryPreserved({
        domain,
        failedFile: fileFor(domain),
        mutateError,
        expectDiagnostics: false,
      });
      fs.rmSync(sessionDir(domain), { recursive: true, force: true });
    }
  });
});

test("commitSessionAuthority keeps snake_case temp-open diagnostics on extensible errors", () => {
  withTempHome(() => {
    const domain = "authority-temp-open-extensible.example.com";
    assertUowTempOpenPrimaryPreserved({
      domain,
      failedFile: sessionNucleusPath(domain),
      mutateError: (error) => error,
      expectDiagnostics: true,
    });
  });
});

test("commitSessionAuthority fresh final collision preserves winner, rolls back predecessors, and retries", () => {
  withTempHome(() => {
    const domain = "authority-final-collision-retry.example.com";
    const nucleusFile = sessionNucleusPath(domain);
    const realLinkSync = fs.linkSync;
    let sentinel = null;
    let thrown = null;

    fs.linkSync = function patchedLinkSync(source, destination) {
      if (!sentinel && isSamePath(destination, nucleusFile)) {
        sentinel = plantSentinel(nucleusFile, "nucleus winner\n");
      }
      return realLinkSync.call(fs, source, destination);
    };
    try {
      assert.throws(
        () => commitState(domain, initialState(domain)),
        (error) => {
          thrown = error;
          assert.match(error.message, /session-nucleus\.json already exists/);
          assert.equal(error.exclusive_receipt.label, "session-nucleus.json");
          assert.equal(error.exclusive_receipt.status, "exists");
          assert.equal(error.exclusive_receipt.phase, "link");
          assert.equal(error.exclusive_receipt.finalCandidate.path, nucleusFile);
          return true;
        },
      );
    } finally {
      fs.linkSync = realLinkSync;
    }

    assert.ok(thrown);
    assert.ok(sentinel);
    assert.equal(fs.existsSync(statePath(domain)), false);
    assert.equal(fs.existsSync(sessionEventsJsonlPath(domain)), false);
    assertSentinelPreserved(sentinel);
    assertNoAuthorityTemps(domain);

    fs.unlinkSync(nucleusFile);
    assertRetryCreatesAuthorityFiles(domain);
  });
});
