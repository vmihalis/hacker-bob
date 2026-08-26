"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const net = require("net");
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
  egress_profile_identity_source: null,
});

function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-storage-eexist-compat-"));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-authority-eexist-compat-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

async function withShortTempDir(fn) {
  const dir = fs.mkdtempSync(path.join("/tmp", "bob-a2s-"));
  try {
    return await fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function patchFs(method, replacement, fn) {
  const original = fs[method];
  fs[method] = replacement(original);
  try {
    return fn();
  } finally {
    fs[method] = original;
  }
}

function isSamePath(left, right) {
  return path.resolve(left) === path.resolve(right);
}

function isTempFor(target, candidate) {
  return path.dirname(candidate) === path.dirname(target)
    && path.basename(candidate).startsWith(`.${path.basename(target)}.`)
    && path.basename(candidate).endsWith(".tmp");
}

function assertNoStorageTemps(target) {
  const entries = fs.existsSync(path.dirname(target))
    ? fs.readdirSync(path.dirname(target))
    : [];
  assert.deepEqual(
    entries.filter((entry) => entry.startsWith(`.${path.basename(target)}.`) && entry.endsWith(".tmp")),
    [],
  );
}

function listenOnSocket(socketPath) {
  const server = net.createServer();
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.off("error", reject);
      resolve(server);
    });
  });
}

function closeServer(server) {
  if (!server || !server.listening) return Promise.resolve();
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function exactUnlink(filePath, expectedStats) {
  const stats = fs.lstatSync(filePath);
  assert.equal(stats.dev, expectedStats.dev);
  assert.equal(stats.ino, expectedStats.ino);
  fs.unlinkSync(filePath);
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
      component: "storage-exclusive-eexist-compat.test",
    },
  };
}

function commitState(domain, state = initialState(domain)) {
  const nextNucleus = sessionNucleusFromState(state);
  return commitSessionAuthority({
    targetDomain: domain,
    nextNucleus,
    stateProjection: {
      rawDocument: {},
      nextState: state,
    },
    event: governanceEvent("governance.session.initialized"),
    expectedNucleusHash: null,
  });
}

function authorityPublications(domain) {
  return [
    { key: "state", label: "state.json", path: statePath(domain) },
    { key: "nucleus", label: "session-nucleus.json", path: sessionNucleusPath(domain) },
    { key: "events", label: "session-events.jsonl", path: sessionEventsJsonlPath(domain) },
  ];
}

function assertNoAuthorityTemps(domain) {
  const dir = sessionDir(domain);
  if (!fs.existsSync(dir)) return;
  const entries = fs.readdirSync(dir);
  for (const publication of authorityPublications(domain)) {
    assert.equal(
      entries.some((entry) => entry.startsWith(`.${publication.label}.`) && entry.endsWith(".tmp")),
      false,
      `${publication.label} temp residue must be absent`,
    );
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

function assertOnlyWinnerFinalExists(domain, winnerPublication, winnerBytes, winnerStats) {
  for (const publication of authorityPublications(domain)) {
    if (publication.key === winnerPublication.key) {
      assert.equal(fs.readFileSync(publication.path, "utf8"), winnerBytes);
      const stats = fs.lstatSync(publication.path);
      assert.equal(stats.dev, winnerStats.dev);
      assert.equal(stats.ino, winnerStats.ino);
    } else {
      assert.equal(fs.existsSync(publication.path), false, `${publication.label} must be absent`);
    }
  }
}

test("exclusive receipt and wrapper treat a socket-at-final EEXIST as an unowned collision", async (t) => {
  await withShortTempDir(async (dir) => {
    const filePath = path.join(dir, "sock");
    let server = null;
    try {
      server = await listenOnSocket(filePath);
    } catch (error) {
      if (error && error.code === "EPERM") {
        t.skip("Unix socket creation is blocked by this environment");
        return;
      }
      throw error;
    }
    try {
      const before = fs.lstatSync(filePath);
      const receipt = writeFileExclusiveAtomicReceipt(filePath, "replacement");

      assert.equal(receipt.status, "exists");
      assert.equal(receipt.phase, "link");
      assert.equal(receipt.error.code, "EEXIST");
      assert.equal(receipt.finalCandidate.type, "other");
      assert.equal(receipt.finalCandidate.owned, false);
      assert.equal(receipt.finalCandidate.dev, before.dev);
      assert.equal(receipt.finalCandidate.ino, before.ino);
      assert.equal(writeFileExclusiveAtomic(filePath, "replacement"), false);
      assertNoStorageTemps(filePath);

      const after = fs.lstatSync(filePath);
      assert.equal(after.dev, before.dev);
      assert.equal(after.ino, before.ino);
      assert.equal(server.listening, true);
    } finally {
      await closeServer(server);
      server = null;
      try { fs.unlinkSync(filePath); } catch {}
    }
  });
});

test("EEXIST-coded postlink proof failure remains a failed receipt and thrown primary", () => {
  function runPostlinkProofFailure(filePath, operation) {
    const realLinkSync = fs.linkSync;
    const realLstatSync = fs.lstatSync;
    const injected = new Error(`injected ${path.basename(filePath)} postlink EEXIST`);
    injected.code = "EEXIST";
    Object.freeze(injected);
    let linked = false;
    let proofThrown = false;
    let linkedStats = null;

    const result = patchFs("linkSync", () => function patchedLinkSync(source, destination) {
      const outcome = realLinkSync.call(fs, source, destination);
      if (isSamePath(destination, filePath)) {
        linked = true;
        linkedStats = realLstatSync.call(fs, destination);
      }
      return outcome;
    }, () => patchFs("lstatSync", () => function patchedLstatSync(target) {
      if (linked && !proofThrown && isSamePath(target, filePath)) {
        proofThrown = true;
        throw injected;
      }
      return realLstatSync.apply(fs, arguments);
    }, operation));

    assert.equal(linked, true);
    assert.equal(proofThrown, true);
    assert.ok(linkedStats);
    return { injected, linkedStats, result };
  }

  withTempDir((dir) => {
    const receiptPath = path.join(dir, "receipt.txt");
    const receiptRun = runPostlinkProofFailure(
      receiptPath,
      () => writeFileExclusiveAtomicReceipt(receiptPath, "owned"),
    );
    const receipt = receiptRun.result;
    assert.equal(receipt.status, "failed");
    assert.equal(receipt.phase, "postlink_proof");
    assert.equal(receipt.error, receiptRun.injected);
    assert.equal(Object.isFrozen(receipt.error), true);
    assert.equal(receipt.tempCandidate.owned, true);
    assert.equal(receipt.finalCandidate, null);
    assert.equal(fs.existsSync(receipt.tempPath), false);
    exactUnlink(receiptPath, receiptRun.linkedStats);

    const wrapperPath = path.join(dir, "wrapper.txt");
    let wrapperReturned = "not-called";
    let wrapperThrown = null;
    const wrapperRun = runPostlinkProofFailure(wrapperPath, () => {
      try {
        wrapperReturned = writeFileExclusiveAtomic(wrapperPath, "owned");
      } catch (error) {
        wrapperThrown = error;
      }
    });
    assert.equal(wrapperThrown, wrapperRun.injected);
    assert.equal(wrapperReturned, "not-called");
    exactUnlink(wrapperPath, wrapperRun.linkedStats);
  });
});

for (const failedKey of ["state", "nucleus", "events"]) {
  test(`commitSessionAuthority preserves an unowned ${failedKey} winner from a final link race`, () => {
    withTempHome(() => {
      const domain = `authority-${failedKey}-final-eexist-race.example.com`;
      const publications = authorityPublications(domain);
      const failedPublication = publications.find((publication) => publication.key === failedKey);
      const failedIndex = publications.indexOf(failedPublication);
      const realLinkSync = fs.linkSync;
      const linkAttempts = [];
      const winnerBytes = `${failedPublication.label} link race winner\n`;
      const collision = new Error(`injected ${failedPublication.label} link race`);
      collision.code = "EEXIST";
      let injected = false;
      let winnerStats = null;
      let thrown = null;

      fs.linkSync = function injectedLink(source, destination) {
        const publication = publications.find((candidate) => isSamePath(candidate.path, destination));
        if (publication) linkAttempts.push(publication.key);
        if (!injected && publication && publication.key === failedKey) {
          injected = true;
          fs.writeFileSync(destination, winnerBytes, "utf8");
          winnerStats = fs.lstatSync(destination);
          throw collision;
        }
        return realLinkSync(source, destination);
      };
      try {
        commitState(domain);
      } catch (error) {
        thrown = error;
      } finally {
        fs.linkSync = realLinkSync;
      }

      assert.ok(thrown);
      assert.notEqual(thrown, collision);
      assert.match(thrown.message, new RegExp(`${failedPublication.label} already exists`));
      assert.equal(thrown.exclusive_receipt.label, failedPublication.label);
      assert.equal(thrown.exclusive_receipt.status, "exists");
      assert.equal(thrown.exclusive_receipt.phase, "link");
      assert.equal(thrown.exclusive_receipt.path, failedPublication.path);
      const finalCandidate = thrown.exclusive_receipt.finalCandidate;
      assert.equal(finalCandidate.path, failedPublication.path);
      assert.equal(finalCandidate.dev, winnerStats.dev);
      assert.equal(finalCandidate.ino, winnerStats.ino);
      assert.equal(finalCandidate.owned, false);
      assert.notEqual(finalCandidate.rollbackOwned, true);
      assert.deepEqual(linkAttempts, publications.slice(0, failedIndex + 1).map((publication) => publication.key));
      assertOnlyWinnerFinalExists(domain, failedPublication, winnerBytes, winnerStats);
      assertNoAuthorityTemps(domain);

      fs.unlinkSync(failedPublication.path);
      assertRetryCreatesAuthorityFiles(domain);
      fs.rmSync(sessionDir(domain), { recursive: true, force: true });
    });
  });
}
