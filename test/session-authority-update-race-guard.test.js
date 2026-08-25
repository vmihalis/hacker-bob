"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  sessionEventsJsonlPath,
  sessionNucleusPath,
  statePath,
} = require("../mcp/core/io/paths.js");
const {
  rollbackFileCasAtomicReceipt,
  writeFileCasAtomicReceipt,
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
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-update-cas-"));
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
    ...buildInitialSessionState(domain, `https://${domain}`, { egressProfile: DEFAULT_EGRESS_PROFILE }),
    ...overrides,
  };
}

function event(kind) {
  return { kind, source: { component: "session-authority-update-race-guard.test" }, payload: {} };
}

function createAuthority(domain) {
  const state = initialState(domain);
  const nucleus = sessionNucleusFromState(state);
  const result = commitSessionAuthority({
    targetDomain: domain,
    nextNucleus: nucleus,
    stateProjection: { rawDocument: {}, nextState: state },
    event: event("governance.session.initialized"),
    expectedNucleusHash: null,
  });
  return { state, result };
}

function updateAuthority(domain, expectedNucleusHash, { projection = true } = {}) {
  const nextState = initialState(domain, { lifecycle_state: "OPEN_FRONTIER", phase: "EVALUATE" });
  return commitSessionAuthority({
    targetDomain: domain,
    nextNucleus: sessionNucleusFromState(nextState),
    stateProjection: projection
      ? {
        rawDocument: fs.existsSync(statePath(domain)) ? readSessionStateStrict(domain).raw : {},
        nextState,
      }
      : null,
    event: event("governance.lifecycle.advanced"),
    expectedNucleusHash,
  });
}

function authorityFiles(domain) {
  return [statePath(domain), sessionNucleusPath(domain), sessionEventsJsonlPath(domain)];
}

function snapshotFiles(domain) {
  return new Map(authorityFiles(domain).map((filePath) => [filePath, {
    exists: fs.existsSync(filePath),
    bytes: fs.existsSync(filePath) ? fs.readFileSync(filePath) : null,
  }]));
}

function assertFileSnapshot(filePath, snapshot) {
  assert.equal(fs.existsSync(filePath), snapshot.exists, `${path.basename(filePath)} existence`);
  if (snapshot.exists) assert.deepEqual(fs.readFileSync(filePath), snapshot.bytes);
}

function isCasTempFor(filePath, candidate) {
  return path.dirname(filePath) === path.dirname(candidate)
    && path.basename(candidate).startsWith(`.${path.basename(filePath)}.`)
    && path.basename(candidate).endsWith(".tmp");
}

function assertNoCasResidue(domain) {
  const directory = path.dirname(sessionNucleusPath(domain));
  const names = fs.existsSync(directory) ? fs.readdirSync(directory) : [];
  for (const filePath of authorityFiles(domain)) {
    assert.equal(
      names.some((name) => name.startsWith(`.${path.basename(filePath)}.`) && name.endsWith(".tmp")),
      false,
      `${path.basename(filePath)} CAS residue`,
    );
  }
}

function casResiduePaths(domain) {
  const directory = path.dirname(sessionNucleusPath(domain));
  const names = fs.existsSync(directory) ? fs.readdirSync(directory) : [];
  return names
    .filter((name) => authorityFiles(domain).some(
      (filePath) => name.startsWith(`.${path.basename(filePath)}.`) && name.endsWith(".tmp"),
    ))
    .map((name) => path.join(directory, name));
}

function frozenFailure(message) {
  const error = new Error(message);
  error.code = "EIO";
  return Object.freeze(error);
}

test("CAS receipt replaces and rolls back exact single-link bytes without residue", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "bob-storage-cas-"));
  try {
    const filePath = path.join(directory, "authority.json");
    fs.writeFileSync(filePath, "before\n");
    const before = fs.lstatSync(filePath);
    const receipt = writeFileCasAtomicReceipt(filePath, Buffer.from("after\n"), {
      exists: true,
      bytes: Buffer.from("before\n"),
      dev: before.dev,
      ino: before.ino,
    });
    assert.equal(receipt.status, "replaced");
    assert.equal(receipt.phase, "complete");
    assert.equal(receipt.stagedCandidate.owned, true);
    assert.equal(receipt.displacedCandidate.owned, true);
    assert.equal(receipt.producedCandidate.owned, true);
    assert.equal(fs.existsSync(receipt.stagePath), false);
    assert.equal(fs.existsSync(receipt.quarantinePath), false);
    assert.equal(fs.readFileSync(filePath, "utf8"), "after\n");
    assert.deepEqual(fs.readdirSync(directory), ["authority.json"]);
    assert.equal(rollbackFileCasAtomicReceipt(receipt), null);
    assert.equal(fs.readFileSync(filePath, "utf8"), "before\n");
    assert.deepEqual(fs.readdirSync(directory), ["authority.json"]);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("CAS receipt preserves quarantine EEXIST winners and the original preimage", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "bob-storage-cas-"));
  const filePath = path.join(directory, "authority.json");
  fs.writeFileSync(filePath, "before\n");
  const before = fs.lstatSync(filePath);
  const realLinkSync = fs.linkSync;
  let winnerPath = null;
  fs.linkSync = function injectedLink(source, destination) {
    if (!winnerPath && path.resolve(source) === path.resolve(filePath) && isCasTempFor(filePath, destination)) {
      winnerPath = destination;
      fs.writeFileSync(winnerPath, "outside winner\n");
      const collision = new Error("injected quarantine collision");
      collision.code = "EEXIST";
      throw collision;
    }
    return realLinkSync(source, destination);
  };
  try {
    const receipt = writeFileCasAtomicReceipt(filePath, "after\n", {
      exists: true,
      bytes: Buffer.from("before\n"),
      dev: before.dev,
      ino: before.ino,
    });
    assert.equal(receipt.status, "conflict");
    assert.equal(receipt.phase, "quarantine_link");
    assert.equal(receipt.displacedCandidate, null);
    assert.equal(fs.readFileSync(filePath, "utf8"), "before\n");
    assert.equal(fs.readFileSync(winnerPath, "utf8"), "outside winner\n");
  } finally {
    fs.linkSync = realLinkSync;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("CAS receipt preserves a same-inode EEXIST winner for an absent preimage", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "bob-storage-cas-"));
  const filePath = path.join(directory, "authority.json");
  const realLinkSync = fs.linkSync;
  let winnerStats = null;
  fs.linkSync = function injectedLink(source, destination) {
    if (!winnerStats && path.resolve(destination) === path.resolve(filePath)) {
      realLinkSync(source, destination);
      winnerStats = fs.lstatSync(destination);
    }
    return realLinkSync(source, destination);
  };
  try {
    const receipt = writeFileCasAtomicReceipt(
      filePath,
      "same-inode winner\n",
      { exists: false },
    );
    assert.equal(receipt.status, "exists");
    assert.equal(receipt.error.code, "EEXIST");
    assert.equal(receipt.stageReceipt.finalCandidate.owned, false);
    assert.equal(fs.lstatSync(filePath).dev, winnerStats.dev);
    assert.equal(fs.lstatSync(filePath).ino, winnerStats.ino);
    assert.equal(fs.readFileSync(filePath, "utf8"), "same-inode winner\n");
    assert.equal(fs.existsSync(receipt.stagePath), false);
  } finally {
    fs.linkSync = realLinkSync;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("CAS receipt preserves a quarantine replacement installed after a successful link", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "bob-storage-cas-"));
  const filePath = path.join(directory, "authority.json");
  const victimPath = path.join(directory, "outside-victim");
  const victimBytes = Buffer.from("outside quarantine replacement\n");
  fs.writeFileSync(filePath, "before\n");
  fs.writeFileSync(victimPath, victimBytes);
  const before = fs.lstatSync(filePath);
  const victimBefore = fs.lstatSync(victimPath);
  const realLinkSync = fs.linkSync;
  let replacementPath = null;
  fs.linkSync = function injectedLink(source, destination) {
    if (!replacementPath
        && path.resolve(source) === path.resolve(filePath)
        && isCasTempFor(filePath, destination)) {
      realLinkSync(source, destination);
      replacementPath = destination;
      fs.unlinkSync(destination);
      realLinkSync(victimPath, destination);
      return;
    }
    return realLinkSync(source, destination);
  };
  try {
    const receipt = writeFileCasAtomicReceipt(filePath, "after\n", {
      exists: true,
      bytes: Buffer.from("before\n"),
      dev: before.dev,
      ino: before.ino,
    });
    assert.equal(receipt.status, "conflict");
    assert.equal(receipt.phase, "preimage_proof");
    assert.equal(receipt.displacedCandidate.dev, before.dev);
    assert.equal(receipt.displacedCandidate.ino, before.ino);
    assert.equal(fs.lstatSync(filePath).ino, before.ino);
    assert.equal(fs.readFileSync(filePath, "utf8"), "before\n");
    assert.equal(fs.lstatSync(replacementPath).dev, victimBefore.dev);
    assert.equal(fs.lstatSync(replacementPath).ino, victimBefore.ino);
    assert.equal(fs.lstatSync(victimPath).ino, victimBefore.ino);
    assert.deepEqual(fs.readFileSync(replacementPath), victimBytes);
    assert.deepEqual(fs.readFileSync(victimPath), victimBytes);
  } finally {
    fs.linkSync = realLinkSync;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("CAS receipt never owns coupled quarantine source and destination replacements", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "bob-storage-cas-"));
  const filePath = path.join(directory, "authority.json");
  const victimPath = path.join(directory, "outside-victim");
  const victimBytes = Buffer.from("outside coupled quarantine replacement\n");
  fs.writeFileSync(filePath, "before\n");
  fs.writeFileSync(victimPath, victimBytes);
  const before = fs.lstatSync(filePath);
  const victimBefore = fs.lstatSync(victimPath);
  const beforeFd = fs.openSync(filePath, "r");
  const realLinkSync = fs.linkSync;
  let replacementPath = null;
  fs.linkSync = function injectedLink(source, destination) {
    if (!replacementPath
        && path.resolve(source) === path.resolve(filePath)
        && isCasTempFor(filePath, destination)) {
      realLinkSync(source, destination);
      replacementPath = destination;
      fs.unlinkSync(source);
      fs.unlinkSync(destination);
      realLinkSync(victimPath, source);
      realLinkSync(victimPath, destination);
      return;
    }
    return realLinkSync(source, destination);
  };
  try {
    const receipt = writeFileCasAtomicReceipt(filePath, "after\n", {
      exists: true,
      bytes: Buffer.from("before\n"),
      dev: before.dev,
      ino: before.ino,
    });
    assert.equal(receipt.status, "conflict");
    assert.equal(receipt.phase, "preimage_proof");
    assert.equal(receipt.displacedCandidate.dev, before.dev);
    assert.equal(receipt.displacedCandidate.ino, before.ino);
    for (const outsiderPath of [victimPath, filePath, replacementPath]) {
      const stats = fs.lstatSync(outsiderPath);
      assert.equal(stats.dev, victimBefore.dev);
      assert.equal(stats.ino, victimBefore.ino);
      assert.deepEqual(fs.readFileSync(outsiderPath), victimBytes);
    }
    assert.equal(fs.fstatSync(beforeFd).nlink, 0);
    assert.equal(fs.existsSync(receipt.stagePath), false);
    assert.deepEqual(
      new Set(fs.readdirSync(directory)),
      new Set([path.basename(filePath), path.basename(victimPath), path.basename(replacementPath)]),
    );
  } finally {
    fs.linkSync = realLinkSync;
    fs.closeSync(beforeFd);
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("CAS receipt preserves a final replacement installed after a successful publish link", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "bob-storage-cas-"));
  const filePath = path.join(directory, "authority.json");
  const victimPath = path.join(directory, "outside-victim");
  const victimBytes = Buffer.from("outside final replacement\n");
  fs.writeFileSync(filePath, "before\n");
  fs.writeFileSync(victimPath, victimBytes);
  const before = fs.lstatSync(filePath);
  const victimBefore = fs.lstatSync(victimPath);
  const realLinkSync = fs.linkSync;
  let replaced = false;
  fs.linkSync = function injectedLink(source, destination) {
    if (!replaced
        && path.resolve(destination) === path.resolve(filePath)
        && isCasTempFor(filePath, source)) {
      realLinkSync(source, destination);
      fs.unlinkSync(destination);
      realLinkSync(victimPath, destination);
      replaced = true;
      return;
    }
    return realLinkSync(source, destination);
  };
  try {
    const receipt = writeFileCasAtomicReceipt(filePath, "after\n", {
      exists: true,
      bytes: Buffer.from("before\n"),
      dev: before.dev,
      ino: before.ino,
    });
    assert.equal(replaced, true);
    assert.equal(receipt.status, "failed");
    assert.equal(receipt.phase, "produced_proof");
    assert.notEqual(receipt.producedCandidate.ino, victimBefore.ino);
    assert.equal(fs.lstatSync(filePath).dev, victimBefore.dev);
    assert.equal(fs.lstatSync(filePath).ino, victimBefore.ino);
    assert.equal(fs.lstatSync(victimPath).ino, victimBefore.ino);
    assert.deepEqual(fs.readFileSync(filePath), victimBytes);
    assert.deepEqual(fs.readFileSync(victimPath), victimBytes);
    assert.equal(fs.existsSync(receipt.stagePath), false);
    assert.equal(fs.existsSync(receipt.quarantinePath), false);
  } finally {
    fs.linkSync = realLinkSync;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("CAS receipt never owns coupled publish source and destination replacements", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "bob-storage-cas-"));
  const filePath = path.join(directory, "authority.json");
  const victimPath = path.join(directory, "outside-victim");
  const victimBytes = Buffer.from("outside coupled publish replacement\n");
  fs.writeFileSync(filePath, "before\n");
  fs.writeFileSync(victimPath, victimBytes);
  const before = fs.lstatSync(filePath);
  const victimBefore = fs.lstatSync(victimPath);
  const beforeFd = fs.openSync(filePath, "r");
  const realLinkSync = fs.linkSync;
  let stagePath = null;
  let stageFd = null;
  fs.linkSync = function injectedLink(source, destination) {
    if (!stagePath
        && path.resolve(destination) === path.resolve(filePath)
        && isCasTempFor(filePath, source)) {
      realLinkSync(source, destination);
      stagePath = source;
      stageFd = fs.openSync(source, "r");
      fs.unlinkSync(source);
      fs.unlinkSync(destination);
      realLinkSync(victimPath, source);
      realLinkSync(victimPath, destination);
      return;
    }
    return realLinkSync(source, destination);
  };
  try {
    const receipt = writeFileCasAtomicReceipt(filePath, "after\n", {
      exists: true,
      bytes: Buffer.from("before\n"),
      dev: before.dev,
      ino: before.ino,
    });
    assert.equal(receipt.status, "failed");
    assert.equal(receipt.phase, "produced_proof");
    assert.equal(receipt.producedCandidate.dev, fs.fstatSync(stageFd).dev);
    assert.equal(receipt.producedCandidate.ino, fs.fstatSync(stageFd).ino);
    assert.notEqual(receipt.producedCandidate.ino, victimBefore.ino);
    for (const outsiderPath of [victimPath, filePath, stagePath]) {
      const stats = fs.lstatSync(outsiderPath);
      assert.equal(stats.dev, victimBefore.dev);
      assert.equal(stats.ino, victimBefore.ino);
      assert.deepEqual(fs.readFileSync(outsiderPath), victimBytes);
    }
    assert.equal(fs.fstatSync(beforeFd).nlink, 0);
    assert.equal(fs.fstatSync(stageFd).nlink, 0);
    assert.equal(fs.existsSync(receipt.quarantinePath), false);
    assert.deepEqual(
      new Set(fs.readdirSync(directory)),
      new Set([path.basename(filePath), path.basename(victimPath), path.basename(stagePath)]),
    );
  } finally {
    fs.linkSync = realLinkSync;
    if (stageFd !== null) fs.closeSync(stageFd);
    fs.closeSync(beforeFd);
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

for (const member of ["state", "nucleus", "events"]) {
  for (const mutation of ["deletion", "in-place", "file", "symlink", "directory", "hardlink", "nlink"]) {
    test(`update CAS preserves ${member} ${mutation} race and rolls back predecessors`, () => {
      withTempHome(() => {
        const domain = `update-${member}-${mutation}.example.com`;
        const { result } = createAuthority(domain);
        const files = {
          state: statePath(domain),
          nucleus: sessionNucleusPath(domain),
          events: sessionEventsJsonlPath(domain),
        };
        const failedFile = files[member];
        const before = snapshotFiles(domain);
        const victim = `${failedFile}.outside`;
        const sidecar = `${failedFile}.hardlink`;
        const realLinkSync = fs.linkSync;
        let injected = false;
        let ambiguousQuarantinePath = null;
        fs.linkSync = function injectedLink(source, destination) {
          if (!injected
              && path.resolve(source) === path.resolve(failedFile)
              && isCasTempFor(failedFile, destination)) {
            injected = true;
            if (mutation === "deletion") fs.unlinkSync(failedFile);
            if (mutation === "in-place") fs.writeFileSync(failedFile, "outside in-place bytes\n");
            if (["file", "symlink", "directory", "hardlink"].includes(mutation)) {
              fs.unlinkSync(failedFile);
              if (mutation === "file") {
                fs.writeFileSync(failedFile, "outside replacement file\n");
              } else if (mutation === "symlink") {
                fs.writeFileSync(victim, "victim survives\n");
                fs.symlinkSync(victim, failedFile);
              } else if (mutation === "directory") {
                fs.mkdirSync(failedFile);
              } else {
                fs.writeFileSync(victim, "hardlink victim survives\n");
                fs.linkSync(victim, failedFile);
              }
            }
            if (mutation === "nlink") fs.linkSync(failedFile, sidecar);
          }
          const linkResult = realLinkSync(source, destination);
          if (injected
              && ambiguousQuarantinePath === null
              && ["file", "symlink", "hardlink"].includes(mutation)
              && path.resolve(source) === path.resolve(failedFile)
              && isCasTempFor(failedFile, destination)) {
            ambiguousQuarantinePath = destination;
          }
          return linkResult;
        };
        let thrown = null;
        try {
          updateAuthority(domain, result.nucleus_hash);
        } catch (error) {
          thrown = error;
        } finally {
          fs.linkSync = realLinkSync;
        }

        assert.ok(thrown, "race must reject the update");
        assert.equal(injected, true);
        for (const filePath of authorityFiles(domain)) {
          if (filePath !== failedFile) assertFileSnapshot(filePath, before.get(filePath));
        }
        if (mutation === "deletion") assert.equal(fs.existsSync(failedFile), false);
        if (mutation === "in-place") assert.equal(fs.readFileSync(failedFile, "utf8"), "outside in-place bytes\n");
        if (mutation === "file") assert.equal(fs.readFileSync(failedFile, "utf8"), "outside replacement file\n");
        if (mutation === "symlink") {
          assert.equal(fs.lstatSync(failedFile).isSymbolicLink(), true);
          assert.equal(fs.readFileSync(victim, "utf8"), "victim survives\n");
        }
        if (mutation === "directory") assert.equal(fs.lstatSync(failedFile).isDirectory(), true);
        if (mutation === "hardlink") {
          assert.equal(fs.lstatSync(failedFile).ino, fs.lstatSync(victim).ino);
          assert.equal(fs.readFileSync(victim, "utf8"), "hardlink victim survives\n");
        }
        if (mutation === "nlink") {
          assert.equal(fs.lstatSync(failedFile).ino, fs.lstatSync(sidecar).ino);
          assert.equal(fs.lstatSync(failedFile).nlink, 2);
        }
        if (ambiguousQuarantinePath) {
          const identityPath = mutation === "symlink" ? victim : failedFile;
          const failedStats = fs.lstatSync(identityPath);
          const ambiguousStats = fs.lstatSync(ambiguousQuarantinePath);
          assert.equal(ambiguousStats.dev, failedStats.dev);
          assert.equal(ambiguousStats.ino, failedStats.ino);
          assert.deepEqual(casResiduePaths(domain), [ambiguousQuarantinePath]);
        } else {
          assertNoCasResidue(domain);
        }

        fs.rmSync(failedFile, { recursive: true, force: true });
        fs.rmSync(victim, { force: true });
        fs.rmSync(sidecar, { force: true });
        if (ambiguousQuarantinePath) fs.rmSync(ambiguousQuarantinePath, { force: true });
        fs.writeFileSync(failedFile, before.get(failedFile).bytes);
        const retried = updateAuthority(domain, result.nucleus_hash);
        assert.equal(retried.target_domain, domain);
        assertNoCasResidue(domain);
      });
    });
  }
}

for (const member of ["state", "nucleus", "events"]) {
  test(`update CAS contains ${member} real-link-then-throw and transient probe fault`, () => {
    withTempHome(() => {
      const domain = `update-post-effect-${member}.example.com`;
      const { result } = createAuthority(domain);
      const files = {
        state: statePath(domain),
        nucleus: sessionNucleusPath(domain),
        events: sessionEventsJsonlPath(domain),
      };
      const failedFile = files[member];
      const before = snapshotFiles(domain);
      const primary = frozenFailure(`injected ${member} publish failure`);
      const probe = frozenFailure(`injected ${member} probe failure`);
      const realLinkSync = fs.linkSync;
      const realLstatSync = fs.lstatSync;
      let linked = false;
      let probed = false;
      fs.linkSync = function injectedLink(source, destination) {
        if (!linked
            && path.resolve(destination) === path.resolve(failedFile)
            && isCasTempFor(failedFile, source)) {
          linked = true;
          realLinkSync(source, destination);
          throw primary;
        }
        return realLinkSync(source, destination);
      };
      fs.lstatSync = function injectedLstat(target) {
        if (linked && !probed && path.resolve(target) === path.resolve(failedFile)) {
          probed = true;
          throw probe;
        }
        return realLstatSync(target);
      };
      let thrown = null;
      try {
        updateAuthority(domain, result.nucleus_hash);
      } catch (error) {
        thrown = error;
      } finally {
        fs.linkSync = realLinkSync;
        fs.lstatSync = realLstatSync;
      }
      assert.equal(thrown, primary);
      assert.equal(linked, true);
      assert.equal(probed, true);
      for (const filePath of authorityFiles(domain)) assertFileSnapshot(filePath, before.get(filePath));
      assertNoCasResidue(domain);
      assert.equal(updateAuthority(domain, result.nucleus_hash).target_domain, domain);
    });
  });
}

for (const member of ["state", "nucleus", "events"]) {
  test(`update CAS contains ${member} post-publish stage-cleanup failure`, () => {
    withTempHome(() => {
      const domain = `update-cleanup-${member}.example.com`;
      const { result } = createAuthority(domain);
      const files = {
        state: statePath(domain),
        nucleus: sessionNucleusPath(domain),
        events: sessionEventsJsonlPath(domain),
      };
      const failedFile = files[member];
      const before = snapshotFiles(domain);
      const primary = frozenFailure(`injected ${member} stage cleanup failure`);
      const realLinkSync = fs.linkSync;
      const realUnlinkSync = fs.unlinkSync;
      let publishedStage = null;
      let cleanupInjected = false;
      fs.linkSync = function observedLink(source, destination) {
        const result = realLinkSync(source, destination);
        if (path.resolve(destination) === path.resolve(failedFile)
            && isCasTempFor(failedFile, source)) {
          publishedStage = source;
        }
        return result;
      };
      fs.unlinkSync = function injectedUnlink(target) {
        if (!cleanupInjected
            && publishedStage
            && path.resolve(target) === path.resolve(publishedStage)) {
          cleanupInjected = true;
          realUnlinkSync(target);
          throw primary;
        }
        return realUnlinkSync(target);
      };
      let thrown = null;
      try {
        updateAuthority(domain, result.nucleus_hash);
      } catch (error) {
        thrown = error;
      } finally {
        fs.linkSync = realLinkSync;
        fs.unlinkSync = realUnlinkSync;
      }
      assert.equal(thrown, primary);
      assert.equal(cleanupInjected, true);
      for (const filePath of authorityFiles(domain)) assertFileSnapshot(filePath, before.get(filePath));
      assertNoCasResidue(domain);
      assert.equal(updateAuthority(domain, result.nucleus_hash).target_domain, domain);
    });
  });
}

test("update rollback preserves a predecessor replacement and rethrows the frozen primary", () => {
  withTempHome(() => {
    const domain = "update-predecessor-replacement.example.com";
    const { result } = createAuthority(domain);
    const stateFile = statePath(domain);
    const nucleusFile = sessionNucleusPath(domain);
    const eventsFile = sessionEventsJsonlPath(domain);
    const before = snapshotFiles(domain);
    const primary = frozenFailure("injected nucleus quarantine failure");
    const sentinel = Buffer.from("outside state replacement\n");
    const realLinkSync = fs.linkSync;
    let injected = false;
    fs.linkSync = function injectedLink(source, destination) {
      if (!injected
          && path.resolve(source) === path.resolve(nucleusFile)
          && isCasTempFor(nucleusFile, destination)) {
        injected = true;
        fs.unlinkSync(stateFile);
        fs.writeFileSync(stateFile, sentinel);
        throw primary;
      }
      return realLinkSync(source, destination);
    };
    let thrown = null;
    try {
      updateAuthority(domain, result.nucleus_hash);
    } catch (error) {
      thrown = error;
    } finally {
      fs.linkSync = realLinkSync;
    }
    assert.equal(thrown, primary);
    assert.deepEqual(fs.readFileSync(stateFile), sentinel);
    assertFileSnapshot(nucleusFile, before.get(nucleusFile));
    assertFileSnapshot(eventsFile, before.get(eventsFile));
    assertNoCasResidue(domain);
    fs.writeFileSync(stateFile, before.get(stateFile).bytes);
    assert.equal(updateAuthority(domain, result.nucleus_hash).target_domain, domain);
  });
});

for (const member of ["state", "events"]) {
  test(`update CAS preserves a late regular winner for absent ${member}`, () => {
    withTempHome(() => {
      const domain = `update-absent-${member}-winner.example.com`;
      const { result } = createAuthority(domain);
      const failedFile = member === "state" ? statePath(domain) : sessionEventsJsonlPath(domain);
      const before = snapshotFiles(domain);
      fs.unlinkSync(failedFile);
      const winner = Buffer.from(`late ${member} winner\n`);
      const realLinkSync = fs.linkSync;
      let injected = false;
      fs.linkSync = function injectedLink(source, destination) {
        if (!injected && path.resolve(destination) === path.resolve(failedFile)) {
          injected = true;
          fs.writeFileSync(failedFile, winner);
        }
        return realLinkSync(source, destination);
      };
      let thrown = null;
      try {
        updateAuthority(domain, result.nucleus_hash);
      } catch (error) {
        thrown = error;
      } finally {
        fs.linkSync = realLinkSync;
      }
      assert.ok(thrown);
      assert.equal(injected, true);
      assert.deepEqual(fs.readFileSync(failedFile), winner);
      for (const filePath of authorityFiles(domain)) {
        if (filePath !== failedFile) assertFileSnapshot(filePath, before.get(filePath));
      }
      assertNoCasResidue(domain);
      fs.writeFileSync(failedFile, before.get(failedFile).bytes);
      assert.equal(updateAuthority(domain, result.nucleus_hash).target_domain, domain);
    });
  });
}

test("update creates absent projections, preserves event order, and enforces retention", () => {
  withTempHome(() => {
    const domain = "update-absent-retention.example.com";
    const { result } = createAuthority(domain);
    const stateFile = statePath(domain);
    const eventsFile = sessionEventsJsonlPath(domain);
    fs.unlinkSync(stateFile);
    const lines = Array.from({ length: 20000 }, (_, index) => JSON.stringify({ index }));
    fs.writeFileSync(eventsFile, `${lines.join("\n")}\n`);
    updateAuthority(domain, result.nucleus_hash);
    assert.equal(fs.existsSync(stateFile), true);
    const retained = fs.readFileSync(eventsFile, "utf8").trim().split("\n");
    assert.equal(retained.length, 20000);
    assert.equal(JSON.parse(retained[0]).index, 1);
    assert.equal(JSON.parse(retained.at(-1)).kind, "governance.lifecycle.advanced");
    assertNoCasResidue(domain);
  });
});

test("null projection never probes state and preserves a late state file", () => {
  withTempHome(() => {
    const domain = "update-null-state.example.com";
    const { result } = createAuthority(domain);
    const stateFile = statePath(domain);
    const nucleusFile = sessionNucleusPath(domain);
    fs.unlinkSync(stateFile);
    const sentinel = "late outside state\n";
    const realLinkSync = fs.linkSync;
    const realLstatSync = fs.lstatSync;
    let lateCreated = false;
    let stateProbeCount = 0;
    fs.linkSync = function injectedLink(source, destination) {
      if (!lateCreated
          && path.resolve(source) === path.resolve(nucleusFile)
          && isCasTempFor(nucleusFile, destination)) {
        lateCreated = true;
        fs.writeFileSync(stateFile, sentinel);
      }
      return realLinkSync(source, destination);
    };
    fs.lstatSync = function injectedLstat(target) {
      if (path.resolve(target) === path.resolve(stateFile)) {
        stateProbeCount += 1;
        throw new Error("null projection probed state.json");
      }
      return realLstatSync(target);
    };
    try {
      updateAuthority(domain, result.nucleus_hash, { projection: false });
    } finally {
      fs.linkSync = realLinkSync;
      fs.lstatSync = realLstatSync;
    }
    assert.equal(lateCreated, true);
    assert.equal(stateProbeCount, 0);
    assert.equal(fs.readFileSync(stateFile, "utf8"), sentinel);
    assertNoCasResidue(domain);
  });
});
