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

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-uow-candidates-"));
  process.env.HOME = home;
  try {
    return fn();
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
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
      source: { component: "session-authority-uow-candidates.test" },
    },
    expectedNucleusHash: null,
  });
}

function publications(domain) {
  return MEMBERS.map((member) => ({
    ...member,
    path: member.pathFor(domain),
  }));
}

function isTempFor(finalPath, candidate) {
  return path.dirname(candidate) === path.dirname(finalPath)
    && path.basename(candidate).startsWith(`.${path.basename(finalPath)}.`)
    && path.basename(candidate).endsWith(".tmp");
}

function authorityTemps(domain) {
  const entries = publications(domain);
  const directories = new Set(entries.map((entry) => path.dirname(entry.path)));
  const temps = [];
  for (const directory of directories) {
    if (!fs.existsSync(directory)) continue;
    for (const name of fs.readdirSync(directory)) {
      const candidate = path.join(directory, name);
      if (entries.some((entry) => isTempFor(entry.path, candidate))) temps.push(candidate);
    }
  }
  return temps.sort();
}

function assertCandidate(candidate, expectedPath, stats) {
  assert.equal(candidate.path, expectedPath);
  assert.equal(candidate.dev, stats.dev);
  assert.equal(candidate.ino, stats.ino);
  assert.equal(candidate.type, "file");
  assert.equal(candidate.owned, true);
}

function assertAuthorityAbsent(domain) {
  for (const publication of publications(domain)) {
    assert.equal(fs.existsSync(publication.path), false, `${publication.label} must be absent`);
  }
}

function assertExactRegular(filePath, identity, bytes) {
  const stats = fs.lstatSync(filePath);
  assert.equal(stats.isFile(), true);
  assert.equal(stats.isSymbolicLink(), false);
  assert.equal(stats.dev, identity.dev);
  assert.equal(stats.ino, identity.ino);
  assert.equal(Buffer.compare(fs.readFileSync(filePath), bytes), 0);
  return stats;
}

function removeExactRegular(filePath, identity) {
  const stats = fs.lstatSync(filePath);
  assert.equal(stats.isFile() && !stats.isSymbolicLink(), true);
  assert.equal(stats.dev, identity.dev);
  assert.equal(stats.ino, identity.ino);
  fs.unlinkSync(filePath);
}

function assertCoherentRetry(domain) {
  const result = commitState(domain);
  const state = readSessionStateStrict(domain).state;
  const nucleus = readVerifiedSessionNucleus(domain);
  const events = readSessionEvents(domain);
  assert.equal(result.target_domain, domain);
  assert.deepEqual(sessionNucleusFromState(state), nucleus);
  assert.equal(result.nucleus_hash, nucleus.nucleus_hash);
  assert.equal(events.length, 1);
  assert.equal(events[0].nucleus_hash, nucleus.nucleus_hash);
  assert.deepEqual(authorityTemps(domain), []);
}

function runPrimaryCleanupCell(member) {
  withTempHome(() => {
    const domain = `a2vr-${member.key}-primary.example.com`;
    const failedPath = member.pathFor(domain);
    const realLinkSync = fs.linkSync;
    const realUnlinkSync = fs.unlinkSync;
    const realLstatSync = fs.lstatSync;
    const primary = new Error(`injected ${member.key} link failure`);
    primary.code = "EIO";
    const cleanup = new Error(`injected ${member.key} temp cleanup failure`);
    let stagedTemp = null;
    let stagedStats = null;
    let cleanupInjected = false;
    let thrown = null;

    assert.equal(Object.isExtensible(primary), true);
    fs.linkSync = function injectedLink(source, destination) {
      if (stagedTemp === null && path.resolve(destination) === path.resolve(failedPath)) {
        stagedTemp = source;
        stagedStats = realLstatSync(source);
        throw primary;
      }
      return realLinkSync(source, destination);
    };
    fs.unlinkSync = function injectedUnlink(target) {
      if (
        stagedTemp !== null
        && !cleanupInjected
        && path.resolve(target) === path.resolve(stagedTemp)
      ) {
        const current = realLstatSync(target);
        assert.equal(current.dev, stagedStats.dev);
        assert.equal(current.ino, stagedStats.ino);
        cleanupInjected = true;
        throw cleanup;
      }
      return realUnlinkSync(target);
    };
    try {
      commitState(domain);
    } catch (error) {
      thrown = error;
    } finally {
      fs.linkSync = realLinkSync;
      fs.unlinkSync = realUnlinkSync;
    }

    assert.equal(thrown, primary);
    assert.equal(cleanupInjected, true);
    assert.ok(stagedTemp);
    assert.equal(isTempFor(failedPath, stagedTemp), true);
    assert.equal(stagedStats.isFile() && !stagedStats.isSymbolicLink(), true);
    assert.equal(stagedStats.nlink, 1);
    assert.equal(thrown.cleanup_error, cleanup.message);
    assert.equal(thrown.rollback_error, undefined);
    const receipt = thrown.exclusive_receipt;
    assert.equal(receipt.label, member.label);
    assert.equal(receipt.status, "failed");
    assert.equal(receipt.phase, "link");
    assert.equal(receipt.path, failedPath);
    assert.equal(receipt.tempPath, stagedTemp);
    assert.equal(receipt.finalCandidate, null);
    assertCandidate(receipt.tempCandidate, stagedTemp, stagedStats);
    assertAuthorityAbsent(domain);
    assert.equal(fs.existsSync(stagedTemp), false);
    assert.deepEqual(authorityTemps(domain), []);
    assertCoherentRetry(domain);
  });
}

function runWrongSourceCell(member) {
  withTempHome(() => {
    const domain = `a2vr-${member.key}-wrong-source.example.com`;
    const failedPath = member.pathFor(domain);
    const sentinel = Buffer.from(`sentinel replacement for ${member.key}\n`, "utf8");
    const realLinkSync = fs.linkSync;
    const realUnlinkSync = fs.unlinkSync;
    const realLstatSync = fs.lstatSync;
    let stagedTemp = null;
    let sourceStats = null;
    let replacementStats = null;
    let thrown = null;

    fs.linkSync = function injectedLink(source, destination) {
      if (stagedTemp === null && path.resolve(destination) === path.resolve(failedPath)) {
        stagedTemp = source;
        sourceStats = realLstatSync(source);
        const sourceDescriptor = fs.openSync(source, "r");
        try {
          realUnlinkSync(source);
          fs.writeFileSync(source, sentinel);
          replacementStats = realLstatSync(source);
        } finally {
          fs.closeSync(sourceDescriptor);
        }
        realLinkSync(source, destination);
        return;
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
    assert.equal(thrown.message, "exclusive final identity does not match temp identity");
    assert.equal(thrown.rollback_error, undefined);
    const receipt = thrown.exclusive_receipt;
    assert.equal(receipt.label, member.label);
    assert.equal(receipt.status, "failed");
    assert.equal(receipt.phase, "postlink_proof");
    assert.equal(receipt.path, failedPath);
    assert.equal(receipt.tempPath, stagedTemp);
    assert.equal(receipt.finalCandidate, null);
    assert.equal(sourceStats.nlink, 1);
    assertCandidate(receipt.tempCandidate, stagedTemp, sourceStats);
    assert.notEqual(replacementStats.dev === sourceStats.dev && replacementStats.ino === sourceStats.ino, true);

    const finalStats = assertExactRegular(failedPath, replacementStats, sentinel);
    const tempStats = assertExactRegular(stagedTemp, replacementStats, sentinel);
    assert.equal(finalStats.dev, tempStats.dev);
    assert.equal(finalStats.ino, tempStats.ino);
    assert.equal(finalStats.nlink, 2);
    assert.equal(tempStats.nlink, 2);
    for (const publication of publications(domain)) {
      if (publication.path !== failedPath) {
        assert.equal(fs.existsSync(publication.path), false, `${publication.label} must be rolled back or absent`);
      }
    }
    assert.deepEqual(authorityTemps(domain), [stagedTemp]);

    removeExactRegular(failedPath, replacementStats);
    assertExactRegular(stagedTemp, replacementStats, sentinel);
    removeExactRegular(stagedTemp, replacementStats);
    assertAuthorityAbsent(domain);
    assert.deepEqual(authorityTemps(domain), []);
    assertCoherentRetry(domain);
  });
}

test("commitSessionAuthority rolls back only receipt-owned candidates across the 3x2 publication matrix", () => {
  for (const member of MEMBERS) runPrimaryCleanupCell(member);
  for (const member of MEMBERS) runWrongSourceCell(member);
});
