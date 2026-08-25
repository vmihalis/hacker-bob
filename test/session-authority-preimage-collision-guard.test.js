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

const PREIMAGE_KINDS = Object.freeze(["file", "symlink", "directory", "hardlink"]);

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-session-authority-preimage-"));
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
      component: "session-authority-preimage-collision-guard.test",
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
    event: governanceEvent(),
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

function publicationFor(domain, key) {
  return authorityPublications(domain).find((publication) => publication.key === key);
}

function isTempFor(publication, candidate) {
  return path.dirname(candidate) === path.dirname(publication.path)
    && path.basename(candidate).startsWith(`.${publication.label}.`)
    && path.basename(candidate).endsWith(".tmp");
}

function traceCommit(domain, fn) {
  const publications = authorityPublications(domain);
  const realLstatSync = fs.lstatSync;
  const realOpenSync = fs.openSync;
  const realLinkSync = fs.linkSync;
  const trace = [];

  function matchingFinal(target) {
    return publications.find((publication) => path.resolve(target) === path.resolve(publication.path));
  }

  function matchingTemp(target) {
    return publications.find((publication) => isTempFor(publication, target));
  }

  fs.lstatSync = function tracedLstatSync(target) {
    const publication = matchingFinal(target);
    if (publication) trace.push({ op: "lstat", label: publication.label, path: target });
    return realLstatSync.apply(fs, arguments);
  };
  fs.openSync = function tracedOpenSync(target) {
    const publication = typeof target === "string" ? matchingTemp(target) : null;
    if (publication) trace.push({ op: "open", label: publication.label, path: target });
    return realOpenSync.apply(fs, arguments);
  };
  fs.linkSync = function tracedLinkSync(source, destination) {
    const publication = matchingFinal(destination) || matchingTemp(source);
    if (publication) {
      trace.push({
        op: "link",
        label: publication.label,
        source,
        destination,
      });
    }
    return realLinkSync.apply(fs, arguments);
  };

  try {
    return { trace, result: fn() };
  } catch (error) {
    return { trace, error };
  } finally {
    fs.lstatSync = realLstatSync;
    fs.openSync = realOpenSync;
    fs.linkSync = realLinkSync;
  }
}

function assertPlannedFinalLstatsBeforeStaging(trace, expectedLabels) {
  const firstStaging = trace.findIndex((entry) => entry.op === "open" || entry.op === "link");
  const preStagingTrace = firstStaging === -1 ? trace : trace.slice(0, firstStaging);
  assert.deepEqual(
    preStagingTrace.filter((entry) => entry.op === "lstat").map((entry) => entry.label),
    expectedLabels,
  );
}

function assertProjectedAuthorityPublicationPreflight(trace) {
  assert.deepEqual(
    trace.filter((entry) => entry.op === "lstat").map((entry) => entry.label),
    ["state.json", "session-nucleus.json", "session-events.jsonl"],
  );
  assertPlannedFinalLstatsBeforeStaging(trace, [
    "state.json",
    "session-nucleus.json",
    "session-events.jsonl",
  ]);
}

function assertNoStaging(trace) {
  assert.deepEqual(trace.filter((entry) => entry.op === "open" || entry.op === "link"), []);
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

function assertOtherAuthorityFinalsAbsent(domain, preimageKey) {
  for (const publication of authorityPublications(domain)) {
    if (publication.key === preimageKey) continue;
    assert.equal(fs.existsSync(publication.path), false, `${publication.label} must be absent`);
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

function createPreimage(kind, publication, home) {
  fs.mkdirSync(path.dirname(publication.path), { recursive: true });
  const bytes = Buffer.from(`${publication.label} ${kind} preimage\n`);

  if (kind === "file") {
    fs.writeFileSync(publication.path, bytes);
    const stats = fs.lstatSync(publication.path);
    return { kind, bytes, stats };
  }

  if (kind === "symlink") {
    const target = path.join(home, `${publication.key}-symlink-target`);
    fs.writeFileSync(target, bytes);
    fs.symlinkSync(target, publication.path);
    const stats = fs.lstatSync(publication.path);
    return { kind, bytes, stats, target, linkTarget: fs.readlinkSync(publication.path) };
  }

  if (kind === "directory") {
    fs.mkdirSync(publication.path);
    const child = path.join(publication.path, "child.txt");
    fs.writeFileSync(child, bytes);
    const stats = fs.lstatSync(publication.path);
    return { kind, bytes, stats, child };
  }

  const peer = path.join(home, `${publication.key}-hardlink-peer`);
  fs.writeFileSync(peer, bytes);
  fs.linkSync(peer, publication.path);
  const stats = fs.lstatSync(publication.path);
  const peerStats = fs.lstatSync(peer);
  return { kind, bytes, stats, peer, peerStats };
}

function assertSameIdentity(actual, expected, label) {
  assert.equal(actual.dev, expected.dev, `${label} dev must be preserved`);
  assert.equal(actual.ino, expected.ino, `${label} ino must be preserved`);
}

function assertPreimagePreserved(publication, preimage) {
  const after = fs.lstatSync(publication.path);
  assertSameIdentity(after, preimage.stats, publication.label);

  if (preimage.kind === "file") {
    assert.equal(Buffer.compare(fs.readFileSync(publication.path), preimage.bytes), 0);
  } else if (preimage.kind === "symlink") {
    assert.equal(after.isSymbolicLink(), true);
    assert.equal(fs.readlinkSync(publication.path), preimage.linkTarget);
    assert.equal(Buffer.compare(fs.readFileSync(preimage.target), preimage.bytes), 0);
  } else if (preimage.kind === "directory") {
    assert.equal(after.isDirectory(), true);
    assert.equal(Buffer.compare(fs.readFileSync(preimage.child), preimage.bytes), 0);
  } else {
    const peerAfter = fs.lstatSync(preimage.peer);
    assertSameIdentity(peerAfter, preimage.peerStats, "hardlink peer");
    assert.equal(after.ino, peerAfter.ino);
    assert.equal(Buffer.compare(fs.readFileSync(preimage.peer), preimage.bytes), 0);
    assert.equal(Buffer.compare(fs.readFileSync(publication.path), preimage.bytes), 0);
  }
}

function removePreimage(publication, preimage) {
  if (preimage.kind === "directory") {
    fs.rmSync(publication.path, { recursive: true, force: true });
    return;
  }
  fs.unlinkSync(publication.path);
}

function assertCollisionError(error, publication, kind, preimage) {
  assert.ok(error);
  if (kind === "file") {
    assert.match(error.message, new RegExp(`${publication.label.replace(".", "\\.")} already exists`));
    assert.equal(error.exclusive_receipt.label, publication.label);
    assert.equal(error.exclusive_receipt.status, "exists");
    assert.equal(error.exclusive_receipt.phase, "preflight");
    assert.equal(error.exclusive_receipt.path, publication.path);
    assert.equal(error.exclusive_receipt.tempPath, null);
    assert.equal(error.exclusive_receipt.tempCandidate, null);
    assert.deepEqual(error.exclusive_receipt.finalCandidate, {
      path: publication.path,
      dev: preimage.stats.dev,
      ino: preimage.stats.ino,
      owned: false,
    });
    return;
  }

  assert.equal(error.exclusive_receipt, undefined);
  if (kind === "symlink") {
    assert.match(error.message, new RegExp(`${publication.label.replace(".", "\\.")} must not be a symbolic link`));
  } else {
    assert.match(error.message, new RegExp(`${publication.label.replace(".", "\\.")} must be a single-link regular file`));
  }
}

for (const preimageKey of ["state", "nucleus", "events"]) {
  for (const kind of PREIMAGE_KINDS) {
    test(`fresh authority preflight rejects ${kind} ${preimageKey} preimage without staging`, () => {
      withTempHome((home) => {
        const domain = `authority-preimage-${preimageKey}-${kind}.example.com`;
        const publication = publicationFor(domain, preimageKey);
        const preimage = createPreimage(kind, publication, home);

        const { trace, error } = traceCommit(domain, () => commitState(domain));

        assertCollisionError(error, publication, kind, preimage);
        assertProjectedAuthorityPublicationPreflight(trace);
        assertNoStaging(trace);
        assertPreimagePreserved(publication, preimage);
        assertOtherAuthorityFinalsAbsent(domain, preimageKey);
        assertNoAuthorityTemps(domain);

        removePreimage(publication, preimage);
        assertRetryCreatesAuthorityFiles(domain);
      });
    });
  }
}

test("fresh authority diagnostics report unsafe preimages before regular file collisions", () => {
  withTempHome((home) => {
    const domain = "authority-preimage-unsafe-outranks-file.example.com";
    const nucleus = publicationFor(domain, "nucleus");
    const events = publicationFor(domain, "events");
    const nucleusPreimage = createPreimage("file", nucleus, home);
    const eventsPreimage = createPreimage("symlink", events, home);

    const { trace, error } = traceCommit(domain, () => commitState(domain));

    assert.match(error.message, /session-events\.jsonl must not be a symbolic link/);
    assert.equal(error.exclusive_receipt, undefined);
    assertProjectedAuthorityPublicationPreflight(trace);
    assertNoStaging(trace);
    assertPreimagePreserved(nucleus, nucleusPreimage);
    assertPreimagePreserved(events, eventsPreimage);
    assertNoAuthorityTemps(domain);
  });
});

test("fresh authority unsafe diagnostics report nucleus before state and events", () => {
  withTempHome((home) => {
    const domain = "authority-preimage-unsafe-order.example.com";
    const state = publicationFor(domain, "state");
    const nucleus = publicationFor(domain, "nucleus");
    const events = publicationFor(domain, "events");
    const statePreimage = createPreimage("directory", state, home);
    const nucleusPreimage = createPreimage("symlink", nucleus, home);

    const { trace, error } = traceCommit(domain, () => commitState(domain));

    assert.match(error.message, /session-nucleus\.json must not be a symbolic link/);
    assert.equal(error.exclusive_receipt, undefined);
    assertProjectedAuthorityPublicationPreflight(trace);
    assertNoStaging(trace);
    assertPreimagePreserved(state, statePreimage);
    assertPreimagePreserved(nucleus, nucleusPreimage);
    assert.equal(fs.existsSync(events.path), false);
    assertNoAuthorityTemps(domain);
  });
});

test("fresh authority regular file diagnostics report nucleus before state and events", () => {
  withTempHome((home) => {
    const domain = "authority-preimage-file-order.example.com";
    const state = publicationFor(domain, "state");
    const nucleus = publicationFor(domain, "nucleus");
    const events = publicationFor(domain, "events");
    const statePreimage = createPreimage("file", state, home);
    const nucleusPreimage = createPreimage("file", nucleus, home);
    const eventsPreimage = createPreimage("file", events, home);

    const { trace, error } = traceCommit(domain, () => commitState(domain));

    assert.match(error.message, /session-nucleus\.json already exists/);
    assert.equal(error.exclusive_receipt.label, "session-nucleus.json");
    assert.equal(error.exclusive_receipt.phase, "preflight");
    assert.equal(error.exclusive_receipt.path, nucleus.path);
    assertProjectedAuthorityPublicationPreflight(trace);
    assertNoStaging(trace);
    assertPreimagePreserved(state, statePreimage);
    assertPreimagePreserved(nucleus, nucleusPreimage);
    assertPreimagePreserved(events, eventsPreimage);
    assertNoAuthorityTemps(domain);
  });
});

test("fresh null-state authority preflight omits state and stages only after planned lstats", () => {
  withTempHome((home) => {
    const domain = "authority-preimage-null-state.example.com";
    const state = publicationFor(domain, "state");
    const externalState = path.join(home, "external-state.json");
    fs.mkdirSync(path.dirname(state.path), { recursive: true });
    fs.writeFileSync(externalState, "external state\n", "utf8");
    fs.symlinkSync(externalState, state.path);
    const linkTarget = fs.readlinkSync(state.path);
    const nextNucleus = sessionNucleusFromState(initialState(domain));

    const { trace, result, error } = traceCommit(domain, () => commitSessionAuthority({
      targetDomain: domain,
      nextNucleus,
      stateProjection: null,
      event: governanceEvent(),
      expectedNucleusHash: null,
    }));

    assert.equal(error, undefined);
    assert.equal(result.state_written, false);
    const lstatLabels = trace.filter((entry) => entry.op === "lstat").map((entry) => entry.label);
    assertPlannedFinalLstatsBeforeStaging(trace, ["session-nucleus.json", "session-events.jsonl"]);
    assert.equal(lstatLabels.includes("state.json"), false);
    assert.equal(fs.readlinkSync(state.path), linkTarget);
    assert.equal(fs.readFileSync(externalState, "utf8"), "external state\n");
    assert.equal(readVerifiedSessionNucleus(domain).nucleus_hash, nextNucleus.nucleus_hash);
    assert.equal(readSessionEvents(domain).length, 1);
    assertNoAuthorityTemps(domain);
  });
});
