"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  SANDBOX_AGENT_UID_ENV,
  SANDBOX_ISOLATION_ACK_ENV,
  SANDBOX_ISOLATION_ACK_TOKEN,
  SANDBOX_SIGNER_UID_ENV,
  probeExactSigningKeyPathIsolation,
} = require("../mcp/core/ledger-integrity/sandbox-isolation-attest.js");
const {
  PHYSICAL_EXPERIMENT_TRUST_PRIVATE_KEY_BASENAME,
} = require("../mcp/core/ledger-integrity/signing-key-custody.js");

const OPERATOR_ENV_NAMES = Object.freeze([
  SANDBOX_ISOLATION_ACK_ENV,
  SANDBOX_SIGNER_UID_ENV,
  SANDBOX_AGENT_UID_ENV,
]);

function processUid() {
  return typeof process.getuid === "function" ? process.getuid() : null;
}

function operatorEnv(overrides = {}) {
  const uid = processUid();
  return {
    [SANDBOX_ISOLATION_ACK_ENV]: SANDBOX_ISOLATION_ACK_TOKEN,
    [SANDBOX_SIGNER_UID_ENV]: uid == null ? undefined : String(uid),
    [SANDBOX_AGENT_UID_ENV]: uid == null ? undefined : String(uid + 1),
    ...overrides,
  };
}

function withOperatorEnv(values, fn) {
  const previous = new Map();
  for (const name of OPERATOR_ENV_NAMES) {
    previous.set(name, process.env[name]);
    const value = values[name];
    if (value == null) delete process.env[name];
    else process.env[name] = String(value);
  }
  try {
    return fn();
  } finally {
    for (const [name, value] of previous) {
      if (value == null) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

function makeFixture() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "bob-exact-key-isolation-"));
  const custodyRoot = path.join(base, "session");
  const campaignRoot = path.join(custodyRoot, "physical-campaign");
  const expectedRoot = path.join(campaignRoot, "experiment-trust");
  const keyPath = path.join(
    expectedRoot,
    PHYSICAL_EXPERIMENT_TRUST_PRIVATE_KEY_BASENAME,
  );
  fs.mkdirSync(custodyRoot, { mode: 0o700 });
  fs.mkdirSync(campaignRoot, { mode: 0o700 });
  fs.mkdirSync(expectedRoot, { mode: 0o700 });
  fs.chmodSync(custodyRoot, 0o700);
  fs.chmodSync(campaignRoot, 0o700);
  fs.chmodSync(expectedRoot, 0o700);
  fs.writeFileSync(keyPath, "fixture-private-material", { mode: 0o400 });
  fs.chmodSync(keyPath, 0o400);
  return {
    base,
    custodyRoot,
    campaignRoot,
    expectedRoot,
    keyPath,
    cleanup() {
      fs.rmSync(base, { recursive: true, force: true });
    },
  };
}

function withFixture(fn) {
  const fixture = makeFixture();
  try {
    return fn(fixture);
  } finally {
    fixture.cleanup();
  }
}

function probeFixture(fixture) {
  return probeExactSigningKeyPathIsolation(fixture.keyPath, {
    expectedRoot: fixture.expectedRoot,
    custodyRoot: fixture.custodyRoot,
  });
}

test("exact signing-key probe proves a real owner-only non-root Mechanism-A path without disclosing paths", (t) => {
  const uid = processUid();
  if (uid == null || uid === 0) {
    t.skip("a positive Mechanism-A proof requires a non-root POSIX uid");
    return;
  }
  withFixture((fixture) => withOperatorEnv(operatorEnv(), () => {
    const result = probeFixture(fixture);
    assert.equal(result.assurance, "mechanism_a_exact_signing_key_path_isolation");
    assert.equal(result.version, 1);
    assert.equal(result.operator_ack_present, true);
    assert.equal(result.process_is_signer, true);
    assert.equal(result.agent_distinct, true);
    assert.equal(result.not_root, true);
    assert.equal(result.expected_root_within_custody_root, true);
    assert.equal(result.key_within_expected_root, true);
    assert.equal(result.parent_chain_real_directories, true);
    assert.equal(result.parent_chain_owner_only_mode, true);
    assert.equal(result.parent_chain_owned_by_signer, true);
    assert.equal(result.parent_chain_stable, true);
    assert.equal(result.key_regular_file, true);
    assert.equal(result.key_single_link, true);
    assert.equal(result.key_owner_read_only_mode, true);
    assert.equal(result.process_owns_key, true);
    assert.equal(result.key_inode_stable, true);
    assert.equal(result.isolated, true);
    assert.equal(Object.isFrozen(result), true);

    const serialized = JSON.stringify(result);
    assert.doesNotMatch(serialized, new RegExp(fixture.base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.doesNotMatch(serialized, /physical-experiment-trust-signing-key-private/);
    assert.equal(Object.hasOwn(result, "key_path"), false);
    assert.equal(Object.hasOwn(result, "custody_root"), false);
    assert.equal(Object.hasOwn(result, "expected_root"), false);
  }));
});

test("exact signing-key probe fails closed on missing acknowledgement, same uid, and a declared root agent", () => {
  const uid = processUid();
  if (uid == null) return;
  withFixture((fixture) => {
    const missingAck = withOperatorEnv(operatorEnv({
      [SANDBOX_ISOLATION_ACK_ENV]: undefined,
    }), () => probeFixture(fixture));
    assert.equal(missingAck.operator_ack_present, false);
    assert.equal(missingAck.isolated, false);

    const sameUid = withOperatorEnv(operatorEnv({
      [SANDBOX_AGENT_UID_ENV]: String(uid),
    }), () => probeFixture(fixture));
    assert.equal(sameUid.agent_distinct, false);
    assert.equal(sameUid.isolated, false);

    const rootAgent = withOperatorEnv(operatorEnv({
      [SANDBOX_AGENT_UID_ENV]: "0",
    }), () => probeFixture(fixture));
    assert.equal(rootAgent.agent_distinct, false);
    assert.equal(rootAgent.isolated, false);
  });
});

test("exact signing-key probe rejects a writable private key and a group-accessible parent", () => {
  withFixture((fixture) => withOperatorEnv(operatorEnv(), () => {
    fs.chmodSync(fixture.keyPath, 0o600);
    const writableKey = probeFixture(fixture);
    assert.equal(writableKey.key_owner_only_mode, true);
    assert.equal(writableKey.key_owner_read_only_mode, false);
    assert.equal(writableKey.isolated, false);

    fs.chmodSync(fixture.keyPath, 0o400);
    fs.chmodSync(fixture.campaignRoot, 0o750);
    const accessibleParent = probeFixture(fixture);
    assert.equal(accessibleParent.parent_chain_owner_only_mode, false);
    assert.equal(accessibleParent.isolated, false);
  }));
});

test("exact signing-key probe rejects key symlinks, parent symlinks, and hard links", () => {
  withFixture((fixture) => withOperatorEnv(operatorEnv(), () => {
    const target = path.join(fixture.base, "symlink-target");
    fs.writeFileSync(target, "target", { mode: 0o400 });
    fs.chmodSync(target, 0o400);
    fs.unlinkSync(fixture.keyPath);
    fs.symlinkSync(target, fixture.keyPath);
    const keySymlink = probeFixture(fixture);
    assert.equal(keySymlink.key_regular_file, false);
    assert.equal(keySymlink.isolated, false);
  }));

  withFixture((fixture) => withOperatorEnv(operatorEnv(), () => {
    const realCampaign = path.join(fixture.base, "real-physical-campaign");
    fs.renameSync(fixture.campaignRoot, realCampaign);
    fs.symlinkSync(realCampaign, fixture.campaignRoot, "dir");
    const parentSymlink = probeFixture(fixture);
    assert.equal(parentSymlink.parent_chain_real_directories, false);
    assert.equal(parentSymlink.isolated, false);
  }));

  withFixture((fixture) => withOperatorEnv(operatorEnv(), () => {
    fs.linkSync(fixture.keyPath, path.join(fixture.expectedRoot, "second-link"));
    const hardLink = probeFixture(fixture);
    assert.equal(hardLink.key_single_link, false);
    assert.equal(hardLink.isolated, false);
  }));
});

test("exact signing-key probe fails closed on containment drift and malformed option objects", () => {
  withFixture((fixture) => withOperatorEnv(operatorEnv(), () => {
    const otherKey = path.join(fixture.custodyRoot, "other-private-key");
    fs.writeFileSync(otherKey, "other", { mode: 0o400 });
    fs.chmodSync(otherKey, 0o400);
    const outsideExpected = probeExactSigningKeyPathIsolation(otherKey, {
      expectedRoot: fixture.expectedRoot,
      custodyRoot: fixture.custodyRoot,
    });
    assert.equal(outsideExpected.key_within_expected_root, false);
    assert.equal(outsideExpected.isolated, false);

    const outsideRoot = path.join(fixture.base, "outside-root");
    const outsideKey = path.join(outsideRoot, "private-key");
    fs.mkdirSync(outsideRoot, { mode: 0o700 });
    fs.chmodSync(outsideRoot, 0o700);
    fs.writeFileSync(outsideKey, "outside", { mode: 0o400 });
    fs.chmodSync(outsideKey, 0o400);
    const outsideCustody = probeExactSigningKeyPathIsolation(outsideKey, {
      expectedRoot: outsideRoot,
      custodyRoot: fixture.custodyRoot,
    });
    assert.equal(outsideCustody.expected_root_within_custody_root, false);
    assert.equal(outsideCustody.isolated, false);

    assert.throws(
      () => probeExactSigningKeyPathIsolation("relative/private-key", {
        expectedRoot: fixture.expectedRoot,
      }),
      /normalized absolute key path/,
    );
    assert.throws(
      () => probeExactSigningKeyPathIsolation(fixture.keyPath, {}),
      /requires expectedRoot/,
    );
    assert.throws(
      () => probeExactSigningKeyPathIsolation(fixture.keyPath, {
        expectedRoot: `${fixture.expectedRoot}${path.sep}..${path.sep}experiment-trust`,
      }),
      /normalized absolute path/,
    );
    assert.throws(
      () => probeExactSigningKeyPathIsolation(fixture.keyPath, {
        expectedRoot: fixture.expectedRoot,
        surprise: true,
      }),
      /unknown fields/,
    );
    assert.throws(
      () => probeExactSigningKeyPathIsolation(fixture.keyPath, new Proxy({
        expectedRoot: fixture.expectedRoot,
      }, {})),
      /options must be an object/,
    );

    let inheritedGetterCalled = false;
    const inherited = Object.create({
      get expectedRoot() {
        inheritedGetterCalled = true;
        return fixture.expectedRoot;
      },
    });
    assert.throws(
      () => probeExactSigningKeyPathIsolation(fixture.keyPath, inherited),
      /plain object/,
    );
    assert.equal(inheritedGetterCalled, false);

    let ownGetterCalled = false;
    const accessor = {};
    Object.defineProperty(accessor, "expectedRoot", {
      enumerable: true,
      get() {
        ownGetterCalled = true;
        return fixture.expectedRoot;
      },
    });
    assert.throws(
      () => probeExactSigningKeyPathIsolation(fixture.keyPath, accessor),
      /enumerable data field/,
    );
    assert.equal(ownGetterCalled, false);
  }));
});

test("exact signing-key probe detects key-inode and parent-chain replacement races", () => {
  withFixture((fixture) => withOperatorEnv(operatorEnv(), () => {
    const realLstatSync = fs.lstatSync;
    let keyReads = 0;
    fs.lstatSync = function lstatWithKeyReplacement(filePath, ...args) {
      const stats = realLstatSync.call(fs, filePath, ...args);
      if (filePath !== fixture.keyPath || ++keyReads !== 2) return stats;
      return new Proxy(stats, {
        get(target, property, receiver) {
          if (property === "ino") return Number(target.ino) + 1;
          return Reflect.get(target, property, receiver);
        },
      });
    };
    let result;
    try {
      result = probeFixture(fixture);
    } finally {
      fs.lstatSync = realLstatSync;
    }
    assert.equal(result.key_inode_stable, false);
    assert.equal(result.isolated, false);
  }));

  withFixture((fixture) => withOperatorEnv(operatorEnv(), () => {
    const realLstatSync = fs.lstatSync;
    let parentReads = 0;
    fs.lstatSync = function lstatWithParentReplacement(filePath, ...args) {
      const stats = realLstatSync.call(fs, filePath, ...args);
      if (filePath !== fixture.campaignRoot || ++parentReads !== 2) return stats;
      return new Proxy(stats, {
        get(target, property, receiver) {
          if (property === "ino") return Number(target.ino) + 1;
          return Reflect.get(target, property, receiver);
        },
      });
    };
    let result;
    try {
      result = probeFixture(fixture);
    } finally {
      fs.lstatSync = realLstatSync;
    }
    assert.equal(result.parent_chain_stable, false);
    assert.equal(result.isolated, false);
  }));
});

test("exact signing-key probe keeps validation stable after Array/Object intrinsic poisoning", (t) => {
  const uid = processUid();
  if (uid == null || uid === 0) {
    t.skip("a positive Mechanism-A proof requires a non-root POSIX uid");
    return;
  }
  withFixture((fixture) => withOperatorEnv(operatorEnv(), () => {
    const originals = {
      arrayIsArray: Array.isArray,
      every: Array.prototype.every,
      find: Array.prototype.find,
      includes: Array.prototype.includes,
      map: Array.prototype.map,
      some: Array.prototype.some,
      getOwnPropertyDescriptor: Object.getOwnPropertyDescriptor,
      getPrototypeOf: Object.getPrototypeOf,
      ownKeys: Reflect.ownKeys,
    };
    const poisoned = () => {
      throw new Error("poisoned intrinsic must not be reached");
    };
    let result;
    try {
      Array.isArray = poisoned;
      Array.prototype.every = poisoned;
      Array.prototype.find = poisoned;
      Array.prototype.includes = poisoned;
      Array.prototype.map = poisoned;
      Array.prototype.some = poisoned;
      Object.getOwnPropertyDescriptor = poisoned;
      Object.getPrototypeOf = poisoned;
      Reflect.ownKeys = poisoned;
      result = probeFixture(fixture);
    } finally {
      Array.isArray = originals.arrayIsArray;
      Array.prototype.every = originals.every;
      Array.prototype.find = originals.find;
      Array.prototype.includes = originals.includes;
      Array.prototype.map = originals.map;
      Array.prototype.some = originals.some;
      Object.getOwnPropertyDescriptor = originals.getOwnPropertyDescriptor;
      Object.getPrototypeOf = originals.getPrototypeOf;
      Reflect.ownKeys = originals.ownKeys;
    }
    assert.equal(result.isolated, true);
  }));
});
