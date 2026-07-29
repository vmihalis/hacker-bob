"use strict";

// Regression locks for the provider-profile-catalog's post-import
// intrinsic-poisoning defenses. Each test poisons ONE global/prototype seam,
// exercises the catalog, and restores the intrinsic in a finally block before
// yielding, so a genuine Map/crypto path is never left corrupted for sibling
// tests. These assert the module keeps authenticating the same representation it
// selects even when Object/Array/RegExp/crypto intrinsics are replaced.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const { hashCanonicalJson } = require("../lib/verification-contracts.js");
const {
  PROFILE_FIELDS,
  buildProviderProfileCatalog,
  normalizeProviderProfile,
  resolveProviderProfile,
} = require("../lib/provider-profile-catalog.js");

const D = (seed) => crypto.createHash("sha256").update(String(seed)).digest("hex");

function profile(overrides = {}) {
  const base = {
    version: 1,
    provider_id: "chameleon_ultra",
    abi_version: "3.0.0",
    provider_version: "2.1.0",
    descriptor_digest: D("descriptor"),
    semantic_manifest_digest: D("manifest"),
    operation_registry_digest: D("opregistry"),
    completion_evidence_domain_digest: D("completion"),
    executor_id: "chameleon_ultra.rf_off_usb_executor",
    semantic_validator_id: "chameleon_ultra.get_app_version_validator",
    ...overrides,
  };
  const basis = { domain: "hacker-bob/provider-profile/v1" };
  for (const field of PROFILE_FIELDS) if (field !== "profile_digest") basis[field] = base[field];
  return { ...base, profile_digest: overrides.profile_digest ?? hashCanonicalJson(basis) };
}

function reviewedDigestsFor(p) {
  return new Set([
    p.descriptor_digest, p.semantic_manifest_digest,
    p.operation_registry_digest, p.completion_evidence_domain_digest,
  ]);
}

function makeIssuer() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const registry_digest = D("trust-registry");
  return {
    publicKey,
    registry_digest,
    issue(receipt_kind, payload) {
      const semantic_digest = hashCanonicalJson({ receipt_kind, payload, registry_digest });
      const signature = crypto.sign(null, Buffer.from(semantic_digest, "hex"), privateKey)
        .toString("base64url");
      return Object.freeze({
        version: 1, receipt_kind, payload: Object.freeze({ ...payload }),
        issuer_registry_digest: registry_digest, semantic_digest,
        signature_scheme: "ed25519", signature,
      });
    },
  };
}

function trustFor(issuer) {
  return { registry_digest: issuer.registry_digest, public_key: issuer.publicKey };
}

test("an Object.prototype setter cannot split the signed profile from the selected one", () => {
  const issuer = makeIssuer();
  const p = profile();
  const catalog = buildProviderProfileCatalog([p], reviewedDigestsFor(p), issuer);
  const evil = profile({ executor_id: "chameleon_ultra.EVIL" });
  // A pollution setter that DEFINES the authentic value on any plain object it
  // touches, so a non-null-proto projection would hash as authentic while a
  // separate lookup returns evil.
  Object.defineProperty(Object.prototype, "executor_id", {
    configurable: true,
    set() {
      Object.defineProperty(this, "executor_id", {
        value: "chameleon_ultra.rf_off_usb_executor",
        enumerable: true, configurable: true, writable: true,
      });
    },
    get() { return undefined; },
  });
  try {
    const hostile = new Map([["chameleon_ultra", evil]]);
    // The polluted evil profile fails its own profile_digest bind (record is
    // null-proto, immune to the setter) rather than being laundered as authentic.
    assert.throws(
      () => resolveProviderProfile({ ...catalog, profiles: hostile }, "chameleon_ultra",
        { trust_registry: trustFor(issuer) }),
      /must be a bounded identifier|does not bind|key does not match/,
    );
  } finally {
    delete Object.prototype.executor_id;
  }
});

test("an Array index setter cannot substitute the selected profile", () => {
  const issuer = makeIssuer();
  const p = profile();
  const catalog = buildProviderProfileCatalog([p], reviewedDigestsFor(p), issuer);
  const original = Object.getOwnPropertyDescriptor(Array.prototype, "0");
  Object.defineProperty(Array.prototype, "0", {
    configurable: true,
    set() {},
    get() { return { ...p, executor_id: "attacker" }; },
  });
  try {
    const selected = resolveProviderProfile(catalog, "chameleon_ultra", { trust_registry: trustFor(issuer) });
    assert.equal(selected.executor_id, "chameleon_ultra.rf_off_usb_executor");
  } finally {
    if (original) Object.defineProperty(Array.prototype, "0", original);
    else delete Array.prototype[0];
  }
});

test("a poisoned Array iterator cannot skip build-time reviewed-digest checks", () => {
  const issuer = makeIssuer();
  const p = profile();
  const realIterator = Array.prototype[Symbol.iterator];
  // eslint-disable-next-line no-extend-native
  Array.prototype[Symbol.iterator] = function* emptyIterator() {};
  try {
    assert.throws(
      () => buildProviderProfileCatalog([profile({ descriptor_digest: D("UNREVIEWED") })],
        reviewedDigestsFor(p), issuer),
      /does not bind|not a reviewed executed-evidence digest/,
    );
  } finally {
    Array.prototype[Symbol.iterator] = realIterator;
  }
});

test("a poisoned RegExp.exec cannot admit a module-path selection id", () => {
  const realExec = RegExp.prototype.exec;
  RegExp.prototype.exec = function poisonedExec() { return null; };
  try {
    assert.throws(
      () => normalizeProviderProfile(profile({ executor_id: "chameleon_ultra./../evil.js" })),
      /must not be a module-path-shaped string|must be namespaced/,
    );
  } finally {
    RegExp.prototype.exec = realExec;
  }
});

test("a polluted Object.prototype.trust_registry cannot supply the verifier key", () => {
  const issuer = makeIssuer();
  const attacker = makeIssuer();
  const p = profile();
  const catalog = buildProviderProfileCatalog([p], reviewedDigestsFor(p), issuer);
  Object.defineProperty(Object.prototype, "trust_registry", {
    configurable: true, value: trustFor(attacker),
  });
  try {
    // resolve WITHOUT an options arg must not inherit the attacker registry.
    assert.throws(() => resolveProviderProfile(catalog, "chameleon_ultra"),
      /requires a trust registry/);
  } finally {
    delete Object.prototype.trust_registry;
  }
});

test("a poisoned Set.prototype.add cannot inject unreviewed digests at build", () => {
  const issuer = makeIssuer();
  const bad = profile({ descriptor_digest: D("UNREVIEWED") });
  const realAdd = Set.prototype.add;
  // eslint-disable-next-line no-extend-native
  Set.prototype.add = function poisonedAdd(v) { realAdd.call(this, v); realAdd.call(this, D("UNREVIEWED")); };
  try {
    // Pass an array reviewed set that OMITS the unreviewed digest; the poisoned
    // add must not be able to smuggle it into the module's derived Set.
    assert.throws(
      () => buildProviderProfileCatalog([bad],
        [bad.semantic_manifest_digest, bad.operation_registry_digest, bad.completion_evidence_domain_digest],
        issuer),
      /is not a reviewed executed-evidence digest/,
    );
  } finally {
    Set.prototype.add = realAdd;
  }
});

test("a huge attacker signature is bounded before base64 decode", () => {
  const issuer = makeIssuer();
  const p = profile();
  const catalog = buildProviderProfileCatalog([p], reviewedDigestsFor(p), issuer);
  const huge = { ...catalog.signed_receipt, signature: "A".repeat(5_000_000) };
  assert.throws(
    () => resolveProviderProfile({ ...catalog, signed_receipt: huge }, "chameleon_ultra",
      { trust_registry: trustFor(issuer) }),
    /signature scheme is unsupported/,
  );
});

test("an Ed448 key with shadowed getters cannot pass the Ed25519 gate", () => {
  const issuer = makeIssuer();
  const p = profile();
  const catalog = buildProviderProfileCatalog([p], reviewedDigestsFor(p), issuer);
  const ed448 = crypto.generateKeyPairSync("ed448").publicKey;
  try { Object.defineProperty(ed448, "asymmetricKeyType", { value: "ed25519", configurable: true }); } catch { /* non-configurable */ }
  try { Object.defineProperty(ed448, "type", { value: "public", configurable: true }); } catch { /* non-configurable */ }
  assert.throws(
    () => resolveProviderProfile(catalog, "chameleon_ultra",
      { trust_registry: { registry_digest: issuer.registry_digest, public_key: ed448 } }),
    /must be an Ed25519 public key/,
  );
});
