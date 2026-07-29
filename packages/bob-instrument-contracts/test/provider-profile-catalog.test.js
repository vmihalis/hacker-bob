"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const { hashCanonicalJson } = require("../lib/verification-contracts.js");
const {
  PROFILE_FIELDS,
  PROVIDER_PROFILE_CATALOG_RECEIPT_KIND,
  assertProviderProfileCatalog,
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

function reviewedDigestsFor(...profiles) {
  const set = new Set();
  for (const p of profiles) {
    for (const f of [
      "descriptor_digest", "semantic_manifest_digest",
      "operation_registry_digest", "completion_evidence_domain_digest",
    ]) set.add(p[f]);
  }
  return set;
}

// Faithful stand-in for a createDurableEvidenceReceiptIssuer instance: signs the
// payload with Ed25519 and returns a receipt shaped like the real one. The real
// issuer is drop-in (same issue() contract) once a provider_profile_catalog
// durable-receipt kind is registered.
function makeIssuer() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const registry_digest = D("trust-registry");
  const issuer = {
    publicKey,
    registry_digest,
    issue(receipt_kind, payload) {
      const semantic_digest = hashCanonicalJson({ receipt_kind, payload, registry_digest });
      const signature = crypto
        .sign(null, Buffer.from(semantic_digest, "hex"), privateKey)
        .toString("base64url");
      return Object.freeze({
        version: 1,
        receipt_kind,
        payload: Object.freeze({ ...payload }),
        issuer_registry_digest: registry_digest,
        semantic_digest,
        signature_scheme: "ed25519",
        signature,
      });
    },
  };
  return issuer;
}

function trustFor(issuer) {
  return { registry_digest: issuer.registry_digest, public_key: issuer.publicKey };
}

test("normalizeProviderProfile accepts an exact scalar profile", () => {
  const p = normalizeProviderProfile(profile());
  assert.equal(p.provider_id, "chameleon_ultra");
  assert.equal(Object.getPrototypeOf(p), null);
  assert.ok(Object.isFrozen(p));
});

test("normalizeProviderProfile rejects a function value (no callbacks)", () => {
  assert.throws(() => normalizeProviderProfile(profile({ executor_id: () => "x" })),
    /must be a scalar id or digest, not a function/);
});

test("normalizeProviderProfile rejects an object/Proxy value", () => {
  const tainted = { ...profile(), semantic_validator_id: new Proxy({}, {}) };
  assert.throws(() => normalizeProviderProfile(tainted),
    /must be a scalar id or digest, not an object\/Proxy/);
});

test("normalizeProviderProfile rejects a Proxy profile", () => {
  assert.throws(() => normalizeProviderProfile(new Proxy(profile(), {})),
    /must be a plain data object/);
});

test("normalizeProviderProfile rejects module-path-shaped strings", () => {
  assert.throws(() => normalizeProviderProfile(profile({
    executor_id: "../bob-instrument-chameleon/lib/rf-off-usb-executor.js",
  })), /must not be a module-path-shaped string/);
});

test("normalizeProviderProfile rejects a mismatched profile_digest", () => {
  assert.throws(() => normalizeProviderProfile(profile({ profile_digest: D("wrong") })),
    /profile_digest does not bind/);
});

test("buildProviderProfileCatalog signs, cross-checks digests, and asserts", () => {
  const p = profile();
  const issuer = makeIssuer();
  const catalog = buildProviderProfileCatalog([p], reviewedDigestsFor(p), issuer);
  assert.equal(catalog.receipt_kind, undefined);
  assert.equal(catalog.signed_receipt.receipt_kind, PROVIDER_PROFILE_CATALOG_RECEIPT_KIND);
  assert.equal(catalog.signed_receipt.payload.catalog_digest, catalog.catalog_digest);
  // signature-verifying assert (the module owns the Ed25519 check)
  assert.equal(
    assertProviderProfileCatalog(catalog, { trust_registry: trustFor(issuer) }),
    catalog,
  );
  // data-only selection (selection requires the trust registry)
  const selected = resolveProviderProfile(catalog, "chameleon_ultra", { trust_registry: trustFor(issuer) });
  assert.equal(selected.executor_id, "chameleon_ultra.rf_off_usb_executor");
});

test("buildProviderProfileCatalog rejects a digest not in the reviewed set", () => {
  const p = profile();
  const issuer = makeIssuer();
  // omit completion_evidence_domain_digest from the reviewed set
  const partial = reviewedDigestsFor(p);
  partial.delete(p.completion_evidence_domain_digest);
  assert.throws(() => buildProviderProfileCatalog([p], partial, issuer),
    /completion_evidence_domain_digest is not a reviewed executed-evidence digest/);
});

test("assertProviderProfileCatalog rejects a tampered catalog digest", () => {
  const p = profile();
  const issuer = makeIssuer();
  const catalog = buildProviderProfileCatalog([p], reviewedDigestsFor(p), issuer);
  const tampered = { ...catalog, catalog_digest: D("tamper") };
  assert.throws(() => assertProviderProfileCatalog(tampered, { trust_registry: trustFor(issuer) }),
    /catalog digest does not bind its profiles/);
});

test("assertProviderProfileCatalog rejects a wrong-key trust registry", () => {
  const p = profile();
  const issuer = makeIssuer();
  const other = makeIssuer();
  const catalog = buildProviderProfileCatalog([p], reviewedDigestsFor(p), issuer);
  assert.throws(() => assertProviderProfileCatalog(catalog, { trust_registry: trustFor(other) }),
    /issuer is not the trusted registry|signature is invalid/);
});

test("resolveProviderProfile throws for an unknown provider_id", () => {
  const p = profile();
  const issuer = makeIssuer();
  const catalog = buildProviderProfileCatalog([p], reviewedDigestsFor(p), issuer);
  assert.throws(() => resolveProviderProfile(catalog, "unknown_provider", { trust_registry: trustFor(issuer) }),
    /is not in the catalog/);
});

test("resolveProviderProfile refuses to select without a trust registry", () => {
  const p = profile();
  const issuer = makeIssuer();
  const catalog = buildProviderProfileCatalog([p], reviewedDigestsFor(p), issuer);
  assert.throws(() => resolveProviderProfile(catalog, "chameleon_ultra"),
    /requires a trust registry/);
});

test("resolveProviderProfile rejects a wrong-key catalog on the selection path", () => {
  const p = profile();
  const issuer = makeIssuer();
  const other = makeIssuer();
  const catalog = buildProviderProfileCatalog([p], reviewedDigestsFor(p), issuer);
  assert.throws(
    () => resolveProviderProfile(catalog, "chameleon_ultra", { trust_registry: trustFor(other) }),
    /issuer is not the trusted registry|signature is invalid/,
  );
});

test("resolveProviderProfile selects from the authenticated iteration, not a hostile .get()", () => {
  const p = profile();
  const issuer = makeIssuer();
  const catalog = buildProviderProfileCatalog([p], reviewedDigestsFor(p), issuer);
  const authentic = catalog.profiles.get("chameleon_ultra");
  // A Map that iterates the authentic (signed) entry but whose .get() returns a
  // hostile executor must not let .get() drive selection.
  const hostile = new Map([["chameleon_ultra", authentic]]);
  hostile.get = () => ({ ...authentic, executor_id: "attacker.evil_executor" });
  const forged = { ...catalog, profiles: hostile };
  const selected = resolveProviderProfile(forged, "chameleon_ultra", { trust_registry: trustFor(issuer) });
  assert.equal(selected.executor_id, "chameleon_ultra.rf_off_usb_executor");
});

test("assertProviderProfileCatalog rejects a catalog key that does not match its profile", () => {
  const p = profile();
  const issuer = makeIssuer();
  const catalog = buildProviderProfileCatalog([p], reviewedDigestsFor(p), issuer);
  const mismatched = new Map([["wrong_id", catalog.profiles.get("chameleon_ultra")]]);
  assert.throws(() => assertProviderProfileCatalog({ ...catalog, profiles: mismatched }),
    /key does not match its profile provider_id/);
});

test("verification rejects a Proxy signed receipt (no stateful payload)", () => {
  const p = profile();
  const issuer = makeIssuer();
  const catalog = buildProviderProfileCatalog([p], reviewedDigestsFor(p), issuer);
  const proxyReceipt = new Proxy(catalog.signed_receipt, {});
  assert.throws(
    () => assertProviderProfileCatalog({ ...catalog, signed_receipt: proxyReceipt },
      { trust_registry: trustFor(issuer) }),
    /signed receipt is malformed/,
  );
});

test("verification requires an Ed25519 public key", () => {
  const p = profile();
  const issuer = makeIssuer();
  const catalog = buildProviderProfileCatalog([p], reviewedDigestsFor(p), issuer);
  const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey;
  for (const badKey of [rsa, "pem-string", Buffer.from("x")]) {
    assert.throws(
      () => assertProviderProfileCatalog(catalog,
        { trust_registry: { registry_digest: issuer.registry_digest, public_key: badKey } }),
      /public_key must be an Ed25519 public key/,
    );
  }
});

test("validateCatalog rejects a non-genuine Map (subclass)", () => {
  const p = profile();
  const issuer = makeIssuer();
  const catalog = buildProviderProfileCatalog([p], reviewedDigestsFor(p), issuer);
  class EvilMap extends Map {}
  const sub = new EvilMap(catalog.profiles);
  assert.throws(
    () => assertProviderProfileCatalog({ ...catalog, profiles: sub }, { trust_registry: trustFor(issuer) }),
    /must be a genuine Map/,
  );
});

test("normalizeProviderProfile rejects a bare (non-namespaced) selection id", () => {
  assert.throws(() => normalizeProviderProfile(profile({ executor_id: "child_process" })),
    /must be namespaced under its provider_id/);
});
