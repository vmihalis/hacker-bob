"use strict";

// Signed, immutable provider-profile catalog. A profile is an exact data record
// of scalar ids and digests that lets the MCP composition root select provider
// code BY DATA — never by a cross-package require. A profile can carry only ids
// and digests: never a function, a Proxy, a signer, a parser, or a
// module-path-shaped string. The catalog is signed as a whole (Ed25519 over the
// canonical receipt; the signing key is catalog custody, never a profile field),
// and selection verifies that signature against a caller-supplied trust root.
//
// Post-import intrinsic-poisoning discipline (matching verification-contracts.js):
//   * every trust-critical intrinsic is captured at import and invoked via
//     reflectApply, so a replaced global/prototype method cannot run attacker code;
//   * every DERIVED object/array (hash bases, id lists) is built on a null
//     prototype with a captured Object.defineProperty data descriptor, so an
//     Object.prototype setter or Array index/species hook cannot intercept
//     construction and split the authenticated representation from the selected one;
//   * every own field is read once through a captured getOwnPropertyDescriptor
//     that rejects accessors, so a getter cannot vary a value across reads;
//   * arrays are iterated by index over own elements, never via a poisonable
//     Symbol.iterator; RegExp checks call the captured exec directly, never test;
//   * both the authenticated digest and the selection lookup are derived from ONE
//     genuine Map.forEach pass, so they cannot diverge.
//
// SCOPE — this is groundwork with no live consumer yet. Two honest limits: (1)
// signing uses this module's own Ed25519-over-receipt contract, NOT the shared
// durable-evidence receipt infrastructure; registering `provider_profile_catalog`
// as a durable receipt kind and issuing through the real (async) issuer is a
// separate integration. (2) Build cross-checks each profile digest against a
// reviewed-digest set the CALLER supplies from the executed-evidence registry;
// the module authenticates the signer and the profile-to-digest binding, not the
// provenance of that set, so "selected digests are reviewed" holds only when the
// build-time set was the genuine projection.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");
const {
  hashCanonicalJson,
  isPlainObject,
} = require("./verification-contracts.js");

// --- Captured intrinsics (never re-looked-up after import) ---------------------
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const objectCreate = Object.create;
const objectFreeze = Object.freeze;
const objectDefineProperty = Object.defineProperty;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectHasOwnProperty = Object.prototype.hasOwnProperty;
const arraySort = Array.prototype.sort;
const arrayIsArray = Array.isArray;
const stringStartsWith = String.prototype.startsWith;
const regexpExec = RegExp.prototype.exec;
const SetIntrinsic = Set;
const setPrototypeHas = Set.prototype.has;
const setPrototypeAdd = Set.prototype.add;
const utilIsProxy = utilTypes.isProxy;
const mapPrototype = Map.prototype;
const MapIntrinsic = Map;
const mapForEach = Map.prototype.forEach;
const mapSet = Map.prototype.set;
const mapSizeGetter = Object.getOwnPropertyDescriptor(Map.prototype, "size").get;
const cryptoVerify = crypto.verify;
const CryptoKeyObject = crypto.KeyObject;
const keyObjectType = Object.getOwnPropertyDescriptor(crypto.KeyObject.prototype, "type").get;
// `asymmetricKeyType` is defined on the PublicKeyObject subclass prototype, not
// KeyObject.prototype; capture it by walking a real public key's prototype chain
// at import so a later prototype swap cannot substitute the getter.
const keyObjectAsymmetricType = (() => {
  const probe = crypto.generateKeyPairSync("ed25519").publicKey;
  for (let proto = Object.getPrototypeOf(probe); proto; proto = Object.getPrototypeOf(proto)) {
    const descriptor = Object.getOwnPropertyDescriptor(proto, "asymmetricKeyType");
    if (descriptor && descriptor.get) return descriptor.get;
  }
  throw new Error("could not capture the KeyObject asymmetricKeyType getter");
})();
const bufferFrom = Buffer.from;

function apply(fn, receiver, args) {
  return reflectApply(fn, receiver, args);
}
function createNull() {
  return reflectApply(objectCreate, Object, [null]);
}
function freeze(value) {
  return reflectApply(objectFreeze, Object, [value]);
}
function hasOwn(target, key) {
  return apply(objectHasOwnProperty, target, [key]);
}
// Define an own enumerable data property via [[DefineOwnProperty]] (captured),
// bypassing any inherited [[Set]] accessor. The descriptor is a null-proto
// dictionary so ToPropertyDescriptor cannot consult a polluted Object.prototype.
function defineData(target, key, value) {
  const descriptor = createNull();
  descriptor.value = value;
  descriptor.enumerable = true;
  descriptor.configurable = true;
  descriptor.writable = true;
  apply(objectDefineProperty, Object, [target, key, descriptor]);
}
// Read one own DATA property (accessors rejected). A getter can never run, so a
// value cannot vary across reads.
function ownDataValue(target, key) {
  const descriptor = apply(objectGetOwnPropertyDescriptor, Object, [target, key]);
  if (!descriptor || !hasOwn(descriptor, "value") || !descriptor.enumerable) {
    return { present: false, value: undefined };
  }
  return { present: true, value: descriptor.value };
}
// Own array length via a captured descriptor read (length is a non-enumerable
// data property, so it must not go through the enumerable-only ownDataValue).
// A Proxy array is rejected: its length trap can report different values across
// reads (array length is non-configurable but writable, so the proxy invariant
// does not pin it), which would allow a bound-check vs iteration TOCTOU.
function arrayLength(array) {
  if (apply(utilIsProxy, utilTypes, [array])) {
    throw new Error("provider profile catalog expected a non-Proxy array");
  }
  const descriptor = apply(objectGetOwnPropertyDescriptor, Object, [array, "length"]);
  if (!descriptor || !hasOwn(descriptor, "value") || !Number.isSafeInteger(descriptor.value)) {
    throw new Error("provider profile catalog expected a genuine array");
  }
  return descriptor.value;
}
// Index-iterate an own-index array (my frozen constants or an engine-created
// array) without invoking a poisonable Symbol.iterator; reads hit own elements.
function eachIndexed(array, fn) {
  const length = arrayLength(array);
  for (let index = 0; index < length; index += 1) fn(array[index], index);
}
function reMatches(re, value) {
  return apply(regexpExec, re, [value]) !== null;
}
function startsWith(value, prefix) {
  return apply(stringStartsWith, value, [prefix]);
}

const PROVIDER_PROFILE_VERSION = 1;
const PROVIDER_PROFILE_CATALOG_VERSION = 1;
const PROVIDER_PROFILE_CATALOG_RECEIPT_KIND = "provider_profile_catalog";
const PROFILE_DIGEST_DOMAIN = "hacker-bob/provider-profile/v1";
const CATALOG_DIGEST_DOMAIN = "hacker-bob/provider-profile-catalog/v1";
const MAX_PROFILES = 256;

const SHA256_RE = /^[a-f0-9]{64}$/;
// An Ed25519 signature is exactly 64 bytes → 86 base64url chars (no padding).
// Bounding it before Buffer.from prevents proportional decode/allocation on a
// huge attacker signature string.
const ED25519_SIGNATURE_RE = /^[A-Za-z0-9_-]{86}$/;
const IDENTIFIER_RE = /^[a-z][a-z0-9._-]{0,127}$/;
const SEMVER_RE = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const MODULE_PATH_RE = /[/\\]|\.(?:js|cjs|mjs|ts|cts|mts|node|wasm|json|py)$/i;

const PROFILE_ID_FIELDS = freeze(["provider_id", "executor_id", "semantic_validator_id"]);
const PROFILE_DIGEST_FIELDS = freeze([
  "descriptor_digest",
  "semantic_manifest_digest",
  "operation_registry_digest",
  "completion_evidence_domain_digest",
]);
const PROFILE_NAMESPACED_ID_FIELDS = freeze(["executor_id", "semantic_validator_id"]);
const PROFILE_FIELDS = freeze([
  "version",
  "provider_id",
  "abi_version",
  "provider_version",
  "descriptor_digest",
  "semantic_manifest_digest",
  "operation_registry_digest",
  "completion_evidence_domain_digest",
  "executor_id",
  "semantic_validator_id",
  "profile_digest",
]);
const RECEIPT_PAYLOAD_FIELDS = freeze(["version", "catalog_digest", "provider_ids"]);

function fieldIncluded(field) {
  let found = false;
  eachIndexed(PROFILE_FIELDS, (name) => { if (name === field) found = true; });
  return found;
}

// A profile carries ids and digests only. Reject every non-scalar and any string
// that looks like a module path — selection can never smuggle in a callback,
// signer, parser, or require target.
function assertScalarProfileValue(field, value) {
  const type = typeof value;
  if (type === "function") {
    throw new Error(`provider_profile.${field} must be a scalar id or digest, not a function`);
  }
  if (type === "object" && value !== null) {
    throw new Error(`provider_profile.${field} must be a scalar id or digest, not an object/Proxy`);
  }
  if (type === "string" && reMatches(MODULE_PATH_RE, value)) {
    throw new Error(`provider_profile.${field} must not be a module-path-shaped string`);
  }
  return value;
}

function assertIntegerVersion(value, label) {
  if (value !== PROVIDER_PROFILE_VERSION) throw new Error(`${label} version is invalid`);
  return value;
}
function assertDigest(value, label) {
  if (typeof value !== "string" || !reMatches(SHA256_RE, value)) {
    throw new Error(`${label} must be a lowercase sha256 digest`);
  }
  return value;
}
function assertIdentifier(value, label) {
  if (typeof value !== "string" || !reMatches(IDENTIFIER_RE, value)) {
    throw new Error(`${label} must be a bounded identifier`);
  }
  return value;
}
function assertSemver(value, label) {
  if (typeof value !== "string" || !reMatches(SEMVER_RE, value)) {
    throw new Error(`${label} must be a semantic version`);
  }
  return value;
}

// Null-proto projection of a validated record's fields (minus profile_digest),
// built via defineData so no inherited setter can intercept construction;
// hashCanonicalJson reads it poison-immunely.
function profileBasis(record) {
  const basis = createNull();
  defineData(basis, "domain", PROFILE_DIGEST_DOMAIN);
  eachIndexed(PROFILE_FIELDS, (field) => {
    if (field !== "profile_digest") defineData(basis, field, record[field]);
  });
  return basis;
}
function profileBasisDigest(record) {
  return hashCanonicalJson(profileBasis(record));
}

// Exact, closed, scalar-only normalization. Returns a frozen null-proto record.
// isPlainObject rejects a Proxy input; every field value is read ONCE via
// ownDataValue (accessors rejected) and that single snapshot drives both
// validation and the record, so a hostile input cannot show a safe value to the
// check and a module-path/callback to the copy.
function normalizeProviderProfile(input) {
  if (!isPlainObject(input)) throw new Error("provider_profile must be a plain data object");
  const keys = apply(reflectOwnKeys, Reflect, [input]);
  eachIndexed(keys, (key) => {
    if (typeof key !== "string") throw new Error("provider_profile cannot contain symbol fields");
    if (!fieldIncluded(key)) throw new Error(`provider_profile has unknown field: ${key}`);
  });
  const values = createNull();
  eachIndexed(PROFILE_FIELDS, (field) => {
    const cell = ownDataValue(input, field);
    if (!cell.present) throw new Error(`provider_profile.${field} must be an enumerable data field`);
    defineData(values, field, cell.value);
    assertScalarProfileValue(field, cell.value);
  });
  assertIntegerVersion(values.version, "provider_profile");
  eachIndexed(PROFILE_ID_FIELDS, (field) => assertIdentifier(values[field], `provider_profile.${field}`));
  assertSemver(values.abi_version, "provider_profile.abi_version");
  assertSemver(values.provider_version, "provider_profile.provider_version");
  eachIndexed(PROFILE_DIGEST_FIELDS, (field) => assertDigest(values[field], `provider_profile.${field}`));
  assertDigest(values.profile_digest, "provider_profile.profile_digest");
  // Selection ids are opaque lookup keys, never require targets. Requiring them
  // to be namespaced under their provider_id also excludes a bare module
  // specifier (child_process, fs, an installed package) from ever being an id.
  eachIndexed(PROFILE_NAMESPACED_ID_FIELDS, (field) => {
    if (!startsWith(values[field], `${values.provider_id}.`)) {
      throw new Error(`provider_profile.${field} must be namespaced under its provider_id`);
    }
  });
  const record = createNull();
  eachIndexed(PROFILE_FIELDS, (field) => defineData(record, field, values[field]));
  if (profileBasisDigest(record) !== values.profile_digest) {
    throw new Error("provider_profile.profile_digest does not bind the profile fields");
  }
  return freeze(record);
}

// A genuine reviewed-digest Set from the executed-evidence registry (own
// prototype is Set.prototype — no instanceof, whose Symbol.hasInstance is
// poisonable). A profile digest not in this set cannot be built.
function reviewedDigestSet(registryOrSet) {
  if (registryOrSet != null && typeof registryOrSet === "object"
      && reflectApply(objectGetPrototypeOf, Object, [registryOrSet]) === SetIntrinsic.prototype) {
    return registryOrSet;
  }
  if (apply(arrayIsArray, null, [registryOrSet])) {
    const set = new SetIntrinsic();
    eachIndexed(registryOrSet, (digest) => { apply(setPrototypeAdd, set, [digest]); });
    return set;
  }
  throw new Error(
    "buildProviderProfileCatalog requires a reviewed-digest Set/array derived from the executed-evidence registry",
  );
}

// Build a poison-immune (own-index) array of null-proto per-profile projections
// from the sorted trusted records — the SAME frozen records selection returns.
function catalogBasis(sortedIds, trusted) {
  const profiles = [];
  eachIndexed(sortedIds, (id, index) => {
    const record = trusted[id];
    const projection = createNull();
    eachIndexed(PROFILE_FIELDS, (field) => defineData(projection, field, record[field]));
    defineData(profiles, `${index}`, projection);
  });
  const basis = createNull();
  defineData(basis, "domain", CATALOG_DIGEST_DOMAIN);
  defineData(basis, "version", PROVIDER_PROFILE_CATALOG_VERSION);
  defineData(basis, "profiles", profiles);
  return basis;
}

// Sorted own string keys of a null-proto trusted lookup (engine-created key
// array is own-index; captured sort orders it deterministically).
function sortedProviderIds(trusted) {
  const keys = apply(reflectOwnKeys, Reflect, [trusted]);
  apply(arraySort, keys, [(a, b) => (a < b ? -1 : a > b ? 1 : 0)]);
  return keys;
}

function equalStringArrays(a, b) {
  if (!apply(arrayIsArray, null, [a]) || !apply(arrayIsArray, null, [b])) return false;
  const lenA = arrayLength(a);
  const lenB = arrayLength(b);
  if (lenA !== lenB) return false;
  for (let index = 0; index < lenA; index += 1) {
    if (a[index] !== b[index]) return false;
  }
  return true;
}

// Build and sign the catalog. `reviewedDigests` is the reviewed-digest set from
// the executed-evidence registry. `issuer.issue(kind, payload)` returns a signed
// receipt; the signing key lives in issuer custody, never a profile field.
function buildProviderProfileCatalog(profiles, reviewedDigests, issuer) {
  if (!apply(arrayIsArray, null, [profiles]) || profiles.length === 0) {
    throw new Error("buildProviderProfileCatalog requires a non-empty profiles array");
  }
  if (profiles.length > MAX_PROFILES) {
    throw new Error(`buildProviderProfileCatalog accepts at most ${MAX_PROFILES} profiles`);
  }
  if (!issuer || typeof issuer.issue !== "function") {
    throw new Error("buildProviderProfileCatalog requires a durable-evidence receipt issuer");
  }
  const digests = reviewedDigestSet(reviewedDigests);
  const trusted = createNull();
  eachIndexed(profiles, (raw) => {
    const profile = normalizeProviderProfile(raw);
    eachIndexed(PROFILE_DIGEST_FIELDS, (field) => {
      if (!apply(setPrototypeHas, digests, [profile[field]])) {
        throw new Error(
          `provider_profile ${profile.provider_id}.${field} is not a reviewed executed-evidence digest`,
        );
      }
    });
    if (hasOwn(trusted, profile.provider_id)) {
      throw new Error(`provider_profile provider_id ${profile.provider_id} is duplicated`);
    }
    defineData(trusted, profile.provider_id, profile);
  });
  const sortedIds = sortedProviderIds(trusted);
  const catalogDigest = hashCanonicalJson(catalogBasis(sortedIds, trusted));
  const signedReceipt = issuer.issue(PROVIDER_PROFILE_CATALOG_RECEIPT_KIND, {
    version: PROVIDER_PROFILE_CATALOG_VERSION,
    catalog_digest: catalogDigest,
    provider_ids: sortedIds,
  });
  if (!signedReceipt || typeof signedReceipt !== "object"
      || signedReceipt.payload == null
      || signedReceipt.payload.catalog_digest !== catalogDigest) {
    throw new Error("provider profile catalog signature does not bind the catalog digest");
  }
  const byId = new MapIntrinsic();
  eachIndexed(sortedIds, (id) => { apply(mapSet, byId, [id, trusted[id]]); });
  return freeze({
    version: PROVIDER_PROFILE_CATALOG_VERSION,
    catalog_digest: catalogDigest,
    provider_ids: freeze(sortedIds),
    profiles: byId,
    signed_receipt: signedReceipt,
  });
}

function assertEd25519PublicKey(publicKey) {
  if (!(publicKey instanceof CryptoKeyObject)) return false;
  // Read type/asymmetricKeyType via the captured native getters, not instance
  // properties an attacker could shadow on an Ed448 key.
  let type;
  let asymmetric;
  try {
    type = apply(keyObjectType, publicKey, []);
    asymmetric = apply(keyObjectAsymmetricType, publicKey, []);
  } catch {
    return false;
  }
  return type === "public" && asymmetric === "ed25519";
}

// Reconstruct the signed payload from its exact own fields (accessor-safe,
// bounded), so an unbounded/nested attacker receipt is never fully traversed and
// a stateful getter cannot bind one digest then verify another.
function boundedReceiptPayload(payload) {
  const keys = apply(reflectOwnKeys, Reflect, [payload]);
  eachIndexed(keys, (key) => {
    let known = false;
    eachIndexed(RECEIPT_PAYLOAD_FIELDS, (field) => { if (field === key) known = true; });
    if (!known) throw new Error("provider profile catalog receipt payload has an unexpected field");
  });
  const version = ownDataValue(payload, "version");
  const catalogDigest = ownDataValue(payload, "catalog_digest");
  const providerIds = ownDataValue(payload, "provider_ids");
  if (version.value !== PROVIDER_PROFILE_CATALOG_VERSION) {
    throw new Error("provider profile catalog receipt payload version is invalid");
  }
  if (typeof catalogDigest.value !== "string" || !reMatches(SHA256_RE, catalogDigest.value)) {
    throw new Error("provider profile catalog receipt payload catalog_digest is malformed");
  }
  if (!apply(arrayIsArray, null, [providerIds.value])
      || arrayLength(providerIds.value) > MAX_PROFILES) {
    throw new Error("provider profile catalog receipt payload provider_ids is malformed");
  }
  const ids = [];
  eachIndexed(providerIds.value, (id, index) => {
    if (typeof id !== "string") throw new Error("provider profile catalog receipt provider_id is malformed");
    defineData(ids, `${index}`, id);
  });
  const out = createNull();
  defineData(out, "version", version.value);
  defineData(out, "catalog_digest", catalogDigest.value);
  defineData(out, "provider_ids", ids);
  return out;
}

// Module-owned signature verification. Every field is read via ownDataValue (a
// getter can never run to swap crypto.verify mid-check); the payload is
// reconstructed into a bounded null-proto snapshot; verification dispatches
// through captured crypto.verify / Buffer.from.
function verifyCatalogReceiptSignature(inputReceipt, trustRegistry, expectedCatalogDigest, expectedIds) {
  if (!isPlainObject(trustRegistry)) {
    throw new Error(
      "provider profile catalog verification requires a trust registry { registry_digest, public_key }",
    );
  }
  const registryDigest = ownDataValue(trustRegistry, "registry_digest").value;
  const publicKey = ownDataValue(trustRegistry, "public_key").value;
  if (typeof registryDigest !== "string" || !reMatches(SHA256_RE, registryDigest)) {
    throw new Error("provider profile catalog trust registry registry_digest must be a sha256 digest");
  }
  // The scheme label alone is not the algorithm: crypto.verify(null, …)
  // dispatches on the key's real type, so require a genuine Ed25519 public key.
  if (!assertEd25519PublicKey(publicKey)) {
    throw new Error("provider profile catalog trust registry public_key must be an Ed25519 public key");
  }
  if (!isPlainObject(inputReceipt)) {
    throw new Error("provider profile catalog signed receipt is malformed");
  }
  const receiptKind = ownDataValue(inputReceipt, "receipt_kind").value;
  const issuerRegistryDigest = ownDataValue(inputReceipt, "issuer_registry_digest").value;
  const signatureScheme = ownDataValue(inputReceipt, "signature_scheme").value;
  const signature = ownDataValue(inputReceipt, "signature").value;
  const semanticDigest = ownDataValue(inputReceipt, "semantic_digest").value;
  const payloadValue = ownDataValue(inputReceipt, "payload").value;
  if (!isPlainObject(payloadValue)) {
    throw new Error("provider profile catalog signed receipt is malformed");
  }
  const payload = boundedReceiptPayload(payloadValue);
  if (receiptKind !== PROVIDER_PROFILE_CATALOG_RECEIPT_KIND) {
    throw new Error("provider profile catalog receipt kind is invalid");
  }
  if (issuerRegistryDigest !== registryDigest) {
    throw new Error("provider profile catalog receipt issuer is not the trusted registry");
  }
  if (signatureScheme !== "ed25519" || typeof signature !== "string"
      || !reMatches(ED25519_SIGNATURE_RE, signature)) {
    throw new Error("provider profile catalog receipt signature scheme is unsupported");
  }
  if (payload.catalog_digest !== expectedCatalogDigest) {
    throw new Error("provider profile catalog signature does not bind the catalog digest");
  }
  if (!equalStringArrays(payload.provider_ids, expectedIds)) {
    throw new Error("provider profile catalog signature does not bind the provider id set");
  }
  const canonicalSemantic = createNull();
  defineData(canonicalSemantic, "receipt_kind", receiptKind);
  defineData(canonicalSemantic, "payload", payload);
  defineData(canonicalSemantic, "registry_digest", issuerRegistryDigest);
  if (semanticDigest !== hashCanonicalJson(canonicalSemantic)) {
    throw new Error("provider profile catalog receipt semantic digest drift");
  }
  let verified = false;
  try {
    verified = apply(cryptoVerify, crypto, [
      null,
      apply(bufferFrom, Buffer, [semanticDigest, "hex"]),
      publicKey,
      apply(bufferFrom, Buffer, [signature, "base64url"]),
    ]);
  } catch {
    verified = false;
  }
  if (verified !== true) {
    throw new Error("provider profile catalog receipt signature is invalid");
  }
}

// Validate the catalog once and return a TRUSTED null-proto lookup built from the
// exact profiles the signature authenticates. profiles must be a genuine Map,
// drained via the captured forEach so no attacker iterator runs; the trusted
// lookup, the authenticated digest, and the id set are all derived from that one
// genuine pass, so authentication and selection cannot diverge.
function validateCatalog(catalog, options) {
  if (!isPlainObject(catalog)) {
    throw new Error("provider profile catalog is malformed");
  }
  if (ownDataValue(catalog, "version").value !== PROVIDER_PROFILE_CATALOG_VERSION) {
    throw new Error("provider profile catalog version is invalid");
  }
  const profilesMap = ownDataValue(catalog, "profiles").value;
  if (profilesMap == null || typeof profilesMap !== "object"
      || reflectApply(objectGetPrototypeOf, Object, [profilesMap]) !== mapPrototype) {
    throw new Error("provider profile catalog profiles must be a genuine Map");
  }
  if (apply(mapSizeGetter, profilesMap, []) > MAX_PROFILES) {
    throw new Error(`provider profile catalog exceeds ${MAX_PROFILES} profiles`);
  }
  const trusted = createNull();
  apply(mapForEach, profilesMap, [(value, key) => {
    const profile = normalizeProviderProfile(value);
    if (key !== profile.provider_id) {
      throw new Error("provider profile catalog key does not match its profile provider_id");
    }
    if (hasOwn(trusted, profile.provider_id)) {
      throw new Error(`provider profile catalog duplicates provider_id ${profile.provider_id}`);
    }
    defineData(trusted, profile.provider_id, profile);
  }]);
  const sortedIds = sortedProviderIds(trusted);
  const recomputed = hashCanonicalJson(catalogBasis(sortedIds, trusted));
  if (recomputed !== ownDataValue(catalog, "catalog_digest").value) {
    throw new Error("provider profile catalog digest does not bind its profiles");
  }
  // The trust root is read as an OWN property of a plain-object options bag: a
  // polluted Object.prototype.trust_registry is inherited, never own, so it can
  // never supply the verifier's key when a caller omits options.
  if (!isPlainObject(options)) {
    throw new Error("provider profile catalog options must be a plain object");
  }
  const trustCell = ownDataValue(options, "trust_registry");
  if (!trustCell.present) {
    throw new Error(
      "provider profile catalog selection requires a trust registry: pass { trust_registry }",
    );
  }
  verifyCatalogReceiptSignature(
    ownDataValue(catalog, "signed_receipt").value,
    trustCell.value,
    recomputed,
    sortedIds,
  );
  return trusted;
}

// Verify the catalog on load: recompute its digest and id set from the
// authenticated profiles, confirm the receipt binds both, and verify its Ed25519
// signature against the caller-supplied trust registry.
function assertProviderProfileCatalog(catalog, options = {}) {
  validateCatalog(catalog, options);
  return catalog;
}

// Data-only selection: resolve (catalog, provider_id) to the reviewed frozen
// profile. Selection is trust-bearing, so it REQUIRES the trust registry
// ({ registry_digest, public_key }); the module verifies the Ed25519 signature
// itself and reads only the trusted null-proto lookup, never catalog.profiles.get().
// NOTE: the reviewed-digest guarantee holds only when the build-time set was the
// genuine executed-evidence projection (see SCOPE) — the module authenticates the
// signer, not the set's provenance.
function resolveProviderProfile(catalog, providerId, options = {}) {
  const trusted = validateCatalog(catalog, options);
  if (typeof providerId !== "string" || !hasOwn(trusted, providerId)) {
    throw new Error(`provider profile ${providerId} is not in the catalog`);
  }
  return trusted[providerId];
}

module.exports = {
  PROVIDER_PROFILE_VERSION,
  PROVIDER_PROFILE_CATALOG_VERSION,
  PROVIDER_PROFILE_CATALOG_RECEIPT_KIND,
  PROFILE_FIELDS,
  PROFILE_DIGEST_FIELDS,
  assertProviderProfileCatalog,
  buildProviderProfileCatalog,
  normalizeProviderProfile,
  resolveProviderProfile,
};
