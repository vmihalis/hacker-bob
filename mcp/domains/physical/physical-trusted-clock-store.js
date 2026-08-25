"use strict";

// Restart-durable trusted-time integration boundary for Plane-PH.
//
// The legacy physical-trusted-clock port is a deliberately non-authorizing
// callback conformance surface.  This module owns the fixed production-shaped
// adapter instead: it reads one exact signed authority bundle from a private
// filesystem root, samples a captured monotonic source, and commits every
// accepted high-water observation through the fixed trusted-clock consumer of
// the independently retained monotonic owner.  No callback, readiness boolean,
// digest assertion, or mutable resolver is accepted from the caller.
//
// Node's process.hrtime source is useful for conformance but does not establish
// a restart-stable OS boot epoch or a separately isolated native clock service.
// Consequently ports opened by this implementation remain explicitly
// non-authorizing until a native fixed adapter supplies those missing facts.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const {
  claimProductionPhysicalTrustedClockMonotonicOwner,
  compareAndSetProductionPhysicalTrustedClockMonotonicOwnerState,
  readProductionPhysicalTrustedClockMonotonicOwnerHistory,
  readProductionPhysicalTrustedClockMonotonicOwnerState,
} = require("./physical-monotonic-owner.js");
const {
  MAX_MAPPING_LIFETIME_MS,
  MAX_UNCERTAINTY_MS,
  TRUSTED_CLOCK_PORT_MODE,
  assertPhysicalTrustedClockValidityWindow,
  createPhysicalTrustedClockPort,
  normalizeSignedPhysicalClockMapping,
  physicalClockMappingSigningMessage,
  publicKeyDigest,
  samplePhysicalTrustedClock,
} = require("./physical-trusted-clock.js");
const { sessionsRoot } = require("../../core/io/paths.js");
const { canonicalJson, hashCanonicalJson } = require("../../core/verification/verification-contracts.js");

const PRODUCTION_PHYSICAL_TRUSTED_CLOCK_VERSION = 1;
const PHYSICAL_TRUSTED_CLOCK_OWNER_CONTEXT_DOMAIN =
  "hacker-bob/physical-trusted-clock-high-water/v1";
const PHYSICAL_TRUSTED_CLOCK_AUTHORITY_BUNDLE_DOMAIN =
  "hacker-bob/physical-trusted-clock-authority-bundle/v1";
const PHYSICAL_TRUSTED_CLOCK_TRUST_DOMAIN =
  "hacker-bob/physical-trusted-clock-current-trust/v1";
const PHYSICAL_TRUSTED_CLOCK_TRUST_SIGNING_DOMAIN =
  "hacker-bob/physical-trusted-clock-current-trust-signature/v1";
const PHYSICAL_TRUSTED_CLOCK_AUTHORITY_FILE = "current-authority-bundle.json";
const FIXED_SOURCE_ASSURANCE = "node_process_hrtime_fixed_adapter_conformance_only";
const FIXED_SOURCE_BLOCKER =
  "native_restart_stable_monotonic_epoch_and_isolated_clock_service_not_installed";
const HASH_RE = /^[a-f0-9]{64}$/u;
const IDENTIFIER_RE = /^[a-z][a-z0-9._-]{0,127}$/u;
const TOKEN_RE = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const SIGNATURE_RE = /^[A-Za-z0-9_-]{86}$/u;
const MAX_AUTHORITY_BYTES = 1024 * 1024;
const MAX_EPOCH_HISTORY = 256;
const MAX_SAMPLE_CAS_ATTEMPTS = 4;

const PROCESS_HRTIME_BIGINT = process.hrtime.bigint.bind(process.hrtime);
const PORTS = new WeakSet();
const PORT_STATE = new WeakMap();
const SAMPLES = new WeakSet();
const SAMPLE_STATE = new WeakMap();

function trustedClockStoreError(code, message, cause = null) {
  const error = new Error(`${code}: ${message}`);
  error.code = code;
  if (cause != null) Object.defineProperty(error, "cause", { value: cause });
  return error;
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || utilTypes.isProxy(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactRecord(input, label, fields) {
  if (!isPlainObject(input)) {
    throw trustedClockStoreError(
      "physical_trusted_clock_contract_invalid",
      `${label} must be an exact plain data object`,
    );
  }
  const keys = Reflect.ownKeys(input);
  const expected = fields.slice().sort();
  const actual = keys.slice().sort();
  if (keys.some((key) => typeof key !== "string")
      || actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) {
    throw trustedClockStoreError(
      "physical_trusted_clock_contract_invalid",
      `${label} fields are not exact`,
    );
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const result = {};
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw trustedClockStoreError(
        "physical_trusted_clock_contract_invalid",
        `${label}.${field} must be an enumerable data property`,
      );
    }
    result[field] = descriptor.value;
  }
  return result;
}

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function digest(value, label) {
  if (typeof value !== "string" || !HASH_RE.test(value)) {
    throw trustedClockStoreError(
      "physical_trusted_clock_contract_invalid",
      `${label} must be a lowercase SHA-256 digest`,
    );
  }
  return value;
}

function identifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_RE.test(value)) {
    throw trustedClockStoreError(
      "physical_trusted_clock_contract_invalid",
      `${label} must be a lowercase identifier`,
    );
  }
  return value;
}

function token(value, label, prefix) {
  if (typeof value !== "string" || !TOKEN_RE.test(value)
      || !value.startsWith(`${prefix}:`) || value.length === prefix.length + 1) {
    throw trustedClockStoreError(
      "physical_trusted_clock_contract_invalid",
      `${label} must be a bounded ${prefix} token`,
    );
  }
  return value;
}

function integer(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw trustedClockStoreError(
      "physical_trusted_clock_contract_invalid",
      `${label} must be a safe integer from ${minimum} through ${maximum}`,
    );
  }
  return value;
}

function timestamp(value, label) {
  if (typeof value !== "string") {
    throw trustedClockStoreError(
      "physical_trusted_clock_contract_invalid",
      `${label} must be a canonical UTC timestamp`,
    );
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw trustedClockStoreError(
      "physical_trusted_clock_contract_invalid",
      `${label} must be a canonical UTC timestamp`,
    );
  }
  return value;
}

function canonicalSignature(value, label) {
  if (typeof value !== "string" || !SIGNATURE_RE.test(value)) {
    throw trustedClockStoreError(
      "physical_trusted_clock_signature_invalid",
      `${label} must be canonical Ed25519 base64url`,
    );
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) {
    throw trustedClockStoreError(
      "physical_trusted_clock_signature_invalid",
      `${label} must be canonical Ed25519 base64url`,
    );
  }
  return value;
}

function importEd25519PublicKey(spkiBase64url, label) {
  if (typeof spkiBase64url !== "string" || spkiBase64url.length < 40
      || spkiBase64url.length > 256 || !/^[A-Za-z0-9_-]+$/u.test(spkiBase64url)) {
    throw trustedClockStoreError(
      "physical_trusted_clock_key_invalid",
      `${label} must be canonical SPKI base64url`,
    );
  }
  const bytes = Buffer.from(spkiBase64url, "base64url");
  if (bytes.toString("base64url") !== spkiBase64url) {
    throw trustedClockStoreError(
      "physical_trusted_clock_key_invalid",
      `${label} must be canonical SPKI base64url`,
    );
  }
  let key;
  try {
    key = crypto.createPublicKey({ key: bytes, type: "spki", format: "der" });
  } catch (cause) {
    throw trustedClockStoreError(
      "physical_trusted_clock_key_invalid",
      `${label} is not a valid public key`,
      cause,
    );
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    throw trustedClockStoreError(
      "physical_trusted_clock_key_invalid",
      `${label} must be an Ed25519 public key`,
    );
  }
  return key;
}

function physicalClockTrustSigningMessage(payloadDigest) {
  return Buffer.from(
    `${PHYSICAL_TRUSTED_CLOCK_TRUST_SIGNING_DOMAIN}\0${digest(
      payloadDigest,
      "trusted clock trust payload digest",
    )}`,
    "utf8",
  );
}

function normalizeTrustPayload(input, label) {
  const value = exactRecord(input, label, [
    "version",
    "target_domain",
    "session_nucleus_hash",
    "trusted",
    "revoked",
    "clock_id",
    "monotonic_epoch_id",
    "current_mapping_generation",
    "current_signed_mapping_digest",
    "trust_root_epoch",
    "authority_epoch",
    "revocation_generation",
    "signer_key_id",
    "signer_public_key_digest",
    "signer_public_key_spki_base64url",
    "trust_root_key_id",
    "trust_root_public_key_digest",
    "not_before",
    "expires_at",
  ]);
  if (value.version !== PRODUCTION_PHYSICAL_TRUSTED_CLOCK_VERSION
      || typeof value.trusted !== "boolean" || typeof value.revoked !== "boolean") {
    throw trustedClockStoreError(
      "physical_trusted_clock_contract_invalid",
      `${label} version or trust disposition is invalid`,
    );
  }
  if (typeof value.target_domain !== "string" || value.target_domain.length < 1
      || value.target_domain.length > 253 || value.target_domain !== value.target_domain.trim()) {
    throw trustedClockStoreError(
      "physical_trusted_clock_contract_invalid",
      `${label}.target_domain is invalid`,
    );
  }
  const notBefore = timestamp(value.not_before, `${label}.not_before`);
  const expiresAt = timestamp(value.expires_at, `${label}.expires_at`);
  const lifetime = Date.parse(expiresAt) - Date.parse(notBefore);
  if (lifetime <= 0 || lifetime > MAX_MAPPING_LIFETIME_MS) {
    throw trustedClockStoreError(
      "physical_trusted_clock_contract_invalid",
      `${label} validity must be positive and no longer than 24 hours`,
    );
  }
  const signerPublicKey = importEd25519PublicKey(
    value.signer_public_key_spki_base64url,
    `${label}.signer_public_key_spki_base64url`,
  );
  const signerPublicKeyDigest = publicKeyDigest(signerPublicKey);
  if (digest(value.signer_public_key_digest, `${label}.signer_public_key_digest`)
      !== signerPublicKeyDigest) {
    throw trustedClockStoreError(
      "physical_trusted_clock_key_invalid",
      `${label}.signer_public_key_digest does not bind its SPKI key`,
    );
  }
  return deepFreeze({
    version: PRODUCTION_PHYSICAL_TRUSTED_CLOCK_VERSION,
    target_domain: value.target_domain,
    session_nucleus_hash: digest(value.session_nucleus_hash, `${label}.session_nucleus_hash`),
    trusted: value.trusted,
    revoked: value.revoked,
    clock_id: token(value.clock_id, `${label}.clock_id`, "physical-clock"),
    monotonic_epoch_id: digest(value.monotonic_epoch_id, `${label}.monotonic_epoch_id`),
    current_mapping_generation: integer(
      value.current_mapping_generation,
      `${label}.current_mapping_generation`,
      1,
    ),
    current_signed_mapping_digest: digest(
      value.current_signed_mapping_digest,
      `${label}.current_signed_mapping_digest`,
    ),
    trust_root_epoch: integer(value.trust_root_epoch, `${label}.trust_root_epoch`, 1),
    authority_epoch: integer(value.authority_epoch, `${label}.authority_epoch`, 1),
    revocation_generation: integer(
      value.revocation_generation,
      `${label}.revocation_generation`,
      0,
    ),
    signer_key_id: token(value.signer_key_id, `${label}.signer_key_id`, "clock-key"),
    signer_public_key_digest: signerPublicKeyDigest,
    signer_public_key_spki_base64url: value.signer_public_key_spki_base64url,
    trust_root_key_id: token(
      value.trust_root_key_id,
      `${label}.trust_root_key_id`,
      "clock-trust-root",
    ),
    trust_root_public_key_digest: digest(
      value.trust_root_public_key_digest,
      `${label}.trust_root_public_key_digest`,
    ),
    not_before: notBefore,
    expires_at: expiresAt,
  });
}

function normalizeSignedPhysicalClockTrustStatement(
  input,
  label = "signed_physical_clock_trust_statement",
) {
  const value = exactRecord(input, label, [
    "version",
    "domain",
    "payload",
    "payload_digest",
    "scheme",
    "signature",
    "trust_statement_digest",
    "trust_root_public_key_spki_base64url",
  ]);
  if (value.version !== PRODUCTION_PHYSICAL_TRUSTED_CLOCK_VERSION
      || value.domain !== PHYSICAL_TRUSTED_CLOCK_TRUST_DOMAIN
      || value.scheme !== "ed25519") {
    throw trustedClockStoreError(
      "physical_trusted_clock_contract_invalid",
      `${label} domain, version, or signature scheme is invalid`,
    );
  }
  const payload = normalizeTrustPayload(value.payload, `${label}.payload`);
  const payloadDigest = digest(value.payload_digest, `${label}.payload_digest`);
  if (payloadDigest !== hashCanonicalJson(payload)) {
    throw trustedClockStoreError(
      "physical_trusted_clock_digest_invalid",
      `${label}.payload_digest does not bind its canonical payload`,
    );
  }
  const rootPublicKey = importEd25519PublicKey(
    value.trust_root_public_key_spki_base64url,
    `${label}.trust_root_public_key_spki_base64url`,
  );
  const rootPublicKeyDigest = publicKeyDigest(rootPublicKey);
  if (rootPublicKeyDigest !== payload.trust_root_public_key_digest) {
    throw trustedClockStoreError(
      "physical_trusted_clock_key_invalid",
      `${label} trust-root digest does not bind its SPKI key`,
    );
  }
  const signature = canonicalSignature(value.signature, `${label}.signature`);
  let verified = false;
  try {
    verified = crypto.verify(
      null,
      physicalClockTrustSigningMessage(payloadDigest),
      rootPublicKey,
      Buffer.from(signature, "base64url"),
    );
  } catch {
    verified = false;
  }
  if (!verified) {
    throw trustedClockStoreError(
      "physical_trusted_clock_signature_invalid",
      `${label} signature is invalid`,
    );
  }
  const basis = {
    version: PRODUCTION_PHYSICAL_TRUSTED_CLOCK_VERSION,
    domain: PHYSICAL_TRUSTED_CLOCK_TRUST_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
    trust_root_public_key_spki_base64url: value.trust_root_public_key_spki_base64url,
  };
  const statementDigest = digest(
    value.trust_statement_digest,
    `${label}.trust_statement_digest`,
  );
  if (statementDigest !== hashCanonicalJson(basis)) {
    throw trustedClockStoreError(
      "physical_trusted_clock_digest_invalid",
      `${label}.trust_statement_digest is invalid`,
    );
  }
  return Object.freeze({
    document: deepFreeze({ ...basis, trust_statement_digest: statementDigest }),
    payload,
    rootPublicKey,
    signerPublicKey: importEd25519PublicKey(
      payload.signer_public_key_spki_base64url,
      `${label}.payload.signer_public_key_spki_base64url`,
    ),
  });
}

function normalizePhysicalTrustedClockAuthorityBundle(
  input,
  label = "physical_trusted_clock_authority_bundle",
) {
  const value = exactRecord(input, label, [
    "version", "domain", "signed_mapping", "signed_trust", "bundle_digest",
  ]);
  if (value.version !== PRODUCTION_PHYSICAL_TRUSTED_CLOCK_VERSION
      || value.domain !== PHYSICAL_TRUSTED_CLOCK_AUTHORITY_BUNDLE_DOMAIN) {
    throw trustedClockStoreError(
      "physical_trusted_clock_contract_invalid",
      `${label} domain or version is invalid`,
    );
  }
  const mapping = normalizeSignedPhysicalClockMapping(
    value.signed_mapping,
    `${label}.signed_mapping`,
  );
  const trust = normalizeSignedPhysicalClockTrustStatement(
    value.signed_trust,
    `${label}.signed_trust`,
  );
  const payload = trust.payload;
  for (const field of [
    "clock_id",
    "monotonic_epoch_id",
    "trust_root_epoch",
    "authority_epoch",
    "revocation_generation",
    "signer_key_id",
    "signer_public_key_digest",
  ]) {
    if (mapping.payload[field] !== payload[field]) {
      throw trustedClockStoreError(
        "physical_trusted_clock_authority_drift",
        `${label} mapping and current trust disagree on ${field}`,
      );
    }
  }
  if (mapping.payload.mapping_generation !== payload.current_mapping_generation
      || mapping.signed_mapping_digest !== payload.current_signed_mapping_digest) {
    throw trustedClockStoreError(
      "physical_trusted_clock_authority_drift",
      `${label} trust statement does not name the exact current mapping`,
    );
  }
  let mappingSignatureValid = false;
  try {
    mappingSignatureValid = crypto.verify(
      null,
      physicalClockMappingSigningMessage(mapping.payload_digest),
      trust.signerPublicKey,
      Buffer.from(mapping.signature, "base64url"),
    );
  } catch {
    mappingSignatureValid = false;
  }
  if (!mappingSignatureValid) {
    throw trustedClockStoreError(
      "physical_trusted_clock_signature_invalid",
      `${label} mapping signature is invalid`,
    );
  }
  const basis = {
    version: PRODUCTION_PHYSICAL_TRUSTED_CLOCK_VERSION,
    domain: PHYSICAL_TRUSTED_CLOCK_AUTHORITY_BUNDLE_DOMAIN,
    signed_mapping: mapping,
    signed_trust: trust.document,
  };
  const bundleDigest = digest(value.bundle_digest, `${label}.bundle_digest`);
  if (bundleDigest !== hashCanonicalJson(basis)) {
    throw trustedClockStoreError(
      "physical_trusted_clock_digest_invalid",
      `${label}.bundle_digest is invalid`,
    );
  }
  return Object.freeze({
    document: deepFreeze({ ...basis, bundle_digest: bundleDigest }),
    mapping,
    trust,
  });
}

function disjointPaths(left, right) {
  const leftToRight = path.relative(left, right);
  const rightToLeft = path.relative(right, left);
  return leftToRight !== "" && rightToLeft !== ""
    && (leftToRight === ".." || leftToRight.startsWith(`..${path.sep}`))
    && (rightToLeft === ".." || rightToLeft.startsWith(`..${path.sep}`));
}

function rootIdentity(root, stats) {
  return hashCanonicalJson({
    domain: "hacker-bob/physical-monotonic-owner-root/v1",
    root_path_digest: crypto.createHash("sha256").update(root).digest("hex"),
    device: String(stats.dev),
    inode: String(stats.ino),
    owner_uid: stats.uid,
    mode: stats.mode & 0o777,
  });
}

function assertAuthorityRoot(rootInput) {
  if (typeof rootInput !== "string" || !path.isAbsolute(rootInput)
      || path.normalize(rootInput) !== rootInput) {
    throw trustedClockStoreError(
      "physical_trusted_clock_storage_invalid",
      "authority_root must be a normalized absolute path",
    );
  }
  let stats;
  try {
    stats = fs.lstatSync(rootInput);
  } catch (cause) {
    throw trustedClockStoreError(
      "physical_trusted_clock_storage_invalid",
      "trusted-clock authority root is unavailable",
      cause,
    );
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (!stats.isDirectory() || stats.isSymbolicLink() || uid == null || stats.uid !== uid
      || (stats.mode & 0o077) !== 0) {
    throw trustedClockStoreError(
      "physical_trusted_clock_storage_invalid",
      "trusted-clock authority root must be a real owner-only directory owned by this process",
    );
  }
  const root = fs.realpathSync(rootInput);
  const bobSessionsRoot = fs.realpathSync(sessionsRoot());
  if (!disjointPaths(root, bobSessionsRoot)) {
    throw trustedClockStoreError(
      "physical_trusted_clock_storage_invalid",
      "trusted-clock authority root must be disjoint from the entire Bob sessions tree",
    );
  }
  return Object.freeze({ root, identityDigest: rootIdentity(root, stats) });
}

function readAuthorityBundle(state) {
  const rootBefore = assertAuthorityRoot(state.authorityRoot);
  if (rootBefore.root !== state.authorityRoot
      || rootBefore.identityDigest !== state.authorityRootIdentityDigest) {
    throw trustedClockStoreError(
      "physical_trusted_clock_storage_drift",
      "trusted-clock authority root identity changed",
    );
  }
  const filePath = path.join(state.authorityRoot, PHYSICAL_TRUSTED_CLOCK_AUTHORITY_FILE);
  let before;
  try {
    before = fs.lstatSync(filePath);
  } catch (cause) {
    throw trustedClockStoreError(
      "physical_trusted_clock_storage_invalid",
      "trusted-clock authority bundle is unavailable",
      cause,
    );
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
      || before.uid !== uid || (before.mode & 0o777) !== 0o600
      || before.size < 2 || before.size > MAX_AUTHORITY_BYTES) {
    throw trustedClockStoreError(
      "physical_trusted_clock_storage_invalid",
      "trusted-clock authority bundle custody is invalid",
    );
  }
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  let parsed;
  try {
    const opened = fs.fstatSync(descriptor);
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.nlink !== 1
        || opened.size !== before.size) {
      throw trustedClockStoreError(
        "physical_trusted_clock_storage_drift",
        "trusted-clock authority bundle changed during open",
      );
    }
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count < 1) {
        throw trustedClockStoreError(
          "physical_trusted_clock_storage_invalid",
          "trusted-clock authority bundle is truncated",
        );
      }
      offset += count;
    }
    try {
      parsed = JSON.parse(bytes.toString("utf8"));
    } catch {
      throw trustedClockStoreError(
        "physical_trusted_clock_storage_invalid",
        "trusted-clock authority bundle is not canonical JSON data",
      );
    } finally {
      bytes.fill(0);
    }
  } finally {
    fs.closeSync(descriptor);
  }
  const rootAfter = assertAuthorityRoot(state.authorityRoot);
  if (rootAfter.identityDigest !== state.authorityRootIdentityDigest) {
    throw trustedClockStoreError(
      "physical_trusted_clock_storage_drift",
      "trusted-clock authority root changed during bundle read",
    );
  }
  return normalizePhysicalTrustedClockAuthorityBundle(parsed);
}

function fixedMonotonicMilliseconds() {
  const value = PROCESS_HRTIME_BIGINT() / 1_000_000n;
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw trustedClockStoreError(
      "physical_trusted_clock_source_invalid",
      "fixed monotonic source exceeded the supported range",
    );
  }
  return Number(value);
}

const HIGH_WATER_FIELDS = Object.freeze([
  "version",
  "target_domain",
  "session_nucleus_hash",
  "clock_id",
  "authority_root_identity_digest",
  "trust_root_public_key_digest",
  "observation_sequence",
  "monotonic_epoch_id",
  "seen_monotonic_epoch_ids",
  "mapping_generation",
  "signed_mapping_digest",
  "monotonic_ms",
  "trusted_utc",
  "trusted_utc_earliest",
  "trusted_utc_latest",
  "max_uncertainty_ms",
  "trust_root_epoch",
  "authority_epoch",
  "revocation_generation",
  "signer_key_id",
  "signer_public_key_digest",
  "trust_statement_digest",
  "bundle_digest",
  "source_assurance",
  "monotonic_revision",
  "monotonic_position",
  "monotonic_value_digest",
]);

function highWaterValueDigest(body) {
  const semantic = { ...body };
  delete semantic.monotonic_revision;
  delete semantic.monotonic_position;
  delete semantic.monotonic_value_digest;
  return hashCanonicalJson({
    domain: "hacker-bob/physical-trusted-clock-high-water-value/v1",
    ...semantic,
  });
}

function normalizeEpochHistory(value, label) {
  if (!Array.isArray(value) || utilTypes.isProxy(value)
      || value.length < 1 || value.length > MAX_EPOCH_HISTORY) {
    throw trustedClockStoreError(
      "physical_trusted_clock_state_invalid",
      `${label} must contain 1..${MAX_EPOCH_HISTORY} epoch digests`,
    );
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const result = [];
  const seen = new Set();
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw trustedClockStoreError(
        "physical_trusted_clock_state_invalid",
        `${label} must be a dense data array`,
      );
    }
    const epoch = digest(descriptor.value, `${label}[${index}]`);
    if (seen.has(epoch)) {
      throw trustedClockStoreError(
        "physical_trusted_clock_epoch_fork",
        `${label} reuses a monotonic epoch`,
      );
    }
    seen.add(epoch);
    result.push(epoch);
  }
  const keys = Reflect.ownKeys(value).filter((key) => key !== "length");
  if (keys.length !== value.length || keys.some((key, index) => key !== String(index))) {
    throw trustedClockStoreError(
      "physical_trusted_clock_state_invalid",
      `${label} contains non-index fields`,
    );
  }
  return Object.freeze(result);
}

function normalizeHighWaterState(input, binding, label) {
  const value = exactRecord(input, label, HIGH_WATER_FIELDS);
  if (value.version !== PRODUCTION_PHYSICAL_TRUSTED_CLOCK_VERSION
      || value.target_domain !== binding.targetDomain
      || value.session_nucleus_hash !== binding.sessionNucleusHash
      || value.clock_id !== binding.clockId
      || value.authority_root_identity_digest !== binding.authorityRootIdentityDigest
      || value.trust_root_public_key_digest !== binding.trustRootPublicKeyDigest
      || value.source_assurance !== FIXED_SOURCE_ASSURANCE) {
    throw trustedClockStoreError(
      "physical_trusted_clock_state_binding_drift",
      `${label} binding changed`,
    );
  }
  const history = normalizeEpochHistory(
    value.seen_monotonic_epoch_ids,
    `${label}.seen_monotonic_epoch_ids`,
  );
  const body = {
    version: PRODUCTION_PHYSICAL_TRUSTED_CLOCK_VERSION,
    target_domain: binding.targetDomain,
    session_nucleus_hash: binding.sessionNucleusHash,
    clock_id: binding.clockId,
    authority_root_identity_digest: binding.authorityRootIdentityDigest,
    trust_root_public_key_digest: binding.trustRootPublicKeyDigest,
    observation_sequence: integer(value.observation_sequence, `${label}.observation_sequence`, 1),
    monotonic_epoch_id: digest(value.monotonic_epoch_id, `${label}.monotonic_epoch_id`),
    seen_monotonic_epoch_ids: history,
    mapping_generation: integer(value.mapping_generation, `${label}.mapping_generation`, 1),
    signed_mapping_digest: digest(value.signed_mapping_digest, `${label}.signed_mapping_digest`),
    monotonic_ms: integer(value.monotonic_ms, `${label}.monotonic_ms`, 0),
    trusted_utc: timestamp(value.trusted_utc, `${label}.trusted_utc`),
    trusted_utc_earliest: timestamp(
      value.trusted_utc_earliest,
      `${label}.trusted_utc_earliest`,
    ),
    trusted_utc_latest: timestamp(value.trusted_utc_latest, `${label}.trusted_utc_latest`),
    max_uncertainty_ms: integer(
      value.max_uncertainty_ms,
      `${label}.max_uncertainty_ms`,
      0,
      MAX_UNCERTAINTY_MS,
    ),
    trust_root_epoch: integer(value.trust_root_epoch, `${label}.trust_root_epoch`, 1),
    authority_epoch: integer(value.authority_epoch, `${label}.authority_epoch`, 1),
    revocation_generation: integer(
      value.revocation_generation,
      `${label}.revocation_generation`,
      0,
    ),
    signer_key_id: token(value.signer_key_id, `${label}.signer_key_id`, "clock-key"),
    signer_public_key_digest: digest(
      value.signer_public_key_digest,
      `${label}.signer_public_key_digest`,
    ),
    trust_statement_digest: digest(
      value.trust_statement_digest,
      `${label}.trust_statement_digest`,
    ),
    bundle_digest: digest(value.bundle_digest, `${label}.bundle_digest`),
    source_assurance: FIXED_SOURCE_ASSURANCE,
    monotonic_revision: integer(value.monotonic_revision, `${label}.monotonic_revision`, 1),
    monotonic_position: integer(value.monotonic_position, `${label}.monotonic_position`, 0),
    monotonic_value_digest: digest(
      value.monotonic_value_digest,
      `${label}.monotonic_value_digest`,
    ),
  };
  if (body.observation_sequence !== body.monotonic_revision
      || body.monotonic_position !== body.monotonic_revision - 1
      || history.at(-1) !== body.monotonic_epoch_id
      || body.monotonic_value_digest !== highWaterValueDigest(body)
      || Date.parse(body.trusted_utc_earliest) > Date.parse(body.trusted_utc)
      || Date.parse(body.trusted_utc) > Date.parse(body.trusted_utc_latest)) {
    throw trustedClockStoreError(
      "physical_trusted_clock_state_invalid",
      `${label} sequence, epoch, digest, or uncertainty interval is invalid`,
    );
  }
  return deepFreeze(body);
}

function assertHighWaterTransition(previous, next, label) {
  if (previous == null) {
    if (next.monotonic_revision !== 1 || next.monotonic_position !== 0
        || next.seen_monotonic_epoch_ids.length !== 1) {
      throw trustedClockStoreError(
        "physical_trusted_clock_state_invalid",
        `${label} genesis is invalid`,
      );
    }
    return next;
  }
  for (const field of [
    "target_domain",
    "session_nucleus_hash",
    "clock_id",
    "authority_root_identity_digest",
    "trust_root_public_key_digest",
    "source_assurance",
  ]) {
    if (previous[field] !== next[field]) {
      throw trustedClockStoreError(
        "physical_trusted_clock_state_binding_drift",
        `${label}.${field} changed`,
      );
    }
  }
  if (next.monotonic_revision !== previous.monotonic_revision + 1
      || next.monotonic_position !== previous.monotonic_position + 1
      || next.observation_sequence !== previous.observation_sequence + 1) {
    throw trustedClockStoreError(
      "physical_trusted_clock_state_invalid",
      `${label} skipped a durable observation`,
    );
  }
  for (const field of ["mapping_generation", "trust_root_epoch", "authority_epoch",
    "revocation_generation"]) {
    if (next[field] < previous[field]) {
      throw trustedClockStoreError(
        "physical_trusted_clock_rollback",
        `${label}.${field} moved backwards`,
      );
    }
  }
  if (next.mapping_generation === previous.mapping_generation
      && next.signed_mapping_digest !== previous.signed_mapping_digest) {
    throw trustedClockStoreError(
      "physical_trusted_clock_mapping_fork",
      `${label} forked the signed mapping at one generation`,
    );
  }
  const epochChanged = next.monotonic_epoch_id !== previous.monotonic_epoch_id;
  if (epochChanged) {
    if (previous.seen_monotonic_epoch_ids.includes(next.monotonic_epoch_id)) {
      throw trustedClockStoreError(
        "physical_trusted_clock_epoch_fork",
        `${label} reused a retired monotonic epoch`,
      );
    }
    if (next.seen_monotonic_epoch_ids.length !== previous.seen_monotonic_epoch_ids.length + 1
        || previous.seen_monotonic_epoch_ids.some((epoch, index) => (
          next.seen_monotonic_epoch_ids[index] !== epoch
        ))
        || next.seen_monotonic_epoch_ids.at(-1) !== next.monotonic_epoch_id
        || next.mapping_generation <= previous.mapping_generation
        || (next.trust_root_epoch <= previous.trust_root_epoch
          && next.authority_epoch <= previous.authority_epoch)) {
      throw trustedClockStoreError(
        "physical_trusted_clock_epoch_transition_invalid",
        `${label} epoch transition lacks a fresh signed authority generation`,
      );
    }
  } else {
    if (next.seen_monotonic_epoch_ids.length !== previous.seen_monotonic_epoch_ids.length
        || previous.seen_monotonic_epoch_ids.some((epoch, index) => (
          next.seen_monotonic_epoch_ids[index] !== epoch
        ))) {
      throw trustedClockStoreError(
        "physical_trusted_clock_epoch_fork",
        `${label} rewrote epoch history`,
      );
    }
    if (next.monotonic_ms < previous.monotonic_ms) {
      throw trustedClockStoreError(
        "physical_trusted_clock_rollback",
        `${label} monotonic source moved backwards within one epoch`,
      );
    }
  }
  for (const field of ["trusted_utc", "trusted_utc_earliest", "trusted_utc_latest"]) {
    if (Date.parse(next[field]) < Date.parse(previous[field])) {
      throw trustedClockStoreError(
        "physical_trusted_clock_rollback",
        `${label}.${field} moved backwards`,
      );
    }
  }
  const authorityAdvanced = next.trust_root_epoch > previous.trust_root_epoch
    || next.authority_epoch > previous.authority_epoch
    || next.revocation_generation > previous.revocation_generation;
  if ((next.signer_key_id !== previous.signer_key_id
        || next.signer_public_key_digest !== previous.signer_public_key_digest)
      && !authorityAdvanced) {
    throw trustedClockStoreError(
      "physical_trusted_clock_authority_drift",
      `${label} rotated the mapping signer without an authority epoch advance`,
    );
  }
  if (next.trust_statement_digest !== previous.trust_statement_digest
      && !authorityAdvanced && next.mapping_generation === previous.mapping_generation) {
    throw trustedClockStoreError(
      "physical_trusted_clock_trust_fork",
      `${label} forked current trust without a monotonic authority advance`,
    );
  }
  return next;
}

function replayHighWaterHistory(ownerPort, binding) {
  const history = readProductionPhysicalTrustedClockMonotonicOwnerHistory(ownerPort);
  let previous = null;
  const normalized = [];
  for (let index = 0; index < history.length; index += 1) {
    const current = normalizeHighWaterState(
      history[index],
      binding,
      `physical trusted-clock high-water history ${index + 1}`,
    );
    assertHighWaterTransition(previous, current, `physical trusted-clock transition ${index + 1}`);
    normalized.push(current);
    previous = current;
  }
  const current = readProductionPhysicalTrustedClockMonotonicOwnerState(ownerPort);
  if ((current == null) !== (previous == null)
      || (current != null && canonicalJson(current) !== canonicalJson(previous))) {
    throw trustedClockStoreError(
      "physical_trusted_clock_state_invalid",
      "trusted-clock current high-water does not match replayed owner history",
    );
  }
  return Object.freeze(normalized);
}

function trustResult(bundle) {
  const payload = bundle.trust.payload;
  return Object.freeze({
    version: PRODUCTION_PHYSICAL_TRUSTED_CLOCK_VERSION,
    trusted: payload.trusted,
    revoked: payload.revoked,
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    current_mapping_generation: payload.current_mapping_generation,
    current_signed_mapping_digest: payload.current_signed_mapping_digest,
    trust_root_epoch: payload.trust_root_epoch,
    authority_epoch: payload.authority_epoch,
    revocation_generation: payload.revocation_generation,
    signer_key_id: payload.signer_key_id,
    signer_public_key_digest: payload.signer_public_key_digest,
    public_key: bundle.trust.signerPublicKey,
  });
}

function sampleFixedBundle(state, bundle) {
  const payload = bundle.trust.payload;
  if (payload.target_domain !== state.binding.targetDomain
      || payload.session_nucleus_hash !== state.binding.sessionNucleusHash
      || payload.clock_id !== state.binding.clockId
      || payload.trust_root_public_key_digest !== state.binding.trustRootPublicKeyDigest) {
    throw trustedClockStoreError(
      "physical_trusted_clock_authority_drift",
      "trusted-clock authority bundle belongs to another session, clock, or trust root",
    );
  }
  const internalPort = createPhysicalTrustedClockPort({
    port_id: state.portId,
    clock_id: state.binding.clockId,
    monotonic_epoch_id: bundle.mapping.payload.monotonic_epoch_id,
    uncertainty_ceiling_ms: state.uncertaintyCeilingMs,
    read_monotonic_ms: fixedMonotonicMilliseconds,
    read_signed_mapping: () => bundle.mapping,
    resolve_current_trust: () => trustResult(bundle),
  });
  const sample = samplePhysicalTrustedClock(internalPort);
  assertPhysicalTrustedClockValidityWindow(sample, {
    not_before: payload.not_before,
    expires_at: payload.expires_at,
  }, "signed trusted-clock current-trust validity");
  return sample;
}

function nextHighWaterState(state, previous, sample, bundle) {
  const revision = previous == null ? 1 : previous.monotonic_revision + 1;
  const epochChanged = previous != null
    && sample.monotonic_epoch_id !== previous.monotonic_epoch_id;
  if (epochChanged && previous.seen_monotonic_epoch_ids.length >= MAX_EPOCH_HISTORY) {
    throw trustedClockStoreError(
      "physical_trusted_clock_capacity_exhausted",
      "trusted-clock monotonic epoch history is full",
    );
  }
  const epochHistory = previous == null
    ? [sample.monotonic_epoch_id]
    : epochChanged
      ? [...previous.seen_monotonic_epoch_ids, sample.monotonic_epoch_id]
      : [...previous.seen_monotonic_epoch_ids];
  const body = {
    version: PRODUCTION_PHYSICAL_TRUSTED_CLOCK_VERSION,
    target_domain: state.binding.targetDomain,
    session_nucleus_hash: state.binding.sessionNucleusHash,
    clock_id: state.binding.clockId,
    authority_root_identity_digest: state.binding.authorityRootIdentityDigest,
    trust_root_public_key_digest: state.binding.trustRootPublicKeyDigest,
    observation_sequence: revision,
    monotonic_epoch_id: sample.monotonic_epoch_id,
    seen_monotonic_epoch_ids: epochHistory,
    mapping_generation: sample.mapping_generation,
    signed_mapping_digest: sample.signed_mapping_digest,
    monotonic_ms: sample.monotonic_ms,
    trusted_utc: sample.trusted_utc,
    trusted_utc_earliest: sample.trusted_utc_earliest,
    trusted_utc_latest: sample.trusted_utc_latest,
    max_uncertainty_ms: sample.max_uncertainty_ms,
    trust_root_epoch: sample.trust_root_epoch,
    authority_epoch: sample.authority_epoch,
    revocation_generation: sample.revocation_generation,
    signer_key_id: bundle.trust.payload.signer_key_id,
    signer_public_key_digest: bundle.trust.payload.signer_public_key_digest,
    trust_statement_digest: bundle.trust.document.trust_statement_digest,
    bundle_digest: bundle.document.bundle_digest,
    source_assurance: FIXED_SOURCE_ASSURANCE,
    monotonic_revision: revision,
    monotonic_position: revision - 1,
    monotonic_value_digest: null,
  };
  body.monotonic_value_digest = highWaterValueDigest(body);
  const normalized = normalizeHighWaterState(
    body,
    state.binding,
    "physical trusted-clock next high-water state",
  );
  return assertHighWaterTransition(
    previous,
    normalized,
    "physical trusted-clock next high-water transition",
  );
}

function rejectSerialization() {
  throw trustedClockStoreError(
    "physical_trusted_clock_serialization_refused",
    "restart-durable trusted-clock ports are process-local capabilities",
  );
}

function openProductionPhysicalTrustedClockPort(input) {
  const value = exactRecord(input, "production physical trusted-clock input", [
    "version",
    "target_domain",
    "session_nucleus_hash",
    "port_id",
    "clock_id",
    "uncertainty_ceiling_ms",
    "authority_root",
    "monotonic_head_owner",
  ]);
  if (value.version !== PRODUCTION_PHYSICAL_TRUSTED_CLOCK_VERSION
      || typeof value.target_domain !== "string" || value.target_domain.length < 1
      || value.target_domain.length > 253 || value.target_domain !== value.target_domain.trim()) {
    throw trustedClockStoreError(
      "physical_trusted_clock_contract_invalid",
      "production physical trusted-clock version or target_domain is invalid",
    );
  }
  const sessionNucleusHash = digest(value.session_nucleus_hash, "session_nucleus_hash");
  const portId = identifier(value.port_id, "production physical trusted-clock port_id");
  const clockId = token(value.clock_id, "production physical trusted-clock clock_id", "physical-clock");
  const uncertaintyCeilingMs = integer(
    value.uncertainty_ceiling_ms,
    "production physical trusted-clock uncertainty_ceiling_ms",
    0,
    MAX_UNCERTAINTY_MS,
  );
  const authority = assertAuthorityRoot(value.authority_root);
  const provisionalState = {
    authorityRoot: authority.root,
    authorityRootIdentityDigest: authority.identityDigest,
  };
  const initialBundle = readAuthorityBundle(provisionalState);
  if (initialBundle.trust.payload.target_domain !== value.target_domain
      || initialBundle.trust.payload.session_nucleus_hash !== sessionNucleusHash
      || initialBundle.trust.payload.clock_id !== clockId) {
    throw trustedClockStoreError(
      "physical_trusted_clock_authority_drift",
      "initial trusted-clock authority bundle belongs to another session or clock",
    );
  }
  const ownerPort = claimProductionPhysicalTrustedClockMonotonicOwner(
    value.monotonic_head_owner,
    {
      version: PRODUCTION_PHYSICAL_TRUSTED_CLOCK_VERSION,
      target_domain: value.target_domain,
      session_nucleus_hash: sessionNucleusHash,
      clock_id: clockId,
      authority_root: authority.root,
      trust_root_public_key_digest:
        initialBundle.trust.payload.trust_root_public_key_digest,
    },
  );
  if (ownerPort.context_domain !== PHYSICAL_TRUSTED_CLOCK_OWNER_CONTEXT_DOMAIN
      || ownerPort.authority_root_identity_digest !== authority.identityDigest) {
    throw trustedClockStoreError(
      "physical_trusted_clock_owner_binding_drift",
      "trusted-clock monotonic owner does not bind the exact fixed authority root",
    );
  }
  const binding = Object.freeze({
    targetDomain: value.target_domain,
    sessionNucleusHash,
    clockId,
    authorityRootIdentityDigest: authority.identityDigest,
    trustRootPublicKeyDigest: initialBundle.trust.payload.trust_root_public_key_digest,
  });
  const state = {
    portId,
    uncertaintyCeilingMs,
    authorityRoot: authority.root,
    authorityRootIdentityDigest: authority.identityDigest,
    ownerPort,
    binding,
    inFlight: false,
  };
  replayHighWaterHistory(ownerPort, binding);
  // Re-read after the owner claim so an authority swap cannot race enrollment.
  const enrolledBundle = readAuthorityBundle(state);
  if (enrolledBundle.trust.payload.trust_root_public_key_digest
      !== binding.trustRootPublicKeyDigest) {
    throw trustedClockStoreError(
      "physical_trusted_clock_authority_drift",
      "trusted-clock trust root changed during enrollment",
    );
  }
  let port = Object.create(null);
  Object.defineProperties(port, {
    version: { value: PRODUCTION_PHYSICAL_TRUSTED_CLOCK_VERSION, enumerable: true },
    kind: { value: "restart_durable_physical_trusted_clock_port", enumerable: true },
    target_domain: { value: binding.targetDomain, enumerable: true },
    session_nucleus_hash: { value: binding.sessionNucleusHash, enumerable: true },
    port_id: { value: portId, enumerable: true },
    clock_id: { value: binding.clockId, enumerable: true },
    mode: { value: TRUSTED_CLOCK_PORT_MODE, enumerable: true },
    uncertainty_ceiling_ms: { value: uncertaintyCeilingMs, enumerable: true },
    monotonic_owner_slot_digest: { value: ownerPort.slot_digest, enumerable: true },
    authority_root_identity_digest: {
      value: binding.authorityRootIdentityDigest,
      enumerable: true,
    },
    trust_root_public_key_digest: {
      value: binding.trustRootPublicKeyDigest,
      enumerable: true,
    },
    source_assurance: { value: FIXED_SOURCE_ASSURANCE, enumerable: true },
    restart_durable: { value: true, enumerable: true },
    exact_signed_time_ready: { value: true, enumerable: true },
    production_ready: { value: false, enumerable: true },
    production_blocker: { value: FIXED_SOURCE_BLOCKER, enumerable: true },
    toJSON: { value: rejectSerialization },
  });
  port = Object.freeze(port);
  PORTS.add(port);
  PORT_STATE.set(port, state);
  return port;
}

function assertRestartDurablePhysicalTrustedClockPort(port) {
  if (!port || !PORTS.has(port) || !PORT_STATE.has(port) || !Object.isFrozen(port)) {
    throw trustedClockStoreError(
      "physical_trusted_clock_port_untrusted",
      "a live privately branded restart-durable trusted-clock port is required",
    );
  }
  const state = PORT_STATE.get(port);
  const authority = assertAuthorityRoot(state.authorityRoot);
  if (authority.identityDigest !== state.authorityRootIdentityDigest) {
    throw trustedClockStoreError(
      "physical_trusted_clock_storage_drift",
      "trusted-clock authority root identity changed",
    );
  }
  replayHighWaterHistory(state.ownerPort, state.binding);
  return port;
}

function assertProductionPhysicalTrustedClockPort(port) {
  const current = assertRestartDurablePhysicalTrustedClockPort(port);
  if (current.production_ready !== true) {
    throw trustedClockStoreError(
      "physical_trusted_clock_not_production",
      `production trusted time is unavailable: ${current.production_blocker}`,
    );
  }
  return current;
}

function sampleRestartDurablePhysicalTrustedClock(portInput) {
  const port = assertRestartDurablePhysicalTrustedClockPort(portInput);
  const state = PORT_STATE.get(port);
  if (state.inFlight) {
    throw trustedClockStoreError(
      "physical_trusted_clock_reentrant",
      "restart-durable trusted-clock sampling is already in progress",
    );
  }
  state.inFlight = true;
  try {
    for (let attempt = 1; attempt <= MAX_SAMPLE_CAS_ATTEMPTS; attempt += 1) {
      const history = replayHighWaterHistory(state.ownerPort, state.binding);
      const previous = history.length === 0 ? null : history.at(-1);
      const bundle = readAuthorityBundle(state);
      const innerSample = sampleFixedBundle(state, bundle);
      const next = nextHighWaterState(state, previous, innerSample, bundle);
      if (!compareAndSetProductionPhysicalTrustedClockMonotonicOwnerState(
        state.ownerPort,
        previous,
        next,
      )) continue;
      const durable = readProductionPhysicalTrustedClockMonotonicOwnerState(state.ownerPort);
      if (canonicalJson(durable) !== canonicalJson(next)) {
        throw trustedClockStoreError(
          "physical_trusted_clock_commit_ambiguous",
          "trusted-clock high-water commit lacks exact durable readback",
        );
      }
      const sample = deepFreeze({
        version: PRODUCTION_PHYSICAL_TRUSTED_CLOCK_VERSION,
        target_domain: state.binding.targetDomain,
        session_nucleus_hash: state.binding.sessionNucleusHash,
        port_id: state.portId,
        clock_id: innerSample.clock_id,
        monotonic_epoch_id: innerSample.monotonic_epoch_id,
        mapping_generation: innerSample.mapping_generation,
        monotonic_ms: innerSample.monotonic_ms,
        trusted_utc: innerSample.trusted_utc,
        trusted_utc_earliest: innerSample.trusted_utc_earliest,
        trusted_utc_latest: innerSample.trusted_utc_latest,
        max_uncertainty_ms: innerSample.max_uncertainty_ms,
        signed_mapping_digest: innerSample.signed_mapping_digest,
        trust_root_epoch: innerSample.trust_root_epoch,
        authority_epoch: innerSample.authority_epoch,
        revocation_generation: innerSample.revocation_generation,
        trust_statement_digest: bundle.trust.document.trust_statement_digest,
        trust_root_public_key_digest: state.binding.trustRootPublicKeyDigest,
        authority_root_identity_digest: state.binding.authorityRootIdentityDigest,
        monotonic_owner_slot_digest: state.ownerPort.slot_digest,
        durable_observation_sequence: next.observation_sequence,
        durable_state_digest: next.monotonic_value_digest,
        source_assurance: FIXED_SOURCE_ASSURANCE,
        restart_durable: true,
        exact_signed_time: true,
        production_ready: port.production_ready === true,
      });
      SAMPLES.add(sample);
      SAMPLE_STATE.set(sample, Object.freeze({ innerSample, port }));
      return sample;
    }
    throw trustedClockStoreError(
      "physical_trusted_clock_commit_contended",
      "trusted-clock high-water CAS remained contended",
    );
  } finally {
    state.inFlight = false;
  }
}

function assertRestartDurablePhysicalTrustedClockSample(sample) {
  if (!sample || !SAMPLES.has(sample) || !SAMPLE_STATE.has(sample)
      || !Object.isFrozen(sample) || sample.restart_durable !== true
      || sample.exact_signed_time !== true) {
    throw trustedClockStoreError(
      "physical_trusted_clock_sample_untrusted",
      "a privately branded restart-durable exact signed-time sample is required",
    );
  }
  const issuance = SAMPLE_STATE.get(sample);
  assertRestartDurablePhysicalTrustedClockPort(issuance.port);
  const current = readProductionPhysicalTrustedClockMonotonicOwnerState(
    PORT_STATE.get(issuance.port).ownerPort,
  );
  if (current == null || current.monotonic_value_digest !== sample.durable_state_digest
      || current.observation_sequence < sample.durable_observation_sequence) {
    throw trustedClockStoreError(
      "physical_trusted_clock_sample_stale",
      "restart-durable trusted-clock sample is no longer backed by its owner history",
    );
  }
  return sample;
}

function assertProductionPhysicalTrustedClockSample(sampleInput) {
  const sample = assertRestartDurablePhysicalTrustedClockSample(sampleInput);
  const issuance = SAMPLE_STATE.get(sample);
  assertProductionPhysicalTrustedClockPort(issuance.port);
  if (sample.production_ready !== true) {
    throw trustedClockStoreError(
      "physical_trusted_clock_sample_not_production",
      "exact signed-time sample was not issued by a production-qualified fixed adapter",
    );
  }
  return sample;
}

function assertRestartDurablePhysicalTrustedClockValidityWindow(
  sampleInput,
  windowInput,
  label = "restart_durable_trusted_clock_validity_window",
) {
  const sample = assertRestartDurablePhysicalTrustedClockSample(sampleInput);
  const issuance = SAMPLE_STATE.get(sample);
  assertPhysicalTrustedClockValidityWindow(issuance.innerSample, windowInput, label);
  return sample;
}

function describeProductionPhysicalTrustedClockPort(portInput) {
  const port = assertRestartDurablePhysicalTrustedClockPort(portInput);
  const state = PORT_STATE.get(port);
  const history = replayHighWaterHistory(state.ownerPort, state.binding);
  const current = history.length === 0 ? null : history.at(-1);
  return deepFreeze({
    version: PRODUCTION_PHYSICAL_TRUSTED_CLOCK_VERSION,
    target_domain: state.binding.targetDomain,
    session_nucleus_hash: state.binding.sessionNucleusHash,
    port_id: state.portId,
    clock_id: state.binding.clockId,
    authority_root_identity_digest: state.binding.authorityRootIdentityDigest,
    trust_root_public_key_digest: state.binding.trustRootPublicKeyDigest,
    monotonic_owner_slot_digest: state.ownerPort.slot_digest,
    restart_durable: true,
    exact_signed_time_ready: true,
    durable_observation_count: history.length,
    current_durable_state_digest: current == null ? null : current.monotonic_value_digest,
    source_assurance: FIXED_SOURCE_ASSURANCE,
    production_ready: false,
    production_blocker: FIXED_SOURCE_BLOCKER,
  });
}

module.exports = Object.freeze({
  FIXED_SOURCE_ASSURANCE,
  FIXED_SOURCE_BLOCKER,
  PHYSICAL_TRUSTED_CLOCK_AUTHORITY_BUNDLE_DOMAIN,
  PHYSICAL_TRUSTED_CLOCK_AUTHORITY_FILE,
  PHYSICAL_TRUSTED_CLOCK_TRUST_DOMAIN,
  PHYSICAL_TRUSTED_CLOCK_TRUST_SIGNING_DOMAIN,
  PRODUCTION_PHYSICAL_TRUSTED_CLOCK_VERSION,
  assertProductionPhysicalTrustedClockPort,
  assertProductionPhysicalTrustedClockSample,
  assertRestartDurablePhysicalTrustedClockPort,
  assertRestartDurablePhysicalTrustedClockSample,
  assertRestartDurablePhysicalTrustedClockValidityWindow,
  describeProductionPhysicalTrustedClockPort,
  normalizePhysicalTrustedClockAuthorityBundle,
  normalizeSignedPhysicalClockTrustStatement,
  openProductionPhysicalTrustedClockPort,
  physicalClockTrustSigningMessage,
  sampleRestartDurablePhysicalTrustedClock,
});
