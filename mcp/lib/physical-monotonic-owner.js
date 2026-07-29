"use strict";

// Generic Mechanism-A monotonic state owner for Plane-PH production stores.
//
// The external root, signing key, context domain, slot, and signed immutable
// head chain are owned here. Consumers put their semantic generation/trust
// binding inside `state`; this module supplies exact canonical CAS and durable
// signed ordering without accepting callbacks, production booleans, slot
// digests, or assurance claims from the caller.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const { readVerifiedSessionNucleus } = require("./governance-store.js");
const { assertSafeDomain, sessionsRoot } = require("./paths.js");
const { probeExactSigningKeyPathIsolation } = require("./sandbox-isolation-attest.js");
const { canonicalJson, hashCanonicalJson } = require("./verification-contracts.js");

const PHYSICAL_MONOTONIC_OWNER_VERSION = 1;
const KEY_FILE = "physical-monotonic-owner-private.json";
const ENROLLMENT_FILE = "physical-monotonic-owner-enrollment.json";
const HEADS_DIR = "heads";
const HEAD_RE = /^([0-9]{8})\.json$/u;
const HASH_RE = /^[a-f0-9]{64}$/u;
const SIGNATURE_RE = /^[A-Za-z0-9_-]{86}$/u;
const CONTEXT_DOMAIN_RE = /^[a-z0-9][a-z0-9._/-]{2,189}$/u;
const MAX_DOCUMENT_BYTES = 1024 * 1024;
const MAX_HEADS = 65_536;
const CLAIM_ENVELOPE_FIELD = "__hacker_bob_physical_monotonic_owner_claim_v1";
const PHYSICAL_EXPERIMENT_OWNER_CONTEXT_DOMAIN =
  "hacker-bob/physical-experiment-row-head/v1";
const PHYSICAL_TRUSTED_CLOCK_OWNER_CONTEXT_DOMAIN =
  "hacker-bob/physical-trusted-clock-high-water/v1";

const PORTS = new WeakSet();
const PORT_STATE = new WeakMap();
const CONSUMER_AUTHORITIES = new WeakSet();
const CONSUMER_AUTHORITY_STATE = new WeakMap();
const CONSUMER_AUTHORITY_CONTEXTS = new Map();
const CONSUMER_PORTS = new WeakSet();
const CONSUMER_PORT_STATE = new WeakMap();
const TRUSTED_CLOCK_CONSUMER_PORTS = new WeakSet();
const TRUSTED_CLOCK_CONSUMER_PORT_STATE = new WeakMap();

function monotonicError(code, message, cause = null) {
  const error = new Error(`${code}: ${message}`);
  error.code = code;
  if (cause != null) Object.defineProperty(error, "cause", { value: cause });
  return error;
}

function exactRecord(input, label, fields) {
  if (input == null || typeof input !== "object" || Array.isArray(input)
      || utilTypes.isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype) {
    throw monotonicError("physical_monotonic_owner_contract_invalid", `${label} must be a plain object`);
  }
  const keys = Reflect.ownKeys(input);
  const expected = fields.slice().sort();
  const actual = keys.slice().sort();
  if (keys.some((key) => typeof key !== "string")
      || actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) {
    throw monotonicError("physical_monotonic_owner_contract_invalid", `${label} fields are not exact`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const result = {};
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw monotonicError(
        "physical_monotonic_owner_contract_invalid",
        `${label}.${field} must be an enumerable data property`,
      );
    }
    result[field] = descriptor.value;
  }
  return result;
}

function digest(value, label) {
  if (typeof value !== "string" || !HASH_RE.test(value)) {
    throw monotonicError("physical_monotonic_owner_contract_invalid", `${label} must be a SHA-256 digest`);
  }
  return value;
}

function boundedToken(value, label, prefix) {
  if (typeof value !== "string" || value.length > 191
      || !/^[A-Za-z0-9][A-Za-z0-9._:@-]*$/u.test(value)
      || !value.startsWith(`${prefix}:`) || value.length === prefix.length + 1) {
    throw monotonicError(
      "physical_monotonic_owner_contract_invalid",
      `${label} must be a bounded ${prefix} token`,
    );
  }
  return value;
}

function contextDomain(value) {
  if (typeof value !== "string" || !CONTEXT_DOMAIN_RE.test(value)
      || value.includes("..") || value.includes("//") || value.endsWith("/")) {
    throw monotonicError(
      "physical_monotonic_owner_contract_invalid",
      "context_domain must be a canonical bounded domain-separation string",
    );
  }
  return value;
}

function canonicalSignature(value, label) {
  if (typeof value !== "string" || !SIGNATURE_RE.test(value)) {
    throw monotonicError("physical_monotonic_owner_signature_invalid", `${label} is invalid`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) {
    throw monotonicError("physical_monotonic_owner_signature_invalid", `${label} is noncanonical`);
  }
  return value;
}

function copyJsonData(value, label, depth = 0, budget = { nodes: 0 }) {
  if (depth > 24 || budget.nodes > 65_536) {
    throw monotonicError("physical_monotonic_owner_contract_invalid", `${label} exceeds bounded JSON limits`);
  }
  budget.nodes += 1;
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) {
    if (utilTypes.isProxy(value) || value.length > 65_536) {
      throw monotonicError("physical_monotonic_owner_contract_invalid", `${label} is not a bounded data array`);
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const result = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || descriptor.enumerable !== true
          || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
        throw monotonicError("physical_monotonic_owner_contract_invalid", `${label} is sparse or accessor-backed`);
      }
      result.push(copyJsonData(descriptor.value, `${label}[${index}]`, depth + 1, budget));
    }
    const extras = Reflect.ownKeys(descriptors).filter((key) => (
      key !== "length" && (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/u.test(key)
        || Number(key) >= value.length)
    ));
    if (extras.length > 0) {
      throw monotonicError("physical_monotonic_owner_contract_invalid", `${label} contains extra fields`);
    }
    return result;
  }
  if (value == null || typeof value !== "object" || utilTypes.isProxy(value)) {
    throw monotonicError("physical_monotonic_owner_contract_invalid", `${label} must contain JSON data only`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw monotonicError("physical_monotonic_owner_contract_invalid", `${label} must contain plain objects only`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length > 4096 || keys.some((key) => typeof key !== "string")) {
    throw monotonicError("physical_monotonic_owner_contract_invalid", `${label} has invalid fields`);
  }
  const result = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw monotonicError("physical_monotonic_owner_contract_invalid", `${label}.${key} is not a data field`);
    }
    result[key] = copyJsonData(descriptor.value, `${label}.${key}`, depth + 1, budget);
  }
  return result;
}

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function fsyncDirectory(directory) {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

function assertOwnedDirectory(directory, label) {
  let stats;
  try { stats = fs.lstatSync(directory); } catch (cause) {
    throw monotonicError("physical_monotonic_owner_storage_invalid", `${label} is unavailable`, cause);
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (!stats.isDirectory() || stats.isSymbolicLink() || uid == null || stats.uid !== uid
      || (stats.mode & 0o077) !== 0) {
    throw monotonicError(
      "physical_monotonic_owner_storage_invalid",
      `${label} must be a real owner-only directory owned by this process`,
    );
  }
  return stats;
}

function ensureOwnedDirectory(directory, label) {
  try { fs.mkdirSync(directory, { mode: 0o700 }); } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  fs.chmodSync(directory, 0o700);
  return assertOwnedDirectory(directory, label);
}

function assertPrivateFile(filePath, label, expectedMode) {
  let before;
  try { before = fs.lstatSync(filePath); } catch (cause) {
    throw monotonicError("physical_monotonic_owner_storage_invalid", `${label} is unavailable`, cause);
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
      || uid == null || before.uid !== uid || (before.mode & 0o777) !== expectedMode) {
    throw monotonicError("physical_monotonic_owner_storage_invalid", `${label} custody is invalid`);
  }
  const descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  const opened = fs.fstatSync(descriptor);
  if (opened.dev !== before.dev || opened.ino !== before.ino || opened.nlink !== 1) {
    fs.closeSync(descriptor);
    throw monotonicError("physical_monotonic_owner_storage_invalid", `${label} changed during open`);
  }
  return { descriptor, stats: before };
}

function readPrivateJson(filePath, label, expectedMode) {
  const opened = assertPrivateFile(filePath, label, expectedMode);
  try {
    if (opened.stats.size < 2 || opened.stats.size > MAX_DOCUMENT_BYTES) {
      throw monotonicError("physical_monotonic_owner_storage_invalid", `${label} size is invalid`);
    }
    const buffer = Buffer.alloc(opened.stats.size);
    let offset = 0;
    while (offset < buffer.length) {
      const count = fs.readSync(opened.descriptor, buffer, offset, buffer.length - offset, offset);
      if (count < 1) throw monotonicError("physical_monotonic_owner_storage_invalid", `${label} is truncated`);
      offset += count;
    }
    try { return JSON.parse(buffer.toString("utf8")); } finally { buffer.fill(0); }
  } finally {
    fs.closeSync(opened.descriptor);
  }
}

function writeExclusiveJson(filePath, value, mode) {
  const directory = path.dirname(filePath);
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, "utf8");
  if (bytes.length > MAX_DOCUMENT_BYTES) {
    bytes.fill(0);
    throw monotonicError("physical_monotonic_owner_capacity_exhausted", "owner document is too large");
  }
  const tempPath = path.join(
    directory,
    `.${path.basename(filePath)}.${process.pid}.${crypto.randomBytes(12).toString("hex")}.tmp`,
  );
  let descriptor;
  try {
    descriptor = fs.openSync(tempPath, "wx", mode);
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = null;
    fs.chmodSync(tempPath, mode);
    try { fs.linkSync(tempPath, filePath); } catch (error) {
      if (error.code === "EEXIST") return false;
      throw error;
    }
    fsyncDirectory(directory);
    return true;
  } finally {
    if (descriptor != null) try { fs.closeSync(descriptor); } catch {}
    bytes.fill(0);
    try { fs.unlinkSync(tempPath); } catch {}
  }
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

function publicKeyDigest(publicKey) {
  return crypto.createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
}

function pathsFor(root) {
  return Object.freeze({
    root,
    key: path.join(root, KEY_FILE),
    enrollment: path.join(root, ENROLLMENT_FILE),
    heads: path.join(root, HEADS_DIR),
  });
}

function keyDocument(state, privateKey) {
  const publicKey = crypto.createPublicKey(privateKey);
  return {
    version: PHYSICAL_MONOTONIC_OWNER_VERSION,
    scheme: "ed25519",
    target_domain: state.domain,
    session_nucleus_hash: state.nucleusHash,
    context_domain: state.contextDomain,
    public_key_spki_base64url: publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
    public_key_spki_sha256: publicKeyDigest(publicKey),
    private_key_pkcs8_base64url: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url"),
  };
}

function normalizeKeyDocument(input, state) {
  const value = exactRecord(input, "physical monotonic owner private key", [
    "version", "scheme", "target_domain", "session_nucleus_hash", "context_domain",
    "public_key_spki_base64url", "public_key_spki_sha256", "private_key_pkcs8_base64url",
  ]);
  if (value.version !== PHYSICAL_MONOTONIC_OWNER_VERSION || value.scheme !== "ed25519"
      || value.target_domain !== state.domain || value.session_nucleus_hash !== state.nucleusHash
      || value.context_domain !== state.contextDomain) {
    throw monotonicError("physical_monotonic_owner_authority_drift", "owner key binding drifted");
  }
  let privateKey;
  let publicKey;
  try {
    privateKey = crypto.createPrivateKey({
      key: Buffer.from(value.private_key_pkcs8_base64url, "base64url"),
      type: "pkcs8",
      format: "der",
    });
    publicKey = crypto.createPublicKey(privateKey);
  } catch (cause) {
    throw monotonicError("physical_monotonic_owner_key_invalid", "owner key is invalid", cause);
  }
  const spki = publicKey.export({ type: "spki", format: "der" });
  if (digest(value.public_key_spki_sha256, "owner public key digest") !== publicKeyDigest(publicKey)
      || spki.toString("base64url") !== value.public_key_spki_base64url) {
    throw monotonicError("physical_monotonic_owner_key_invalid", "owner public key projection drifted");
  }
  return Object.freeze({ document: deepFreeze(value), privateKey, publicKey });
}

function readOrCreateKey(state) {
  if (!fs.existsSync(state.paths.key)) {
    const pair = crypto.generateKeyPairSync("ed25519");
    writeExclusiveJson(state.paths.key, keyDocument(state, pair.privateKey), 0o400);
  }
  return normalizeKeyDocument(
    readPrivateJson(state.paths.key, "physical monotonic owner private key", 0o400),
    state,
  );
}

function signDigest(state, payloadDigest) {
  return crypto.sign(null, Buffer.from(digest(payloadDigest, "owner signing payload"), "hex"),
    state.key.privateKey).toString("base64url");
}

function verifyDigest(state, payloadDigest, signature) {
  return crypto.verify(
    null,
    Buffer.from(digest(payloadDigest, "owner verification payload"), "hex"),
    state.key.publicKey,
    Buffer.from(canonicalSignature(signature, "owner signature"), "base64url"),
  );
}

function enrollmentPayload(state, input) {
  return {
    version: PHYSICAL_MONOTONIC_OWNER_VERSION,
    target_domain: state.domain,
    session_nucleus_hash: state.nucleusHash,
    context_domain: state.contextDomain,
    external_owner_root_identity_digest: state.rootIdentityDigest,
    signing_key_spki_sha256: state.key.document.public_key_spki_sha256,
    slot_digest: input.slot_digest,
    enrolled_at: input.enrolled_at,
  };
}

function issueEnrollment(state) {
  const slotDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-monotonic-owner-slot/v1",
    target_domain: state.domain,
    session_nucleus_hash: state.nucleusHash,
    context_domain: state.contextDomain,
    external_owner_root_identity_digest: state.rootIdentityDigest,
    signing_key_spki_sha256: state.key.document.public_key_spki_sha256,
  });
  const payload = enrollmentPayload(state, {
    slot_digest: slotDigest,
    enrolled_at: new Date().toISOString(),
  });
  const payloadDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-monotonic-owner-enrollment-payload/v1",
    ...payload,
  });
  const signature = signDigest(state, payloadDigest);
  return deepFreeze({
    ...payload,
    payload_digest: payloadDigest,
    signature,
    enrollment_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-monotonic-owner-enrollment/v1",
      ...payload,
      payload_digest: payloadDigest,
      signature,
    }),
  });
}

function normalizeEnrollment(input, state) {
  const value = exactRecord(input, "physical monotonic owner enrollment", [
    "version", "target_domain", "session_nucleus_hash", "context_domain",
    "external_owner_root_identity_digest", "signing_key_spki_sha256", "slot_digest",
    "enrolled_at", "payload_digest", "signature", "enrollment_digest",
  ]);
  const payload = enrollmentPayload(state, value);
  const payloadDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-monotonic-owner-enrollment-payload/v1",
    ...payload,
  });
  const enrollmentDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-monotonic-owner-enrollment/v1",
    ...payload,
    payload_digest: payloadDigest,
    signature: value.signature,
  });
  if (value.version !== PHYSICAL_MONOTONIC_OWNER_VERSION
      || value.target_domain !== state.domain || value.session_nucleus_hash !== state.nucleusHash
      || value.context_domain !== state.contextDomain
      || value.external_owner_root_identity_digest !== state.rootIdentityDigest
      || value.signing_key_spki_sha256 !== state.key.document.public_key_spki_sha256
      || digest(value.slot_digest, "owner slot digest") !== state.expectedSlotDigest
      || digest(value.payload_digest, "owner enrollment payload digest") !== payloadDigest
      || digest(value.enrollment_digest, "owner enrollment digest") !== enrollmentDigest
      || !verifyDigest(state, payloadDigest, value.signature)) {
    throw monotonicError("physical_monotonic_owner_authority_drift", "owner enrollment drifted");
  }
  return deepFreeze({ ...payload, payload_digest: payloadDigest,
    signature: value.signature, enrollment_digest: enrollmentDigest });
}

function readOrCreateEnrollment(state) {
  state.expectedSlotDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-monotonic-owner-slot/v1",
    target_domain: state.domain,
    session_nucleus_hash: state.nucleusHash,
    context_domain: state.contextDomain,
    external_owner_root_identity_digest: state.rootIdentityDigest,
    signing_key_spki_sha256: state.key.document.public_key_spki_sha256,
  });
  if (!fs.existsSync(state.paths.enrollment)) {
    writeExclusiveJson(state.paths.enrollment, issueEnrollment(state), 0o600);
  }
  return normalizeEnrollment(
    readPrivateJson(state.paths.enrollment, "physical monotonic owner enrollment", 0o600),
    state,
  );
}

function currentNucleus(state) {
  const nucleus = readVerifiedSessionNucleus(state.domain);
  if (!nucleus.physical_scope || nucleus.nucleus_hash !== state.nucleusHash
      || (nucleus.target_domain != null && nucleus.target_domain !== state.domain)) {
    throw monotonicError(
      "physical_monotonic_owner_authority_drift",
      "owner is not bound to the exact current physical session nucleus",
    );
  }
  return nucleus;
}

function liveCustody(state) {
  const stats = assertOwnedDirectory(state.paths.root, "physical monotonic external owner root");
  const root = fs.realpathSync(state.paths.root);
  const bobSessionsRoot = fs.realpathSync(sessionsRoot());
  const disjoint = disjointPaths(root, bobSessionsRoot);
  const identity = rootIdentity(root, stats);
  const probe = probeExactSigningKeyPathIsolation(state.paths.key, {
    expectedRoot: root,
    custodyRoot: root,
  });
  const productionReady = disjoint && identity === state.rootIdentityDigest
    && probe.assurance === "mechanism_a_exact_signing_key_path_isolation"
    && probe.isolated === true;
  const basis = {
    version: PHYSICAL_MONOTONIC_OWNER_VERSION,
    target_domain: state.domain,
    session_nucleus_hash: state.nucleusHash,
    context_domain: state.contextDomain,
    external_owner_root_identity_digest: identity,
    owner_root_disjoint_from_sessions_root: disjoint,
    isolation_probe: probe,
    production_ready: productionReady,
  };
  return deepFreeze({
    ...basis,
    custody_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-monotonic-owner-custody/v1",
      ...basis,
    }),
  });
}

function assertOwnerCurrent(state) {
  const nucleus = currentNucleus(state);
  const custody = liveCustody(state);
  const key = normalizeKeyDocument(
    readPrivateJson(state.paths.key, "physical monotonic owner private key", 0o400),
    state,
  );
  if (key.document.public_key_spki_sha256 !== state.key.document.public_key_spki_sha256) {
    throw monotonicError("physical_monotonic_owner_authority_drift", "owner key changed");
  }
  const enrollment = normalizeEnrollment(
    readPrivateJson(state.paths.enrollment, "physical monotonic owner enrollment", 0o600),
    state,
  );
  if (enrollment.enrollment_digest !== state.enrollment.enrollment_digest) {
    throw monotonicError("physical_monotonic_owner_authority_drift", "owner enrollment changed");
  }
  return Object.freeze({ nucleus, custody, enrollment });
}

function headPayload(state, sequence, previousHeadDigest, ownerState) {
  const canonicalState = copyJsonData(ownerState, "physical monotonic owner state");
  return {
    version: PHYSICAL_MONOTONIC_OWNER_VERSION,
    sequence,
    previous_head_digest: previousHeadDigest,
    target_domain: state.domain,
    session_nucleus_hash: state.nucleusHash,
    context_domain: state.contextDomain,
    slot_digest: state.enrollment.slot_digest,
    enrollment_digest: state.enrollment.enrollment_digest,
    state_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-monotonic-owner-state/v1",
      context_domain: state.contextDomain,
      state: canonicalState,
    }),
    state: canonicalState,
  };
}

function issueHead(state, sequence, previousHeadDigest, ownerState) {
  const payload = headPayload(state, sequence, previousHeadDigest, ownerState);
  const payloadDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-monotonic-owner-head-payload/v1",
    ...payload,
  });
  const signature = signDigest(state, payloadDigest);
  return deepFreeze({
    ...payload,
    payload_digest: payloadDigest,
    signature,
    head_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-monotonic-owner-head/v1",
      ...payload,
      payload_digest: payloadDigest,
      signature,
    }),
  });
}

function normalizeHead(input, state, sequence, previousHeadDigest) {
  const value = exactRecord(input, `physical monotonic owner head ${sequence}`, [
    "version", "sequence", "previous_head_digest", "target_domain", "session_nucleus_hash",
    "context_domain", "slot_digest", "enrollment_digest", "state_digest", "state",
    "payload_digest", "signature", "head_digest",
  ]);
  const payload = headPayload(state, value.sequence, value.previous_head_digest, value.state);
  const payloadDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-monotonic-owner-head-payload/v1",
    ...payload,
  });
  const headDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-monotonic-owner-head/v1",
    ...payload,
    payload_digest: payloadDigest,
    signature: value.signature,
  });
  if (value.version !== PHYSICAL_MONOTONIC_OWNER_VERSION || value.sequence !== sequence
      || value.previous_head_digest !== previousHeadDigest || value.target_domain !== state.domain
      || value.session_nucleus_hash !== state.nucleusHash
      || value.context_domain !== state.contextDomain
      || value.slot_digest !== state.enrollment.slot_digest
      || value.enrollment_digest !== state.enrollment.enrollment_digest
      || digest(value.state_digest, "owner state digest") !== payload.state_digest
      || digest(value.payload_digest, "owner head payload digest") !== payloadDigest
      || digest(value.head_digest, "owner head digest") !== headDigest
      || !verifyDigest(state, payloadDigest, value.signature)) {
    throw monotonicError("physical_monotonic_owner_head_invalid", "signed monotonic head chain is invalid");
  }
  return deepFreeze({ ...payload, payload_digest: payloadDigest,
    signature: value.signature, head_digest: headDigest });
}

function readHeads(state) {
  assertOwnedDirectory(state.paths.heads, "physical monotonic owner head directory");
  const names = fs.readdirSync(state.paths.heads).sort();
  if (names.length > MAX_HEADS || names.some((name) => !HEAD_RE.test(name))) {
    throw monotonicError("physical_monotonic_owner_head_invalid", "head directory is malformed");
  }
  const heads = [];
  let previous = "0".repeat(64);
  for (let index = 0; index < names.length; index += 1) {
    const sequence = index + 1;
    if (names[index] !== `${String(sequence).padStart(8, "0")}.json`) {
      throw monotonicError("physical_monotonic_owner_head_invalid", "head chain has a gap");
    }
    const head = normalizeHead(
      readPrivateJson(path.join(state.paths.heads, names[index]), `physical monotonic owner head ${sequence}`, 0o600),
      state,
      sequence,
      previous,
    );
    heads.push(head);
    previous = head.head_digest;
  }
  return heads;
}

function rejectSerialization() {
  throw monotonicError(
    "physical_monotonic_owner_serialization_refused",
    "physical monotonic owner ports are process-local capabilities",
  );
}

function registerPhysicalMonotonicOwnerConsumer(input) {
  const value = exactRecord(input, "physical monotonic owner consumer registration", [
    "version", "context_domain", "consumer_id",
  ]);
  if (value.version !== PHYSICAL_MONOTONIC_OWNER_VERSION) {
    throw monotonicError(
      "physical_monotonic_owner_contract_invalid",
      "physical monotonic owner consumer version must be 1",
    );
  }
  const context = contextDomain(value.context_domain);
  const consumerId = contextDomain(value.consumer_id);
  if (CONSUMER_AUTHORITY_CONTEXTS.has(context)) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_conflict",
      "physical monotonic owner context already has a process-local consumer authority",
    );
  }
  let authority = Object.create(null);
  Object.defineProperties(authority, {
    version: { value: PHYSICAL_MONOTONIC_OWNER_VERSION, enumerable: true },
    kind: { value: "physical_monotonic_owner_consumer_authority", enumerable: true },
    context_domain: { value: context, enumerable: true },
    consumer_id: { value: consumerId, enumerable: true },
    toJSON: { value: rejectSerialization },
  });
  authority = Object.freeze(authority);
  const state = Object.freeze({ contextDomain: context, consumerId });
  CONSUMER_AUTHORITIES.add(authority);
  CONSUMER_AUTHORITY_STATE.set(authority, state);
  CONSUMER_AUTHORITY_CONTEXTS.set(context, authority);
  return authority;
}

const PHYSICAL_EXPERIMENT_CONSUMER_AUTHORITY = registerPhysicalMonotonicOwnerConsumer({
  version: 1,
  context_domain: PHYSICAL_EXPERIMENT_OWNER_CONTEXT_DOMAIN,
  consumer_id: "hacker-bob/physical-experiment-store/v1",
});

const PHYSICAL_TRUSTED_CLOCK_CONSUMER_AUTHORITY = registerPhysicalMonotonicOwnerConsumer({
  version: 1,
  context_domain: PHYSICAL_TRUSTED_CLOCK_OWNER_CONTEXT_DOMAIN,
  consumer_id: "hacker-bob/physical-trusted-clock-store/v1",
});

function assertConsumerAuthority(authority) {
  if (!authority || !CONSUMER_AUTHORITIES.has(authority)
      || !CONSUMER_AUTHORITY_STATE.has(authority) || !Object.isFrozen(authority)) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_untrusted",
      "a live privately branded monotonic owner consumer authority is required",
    );
  }
  const state = CONSUMER_AUTHORITY_STATE.get(authority);
  if (CONSUMER_AUTHORITY_CONTEXTS.get(state.contextDomain) !== authority) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_untrusted",
      "physical monotonic owner consumer authority is no longer current",
    );
  }
  return state;
}

function normalizePhysicalExperimentClaimBinding(input, state) {
  const value = exactRecord(input, "physical experiment monotonic owner claim binding", [
    "version",
    "target_domain",
    "session_nucleus_hash",
    "plan_hash",
    "store_binding_digest",
    "trust_binding_digest",
    "trust_head_digest",
    "signer_owner_custody_digest",
  ]);
  if (value.version !== PHYSICAL_MONOTONIC_OWNER_VERSION
      || value.target_domain !== state.domain
      || value.session_nucleus_hash !== state.nucleusHash) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_conflict",
      "physical experiment owner claim belongs to another target or session nucleus",
    );
  }
  for (const field of [
    "plan_hash",
    "store_binding_digest",
    "trust_binding_digest",
    "trust_head_digest",
    "signer_owner_custody_digest",
  ]) digest(value[field], `physical experiment owner claim.${field}`);
  return deepFreeze({ ...value });
}

function normalizePhysicalTrustedClockClaimBinding(input, state) {
  const value = exactRecord(input, "physical trusted-clock monotonic owner claim binding", [
    "version",
    "target_domain",
    "session_nucleus_hash",
    "clock_id",
    "authority_root",
    "trust_root_public_key_digest",
  ]);
  if (value.version !== PHYSICAL_MONOTONIC_OWNER_VERSION
      || value.target_domain !== state.domain
      || value.session_nucleus_hash !== state.nucleusHash) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_conflict",
      "physical trusted-clock owner claim belongs to another target or session nucleus",
    );
  }
  const clockId = boundedToken(
    value.clock_id,
    "physical trusted-clock owner claim.clock_id",
    "physical-clock",
  );
  const trustRootPublicKeyDigest = digest(
    value.trust_root_public_key_digest,
    "physical trusted-clock owner claim.trust_root_public_key_digest",
  );
  if (typeof value.authority_root !== "string" || !path.isAbsolute(value.authority_root)
      || path.normalize(value.authority_root) !== value.authority_root) {
    throw monotonicError(
      "physical_monotonic_owner_contract_invalid",
      "physical trusted-clock authority_root must be a normalized absolute path",
    );
  }
  const authorityStats = assertOwnedDirectory(
    value.authority_root,
    "physical trusted-clock authority root",
  );
  const authorityRoot = fs.realpathSync(value.authority_root);
  const bobSessionsRoot = fs.realpathSync(sessionsRoot());
  if (!disjointPaths(authorityRoot, bobSessionsRoot)
      || !disjointPaths(authorityRoot, state.paths.root)) {
    throw monotonicError(
      "physical_monotonic_owner_storage_invalid",
      "physical trusted-clock authority, monotonic owner, and Bob sessions roots must be disjoint",
    );
  }
  return deepFreeze({
    version: PHYSICAL_MONOTONIC_OWNER_VERSION,
    target_domain: state.domain,
    session_nucleus_hash: state.nucleusHash,
    clock_id: clockId,
    authority_root_identity_digest: rootIdentity(authorityRoot, authorityStats),
    trust_root_public_key_digest: trustRootPublicKeyDigest,
  });
}

function ownerClaimBody(state, authorityState, claimBinding) {
  return {
    version: PHYSICAL_MONOTONIC_OWNER_VERSION,
    target_domain: state.domain,
    session_nucleus_hash: state.nucleusHash,
    context_domain: state.contextDomain,
    slot_digest: state.enrollment.slot_digest,
    enrollment_digest: state.enrollment.enrollment_digest,
    consumer_id: authorityState.consumerId,
    plan_hash: claimBinding.plan_hash,
    store_binding_digest: claimBinding.store_binding_digest,
    trust_binding_digest: claimBinding.trust_binding_digest,
    trust_head_digest: claimBinding.trust_head_digest,
    signer_owner_custody_digest: claimBinding.signer_owner_custody_digest,
  };
}

function ownerClaim(state, authorityState, claimBinding) {
  const body = ownerClaimBody(state, authorityState, claimBinding);
  return deepFreeze({
    ...body,
    claim_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-monotonic-owner-exclusive-consumer/v1",
      ...body,
    }),
  });
}

function normalizeOwnerClaimEnvelope(input, state, authorityState, claimBinding, label) {
  const envelope = exactRecord(input, label, [CLAIM_ENVELOPE_FIELD, "consumer_state"]);
  const claim = exactRecord(
    envelope[CLAIM_ENVELOPE_FIELD],
    `${label}.${CLAIM_ENVELOPE_FIELD}`,
    [
      "version", "target_domain", "session_nucleus_hash", "context_domain", "slot_digest",
      "enrollment_digest", "consumer_id", "plan_hash", "store_binding_digest",
      "trust_binding_digest", "trust_head_digest", "signer_owner_custody_digest",
      "claim_digest",
    ],
  );
  const body = ownerClaimBody(state, authorityState, claimBinding);
  for (const [field, expected] of Object.entries(body)) {
    if (claim[field] !== expected) {
      throw monotonicError(
        "physical_monotonic_owner_consumer_conflict",
        `${label}.${field} consumer binding drifted`,
      );
    }
  }
  const claimDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-monotonic-owner-exclusive-consumer/v1",
    ...body,
  });
  if (digest(claim.claim_digest, `${label}.claim_digest`) !== claimDigest) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_conflict",
      `${label} consumer claim digest drifted`,
    );
  }
  return deepFreeze({
    [CLAIM_ENVELOPE_FIELD]: { ...body, claim_digest: claimDigest },
    consumer_state: copyJsonData(envelope.consumer_state, `${label}.consumer_state`),
  });
}

function isOwnerClaimEnvelope(value) {
  return value != null && typeof value === "object" && !Array.isArray(value)
    && Object.prototype.hasOwnProperty.call(value, CLAIM_ENVELOPE_FIELD);
}

function issueOwnerClaimEnvelope(state, authorityState, claimBinding, consumerState) {
  return normalizeOwnerClaimEnvelope({
    [CLAIM_ENVELOPE_FIELD]: ownerClaim(state, authorityState, claimBinding),
    consumer_state: consumerState,
  }, state, authorityState, claimBinding, "physical monotonic owner exclusive consumer envelope");
}

function trustedClockOwnerClaimBody(state, authorityState, claimBinding) {
  return {
    version: PHYSICAL_MONOTONIC_OWNER_VERSION,
    target_domain: state.domain,
    session_nucleus_hash: state.nucleusHash,
    context_domain: state.contextDomain,
    slot_digest: state.enrollment.slot_digest,
    enrollment_digest: state.enrollment.enrollment_digest,
    consumer_id: authorityState.consumerId,
    clock_id: claimBinding.clock_id,
    authority_root_identity_digest: claimBinding.authority_root_identity_digest,
    trust_root_public_key_digest: claimBinding.trust_root_public_key_digest,
  };
}

function trustedClockOwnerClaim(state, authorityState, claimBinding) {
  const body = trustedClockOwnerClaimBody(state, authorityState, claimBinding);
  return deepFreeze({
    ...body,
    claim_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-monotonic-owner-exclusive-trusted-clock-consumer/v1",
      ...body,
    }),
  });
}

function normalizeTrustedClockOwnerClaimEnvelope(
  input,
  state,
  authorityState,
  claimBinding,
  label,
) {
  const envelope = exactRecord(input, label, [CLAIM_ENVELOPE_FIELD, "consumer_state"]);
  const claim = exactRecord(
    envelope[CLAIM_ENVELOPE_FIELD],
    `${label}.${CLAIM_ENVELOPE_FIELD}`,
    [
      "version", "target_domain", "session_nucleus_hash", "context_domain", "slot_digest",
      "enrollment_digest", "consumer_id", "clock_id", "authority_root_identity_digest",
      "trust_root_public_key_digest", "claim_digest",
    ],
  );
  const body = trustedClockOwnerClaimBody(state, authorityState, claimBinding);
  for (const [field, expected] of Object.entries(body)) {
    if (claim[field] !== expected) {
      throw monotonicError(
        "physical_monotonic_owner_consumer_conflict",
        `${label}.${field} trusted-clock consumer binding drifted`,
      );
    }
  }
  const claimDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-monotonic-owner-exclusive-trusted-clock-consumer/v1",
    ...body,
  });
  if (digest(claim.claim_digest, `${label}.claim_digest`) !== claimDigest) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_conflict",
      `${label} trusted-clock consumer claim digest drifted`,
    );
  }
  return deepFreeze({
    [CLAIM_ENVELOPE_FIELD]: { ...body, claim_digest: claimDigest },
    consumer_state: copyJsonData(envelope.consumer_state, `${label}.consumer_state`),
  });
}

function issueTrustedClockOwnerClaimEnvelope(
  state,
  authorityState,
  claimBinding,
  consumerState,
) {
  return normalizeTrustedClockOwnerClaimEnvelope({
    [CLAIM_ENVELOPE_FIELD]: trustedClockOwnerClaim(state, authorityState, claimBinding),
    consumer_state: consumerState,
  }, state, authorityState, claimBinding,
  "physical monotonic owner exclusive trusted-clock consumer envelope");
}

function normalizeConsumerMonotonicMetadata(value, label) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_transition_invalid",
      `${label} must be a monotonic-position state object`,
    );
  }
  if (!Number.isSafeInteger(value.monotonic_revision) || value.monotonic_revision < 1
      || !Number.isSafeInteger(value.monotonic_position) || value.monotonic_position < 0) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_transition_invalid",
      `${label} has an invalid monotonic revision or position`,
    );
  }
  return Object.freeze({
    revision: value.monotonic_revision,
    position: value.monotonic_position,
    valueDigest: digest(value.monotonic_value_digest, `${label}.monotonic_value_digest`),
  });
}

function assertConsumerMonotonicTransition(previousState, nextState, label) {
  const next = normalizeConsumerMonotonicMetadata(nextState, `${label}.next`);
  if (previousState == null) {
    if (next.revision !== 1) {
      throw monotonicError(
        "physical_monotonic_owner_consumer_transition_invalid",
        `${label} genesis revision must be 1`,
      );
    }
    return next;
  }
  const previous = normalizeConsumerMonotonicMetadata(previousState, `${label}.previous`);
  if (next.revision !== previous.revision + 1
      || next.position < previous.position || next.position > previous.position + 1
      || (next.position === previous.position && next.valueDigest !== previous.valueDigest)) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_transition_invalid",
      `${label} regresses, skips, or rewrites its committed monotonic position`,
    );
  }
  return next;
}

function appendOwnerHead(state, heads, nextState) {
  if (heads.length >= MAX_HEADS) {
    throw monotonicError("physical_monotonic_owner_capacity_exhausted", "signed head journal is full");
  }
  const candidate = issueHead(
    state,
    heads.length + 1,
    heads.length === 0 ? "0".repeat(64) : heads.at(-1).head_digest,
    nextState,
  );
  const filePath = path.join(state.paths.heads, `${String(candidate.sequence).padStart(8, "0")}.json`);
  if (!writeExclusiveJson(filePath, candidate, 0o600)) return false;
  const durable = readHeads(state).at(-1);
  if (!durable || durable.head_digest !== candidate.head_digest
      || canonicalJson(durable.state) !== canonicalJson(nextState)) {
    throw monotonicError(
      "physical_monotonic_owner_commit_ambiguous",
      "signed head commit lacks exact durable readback",
    );
  }
  assertOwnerCurrent(state);
  return true;
}

function readClaimedOwnerHeads(state, authorityState, claimBinding) {
  const heads = readHeads(state);
  if (heads.length === 0) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_conflict",
      "physical monotonic owner has no durable exclusive-consumer claim",
    );
  }
  const envelopes = heads.map((head, index) => normalizeOwnerClaimEnvelope(
    head.state,
    state,
    authorityState,
    claimBinding,
    `physical monotonic owner claimed head ${index + 1}`,
  ));
  if (envelopes[0].consumer_state !== null) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_conflict",
      "physical monotonic owner claim genesis must have an empty consumer state",
    );
  }
  const claimDigest = envelopes[0][CLAIM_ENVELOPE_FIELD].claim_digest;
  if (envelopes.some((envelope) => (
    envelope[CLAIM_ENVELOPE_FIELD].claim_digest !== claimDigest
  ))) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_conflict",
      "physical monotonic owner consumer claim changed within the signed head chain",
    );
  }
  let previousState = null;
  for (let index = 1; index < envelopes.length; index += 1) {
    const nextState = envelopes[index].consumer_state;
    if (nextState == null) {
      throw monotonicError(
        "physical_monotonic_owner_consumer_transition_invalid",
        "physical monotonic owner consumer state cannot return to null after claim genesis",
      );
    }
    assertConsumerMonotonicTransition(
      previousState,
      nextState,
      `physical monotonic owner claimed transition ${index}`,
    );
    previousState = nextState;
  }
  return Object.freeze({ heads, envelopes });
}

function readTrustedClockClaimedOwnerHeads(state, authorityState, claimBinding) {
  const heads = readHeads(state);
  if (heads.length === 0) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_conflict",
      "physical monotonic owner has no durable trusted-clock consumer claim",
    );
  }
  const envelopes = heads.map((head, index) => normalizeTrustedClockOwnerClaimEnvelope(
    head.state,
    state,
    authorityState,
    claimBinding,
    `physical monotonic owner trusted-clock claimed head ${index + 1}`,
  ));
  if (envelopes[0].consumer_state !== null) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_conflict",
      "physical monotonic owner trusted-clock claim genesis must have an empty consumer state",
    );
  }
  const claimDigest = envelopes[0][CLAIM_ENVELOPE_FIELD].claim_digest;
  if (envelopes.some((envelope) => (
    envelope[CLAIM_ENVELOPE_FIELD].claim_digest !== claimDigest
  ))) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_conflict",
      "physical monotonic owner trusted-clock consumer claim changed within the signed head chain",
    );
  }
  let previousState = null;
  for (let index = 1; index < envelopes.length; index += 1) {
    const nextState = envelopes[index].consumer_state;
    if (nextState == null) {
      throw monotonicError(
        "physical_monotonic_owner_consumer_transition_invalid",
        "physical monotonic owner trusted-clock state cannot return to null after claim genesis",
      );
    }
    assertConsumerMonotonicTransition(
      previousState,
      nextState,
      `physical monotonic owner trusted-clock claimed transition ${index}`,
    );
    previousState = nextState;
  }
  return Object.freeze({ heads, envelopes });
}

function openProductionPhysicalMonotonicOwner(input) {
  const values = exactRecord(input, "production physical monotonic owner input", [
    "version", "target_domain", "session_nucleus_hash", "external_owner_root", "context_domain",
  ]);
  if (values.version !== PHYSICAL_MONOTONIC_OWNER_VERSION) {
    throw monotonicError("physical_monotonic_owner_contract_invalid", "owner version must be 1");
  }
  const domain = assertSafeDomain(values.target_domain);
  const nucleusHash = digest(values.session_nucleus_hash, "session_nucleus_hash");
  const context = contextDomain(values.context_domain);
  if (typeof values.external_owner_root !== "string" || !path.isAbsolute(values.external_owner_root)
      || path.normalize(values.external_owner_root) !== values.external_owner_root) {
    throw monotonicError(
      "physical_monotonic_owner_contract_invalid",
      "external_owner_root must be a normalized absolute path",
    );
  }
  const rootStats = assertOwnedDirectory(values.external_owner_root, "physical monotonic external owner root");
  const root = fs.realpathSync(values.external_owner_root);
  const bobSessionsRoot = fs.realpathSync(sessionsRoot());
  if (!disjointPaths(root, bobSessionsRoot)) {
    throw monotonicError(
      "physical_monotonic_owner_storage_invalid",
      "external owner root must be disjoint from the entire Bob sessions tree",
    );
  }
  const state = {
    domain,
    nucleusHash,
    contextDomain: context,
    paths: pathsFor(root),
    rootIdentityDigest: rootIdentity(root, rootStats),
    expectedSlotDigest: null,
    key: null,
    enrollment: null,
  };
  currentNucleus(state);
  ensureOwnedDirectory(state.paths.heads, "physical monotonic owner head directory");
  state.key = readOrCreateKey(state);
  state.enrollment = readOrCreateEnrollment(state);
  const custody = liveCustody(state);
  let port = Object.create(null);
  Object.defineProperties(port, {
    version: { value: PHYSICAL_MONOTONIC_OWNER_VERSION, enumerable: true },
    kind: { value: "physical_monotonic_owner_port", enumerable: true },
    target_domain: { value: domain, enumerable: true },
    session_nucleus_hash: { value: nucleusHash, enumerable: true },
    context_domain: { value: context, enumerable: true },
    slot_digest: { value: state.enrollment.slot_digest, enumerable: true },
    production_ready: { value: custody.production_ready, enumerable: true },
    toJSON: { value: rejectSerialization },
  });
  port = Object.freeze(port);
  PORTS.add(port);
  PORT_STATE.set(port, state);
  assertOwnerCurrent(state);
  readHeads(state);
  return port;
}

function assertPhysicalMonotonicOwnerPort(port) {
  if (!port || !PORTS.has(port) || !PORT_STATE.has(port) || !Object.isFrozen(port)) {
    throw monotonicError(
      "physical_monotonic_owner_port_untrusted",
      "a live privately branded physical monotonic owner port is required",
    );
  }
  const current = assertOwnerCurrent(PORT_STATE.get(port));
  // A conformance owner may remain usable as a non-authorizing CAS fixture,
  // but a port born production-qualified must fail closed if live structural
  // custody later degrades. Callers cannot keep using a stale true field.
  if (port.production_ready === true && current.custody.production_ready !== true) {
    throw monotonicError(
      "physical_monotonic_owner_custody_drift",
      "production monotonic owner lost live Mechanism-A custody",
    );
  }
  return port;
}

function assertProductionPhysicalMonotonicOwnerPort(port) {
  const current = assertPhysicalMonotonicOwnerPort(port);
  const owner = assertOwnerCurrent(PORT_STATE.get(current));
  if (current.production_ready !== true || owner.custody.production_ready !== true) {
    throw monotonicError(
      "physical_monotonic_owner_not_production",
      "production monotonic state requires Mechanism-A isolated owner custody",
    );
  }
  return current;
}

function claimProductionPhysicalExperimentMonotonicOwner(portInput, claimBindingInput) {
  const port = assertProductionPhysicalMonotonicOwnerPort(portInput);
  const authorityState = assertConsumerAuthority(PHYSICAL_EXPERIMENT_CONSUMER_AUTHORITY);
  const state = PORT_STATE.get(port);
  const claimBinding = normalizePhysicalExperimentClaimBinding(claimBindingInput, state);
  if (authorityState.contextDomain !== state.contextDomain) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_conflict",
      "physical monotonic owner consumer authority belongs to another context",
    );
  }
  let heads = readHeads(state);
  if (heads.length === 0) {
    const claimGenesis = issueOwnerClaimEnvelope(state, authorityState, claimBinding, null);
    if (!appendOwnerHead(state, heads, claimGenesis)) heads = readHeads(state);
    else heads = readHeads(state);
  }
  const claimed = readClaimedOwnerHeads(state, authorityState, claimBinding);
  let consumerPort = Object.create(null);
  Object.defineProperties(consumerPort, {
    version: { value: PHYSICAL_MONOTONIC_OWNER_VERSION, enumerable: true },
    kind: { value: "physical_experiment_monotonic_owner_port", enumerable: true },
    target_domain: { value: state.domain, enumerable: true },
    session_nucleus_hash: { value: state.nucleusHash, enumerable: true },
    context_domain: { value: state.contextDomain, enumerable: true },
    consumer_id: { value: authorityState.consumerId, enumerable: true },
    slot_digest: { value: state.enrollment.slot_digest, enumerable: true },
    claim_digest: {
      value: claimed.envelopes[0][CLAIM_ENVELOPE_FIELD].claim_digest,
      enumerable: true,
    },
    production_ready: { value: true, enumerable: true },
    toJSON: { value: rejectSerialization },
  });
  consumerPort = Object.freeze(consumerPort);
  CONSUMER_PORTS.add(consumerPort);
  CONSUMER_PORT_STATE.set(consumerPort, Object.freeze({
    state,
    authorityState,
    claimBinding,
  }));
  return consumerPort;
}

function assertProductionPhysicalExperimentMonotonicOwnerPort(port) {
  if (!port || !CONSUMER_PORTS.has(port) || !CONSUMER_PORT_STATE.has(port)
      || !Object.isFrozen(port) || port.production_ready !== true) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_untrusted",
      "a live privately branded production monotonic owner consumer port is required",
    );
  }
  const consumer = CONSUMER_PORT_STATE.get(port);
  const current = assertOwnerCurrent(consumer.state);
  if (current.custody.production_ready !== true) {
    throw monotonicError(
      "physical_monotonic_owner_custody_drift",
      "production monotonic owner consumer lost live Mechanism-A custody",
    );
  }
  const claimed = readClaimedOwnerHeads(
    consumer.state,
    consumer.authorityState,
    consumer.claimBinding,
  );
  if (claimed.envelopes[0][CLAIM_ENVELOPE_FIELD].claim_digest !== port.claim_digest) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_conflict",
      "physical monotonic owner consumer claim changed",
    );
  }
  return port;
}

function readProductionPhysicalExperimentMonotonicOwnerState(portInput) {
  const port = assertProductionPhysicalExperimentMonotonicOwnerPort(portInput);
  const consumer = CONSUMER_PORT_STATE.get(port);
  const claimed = readClaimedOwnerHeads(
    consumer.state,
    consumer.authorityState,
    consumer.claimBinding,
  );
  assertOwnerCurrent(consumer.state);
  return deepFreeze(copyJsonData(
    claimed.envelopes.at(-1).consumer_state,
    "physical monotonic owner consumer state readback",
  ));
}

function readProductionPhysicalExperimentMonotonicOwnerHistory(portInput) {
  const port = assertProductionPhysicalExperimentMonotonicOwnerPort(portInput);
  const consumer = CONSUMER_PORT_STATE.get(port);
  const claimed = readClaimedOwnerHeads(
    consumer.state,
    consumer.authorityState,
    consumer.claimBinding,
  );
  assertOwnerCurrent(consumer.state);
  return deepFreeze(claimed.envelopes.slice(1).map((envelope, index) => copyJsonData(
    envelope.consumer_state,
    `physical experiment monotonic owner history state ${index + 1}`,
  )));
}

function compareAndSetProductionPhysicalExperimentMonotonicOwnerState(
  portInput,
  expectedState,
  nextState,
) {
  const port = assertProductionPhysicalExperimentMonotonicOwnerPort(portInput);
  const consumer = CONSUMER_PORT_STATE.get(port);
  const expected = expectedState == null
    ? null
    : copyJsonData(expectedState, "physical monotonic owner consumer expected state");
  if (nextState == null) {
    throw monotonicError(
      "physical_monotonic_owner_contract_invalid",
      "next consumer state cannot be null",
    );
  }
  const next = copyJsonData(nextState, "physical monotonic owner next consumer state");
  const claimed = readClaimedOwnerHeads(
    consumer.state,
    consumer.authorityState,
    consumer.claimBinding,
  );
  const current = claimed.envelopes.at(-1).consumer_state;
  if (canonicalJson(current) !== canonicalJson(expected)) return false;
  assertConsumerMonotonicTransition(
    current,
    next,
    "physical monotonic owner consumer CAS",
  );
  const envelope = issueOwnerClaimEnvelope(
    consumer.state,
    consumer.authorityState,
    consumer.claimBinding,
    next,
  );
  return appendOwnerHead(consumer.state, claimed.heads, envelope);
}

function claimProductionPhysicalTrustedClockMonotonicOwner(portInput, claimBindingInput) {
  const port = assertProductionPhysicalMonotonicOwnerPort(portInput);
  const authorityState = assertConsumerAuthority(PHYSICAL_TRUSTED_CLOCK_CONSUMER_AUTHORITY);
  const state = PORT_STATE.get(port);
  const claimBinding = normalizePhysicalTrustedClockClaimBinding(claimBindingInput, state);
  if (authorityState.contextDomain !== state.contextDomain) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_conflict",
      "physical monotonic owner trusted-clock authority belongs to another context",
    );
  }
  let heads = readHeads(state);
  if (heads.length === 0) {
    const claimGenesis = issueTrustedClockOwnerClaimEnvelope(
      state,
      authorityState,
      claimBinding,
      null,
    );
    if (!appendOwnerHead(state, heads, claimGenesis)) heads = readHeads(state);
    else heads = readHeads(state);
  }
  const claimed = readTrustedClockClaimedOwnerHeads(state, authorityState, claimBinding);
  let consumerPort = Object.create(null);
  Object.defineProperties(consumerPort, {
    version: { value: PHYSICAL_MONOTONIC_OWNER_VERSION, enumerable: true },
    kind: { value: "physical_trusted_clock_monotonic_owner_port", enumerable: true },
    target_domain: { value: state.domain, enumerable: true },
    session_nucleus_hash: { value: state.nucleusHash, enumerable: true },
    context_domain: { value: state.contextDomain, enumerable: true },
    consumer_id: { value: authorityState.consumerId, enumerable: true },
    clock_id: { value: claimBinding.clock_id, enumerable: true },
    authority_root_identity_digest: {
      value: claimBinding.authority_root_identity_digest,
      enumerable: true,
    },
    trust_root_public_key_digest: {
      value: claimBinding.trust_root_public_key_digest,
      enumerable: true,
    },
    slot_digest: { value: state.enrollment.slot_digest, enumerable: true },
    claim_digest: {
      value: claimed.envelopes[0][CLAIM_ENVELOPE_FIELD].claim_digest,
      enumerable: true,
    },
    production_ready: { value: true, enumerable: true },
    toJSON: { value: rejectSerialization },
  });
  consumerPort = Object.freeze(consumerPort);
  TRUSTED_CLOCK_CONSUMER_PORTS.add(consumerPort);
  TRUSTED_CLOCK_CONSUMER_PORT_STATE.set(consumerPort, Object.freeze({
    state,
    authorityState,
    claimBinding,
  }));
  return consumerPort;
}

function assertProductionPhysicalTrustedClockMonotonicOwnerPort(port) {
  if (!port || !TRUSTED_CLOCK_CONSUMER_PORTS.has(port)
      || !TRUSTED_CLOCK_CONSUMER_PORT_STATE.has(port)
      || !Object.isFrozen(port) || port.production_ready !== true) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_untrusted",
      "a live privately branded production trusted-clock monotonic owner port is required",
    );
  }
  const consumer = TRUSTED_CLOCK_CONSUMER_PORT_STATE.get(port);
  const current = assertOwnerCurrent(consumer.state);
  if (current.custody.production_ready !== true) {
    throw monotonicError(
      "physical_monotonic_owner_custody_drift",
      "production trusted-clock monotonic owner lost live Mechanism-A custody",
    );
  }
  const claimed = readTrustedClockClaimedOwnerHeads(
    consumer.state,
    consumer.authorityState,
    consumer.claimBinding,
  );
  if (claimed.envelopes[0][CLAIM_ENVELOPE_FIELD].claim_digest !== port.claim_digest) {
    throw monotonicError(
      "physical_monotonic_owner_consumer_conflict",
      "physical monotonic owner trusted-clock consumer claim changed",
    );
  }
  return port;
}

function readProductionPhysicalTrustedClockMonotonicOwnerState(portInput) {
  const port = assertProductionPhysicalTrustedClockMonotonicOwnerPort(portInput);
  const consumer = TRUSTED_CLOCK_CONSUMER_PORT_STATE.get(port);
  const claimed = readTrustedClockClaimedOwnerHeads(
    consumer.state,
    consumer.authorityState,
    consumer.claimBinding,
  );
  assertOwnerCurrent(consumer.state);
  return deepFreeze(copyJsonData(
    claimed.envelopes.at(-1).consumer_state,
    "physical trusted-clock monotonic owner state readback",
  ));
}

function readProductionPhysicalTrustedClockMonotonicOwnerHistory(portInput) {
  const port = assertProductionPhysicalTrustedClockMonotonicOwnerPort(portInput);
  const consumer = TRUSTED_CLOCK_CONSUMER_PORT_STATE.get(port);
  const claimed = readTrustedClockClaimedOwnerHeads(
    consumer.state,
    consumer.authorityState,
    consumer.claimBinding,
  );
  assertOwnerCurrent(consumer.state);
  return deepFreeze(claimed.envelopes.slice(1).map((envelope, index) => copyJsonData(
    envelope.consumer_state,
    `physical trusted-clock monotonic owner history state ${index + 1}`,
  )));
}

function compareAndSetProductionPhysicalTrustedClockMonotonicOwnerState(
  portInput,
  expectedState,
  nextState,
) {
  const port = assertProductionPhysicalTrustedClockMonotonicOwnerPort(portInput);
  const consumer = TRUSTED_CLOCK_CONSUMER_PORT_STATE.get(port);
  const expected = expectedState == null
    ? null
    : copyJsonData(expectedState, "physical trusted-clock monotonic expected state");
  if (nextState == null) {
    throw monotonicError(
      "physical_monotonic_owner_contract_invalid",
      "next trusted-clock monotonic owner state cannot be null",
    );
  }
  const next = copyJsonData(nextState, "physical trusted-clock monotonic next state");
  const claimed = readTrustedClockClaimedOwnerHeads(
    consumer.state,
    consumer.authorityState,
    consumer.claimBinding,
  );
  const current = claimed.envelopes.at(-1).consumer_state;
  if (canonicalJson(current) !== canonicalJson(expected)) return false;
  assertConsumerMonotonicTransition(
    current,
    next,
    "physical trusted-clock monotonic owner CAS",
  );
  const envelope = issueTrustedClockOwnerClaimEnvelope(
    consumer.state,
    consumer.authorityState,
    consumer.claimBinding,
    next,
  );
  return appendOwnerHead(consumer.state, claimed.heads, envelope);
}

function readPhysicalMonotonicOwnerState(portInput) {
  const port = assertPhysicalMonotonicOwnerPort(portInput);
  const state = PORT_STATE.get(port);
  const heads = readHeads(state);
  assertOwnerCurrent(state);
  if (heads.length > 0 && isOwnerClaimEnvelope(heads.at(-1).state)) {
    throw monotonicError(
      "physical_monotonic_owner_exclusively_claimed",
      "physical monotonic owner mutation and state are exclusively claimed by its fixed consumer",
    );
  }
  return heads.length === 0 ? null : deepFreeze(copyJsonData(heads.at(-1).state, "owner state readback"));
}

function compareAndSetPhysicalMonotonicOwnerState(portInput, expectedState, nextState) {
  const port = assertPhysicalMonotonicOwnerPort(portInput);
  const state = PORT_STATE.get(port);
  const expected = expectedState == null
    ? null
    : copyJsonData(expectedState, "physical monotonic expected state");
  if (nextState == null) {
    throw monotonicError("physical_monotonic_owner_contract_invalid", "next state cannot be null");
  }
  const next = copyJsonData(nextState, "physical monotonic next state");
  if (isOwnerClaimEnvelope(next)) {
    throw monotonicError(
      "physical_monotonic_owner_contract_invalid",
      "generic callers cannot mint the reserved exclusive-consumer envelope",
    );
  }
  const heads = readHeads(state);
  if (heads.length > 0 && isOwnerClaimEnvelope(heads.at(-1).state)) {
    throw monotonicError(
      "physical_monotonic_owner_exclusively_claimed",
      "physical monotonic owner mutation is exclusively claimed by its fixed consumer",
    );
  }
  const current = heads.length === 0 ? null : heads.at(-1).state;
  if (canonicalJson(current) !== canonicalJson(expected)) return false;
  return appendOwnerHead(state, heads, next);
}

function describePhysicalMonotonicOwner(portInput) {
  const port = assertPhysicalMonotonicOwnerPort(portInput);
  const state = PORT_STATE.get(port);
  const current = assertOwnerCurrent(state);
  const heads = readHeads(state);
  const head = heads.length === 0 ? null : heads.at(-1);
  assertOwnerCurrent(state);
  return deepFreeze({
    version: PHYSICAL_MONOTONIC_OWNER_VERSION,
    target_domain: state.domain,
    session_nucleus_hash: state.nucleusHash,
    context_domain: state.contextDomain,
    slot_digest: state.enrollment.slot_digest,
    enrollment_digest: state.enrollment.enrollment_digest,
    owner_custody_digest: current.custody.custody_digest,
    external_owner_root_identity_digest: state.rootIdentityDigest,
    signing_key_spki_sha256: state.key.document.public_key_spki_sha256,
    head_sequence: head == null ? 0 : head.sequence,
    head_digest: head == null ? null : head.head_digest,
    state_digest: head == null ? null : head.state_digest,
    production_ready: current.custody.production_ready,
    assurance: current.custody.production_ready
      ? "mechanism_a_isolated_owner_signed_monotonic_state"
      : "same_uid_signed_monotonic_state_conformance_only_non_authorizing",
  });
}

module.exports = Object.freeze({
  PHYSICAL_MONOTONIC_OWNER_VERSION,
  assertPhysicalMonotonicOwnerPort,
  assertProductionPhysicalExperimentMonotonicOwnerPort,
  assertProductionPhysicalTrustedClockMonotonicOwnerPort,
  assertProductionPhysicalMonotonicOwnerPort,
  claimProductionPhysicalExperimentMonotonicOwner,
  claimProductionPhysicalTrustedClockMonotonicOwner,
  compareAndSetProductionPhysicalExperimentMonotonicOwnerState,
  compareAndSetProductionPhysicalTrustedClockMonotonicOwnerState,
  compareAndSetPhysicalMonotonicOwnerState,
  describePhysicalMonotonicOwner,
  openProductionPhysicalMonotonicOwner,
  readProductionPhysicalExperimentMonotonicOwnerHistory,
  readProductionPhysicalExperimentMonotonicOwnerState,
  readProductionPhysicalTrustedClockMonotonicOwnerHistory,
  readProductionPhysicalTrustedClockMonotonicOwnerState,
  readPhysicalMonotonicOwnerState,
});
