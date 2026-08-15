"use strict";

// Bob-owned authenticated enrollment and current-trust head for production
// physical experiments.  Registry builders describe candidates; this journal
// is the production trust decision.  Each head is signed by a session-local
// Bob key, chained monotonically, bound to the verified physical nucleus, and
// reread on every authoritative use.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const { readVerifiedSessionNucleus } = require("../../core/governance/governance-store.js");
const {
  assertSafeDomain,
  physicalCampaignDir,
  sessionDir,
  sessionsRoot,
} = require("../../core/io/paths.js");
const {
  assertSafeSessionDirectoryIdentity,
  withSessionLock,
} = require("../../core/io/storage.js");
const {
  probeExactSigningKeyPathIsolation,
} = require("../../core/ledger-integrity/sandbox-isolation-attest.js");
const {
  PHYSICAL_EXPERIMENT_TRUST_PRIVATE_KEY_BASENAME,
} = require("../../core/ledger-integrity/signing-key-custody.js");

// Capture the small mutable-prototype surface used by the authority journal.
// A dependency that poisons Array/Object helpers after module load must not be
// able to redirect head ordering, exact-field checks, or live port validation.
const INTRINSIC_ARRAY_IS_ARRAY = Array.isArray;
const INTRINSIC_ARRAY_JOIN = Function.prototype.call.bind(Array.prototype.join);
const INTRINSIC_ARRAY_SLICE = Function.prototype.call.bind(Array.prototype.slice);
const INTRINSIC_ARRAY_SORT = Function.prototype.call.bind(Array.prototype.sort);
const INTRINSIC_HAS_OWN = Function.prototype.call.bind(Object.prototype.hasOwnProperty);
const INTRINSIC_OBJECT_CREATE = Object.create;
const INTRINSIC_OBJECT_FREEZE = Object.freeze;
const INTRINSIC_OBJECT_GET_DESCRIPTORS = Object.getOwnPropertyDescriptors;
const INTRINSIC_OBJECT_GET_PROTOTYPE = Object.getPrototypeOf;
const INTRINSIC_OBJECT_IS_FROZEN = Object.isFrozen;
const INTRINSIC_OBJECT_KEYS = Object.keys;
const INTRINSIC_OBJECT_PROTOTYPE = Object.prototype;
const INTRINSIC_OBJECT_VALUES = Object.values;
const INTRINSIC_OWN_KEYS = Reflect.ownKeys;
const INTRINSIC_JSON_PARSE = JSON.parse.bind(JSON);
const INTRINSIC_JSON_STRINGIFY = JSON.stringify.bind(JSON);

const PHYSICAL_EXPERIMENT_TRUST_HEAD_VERSION = 1;
const ZERO_HASH = "0".repeat(64);
const HASH_RE = /^[a-f0-9]{64}$/u;
const HEAD_FILE_RE = /^([0-9]{6})\.json$/u;
const STAGING_FILE_RE = /^\.(trust-signing-key\.json|physical-experiment-trust-signing-key-private\.json|[0-9]{6}\.json)\.([1-9][0-9]*)\.([0-9]+)\.([a-f0-9]{24})\.tmp$/u;
const MAX_KEY_BYTES = 64 * 1024;
const MAX_HEAD_BYTES = 256 * 1024;
const MAX_HEADS = 4096;
const TRUST_BINDING_FIELDS = INTRINSIC_OBJECT_FREEZE([
  "signer_trust_registry_digest",
  "observer_enrollment_registry_digest",
  "physical_receipt_registry_digest",
  "evidence_receipt_registry_digest",
  "requested_effects_registry_digest",
  "executed_evidence_registry_digest",
]);
const TRUST_PORTS = new WeakSet();
const TRUST_PORT_STATE = new WeakMap();
const SIGNER_OWNER_PORTS = new WeakSet();
const SIGNER_OWNER_PORT_STATE = new WeakMap();
const INTRINSIC_DATE = Date;
const INTRINSIC_DATE_NOW = Date.now.bind(Date);
const INTRINSIC_DATE_PARSE = Date.parse.bind(Date);
const INTRINSIC_DATE_TO_ISO = Function.prototype.call.bind(Date.prototype.toISOString);
const INTRINSIC_CREATE_HASH = crypto.createHash.bind(crypto);
const INTRINSIC_CREATE_PRIVATE_KEY = crypto.createPrivateKey.bind(crypto);
const INTRINSIC_CREATE_PUBLIC_KEY = crypto.createPublicKey.bind(crypto);
const INTRINSIC_GENERATE_KEY_PAIR = crypto.generateKeyPairSync.bind(crypto);
const INTRINSIC_RANDOM_BYTES = crypto.randomBytes.bind(crypto);
const INTRINSIC_SIGN = crypto.sign.bind(crypto);
const INTRINSIC_VERIFY = crypto.verify.bind(crypto);

function nowIso() {
  return INTRINSIC_DATE_TO_ISO(new INTRINSIC_DATE(INTRINSIC_DATE_NOW()));
}

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || INTRINSIC_OBJECT_IS_FROZEN(value)) return value;
  const children = INTRINSIC_OBJECT_VALUES(value);
  for (let index = 0; index < children.length; index += 1) deepFreeze(children[index]);
  return INTRINSIC_OBJECT_FREEZE(value);
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || INTRINSIC_ARRAY_IS_ARRAY(value)
      || utilTypes.isProxy(value)) return false;
  const prototype = INTRINSIC_OBJECT_GET_PROTOTYPE(value);
  return prototype === INTRINSIC_OBJECT_PROTOTYPE || prototype === null;
}

function cloneData(value, label, depth = 0) {
  if (depth > 12) throw new Error(`${label} exceeds the maximum nesting depth`);
  if (value == null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error(`${label} contains a non-finite number`);
    return value;
  }
  if (INTRINSIC_ARRAY_IS_ARRAY(value)) {
    if (utilTypes.isProxy(value) || value.length > 4096) {
      throw new Error(`${label} must be a bounded non-proxy array`);
    }
    const descriptors = INTRINSIC_OBJECT_GET_DESCRIPTORS(value);
    const keys = INTRINSIC_OWN_KEYS(value);
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      if (key === "length") continue;
      const descriptor = descriptors[key];
      if (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/u.test(key)
          || !descriptor || !INTRINSIC_HAS_OWN(descriptor, "value")
          || descriptor.enumerable !== true) {
        throw new Error(`${label} contains a non-data array field`);
      }
    }
    const result = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor) throw new Error(`${label} cannot be sparse`);
      result[index] = cloneData(descriptor.value, `${label}[${index}]`, depth + 1);
    }
    return result;
  }
  if (!isPlainDataObject(value)) throw new Error(`${label} must contain only plain data objects`);
  const descriptors = INTRINSIC_OBJECT_GET_DESCRIPTORS(value);
  const keys = INTRINSIC_OWN_KEYS(value);
  if (keys.length > 128) {
    throw new Error(`${label} has invalid or excessive fields`);
  }
  const result = {};
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (typeof key !== "string") throw new Error(`${label} has invalid or excessive fields`);
    const descriptor = descriptors[key];
    if (!descriptor || !INTRINSIC_HAS_OWN(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw new Error(`${label}.${key} must be an enumerable data property`);
    }
    result[key] = cloneData(descriptor.value, `${label}.${key}`, depth + 1);
  }
  return result;
}

function exactObject(value, label, fields) {
  const copy = cloneData(value, label);
  if (!isPlainDataObject(copy)) throw new Error(`${label} must be a plain data object`);
  const actual = INTRINSIC_ARRAY_SORT(INTRINSIC_OBJECT_KEYS(copy));
  const expected = INTRINSIC_ARRAY_SORT(INTRINSIC_ARRAY_SLICE(fields));
  let mismatch = actual.length !== expected.length;
  for (let index = 0; !mismatch && index < actual.length; index += 1) {
    mismatch = actual[index] !== expected[index];
  }
  if (mismatch) {
    throw new Error(`${label} must carry exactly ${INTRINSIC_ARRAY_JOIN(fields, ", ")}`);
  }
  return copy;
}

function canonicalizeTrustValue(value) {
  if (INTRINSIC_ARRAY_IS_ARRAY(value)) {
    const result = new Array(value.length);
    for (let index = 0; index < value.length; index += 1) {
      result[index] = canonicalizeTrustValue(value[index]);
    }
    return result;
  }
  if (value != null && typeof value === "object") {
    const result = INTRINSIC_OBJECT_CREATE(null);
    const keys = INTRINSIC_ARRAY_SORT(INTRINSIC_OBJECT_KEYS(value));
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      if (value[key] !== undefined) result[key] = canonicalizeTrustValue(value[key]);
    }
    return result;
  }
  return value;
}

function trustHashCanonicalJson(value) {
  return INTRINSIC_CREATE_HASH("sha256")
    .update(INTRINSIC_JSON_STRINGIFY(canonicalizeTrustValue(value)))
    .digest("hex");
}

function digest(value, label) {
  if (typeof value !== "string" || !HASH_RE.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function integer(value, label, min = 0, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${label} must be a safe integer between ${min} and ${max}`);
  }
  return value;
}

function timestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(INTRINSIC_DATE_PARSE(value))
      || INTRINSIC_DATE_TO_ISO(new INTRINSIC_DATE(value)) !== value) {
    throw new Error(`${label} must be a canonical UTC timestamp`);
  }
  return value;
}

function targetDomain(value) {
  if (typeof value !== "string" || value !== value.trim() || value.length > 253) {
    throw new Error("physical experiment trust target_domain is invalid");
  }
  const domain = assertSafeDomain(value);
  const root = sessionsRoot();
  const directory = sessionDir(domain);
  if (domain === "." || directory === root || path.dirname(directory) !== root) {
    throw new Error("physical experiment trust target_domain must identify one session child");
  }
  return domain;
}

function trustBinding(input, label = "physical experiment trust binding") {
  const copy = exactObject(input, label, TRUST_BINDING_FIELDS);
  const result = {};
  for (const field of TRUST_BINDING_FIELDS) result[field] = digest(copy[field], `${label}.${field}`);
  return deepFreeze(result);
}

function fsyncDirectory(directoryPath) {
  const descriptor = fs.openSync(directoryPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function ownedDirectory(directoryPath, label, { create = false } = {}) {
  let created = false;
  let stats;
  try {
    stats = fs.lstatSync(directoryPath);
  } catch (error) {
    if (!create || !error || error.code !== "ENOENT") throw new Error(`${label} is unavailable`);
    fs.mkdirSync(directoryPath, { recursive: false, mode: 0o700 });
    created = true;
    stats = fs.lstatSync(directoryPath);
  }
  const ownerMismatch = typeof process.getuid === "function" && stats.uid !== process.getuid();
  if (!stats.isDirectory() || stats.isSymbolicLink() || ownerMismatch || (stats.mode & 0o077) !== 0) {
    throw new Error(`${label} must be a Bob-owned mode-0700 real directory`);
  }
  if (created) fsyncDirectory(path.dirname(directoryPath));
  return INTRINSIC_OBJECT_FREEZE({ path: directoryPath, dev: stats.dev, ino: stats.ino });
}

function assertDirectory(identity, label) {
  const stats = fs.lstatSync(identity.path);
  const ownerMismatch = typeof process.getuid === "function" && stats.uid !== process.getuid();
  if (!stats.isDirectory() || stats.isSymbolicLink() || ownerMismatch
      || (stats.mode & 0o077) !== 0 || stats.dev !== identity.dev || stats.ino !== identity.ino) {
    throw new Error(`${label} changed during trust-store operation`);
  }
}

function pathsFor(domain) {
  const root = path.join(physicalCampaignDir(domain), "experiment-trust");
  return INTRINSIC_OBJECT_FREEZE({
    root,
    key: path.join(root, "trust-signing-key.json"),
    privateKey: path.join(root, PHYSICAL_EXPERIMENT_TRUST_PRIVATE_KEY_BASENAME),
    heads: path.join(root, "heads"),
    staging: path.join(root, ".staging"),
  });
}

function ensureLayout(domain, directoryIdentity) {
  assertSafeSessionDirectoryIdentity(directoryIdentity);
  const campaign = physicalCampaignDir(domain);
  const campaignIdentity = ownedDirectory(
    campaign,
    "physical campaign directory",
    { create: true },
  );
  const paths = pathsFor(domain);
  const root = ownedDirectory(paths.root, "physical experiment trust directory", { create: true });
  ownedDirectory(paths.heads, "physical experiment trust heads directory", { create: true });
  ownedDirectory(paths.staging, "physical experiment trust staging directory", { create: true });
  assertDirectory(campaignIdentity, "physical campaign directory");
  assertDirectory(root, "physical experiment trust directory");
  assertSafeSessionDirectoryIdentity(directoryIdentity);
  return paths;
}

function readOwnedJson(filePath, label, maximumBytes) {
  const parent = ownedDirectory(path.dirname(filePath), `${label} parent`);
  const pathStats = fs.lstatSync(filePath);
  const ownerMismatch = typeof process.getuid === "function" && pathStats.uid !== process.getuid();
  if (!pathStats.isFile() || pathStats.isSymbolicLink() || pathStats.nlink !== 1
      || pathStats.size < 1 || pathStats.size > maximumBytes || ownerMismatch
      || (pathStats.mode & 0o077) !== 0) {
    throw new Error(`${label} failed Bob-owned verified-read constraints`);
  }
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const stats = fs.fstatSync(descriptor);
    if (!stats.isFile() || stats.nlink !== 1 || stats.dev !== pathStats.dev
        || stats.ino !== pathStats.ino || stats.size !== pathStats.size) {
      throw new Error(`${label} changed before verified read`);
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    const finalStats = fs.lstatSync(filePath);
    if (after.dev !== stats.dev || after.ino !== stats.ino || after.size !== stats.size
        || finalStats.dev !== stats.dev || finalStats.ino !== stats.ino
        || finalStats.nlink !== 1 || finalStats.isSymbolicLink()) {
      throw new Error(`${label} changed during verified read`);
    }
    assertDirectory(parent, `${label} parent`);
    let parsed;
    try {
      parsed = INTRINSIC_JSON_PARSE(bytes.toString("utf8"));
    } catch {
      throw new Error(`${label} must contain valid JSON`);
    }
    return cloneData(parsed, label);
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
  }
}

function unlinkExact(filePath, expected, parent, label) {
  assertDirectory(parent, `${label} parent`);
  const current = fs.lstatSync(filePath);
  if (!current.isFile() || current.isSymbolicLink()
      || current.dev !== expected.dev || current.ino !== expected.ino
      || current.nlink !== expected.nlink) {
    throw new Error(`${label} changed before unlink`);
  }
  fs.unlinkSync(filePath);
  assertDirectory(parent, `${label} parent`);
}

function recoverStaging(paths) {
  const staging = ownedDirectory(paths.staging, "physical experiment trust staging directory");
  const names = INTRINSIC_ARRAY_SORT(fs.readdirSync(paths.staging));
  if (names.length > 128) throw new Error("physical experiment trust staging contains excessive entries");
  let changed = false;
  for (const name of names) {
    const match = STAGING_FILE_RE.exec(name);
    if (!match) throw new Error("physical experiment trust staging contains an unknown entry");
    const stagedPath = path.join(paths.staging, name);
    const staged = fs.lstatSync(stagedPath);
    const ownerMismatch = typeof process.getuid === "function" && staged.uid !== process.getuid();
    if (!staged.isFile() || staged.isSymbolicLink()
        || (staged.nlink !== 1 && staged.nlink !== 2)
        || staged.size > MAX_HEAD_BYTES || ownerMismatch || (staged.mode & 0o077) !== 0) {
      throw new Error("physical experiment trust staging entry is unsafe");
    }
    const basename = match[1];
    const finalPath = basename === "trust-signing-key.json"
      ? paths.key
      : basename === PHYSICAL_EXPERIMENT_TRUST_PRIVATE_KEY_BASENAME
        ? paths.privateKey
        : path.join(paths.heads, basename);
    let final = null;
    try {
      final = fs.lstatSync(finalPath);
    } catch (error) {
      if (!error || error.code !== "ENOENT") throw error;
    }
    if (staged.nlink === 2) {
      if (basename === "trust-signing-key.json"
          || basename === PHYSICAL_EXPERIMENT_TRUST_PRIVATE_KEY_BASENAME
          || final == null
          || !final.isFile() || final.isSymbolicLink()
          || final.dev !== staged.dev || final.ino !== staged.ino || final.nlink !== 2) {
        throw new Error("physical experiment trust staging entry conflicts with its final path");
      }
      fsyncDirectory(path.dirname(finalPath));
    }
    unlinkExact(stagedPath, staged, staging, "physical experiment trust staging entry");
    if (final != null && staged.nlink === 2) {
      const recovered = fs.lstatSync(finalPath);
      if (!recovered.isFile() || recovered.isSymbolicLink() || recovered.nlink !== 1
          || recovered.dev !== final.dev || recovered.ino !== final.ino) {
        throw new Error("physical experiment trust final file failed crash recovery");
      }
    }
    changed = true;
  }
  if (changed) fsyncDirectory(paths.staging);
  assertDirectory(staging, "physical experiment trust staging directory");
}

function tempPath(paths, finalPath) {
  return path.join(
    paths.staging,
    `.${path.basename(finalPath)}.${process.pid}.${INTRINSIC_DATE_NOW()}.${INTRINSIC_RANDOM_BYTES(12).toString("hex")}.tmp`,
  );
}

function writeKeyAtomic(paths, finalPath, document, mode, label) {
  const staging = ownedDirectory(paths.staging, "physical experiment trust staging directory");
  const root = ownedDirectory(paths.root, "physical experiment trust directory");
  const content = `${INTRINSIC_JSON_STRINGIFY(document)}\n`;
  if (Buffer.byteLength(content) > MAX_KEY_BYTES) throw new Error("physical experiment trust key exceeds its cap");
  const temporary = tempPath(paths, finalPath);
  let descriptor;
  let renamed = false;
  try {
    descriptor = fs.openSync(
      temporary,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY
        | (fs.constants.O_NOFOLLOW || 0),
      mode,
    );
    fs.writeFileSync(descriptor, content, "utf8");
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = null;
    assertDirectory(staging, "physical experiment trust staging directory");
    assertDirectory(root, "physical experiment trust directory");
    try {
      fs.lstatSync(finalPath);
      throw new Error(`${label} already exists`);
    } catch (error) {
      if (!error || error.code !== "ENOENT") throw error;
    }
    fs.renameSync(temporary, finalPath);
    renamed = true;
    fsyncDirectory(paths.root);
    fsyncDirectory(paths.staging);
    const final = fs.lstatSync(finalPath);
    const ownerMismatch = typeof process.getuid === "function" && final.uid !== process.getuid();
    if (!final.isFile() || final.isSymbolicLink() || final.nlink !== 1
        || ownerMismatch || (final.mode & 0o077) !== 0) {
      throw new Error(`${label} publication is unsafe`);
    }
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
    if (!renamed) {
      try {
        fs.unlinkSync(temporary);
        fsyncDirectory(paths.staging);
      } catch {}
    }
  }
}

function publishHead(paths, filePath, document) {
  const heads = ownedDirectory(paths.heads, "physical experiment trust heads directory");
  const staging = ownedDirectory(paths.staging, "physical experiment trust staging directory");
  const content = `${INTRINSIC_JSON_STRINGIFY(document)}\n`;
  if (Buffer.byteLength(content) > MAX_HEAD_BYTES) throw new Error("physical experiment trust head exceeds its cap");
  const temporary = tempPath(paths, filePath);
  let descriptor;
  let linked = false;
  try {
    descriptor = fs.openSync(
      temporary,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY
        | (fs.constants.O_NOFOLLOW || 0),
      0o600,
    );
    fs.writeFileSync(descriptor, content, "utf8");
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = null;
    assertDirectory(heads, "physical experiment trust heads directory");
    assertDirectory(staging, "physical experiment trust staging directory");
    try {
      fs.linkSync(temporary, filePath);
      linked = true;
    } catch (error) {
      if (!error || error.code !== "EEXIST") throw error;
      return false;
    }
    fsyncDirectory(paths.heads);
    fs.unlinkSync(temporary);
    fsyncDirectory(paths.staging);
    const final = fs.lstatSync(filePath);
    if (!final.isFile() || final.isSymbolicLink() || final.nlink !== 1) {
      throw new Error("physical experiment trust head publication is unsafe");
    }
    return true;
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
    try {
      fs.unlinkSync(temporary);
      fsyncDirectory(paths.staging);
    } catch {}
    if (linked) {
      assertDirectory(heads, "physical experiment trust heads directory");
      assertDirectory(staging, "physical experiment trust staging directory");
    }
  }
}

function normalizePrivateKeyDocument(input, domain) {
  const copy = exactObject(input, "physical experiment trust private owner key", [
    "version",
    "target_domain",
    "signature_scheme",
    "private_key_der_base64url",
    "created_at",
    "record_digest",
  ]);
  if (copy.version !== PHYSICAL_EXPERIMENT_TRUST_HEAD_VERSION
      || copy.target_domain !== domain
      || copy.signature_scheme !== "ed25519") {
    throw new Error("physical experiment trust private owner key binding drift");
  }
  if (typeof copy.private_key_der_base64url !== "string"
      || copy.private_key_der_base64url.length < 32
      || copy.private_key_der_base64url.length > 4096
      || !/^[A-Za-z0-9_-]+$/u.test(copy.private_key_der_base64url)) {
    throw new Error("physical experiment trust private owner key material is invalid");
  }
  let privateKey;
  try {
    privateKey = INTRINSIC_CREATE_PRIVATE_KEY({
      key: Buffer.from(copy.private_key_der_base64url, "base64url"),
      format: "der",
      type: "pkcs8",
    });
  } catch {
    throw new Error("physical experiment trust private owner key material is unreadable");
  }
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("physical experiment trust private owner key must be Ed25519");
  }
  const publicKey = INTRINSIC_CREATE_PUBLIC_KEY(privateKey);
  const spkiDigest = INTRINSIC_CREATE_HASH("sha256")
    .update(publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
  const body = {
    version: PHYSICAL_EXPERIMENT_TRUST_HEAD_VERSION,
    target_domain: domain,
    signature_scheme: "ed25519",
    private_key_der_base64url: copy.private_key_der_base64url,
    created_at: timestamp(copy.created_at, "physical experiment trust private owner key.created_at"),
  };
  const recordDigest = trustHashCanonicalJson({
    domain: "hacker-bob/physical-experiment-trust-private-owner-key/v1",
    ...body,
  });
  if (digest(copy.record_digest, "physical experiment trust private owner key.record_digest")
      !== recordDigest) {
    throw new Error("physical experiment trust private owner key record digest drift");
  }
  return { document: deepFreeze({ ...body, record_digest: recordDigest }), privateKey, publicKey, spkiDigest };
}

function normalizeKeyDocument(input, domain, expectedPublicKey) {
  const copy = exactObject(input, "physical experiment trust public key descriptor", [
    "version",
    "target_domain",
    "key_id",
    "signature_scheme",
    "public_key_pem",
    "public_key_spki_sha256",
    "private_owner_key_path_digest",
    "created_at",
    "record_digest",
  ]);
  if (copy.version !== PHYSICAL_EXPERIMENT_TRUST_HEAD_VERSION
      || copy.target_domain !== domain
      || copy.signature_scheme !== "ed25519"
      || typeof copy.key_id !== "string"
      || !copy.key_id.startsWith("physical-experiment-trust-key:v1:")) {
    throw new Error("physical experiment trust public key descriptor binding drift");
  }
  if (typeof copy.public_key_pem !== "string" || copy.public_key_pem.length > 16_384) {
    throw new Error("physical experiment trust public key descriptor material is invalid");
  }
  let publicKey;
  try {
    publicKey = INTRINSIC_CREATE_PUBLIC_KEY(copy.public_key_pem);
  } catch {
    throw new Error("physical experiment trust public key descriptor is unreadable");
  }
  if (publicKey.asymmetricKeyType !== "ed25519") {
    throw new Error("physical experiment trust public key descriptor must be Ed25519");
  }
  const body = {
    version: PHYSICAL_EXPERIMENT_TRUST_HEAD_VERSION,
    target_domain: domain,
    key_id: copy.key_id,
    signature_scheme: "ed25519",
    public_key_pem: copy.public_key_pem,
    public_key_spki_sha256: digest(copy.public_key_spki_sha256, "trust key public digest"),
    private_owner_key_path_digest: digest(
      copy.private_owner_key_path_digest,
      "trust key private owner path digest",
    ),
    created_at: timestamp(copy.created_at, "trust key created_at"),
  };
  const expectedSpki = INTRINSIC_CREATE_HASH("sha256")
    .update(expectedPublicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
  const descriptorSpki = INTRINSIC_CREATE_HASH("sha256")
    .update(publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
  if (body.public_key_spki_sha256 !== descriptorSpki
      || body.public_key_spki_sha256 !== expectedSpki
      || body.key_id !== `physical-experiment-trust-key:v1:${expectedSpki}`
      || publicKey.export({ type: "spki", format: "der" }).toString("hex")
        !== expectedPublicKey.export({ type: "spki", format: "der" }).toString("hex")) {
    throw new Error("physical experiment trust public key descriptor identity drift");
  }
  const recordDigest = trustHashCanonicalJson({
    domain: "hacker-bob/physical-experiment-trust-public-key-descriptor/v1",
    ...body,
  });
  if (digest(copy.record_digest, "trust key record_digest") !== recordDigest) {
    throw new Error("physical experiment trust public key descriptor record digest drift");
  }
  return { document: deepFreeze({ ...body, record_digest: recordDigest }), publicKey };
}

function readOrCreateKey(paths, domain) {
  let privateOwner;
  try {
    privateOwner = normalizePrivateKeyDocument(
      readOwnedJson(paths.privateKey, "physical experiment trust private owner key", MAX_KEY_BYTES),
      domain,
    );
  } catch (error) {
    if (!error || (error.code !== "ENOENT" && error.code !== "ENOTDIR")) {
      try {
        fs.lstatSync(paths.privateKey);
        throw error;
      } catch (statsError) {
        if (!statsError || statsError.code !== "ENOENT") throw error;
      }
    }
  }
  if (!privateOwner) {
    const pair = INTRINSIC_GENERATE_KEY_PAIR("ed25519");
    const privateBody = {
      version: PHYSICAL_EXPERIMENT_TRUST_HEAD_VERSION,
      target_domain: domain,
      signature_scheme: "ed25519",
      private_key_der_base64url: pair.privateKey
        .export({ type: "pkcs8", format: "der" })
        .toString("base64url"),
      created_at: nowIso(),
    };
    writeKeyAtomic(paths, paths.privateKey, {
      ...privateBody,
      record_digest: trustHashCanonicalJson({
        domain: "hacker-bob/physical-experiment-trust-private-owner-key/v1",
        ...privateBody,
      }),
    }, 0o400, "physical experiment trust private owner key");
    privateOwner = normalizePrivateKeyDocument(
      readOwnedJson(paths.privateKey, "physical experiment trust private owner key", MAX_KEY_BYTES),
      domain,
    );
  }
  const pathDigest = trustHashCanonicalJson({
    domain: "hacker-bob/physical-experiment-trust-private-owner-key-path/v1",
    target_domain: domain,
    private_owner_key_path: paths.privateKey,
  });
  let descriptor;
  try {
    descriptor = normalizeKeyDocument(
      readOwnedJson(paths.key, "physical experiment trust public key descriptor", MAX_KEY_BYTES),
      domain,
      privateOwner.publicKey,
    );
  } catch (error) {
    let missing = false;
    try {
      fs.lstatSync(paths.key);
    } catch (statsError) {
      missing = Boolean(statsError && statsError.code === "ENOENT");
    }
    if (!missing) throw error;
  }
  if (!descriptor) {
    const spkiDigest = privateOwner.spkiDigest;
    const descriptorBody = {
      version: PHYSICAL_EXPERIMENT_TRUST_HEAD_VERSION,
      target_domain: domain,
      key_id: `physical-experiment-trust-key:v1:${spkiDigest}`,
      signature_scheme: "ed25519",
      public_key_pem: privateOwner.publicKey.export({ type: "spki", format: "pem" }),
      public_key_spki_sha256: spkiDigest,
      private_owner_key_path_digest: pathDigest,
      created_at: privateOwner.document.created_at,
    };
    writeKeyAtomic(paths, paths.key, {
      ...descriptorBody,
      record_digest: trustHashCanonicalJson({
        domain: "hacker-bob/physical-experiment-trust-public-key-descriptor/v1",
        ...descriptorBody,
      }),
    }, 0o600, "physical experiment trust public key descriptor");
    descriptor = normalizeKeyDocument(
      readOwnedJson(paths.key, "physical experiment trust public key descriptor", MAX_KEY_BYTES),
      domain,
      privateOwner.publicKey,
    );
  }
  if (descriptor.document.private_owner_key_path_digest !== pathDigest) {
    throw new Error("physical experiment trust public descriptor private-owner path drift");
  }
  return {
    document: descriptor.document,
    publicKey: descriptor.publicKey,
    privateOwnerPath: paths.privateKey,
  };
}

function liveSignerOwnerCustody(domain, paths, key) {
  const isolationProbe = probeExactSigningKeyPathIsolation(paths.privateKey, {
    expectedRoot: paths.root,
    custodyRoot: sessionDir(domain),
  });
  const expectedPrivatePath = path.dirname(paths.privateKey) === paths.root
    && path.basename(paths.privateKey) === PHYSICAL_EXPERIMENT_TRUST_PRIVATE_KEY_BASENAME;
  const publicSpki = INTRINSIC_CREATE_HASH("sha256")
    .update(key.publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
  const publicKeyCurrent = publicSpki === key.document.public_key_spki_sha256;
  const productionReady = isolationProbe.version === 1
    && isolationProbe.assurance === "mechanism_a_exact_signing_key_path_isolation"
    && isolationProbe.isolated === true
    && expectedPrivatePath
    && publicKeyCurrent;
  const proofBody = {
    version: 1,
    target_domain: domain,
    private_owner_key_path_digest: key.document.private_owner_key_path_digest,
    signing_key_spki_sha256: publicSpki,
    expected_private_path: expectedPrivatePath,
    public_key_current: publicKeyCurrent,
    isolation_probe: isolationProbe,
    production_ready: productionReady,
  };
  return deepFreeze({
    ...proofBody,
    custody_digest: trustHashCanonicalJson({
      domain: "hacker-bob/physical-experiment-trust-signer-owner-custody/v1",
      ...proofBody,
    }),
    blocker: productionReady
      ? null
      : "isolated_physical_experiment_trust_signer_owner_unavailable",
  });
}

function createSignerOwnerPort(domain, paths, key) {
  const custody = liveSignerOwnerCustody(domain, paths, key);
  const port = deepFreeze({
    version: 1,
    production_ready: custody.production_ready,
    custody_assurance: custody.production_ready
      ? "mechanism_a_exact_signing_key_path_isolation"
      : "same_uid_local_conformance_signer_non_authorizing",
    target_domain: domain,
    signing_key_spki_sha256: key.document.public_key_spki_sha256,
    private_owner_key_path_digest: key.document.private_owner_key_path_digest,
    custody_digest: custody.custody_digest,
    blocker: custody.blocker,
  });
  SIGNER_OWNER_PORTS.add(port);
  SIGNER_OWNER_PORT_STATE.set(port, { domain, paths, key, custody });
  return port;
}

function assertSignerOwnerPortCurrent(port, { requireProduction = false } = {}) {
  if (!port || !SIGNER_OWNER_PORTS.has(port) || !SIGNER_OWNER_PORT_STATE.has(port)
      || !INTRINSIC_OBJECT_IS_FROZEN(port)) {
    throw new Error("physical experiment trust signer owner must be a live private Bob owner port");
  }
  const state = SIGNER_OWNER_PORT_STATE.get(port);
  const custody = liveSignerOwnerCustody(state.domain, state.paths, state.key);
  if (custody.custody_digest !== state.custody.custody_digest
      || custody.production_ready !== state.custody.production_ready
      || custody.production_ready !== port.production_ready) {
    throw new Error("physical experiment trust signer-owner custody changed");
  }
  if (requireProduction && custody.production_ready !== true) {
    throw new Error(
      "production physical experiment trust requires Mechanism-A isolated signer-owner custody",
    );
  }
  return custody;
}

function signWithSignerOwner(port, payloadDigest) {
  const state = SIGNER_OWNER_PORT_STATE.get(port);
  if (!state) throw new Error("physical experiment trust signer owner is unavailable");
  assertSignerOwnerPortCurrent(port);
  const privateOwner = normalizePrivateKeyDocument(
    readOwnedJson(
      state.paths.privateKey,
      "physical experiment trust private owner key",
      MAX_KEY_BYTES,
    ),
    state.domain,
  );
  if (privateOwner.spkiDigest !== port.signing_key_spki_sha256) {
    throw new Error("physical experiment trust signer-owner key identity changed");
  }
  const signature = INTRINSIC_SIGN(
    null,
    Buffer.from(digest(payloadDigest, "physical experiment trust signing payload"), "hex"),
    privateOwner.privateKey,
  ).toString("base64url");
  assertSignerOwnerPortCurrent(port);
  return signature;
}

function headPayload(input) {
  return {
    version: PHYSICAL_EXPERIMENT_TRUST_HEAD_VERSION,
    sequence: integer(input.sequence, "physical experiment trust head.sequence", 1, MAX_HEADS),
    previous_head_digest: digest(
      input.previous_head_digest,
      "physical experiment trust head.previous_head_digest",
    ),
    target_domain: targetDomain(input.target_domain),
    session_nucleus_hash: digest(
      input.session_nucleus_hash,
      "physical experiment trust head.session_nucleus_hash",
    ),
    authority_epoch: integer(input.authority_epoch, "physical experiment trust head.authority_epoch", 1),
    revocation_generation: integer(
      input.revocation_generation,
      "physical experiment trust head.revocation_generation",
      0,
    ),
    trust_binding: trustBinding(input.trust_binding),
    trust_binding_digest: digest(
      input.trust_binding_digest,
      "physical experiment trust head.trust_binding_digest",
    ),
    signing_key_id: input.signing_key_id,
    signing_key_spki_sha256: digest(
      input.signing_key_spki_sha256,
      "physical experiment trust head.signing_key_spki_sha256",
    ),
    signer_owner_custody_digest: digest(
      input.signer_owner_custody_digest,
      "physical experiment trust head.signer_owner_custody_digest",
    ),
    enrolled_at: timestamp(input.enrolled_at, "physical experiment trust head.enrolled_at"),
  };
}

function normalizeHead(input, key, ownerPort, expectedDomain) {
  const copy = exactObject(input, "physical experiment trust head", [
    "version",
    "sequence",
    "previous_head_digest",
    "target_domain",
    "session_nucleus_hash",
    "authority_epoch",
    "revocation_generation",
    "trust_binding",
    "trust_binding_digest",
    "signing_key_id",
    "signing_key_spki_sha256",
    "signer_owner_custody_digest",
    "enrolled_at",
    "payload_digest",
    "signature",
    "head_digest",
  ]);
  const payload = headPayload(copy);
  if (payload.target_domain !== expectedDomain
      || payload.signing_key_id !== key.document.key_id
      || payload.signing_key_spki_sha256 !== key.document.public_key_spki_sha256
      || payload.signer_owner_custody_digest !== ownerPort.custody_digest) {
    throw new Error("physical experiment trust head authority binding drift");
  }
  const trustBindingDigest = trustHashCanonicalJson({
    domain: "hacker-bob/physical-experiment-production-trust-binding/v2",
    target_domain: payload.target_domain,
    session_nucleus_hash: payload.session_nucleus_hash,
    authority_epoch: payload.authority_epoch,
    revocation_generation: payload.revocation_generation,
    ...payload.trust_binding,
  });
  if (payload.trust_binding_digest !== trustBindingDigest) {
    throw new Error("physical experiment trust head binding digest drift");
  }
  const payloadDigest = trustHashCanonicalJson({
    domain: "hacker-bob/physical-experiment-trust-head-payload/v1",
    ...payload,
  });
  if (digest(copy.payload_digest, "physical experiment trust head.payload_digest") !== payloadDigest) {
    throw new Error("physical experiment trust head payload digest drift");
  }
  if (typeof copy.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/u.test(copy.signature)) {
    throw new Error("physical experiment trust head signature is invalid");
  }
  if (!INTRINSIC_VERIFY(
    null,
    Buffer.from(payloadDigest, "hex"),
    key.publicKey,
    Buffer.from(copy.signature, "base64url"),
  )) throw new Error("physical experiment trust head signature verification failed");
  const headDigest = trustHashCanonicalJson({
    domain: "hacker-bob/physical-experiment-trust-head/v1",
    ...payload,
    payload_digest: payloadDigest,
    signature: copy.signature,
  });
  if (digest(copy.head_digest, "physical experiment trust head.head_digest") !== headDigest) {
    throw new Error("physical experiment trust head digest drift");
  }
  return deepFreeze({
    ...payload,
    payload_digest: payloadDigest,
    signature: copy.signature,
    head_digest: headDigest,
  });
}

function readHeads(paths, key, ownerPort, domain) {
  const identity = ownedDirectory(paths.heads, "physical experiment trust heads directory");
  const names = INTRINSIC_ARRAY_SORT(fs.readdirSync(paths.heads));
  let invalidName = names.length > MAX_HEADS;
  for (let index = 0; !invalidName && index < names.length; index += 1) {
    invalidName = !HEAD_FILE_RE.test(names[index]);
  }
  if (invalidName) {
    throw new Error("physical experiment trust journal contains unknown or excessive entries");
  }
  const heads = [];
  for (let index = 0; index < names.length; index += 1) {
    const sequence = index + 1;
    if (names[index] !== `${String(sequence).padStart(6, "0")}.json`) {
      throw new Error("physical experiment trust journal contains a gap");
    }
    const head = normalizeHead(
      readOwnedJson(
        path.join(paths.heads, names[index]),
        `physical experiment trust head ${sequence}`,
        MAX_HEAD_BYTES,
      ),
      key,
      ownerPort,
      domain,
    );
    if (head.sequence !== sequence
        || head.previous_head_digest !== (sequence === 1 ? ZERO_HASH : heads[index - 1].head_digest)) {
      throw new Error("physical experiment trust journal chain is invalid");
    }
    heads.push(head);
  }
  assertDirectory(identity, "physical experiment trust heads directory");
  return INTRINSIC_OBJECT_FREEZE(heads);
}

function currentPhysicalNucleus(domain, expectedHash = null) {
  const nucleus = readVerifiedSessionNucleus(domain);
  if (!nucleus.physical_scope
      || (expectedHash != null && nucleus.nucleus_hash !== expectedHash)) {
    throw new Error("physical experiment trust requires the exact current physical session nucleus");
  }
  if (nucleus.target_domain != null && nucleus.target_domain !== domain) {
    throw new Error("physical experiment trust session target binding drift");
  }
  return nucleus;
}

function bindingDigest(domain, nucleus, binding) {
  return trustHashCanonicalJson({
    domain: "hacker-bob/physical-experiment-production-trust-binding/v2",
    target_domain: domain,
    session_nucleus_hash: nucleus.nucleus_hash,
    authority_epoch: nucleus.physical_scope.authority_epoch,
    revocation_generation: nucleus.physical_scope.revocation_generation,
    ...binding,
  });
}

function sameBinding(left, right) {
  return trustHashCanonicalJson(left) === trustHashCanonicalJson(right);
}

function issueHead({ domain, nucleus, binding, key, ownerPort, sequence, previousHeadDigest }) {
  const payload = headPayload({
    version: PHYSICAL_EXPERIMENT_TRUST_HEAD_VERSION,
    sequence,
    previous_head_digest: previousHeadDigest,
    target_domain: domain,
    session_nucleus_hash: nucleus.nucleus_hash,
    authority_epoch: nucleus.physical_scope.authority_epoch,
    revocation_generation: nucleus.physical_scope.revocation_generation,
    trust_binding: binding,
    trust_binding_digest: bindingDigest(domain, nucleus, binding),
    signing_key_id: key.document.key_id,
    signing_key_spki_sha256: key.document.public_key_spki_sha256,
    signer_owner_custody_digest: ownerPort.custody_digest,
    enrolled_at: nowIso(),
  });
  const payloadDigest = trustHashCanonicalJson({
    domain: "hacker-bob/physical-experiment-trust-head-payload/v1",
    ...payload,
  });
  const signature = signWithSignerOwner(ownerPort, payloadDigest);
  return normalizeHead({
    ...payload,
    payload_digest: payloadDigest,
    signature,
    head_digest: trustHashCanonicalJson({
      domain: "hacker-bob/physical-experiment-trust-head/v1",
      ...payload,
      payload_digest: payloadDigest,
      signature,
    }),
  }, key, ownerPort, domain);
}

function createPort(domain, head, ownerPort) {
  const productionReady = ownerPort.production_ready === true;
  const port = deepFreeze({
    version: PHYSICAL_EXPERIMENT_TRUST_HEAD_VERSION,
    production_ready: productionReady,
    trust_assurance: productionReady
      ? "mechanism_a_isolated_owner_signed_current_nucleus_trust_head"
      : "same_uid_signed_trust_head_conformance_only_non_authorizing",
    production_blocker: productionReady
      ? null
      : "isolated_physical_experiment_trust_signer_owner_unavailable",
    target_domain: domain,
    session_nucleus_hash: head.session_nucleus_hash,
    authority_epoch: head.authority_epoch,
    revocation_generation: head.revocation_generation,
    trust_binding_digest: head.trust_binding_digest,
    trust_head_sequence: head.sequence,
    trust_head_digest: head.head_digest,
    signing_key_spki_sha256: head.signing_key_spki_sha256,
    signer_owner_custody_digest: head.signer_owner_custody_digest,
  });
  TRUST_PORTS.add(port);
  TRUST_PORT_STATE.set(port, deepFreeze({ domain, head, ownerPort }));
  return port;
}

function enrollProductionPhysicalExperimentTrustHead(input) {
  const copy = exactObject(input, "production physical experiment trust enrollment", [
    "version",
    "target_domain",
    "session_nucleus_hash",
    "trust_binding",
  ]);
  if (copy.version !== PHYSICAL_EXPERIMENT_TRUST_HEAD_VERSION) {
    throw new Error("production physical experiment trust enrollment.version must be 1");
  }
  const domain = targetDomain(copy.target_domain);
  const expectedNucleusHash = digest(
    copy.session_nucleus_hash,
    "production physical experiment trust enrollment.session_nucleus_hash",
  );
  const binding = trustBinding(copy.trust_binding);
  let selected;
  withSessionLock(domain, (directoryIdentity) => {
    const nucleus = currentPhysicalNucleus(domain, expectedNucleusHash);
    const paths = ensureLayout(domain, directoryIdentity);
    recoverStaging(paths);
    const key = readOrCreateKey(paths, domain);
    const ownerPort = createSignerOwnerPort(domain, paths, key);
    const heads = readHeads(paths, key, ownerPort, domain);
    const last = heads.length === 0 ? null : heads[heads.length - 1];
    const desiredBindingDigest = bindingDigest(domain, nucleus, binding);
    if (last && last.session_nucleus_hash === nucleus.nucleus_hash
        && last.trust_binding_digest === desiredBindingDigest
        && sameBinding(last.trust_binding, binding)) {
      selected = last;
    } else {
      if (last && last.session_nucleus_hash === nucleus.nucleus_hash) {
        throw new Error("current physical session nucleus already has a conflicting trust enrollment");
      }
      if (last) {
        const regressed = nucleus.physical_scope.authority_epoch < last.authority_epoch
          || (nucleus.physical_scope.authority_epoch === last.authority_epoch
            && nucleus.physical_scope.revocation_generation < last.revocation_generation);
        if (regressed) throw new Error("physical experiment trust authority generation cannot regress");
        const bindingChanged = !sameBinding(last.trust_binding, binding);
        const authorityAdvanced = nucleus.physical_scope.authority_epoch > last.authority_epoch
          || nucleus.physical_scope.revocation_generation > last.revocation_generation;
        if (bindingChanged && !authorityAdvanced) {
          throw new Error("physical experiment trust replacement requires an advanced authority or revocation generation");
        }
      }
      if (heads.length >= MAX_HEADS) throw new Error("physical experiment trust journal is full");
      const candidate = issueHead({
        domain,
        nucleus,
        binding,
        key,
        ownerPort,
        sequence: heads.length + 1,
        previousHeadDigest: last == null ? ZERO_HASH : last.head_digest,
      });
      const filePath = path.join(paths.heads, `${String(candidate.sequence).padStart(6, "0")}.json`);
      const published = publishHead(paths, filePath, candidate);
      const durableHeads = readHeads(paths, key, ownerPort, domain);
      const durable = durableHeads.length === 0
        ? null
        : durableHeads[durableHeads.length - 1];
      if (!durable || durable.head_digest !== candidate.head_digest) {
        if (!published) throw new Error("physical experiment trust enrollment lost its monotonic head race");
        throw new Error("physical experiment trust enrollment lacks exact durable readback");
      }
      selected = durable;
    }
    assertSignerOwnerPortCurrent(ownerPort, { requireProduction: ownerPort.production_ready === true });
    currentPhysicalNucleus(domain, expectedNucleusHash);
    assertSafeSessionDirectoryIdentity(directoryIdentity);
    selected = { head: selected, ownerPort };
  });
  return createPort(domain, selected.head, selected.ownerPort);
}

function assertPhysicalExperimentTrustPort(port) {
  if (!port || !TRUST_PORTS.has(port) || !TRUST_PORT_STATE.has(port)
      || !INTRINSIC_OBJECT_IS_FROZEN(port)) {
    throw new Error("physical experiment trust requires a live signed trust port");
  }
  return port;
}

function assertProductionPhysicalExperimentTrustPort(port) {
  assertPhysicalExperimentTrustPort(port);
  if (port.production_ready !== true) {
    throw new Error(
      "production physical experiment trust requires Mechanism-A isolated signer-owner custody",
    );
  }
  const state = TRUST_PORT_STATE.get(port);
  assertSignerOwnerPortCurrent(state.ownerPort, { requireProduction: true });
  return port;
}

function assertProductionPhysicalExperimentTrustHeadCurrent(port) {
  const state = TRUST_PORT_STATE.get(assertProductionPhysicalExperimentTrustPort(port));
  let current;
  withSessionLock(state.domain, (directoryIdentity) => {
    const nucleus = currentPhysicalNucleus(state.domain, state.head.session_nucleus_hash);
    if (nucleus.physical_scope.authority_epoch !== state.head.authority_epoch
        || nucleus.physical_scope.revocation_generation !== state.head.revocation_generation) {
      throw new Error("physical experiment trust authority or revocation generation drifted");
    }
    const paths = ensureLayout(state.domain, directoryIdentity);
    recoverStaging(paths);
    const key = readOrCreateKey(paths, state.domain);
    assertSignerOwnerPortCurrent(state.ownerPort, { requireProduction: true });
    const heads = readHeads(paths, key, state.ownerPort, state.domain);
    const head = heads.length === 0 ? null : heads[heads.length - 1];
    if (!head || head.head_digest !== state.head.head_digest
        || head.sequence !== state.head.sequence
        || head.trust_binding_digest !== state.head.trust_binding_digest
        || head.signing_key_spki_sha256 !== state.head.signing_key_spki_sha256
        || head.signer_owner_custody_digest !== state.head.signer_owner_custody_digest) {
      throw new Error("production physical experiment trust port is stale or the signed head changed");
    }
    current = head;
    assertSignerOwnerPortCurrent(state.ownerPort, { requireProduction: true });
    currentPhysicalNucleus(state.domain, state.head.session_nucleus_hash);
    assertSafeSessionDirectoryIdentity(directoryIdentity);
  });
  return current;
}

function describeProductionPhysicalExperimentTrustPort(port) {
  const head = assertProductionPhysicalExperimentTrustHeadCurrent(port);
  return deepFreeze({
    target_domain: head.target_domain,
    session_nucleus_hash: head.session_nucleus_hash,
    authority_epoch: head.authority_epoch,
    revocation_generation: head.revocation_generation,
    trust_binding: head.trust_binding,
    trust_binding_digest: head.trust_binding_digest,
    trust_head_sequence: head.sequence,
    trust_head_digest: head.head_digest,
    signing_key_spki_sha256: head.signing_key_spki_sha256,
    signer_owner_custody_digest: head.signer_owner_custody_digest,
  });
}

module.exports = INTRINSIC_OBJECT_FREEZE({
  PHYSICAL_EXPERIMENT_TRUST_HEAD_VERSION,
  assertProductionPhysicalExperimentTrustHeadCurrent,
  assertProductionPhysicalExperimentTrustPort,
  describeProductionPhysicalExperimentTrustPort,
  enrollProductionPhysicalExperimentTrustHead,
});
