"use strict";

// Bob-owned durable storage for PhysicalExperimentLedger.  The journal is
// deliberately file-per-row. A second append-only row-head chain lives under
// the signer-custodied experiment-trust subtree, outside each experiment plan
// directory, so plan-local tail deletion is detected after restart. This local
// anchor is still in the same session snapshot/UID rollback domain and is not
// independently retained monotonic storage. Every operation runs under Bob's
// session lock and rechecks the current verified session nucleus.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const {
  readVerifiedSessionNucleus,
} = require("./governance-store.js");
const {
  assertSafeDomain,
  physicalCampaignDir,
  sessionDir,
  sessionsRoot,
} = require("./paths.js");
const {
  assertSafeSessionDirectoryIdentity,
  withSessionLock,
} = require("./storage.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  assertProductionPhysicalExperimentTrustPort,
  describeProductionPhysicalExperimentTrustPort,
} = require("./physical-experiment-trust-store.js");
const {
  assertProductionPhysicalExperimentMonotonicOwnerPort,
  assertProductionPhysicalMonotonicOwnerPort,
  claimProductionPhysicalExperimentMonotonicOwner,
  compareAndSetProductionPhysicalExperimentMonotonicOwnerState,
  readProductionPhysicalExperimentMonotonicOwnerHistory,
} = require("./physical-monotonic-owner.js");

const PHYSICAL_EXPERIMENT_STORE_VERSION = 1;
const MAX_BINDING_BYTES = 64 * 1024;
const MAX_ROW_ANCHOR_BYTES = 64 * 1024;
const MAX_ROW_RECORD_BYTES = 4 * 1024 * 1024;
const MAX_RECEIPT_RECORD_BYTES = 2 * 1024 * 1024;
const MAX_ROWS = 4096;
const MAX_RECEIPTS = MAX_ROWS * 4;
const MAX_RECEIPT_JOURNAL_BYTES = 256 * 1024 * 1024;
const MAX_STAGING_ENTRIES = 128;
const HASH_RE = /^[a-f0-9]{64}$/u;
const RECEIPT_REF_RE = /^[a-z][a-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const ROW_FILE_RE = /^([0-9]{6})\.json$/u;
const RECEIPT_FILE_RE = /^([a-f0-9]{64})\.json$/u;
const STAGING_FILE_RE = /^\.(binding\.json|[0-9]{6}\.json|[a-f0-9]{64}\.json)\.([1-9][0-9]*)\.([0-9]+)\.([a-f0-9]{24})\.tmp$/u;
const ROW_ANCHOR_STAGING_FILE_RE = /^\.(binding\.json|[0-9]{6}\.json)\.([1-9][0-9]*)\.([0-9]+)\.([a-f0-9]{24})\.tmp$/u;
const ZERO_HASH = "0".repeat(64);
const ROW_REF_PREFIX = Object.freeze({
  execution_receipt: "physical-execution-receipt",
  observation: "physical-observation",
  claim_verdict: "physical-claim-verdict",
  cleanup_verdict: "physical-cleanup-verdict",
});
const PRODUCTION_OWNER_CONTEXT_DOMAIN =
  "hacker-bob/physical-experiment-row-head/v1";
const MECHANISM_A_PORTS = new WeakSet();
const MECHANISM_A_PORT_STATE = new WeakMap();
const PRODUCTION_PORTS = new WeakSet();
const PRODUCTION_PORT_STATE = new WeakMap();

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || utilTypes.isProxy(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function cloneStrictData(value, label, depth = 0) {
  if (depth > 16) throw new Error(`${label} exceeds the maximum nesting depth`);
  if (value == null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error(`${label} contains a non-finite number`);
    return value;
  }
  if (Array.isArray(value)) {
    if (utilTypes.isProxy(value) || value.length > 4096) {
      throw new Error(`${label} must be a bounded non-proxy array`);
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(value);
    for (const key of keys) {
      if (key === "length") continue;
      if (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/u.test(key)) {
        throw new Error(`${label} contains a non-index array field`);
      }
      const descriptor = descriptors[key];
      if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
          || descriptor.enumerable !== true) {
        throw new Error(`${label}[${key}] must be an enumerable data property`);
      }
    }
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.prototype.hasOwnProperty.call(descriptors, String(index))) {
        throw new Error(`${label} cannot be sparse`);
      }
    }
    return value.map((entry, index) => cloneStrictData(entry, `${label}[${index}]`, depth + 1));
  }
  if (!isPlainDataObject(value)) throw new Error(`${label} must contain only plain data objects`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(value);
  if (keys.length > 512 || keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} has invalid or excessive fields`);
  }
  const result = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw new Error(`${label}.${key} must be an enumerable data property`);
    }
    result[key] = cloneStrictData(descriptor.value, `${label}.${key}`, depth + 1);
  }
  return result;
}

function assertClosedDataObject(value, label, fields) {
  const copy = cloneStrictData(value, label);
  if (!isPlainDataObject(copy)) throw new Error(`${label} must be a plain data object`);
  const keys = Object.keys(copy).sort();
  const expected = [...fields].sort();
  if (keys.length !== expected.length || keys.some((field, index) => field !== expected[index])) {
    throw new Error(`${label} must carry exactly ${fields.join(", ")}`);
  }
  return copy;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_RE.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertTargetDomain(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 253
      || value !== value.trim() || /[\\/\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error("physical experiment store target_domain is invalid");
  }
  const domain = assertSafeDomain(value);
  const root = sessionsRoot();
  const directory = sessionDir(domain);
  if (domain === "." || directory === root || path.dirname(directory) !== root) {
    throw new Error("physical experiment store target_domain must identify one session child");
  }
  return domain;
}

function assertReceiptRef(value, label) {
  if (typeof value !== "string" || !RECEIPT_REF_RE.test(value) || value.includes("..")) {
    throw new Error(`${label} must be a namespaced opaque receipt reference`);
  }
  return value;
}

function ensureRealDirectory(directoryPath, label, { create = false } = {}) {
  let created = false;
  if (create) {
    try {
      fs.lstatSync(directoryPath);
    } catch (error) {
      if (!error || error.code !== "ENOENT") throw error;
      try {
        fs.mkdirSync(directoryPath, { recursive: true, mode: 0o700 });
        created = true;
      } catch (mkdirError) {
        if (!mkdirError || mkdirError.code !== "EEXIST") throw mkdirError;
      }
    }
  }
  let stats;
  try {
    stats = fs.lstatSync(directoryPath);
  } catch {
    throw new Error(`${label} must be a real directory`);
  }
  const ownerMismatch = typeof process.getuid === "function" && stats.uid !== process.getuid();
  if (!stats.isDirectory() || stats.isSymbolicLink() || ownerMismatch
      || (stats.mode & 0o077) !== 0) {
    throw new Error(`${label} must be a Bob-owned mode-0700 real directory`);
  }
  if (created) fsyncDirectory(path.dirname(directoryPath));
  return Object.freeze({ dev: stats.dev, ino: stats.ino, path: directoryPath });
}

function assertDirectoryIdentity(identity, label) {
  let stats;
  try {
    stats = fs.lstatSync(identity.path);
  } catch {
    throw new Error(`${label} changed during storage operation`);
  }
  const ownerMismatch = typeof process.getuid === "function" && stats.uid !== process.getuid();
  if (!stats.isDirectory() || stats.isSymbolicLink() || ownerMismatch
      || (stats.mode & 0o077) !== 0
      || stats.dev !== identity.dev || stats.ino !== identity.ino) {
    throw new Error(`${label} changed during storage operation`);
  }
}

function fsyncDirectory(directoryPath) {
  const descriptor = fs.openSync(directoryPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function readVerifiedFile(filePath, label, maximumBytes) {
  const parent = ensureRealDirectory(path.dirname(filePath), `${label} parent`);
  let pathStats;
  try {
    pathStats = fs.lstatSync(filePath);
  } catch {
    throw new Error(`${label} is missing`);
  }
  const ownerMismatch = typeof process.getuid === "function" && pathStats.uid !== process.getuid();
  if (!pathStats.isFile() || pathStats.isSymbolicLink() || pathStats.nlink !== 1
      || pathStats.size < 1 || pathStats.size > maximumBytes || ownerMismatch
      || (pathStats.mode & 0o077) !== 0) {
    throw new Error(`${label} failed verified-read constraints`);
  }
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const stats = fs.fstatSync(descriptor);
    if (!stats.isFile() || stats.nlink !== 1 || stats.dev !== pathStats.dev
        || stats.ino !== pathStats.ino || stats.size !== pathStats.size) {
      throw new Error(`${label} changed before verified read`);
    }
    const bytes = Buffer.alloc(stats.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count === 0) throw new Error(`${label} changed while reading`);
      offset += count;
    }
    const after = fs.fstatSync(descriptor);
    const finalPathStats = fs.lstatSync(filePath);
    if (!after.isFile() || after.nlink !== 1 || after.size !== stats.size
        || after.dev !== stats.dev || after.ino !== stats.ino
        || !finalPathStats.isFile() || finalPathStats.isSymbolicLink()
        || finalPathStats.nlink !== 1 || finalPathStats.size !== stats.size
        || finalPathStats.dev !== stats.dev || finalPathStats.ino !== stats.ino) {
      throw new Error(`${label} changed during verified read`);
    }
    assertDirectoryIdentity(parent, `${label} parent`);
    return bytes.toString("utf8");
  } catch (error) {
    if (error && ["ELOOP", "EMLINK"].includes(error.code)) {
      throw new Error(`${label} must not be a symbolic or multiply linked file`);
    }
    throw error;
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
  }
}

function parseVerifiedJson(filePath, label, maximumBytes) {
  let parsed;
  try {
    parsed = JSON.parse(readVerifiedFile(filePath, label, maximumBytes));
  } catch (error) {
    if (error && !/JSON/u.test(error.message || "") && !(error instanceof SyntaxError)) throw error;
    throw new Error(`${label} must contain valid JSON`);
  }
  return cloneStrictData(parsed, label);
}

function publishImmutableJson(filePath, document, label, stagingDirectoryPath, maximumBytes) {
  const parent = ensureRealDirectory(path.dirname(filePath), `${label} parent`, { create: true });
  const staging = ensureRealDirectory(stagingDirectoryPath, `${label} staging directory`, { create: true });
  const content = `${JSON.stringify(document)}\n`;
  const contentBytes = Buffer.byteLength(content);
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || contentBytes > maximumBytes) {
    throw new Error(`${label} exceeds its serialized size cap`);
  }
  const tempPath = path.join(
    staging.path,
    `.${path.basename(filePath)}.${process.pid}.${Date.now()}.${crypto.randomBytes(12).toString("hex")}.tmp`,
  );
  let descriptor;
  let linked = false;
  try {
    descriptor = fs.openSync(
      tempPath,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY
        | (fs.constants.O_NOFOLLOW || 0),
      0o600,
    );
    fs.writeFileSync(descriptor, content, "utf8");
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = null;
    assertDirectoryIdentity(parent, `${label} parent`);
    assertDirectoryIdentity(staging, `${label} staging directory`);
    try {
      fs.linkSync(tempPath, filePath);
      linked = true;
    } catch (error) {
      if (!error || error.code !== "EEXIST") throw error;
      return false;
    }
    fsyncDirectory(parent.path);
    fs.unlinkSync(tempPath);
    fsyncDirectory(staging.path);
    const stats = fs.lstatSync(filePath);
    const ownerMismatch = typeof process.getuid === "function" && stats.uid !== process.getuid();
    if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink !== 1
        || ownerMismatch || (stats.mode & 0o077) !== 0) {
      throw new Error(`${label} publication produced an unsafe file`);
    }
    return true;
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
    try {
      fs.unlinkSync(tempPath);
      fsyncDirectory(staging.path);
    } catch {}
    if (linked) {
      assertDirectoryIdentity(parent, `${label} parent`);
      assertDirectoryIdentity(staging, `${label} staging directory`);
    }
  }
}

function bindingBody(input) {
  return {
    version: PHYSICAL_EXPERIMENT_STORE_VERSION,
    target_domain: assertTargetDomain(input.target_domain),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, "session_nucleus_hash"),
    plan_hash: assertDigest(input.plan_hash, "plan_hash"),
    trust_binding_digest: assertDigest(input.trust_binding_digest, "trust_binding_digest"),
    trust_head_digest: assertDigest(input.trust_head_digest, "trust_head_digest"),
    signer_owner_custody_digest: assertDigest(
      input.signer_owner_custody_digest,
      "signer_owner_custody_digest",
    ),
  };
}

function normalizeBinding(input, expected = null) {
  const copy = assertClosedDataObject(input, "physical experiment store binding", [
    "version",
    "target_domain",
    "session_nucleus_hash",
    "plan_hash",
    "trust_binding_digest",
    "trust_head_digest",
    "signer_owner_custody_digest",
    "binding_digest",
  ]);
  if (copy.version !== PHYSICAL_EXPERIMENT_STORE_VERSION) {
    throw new Error(`physical experiment store binding.version must be ${PHYSICAL_EXPERIMENT_STORE_VERSION}`);
  }
  const body = bindingBody(copy);
  const digest = hashCanonicalJson({
    domain: "hacker-bob/physical-experiment-store-binding/v1",
    ...body,
  });
  if (assertDigest(copy.binding_digest, "physical experiment store binding.binding_digest") !== digest) {
    throw new Error("physical experiment store binding digest drift");
  }
  if (expected && hashCanonicalJson(body) !== hashCanonicalJson(expected)) {
    throw new Error("physical experiment store binding conflicts with the requested runtime");
  }
  return deepFreeze({ ...body, binding_digest: digest });
}

function pathsFor(binding) {
  const root = path.join(physicalCampaignDir(binding.target_domain), "experiments");
  const plan = path.join(root, binding.plan_hash);
  return Object.freeze({
    root,
    plan,
    binding: path.join(plan, "binding.json"),
    rows: path.join(plan, "rows"),
    receipts: path.join(plan, "receipts"),
    staging: path.join(plan, ".staging"),
  });
}

function rowAnchorPathsFor(binding) {
  const trustRoot = path.join(
    physicalCampaignDir(binding.target_domain),
    "experiment-trust",
  );
  const root = path.join(trustRoot, "experiment-row-head-anchors");
  const plan = path.join(root, binding.plan_hash);
  return Object.freeze({
    trustRoot,
    root,
    plan,
    binding: path.join(plan, "binding.json"),
    heads: path.join(plan, "heads"),
    staging: path.join(plan, ".staging"),
  });
}

function stagingFinalPath(paths, basename) {
  if (basename === "binding.json") return paths.binding;
  if (ROW_FILE_RE.test(basename)) return path.join(paths.rows, basename);
  if (RECEIPT_FILE_RE.test(basename)) return path.join(paths.receipts, basename);
  throw new Error("physical experiment staging entry has no authoritative destination");
}

function unlinkExactStagingEntry(filePath, expected, stagingIdentity) {
  assertDirectoryIdentity(stagingIdentity, "physical experiment staging directory");
  const current = fs.lstatSync(filePath);
  if (!current.isFile() || current.isSymbolicLink()
      || current.dev !== expected.dev || current.ino !== expected.ino
      || current.nlink !== expected.nlink) {
    throw new Error("physical experiment staging entry changed during recovery");
  }
  fs.unlinkSync(filePath);
  assertDirectoryIdentity(stagingIdentity, "physical experiment staging directory");
}

function recoverStaging(paths) {
  const staging = ensureRealDirectory(paths.staging, "physical experiment staging directory");
  const names = fs.readdirSync(paths.staging).sort();
  if (names.length > MAX_STAGING_ENTRIES) {
    throw new Error("physical experiment staging directory contains excessive entries");
  }
  let changed = false;
  for (const name of names) {
    const match = STAGING_FILE_RE.exec(name);
    if (!match) throw new Error("physical experiment staging directory contains an unknown entry");
    const stagedPath = path.join(paths.staging, name);
    const staged = fs.lstatSync(stagedPath);
    const ownerMismatch = typeof process.getuid === "function" && staged.uid !== process.getuid();
    if (!staged.isFile() || staged.isSymbolicLink() || ![1, 2].includes(staged.nlink)
        || staged.size > MAX_ROW_RECORD_BYTES || ownerMismatch || (staged.mode & 0o077) !== 0) {
      throw new Error("physical experiment staging entry failed recovery constraints");
    }
    const finalPath = stagingFinalPath(paths, match[1]);
    let final = null;
    try {
      final = fs.lstatSync(finalPath);
    } catch (error) {
      if (!error || error.code !== "ENOENT") throw error;
    }
    if (staged.nlink === 2) {
      if (final == null || !final.isFile() || final.isSymbolicLink()
          || final.dev !== staged.dev || final.ino !== staged.ino
          || final.nlink !== 2) {
        throw new Error("physical experiment staging entry conflicts with authoritative content");
      }
      // The authoritative link must be durable before recovery drops the
      // only remaining staged witness to its inode.
      fsyncDirectory(path.dirname(finalPath));
    }
    unlinkExactStagingEntry(stagedPath, staged, staging);
    if (final != null) {
      const recovered = fs.lstatSync(finalPath);
      if (!recovered.isFile() || recovered.isSymbolicLink() || recovered.nlink !== 1
          || recovered.dev !== final.dev || recovered.ino !== final.ino) {
        throw new Error("physical experiment authoritative file failed staging recovery");
      }
    }
    changed = true;
  }
  if (changed) fsyncDirectory(paths.staging);
  assertDirectoryIdentity(staging, "physical experiment staging directory");
}

function recoverRowAnchorStaging(paths) {
  const staging = ensureRealDirectory(
    paths.staging,
    "physical experiment row-anchor staging directory",
  );
  const names = fs.readdirSync(paths.staging).sort();
  if (names.length > MAX_STAGING_ENTRIES) {
    throw new Error("physical experiment row-anchor staging contains excessive entries");
  }
  let changed = false;
  for (const name of names) {
    const match = ROW_ANCHOR_STAGING_FILE_RE.exec(name);
    if (!match) {
      throw new Error("physical experiment row-anchor staging contains an unknown entry");
    }
    const stagedPath = path.join(paths.staging, name);
    const staged = fs.lstatSync(stagedPath);
    const ownerMismatch = typeof process.getuid === "function" && staged.uid !== process.getuid();
    if (!staged.isFile() || staged.isSymbolicLink() || ![1, 2].includes(staged.nlink)
        || staged.size > MAX_ROW_ANCHOR_BYTES || ownerMismatch
        || (staged.mode & 0o077) !== 0) {
      throw new Error("physical experiment row-anchor staging entry is unsafe");
    }
    const basename = match[1];
    const finalPath = basename === "binding.json"
      ? paths.binding
      : path.join(paths.heads, basename);
    let final = null;
    try {
      final = fs.lstatSync(finalPath);
    } catch (error) {
      if (!error || error.code !== "ENOENT") throw error;
    }
    if (staged.nlink === 2) {
      if (final == null || !final.isFile() || final.isSymbolicLink()
          || final.dev !== staged.dev || final.ino !== staged.ino
          || final.nlink !== 2) {
        throw new Error("physical experiment row-anchor staging conflicts with authoritative content");
      }
      fsyncDirectory(path.dirname(finalPath));
    }
    assertDirectoryIdentity(staging, "physical experiment row-anchor staging directory");
    const current = fs.lstatSync(stagedPath);
    if (!current.isFile() || current.isSymbolicLink()
        || current.dev !== staged.dev || current.ino !== staged.ino
        || current.nlink !== staged.nlink) {
      throw new Error("physical experiment row-anchor staging changed during recovery");
    }
    fs.unlinkSync(stagedPath);
    assertDirectoryIdentity(staging, "physical experiment row-anchor staging directory");
    if (final != null) {
      const recovered = fs.lstatSync(finalPath);
      if (!recovered.isFile() || recovered.isSymbolicLink() || recovered.nlink !== 1
          || recovered.dev !== final.dev || recovered.ino !== final.ino) {
        throw new Error("physical experiment row-anchor final failed staging recovery");
      }
    }
    changed = true;
  }
  if (changed) fsyncDirectory(paths.staging);
  assertDirectoryIdentity(staging, "physical experiment row-anchor staging directory");
}

function assertCurrentNucleus(binding) {
  const nucleus = readVerifiedSessionNucleus(binding.target_domain);
  if (!nucleus.physical_scope || nucleus.nucleus_hash !== binding.session_nucleus_hash) {
    throw new Error("physical experiment store session nucleus is unavailable or has drifted");
  }
  return nucleus;
}

function ensureLayout(binding, directoryIdentity) {
  assertSafeSessionDirectoryIdentity(directoryIdentity);
  const paths = pathsFor(binding);
  ensureRealDirectory(physicalCampaignDir(binding.target_domain), "physical campaign directory", { create: true });
  ensureRealDirectory(paths.root, "physical experiments directory", { create: true });
  ensureRealDirectory(paths.plan, "physical experiment plan directory", { create: true });
  ensureRealDirectory(paths.rows, "physical experiment rows directory", { create: true });
  ensureRealDirectory(paths.receipts, "physical experiment receipts directory", { create: true });
  ensureRealDirectory(paths.staging, "physical experiment staging directory", { create: true });
  recoverStaging(paths);
  if (!fs.existsSync(paths.binding)) {
    const body = bindingBody(binding);
    const document = {
      ...body,
      binding_digest: hashCanonicalJson({
        domain: "hacker-bob/physical-experiment-store-binding/v1",
        ...body,
      }),
    };
    publishImmutableJson(
      paths.binding,
      document,
      "physical experiment store binding",
      paths.staging,
      MAX_BINDING_BYTES,
    );
  }
  const persisted = normalizeBinding(
    parseVerifiedJson(paths.binding, "physical experiment store binding", MAX_BINDING_BYTES),
    bindingBody(binding),
  );
  const rowRecords = readRowRecords(paths, persisted);
  const rowAnchorLayout = ensureRowAnchorLayout(persisted, rowRecords);
  reconcileRowAnchors(rowAnchorLayout, persisted, rowRecords, { recoverMissing: true });
  assertSafeSessionDirectoryIdentity(directoryIdentity);
  return Object.freeze({ paths, persisted, rowAnchorLayout });
}

function normalizeCommit(input, label) {
  const copy = assertClosedDataObject(input, label, [
    "version",
    "plan_hash",
    "expected_sequence",
    "previous_row_hash",
    "append_receipt_digest",
    "row_digest",
    "row_commit_digest",
  ]);
  if (copy.version !== 1 || !Number.isSafeInteger(copy.expected_sequence)
      || copy.expected_sequence < 1 || copy.expected_sequence > MAX_ROWS) {
    throw new Error(`${label} has an invalid version or sequence`);
  }
  for (const field of [
    "plan_hash", "previous_row_hash", "append_receipt_digest", "row_digest", "row_commit_digest",
  ]) assertDigest(copy[field], `${label}.${field}`);
  const digest = hashCanonicalJson({
    domain: "hacker-bob/physical-experiment-row-commit/v1",
    version: copy.version,
    plan_hash: copy.plan_hash,
    expected_sequence: copy.expected_sequence,
    previous_row_hash: copy.previous_row_hash,
    append_receipt_digest: copy.append_receipt_digest,
    row_digest: copy.row_digest,
  });
  if (copy.row_commit_digest !== digest) throw new Error(`${label}.row_commit_digest drift`);
  return deepFreeze(copy);
}

function normalizeRowRecord(input, binding, label) {
  const copy = assertClosedDataObject(input, label, [
    "version",
    "target_domain",
    "session_nucleus_hash",
    "plan_hash",
    "commit",
    "row",
    "record_digest",
  ]);
  if (copy.version !== PHYSICAL_EXPERIMENT_STORE_VERSION
      || copy.target_domain !== binding.target_domain
      || copy.session_nucleus_hash !== binding.session_nucleus_hash
      || copy.plan_hash !== binding.plan_hash) {
    throw new Error(`${label} store binding drift`);
  }
  const commit = normalizeCommit(copy.commit, `${label}.commit`);
  if (commit.plan_hash !== binding.plan_hash) throw new Error(`${label} commit belongs to another plan`);
  const row = assertClosedDataObject(copy.row, `${label}.row`, [
    "version", "row_kind", "payload", "envelope", "row_hash", "row_ref",
  ]);
  const rowPrefix = ROW_REF_PREFIX[row.row_kind];
  if (row.version !== 1 || rowPrefix == null || !isPlainDataObject(row.payload)
      || !isPlainDataObject(row.envelope)) {
    throw new Error(`${label} contains an invalid signed row shape`);
  }
  const derivedRowHash = hashCanonicalJson({
    version: row.version,
    row_kind: row.row_kind,
    payload: row.payload,
    envelope: row.envelope,
  });
  if (assertDigest(row.row_hash, `${label}.row.row_hash`) !== derivedRowHash
      || row.row_hash !== commit.row_digest
      || row.row_ref !== `${rowPrefix}:v1:${derivedRowHash}`
      || row.envelope.sequence !== commit.expected_sequence
      || row.envelope.previous_row_hash !== commit.previous_row_hash
      || row.envelope.append_receipt?.receipt_digest !== commit.append_receipt_digest) {
    throw new Error(`${label} does not bind the exact signed row digest`);
  }
  const body = {
    version: PHYSICAL_EXPERIMENT_STORE_VERSION,
    target_domain: binding.target_domain,
    session_nucleus_hash: binding.session_nucleus_hash,
    plan_hash: binding.plan_hash,
    commit,
    row,
  };
  const digest = hashCanonicalJson({
    domain: "hacker-bob/physical-experiment-store-row/v1",
    ...body,
  });
  if (assertDigest(copy.record_digest, `${label}.record_digest`) !== digest) {
    throw new Error(`${label} record digest drift`);
  }
  return deepFreeze({ ...body, record_digest: digest });
}

function rowFileName(sequence) {
  return `${String(sequence).padStart(6, "0")}.json`;
}

function readRowRecords(paths, binding) {
  const rowsIdentity = ensureRealDirectory(paths.rows, "physical experiment rows directory");
  const names = fs.readdirSync(paths.rows).sort();
  if (names.length > MAX_ROWS || names.some((name) => !ROW_FILE_RE.test(name))) {
    throw new Error("physical experiment row journal contains an unknown or excessive entry");
  }
  const records = [];
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index];
    const match = ROW_FILE_RE.exec(name);
    const sequence = Number(match[1]);
    if (sequence !== index + 1 || name !== rowFileName(sequence)) {
      throw new Error("physical experiment row journal contains a gap or noncanonical sequence");
    }
    const record = normalizeRowRecord(
      parseVerifiedJson(
        path.join(paths.rows, name),
        `physical experiment row ${sequence}`,
        MAX_ROW_RECORD_BYTES,
      ),
      binding,
      `physical experiment row ${sequence}`,
    );
    if (record.commit.expected_sequence !== sequence) {
      throw new Error(`physical experiment row ${sequence} sequence binding drift`);
    }
    const expectedPrevious = index === 0 ? "0".repeat(64) : records[index - 1].commit.row_digest;
    if (record.commit.previous_row_hash !== expectedPrevious) {
      throw new Error(`physical experiment row ${sequence} forks the immutable journal`);
    }
    records.push(record);
  }
  assertDirectoryIdentity(rowsIdentity, "physical experiment rows directory");
  return Object.freeze(records);
}

function productionOwnerStateDigest(state) {
  return hashCanonicalJson({
    domain: "hacker-bob/physical-experiment-production-owner-state/v1",
    state,
  });
}

function productionOwnerStateCommon(binding, ownerPort) {
  return {
    version: PHYSICAL_EXPERIMENT_STORE_VERSION,
    state_kind: "physical_experiment_row_head",
    target_domain: binding.target_domain,
    session_nucleus_hash: binding.session_nucleus_hash,
    plan_hash: binding.plan_hash,
    store_binding_digest: binding.binding_digest,
    trust_binding_digest: binding.trust_binding_digest,
    trust_head_digest: binding.trust_head_digest,
    signer_owner_custody_digest: binding.signer_owner_custody_digest,
    owner_slot_digest: assertDigest(
      ownerPort.slot_digest,
      "production physical experiment owner slot digest",
    ),
  };
}

function normalizeProductionOwnerState(input, binding, ownerPort, label) {
  const copy = assertClosedDataObject(input, label, [
    "version",
    "state_kind",
    "phase",
    "target_domain",
    "session_nucleus_hash",
    "plan_hash",
    "store_binding_digest",
    "trust_binding_digest",
    "trust_head_digest",
    "signer_owner_custody_digest",
    "owner_slot_digest",
    "monotonic_revision",
    "monotonic_position",
    "monotonic_value_digest",
    "logical_sequence",
    "row_commit",
    "row_record_digest",
    "pending_commit",
    "pending_row_record_digest",
    "transition_digest",
  ]);
  const common = productionOwnerStateCommon(binding, ownerPort);
  for (const [field, expected] of Object.entries(common)) {
    if (copy[field] !== expected) throw new Error(`${label}.${field} binding drift`);
  }
  if (!["committed", "prepared"].includes(copy.phase)
      || !Number.isSafeInteger(copy.logical_sequence)
      || copy.logical_sequence < 0 || copy.logical_sequence > MAX_ROWS) {
    throw new Error(`${label} has an invalid phase or logical sequence`);
  }
  if (!Number.isSafeInteger(copy.monotonic_revision) || copy.monotonic_revision < 1
      || copy.monotonic_position !== copy.logical_sequence) {
    throw new Error(`${label} has an invalid owner revision or monotonic position`);
  }
  const rowCommit = copy.row_commit == null
    ? null
    : normalizeCommit(copy.row_commit, `${label}.row_commit`);
  const pendingCommit = copy.pending_commit == null
    ? null
    : normalizeCommit(copy.pending_commit, `${label}.pending_commit`);
  const rowRecordDigest = assertDigest(copy.row_record_digest, `${label}.row_record_digest`);
  const pendingRowRecordDigest = assertDigest(
    copy.pending_row_record_digest,
    `${label}.pending_row_record_digest`,
  );
  const transitionDigest = assertDigest(copy.transition_digest, `${label}.transition_digest`);
  const monotonicValueDigest = assertDigest(
    copy.monotonic_value_digest,
    `${label}.monotonic_value_digest`,
  );
  if (copy.logical_sequence === 0) {
    if (rowCommit != null || rowRecordDigest !== ZERO_HASH) {
      throw new Error(`${label} genesis head is not empty`);
    }
  } else if (rowCommit == null
      || rowCommit.expected_sequence !== copy.logical_sequence
      || rowCommit.plan_hash !== binding.plan_hash
      || rowRecordDigest === ZERO_HASH) {
    throw new Error(`${label} committed row head is incomplete`);
  }
  if (monotonicValueDigest !== rowRecordDigest) {
    throw new Error(`${label} monotonic value does not bind its exact committed row record`);
  }
  if (copy.phase === "committed") {
    if (pendingCommit != null || pendingRowRecordDigest !== ZERO_HASH) {
      throw new Error(`${label} committed head carries a pending append`);
    }
  } else if (pendingCommit == null
      || pendingCommit.plan_hash !== binding.plan_hash
      || pendingCommit.expected_sequence !== copy.logical_sequence + 1
      || pendingCommit.previous_row_hash !== (rowCommit == null ? ZERO_HASH : rowCommit.row_digest)
      || pendingRowRecordDigest === ZERO_HASH) {
    throw new Error(`${label} prepared head does not extend its exact committed row`);
  }
  return deepFreeze({
    ...common,
    monotonic_revision: copy.monotonic_revision,
    monotonic_position: copy.logical_sequence,
    monotonic_value_digest: monotonicValueDigest,
    phase: copy.phase,
    logical_sequence: copy.logical_sequence,
    row_commit: rowCommit,
    row_record_digest: rowRecordDigest,
    pending_commit: pendingCommit,
    pending_row_record_digest: pendingRowRecordDigest,
    transition_digest: transitionDigest,
  });
}

function committedProductionOwnerState(binding, ownerPort, rowRecord, transitionDigest, revision) {
  const common = productionOwnerStateCommon(binding, ownerPort);
  return normalizeProductionOwnerState({
    ...common,
    monotonic_revision: revision,
    monotonic_position: rowRecord == null ? 0 : rowRecord.commit.expected_sequence,
    monotonic_value_digest: rowRecord == null ? ZERO_HASH : rowRecord.record_digest,
    phase: "committed",
    logical_sequence: rowRecord == null ? 0 : rowRecord.commit.expected_sequence,
    row_commit: rowRecord == null ? null : rowRecord.commit,
    row_record_digest: rowRecord == null ? ZERO_HASH : rowRecord.record_digest,
    pending_commit: null,
    pending_row_record_digest: ZERO_HASH,
    transition_digest: transitionDigest,
  }, binding, ownerPort, "production physical experiment committed owner state");
}

function preparedProductionOwnerState(binding, ownerPort, currentState, pendingRecord) {
  const common = productionOwnerStateCommon(binding, ownerPort);
  return normalizeProductionOwnerState({
    ...common,
    monotonic_revision: currentState.monotonic_revision + 1,
    monotonic_position: currentState.logical_sequence,
    monotonic_value_digest: currentState.row_record_digest,
    phase: "prepared",
    logical_sequence: currentState.logical_sequence,
    row_commit: currentState.row_commit,
    row_record_digest: currentState.row_record_digest,
    pending_commit: pendingRecord.commit,
    pending_row_record_digest: pendingRecord.record_digest,
    transition_digest: productionOwnerStateDigest(currentState),
  }, binding, ownerPort, "production physical experiment prepared owner state");
}

function exactProductionOwnerState(left, right) {
  return left != null && right != null
    && productionOwnerStateDigest(left) === productionOwnerStateDigest(right);
}

function assertProductionOwnerTransition(expectedState, nextState) {
  if (expectedState == null) {
    if (nextState.phase !== "committed" || nextState.logical_sequence !== 0
        || nextState.monotonic_revision !== 1 || nextState.transition_digest !== ZERO_HASH) {
      throw new Error("production physical experiment owner genesis transition is invalid");
    }
    return nextState;
  }
  if (nextState.monotonic_revision !== expectedState.monotonic_revision + 1
      || nextState.transition_digest !== productionOwnerStateDigest(expectedState)) {
    throw new Error("production physical experiment owner transition does not extend the exact head");
  }
  if (expectedState.phase === "committed") {
    if (nextState.phase !== "prepared"
        || nextState.logical_sequence !== expectedState.logical_sequence
        || nextState.row_record_digest !== expectedState.row_record_digest
        || hashCanonicalJson(nextState.row_commit) !== hashCanonicalJson(expectedState.row_commit)) {
      throw new Error("production physical experiment owner prepare transition is invalid");
    }
    return nextState;
  }
  if (nextState.phase !== "committed") {
    throw new Error("production physical experiment prepared owner must settle to committed");
  }
  if (nextState.logical_sequence === expectedState.logical_sequence) {
    if (nextState.row_record_digest !== expectedState.row_record_digest
        || hashCanonicalJson(nextState.row_commit) !== hashCanonicalJson(expectedState.row_commit)) {
      throw new Error("production physical experiment owner abort rewrites its committed base");
    }
    return nextState;
  }
  if (nextState.logical_sequence !== expectedState.logical_sequence + 1
      || nextState.row_record_digest !== expectedState.pending_row_record_digest
      || hashCanonicalJson(nextState.row_commit) !== hashCanonicalJson(expectedState.pending_commit)) {
    throw new Error("production physical experiment owner commit does not promote its exact prepared row");
  }
  return nextState;
}

function ownerStateMatchesRows(ownerState, rowRecords) {
  if (ownerState.logical_sequence !== rowRecords.length) return false;
  if (rowRecords.length === 0) {
    return ownerState.row_commit == null && ownerState.row_record_digest === ZERO_HASH;
  }
  const last = rowRecords[rowRecords.length - 1];
  return ownerState.row_commit.row_commit_digest === last.commit.row_commit_digest
    && hashCanonicalJson(ownerState.row_commit) === hashCanonicalJson(last.commit)
    && ownerState.row_record_digest === last.record_digest;
}

function readProductionOwnerState(state) {
  const rawHistory = readProductionPhysicalExperimentMonotonicOwnerHistory(
    state.monotonicOwnerPort,
  );
  let previous = null;
  for (let index = 0; index < rawHistory.length; index += 1) {
    const current = normalizeProductionOwnerState(
      rawHistory[index],
      state.binding,
      state.monotonicOwnerPort,
      `production physical experiment monotonic owner state ${index + 1}`,
    );
    assertProductionOwnerTransition(previous, current);
    previous = current;
  }
  return previous;
}

function compareAndSetProductionOwnerState(state, expectedState, nextState) {
  assertProductionOwnerTransition(expectedState, nextState);
  let compareResult;
  let compareError = null;
  try {
    compareResult = compareAndSetProductionPhysicalExperimentMonotonicOwnerState(
      state.monotonicOwnerPort,
      expectedState,
      nextState,
    );
  } catch (error) {
    compareError = error;
  }
  if (compareError == null && typeof compareResult !== "boolean") {
    throw new Error("production physical experiment monotonic owner CAS must return a boolean");
  }
  const current = readProductionOwnerState(state);
  if (exactProductionOwnerState(current, nextState)) return nextState;
  if (compareError != null) {
    const error = new Error(
      "production physical experiment monotonic owner acknowledgement was lost without exact readback",
    );
    Object.defineProperty(error, "cause", { value: compareError });
    throw error;
  }
  if (compareResult) {
    throw new Error("production physical experiment monotonic owner claimed success without exact readback");
  }
  return null;
}

function reconcileProductionOwnerState(state, layout) {
  const records = readRowRecords(layout.paths, state.binding);
  let ownerState = readProductionOwnerState(state);
  if (ownerState == null) {
    if (records.length > 0) {
      throw new Error(
        "production physical experiment row journal predates its independent monotonic owner",
      );
    }
    const genesis = committedProductionOwnerState(
      state.binding,
      state.monotonicOwnerPort,
      null,
      ZERO_HASH,
      1,
    );
    ownerState = compareAndSetProductionOwnerState(state, null, genesis)
      || readProductionOwnerState(state);
    if (!exactProductionOwnerState(ownerState, genesis)) {
      throw new Error("production physical experiment monotonic owner genesis conflicts");
    }
  }

  for (let attempt = 0; ownerState.phase === "prepared" && attempt < 3; attempt += 1) {
    if (records.length < ownerState.logical_sequence) {
      throw new Error(
        "physical experiment whole-tree rollback detected by independent monotonic owner",
      );
    }
    if (records.length === ownerState.logical_sequence) {
      if (!ownerStateMatchesRows(ownerState, records)) {
        throw new Error("physical experiment prepared owner base conflicts with the local journal");
      }
      const priorRecord = records.length === 0 ? null : records[records.length - 1];
      const aborted = committedProductionOwnerState(
        state.binding,
        state.monotonicOwnerPort,
        priorRecord,
        productionOwnerStateDigest(ownerState),
        ownerState.monotonic_revision + 1,
      );
      ownerState = compareAndSetProductionOwnerState(state, ownerState, aborted)
        || readProductionOwnerState(state);
      continue;
    }
    if (records.length === ownerState.logical_sequence + 1) {
      const pendingRecord = records[records.length - 1];
      if (pendingRecord.commit.row_commit_digest !== ownerState.pending_commit.row_commit_digest
          || hashCanonicalJson(pendingRecord.commit) !== hashCanonicalJson(ownerState.pending_commit)
          || pendingRecord.record_digest !== ownerState.pending_row_record_digest) {
        throw new Error("physical experiment prepared owner conflicts with its pending local row");
      }
      const committed = committedProductionOwnerState(
        state.binding,
        state.monotonicOwnerPort,
        pendingRecord,
        productionOwnerStateDigest(ownerState),
        ownerState.monotonic_revision + 1,
      );
      ownerState = compareAndSetProductionOwnerState(state, ownerState, committed)
        || readProductionOwnerState(state);
      continue;
    }
    throw new Error("physical experiment local journal advanced beyond its prepared monotonic owner");
  }
  if (ownerState == null || ownerState.phase !== "committed") {
    throw new Error("production physical experiment monotonic owner recovery did not settle");
  }
  if (ownerState.logical_sequence > records.length) {
    throw new Error("physical experiment whole-tree rollback detected by independent monotonic owner");
  }
  if (ownerState.logical_sequence < records.length) {
    throw new Error("physical experiment local row journal is ahead of its independent monotonic owner");
  }
  if (!ownerStateMatchesRows(ownerState, records)) {
    throw new Error("physical experiment local row journal conflicts with its independent monotonic owner");
  }
  return ownerState;
}

function rowAnchorBindingBody(binding) {
  return {
    version: PHYSICAL_EXPERIMENT_STORE_VERSION,
    target_domain: binding.target_domain,
    session_nucleus_hash: binding.session_nucleus_hash,
    plan_hash: binding.plan_hash,
    store_binding_digest: binding.binding_digest,
    trust_head_digest: binding.trust_head_digest,
    signer_owner_custody_digest: binding.signer_owner_custody_digest,
    assurance: "mechanism_a_local_signer_custodied_row_head_rollback_detection",
  };
}

function normalizeRowAnchorBinding(input, binding) {
  const copy = assertClosedDataObject(input, "physical experiment row-anchor binding", [
    "version",
    "target_domain",
    "session_nucleus_hash",
    "plan_hash",
    "store_binding_digest",
    "trust_head_digest",
    "signer_owner_custody_digest",
    "assurance",
    "anchor_binding_digest",
  ]);
  const body = rowAnchorBindingBody(binding);
  if (copy.version !== body.version
      || copy.target_domain !== body.target_domain
      || copy.session_nucleus_hash !== body.session_nucleus_hash
      || copy.plan_hash !== body.plan_hash
      || copy.store_binding_digest !== body.store_binding_digest
      || copy.trust_head_digest !== body.trust_head_digest
      || copy.signer_owner_custody_digest !== body.signer_owner_custody_digest
      || copy.assurance !== body.assurance) {
    throw new Error("physical experiment row-anchor binding drift");
  }
  const anchorBindingDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-experiment-row-anchor-binding/v1",
    ...body,
  });
  if (assertDigest(
    copy.anchor_binding_digest,
    "physical experiment row-anchor binding.anchor_binding_digest",
  ) !== anchorBindingDigest) {
    throw new Error("physical experiment row-anchor binding digest drift");
  }
  return deepFreeze({ ...body, anchor_binding_digest: anchorBindingDigest });
}

function pathEntryExists(filePath, label) {
  try {
    fs.lstatSync(filePath);
    return true;
  } catch (error) {
    if (error && error.code === "ENOENT") return false;
    throw new Error(`${label} availability could not be established`);
  }
}

function ensureRowAnchorLayout(binding, rowRecords) {
  const paths = rowAnchorPathsFor(binding);
  ensureRealDirectory(paths.trustRoot, "physical experiment trust directory");
  const planWasPresent = pathEntryExists(paths.plan, "physical experiment row-anchor plan");
  if (!planWasPresent && rowRecords.length > 0) {
    throw new Error(
      "physical experiment row journal predates its required signer-custodied rollback anchor",
    );
  }
  ensureRealDirectory(paths.root, "physical experiment row-anchor root", { create: true });
  ensureRealDirectory(paths.plan, "physical experiment row-anchor plan", { create: true });
  ensureRealDirectory(paths.heads, "physical experiment row-anchor heads", { create: true });
  ensureRealDirectory(paths.staging, "physical experiment row-anchor staging directory", { create: true });
  recoverRowAnchorStaging(paths);
  const bindingPresent = pathEntryExists(
    paths.binding,
    "physical experiment row-anchor binding",
  );
  if (!bindingPresent) {
    if (rowRecords.length > 0) {
      throw new Error(
        "physical experiment row journal has no signer-custodied rollback-anchor binding",
      );
    }
    const body = rowAnchorBindingBody(binding);
    publishImmutableJson(
      paths.binding,
      {
        ...body,
        anchor_binding_digest: hashCanonicalJson({
          domain: "hacker-bob/physical-experiment-row-anchor-binding/v1",
          ...body,
        }),
      },
      "physical experiment row-anchor binding",
      paths.staging,
      MAX_ROW_ANCHOR_BYTES,
    );
  }
  const persisted = normalizeRowAnchorBinding(
    parseVerifiedJson(
      paths.binding,
      "physical experiment row-anchor binding",
      MAX_ROW_ANCHOR_BYTES,
    ),
    binding,
  );
  return Object.freeze({ paths, persisted });
}

function rowAnchorBody(binding, anchorBinding, rowRecord, previousAnchorDigest) {
  return {
    version: PHYSICAL_EXPERIMENT_STORE_VERSION,
    target_domain: binding.target_domain,
    session_nucleus_hash: binding.session_nucleus_hash,
    plan_hash: binding.plan_hash,
    store_binding_digest: binding.binding_digest,
    trust_head_digest: binding.trust_head_digest,
    signer_owner_custody_digest: binding.signer_owner_custody_digest,
    anchor_binding_digest: anchorBinding.anchor_binding_digest,
    sequence: rowRecord.commit.expected_sequence,
    previous_anchor_digest: previousAnchorDigest,
    row_digest: rowRecord.commit.row_digest,
    row_commit_digest: rowRecord.commit.row_commit_digest,
    row_record_digest: rowRecord.record_digest,
  };
}

function normalizeRowAnchor(input, binding, anchorBinding, label) {
  const copy = assertClosedDataObject(input, label, [
    "version",
    "target_domain",
    "session_nucleus_hash",
    "plan_hash",
    "store_binding_digest",
    "trust_head_digest",
    "signer_owner_custody_digest",
    "anchor_binding_digest",
    "sequence",
    "previous_anchor_digest",
    "row_digest",
    "row_commit_digest",
    "row_record_digest",
    "anchor_digest",
  ]);
  if (copy.version !== PHYSICAL_EXPERIMENT_STORE_VERSION
      || copy.target_domain !== binding.target_domain
      || copy.session_nucleus_hash !== binding.session_nucleus_hash
      || copy.plan_hash !== binding.plan_hash
      || copy.store_binding_digest !== binding.binding_digest
      || copy.trust_head_digest !== binding.trust_head_digest
      || copy.signer_owner_custody_digest !== binding.signer_owner_custody_digest
      || copy.anchor_binding_digest !== anchorBinding.anchor_binding_digest
      || !Number.isSafeInteger(copy.sequence) || copy.sequence < 1 || copy.sequence > MAX_ROWS) {
    throw new Error(`${label} binding or sequence drift`);
  }
  for (const field of [
    "previous_anchor_digest",
    "row_digest",
    "row_commit_digest",
    "row_record_digest",
  ]) assertDigest(copy[field], `${label}.${field}`);
  const body = {
    version: PHYSICAL_EXPERIMENT_STORE_VERSION,
    target_domain: binding.target_domain,
    session_nucleus_hash: binding.session_nucleus_hash,
    plan_hash: binding.plan_hash,
    store_binding_digest: binding.binding_digest,
    trust_head_digest: binding.trust_head_digest,
    signer_owner_custody_digest: binding.signer_owner_custody_digest,
    anchor_binding_digest: anchorBinding.anchor_binding_digest,
    sequence: copy.sequence,
    previous_anchor_digest: copy.previous_anchor_digest,
    row_digest: copy.row_digest,
    row_commit_digest: copy.row_commit_digest,
    row_record_digest: copy.row_record_digest,
  };
  const anchorDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-experiment-row-head-anchor/v1",
    ...body,
  });
  if (assertDigest(copy.anchor_digest, `${label}.anchor_digest`) !== anchorDigest) {
    throw new Error(`${label} digest drift`);
  }
  return deepFreeze({ ...body, anchor_digest: anchorDigest });
}

function readRowAnchors(anchorLayout, binding) {
  const identity = ensureRealDirectory(
    anchorLayout.paths.heads,
    "physical experiment row-anchor heads",
  );
  const names = fs.readdirSync(anchorLayout.paths.heads).sort();
  if (names.length > MAX_ROWS || names.some((name) => !ROW_FILE_RE.test(name))) {
    throw new Error("physical experiment row-anchor journal contains unknown or excessive entries");
  }
  const anchors = [];
  for (let index = 0; index < names.length; index += 1) {
    const sequence = Number(ROW_FILE_RE.exec(names[index])[1]);
    if (sequence !== index + 1 || names[index] !== rowFileName(sequence)) {
      throw new Error("physical experiment row-anchor journal contains a gap");
    }
    const anchor = normalizeRowAnchor(
      parseVerifiedJson(
        path.join(anchorLayout.paths.heads, names[index]),
        `physical experiment row anchor ${sequence}`,
        MAX_ROW_ANCHOR_BYTES,
      ),
      binding,
      anchorLayout.persisted,
      `physical experiment row anchor ${sequence}`,
    );
    const expectedPrevious = index === 0 ? ZERO_HASH : anchors[index - 1].anchor_digest;
    if (anchor.sequence !== sequence || anchor.previous_anchor_digest !== expectedPrevious) {
      throw new Error(`physical experiment row anchor ${sequence} forks its monotonic chain`);
    }
    anchors.push(anchor);
  }
  assertDirectoryIdentity(identity, "physical experiment row-anchor heads");
  return Object.freeze(anchors);
}

function publishRowAnchor(anchorLayout, binding, rowRecord, previousAnchor) {
  const previousAnchorDigest = previousAnchor == null
    ? ZERO_HASH
    : previousAnchor.anchor_digest;
  const body = rowAnchorBody(
    binding,
    anchorLayout.persisted,
    rowRecord,
    previousAnchorDigest,
  );
  const candidate = {
    ...body,
    anchor_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-experiment-row-head-anchor/v1",
      ...body,
    }),
  };
  const filePath = path.join(
    anchorLayout.paths.heads,
    rowFileName(rowRecord.commit.expected_sequence),
  );
  const published = publishImmutableJson(
    filePath,
    candidate,
    `physical experiment row anchor ${rowRecord.commit.expected_sequence}`,
    anchorLayout.paths.staging,
    MAX_ROW_ANCHOR_BYTES,
  );
  const durable = normalizeRowAnchor(
    parseVerifiedJson(
      filePath,
      `physical experiment row anchor ${rowRecord.commit.expected_sequence}`,
      MAX_ROW_ANCHOR_BYTES,
    ),
    binding,
    anchorLayout.persisted,
    `physical experiment row anchor ${rowRecord.commit.expected_sequence}`,
  );
  if (durable.anchor_digest !== candidate.anchor_digest) {
    if (!published) throw new Error("physical experiment row anchor conflicts with durable content");
    throw new Error("physical experiment row anchor lacks exact durable readback");
  }
  return durable;
}

function reconcileRowAnchors(anchorLayout, binding, rowRecords, { recoverMissing }) {
  let anchors = readRowAnchors(anchorLayout, binding);
  if (anchors.length > rowRecords.length) {
    throw new Error(
      "physical experiment row journal rollback detected by signer-custodied row-head anchor",
    );
  }
  for (let index = 0; index < anchors.length; index += 1) {
    const anchor = anchors[index];
    const row = rowRecords[index];
    if (anchor.sequence !== row.commit.expected_sequence
        || anchor.row_digest !== row.commit.row_digest
        || anchor.row_commit_digest !== row.commit.row_commit_digest
        || anchor.row_record_digest !== row.record_digest) {
      throw new Error(`physical experiment row ${index + 1} conflicts with its rollback anchor`);
    }
  }
  if (anchors.length < rowRecords.length) {
    if (!recoverMissing) {
      throw new Error("physical experiment row-head anchor is behind the durable row journal");
    }
    let previous = anchors.length === 0 ? null : anchors[anchors.length - 1];
    for (let index = anchors.length; index < rowRecords.length; index += 1) {
      previous = publishRowAnchor(anchorLayout, binding, rowRecords[index], previous);
    }
    anchors = readRowAnchors(anchorLayout, binding);
    if (anchors.length !== rowRecords.length) {
      throw new Error("physical experiment row-head crash recovery lacks exact durable readback");
    }
    for (let index = 0; index < anchors.length; index += 1) {
      if (anchors[index].row_record_digest !== rowRecords[index].record_digest) {
        throw new Error("physical experiment recovered row-head anchor conflicts with row journal");
      }
    }
  }
  return anchors;
}

function withPortState(port, operation) {
  let state;
  let production = false;
  if (PRODUCTION_PORTS.has(port)) {
    state = PRODUCTION_PORT_STATE.get(assertProductionPhysicalExperimentDurableHeadPort(port));
    assertProductionPhysicalExperimentMonotonicOwnerPort(state.monotonicOwnerPort);
    production = true;
  } else {
    state = MECHANISM_A_PORT_STATE.get(assertMechanismAPhysicalExperimentDurableHeadPort(port));
  }
  const trustHead = describeProductionPhysicalExperimentTrustPort(state.trustEnrollment);
  if (trustHead.target_domain !== state.binding.target_domain
      || trustHead.session_nucleus_hash !== state.binding.session_nucleus_hash
      || trustHead.trust_head_digest !== state.binding.trust_head_digest
      || trustHead.signer_owner_custody_digest !== state.binding.signer_owner_custody_digest) {
    throw new Error("physical experiment durable store isolated-owner trust binding drift");
  }
  return withSessionLock(state.binding.target_domain, (directoryIdentity) => {
    assertCurrentNucleus(state.binding);
    const layout = ensureLayout(state.binding, directoryIdentity);
    if (production) reconcileProductionOwnerState(state, layout);
    const result = operation(state, layout, directoryIdentity);
    const currentRows = readRowRecords(layout.paths, state.binding);
    reconcileRowAnchors(
      layout.rowAnchorLayout,
      state.binding,
      currentRows,
      { recoverMissing: false },
    );
    if (production) reconcileProductionOwnerState(state, layout);
    assertCurrentNucleus(state.binding);
    const currentTrustHead = describeProductionPhysicalExperimentTrustPort(state.trustEnrollment);
    if (currentTrustHead.trust_head_digest !== state.binding.trust_head_digest
        || currentTrustHead.signer_owner_custody_digest !== state.binding.signer_owner_custody_digest) {
      throw new Error("physical experiment durable store isolated-owner trust changed");
    }
    assertSafeSessionDirectoryIdentity(directoryIdentity);
    return result;
  });
}

function openMechanismAPhysicalExperimentDurableHeadPort(input, trustEnrollment) {
  const copy = assertClosedDataObject(input, "production physical experiment durable head", [
    "version",
    "target_domain",
    "session_nucleus_hash",
    "plan_hash",
    "trust_binding_digest",
    "trust_head_digest",
    "signer_owner_custody_digest",
  ]);
  if (copy.version !== PHYSICAL_EXPERIMENT_STORE_VERSION) {
    throw new Error(`production physical experiment durable head.version must be ${PHYSICAL_EXPERIMENT_STORE_VERSION}`);
  }
  const productionTrust = assertProductionPhysicalExperimentTrustPort(trustEnrollment);
  const trustHead = describeProductionPhysicalExperimentTrustPort(productionTrust);
  const binding = deepFreeze(bindingBody(copy));
  if (trustHead.target_domain !== binding.target_domain
      || trustHead.session_nucleus_hash !== binding.session_nucleus_hash
      || trustHead.trust_head_digest !== binding.trust_head_digest
      || trustHead.signer_owner_custody_digest !== binding.signer_owner_custody_digest) {
    throw new Error("production physical experiment durable head requires the exact isolated-owner trust head");
  }
  let persisted;
  withSessionLock(binding.target_domain, (directoryIdentity) => {
    assertCurrentNucleus(binding);
    persisted = ensureLayout(binding, directoryIdentity).persisted;
    assertCurrentNucleus(binding);
  });
  const port = deepFreeze({
    version: PHYSICAL_EXPERIMENT_STORE_VERSION,
    port_id: `physical-ledger-head-port:session-${persisted.binding_digest}`,
    consistency_model: "linearizable_session_locked_immutable_compare_and_append",
    production_ready: false,
    durability_trust_class: "mechanism_a_local_signer_custodied_rollback_detection",
    backend_assurance:
      "mechanism_a_local_signed_row_journal_with_signer_custodied_row_head_anchor",
    external_monotonic_owner_bound: false,
    external_monotonic_owner_digest: null,
    blocker: "independently_retained_monotonic_row_head_owner_unavailable",
    target_domain: binding.target_domain,
    session_nucleus_hash: binding.session_nucleus_hash,
    plan_hash: binding.plan_hash,
    trust_binding_digest: binding.trust_binding_digest,
    trust_head_digest: binding.trust_head_digest,
    signer_owner_custody_digest: binding.signer_owner_custody_digest,
    store_binding_digest: persisted.binding_digest,
  });
  MECHANISM_A_PORTS.add(port);
  MECHANISM_A_PORT_STATE.set(port, {
    binding: persisted,
    paths: pathsFor(persisted),
    trustEnrollment: productionTrust,
  });
  return port;
}

function assertMechanismAPhysicalExperimentDurableHeadPort(port) {
  if (!port || !MECHANISM_A_PORTS.has(port) || !MECHANISM_A_PORT_STATE.has(port)
      || !Object.isFrozen(port) || port.production_ready !== false
      || port.durability_trust_class
        !== "mechanism_a_local_signer_custodied_rollback_detection") {
    throw new Error("physical experiment durable head must be a live Mechanism-A local port");
  }
  return port;
}

function assertProductionPhysicalExperimentDurableHeadPort(port) {
  if (!port || !PRODUCTION_PORTS.has(port) || !PRODUCTION_PORT_STATE.has(port)
      || !Object.isFrozen(port) || port.production_ready !== true
      || port.durability_trust_class !== "independently_retained_monotonic_owner"
      || port.external_monotonic_owner_bound !== true) {
    throw new Error(
      "production physical experiment durability requires a genuine independently retained monotonic row-head owner",
    );
  }
  const state = PRODUCTION_PORT_STATE.get(port);
  assertProductionPhysicalExperimentMonotonicOwnerPort(state.monotonicOwnerPort);
  return port;
}

function openProductionPhysicalExperimentDurableHeadPort(input, trustEnrollment, monotonicOwnerPort) {
  const copy = assertClosedDataObject(input, "production physical experiment durable head", [
    "version",
    "target_domain",
    "session_nucleus_hash",
    "plan_hash",
    "trust_binding_digest",
    "trust_head_digest",
    "signer_owner_custody_digest",
  ]);
  if (copy.version !== PHYSICAL_EXPERIMENT_STORE_VERSION) {
    throw new Error(`production physical experiment durable head.version must be ${PHYSICAL_EXPERIMENT_STORE_VERSION}`);
  }
  const owner = assertProductionPhysicalMonotonicOwnerPort(monotonicOwnerPort);
  const productionTrust = assertProductionPhysicalExperimentTrustPort(trustEnrollment);
  const trustHead = describeProductionPhysicalExperimentTrustPort(productionTrust);
  const binding = deepFreeze(bindingBody(copy));
  if (owner.target_domain !== binding.target_domain
      || owner.session_nucleus_hash !== binding.session_nucleus_hash
      || owner.context_domain !== PRODUCTION_OWNER_CONTEXT_DOMAIN) {
    throw new Error("production physical experiment monotonic owner belongs to another context");
  }
  if (trustHead.target_domain !== binding.target_domain
      || trustHead.session_nucleus_hash !== binding.session_nucleus_hash
      || trustHead.trust_head_digest !== binding.trust_head_digest
      || trustHead.signer_owner_custody_digest !== binding.signer_owner_custody_digest) {
    throw new Error("production physical experiment durable head requires the exact isolated-owner trust head");
  }
  let persisted;
  let consumerOwner;
  withSessionLock(binding.target_domain, (directoryIdentity) => {
    assertCurrentNucleus(binding);
    const layout = ensureLayout(binding, directoryIdentity);
    persisted = layout.persisted;
    consumerOwner = claimProductionPhysicalExperimentMonotonicOwner(owner, {
      version: PHYSICAL_EXPERIMENT_STORE_VERSION,
      target_domain: persisted.target_domain,
      session_nucleus_hash: persisted.session_nucleus_hash,
      plan_hash: persisted.plan_hash,
      store_binding_digest: persisted.binding_digest,
      trust_binding_digest: persisted.trust_binding_digest,
      trust_head_digest: persisted.trust_head_digest,
      signer_owner_custody_digest: persisted.signer_owner_custody_digest,
    });
    reconcileProductionOwnerState({
      binding: persisted,
      trustEnrollment: productionTrust,
      monotonicOwnerPort: consumerOwner,
    }, layout);
    assertCurrentNucleus(binding);
    assertSafeSessionDirectoryIdentity(directoryIdentity);
  });
  const port = deepFreeze({
    version: PHYSICAL_EXPERIMENT_STORE_VERSION,
    port_id: `physical-ledger-head-port:external-${owner.slot_digest}`,
    consistency_model: "linearizable_external_monotonic_compare_and_append",
    production_ready: true,
    durability_trust_class: "independently_retained_monotonic_owner",
    backend_assurance:
      "mechanism_a_disjoint_root_signed_monotonic_owner_with_two_phase_row_commit",
    external_monotonic_owner_bound: true,
    external_monotonic_owner_digest: owner.slot_digest,
    blocker: null,
    target_domain: binding.target_domain,
    session_nucleus_hash: binding.session_nucleus_hash,
    plan_hash: binding.plan_hash,
    trust_binding_digest: binding.trust_binding_digest,
    trust_head_digest: binding.trust_head_digest,
    signer_owner_custody_digest: binding.signer_owner_custody_digest,
    store_binding_digest: persisted.binding_digest,
  });
  PRODUCTION_PORTS.add(port);
  PRODUCTION_PORT_STATE.set(port, {
    binding: persisted,
    paths: pathsFor(persisted),
    trustEnrollment: productionTrust,
    monotonicOwnerPort: consumerOwner,
  });
  return port;
}

function readMechanismAPhysicalExperimentHead(port) {
  assertMechanismAPhysicalExperimentDurableHeadPort(port);
  return readPhysicalExperimentHeadFromPort(port);
}

function readProductionPhysicalExperimentHead(port) {
  assertProductionPhysicalExperimentDurableHeadPort(port);
  return readPhysicalExperimentHeadFromPort(port);
}

function readPhysicalExperimentHeadFromPort(port) {
  return withPortState(port, (state, layout) => {
    const records = readRowRecords(layout.paths, state.binding);
    return records.length === 0 ? null : records[records.length - 1].commit;
  });
}

function readMechanismAPhysicalExperimentRows(port) {
  assertMechanismAPhysicalExperimentDurableHeadPort(port);
  return readPhysicalExperimentRowsFromPort(port);
}

function readProductionPhysicalExperimentRows(port) {
  assertProductionPhysicalExperimentDurableHeadPort(port);
  return readPhysicalExperimentRowsFromPort(port);
}

function readPhysicalExperimentRowsFromPort(port) {
  return withPortState(port, (state, layout) => (
    deepFreeze(readRowRecords(layout.paths, state.binding).map((record) => record.row))
  ));
}

function resolveMechanismAPhysicalExperimentCommit(port, request) {
  assertMechanismAPhysicalExperimentDurableHeadPort(port);
  return resolvePhysicalExperimentCommitFromPort(port, request);
}

function resolveProductionPhysicalExperimentCommit(port, request) {
  assertProductionPhysicalExperimentDurableHeadPort(port);
  return resolvePhysicalExperimentCommitFromPort(port, request);
}

function resolvePhysicalExperimentCommitFromPort(port, request) {
  const copy = assertClosedDataObject(request, "production physical experiment commit lookup", [
    "version", "plan_hash", "row_commit_digest",
  ]);
  if (copy.version !== 1) throw new Error("production physical experiment commit lookup.version must be 1");
  assertDigest(copy.plan_hash, "production physical experiment commit lookup.plan_hash");
  assertDigest(copy.row_commit_digest, "production physical experiment commit lookup.row_commit_digest");
  return withPortState(port, (state, layout) => {
    if (copy.plan_hash !== state.binding.plan_hash) {
      throw new Error("production physical experiment commit lookup belongs to another plan");
    }
    const records = readRowRecords(layout.paths, state.binding);
    const record = records.find((entry) => entry.commit.row_commit_digest === copy.row_commit_digest);
    return record == null ? null : record.commit;
  });
}

function buildPhysicalExperimentRowRecord(state, commit, row) {
  const body = {
    version: PHYSICAL_EXPERIMENT_STORE_VERSION,
    target_domain: state.binding.target_domain,
    session_nucleus_hash: state.binding.session_nucleus_hash,
    plan_hash: state.binding.plan_hash,
    commit,
    row: cloneStrictData(row, "production physical experiment append.row"),
  };
  return normalizeRowRecord({
    ...body,
    record_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-experiment-store-row/v1",
      ...body,
    }),
  }, state.binding, "production physical experiment append record");
}

function publishPhysicalExperimentRow(layout, state, record) {
  const commit = record.commit;
  const filePath = path.join(layout.paths.rows, rowFileName(commit.expected_sequence));
  const published = publishImmutableJson(
    filePath,
    record,
    `physical experiment row ${commit.expected_sequence}`,
    layout.paths.staging,
    MAX_ROW_RECORD_BYTES,
  );
  const durable = readRowRecords(layout.paths, state.binding)[commit.expected_sequence - 1] || null;
  if (!durable || durable.commit.row_commit_digest !== commit.row_commit_digest
      || hashCanonicalJson(durable.row) !== hashCanonicalJson(record.row)) {
    if (!published) return null;
    throw new Error("physical experiment row publication lacks exact durable readback");
  }
  const anchors = readRowAnchors(layout.rowAnchorLayout, state.binding);
  if (anchors.length !== commit.expected_sequence - 1) {
    throw new Error("physical experiment row anchor is not at the exact pre-append head");
  }
  const previousAnchor = anchors.length === 0 ? null : anchors[anchors.length - 1];
  const durableAnchor = publishRowAnchor(
    layout.rowAnchorLayout,
    state.binding,
    durable,
    previousAnchor,
  );
  if (durableAnchor.sequence !== commit.expected_sequence
      || durableAnchor.row_digest !== commit.row_digest
      || durableAnchor.row_commit_digest !== commit.row_commit_digest) {
    throw new Error("physical experiment row anchor publication drifted from exact append");
  }
  return durable;
}

function prepareAppend(port, input, expectedProduction) {
  const copy = assertClosedDataObject(input, "production physical experiment append", ["commit", "row"]);
  return withPortState(port, (state, layout) => {
    const commit = normalizeCommit(copy.commit, "production physical experiment append.commit");
    if (commit.plan_hash !== state.binding.plan_hash) {
      throw new Error("production physical experiment append belongs to another plan");
    }
    const records = readRowRecords(layout.paths, state.binding);
    const existing = records[commit.expected_sequence - 1] || null;
    if (existing) {
      return existing.commit.row_commit_digest === commit.row_commit_digest
        && hashCanonicalJson(existing.row) === hashCanonicalJson(copy.row);
    }
    const currentSequence = records.length;
    const currentDigest = currentSequence === 0 ? ZERO_HASH : records[currentSequence - 1].commit.row_digest;
    if (commit.expected_sequence !== currentSequence + 1
        || commit.previous_row_hash !== currentDigest) return false;
    const record = buildPhysicalExperimentRowRecord(state, commit, copy.row);
    if (!expectedProduction) return publishPhysicalExperimentRow(layout, state, record) != null;

    const currentOwnerState = reconcileProductionOwnerState(state, layout);
    if (currentOwnerState.phase !== "committed"
        || currentOwnerState.logical_sequence !== currentSequence) {
      throw new Error("production physical experiment monotonic owner is not at the append base");
    }
    const prepared = preparedProductionOwnerState(
      state.binding,
      state.monotonicOwnerPort,
      currentOwnerState,
      record,
    );
    const preparedReadback = compareAndSetProductionOwnerState(
      state,
      currentOwnerState,
      prepared,
    );
    if (preparedReadback == null) return false;

    let durable;
    try {
      durable = publishPhysicalExperimentRow(layout, state, record);
    } catch (error) {
      // Recovery appends an authenticated abort head when no row was published,
      // or finalizes the prepared head when exact durable bytes already exist.
      try { reconcileProductionOwnerState(state, layout); } catch {}
      throw error;
    }
    if (durable == null) {
      reconcileProductionOwnerState(state, layout);
      return false;
    }
    const committed = committedProductionOwnerState(
      state.binding,
      state.monotonicOwnerPort,
      durable,
      productionOwnerStateDigest(prepared),
      prepared.monotonic_revision + 1,
    );
    const committedReadback = compareAndSetProductionOwnerState(state, prepared, committed);
    if (committedReadback == null) {
      const reconciled = reconcileProductionOwnerState(state, layout);
      if (!exactProductionOwnerState(reconciled, committed)) return false;
    }
    return true;
  });
}

function appendMechanismAPhysicalExperimentRow(port, input) {
  assertMechanismAPhysicalExperimentDurableHeadPort(port);
  return prepareAppend(port, input, false);
}

function appendProductionPhysicalExperimentRow(port, input) {
  assertProductionPhysicalExperimentDurableHeadPort(port);
  return prepareAppend(port, input, true);
}

function normalizeReceiptRecord(input, binding, label) {
  const copy = assertClosedDataObject(input, label, [
    "version",
    "target_domain",
    "session_nucleus_hash",
    "plan_hash",
    "receipt_ref",
    "receipt_digest",
    "receipt",
    "record_digest",
  ]);
  if (copy.version !== PHYSICAL_EXPERIMENT_STORE_VERSION
      || copy.target_domain !== binding.target_domain
      || copy.session_nucleus_hash !== binding.session_nucleus_hash
      || copy.plan_hash !== binding.plan_hash) {
    throw new Error(`${label} store binding drift`);
  }
  const receiptRef = assertReceiptRef(copy.receipt_ref, `${label}.receipt_ref`);
  const receiptDigest = assertDigest(copy.receipt_digest, `${label}.receipt_digest`);
  if (!isPlainDataObject(copy.receipt)
      || copy.receipt.receipt_ref !== receiptRef
      || copy.receipt.receipt_digest !== receiptDigest) {
    throw new Error(`${label} does not bind the exact signed receipt`);
  }
  const body = {
    version: PHYSICAL_EXPERIMENT_STORE_VERSION,
    target_domain: binding.target_domain,
    session_nucleus_hash: binding.session_nucleus_hash,
    plan_hash: binding.plan_hash,
    receipt_ref: receiptRef,
    receipt_digest: receiptDigest,
    receipt: copy.receipt,
  };
  const digest = hashCanonicalJson({
    domain: "hacker-bob/physical-experiment-store-receipt/v1",
    ...body,
  });
  if (assertDigest(copy.record_digest, `${label}.record_digest`) !== digest) {
    throw new Error(`${label} record digest drift`);
  }
  return deepFreeze({ ...body, record_digest: digest });
}

function assertReceiptJournalCapacity(paths, desiredFileName, additionalBytes) {
  const identity = ensureRealDirectory(paths.receipts, "physical experiment receipts directory");
  const names = fs.readdirSync(paths.receipts).sort();
  if (names.length > MAX_RECEIPTS || names.some((name) => !RECEIPT_FILE_RE.test(name))) {
    throw new Error("physical experiment receipt journal contains an unknown or excessive entry");
  }
  let aggregateBytes = 0;
  for (const name of names) {
    const stats = fs.lstatSync(path.join(paths.receipts, name));
    const ownerMismatch = typeof process.getuid === "function" && stats.uid !== process.getuid();
    if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink !== 1
        || stats.size < 1 || stats.size > MAX_RECEIPT_RECORD_BYTES
        || ownerMismatch || (stats.mode & 0o077) !== 0) {
      throw new Error("physical experiment receipt journal contains an unsafe entry");
    }
    aggregateBytes += stats.size;
    if (!Number.isSafeInteger(aggregateBytes) || aggregateBytes > MAX_RECEIPT_JOURNAL_BYTES) {
      throw new Error("physical experiment receipt journal exceeds its aggregate size cap");
    }
  }
  if (!names.includes(desiredFileName)) {
    if (names.length >= MAX_RECEIPTS) {
      throw new Error("physical experiment receipt journal is full");
    }
    if (!Number.isSafeInteger(additionalBytes) || additionalBytes < 1
        || aggregateBytes + additionalBytes > MAX_RECEIPT_JOURNAL_BYTES) {
      throw new Error("physical experiment receipt journal would exceed its aggregate size cap");
    }
  }
  assertDirectoryIdentity(identity, "physical experiment receipts directory");
}

function ingestMechanismAPhysicalExperimentReceipt(port, receiptInput) {
  assertMechanismAPhysicalExperimentDurableHeadPort(port);
  return ingestPhysicalExperimentReceiptForPort(port, receiptInput);
}

function ingestProductionPhysicalExperimentReceipt(port, receiptInput) {
  assertProductionPhysicalExperimentDurableHeadPort(port);
  return ingestPhysicalExperimentReceiptForPort(port, receiptInput);
}

function ingestPhysicalExperimentReceiptForPort(port, receiptInput) {
  const receipt = cloneStrictData(receiptInput, "production physical experiment receipt");
  return withPortState(port, (state, layout) => {
    if (!isPlainDataObject(receipt)) throw new Error("production physical experiment receipt must be an object");
    const body = {
      version: PHYSICAL_EXPERIMENT_STORE_VERSION,
      target_domain: state.binding.target_domain,
      session_nucleus_hash: state.binding.session_nucleus_hash,
      plan_hash: state.binding.plan_hash,
      receipt_ref: receipt.receipt_ref,
      receipt_digest: receipt.receipt_digest,
      receipt,
    };
    const record = normalizeReceiptRecord({
      ...body,
      record_digest: hashCanonicalJson({
        domain: "hacker-bob/physical-experiment-store-receipt/v1",
        ...body,
      }),
    }, state.binding, "production physical experiment receipt record");
    const fileName = `${record.receipt_digest}.json`;
    const filePath = path.join(layout.paths.receipts, fileName);
    const recordBytes = Buffer.byteLength(`${JSON.stringify(record)}\n`);
    if (recordBytes > MAX_RECEIPT_RECORD_BYTES) {
      throw new Error("physical experiment evidence receipt exceeds its serialized size cap");
    }
    assertReceiptJournalCapacity(layout.paths, fileName, recordBytes);
    const published = publishImmutableJson(
      filePath,
      record,
      "physical experiment evidence receipt",
      layout.paths.staging,
      MAX_RECEIPT_RECORD_BYTES,
    );
    const durable = normalizeReceiptRecord(
      parseVerifiedJson(filePath, "physical experiment evidence receipt", MAX_RECEIPT_RECORD_BYTES),
      state.binding,
      "physical experiment evidence receipt",
    );
    if (durable.receipt_ref !== record.receipt_ref
        || durable.receipt_digest !== record.receipt_digest
        || hashCanonicalJson(durable.receipt) !== hashCanonicalJson(record.receipt)) {
      if (!published) throw new Error("physical experiment evidence receipt conflicts with durable content");
      throw new Error("physical experiment evidence receipt lacks exact durable readback");
    }
    return durable.receipt;
  });
}

function resolveMechanismAPhysicalExperimentReceipt(port, request) {
  assertMechanismAPhysicalExperimentDurableHeadPort(port);
  return resolvePhysicalExperimentReceiptForPort(port, request);
}

function resolveProductionPhysicalExperimentReceipt(port, request) {
  assertProductionPhysicalExperimentDurableHeadPort(port);
  return resolvePhysicalExperimentReceiptForPort(port, request);
}

function resolvePhysicalExperimentReceiptForPort(port, request) {
  const copy = assertClosedDataObject(request, "production physical experiment receipt lookup", [
    "receipt_ref", "receipt_digest",
  ]);
  const receiptRef = assertReceiptRef(copy.receipt_ref, "production physical experiment receipt lookup.receipt_ref");
  const receiptDigest = assertDigest(copy.receipt_digest, "production physical experiment receipt lookup.receipt_digest");
  return withPortState(port, (state, layout) => {
    const receiptIdentity = ensureRealDirectory(
      layout.paths.receipts,
      "physical experiment receipts directory",
    );
    const names = fs.readdirSync(layout.paths.receipts).sort();
    if (names.length > MAX_RECEIPTS || names.some((name) => !RECEIPT_FILE_RE.test(name))) {
      throw new Error("physical experiment receipt journal contains an unknown or excessive entry");
    }
    const fileName = `${receiptDigest}.json`;
    if (!names.includes(fileName)) return null;
    const record = normalizeReceiptRecord(
      parseVerifiedJson(
        path.join(layout.paths.receipts, fileName),
        "physical experiment evidence receipt",
        MAX_RECEIPT_RECORD_BYTES,
      ),
      state.binding,
      "physical experiment evidence receipt",
    );
    assertDirectoryIdentity(receiptIdentity, "physical experiment receipts directory");
    if (record.receipt_ref !== receiptRef || record.receipt_digest !== receiptDigest) {
      throw new Error("physical experiment receipt lookup returned conflicting durable content");
    }
    return record.receipt;
  });
}

module.exports = Object.freeze({
  PHYSICAL_EXPERIMENT_STORE_VERSION,
  appendMechanismAPhysicalExperimentRow,
  appendProductionPhysicalExperimentRow,
  assertMechanismAPhysicalExperimentDurableHeadPort,
  assertProductionPhysicalExperimentDurableHeadPort,
  ingestMechanismAPhysicalExperimentReceipt,
  ingestProductionPhysicalExperimentReceipt,
  openMechanismAPhysicalExperimentDurableHeadPort,
  openProductionPhysicalExperimentDurableHeadPort,
  readMechanismAPhysicalExperimentHead,
  readMechanismAPhysicalExperimentRows,
  readProductionPhysicalExperimentHead,
  readProductionPhysicalExperimentRows,
  resolveMechanismAPhysicalExperimentCommit,
  resolveMechanismAPhysicalExperimentReceipt,
  resolveProductionPhysicalExperimentCommit,
  resolveProductionPhysicalExperimentReceipt,
});
