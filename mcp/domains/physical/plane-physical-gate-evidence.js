"use strict";

// PH-X8 production gate-evidence.
//
// Unlike the callback-backed v1 conformance contract, this runtime owns its
// clock and durable store. Issuers are permanently separated by evidence
// class, every document is Ed25519 signed, and every accepted document extends
// a store-signed, fsync-before-return sequence chain. No caller supplies wall
// time, nonce, sequence, receipt, readiness, or HIL flags.

const crypto = require("node:crypto");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { types: utilTypes } = require("node:util");
const {
  assertProductionPhysicalMonotonicOwnerPort,
  compareAndSetPhysicalMonotonicOwnerState,
  describePhysicalMonotonicOwner,
  readPhysicalMonotonicOwnerState,
} = require("./physical-monotonic-owner.js");
const {
  assertProductionPhysicalTrustedClockPort,
  assertProductionPhysicalTrustedClockSample,
  describeProductionPhysicalTrustedClockPort,
  sampleRestartDurablePhysicalTrustedClock,
} = require("./physical-trusted-clock-store.js");
const { assertSafeDomain } = require("../../core/io/paths.js");

const VERSION = 1;
const DOMAIN = "hacker-bob/plane-physical-gate-evidence";
const KIND = "plane_physical_gate_evidence";
const CONFORMANCE_ASSURANCE = "server_owned_process_clock_signed_store_conformance";
const PRODUCTION_ASSURANCE = "authenticated_clock_mechanism_a_monotonic_signed_store";
const CONFORMANCE_BLOCKERS = Object.freeze([
  "authenticated_boot_continuous_trusted_clock_unavailable",
  "independent_mechanism_a_monotonic_store_custody_unavailable",
  "independent_signer_custody_unavailable",
  "independent_release_action_custody_unavailable",
]);
const RECEIPT_DOMAIN = "hacker-bob/plane-physical-gate-evidence-receipt";
const TIME_DOMAIN = "hacker-bob/plane-physical-gate-evidence-trusted-time";
const REVOCATION_DOMAIN = "hacker-bob/plane-physical-gate-evidence-revocation";
const NONCE_DOMAIN = "hacker-bob/plane-physical-gate-evidence-nonce-claim";
const ISSUE_TRANSACTION_DOMAIN =
  "hacker-bob/plane-physical-gate-evidence-issue-transaction";
const AUTHORITY_DOMAIN = "hacker-bob/plane-physical-gate-evidence-authority";
const LOCK_DOMAIN = "hacker-bob/plane-physical-gate-evidence-lock";
const RELEASE_SNAPSHOT_RECEIPT_DOMAIN =
  "hacker-bob/plane-physical-release-snapshot-receipt";
const CANDIDATE_DOMAIN = "hacker-bob/plane-physical-release-candidate";
const EVIDENCE_REF_PREFIX = "bob-evidence:sha256:";
const RECEIPT_REF_PREFIX = "gate-evidence-receipt:";
const RELEASE_SNAPSHOT_RECEIPT_REF_PREFIX = "gate-release-snapshot-receipt:";
const RUNTIME_KIND = "plane_physical_gate_evidence_runtime";

const EVIDENCE_CLASSES = Object.freeze(["engineering", "review", "hil", "qualification"]);
const GATE_KINDS = Object.freeze(["engineering", "review", "hil"]);
const VERDICTS = Object.freeze(["failed", "inconclusive", "passed"]);
const CLASS_GATE = Object.freeze({
  engineering: "engineering",
  review: "review",
  hil: "hil",
  qualification: "engineering",
});

const DIGEST_RE = /^[a-f0-9]{64}$/u;
const TOKEN_RE = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const IDENTIFIER_RE = /^[a-z][a-z0-9._-]{0,127}$/u;
const OPAQUE_REF_RE = /^[a-z][a-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const EVIDENCE_REF_RE = /^bob-evidence:sha256:([a-f0-9]{64})$/u;
const RECEIPT_REF_RE = /^gate-evidence-receipt:([a-f0-9]{64})$/u;
const SIGNATURE_RE = /^[A-Za-z0-9_-]{86}$/u;
const SEQUENCE_FILE_RE = /^(0[0-9]{19})\.json$/u;
const ATOMIC_STAGE_FILE_RE = /^\.(.+)\.([a-f0-9]{64})\.(0400|0600)\.([1-9][0-9]{0,19})\.([a-f0-9]{16})\.([a-f0-9]{32})\.([a-f0-9]{32})\.stage$/u;
const MAX_VALIDITY_MS = 7 * 24 * 60 * 60 * 1000;
const MIN_VALIDITY_MS = 1;
const KEY_MODE = 0o400;
const FILE_MODE = 0o600;
const DIRECTORY_MODE = 0o700;
const MAX_ATOMIC_STAGE_FILES = 64;

const RUNTIMES = new WeakSet();
const RUNTIME_STATE = new WeakMap();
const PROJECTIONS = new WeakSet();
const PROJECTION_STATE = new WeakMap();
const BATCH_PROJECTIONS = new WeakSet();
const BATCH_PROJECTION_STATE = new WeakMap();
const MAX_BATCH_ENTRIES = 4096;
const RELEASE_SNAPSHOT_RECEIPT_VALIDITY_MS = 5 * 60 * 1000;
const RELEASE_SNAPSHOT_RECEIPT_PROJECTIONS = new WeakSet();
const RELEASE_SNAPSHOT_RECEIPT_PROJECTION_STATE = new WeakMap();
let CURRENT_PROCESS_START_TOKEN = null;

const ISSUE_FIELDS = Object.freeze([
  "graph_id",
  "node_id",
  "gate_kind",
  "evidence_class",
  "session_nucleus_hash",
  "source_tree_digest",
  "release_candidate_digest",
  "package_digest",
  "task_graph_digest",
  "release_snapshot_digest",
  "node_contract_digest",
  "gate_contract_digest",
  "acceptance_digest",
  "result_digest",
  "verdict",
]);

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("gate evidence canonical data is non-finite");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (utilTypes.isProxy(value)) throw new Error("gate evidence cannot contain Proxy arrays");
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (!value || typeof value !== "object" || utilTypes.isProxy(value)
      || (Object.getPrototypeOf(value) !== Object.prototype
        && Object.getPrototypeOf(value) !== null)) {
    throw new Error("gate evidence canonical data must be plain JSON data");
  }
  const fields = Object.keys(value).sort();
  return `{${fields.map((field) => (
    `${JSON.stringify(field)}:${canonicalJson(value[field])}`
  )).join(",")}}`;
}

function digestJson(value) {
  return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function exactObject(value, label, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value) || utilTypes.isProxy(value)
      || (Object.getPrototypeOf(value) !== Object.prototype
        && Object.getPrototypeOf(value) !== null)) {
    throw new Error(`${label} must be an exact plain data object`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actual = Reflect.ownKeys(value);
  if (actual.some((field) => typeof field !== "string")
      || actual.length !== fields.length
      || [...actual].sort().some((field, index) => field !== [...fields].sort()[index])) {
    throw new Error(`${label} fields are not exact`);
  }
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) {
      throw new Error(`${label}.${field} must be an enumerable data property`);
    }
  }
  return value;
}

function exactDenseDataArray(value, label, expectedLength) {
  if (!Array.isArray(value) || utilTypes.isProxy(value)) {
    throw new Error(`${label} must be a dense non-Proxy data-only array`);
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const expectedNames = [
    ...Array.from({ length: expectedLength }, (_, index) => String(index)),
    "length",
  ].sort();
  const actualNames = Object.getOwnPropertyNames(value).sort();
  if (actualNames.length !== expectedNames.length
      || actualNames.some((name, index) => name !== expectedNames[index])
      || descriptors.length?.value !== expectedLength) {
    throw new Error(`${label} must contain exactly ${expectedLength} dense entries`);
  }
  return Object.freeze(Array.from({ length: expectedLength }, (_, index) => {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) {
      throw new Error(`${label}[${index}] must be an enumerable data property`);
    }
    return descriptor.value;
  }));
}

function boundedDenseDataArray(value, label, minimumLength, maximumLength) {
  if (!Array.isArray(value) || utilTypes.isProxy(value)) {
    throw new Error(`${label} must be a dense non-Proxy data-only array`);
  }
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  const length = lengthDescriptor?.value;
  if (!Number.isSafeInteger(length) || length < minimumLength || length > maximumLength) {
    throw new Error(`${label} length must be in [${minimumLength}, ${maximumLength}]`);
  }
  return exactDenseDataArray(value, label, length);
}

function digest(value, label) {
  if (typeof value !== "string" || !DIGEST_RE.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function token(value, label) {
  if (typeof value !== "string" || !TOKEN_RE.test(value)) {
    throw new Error(`${label} must be a bounded opaque token`);
  }
  return value;
}

function identifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_RE.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function opaqueRef(value, label, prefix) {
  if (typeof value !== "string" || !OPAQUE_REF_RE.test(value)
      || !value.startsWith(`${prefix}:`)) {
    throw new Error(`${label} must use the ${prefix}: namespace`);
  }
  return value;
}

function enumValue(value, values, label) {
  if (!values.includes(value)) throw new Error(`${label} is not an allowed enum value`);
  return value;
}

function boundedInteger(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be an integer in [${minimum}, ${maximum}]`);
  }
  return value;
}

function canonicalTimestamp(value, label) {
  const milliseconds = typeof value === "string" ? Date.parse(value) : NaN;
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC timestamp`);
  }
  return value;
}

function canonicalSignature(value, label) {
  if (typeof value !== "string" || !SIGNATURE_RE.test(value)) {
    throw new Error(`${label} must be a canonical Ed25519 signature`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) {
    throw new Error(`${label} must be a canonical Ed25519 signature`);
  }
  return value;
}

function keyPairDescriptor(privateKeyPem, label) {
  if (typeof privateKeyPem !== "string" || Buffer.byteLength(privateKeyPem) > 16_384) {
    throw new Error(`${label} must be a bounded Ed25519 private key`);
  }
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(privateKeyPem);
  } catch {
    throw new Error(`${label} must be a valid Ed25519 private key`);
  }
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error(`${label} must be a valid Ed25519 private key`);
  }
  const publicKey = crypto.createPublicKey(privateKey);
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  return Object.freeze({
    privateKey,
    publicKey,
    publicKeyDigest: crypto.createHash("sha256").update(publicDer).digest("hex"),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
  });
}

function verifySignature(publicKey, messageDigest, signature, label) {
  if (!crypto.verify(
    null,
    Buffer.from(digest(messageDigest, `${label}.message_digest`), "hex"),
    publicKey,
    Buffer.from(canonicalSignature(signature, `${label}.signature`), "base64url"),
  )) throw new Error(`${label} signature verification failed`);
}

function evidenceKeyUsage(evidenceClass) {
  return `plane_physical_gate_evidence_${evidenceClass}_signing`;
}

function evidenceRef(value, label = "evidence_ref") {
  if (typeof value !== "string" || !EVIDENCE_REF_RE.test(value)) {
    throw new Error(`${label} must be bob-evidence:sha256:<digest>`);
  }
  return value;
}

function receiptRef(value, label = "receipt_ref") {
  if (typeof value !== "string" || !RECEIPT_REF_RE.test(value)) {
    throw new Error(`${label} must be a content-addressed receipt reference`);
  }
  return value;
}

function releaseCandidateDigest(input) {
  exactObject(input, "plane physical release candidate", [
    "session_nucleus_hash",
    "source_tree_digest",
    "package_digest",
    "task_graph_digest",
    "release_snapshot_digest",
  ]);
  return digestJson({
    domain: CANDIDATE_DOMAIN,
    version: VERSION,
    session_nucleus_hash: digest(input.session_nucleus_hash, "session_nucleus_hash"),
    source_tree_digest: digest(input.source_tree_digest, "source_tree_digest"),
    package_digest: digest(input.package_digest, "package_digest"),
    task_graph_digest: digest(input.task_graph_digest, "task_graph_digest"),
    release_snapshot_digest: digest(input.release_snapshot_digest, "release_snapshot_digest"),
  });
}

function assertOwnedDirectory(rootInput) {
  if (typeof rootInput !== "string" || !path.isAbsolute(rootInput)
      || path.normalize(rootInput) !== rootInput) {
    throw new Error("gate evidence runtime root must be a normalized absolute path");
  }
  const inputStats = fs.lstatSync(rootInput);
  if (inputStats.isSymbolicLink()) {
    throw new Error("gate evidence runtime root cannot be a symbolic link");
  }
  const root = fs.realpathSync(rootInput);
  const stats = fs.lstatSync(root);
  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    throw new Error("gate evidence runtime root must be a real directory");
  }
  if ((stats.mode & 0o777) !== DIRECTORY_MODE) {
    throw new Error("gate evidence runtime root must be owner-only mode 0700");
  }
  if (typeof process.getuid === "function" && stats.uid !== process.getuid()) {
    throw new Error("gate evidence runtime root must be owned by this process uid");
  }
  return root;
}

function ensureDirectory(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: DIRECTORY_MODE });
  const stats = fs.lstatSync(directory);
  if (!stats.isDirectory() || stats.isSymbolicLink() || (stats.mode & 0o777) !== DIRECTORY_MODE) {
    throw new Error(`gate evidence directory custody is invalid: ${directory}`);
  }
  if (typeof process.getuid === "function" && stats.uid !== process.getuid()) {
    throw new Error(`gate evidence directory ownership is invalid: ${directory}`);
  }
}

function filesystemIdentity(stats) {
  return Object.freeze({
    device: String(stats.dev),
    inode: String(stats.ino),
    uid: typeof stats.uid === "number" ? stats.uid : null,
    mode: stats.mode & 0o777,
    nlink: typeof stats.nlink === "number" ? stats.nlink : null,
  });
}

function sameFilesystemIdentity(left, right, includeNlink = true) {
  return left.device === right.device
    && left.inode === right.inode
    && left.uid === right.uid
    && left.mode === right.mode
    && (!includeNlink || left.nlink === right.nlink);
}

function exactDirectoryIdentity(directory, label) {
  let real;
  try { real = fs.realpathSync(directory); } catch { throw new Error(`${label} is unavailable`); }
  if (real !== directory) throw new Error(`${label} realpath changed`);
  const stats = fs.lstatSync(directory);
  if (!stats.isDirectory() || stats.isSymbolicLink()
      || (stats.mode & 0o777) !== DIRECTORY_MODE
      || (typeof process.getuid === "function" && stats.uid !== process.getuid())) {
    throw new Error(`${label} live custody is invalid`);
  }
  return filesystemIdentity(stats);
}

function fsyncDirectory(directory) {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY);
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

function readTextFileExact(filePath, label, mode = FILE_MODE, allowedLinks = [1]) {
  if (!Number.isInteger(fs.constants.O_NOFOLLOW)) {
    throw new Error(`${label} requires O_NOFOLLOW support`);
  }
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
    );
  } catch {
    throw new Error(`${label} no-follow open failed`);
  }
  try {
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || !allowedLinks.includes(before.nlink)
        || (before.mode & 0o777) !== mode
        || (typeof process.getuid === "function" && before.uid !== process.getuid())) {
      throw new Error(`${label} custody is invalid`);
    }
    const text = fs.readFileSync(descriptor, "utf8");
    const after = fs.fstatSync(descriptor);
    const pathStats = fs.lstatSync(filePath);
    const beforeIdentity = filesystemIdentity(before);
    if (pathStats.isSymbolicLink()
        || !sameFilesystemIdentity(beforeIdentity, filesystemIdentity(after))
        || !sameFilesystemIdentity(beforeIdentity, filesystemIdentity(pathStats))) {
      throw new Error(`${label} changed during no-follow readback`);
    }
    return Object.freeze({ text, identity: beforeIdentity });
  } finally {
    fs.closeSync(descriptor);
  }
}

function readFileExact(filePath, label, mode = FILE_MODE) {
  const { text } = readTextFileExact(filePath, label, mode);
  try { return JSON.parse(text); } catch { throw new Error(`${label} is not valid JSON`); }
}

function writeAll(descriptor, buffer) {
  let offset = 0;
  while (offset < buffer.length) {
    const written = fs.writeSync(descriptor, buffer, offset, buffer.length - offset, offset);
    if (!Number.isSafeInteger(written) || written < 1) {
      throw new Error("gate evidence staged write made no forward progress");
    }
    offset += written;
  }
}

function sameInode(left, right) {
  const leftDevice = Object.hasOwn(left, "device") ? left.device : String(left.dev);
  const rightDevice = Object.hasOwn(right, "device") ? right.device : String(right.dev);
  const leftInode = Object.hasOwn(left, "inode") ? left.inode : String(left.ino);
  const rightInode = Object.hasOwn(right, "inode") ? right.inode : String(right.ino);
  return leftDevice === rightDevice && leftInode === rightInode;
}

function unlinkExactOwnedFile(filePath, identity) {
  let current;
  try { current = fs.lstatSync(filePath); } catch (error) {
    if (error && error.code === "ENOENT") return true;
    return false;
  }
  if (!current.isFile() || current.isSymbolicLink() || !sameInode(current, identity)
      || (current.mode & 0o777) !== (identity.mode & 0o777)
      || (typeof process.getuid === "function" && current.uid !== process.getuid())) {
    return false;
  }
  fs.unlinkSync(filePath);
  return true;
}

function atomicStageOwnerBinding() {
  const processStart = currentProcessStartToken();
  if (processStart == null) {
    throw new Error("gate evidence atomic publication process identity is unavailable");
  }
  return Object.freeze({
    pid: String(process.pid),
    hostnameDigest: hashText(os.hostname()).slice(0, 16),
    processStartDigest: hashText(processStart).slice(0, 32),
  });
}

function atomicStageOwnerLiveness(match) {
  const pid = Number(match[4]);
  if (!Number.isSafeInteger(pid) || pid < 1) return "invalid";
  if (match[5] !== hashText(os.hostname()).slice(0, 16)) return "unknown";
  try {
    process.kill(pid, 0);
  } catch (error) {
    if (error && error.code === "ESRCH") return "dead";
    return "unknown";
  }
  const processStart = processStartToken(pid);
  if (processStart == null) return "unknown";
  return hashText(processStart).slice(0, 32) === match[6] ? "alive" : "dead";
}

function repairPublishedAtomicStages(directory, label) {
  const stageNames = fs.readdirSync(directory).filter(
    (name) => ATOMIC_STAGE_FILE_RE.test(name),
  );
  let repaired = false;
  let remaining = 0;
  for (const name of stageNames) {
    const match = ATOMIC_STAGE_FILE_RE.exec(name);
    const stagePath = path.join(directory, name);
    const stage = fs.lstatSync(stagePath);
    const stageMode = Number.parseInt(match[3], 8);
    const ownerLiveness = atomicStageOwnerLiveness(match);
    if (!stage.isFile() || stage.isSymbolicLink() || stage.nlink < 1 || stage.nlink > 2
        || ![KEY_MODE, FILE_MODE].includes(stageMode)
        || ownerLiveness === "invalid"
        || (stage.mode & 0o777) !== stageMode
        || (typeof process.getuid === "function" && stage.uid !== process.getuid())) {
      throw new Error(`${label} contains an unsafe atomic publication stage`);
    }
    // A single-link stage was never a commit point.  Keep a live or remotely
    // owned writer untouched; reclaim an exact local stage only after its PID
    // and process-start binding prove that the writer is dead.
    if (stage.nlink === 1) {
      if (ownerLiveness !== "dead") {
        remaining += 1;
        continue;
      }
      const current = fs.lstatSync(stagePath);
      if (!sameInode(stage, current) || current.nlink !== 1
          || atomicStageOwnerLiveness(match) !== "dead"
          || !unlinkExactOwnedFile(stagePath, stage)) {
        throw new Error(`${label} atomic publication stage changed during recovery`);
      }
      repaired = true;
      continue;
    }
    // A two-link stage proves publication only when its sibling final path is
    // the exact same inode and its content hash is bound by the stage name.
    const finalName = match[1];
    if (path.basename(finalName) !== finalName || ATOMIC_STAGE_FILE_RE.test(finalName)) {
      throw new Error(`${label} atomic publication stage target is invalid`);
    }
    const finalPath = path.join(directory, finalName);
    const final = fs.lstatSync(finalPath);
    if (!final.isFile() || final.isSymbolicLink() || final.nlink !== 2
        || !sameInode(stage, final)) {
      throw new Error(`${label} atomic publication stage has no exact final sibling`);
    }
    const staged = readTextFileExact(
      stagePath,
      `${label} atomic stage`,
      stageMode,
      [2],
    );
    if (hashText(staged.text) !== match[2]) {
      throw new Error(`${label} atomic publication stage content digest drift`);
    }
    if (ownerLiveness !== "dead") {
      remaining += 1;
      continue;
    }
    const current = fs.lstatSync(stagePath);
    if (!sameInode(stage, current) || current.nlink !== 2
        || atomicStageOwnerLiveness(match) !== "dead"
        || !unlinkExactOwnedFile(stagePath, stage)) {
      throw new Error(`${label} atomic publication stage changed during recovery`);
    }
    repaired = true;
  }
  if (repaired) fsyncDirectory(directory);
  if (remaining >= MAX_ATOMIC_STAGE_FILES) {
    throw new Error(`${label} contains too many atomic publication stages`);
  }
}

function atomicDirectoryNames(directory, label) {
  repairPublishedAtomicStages(directory, label);
  return fs.readdirSync(directory).filter((name) => !ATOMIC_STAGE_FILE_RE.test(name));
}

function exactPublishedText(
  filePath,
  expectedText,
  label,
  allowedLinks = [1],
  mode = FILE_MODE,
) {
  try {
    return readTextFileExact(filePath, label, mode, allowedLinks).text === expectedText;
  } catch {
    return false;
  }
}

function publishExclusiveAtomicFile(filePath, text, label, mode = FILE_MODE) {
  if (!Number.isInteger(fs.constants.O_NOFOLLOW)) {
    throw new Error(`${label} requires O_NOFOLLOW support`);
  }
  if (![KEY_MODE, FILE_MODE].includes(mode)) {
    throw new Error(`${label} atomic publication mode is invalid`);
  }
  const directory = path.dirname(filePath);
  const finalName = path.basename(filePath);
  if (finalName !== path.basename(finalName) || ATOMIC_STAGE_FILE_RE.test(finalName)) {
    throw new Error(`${label} final path is invalid`);
  }
  repairPublishedAtomicStages(directory, label);
  const encoded = Buffer.from(text, "utf8");
  const contentDigest = hashText(text);
  const stageOwner = atomicStageOwnerBinding();
  const stagePath = path.join(
    directory,
    `.${finalName}.${contentDigest}.${mode.toString(8).padStart(4, "0")}`
      + `.${stageOwner.pid}.${stageOwner.hostnameDigest}`
      + `.${stageOwner.processStartDigest}.${crypto.randomBytes(16).toString("hex")}.stage`,
  );
  let descriptor = null;
  let createdIdentity = null;
  try {
    descriptor = fs.openSync(
      stagePath,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY
        | fs.constants.O_NOFOLLOW,
      mode,
    );
    createdIdentity = fs.fstatSync(descriptor);
    if (!createdIdentity.isFile() || createdIdentity.nlink !== 1
        || (createdIdentity.mode & 0o777) !== mode
        || (typeof process.getuid === "function"
          && createdIdentity.uid !== process.getuid())) {
      throw new Error(`${label} staged file custody is invalid`);
    }
    writeAll(descriptor, encoded);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = null;
    const staged = readTextFileExact(stagePath, `${label} staged file`, mode);
    if (staged.text !== text || hashText(staged.text) !== contentDigest) {
      throw new Error(`${label} staged file exact readback failed`);
    }

    let publishedByThisCall = false;
    try {
      fs.linkSync(stagePath, filePath);
      publishedByThisCall = true;
    } catch (error) {
      // link(2) can report an acknowledgement failure after the directory entry
      // became visible.  Reconcile only the exact intended bytes; a conflicting,
      // malformed, symlinked, or hardlinked final is never removed or replaced.
      if (!exactPublishedText(filePath, text, label, [1, 2], mode)) {
        if (error && error.code === "EEXIST") {
          throw new Error(`${label} conflicts with immutable durable state`);
        }
        throw error;
      }
    }

    const final = fs.lstatSync(filePath);
    const stage = fs.lstatSync(stagePath);
    if (publishedByThisCall && (!sameInode(final, stage) || final.nlink !== 2
      || stage.nlink !== 2)) {
      throw new Error(`${label} exclusive publication identity drift`);
    }
    if (!unlinkExactOwnedFile(stagePath, createdIdentity)) {
      throw new Error(`${label} could not clean its exact staged inode`);
    }
    createdIdentity = null;
    try {
      fsyncDirectory(directory);
    } catch (error) {
      // A one-shot lost fsync acknowledgement is recoverable only while the
      // exact final bytes remain present.  Retry the directory barrier; a
      // persistent failure still escapes and the exact final is reconciled by
      // the next caller.
      if (!exactPublishedText(filePath, text, label, [1], mode)) throw error;
      fsyncDirectory(directory);
    }
    if (!exactPublishedText(filePath, text, label, [1], mode)) {
      throw new Error(`${label} custody lacks exact durable atomic readback`);
    }
    return Object.freeze({ published: publishedByThisCall, content_digest: contentDigest });
  } finally {
    encoded.fill(0);
    if (descriptor != null) fs.closeSync(descriptor);
    if (createdIdentity != null) {
      try {
        if (unlinkExactOwnedFile(stagePath, createdIdentity)) fsyncDirectory(directory);
      } catch {}
    }
  }
}

function jsonLine(document) {
  return `${JSON.stringify(document)}\n`;
}

function sequenceFile(sequence) {
  const text = String(sequence);
  if (!/^(0|[1-9][0-9]*)$/u.test(text) || BigInt(text) < 1n
      || BigInt(text) > 18_446_744_073_709_551_615n) {
    throw new Error("gate evidence sequence must be a canonical uint64 >= 1");
  }
  return `${text.padStart(20, "0")}.json`;
}

function parseSequenceFiles(directory, label) {
  const names = atomicDirectoryNames(directory, label).sort();
  const result = [];
  for (let index = 0; index < names.length; index += 1) {
    const match = SEQUENCE_FILE_RE.exec(names[index]);
    if (!match || BigInt(match[1]) !== BigInt(index + 1)) {
      throw new Error(`${label} sequence is forked, gapped, or rolled back`);
    }
    result.push({
      sequence: String(index + 1),
      filePath: path.join(directory, names[index]),
    });
  }
  return result;
}

function runtimePaths(root) {
  return Object.freeze({
    root,
    authority: path.join(root, "authority.json"),
    storePrivateKey: path.join(root, "store-signing-key.pem"),
    documents: path.join(root, "documents"),
    scopes: path.join(root, "scopes"),
    nonces: path.join(root, "nonces"),
    time: path.join(root, "trusted-time"),
    revocations: path.join(root, "revocations"),
    issueTransactions: path.join(root, "issue-transactions"),
    releaseReceipts: path.join(root, "release-snapshot-receipts"),
    lock: path.join(root, ".gate-evidence.lock"),
  });
}

function managedTopLevelDirectories(paths) {
  return [
    paths.documents,
    paths.scopes,
    paths.nonces,
    paths.time,
    paths.revocations,
    paths.issueTransactions,
    paths.releaseReceipts,
  ];
}

function hashText(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}

function captureRuntimeCustody(state) {
  const rootIdentity = exactDirectoryIdentity(state.paths.root, "gate evidence runtime root");
  const directoryIdentities = new Map();
  for (const directory of managedTopLevelDirectories(state.paths)) {
    directoryIdentities.set(
      directory,
      exactDirectoryIdentity(directory, `gate evidence managed directory ${path.basename(directory)}`),
    );
  }
  const authorityRead = readTextFileExact(
    state.paths.authority,
    "gate evidence authority",
  );
  let authorityDocument;
  try { authorityDocument = JSON.parse(authorityRead.text); }
  catch { throw new Error("gate evidence authority is not valid JSON"); }
  const authority = validateAuthority(authorityDocument, state);
  if (authority.authority_digest !== state.authority.authority_digest
      || canonicalJson(authority) !== canonicalJson(state.authority)) {
    throw new Error("gate evidence authority changed before custody capture");
  }
  const keyRead = readTextFileExact(
    state.paths.storePrivateKey,
    "gate evidence store signing key",
    KEY_MODE,
  );
  const key = keyPairDescriptor(keyRead.text, "gate evidence live store signing key");
  if (key.publicKeyDigest !== state.storeKey.publicKeyDigest) {
    throw new Error("gate evidence store signing key changed before custody capture");
  }
  return Object.freeze({
    rootIdentity,
    directoryIdentities,
    authorityIdentity: authorityRead.identity,
    authorityFileDigest: hashText(authorityRead.text),
    authorityDigest: authority.authority_digest,
    keyIdentity: keyRead.identity,
    keyFileDigest: hashText(keyRead.text),
    keyPublicDigest: key.publicKeyDigest,
  });
}

function assertObservedScopeDirectoryCustody(state) {
  for (const entry of fs.readdirSync(state.paths.scopes, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.isSymbolicLink() || !DIGEST_RE.test(entry.name)) {
      throw new Error("gate evidence scope directory custody changed");
    }
    const directory = path.join(state.paths.scopes, entry.name);
    const current = exactDirectoryIdentity(directory, `gate evidence scope ${entry.name}`);
    const prior = state.observedDirectoryIdentities.get(directory);
    if (prior && !sameFilesystemIdentity(prior, current, false)) {
      throw new Error(`gate evidence scope directory identity changed: ${entry.name}`);
    }
    state.observedDirectoryIdentities.set(directory, current);
  }
  for (const directory of state.observedDirectoryIdentities.keys()) {
    if (!fs.existsSync(directory)) {
      throw new Error(`gate evidence observed directory was deleted: ${directory}`);
    }
  }
}

function assertLiveRuntimeCustody(state) {
  const expected = state.custody;
  if (!expected) throw new Error("gate evidence runtime custody was not captured");
  const rootIdentity = exactDirectoryIdentity(state.paths.root, "gate evidence runtime root");
  if (!sameFilesystemIdentity(expected.rootIdentity, rootIdentity, false)) {
    throw new Error("gate evidence runtime root identity changed");
  }
  for (const [directory, identity] of expected.directoryIdentities) {
    const current = exactDirectoryIdentity(
      directory,
      `gate evidence managed directory ${path.basename(directory)}`,
    );
    if (!sameFilesystemIdentity(identity, current, false)) {
      throw new Error(`gate evidence managed directory identity changed: ${path.basename(directory)}`);
    }
  }
  assertObservedScopeDirectoryCustody(state);

  const authorityRead = readTextFileExact(state.paths.authority, "gate evidence authority");
  if (!sameFilesystemIdentity(expected.authorityIdentity, authorityRead.identity)
      || hashText(authorityRead.text) !== expected.authorityFileDigest) {
    throw new Error("gate evidence authority live identity or digest changed");
  }
  let authorityDocument;
  try { authorityDocument = JSON.parse(authorityRead.text); }
  catch { throw new Error("gate evidence authority is not valid JSON"); }
  const authority = validateAuthority(authorityDocument, state);
  if (authority.authority_digest !== expected.authorityDigest
      || authority.authority_digest !== state.authority.authority_digest
      || canonicalJson(authority) !== canonicalJson(state.authority)) {
    throw new Error("gate evidence authority live binding changed");
  }

  const keyRead = readTextFileExact(
    state.paths.storePrivateKey,
    "gate evidence store signing key",
    KEY_MODE,
  );
  if (!sameFilesystemIdentity(expected.keyIdentity, keyRead.identity)
      || hashText(keyRead.text) !== expected.keyFileDigest) {
    throw new Error("gate evidence store key live identity or digest changed");
  }
  const key = keyPairDescriptor(keyRead.text, "gate evidence live store signing key");
  if (key.publicKeyDigest !== expected.keyPublicDigest
      || key.publicKeyDigest !== state.storeKey.publicKeyDigest) {
    throw new Error("gate evidence store key live public identity changed");
  }
  return true;
}

const LOCK_BODY_FIELDS = Object.freeze([
  "version",
  "domain",
  "runtime_id",
  "pid",
  "hostname",
  "process_start_token",
  "token",
  "acquired_at",
  "lock_digest",
]);

function processStartToken(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return null;
  if (process.platform === "linux") {
    try {
      const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
      const close = stat.lastIndexOf(")");
      if (close < 1) return null;
      const fields = stat.slice(close + 2).trim().split(/\s+/u);
      const startTicks = fields[19];
      return /^[0-9]+$/u.test(startTicks) ? `linux:${startTicks}` : null;
    } catch { return null; }
  }
  try {
    const output = childProcess.execFileSync("/bin/ps", [
      "-p",
      String(pid),
      "-o",
      "lstart=",
    ], {
      encoding: "utf8",
      timeout: 1_000,
      env: { LC_ALL: "C", PATH: "/usr/bin:/bin" },
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return output.length === 0 ? null : `${process.platform}:${output}`;
  } catch { return null; }
}

function currentProcessStartToken() {
  if (CURRENT_PROCESS_START_TOKEN == null) {
    CURRENT_PROCESS_START_TOKEN = processStartToken(process.pid);
  }
  return CURRENT_PROCESS_START_TOKEN;
}

function lockOwnerLiveness(owner) {
  try {
    process.kill(owner.pid, 0);
  } catch (error) {
    if (error && error.code === "ESRCH") return "dead";
    return "unknown";
  }
  const currentStart = processStartToken(owner.pid);
  if (currentStart == null) return "unknown";
  return currentStart === owner.process_start_token ? "alive" : "dead";
}

function lockCandidatePath(state, token) {
  return path.join(state.paths.root, `.gate-evidence.lock.${token}.candidate`);
}

function normalizeLockRecord(document, state, label = "gate evidence store lock") {
  const body = verifyStoreBody(state, document, LOCK_DOMAIN, LOCK_BODY_FIELDS, label);
  if (body.version !== VERSION || body.domain !== LOCK_DOMAIN
      || body.runtime_id !== state.runtimeId
      || !Number.isSafeInteger(body.pid) || body.pid < 1
      || body.hostname !== os.hostname()
      || typeof body.process_start_token !== "string"
      || body.process_start_token.length < 1 || body.process_start_token.length > 512
      || typeof body.token !== "string" || !/^[a-f0-9]{32}$/u.test(body.token)) {
    throw new Error(`${label} binding is invalid`);
  }
  canonicalTimestamp(body.acquired_at, `${label}.acquired_at`);
  const basis = Object.fromEntries(LOCK_BODY_FIELDS.slice(0, -1)
    .map((field) => [field, body[field]]));
  if (body.lock_digest !== digestJson(basis)) {
    throw new Error(`${label} canonical digest drift`);
  }
  return deepFreeze({ ...document });
}

function readLockSnapshot(state) {
  let read;
  try {
    read = readTextFileExact(
      state.paths.lock,
      "gate evidence store lock",
      FILE_MODE,
      [1, 2],
    );
  } catch (error) {
    if (!fs.existsSync(state.paths.lock)) return null;
    throw error;
  }
  let document;
  try { document = JSON.parse(read.text); } catch {
    throw new Error("gate evidence store lock is not valid JSON");
  }
  return Object.freeze({
    identity: read.identity,
    content_digest: hashText(read.text),
    owner: normalizeLockRecord(document, state),
  });
}

function sameLockSnapshot(left, right) {
  return left != null && right != null
    && sameFilesystemIdentity(left.identity, right.identity)
    && left.content_digest === right.content_digest
    && left.owner.lock_digest === right.owner.lock_digest;
}

function cleanupDeadLockCandidates(state) {
  // Candidate files themselves are published through the same staged hardlink
  // protocol as durable records.  Repair a crash after the candidate link but
  // before its stage unlink before authenticating candidate ownership below.
  // An incomplete single-link stage remains inert because it may still belong
  // to a live writer; the global stage bound prevents unbounded accumulation.
  repairPublishedAtomicStages(state.paths.root, "gate evidence store lock candidate");
  const matches = fs.readdirSync(state.paths.root).filter(
    (name) => /^\.gate-evidence\.lock\.([a-f0-9]{32})\.candidate$/u.test(name),
  );
  if (matches.length > 64) {
    throw new Error("gate evidence store has too many orphan lock candidates");
  }
  let cleaned = false;
  for (const name of matches) {
    const token = /^\.gate-evidence\.lock\.([a-f0-9]{32})\.candidate$/u.exec(name)[1];
    const candidatePath = path.join(state.paths.root, name);
    const read = readTextFileExact(
      candidatePath,
      "gate evidence orphan lock candidate",
      FILE_MODE,
      [1, 2],
    );
    let document;
    try { document = JSON.parse(read.text); } catch {
      throw new Error("gate evidence orphan lock candidate is not valid JSON");
    }
    const owner = normalizeLockRecord(
      document,
      state,
      "gate evidence orphan lock candidate",
    );
    if (owner.token !== token) {
      throw new Error("gate evidence orphan lock candidate token drift");
    }
    if (lockOwnerLiveness(owner) !== "dead") continue;
    const current = fs.lstatSync(candidatePath);
    if (!sameInode(current, read.identity)) continue;
    if (current.nlink === 2) {
      let final;
      try { final = fs.lstatSync(state.paths.lock); } catch { final = null; }
      if (!final || !sameInode(final, current)) {
        throw new Error("gate evidence orphan lock candidate has an unknown hardlink");
      }
      continue;
    }
    if (current.nlink !== 1) {
      throw new Error("gate evidence orphan lock candidate link count is invalid");
    }
    fs.unlinkSync(candidatePath);
    cleaned = true;
  }
  if (cleaned) fsyncDirectory(state.paths.root);
}

function reclaimDeadLock(state) {
  const initial = readLockSnapshot(state);
  if (!initial || initial.owner.hostname !== os.hostname()
      || lockOwnerLiveness(initial.owner) !== "dead") return false;
  const stable = readLockSnapshot(state);
  if (!sameLockSnapshot(initial, stable)
      || lockOwnerLiveness(stable.owner) !== "dead") return false;
  const atPath = fs.lstatSync(state.paths.lock);
  if (!atPath.isFile() || atPath.isSymbolicLink()
      || !sameInode(atPath, stable.identity)
      || ![1, 2].includes(atPath.nlink)) return false;
  fs.unlinkSync(state.paths.lock);
  const candidatePath = lockCandidatePath(state, stable.owner.token);
  try {
    const candidate = fs.lstatSync(candidatePath);
    if (candidate.isFile() && !candidate.isSymbolicLink()
        && sameInode(candidate, stable.identity)) fs.unlinkSync(candidatePath);
  } catch {}
  fsyncDirectory(state.paths.root);
  return true;
}

function createLockCandidate(state, record, token) {
  const candidatePath = lockCandidatePath(state, token);
  const encoded = jsonLine(record);
  publishExclusiveAtomicFile(
    candidatePath,
    encoded,
    "gate evidence store lock candidate",
  );
  const readback = readTextFileExact(
    candidatePath,
    "gate evidence store lock candidate",
  );
  if (readback.text !== encoded) {
    throw new Error("gate evidence store lock candidate readback drift");
  }
  return Object.freeze({ path: candidatePath, identity: readback.identity });
}

function acquireLock(state) {
  if (state.inFlight) throw new Error("gate evidence runtime reentrancy rejected");
  state.inFlight = true;
  try {
    cleanupDeadLockCandidates(state);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const processStart = currentProcessStartToken();
      if (processStart == null) {
        throw new Error("gate evidence process start identity is unavailable");
      }
      const token = crypto.randomBytes(16).toString("hex");
      const basis = {
        version: VERSION,
        domain: LOCK_DOMAIN,
        runtime_id: state.runtimeId,
        pid: process.pid,
        hostname: os.hostname(),
        process_start_token: processStart,
        token,
        acquired_at: new Date().toISOString(),
      };
      const record = signStoreBody(
        state,
        LOCK_DOMAIN,
        { ...basis, lock_digest: digestJson(basis) },
      );
      const candidate = createLockCandidate(state, record, token);
      let acquired = false;
      try {
        try {
          fs.linkSync(candidate.path, state.paths.lock);
          acquired = true;
        } catch (error) {
          let reconciled = false;
          try {
            const final = readLockSnapshot(state);
            const candidateStats = fs.lstatSync(candidate.path);
            reconciled = final != null
              && final.owner.lock_digest === record.lock_digest
              && sameInode(final.identity, candidateStats);
          } catch {}
          if (!reconciled) {
            if (unlinkExactOwnedFile(candidate.path, candidate.identity)) {
              fsyncDirectory(state.paths.root);
            }
            if (attempt === 0 && reclaimDeadLock(state)) continue;
            throw new Error(
              `gate evidence durable store is contended: ${error.code || "lock_failed"}`,
            );
          }
          acquired = true;
        }
        const final = fs.lstatSync(state.paths.lock);
        const staged = fs.lstatSync(candidate.path);
        if (!sameInode(final, staged) || final.nlink !== 2 || staged.nlink !== 2) {
          throw new Error("gate evidence store lock publication identity drift");
        }
        if (!unlinkExactOwnedFile(candidate.path, candidate.identity)) {
          throw new Error("gate evidence store lock candidate cleanup failed");
        }
        fsyncDirectory(state.paths.root);
        const snapshot = readLockSnapshot(state);
        if (!snapshot || snapshot.owner.token !== token
            || snapshot.owner.process_start_token !== processStart
            || snapshot.identity.nlink !== 1) {
          throw new Error("gate evidence store lock exact acquisition readback failed");
        }
        state.lockOwnership = Object.freeze({
          identity: snapshot.identity,
          token,
          processStart,
        });
        return;
      } catch (error) {
        if (acquired) {
          try {
            const current = readLockSnapshot(state);
            if (current && current.owner.token === token
                && sameInode(current.identity, candidate.identity)) {
              fs.unlinkSync(state.paths.lock);
              fsyncDirectory(state.paths.root);
            }
          } catch {}
        }
        try { unlinkExactOwnedFile(candidate.path, candidate.identity); } catch {}
        throw error;
      }
    }
  } catch (error) {
    state.lockOwnership = null;
    state.inFlight = false;
    throw error;
  }
}

function releaseLock(state) {
  const owned = state.lockOwnership;
  state.lockOwnership = null;
  try {
    if (!owned) return;
    const current = readLockSnapshot(state);
    if (!current || current.owner.token !== owned.token
        || current.owner.pid !== process.pid
        || current.owner.process_start_token !== owned.processStart
        || !sameInode(current.identity, owned.identity)) return;
    const atPath = fs.lstatSync(state.paths.lock);
    if (!atPath.isFile() || atPath.isSymbolicLink() || atPath.nlink !== 1
        || !sameInode(atPath, owned.identity)) return;
    fs.unlinkSync(state.paths.lock);
    fsyncDirectory(state.paths.root);
  } finally {
    state.inFlight = false;
  }
}

function withLock(state, operation) {
  assertLiveRuntimeCustody(state);
  acquireLock(state);
  let result;
  let operationError = null;
  try {
    assertLiveRuntimeCustody(state);
    try { result = operation(); } catch (error) { operationError = error; }
    // The after fence always runs, including when the operation failed, so a
    // concurrent custody substitution cannot be hidden behind another error.
    assertLiveRuntimeCustody(state);
    if (operationError) throw operationError;
    return result;
  } finally {
    releaseLock(state);
  }
}

function storeSignatureInput(domain, body) {
  return digestJson({ domain, version: VERSION, body });
}

function signStoreBody(state, domain, body) {
  const signatureInputDigest = storeSignatureInput(domain, body);
  return deepFreeze({
    ...body,
    store_key_digest: state.storeKey.publicKeyDigest,
    signature_input_digest: signatureInputDigest,
    signature: crypto.sign(
      null,
      Buffer.from(signatureInputDigest, "hex"),
      state.storeKey.privateKey,
    ).toString("base64url"),
  });
}

function verifyStoreBody(state, document, domain, bodyFields, label) {
  exactObject(document, label, [
    ...bodyFields,
    "store_key_digest",
    "signature_input_digest",
    "signature",
  ]);
  if (document.store_key_digest !== state.storeKey.publicKeyDigest) {
    throw new Error(`${label} store key drift`);
  }
  const body = Object.fromEntries(bodyFields.map((field) => [field, document[field]]));
  const expected = storeSignatureInput(domain, body);
  if (document.signature_input_digest !== expected) {
    throw new Error(`${label} signature input drift`);
  }
  verifySignature(state.storeKey.publicKey, expected, document.signature, label);
  return body;
}

function readOrCreateStoreKey(paths) {
  repairPublishedAtomicStages(paths.root, "gate evidence store signing key");
  if (!fs.existsSync(paths.storePrivateKey)) {
    const pair = crypto.generateKeyPairSync("ed25519");
    const pem = pair.privateKey.export({ type: "pkcs8", format: "pem" });
    publishExclusiveAtomicFile(
      paths.storePrivateKey,
      pem,
      "gate evidence store signing key",
      KEY_MODE,
    );
  }
  const { text } = readTextFileExact(
    paths.storePrivateKey,
    "gate evidence store signing key",
    KEY_MODE,
  );
  return keyPairDescriptor(text, "store signing key");
}

function normalizeSignerDefinition(input, label) {
  exactObject(input, label, [
    "evidence_class",
    "signer_principal_id",
    "signer_key_id",
    "signer_epoch",
    "private_key_pem",
    "signer_validity_ms",
    "evidence_validity_ms",
  ]);
  const evidenceClass = enumValue(input.evidence_class, EVIDENCE_CLASSES, `${label}.evidence_class`);
  const key = keyPairDescriptor(input.private_key_pem, `${label}.private_key_pem`);
  return Object.freeze({
    evidenceClass,
    principalId: opaqueRef(input.signer_principal_id, `${label}.signer_principal_id`, "principal"),
    keyId: opaqueRef(input.signer_key_id, `${label}.signer_key_id`, "signer-key"),
    epoch: boundedInteger(input.signer_epoch, `${label}.signer_epoch`, 1, 2_147_483_647),
    signerValidityMs: boundedInteger(
      input.signer_validity_ms,
      `${label}.signer_validity_ms`,
      MIN_VALIDITY_MS,
      MAX_VALIDITY_MS,
    ),
    evidenceValidityMs: boundedInteger(
      input.evidence_validity_ms,
      `${label}.evidence_validity_ms`,
      MIN_VALIDITY_MS,
      MAX_VALIDITY_MS,
    ),
    key,
  });
}

const AUTHORITY_FIELDS = Object.freeze([
  "version",
  "domain",
  "runtime_id",
  "target_domain",
  "session_nucleus_hash",
  "trust_root_id",
  "trust_root_epoch",
  "trust_valid_from",
  "trust_expires_at",
  "storage_root_identity_digest",
  "store_key_digest",
  "trusted_clock_port_id",
  "monotonic_owner_slot_digest",
  "assurance",
  "production_ready",
  "production_blockers",
  "signers",
  "authority_digest",
]);

function authorityBasis(state, createdAt, trustExpiresAt) {
  return {
    version: VERSION,
    domain: AUTHORITY_DOMAIN,
    runtime_id: state.runtimeId,
    target_domain: state.targetDomain,
    session_nucleus_hash: state.sessionNucleusHash,
    trust_root_id: state.trustRootId,
    trust_root_epoch: state.trustRootEpoch,
    trust_valid_from: createdAt,
    trust_expires_at: trustExpiresAt,
    storage_root_identity_digest: state.storageRootIdentityDigest,
    store_key_digest: state.storeKey.publicKeyDigest,
    trusted_clock_port_id: state.trustedClockPort == null
      ? null
      : state.trustedClockPort.port_id,
    monotonic_owner_slot_digest: state.monotonicOwnerPort == null
      ? null
      : state.monotonicOwnerPort.slot_digest,
    assurance: state.productionReady ? PRODUCTION_ASSURANCE : CONFORMANCE_ASSURANCE,
    production_ready: state.productionReady,
    production_blockers: state.productionReady ? [] : [...CONFORMANCE_BLOCKERS],
    signers: EVIDENCE_CLASSES.map((evidenceClass) => {
      const signer = state.signers.get(evidenceClass);
      return {
        evidence_class: evidenceClass,
        gate_kind: CLASS_GATE[evidenceClass],
        signer_principal_id: signer.principalId,
        signer_key_id: signer.keyId,
        signer_epoch: signer.epoch,
        signer_public_key_digest: signer.key.publicKeyDigest,
        signer_public_key_pem: signer.key.publicKeyPem,
        key_usage: evidenceKeyUsage(evidenceClass),
        signer_valid_from: createdAt,
        signer_expires_at: new Date(
          Date.parse(createdAt) + signer.signerValidityMs,
        ).toISOString(),
        evidence_validity_ms: signer.evidenceValidityMs,
      };
    }),
  };
}

function validateAuthority(input, state) {
  exactObject(input, "gate evidence authority", AUTHORITY_FIELDS);
  const basis = {
    version: input.version,
    domain: input.domain,
    runtime_id: input.runtime_id,
    target_domain: input.target_domain,
    session_nucleus_hash: input.session_nucleus_hash,
    trust_root_id: input.trust_root_id,
    trust_root_epoch: input.trust_root_epoch,
    trust_valid_from: input.trust_valid_from,
    trust_expires_at: input.trust_expires_at,
    storage_root_identity_digest: input.storage_root_identity_digest,
    store_key_digest: input.store_key_digest,
    trusted_clock_port_id: input.trusted_clock_port_id,
    monotonic_owner_slot_digest: input.monotonic_owner_slot_digest,
    assurance: input.assurance,
    production_ready: input.production_ready,
    production_blockers: input.production_blockers,
    signers: input.signers,
  };
  if (input.version !== VERSION || input.domain !== AUTHORITY_DOMAIN
      || input.runtime_id !== state.runtimeId || input.target_domain !== state.targetDomain
      || input.session_nucleus_hash !== state.sessionNucleusHash
      || input.trust_root_id !== state.trustRootId
      || input.trust_root_epoch !== state.trustRootEpoch
      || input.storage_root_identity_digest !== state.storageRootIdentityDigest
      || input.store_key_digest !== state.storeKey.publicKeyDigest
      || input.trusted_clock_port_id !== (state.trustedClockPort?.port_id || null)
      || input.monotonic_owner_slot_digest !== (state.monotonicOwnerPort?.slot_digest || null)
      || input.assurance !== (state.productionReady ? PRODUCTION_ASSURANCE : CONFORMANCE_ASSURANCE)
      || input.production_ready !== state.productionReady
      || canonicalJson(input.production_blockers)
        !== canonicalJson(state.productionReady ? [] : CONFORMANCE_BLOCKERS)
      || digestJson(basis) !== digest(input.authority_digest, "authority_digest")) {
    throw new Error("gate evidence authority binding drift");
  }
  canonicalTimestamp(input.trust_valid_from, "authority.trust_valid_from");
  canonicalTimestamp(input.trust_expires_at, "authority.trust_expires_at");
  const trustValidFromMs = Date.parse(input.trust_valid_from);
  if (input.trust_expires_at !== new Date(
    trustValidFromMs + state.trustValidityMs,
  ).toISOString()) {
    throw new Error("gate evidence authority trust validity window drift");
  }
  if (!Array.isArray(input.signers) || input.signers.length !== EVIDENCE_CLASSES.length) {
    throw new Error("gate evidence authority must enroll four separated evidence classes");
  }
  const actualClasses = new Set();
  const actualPrincipals = new Set();
  const actualKeys = new Set();
  const actualPublicKeys = new Set();
  for (const record of input.signers) {
    exactObject(record, "gate evidence authority signer", [
      "evidence_class",
      "gate_kind",
      "signer_principal_id",
      "signer_key_id",
      "signer_epoch",
      "signer_public_key_digest",
      "signer_public_key_pem",
      "key_usage",
      "signer_valid_from",
      "signer_expires_at",
      "evidence_validity_ms",
    ]);
    const evidenceClass = enumValue(
      record.evidence_class,
      EVIDENCE_CLASSES,
      "authority signer.evidence_class",
    );
    if (actualClasses.has(evidenceClass)) throw new Error("duplicate authority evidence class");
    actualClasses.add(evidenceClass);
    const configured = state.signers.get(evidenceClass);
    if (!configured || record.gate_kind !== CLASS_GATE[evidenceClass]
        || record.signer_principal_id !== configured.principalId
        || record.signer_key_id !== configured.keyId
        || record.signer_epoch !== configured.epoch
        || record.signer_public_key_digest !== configured.key.publicKeyDigest
        || record.signer_public_key_pem !== configured.key.publicKeyPem
        || record.key_usage !== evidenceKeyUsage(evidenceClass)
        || record.evidence_validity_ms !== configured.evidenceValidityMs) {
      throw new Error(`gate evidence ${evidenceClass} issuer enrollment drift`);
    }
    canonicalTimestamp(record.signer_valid_from, "authority signer.signer_valid_from");
    canonicalTimestamp(record.signer_expires_at, "authority signer.signer_expires_at");
    if (record.signer_valid_from !== input.trust_valid_from
        || record.signer_expires_at !== new Date(
          trustValidFromMs + configured.signerValidityMs,
        ).toISOString()) {
      throw new Error(`gate evidence ${evidenceClass} signer validity window drift`);
    }
    if (actualPrincipals.has(record.signer_principal_id)
        || actualKeys.has(record.signer_key_id)
        || actualPublicKeys.has(record.signer_public_key_digest)) {
      throw new Error("gate evidence classes must use independent principals and key material");
    }
    actualPrincipals.add(record.signer_principal_id);
    actualKeys.add(record.signer_key_id);
    actualPublicKeys.add(record.signer_public_key_digest);
  }
  return deepFreeze(structuredClone(input));
}

function readOrCreateAuthority(state, trustValidityMs) {
  repairPublishedAtomicStages(state.paths.root, "gate evidence authority");
  if (!fs.existsSync(state.paths.authority)) {
    // A production authority may never inherit process-wall-clock enrollment.
    // The current public production factory is deliberately closed until
    // independent class-signer custody ports exist, but preserve this invariant
    // here so a future factory cannot accidentally reuse the conformance path.
    const createdAt = state.productionReady
      ? assertProductionPhysicalTrustedClockSample(
        sampleRestartDurablePhysicalTrustedClock(state.trustedClockPort),
      ).trusted_utc_earliest
      : new Date(Date.now()).toISOString();
    const basis = authorityBasis(
      state,
      createdAt,
      new Date(Date.parse(createdAt) + trustValidityMs).toISOString(),
    );
    publishExclusiveAtomicFile(
      state.paths.authority,
      jsonLine({
        ...basis,
        authority_digest: digestJson(basis),
      }),
      "gate evidence authority",
    );
  }
  return validateAuthority(
    readFileExact(state.paths.authority, "gate evidence authority"),
    state,
  );
}

const TIME_BODY_FIELDS = Object.freeze([
  "version",
  "domain",
  "runtime_id",
  "sequence",
  "observed_at",
  "trusted_utc_earliest",
  "trusted_utc_latest",
  "source_assurance",
  "trusted_clock_durable_state_digest",
  "previous_time_digest",
  "time_digest",
]);

function readTimeHistory(state) {
  const files = parseSequenceFiles(state.paths.time, "gate evidence trusted-time");
  const records = [];
  let previousDigest = null;
  let previousMs = null;
  for (const file of files) {
    const document = readFileExact(file.filePath, "gate evidence trusted-time record");
    const body = verifyStoreBody(state, document, TIME_DOMAIN, TIME_BODY_FIELDS,
      "gate evidence trusted-time record");
    if (body.version !== VERSION || body.domain !== TIME_DOMAIN
        || body.runtime_id !== state.runtimeId || body.sequence !== file.sequence
        || body.previous_time_digest !== previousDigest) {
      throw new Error("gate evidence trusted-time chain fork or binding drift");
    }
    const basis = {
      version: body.version,
      domain: body.domain,
      runtime_id: body.runtime_id,
      sequence: body.sequence,
      observed_at: canonicalTimestamp(body.observed_at, "trusted_time.observed_at"),
      trusted_utc_earliest: canonicalTimestamp(
        body.trusted_utc_earliest,
        "trusted_time.trusted_utc_earliest",
      ),
      trusted_utc_latest: canonicalTimestamp(
        body.trusted_utc_latest,
        "trusted_time.trusted_utc_latest",
      ),
      source_assurance: identifier(body.source_assurance, "trusted_time.source_assurance"),
      trusted_clock_durable_state_digest: body.trusted_clock_durable_state_digest == null
        ? null
        : digest(
          body.trusted_clock_durable_state_digest,
          "trusted_time.trusted_clock_durable_state_digest",
        ),
      previous_time_digest: body.previous_time_digest,
    };
    if (Date.parse(basis.trusted_utc_earliest) > Date.parse(basis.observed_at)
        || Date.parse(basis.observed_at) > Date.parse(basis.trusted_utc_latest)) {
      throw new Error("gate evidence trusted-time uncertainty interval is invalid");
    }
    if (body.time_digest !== digestJson(basis)) {
      throw new Error("gate evidence trusted-time digest drift");
    }
    const milliseconds = Date.parse(body.observed_at);
    if (previousMs != null && milliseconds < previousMs) {
      throw new Error("gate evidence trusted-time history moved backwards");
    }
    previousMs = milliseconds;
    previousDigest = body.time_digest;
    records.push(deepFreeze({ ...document }));
  }
  const headDigest = records.at(-1)?.time_digest || null;
  if (state.observedTimeCount != null
      && (records.length < state.observedTimeCount
        || (state.observedTimeCount > 0
          && records[state.observedTimeCount - 1]?.time_digest
            !== state.observedTimeHeadDigest))) {
    throw new Error("gate evidence trusted-time history rolled back or forked");
  }
  state.observedTimeCount = records.length;
  state.observedTimeHeadDigest = headDigest;
  return records;
}

function sampleTrustedNowLocked(state) {
  const history = readTimeHistory(state);
  const previous = history.length === 0 ? null : history.at(-1);
  let observedAt;
  let earliest;
  let latest;
  let sourceAssurance;
  let trustedClockDurableStateDigest;
  if (state.productionReady) {
    const sample = assertProductionPhysicalTrustedClockSample(
      sampleRestartDurablePhysicalTrustedClock(state.trustedClockPort),
    );
    observedAt = sample.trusted_utc;
    earliest = sample.trusted_utc_earliest;
    latest = sample.trusted_utc_latest;
    sourceAssurance = "authenticated_restart_durable_trusted_clock";
    trustedClockDurableStateDigest = sample.durable_state_digest;
  } else {
    observedAt = new Date(Date.now()).toISOString();
    earliest = observedAt;
    latest = observedAt;
    sourceAssurance = "process_wall_clock_conformance_only";
    trustedClockDurableStateDigest = null;
  }
  if (previous && Date.parse(observedAt) < Date.parse(previous.observed_at)) {
    throw new Error("gate evidence server-owned trusted clock moved backwards");
  }
  const sequence = String(history.length + 1);
  const basis = {
    version: VERSION,
    domain: TIME_DOMAIN,
    runtime_id: state.runtimeId,
    sequence,
    observed_at: observedAt,
    trusted_utc_earliest: earliest,
    trusted_utc_latest: latest,
    source_assurance: sourceAssurance,
    trusted_clock_durable_state_digest: trustedClockDurableStateDigest,
    previous_time_digest: previous == null ? null : previous.time_digest,
  };
  const body = { ...basis, time_digest: digestJson(basis) };
  const document = signStoreBody(state, TIME_DOMAIN, body);
  const filePath = path.join(state.paths.time, sequenceFile(sequence));
  publishExclusiveAtomicFile(
    filePath,
    jsonLine(document),
    "gate evidence trusted-time record",
  );
  const readback = readTimeHistory(state).at(-1);
  if (!readback || readback.time_digest !== document.time_digest) {
    throw new Error("gate evidence trusted-time fsync lacks exact durable readback");
  }
  return deepFreeze({
    observed_at: observedAt,
    observed_ms: Date.parse(observedAt),
    trusted_utc_earliest: earliest,
    trusted_utc_latest: latest,
    time_sequence: sequence,
    time_digest: document.time_digest,
  });
}

const REVOCATION_BODY_FIELDS = Object.freeze([
  "version",
  "domain",
  "runtime_id",
  "sequence",
  "evidence_class",
  "signer_key_id",
  "signer_epoch",
  "reason_digest",
  "revoked_at",
  "previous_revocation_digest",
  "revocation_digest",
]);

function normalizeRevocationRecord(document, state, expectedSequence, previousDigest, classes) {
  const body = verifyStoreBody(state, document, REVOCATION_DOMAIN,
    REVOCATION_BODY_FIELDS, "gate evidence revocation record");
  const evidenceClass = enumValue(body.evidence_class, EVIDENCE_CLASSES,
    "revocation.evidence_class");
  const signer = state.signers.get(evidenceClass);
  if (body.version !== VERSION || body.domain !== REVOCATION_DOMAIN
      || body.runtime_id !== state.runtimeId || body.sequence !== expectedSequence
      || body.previous_revocation_digest !== previousDigest
      || body.signer_key_id !== signer.keyId || body.signer_epoch !== signer.epoch
      || classes.has(evidenceClass)) {
    throw new Error("gate evidence revocation chain fork or binding drift");
  }
  canonicalTimestamp(body.revoked_at, "revocation.revoked_at");
  digest(body.reason_digest, "revocation.reason_digest");
  const basis = Object.fromEntries(REVOCATION_BODY_FIELDS.slice(0, -1)
    .map((field) => [field, body[field]]));
  if (body.revocation_digest !== digestJson(basis)) {
    throw new Error("gate evidence revocation digest drift");
  }
  classes.add(evidenceClass);
  return deepFreeze({ ...document });
}

function readRevocations(state) {
  const files = parseSequenceFiles(state.paths.revocations, "gate evidence revocation");
  const result = [];
  let previousDigest = null;
  const classes = new Set();
  for (const file of files) {
    const document = readFileExact(file.filePath, "gate evidence revocation record");
    const record = normalizeRevocationRecord(
      document,
      state,
      file.sequence,
      previousDigest,
      classes,
    );
    previousDigest = record.revocation_digest;
    result.push(record);
  }
  const headDigest = result.at(-1)?.revocation_digest || null;
  if (state.observedRevocationCount != null
      && (result.length < state.observedRevocationCount
        || (state.observedRevocationCount > 0
          && result[state.observedRevocationCount - 1]?.revocation_digest
            !== state.observedRevocationHeadDigest))) {
    throw new Error("gate evidence revocation history rolled back or forked");
  }
  state.observedRevocationCount = result.length;
  state.observedRevocationHeadDigest = headDigest;
  return result;
}

function storageRootIdentity(root) {
  const stats = fs.statSync(root);
  return digestJson({
    domain: "hacker-bob/plane-physical-gate-evidence-storage-root",
    realpath: root,
    device: String(stats.dev),
    inode: String(stats.ino),
    uid: typeof stats.uid === "number" ? stats.uid : null,
    mode: stats.mode & 0o777,
  });
}

function normalizeRuntimeInput(input, production) {
  const fields = [
    "version",
    "root",
    "runtime_id",
    "target_domain",
    "session_nucleus_hash",
    "trust_root_id",
    "trust_root_epoch",
    "trust_validity_ms",
    "signers",
    ...(production ? ["trusted_clock_port", "monotonic_owner_port"] : []),
  ];
  exactObject(input, "gate evidence runtime input", fields);
  if (input.version !== VERSION) throw new Error(`gate evidence runtime version must be ${VERSION}`);
  const signerInputs = exactDenseDataArray(
    input.signers,
    "runtime.signers",
    EVIDENCE_CLASSES.length,
  );
  const signers = new Map();
  const principals = new Set();
  const keyIds = new Set();
  const publicKeyDigests = new Set();
  let maximumSignerValidityMs = 0;
  for (let index = 0; index < signerInputs.length; index += 1) {
    const signer = normalizeSignerDefinition(signerInputs[index], `runtime.signers[${index}]`);
    if (signers.has(signer.evidenceClass)) {
      throw new Error(`duplicate gate evidence class signer: ${signer.evidenceClass}`);
    }
    if (principals.has(signer.principalId) || keyIds.has(signer.keyId)
        || publicKeyDigests.has(signer.key.publicKeyDigest)) {
      throw new Error(
        "gate evidence classes require independent principals, signer keys, and key material",
      );
    }
    signers.set(signer.evidenceClass, signer);
    principals.add(signer.principalId);
    keyIds.add(signer.keyId);
    publicKeyDigests.add(signer.key.publicKeyDigest);
    maximumSignerValidityMs = Math.max(maximumSignerValidityMs, signer.signerValidityMs);
  }
  for (const evidenceClass of EVIDENCE_CLASSES) {
    if (!signers.has(evidenceClass)) throw new Error(`missing ${evidenceClass} evidence signer`);
  }
  const trustValidityMs = boundedInteger(
    input.trust_validity_ms,
    "runtime.trust_validity_ms",
    MIN_VALIDITY_MS,
    MAX_VALIDITY_MS,
  );
  if (trustValidityMs < maximumSignerValidityMs) {
    throw new Error("gate evidence trust root cannot expire before an enrolled signer");
  }
  const root = assertOwnedDirectory(input.root);
  return {
    root,
    runtimeId: identifier(input.runtime_id, "runtime.runtime_id"),
    targetDomain: assertSafeDomain(input.target_domain),
    sessionNucleusHash: digest(input.session_nucleus_hash, "runtime.session_nucleus_hash"),
    trustRootId: opaqueRef(input.trust_root_id, "runtime.trust_root_id", "trust-root"),
    trustRootEpoch: boundedInteger(
      input.trust_root_epoch,
      "runtime.trust_root_epoch",
      1,
      2_147_483_647,
    ),
    trustValidityMs,
    signers,
    trustedClockPort: production ? input.trusted_clock_port : null,
    monotonicOwnerPort: production ? input.monotonic_owner_port : null,
  };
}

function openRuntime(input, production) {
  const normalized = normalizeRuntimeInput(input, production);
  if (production) {
    assertProductionPhysicalTrustedClockPort(normalized.trustedClockPort);
    assertProductionPhysicalMonotonicOwnerPort(normalized.monotonicOwnerPort);
    const clock = describeProductionPhysicalTrustedClockPort(normalized.trustedClockPort);
    const owner = describePhysicalMonotonicOwner(normalized.monotonicOwnerPort);
    if (clock.target_domain !== normalized.targetDomain
        || clock.session_nucleus_hash !== normalized.sessionNucleusHash
        || owner.target_domain !== normalized.targetDomain
        || owner.session_nucleus_hash !== normalized.sessionNucleusHash
        || owner.production_ready !== true) {
      throw new Error("gate evidence production time/store ports bind another release session");
    }
  }
  const paths = runtimePaths(normalized.root);
  for (const directory of managedTopLevelDirectories(paths)) ensureDirectory(directory);
  const state = {
    ...normalized,
    paths,
    productionReady: production,
    storageRootIdentityDigest: storageRootIdentity(normalized.root),
    storeKey: readOrCreateStoreKey(paths),
    authority: null,
    inFlight: false,
    lockOwnership: null,
    observedTimeCount: null,
    observedTimeHeadDigest: null,
    observedRevocationCount: null,
    observedRevocationHeadDigest: null,
    observedScopeHeads: new Map(),
    observedIssueTransactionDigests: new Set(),
    observedDirectoryIdentities: new Map(),
    observedReleaseReceiptCount: null,
    observedReleaseReceiptHeadDigest: null,
    custody: null,
  };
  state.authority = readOrCreateAuthority(state, normalized.trustValidityMs);
  readTimeHistory(state);
  readRevocations(state);
  readReleaseSnapshotReceiptHistory(state);
  if (production) {
    const current = readPhysicalMonotonicOwnerState(state.monotonicOwnerPort);
    if (current != null && (current.version !== VERSION
      || current.runtime_id !== state.runtimeId
      || current.target_domain !== state.targetDomain
      || current.session_nucleus_hash !== state.sessionNucleusHash)) {
      throw new Error("gate evidence Mechanism-A monotonic owner is claimed by another runtime");
    }
  }
  state.custody = captureRuntimeCustody(state);
  assertObservedScopeDirectoryCustody(state);
  let runtime = Object.create(null);
  Object.defineProperties(runtime, {
    version: { value: VERSION, enumerable: true },
    kind: { value: RUNTIME_KIND, enumerable: true },
    runtime_id: { value: state.runtimeId, enumerable: true },
    target_domain: { value: state.targetDomain, enumerable: true },
    session_nucleus_hash: { value: state.sessionNucleusHash, enumerable: true },
    assurance: {
      value: production ? PRODUCTION_ASSURANCE : CONFORMANCE_ASSURANCE,
      enumerable: true,
    },
    production_ready: { value: production, enumerable: true },
    production_blockers: {
      value: Object.freeze(production ? [] : [...CONFORMANCE_BLOCKERS]),
      enumerable: true,
    },
    commit_release_snapshot_receipt: {
      value(batchProjection, entries) {
        return commitPlanePhysicalGateEvidenceReleaseSnapshotReceipt(
          runtime,
          batchProjection,
          entries,
        );
      },
    },
    assert_current_release_snapshot_receipt: {
      value(receiptProjection, expected) {
        return assertCurrentPlanePhysicalGateEvidenceReleaseSnapshotReceipt(
          receiptProjection,
          runtime,
          expected,
        );
      },
    },
    toJSON: {
      value() { throw new Error("gate evidence runtime is process-local and non-serializable"); },
    },
  });
  runtime = Object.freeze(runtime);
  RUNTIMES.add(runtime);
  RUNTIME_STATE.set(runtime, state);
  return runtime;
}

function createConformancePlanePhysicalGateEvidenceRuntime(input) {
  return openRuntime(input, false);
}

function createProductionPlanePhysicalGateEvidenceRuntime(input) {
  // Four distinct PEMs held by one process are four key identities, not four
  // independent issuers.  Until the engineering, review, HIL, and qualification
  // signers each arrive through a private-branded Mechanism-A/OS-principal
  // custody port, no clock/store combination may promote this runtime.
  void input;
  throw new Error(
    "gate evidence production construction is unavailable: independent_signer_custody_unavailable",
  );
}

function assertRuntime(input) {
  if (!input || !RUNTIMES.has(input) || !RUNTIME_STATE.has(input)
      || !Object.isFrozen(input)) {
    throw new Error("gate evidence requires a live privately branded runtime");
  }
  const state = RUNTIME_STATE.get(input);
  if (state.productionReady) {
    assertProductionPhysicalTrustedClockPort(state.trustedClockPort);
    assertProductionPhysicalMonotonicOwnerPort(state.monotonicOwnerPort);
  }
  return input;
}

function assertProductionRuntime(input) {
  const runtime = assertRuntime(input);
  if (runtime.production_ready !== true || !RUNTIME_STATE.get(runtime).productionReady) {
    throw new Error(
      "gate evidence runtime is conformance-only: authenticated clock, Mechanism-A store custody, and independent signer custody are required",
    );
  }
  return runtime;
}

function revokePlanePhysicalGateEvidenceSigner(runtimeInput, input) {
  const runtime = assertRuntime(runtimeInput);
  exactObject(input, "gate evidence revocation input", ["evidence_class", "reason_digest"]);
  const evidenceClass = enumValue(
    input.evidence_class,
    EVIDENCE_CLASSES,
    "revocation.evidence_class",
  );
  const reasonDigest = digest(input.reason_digest, "revocation.reason_digest");
  const state = RUNTIME_STATE.get(runtime);
  return withLock(state, () => {
    const ownerCollections = authoritativeLedgerCollections(state);
    const prior = ownerCollections == null
      ? readRevocations(state)
      : ownerCollections.revocations;
    const existing = prior.find((record) => record.evidence_class === evidenceClass);
    if (existing) {
      if (existing.reason_digest !== reasonDigest) {
        throw new Error(
          "gate evidence signer revocation already exists with a conflicting reason_digest",
        );
      }
      return existing;
    }
    const observed = sampleTrustedNowLocked(state);
    const signer = state.signers.get(evidenceClass);
    const sequence = String(prior.length + 1);
    const basis = {
      version: VERSION,
      domain: REVOCATION_DOMAIN,
      runtime_id: state.runtimeId,
      sequence,
      evidence_class: evidenceClass,
      signer_key_id: signer.keyId,
      signer_epoch: signer.epoch,
      reason_digest: reasonDigest,
      revoked_at: observed.observed_at,
      previous_revocation_digest: prior.length === 0 ? null : prior.at(-1).revocation_digest,
    };
    const body = { ...basis, revocation_digest: digestJson(basis) };
    const document = signStoreBody(state, REVOCATION_DOMAIN, body);
    if (ownerCollections != null) {
      commitOwnerLedger(
        state,
        ownerCollections.ledger,
        ownerCollections.documents,
        ownerCollections.receipts,
        [...ownerCollections.revocations, document],
      );
    }
    publishExclusiveAtomicFile(
      path.join(state.paths.revocations, sequenceFile(sequence)),
      jsonLine(document),
      "gate evidence revocation record",
    );
    const readback = ownerCollections == null
      ? readRevocations(state).at(-1)
      : authoritativeLedgerCollections(state).revocations.at(-1);
    if (!readback || readback.revocation_digest !== document.revocation_digest) {
      throw new Error("gate evidence revocation lacks exact durable readback");
    }
    return readback;
  });
}

const PAYLOAD_FIELDS = Object.freeze([
  "version",
  ...ISSUE_FIELDS,
  "nonce",
  "sequence",
  "issued_at",
  "not_before",
  "expires_at",
]);

const AUTHENTICATION_FIELDS = Object.freeze([
  "version",
  "method",
  "trust_root_id",
  "trust_root_epoch",
  "trust_registry_digest",
  "signer_principal_id",
  "signer_key_id",
  "signer_epoch",
  "signer_public_key_digest",
  "evidence_class",
  "key_usage",
  "signed_at",
  "signed_payload_digest",
  "signature",
]);

function normalizeIssueBindings(input, label = "gate evidence issue") {
  exactObject(input, label, ISSUE_FIELDS);
  const evidenceClass = enumValue(input.evidence_class, EVIDENCE_CLASSES,
    `${label}.evidence_class`);
  const gateKind = enumValue(input.gate_kind, GATE_KINDS, `${label}.gate_kind`);
  if (CLASS_GATE[evidenceClass] !== gateKind) {
    throw new Error(`${label} evidence_class is not authorized for gate_kind`);
  }
  const normalized = {
    graph_id: token(input.graph_id, `${label}.graph_id`),
    node_id: token(input.node_id, `${label}.node_id`),
    gate_kind: gateKind,
    evidence_class: evidenceClass,
    session_nucleus_hash: digest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    source_tree_digest: digest(input.source_tree_digest, `${label}.source_tree_digest`),
    release_candidate_digest: digest(
      input.release_candidate_digest,
      `${label}.release_candidate_digest`,
    ),
    package_digest: digest(input.package_digest, `${label}.package_digest`),
    task_graph_digest: digest(input.task_graph_digest, `${label}.task_graph_digest`),
    release_snapshot_digest: digest(
      input.release_snapshot_digest,
      `${label}.release_snapshot_digest`,
    ),
    node_contract_digest: digest(input.node_contract_digest, `${label}.node_contract_digest`),
    gate_contract_digest: digest(input.gate_contract_digest, `${label}.gate_contract_digest`),
    acceptance_digest: digest(input.acceptance_digest, `${label}.acceptance_digest`),
    result_digest: digest(input.result_digest, `${label}.result_digest`),
    verdict: enumValue(input.verdict, VERDICTS, `${label}.verdict`),
  };
  const candidate = releaseCandidateDigest({
    session_nucleus_hash: normalized.session_nucleus_hash,
    source_tree_digest: normalized.source_tree_digest,
    package_digest: normalized.package_digest,
    task_graph_digest: normalized.task_graph_digest,
    release_snapshot_digest: normalized.release_snapshot_digest,
  });
  if (candidate !== normalized.release_candidate_digest) {
    throw new Error(`${label}.release_candidate_digest does not bind the exact release inputs`);
  }
  return deepFreeze(normalized);
}

function normalizePayload(input, label = "gate evidence payload") {
  exactObject(input, label, PAYLOAD_FIELDS);
  if (input.version !== VERSION) throw new Error(`${label}.version must be ${VERSION}`);
  const bindings = normalizeIssueBindings(
    Object.fromEntries(ISSUE_FIELDS.map((field) => [field, input[field]])),
    label,
  );
  const issuedAt = canonicalTimestamp(input.issued_at, `${label}.issued_at`);
  const notBefore = canonicalTimestamp(input.not_before, `${label}.not_before`);
  const expiresAt = canonicalTimestamp(input.expires_at, `${label}.expires_at`);
  if (Date.parse(issuedAt) < Date.parse(notBefore)
      || Date.parse(expiresAt) <= Date.parse(issuedAt)) {
    throw new Error(`${label} validity window is invalid`);
  }
  const sequence = String(input.sequence);
  sequenceFile(sequence);
  if (typeof input.nonce !== "string" || !/^[a-f0-9]{64}$/u.test(input.nonce)) {
    throw new Error(`${label}.nonce must be a server-generated 256-bit hex nonce`);
  }
  return deepFreeze({
    version: VERSION,
    ...bindings,
    nonce: input.nonce,
    sequence,
    issued_at: issuedAt,
    not_before: notBefore,
    expires_at: expiresAt,
  });
}

const RECEIPT_BODY_FIELDS = Object.freeze([
  "version",
  "domain",
  "runtime_id",
  "scope_digest",
  "sequence",
  "previous_receipt_digest",
  "nonce_digest",
  "evidence_ref",
  "evidence_digest",
  "payload_digest",
  "committed_at",
  "trusted_time_digest",
  "receipt_digest",
]);

function scopeDigest(payload) {
  return digestJson({
    domain: "hacker-bob/plane-physical-gate-evidence-scope",
    version: VERSION,
    graph_id: payload.graph_id,
    node_id: payload.node_id,
    gate_kind: payload.gate_kind,
    evidence_class: payload.evidence_class,
    session_nucleus_hash: payload.session_nucleus_hash,
    release_candidate_digest: payload.release_candidate_digest,
  });
}

function normalizeReceipt(input, state, label = "gate evidence receipt") {
  const body = verifyStoreBody(state, input, RECEIPT_DOMAIN, RECEIPT_BODY_FIELDS, label);
  if (body.version !== VERSION || body.domain !== RECEIPT_DOMAIN
      || body.runtime_id !== state.runtimeId) {
    throw new Error(`${label} runtime binding drift`);
  }
  digest(body.scope_digest, `${label}.scope_digest`);
  sequenceFile(body.sequence);
  if (body.previous_receipt_digest != null) {
    digest(body.previous_receipt_digest, `${label}.previous_receipt_digest`);
  }
  digest(body.nonce_digest, `${label}.nonce_digest`);
  evidenceRef(body.evidence_ref, `${label}.evidence_ref`);
  const evidenceDigest = digest(body.evidence_digest, `${label}.evidence_digest`);
  if (body.evidence_ref !== `${EVIDENCE_REF_PREFIX}${evidenceDigest}`) {
    throw new Error(`${label} evidence content-address binding drift`);
  }
  digest(body.payload_digest, `${label}.payload_digest`);
  canonicalTimestamp(body.committed_at, `${label}.committed_at`);
  digest(body.trusted_time_digest, `${label}.trusted_time_digest`);
  const basis = Object.fromEntries(RECEIPT_BODY_FIELDS.slice(0, -1)
    .map((field) => [field, body[field]]));
  if (body.receipt_digest !== digestJson(basis)) {
    throw new Error(`${label} canonical digest drift`);
  }
  return deepFreeze({ ...input });
}

function readScopeHistoryFromDisk(state, scope) {
  digest(scope, "gate evidence scope digest");
  const directory = path.join(state.paths.scopes, scope);
  ensureDirectory(directory);
  const files = parseSequenceFiles(directory, `gate evidence scope ${scope}`);
  const receipts = [];
  let previousDigest = null;
  for (const file of files) {
    const receipt = normalizeReceipt(
      readFileExact(file.filePath, "gate evidence receipt"),
      state,
    );
    if (receipt.scope_digest !== scope || receipt.sequence !== file.sequence
        || receipt.previous_receipt_digest !== previousDigest) {
      throw new Error("gate evidence receipt sequence fork, gap, or rollback");
    }
    previousDigest = receipt.receipt_digest;
    receipts.push(receipt);
  }
  const observed = state.observedScopeHeads.get(scope);
  if (observed && (receipts.length < observed.count
      || (observed.count > 0
        && receipts[observed.count - 1]?.receipt_digest !== observed.digest))) {
    throw new Error("gate evidence receipt history rolled back or forked");
  }
  state.observedScopeHeads.set(scope, {
    count: receipts.length,
    digest: receipts.length === 0 ? null : receipts.at(-1).receipt_digest,
  });
  return receipts;
}

function normalizeOwnerLedger(input, state) {
  exactObject(input, "gate evidence Mechanism-A ledger", [
    "version",
    "kind",
    "runtime_id",
    "target_domain",
    "session_nucleus_hash",
    "generation",
    "previous_ledger_digest",
    "documents",
    "receipts",
    "revocations",
    "ledger_digest",
  ]);
  if (input.version !== VERSION || input.kind !== "plane_physical_gate_evidence_ledger"
      || input.runtime_id !== state.runtimeId || input.target_domain !== state.targetDomain
      || input.session_nucleus_hash !== state.sessionNucleusHash
      || !Number.isSafeInteger(input.generation) || input.generation < 1
      || !Array.isArray(input.documents) || !Array.isArray(input.receipts)
      || !Array.isArray(input.revocations)) {
    throw new Error("gate evidence Mechanism-A ledger binding is invalid");
  }
  if (input.previous_ledger_digest != null) {
    digest(input.previous_ledger_digest, "owner ledger.previous_ledger_digest");
  }
  const basis = { ...input };
  delete basis.ledger_digest;
  if (input.ledger_digest !== digestJson(basis)) {
    throw new Error("gate evidence Mechanism-A ledger digest drift");
  }
  return deepFreeze(structuredClone(input));
}

function readOwnerLedger(state) {
  if (!state.productionReady) return null;
  const raw = readPhysicalMonotonicOwnerState(state.monotonicOwnerPort);
  return raw == null ? null : normalizeOwnerLedger(raw, state);
}

function commitOwnerLedger(state, expected, documents, receipts, revocations) {
  if (!state.productionReady) return null;
  const basis = {
    version: VERSION,
    kind: "plane_physical_gate_evidence_ledger",
    runtime_id: state.runtimeId,
    target_domain: state.targetDomain,
    session_nucleus_hash: state.sessionNucleusHash,
    generation: expected == null ? 1 : expected.generation + 1,
    previous_ledger_digest: expected == null ? null : expected.ledger_digest,
    documents,
    receipts,
    revocations,
  };
  const next = deepFreeze({ ...basis, ledger_digest: digestJson(basis) });
  if (!compareAndSetPhysicalMonotonicOwnerState(state.monotonicOwnerPort, expected, next)) {
    throw new Error("gate evidence Mechanism-A monotonic claim was contended");
  }
  const readback = readOwnerLedger(state);
  if (!readback || readback.ledger_digest !== next.ledger_digest) {
    throw new Error("gate evidence Mechanism-A monotonic claim lacks exact durable readback");
  }
  return readback;
}

function authoritativeLedgerCollections(state) {
  if (!state.productionReady) return null;
  const ledger = readOwnerLedger(state);
  if (ledger == null) {
    return { ledger: null, documents: [], receipts: [], revocations: [] };
  }
  const revocationClasses = new Set();
  let previousRevocationDigest = null;
  const revocations = ledger.revocations.map((record, index) => {
    const normalized = normalizeRevocationRecord(
      record,
      state,
      String(index + 1),
      previousRevocationDigest,
      revocationClasses,
    );
    previousRevocationDigest = normalized.revocation_digest;
    return normalized;
  });
  return {
    ledger,
    documents: ledger.documents.map((document) => (
      normalizeSignedPlanePhysicalGateEvidence(document, "owner gate evidence document")
    )),
    receipts: ledger.receipts.map((receipt) => normalizeReceipt(receipt, state)),
    revocations,
  };
}

function authoritySigner(state, evidenceClass) {
  const signer = state.authority.signers.find(
    (candidate) => candidate.evidence_class === evidenceClass,
  );
  if (!signer) throw new Error(`gate evidence authority has no ${evidenceClass} signer`);
  return signer;
}

function normalizeAuthentication(input, payload, label = "gate evidence authentication") {
  exactObject(input, label, AUTHENTICATION_FIELDS);
  if (input.version !== VERSION || input.method !== "ed25519"
      || input.evidence_class !== payload.evidence_class
      || input.key_usage !== evidenceKeyUsage(payload.evidence_class)
      || input.signed_at !== payload.issued_at
      || input.signed_payload_digest !== digestJson(payload)) {
    throw new Error(`${label} does not bind the exact signed payload and evidence class`);
  }
  return deepFreeze({
    version: VERSION,
    method: "ed25519",
    trust_root_id: opaqueRef(input.trust_root_id, `${label}.trust_root_id`, "trust-root"),
    trust_root_epoch: boundedInteger(input.trust_root_epoch,
      `${label}.trust_root_epoch`, 1, 2_147_483_647),
    trust_registry_digest: digest(input.trust_registry_digest, `${label}.trust_registry_digest`),
    signer_principal_id: opaqueRef(
      input.signer_principal_id,
      `${label}.signer_principal_id`,
      "principal",
    ),
    signer_key_id: opaqueRef(input.signer_key_id, `${label}.signer_key_id`, "signer-key"),
    signer_epoch: boundedInteger(input.signer_epoch,
      `${label}.signer_epoch`, 1, 2_147_483_647),
    signer_public_key_digest: digest(
      input.signer_public_key_digest,
      `${label}.signer_public_key_digest`,
    ),
    evidence_class: payload.evidence_class,
    key_usage: evidenceKeyUsage(payload.evidence_class),
    signed_at: payload.issued_at,
    signed_payload_digest: digestJson(payload),
    signature: canonicalSignature(input.signature, `${label}.signature`),
  });
}

function authenticationBasis(authentication) {
  const basis = { ...authentication };
  delete basis.signature;
  return basis;
}

function signatureInputDigest(payload, authentication, productionReady) {
  return digestJson({
    domain: DOMAIN,
    version: VERSION,
    kind: KIND,
    assurance: productionReady ? PRODUCTION_ASSURANCE : CONFORMANCE_ASSURANCE,
    production_ready: productionReady,
    payload,
    authentication: authenticationBasis(authentication),
  });
}

function normalizeSignedPlanePhysicalGateEvidence(
  input,
  label = "plane physical gate evidence",
) {
  exactObject(input, label, [
    "version",
    "domain",
    "kind",
    "assurance",
    "production_ready",
    "payload",
    "authentication",
    "evidence_digest",
    "evidence_ref",
  ]);
  if (input.version !== VERSION || input.domain !== DOMAIN || input.kind !== KIND
      || (input.production_ready !== true && input.production_ready !== false)
      || input.assurance !== (input.production_ready
        ? PRODUCTION_ASSURANCE : CONFORMANCE_ASSURANCE)) {
    throw new Error(`${label} version, domain, assurance, or readiness is invalid`);
  }
  const payload = normalizePayload(input.payload, `${label}.payload`);
  const authentication = normalizeAuthentication(
    input.authentication,
    payload,
    `${label}.authentication`,
  );
  const signedBody = {
    version: VERSION,
    domain: DOMAIN,
    kind: KIND,
    assurance: input.assurance,
    production_ready: input.production_ready,
    payload,
    authentication,
  };
  const evidenceDigest = digestJson(signedBody);
  if (input.evidence_digest !== evidenceDigest
      || input.evidence_ref !== `${EVIDENCE_REF_PREFIX}${evidenceDigest}`) {
    throw new Error(`${label} content address or canonical digest drift`);
  }
  evidenceRef(input.evidence_ref, `${label}.evidence_ref`);
  return deepFreeze({
    ...signedBody,
    evidence_digest: evidenceDigest,
    evidence_ref: input.evidence_ref,
  });
}

const NONCE_BODY_FIELDS = Object.freeze([
  "version",
  "domain",
  "runtime_id",
  "nonce_digest",
  "scope_digest",
  "sequence",
  "evidence_ref",
  "receipt_digest",
]);

function normalizeNonceClaim(input, state, label = "gate evidence nonce claim") {
  const body = verifyStoreBody(state, input, NONCE_DOMAIN, NONCE_BODY_FIELDS, label);
  if (body.version !== VERSION || body.domain !== NONCE_DOMAIN
      || body.runtime_id !== state.runtimeId) {
    throw new Error(`${label} runtime binding drift`);
  }
  digest(body.nonce_digest, `${label}.nonce_digest`);
  digest(body.scope_digest, `${label}.scope_digest`);
  sequenceFile(body.sequence);
  evidenceRef(body.evidence_ref, `${label}.evidence_ref`);
  digest(body.receipt_digest, `${label}.receipt_digest`);
  return deepFreeze({ ...input });
}

function readDocumentFromDisk(state, ref) {
  const match = EVIDENCE_REF_RE.exec(evidenceRef(ref));
  const filePath = path.join(state.paths.documents, `${match[1]}.json`);
  if (!fs.existsSync(filePath)) return null;
  const document = normalizeSignedPlanePhysicalGateEvidence(
    readFileExact(filePath, "gate evidence document"),
    "stored gate evidence document",
  );
  if (document.evidence_ref !== ref) throw new Error("stored gate evidence reference drift");
  return document;
}

function writeImmutableMirror(filePath, document, label) {
  const encoded = jsonLine(document);
  repairPublishedAtomicStages(path.dirname(filePath), label);
  if (exactPublishedText(filePath, encoded, label)) return;
  publishExclusiveAtomicFile(filePath, encoded, label);
}

function receiptRefFor(receipt) {
  return `${RECEIPT_REF_PREFIX}${receipt.receipt_digest}`;
}

const ISSUE_TRANSACTION_BODY_FIELDS = Object.freeze([
  "version",
  "domain",
  "runtime_id",
  "scope_digest",
  "sequence",
  "evidence_ref",
  "evidence_digest",
  "nonce_digest",
  "receipt_digest",
  "document",
  "nonce_claim",
  "receipt",
  "transaction_digest",
]);

function issueTransactionRecord(state, document, nonceClaim, receipt) {
  const basis = {
    version: VERSION,
    domain: ISSUE_TRANSACTION_DOMAIN,
    runtime_id: state.runtimeId,
    scope_digest: receipt.scope_digest,
    sequence: receipt.sequence,
    evidence_ref: document.evidence_ref,
    evidence_digest: document.evidence_digest,
    nonce_digest: receipt.nonce_digest,
    receipt_digest: receipt.receipt_digest,
    document,
    nonce_claim: nonceClaim,
    receipt,
  };
  return signStoreBody(
    state,
    ISSUE_TRANSACTION_DOMAIN,
    { ...basis, transaction_digest: digestJson(basis) },
  );
}

function normalizeIssueTransaction(input, state, label = "gate evidence issue transaction") {
  const body = verifyStoreBody(
    state,
    input,
    ISSUE_TRANSACTION_DOMAIN,
    ISSUE_TRANSACTION_BODY_FIELDS,
    label,
  );
  if (body.version !== VERSION || body.domain !== ISSUE_TRANSACTION_DOMAIN
      || body.runtime_id !== state.runtimeId) {
    throw new Error(`${label} runtime binding drift`);
  }
  const document = normalizeSignedPlanePhysicalGateEvidence(
    body.document,
    `${label}.document`,
  );
  const nonceClaim = normalizeNonceClaim(body.nonce_claim, state, `${label}.nonce_claim`);
  const receipt = normalizeReceipt(body.receipt, state, `${label}.receipt`);
  const basis = Object.fromEntries(ISSUE_TRANSACTION_BODY_FIELDS.slice(0, -1)
    .map((field) => [field, body[field]]));
  if (body.transaction_digest !== digestJson(basis)
      || body.scope_digest !== receipt.scope_digest
      || body.scope_digest !== scopeDigest(document.payload)
      || body.sequence !== receipt.sequence
      || body.sequence !== document.payload.sequence
      || body.evidence_ref !== document.evidence_ref
      || body.evidence_ref !== receipt.evidence_ref
      || body.evidence_ref !== nonceClaim.evidence_ref
      || body.evidence_digest !== document.evidence_digest
      || body.evidence_digest !== receipt.evidence_digest
      || body.nonce_digest !== receipt.nonce_digest
      || body.nonce_digest !== nonceClaim.nonce_digest
      || body.nonce_digest !== digestJson({ nonce: document.payload.nonce })
      || body.receipt_digest !== receipt.receipt_digest
      || body.receipt_digest !== nonceClaim.receipt_digest
      || nonceClaim.scope_digest !== body.scope_digest
      || nonceClaim.sequence !== body.sequence) {
    throw new Error(`${label} exact document/nonce/receipt binding drift`);
  }
  return deepFreeze({ ...input });
}

function readIssueTransactions(state) {
  const records = exactJsonFiles(
    state.paths.issueTransactions,
    /^([a-f0-9]{64})\.json$/u,
    "gate evidence issue transaction store",
  ).map((entry) => {
    const record = normalizeIssueTransaction(
      readFileExact(entry.filePath, "gate evidence issue transaction"),
      state,
    );
    if (record.transaction_digest !== entry.match[1]) {
      throw new Error("gate evidence issue transaction filename/content drift");
    }
    return record;
  });
  const current = new Set(records.map((record) => record.transaction_digest));
  for (const observed of state.observedIssueTransactionDigests) {
    if (!current.has(observed)) {
      throw new Error("gate evidence issue transaction set rolled back or forked");
    }
  }
  for (const transactionDigest of current) {
    state.observedIssueTransactionDigests.add(transactionDigest);
  }
  return records;
}

function reconcileIssueTransactionMirrors(state, transactions) {
  for (const transaction of transactions) {
    const scopeDirectory = path.join(state.paths.scopes, transaction.scope_digest);
    ensureDirectory(scopeDirectory);
    writeImmutableMirror(
      path.join(state.paths.documents, `${transaction.evidence_digest}.json`),
      transaction.document,
      "gate evidence document mirror",
    );
    writeImmutableMirror(
      path.join(state.paths.nonces, `${transaction.nonce_digest}.json`),
      transaction.nonce_claim,
      "gate evidence nonce mirror",
    );
    writeImmutableMirror(
      path.join(scopeDirectory, sequenceFile(transaction.sequence)),
      transaction.receipt,
      "gate evidence receipt mirror",
    );
  }
}

function validateLedgerCollections(state, documents, receipts) {
  const documentsByRef = new Map();
  for (const document of documents) {
    if (documentsByRef.has(document.evidence_ref)) {
      throw new Error("gate evidence ledger contains duplicate document references");
    }
    documentsByRef.set(document.evidence_ref, document);
  }
  const receiptsByScope = new Map();
  const nonces = new Set();
  const evidenceRefs = new Set();
  for (const receipt of receipts) {
    if (!receiptsByScope.has(receipt.scope_digest)) receiptsByScope.set(receipt.scope_digest, []);
    receiptsByScope.get(receipt.scope_digest).push(receipt);
    if (nonces.has(receipt.nonce_digest) || evidenceRefs.has(receipt.evidence_ref)) {
      throw new Error("gate evidence ledger replayed a nonce or evidence document");
    }
    nonces.add(receipt.nonce_digest);
    evidenceRefs.add(receipt.evidence_ref);
    const document = documentsByRef.get(receipt.evidence_ref);
    if (!document || document.evidence_digest !== receipt.evidence_digest
        || digestJson(document.payload) !== receipt.payload_digest
        || digestJson({ nonce: document.payload.nonce }) !== receipt.nonce_digest
        || scopeDigest(document.payload) !== receipt.scope_digest
        || document.payload.sequence !== receipt.sequence) {
      throw new Error("gate evidence receipt does not bind its exact signed document");
    }
  }
  for (const [scope, scoped] of receiptsByScope) {
    scoped.sort((left, right) => (
      BigInt(left.sequence) < BigInt(right.sequence)
        ? -1
        : BigInt(left.sequence) > BigInt(right.sequence) ? 1 : 0
    ));
    let previous = null;
    for (let index = 0; index < scoped.length; index += 1) {
      if (scoped[index].sequence !== String(index + 1)
          || scoped[index].previous_receipt_digest !== previous) {
        throw new Error(`gate evidence scope ${scope} forked, gapped, or rolled back`);
      }
      previous = scoped[index].receipt_digest;
    }
  }
  if (documentsByRef.size !== receipts.length) {
    throw new Error("gate evidence ledger contains an orphan document or receipt");
  }
  return { documentsByRef, receiptsByScope };
}

function exactJsonFiles(directory, pattern, label) {
  const result = [];
  for (const name of atomicDirectoryNames(directory, label)) {
    const filePath = path.join(directory, name);
    const entry = fs.lstatSync(filePath);
    const match = pattern.exec(name);
    if (!entry.isFile() || entry.isSymbolicLink() || !match) {
      throw new Error(`${label} contains an unexpected or unsafe entry`);
    }
    result.push({ name, match, filePath });
  }
  result.sort((left, right) => left.name.localeCompare(right.name));
  return result;
}

function readConformanceCollections(state) {
  const transactions = readIssueTransactions(state);
  reconcileIssueTransactionMirrors(state, transactions);
  const documents = exactJsonFiles(
    state.paths.documents,
    /^([a-f0-9]{64})\.json$/u,
    "gate evidence document store",
  ).map((entry) => {
    const document = normalizeSignedPlanePhysicalGateEvidence(
      readFileExact(entry.filePath, "gate evidence document"),
      "stored gate evidence document",
    );
    if (document.evidence_digest !== entry.match[1]) {
      throw new Error("gate evidence document filename/content address drift");
    }
    return document;
  });

  const receipts = [];
  for (const entry of fs.readdirSync(state.paths.scopes, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.isSymbolicLink() || !DIGEST_RE.test(entry.name)) {
      throw new Error("gate evidence scope store contains an unexpected or unsafe entry");
    }
    receipts.push(...readScopeHistoryFromDisk(state, entry.name));
  }
  const validated = validateLedgerCollections(state, documents, receipts);

  const nonceClaims = exactJsonFiles(
    state.paths.nonces,
    /^([a-f0-9]{64})\.json$/u,
    "gate evidence nonce store",
  ).map((entry) => {
    const claim = normalizeNonceClaim(
      readFileExact(entry.filePath, "gate evidence nonce claim"),
      state,
    );
    if (claim.nonce_digest !== entry.match[1]) {
      throw new Error("gate evidence nonce filename/content address drift");
    }
    return claim;
  });
  if (nonceClaims.length !== receipts.length) {
    throw new Error("gate evidence nonce store contains an orphan or missing claim");
  }
  const nonceByDigest = new Map();
  for (const claim of nonceClaims) {
    if (nonceByDigest.has(claim.nonce_digest)) {
      throw new Error("gate evidence nonce store contains a duplicate claim");
    }
    nonceByDigest.set(claim.nonce_digest, claim);
  }
  for (const receipt of receipts) {
    const claim = nonceByDigest.get(receipt.nonce_digest);
    if (!claim || claim.scope_digest !== receipt.scope_digest
        || claim.sequence !== receipt.sequence
        || claim.evidence_ref !== receipt.evidence_ref
        || claim.receipt_digest !== receipt.receipt_digest) {
      throw new Error("gate evidence nonce claim does not bind its exact receipt");
    }
  }
  if (transactions.length !== documents.length || transactions.length !== receipts.length
      || transactions.length !== nonceClaims.length) {
    throw new Error("gate evidence derived mirrors do not match committed issue transactions");
  }
  const transactionsByReceipt = new Map();
  for (const transaction of transactions) {
    if (transactionsByReceipt.has(transaction.receipt_digest)) {
      throw new Error("gate evidence issue transaction store contains a duplicate receipt");
    }
    transactionsByReceipt.set(transaction.receipt_digest, transaction);
  }
  for (const receipt of receipts) {
    const transaction = transactionsByReceipt.get(receipt.receipt_digest);
    const document = validated.documentsByRef.get(receipt.evidence_ref);
    const nonceClaim = nonceByDigest.get(receipt.nonce_digest);
    if (!transaction || !document || !nonceClaim
        || canonicalJson(transaction.document) !== canonicalJson(document)
        || canonicalJson(transaction.receipt) !== canonicalJson(receipt)
        || canonicalJson(transaction.nonce_claim) !== canonicalJson(nonceClaim)) {
      throw new Error("gate evidence derived mirror drifted from its issue transaction");
    }
  }
  return {
    ledger: null,
    documents,
    receipts,
    nonceClaimsByDigest: nonceByDigest,
    revocations: readRevocations(state),
    ...validated,
  };
}

function verifyDocumentSignatureAndTrust(state, document, observed, revocations) {
  if (document.production_ready !== state.productionReady
      || document.payload.session_nucleus_hash !== state.sessionNucleusHash) {
    throw new Error("gate evidence document readiness or release-session binding drift");
  }
  const enrolled = authoritySigner(state, document.payload.evidence_class);
  const authentication = document.authentication;
  if (authentication.trust_root_id !== state.authority.trust_root_id
      || authentication.trust_root_epoch !== state.authority.trust_root_epoch
      || authentication.trust_registry_digest !== state.authority.authority_digest
      || authentication.signer_principal_id !== enrolled.signer_principal_id
      || authentication.signer_key_id !== enrolled.signer_key_id
      || authentication.signer_epoch !== enrolled.signer_epoch
      || authentication.signer_public_key_digest !== enrolled.signer_public_key_digest
      || authentication.key_usage !== enrolled.key_usage) {
    throw new Error("gate evidence document signer or trust-root binding drift");
  }
  if (revocations.some((record) => (
    record.evidence_class === document.payload.evidence_class
      && record.signer_key_id === authentication.signer_key_id
      && record.signer_epoch === authentication.signer_epoch
  ))) throw new Error("gate evidence signer is revoked");
  const issuedMs = Date.parse(document.payload.issued_at);
  const notBeforeMs = Date.parse(document.payload.not_before);
  const expiresMs = Date.parse(document.payload.expires_at);
  const earliestMs = Date.parse(observed.trusted_utc_earliest);
  const latestMs = Date.parse(observed.trusted_utc_latest);
  if (earliestMs < notBeforeMs || latestMs >= expiresMs) {
    throw new Error(latestMs >= expiresMs
      ? "gate evidence has expired under trusted-clock uncertainty"
      : "gate evidence is not yet valid under trusted-clock uncertainty");
  }
  if (issuedMs < Date.parse(state.authority.trust_valid_from)
      || issuedMs >= Date.parse(state.authority.trust_expires_at)
      || earliestMs < Date.parse(state.authority.trust_valid_from)
      || latestMs >= Date.parse(state.authority.trust_expires_at)
      || issuedMs < Date.parse(enrolled.signer_valid_from)
      || issuedMs >= Date.parse(enrolled.signer_expires_at)
      || earliestMs < Date.parse(enrolled.signer_valid_from)
      || latestMs >= Date.parse(enrolled.signer_expires_at)) {
    throw new Error("gate evidence root or class issuer is outside its current validity window");
  }
  const publicKey = crypto.createPublicKey(enrolled.signer_public_key_pem);
  verifySignature(
    publicKey,
    signatureInputDigest(document.payload, authentication, state.productionReady),
    authentication.signature,
    "gate evidence document",
  );
  return document;
}

function issuePlanePhysicalGateEvidence(runtimeInput, issueInput) {
  const runtime = assertRuntime(runtimeInput);
  const bindings = normalizeIssueBindings(issueInput);
  const state = RUNTIME_STATE.get(runtime);
  if (bindings.session_nucleus_hash !== state.sessionNucleusHash) {
    throw new Error("gate evidence issue belongs to another release session");
  }
  return withLock(state, () => {
    const ownerCollections = authoritativeLedgerCollections(state);
    const collections = ownerCollections == null
      ? readConformanceCollections(state)
      : ownerCollections;
    const revocations = collections.revocations;
    if (revocations.some((record) => record.evidence_class === bindings.evidence_class)) {
      throw new Error(`gate evidence ${bindings.evidence_class} signer is revoked`);
    }
    const observed = sampleTrustedNowLocked(state);
    const signer = state.signers.get(bindings.evidence_class);
    const enrolled = authoritySigner(state, bindings.evidence_class);
    const scope = digestJson({
      domain: "hacker-bob/plane-physical-gate-evidence-scope",
      version: VERSION,
      graph_id: bindings.graph_id,
      node_id: bindings.node_id,
      gate_kind: bindings.gate_kind,
      evidence_class: bindings.evidence_class,
      session_nucleus_hash: bindings.session_nucleus_hash,
      release_candidate_digest: bindings.release_candidate_digest,
    });
    let history;
    if (ownerCollections != null) {
      validateLedgerCollections(state, collections.documents, collections.receipts);
    }
    history = collections.receipts
      .filter((receipt) => receipt.scope_digest === scope)
      .sort((left, right) => (
        BigInt(left.sequence) < BigInt(right.sequence)
          ? -1
          : BigInt(left.sequence) > BigInt(right.sequence) ? 1 : 0
      ));
    const sequence = String(history.length + 1);
    const nonce = crypto.randomBytes(32).toString("hex");
    const payload = normalizePayload({
      version: VERSION,
      ...bindings,
      nonce,
      sequence,
      // issued_at is the authenticated clock's observation and therefore also
      // equals the durable receipt commit time.  not_before uses the lower
      // uncertainty bound so non-zero production uncertainty stays resolvable.
      issued_at: observed.observed_at,
      not_before: observed.trusted_utc_earliest,
      expires_at: new Date(
        Date.parse(observed.trusted_utc_latest) + signer.evidenceValidityMs,
      ).toISOString(),
    });
    const authenticationBasis = {
      version: VERSION,
      method: "ed25519",
      trust_root_id: state.authority.trust_root_id,
      trust_root_epoch: state.authority.trust_root_epoch,
      trust_registry_digest: state.authority.authority_digest,
      signer_principal_id: enrolled.signer_principal_id,
      signer_key_id: enrolled.signer_key_id,
      signer_epoch: enrolled.signer_epoch,
      signer_public_key_digest: enrolled.signer_public_key_digest,
      evidence_class: bindings.evidence_class,
      key_usage: enrolled.key_usage,
      signed_at: payload.issued_at,
      signed_payload_digest: digestJson(payload),
    };
    const signature = crypto.sign(
      null,
      Buffer.from(signatureInputDigest(payload, authenticationBasis, state.productionReady), "hex"),
      signer.key.privateKey,
    ).toString("base64url");
    const signedBody = {
      version: VERSION,
      domain: DOMAIN,
      kind: KIND,
      assurance: state.productionReady ? PRODUCTION_ASSURANCE : CONFORMANCE_ASSURANCE,
      production_ready: state.productionReady,
      payload,
      authentication: { ...authenticationBasis, signature },
    };
    const evidenceDigest = digestJson(signedBody);
    const document = normalizeSignedPlanePhysicalGateEvidence({
      ...signedBody,
      evidence_digest: evidenceDigest,
      evidence_ref: `${EVIDENCE_REF_PREFIX}${evidenceDigest}`,
    });
    verifyDocumentSignatureAndTrust(state, document, observed, revocations);
    const receiptBasis = {
      version: VERSION,
      domain: RECEIPT_DOMAIN,
      runtime_id: state.runtimeId,
      scope_digest: scope,
      sequence,
      previous_receipt_digest: history.length === 0 ? null : history.at(-1).receipt_digest,
      nonce_digest: digestJson({ nonce }),
      evidence_ref: document.evidence_ref,
      evidence_digest: document.evidence_digest,
      payload_digest: digestJson(document.payload),
      committed_at: observed.observed_at,
      trusted_time_digest: observed.time_digest,
    };
    const receiptBody = { ...receiptBasis, receipt_digest: digestJson(receiptBasis) };
    const receipt = normalizeReceipt(
      signStoreBody(state, RECEIPT_DOMAIN, receiptBody),
      state,
    );
    const nonceBody = {
      version: VERSION,
      domain: NONCE_DOMAIN,
      runtime_id: state.runtimeId,
      nonce_digest: receipt.nonce_digest,
      scope_digest: scope,
      sequence,
      evidence_ref: document.evidence_ref,
      receipt_digest: receipt.receipt_digest,
    };
    const nonceClaim = normalizeNonceClaim(
      signStoreBody(state, NONCE_DOMAIN, nonceBody),
      state,
    );
    const transaction = normalizeIssueTransaction(
      issueTransactionRecord(state, document, nonceClaim, receipt),
      state,
    );

    if (ownerCollections != null) {
      commitOwnerLedger(
        state,
        ownerCollections.ledger,
        [...ownerCollections.documents, document],
        [...ownerCollections.receipts, receipt],
        ownerCollections.revocations,
      );
    }
    writeImmutableMirror(
      path.join(
        state.paths.issueTransactions,
        `${transaction.transaction_digest}.json`,
      ),
      transaction,
      "gate evidence issue transaction commit",
    );
    reconcileIssueTransactionMirrors(state, [transaction]);

    if (ownerCollections == null) {
      const durable = readConformanceCollections(state);
      const durableDocument = durable.documentsByRef.get(document.evidence_ref);
      const durableHistory = durable.receiptsByScope.get(scope) || [];
      const durableNonce = normalizeNonceClaim(durable.nonceClaimsByDigest.get(
        receipt.nonce_digest,
      ), state);
      if (!durableDocument || durableDocument.evidence_digest !== document.evidence_digest
          || durableHistory.at(-1)?.receipt_digest !== receipt.receipt_digest
          || durableNonce.receipt_digest !== receipt.receipt_digest) {
        throw new Error("gate evidence commit lacks exact durable atomic readback");
      }
    } else {
      const durable = authoritativeLedgerCollections(state);
      validateLedgerCollections(state, durable.documents, durable.receipts);
      if (!durable.documents.some((item) => item.evidence_ref === document.evidence_ref)
          || !durable.receipts.some((item) => item.receipt_digest === receipt.receipt_digest)) {
        throw new Error("gate evidence Mechanism-A commit lacks exact durable readback");
      }
    }
    return document;
  });
}

function assertPayloadBindings(payload, expected, label) {
  for (const field of ISSUE_FIELDS) {
    if (payload[field] !== expected[field]) {
      throw new Error(`${label}.${field} does not match the exact expected release binding`);
    }
  }
}

function collectionSnapshotDigest(collections) {
  return digestJson({
    documents: collections.documents.map((item) => item.evidence_digest).sort(),
    receipts: collections.receipts.map((item) => item.receipt_digest).sort(),
    revocations: collections.revocations.map((item) => item.revocation_digest),
    owner_ledger_digest: collections.ledger?.ledger_digest || null,
  });
}

function resolveCollections(state) {
  const collections = authoritativeLedgerCollections(state) || readConformanceCollections(state);
  const validated = validateLedgerCollections(
    state,
    collections.documents,
    collections.receipts,
  );
  return { ...collections, ...validated };
}

function exactReceiptFor(collections, document) {
  const scope = scopeDigest(document.payload);
  const matches = (collections.receiptsByScope.get(scope) || []).filter(
    (receipt) => receipt.evidence_ref === document.evidence_ref,
  );
  if (matches.length !== 1) {
    throw new Error("gate evidence document lacks exactly one monotonic receipt");
  }
  const receipt = matches[0];
  if (receipt.sequence !== document.payload.sequence
      || receipt.evidence_digest !== document.evidence_digest
      || receipt.payload_digest !== digestJson(document.payload)
      || receipt.nonce_digest !== digestJson({ nonce: document.payload.nonce })) {
    throw new Error("gate evidence monotonic receipt exact binding drift");
  }
  return receipt;
}

function assertReceiptTrustedTimeFromHistory(history, receipt, document) {
  const matches = history.filter(
    (record) => record.time_digest === receipt.trusted_time_digest,
  );
  if (matches.length !== 1 || matches[0].observed_at !== receipt.committed_at
      || receipt.committed_at !== document.payload.issued_at) {
    throw new Error("gate evidence receipt lacks its exact server-owned trusted-time observation");
  }
  return matches[0];
}

function assertReceiptTrustedTime(state, receipt, document) {
  return assertReceiptTrustedTimeFromHistory(readTimeHistory(state), receipt, document);
}

function resolveMaterialLocked(state, refInput, expectedInput) {
  const ref = evidenceRef(refInput);
  const expected = normalizeIssueBindings(expectedInput, "gate evidence expected bindings");
  if (expected.session_nucleus_hash !== state.sessionNucleusHash) {
    throw new Error("gate evidence expected bindings belong to another release session");
  }
  const initial = resolveCollections(state);
  const document = initial.documentsByRef.get(ref);
  if (!document) throw new Error("gate evidence reference is absent from durable state");
  assertPayloadBindings(document.payload, expected, "gate evidence payload");
  const receipt = exactReceiptFor(initial, document);
  assertReceiptTrustedTime(state, receipt, document);

  const firstObserved = sampleTrustedNowLocked(state);
  verifyDocumentSignatureAndTrust(state, document, firstObserved, initial.revocations);

  // Re-read every authoritative collection after verification.  This rejects
  // equivocation, fork, deletion, and in-process rollback between lookup and
  // projection.  Production uses the independently custodied owner ledger;
  // conformance uses the complete signed filesystem mirror and remains blocked.
  const stable = resolveCollections(state);
  const stableDocument = stable.documentsByRef.get(ref);
  const stableReceipt = stableDocument == null ? null : exactReceiptFor(stable, stableDocument);
  if (!stableDocument || !stableReceipt
      || stableDocument.evidence_digest !== document.evidence_digest
      || stableReceipt.receipt_digest !== receipt.receipt_digest
      || collectionSnapshotDigest(stable) !== collectionSnapshotDigest(initial)) {
    throw new Error("gate evidence durable state forked or changed during exact readback");
  }
  const finalObserved = sampleTrustedNowLocked(state);
  verifyDocumentSignatureAndTrust(state, stableDocument, finalObserved, stable.revocations);
  return {
    document: stableDocument,
    receipt: stableReceipt,
    expected,
    observed: finalObserved,
    collections: stable,
  };
}

function projectionFromMaterial(runtime, material) {
  const state = RUNTIME_STATE.get(runtime);
  const { document, receipt, observed, collections } = material;
  const body = {
    version: VERSION,
    domain: "hacker-bob/plane-physical-gate-evidence-verification",
    evidence_ref: document.evidence_ref,
    evidence_digest: document.evidence_digest,
    payload_digest: digestJson(document.payload),
    ...document.payload,
    signer_principal_id: document.authentication.signer_principal_id,
    signer_key_id: document.authentication.signer_key_id,
    signer_epoch: document.authentication.signer_epoch,
    signer_public_key_digest: document.authentication.signer_public_key_digest,
    key_usage: document.authentication.key_usage,
    trust_root_id: document.authentication.trust_root_id,
    trust_root_epoch: document.authentication.trust_root_epoch,
    trust_registry_digest: document.authentication.trust_registry_digest,
    receipt_ref: receiptRefFor(receipt),
    receipt_digest: receipt.receipt_digest,
    receipt_scope_digest: receipt.scope_digest,
    receipt_sequence: receipt.sequence,
    verified_at: observed.observed_at,
    verified_trusted_utc_earliest: observed.trusted_utc_earliest,
    verified_trusted_utc_latest: observed.trusted_utc_latest,
    verified_time_digest: observed.time_digest,
    authority_digest: state.authority.authority_digest,
    storage_root_identity_digest: state.storageRootIdentityDigest,
    monotonic_owner_ledger_digest: collections.ledger?.ledger_digest || null,
    runtime_id: state.runtimeId,
    assurance: runtime.assurance,
    production_ready: runtime.production_ready,
    production_blockers: [...runtime.production_blockers],
  };
  const projection = deepFreeze({ ...body, projection_digest: digestJson(body) });
  PROJECTIONS.add(projection);
  PROJECTION_STATE.set(projection, Object.freeze({
    runtime,
    expected_digest: digestJson(material.expected),
    evidence_digest: document.evidence_digest,
    receipt_digest: receipt.receipt_digest,
    projection_digest: projection.projection_digest,
  }));
  return projection;
}

function resolveAndVerifyPlanePhysicalGateEvidence(
  evidenceRefInput,
  runtimeInput,
  expectedBindingsInput,
) {
  const runtime = assertRuntime(runtimeInput);
  const state = RUNTIME_STATE.get(runtime);
  return withLock(state, () => projectionFromMaterial(
    runtime,
    resolveMaterialLocked(state, evidenceRefInput, expectedBindingsInput),
  ));
}

function assertProjectionIntegrity(input, runtime, expected) {
  const projectionState = input == null ? null : PROJECTION_STATE.get(input);
  if (!input || !Object.isFrozen(input) || !PROJECTIONS.has(input) || !projectionState
      || projectionState.runtime !== runtime) {
    throw new Error("gate evidence projection was not privately issued by this runtime");
  }
  if (projectionState.expected_digest !== digestJson(expected)) {
    throw new Error("gate evidence projection expected bindings changed");
  }
  const body = { ...input };
  delete body.projection_digest;
  if (input.projection_digest !== projectionState.projection_digest
      || digestJson(body) !== projectionState.projection_digest) {
    throw new Error("gate evidence projection integrity drift");
  }
  return projectionState;
}

function assertConformancePlanePhysicalGateEvidence(
  input,
  runtimeInput,
  expectedBindingsInput,
) {
  const runtime = assertRuntime(runtimeInput);
  const expected = normalizeIssueBindings(
    expectedBindingsInput,
    "gate evidence assertion bindings",
  );
  const projectionState = assertProjectionIntegrity(input, runtime, expected);
  const current = resolveAndVerifyPlanePhysicalGateEvidence(
    input.evidence_ref,
    runtime,
    expected,
  );
  if (current.evidence_digest !== projectionState.evidence_digest
      || current.receipt_digest !== projectionState.receipt_digest) {
    throw new Error("gate evidence projection drifted from current durable state");
  }
  return input;
}

function assertVerifiedPlanePhysicalGateEvidence(
  input,
  runtimeInput,
  expectedBindingsInput,
) {
  const projection = assertConformancePlanePhysicalGateEvidence(
    input,
    runtimeInput,
    expectedBindingsInput,
  );
  assertProductionRuntime(runtimeInput);
  if (projection.production_ready !== true) {
    throw new Error("gate evidence is not production-qualified");
  }
  return projection;
}

function normalizeBatchRequestEntries(input, state, label = "gate evidence batch entries") {
  const values = boundedDenseDataArray(input, label, 1, MAX_BATCH_ENTRIES);
  const entries = [];
  const seenRefs = new Set();
  let common = null;
  for (let index = 0; index < values.length; index += 1) {
    const entry = exactObject(values[index], `${label}[${index}]`, [
      "evidence_ref",
      "expected_bindings",
    ]);
    const ref = evidenceRef(entry.evidence_ref, `${label}[${index}].evidence_ref`);
    if (seenRefs.has(ref)) throw new Error("gate evidence batch contains a duplicate evidence_ref");
    seenRefs.add(ref);
    const expected = normalizeIssueBindings(
      entry.expected_bindings,
      `${label}[${index}].expected_bindings`,
    );
    if (expected.session_nucleus_hash !== state.sessionNucleusHash) {
      throw new Error("gate evidence batch belongs to another release session");
    }
    const candidateBinding = {
      session_nucleus_hash: expected.session_nucleus_hash,
      source_tree_digest: expected.source_tree_digest,
      release_candidate_digest: expected.release_candidate_digest,
      package_digest: expected.package_digest,
      task_graph_digest: expected.task_graph_digest,
      release_snapshot_digest: expected.release_snapshot_digest,
    };
    if (common == null) common = candidateBinding;
    else if (canonicalJson(common) !== canonicalJson(candidateBinding)) {
      throw new Error("gate evidence batch must bind one exact session and release candidate");
    }
    entries.push(deepFreeze({ evidence_ref: ref, expected_bindings: expected }));
  }
  entries.sort((left, right) => left.evidence_ref.localeCompare(right.evidence_ref));
  return deepFreeze(entries);
}

function batchRequestEntrySetDigest(entries) {
  return digestJson(entries.map((entry) => ({
    evidence_ref: entry.evidence_ref,
    expected_bindings_digest: digestJson(entry.expected_bindings),
  })));
}

function materializeBatchEntries(collections, entries, receiptTimeHistory) {
  return entries.map((entry) => {
    const document = collections.documentsByRef.get(entry.evidence_ref);
    if (!document) {
      throw new Error(`gate evidence batch reference is absent: ${entry.evidence_ref}`);
    }
    assertPayloadBindings(
      document.payload,
      entry.expected_bindings,
      "gate evidence batch payload",
    );
    const receipt = exactReceiptFor(collections, document);
    assertReceiptTrustedTimeFromHistory(receiptTimeHistory, receipt, document);
    return { document, receipt, expected: entry.expected_bindings };
  });
}

function resolveBatchMaterialLocked(state, entries) {
  const initial = resolveCollections(state);
  const receiptTimeHistory = readTimeHistory(state);
  const initialEntries = materializeBatchEntries(initial, entries, receiptTimeHistory);
  const firstObserved = sampleTrustedNowLocked(state);
  for (const material of initialEntries) {
    verifyDocumentSignatureAndTrust(
      state,
      material.document,
      firstObserved,
      initial.revocations,
    );
  }

  const stable = resolveCollections(state);
  const stableEntries = materializeBatchEntries(stable, entries, readTimeHistory(state));
  if (collectionSnapshotDigest(stable) !== collectionSnapshotDigest(initial)) {
    throw new Error("gate evidence batch durable collection changed during stable readback");
  }
  for (let index = 0; index < stableEntries.length; index += 1) {
    if (stableEntries[index].document.evidence_digest
          !== initialEntries[index].document.evidence_digest
        || stableEntries[index].receipt.receipt_digest
          !== initialEntries[index].receipt.receipt_digest) {
      throw new Error("gate evidence batch entry forked during stable readback");
    }
  }
  const finalObserved = sampleTrustedNowLocked(state);
  for (const material of stableEntries) {
    verifyDocumentSignatureAndTrust(
      state,
      material.document,
      finalObserved,
      stable.revocations,
    );
  }
  return {
    entries: stableEntries,
    requestEntries: entries,
    observed: finalObserved,
    collections: stable,
  };
}

function batchProjectionEntry(material) {
  const { document, receipt, expected } = material;
  const body = {
    evidence_ref: document.evidence_ref,
    evidence_digest: document.evidence_digest,
    payload_digest: digestJson(document.payload),
    expected_bindings_digest: digestJson(expected),
    graph_id: document.payload.graph_id,
    node_id: document.payload.node_id,
    gate_kind: document.payload.gate_kind,
    evidence_class: document.payload.evidence_class,
    release_candidate_digest: document.payload.release_candidate_digest,
    node_contract_digest: document.payload.node_contract_digest,
    gate_contract_digest: document.payload.gate_contract_digest,
    acceptance_digest: document.payload.acceptance_digest,
    result_digest: document.payload.result_digest,
    verdict: document.payload.verdict,
    signer_principal_id: document.authentication.signer_principal_id,
    signer_key_id: document.authentication.signer_key_id,
    signer_epoch: document.authentication.signer_epoch,
    signer_public_key_digest: document.authentication.signer_public_key_digest,
    receipt_ref: receiptRefFor(receipt),
    receipt_digest: receipt.receipt_digest,
    receipt_scope_digest: receipt.scope_digest,
    receipt_sequence: receipt.sequence,
  };
  return deepFreeze({ ...body, entry_digest: digestJson(body) });
}

function batchProjectionFromMaterial(runtime, material) {
  const state = RUNTIME_STATE.get(runtime);
  const projectedEntries = material.entries.map(batchProjectionEntry);
  const revocationDigests = material.collections.revocations.map(
    (record) => record.revocation_digest,
  );
  const body = {
    version: VERSION,
    domain: "hacker-bob/plane-physical-gate-evidence-batch-verification",
    runtime_id: state.runtimeId,
    session_nucleus_hash: material.requestEntries[0].expected_bindings.session_nucleus_hash,
    release_candidate_digest:
      material.requestEntries[0].expected_bindings.release_candidate_digest,
    request_entry_set_digest: batchRequestEntrySetDigest(material.requestEntries),
    verified_entry_set_digest: digestJson(projectedEntries),
    entry_count: projectedEntries.length,
    entries: projectedEntries,
    authority_digest: state.authority.authority_digest,
    storage_root_identity_digest: state.storageRootIdentityDigest,
    owner_ledger_digest: material.collections.ledger?.ledger_digest || null,
    revocation_set_digest: digestJson(revocationDigests),
    revocation_head_digest: revocationDigests.at(-1) || null,
    collection_snapshot_digest: collectionSnapshotDigest(material.collections),
    common_verified_at: material.observed.observed_at,
    common_trusted_utc_earliest: material.observed.trusted_utc_earliest,
    common_trusted_utc_latest: material.observed.trusted_utc_latest,
    common_trusted_time_digest: material.observed.time_digest,
    assurance: runtime.assurance,
    production_ready: runtime.production_ready,
    production_blockers: [...runtime.production_blockers],
  };
  const projection = deepFreeze({ ...body, batch_projection_digest: digestJson(body) });
  BATCH_PROJECTIONS.add(projection);
  BATCH_PROJECTION_STATE.set(projection, Object.freeze({
    runtime,
    request_entry_set_digest: body.request_entry_set_digest,
    verified_entry_set_digest: body.verified_entry_set_digest,
    collection_snapshot_digest: body.collection_snapshot_digest,
    revocation_set_digest: body.revocation_set_digest,
    owner_ledger_digest: body.owner_ledger_digest,
    batch_projection_digest: projection.batch_projection_digest,
  }));
  return projection;
}

function resolveAndVerifyPlanePhysicalGateEvidenceBatch(entriesInput, runtimeInput) {
  const runtime = assertRuntime(runtimeInput);
  const state = RUNTIME_STATE.get(runtime);
  const entries = normalizeBatchRequestEntries(entriesInput, state);
  return withLock(state, () => batchProjectionFromMaterial(
    runtime,
    resolveBatchMaterialLocked(state, entries),
  ));
}

function assertBatchProjectionIntegrity(input, runtime, entries) {
  const projectionState = input == null ? null : BATCH_PROJECTION_STATE.get(input);
  if (!input || !Object.isFrozen(input) || !BATCH_PROJECTIONS.has(input) || !projectionState
      || projectionState.runtime !== runtime) {
    throw new Error("gate evidence batch projection was not privately issued by this runtime");
  }
  const requestDigest = batchRequestEntrySetDigest(entries);
  if (requestDigest !== projectionState.request_entry_set_digest
      || input.request_entry_set_digest !== requestDigest) {
    throw new Error("gate evidence batch assertion entry set changed");
  }
  const body = { ...input };
  delete body.batch_projection_digest;
  if (input.batch_projection_digest !== projectionState.batch_projection_digest
      || digestJson(body) !== projectionState.batch_projection_digest) {
    throw new Error("gate evidence batch projection integrity drift");
  }
  return projectionState;
}

function assertConformancePlanePhysicalGateEvidenceBatch(
  input,
  runtimeInput,
  entriesInput,
) {
  const runtime = assertRuntime(runtimeInput);
  const state = RUNTIME_STATE.get(runtime);
  const entries = normalizeBatchRequestEntries(
    entriesInput,
    state,
    "gate evidence batch assertion entries",
  );
  const projectionState = assertBatchProjectionIntegrity(input, runtime, entries);
  const current = resolveAndVerifyPlanePhysicalGateEvidenceBatch(entries, runtime);
  if (current.request_entry_set_digest !== projectionState.request_entry_set_digest
      || current.verified_entry_set_digest !== projectionState.verified_entry_set_digest
      || current.collection_snapshot_digest !== projectionState.collection_snapshot_digest
      || current.revocation_set_digest !== projectionState.revocation_set_digest
      || current.owner_ledger_digest !== projectionState.owner_ledger_digest) {
    throw new Error("gate evidence batch projection is no longer the current atomic set");
  }
  return current;
}

function assertVerifiedPlanePhysicalGateEvidenceBatch(
  input,
  runtimeInput,
  entriesInput,
) {
  const current = assertConformancePlanePhysicalGateEvidenceBatch(
    input,
    runtimeInput,
    entriesInput,
  );
  assertProductionRuntime(runtimeInput);
  if (current.production_ready !== true) {
    throw new Error("gate evidence atomic batch is not production-qualified");
  }
  return current;
}

const RELEASE_SNAPSHOT_RECEIPT_BODY_FIELDS = Object.freeze([
  "version",
  "domain",
  "runtime_id",
  "sequence",
  "previous_receipt_digest",
  "session_nucleus_hash",
  "release_candidate_digest",
  "request_entry_set_digest",
  "verified_entry_set_digest",
  "batch_projection_digest",
  "entry_count",
  "authority_digest",
  "storage_root_identity_digest",
  "owner_ledger_digest",
  "revocation_set_digest",
  "revocation_head_digest",
  "collection_snapshot_digest",
  "common_verified_at",
  "common_trusted_utc_earliest",
  "common_trusted_utc_latest",
  "common_trusted_time_digest",
  "issued_at",
  "not_before",
  "expires_at",
  "assurance",
  "production_blockers",
  "receipt_digest",
]);

function normalizeReleaseSnapshotReceiptRecord(
  document,
  state,
  expectedSequence,
  previousDigest,
) {
  const body = verifyStoreBody(
    state,
    document,
    RELEASE_SNAPSHOT_RECEIPT_DOMAIN,
    RELEASE_SNAPSHOT_RECEIPT_BODY_FIELDS,
    "plane physical release snapshot receipt record",
  );
  if (body.version !== VERSION || body.domain !== RELEASE_SNAPSHOT_RECEIPT_DOMAIN
      || body.runtime_id !== state.runtimeId || body.sequence !== expectedSequence
      || body.previous_receipt_digest !== previousDigest
      || body.session_nucleus_hash !== state.sessionNucleusHash
      || body.authority_digest !== state.authority.authority_digest
      || body.storage_root_identity_digest !== state.storageRootIdentityDigest
      || body.assurance !== CONFORMANCE_ASSURANCE
      || !Number.isSafeInteger(body.entry_count) || body.entry_count < 1
      || canonicalJson(body.production_blockers) !== canonicalJson(CONFORMANCE_BLOCKERS)) {
    throw new Error("plane physical release snapshot receipt record binding drift");
  }
  for (const [field, value] of Object.entries({
    release_candidate_digest: body.release_candidate_digest,
    request_entry_set_digest: body.request_entry_set_digest,
    verified_entry_set_digest: body.verified_entry_set_digest,
    batch_projection_digest: body.batch_projection_digest,
    revocation_set_digest: body.revocation_set_digest,
    collection_snapshot_digest: body.collection_snapshot_digest,
    common_trusted_time_digest: body.common_trusted_time_digest,
  })) digest(value, `release snapshot receipt.${field}`);
  if (body.owner_ledger_digest != null) {
    digest(body.owner_ledger_digest, "release snapshot receipt.owner_ledger_digest");
  }
  if (body.revocation_head_digest != null) {
    digest(body.revocation_head_digest, "release snapshot receipt.revocation_head_digest");
  }
  if (body.previous_receipt_digest != null) {
    digest(body.previous_receipt_digest, "release snapshot receipt.previous_receipt_digest");
  }
  const issuedAt = canonicalTimestamp(body.issued_at, "release snapshot receipt.issued_at");
  const notBefore = canonicalTimestamp(
    body.not_before,
    "release snapshot receipt.not_before",
  );
  const expiresAt = canonicalTimestamp(
    body.expires_at,
    "release snapshot receipt.expires_at",
  );
  const commonAt = canonicalTimestamp(
    body.common_verified_at,
    "release snapshot receipt.common_verified_at",
  );
  const commonEarliest = canonicalTimestamp(
    body.common_trusted_utc_earliest,
    "release snapshot receipt.common_trusted_utc_earliest",
  );
  const commonLatest = canonicalTimestamp(
    body.common_trusted_utc_latest,
    "release snapshot receipt.common_trusted_utc_latest",
  );
  if (issuedAt !== commonAt || Date.parse(commonEarliest) > Date.parse(commonAt)
      || Date.parse(commonAt) > Date.parse(commonLatest)
      || notBefore !== commonEarliest
      || expiresAt !== new Date(
        Date.parse(commonLatest) + RELEASE_SNAPSHOT_RECEIPT_VALIDITY_MS,
      ).toISOString()) {
    throw new Error("plane physical release snapshot receipt trusted-time window drift");
  }
  const basis = Object.fromEntries(RELEASE_SNAPSHOT_RECEIPT_BODY_FIELDS.slice(0, -1)
    .map((field) => [field, body[field]]));
  if (body.receipt_digest !== digestJson(basis)) {
    throw new Error("plane physical release snapshot receipt canonical digest drift");
  }
  return deepFreeze({ ...document });
}

function readReleaseSnapshotReceiptHistory(state) {
  const files = parseSequenceFiles(
    state.paths.releaseReceipts,
    "plane physical release snapshot receipt",
  );
  const result = [];
  let previousDigest = null;
  for (const file of files) {
    const record = normalizeReleaseSnapshotReceiptRecord(
      readFileExact(file.filePath, "plane physical release snapshot receipt record"),
      state,
      file.sequence,
      previousDigest,
    );
    previousDigest = record.receipt_digest;
    result.push(record);
  }
  if (state.observedReleaseReceiptCount != null
      && (result.length < state.observedReleaseReceiptCount
        || (state.observedReleaseReceiptCount > 0
          && result[state.observedReleaseReceiptCount - 1]?.receipt_digest
            !== state.observedReleaseReceiptHeadDigest))) {
    throw new Error("plane physical release snapshot receipt history rolled back or forked");
  }
  state.observedReleaseReceiptCount = result.length;
  state.observedReleaseReceiptHeadDigest = result.at(-1)?.receipt_digest || null;
  return result;
}

function releaseSnapshotReceiptProjection(runtime, record, entries) {
  const body = {
    version: VERSION,
    domain: "hacker-bob/plane-physical-release-snapshot-receipt-projection",
    receipt_ref: `${RELEASE_SNAPSHOT_RECEIPT_REF_PREFIX}${record.receipt_digest}`,
    receipt_digest: record.receipt_digest,
    receipt_sequence: record.sequence,
    previous_receipt_digest: record.previous_receipt_digest,
    session_nucleus_hash: record.session_nucleus_hash,
    release_candidate_digest: record.release_candidate_digest,
    request_entry_set_digest: record.request_entry_set_digest,
    verified_entry_set_digest: record.verified_entry_set_digest,
    batch_projection_digest: record.batch_projection_digest,
    entry_count: record.entry_count,
    authority_digest: record.authority_digest,
    storage_root_identity_digest: record.storage_root_identity_digest,
    owner_ledger_digest: record.owner_ledger_digest,
    revocation_set_digest: record.revocation_set_digest,
    revocation_head_digest: record.revocation_head_digest,
    collection_snapshot_digest: record.collection_snapshot_digest,
    common_verified_at: record.common_verified_at,
    common_trusted_utc_earliest: record.common_trusted_utc_earliest,
    common_trusted_utc_latest: record.common_trusted_utc_latest,
    common_trusted_time_digest: record.common_trusted_time_digest,
    issued_at: record.issued_at,
    not_before: record.not_before,
    expires_at: record.expires_at,
    assurance: CONFORMANCE_ASSURANCE,
    production_blockers: [...CONFORMANCE_BLOCKERS],
  };
  const projection = deepFreeze({
    ...body,
    receipt_projection_digest: digestJson(body),
  });
  RELEASE_SNAPSHOT_RECEIPT_PROJECTIONS.add(projection);
  RELEASE_SNAPSHOT_RECEIPT_PROJECTION_STATE.set(projection, Object.freeze({
    runtime,
    record_digest: record.receipt_digest,
    sequence: record.sequence,
    entries,
    request_entry_set_digest: record.request_entry_set_digest,
    receipt_projection_digest: projection.receipt_projection_digest,
  }));
  return projection;
}

// The wall-clock-stable material identity of a release-snapshot receipt: every
// basis field except the position (sequence, previous), the constant
// (assurance, production_blockers), and the trusted-time fields (common_*,
// issued_at, not_before, expires_at) plus batch_projection_digest, which folds
// common_verified_at. Two evaluations of the same release with the same resolved
// evidence share this digest; a materially different evaluation (changed
// candidate, request/verified set, authority, ownership, or revocation state)
// does not.
const RELEASE_SNAPSHOT_RECEIPT_IDENTITY_FIELDS = Object.freeze([
  "session_nucleus_hash",
  "release_candidate_digest",
  "request_entry_set_digest",
  "verified_entry_set_digest",
  "entry_count",
  "authority_digest",
  "storage_root_identity_digest",
  "owner_ledger_digest",
  "revocation_set_digest",
  "revocation_head_digest",
  "collection_snapshot_digest",
]);

function releaseSnapshotReceiptIdentityDigest(source) {
  return digestJson(Object.fromEntries(
    RELEASE_SNAPSHOT_RECEIPT_IDENTITY_FIELDS.map((field) => [field, source[field]]),
  ));
}

function commitPlanePhysicalGateEvidenceReleaseSnapshotReceipt(
  runtimeInput,
  batchProjectionInput,
  entriesInput,
) {
  if (arguments.length !== 3) {
    throw new Error("release snapshot receipt commit requires runtime, batch, and entries only");
  }
  const runtime = assertRuntime(runtimeInput);
  const state = RUNTIME_STATE.get(runtime);
  const entries = normalizeBatchRequestEntries(
    entriesInput,
    state,
    "release snapshot receipt batch entries",
  );
  const batchState = assertBatchProjectionIntegrity(batchProjectionInput, runtime, entries);
  return withLock(state, () => {
    const finalMaterial = resolveBatchMaterialLocked(state, entries);
    const finalBatch = batchProjectionFromMaterial(runtime, finalMaterial);
    if (finalBatch.request_entry_set_digest !== batchState.request_entry_set_digest
        || finalBatch.verified_entry_set_digest !== batchState.verified_entry_set_digest
        || finalBatch.release_candidate_digest
          !== batchProjectionInput.release_candidate_digest) {
      throw new Error("release snapshot receipt batch changed before atomic commit");
    }
    const history = readReleaseSnapshotReceiptHistory(state);
    const head = history.at(-1);
    if (head
        && releaseSnapshotReceiptIdentityDigest(head)
          === releaseSnapshotReceiptIdentityDigest(finalBatch)
        && Date.parse(head.expires_at) > Date.parse(finalBatch.common_trusted_utc_latest)) {
      // Idempotent rehydration: an identical evaluation whose durable head
      // receipt is still within its validity window re-reads that head instead
      // of appending a duplicate, which also recovers a lost fsync
      // acknowledgement. Once the head's window has expired, idempotency yields
      // to renewal below: a fresh receipt with a current window is appended so
      // an unchanged release can still be re-attested rather than locked to a
      // stale, already-expired projection.
      return releaseSnapshotReceiptProjection(runtime, head, entries);
    }
    const sequence = String(history.length + 1);
    const previousReceiptDigest = head?.receipt_digest || null;
    const basis = {
      version: VERSION,
      domain: RELEASE_SNAPSHOT_RECEIPT_DOMAIN,
      runtime_id: state.runtimeId,
      sequence,
      previous_receipt_digest: previousReceiptDigest,
      session_nucleus_hash: finalBatch.session_nucleus_hash,
      release_candidate_digest: finalBatch.release_candidate_digest,
      request_entry_set_digest: finalBatch.request_entry_set_digest,
      verified_entry_set_digest: finalBatch.verified_entry_set_digest,
      batch_projection_digest: finalBatch.batch_projection_digest,
      entry_count: finalBatch.entry_count,
      authority_digest: finalBatch.authority_digest,
      storage_root_identity_digest: finalBatch.storage_root_identity_digest,
      owner_ledger_digest: finalBatch.owner_ledger_digest,
      revocation_set_digest: finalBatch.revocation_set_digest,
      revocation_head_digest: finalBatch.revocation_head_digest,
      collection_snapshot_digest: finalBatch.collection_snapshot_digest,
      common_verified_at: finalBatch.common_verified_at,
      common_trusted_utc_earliest: finalBatch.common_trusted_utc_earliest,
      common_trusted_utc_latest: finalBatch.common_trusted_utc_latest,
      common_trusted_time_digest: finalBatch.common_trusted_time_digest,
      issued_at: finalBatch.common_verified_at,
      not_before: finalBatch.common_trusted_utc_earliest,
      expires_at: new Date(
        Date.parse(finalBatch.common_trusted_utc_latest)
          + RELEASE_SNAPSHOT_RECEIPT_VALIDITY_MS,
      ).toISOString(),
      assurance: CONFORMANCE_ASSURANCE,
      production_blockers: [...CONFORMANCE_BLOCKERS],
    };
    const recordBody = { ...basis, receipt_digest: digestJson(basis) };
    const record = signStoreBody(state, RELEASE_SNAPSHOT_RECEIPT_DOMAIN, recordBody);
    const validatedRecord = normalizeReleaseSnapshotReceiptRecord(
      record,
      state,
      sequence,
      previousReceiptDigest,
    );
    publishExclusiveAtomicFile(
      path.join(state.paths.releaseReceipts, sequenceFile(sequence)),
      jsonLine(record),
      "plane physical release snapshot receipt",
    );
    const readback = readReleaseSnapshotReceiptHistory(state).at(-1);
    if (!readback || readback.receipt_digest !== record.receipt_digest
        || readback.sequence !== sequence) {
      throw new Error("plane physical release snapshot receipt lacks exact durable readback");
    }
    return releaseSnapshotReceiptProjection(runtime, validatedRecord, entries);
  });
}

function assertReleaseSnapshotReceiptProjectionIntegrity(input, runtime, expected) {
  const projectionState = input == null
    ? null
    : RELEASE_SNAPSHOT_RECEIPT_PROJECTION_STATE.get(input);
  if (!input || !Object.isFrozen(input)
      || !RELEASE_SNAPSHOT_RECEIPT_PROJECTIONS.has(input)
      || !projectionState || projectionState.runtime !== runtime) {
    throw new Error(
      "release snapshot receipt must be a live privately branded projection",
    );
  }
  if (input.release_candidate_digest !== expected.release_candidate_digest) {
    throw new Error("release snapshot receipt expected candidate changed");
  }
  const body = { ...input };
  delete body.receipt_projection_digest;
  if (input.receipt_projection_digest !== projectionState.receipt_projection_digest
      || digestJson(body) !== projectionState.receipt_projection_digest) {
    throw new Error("release snapshot receipt projection integrity drift");
  }
  return projectionState;
}

function assertCurrentPlanePhysicalGateEvidenceReleaseSnapshotReceipt(
  input,
  runtimeInput,
  expectedInput,
) {
  const runtime = assertRuntime(runtimeInput);
  exactObject(expectedInput, "release snapshot receipt currentness expectation", [
    "release_candidate_digest",
  ]);
  const expected = {
    release_candidate_digest: digest(
      expectedInput.release_candidate_digest,
      "release snapshot receipt expected release_candidate_digest",
    ),
  };
  const projectionState = assertReleaseSnapshotReceiptProjectionIntegrity(
    input,
    runtime,
    expected,
  );
  const state = RUNTIME_STATE.get(runtime);
  return withLock(state, () => {
    const history = readReleaseSnapshotReceiptHistory(state);
    const currentRecord = history.at(-1);
    if (!currentRecord || currentRecord.receipt_digest !== projectionState.record_digest
        || currentRecord.sequence !== projectionState.sequence) {
      throw new Error("release snapshot receipt generation is no longer current");
    }
    const material = resolveBatchMaterialLocked(state, projectionState.entries);
    const currentBatch = batchProjectionFromMaterial(runtime, material);
    if (currentBatch.request_entry_set_digest !== input.request_entry_set_digest
        || currentBatch.verified_entry_set_digest !== input.verified_entry_set_digest
        || currentBatch.collection_snapshot_digest !== input.collection_snapshot_digest
        || currentBatch.revocation_set_digest !== input.revocation_set_digest
        || currentBatch.owner_ledger_digest !== input.owner_ledger_digest) {
      throw new Error("release snapshot receipt evidence set is no longer current");
    }
    const earliest = Date.parse(material.observed.trusted_utc_earliest);
    const latest = Date.parse(material.observed.trusted_utc_latest);
    if (earliest < Date.parse(currentRecord.not_before)
        || latest >= Date.parse(currentRecord.expires_at)) {
      throw new Error("release snapshot receipt has expired or is not yet current");
    }
    const stableHistory = readReleaseSnapshotReceiptHistory(state);
    if (stableHistory.at(-1)?.receipt_digest !== currentRecord.receipt_digest) {
      throw new Error(
        "release snapshot receipt generation changed during currentness assertion",
      );
    }
    return input;
  });
}

module.exports = Object.freeze({
  PLANE_PHYSICAL_GATE_EVIDENCE_ASSURANCE: CONFORMANCE_ASSURANCE,
  PLANE_PHYSICAL_GATE_EVIDENCE_BLOCKERS: CONFORMANCE_BLOCKERS,
  PLANE_PHYSICAL_GATE_EVIDENCE_DOMAIN: DOMAIN,
  PLANE_PHYSICAL_GATE_EVIDENCE_EVIDENCE_CLASSES: EVIDENCE_CLASSES,
  PLANE_PHYSICAL_GATE_EVIDENCE_GATE_KINDS: GATE_KINDS,
  PLANE_PHYSICAL_GATE_EVIDENCE_VERSION: VERSION,
  PLANE_PHYSICAL_RELEASE_SNAPSHOT_RECEIPT_DOMAIN:
    RELEASE_SNAPSHOT_RECEIPT_DOMAIN,
  PLANE_PHYSICAL_RELEASE_SNAPSHOT_RECEIPT_VALIDITY_MS:
    RELEASE_SNAPSHOT_RECEIPT_VALIDITY_MS,
  assertConformancePlanePhysicalGateEvidence,
  assertConformancePlanePhysicalGateEvidenceBatch,
  assertCurrentPlanePhysicalGateEvidenceReleaseSnapshotReceipt,
  assertVerifiedPlanePhysicalGateEvidence,
  assertVerifiedPlanePhysicalGateEvidenceBatch,
  commitPlanePhysicalGateEvidenceReleaseSnapshotReceipt,
  createConformancePlanePhysicalGateEvidenceRuntime,
  createProductionPlanePhysicalGateEvidenceRuntime,
  issuePlanePhysicalGateEvidence,
  normalizeSignedPlanePhysicalGateEvidence,
  planePhysicalReleaseCandidateDigest: releaseCandidateDigest,
  resolveAndVerifyPlanePhysicalGateEvidence,
  resolveAndVerifyPlanePhysicalGateEvidenceBatch,
  revokePlanePhysicalGateEvidenceSigner,
});
