"use strict";

// Genuine Plane-PH campaign closure owner.
//
// Unlike physical-campaign-anchor's callback adapter, this owner retains its
// monotonic head in an owner-only filesystem domain outside the Bob session
// tree.  It issues the campaign id before assignment construction, owns the
// exact Ed25519 segment signer, binds the verified physical nucleus, and reads
// zero-active-effects from the live durable lease broker.  Mechanism-A is a
// structural property of the exact key/root path; no boolean or supplied
// digest promotes this port.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const {
  PHYSICAL_CAMPAIGN_IDENTITY_VERSION,
  assertPhysicalCampaignClosureSatisfied,
  createPhysicalCampaignEd25519SignerPort,
  createPhysicalCampaignEd25519VerifierPort,
  normalizePhysicalCampaignClosurePreflight,
} = require("./physical-campaign-closure.js");
const { readVerifiedSessionNucleus } = require("../../core/governance/governance-store.js");
const {
  assertDurableInstrumentLeaseBrokerPort,
  readDurableInstrumentLeaseBrokerClosureState,
} = require("./instrument-lease-store.js");
const {
  assertSafeDomain,
  sessionDir,
} = require("../../core/io/paths.js");
const {
  probeExactSigningKeyPathIsolation,
} = require("../../core/ledger-integrity/sandbox-isolation-attest.js");
const {
  canonicalJson,
  hashCanonicalJson,
} = require("../../core/verification/verification-contracts.js");

const OWNER_VERSION = 1;
const ANCHOR_NAMESPACE = "hacker-bob/physical-campaign-anchor/v1";
const OWNER_KIND = "production_physical_campaign_closure_owner";
const ANCHOR_KIND = "physical_campaign_owner_anchor_port";
const KEY_FILE = "campaign-closure-owner-private.json";
const OBLIGATION_FILE = "campaign-obligation.json";
const HEADS_DIR = "anchor-heads";
const CLOSURE_FILE = "closure-attestation.json";
const HEAD_RE = /^([0-9]{8})\.json$/u;
const HASH_RE = /^[a-f0-9]{64}$/u;
const SIGNATURE_RE = /^[A-Za-z0-9_-]{86}$/u;
const MAX_OWNER_BYTES = 256 * 1024;
const MAX_HEADS = 65_537;

const OWNERS = new WeakSet();
const OWNER_STATE = new WeakMap();
const ANCHOR_PORTS = new WeakSet();
const ANCHOR_PORT_STATE = new WeakMap();

function ownerError(code, message, cause = null) {
  const error = new Error(`${code}: ${message}`);
  error.code = code;
  if (cause != null) Object.defineProperty(error, "cause", { value: cause });
  return error;
}

function exactRecord(input, label, fields) {
  if (input == null || typeof input !== "object" || Array.isArray(input)
      || utilTypes.isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype) {
    throw ownerError("physical_campaign_owner_contract_invalid", `${label} must be a plain object`);
  }
  const keys = Reflect.ownKeys(input);
  const expected = fields.slice().sort();
  const actual = keys.slice().sort();
  if (keys.some((key) => typeof key !== "string")
      || actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) {
    throw ownerError("physical_campaign_owner_contract_invalid", `${label} fields are not exact`);
  }
  const result = {};
  const descriptors = Object.getOwnPropertyDescriptors(input);
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw ownerError(
        "physical_campaign_owner_contract_invalid",
        `${label}.${field} must be an enumerable data property`,
      );
    }
    result[field] = descriptor.value;
  }
  return result;
}

function digest(value, label) {
  if (typeof value !== "string" || !HASH_RE.test(value)) {
    throw ownerError("physical_campaign_owner_contract_invalid", `${label} must be a SHA-256 digest`);
  }
  return value;
}

function canonicalSignature(value, label) {
  if (typeof value !== "string" || !SIGNATURE_RE.test(value)) {
    throw ownerError("physical_campaign_owner_signature_invalid", `${label} is invalid`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) {
    throw ownerError("physical_campaign_owner_signature_invalid", `${label} is noncanonical`);
  }
  return value;
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
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
    throw ownerError("physical_campaign_owner_storage_invalid", `${label} is unavailable`, cause);
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (!stats.isDirectory() || stats.isSymbolicLink()
      || uid == null || stats.uid !== uid || (stats.mode & 0o077) !== 0) {
    throw ownerError(
      "physical_campaign_owner_storage_invalid",
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

function assertPrivateFile(filePath, label, expectedMode = null) {
  const before = fs.lstatSync(filePath);
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
      || uid == null || before.uid !== uid || (before.mode & 0o077) !== 0
      || (expectedMode != null && (before.mode & 0o777) !== expectedMode)) {
    throw ownerError("physical_campaign_owner_storage_invalid", `${label} custody is invalid`);
  }
  const descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(descriptor);
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.nlink !== 1) {
      throw ownerError("physical_campaign_owner_storage_invalid", `${label} changed during open`);
    }
    return { descriptor, stats: before };
  } catch (error) {
    fs.closeSync(descriptor);
    throw error;
  }
}

function readPrivateJson(filePath, label, maximum = MAX_OWNER_BYTES, expectedMode = null) {
  const opened = assertPrivateFile(filePath, label, expectedMode);
  try {
    if (opened.stats.size < 2 || opened.stats.size > maximum) {
      throw ownerError("physical_campaign_owner_storage_invalid", `${label} size is invalid`);
    }
    const buffer = Buffer.alloc(opened.stats.size);
    let offset = 0;
    while (offset < buffer.length) {
      const count = fs.readSync(opened.descriptor, buffer, offset, buffer.length - offset, offset);
      if (count < 1) throw ownerError("physical_campaign_owner_storage_invalid", `${label} is truncated`);
      offset += count;
    }
    try { return JSON.parse(buffer.toString("utf8")); } finally { buffer.fill(0); }
  } finally {
    fs.closeSync(opened.descriptor);
  }
}

function writeExclusiveJson(filePath, value, mode) {
  const directory = path.dirname(filePath);
  const tempPath = path.join(
    directory,
    `.${path.basename(filePath)}.${process.pid}.${crypto.randomBytes(12).toString("hex")}.tmp`,
  );
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, "utf8");
  let descriptor;
  try {
    descriptor = fs.openSync(tempPath, "wx", mode);
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = null;
    fs.chmodSync(tempPath, mode);
    try {
      fs.linkSync(tempPath, filePath);
    } catch (error) {
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

function pathsFor(root) {
  return Object.freeze({
    root,
    key: path.join(root, KEY_FILE),
    obligation: path.join(root, OBLIGATION_FILE),
    heads: path.join(root, HEADS_DIR),
    closure: path.join(root, CLOSURE_FILE),
  });
}

function disjointPaths(left, right) {
  const relativeLeft = path.relative(left, right);
  const relativeRight = path.relative(right, left);
  return relativeLeft !== "" && relativeRight !== ""
    && (relativeLeft === ".." || relativeLeft.startsWith(`..${path.sep}`))
    && (relativeRight === ".." || relativeRight.startsWith(`..${path.sep}`));
}

function rootIdentity(root, stats) {
  return hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-external-owner-root/v1",
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

function keyDocument(domain, nucleusHash, privateKey) {
  const publicKey = crypto.createPublicKey(privateKey);
  return {
    version: OWNER_VERSION,
    scheme: "ed25519",
    target_domain: domain,
    session_nucleus_hash: nucleusHash,
    public_key_spki_base64url: publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
    public_key_spki_sha256: publicKeyDigest(publicKey),
    private_key_pkcs8_base64url: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url"),
  };
}

function normalizeKeyDocument(input, domain, nucleusHash) {
  const value = exactRecord(input, "physical campaign owner key", [
    "version", "scheme", "target_domain", "session_nucleus_hash",
    "public_key_spki_base64url", "public_key_spki_sha256", "private_key_pkcs8_base64url",
  ]);
  if (value.version !== OWNER_VERSION || value.scheme !== "ed25519"
      || value.target_domain !== domain || value.session_nucleus_hash !== nucleusHash) {
    throw ownerError("physical_campaign_owner_authority_drift", "owner key binding drifted");
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
    throw ownerError("physical_campaign_owner_key_invalid", "owner private key is invalid", cause);
  }
  const digestValue = publicKeyDigest(publicKey);
  if (digest(value.public_key_spki_sha256, "owner public key digest") !== digestValue
      || publicKey.export({ type: "spki", format: "der" }).toString("base64url")
        !== value.public_key_spki_base64url) {
    throw ownerError("physical_campaign_owner_key_invalid", "owner public key projection drifted");
  }
  return Object.freeze({ document: deepFreeze(value), privateKey, publicKey });
}

function readOrCreateKey(paths, domain, nucleusHash) {
  if (!fs.existsSync(paths.key)) {
    const pair = crypto.generateKeyPairSync("ed25519");
    writeExclusiveJson(paths.key, keyDocument(domain, nucleusHash, pair.privateKey), 0o400);
  }
  return normalizeKeyDocument(
    readPrivateJson(paths.key, "physical campaign owner private key", MAX_OWNER_BYTES, 0o400),
    domain,
    nucleusHash,
  );
}

function signDigest(privateKey, payloadDigest) {
  return crypto.sign(null, Buffer.from(digest(payloadDigest, "signing payload"), "hex"), privateKey)
    .toString("base64url");
}

function verifyDigest(publicKey, payloadDigest, signature) {
  return crypto.verify(
    null,
    Buffer.from(digest(payloadDigest, "verification payload"), "hex"),
    publicKey,
    Buffer.from(canonicalSignature(signature, "owner signature"), "base64url"),
  );
}

function obligationPayload(input) {
  return {
    version: OWNER_VERSION,
    target_domain: input.target_domain,
    session_nucleus_hash: input.session_nucleus_hash,
    campaign_identity_version: PHYSICAL_CAMPAIGN_IDENTITY_VERSION,
    campaign_id: input.campaign_id,
    reservation_nonce_digest: input.reservation_nonce_digest,
    signer_key_ref: input.signer_key_ref,
    signer_public_key_digest: input.signer_public_key_digest,
    external_owner_root_identity_digest: input.external_owner_root_identity_digest,
    anchor_slot_digest: input.anchor_slot_digest,
    issued_at: input.issued_at,
  };
}

function issueObligation(state) {
  const nonce = crypto.randomBytes(32);
  const nonceDigest = crypto.createHash("sha256").update(nonce).digest("hex");
  const campaignId = `physical-campaign:${hashCanonicalJson({
    domain: "hacker-bob/server-issued-physical-campaign-id/v2",
    target_domain: state.domain,
    session_nucleus_hash: state.nucleusHash,
    reservation_nonce: nonce.toString("base64url"),
    external_owner_root_identity_digest: state.rootIdentityDigest,
    signer_public_key_digest: state.key.document.public_key_spki_sha256,
  })}`;
  nonce.fill(0);
  const signerKeyRef = `campaign-closure-signer:${campaignId.slice("physical-campaign:".length, 45)}`;
  const anchorSlotDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-external-owner-slot/v1",
    target_domain: state.domain,
    session_nucleus_hash: state.nucleusHash,
    external_owner_root_identity_digest: state.rootIdentityDigest,
    signer_public_key_digest: state.key.document.public_key_spki_sha256,
  });
  const payload = obligationPayload({
    target_domain: state.domain,
    session_nucleus_hash: state.nucleusHash,
    campaign_id: campaignId,
    reservation_nonce_digest: nonceDigest,
    signer_key_ref: signerKeyRef,
    signer_public_key_digest: state.key.document.public_key_spki_sha256,
    external_owner_root_identity_digest: state.rootIdentityDigest,
    anchor_slot_digest: anchorSlotDigest,
    issued_at: new Date().toISOString(),
  });
  const payloadDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-server-obligation-payload/v1",
    ...payload,
  });
  const signature = signDigest(state.key.privateKey, payloadDigest);
  return deepFreeze({
    ...payload,
    payload_digest: payloadDigest,
    signature,
    obligation_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-campaign-server-obligation/v1",
      ...payload,
      payload_digest: payloadDigest,
      signature,
    }),
  });
}

function normalizeObligation(input, state) {
  const value = exactRecord(input, "physical campaign server obligation", [
    "version", "target_domain", "session_nucleus_hash", "campaign_identity_version",
    "campaign_id", "reservation_nonce_digest", "signer_key_ref", "signer_public_key_digest",
    "external_owner_root_identity_digest", "anchor_slot_digest", "issued_at",
    "payload_digest", "signature", "obligation_digest",
  ]);
  const payload = obligationPayload(value);
  const expectedPayloadDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-server-obligation-payload/v1",
    ...payload,
  });
  const expectedObligationDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-server-obligation/v1",
    ...payload,
    payload_digest: expectedPayloadDigest,
    signature: value.signature,
  });
  if (payload.version !== OWNER_VERSION
      || payload.target_domain !== state.domain
      || payload.session_nucleus_hash !== state.nucleusHash
      || payload.campaign_identity_version !== PHYSICAL_CAMPAIGN_IDENTITY_VERSION
      || payload.signer_public_key_digest !== state.key.document.public_key_spki_sha256
      || payload.external_owner_root_identity_digest !== state.rootIdentityDigest
      || digest(value.payload_digest, "obligation payload digest") !== expectedPayloadDigest
      || digest(value.obligation_digest, "obligation digest") !== expectedObligationDigest
      || !verifyDigest(state.key.publicKey, expectedPayloadDigest, value.signature)) {
    throw ownerError("physical_campaign_owner_authority_drift", "server obligation binding drifted");
  }
  return deepFreeze({ ...payload, payload_digest: expectedPayloadDigest,
    signature: value.signature, obligation_digest: expectedObligationDigest });
}

function readOrCreateObligation(state) {
  if (!fs.existsSync(state.paths.obligation)) {
    writeExclusiveJson(state.paths.obligation, issueObligation(state), 0o600);
  }
  return normalizeObligation(
    readPrivateJson(state.paths.obligation, "physical campaign server obligation", MAX_OWNER_BYTES, 0o600),
    state,
  );
}

function currentNucleus(state) {
  const nucleus = readVerifiedSessionNucleus(state.domain);
  if (!nucleus.physical_scope || nucleus.nucleus_hash !== state.nucleusHash
      || (nucleus.target_domain != null && nucleus.target_domain !== state.domain)) {
    throw ownerError(
      "physical_campaign_owner_authority_drift",
      "campaign owner is not bound to the exact current physical nucleus",
    );
  }
  return nucleus;
}

function liveCustody(state) {
  const rootStats = assertOwnedDirectory(state.paths.root, "physical campaign external owner root");
  const sessionRoot = fs.realpathSync(sessionDir(state.domain));
  const ownerRoot = fs.realpathSync(state.paths.root);
  const disjoint = disjointPaths(ownerRoot, sessionRoot);
  const currentIdentity = rootIdentity(ownerRoot, rootStats);
  const probe = probeExactSigningKeyPathIsolation(state.paths.key, {
    expectedRoot: ownerRoot,
    custodyRoot: ownerRoot,
  });
  const productionReady = disjoint
    && currentIdentity === state.rootIdentityDigest
    && probe.assurance === "mechanism_a_exact_signing_key_path_isolation"
    && probe.isolated === true;
  const basis = {
    version: OWNER_VERSION,
    target_domain: state.domain,
    session_nucleus_hash: state.nucleusHash,
    external_owner_root_identity_digest: currentIdentity,
    owner_root_disjoint_from_session: disjoint,
    isolation_probe: probe,
    production_ready: productionReady,
  };
  return deepFreeze({
    ...basis,
    custody_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-campaign-closure-owner-custody/v1",
      ...basis,
    }),
  });
}

function assertOwnerCurrent(state) {
  currentNucleus(state);
  const key = normalizeKeyDocument(
    readPrivateJson(state.paths.key, "physical campaign owner private key", MAX_OWNER_BYTES, 0o400),
    state.domain,
    state.nucleusHash,
  );
  if (key.document.public_key_spki_sha256 !== state.key.document.public_key_spki_sha256) {
    throw ownerError("physical_campaign_owner_authority_drift", "owner key changed");
  }
  const custody = liveCustody(state);
  const obligation = normalizeObligation(
    readPrivateJson(state.paths.obligation, "physical campaign server obligation", MAX_OWNER_BYTES, 0o600),
    state,
  );
  if (obligation.obligation_digest !== state.obligation.obligation_digest) {
    throw ownerError("physical_campaign_owner_authority_drift", "server obligation changed");
  }
  return Object.freeze({ custody, obligation });
}

function headPayload(state, sequence, previousHeadDigest, anchorState) {
  return {
    version: OWNER_VERSION,
    sequence,
    previous_head_digest: previousHeadDigest,
    target_domain: state.domain,
    session_nucleus_hash: state.nucleusHash,
    campaign_obligation_digest: state.obligation.obligation_digest,
    anchor_state: cloneJson(anchorState),
  };
}

function issueHead(state, sequence, previousHeadDigest, anchorState) {
  const payload = headPayload(state, sequence, previousHeadDigest, anchorState);
  const payloadDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-external-head-payload/v1",
    ...payload,
  });
  const signature = signDigest(state.key.privateKey, payloadDigest);
  return deepFreeze({
    ...payload,
    payload_digest: payloadDigest,
    signature,
    head_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-campaign-external-head/v1",
      ...payload,
      payload_digest: payloadDigest,
      signature,
    }),
  });
}

function normalizeHead(input, state, sequence, previousHeadDigest) {
  const value = exactRecord(input, `physical campaign external head ${sequence}`, [
    "version", "sequence", "previous_head_digest", "target_domain", "session_nucleus_hash",
    "campaign_obligation_digest", "anchor_state", "payload_digest", "signature", "head_digest",
  ]);
  const payload = headPayload(state, value.sequence, value.previous_head_digest, value.anchor_state);
  const payloadDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-external-head-payload/v1",
    ...payload,
  });
  const headDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-external-head/v1",
    ...payload,
    payload_digest: payloadDigest,
    signature: value.signature,
  });
  if (value.version !== OWNER_VERSION || value.sequence !== sequence
      || value.previous_head_digest !== previousHeadDigest
      || value.target_domain !== state.domain || value.session_nucleus_hash !== state.nucleusHash
      || value.campaign_obligation_digest !== state.obligation.obligation_digest
      || digest(value.payload_digest, "head payload digest") !== payloadDigest
      || digest(value.head_digest, "head digest") !== headDigest
      || !verifyDigest(state.key.publicKey, payloadDigest, value.signature)) {
    throw ownerError("physical_campaign_anchor_rollback", "external owner head chain is invalid");
  }
  return deepFreeze({ ...payload, payload_digest: payloadDigest,
    signature: value.signature, head_digest: headDigest });
}

function readHeads(state) {
  assertOwnedDirectory(state.paths.heads, "physical campaign external head directory");
  const names = fs.readdirSync(state.paths.heads).sort();
  if (names.length > MAX_HEADS || names.some((name) => !HEAD_RE.test(name))) {
    throw ownerError("physical_campaign_anchor_rollback", "external head directory is malformed");
  }
  const heads = [];
  let previous = "0".repeat(64);
  for (let index = 0; index < names.length; index += 1) {
    const sequence = index + 1;
    const expectedName = `${String(sequence).padStart(8, "0")}.json`;
    if (names[index] !== expectedName) {
      throw ownerError("physical_campaign_anchor_rollback", "external head chain has a gap");
    }
    const head = normalizeHead(
      readPrivateJson(path.join(state.paths.heads, names[index]), `external head ${sequence}`, MAX_OWNER_BYTES, 0o600),
      state,
      sequence,
      previous,
    );
    heads.push(head);
    previous = head.head_digest;
  }
  return heads;
}

function assertAnchorContext(context, state) {
  const value = exactRecord(context, "physical campaign owner anchor context", [
    "version", "anchor_namespace", "target_domain", "anchor_slot_digest",
  ]);
  if (value.version !== OWNER_VERSION || value.anchor_namespace !== ANCHOR_NAMESPACE
      || value.target_domain !== state.domain
      || value.anchor_slot_digest !== state.obligation.anchor_slot_digest) {
    throw ownerError("physical_campaign_owner_authority_drift", "anchor context drifted");
  }
}

function readProductionPhysicalCampaignAnchor(port, context) {
  const state = ANCHOR_PORT_STATE.get(assertProductionPhysicalCampaignAnchorPort(port));
  assertAnchorContext(context, state);
  assertOwnerCurrent(state);
  const heads = readHeads(state);
  assertOwnerCurrent(state);
  return heads.length === 0 ? null : deepFreeze(cloneJson(heads.at(-1).anchor_state));
}

function compareAndSetProductionPhysicalCampaignAnchor(port, context, expectedState, nextState) {
  const state = ANCHOR_PORT_STATE.get(assertProductionPhysicalCampaignAnchorPort(port));
  assertAnchorContext(context, state);
  assertOwnerCurrent(state);
  const heads = readHeads(state);
  const current = heads.length === 0 ? null : heads.at(-1).anchor_state;
  if (canonicalJson(current) !== canonicalJson(expectedState)) return false;
  if (heads.length >= MAX_HEADS) {
    throw ownerError("physical_campaign_anchor_capacity_exhausted", "external head journal is full");
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
  if (!durable || durable.head_digest !== candidate.head_digest) {
    throw ownerError("physical_campaign_anchor_commit_ambiguous", "external head lacks exact readback");
  }
  assertOwnerCurrent(state);
  return true;
}

function falseAssurance(state, assurance, blocker) {
  return Object.freeze({
    anchor_assurance: assurance,
    anchor_externality_attested: false,
    anchor_attestation_digest: null,
    campaign_obligation_server_issued: false,
    campaign_obligation_digest: null,
    physical_nucleus_authority_attested: false,
    physical_nucleus_authority_digest: null,
    closure_signer_production_enrolled: false,
    closure_signer_enrollment_digest: null,
    terminal_witnesses_production_attested: false,
    terminal_witness_attestation_digest: null,
    no_active_effects_durably_attested: false,
    no_active_effects_attestation_digest: null,
    production_ready: false,
    production_blocker: blocker,
    anchor_slot_digest: state.obligation.anchor_slot_digest,
    local_anchor_role: "crash_journal_only",
  });
}

function normalizeAssuranceContext(input, state) {
  const allowed = input && Object.prototype.hasOwnProperty.call(input, "manifest")
    ? ["target_domain", "session_nucleus_hash", "preflight", "manifest"]
    : ["target_domain", "session_nucleus_hash", "preflight"];
  const value = exactRecord(input, "physical campaign owner assurance context", allowed);
  if (value.target_domain !== state.domain || value.session_nucleus_hash !== state.nucleusHash) {
    throw ownerError("physical_campaign_owner_authority_drift", "assurance context session drifted");
  }
  return value;
}

function closureAttestationPayload(state, preflight, manifest, anchorHead, brokerState,
  terminalWitnessDigest, noActiveEffectsDigest) {
  return {
    version: OWNER_VERSION,
    target_domain: state.domain,
    session_nucleus_hash: state.nucleusHash,
    campaign_identity_version: PHYSICAL_CAMPAIGN_IDENTITY_VERSION,
    campaign_id: state.obligation.campaign_id,
    campaign_obligation_digest: state.obligation.obligation_digest,
    preflight_digest: preflight.preflight_digest,
    manifest_digest: manifest.manifest_digest,
    checkpoint_digest: manifest.checkpoint_digest,
    aggregate_closure_root: manifest.aggregate_closure_root,
    terminal_cells_merkle_root: manifest.terminal_cells_merkle_root,
    terminal_cell_count: manifest.terminal_cell_count,
    anchor_head_digest: anchorHead.head_digest,
    anchor_sequence: anchorHead.sequence,
    lease_broker_owner_state_digest: brokerState.owner_state_digest,
    lease_broker_generation: brokerState.generation,
    lease_broker_head_event_digest: brokerState.head_event_digest,
    terminal_witness_attestation_digest: terminalWitnessDigest,
    no_active_effects_attestation_digest: noActiveEffectsDigest,
  };
}

function issueClosureAttestation(state, payload) {
  const enriched = { ...payload, issued_at: new Date().toISOString() };
  const payloadDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-closure-attestation-payload/v1",
    ...enriched,
  });
  const signature = signDigest(state.key.privateKey, payloadDigest);
  return deepFreeze({
    ...enriched,
    payload_digest: payloadDigest,
    signature,
    closure_attestation_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-campaign-closure-attestation/v1",
      ...enriched,
      payload_digest: payloadDigest,
      signature,
    }),
  });
}

function normalizeClosureAttestation(input, state) {
  const fields = [
    "version", "target_domain", "session_nucleus_hash", "campaign_identity_version",
    "campaign_id", "campaign_obligation_digest", "preflight_digest", "manifest_digest",
    "checkpoint_digest", "aggregate_closure_root", "terminal_cells_merkle_root",
    "terminal_cell_count", "anchor_head_digest", "anchor_sequence",
    "lease_broker_owner_state_digest", "lease_broker_generation",
    "lease_broker_head_event_digest", "terminal_witness_attestation_digest",
    "no_active_effects_attestation_digest", "issued_at", "payload_digest", "signature",
    "closure_attestation_digest",
  ];
  const value = exactRecord(input, "physical campaign closure attestation", fields);
  const payload = Object.fromEntries(fields.slice(0, -3).map((field) => [field, value[field]]));
  const payloadDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-closure-attestation-payload/v1",
    ...payload,
  });
  const attestationDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-closure-attestation/v1",
    ...payload,
    payload_digest: payloadDigest,
    signature: value.signature,
  });
  if (value.version !== OWNER_VERSION || value.target_domain !== state.domain
      || value.session_nucleus_hash !== state.nucleusHash
      || value.campaign_id !== state.obligation.campaign_id
      || value.campaign_obligation_digest !== state.obligation.obligation_digest
      || digest(value.payload_digest, "closure payload digest") !== payloadDigest
      || digest(value.closure_attestation_digest, "closure attestation digest") !== attestationDigest
      || !verifyDigest(state.key.publicKey, payloadDigest, value.signature)) {
    throw ownerError("physical_campaign_owner_attestation_invalid", "closure attestation is invalid");
  }
  return deepFreeze({ ...payload, payload_digest: payloadDigest,
    signature: value.signature, closure_attestation_digest: attestationDigest });
}

function productionPhysicalCampaignAnchorAssurance(port, contextInput = null) {
  const state = ANCHOR_PORT_STATE.get(assertProductionPhysicalCampaignAnchorPort(port));
  const current = assertOwnerCurrent(state);
  if (current.custody.production_ready !== true) {
    return falseAssurance(
      state,
      "same_uid_external_owner_conformance_only_non_authorizing",
      "mechanism_a_campaign_closure_owner_unavailable",
    );
  }
  if (contextInput == null) {
    return falseAssurance(
      state,
      "mechanism_a_owner_requires_exact_v2_preflight",
      "physical_campaign_v2_preflight_not_finalized",
    );
  }
  const context = normalizeAssuranceContext(contextInput, state);
  const preflight = normalizePhysicalCampaignClosurePreflight(context.preflight);
  if (preflight.campaign_identity_version !== PHYSICAL_CAMPAIGN_IDENTITY_VERSION
      || preflight.campaign_id !== state.obligation.campaign_id
      || preflight.session_nucleus_hash !== state.nucleusHash
      || preflight.closure_signer_key_ref !== state.obligation.signer_key_ref
      || preflight.closure_signer_public_key_digest
        !== state.obligation.signer_public_key_digest) {
    return falseAssurance(
      state,
      "mechanism_a_owner_rejected_unbound_preflight",
      "physical_campaign_server_obligation_not_finalized",
    );
  }
  const heads = readHeads(state);
  const lastHead = heads.length === 0 ? null : heads.at(-1);
  const anchorAttestationDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-external-anchor-attestation/v1",
    campaign_obligation_digest: state.obligation.obligation_digest,
    owner_custody_digest: current.custody.custody_digest,
    external_owner_root_identity_digest: state.rootIdentityDigest,
    anchor_head_digest: lastHead == null ? null : lastHead.head_digest,
    anchor_sequence: lastHead == null ? 0 : lastHead.sequence,
  });
  const nucleus = currentNucleus(state);
  const nucleusAuthorityDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-nucleus-authority-attestation/v1",
    target_domain: state.domain,
    session_nucleus_hash: nucleus.nucleus_hash,
    authority_epoch: nucleus.physical_scope.authority_epoch,
    revocation_generation: nucleus.physical_scope.revocation_generation,
    campaign_obligation_digest: state.obligation.obligation_digest,
    preflight_digest: preflight.preflight_digest,
  });
  const signerEnrollmentDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-closure-signer-enrollment/v1",
    campaign_obligation_digest: state.obligation.obligation_digest,
    signer_key_ref: state.obligation.signer_key_ref,
    signer_public_key_digest: state.obligation.signer_public_key_digest,
    owner_custody_digest: current.custody.custody_digest,
  });
  const core = {
    anchor_assurance: "mechanism_a_isolated_owner_signed_monotonic_campaign_anchor",
    anchor_externality_attested: true,
    anchor_attestation_digest: anchorAttestationDigest,
    campaign_obligation_server_issued: true,
    campaign_obligation_digest: state.obligation.obligation_digest,
    physical_nucleus_authority_attested: true,
    physical_nucleus_authority_digest: nucleusAuthorityDigest,
    closure_signer_production_enrolled: true,
    closure_signer_enrollment_digest: signerEnrollmentDigest,
    anchor_slot_digest: state.obligation.anchor_slot_digest,
    local_anchor_role: "crash_journal_only",
  };
  if (!Object.prototype.hasOwnProperty.call(context, "manifest")) {
    return Object.freeze({
      ...core,
      terminal_witnesses_production_attested: false,
      terminal_witness_attestation_digest: null,
      no_active_effects_durably_attested: false,
      no_active_effects_attestation_digest: null,
      production_ready: false,
      production_blocker: "verified_terminal_manifest_and_zero_active_effects_required",
    });
  }
  const manifest = assertPhysicalCampaignClosureSatisfied(context.manifest);
  if (manifest.campaign_identity_version !== PHYSICAL_CAMPAIGN_IDENTITY_VERSION
      || manifest.campaign_id !== preflight.campaign_id
      || manifest.preflight_digest !== preflight.preflight_digest
      || lastHead == null || lastHead.anchor_state == null
      || lastHead.anchor_state.generation !== preflight.segment_count
      || lastHead.anchor_state.campaign_id !== preflight.campaign_id
      || lastHead.anchor_state.preflight_digest !== preflight.preflight_digest
      || lastHead.anchor_state.session_nucleus_hash !== preflight.session_nucleus_hash) {
    throw ownerError(
      "physical_campaign_owner_attestation_invalid",
      "verified manifest is not bound to the final external campaign head",
    );
  }
  const brokerState = readDurableInstrumentLeaseBrokerClosureState(state.leaseBrokerPort);
  if (brokerState.session_nucleus_hash !== state.nucleusHash
      || brokerState.active_effect_count !== 0) {
    throw ownerError(
      "physical_campaign_active_effects_remain",
      "durable lease owner does not attest zero active effects",
    );
  }
  const terminalWitnessDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-terminal-witness-attestation/v1",
    campaign_obligation_digest: state.obligation.obligation_digest,
    preflight_digest: preflight.preflight_digest,
    manifest_digest: manifest.manifest_digest,
    terminal_cells_merkle_root: manifest.terminal_cells_merkle_root,
    terminal_cell_count: manifest.terminal_cell_count,
    closure_signer_enrollment_digest: signerEnrollmentDigest,
  });
  const noActiveEffectsDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-zero-active-effects-attestation/v1",
    campaign_obligation_digest: state.obligation.obligation_digest,
    manifest_digest: manifest.manifest_digest,
    external_anchor_head_digest: lastHead.head_digest,
    lease_broker_owner_state_digest: brokerState.owner_state_digest,
    active_effect_count: brokerState.active_effect_count,
  });
  const desiredPayload = closureAttestationPayload(
    state,
    preflight,
    manifest,
    lastHead,
    brokerState,
    terminalWitnessDigest,
    noActiveEffectsDigest,
  );
  if (!fs.existsSync(state.paths.closure)) {
    writeExclusiveJson(state.paths.closure, issueClosureAttestation(state, desiredPayload), 0o600);
  }
  const closure = normalizeClosureAttestation(
    readPrivateJson(state.paths.closure, "physical campaign closure attestation", MAX_OWNER_BYTES, 0o600),
    state,
  );
  for (const [field, expected] of Object.entries(desiredPayload)) {
    if (closure[field] !== expected) {
      throw ownerError(
        "physical_campaign_owner_attestation_stale",
        `closure attestation ${field} no longer matches live authority`,
      );
    }
  }
  assertOwnerCurrent(state);
  return Object.freeze({
    ...core,
    terminal_witnesses_production_attested: true,
    terminal_witness_attestation_digest: terminalWitnessDigest,
    no_active_effects_durably_attested: true,
    no_active_effects_attestation_digest: noActiveEffectsDigest,
    production_ready: true,
    production_blocker: null,
  });
}

function rejectSerialization() {
  throw ownerError(
    "physical_campaign_owner_serialization_refused",
    "physical campaign owner capabilities are process-local",
  );
}

function openProductionPhysicalCampaignClosureOwner(input) {
  const values = exactRecord(input, "production physical campaign closure owner input", [
    "version", "target_domain", "session_nucleus_hash", "external_owner_root", "lease_broker_port",
  ]);
  if (values.version !== OWNER_VERSION) {
    throw ownerError("physical_campaign_owner_contract_invalid", "owner version must be 1");
  }
  const domain = assertSafeDomain(values.target_domain);
  const nucleusHash = digest(values.session_nucleus_hash, "session_nucleus_hash");
  const leaseBrokerPort = assertDurableInstrumentLeaseBrokerPort(values.lease_broker_port);
  if (typeof values.external_owner_root !== "string"
      || !path.isAbsolute(values.external_owner_root)
      || path.normalize(values.external_owner_root) !== values.external_owner_root) {
    throw ownerError(
      "physical_campaign_owner_contract_invalid",
      "external_owner_root must be a normalized absolute path",
    );
  }
  const rootStats = assertOwnedDirectory(values.external_owner_root, "physical campaign external owner root");
  const root = fs.realpathSync(values.external_owner_root);
  const sessionRoot = fs.realpathSync(sessionDir(domain));
  if (!disjointPaths(root, sessionRoot)) {
    throw ownerError(
      "physical_campaign_owner_storage_invalid",
      "external owner root must be disjoint from the local session and campaign root",
    );
  }
  const state = {
    domain,
    nucleusHash,
    leaseBrokerPort,
    paths: pathsFor(root),
    rootIdentityDigest: rootIdentity(root, rootStats),
    key: null,
    obligation: null,
  };
  currentNucleus(state);
  ensureOwnedDirectory(state.paths.heads, "physical campaign external head directory");
  state.key = readOrCreateKey(state.paths, domain, nucleusHash);
  state.obligation = readOrCreateObligation(state);
  const signer = createPhysicalCampaignEd25519SignerPort({
    signer_key_ref: state.obligation.signer_key_ref,
    private_key: state.key.privateKey,
  });
  const verifier = createPhysicalCampaignEd25519VerifierPort({
    signer_key_ref: state.obligation.signer_key_ref,
    public_key: state.key.publicKey,
  });
  const custody = liveCustody(state);
  let anchorPort = Object.create(null);
  Object.defineProperties(anchorPort, {
    version: { value: OWNER_VERSION, enumerable: true },
    kind: { value: ANCHOR_KIND, enumerable: true },
    anchor_slot_digest: { value: state.obligation.anchor_slot_digest, enumerable: true },
    production_ready: { value: custody.production_ready, enumerable: true },
    toJSON: { value: rejectSerialization },
  });
  anchorPort = Object.freeze(anchorPort);
  ANCHOR_PORTS.add(anchorPort);
  ANCHOR_PORT_STATE.set(anchorPort, state);
  let owner = Object.create(null);
  Object.defineProperties(owner, {
    version: { value: OWNER_VERSION, enumerable: true },
    kind: { value: OWNER_KIND, enumerable: true },
    target_domain: { value: domain, enumerable: true },
    session_nucleus_hash: { value: nucleusHash, enumerable: true },
    campaign_identity_version: { value: PHYSICAL_CAMPAIGN_IDENTITY_VERSION, enumerable: true },
    campaign_id: { value: state.obligation.campaign_id, enumerable: true },
    signer: { value: signer, enumerable: true },
    verifier: { value: verifier, enumerable: true },
    anchor_port: { value: anchorPort, enumerable: true },
    production_ready: { value: custody.production_ready, enumerable: true },
    toJSON: { value: rejectSerialization },
  });
  owner = Object.freeze(owner);
  OWNERS.add(owner);
  OWNER_STATE.set(owner, state);
  assertOwnerCurrent(state);
  readHeads(state);
  return owner;
}

function assertPhysicalCampaignClosureOwner(owner) {
  if (!owner || !OWNERS.has(owner) || !OWNER_STATE.has(owner) || !Object.isFrozen(owner)) {
    throw ownerError(
      "physical_campaign_owner_untrusted",
      "a live privately branded physical campaign closure owner is required",
    );
  }
  assertOwnerCurrent(OWNER_STATE.get(owner));
  return owner;
}

function assertProductionPhysicalCampaignClosureOwner(owner) {
  const current = assertPhysicalCampaignClosureOwner(owner);
  if (current.production_ready !== true
      || assertOwnerCurrent(OWNER_STATE.get(current)).custody.production_ready !== true) {
    throw ownerError(
      "physical_campaign_owner_not_production",
      "production campaign closure requires Mechanism-A isolated owner custody",
    );
  }
  return current;
}

function isProductionPhysicalCampaignAnchorPort(port) {
  return !!port && ANCHOR_PORTS.has(port) && ANCHOR_PORT_STATE.has(port) && Object.isFrozen(port);
}

function assertProductionPhysicalCampaignAnchorPort(port) {
  if (!isProductionPhysicalCampaignAnchorPort(port)) {
    throw ownerError(
      "physical_campaign_anchor_port_untrusted",
      "a genuine physical campaign owner anchor port is required",
    );
  }
  return port;
}

module.exports = Object.freeze({
  PHYSICAL_CAMPAIGN_CLOSURE_OWNER_VERSION: OWNER_VERSION,
  assertPhysicalCampaignClosureOwner,
  assertProductionPhysicalCampaignAnchorPort,
  assertProductionPhysicalCampaignClosureOwner,
  compareAndSetProductionPhysicalCampaignAnchor,
  isProductionPhysicalCampaignAnchorPort,
  openProductionPhysicalCampaignClosureOwner,
  productionPhysicalCampaignAnchorAssurance,
  readProductionPhysicalCampaignAnchor,
});
