"use strict";

// Durable, provider-neutral authority for ABI-v3 bootstrap observations. This
// store has its own event namespace and credentials; it never fabricates an
// active lease, resource reservation, workspace, snapshot, or fencing token.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const {
  INSTRUMENT_BOOTSTRAP_EVENT_KINDS,
  INSTRUMENT_BOOTSTRAP_PROVIDER_ABI_VERSION,
  INSTRUMENT_BOOTSTRAP_STORE_VERSION,
  INSTRUMENT_BOOTSTRAP_TERMINAL_STATES,
  INTENT_FIELDS,
  instrumentBootstrapProviderReportDigest,
  instrumentBootstrapRequestDigest,
  normalizeInstrumentBootstrapCommitRequest,
  normalizeInstrumentBootstrapDurableAmbiguity,
  normalizeInstrumentBootstrapMarkAmbiguousRequest,
  normalizeInstrumentBootstrapPrecommitRequest,
  normalizeInstrumentBootstrapProviderRedemptionRequest,
  normalizeInstrumentBootstrapProviderReport,
  normalizeInstrumentBootstrapRedemptionExpected,
  normalizeInstrumentBootstrapTerminalBinding,
  recoveryDispositionForState,
} = require("./instrument-bootstrap-contract.js");
const {
  normalizeOpaqueRef,
} = require("./physical-quantities.js");
const {
  canonicalJson,
  hashCanonicalJson,
} = require("./verification-contracts.js");

const STORE_VERSION = INSTRUMENT_BOOTSTRAP_STORE_VERSION;
const EVENT_DOMAIN = "hacker-bob/instrument-bootstrap-event/v1";
const ENVELOPE_DOMAIN = "hacker-bob/instrument-bootstrap-event-envelope/v1";
const KEY_INFO = "hacker-bob/instrument-bootstrap-store/aes-256-gcm/v1";
const RUNTIME_ID_PATTERN = /^physical-runtime:v1:[A-Za-z0-9._:@-]{8,190}$/;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const EVENT_FILE_PATTERN = /^([0-9]{12})\.bootstrap-event\.json$/;
const MAX_EVENTS = 16_384;
const MAX_EVENT_FILE_BYTES = 1024 * 1024;
const MAX_METADATA_BYTES = 32 * 1024;
const DEFAULT_ASYNC_OBSERVATION_TIMEOUT_MS = 120_000;
const MAX_ASYNC_OBSERVATION_TIMEOUT_MS = 7_200_000;

const DURABLE_STORES = new WeakSet();
const DURABLE_STORE_STATE = new WeakMap();
const BROKER_PORTS = new WeakSet();
const BROKER_PORT_STATE = new WeakMap();
const PROVIDER_PORTS = new WeakSet();
const PROVIDER_PORT_STATE = new WeakMap();
const DISPATCH_CREDENTIALS = new WeakSet();
const DISPATCH_CREDENTIAL_STATE = new WeakMap();
const OBSERVATION_PERMITS = new WeakSet();
const OBSERVATION_PERMIT_STATE = new WeakMap();
const OBSERVATION_COMPLETION_CAPABILITIES = new WeakSet();
const OBSERVATION_COMPLETION_CAPABILITY_STATE = new WeakMap();
const CUSTODY_BINDINGS = new WeakSet();
const CUSTODY_BINDING_STATE = new WeakMap();
const CUSTODY_PROJECTIONS = new WeakSet();
const CUSTODY_PROJECTION_STATE = new WeakMap();

// A custody binding wraps an already-approved provider-neutral custody object
// by exact in-process identity. Its random instance secret never leaves this
// module. Only a generation-specific digest is persisted, so durable lineage
// names no handle, path, serial, or device. This is a software authority seam,
// not evidence of native device ACLs, peer credentials, or HIL conformance.

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function cloneJson(value) {
  return value == null ? null : JSON.parse(JSON.stringify(value));
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || utilTypes.isProxy(value)
      || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(input, label, required, optional = []) {
  if (!isPlainObject(input)) throw new Error(`${label} must be a plain object`);
  const keys = Reflect.ownKeys(input);
  if (keys.some((field) => typeof field !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...required, ...optional]);
  const unknown = keys.filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((field) => !keys.includes(field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  const descriptors = Object.getOwnPropertyDescriptors(input);
  for (const field of keys) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw new Error(`${label}.${field} must be an enumerable data field`);
    }
  }
  return input;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertInteger(value, label, min = 0) {
  if (!Number.isSafeInteger(value) || value < min) {
    throw new Error(`${label} must be a safe integer >= ${min}`);
  }
  return value;
}

function assertCanonicalTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))
      || new Date(value).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC ISO-8601 timestamp`);
  }
  return value;
}

function assertPrivateDirectory(directory, label = "instrument bootstrap directory") {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`${label} must be a real directory`);
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    throw new Error(`${label} must be owned by the current user`);
  }
  if ((stat.mode & 0o077) !== 0) throw new Error(`${label} must not permit group/other access`);
  return Object.freeze({ dev: stat.dev, ino: stat.ino });
}

function assertDirectoryIdentity(directory, identity, label) {
  const current = assertPrivateDirectory(directory, label);
  if (current.dev !== identity.dev || current.ino !== identity.ino) {
    throw new Error(`${label} identity changed while the store was open`);
  }
}

function fsyncDirectory(directory) {
  const fd = fs.openSync(directory, fs.constants.O_RDONLY);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function publishExclusiveDurable(filePath, buffer) {
  let fd;
  try {
    fd = fs.openSync(filePath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
  } catch (error) {
    if (error && error.code === "EEXIST") return false;
    throw error;
  }
  try {
    let offset = 0;
    while (offset < buffer.length) offset += fs.writeSync(fd, buffer, offset);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fsyncDirectory(path.dirname(filePath));
  return true;
}

function readPrivateFile(filePath, label, maxBytes) {
  const before = fs.lstatSync(filePath);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) {
    throw new Error(`${label} must be a single-link regular file`);
  }
  if (typeof process.getuid === "function" && before.uid !== process.getuid()) {
    throw new Error(`${label} must be owned by the current user`);
  }
  if ((before.mode & 0o077) !== 0 || before.size < 1 || before.size > maxBytes) {
    throw new Error(`${label} has unsafe permissions or size`);
  }
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1
        || opened.dev !== before.dev || opened.ino !== before.ino
        || opened.size !== before.size) {
      throw new Error(`${label} identity changed while opening`);
    }
    const buffer = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < buffer.length) {
      const count = fs.readSync(fd, buffer, offset, buffer.length - offset, offset);
      if (count === 0) throw new Error(`${label} ended before its declared size`);
      offset += count;
    }
    const after = fs.fstatSync(fd);
    const livePath = fs.lstatSync(filePath);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.nlink !== 1
        || after.size !== opened.size || livePath.dev !== opened.dev
        || livePath.ino !== opened.ino || livePath.nlink !== 1) {
      buffer.fill(0);
      throw new Error(`${label} identity changed while reading`);
    }
    return buffer;
  } finally {
    fs.closeSync(fd);
  }
}

function normalizeMetadata(input, sessionNucleusHash, runtimeId) {
  assertClosedObject(input, "instrument bootstrap metadata", [
    "version",
    "runtime_id",
    "session_nucleus_hash",
    "kdf_salt",
    "created_at",
  ]);
  if (input.version !== STORE_VERSION || input.runtime_id !== runtimeId
      || input.session_nucleus_hash !== sessionNucleusHash) {
    throw new Error("instrument bootstrap metadata binding drift");
  }
  const salt = Buffer.from(input.kdf_salt, "base64");
  if (salt.length !== 32 || salt.toString("base64") !== input.kdf_salt) {
    throw new Error("instrument bootstrap metadata kdf_salt is invalid");
  }
  salt.fill(0);
  return deepFreeze({
    version: STORE_VERSION,
    runtime_id: runtimeId,
    session_nucleus_hash: assertDigest(sessionNucleusHash, "sessionNucleusHash"),
    kdf_salt: input.kdf_salt,
    created_at: assertCanonicalTimestamp(input.created_at, "instrument bootstrap metadata.created_at"),
  });
}

function deriveStoreKey(masterKey, metadata) {
  return Buffer.from(crypto.hkdfSync(
    "sha256",
    masterKey,
    Buffer.from(metadata.kdf_salt, "base64"),
    Buffer.from(`${KEY_INFO}\0${metadata.runtime_id}\0${metadata.session_nucleus_hash}`, "utf8"),
    32,
  ));
}

function anchorContext(metadata) {
  return Object.freeze({
    version: STORE_VERSION,
    domain: "hacker-bob/instrument-bootstrap-state-anchor/v1",
    runtime_id: metadata.runtime_id,
    session_nucleus_hash: metadata.session_nucleus_hash,
  });
}

function normalizeAnchor(input, metadata) {
  if (input == null) return null;
  assertClosedObject(input, "instrument bootstrap state anchor", [
    "version",
    "runtime_id",
    "session_nucleus_hash",
    "generation",
    "head_event_digest",
  ]);
  if (input.version !== STORE_VERSION || input.runtime_id !== metadata.runtime_id
      || input.session_nucleus_hash !== metadata.session_nucleus_hash
      || !Number.isSafeInteger(input.generation) || input.generation < 1) {
    throw new Error("instrument bootstrap state anchor binding drift");
  }
  return deepFreeze({
    version: STORE_VERSION,
    runtime_id: metadata.runtime_id,
    session_nucleus_hash: metadata.session_nucleus_hash,
    generation: input.generation,
    head_event_digest: assertDigest(input.head_event_digest, "anchor.head_event_digest"),
  });
}

function anchorFor(metadata, generation, headEventDigest) {
  if (generation === 0) return null;
  return deepFreeze({
    version: STORE_VERSION,
    runtime_id: metadata.runtime_id,
    session_nucleus_hash: metadata.session_nucleus_hash,
    generation,
    head_event_digest: headEventDigest,
  });
}

function sameAnchor(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function eventAad(metadata, generation, eventDigest) {
  return Buffer.from(canonicalJson({
    domain: ENVELOPE_DOMAIN,
    version: STORE_VERSION,
    runtime_id: metadata.runtime_id,
    session_nucleus_hash: metadata.session_nucleus_hash,
    generation,
    event_digest: eventDigest,
  }), "utf8");
}

function encryptEvent(storeKey, metadata, event) {
  const eventDigest = hashCanonicalJson(event);
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", storeKey, nonce);
  const aad = eventAad(metadata, event.generation, eventDigest);
  cipher.setAAD(aad);
  const plaintext = Buffer.from(canonicalJson(event), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  plaintext.fill(0);
  aad.fill(0);
  const envelope = {
    version: STORE_VERSION,
    domain: ENVELOPE_DOMAIN,
    runtime_id: metadata.runtime_id,
    session_nucleus_hash: metadata.session_nucleus_hash,
    generation: event.generation,
    event_digest: eventDigest,
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    authentication_tag: tag.toString("base64"),
  };
  nonce.fill(0);
  ciphertext.fill(0);
  tag.fill(0);
  return deepFreeze(envelope);
}

function decryptEvent(storeKey, metadata, envelope) {
  assertClosedObject(envelope, "instrument bootstrap event envelope", [
    "version",
    "domain",
    "runtime_id",
    "session_nucleus_hash",
    "generation",
    "event_digest",
    "nonce",
    "ciphertext",
    "authentication_tag",
  ]);
  if (envelope.version !== STORE_VERSION || envelope.domain !== ENVELOPE_DOMAIN
      || envelope.runtime_id !== metadata.runtime_id
      || envelope.session_nucleus_hash !== metadata.session_nucleus_hash
      || !Number.isSafeInteger(envelope.generation) || envelope.generation < 1) {
    throw new Error("instrument bootstrap event envelope binding drift");
  }
  const eventDigest = assertDigest(envelope.event_digest, "event envelope.event_digest");
  const nonce = Buffer.from(envelope.nonce, "base64");
  const ciphertext = Buffer.from(envelope.ciphertext, "base64");
  const tag = Buffer.from(envelope.authentication_tag, "base64");
  if (nonce.length !== 12 || tag.length !== 16) throw new Error("instrument bootstrap envelope encoding invalid");
  const aad = eventAad(metadata, envelope.generation, eventDigest);
  let plaintext;
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", storeKey, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const event = JSON.parse(plaintext.toString("utf8"));
    if (hashCanonicalJson(event) !== eventDigest || event.generation !== envelope.generation) {
      throw new Error("instrument bootstrap event digest drift");
    }
    return event;
  } finally {
    nonce.fill(0);
    ciphertext.fill(0);
    tag.fill(0);
    aad.fill(0);
    if (plaintext) plaintext.fill(0);
  }
}

function rejectCredentialSerialization() {
  throw new Error("instrument bootstrap dispatch credential is not serializable");
}

function rejectCompletionCapabilitySerialization() {
  throw new Error("instrument bootstrap observation completion capability is not serializable");
}

function rejectCustodyCapabilitySerialization() {
  throw new Error("instrument bootstrap custody capability is not serializable");
}

function attemptDigest(attempt) {
  const basis = { ...attempt };
  delete basis.attempt_digest;
  delete basis.recovery_disposition;
  return hashCanonicalJson({
    domain: "hacker-bob/instrument-bootstrap-attempt-head/v1",
    ...basis,
  });
}

function finalizeAttempt(attemptInput) {
  const basis = cloneJson(attemptInput);
  delete basis.attempt_digest;
  delete basis.recovery_disposition;
  return deepFreeze({
    ...basis,
    recovery_disposition: recoveryDispositionForState(basis.state),
    attempt_digest: attemptDigest(basis),
  });
}

function emptyProjection() {
  return {
    generation: 0,
    head_event_digest: null,
    attempts: new Map(),
    signed_grants: new Map(),
    execution_requests: new Map(),
    replay_receipts: new Map(),
  };
}

function requestBindingFor(attempt) {
  if (!attempt.dispatch) throw new Error("bootstrap attempt has no dispatch binding");
  return {
    version: STORE_VERSION,
    provider_abi_version: attempt.provider_abi_version,
    ...Object.fromEntries(
      INTENT_FIELDS.map((field) => [field, attempt[field]]),
    ),
    bootstrap_intent_digest: attempt.bootstrap_intent_digest,
    bootstrap_grant_projection_digest: attempt.bootstrap_grant_projection_digest,
    custody_binding_digest: attempt.custody_binding_digest,
    durable_attempt_binding_digest: attempt.durable_attempt_binding_digest,
    dispatch_record_digest: attempt.dispatch.dispatch_record_digest,
    bootstrap_request_digest: attempt.dispatch.bootstrap_request_digest,
  };
}

function normalizeDispatchRecord(input, attempt, label = "instrument_bootstrap_dispatch_record") {
  assertClosedObject(input, label, [
    "version",
    "attempt_ref",
    "durable_attempt_binding_digest",
    "bootstrap_intent_digest",
    "custody_binding_digest",
    "connection_ref",
    "connection_generation",
    "committed_at",
    "dispatch_record_digest",
    "bootstrap_request_digest",
  ]);
  if (input.version !== STORE_VERSION || input.attempt_ref !== attempt.attempt_ref
      || input.durable_attempt_binding_digest !== attempt.durable_attempt_binding_digest
      || input.bootstrap_intent_digest !== attempt.bootstrap_intent_digest
      || input.custody_binding_digest !== attempt.custody_binding_digest
      || input.connection_ref !== attempt.connection_ref
      || input.connection_generation !== attempt.connection_generation) {
    throw new Error(`${label} binding drift`);
  }
  const basis = {
    version: STORE_VERSION,
    attempt_ref: attempt.attempt_ref,
    durable_attempt_binding_digest: attempt.durable_attempt_binding_digest,
    bootstrap_intent_digest: attempt.bootstrap_intent_digest,
    custody_binding_digest: attempt.custody_binding_digest,
    connection_ref: attempt.connection_ref,
    connection_generation: attempt.connection_generation,
    committed_at: assertCanonicalTimestamp(input.committed_at, `${label}.committed_at`),
  };
  const dispatchRecordDigest = hashCanonicalJson({
    domain: "hacker-bob/instrument-bootstrap-dispatch/v1",
    ...basis,
  });
  if (assertDigest(input.dispatch_record_digest, `${label}.dispatch_record_digest`)
      !== dispatchRecordDigest) throw new Error(`${label}.dispatch_record_digest drift`);
  const bootstrapRequestDigest = instrumentBootstrapRequestDigest({
    ...Object.fromEntries(
      INTENT_FIELDS.map((field) => [field, attempt[field]]),
    ),
    bootstrap_intent_digest: attempt.bootstrap_intent_digest,
    dispatch_record_digest: dispatchRecordDigest,
  });
  if (assertDigest(input.bootstrap_request_digest, `${label}.bootstrap_request_digest`)
      !== bootstrapRequestDigest) throw new Error(`${label}.bootstrap_request_digest drift`);
  return deepFreeze({ ...basis, dispatch_record_digest: dispatchRecordDigest, bootstrap_request_digest: bootstrapRequestDigest });
}

function createDispatchRecord(attempt, committedAt) {
  const basis = {
    version: STORE_VERSION,
    attempt_ref: attempt.attempt_ref,
    durable_attempt_binding_digest: attempt.durable_attempt_binding_digest,
    bootstrap_intent_digest: attempt.bootstrap_intent_digest,
    custody_binding_digest: attempt.custody_binding_digest,
    connection_ref: attempt.connection_ref,
    connection_generation: attempt.connection_generation,
    committed_at: committedAt,
  };
  const dispatchRecordDigest = hashCanonicalJson({
    domain: "hacker-bob/instrument-bootstrap-dispatch/v1",
    ...basis,
  });
  const bootstrapRequestDigest = instrumentBootstrapRequestDigest({
    ...Object.fromEntries(
      INTENT_FIELDS.map((field) => [field, attempt[field]]),
    ),
    bootstrap_intent_digest: attempt.bootstrap_intent_digest,
    dispatch_record_digest: dispatchRecordDigest,
  });
  return deepFreeze({ ...basis, dispatch_record_digest: dispatchRecordDigest, bootstrap_request_digest: bootstrapRequestDigest });
}

function normalizeRedemptionRecord(input, attempt, label = "instrument_bootstrap_redemption") {
  assertClosedObject(input, label, [
    "version",
    "attempt_ref",
    "dispatch_record_digest",
    "bootstrap_request_digest",
    "custody_binding_digest",
    "connection_ref",
    "connection_generation",
    "redeemed_at",
    "dispatch_redemption_digest",
  ]);
  if (!attempt.dispatch || input.version !== STORE_VERSION || input.attempt_ref !== attempt.attempt_ref
      || input.dispatch_record_digest !== attempt.dispatch.dispatch_record_digest
      || input.bootstrap_request_digest !== attempt.dispatch.bootstrap_request_digest
      || input.custody_binding_digest !== attempt.custody_binding_digest
      || input.connection_ref !== attempt.connection_ref
      || input.connection_generation !== attempt.connection_generation) {
    throw new Error(`${label} binding drift`);
  }
  const basis = {
    version: STORE_VERSION,
    attempt_ref: attempt.attempt_ref,
    dispatch_record_digest: attempt.dispatch.dispatch_record_digest,
    bootstrap_request_digest: attempt.dispatch.bootstrap_request_digest,
    custody_binding_digest: attempt.custody_binding_digest,
    connection_ref: attempt.connection_ref,
    connection_generation: attempt.connection_generation,
    redeemed_at: assertCanonicalTimestamp(input.redeemed_at, `${label}.redeemed_at`),
  };
  const digest = hashCanonicalJson({
    domain: "hacker-bob/instrument-bootstrap-dispatch-redemption/v1",
    ...basis,
  });
  if (assertDigest(input.dispatch_redemption_digest, `${label}.dispatch_redemption_digest`) !== digest) {
    throw new Error(`${label}.dispatch_redemption_digest drift`);
  }
  return deepFreeze({ ...basis, dispatch_redemption_digest: digest });
}

function createRedemptionRecord(attempt, redeemedAt) {
  const basis = {
    version: STORE_VERSION,
    attempt_ref: attempt.attempt_ref,
    dispatch_record_digest: attempt.dispatch.dispatch_record_digest,
    bootstrap_request_digest: attempt.dispatch.bootstrap_request_digest,
    custody_binding_digest: attempt.custody_binding_digest,
    connection_ref: attempt.connection_ref,
    connection_generation: attempt.connection_generation,
    redeemed_at: redeemedAt,
  };
  return deepFreeze({
    ...basis,
    dispatch_redemption_digest: hashCanonicalJson({
      domain: "hacker-bob/instrument-bootstrap-dispatch-redemption/v1",
      ...basis,
    }),
  });
}

function providerRedemptionProjection(redemption) {
  return deepFreeze({
    attempt_ref: redemption.attempt_ref,
    dispatch_record_digest: redemption.dispatch_record_digest,
    bootstrap_request_digest: redemption.bootstrap_request_digest,
    custody_binding_digest: redemption.custody_binding_digest,
    connection_ref: redemption.connection_ref,
    connection_generation: redemption.connection_generation,
    redeemed_at: redemption.redeemed_at,
    dispatch_redemption_digest: redemption.dispatch_redemption_digest,
  });
}

function applyEvent(projection, event) {
  assertClosedObject(event, "instrument bootstrap event", [
    "version",
    "domain",
    "runtime_id",
    "session_nucleus_hash",
    "generation",
    "previous_event_digest",
    "kind",
    "payload",
    "recorded_at",
  ]);
  if (event.version !== STORE_VERSION || event.domain !== EVENT_DOMAIN
      || event.generation !== projection.generation + 1
      || event.previous_event_digest !== projection.head_event_digest
      || !INSTRUMENT_BOOTSTRAP_EVENT_KINDS.includes(event.kind)) {
    throw new Error("instrument bootstrap event chain or kind drift");
  }
  assertCanonicalTimestamp(event.recorded_at, "instrument bootstrap event.recorded_at");
  const eventDigest = hashCanonicalJson(event);
  if (event.kind === "bootstrap_attempt_precommitted") {
    const precommit = normalizeInstrumentBootstrapPrecommitRequest(event.payload);
    if (projection.attempts.has(precommit.attempt_ref)) throw new Error("bootstrap attempt already exists");
    for (const [map, key, label] of [
      [projection.signed_grants, precommit.signed_grant_digest, "signed grant"],
      [projection.execution_requests, precommit.execution_request_digest, "execution request"],
      [projection.replay_receipts, precommit.replay_reservation_receipt_digest, "replay receipt"],
    ]) {
      if (map.has(key)) throw new Error(`bootstrap ${label} is already bound to another attempt`);
      map.set(key, precommit.attempt_ref);
    }
    projection.attempts.set(precommit.attempt_ref, finalizeAttempt({
      version: STORE_VERSION,
      ...precommit,
      state: "precommitted",
      sequence: 1,
      dispatch: null,
      redemption: null,
      provider_report: null,
      provider_report_digest: null,
      terminal_binding: null,
      durable_ambiguity: null,
      terminal_reason_code: null,
      last_event_digest: eventDigest,
    }));
  } else {
    if (!isPlainObject(event.payload) || typeof event.payload.attempt_ref !== "string") {
      throw new Error("instrument bootstrap transition payload lacks attempt_ref");
    }
    const previous = projection.attempts.get(event.payload.attempt_ref);
    if (!previous) throw new Error("instrument bootstrap transition references unknown attempt");
    let next;
    if (event.kind === "bootstrap_dispatch_committed") {
      if (previous.state !== "precommitted") throw new Error("bootstrap dispatch requires precommitted");
      const dispatch = normalizeDispatchRecord(event.payload.dispatch, previous);
      next = { ...previous, state: "dispatch_committed", dispatch };
    } else if (event.kind === "bootstrap_dispatch_redeemed") {
      if (previous.state !== "dispatch_committed") throw new Error("bootstrap redemption requires dispatch_committed");
      const redemption = normalizeRedemptionRecord(event.payload.redemption, previous);
      next = { ...previous, state: "redeemed", redemption };
    } else if (event.kind === "bootstrap_attempt_completed") {
      if (previous.state !== "redeemed") throw new Error("bootstrap completion requires redeemed");
      const request = requestBindingFor(previous);
      const report = normalizeInstrumentBootstrapProviderReport(event.payload.provider_report, request);
      if (!previous.redemption || report.dispatch_redemption_digest
          !== previous.redemption.dispatch_redemption_digest
          || !["succeeded", "refused_no_effect"].includes(report.outcome)) {
        throw new Error("bootstrap completion report drift");
      }
      const terminal = normalizeInstrumentBootstrapTerminalBinding(
        event.payload.terminal_binding,
        report,
        request,
      );
      next = {
        ...previous,
        state: report.outcome,
        provider_report: report,
        provider_report_digest: instrumentBootstrapProviderReportDigest(report, request),
        terminal_binding: terminal,
        terminal_reason_code: event.payload.reason_code == null
          ? null
          : assertIdentifier(event.payload.reason_code, "bootstrap completion reason_code"),
      };
    } else if (event.payload.kind === "provider_report") {
      if (previous.state !== "redeemed") throw new Error("provider ambiguity requires redeemed");
      const request = requestBindingFor(previous);
      const report = normalizeInstrumentBootstrapProviderReport(event.payload.provider_report, request);
      if (report.outcome !== "ambiguous" || !previous.redemption
          || report.dispatch_redemption_digest !== previous.redemption.dispatch_redemption_digest) {
        throw new Error("bootstrap provider ambiguity report drift");
      }
      const terminal = normalizeInstrumentBootstrapTerminalBinding(
        event.payload.terminal_binding,
        report,
        request,
      );
      next = {
        ...previous,
        state: "ambiguous",
        provider_report: report,
        provider_report_digest: instrumentBootstrapProviderReportDigest(report, request),
        terminal_binding: terminal,
        terminal_reason_code: assertIdentifier(
          event.payload.reason_code,
          "bootstrap ambiguity reason_code",
        ),
      };
    } else {
      if (!["dispatch_committed", "redeemed"].includes(previous.state)) {
        throw new Error("durable bootstrap ambiguity requires an in-flight attempt");
      }
      const ambiguity = normalizeInstrumentBootstrapDurableAmbiguity(event.payload.durable_ambiguity);
      if (ambiguity.attempt_ref !== previous.attempt_ref
          || ambiguity.durable_attempt_binding_digest !== previous.durable_attempt_binding_digest
          || ambiguity.custody_binding_digest !== previous.custody_binding_digest
          || !previous.dispatch
          || ambiguity.dispatch_record_digest !== previous.dispatch.dispatch_record_digest
          || ambiguity.dispatch_redemption_digest !== (previous.redemption
            ? previous.redemption.dispatch_redemption_digest : null)) {
        throw new Error("durable bootstrap ambiguity binding drift");
      }
      next = {
        ...previous,
        state: "ambiguous",
        durable_ambiguity: ambiguity,
        terminal_reason_code: ambiguity.reason_code,
      };
    }
    delete next.attempt_digest;
    delete next.recovery_disposition;
    next.sequence = previous.sequence + 1;
    next.last_event_digest = eventDigest;
    projection.attempts.set(previous.attempt_ref, finalizeAttempt(next));
  }
  projection.generation = event.generation;
  projection.head_event_digest = eventDigest;
}

function publicAttempt(attempt) {
  return deepFreeze(cloneJson(attempt));
}

function publicProjection(projection) {
  return deepFreeze({
    version: STORE_VERSION,
    generation: projection.generation,
    head_event_digest: projection.head_event_digest,
    attempts: [...projection.attempts.values()]
      .sort((left, right) => left.attempt_ref.localeCompare(right.attempt_ref))
      .map(publicAttempt),
  });
}

function callSynchronous(callback, argument, label) {
  let result;
  try { result = callback(deepFreeze(cloneJson(argument))); } catch (cause) {
    const error = new Error(`${label} failed`);
    Object.defineProperty(error, "cause", { value: cause });
    throw error;
  }
  if (result && (typeof result === "object" || typeof result === "function")
      && typeof result.then === "function") {
    throw new Error(`${label} must be synchronous`);
  }
  return result;
}

function createDurableInstrumentBootstrapStore({
  root,
  runtimeId,
  sessionNucleusHash,
  masterKey,
  stateAnchor,
  now = () => new Date(),
} = {}) {
  if (typeof root !== "string" || !path.isAbsolute(root)) {
    throw new Error("instrument bootstrap store root must be an absolute path");
  }
  if (typeof runtimeId !== "string" || !RUNTIME_ID_PATTERN.test(runtimeId)) {
    throw new Error("runtimeId must be an enrolled physical-runtime:v1 identity");
  }
  assertDigest(sessionNucleusHash, "sessionNucleusHash");
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) {
    throw new Error("masterKey must be a 32-byte Buffer supplied outside the store filesystem");
  }
  if (!stateAnchor || typeof stateAnchor.readState !== "function"
      || typeof stateAnchor.compareAndSet !== "function") {
    throw new Error("stateAnchor must provide readState and compareAndSet");
  }
  if (typeof now !== "function") throw new Error("now must be a function");
  const rootIdentity = assertPrivateDirectory(root, "instrument bootstrap store root");
  const eventsRoot = path.join(root, "bootstrap-events");
  if (!fs.existsSync(eventsRoot)) {
    fs.mkdirSync(eventsRoot, { mode: 0o700 });
    fsyncDirectory(root);
  }
  const eventsIdentity = assertPrivateDirectory(eventsRoot, "instrument bootstrap events directory");
  const metadataPath = path.join(root, "bootstrap-runtime.json");
  let metadata;
  let lastNowMs = null;

  function nowIso() {
    const value = now();
    if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
      throw new Error("instrument bootstrap store clock returned an invalid Date");
    }
    if (lastNowMs != null && value.getTime() < lastNowMs) {
      throw new Error("instrument bootstrap store clock moved backwards");
    }
    lastNowMs = value.getTime();
    return value.toISOString();
  }

  if (fs.existsSync(metadataPath)) {
    const buffer = readPrivateFile(metadataPath, "instrument bootstrap metadata", MAX_METADATA_BYTES);
    try { metadata = normalizeMetadata(JSON.parse(buffer.toString("utf8")), sessionNucleusHash, runtimeId); }
    finally { buffer.fill(0); }
  } else {
    if (fs.readdirSync(eventsRoot).some((name) => EVENT_FILE_PATTERN.test(name))) {
      throw new Error("instrument bootstrap events exist without metadata");
    }
    const candidate = {
      version: STORE_VERSION,
      runtime_id: runtimeId,
      session_nucleus_hash: sessionNucleusHash,
      kdf_salt: crypto.randomBytes(32).toString("base64"),
      created_at: nowIso(),
    };
    const encoded = Buffer.from(`${canonicalJson(candidate)}\n`, "utf8");
    const published = publishExclusiveDurable(metadataPath, encoded);
    encoded.fill(0);
    if (!published) throw new Error("instrument bootstrap metadata was concurrently created");
    metadata = normalizeMetadata(candidate, sessionNucleusHash, runtimeId);
  }
  const keyMaterial = Buffer.from(masterKey);
  const storeKey = deriveStoreKey(keyMaterial, metadata);
  keyMaterial.fill(0);
  const context = anchorContext(metadata);
  let closed = false;
  let busy = false;
  let cached = null;
  const activeObservationCompletions = new Set();
  const activeAttemptCustodyBindings = new Map();
  const custodyAuthorityBindings = new WeakMap();

  function assertOpen() {
    if (closed) throw new Error("instrument bootstrap store is closed");
    assertDirectoryIdentity(root, rootIdentity, "instrument bootstrap store root");
    assertDirectoryIdentity(eventsRoot, eventsIdentity, "instrument bootstrap events directory");
  }

  function custodyProjectionBasis(sample) {
    return {
      version: STORE_VERSION,
      connection_ref: normalizeOpaqueRef(
        sample.connection_ref,
        "instrument bootstrap custody connection_ref",
        { prefix: "instrument-connection" },
      ),
      connection_generation: assertInteger(
        sample.connection_generation,
        "instrument bootstrap custody connection_generation",
        1,
      ),
    };
  }

  function sampleCustodyBinding(bindingState) {
    assertOpen();
    const sample = callSynchronous(
      bindingState.read_connection_generation,
      {
        version: STORE_VERSION,
        purpose: "bootstrap_custody_projection",
      },
      "instrument bootstrap custody generation read",
    );
    assertClosedObject(sample, "instrument bootstrap custody generation", [
      "connection_ref",
      "connection_generation",
      "connected",
    ]);
    if (typeof sample.connected !== "boolean") {
      throw new Error("instrument bootstrap custody generation.connected must be boolean");
    }
    const basis = custodyProjectionBasis(sample);
    assertOpen();
    return Object.freeze({
      ...basis,
      connected: sample.connected,
      custody_binding_digest: hashCanonicalJson({
        domain: "hacker-bob/instrument-bootstrap-custody-connection/v1",
        custody_instance_digest: bindingState.custody_instance_digest,
        connection_ref: basis.connection_ref,
        connection_generation: basis.connection_generation,
      }),
    });
  }

  function createCustodyBinding(input) {
    assertOpen();
    assertClosedObject(input, "instrument bootstrap custody binding", [
      "custody_authority",
      "read_connection_generation",
    ]);
    const authority = input.custody_authority;
    if (!authority || typeof authority !== "object" || utilTypes.isProxy(authority)
        || !Object.isFrozen(authority)) {
      throw new Error("instrument bootstrap custody authority must be an exact frozen object");
    }
    if (typeof input.read_connection_generation !== "function") {
      throw new Error("instrument bootstrap custody read_connection_generation must be a function");
    }
    if (custodyAuthorityBindings.has(authority)) {
      throw new Error("instrument bootstrap custody authority is already bound by this store");
    }
    const nonce = crypto.randomBytes(32);
    let custodyInstanceDigest;
    try {
      custodyInstanceDigest = hashCanonicalJson({
        domain: "hacker-bob/instrument-bootstrap-custody-instance/v1",
        runtime_id: metadata.runtime_id,
        session_nucleus_hash: metadata.session_nucleus_hash,
        nonce: nonce.toString("hex"),
      });
    } finally {
      nonce.fill(0);
    }
    const binding = Object.create(null);
    Object.defineProperties(binding, {
      version: { value: STORE_VERSION, enumerable: true },
      kind: { value: "instrument_bootstrap_custody_binding", enumerable: true },
      toJSON: { value: rejectCustodyCapabilitySerialization },
    });
    Object.freeze(binding);
    const bindingState = {
      store,
      authority,
      read_connection_generation: input.read_connection_generation,
      custody_instance_digest: custodyInstanceDigest,
    };
    CUSTODY_BINDINGS.add(binding);
    CUSTODY_BINDING_STATE.set(binding, bindingState);
    custodyAuthorityBindings.set(authority, binding);
    return binding;
  }

  function readCustodyProjection(binding) {
    const bindingState = binding == null ? null : CUSTODY_BINDING_STATE.get(binding);
    if (!binding || !CUSTODY_BINDINGS.has(binding) || !bindingState
        || bindingState.store !== store || !Object.isFrozen(binding)) {
      throw new Error("instrument bootstrap custody binding was not issued by this live store");
    }
    const sample = sampleCustodyBinding(bindingState);
    const projection = Object.create(null);
    for (const [field, value] of Object.entries({
      version: STORE_VERSION,
      kind: "instrument_bootstrap_custody_projection",
      connection_ref: sample.connection_ref,
      connection_generation: sample.connection_generation,
      connected: sample.connected,
      custody_binding_digest: sample.custody_binding_digest,
    })) {
      Object.defineProperty(projection, field, { value, enumerable: true });
    }
    Object.defineProperty(projection, "toJSON", {
      value: rejectCustodyCapabilitySerialization,
    });
    Object.freeze(projection);
    CUSTODY_PROJECTIONS.add(projection);
    CUSTODY_PROJECTION_STATE.set(projection, { store, binding });
    return projection;
  }

  function assertLiveCustodyBinding(binding, { requireConnected = true } = {}) {
    const bindingState = binding == null ? null : CUSTODY_BINDING_STATE.get(binding);
    if (!binding || !CUSTODY_BINDINGS.has(binding) || !bindingState
        || bindingState.store !== store || !Object.isFrozen(binding)) {
      throw new Error("instrument bootstrap custody binding was not issued by this live store");
    }
    const current = sampleCustodyBinding(bindingState);
    if (requireConnected && current.connected !== true) {
      throw new Error("instrument bootstrap custody binding is not connected");
    }
    return Object.freeze({
      binding,
      connection_ref: current.connection_ref,
      connection_generation: current.connection_generation,
      custody_binding_digest: current.custody_binding_digest,
    });
  }

  function assertLiveCustodyProjection(projection, { requireConnected = true } = {}) {
    const projectionState = projection == null ? null : CUSTODY_PROJECTION_STATE.get(projection);
    if (!projection || !CUSTODY_PROJECTIONS.has(projection) || !projectionState
        || projectionState.store !== store || !Object.isFrozen(projection)) {
      throw new Error("instrument bootstrap custody projection was not issued by this live store");
    }
    const bindingState = CUSTODY_BINDING_STATE.get(projectionState.binding);
    if (!bindingState || bindingState.store !== store) {
      throw new Error("instrument bootstrap custody projection lost its exact binding");
    }
    const current = sampleCustodyBinding(bindingState);
    for (const field of [
      "connection_ref",
      "connection_generation",
      "connected",
      "custody_binding_digest",
    ]) {
      if (projection[field] !== current[field]) {
        throw new Error(`instrument bootstrap custody projection ${field} drifted`);
      }
    }
    if (requireConnected && current.connected !== true) {
      throw new Error("instrument bootstrap custody projection is not connected");
    }
    return Object.freeze({
      binding: projectionState.binding,
      connection_ref: current.connection_ref,
      connection_generation: current.connection_generation,
      custody_binding_digest: current.custody_binding_digest,
    });
  }

  function readAnchor() {
    const result = callSynchronous(
      stateAnchor.readState.bind(stateAnchor),
      context,
      "instrument bootstrap state anchor read",
    );
    return normalizeAnchor(result, metadata);
  }

  function commitAnchor(expected, next) {
    let result;
    let failure = null;
    try {
      result = callSynchronous(
        stateAnchor.compareAndSet.bind(stateAnchor),
        {
          ...context,
          expected_generation: expected == null ? null : expected.generation,
          expected_head_event_digest: expected == null ? null : expected.head_event_digest,
          next_state: next,
        },
        "instrument bootstrap state anchor compareAndSet",
      );
    } catch (error) { failure = error; }
    let observed = null;
    try { observed = readAnchor(); } catch (error) { if (!failure) failure = error; }
    if (observed && sameAnchor(observed, next)) return;
    if (result === true && observed == null && next == null) return;
    const error = new Error("instrument bootstrap external anchor commit outcome is ambiguous");
    Object.defineProperty(error, "cause", { value: failure });
    Object.defineProperty(error, "anchor_commit_outcome", { value: "ambiguous" });
    throw error;
  }

  function loadProjection({ reconcile = true } = {}) {
    assertOpen();
    const names = fs.readdirSync(eventsRoot).filter((name) => EVENT_FILE_PATTERN.test(name)).sort();
    if (names.length > MAX_EVENTS) throw new Error(`instrument bootstrap event count exceeds ${MAX_EVENTS}`);
    const projection = emptyProjection();
    let lastEventPreviousDigest = null;
    for (let index = 0; index < names.length; index += 1) {
      const match = EVENT_FILE_PATTERN.exec(names[index]);
      if (!match || Number(match[1]) !== index + 1) throw new Error("instrument bootstrap event sequence has a gap");
      const buffer = readPrivateFile(
        path.join(eventsRoot, names[index]),
        `instrument bootstrap event ${index + 1}`,
        MAX_EVENT_FILE_BYTES,
      );
      try {
        const envelope = JSON.parse(buffer.toString("utf8"));
        const event = decryptEvent(storeKey, metadata, envelope);
        if (event.runtime_id !== metadata.runtime_id
            || event.session_nucleus_hash !== metadata.session_nucleus_hash) {
          throw new Error("instrument bootstrap event metadata binding drift");
        }
        lastEventPreviousDigest = event.previous_event_digest;
        applyEvent(projection, event);
      } finally { buffer.fill(0); }
    }
    const localAnchor = anchorFor(metadata, projection.generation, projection.head_event_digest);
    const external = readAnchor();
    if (sameAnchor(localAnchor, external)) return projection;
    // A hot store has already witnessed its cached anchor. Never reinterpret a
    // later external rollback to null as a recoverable first-event crash tail.
    // The one-tail path below remains available on a fresh process, where a
    // local fsync may genuinely have won immediately before the anchor CAS.
    const cachedAnchor = cached == null
      ? null
      : anchorFor(metadata, cached.generation, cached.head_event_digest);
    if (cachedAnchor != null && sameAnchor(localAnchor, cachedAnchor)
        && !sameAnchor(external, cachedAnchor)) {
      throw new Error("instrument bootstrap store rollback, truncation, or anchor fork detected");
    }
    const oneLocalTail = reconcile && localAnchor != null
      && localAnchor.generation === (external == null ? 1 : external.generation + 1)
      && lastEventPreviousDigest === (external == null ? null : external.head_event_digest);
    if (oneLocalTail) {
      commitAnchor(external, localAnchor);
      return projection;
    }
    throw new Error("instrument bootstrap store rollback, truncation, or anchor fork detected");
  }

  function appendEventUnlocked(kind, payload) {
    const projection = loadProjection();
    if (projection.generation >= MAX_EVENTS) throw new Error(`instrument bootstrap event cap ${MAX_EVENTS} reached`);
    const event = {
      version: STORE_VERSION,
      domain: EVENT_DOMAIN,
      runtime_id: metadata.runtime_id,
      session_nucleus_hash: metadata.session_nucleus_hash,
      generation: projection.generation + 1,
      previous_event_digest: projection.head_event_digest,
      kind,
      payload: cloneJson(payload),
      recorded_at: nowIso(),
    };
    const validation = loadProjection();
    applyEvent(validation, event);
    const envelope = encryptEvent(storeKey, metadata, event);
    const encoded = Buffer.from(`${canonicalJson(envelope)}\n`, "utf8");
    if (encoded.length > MAX_EVENT_FILE_BYTES) {
      encoded.fill(0);
      throw new Error("instrument bootstrap event exceeds file cap");
    }
    const filePath = path.join(
      eventsRoot,
      `${String(event.generation).padStart(12, "0")}.bootstrap-event.json`,
    );
    const published = publishExclusiveDurable(filePath, encoded);
    encoded.fill(0);
    if (!published) throw new Error("instrument bootstrap event generation concurrently published");
    commitAnchor(
      anchorFor(metadata, projection.generation, projection.head_event_digest),
      anchorFor(metadata, validation.generation, validation.head_event_digest),
    );
    cached = validation;
    return { event, projection: validation };
  }

  function exclusive(callback) {
    assertOpen();
    if (busy) throw new Error("instrument bootstrap store reentrant mutation rejected");
    busy = true;
    try { return callback(); } finally { busy = false; }
  }

  function assertGrantWindow(attempt, label) {
    const observed = Date.parse(nowIso());
    if (observed < Date.parse(attempt.grant_not_before)
        || observed >= Date.parse(attempt.grant_expires_at)) {
      throw new Error(`${label} is outside the bootstrap grant window`);
    }
  }

  function precommitAttempt(requestInput, custodyProjectionInput) {
    return exclusive(() => {
      const custody = assertLiveCustodyProjection(custodyProjectionInput);
      const request = normalizeInstrumentBootstrapPrecommitRequest(requestInput);
      if (request.session_nucleus_hash !== metadata.session_nucleus_hash) {
        throw new Error("bootstrap precommit session nucleus drift");
      }
      for (const [field, expected] of [
        ["connection_ref", custody.connection_ref],
        ["connection_generation", custody.connection_generation],
        ["custody_binding_digest", custody.custody_binding_digest],
      ]) {
        if (request[field] !== expected) {
          throw new Error(`bootstrap precommit ${field} drifted from exact custody`);
        }
      }
      assertGrantWindow(request, "bootstrap precommit");
      const projection = loadProjection();
      const existing = projection.attempts.get(request.attempt_ref);
      const activeCustody = activeAttemptCustodyBindings.get(request.attempt_ref);
      if (activeCustody && activeCustody !== custody.binding) {
        throw new Error("bootstrap attempt_ref is crosswired to another live custody instance");
      }
      activeAttemptCustodyBindings.set(request.attempt_ref, custody.binding);
      if (existing) {
        if (existing.durable_attempt_binding_digest !== request.durable_attempt_binding_digest) {
          throw new Error("bootstrap attempt_ref is bound to a different durable intent");
        }
        return publicAttempt(existing);
      }
      const result = appendEventUnlocked("bootstrap_attempt_precommitted", request);
      return publicAttempt(result.projection.attempts.get(request.attempt_ref));
    });
  }

  function commitDispatch(requestInput, custodyProjectionInput) {
    return exclusive(() => {
      const custody = assertLiveCustodyProjection(custodyProjectionInput);
      const request = normalizeInstrumentBootstrapCommitRequest(requestInput);
      const projection = loadProjection();
      const attempt = projection.attempts.get(request.attempt_ref);
      if (!attempt) throw new Error("bootstrap dispatch references unknown attempt");
      if (attempt.durable_attempt_binding_digest
          !== request.expected_durable_attempt_binding_digest) {
        throw new Error("bootstrap dispatch durable attempt binding is stale");
      }
      if (activeAttemptCustodyBindings.get(attempt.attempt_ref) !== custody.binding) {
        throw new Error("bootstrap dispatch lost its exact live custody instance");
      }
      for (const [field, expected] of [
        ["connection_ref", custody.connection_ref],
        ["connection_generation", custody.connection_generation],
        ["custody_binding_digest", custody.custody_binding_digest],
      ]) {
        if (attempt[field] !== expected) {
          throw new Error(`bootstrap dispatch ${field} drifted from exact custody`);
        }
      }
      if (attempt.state !== "precommitted") {
        return deepFreeze({ attempt: publicAttempt(attempt), dispatch: attempt.dispatch, dispatch_credential: null, already_committed: true });
      }
      assertGrantWindow(attempt, "bootstrap dispatch");
      const dispatch = createDispatchRecord(attempt, nowIso());
      const result = appendEventUnlocked("bootstrap_dispatch_committed", {
        attempt_ref: attempt.attempt_ref,
        dispatch,
      });
      const durableAttempt = result.projection.attempts.get(attempt.attempt_ref);
      const credential = Object.freeze({
        version: STORE_VERSION,
        kind: "instrument_bootstrap_dispatch_credential",
        attempt_ref: attempt.attempt_ref,
        dispatch_record_digest: dispatch.dispatch_record_digest,
        bootstrap_request_digest: dispatch.bootstrap_request_digest,
        credential_ref: `bootstrap-dispatch-credential:${crypto.randomBytes(24).toString("hex")}`,
        toJSON: rejectCredentialSerialization,
      });
      DISPATCH_CREDENTIALS.add(credential);
      DISPATCH_CREDENTIAL_STATE.set(credential, {
        store,
        attempt_ref: attempt.attempt_ref,
        dispatch_record_digest: dispatch.dispatch_record_digest,
        bootstrap_request_digest: dispatch.bootstrap_request_digest,
        custody_binding_digest: attempt.custody_binding_digest,
        connection_ref: attempt.connection_ref,
        connection_generation: attempt.connection_generation,
        custody_binding: custody.binding,
        consumed: false,
      });
      return deepFreeze({
        attempt: publicAttempt(durableAttempt),
        dispatch: deepFreeze(cloneJson(dispatch)),
        dispatch_credential: credential,
        already_committed: false,
      });
    });
  }

  function buildDurableAmbiguity(attempt, reasonCode, timestamp) {
    if (!attempt.dispatch) throw new Error("durable ambiguity requires a dispatch");
    const receiptBasis = {
      version: STORE_VERSION,
      attempt_ref: attempt.attempt_ref,
      dispatch_record_digest: attempt.dispatch.dispatch_record_digest,
      dispatch_redemption_digest: attempt.redemption
        ? attempt.redemption.dispatch_redemption_digest : null,
      reason_code: reasonCode,
      recorded_at: timestamp,
    };
    const receiptDigest = hashCanonicalJson({
      domain: "hacker-bob/instrument-bootstrap-ambiguity-receipt/v1",
      ...receiptBasis,
    });
    return normalizeInstrumentBootstrapDurableAmbiguity({
      version: STORE_VERSION,
      attempt_ref: attempt.attempt_ref,
      durable_attempt_binding_digest: attempt.durable_attempt_binding_digest,
      custody_binding_digest: attempt.custody_binding_digest,
      dispatch_record_digest: attempt.dispatch.dispatch_record_digest,
      dispatch_redemption_digest: attempt.redemption
        ? attempt.redemption.dispatch_redemption_digest : null,
      reason_code: reasonCode,
      ambiguity_receipt_ref: `bootstrap-ambiguity-receipt:${receiptDigest.slice(0, 40)}`,
      ambiguity_receipt_digest: receiptDigest,
      terminal_recorded_at: timestamp,
    });
  }

  function markAmbiguous(requestInput) {
    return exclusive(() => {
      const request = normalizeInstrumentBootstrapMarkAmbiguousRequest(requestInput);
      const projection = loadProjection();
      const attempt = projection.attempts.get(request.attempt_ref);
      if (!attempt) throw new Error("bootstrap ambiguity references unknown attempt");
      if (attempt.state === "ambiguous" && attempt.durable_ambiguity
          && attempt.durable_ambiguity.reason_code === request.reason_code) {
        return publicAttempt(attempt);
      }
      if (attempt.attempt_digest !== request.expected_attempt_digest) {
        throw new Error("bootstrap ambiguity expected_attempt_digest is stale");
      }
      if (!["dispatch_committed", "redeemed"].includes(attempt.state)) {
        throw new Error("bootstrap ambiguity requires an in-flight dispatch");
      }
      const ambiguity = buildDurableAmbiguity(attempt, request.reason_code, nowIso());
      const result = appendEventUnlocked("bootstrap_attempt_ambiguous", {
        attempt_ref: attempt.attempt_ref,
        kind: "durable_ambiguity",
        durable_ambiguity: ambiguity,
      });
      return publicAttempt(result.projection.attempts.get(attempt.attempt_ref));
    });
  }

  function readAttempt(attemptRefInput) {
    assertOpen();
    const attemptRef = normalizeOpaqueRef(attemptRefInput, "bootstrap attempt_ref", {
      prefix: "bootstrap-attempt",
    });
    const projection = loadProjection();
    const attempt = projection.attempts.get(attemptRef);
    return attempt == null ? null : publicAttempt(attempt);
  }

  function snapshot() {
    assertOpen();
    cached = loadProjection();
    return publicProjection(cached);
  }

  function retireObservationCompletion(capability, capabilityState) {
    capabilityState.consumed = true;
    activeObservationCompletions.delete(capability);
    if (capabilityState.timer != null) clearTimeout(capabilityState.timer);
    capabilityState.timer = null;
  }

  function close() {
    if (closed) return;
    for (const capability of activeObservationCompletions) {
      const capabilityState = OBSERVATION_COMPLETION_CAPABILITY_STATE.get(capability);
      if (capabilityState) retireObservationCompletion(capability, capabilityState);
    }
    activeAttemptCustodyBindings.clear();
    closed = true;
    storeKey.fill(0);
  }

  function redeemCredential(credential, enrollment, expected, port) {
    return exclusive(() => {
      const state = credential == null ? null : DISPATCH_CREDENTIAL_STATE.get(credential);
      if (!credential || !DISPATCH_CREDENTIALS.has(credential) || !state
          || state.store !== store || state.consumed) {
        throw new Error("bootstrap dispatch credential was not issued by this live durable store");
      }
      if (enrollment.custody_binding !== state.custody_binding) {
        throw new Error("bootstrap redemption provider port is crosswired to another custody instance");
      }
      const providerRequest = normalizeInstrumentBootstrapProviderRedemptionRequest(expected);
      if (providerRequest.attempt_ref !== state.attempt_ref
          || providerRequest.dispatch_record_digest !== state.dispatch_record_digest
          || providerRequest.bootstrap_request_digest !== state.bootstrap_request_digest) {
        throw new Error("bootstrap redemption credential request drift");
      }
      const projection = loadProjection();
      const attempt = projection.attempts.get(providerRequest.attempt_ref);
      if (!attempt || attempt.state !== "dispatch_committed"
          || attempt.dispatch.dispatch_record_digest !== providerRequest.dispatch_record_digest) {
        throw new Error("bootstrap redemption requires the exact live dispatch head");
      }
      const request = normalizeInstrumentBootstrapRedemptionExpected(requestBindingFor(attempt));
      for (const field of [
        ...INTENT_FIELDS,
        "bootstrap_intent_digest",
        "dispatch_record_digest",
        "bootstrap_request_digest",
      ]) {
        if (providerRequest[field] !== request[field]) {
          throw new Error(`bootstrap redemption ${field} drifted from the durable dispatch`);
        }
      }
      for (const [field, wanted] of Object.entries({
        provider_id: enrollment.provider_id,
        provider_descriptor_digest: enrollment.provider_descriptor_digest,
        provider_binary_digest: enrollment.provider_binary_digest,
        transport_digest: enrollment.transport_digest,
        bootstrap_manifest_digest: enrollment.bootstrap_manifest_digest,
        bootstrap_invariants_digest: enrollment.bootstrap_invariants_digest,
        execution_principal_id: enrollment.execution_principal_id,
        instrument_ref: enrollment.instrument_ref,
        enrollment_candidate_ref: enrollment.enrollment_candidate_ref,
      })) {
        if (request[field] !== wanted) throw new Error(`bootstrap redemption ${field} enrollment drift`);
      }
      const custody = assertLiveCustodyBinding(enrollment.custody_binding);
      if (custody.binding !== state.custody_binding) {
        throw new Error("bootstrap redemption exact custody identity drifted");
      }
      for (const [field, expected] of [
        ["connection_ref", custody.connection_ref],
        ["connection_generation", custody.connection_generation],
        ["custody_binding_digest", custody.custody_binding_digest],
      ]) {
        if (request[field] !== expected || state[field] !== expected) {
          throw new Error(`bootstrap redemption ${field} custody drift`);
        }
      }
      assertGrantWindow(attempt, "bootstrap credential redemption");
      if (callSynchronous(
        enrollment.revalidateBootstrapAuthority,
        request,
        "bootstrap authority revalidation",
      ) !== true) throw new Error("bootstrap authority revalidation refused");
      const redemption = createRedemptionRecord(attempt, nowIso());
      const result = appendEventUnlocked("bootstrap_dispatch_redeemed", {
        attempt_ref: attempt.attempt_ref,
        redemption,
      });
      state.consumed = true;
      const permit = Object.freeze(Object.create(null));
      const redemptionProjection = providerRedemptionProjection(redemption);
      OBSERVATION_PERMITS.add(permit);
      OBSERVATION_PERMIT_STATE.set(permit, {
        store,
        port,
        consumed: false,
        enrollment,
        expected: request,
        redemption,
        redemption_projection: redemptionProjection,
      });
      return deepFreeze({
        permit,
        redemption_projection: redemptionProjection,
      });
    });
  }

  function generatedProviderReport(attempt, outcome, timestamp, reasonCode) {
    if (!attempt.redemption) throw new Error("generated provider report requires redemption");
    const receiptBasis = {
      version: STORE_VERSION,
      attempt_ref: attempt.attempt_ref,
      dispatch_record_digest: attempt.dispatch.dispatch_record_digest,
      dispatch_redemption_digest: attempt.redemption.dispatch_redemption_digest,
      outcome,
      reason_code: reasonCode,
      recorded_at: timestamp,
    };
    const receiptDigest = hashCanonicalJson({
      domain: "hacker-bob/instrument-bootstrap-store-provider-receipt/v1",
      ...receiptBasis,
    });
    return {
      version: STORE_VERSION,
      attempt_ref: attempt.attempt_ref,
      operation_id: attempt.operation_id,
      bootstrap_intent_digest: attempt.bootstrap_intent_digest,
      bootstrap_request_digest: attempt.dispatch.bootstrap_request_digest,
      signed_grant_digest: attempt.signed_grant_digest,
      replay_reservation_receipt_digest: attempt.replay_reservation_receipt_digest,
      dispatch_record_digest: attempt.dispatch.dispatch_record_digest,
      dispatch_redemption_digest: attempt.redemption.dispatch_redemption_digest,
      connection_generation: attempt.connection_generation,
      outcome,
      observation_ref: null,
      observation_digest: null,
      receipt_ref: `bootstrap-receipt:${receiptDigest.slice(0, 40)}`,
      receipt_digest: receiptDigest,
      response_digest: null,
      observed_at: timestamp,
      assurance_claims_digest: null,
      invariant_witness_digest: null,
    };
  }

  function appendProviderTerminal(attempt, reportInput, reasonCode) {
    const request = requestBindingFor(attempt);
    const report = normalizeInstrumentBootstrapProviderReport(reportInput, request);
    const timestamp = nowIso();
    const terminal = normalizeInstrumentBootstrapTerminalBinding({
      version: STORE_VERSION,
      attempt_ref: attempt.attempt_ref,
      terminal_state: report.outcome,
      durable_attempt_binding_digest: attempt.durable_attempt_binding_digest,
      custody_binding_digest: attempt.custody_binding_digest,
      dispatch_record_digest: report.dispatch_record_digest,
      dispatch_redemption_digest: report.dispatch_redemption_digest,
      provider_report_digest: instrumentBootstrapProviderReportDigest(report, request),
      terminal_recorded_at: timestamp,
    }, report, request);
    const ambiguous = report.outcome === "ambiguous";
    const payload = {
      attempt_ref: attempt.attempt_ref,
      ...(ambiguous ? { kind: "provider_report" } : {}),
      provider_report: report,
      terminal_binding: terminal,
      reason_code: reasonCode,
    };
    const result = appendEventUnlocked(
      ambiguous ? "bootstrap_attempt_ambiguous" : "bootstrap_attempt_completed",
      payload,
    );
    return result.projection.attempts.get(attempt.attempt_ref).provider_report;
  }

  function observationPreflightFailure(attempt, permitState) {
    try {
      assertGrantWindow(attempt, "bootstrap observation");
      if (callSynchronous(
        permitState.enrollment.revalidateBootstrapAuthority,
        permitState.expected,
        "bootstrap authority revalidation",
      ) !== true) throw new Error("bootstrap authority revalidation refused");
      const custody = assertLiveCustodyBinding(permitState.enrollment.custody_binding);
      if (custody.binding !== permitState.enrollment.custody_binding
          || custody.connection_ref !== attempt.connection_ref
          || custody.connection_generation !== attempt.connection_generation
          || custody.custody_binding_digest !== attempt.custody_binding_digest) {
        throw new Error("bootstrap custody drifted before source observation");
      }
      return null;
    } catch (error) {
      return error;
    }
  }

  function exactRedeemedAttemptForCapability(capabilityState) {
    const projection = loadProjection();
    const attempt = projection.attempts.get(capabilityState.attempt_ref);
    if (!attempt || attempt.state !== "redeemed" || !attempt.redemption
        || attempt.last_event_digest !== capabilityState.redeemed_event_digest
        || attempt.redemption.dispatch_redemption_digest
          !== capabilityState.dispatch_redemption_digest) {
      return null;
    }
    return attempt;
  }

  function expireObservationCompletion(capability) {
    const capabilityState = OBSERVATION_COMPLETION_CAPABILITY_STATE.get(capability);
    if (!capabilityState || capabilityState.store !== store || capabilityState.consumed) return;
    try {
      exclusive(() => {
        if (capabilityState.consumed) return;
        retireObservationCompletion(capability, capabilityState);
        const attempt = exactRedeemedAttemptForCapability(capabilityState);
        if (!attempt) return;
        appendProviderTerminal(
          attempt,
          generatedProviderReport(attempt, "ambiguous", nowIso(), "observation_timeout"),
          "observation_timeout",
        );
      });
    } catch {
      // The capability has already been destroyed. A closed store is made
      // sticky ambiguous by restart recovery; an anchor/filesystem failure
      // cannot safely restore or remint completion authority.
      retireObservationCompletion(capability, capabilityState);
    }
  }

  function beginPermit(permit, port, observationTimeoutMs) {
    return exclusive(() => {
      const permitState = permit == null ? null : OBSERVATION_PERMIT_STATE.get(permit);
      if (!permit || !OBSERVATION_PERMITS.has(permit) || !permitState
          || permitState.store !== store || permitState.port !== port || permitState.consumed) {
        throw new Error("bootstrap observation permit was not issued to this provider port");
      }
      const projection = loadProjection();
      const attempt = projection.attempts.get(permitState.expected.attempt_ref);
      if (!attempt || attempt.state !== "redeemed" || !attempt.redemption
          || attempt.redemption.dispatch_redemption_digest
            !== permitState.redemption.dispatch_redemption_digest) {
        throw new Error("bootstrap observation permit lost its exact redemption head");
      }
      permitState.consumed = true;
      const preflightFailure = observationPreflightFailure(attempt, permitState);
      if (preflightFailure) {
        const report = appendProviderTerminal(
          attempt,
          generatedProviderReport(attempt, "refused_no_effect", nowIso(), "preflight_refused"),
          "preflight_refused",
        );
        return deepFreeze({
          started: false,
          completion_capability: null,
          redemption_projection: permitState.redemption_projection,
          provider_report: report,
        });
      }

      const capability = Object.create(null);
      Object.defineProperty(capability, "toJSON", {
        value: rejectCompletionCapabilitySerialization,
      });
      Object.freeze(capability);
      const capabilityState = {
        store,
        port,
        consumed: false,
        timer: null,
        attempt_ref: attempt.attempt_ref,
        redeemed_event_digest: attempt.last_event_digest,
        dispatch_redemption_digest: attempt.redemption.dispatch_redemption_digest,
        deadline_monotonic_ns: process.hrtime.bigint()
          + (BigInt(observationTimeoutMs) * 1_000_000n),
      };
      OBSERVATION_COMPLETION_CAPABILITIES.add(capability);
      OBSERVATION_COMPLETION_CAPABILITY_STATE.set(capability, capabilityState);
      activeObservationCompletions.add(capability);
      capabilityState.timer = setTimeout(
        () => expireObservationCompletion(capability),
        observationTimeoutMs,
      );
      if (typeof capabilityState.timer.unref === "function") capabilityState.timer.unref();
      return deepFreeze({
        started: true,
        completion_capability: capability,
        redemption_projection: permitState.redemption_projection,
        provider_report: null,
      });
    });
  }

  function completeObservation(capability, reportInput, port) {
    return exclusive(() => {
      const capabilityState = capability == null
        ? null : OBSERVATION_COMPLETION_CAPABILITY_STATE.get(capability);
      if (!capability || !OBSERVATION_COMPLETION_CAPABILITIES.has(capability)
          || !capabilityState || capabilityState.store !== store
          || capabilityState.port !== port || capabilityState.consumed) {
        throw new Error("bootstrap observation completion capability was not issued to this provider port");
      }
      retireObservationCompletion(capability, capabilityState);
      const attempt = exactRedeemedAttemptForCapability(capabilityState);
      if (!attempt) {
        throw new Error("bootstrap observation completion lost its exact redeemed record");
      }
      if (process.hrtime.bigint() >= capabilityState.deadline_monotonic_ns) {
        return appendProviderTerminal(
          attempt,
          generatedProviderReport(attempt, "ambiguous", nowIso(), "observation_timeout"),
          "observation_timeout",
        );
      }
      let report;
      try {
        report = normalizeInstrumentBootstrapProviderReport(
          reportInput,
          requestBindingFor(attempt),
        );
      } catch {
        return appendProviderTerminal(
          attempt,
          generatedProviderReport(attempt, "ambiguous", nowIso(), "provider_report_invalid"),
          "provider_report_invalid",
        );
      }
      return appendProviderTerminal(
        attempt,
        report,
        report.outcome === "succeeded" ? null : "provider_reported_terminal",
      );
    });
  }

  function consumePermit(permit, callback, port) {
    return exclusive(() => {
      const permitState = permit == null ? null : OBSERVATION_PERMIT_STATE.get(permit);
      if (!permit || !OBSERVATION_PERMITS.has(permit) || !permitState
          || permitState.store !== store || permitState.port !== port || permitState.consumed) {
        throw new Error("bootstrap observation permit was not issued to this provider port");
      }
      if (typeof callback !== "function"
          || (callback.constructor && callback.constructor.name === "AsyncFunction")) {
        throw new Error("bootstrap observation callback must be synchronous");
      }
      const projection = loadProjection();
      const attempt = projection.attempts.get(permitState.expected.attempt_ref);
      if (!attempt || attempt.state !== "redeemed" || !attempt.redemption
          || attempt.redemption.dispatch_redemption_digest
            !== permitState.redemption.dispatch_redemption_digest) {
        throw new Error("bootstrap observation permit lost its exact redemption head");
      }
      const preflightFailure = observationPreflightFailure(attempt, permitState);
      permitState.consumed = true;
      if (preflightFailure) {
        return appendProviderTerminal(
          attempt,
          generatedProviderReport(attempt, "refused_no_effect", nowIso(), "preflight_refused"),
          "preflight_refused",
        );
      }
      let callbackResult;
      let callbackFailure = null;
      try {
        callbackResult = callback(permitState.redemption_projection);
      } catch (error) { callbackFailure = error; }
      if (callbackResult && (typeof callbackResult === "object" || typeof callbackResult === "function")
          && typeof callbackResult.then === "function") {
        callbackFailure = new Error("bootstrap observation callback must complete synchronously");
      }
      if (callbackFailure) {
        return appendProviderTerminal(
          attempt,
          generatedProviderReport(attempt, "ambiguous", nowIso(), "provider_callback_failed"),
          "provider_callback_failed",
        );
      }
      let report;
      try {
        report = normalizeInstrumentBootstrapProviderReport(
          callbackResult,
          requestBindingFor(attempt),
        );
      } catch (error) {
        return appendProviderTerminal(
          attempt,
          generatedProviderReport(attempt, "ambiguous", nowIso(), "provider_report_invalid"),
          "provider_report_invalid",
        );
      }
      return appendProviderTerminal(
        attempt,
        report,
        report.outcome === "succeeded" ? null : "provider_reported_terminal",
      );
    });
  }

  const store = Object.freeze({
    close,
    commitDispatch,
    markAmbiguous,
    precommitAttempt,
    readAttempt,
    snapshot,
  });
  DURABLE_STORES.add(store);
  DURABLE_STORE_STATE.set(store, {
    assertLiveCustodyProjection,
    beginPermit,
    completeObservation,
    consumePermit,
    createCustodyBinding,
    readCustodyProjection,
    redeemCredential,
  });
  cached = loadProjection();

  // A process restart destroys every in-memory credential/permit. Any durable
  // dispatch/redeem head is therefore terminally ambiguous; never remint it.
  for (const attempt of [...cached.attempts.values()]) {
    if (!["dispatch_committed", "redeemed"].includes(attempt.state)) continue;
    markAmbiguous({
      version: STORE_VERSION,
      attempt_ref: attempt.attempt_ref,
      expected_attempt_digest: attempt.attempt_digest,
      reason_code: "restart_in_flight",
    });
  }
  return store;
}

function assertDurableInstrumentBootstrapStore(input) {
  if (!input || !DURABLE_STORES.has(input) || !DURABLE_STORE_STATE.has(input)) {
    throw new Error("instrument bootstrap store must be created by Bob's durable store factory");
  }
  return input;
}

function assertInstrumentBootstrapCustodyBinding(input) {
  const state = input == null ? null : CUSTODY_BINDING_STATE.get(input);
  if (!input || !CUSTODY_BINDINGS.has(input) || !state || !Object.isFrozen(input)
      || input.version !== STORE_VERSION
      || input.kind !== "instrument_bootstrap_custody_binding"
      || Reflect.ownKeys(input).length !== 3
      || typeof input.toJSON !== "function") {
    throw new Error("instrument bootstrap custody binding must be a private store-issued capability");
  }
  return input;
}

function assertInstrumentBootstrapCustodyProjection(input) {
  const state = input == null ? null : CUSTODY_PROJECTION_STATE.get(input);
  if (!input || !CUSTODY_PROJECTIONS.has(input) || !state || !Object.isFrozen(input)
      || input.version !== STORE_VERSION
      || input.kind !== "instrument_bootstrap_custody_projection"
      || Reflect.ownKeys(input).length !== 7
      || typeof input.toJSON !== "function") {
    throw new Error("instrument bootstrap custody projection must be a private store-issued capability");
  }
  return input;
}

function assertInstrumentBootstrapCustodyBindingForBrokerPort(bindingInput, portInput) {
  const binding = assertInstrumentBootstrapCustodyBinding(bindingInput);
  const port = assertInstrumentBootstrapBrokerPort(portInput);
  const bindingState = CUSTODY_BINDING_STATE.get(binding);
  const portState = BROKER_PORT_STATE.get(port);
  if (!bindingState || !portState || bindingState.store !== portState.store) {
    throw new Error("instrument bootstrap custody binding belongs to another broker store");
  }
  return binding;
}

function createInstrumentBootstrapCustodyBinding(storeInput, input) {
  if (arguments.length !== 2) {
    throw new Error("instrument bootstrap custody binding creation requires store and binding input");
  }
  const store = assertDurableInstrumentBootstrapStore(storeInput);
  return DURABLE_STORE_STATE.get(store).createCustodyBinding(input);
}

function createInstrumentBootstrapBrokerCustodyBinding(portInput, input) {
  if (arguments.length !== 2) {
    throw new Error("broker custody binding creation requires broker port and binding input");
  }
  const port = assertInstrumentBootstrapBrokerPort(portInput);
  const state = BROKER_PORT_STATE.get(port);
  return DURABLE_STORE_STATE.get(state.store).createCustodyBinding(input);
}

function readInstrumentBootstrapCustodyProjection(bindingInput) {
  if (arguments.length !== 1) {
    throw new Error("instrument bootstrap custody projection read requires one binding");
  }
  const binding = assertInstrumentBootstrapCustodyBinding(bindingInput);
  const state = CUSTODY_BINDING_STATE.get(binding);
  return DURABLE_STORE_STATE.get(state.store).readCustodyProjection(binding);
}

function normalizeProviderEnrollment(input, store) {
  assertClosedObject(input, "instrument bootstrap provider enrollment", [
    "provider_id",
    "provider_descriptor_digest",
    "provider_binary_digest",
    "transport_digest",
    "bootstrap_manifest_digest",
    "bootstrap_invariants_digest",
    "execution_principal_id",
    "instrument_ref",
    "enrollment_candidate_ref",
    "custody_binding",
    "revalidateBootstrapAuthority",
  ]);
  for (const field of ["revalidateBootstrapAuthority"]) {
    if (typeof input[field] !== "function") throw new Error(`provider enrollment ${field} must be a function`);
  }
  const custodyBinding = assertInstrumentBootstrapCustodyBinding(input.custody_binding);
  const custodyState = CUSTODY_BINDING_STATE.get(custodyBinding);
  if (!custodyState || custodyState.store !== store) {
    throw new Error("provider enrollment custody binding belongs to another durable store");
  }
  return Object.freeze({
    provider_id: assertIdentifier(input.provider_id, "provider enrollment.provider_id"),
    provider_descriptor_digest: assertDigest(input.provider_descriptor_digest, "provider enrollment.provider_descriptor_digest"),
    provider_binary_digest: assertDigest(input.provider_binary_digest, "provider enrollment.provider_binary_digest"),
    transport_digest: assertDigest(input.transport_digest, "provider enrollment.transport_digest"),
    bootstrap_manifest_digest: assertDigest(input.bootstrap_manifest_digest, "provider enrollment.bootstrap_manifest_digest"),
    bootstrap_invariants_digest: assertDigest(input.bootstrap_invariants_digest, "provider enrollment.bootstrap_invariants_digest"),
    execution_principal_id: normalizeOpaqueRef(input.execution_principal_id, "provider enrollment.execution_principal_id", { prefix: "principal" }),
    instrument_ref: normalizeOpaqueRef(input.instrument_ref, "provider enrollment.instrument_ref", { prefix: "instrument" }),
    enrollment_candidate_ref: normalizeOpaqueRef(input.enrollment_candidate_ref, "provider enrollment.enrollment_candidate_ref", { prefix: "enrollment-candidate" }),
    custody_binding: custodyBinding,
    revalidateBootstrapAuthority: input.revalidateBootstrapAuthority,
  });
}

function normalizeProviderPortOptions(input) {
  assertClosedObject(
    input,
    "instrument bootstrap provider port options",
    [],
    ["observation_timeout_ms"],
  );
  const observationTimeoutMs = input.observation_timeout_ms
    == null ? DEFAULT_ASYNC_OBSERVATION_TIMEOUT_MS : input.observation_timeout_ms;
  if (!Number.isSafeInteger(observationTimeoutMs) || observationTimeoutMs < 1
      || observationTimeoutMs > MAX_ASYNC_OBSERVATION_TIMEOUT_MS) {
    throw new Error(
      `provider port observation_timeout_ms must be an integer from 1 through ${MAX_ASYNC_OBSERVATION_TIMEOUT_MS}`,
    );
  }
  return Object.freeze({ observation_timeout_ms: observationTimeoutMs });
}

function createInstrumentBootstrapProviderRedemptionPort(
  storeInput,
  enrollmentInput,
  optionsInput = {},
) {
  const store = assertDurableInstrumentBootstrapStore(storeInput);
  const storeState = DURABLE_STORE_STATE.get(store);
  const enrollment = normalizeProviderEnrollment(enrollmentInput, store);
  const options = normalizeProviderPortOptions(optionsInput);
  let port;
  port = Object.freeze({
    redeem(credential, expected) {
      if (arguments.length !== 2) throw new Error("bootstrap provider redeem requires credential and expected binding");
      return storeState.redeemCredential(credential, enrollment, expected, port);
    },
    beginBootstrapObservation(permit) {
      if (arguments.length !== 1) throw new Error("beginBootstrapObservation requires one permit");
      return storeState.beginPermit(permit, port, options.observation_timeout_ms);
    },
    completeBootstrapObservation(completionCapability, report) {
      if (arguments.length !== 2) {
        throw new Error("completeBootstrapObservation requires completion capability and report");
      }
      return storeState.completeObservation(completionCapability, report, port);
    },
    consumeBootstrapObservation(permit, callback) {
      if (arguments.length !== 2) throw new Error("consumeBootstrapObservation requires permit and callback");
      return storeState.consumePermit(permit, callback, port);
    },
  });
  PROVIDER_PORTS.add(port);
  PROVIDER_PORT_STATE.set(port, { store, enrollment, options });
  return port;
}

function assertInstrumentBootstrapProviderRedemptionPort(input) {
  if (!input || !PROVIDER_PORTS.has(input) || !PROVIDER_PORT_STATE.has(input)) {
    throw new Error("instrument bootstrap provider port must be enrolled by a Bob durable store");
  }
  return input;
}

function callPortHook(hook, method) {
  if (hook == null) return;
  const result = hook(Object.freeze({ version: STORE_VERSION, method }));
  if (result !== undefined) throw new Error("instrument bootstrap broker port hook must return undefined");
}

function createInstrumentBootstrapBrokerPort(storeInput, options = {}) {
  const store = assertDurableInstrumentBootstrapStore(storeInput);
  assertClosedObject(options, "instrument bootstrap broker port options", [], ["before_call", "after_call"]);
  for (const field of ["before_call", "after_call"]) {
    if (options[field] != null && typeof options[field] !== "function") {
      throw new Error(`instrument bootstrap broker port ${field} must be a function`);
    }
  }
  const port = {};
  for (const method of ["precommitAttempt", "commitDispatch", "markAmbiguous", "readAttempt", "snapshot"]) {
    port[method] = (...args) => {
      const expectedArgs = ["precommitAttempt", "commitDispatch"].includes(method)
        ? 2
        : ["readAttempt", "markAmbiguous"].includes(method) ? 1 : 0;
      if (args.length !== expectedArgs) throw new Error(`instrument bootstrap broker port ${method} argument count invalid`);
      callPortHook(options.before_call, method);
      const result = store[method](...args);
      callPortHook(options.after_call, method);
      return result;
    };
  }
  const frozen = Object.freeze(port);
  BROKER_PORTS.add(frozen);
  BROKER_PORT_STATE.set(frozen, { store });
  return frozen;
}

function assertInstrumentBootstrapBrokerPort(input) {
  if (!input || !BROKER_PORTS.has(input) || !BROKER_PORT_STATE.has(input)) {
    throw new Error("instrument bootstrap broker port must attenuate a Bob durable store");
  }
  return input;
}

module.exports = {
  INSTRUMENT_BOOTSTRAP_ASYNC_OBSERVATION_MAX_TIMEOUT_MS: MAX_ASYNC_OBSERVATION_TIMEOUT_MS,
  INSTRUMENT_BOOTSTRAP_STORE_MAX_EVENTS: MAX_EVENTS,
  INSTRUMENT_BOOTSTRAP_STORE_VERSION: STORE_VERSION,
  assertDurableInstrumentBootstrapStore,
  assertInstrumentBootstrapCustodyBinding,
  assertInstrumentBootstrapCustodyBindingForBrokerPort,
  assertInstrumentBootstrapCustodyProjection,
  assertInstrumentBootstrapBrokerPort,
  assertInstrumentBootstrapProviderRedemptionPort,
  createDurableInstrumentBootstrapStore,
  createInstrumentBootstrapBrokerCustodyBinding,
  createInstrumentBootstrapCustodyBinding,
  createInstrumentBootstrapBrokerPort,
  createInstrumentBootstrapProviderRedemptionPort,
  readInstrumentBootstrapCustodyProjection,
};
