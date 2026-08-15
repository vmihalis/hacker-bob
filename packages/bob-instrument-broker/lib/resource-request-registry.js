"use strict";

// Plane-PH authenticated request/admission join registry. A request is first
// durably prepared here, then enqueued through the independent arbiter store,
// and finally joined to the exact admission receipt. Those are deliberately
// separate commits: this module never claims atomicity across the two stores.

const crypto = require("node:crypto");

const {
  normalizePhysicalReservationRequest,
  normalizePhysicalResourceBundle,
} = require("../../../mcp/core/physical-resource-contracts.js");
const {
  normalizePhysicalResourceQueueTicket,
} = require("../../../mcp/domains/physical/physical-resource-arbiter.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");
const {
  assertPhysicalResourceArbiterAdmissionPort,
  derivePhysicalResourceArbiterBatchKey,
  verifyPhysicalResourceArbiterAdmissionBinding,
} = require("./resource-arbiter-admission.js");

const RESOURCE_REQUEST_REGISTRY_VERSION = 1;
const RESOURCE_REQUEST_REGISTRY_STATE_PORT_VERSION = 1;
const RESOURCE_REQUEST_REGISTRY_SIGNER_VERSION = 1;
const RESOURCE_REQUEST_REGISTRY_RECORD_VERSION = 1;
const RESOURCE_REQUEST_REGISTRY_STATE_VERSION = 1;
const RESOURCE_REQUEST_REGISTRY_CHECKPOINT_VERSION = 1;
const RESOURCE_REQUEST_REGISTRY_CAPABILITY_VERSION = 1;
const RESOURCE_REQUEST_REGISTRY_PROJECTION_VERSION = 1;
const RESOURCE_REQUEST_REGISTRY_READINESS_VERSION = 1;
const RESOURCE_REQUEST_REGISTRY_CAS_VERSION = 1;
const RESOURCE_REQUEST_REGISTRY_RECORD_DOMAIN =
  "hacker-bob/physical-resource-request-registry-record/v1";
const RESOURCE_REQUEST_REGISTRY_STATE_DOMAIN =
  "hacker-bob/physical-resource-request-registry-state/v1";
const RESOURCE_REQUEST_REGISTRY_KEY_USAGE = "physical_resource_request_registry_signing";
const RESOURCE_REQUEST_REGISTRY_WORKFLOW =
  "durable-prepare-then-external-arbiter-enqueue-then-finalize-or-reconcile-v1";
const RESOURCE_REQUEST_REGISTRY_DURABILITY_ASSURANCE =
  "caller_asserted_external_linearizable_cas_checkpoint_unattested";
const RESOURCE_REQUEST_REGISTRY_ISOLATION_ASSURANCE = "same_isolate_weak_brand_only";
const MAX_REGISTRY_RECORDS = 4_096;

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;

const STATE_PORTS = new WeakSet();
const STATE_PORT_PRIVATE = new WeakMap();
const SIGNERS = new WeakSet();
const SIGNER_PRIVATE = new WeakMap();
const REGISTRIES = new WeakSet();
const REGISTRY_PRIVATE = new WeakMap();
const PREPARE_CAPABILITIES = new WeakSet();
const PREPARE_CAPABILITY_PRIVATE = new WeakMap();
const ACTIVE_REGISTRIES = new WeakSet();
const ACTIVE_STATE_PORTS = new WeakSet();

function compareProtocolStrings(left, right) {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...required, ...optional]);
  const unknown = keys.filter((key) => !allowed.has(key)).sort(compareProtocolStrings);
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((key) => !Object.prototype.hasOwnProperty.call(value, key));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${label}.${key} must be an enumerable data field`);
    }
  }
  return value;
}

function assertDataArray(value, label, minimum = 0, maximum = MAX_REGISTRY_RECORDS) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    throw new Error(`${label} must contain ${minimum}-${maximum} entries`);
  }
  const allowed = new Set(["length"]);
  for (let index = 0; index < value.length; index += 1) allowed.add(String(index));
  if (Reflect.ownKeys(value).some((key) => !allowed.has(key))) {
    throw new Error(`${label} cannot contain sparse, extra, or symbol fields`);
  }
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${label}[${index}] must be an enumerable data field`);
    }
  }
  return value;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertToken(value, label, prefix = null) {
  if (typeof value !== "string" || !TOKEN_PATTERN.test(value)) {
    throw new Error(`${label} must be a bounded opaque token`);
  }
  if (prefix != null && !value.startsWith(`${prefix}:`)) {
    throw new Error(`${label} must use the ${prefix}: namespace`);
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertNullableDigest(value, label) {
  return value === null ? null : assertDigest(value, label);
}

function assertInteger(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function assertEd25519Key(key, kind, label) {
  if (!(key instanceof crypto.KeyObject) || key.type !== kind || key.asymmetricKeyType !== "ed25519") {
    throw new Error(`${label} must be an Ed25519 ${kind} KeyObject`);
  }
  return key;
}

function publicKeyDigest(key) {
  const publicKey = key.type === "private" ? crypto.createPublicKey(key) : key;
  assertEd25519Key(publicKey, "public", "registry_public_key");
  return crypto.createHash("sha256").update(
    publicKey.export({ type: "spki", format: "der" }),
  ).digest("hex");
}

function assertCanonicalSignature(value, label) {
  if (typeof value !== "string" || !SIGNATURE_PATTERN.test(value)) {
    throw new Error(`${label} must be a canonical Ed25519 base64url signature`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) {
    throw new Error(`${label} must be canonical Ed25519 base64url`);
  }
  return value;
}

function registryError(code, message, cause = null) {
  const error = new Error(message, cause == null ? undefined : { cause });
  Object.defineProperty(error, "code", { value: code, enumerable: true });
  return error;
}

function assertSynchronousResult(value, label) {
  if (value && (typeof value === "object" || typeof value === "function")) {
    let then;
    try {
      then = value.then;
    } catch (cause) {
      throw registryError("resource_request_registry_callback_invalid", `${label} returned a hostile thenable`, cause);
    }
    if (typeof then === "function") {
      throw registryError("resource_request_registry_callback_invalid", `${label} must be synchronous`);
    }
  }
  return value;
}

function authenticationBasis(authentication) {
  return deepFreeze({
    scheme: authentication.scheme,
    key_usage: authentication.key_usage,
    key_id: authentication.key_id,
    signer_epoch: authentication.signer_epoch,
    public_key_digest: authentication.public_key_digest,
    signed_payload_digest: authentication.signed_payload_digest,
  });
}

function signatureInputDigest(domain, registryDomainDigest, payload, authentication) {
  return hashCanonicalJson({
    domain,
    registry_domain_digest: registryDomainDigest,
    payload,
    authentication: authenticationBasis(authentication),
  });
}

function createPhysicalResourceRequestRegistryStatePort(input = {}) {
  assertClosedObject(input, "physical_resource_request_registry_state_port", [
    "port_id",
    "registry_domain_digest",
    "read_current",
    "compare_and_set",
  ]);
  if (typeof input.read_current !== "function" || typeof input.compare_and_set !== "function") {
    throw new Error("registry state read_current and compare_and_set must be functions");
  }
  const port = deepFreeze({
    version: RESOURCE_REQUEST_REGISTRY_STATE_PORT_VERSION,
    port_id: assertIdentifier(input.port_id, "physical_resource_request_registry_state_port.port_id"),
    registry_domain_digest: assertDigest(
      input.registry_domain_digest,
      "physical_resource_request_registry_state_port.registry_domain_digest",
    ),
    state_contract: "external-linearizable-state-and-checkpoint-cas-v1",
    durability_assurance: RESOURCE_REQUEST_REGISTRY_DURABILITY_ASSURANCE,
    production_attested: false,
  });
  STATE_PORTS.add(port);
  STATE_PORT_PRIVATE.set(port, Object.freeze({
    read_current: input.read_current,
    compare_and_set: input.compare_and_set,
  }));
  return port;
}

function assertPhysicalResourceRequestRegistryStatePort(port) {
  if (!port || !Object.isFrozen(port) || !STATE_PORTS.has(port) || !STATE_PORT_PRIVATE.has(port)) {
    throw new Error("registry state port must be created by Bob's private factory");
  }
  return port;
}

function createPhysicalResourceRequestRegistrySigner(input = {}) {
  assertClosedObject(input, "physical_resource_request_registry_signer", [
    "signer_id", "key_id", "signer_epoch", "private_key",
  ]);
  const privateKey = assertEd25519Key(
    input.private_key,
    "private",
    "physical_resource_request_registry_signer.private_key",
  );
  const digest = publicKeyDigest(privateKey);
  const signer = deepFreeze({
    version: RESOURCE_REQUEST_REGISTRY_SIGNER_VERSION,
    signer_id: assertIdentifier(input.signer_id, "physical_resource_request_registry_signer.signer_id"),
    key_id: assertToken(input.key_id, "physical_resource_request_registry_signer.key_id", "registry-key"),
    signer_epoch: assertInteger(
      input.signer_epoch,
      "physical_resource_request_registry_signer.signer_epoch",
      1,
    ),
    public_key_digest: digest,
    isolation_assurance: RESOURCE_REQUEST_REGISTRY_ISOLATION_ASSURANCE,
    production_attested: false,
  });
  SIGNERS.add(signer);
  SIGNER_PRIVATE.set(signer, Object.freeze({ private_key: privateKey }));
  return signer;
}

function assertPhysicalResourceRequestRegistrySigner(signer) {
  if (!signer || !Object.isFrozen(signer) || !SIGNERS.has(signer) || !SIGNER_PRIVATE.has(signer)) {
    throw new Error("registry signer must be created by Bob's private factory");
  }
  return signer;
}

function normalizeTrustedSigners(input) {
  assertDataArray(input, "physical_resource_request_registry.trusted_signers", 1, 64);
  const entries = input.map((entry, index) => {
    const label = `physical_resource_request_registry.trusted_signers[${index}]`;
    assertClosedObject(entry, label, [
      "key_id", "signer_epoch", "public_key_digest", "public_key",
    ]);
    const publicKey = assertEd25519Key(entry.public_key, "public", `${label}.public_key`);
    const digest = publicKeyDigest(publicKey);
    if (assertDigest(entry.public_key_digest, `${label}.public_key_digest`) !== digest) {
      throw new Error(`${label}.public_key_digest does not match public_key`);
    }
    return Object.freeze({
      key_id: assertToken(entry.key_id, `${label}.key_id`, "registry-key"),
      signer_epoch: assertInteger(entry.signer_epoch, `${label}.signer_epoch`, 1),
      public_key_digest: digest,
      public_key: publicKey,
    });
  }).sort((left, right) => left.signer_epoch - right.signer_epoch
    || compareProtocolStrings(left.key_id, right.key_id));
  const keyIds = new Set();
  const epochs = new Set();
  const digests = new Set();
  for (const entry of entries) {
    if (keyIds.has(entry.key_id) || epochs.has(entry.signer_epoch)
        || digests.has(entry.public_key_digest)) {
      throw new Error("trusted registry signer key ids, epochs, and public keys must be unique");
    }
    keyIds.add(entry.key_id);
    epochs.add(entry.signer_epoch);
    digests.add(entry.public_key_digest);
  }
  return entries;
}

function trustMapFromEntries(entries) {
  return new Map(entries.map((entry) => [entry.key_id, entry]));
}

function signPayload(privateState, domain, payload) {
  const signer = privateState.signer;
  const authentication = deepFreeze({
    scheme: "ed25519",
    key_usage: RESOURCE_REQUEST_REGISTRY_KEY_USAGE,
    key_id: signer.key_id,
    signer_epoch: signer.signer_epoch,
    public_key_digest: signer.public_key_digest,
    signed_payload_digest: hashCanonicalJson(payload),
  });
  const inputDigest = signatureInputDigest(
    domain,
    privateState.registry_domain_digest,
    payload,
    authentication,
  );
  return deepFreeze({
    ...authentication,
    signature: crypto.sign(
      null,
      Buffer.from(inputDigest, "hex"),
      SIGNER_PRIVATE.get(signer).private_key,
    ).toString("base64url"),
  });
}

function normalizeAuthentication(input, payloadDigest, trustMap, label) {
  assertClosedObject(input, label, [
    "scheme",
    "key_usage",
    "key_id",
    "signer_epoch",
    "public_key_digest",
    "signed_payload_digest",
    "signature",
  ]);
  const authentication = deepFreeze({
    scheme: input.scheme,
    key_usage: input.key_usage,
    key_id: assertToken(input.key_id, `${label}.key_id`, "registry-key"),
    signer_epoch: assertInteger(input.signer_epoch, `${label}.signer_epoch`, 1),
    public_key_digest: assertDigest(input.public_key_digest, `${label}.public_key_digest`),
    signed_payload_digest: assertDigest(input.signed_payload_digest, `${label}.signed_payload_digest`),
    signature: assertCanonicalSignature(input.signature, `${label}.signature`),
  });
  if (authentication.scheme !== "ed25519"
      || authentication.key_usage !== RESOURCE_REQUEST_REGISTRY_KEY_USAGE
      || authentication.signed_payload_digest !== payloadDigest) {
    throw registryError("resource_request_registry_auth_invalid", `${label} is not valid for this signed payload`);
  }
  const trusted = trustMap.get(authentication.key_id);
  if (!trusted || trusted.signer_epoch !== authentication.signer_epoch
      || trusted.public_key_digest !== authentication.public_key_digest) {
    throw registryError("resource_request_registry_auth_invalid", `${label} signer is not enrolled`);
  }
  return { authentication, trusted };
}

function verifyAuthentication(domain, registryDomainDigest, payload, authentication, trusted) {
  const inputDigest = signatureInputDigest(
    domain,
    registryDomainDigest,
    payload,
    authentication,
  );
  if (!crypto.verify(
    null,
    Buffer.from(inputDigest, "hex"),
    trusted.public_key,
    Buffer.from(authentication.signature, "base64url"),
  )) {
    throw registryError("resource_request_registry_auth_invalid", "registry signature verification failed");
  }
}

function normalizeArbiterCommit(input, label) {
  assertClosedObject(input, label, [
    "version",
    "generation",
    "head_digest",
    "prior_head_digest",
    "state_digest",
    "queue_digest",
    "transition_digest",
  ]);
  if (input.version !== 1) throw new Error(`${label}.version must be 1`);
  return deepFreeze({
    version: 1,
    generation: assertInteger(input.generation, `${label}.generation`, 1),
    head_digest: assertDigest(input.head_digest, `${label}.head_digest`),
    prior_head_digest: assertDigest(input.prior_head_digest, `${label}.prior_head_digest`),
    state_digest: assertDigest(input.state_digest, `${label}.state_digest`),
    queue_digest: assertDigest(input.queue_digest, `${label}.queue_digest`),
    transition_digest: assertDigest(input.transition_digest, `${label}.transition_digest`),
  });
}

function normalizeRecordPayload(input, privateState, label) {
  assertClosedObject(input, label, [
    "version",
    "registry_id",
    "registry_domain_digest",
    "registration_state",
    "record_revision",
    "prior_record_digest",
    "reservation_request",
    "resource_bundle",
    "batch_semantics_digest",
    "admission_binding",
    "ticket",
    "arbiter_commit",
  ]);
  if (input.version !== RESOURCE_REQUEST_REGISTRY_RECORD_VERSION) {
    throw new Error(`${label}.version must be ${RESOURCE_REQUEST_REGISTRY_RECORD_VERSION}`);
  }
  if (!["prepared", "finalized"].includes(input.registration_state)) {
    throw new Error(`${label}.registration_state is invalid`);
  }
  const request = normalizePhysicalReservationRequest(
    input.reservation_request,
    `${label}.reservation_request`,
  );
  const bundle = normalizePhysicalResourceBundle(input.resource_bundle, `${label}.resource_bundle`);
  const batchSemanticsDigest = derivePhysicalResourceArbiterBatchKey(bundle);
  if (request.resource_bundle_digest !== bundle.resource_bundle_digest
      || request.source_graph_hash !== privateState.source_graph_hash
      || request.session_nucleus_hash !== privateState.session_nucleus_hash
      || assertDigest(input.batch_semantics_digest, `${label}.batch_semantics_digest`)
        !== batchSemanticsDigest) {
    throw registryError(
      "resource_request_registry_binding_invalid",
      `${label} request, bundle, graph, session, or batch semantics drifted`,
    );
  }
  const base = {
    version: RESOURCE_REQUEST_REGISTRY_RECORD_VERSION,
    registry_id: assertIdentifier(input.registry_id, `${label}.registry_id`),
    registry_domain_digest: assertDigest(
      input.registry_domain_digest,
      `${label}.registry_domain_digest`,
    ),
    registration_state: input.registration_state,
    record_revision: assertInteger(input.record_revision, `${label}.record_revision`, 1, 2),
    prior_record_digest: assertNullableDigest(input.prior_record_digest, `${label}.prior_record_digest`),
    reservation_request: request,
    resource_bundle: bundle,
    batch_semantics_digest: batchSemanticsDigest,
    admission_binding: null,
    ticket: null,
    arbiter_commit: null,
  };
  if (base.registry_id !== privateState.registry_id
      || base.registry_domain_digest !== privateState.registry_domain_digest) {
    throw registryError(
      "resource_request_registry_binding_invalid",
      `${label} is outside the registry domain`,
    );
  }
  if (input.registration_state === "prepared") {
    if (base.record_revision !== 1 || base.prior_record_digest !== null
        || input.admission_binding !== null || input.ticket !== null || input.arbiter_commit !== null) {
      throw registryError(
        "resource_request_registry_binding_invalid",
        `${label} prepared state must not claim an arbiter admission`,
      );
    }
    return deepFreeze(base);
  }
  if (base.record_revision !== 2 || base.prior_record_digest === null
      || input.admission_binding === null || input.ticket === null || input.arbiter_commit === null) {
    throw registryError(
      "resource_request_registry_binding_invalid",
      `${label} finalized state requires an exact prepared predecessor and admission join`,
    );
  }
  const ticket = normalizePhysicalResourceQueueTicket(input.ticket, `${label}.ticket`);
  const arbiterCommit = normalizeArbiterCommit(input.arbiter_commit, `${label}.arbiter_commit`);
  const admissionBinding = verifyPhysicalResourceArbiterAdmissionBinding(
    privateState.admission_port,
    {
      binding: input.admission_binding,
      reservation_request: request,
      resource_bundle: bundle,
      ticket,
      arbiter_commit: arbiterCommit,
    },
  );
  return deepFreeze({
    ...base,
    admission_binding: admissionBinding,
    ticket,
    arbiter_commit: arbiterCommit,
  });
}

function signRegistryRecord(privateState, payloadInput) {
  const payload = normalizeRecordPayload(payloadInput, privateState, "resource_request_registry_record.payload");
  const authentication = signPayload(
    privateState,
    RESOURCE_REQUEST_REGISTRY_RECORD_DOMAIN,
    payload,
  );
  const envelope = deepFreeze({ payload, authentication });
  return deepFreeze({ ...envelope, record_digest: hashCanonicalJson(envelope) });
}

function normalizeSignedRegistryRecord(input, privateState, label) {
  assertClosedObject(input, label, ["payload", "authentication", "record_digest"]);
  const payload = normalizeRecordPayload(input.payload, privateState, `${label}.payload`);
  const payloadDigest = hashCanonicalJson(payload);
  const { authentication, trusted } = normalizeAuthentication(
    input.authentication,
    payloadDigest,
    privateState.trust_map,
    `${label}.authentication`,
  );
  verifyAuthentication(
    RESOURCE_REQUEST_REGISTRY_RECORD_DOMAIN,
    privateState.registry_domain_digest,
    payload,
    authentication,
    trusted,
  );
  const envelope = deepFreeze({ payload, authentication });
  const recordDigest = hashCanonicalJson(envelope);
  if (assertDigest(input.record_digest, `${label}.record_digest`) !== recordDigest) {
    throw registryError(
      "resource_request_registry_auth_invalid",
      `${label}.record_digest does not bind the signed record`,
    );
  }
  return deepFreeze({ ...envelope, record_digest: recordDigest });
}

function sortedRegistryRecords(records) {
  return records.slice().sort((left, right) => compareProtocolStrings(
    left.payload.reservation_request.reservation_request_id,
    right.payload.reservation_request.reservation_request_id,
  ));
}

function normalizeRegistryStatePayload(input, privateState, label) {
  assertClosedObject(input, label, [
    "version",
    "registry_id",
    "registry_domain_digest",
    "max_records",
    "generation",
    "prior_head_digest",
    "record_count",
    "records_digest",
    "records",
    "current_signer_key_id",
    "current_signer_epoch",
  ]);
  if (input.version !== RESOURCE_REQUEST_REGISTRY_STATE_VERSION) {
    throw new Error(`${label}.version must be ${RESOURCE_REQUEST_REGISTRY_STATE_VERSION}`);
  }
  assertDataArray(input.records, `${label}.records`, 0, privateState.max_records);
  const records = sortedRegistryRecords(input.records.map((record, index) => (
    normalizeSignedRegistryRecord(record, privateState, `${label}.records[${index}]`)
  )));
  for (let index = 1; index < records.length; index += 1) {
    if (records[index - 1].payload.reservation_request.reservation_request_id
        === records[index].payload.reservation_request.reservation_request_id) {
      throw registryError(
        "resource_request_registry_duplicate_id",
        `${label} contains duplicate reservation request ids`,
      );
    }
  }
  if (hashCanonicalJson(input.records) !== hashCanonicalJson(records)) {
    throw registryError(
      "resource_request_registry_state_invalid",
      `${label}.records are not in canonical code-unit order`,
    );
  }
  const recordsDigest = hashCanonicalJson(records);
  const payload = deepFreeze({
    version: RESOURCE_REQUEST_REGISTRY_STATE_VERSION,
    registry_id: assertIdentifier(input.registry_id, `${label}.registry_id`),
    registry_domain_digest: assertDigest(
      input.registry_domain_digest,
      `${label}.registry_domain_digest`,
    ),
    max_records: assertInteger(input.max_records, `${label}.max_records`, 1, MAX_REGISTRY_RECORDS),
    generation: assertInteger(input.generation, `${label}.generation`, 0),
    prior_head_digest: assertNullableDigest(input.prior_head_digest, `${label}.prior_head_digest`),
    record_count: assertInteger(input.record_count, `${label}.record_count`, 0, privateState.max_records),
    records_digest: assertDigest(input.records_digest, `${label}.records_digest`),
    records: Object.freeze(records),
    current_signer_key_id: assertToken(
      input.current_signer_key_id,
      `${label}.current_signer_key_id`,
      "registry-key",
    ),
    current_signer_epoch: assertInteger(input.current_signer_epoch, `${label}.current_signer_epoch`, 1),
  });
  if (payload.registry_id !== privateState.registry_id
      || payload.registry_domain_digest !== privateState.registry_domain_digest
      || payload.max_records !== privateState.max_records
      || payload.record_count !== records.length
      || payload.records_digest !== recordsDigest
      || (payload.generation === 0) !== (payload.prior_head_digest === null)) {
    throw registryError(
      "resource_request_registry_state_invalid",
      `${label} metadata or genesis coordinates drifted`,
    );
  }
  return payload;
}

function signRegistryState(privateState, input) {
  const payload = normalizeRegistryStatePayload(input, privateState, "resource_request_registry_state.payload");
  const authentication = signPayload(
    privateState,
    RESOURCE_REQUEST_REGISTRY_STATE_DOMAIN,
    payload,
  );
  const stateDigest = hashCanonicalJson(payload);
  const envelope = deepFreeze({ payload, authentication, state_digest: stateDigest });
  return deepFreeze({ ...envelope, head_digest: hashCanonicalJson(envelope) });
}

function normalizeSignedRegistryState(input, privateState, label = "resource_request_registry_state") {
  assertClosedObject(input, label, ["payload", "authentication", "state_digest", "head_digest"]);
  const payload = normalizeRegistryStatePayload(input.payload, privateState, `${label}.payload`);
  const stateDigest = hashCanonicalJson(payload);
  if (assertDigest(input.state_digest, `${label}.state_digest`) !== stateDigest) {
    throw registryError("resource_request_registry_state_invalid", `${label}.state_digest drifted`);
  }
  const { authentication, trusted } = normalizeAuthentication(
    input.authentication,
    stateDigest,
    privateState.trust_map,
    `${label}.authentication`,
  );
  if (payload.current_signer_key_id !== authentication.key_id
      || payload.current_signer_epoch !== authentication.signer_epoch) {
    throw registryError(
      "resource_request_registry_auth_invalid",
      `${label} signer coordinates do not match its payload`,
    );
  }
  verifyAuthentication(
    RESOURCE_REQUEST_REGISTRY_STATE_DOMAIN,
    privateState.registry_domain_digest,
    payload,
    authentication,
    trusted,
  );
  const envelope = deepFreeze({ payload, authentication, state_digest: stateDigest });
  const headDigest = hashCanonicalJson(envelope);
  if (assertDigest(input.head_digest, `${label}.head_digest`) !== headDigest) {
    throw registryError("resource_request_registry_state_invalid", `${label}.head_digest drifted`);
  }
  return deepFreeze({ ...envelope, head_digest: headDigest });
}

function checkpointForState(state) {
  const value = {
    version: RESOURCE_REQUEST_REGISTRY_CHECKPOINT_VERSION,
    registry_id: state.payload.registry_id,
    registry_domain_digest: state.payload.registry_domain_digest,
    generation: state.payload.generation,
    head_digest: state.head_digest,
    state_digest: state.state_digest,
    records_digest: state.payload.records_digest,
    record_count: state.payload.record_count,
    current_signer_key_id: state.payload.current_signer_key_id,
    current_signer_epoch: state.payload.current_signer_epoch,
  };
  return deepFreeze({ ...value, checkpoint_digest: hashCanonicalJson(value) });
}

function normalizeRegistryCheckpoint(input, privateState, label) {
  assertClosedObject(input, label, [
    "version",
    "registry_id",
    "registry_domain_digest",
    "generation",
    "head_digest",
    "state_digest",
    "records_digest",
    "record_count",
    "current_signer_key_id",
    "current_signer_epoch",
    "checkpoint_digest",
  ]);
  if (input.version !== RESOURCE_REQUEST_REGISTRY_CHECKPOINT_VERSION) {
    throw new Error(`${label}.version must be ${RESOURCE_REQUEST_REGISTRY_CHECKPOINT_VERSION}`);
  }
  const value = deepFreeze({
    version: RESOURCE_REQUEST_REGISTRY_CHECKPOINT_VERSION,
    registry_id: assertIdentifier(input.registry_id, `${label}.registry_id`),
    registry_domain_digest: assertDigest(input.registry_domain_digest, `${label}.registry_domain_digest`),
    generation: assertInteger(input.generation, `${label}.generation`, 0),
    head_digest: assertDigest(input.head_digest, `${label}.head_digest`),
    state_digest: assertDigest(input.state_digest, `${label}.state_digest`),
    records_digest: assertDigest(input.records_digest, `${label}.records_digest`),
    record_count: assertInteger(input.record_count, `${label}.record_count`, 0, privateState.max_records),
    current_signer_key_id: assertToken(
      input.current_signer_key_id,
      `${label}.current_signer_key_id`,
      "registry-key",
    ),
    current_signer_epoch: assertInteger(input.current_signer_epoch, `${label}.current_signer_epoch`, 1),
  });
  const checkpointDigest = hashCanonicalJson(value);
  if (assertDigest(input.checkpoint_digest, `${label}.checkpoint_digest`) !== checkpointDigest
      || value.registry_id !== privateState.registry_id
      || value.registry_domain_digest !== privateState.registry_domain_digest) {
    throw registryError("resource_request_registry_checkpoint_invalid", `${label} drifted`);
  }
  return deepFreeze({ ...value, checkpoint_digest: checkpointDigest });
}

function assertCheckpointMatchesState(checkpoint, state, label) {
  const expected = checkpointForState(state);
  if (hashCanonicalJson(checkpoint) !== hashCanonicalJson(expected)) {
    throw registryError(
      "resource_request_registry_checkpoint_invalid",
      `${label} does not bind the exact signed state`,
    );
  }
}

function normalizeRegistrySnapshot(input, privateState, label = "resource_request_registry_snapshot") {
  assertClosedObject(input, label, ["version", "state", "checkpoint"]);
  if (input.version !== RESOURCE_REQUEST_REGISTRY_CAS_VERSION) {
    throw new Error(`${label}.version must be ${RESOURCE_REQUEST_REGISTRY_CAS_VERSION}`);
  }
  if ((input.state === null) !== (input.checkpoint === null)) {
    throw registryError(
      "resource_request_registry_checkpoint_invalid",
      `${label} state and checkpoint must be absent or present together`,
    );
  }
  if (input.state === null) return deepFreeze({ version: 1, state: null, checkpoint: null });
  const state = normalizeSignedRegistryState(input.state, privateState, `${label}.state`);
  const checkpoint = normalizeRegistryCheckpoint(
    input.checkpoint,
    privateState,
    `${label}.checkpoint`,
  );
  assertCheckpointMatchesState(checkpoint, state, label);
  return deepFreeze({ version: 1, state, checkpoint });
}

function withStatePortOperation(statePort, callback) {
  if (ACTIVE_STATE_PORTS.has(statePort)) {
    throw registryError(
      "resource_request_registry_reentrant",
      "registry state port cannot be re-entered",
    );
  }
  ACTIVE_STATE_PORTS.add(statePort);
  try {
    return callback();
  } finally {
    ACTIVE_STATE_PORTS.delete(statePort);
  }
}

function readRegistrySnapshot(privateState) {
  const port = privateState.state_port;
  let raw;
  try {
    raw = withStatePortOperation(port, () => assertSynchronousResult(
      STATE_PORT_PRIVATE.get(port).read_current(),
      "registry state read_current",
    ));
  } catch (cause) {
    if (cause && cause.code === "resource_request_registry_reentrant") throw cause;
    throw registryError(
      "resource_request_registry_state_unavailable",
      "registry state could not be read synchronously",
      cause,
    );
  }
  try {
    return normalizeRegistrySnapshot(raw, privateState);
  } catch (cause) {
    throw registryError(
      "resource_request_registry_state_invalid",
      "registry state/checkpoint is invalid",
      cause,
    );
  }
}

function normalizeCasResult(input, privateState) {
  assertClosedObject(input, "resource_request_registry_cas_result", [
    "version", "disposition", "observed_checkpoint",
  ]);
  if (input.version !== RESOURCE_REQUEST_REGISTRY_CAS_VERSION
      || !["committed", "conflict", "ambiguous"].includes(input.disposition)) {
    throw new Error("resource_request_registry_cas_result is invalid");
  }
  const checkpoint = input.observed_checkpoint === null
    ? null
    : normalizeRegistryCheckpoint(
      input.observed_checkpoint,
      privateState,
      "resource_request_registry_cas_result.observed_checkpoint",
    );
  return deepFreeze({
    version: RESOURCE_REQUEST_REGISTRY_CAS_VERSION,
    disposition: input.disposition,
    observed_checkpoint: checkpoint,
  });
}

function invokeRegistryCas(privateState, expectedCheckpoint, nextState, nextCheckpoint) {
  const request = deepFreeze({
    version: RESOURCE_REQUEST_REGISTRY_CAS_VERSION,
    expected_checkpoint: expectedCheckpoint,
    next_state: nextState,
    next_checkpoint: nextCheckpoint,
  });
  let raw;
  try {
    raw = withStatePortOperation(privateState.state_port, () => assertSynchronousResult(
      STATE_PORT_PRIVATE.get(privateState.state_port).compare_and_set(request),
      "registry state compare_and_set",
    ));
  } catch (cause) {
    throw registryError(
      "resource_request_registry_cas_ambiguous",
      "registry CAS failed without a definitive disposition",
      cause,
    );
  }
  try {
    return normalizeCasResult(raw, privateState);
  } catch (cause) {
    throw registryError(
      "resource_request_registry_cas_ambiguous",
      "registry CAS returned an invalid disposition",
      cause,
    );
  }
}

function assertRuntimeCheckpointProgress(privateState, checkpoint, state) {
  const previous = privateState.last_checkpoint;
  if (!previous) return;
  if (checkpoint.current_signer_epoch < previous.current_signer_epoch) {
    throw registryError(
      "resource_request_registry_signer_rollback",
      "registry signer epoch rolled back",
    );
  }
  if (checkpoint.generation < previous.generation) {
    throw registryError("resource_request_registry_rollback", "registry checkpoint rolled back");
  }
  if (checkpoint.generation === previous.generation) {
    if (checkpoint.checkpoint_digest !== previous.checkpoint_digest) {
      throw registryError("resource_request_registry_fork", "registry checkpoint forked at one generation");
    }
    return;
  }
  if (checkpoint.generation !== previous.generation + 1
      || state.payload.prior_head_digest !== previous.head_digest) {
    throw registryError(
      "resource_request_registry_history_gap",
      "registry checkpoint skipped an unverified predecessor",
    );
  }
  const nextRecords = new Map(state.payload.records.map((record) => [
    record.payload.reservation_request.reservation_request_id,
    record,
  ]));
  for (const priorRecord of privateState.last_records) {
    const nextRecord = nextRecords.get(
      priorRecord.payload.reservation_request.reservation_request_id,
    );
    if (!nextRecord) {
      throw registryError(
        "resource_request_registry_history_rewrite",
        "registry successor evicted an authenticated request record",
      );
    }
    if (nextRecord.record_digest === priorRecord.record_digest) continue;
    const priorPayload = priorRecord.payload;
    const nextPayload = nextRecord.payload;
    if (priorPayload.registration_state !== "prepared"
        || nextPayload.registration_state !== "finalized"
        || nextPayload.prior_record_digest !== priorRecord.record_digest
        || hashCanonicalJson(nextPayload.reservation_request)
          !== hashCanonicalJson(priorPayload.reservation_request)
        || hashCanonicalJson(nextPayload.resource_bundle)
          !== hashCanonicalJson(priorPayload.resource_bundle)
        || nextPayload.batch_semantics_digest !== priorPayload.batch_semantics_digest) {
      throw registryError(
        "resource_request_registry_history_rewrite",
        "registry successor rewrote authenticated request history",
      );
    }
  }
}

function retainRegistrySnapshot(privateState, snapshot) {
  privateState.last_checkpoint = snapshot.checkpoint;
  privateState.last_record_count = snapshot.state.payload.record_count;
  privateState.last_records = snapshot.state.payload.records;
}

function readCurrentRegistryState(privateState) {
  const snapshot = readRegistrySnapshot(privateState);
  if (!snapshot.state) {
    throw registryError("resource_request_registry_rollback", "initialized registry state disappeared");
  }
  assertRuntimeCheckpointProgress(privateState, snapshot.checkpoint, snapshot.state);
  if (snapshot.state.payload.current_signer_epoch > privateState.signer.signer_epoch) {
    throw registryError("resource_request_registry_signer_rollback", "current signer epoch is stale");
  }
  retainRegistrySnapshot(privateState, snapshot);
  return snapshot;
}

function makeRegistryState(privateState, generation, priorHeadDigest, records) {
  const canonicalRecords = Object.freeze(sortedRegistryRecords(records));
  return signRegistryState(privateState, {
    version: RESOURCE_REQUEST_REGISTRY_STATE_VERSION,
    registry_id: privateState.registry_id,
    registry_domain_digest: privateState.registry_domain_digest,
    max_records: privateState.max_records,
    generation,
    prior_head_digest: priorHeadDigest,
    record_count: canonicalRecords.length,
    records_digest: hashCanonicalJson(canonicalRecords),
    records: canonicalRecords,
    current_signer_key_id: privateState.signer.key_id,
    current_signer_epoch: privateState.signer.signer_epoch,
  });
}

function commitRegistryRecords(privateState, currentSnapshot, records) {
  const nextState = makeRegistryState(
    privateState,
    currentSnapshot.state.payload.generation + 1,
    currentSnapshot.state.head_digest,
    records,
  );
  const nextCheckpoint = checkpointForState(nextState);
  const result = invokeRegistryCas(
    privateState,
    currentSnapshot.checkpoint,
    nextState,
    nextCheckpoint,
  );
  if (result.disposition === "ambiguous") {
    throw registryError(
      "resource_request_registry_cas_ambiguous",
      "registry CAS outcome is ambiguous; reconcile before retrying external work",
    );
  }
  if (result.disposition === "conflict") {
    throw registryError(
      "resource_request_registry_cas_stale",
      "registry CAS predecessor is stale",
    );
  }
  if (!result.observed_checkpoint
      || result.observed_checkpoint.checkpoint_digest !== nextCheckpoint.checkpoint_digest) {
    throw registryError(
      "resource_request_registry_cas_ambiguous",
      "registry CAS acknowledgement did not bind the exact next checkpoint",
    );
  }
  const confirmed = readRegistrySnapshot(privateState);
  if (!confirmed.state || !confirmed.checkpoint
      || confirmed.checkpoint.checkpoint_digest !== nextCheckpoint.checkpoint_digest
      || confirmed.state.head_digest !== nextState.head_digest) {
    throw registryError(
      "resource_request_registry_cas_ambiguous",
      "registry CAS acknowledgement was not confirmed by an exact read",
    );
  }
  assertRuntimeCheckpointProgress(privateState, confirmed.checkpoint, confirmed.state);
  retainRegistrySnapshot(privateState, confirmed);
  return confirmed;
}

function withRegistryOperation(registry, callback) {
  if (ACTIVE_REGISTRIES.has(registry)) {
    throw registryError("resource_request_registry_reentrant", "registry operation cannot re-enter");
  }
  ACTIVE_REGISTRIES.add(registry);
  try {
    return callback();
  } finally {
    ACTIVE_REGISTRIES.delete(registry);
  }
}

function createPhysicalResourceRequestRegistry(input = {}) {
  assertClosedObject(input, "physical_resource_request_registry", [
    "registry_id",
    "registry_domain_digest",
    "state_port",
    "admission_port",
    "signer",
    "trusted_signers",
    "max_records",
  ], ["restart_checkpoint"]);
  const statePort = assertPhysicalResourceRequestRegistryStatePort(input.state_port);
  const admissionPort = assertPhysicalResourceArbiterAdmissionPort(input.admission_port);
  const signer = assertPhysicalResourceRequestRegistrySigner(input.signer);
  const registryDomainDigest = assertDigest(
    input.registry_domain_digest,
    "physical_resource_request_registry.registry_domain_digest",
  );
  if (statePort.registry_domain_digest !== registryDomainDigest) {
    throw registryError(
      "resource_request_registry_domain_drift",
      "registry state port domain does not match the registry",
    );
  }
  const trustedSigners = normalizeTrustedSigners(input.trusted_signers);
  const trustMap = trustMapFromEntries(trustedSigners);
  const currentTrust = trustMap.get(signer.key_id);
  const highestEpoch = trustedSigners[trustedSigners.length - 1].signer_epoch;
  if (!currentTrust || currentTrust.signer_epoch !== signer.signer_epoch
      || currentTrust.public_key_digest !== signer.public_key_digest
      || signer.signer_epoch !== highestEpoch) {
    throw registryError(
      "resource_request_registry_signer_invalid",
      "registry signer is not the exact highest-epoch enrolled key",
    );
  }
  const privateState = {
    registry_id: assertIdentifier(input.registry_id, "physical_resource_request_registry.registry_id"),
    registry_domain_digest: registryDomainDigest,
    state_port: statePort,
    admission_port: admissionPort,
    signer,
    trusted_signers: trustedSigners,
    trust_map: trustMap,
    max_records: assertInteger(
      input.max_records,
      "physical_resource_request_registry.max_records",
      1,
      MAX_REGISTRY_RECORDS,
    ),
    source_graph_hash: admissionPort.source_graph_hash,
    session_nucleus_hash: admissionPort.session_nucleus_hash,
    last_checkpoint: null,
    last_record_count: 0,
    last_records: Object.freeze([]),
  };
  const snapshot = readRegistrySnapshot(privateState);
  if (!snapshot.state) {
    if (input.restart_checkpoint != null) {
      throw registryError(
        "resource_request_registry_restart_invalid",
        "restart checkpoint was supplied for an empty registry",
      );
    }
    const genesis = makeRegistryState(privateState, 0, null, []);
    const checkpoint = checkpointForState(genesis);
    const result = invokeRegistryCas(privateState, null, genesis, checkpoint);
    if (result.disposition !== "committed" || !result.observed_checkpoint
        || result.observed_checkpoint.checkpoint_digest !== checkpoint.checkpoint_digest) {
      throw registryError(
        result.disposition === "conflict"
          ? "resource_request_registry_cas_stale"
          : "resource_request_registry_cas_ambiguous",
        "registry genesis was not committed exactly",
      );
    }
    const confirmed = readRegistrySnapshot(privateState);
    if (!confirmed.state || confirmed.state.head_digest !== genesis.head_digest
        || confirmed.checkpoint.checkpoint_digest !== checkpoint.checkpoint_digest) {
      throw registryError(
        "resource_request_registry_cas_ambiguous",
        "registry genesis acknowledgement was not confirmed",
      );
    }
    retainRegistrySnapshot(privateState, confirmed);
  } else {
    if (input.restart_checkpoint == null) {
      throw registryError(
        "resource_request_registry_restart_checkpoint_required",
        "existing registry state requires the retained restart checkpoint",
      );
    }
    const restartCheckpoint = normalizeRegistryCheckpoint(
      input.restart_checkpoint,
      privateState,
      "physical_resource_request_registry.restart_checkpoint",
    );
    if (restartCheckpoint.checkpoint_digest !== snapshot.checkpoint.checkpoint_digest) {
      throw registryError(
        "resource_request_registry_rollback",
        "registry state does not match the retained restart checkpoint",
      );
    }
    if (snapshot.state.payload.current_signer_epoch > signer.signer_epoch) {
      throw registryError(
        "resource_request_registry_signer_rollback",
        "registry restart signer epoch is older than the durable state",
      );
    }
    retainRegistrySnapshot(privateState, snapshot);
  }
  const registry = deepFreeze({
    version: RESOURCE_REQUEST_REGISTRY_VERSION,
    registry_id: privateState.registry_id,
    registry_domain_digest: registryDomainDigest,
    state_port_id: statePort.port_id,
    admission_port_id: admissionPort.port_id,
    journal_domain_digest: admissionPort.journal_domain_digest,
    arbiter_config_digest: admissionPort.arbiter_config_digest,
    source_graph_hash: privateState.source_graph_hash,
    session_nucleus_hash: privateState.session_nucleus_hash,
    max_records: privateState.max_records,
    workflow_contract: RESOURCE_REQUEST_REGISTRY_WORKFLOW,
    current_signer_key_id: signer.key_id,
    current_signer_epoch: signer.signer_epoch,
    current_signer_public_key_digest: signer.public_key_digest,
    durability_assurance: RESOURCE_REQUEST_REGISTRY_DURABILITY_ASSURANCE,
    isolation_assurance: RESOURCE_REQUEST_REGISTRY_ISOLATION_ASSURANCE,
    production_attested: false,
  });
  REGISTRIES.add(registry);
  REGISTRY_PRIVATE.set(registry, privateState);
  return registry;
}

function assertPhysicalResourceRequestRegistry(registry) {
  if (!registry || !Object.isFrozen(registry) || !REGISTRIES.has(registry)
      || !REGISTRY_PRIVATE.has(registry)) {
    throw new Error("resource request registry must be created by Bob's private factory");
  }
  return registry;
}

function findRecord(state, reservationRequestId) {
  return state.payload.records.find((record) => (
    record.payload.reservation_request.reservation_request_id === reservationRequestId
  )) || null;
}

function projectRegistrationRecord(record) {
  const payload = record.payload;
  const binding = payload.admission_binding;
  return deepFreeze({
    version: RESOURCE_REQUEST_REGISTRY_PROJECTION_VERSION,
    registration_state: payload.registration_state,
    record_revision: payload.record_revision,
    record_digest: record.record_digest,
    prior_record_digest: payload.prior_record_digest,
    reservation_request_id: payload.reservation_request.reservation_request_id,
    reservation_request_digest: payload.reservation_request.reservation_request_digest,
    node_id: payload.reservation_request.node_id,
    contract_hash: payload.reservation_request.contract_hash,
    source_graph_hash: payload.reservation_request.source_graph_hash,
    session_nucleus_hash: payload.reservation_request.session_nucleus_hash,
    resource_bundle_digest: payload.resource_bundle.resource_bundle_digest,
    batch_semantics_digest: payload.batch_semantics_digest,
    admission_binding_digest: binding == null ? null : binding.binding_digest,
    ticket_digest: payload.ticket == null ? null : payload.ticket.ticket_digest,
    enqueue_command_digest: binding == null ? null : binding.enqueue_command_digest,
    commit_generation: binding == null ? null : binding.commit_generation,
    commit_head_digest: binding == null ? null : binding.commit_head_digest,
    commit_prior_head_digest: binding == null ? null : binding.commit_prior_head_digest,
    commit_state_digest: binding == null ? null : binding.commit_state_digest,
    commit_queue_digest: binding == null ? null : binding.commit_queue_digest,
    commit_transition_digest: binding == null ? null : binding.commit_transition_digest,
    requires_arbiter_reconciliation: payload.registration_state === "prepared",
    production_attested: false,
  });
}

function mintPrepareCapability(registry, record) {
  const payload = record.payload;
  const capability = deepFreeze({
    version: RESOURCE_REQUEST_REGISTRY_CAPABILITY_VERSION,
    registry_id: registry.registry_id,
    reservation_request_id: payload.reservation_request.reservation_request_id,
    reservation_request_digest: payload.reservation_request.reservation_request_digest,
    prepared_record_digest: payload.registration_state === "prepared"
      ? record.record_digest
      : payload.prior_record_digest,
  });
  PREPARE_CAPABILITIES.add(capability);
  PREPARE_CAPABILITY_PRIVATE.set(capability, Object.freeze({ registry }));
  return capability;
}

function assertPrepareCapability(registry, capability) {
  if (!capability || !Object.isFrozen(capability) || !PREPARE_CAPABILITIES.has(capability)
      || !PREPARE_CAPABILITY_PRIVATE.has(capability)
      || PREPARE_CAPABILITY_PRIVATE.get(capability).registry !== registry) {
    throw registryError(
      "resource_request_registry_capability_invalid",
      "prepare capability is not privately bound to this registry",
    );
  }
  return capability;
}

function makePrepareResult(registry, disposition, record) {
  return deepFreeze({
    version: RESOURCE_REQUEST_REGISTRY_PROJECTION_VERSION,
    disposition,
    registration: projectRegistrationRecord(record),
    prepare_capability: mintPrepareCapability(registry, record),
  });
}

function assertExactPreparedInput(existing, request, bundle, batchSemanticsDigest) {
  const payload = existing.payload;
  if (payload.reservation_request.reservation_request_digest !== request.reservation_request_digest
      || payload.resource_bundle.resource_bundle_digest !== bundle.resource_bundle_digest
      || payload.batch_semantics_digest !== batchSemanticsDigest
      || hashCanonicalJson(payload.reservation_request) !== hashCanonicalJson(request)
      || hashCanonicalJson(payload.resource_bundle) !== hashCanonicalJson(bundle)) {
    throw registryError(
      "resource_request_registry_duplicate_conflict",
      "reservation request id is already bound to different canonical content",
    );
  }
}

function preparePhysicalResourceRequestRegistration(registry, input = {}) {
  assertPhysicalResourceRequestRegistry(registry);
  assertClosedObject(input, "physical_resource_request_registration_prepare", [
    "reservation_request", "resource_bundle",
  ]);
  return withRegistryOperation(registry, () => {
    const privateState = REGISTRY_PRIVATE.get(registry);
    const request = normalizePhysicalReservationRequest(
      input.reservation_request,
      "physical_resource_request_registration_prepare.reservation_request",
    );
    const bundle = normalizePhysicalResourceBundle(
      input.resource_bundle,
      "physical_resource_request_registration_prepare.resource_bundle",
    );
    const batchSemanticsDigest = derivePhysicalResourceArbiterBatchKey(bundle);
    if (request.resource_bundle_digest !== bundle.resource_bundle_digest
        || request.source_graph_hash !== privateState.source_graph_hash
        || request.session_nucleus_hash !== privateState.session_nucleus_hash) {
      throw registryError(
        "resource_request_registry_binding_invalid",
        "prepared request/bundle is outside the registry graph, session, or bundle binding",
      );
    }
    const current = readCurrentRegistryState(privateState);
    const existing = findRecord(current.state, request.reservation_request_id);
    if (existing) {
      assertExactPreparedInput(existing, request, bundle, batchSemanticsDigest);
      return makePrepareResult(
        registry,
        existing.payload.registration_state === "prepared"
          ? "existing_prepared"
          : "existing_finalized",
        existing,
      );
    }
    if (current.state.payload.record_count >= privateState.max_records) {
      throw registryError(
        "resource_request_registry_capacity_exhausted",
        "registry capacity is exhausted; records cannot be evicted without a checkpointed proof",
      );
    }
    const record = signRegistryRecord(privateState, {
      version: RESOURCE_REQUEST_REGISTRY_RECORD_VERSION,
      registry_id: privateState.registry_id,
      registry_domain_digest: privateState.registry_domain_digest,
      registration_state: "prepared",
      record_revision: 1,
      prior_record_digest: null,
      reservation_request: request,
      resource_bundle: bundle,
      batch_semantics_digest: batchSemanticsDigest,
      admission_binding: null,
      ticket: null,
      arbiter_commit: null,
    });
    const committed = commitRegistryRecords(
      privateState,
      current,
      [...current.state.payload.records, record],
    );
    const retained = findRecord(committed.state, request.reservation_request_id);
    if (!retained || retained.record_digest !== record.record_digest) {
      throw registryError(
        "resource_request_registry_cas_ambiguous",
        "prepared record was not retained exactly after CAS",
      );
    }
    return makePrepareResult(registry, "created_prepared", retained);
  });
}

function rehydratePhysicalResourceRequestRegistrationCapability(registry, input = {}) {
  assertPhysicalResourceRequestRegistry(registry);
  assertClosedObject(input, "physical_resource_request_registration_rehydrate", [
    "reservation_request_id", "reservation_request_digest",
  ]);
  return withRegistryOperation(registry, () => {
    const privateState = REGISTRY_PRIVATE.get(registry);
    const requestId = assertToken(
      input.reservation_request_id,
      "physical_resource_request_registration_rehydrate.reservation_request_id",
      "reservation-request",
    );
    const requestDigest = assertDigest(
      input.reservation_request_digest,
      "physical_resource_request_registration_rehydrate.reservation_request_digest",
    );
    const current = readCurrentRegistryState(privateState);
    const record = findRecord(current.state, requestId);
    if (!record || record.payload.reservation_request.reservation_request_digest !== requestDigest) {
      throw registryError(
        "resource_request_registry_record_not_found",
        "exact prepared request registration was not found",
      );
    }
    return mintPrepareCapability(registry, record);
  });
}

function verifyFinalizeProof(privateState, record, input) {
  const ticket = normalizePhysicalResourceQueueTicket(
    input.ticket,
    "physical_resource_request_registration_finalize.ticket",
  );
  const arbiterCommit = normalizeArbiterCommit(
    input.arbiter_commit,
    "physical_resource_request_registration_finalize.arbiter_commit",
  );
  const admissionBinding = verifyPhysicalResourceArbiterAdmissionBinding(
    privateState.admission_port,
    {
      binding: input.admission_binding,
      reservation_request: record.payload.reservation_request,
      resource_bundle: record.payload.resource_bundle,
      ticket,
      arbiter_commit: arbiterCommit,
    },
  );
  return { admissionBinding, ticket, arbiterCommit };
}

function finalizePhysicalResourceRequestRegistration(registry, input = {}) {
  assertPhysicalResourceRequestRegistry(registry);
  assertClosedObject(input, "physical_resource_request_registration_finalize", [
    "prepare_capability", "admission_binding", "ticket", "arbiter_commit",
  ]);
  const capability = assertPrepareCapability(registry, input.prepare_capability);
  return withRegistryOperation(registry, () => {
    const privateState = REGISTRY_PRIVATE.get(registry);
    const current = readCurrentRegistryState(privateState);
    const record = findRecord(current.state, capability.reservation_request_id);
    if (!record
        || record.payload.reservation_request.reservation_request_digest
          !== capability.reservation_request_digest) {
      throw registryError(
        "resource_request_registry_capability_invalid",
        "prepare capability no longer resolves to its exact request",
      );
    }
    const proof = verifyFinalizeProof(privateState, record, input);
    if (record.payload.registration_state === "finalized") {
      if (record.payload.prior_record_digest !== capability.prepared_record_digest
          || hashCanonicalJson(record.payload.admission_binding)
            !== hashCanonicalJson(proof.admissionBinding)
          || hashCanonicalJson(record.payload.ticket) !== hashCanonicalJson(proof.ticket)
          || hashCanonicalJson(record.payload.arbiter_commit)
            !== hashCanonicalJson(proof.arbiterCommit)) {
        throw registryError(
          "resource_request_registry_duplicate_conflict",
          "finalized request is already bound to different arbiter admission coordinates",
        );
      }
      return deepFreeze({
        version: RESOURCE_REQUEST_REGISTRY_PROJECTION_VERSION,
        disposition: "existing_finalized",
        registration: projectRegistrationRecord(record),
      });
    }
    if (record.record_digest !== capability.prepared_record_digest) {
      throw registryError(
        "resource_request_registry_capability_invalid",
        "prepare capability does not bind the current prepared record",
      );
    }
    const finalized = signRegistryRecord(privateState, {
      ...record.payload,
      registration_state: "finalized",
      record_revision: 2,
      prior_record_digest: record.record_digest,
      admission_binding: proof.admissionBinding,
      ticket: proof.ticket,
      arbiter_commit: proof.arbiterCommit,
    });
    const records = current.state.payload.records.map((candidate) => (
      candidate.record_digest === record.record_digest ? finalized : candidate
    ));
    const committed = commitRegistryRecords(privateState, current, records);
    const retained = findRecord(committed.state, capability.reservation_request_id);
    if (!retained || retained.record_digest !== finalized.record_digest) {
      throw registryError(
        "resource_request_registry_cas_ambiguous",
        "finalized admission join was not retained exactly after CAS",
      );
    }
    return deepFreeze({
      version: RESOURCE_REQUEST_REGISTRY_PROJECTION_VERSION,
      disposition: "created_finalized",
      registration: projectRegistrationRecord(retained),
    });
  });
}

function reconcilePhysicalResourceRequestRegistration(registry, input = {}) {
  assertPhysicalResourceRequestRegistry(registry);
  assertClosedObject(input, "physical_resource_request_registration_reconcile", [
    "reservation_request_id", "reservation_request_digest",
  ]);
  return withRegistryOperation(registry, () => {
    const requestId = assertToken(
      input.reservation_request_id,
      "physical_resource_request_registration_reconcile.reservation_request_id",
      "reservation-request",
    );
    const requestDigest = assertDigest(
      input.reservation_request_digest,
      "physical_resource_request_registration_reconcile.reservation_request_digest",
    );
    const current = readCurrentRegistryState(REGISTRY_PRIVATE.get(registry));
    const record = findRecord(current.state, requestId);
    if (!record || record.payload.reservation_request.reservation_request_digest !== requestDigest) {
      throw registryError(
        "resource_request_registry_record_not_found",
        "exact request registration was not found",
      );
    }
    return projectRegistrationRecord(record);
  });
}

function projectPhysicalResourceRequestRegistry(registry) {
  assertPhysicalResourceRequestRegistry(registry);
  return withRegistryOperation(registry, () => {
    const privateState = REGISTRY_PRIVATE.get(registry);
    const current = readCurrentRegistryState(privateState);
    return deepFreeze({
      version: RESOURCE_REQUEST_REGISTRY_PROJECTION_VERSION,
      registry_id: registry.registry_id,
      registry_domain_digest: registry.registry_domain_digest,
      generation: current.state.payload.generation,
      head_digest: current.state.head_digest,
      state_digest: current.state.state_digest,
      records_digest: current.state.payload.records_digest,
      record_count: current.state.payload.record_count,
      max_records: registry.max_records,
      current_signer_key_id: current.state.payload.current_signer_key_id,
      current_signer_epoch: current.state.payload.current_signer_epoch,
      checkpoint: current.checkpoint,
      durability_assurance: registry.durability_assurance,
      production_attested: false,
    });
  });
}

function physicalResourceRequestRegistryReadiness(registry) {
  assertPhysicalResourceRequestRegistry(registry);
  const privateState = REGISTRY_PRIVATE.get(registry);
  return deepFreeze({
    version: RESOURCE_REQUEST_REGISTRY_READINESS_VERSION,
    production_ready: false,
    production_attested: false,
    workflow_contract: RESOURCE_REQUEST_REGISTRY_WORKFLOW,
    durability_assurance: RESOURCE_REQUEST_REGISTRY_DURABILITY_ASSURANCE,
    isolation_assurance: RESOURCE_REQUEST_REGISTRY_ISOLATION_ASSURANCE,
    generation: privateState.last_checkpoint.generation,
    head_digest: privateState.last_checkpoint.head_digest,
    record_count: privateState.last_record_count,
    max_records: privateState.max_records,
    blockers: Object.freeze([
      "registry_prepare_and_arbiter_enqueue_are_not_one_atomic_external_transaction",
      "registry_state_and_checkpoint_callback_durability_is_unattested",
      "registry_brand_and_signer_are_not_a_process_or_os_security_boundary",
      "prepared_records_require_arbiter_journal_reconciliation_after_crash",
      "proof_preserving_registry_compaction_is_not_implemented",
    ]),
  });
}

module.exports = {
  MAX_REGISTRY_RECORDS,
  RESOURCE_REQUEST_REGISTRY_DURABILITY_ASSURANCE,
  RESOURCE_REQUEST_REGISTRY_ISOLATION_ASSURANCE,
  RESOURCE_REQUEST_REGISTRY_WORKFLOW,
  assertPhysicalResourceRequestRegistry,
  assertPhysicalResourceRequestRegistrySigner,
  assertPhysicalResourceRequestRegistryStatePort,
  createPhysicalResourceRequestRegistry,
  createPhysicalResourceRequestRegistrySigner,
  createPhysicalResourceRequestRegistryStatePort,
  finalizePhysicalResourceRequestRegistration,
  physicalResourceRequestRegistryReadiness,
  preparePhysicalResourceRequestRegistration,
  projectPhysicalResourceRequestRegistry,
  reconcilePhysicalResourceRequestRegistration,
  rehydratePhysicalResourceRequestRegistrationCapability,
};
