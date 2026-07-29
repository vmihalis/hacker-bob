"use strict";

// Provider-neutral authenticated grant/GO/result exchange for the final
// physical effect seam. This JavaScript implementation is a contract and
// hostile-test fixture: caller-held keys and caller-supplied durability
// observations are never production authority. A native, independently
// privileged custodian must perform the writes, fsyncs, signing, and live-state
// reads before this protocol can authorize hardware.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const {
  canonicalJson,
  hashCanonicalJson,
} = require("../../../mcp/lib/verification-contracts.js");

// Capture the small primordial surface used while traversing caller records.
// In particular, never append through Array.prototype: a numeric prototype
// setter must not intercept construction of a verified chain projection.
const arrayIsArray = Array.isArray;
const arrayPrototype = Array.prototype;
const bufferCompare = Buffer.compare;
const bufferFrom = Buffer.from;
const bufferIsBuffer = Buffer.isBuffer;
const bufferPrototypeToString = Buffer.prototype.toString;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectIsFrozen = Object.isFrozen;
const asyncFunctionPrototype = objectGetPrototypeOf(async function asyncFunctionPrimordial() {});
const objectPrototype = Object.prototype;
const reflectOwnKeys = Reflect.ownKeys;
const utilIsProxy = utilTypes.isProxy;

const AUTHENTICATED_EXCHANGE_VERSION = 1;
const AUTHENTICATED_EXCHANGE_PROTOCOL =
  "hacker-bob/authenticated-durable-physical-exchange/v1";
const SIGNATURE_SCHEME = "ed25519";
const FIXTURE_ASSURANCE = "caller_held_javascript_contract_fixture";
const DURABILITY_SCHEME = "append_fdatasync_directory_fsync_v1";
const DURABILITY_EVIDENCE_ORIGIN = "caller_asserted_non_production_fixture";
const DURABLE_READBACK_CONSISTENCY_MODEL =
  "synchronous_strongly_consistent_exact_canonical_bytes_v1";
const MAX_RECORD_BYTES = 128 * 1024;
const MAX_CHAIN_ENTRIES = 256;
const MAX_DURABILITY_ENTRIES = MAX_CHAIN_ENTRIES + 2;
const MAX_UINT64 = (1n << 64n) - 1n;

const ROLE_DEFINITIONS = Object.freeze({
  grant_authority: Object.freeze({
    key_usage: "physical_capability_grant_signing",
    record_kinds: Object.freeze(["capability_grant"]),
  }),
  go_authority: Object.freeze({
    key_usage: "physical_commit_go_signing",
    record_kinds: Object.freeze(["commit_go"]),
  }),
  effect_worker: Object.freeze({
    key_usage: "physical_terminal_receipt_signing",
    record_kinds: Object.freeze(["terminal_receipt"]),
  }),
  durability_custodian: Object.freeze({
    key_usage: "physical_durable_exchange_signing",
    record_kinds: Object.freeze([
      "journal_entry",
      "outbox_record",
      "durability_attestation",
    ]),
  }),
});
const ROLES = Object.freeze(Object.keys(ROLE_DEFINITIONS));
const recordRoleTable = objectCreate(null);
for (let roleIndex = 0; roleIndex < ROLES.length; roleIndex += 1) {
  const role = ROLES[roleIndex];
  const kinds = ROLE_DEFINITIONS[role].record_kinds;
  for (let kindIndex = 0; kindIndex < kinds.length; kindIndex += 1) {
    objectDefineProperty(recordRoleTable, kinds[kindIndex], {
      value: role, enumerable: true, writable: false, configurable: false,
    });
  }
}
const RECORD_ROLE = objectFreeze(recordRoleTable);
const RECORD_DOMAINS = Object.freeze({
  capability_grant: "hacker-bob/physical-capability-grant-record/v1",
  commit_go: "hacker-bob/physical-commit-go-record/v1",
  terminal_receipt: "hacker-bob/physical-terminal-receipt-record/v1",
  journal_entry: "hacker-bob/physical-exchange-journal-entry/v1",
  outbox_record: "hacker-bob/physical-exchange-outbox-record/v1",
  durability_attestation: "hacker-bob/physical-exchange-durability-attestation/v1",
});
const signatureDomainTable = objectCreate(null);
const recordDomainKinds = Object.keys(RECORD_DOMAINS);
for (let index = 0; index < recordDomainKinds.length; index += 1) {
  const kind = recordDomainKinds[index];
  objectDefineProperty(signatureDomainTable, kind, {
    value: `${RECORD_DOMAINS[kind]}/ed25519-signature`,
    enumerable: true,
    writable: false,
    configurable: false,
  });
}
const SIGNATURE_DOMAINS = objectFreeze(signatureDomainTable);

const BINDING_FIELDS = Object.freeze([
  "version",
  "protocol",
  "exchange_id",
  "release_manifest_digest",
  "component_id",
  "component_manifest_digest",
  "release_artifact_digest",
  "capability_abi_digest",
  "handoff_session_id",
  "handoff_session_digest",
  "supervisor_audit_token_digest",
  "supervisor_process_id",
  "supervisor_process_pidversion",
  "supervisor_process_instance_digest",
  "supervisor_process_start_digest",
  "supervisor_mapped_image_digest",
  "supervisor_principal_id",
  "supervisor_principal_policy_digest",
  "supervisor_listener_generation",
  "supervisor_listener_identity_digest",
  "worker_audit_token_digest",
  "worker_process_id",
  "worker_process_pidversion",
  "worker_process_instance_digest",
  "worker_process_start_digest",
  "worker_mapped_image_digest",
  "worker_principal_id",
  "worker_principal_policy_digest",
  "worker_direct_parent_audit_token_digest",
  "worker_direct_parent_instance_digest",
  "worker_direct_parent_start_digest",
  "launch_nonce",
  "launch_nonce_digest",
  "launch_generation",
  "authority_id",
  "authority_epoch",
  "revocation_generation",
  "revocation_state_digest",
  "resource_epoch",
  "resource_state_digest",
  "capability_set_digest",
  "expected_descriptor_semantics_digest",
  "observed_descriptor_semantics_digest",
  "descriptor_identity_digest",
  "receiver_cloexec_applied",
  "descriptor_aliases_absent",
  "unexpected_descriptors_closed",
  "capability_generation",
  "grant_sequence",
  "go_sequence",
  "clock_epoch_digest",
  "not_before_monotonic_ns",
  "grant_deadline_monotonic_ns",
  "go_deadline_monotonic_ns",
  "result_deadline_monotonic_ns",
  "cleanup_deadline_monotonic_ns",
  "parent_deadline_monotonic_ns",
]);
const GRANT_FIELDS = Object.freeze([
  "version", "protocol", "kind", "binding", "binding_digest", "grant_id",
  "grant_nonce", "one_use", "operation_digest", "authorized_transition_digest",
  "cleanup_plan_digest", "result_contract_digest", "previous_journal_entry_digest",
  "issued_monotonic_ns", "capabilities_only_after_durable_grant",
  "effect_forbidden_before_go",
]);
const GO_FIELDS = Object.freeze([
  "version", "protocol", "kind", "binding", "binding_digest", "go_id",
  "grant_envelope_digest", "grant_payload_digest", "grant_journal_entry_digest",
  "capability_transfer_ack_digest", "ready_no_effect_digest",
  "previous_journal_entry_digest", "issued_monotonic_ns", "one_use",
  "effect_only_after_durable_go",
]);
const EXACT_RESULT_FIELDS = Object.freeze([
  "result_status", "effect_state", "result_code", "response_digest",
  "response_byte_length", "device_state_digest", "external_observation_digest",
  "cleanup_state", "cleanup_evidence_digest",
]);
const RECEIPT_FIELDS = Object.freeze([
  "version", "protocol", "kind", "binding", "binding_digest", "receipt_id",
  "grant_envelope_digest", "go_envelope_digest", "go_journal_entry_digest",
  "receipt_sequence", "terminal_state", "exact_result", "exact_result_digest",
  "cleanup_plan_digest", "capabilities_closed", "transport_fenced",
  "completed_monotonic_ns",
]);
const JOURNAL_FIELDS = Object.freeze([
  "version", "protocol", "kind", "binding", "binding_digest", "journal_id",
  "entry_sequence", "previous_entry_digest", "from_state", "to_state", "event",
  "subject_kind", "subject_digest", "recorded_monotonic_ns",
]);
const OUTBOX_FIELDS = Object.freeze([
  "version", "protocol", "kind", "binding", "binding_digest", "outbox_id",
  "entry_sequence", "previous_entry_digest", "event", "delivery_id",
  "delivery_state", "terminal_state", "terminal_journal_entry_digest",
  "grant_envelope_digest", "go_envelope_digest", "receipt_observation",
  "receipt_envelope_digest", "receipt_evidence_digest", "exact_result",
  "exact_result_digest", "cleanup_state", "retry_disposition", "subject_digest",
  "acknowledgement_digest", "recorded_monotonic_ns",
]);
const DURABILITY_FIELDS = Object.freeze([
  "version", "protocol", "kind", "binding", "binding_digest", "attestation_id",
  "durability_sequence", "previous_attestation_digest", "chain_kind",
  "chain_sequence", "record_envelope_digest", "record_payload_digest",
  "record_canonical_sha256", "previous_record_envelope_digest", "store_id",
  "store_epoch", "file_identity_digest", "file_generation", "record_offset",
  "record_byte_length", "append_sequence", "append_completed_monotonic_ns",
  "data_fsync_sequence", "data_fsync_completed_monotonic_ns",
  "directory_fsync_sequence", "directory_fsync_completed_monotonic_ns",
  "exclusive_writer_principal_id", "durability_scheme", "evidence_origin",
  "stable_bytes_verified",
]);
const ENVELOPE_FIELDS = Object.freeze([
  "version", "kind", "domain", "payload", "payload_digest", "authentication",
  "envelope_digest",
]);
const AUTHENTICATION_FIELDS = Object.freeze([
  "scheme", "key_usage", "role", "principal_id", "key_id", "public_key_digest",
  "trust_epoch", "signed_payload_digest", "signature",
]);
const AUTHENTICATION_BASIS_FIELDS = Object.freeze([
  "scheme", "key_usage", "role", "principal_id", "key_id", "public_key_digest",
  "trust_epoch", "signed_payload_digest",
]);
const ENVELOPE_BASIS_FIELDS = Object.freeze([
  "version", "kind", "domain", "payload", "payload_digest", "authentication",
]);
const SIGNER_FIELDS = Object.freeze([
  "version", "kind", "role", "principal_id", "key_id", "trust_epoch", "private_key",
]);
const KEYRING_FIELDS = Object.freeze([
  "version", "kind", "trust_epoch", "revocation_generation",
  "revocation_state_digest", "entries",
]);
const KEYRING_ENTRY_FIELDS = Object.freeze([
  "role", "key_usage", "principal_id", "key_id", "trust_epoch", "revoked",
  "public_key",
]);
const CURRENT_STATE_FIELDS = Object.freeze([
  "release_manifest_digest", "component_id", "component_manifest_digest",
  "release_artifact_digest", "capability_abi_digest", "handoff_session_id",
  "handoff_session_digest", "supervisor_audit_token_digest", "supervisor_process_id",
  "supervisor_process_pidversion", "supervisor_process_instance_digest",
  "supervisor_process_start_digest", "supervisor_mapped_image_digest",
  "supervisor_principal_id", "supervisor_principal_policy_digest",
  "supervisor_listener_generation", "supervisor_listener_identity_digest",
  "worker_audit_token_digest", "worker_process_id", "worker_process_pidversion",
  "worker_process_instance_digest", "worker_process_start_digest", "worker_mapped_image_digest",
  "worker_principal_id", "worker_principal_policy_digest",
  "worker_direct_parent_audit_token_digest", "worker_direct_parent_instance_digest",
  "worker_direct_parent_start_digest",
  "launch_nonce", "launch_nonce_digest", "launch_generation", "authority_id", "authority_epoch",
  "revocation_generation", "revocation_state_digest", "resource_epoch",
  "resource_state_digest", "capability_set_digest", "expected_descriptor_semantics_digest",
  "observed_descriptor_semantics_digest", "descriptor_identity_digest",
  "receiver_cloexec_applied", "descriptor_aliases_absent", "unexpected_descriptors_closed",
  "capability_generation",
  "clock_epoch_digest", "observed_monotonic_ns",
]);
const RECONCILE_FIELDS = Object.freeze([
  "version", "grant", "go", "receipt", "receipt_observation",
  "malformed_receipt_digest", "journal_entries", "outbox_entries",
  "durability_attestations", "durable_readback_port", "current_state",
  "auto_retry_requested", "verifier",
]);
const DURABLE_READBACK_PORT_INPUT_FIELDS = Object.freeze([
  "version", "kind", "port_id", "test_only", "consistency_model", "read_snapshot",
]);
const DURABLE_READBACK_PORT_FIELDS = Object.freeze([
  "version", "kind", "port_id", "consistency_model", "assurance",
  "caller_supplied_backend", "production_ready",
]);
const DURABLE_READBACK_SNAPSHOT_FIELDS = Object.freeze([
  "version", "kind", "exchange_id", "binding_digest", "snapshot_id",
  "snapshot_sequence", "journal", "outbox", "durability",
]);
const DURABLE_READBACK_REQUEST_FIELDS = Object.freeze([
  "version", "kind", "exchange_id", "binding_digest",
]);
const DURABLE_READBACK_STORE_FIELDS = Object.freeze([
  "version", "kind", "chain_kind", "store_id", "store_epoch",
  "file_identity_digest", "file_generation", "record_count",
  "record_byte_length", "head_envelope_digest", "record_bytes",
]);

const TERMINAL_STATES = Object.freeze([
  "rejected_no_effect",
  "completed",
  "restored",
  "quarantined",
  "ambiguous_quarantined",
]);
const RECEIPT_TERMINAL_STATES = Object.freeze([
  "completed",
  "restored",
  "quarantined",
  "ambiguous_quarantined",
]);
const JOURNAL_STATES = Object.freeze([
  "none",
  "grant_reserved",
  "capabilities_transferred",
  "ready_no_effect",
  "go_reserved",
  "effect_started",
  "receipt_recorded",
  "rejected_no_effect",
  "completed",
  "restored",
  "quarantined",
  "ambiguous_quarantined",
]);
const CLEANUP_STATES = Object.freeze([
  "not_required", "restored", "quarantined", "failed_ambiguous",
]);
const RESULT_STATUS = Object.freeze(["succeeded", "failed", "rejected", "ambiguous"]);
const EFFECT_STATES = Object.freeze(["confirmed_none", "confirmed_effect", "unknown_effect"]);
const RECEIPT_OBSERVATIONS = Object.freeze([
  "not_applicable", "present", "missing", "malformed",
]);
const TRANSITIONS = Object.freeze({
  grant_fsynced: Object.freeze([["none", "grant_reserved"]]),
  capabilities_transferred: Object.freeze([["grant_reserved", "capabilities_transferred"]]),
  ready_no_effect: Object.freeze([["capabilities_transferred", "ready_no_effect"]]),
  go_fsynced: Object.freeze([["ready_no_effect", "go_reserved"]]),
  effect_started: Object.freeze([["go_reserved", "effect_started"]]),
  receipt_fsynced: Object.freeze([["effect_started", "receipt_recorded"]]),
  terminal_completed: Object.freeze([["receipt_recorded", "completed"]]),
  terminal_restored: Object.freeze([["receipt_recorded", "restored"]]),
  terminal_quarantined: Object.freeze([["receipt_recorded", "quarantined"]]),
  terminal_ambiguous: Object.freeze([
    ["go_reserved", "ambiguous_quarantined"],
    ["effect_started", "ambiguous_quarantined"],
    ["receipt_recorded", "ambiguous_quarantined"],
  ]),
  rejected_no_effect: Object.freeze([
    ["grant_reserved", "rejected_no_effect"],
    ["capabilities_transferred", "rejected_no_effect"],
    ["ready_no_effect", "rejected_no_effect"],
  ]),
});
const TERMINAL_EVENT = Object.freeze({
  completed: "terminal_completed",
  restored: "terminal_restored",
  quarantined: "terminal_quarantined",
  ambiguous_quarantined: "terminal_ambiguous",
  rejected_no_effect: "rejected_no_effect",
});

const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/u;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,190}$/u;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/u;

const SIGNER_PRIVATE = new WeakMap();
const VERIFIER_KEYS = new WeakMap();
const DURABLE_READBACK_PORTS = new WeakSet();
const DURABLE_READBACK_PRIVATE = new WeakMap();

function exchangeError(code, message, cause = null) {
  const error = new Error(message, cause == null ? undefined : { cause });
  objectDefineProperty(error, "code", { value: code, enumerable: true });
  return error;
}

function reject(code, message, cause = null) {
  throw exchangeError(code, message, cause);
}

function arrayContains(array, sought) {
  for (let index = 0; index < array.length; index += 1) {
    if (array[index] === sought) return true;
  }
  return false;
}

function ownDataValue(input, field, label, code = "schema_invalid") {
  let descriptor;
  try {
    descriptor = objectGetOwnPropertyDescriptor(input, field);
  } catch (cause) {
    reject(code, `${label}.${field} cannot be inspected`, cause);
  }
  if (!descriptor || !("value" in descriptor) || descriptor.get || descriptor.set) {
    reject(code, `${label}.${field} must be an own data property`);
  }
  return descriptor.value;
}

function assertExactObject(input, fields, label, code = "schema_invalid") {
  if (input == null || typeof input !== "object" || arrayIsArray(input)
      || utilIsProxy(input)) {
    reject(code, `${label} must be a non-proxy object`);
  }
  let prototype;
  let keys;
  try {
    prototype = objectGetPrototypeOf(input);
    keys = reflectOwnKeys(input);
  } catch (cause) {
    reject(code, `${label} cannot be inspected`, cause);
  }
  if (prototype !== objectPrototype && prototype !== null) {
    reject(code, `${label} must have a plain or null prototype`);
  }
  if (keys.length !== fields.length) reject(code, `${label} must have the exact closed schema`);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (typeof key !== "string" || !arrayContains(fields, key)) {
      reject(code, `${label} must have the exact closed schema`);
    }
  }
  for (let index = 0; index < fields.length; index += 1) {
    ownDataValue(input, fields[index], label, code);
  }
  return input;
}

function assertDenseArray(input, label, maximum = MAX_CHAIN_ENTRIES) {
  if (!arrayIsArray(input) || utilIsProxy(input) || input.length > maximum
      || objectGetPrototypeOf(input) !== arrayPrototype) {
    reject("schema_invalid", `${label} must be a bounded dense array`);
  }
  const keys = reflectOwnKeys(input);
  let indexKeyCount = 0;
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (typeof key === "symbol"
        || (key !== "length" && !/^(?:0|[1-9][0-9]*)$/u.test(key))) {
      reject("schema_invalid", `${label} must be a dense data-property array`);
    }
    if (key !== "length") indexKeyCount += 1;
  }
  if (indexKeyCount !== input.length) {
    reject("schema_invalid", `${label} must be a dense data-property array`);
  }
  for (let index = 0; index < input.length; index += 1) {
    ownDataValue(input, String(index), label);
  }
  return input;
}

function makeRecord(fields, values) {
  const output = objectCreate(null);
  for (let index = 0; index < fields.length; index += 1) {
    objectDefineProperty(output, fields[index], {
      value: values[index], enumerable: true, writable: false, configurable: false,
    });
  }
  return objectFreeze(output);
}

function appendOwnArrayValue(array, value) {
  objectDefineProperty(array, String(array.length), {
    value, enumerable: true, writable: true, configurable: true,
  });
}

function valuesForFields(source, fields) {
  const values = [];
  for (let index = 0; index < fields.length; index += 1) {
    appendOwnArrayValue(values, source[fields[index]]);
  }
  return values;
}

function assertString(value, label, pattern = TOKEN_PATTERN) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > 512
      || (pattern && !pattern.test(value))) {
    reject("schema_invalid", `${label} is invalid`);
  }
  return value;
}

function assertExact(value, expected, label) {
  if (value !== expected) reject("schema_invalid", `${label} must be ${String(expected)}`);
  return value;
}

function assertBoolean(value, label, expected = null) {
  if (typeof value !== "boolean" || (expected != null && value !== expected)) {
    reject("schema_invalid", `${label} must be ${expected == null ? "boolean" : expected}`);
  }
  return value;
}

function assertInteger(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    reject("schema_invalid", `${label} must be a safe integer >= ${minimum}`);
  }
  return value;
}

function assertEnum(value, allowed, label) {
  if (!arrayContains(allowed, value)) {
    reject("schema_invalid", `${label} is not an allowed value`);
  }
  return value;
}

function assertDigest(value, label) {
  return assertString(value, label, DIGEST_PATTERN);
}

function assertNullableDigest(value, label) {
  return value === null ? null : assertDigest(value, label);
}

function assertIdentifier(value, label) {
  return assertString(value, label, IDENTIFIER_PATTERN);
}

function assertToken(value, label) {
  return assertString(value, label, TOKEN_PATTERN);
}

function assertNonce(value, label) {
  assertString(value, label, BASE64URL_PATTERN);
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 32 || bytes.toString("base64url") !== value) {
    reject("schema_invalid", `${label} must be canonical 256-bit base64url`);
  }
  return value;
}

function launchNonceDigest(value) {
  return crypto.createHash("sha256").update(Buffer.from(value, "base64url")).digest("hex");
}

function assertUint64String(value, label, positive = false) {
  assertString(value, label, DECIMAL_PATTERN);
  let parsed;
  try {
    parsed = BigInt(value);
  } catch (cause) {
    reject("schema_invalid", `${label} is not uint64`, cause);
  }
  if (parsed > MAX_UINT64 || (positive && parsed === 0n)) {
    reject("schema_invalid", `${label} is outside uint64`);
  }
  return value;
}

function ns(value) {
  return BigInt(value);
}

function assertEd25519Key(key, kind, label) {
  if (!(key instanceof crypto.KeyObject) || key.type !== kind
      || key.asymmetricKeyType !== "ed25519") {
    reject("key_invalid", `${label} must be an Ed25519 ${kind} KeyObject`);
  }
  return key;
}

function publicKeyDigest(keyInput) {
  const key = keyInput.type === "private" ? crypto.createPublicKey(keyInput) : keyInput;
  assertEd25519Key(key, "public", "public_key");
  return crypto.createHash("sha256").update(
    key.export({ format: "der", type: "spki" }),
  ).digest("hex");
}

function canonicalRecordSha256(record) {
  return crypto.createHash("sha256").update(canonicalJson(record), "utf8").digest("hex");
}

function canonicalRecordByteLength(record) {
  return Buffer.byteLength(canonicalJson(record), "utf8");
}

function assertBoundedRecord(record, label) {
  const bytes = canonicalRecordByteLength(record);
  if (bytes < 1 || bytes > MAX_RECORD_BYTES) {
    reject("record_too_large", `${label} exceeds the canonical record byte limit`);
  }
  return bytes;
}

function decodeCanonicalDurableRecord(bytesInput, label) {
  if (utilIsProxy(bytesInput) || !bufferIsBuffer(bytesInput)) {
    reject("durable_readback_invalid", `${label} must be an exact Buffer of persisted bytes`);
  }
  if (bytesInput.length < 1 || bytesInput.length > MAX_RECORD_BYTES) {
    reject("record_too_large", `${label} exceeds the durable record byte limit`);
  }
  const bytes = bufferFrom(bytesInput);
  const text = bufferPrototypeToString.call(bytes, "utf8");
  if (bufferCompare(bufferFrom(text, "utf8"), bytes) !== 0) {
    reject("durable_readback_invalid", `${label} is not canonical UTF-8`);
  }
  let record;
  try {
    record = JSON.parse(text);
  } catch (cause) {
    reject("durable_readback_invalid", `${label} is not one canonical JSON record`, cause);
  }
  let canonical;
  try {
    canonical = canonicalJson(record);
  } catch (cause) {
    reject("durable_readback_invalid", `${label} cannot be canonicalized`, cause);
  }
  if (canonical !== text) {
    reject("durable_readback_invalid",
      `${label} uses an alternate encoding instead of exact canonical JSON bytes`);
  }
  return objectFreeze({ bytes, record });
}

function normalizeDurableReadbackStore(input, chainKind) {
  const label = `authenticated_exchange.durable_readback.${chainKind}`;
  assertExactObject(input, DURABLE_READBACK_STORE_FIELDS, label,
    "durable_readback_invalid");
  assertExact(ownDataValue(input, "version", label, "durable_readback_invalid"),
    AUTHENTICATED_EXCHANGE_VERSION, `${label}.version`);
  assertExact(ownDataValue(input, "kind", label, "durable_readback_invalid"),
    "authenticated_exchange_durable_store_readback", `${label}.kind`);
  assertExact(ownDataValue(input, "chain_kind", label, "durable_readback_invalid"),
    chainKind, `${label}.chain_kind`);
  const maximum = chainKind === "journal" ? MAX_CHAIN_ENTRIES
    : chainKind === "outbox" ? 2 : MAX_DURABILITY_ENTRIES;
  const bytesInput = ownDataValue(input, "record_bytes", label, "durable_readback_invalid");
  assertDenseArray(bytesInput, `${label}.record_bytes`, maximum);
  const declaredCount = assertInteger(
    ownDataValue(input, "record_count", label, "durable_readback_invalid"),
    `${label}.record_count`, 0,
  );
  if (declaredCount !== bytesInput.length) {
    reject("durable_readback_invalid", `${label}.record_count disagrees with stable bytes`);
  }
  const decoded = [];
  const records = [];
  const bytes = [];
  let byteLength = 0;
  for (let index = 0; index < bytesInput.length; index += 1) {
    const item = decodeCanonicalDurableRecord(
      ownDataValue(bytesInput, String(index), `${label}.record_bytes`,
        "durable_readback_invalid"),
      `${label}.record_bytes[${index}]`,
    );
    appendOwnArrayValue(decoded, item);
    appendOwnArrayValue(records, item.record);
    appendOwnArrayValue(bytes, item.bytes);
    byteLength += item.bytes.length;
  }
  const declaredByteLength = assertInteger(
    ownDataValue(input, "record_byte_length", label, "durable_readback_invalid"),
    `${label}.record_byte_length`, 0,
  );
  if (declaredByteLength !== byteLength) {
    reject("durable_readback_invalid",
      `${label}.record_byte_length disagrees with the exact stable bytes`);
  }
  const head = assertNullableDigest(
    ownDataValue(input, "head_envelope_digest", label, "durable_readback_invalid"),
    `${label}.head_envelope_digest`,
  );
  const byteHead = records.length === 0 ? null : records[records.length - 1].envelope_digest;
  if (head !== byteHead) {
    reject("durable_readback_invalid",
      `${label}.head_envelope_digest disagrees with the stable-byte tail`);
  }
  const descriptor = objectFreeze({
    chain_kind: chainKind,
    store_id: assertToken(ownDataValue(input, "store_id", label,
      "durable_readback_invalid"), `${label}.store_id`),
    store_epoch: assertUint64String(ownDataValue(input, "store_epoch", label,
      "durable_readback_invalid"), `${label}.store_epoch`, true),
    file_identity_digest: assertDigest(ownDataValue(input, "file_identity_digest", label,
      "durable_readback_invalid"), `${label}.file_identity_digest`),
    file_generation: assertUint64String(ownDataValue(input, "file_generation", label,
      "durable_readback_invalid"), `${label}.file_generation`, true),
    record_count: declaredCount,
    record_byte_length: declaredByteLength,
    head_envelope_digest: head,
  });
  return objectFreeze({
    descriptor,
    decoded: objectFreeze(decoded),
    records: objectFreeze(records),
    bytes: objectFreeze(bytes),
  });
}

function normalizeDurableReadbackSnapshot(input, binding) {
  const label = "authenticated_exchange.durable_readback_snapshot";
  assertExactObject(input, DURABLE_READBACK_SNAPSHOT_FIELDS, label,
    "durable_readback_invalid");
  assertExact(ownDataValue(input, "version", label, "durable_readback_invalid"),
    AUTHENTICATED_EXCHANGE_VERSION, `${label}.version`);
  assertExact(ownDataValue(input, "kind", label, "durable_readback_invalid"),
    "authenticated_exchange_durable_snapshot", `${label}.kind`);
  assertExact(ownDataValue(input, "exchange_id", label, "durable_readback_invalid"),
    binding.exchange_id, `${label}.exchange_id`);
  assertExact(ownDataValue(input, "binding_digest", label, "durable_readback_invalid"),
    hashCanonicalJson(binding), `${label}.binding_digest`);
  const snapshotId = assertToken(ownDataValue(input, "snapshot_id", label,
    "durable_readback_invalid"), `${label}.snapshot_id`);
  const snapshotSequence = assertUint64String(ownDataValue(input, "snapshot_sequence", label,
    "durable_readback_invalid"), `${label}.snapshot_sequence`, true);
  const stores = objectFreeze({
    journal: normalizeDurableReadbackStore(
      ownDataValue(input, "journal", label, "durable_readback_invalid"), "journal",
    ),
    outbox: normalizeDurableReadbackStore(
      ownDataValue(input, "outbox", label, "durable_readback_invalid"), "outbox",
    ),
    durability: normalizeDurableReadbackStore(
      ownDataValue(input, "durability", label, "durable_readback_invalid"), "durability",
    ),
  });
  return objectFreeze({
    snapshot_id: snapshotId,
    snapshot_sequence: snapshotSequence,
    exchange_id: binding.exchange_id,
    binding_digest: hashCanonicalJson(binding),
    stores,
  });
}

function createFixtureDurableReadbackPort(input) {
  const label = "authenticated_exchange_fixture_durable_readback_port";
  assertExactObject(input, DURABLE_READBACK_PORT_INPUT_FIELDS, label,
    "durable_readback_port_invalid");
  assertExact(ownDataValue(input, "version", label, "durable_readback_port_invalid"),
    AUTHENTICATED_EXCHANGE_VERSION, `${label}.version`);
  assertExact(ownDataValue(input, "kind", label, "durable_readback_port_invalid"),
    "authenticated_exchange_fixture_durable_readback_port", `${label}.kind`);
  assertBoolean(ownDataValue(input, "test_only", label, "durable_readback_port_invalid"),
    `${label}.test_only`, true);
  assertExact(ownDataValue(input, "consistency_model", label,
    "durable_readback_port_invalid"), DURABLE_READBACK_CONSISTENCY_MODEL,
  `${label}.consistency_model`);
  const callback = ownDataValue(input, "read_snapshot", label,
    "durable_readback_port_invalid");
  if (typeof callback !== "function" || utilIsProxy(callback)
      || objectGetPrototypeOf(callback) === asyncFunctionPrototype) {
    reject("durable_readback_port_invalid",
      `${label}.read_snapshot must be a non-proxy synchronous function`);
  }
  const port = makeRecord(DURABLE_READBACK_PORT_FIELDS, [
    AUTHENTICATED_EXCHANGE_VERSION,
    "authenticated_exchange_fixture_durable_readback_port",
    assertToken(ownDataValue(input, "port_id", label, "durable_readback_port_invalid"),
      `${label}.port_id`),
    DURABLE_READBACK_CONSISTENCY_MODEL,
    FIXTURE_ASSURANCE,
    true,
    false,
  ]);
  DURABLE_READBACK_PORTS.add(port);
  DURABLE_READBACK_PRIVATE.set(port, objectFreeze({ read_snapshot: callback }));
  return port;
}

function assertFixtureDurableReadbackPort(port) {
  if (port == null || typeof port !== "object" || utilIsProxy(port)
      || !objectIsFrozen(port) || !DURABLE_READBACK_PORTS.has(port)
      || !DURABLE_READBACK_PRIVATE.has(port)) {
    reject("durable_readback_port_invalid",
      "reconciliation requires a privately branded synchronous durable readback port");
  }
  return port;
}

function assertSynchronousReadbackResult(value) {
  if (value == null || (typeof value !== "object" && typeof value !== "function")) return value;
  let cursor = value;
  for (let depth = 0; cursor != null && depth < 16; depth += 1) {
    if (utilIsProxy(cursor)) {
      reject("durable_readback_invalid", "durable readback result must not be a Proxy");
    }
    let descriptor;
    try {
      descriptor = objectGetOwnPropertyDescriptor(cursor, "then");
    } catch (cause) {
      reject("durable_readback_invalid", "durable readback result cannot be inspected", cause);
    }
    if (descriptor) {
      if (!("value" in descriptor)) {
        reject("durable_readback_invalid",
          "durable readback result cannot expose an accessor then property");
      }
      if (typeof descriptor.value === "function") {
        reject("durable_readback_async",
          "durable readback must resolve synchronously; async ports are rejected");
      }
      return value;
    }
    try {
      cursor = objectGetPrototypeOf(cursor);
    } catch (cause) {
      reject("durable_readback_invalid", "durable readback prototype cannot be inspected", cause);
    }
  }
  if (cursor != null) {
    reject("durable_readback_invalid", "durable readback prototype chain is too deep");
  }
  return value;
}

function readDurableSnapshot(portInput, binding) {
  const port = assertFixtureDurableReadbackPort(portInput);
  const callback = DURABLE_READBACK_PRIVATE.get(port).read_snapshot;
  const request = makeRecord(DURABLE_READBACK_REQUEST_FIELDS, [
    AUTHENTICATED_EXCHANGE_VERSION,
    "authenticated_exchange_durable_snapshot_request",
    binding.exchange_id,
    hashCanonicalJson(binding),
  ]);
  let raw;
  try {
    raw = callback(request);
  } catch (cause) {
    reject("durable_readback_failed", "synchronous durable readback failed", cause);
  }
  assertSynchronousReadbackResult(raw);
  return normalizeDurableReadbackSnapshot(raw, binding);
}

function assertClaimPrefix(claimsInput, durableStore, label, maximum) {
  assertDenseArray(claimsInput, label, maximum);
  if (claimsInput.length > durableStore.records.length) {
    reject("durable_readback_mismatch", `${label} is ahead of the exact durable readback`);
  }
  for (let index = 0; index < claimsInput.length; index += 1) {
    const claim = ownDataValue(claimsInput, String(index), label);
    let expected;
    try {
      expected = bufferFrom(canonicalJson(claim), "utf8");
    } catch (cause) {
      reject("durable_readback_mismatch", `${label}[${index}] cannot be canonicalized`, cause);
    }
    if (bufferCompare(expected, durableStore.bytes[index]) !== 0) {
      reject("durable_readback_mismatch",
        `${label}[${index}] differs from the exact persisted canonical bytes`);
    }
  }
  return claimsInput.length;
}

function resolveDurableExchangeRecords(input, binding) {
  const snapshot = readDurableSnapshot(
    ownDataValue(input, "durable_readback_port", "reconcile_authenticated_exchange"), binding,
  );
  const journalClaims = ownDataValue(input, "journal_entries",
    "reconcile_authenticated_exchange");
  const outboxClaims = ownDataValue(input, "outbox_entries",
    "reconcile_authenticated_exchange");
  const durabilityClaims = ownDataValue(input, "durability_attestations",
    "reconcile_authenticated_exchange");
  const journalCount = assertClaimPrefix(journalClaims, snapshot.stores.journal,
    "authenticated_exchange.journal_entries", MAX_CHAIN_ENTRIES);
  const outboxCount = assertClaimPrefix(outboxClaims, snapshot.stores.outbox,
    "authenticated_exchange.outbox_entries", 2);
  const durabilityCount = assertClaimPrefix(durabilityClaims, snapshot.stores.durability,
    "authenticated_exchange.durability_attestations", MAX_DURABILITY_ENTRIES);
  const exact = journalCount === snapshot.stores.journal.records.length
    && outboxCount === snapshot.stores.outbox.records.length
    && durabilityCount === snapshot.stores.durability.records.length;
  const recoveredAcknowledgement = journalCount === snapshot.stores.journal.records.length
    && outboxCount === 1 && snapshot.stores.outbox.records.length === 2
    && durabilityCount + 1 === snapshot.stores.durability.records.length;
  if (!exact && !recoveredAcknowledgement) {
    reject("durable_readback_mismatch",
      "caller transcript is neither the exact durable snapshot nor its lost-ACK prefix");
  }
  if (recoveredAcknowledgement) {
    const durableTail = snapshot.stores.durability.records[durabilityCount];
    const outboxTail = snapshot.stores.outbox.records[1];
    if (durableTail == null || outboxTail == null
        || durableTail.kind !== "durability_attestation"
        || durableTail.payload == null
        || durableTail.payload.chain_kind !== "outbox"
        || durableTail.payload.chain_sequence !== "2"
        || durableTail.payload.record_envelope_digest !== outboxTail.envelope_digest) {
      reject("durable_readback_mismatch",
        "lost acknowledgement readback does not contain one exact ACK durability suffix");
    }
  }
  return objectFreeze({ snapshot, recovered_acknowledgement: recoveredAcknowledgement });
}

function normalizeBinding(input, label = "exchange_binding") {
  assertExactObject(input, BINDING_FIELDS, label);
  const values = [
    assertExact(ownDataValue(input, "version", label), AUTHENTICATED_EXCHANGE_VERSION,
      `${label}.version`),
    assertExact(ownDataValue(input, "protocol", label), AUTHENTICATED_EXCHANGE_PROTOCOL,
      `${label}.protocol`),
    assertToken(ownDataValue(input, "exchange_id", label), `${label}.exchange_id`),
    assertDigest(ownDataValue(input, "release_manifest_digest", label),
      `${label}.release_manifest_digest`),
    assertIdentifier(ownDataValue(input, "component_id", label), `${label}.component_id`),
    assertDigest(ownDataValue(input, "component_manifest_digest", label),
      `${label}.component_manifest_digest`),
    assertDigest(ownDataValue(input, "release_artifact_digest", label),
      `${label}.release_artifact_digest`),
    assertDigest(ownDataValue(input, "capability_abi_digest", label),
      `${label}.capability_abi_digest`),
    assertToken(ownDataValue(input, "handoff_session_id", label),
      `${label}.handoff_session_id`),
    assertDigest(ownDataValue(input, "handoff_session_digest", label),
      `${label}.handoff_session_digest`),
    assertDigest(ownDataValue(input, "supervisor_audit_token_digest", label),
      `${label}.supervisor_audit_token_digest`),
    assertInteger(ownDataValue(input, "supervisor_process_id", label),
      `${label}.supervisor_process_id`, 1),
    assertInteger(ownDataValue(input, "supervisor_process_pidversion", label),
      `${label}.supervisor_process_pidversion`, 1),
    assertDigest(ownDataValue(input, "supervisor_process_instance_digest", label),
      `${label}.supervisor_process_instance_digest`),
    assertDigest(ownDataValue(input, "supervisor_process_start_digest", label),
      `${label}.supervisor_process_start_digest`),
    assertDigest(ownDataValue(input, "supervisor_mapped_image_digest", label),
      `${label}.supervisor_mapped_image_digest`),
    assertToken(ownDataValue(input, "supervisor_principal_id", label),
      `${label}.supervisor_principal_id`),
    assertDigest(ownDataValue(input, "supervisor_principal_policy_digest", label),
      `${label}.supervisor_principal_policy_digest`),
    assertUint64String(ownDataValue(input, "supervisor_listener_generation", label),
      `${label}.supervisor_listener_generation`, true),
    assertDigest(ownDataValue(input, "supervisor_listener_identity_digest", label),
      `${label}.supervisor_listener_identity_digest`),
    assertDigest(ownDataValue(input, "worker_audit_token_digest", label),
      `${label}.worker_audit_token_digest`),
    assertInteger(ownDataValue(input, "worker_process_id", label),
      `${label}.worker_process_id`, 1),
    assertInteger(ownDataValue(input, "worker_process_pidversion", label),
      `${label}.worker_process_pidversion`, 1),
    assertDigest(ownDataValue(input, "worker_process_instance_digest", label),
      `${label}.worker_process_instance_digest`),
    assertDigest(ownDataValue(input, "worker_process_start_digest", label),
      `${label}.worker_process_start_digest`),
    assertDigest(ownDataValue(input, "worker_mapped_image_digest", label),
      `${label}.worker_mapped_image_digest`),
    assertToken(ownDataValue(input, "worker_principal_id", label),
      `${label}.worker_principal_id`),
    assertDigest(ownDataValue(input, "worker_principal_policy_digest", label),
      `${label}.worker_principal_policy_digest`),
    assertDigest(ownDataValue(input, "worker_direct_parent_audit_token_digest", label),
      `${label}.worker_direct_parent_audit_token_digest`),
    assertDigest(ownDataValue(input, "worker_direct_parent_instance_digest", label),
      `${label}.worker_direct_parent_instance_digest`),
    assertDigest(ownDataValue(input, "worker_direct_parent_start_digest", label),
      `${label}.worker_direct_parent_start_digest`),
    assertNonce(ownDataValue(input, "launch_nonce", label), `${label}.launch_nonce`),
    assertDigest(ownDataValue(input, "launch_nonce_digest", label),
      `${label}.launch_nonce_digest`),
    assertUint64String(ownDataValue(input, "launch_generation", label),
      `${label}.launch_generation`, true),
    assertToken(ownDataValue(input, "authority_id", label), `${label}.authority_id`),
    assertUint64String(ownDataValue(input, "authority_epoch", label),
      `${label}.authority_epoch`, true),
    assertUint64String(ownDataValue(input, "revocation_generation", label),
      `${label}.revocation_generation`),
    assertDigest(ownDataValue(input, "revocation_state_digest", label),
      `${label}.revocation_state_digest`),
    assertUint64String(ownDataValue(input, "resource_epoch", label),
      `${label}.resource_epoch`, true),
    assertDigest(ownDataValue(input, "resource_state_digest", label),
      `${label}.resource_state_digest`),
    assertDigest(ownDataValue(input, "capability_set_digest", label),
      `${label}.capability_set_digest`),
    assertDigest(ownDataValue(input, "expected_descriptor_semantics_digest", label),
      `${label}.expected_descriptor_semantics_digest`),
    assertDigest(ownDataValue(input, "observed_descriptor_semantics_digest", label),
      `${label}.observed_descriptor_semantics_digest`),
    assertDigest(ownDataValue(input, "descriptor_identity_digest", label),
      `${label}.descriptor_identity_digest`),
    assertBoolean(ownDataValue(input, "receiver_cloexec_applied", label),
      `${label}.receiver_cloexec_applied`, true),
    assertBoolean(ownDataValue(input, "descriptor_aliases_absent", label),
      `${label}.descriptor_aliases_absent`, true),
    assertBoolean(ownDataValue(input, "unexpected_descriptors_closed", label),
      `${label}.unexpected_descriptors_closed`, true),
    assertUint64String(ownDataValue(input, "capability_generation", label),
      `${label}.capability_generation`, true),
    assertUint64String(ownDataValue(input, "grant_sequence", label),
      `${label}.grant_sequence`, true),
    assertUint64String(ownDataValue(input, "go_sequence", label),
      `${label}.go_sequence`, true),
    assertDigest(ownDataValue(input, "clock_epoch_digest", label),
      `${label}.clock_epoch_digest`),
    assertUint64String(ownDataValue(input, "not_before_monotonic_ns", label),
      `${label}.not_before_monotonic_ns`),
    assertUint64String(ownDataValue(input, "grant_deadline_monotonic_ns", label),
      `${label}.grant_deadline_monotonic_ns`, true),
    assertUint64String(ownDataValue(input, "go_deadline_monotonic_ns", label),
      `${label}.go_deadline_monotonic_ns`, true),
    assertUint64String(ownDataValue(input, "result_deadline_monotonic_ns", label),
      `${label}.result_deadline_monotonic_ns`, true),
    assertUint64String(ownDataValue(input, "cleanup_deadline_monotonic_ns", label),
      `${label}.cleanup_deadline_monotonic_ns`, true),
    assertUint64String(ownDataValue(input, "parent_deadline_monotonic_ns", label),
      `${label}.parent_deadline_monotonic_ns`, true),
  ];
  const output = makeRecord(BINDING_FIELDS, values);
  if (output.expected_descriptor_semantics_digest
      !== output.observed_descriptor_semantics_digest) {
    reject("descriptor_semantics_invalid",
      `${label} observed descriptor access/status/CLOEXEC semantics do not match the manifest`);
  }
  if (output.launch_nonce_digest !== launchNonceDigest(output.launch_nonce)) {
    reject("process_lineage_invalid", `${label}.launch_nonce_digest does not match launch_nonce`);
  }
  if (output.worker_direct_parent_audit_token_digest !== output.supervisor_audit_token_digest
      || output.worker_direct_parent_instance_digest
        !== output.supervisor_process_instance_digest
      || output.worker_direct_parent_start_digest !== output.supervisor_process_start_digest
      || output.worker_principal_id === output.supervisor_principal_id) {
    reject("process_lineage_invalid",
      `${label} worker direct-parent lineage or principal separation is invalid`);
  }
  if (ns(output.go_sequence) <= ns(output.grant_sequence)) {
    reject("sequence_invalid", `${label}.go_sequence must be greater than grant_sequence`);
  }
  const deadlines = [
    ns(output.not_before_monotonic_ns),
    ns(output.grant_deadline_monotonic_ns),
    ns(output.go_deadline_monotonic_ns),
    ns(output.result_deadline_monotonic_ns),
    ns(output.cleanup_deadline_monotonic_ns),
    ns(output.parent_deadline_monotonic_ns),
  ];
  for (let index = 1; index < deadlines.length; index += 1) {
    if (deadlines[index] <= deadlines[index - 1]) {
      reject("deadline_invalid", `${label} deadlines must be strictly increasing`);
    }
  }
  return output;
}

function normalizeBindingPair(input, digestInput, label) {
  const binding = normalizeBinding(input, `${label}.binding`);
  const bindingDigest = assertDigest(digestInput, `${label}.binding_digest`);
  if (hashCanonicalJson(binding) !== bindingDigest) {
    reject("binding_invalid", `${label}.binding_digest does not match binding`);
  }
  return { binding, bindingDigest };
}

function normalizeCapabilityGrantPayload(input) {
  const label = "capability_grant.payload";
  assertExactObject(input, GRANT_FIELDS, label);
  const pair = normalizeBindingPair(
    ownDataValue(input, "binding", label), ownDataValue(input, "binding_digest", label), label,
  );
  const issued = assertUint64String(ownDataValue(input, "issued_monotonic_ns", label),
    `${label}.issued_monotonic_ns`);
  if (ns(issued) < ns(pair.binding.not_before_monotonic_ns)
      || ns(issued) >= ns(pair.binding.grant_deadline_monotonic_ns)) {
    reject("deadline_invalid", `${label}.issued_monotonic_ns is outside the grant window`);
  }
  return makeRecord(GRANT_FIELDS, [
    AUTHENTICATED_EXCHANGE_VERSION,
    assertExact(ownDataValue(input, "protocol", label), AUTHENTICATED_EXCHANGE_PROTOCOL,
      `${label}.protocol`),
    assertExact(ownDataValue(input, "kind", label), "capability_grant", `${label}.kind`),
    pair.binding,
    pair.bindingDigest,
    assertToken(ownDataValue(input, "grant_id", label), `${label}.grant_id`),
    assertNonce(ownDataValue(input, "grant_nonce", label), `${label}.grant_nonce`),
    assertBoolean(ownDataValue(input, "one_use", label), `${label}.one_use`, true),
    assertDigest(ownDataValue(input, "operation_digest", label), `${label}.operation_digest`),
    assertDigest(ownDataValue(input, "authorized_transition_digest", label),
      `${label}.authorized_transition_digest`),
    assertDigest(ownDataValue(input, "cleanup_plan_digest", label),
      `${label}.cleanup_plan_digest`),
    assertDigest(ownDataValue(input, "result_contract_digest", label),
      `${label}.result_contract_digest`),
    assertNullableDigest(ownDataValue(input, "previous_journal_entry_digest", label),
      `${label}.previous_journal_entry_digest`),
    issued,
    assertBoolean(ownDataValue(input, "capabilities_only_after_durable_grant", label),
      `${label}.capabilities_only_after_durable_grant`, true),
    assertBoolean(ownDataValue(input, "effect_forbidden_before_go", label),
      `${label}.effect_forbidden_before_go`, true),
  ]);
}

function normalizeCommitGoPayload(input) {
  const label = "commit_go.payload";
  assertExactObject(input, GO_FIELDS, label);
  const pair = normalizeBindingPair(
    ownDataValue(input, "binding", label), ownDataValue(input, "binding_digest", label), label,
  );
  const issued = assertUint64String(ownDataValue(input, "issued_monotonic_ns", label),
    `${label}.issued_monotonic_ns`);
  if (ns(issued) < ns(pair.binding.not_before_monotonic_ns)
      || ns(issued) >= ns(pair.binding.go_deadline_monotonic_ns)) {
    reject("deadline_invalid", `${label}.issued_monotonic_ns is outside the GO window`);
  }
  return makeRecord(GO_FIELDS, [
    AUTHENTICATED_EXCHANGE_VERSION,
    assertExact(ownDataValue(input, "protocol", label), AUTHENTICATED_EXCHANGE_PROTOCOL,
      `${label}.protocol`),
    assertExact(ownDataValue(input, "kind", label), "commit_go", `${label}.kind`),
    pair.binding,
    pair.bindingDigest,
    assertToken(ownDataValue(input, "go_id", label), `${label}.go_id`),
    assertDigest(ownDataValue(input, "grant_envelope_digest", label),
      `${label}.grant_envelope_digest`),
    assertDigest(ownDataValue(input, "grant_payload_digest", label),
      `${label}.grant_payload_digest`),
    assertDigest(ownDataValue(input, "grant_journal_entry_digest", label),
      `${label}.grant_journal_entry_digest`),
    assertDigest(ownDataValue(input, "capability_transfer_ack_digest", label),
      `${label}.capability_transfer_ack_digest`),
    assertDigest(ownDataValue(input, "ready_no_effect_digest", label),
      `${label}.ready_no_effect_digest`),
    assertDigest(ownDataValue(input, "previous_journal_entry_digest", label),
      `${label}.previous_journal_entry_digest`),
    issued,
    assertBoolean(ownDataValue(input, "one_use", label), `${label}.one_use`, true),
    assertBoolean(ownDataValue(input, "effect_only_after_durable_go", label),
      `${label}.effect_only_after_durable_go`, true),
  ]);
}

function normalizeExactResult(input, label = "exact_result") {
  assertExactObject(input, EXACT_RESULT_FIELDS, label);
  const output = makeRecord(EXACT_RESULT_FIELDS, [
    assertEnum(ownDataValue(input, "result_status", label), RESULT_STATUS,
      `${label}.result_status`),
    assertEnum(ownDataValue(input, "effect_state", label), EFFECT_STATES,
      `${label}.effect_state`),
    assertIdentifier(ownDataValue(input, "result_code", label), `${label}.result_code`),
    assertNullableDigest(ownDataValue(input, "response_digest", label),
      `${label}.response_digest`),
    assertInteger(ownDataValue(input, "response_byte_length", label),
      `${label}.response_byte_length`, 0),
    assertNullableDigest(ownDataValue(input, "device_state_digest", label),
      `${label}.device_state_digest`),
    assertNullableDigest(ownDataValue(input, "external_observation_digest", label),
      `${label}.external_observation_digest`),
    assertEnum(ownDataValue(input, "cleanup_state", label), CLEANUP_STATES,
      `${label}.cleanup_state`),
    assertNullableDigest(ownDataValue(input, "cleanup_evidence_digest", label),
      `${label}.cleanup_evidence_digest`),
  ]);
  if ((output.response_byte_length === 0) !== (output.response_digest === null)) {
    reject("result_invalid", `${label} response digest and byte length disagree`);
  }
  if (output.result_status === "ambiguous"
      && (output.effect_state !== "unknown_effect"
        || !arrayContains(["quarantined", "failed_ambiguous"], output.cleanup_state))) {
    reject("result_invalid", `${label} ambiguous result must be unknown and quarantined`);
  }
  if (output.effect_state === "unknown_effect" && output.result_status !== "ambiguous") {
    reject("result_invalid", `${label} unknown effect must be ambiguous`);
  }
  if (output.cleanup_state === "not_required" && output.cleanup_evidence_digest !== null) {
    reject("result_invalid", `${label} not-required cleanup cannot carry cleanup evidence`);
  }
  if (output.cleanup_state !== "not_required" && output.cleanup_evidence_digest === null) {
    reject("result_invalid", `${label} cleanup disposition requires evidence`);
  }
  if (output.result_status === "rejected"
      && (output.effect_state !== "confirmed_none"
        || output.response_digest !== null
        || output.cleanup_state !== "not_required")) {
    reject("result_invalid", `${label} rejected result must prove no effect and no cleanup`);
  }
  return output;
}

function expectedTerminalForResult(result) {
  if (result.result_status === "ambiguous") return "ambiguous_quarantined";
  if (result.result_status === "rejected") return "rejected_no_effect";
  if (result.cleanup_state === "restored") return "restored";
  if (result.cleanup_state === "quarantined") return "quarantined";
  if (result.cleanup_state === "failed_ambiguous") return "ambiguous_quarantined";
  return "completed";
}

function normalizeTerminalReceiptPayload(input) {
  const label = "terminal_receipt.payload";
  assertExactObject(input, RECEIPT_FIELDS, label);
  const pair = normalizeBindingPair(
    ownDataValue(input, "binding", label), ownDataValue(input, "binding_digest", label), label,
  );
  const result = normalizeExactResult(ownDataValue(input, "exact_result", label),
    `${label}.exact_result`);
  const resultDigest = assertDigest(ownDataValue(input, "exact_result_digest", label),
    `${label}.exact_result_digest`);
  if (resultDigest !== hashCanonicalJson(result)) {
    reject("result_invalid", `${label}.exact_result_digest does not match exact_result`);
  }
  const terminalState = assertEnum(ownDataValue(input, "terminal_state", label),
    RECEIPT_TERMINAL_STATES,
    `${label}.terminal_state`);
  if (terminalState !== expectedTerminalForResult(result)) {
    reject("result_invalid", `${label}.terminal_state disagrees with exact_result`);
  }
  const completed = assertUint64String(
    ownDataValue(input, "completed_monotonic_ns", label), `${label}.completed_monotonic_ns`, true,
  );
  if (ns(completed) >= ns(pair.binding.cleanup_deadline_monotonic_ns)) {
    reject("deadline_invalid", `${label}.completed_monotonic_ns exceeds cleanup deadline`);
  }
  const transportFenced = assertBoolean(ownDataValue(input, "transport_fenced", label),
    `${label}.transport_fenced`);
  if (terminalState === "ambiguous_quarantined" && !transportFenced) {
    reject("result_invalid", `${label} ambiguous result requires a fenced transport`);
  }
  return makeRecord(RECEIPT_FIELDS, [
    AUTHENTICATED_EXCHANGE_VERSION,
    assertExact(ownDataValue(input, "protocol", label), AUTHENTICATED_EXCHANGE_PROTOCOL,
      `${label}.protocol`),
    assertExact(ownDataValue(input, "kind", label), "terminal_receipt", `${label}.kind`),
    pair.binding,
    pair.bindingDigest,
    assertToken(ownDataValue(input, "receipt_id", label), `${label}.receipt_id`),
    assertDigest(ownDataValue(input, "grant_envelope_digest", label),
      `${label}.grant_envelope_digest`),
    assertDigest(ownDataValue(input, "go_envelope_digest", label),
      `${label}.go_envelope_digest`),
    assertDigest(ownDataValue(input, "go_journal_entry_digest", label),
      `${label}.go_journal_entry_digest`),
    assertUint64String(ownDataValue(input, "receipt_sequence", label),
      `${label}.receipt_sequence`, true),
    terminalState,
    result,
    resultDigest,
    assertDigest(ownDataValue(input, "cleanup_plan_digest", label),
      `${label}.cleanup_plan_digest`),
    assertBoolean(ownDataValue(input, "capabilities_closed", label),
      `${label}.capabilities_closed`, true),
    transportFenced,
    completed,
  ]);
}

function transitionAllowed(event, fromState, toState) {
  const choices = TRANSITIONS[event];
  if (!choices) return false;
  for (let index = 0; index < choices.length; index += 1) {
    const choice = choices[index];
    if (choice[0] === fromState && choice[1] === toState) return true;
  }
  return false;
}

function normalizeJournalEntryPayload(input) {
  const label = "journal_entry.payload";
  assertExactObject(input, JOURNAL_FIELDS, label);
  const pair = normalizeBindingPair(
    ownDataValue(input, "binding", label), ownDataValue(input, "binding_digest", label), label,
  );
  const fromState = assertEnum(ownDataValue(input, "from_state", label), JOURNAL_STATES,
    `${label}.from_state`);
  const toState = assertEnum(ownDataValue(input, "to_state", label), JOURNAL_STATES,
    `${label}.to_state`);
  const event = assertIdentifier(ownDataValue(input, "event", label), `${label}.event`);
  if (!transitionAllowed(event, fromState, toState)) {
    reject("transition_invalid", `${label} transition ${fromState}/${event}/${toState} is illegal`);
  }
  const sequence = assertUint64String(ownDataValue(input, "entry_sequence", label),
    `${label}.entry_sequence`, true);
  const previous = assertNullableDigest(ownDataValue(input, "previous_entry_digest", label),
    `${label}.previous_entry_digest`);
  if ((sequence === "1") !== (previous === null)) {
    reject("chain_invalid", `${label} first-entry/previous digest invariant failed`);
  }
  const subjectKind = assertIdentifier(
    ownDataValue(input, "subject_kind", label), `${label}.subject_kind`,
  );
  if (event === "rejected_no_effect" && subjectKind !== "no_go_child_exit_evidence") {
    reject("binding_invalid",
      `${label} rejected_no_effect requires authenticated no-GO/child-exit evidence`);
  }
  return makeRecord(JOURNAL_FIELDS, [
    AUTHENTICATED_EXCHANGE_VERSION,
    assertExact(ownDataValue(input, "protocol", label), AUTHENTICATED_EXCHANGE_PROTOCOL,
      `${label}.protocol`),
    assertExact(ownDataValue(input, "kind", label), "journal_entry", `${label}.kind`),
    pair.binding,
    pair.bindingDigest,
    assertToken(ownDataValue(input, "journal_id", label), `${label}.journal_id`),
    sequence,
    previous,
    fromState,
    toState,
    event,
    subjectKind,
    assertDigest(ownDataValue(input, "subject_digest", label), `${label}.subject_digest`),
    assertUint64String(ownDataValue(input, "recorded_monotonic_ns", label),
      `${label}.recorded_monotonic_ns`, true),
  ]);
}

function normalizeOutboxRecordPayload(input) {
  const label = "outbox_record.payload";
  assertExactObject(input, OUTBOX_FIELDS, label);
  const pair = normalizeBindingPair(
    ownDataValue(input, "binding", label), ownDataValue(input, "binding_digest", label), label,
  );
  const sequence = assertUint64String(ownDataValue(input, "entry_sequence", label),
    `${label}.entry_sequence`, true);
  const previous = assertNullableDigest(ownDataValue(input, "previous_entry_digest", label),
    `${label}.previous_entry_digest`);
  if ((sequence === "1") !== (previous === null)) {
    reject("chain_invalid", `${label} first-entry/previous digest invariant failed`);
  }
  const event = assertEnum(ownDataValue(input, "event", label),
    ["terminal_enqueued", "terminal_acknowledged"], `${label}.event`);
  const deliveryState = assertEnum(ownDataValue(input, "delivery_state", label),
    ["pending", "acknowledged"], `${label}.delivery_state`);
  if ((event === "terminal_enqueued") !== (deliveryState === "pending")) {
    reject("outbox_invalid", `${label} event and delivery state disagree`);
  }
  if ((event === "terminal_enqueued") !== (sequence === "1")) {
    reject("outbox_invalid", `${label} enqueue must be sequence one`);
  }
  if (event === "terminal_acknowledged" && sequence !== "2") {
    reject("outbox_invalid", `${label} acknowledgement must be sequence two`);
  }
  const terminalState = assertEnum(ownDataValue(input, "terminal_state", label),
    TERMINAL_STATES, `${label}.terminal_state`);
  const observation = assertEnum(ownDataValue(input, "receipt_observation", label),
    RECEIPT_OBSERVATIONS, `${label}.receipt_observation`);
  const receiptDigest = assertNullableDigest(
    ownDataValue(input, "receipt_envelope_digest", label), `${label}.receipt_envelope_digest`,
  );
  const receiptEvidence = assertNullableDigest(
    ownDataValue(input, "receipt_evidence_digest", label), `${label}.receipt_evidence_digest`,
  );
  if ((observation === "present" && (receiptDigest === null || receiptEvidence !== null))
      || (observation === "malformed" && (receiptDigest !== null || receiptEvidence === null))
      || (arrayContains(["missing", "not_applicable"], observation)
        && (receiptDigest !== null || receiptEvidence !== null))) {
    reject("receipt_invalid", `${label} receipt observation fields disagree`);
  }
  const result = normalizeExactResult(ownDataValue(input, "exact_result", label),
    `${label}.exact_result`);
  const resultDigest = assertDigest(ownDataValue(input, "exact_result_digest", label),
    `${label}.exact_result_digest`);
  if (resultDigest !== hashCanonicalJson(result)
      || terminalState !== expectedTerminalForResult(result)
      || ownDataValue(input, "cleanup_state", label) !== result.cleanup_state) {
    reject("result_invalid", `${label} result, cleanup, or terminal binding disagrees`);
  }
  if (arrayContains(["missing", "malformed"], observation)
      && terminalState !== "ambiguous_quarantined") {
    reject("receipt_invalid", `${label} absent post-GO receipt must be ambiguous_quarantined`);
  }
  if (observation === "not_applicable" && terminalState !== "rejected_no_effect") {
    reject("receipt_invalid", `${label} pre-GO terminal must be rejected_no_effect`);
  }
  const acknowledgement = assertNullableDigest(
    ownDataValue(input, "acknowledgement_digest", label), `${label}.acknowledgement_digest`,
  );
  if ((deliveryState === "acknowledged") !== (acknowledgement !== null)) {
    reject("outbox_invalid", `${label} acknowledgement fields disagree`);
  }
  return makeRecord(OUTBOX_FIELDS, [
    AUTHENTICATED_EXCHANGE_VERSION,
    assertExact(ownDataValue(input, "protocol", label), AUTHENTICATED_EXCHANGE_PROTOCOL,
      `${label}.protocol`),
    assertExact(ownDataValue(input, "kind", label), "outbox_record", `${label}.kind`),
    pair.binding,
    pair.bindingDigest,
    assertToken(ownDataValue(input, "outbox_id", label), `${label}.outbox_id`),
    sequence,
    previous,
    event,
    assertToken(ownDataValue(input, "delivery_id", label), `${label}.delivery_id`),
    deliveryState,
    terminalState,
    assertDigest(ownDataValue(input, "terminal_journal_entry_digest", label),
      `${label}.terminal_journal_entry_digest`),
    assertDigest(ownDataValue(input, "grant_envelope_digest", label),
      `${label}.grant_envelope_digest`),
    assertNullableDigest(ownDataValue(input, "go_envelope_digest", label),
      `${label}.go_envelope_digest`),
    observation,
    receiptDigest,
    receiptEvidence,
    result,
    resultDigest,
    assertEnum(ownDataValue(input, "cleanup_state", label), CLEANUP_STATES,
      `${label}.cleanup_state`),
    assertExact(ownDataValue(input, "retry_disposition", label), "effect_retry_forbidden",
      `${label}.retry_disposition`),
    assertDigest(ownDataValue(input, "subject_digest", label), `${label}.subject_digest`),
    acknowledgement,
    assertUint64String(ownDataValue(input, "recorded_monotonic_ns", label),
      `${label}.recorded_monotonic_ns`, true),
  ]);
}

function normalizeDurabilityAttestationPayload(input) {
  const label = "durability_attestation.payload";
  assertExactObject(input, DURABILITY_FIELDS, label);
  const pair = normalizeBindingPair(
    ownDataValue(input, "binding", label), ownDataValue(input, "binding_digest", label), label,
  );
  const appendCompleted = assertUint64String(
    ownDataValue(input, "append_completed_monotonic_ns", label),
    `${label}.append_completed_monotonic_ns`, true,
  );
  const dataFsyncCompleted = assertUint64String(
    ownDataValue(input, "data_fsync_completed_monotonic_ns", label),
    `${label}.data_fsync_completed_monotonic_ns`, true,
  );
  const directoryFsyncCompleted = assertUint64String(
    ownDataValue(input, "directory_fsync_completed_monotonic_ns", label),
    `${label}.directory_fsync_completed_monotonic_ns`, true,
  );
  if (!(ns(appendCompleted) < ns(dataFsyncCompleted)
      && ns(dataFsyncCompleted) <= ns(directoryFsyncCompleted))) {
    reject("durability_order_invalid", `${label} append/fsync ordering is invalid`);
  }
  const appendSequence = assertUint64String(ownDataValue(input, "append_sequence", label),
    `${label}.append_sequence`, true);
  const dataSequence = assertUint64String(ownDataValue(input, "data_fsync_sequence", label),
    `${label}.data_fsync_sequence`, true);
  const directorySequence = assertUint64String(
    ownDataValue(input, "directory_fsync_sequence", label),
    `${label}.directory_fsync_sequence`, true,
  );
  if (!(ns(appendSequence) < ns(dataSequence) && ns(dataSequence) < ns(directorySequence))) {
    reject("durability_order_invalid", `${label} append/fsync sequences are invalid`);
  }
  const durabilitySequence = assertUint64String(
    ownDataValue(input, "durability_sequence", label), `${label}.durability_sequence`, true,
  );
  const previousAttestation = assertNullableDigest(
    ownDataValue(input, "previous_attestation_digest", label),
    `${label}.previous_attestation_digest`,
  );
  if ((durabilitySequence === "1") !== (previousAttestation === null)) {
    reject("chain_invalid", `${label} first-attestation/previous digest invariant failed`);
  }
  return makeRecord(DURABILITY_FIELDS, [
    AUTHENTICATED_EXCHANGE_VERSION,
    assertExact(ownDataValue(input, "protocol", label), AUTHENTICATED_EXCHANGE_PROTOCOL,
      `${label}.protocol`),
    assertExact(ownDataValue(input, "kind", label), "durability_attestation", `${label}.kind`),
    pair.binding,
    pair.bindingDigest,
    assertToken(ownDataValue(input, "attestation_id", label), `${label}.attestation_id`),
    durabilitySequence,
    previousAttestation,
    assertEnum(ownDataValue(input, "chain_kind", label), ["journal", "outbox"],
      `${label}.chain_kind`),
    assertUint64String(ownDataValue(input, "chain_sequence", label),
      `${label}.chain_sequence`, true),
    assertDigest(ownDataValue(input, "record_envelope_digest", label),
      `${label}.record_envelope_digest`),
    assertDigest(ownDataValue(input, "record_payload_digest", label),
      `${label}.record_payload_digest`),
    assertDigest(ownDataValue(input, "record_canonical_sha256", label),
      `${label}.record_canonical_sha256`),
    assertNullableDigest(ownDataValue(input, "previous_record_envelope_digest", label),
      `${label}.previous_record_envelope_digest`),
    assertToken(ownDataValue(input, "store_id", label), `${label}.store_id`),
    assertUint64String(ownDataValue(input, "store_epoch", label),
      `${label}.store_epoch`, true),
    assertDigest(ownDataValue(input, "file_identity_digest", label),
      `${label}.file_identity_digest`),
    assertUint64String(ownDataValue(input, "file_generation", label),
      `${label}.file_generation`, true),
    assertUint64String(ownDataValue(input, "record_offset", label),
      `${label}.record_offset`),
    assertInteger(ownDataValue(input, "record_byte_length", label),
      `${label}.record_byte_length`, 1),
    appendSequence,
    appendCompleted,
    dataSequence,
    dataFsyncCompleted,
    directorySequence,
    directoryFsyncCompleted,
    assertToken(ownDataValue(input, "exclusive_writer_principal_id", label),
      `${label}.exclusive_writer_principal_id`),
    assertExact(ownDataValue(input, "durability_scheme", label), DURABILITY_SCHEME,
      `${label}.durability_scheme`),
    assertExact(ownDataValue(input, "evidence_origin", label), DURABILITY_EVIDENCE_ORIGIN,
      `${label}.evidence_origin`),
    assertBoolean(ownDataValue(input, "stable_bytes_verified", label),
      `${label}.stable_bytes_verified`, true),
  ]);
}

const NORMALIZERS = Object.freeze({
  capability_grant: normalizeCapabilityGrantPayload,
  commit_go: normalizeCommitGoPayload,
  terminal_receipt: normalizeTerminalReceiptPayload,
  journal_entry: normalizeJournalEntryPayload,
  outbox_record: normalizeOutboxRecordPayload,
  durability_attestation: normalizeDurabilityAttestationPayload,
});

function createFixtureExchangeSigner(input) {
  const label = "authenticated_exchange_fixture_signer";
  assertExactObject(input, SIGNER_FIELDS, label, "signer_invalid");
  assertExact(ownDataValue(input, "version", label), AUTHENTICATED_EXCHANGE_VERSION,
    `${label}.version`);
  assertExact(ownDataValue(input, "kind", label), "authenticated_exchange_fixture_signer",
    `${label}.kind`);
  const role = assertEnum(ownDataValue(input, "role", label), ROLES, `${label}.role`);
  const privateKey = assertEd25519Key(ownDataValue(input, "private_key", label), "private",
    `${label}.private_key`);
  const signer = makeRecord([
    "version", "kind", "role", "key_usage", "principal_id", "key_id",
    "public_key_digest", "trust_epoch", "assurance", "production_ready",
  ], [
    AUTHENTICATED_EXCHANGE_VERSION,
    "authenticated_exchange_fixture_signer",
    role,
    ROLE_DEFINITIONS[role].key_usage,
    assertToken(ownDataValue(input, "principal_id", label), `${label}.principal_id`),
    assertToken(ownDataValue(input, "key_id", label), `${label}.key_id`),
    publicKeyDigest(privateKey),
    assertInteger(ownDataValue(input, "trust_epoch", label), `${label}.trust_epoch`, 1),
    FIXTURE_ASSURANCE,
    false,
  ]);
  SIGNER_PRIVATE.set(signer, privateKey);
  return signer;
}

function createFixtureExchangeVerifier(input) {
  const label = "authenticated_exchange_fixture_keyring";
  assertExactObject(input, KEYRING_FIELDS, label, "keyring_invalid");
  assertExact(ownDataValue(input, "version", label), AUTHENTICATED_EXCHANGE_VERSION,
    `${label}.version`);
  assertExact(ownDataValue(input, "kind", label), "authenticated_exchange_fixture_keyring",
    `${label}.kind`);
  const trustEpoch = assertInteger(ownDataValue(input, "trust_epoch", label),
    `${label}.trust_epoch`, 1);
  const entriesInput = ownDataValue(input, "entries", label);
  assertDenseArray(entriesInput, `${label}.entries`, ROLES.length);
  if (entriesInput.length !== ROLES.length) {
    reject("keyring_invalid", `${label}.entries must contain exactly four roles`);
  }
  const principals = new Set();
  const keyIds = new Set();
  const keyDigests = new Set();
  const keys = new Map();
  const projections = [];
  for (let index = 0; index < entriesInput.length; index += 1) {
    const entryLabel = `${label}.entries[${index}]`;
    const entry = ownDataValue(entriesInput, String(index), `${label}.entries`);
    assertExactObject(entry, KEYRING_ENTRY_FIELDS, entryLabel, "keyring_invalid");
    const role = assertExact(ownDataValue(entry, "role", entryLabel), ROLES[index],
      `${entryLabel}.role`);
    const keyUsage = assertExact(ownDataValue(entry, "key_usage", entryLabel),
      ROLE_DEFINITIONS[role].key_usage, `${entryLabel}.key_usage`);
    const principalId = assertToken(ownDataValue(entry, "principal_id", entryLabel),
      `${entryLabel}.principal_id`);
    const keyId = assertToken(ownDataValue(entry, "key_id", entryLabel), `${entryLabel}.key_id`);
    const entryTrustEpoch = assertInteger(ownDataValue(entry, "trust_epoch", entryLabel),
      `${entryLabel}.trust_epoch`, 1);
    if (entryTrustEpoch > trustEpoch) {
      reject("keyring_invalid", `${entryLabel}.trust_epoch exceeds keyring trust epoch`);
    }
    const publicKey = assertEd25519Key(ownDataValue(entry, "public_key", entryLabel), "public",
      `${entryLabel}.public_key`);
    const digest = publicKeyDigest(publicKey);
    if (principals.has(principalId) || keyIds.has(keyId) || keyDigests.has(digest)) {
      reject("keyring_invalid", `${label} roles must use pairwise-distinct principals and keys`);
    }
    principals.add(principalId);
    keyIds.add(keyId);
    keyDigests.add(digest);
    const revoked = assertBoolean(ownDataValue(entry, "revoked", entryLabel),
      `${entryLabel}.revoked`);
    keys.set(role, objectFreeze({
      role, key_usage: keyUsage, principal_id: principalId, key_id: keyId,
      trust_epoch: entryTrustEpoch, public_key_digest: digest, public_key: publicKey, revoked,
    }));
    appendOwnArrayValue(projections, makeRecord([
      "role", "key_usage", "principal_id", "key_id", "public_key_digest", "trust_epoch",
      "revoked",
    ], [role, keyUsage, principalId, keyId, digest, entryTrustEpoch, revoked]));
  }
  const verifier = makeRecord([
    "version", "kind", "trust_epoch", "revocation_generation", "revocation_state_digest",
    "entries", "assurance", "production_ready", "caller_supplied_trust",
  ], [
    AUTHENTICATED_EXCHANGE_VERSION,
    "authenticated_exchange_fixture_verifier",
    trustEpoch,
    assertUint64String(ownDataValue(input, "revocation_generation", label),
      `${label}.revocation_generation`),
    assertDigest(ownDataValue(input, "revocation_state_digest", label),
      `${label}.revocation_state_digest`),
    objectFreeze(projections),
    FIXTURE_ASSURANCE,
    false,
    true,
  ]);
  VERIFIER_KEYS.set(verifier, keys);
  return verifier;
}

function authenticationBasis(authentication) {
  return makeRecord(AUTHENTICATION_BASIS_FIELDS,
    valuesForFields(authentication, AUTHENTICATION_BASIS_FIELDS));
}

function signatureMessage(kind, payloadDigest, authentication) {
  return Buffer.from(canonicalJson({
    domain: SIGNATURE_DOMAINS[kind],
    payload_digest: payloadDigest,
    authentication: authenticationBasis(authentication),
  }), "utf8");
}

function signRecord(kind, input) {
  const label = `sign_${kind}`;
  assertExactObject(input, ["payload", "signer"], label, "signer_invalid");
  const signer = ownDataValue(input, "signer", label, "signer_invalid");
  const privateKey = SIGNER_PRIVATE.get(signer);
  if (!privateKey || signer.role !== RECORD_ROLE[kind]) {
    reject("signer_invalid", `${label} requires the exact fixture signer role`);
  }
  const payload = NORMALIZERS[kind](ownDataValue(input, "payload", label));
  const payloadDigest = hashCanonicalJson(payload);
  const authBasis = makeRecord(AUTHENTICATION_BASIS_FIELDS, [
    SIGNATURE_SCHEME,
    ROLE_DEFINITIONS[signer.role].key_usage,
    signer.role,
    signer.principal_id,
    signer.key_id,
    signer.public_key_digest,
    signer.trust_epoch,
    payloadDigest,
  ]);
  const signature = crypto.sign(null, signatureMessage(kind, payloadDigest, authBasis), privateKey)
    .toString("base64url");
  const authenticationValues = valuesForFields(authBasis, AUTHENTICATION_BASIS_FIELDS);
  appendOwnArrayValue(authenticationValues, signature);
  const authentication = makeRecord(AUTHENTICATION_FIELDS, authenticationValues);
  const basis = makeRecord(ENVELOPE_BASIS_FIELDS, [
    AUTHENTICATED_EXCHANGE_VERSION,
    kind,
    RECORD_DOMAINS[kind],
    payload,
    payloadDigest,
    authentication,
  ]);
  const envelopeValues = valuesForFields(basis, ENVELOPE_BASIS_FIELDS);
  appendOwnArrayValue(envelopeValues, hashCanonicalJson(basis));
  const envelope = makeRecord(ENVELOPE_FIELDS, envelopeValues);
  assertBoundedRecord(envelope, `${kind}.envelope`);
  return envelope;
}

function normalizeAuthentication(input, kind, payloadDigest, label) {
  assertExactObject(input, AUTHENTICATION_FIELDS, label, "authentication_invalid");
  const role = RECORD_ROLE[kind];
  const values = [
    assertExact(ownDataValue(input, "scheme", label), SIGNATURE_SCHEME, `${label}.scheme`),
    assertExact(ownDataValue(input, "key_usage", label), ROLE_DEFINITIONS[role].key_usage,
      `${label}.key_usage`),
    assertExact(ownDataValue(input, "role", label), role, `${label}.role`),
    assertToken(ownDataValue(input, "principal_id", label), `${label}.principal_id`),
    assertToken(ownDataValue(input, "key_id", label), `${label}.key_id`),
    assertDigest(ownDataValue(input, "public_key_digest", label),
      `${label}.public_key_digest`),
    assertInteger(ownDataValue(input, "trust_epoch", label), `${label}.trust_epoch`, 1),
    assertExact(ownDataValue(input, "signed_payload_digest", label), payloadDigest,
      `${label}.signed_payload_digest`),
    assertString(ownDataValue(input, "signature", label), `${label}.signature`, SIGNATURE_PATTERN),
  ];
  const signatureBytes = Buffer.from(values[8], "base64url");
  if (signatureBytes.length !== 64 || signatureBytes.toString("base64url") !== values[8]) {
    reject("authentication_invalid", `${label}.signature is not canonical Ed25519`);
  }
  return makeRecord(AUTHENTICATION_FIELDS, values);
}

function verifyRecord(kind, input, verifier) {
  const label = `${kind}.envelope`;
  const keys = VERIFIER_KEYS.get(verifier);
  if (!keys) reject("keyring_invalid", `${label} requires the exact fixture verifier`);
  assertExactObject(input, ENVELOPE_FIELDS, label, "envelope_invalid");
  assertExact(ownDataValue(input, "version", label), AUTHENTICATED_EXCHANGE_VERSION,
    `${label}.version`);
  assertExact(ownDataValue(input, "kind", label), kind, `${label}.kind`);
  assertExact(ownDataValue(input, "domain", label), RECORD_DOMAINS[kind], `${label}.domain`);
  const payload = NORMALIZERS[kind](ownDataValue(input, "payload", label));
  const payloadDigest = assertDigest(ownDataValue(input, "payload_digest", label),
    `${label}.payload_digest`);
  if (payloadDigest !== hashCanonicalJson(payload)) {
    reject("envelope_invalid", `${label}.payload_digest does not match payload`);
  }
  const authentication = normalizeAuthentication(
    ownDataValue(input, "authentication", label), kind, payloadDigest, `${label}.authentication`,
  );
  const key = keys.get(RECORD_ROLE[kind]);
  if (!key || key.revoked
      || authentication.role !== key.role
      || authentication.key_usage !== key.key_usage
      || authentication.principal_id !== key.principal_id
      || authentication.key_id !== key.key_id
      || authentication.public_key_digest !== key.public_key_digest
      || authentication.trust_epoch !== key.trust_epoch) {
    reject("authentication_invalid", `${label} signer is not the enrolled live role key`);
  }
  let verified = false;
  try {
    verified = crypto.verify(
      null,
      signatureMessage(kind, payloadDigest, authentication),
      key.public_key,
      Buffer.from(authentication.signature, "base64url"),
    );
  } catch (cause) {
    reject("authentication_invalid", `${label} signature verification failed`, cause);
  }
  if (!verified) reject("authentication_invalid", `${label} signature is invalid`);
  const basis = makeRecord(ENVELOPE_BASIS_FIELDS, [
    AUTHENTICATED_EXCHANGE_VERSION, kind, RECORD_DOMAINS[kind], payload, payloadDigest,
    authentication,
  ]);
  const envelopeDigest = assertDigest(ownDataValue(input, "envelope_digest", label),
    `${label}.envelope_digest`);
  if (envelopeDigest !== hashCanonicalJson(basis)) {
    reject("envelope_invalid", `${label}.envelope_digest does not match envelope`);
  }
  const envelopeValues = valuesForFields(basis, ENVELOPE_BASIS_FIELDS);
  appendOwnArrayValue(envelopeValues, envelopeDigest);
  const output = makeRecord(ENVELOPE_FIELDS, envelopeValues);
  assertBoundedRecord(output, label);
  return output;
}

function assertSameBinding(reference, candidate, label) {
  if (reference.binding_digest !== candidate.binding_digest
      || canonicalJson(reference.binding) !== canonicalJson(candidate.binding)) {
    reject("binding_invalid", `${label} exchange binding drift`);
  }
}

function normalizeCurrentState(input) {
  const label = "authenticated_exchange.current_state";
  assertExactObject(input, CURRENT_STATE_FIELDS, label);
  return makeRecord(CURRENT_STATE_FIELDS, [
    assertDigest(ownDataValue(input, "release_manifest_digest", label),
      `${label}.release_manifest_digest`),
    assertIdentifier(ownDataValue(input, "component_id", label), `${label}.component_id`),
    assertDigest(ownDataValue(input, "component_manifest_digest", label),
      `${label}.component_manifest_digest`),
    assertDigest(ownDataValue(input, "release_artifact_digest", label),
      `${label}.release_artifact_digest`),
    assertDigest(ownDataValue(input, "capability_abi_digest", label),
      `${label}.capability_abi_digest`),
    assertToken(ownDataValue(input, "handoff_session_id", label),
      `${label}.handoff_session_id`),
    assertDigest(ownDataValue(input, "handoff_session_digest", label),
      `${label}.handoff_session_digest`),
    assertDigest(ownDataValue(input, "supervisor_audit_token_digest", label),
      `${label}.supervisor_audit_token_digest`),
    assertInteger(ownDataValue(input, "supervisor_process_id", label),
      `${label}.supervisor_process_id`, 1),
    assertInteger(ownDataValue(input, "supervisor_process_pidversion", label),
      `${label}.supervisor_process_pidversion`, 1),
    assertDigest(ownDataValue(input, "supervisor_process_instance_digest", label),
      `${label}.supervisor_process_instance_digest`),
    assertDigest(ownDataValue(input, "supervisor_process_start_digest", label),
      `${label}.supervisor_process_start_digest`),
    assertDigest(ownDataValue(input, "supervisor_mapped_image_digest", label),
      `${label}.supervisor_mapped_image_digest`),
    assertToken(ownDataValue(input, "supervisor_principal_id", label),
      `${label}.supervisor_principal_id`),
    assertDigest(ownDataValue(input, "supervisor_principal_policy_digest", label),
      `${label}.supervisor_principal_policy_digest`),
    assertUint64String(ownDataValue(input, "supervisor_listener_generation", label),
      `${label}.supervisor_listener_generation`, true),
    assertDigest(ownDataValue(input, "supervisor_listener_identity_digest", label),
      `${label}.supervisor_listener_identity_digest`),
    assertDigest(ownDataValue(input, "worker_audit_token_digest", label),
      `${label}.worker_audit_token_digest`),
    assertInteger(ownDataValue(input, "worker_process_id", label),
      `${label}.worker_process_id`, 1),
    assertInteger(ownDataValue(input, "worker_process_pidversion", label),
      `${label}.worker_process_pidversion`, 1),
    assertDigest(ownDataValue(input, "worker_process_instance_digest", label),
      `${label}.worker_process_instance_digest`),
    assertDigest(ownDataValue(input, "worker_process_start_digest", label),
      `${label}.worker_process_start_digest`),
    assertDigest(ownDataValue(input, "worker_mapped_image_digest", label),
      `${label}.worker_mapped_image_digest`),
    assertToken(ownDataValue(input, "worker_principal_id", label),
      `${label}.worker_principal_id`),
    assertDigest(ownDataValue(input, "worker_principal_policy_digest", label),
      `${label}.worker_principal_policy_digest`),
    assertDigest(ownDataValue(input, "worker_direct_parent_audit_token_digest", label),
      `${label}.worker_direct_parent_audit_token_digest`),
    assertDigest(ownDataValue(input, "worker_direct_parent_instance_digest", label),
      `${label}.worker_direct_parent_instance_digest`),
    assertDigest(ownDataValue(input, "worker_direct_parent_start_digest", label),
      `${label}.worker_direct_parent_start_digest`),
    assertNonce(ownDataValue(input, "launch_nonce", label), `${label}.launch_nonce`),
    assertDigest(ownDataValue(input, "launch_nonce_digest", label),
      `${label}.launch_nonce_digest`),
    assertUint64String(ownDataValue(input, "launch_generation", label),
      `${label}.launch_generation`, true),
    assertToken(ownDataValue(input, "authority_id", label), `${label}.authority_id`),
    assertUint64String(ownDataValue(input, "authority_epoch", label),
      `${label}.authority_epoch`, true),
    assertUint64String(ownDataValue(input, "revocation_generation", label),
      `${label}.revocation_generation`),
    assertDigest(ownDataValue(input, "revocation_state_digest", label),
      `${label}.revocation_state_digest`),
    assertUint64String(ownDataValue(input, "resource_epoch", label),
      `${label}.resource_epoch`, true),
    assertDigest(ownDataValue(input, "resource_state_digest", label),
      `${label}.resource_state_digest`),
    assertDigest(ownDataValue(input, "capability_set_digest", label),
      `${label}.capability_set_digest`),
    assertDigest(ownDataValue(input, "expected_descriptor_semantics_digest", label),
      `${label}.expected_descriptor_semantics_digest`),
    assertDigest(ownDataValue(input, "observed_descriptor_semantics_digest", label),
      `${label}.observed_descriptor_semantics_digest`),
    assertDigest(ownDataValue(input, "descriptor_identity_digest", label),
      `${label}.descriptor_identity_digest`),
    assertBoolean(ownDataValue(input, "receiver_cloexec_applied", label),
      `${label}.receiver_cloexec_applied`, true),
    assertBoolean(ownDataValue(input, "descriptor_aliases_absent", label),
      `${label}.descriptor_aliases_absent`, true),
    assertBoolean(ownDataValue(input, "unexpected_descriptors_closed", label),
      `${label}.unexpected_descriptors_closed`, true),
    assertUint64String(ownDataValue(input, "capability_generation", label),
      `${label}.capability_generation`, true),
    assertDigest(ownDataValue(input, "clock_epoch_digest", label),
      `${label}.clock_epoch_digest`),
    assertUint64String(ownDataValue(input, "observed_monotonic_ns", label),
      `${label}.observed_monotonic_ns`, true),
  ]);
}

const LIVE_BINDINGS = Object.freeze([
  "release_manifest_digest", "component_id", "component_manifest_digest",
  "release_artifact_digest", "capability_abi_digest", "handoff_session_id",
  "handoff_session_digest", "supervisor_audit_token_digest", "supervisor_process_id",
  "supervisor_process_pidversion", "supervisor_process_instance_digest",
  "supervisor_process_start_digest", "supervisor_mapped_image_digest",
  "supervisor_principal_id", "supervisor_principal_policy_digest",
  "supervisor_listener_generation", "supervisor_listener_identity_digest",
  "worker_audit_token_digest", "worker_process_id", "worker_process_pidversion",
  "worker_process_instance_digest", "worker_process_start_digest", "worker_mapped_image_digest",
  "worker_principal_id", "worker_principal_policy_digest",
  "worker_direct_parent_audit_token_digest", "worker_direct_parent_instance_digest",
  "worker_direct_parent_start_digest", "launch_nonce", "launch_nonce_digest",
  "launch_generation", "authority_id", "authority_epoch", "revocation_generation",
  "revocation_state_digest", "resource_epoch", "resource_state_digest",
  "capability_set_digest", "expected_descriptor_semantics_digest",
  "observed_descriptor_semantics_digest", "descriptor_identity_digest",
  "receiver_cloexec_applied", "descriptor_aliases_absent", "unexpected_descriptors_closed",
  "capability_generation", "clock_epoch_digest",
]);

function assertLiveExchangeState(input) {
  const label = "assert_live_exchange_state";
  assertExactObject(input, ["binding", "current_state", "phase"], label);
  const binding = normalizeBinding(ownDataValue(input, "binding", label));
  const current = normalizeCurrentState(ownDataValue(input, "current_state", label));
  const phase = assertEnum(ownDataValue(input, "phase", label),
    ["grant", "go", "effect", "result", "cleanup"], `${label}.phase`);
  for (let index = 0; index < LIVE_BINDINGS.length; index += 1) {
    const field = LIVE_BINDINGS[index];
    if (binding[field] !== current[field]) {
      reject("live_state_drift", `${label}.${field} drifted before ${phase}`);
    }
  }
  const deadlineField = phase === "effect" ? "result_deadline_monotonic_ns"
    : `${phase}_deadline_monotonic_ns`;
  if (ns(current.observed_monotonic_ns) < ns(binding.not_before_monotonic_ns)
      || ns(current.observed_monotonic_ns) >= ns(binding[deadlineField])) {
    reject("live_state_drift", `${label} is outside the ${phase} deadline`);
  }
  return objectFreeze({
    version: AUTHENTICATED_EXCHANGE_VERSION,
    phase,
    binding_digest: hashCanonicalJson(binding),
    observed_monotonic_ns: current.observed_monotonic_ns,
    valid: true,
    production_ready: false,
    assurance: FIXTURE_ASSURANCE,
  });
}

function verifyJournalChain(entriesInput, verifier, binding, records) {
  assertDenseArray(entriesInput, "authenticated_exchange.journal_entries");
  const entries = [];
  let previous = null;
  let state = "none";
  let journalId = null;
  for (let index = 0; index < entriesInput.length; index += 1) {
    const entry = verifyRecord("journal_entry",
      ownDataValue(entriesInput, String(index), "authenticated_exchange.journal_entries"),
      verifier);
    assertSameBinding({ binding, binding_digest: hashCanonicalJson(binding) }, entry.payload,
      `journal_entries[${index}]`);
    if (entry.payload.entry_sequence !== String(index + 1)
        || entry.payload.previous_entry_digest !== previous
        || entry.payload.from_state !== state
        || (journalId != null && entry.payload.journal_id !== journalId)) {
      reject("chain_invalid", `journal_entries[${index}] chain or state fork`);
    }
    if (journalId == null) journalId = entry.payload.journal_id;
    const expected = records[entry.payload.subject_kind];
    if (expected && expected !== entry.payload.subject_digest) {
      reject("binding_invalid", `journal_entries[${index}] subject digest drift`);
    }
    appendOwnArrayValue(entries, entry);
    previous = entry.envelope_digest;
    state = entry.payload.to_state;
  }
  return { entries: objectFreeze(entries), state, head: previous };
}

function terminalOutboxIdentityDigest(payload) {
  return hashCanonicalJson({
    version: AUTHENTICATED_EXCHANGE_VERSION,
    binding_digest: payload.binding_digest,
    outbox_id: payload.outbox_id,
    delivery_id: payload.delivery_id,
    terminal_state: payload.terminal_state,
    terminal_journal_entry_digest: payload.terminal_journal_entry_digest,
    grant_envelope_digest: payload.grant_envelope_digest,
    go_envelope_digest: payload.go_envelope_digest,
    receipt_observation: payload.receipt_observation,
    receipt_envelope_digest: payload.receipt_envelope_digest,
    receipt_evidence_digest: payload.receipt_evidence_digest,
    exact_result_digest: payload.exact_result_digest,
    cleanup_state: payload.cleanup_state,
    retry_disposition: payload.retry_disposition,
  });
}

function verifyOutboxChain(entriesInput, verifier, binding, records, terminalJournal) {
  assertDenseArray(entriesInput, "authenticated_exchange.outbox_entries", 2);
  const entries = [];
  let previous = null;
  let enqueue = null;
  let outboxId = null;
  for (let index = 0; index < entriesInput.length; index += 1) {
    const entry = verifyRecord("outbox_record",
      ownDataValue(entriesInput, String(index), "authenticated_exchange.outbox_entries"),
      verifier);
    assertSameBinding({ binding, binding_digest: hashCanonicalJson(binding) }, entry.payload,
      `outbox_entries[${index}]`);
    if (entry.payload.entry_sequence !== String(index + 1)
        || entry.payload.previous_entry_digest !== previous
        || entry.payload.grant_envelope_digest !== records.capability_grant
        || entry.payload.go_envelope_digest !== records.commit_go
        || entry.payload.terminal_journal_entry_digest !== terminalJournal
        || (outboxId != null && entry.payload.outbox_id !== outboxId)) {
      reject("chain_invalid", `outbox_entries[${index}] chain or terminal binding drift`);
    }
    if (outboxId == null) outboxId = entry.payload.outbox_id;
    if (index === 0 && entry.payload.subject_digest !== terminalJournal) {
      reject("chain_invalid", "outbox enqueue does not bind the terminal journal head");
    }
    if (index === 0) enqueue = entry;
    if (index === 1 && (
      terminalOutboxIdentityDigest(entry.payload) !== terminalOutboxIdentityDigest(enqueue.payload)
      || entry.payload.subject_digest !== entry.payload.acknowledgement_digest
    )) {
      reject("chain_invalid", "outbox acknowledgement is spliced from another delivery");
    }
    appendOwnArrayValue(entries, entry);
    previous = entry.envelope_digest;
  }
  return {
    entries: objectFreeze(entries),
    head: previous,
    terminal_identity_digest: enqueue == null ? null : terminalOutboxIdentityDigest(enqueue.payload),
  };
}

function verifyDurabilityChain(
  input, verifier, binding, journalEntries, outboxEntries, durableStores,
) {
  assertDenseArray(input, "authenticated_exchange.durability_attestations",
    journalEntries.length + outboxEntries.length);
  if (input.length !== journalEntries.length + outboxEntries.length) {
    reject("durability_missing", "every journal/outbox record needs one durability attestation");
  }
  const byDigest = new Map();
  let previous = null;
  let previousFsync = null;
  let previousDirectorySequence = 0n;
  const chainStorage = new Map();
  const chainOffsets = new Map();
  chainOffsets.set("journal", 0n);
  chainOffsets.set("outbox", 0n);
  const nextChainSequence = new Map();
  nextChainSequence.set("journal", 1n);
  nextChainSequence.set("outbox", 1n);
  const verifierKeys = VERIFIER_KEYS.get(verifier);
  const durabilityKey = verifierKeys && verifierKeys.get("durability_custodian");
  if (!durabilityKey) reject("keyring_invalid", "durability custodian key is not enrolled");
  for (let index = 0; index < input.length; index += 1) {
    const attestation = verifyRecord("durability_attestation",
      ownDataValue(input, String(index), "authenticated_exchange.durability_attestations"),
      verifier);
    const payload = attestation.payload;
    assertSameBinding({ binding, binding_digest: hashCanonicalJson(binding) }, payload,
      `durability_attestations[${index}]`);
    if (payload.durability_sequence !== String(index + 1)
        || payload.previous_attestation_digest !== previous
        || ns(payload.append_sequence) <= previousDirectorySequence
        || (previousFsync != null
          && ns(payload.append_completed_monotonic_ns) < ns(previousFsync))) {
      reject("durability_order_invalid", `durability_attestations[${index}] chain/order fork`);
    }
    const chain = payload.chain_kind === "journal" ? journalEntries : outboxEntries;
    const durableStore = durableStores[payload.chain_kind];
    const chainSequence = ns(payload.chain_sequence);
    const record = chainSequence <= BigInt(chain.length)
      ? chain[Number(chainSequence - 1n)] : null;
    const stableBytes = durableStore && chainSequence <= BigInt(durableStore.bytes.length)
      ? durableStore.bytes[Number(chainSequence - 1n)] : null;
    const storageIdentity = canonicalJson({
      store_id: payload.store_id,
      store_epoch: payload.store_epoch,
      file_identity_digest: payload.file_identity_digest,
      file_generation: payload.file_generation,
    });
    const enrolledStorage = chainStorage.get(payload.chain_kind);
    if (!record || !stableBytes) {
      reject("durability_invalid",
        `durability_attestations[${index}] names no exact durable chain bytes`);
    }
    if (chainSequence !== nextChainSequence.get(payload.chain_kind)
        || ns(record.payload.recorded_monotonic_ns)
          > ns(payload.append_completed_monotonic_ns)) {
      reject("durability_order_invalid",
        `durability_attestations[${index}] append order precedes its signed record`);
    }
    const stableSha256 = crypto.createHash("sha256").update(stableBytes).digest("hex");
    if (payload.record_envelope_digest !== record.envelope_digest
        || payload.record_payload_digest !== record.payload_digest
        || payload.record_canonical_sha256 !== stableSha256
        || payload.record_byte_length !== stableBytes.length
        || bufferCompare(stableBytes, bufferFrom(canonicalJson(record), "utf8")) !== 0
        || payload.previous_record_envelope_digest
          !== (payload.chain_sequence === "1"
            ? null : chain[Number(chainSequence - 2n)].envelope_digest)
        || payload.store_id !== durableStore.descriptor.store_id
        || payload.store_epoch !== durableStore.descriptor.store_epoch
        || payload.file_identity_digest !== durableStore.descriptor.file_identity_digest
        || payload.file_generation !== durableStore.descriptor.file_generation
        || (enrolledStorage != null && storageIdentity !== enrolledStorage)
        || ns(payload.record_offset) !== chainOffsets.get(payload.chain_kind)
        || payload.exclusive_writer_principal_id !== durabilityKey.principal_id) {
      reject("durability_invalid", `durability_attestations[${index}] does not bind stable bytes`);
    }
    if (enrolledStorage == null) chainStorage.set(payload.chain_kind, storageIdentity);
    nextChainSequence.set(payload.chain_kind, chainSequence + 1n);
    chainOffsets.set(payload.chain_kind,
      chainOffsets.get(payload.chain_kind) + BigInt(payload.record_byte_length));
    if (byDigest.has(record.envelope_digest)) {
      reject("durability_invalid", "a record cannot receive duplicate durability attestations");
    }
    byDigest.set(record.envelope_digest, attestation);
    previous = attestation.envelope_digest;
    previousFsync = payload.directory_fsync_completed_monotonic_ns;
    previousDirectorySequence = ns(payload.directory_fsync_sequence);
  }
  return { attestations: byDigest, head: previous };
}

function assertEventBindings(journal, grant, go, receipt, observation) {
  const eventEntries = new Map();
  for (let index = 0; index < journal.entries.length; index += 1) {
    const entry = journal.entries[index];
    if (eventEntries.has(entry.payload.event)) {
      reject("single_use_violation", `journal duplicates ${entry.payload.event}`);
    }
    eventEntries.set(entry.payload.event, entry);
  }
  const grantEntry = eventEntries.get("grant_fsynced");
  if (grantEntry && (grantEntry.payload.subject_kind !== "capability_grant"
      || grantEntry.payload.subject_digest !== grant.envelope_digest)) {
    reject("binding_invalid", "grant journal entry does not bind the exact signed grant");
  }
  const goEntry = eventEntries.get("go_fsynced");
  if (go && (!goEntry || goEntry.payload.subject_kind !== "commit_go"
      || goEntry.payload.subject_digest !== go.envelope_digest)) {
    reject("binding_invalid", "GO record is not consumed by the exact durable journal entry");
  }
  if (!go && goEntry) reject("binding_invalid", "journal claims a missing GO record");
  const effectEntry = eventEntries.get("effect_started");
  if (effectEntry && (!go || effectEntry.payload.subject_kind !== "effect_start_authority"
      || effectEntry.payload.subject_digest !== go.envelope_digest)) {
    reject("binding_invalid", "effect start is detached from the exact signed GO");
  }
  const receiptEntry = eventEntries.get("receipt_fsynced");
  if (receipt && (!receiptEntry || receiptEntry.payload.subject_kind !== "terminal_receipt"
      || receiptEntry.payload.subject_digest !== receipt.envelope_digest)) {
    reject("binding_invalid", "receipt is not consumed by the exact durable journal entry");
  }
  if (!receipt && receiptEntry) reject("binding_invalid", "journal claims a missing receipt");
  if (observation !== "present" && receipt) {
    reject("receipt_invalid", "non-present receipt observation cannot carry a receipt");
  }
  return eventEntries;
}

function assertCrossRecordBindings(grant, go, receipt, journal, eventEntries) {
  if (grant.payload.previous_journal_entry_digest !== null) {
    reject("binding_invalid", "one-exchange grant must begin at an empty journal head");
  }
  if (go) {
    assertSameBinding(grant.payload, go.payload, "commit_go");
    const grantEntry = eventEntries.get("grant_fsynced");
    const readyEntry = eventEntries.get("ready_no_effect");
    const transferEntry = eventEntries.get("capabilities_transferred");
    if (!grantEntry || !transferEntry || !readyEntry
        || go.payload.grant_envelope_digest !== grant.envelope_digest
        || go.payload.grant_payload_digest !== grant.payload_digest
        || go.payload.grant_journal_entry_digest !== grantEntry.envelope_digest
        || go.payload.capability_transfer_ack_digest !== transferEntry.payload.subject_digest
        || go.payload.ready_no_effect_digest !== readyEntry.payload.subject_digest
        || go.payload.previous_journal_entry_digest !== readyEntry.envelope_digest
        || ns(go.payload.issued_monotonic_ns) <= ns(grant.payload.issued_monotonic_ns)) {
      reject("binding_invalid", "GO is detached from grant or READY journal history");
    }
  }
  if (receipt) {
    if (!go) reject("receipt_invalid", "post-effect receipt requires a GO");
    assertSameBinding(grant.payload, receipt.payload, "terminal_receipt");
    const goEntry = eventEntries.get("go_fsynced");
    const effectEntry = eventEntries.get("effect_started");
    if (!goEntry || !effectEntry
        || receipt.payload.grant_envelope_digest !== grant.envelope_digest
        || receipt.payload.go_envelope_digest !== go.envelope_digest
        || receipt.payload.go_journal_entry_digest !== goEntry.envelope_digest
        || receipt.payload.cleanup_plan_digest !== grant.payload.cleanup_plan_digest
        || effectEntry.payload.subject_digest !== go.envelope_digest
        || ns(receipt.payload.completed_monotonic_ns)
          < ns(effectEntry.payload.recorded_monotonic_ns)
        || (receipt.payload.exact_result.cleanup_state === "not_required"
          && ns(receipt.payload.completed_monotonic_ns)
            >= ns(receipt.payload.binding.result_deadline_monotonic_ns))) {
      reject("binding_invalid", "receipt is detached from grant, GO, journal, or cleanup plan");
    }
  }
  if (arrayContains(TERMINAL_STATES, journal.state)) {
    const tail = journal.entries[journal.entries.length - 1];
    if (tail.payload.event !== TERMINAL_EVENT[journal.state]) {
      reject("transition_invalid", "journal terminal state has the wrong terminal event");
    }
    if (receipt && journal.state !== receipt.payload.terminal_state) {
      reject("result_invalid", "journal terminal state disagrees with signed receipt");
    }
    if (receipt && tail.payload.subject_digest !== receipt.envelope_digest) {
      reject("binding_invalid", "terminal journal entry does not bind the signed receipt");
    }
  }
}

function assertFsyncBeforeEffects(journal, outbox, durability, grant, go, receipt) {
  const events = new Map();
  for (let index = 0; index < journal.entries.length; index += 1) {
    const entry = journal.entries[index];
    events.set(entry.payload.event, entry);
  }
  const grantEntry = events.get("grant_fsynced");
  if (grantEntry && (ns(grantEntry.payload.recorded_monotonic_ns)
      < ns(grant.payload.issued_monotonic_ns)
      || ns(grantEntry.payload.recorded_monotonic_ns)
        >= ns(grant.payload.binding.grant_deadline_monotonic_ns))) {
    reject("durability_order_invalid", "grant journal commit is outside the grant window");
  }
  for (let index = 1; index < journal.entries.length; index += 1) {
    const prior = journal.entries[index - 1];
    const current = journal.entries[index];
    const durable = durability.attestations.get(prior.envelope_digest);
    if (!durable || ns(current.payload.recorded_monotonic_ns)
        < ns(durable.payload.directory_fsync_completed_monotonic_ns)) {
      reject("durability_order_invalid", "journal transition occurred before prior fsync");
    }
  }
  if (grantEntry) {
    const grantDurable = durability.attestations.get(grantEntry.envelope_digest);
    if (!grantDurable || ns(grantDurable.payload.directory_fsync_completed_monotonic_ns)
      >= ns(grant.payload.binding.grant_deadline_monotonic_ns)) {
      reject("durability_order_invalid", "grant did not become durable inside its window");
    }
  }
  if (go) {
    const ready = events.get("ready_no_effect");
    const grantJournal = events.get("grant_fsynced");
    const grantDurable = grantJournal
      && durability.attestations.get(grantJournal.envelope_digest);
    const readyDurable = ready && durability.attestations.get(ready.envelope_digest);
    if (!grantDurable || !readyDurable
        || ns(go.payload.issued_monotonic_ns)
          < ns(readyDurable.payload.directory_fsync_completed_monotonic_ns)) {
      reject("durability_order_invalid", "GO issued before durable grant and READY history");
    }
    const goEntry = events.get("go_fsynced");
    const effect = events.get("effect_started");
    const goDurable = goEntry && durability.attestations.get(goEntry.envelope_digest);
    if (!goDurable || ns(goDurable.payload.directory_fsync_completed_monotonic_ns)
      >= ns(go.payload.binding.go_deadline_monotonic_ns)) {
      reject("durability_order_invalid", "GO journal did not become durable inside its window");
    }
    if (effect && (!goDurable || ns(effect.payload.recorded_monotonic_ns)
      < ns(goDurable.payload.directory_fsync_completed_monotonic_ns)
      || ns(effect.payload.recorded_monotonic_ns)
        >= ns(go.payload.binding.result_deadline_monotonic_ns))) {
      reject("durability_order_invalid", "effect started before the GO journal fsync");
    }
  }
  if (receipt && arrayContains(TERMINAL_STATES, journal.state)) {
    const receiptEntry = events.get("receipt_fsynced");
    const terminal = journal.entries[journal.entries.length - 1];
    const receiptDurable = receiptEntry && durability.attestations.get(receiptEntry.envelope_digest);
    if (!receiptDurable || ns(terminal.payload.recorded_monotonic_ns)
      < ns(receiptDurable.payload.directory_fsync_completed_monotonic_ns)) {
      reject("durability_order_invalid", "terminal state preceded receipt fsync");
    }
  }
  if (arrayContains(TERMINAL_STATES, journal.state)) {
    const terminal = journal.entries[journal.entries.length - 1];
    const terminalDurable = durability.attestations.get(terminal.envelope_digest);
    const deadline = journal.state === "rejected_no_effect"
      ? grant.payload.binding.go_deadline_monotonic_ns
      : journal.state === "completed"
        ? grant.payload.binding.result_deadline_monotonic_ns
        : grant.payload.binding.cleanup_deadline_monotonic_ns;
    if (!terminalDurable
        || ns(terminal.payload.recorded_monotonic_ns) >= ns(deadline)
        || ns(terminalDurable.payload.directory_fsync_completed_monotonic_ns) >= ns(deadline)) {
      reject("durability_order_invalid", "terminal journal missed its signed phase deadline");
    }
  }
  if (outbox.entries.length > 0) {
    const terminal = journal.entries[journal.entries.length - 1];
    const terminalDurable = durability.attestations.get(terminal.envelope_digest);
    if (!terminalDurable || ns(outbox.entries[0].payload.recorded_monotonic_ns)
      < ns(terminalDurable.payload.directory_fsync_completed_monotonic_ns)) {
      reject("durability_order_invalid", "outbox enqueue preceded terminal journal fsync");
    }
    const enqueueDurable = durability.attestations.get(outbox.entries[0].envelope_digest);
    if (!enqueueDurable || ns(enqueueDurable.payload.directory_fsync_completed_monotonic_ns)
      >= ns(grant.payload.binding.parent_deadline_monotonic_ns)) {
      reject("durability_order_invalid", "terminal outbox missed the parent deadline");
    }
  }
  if (outbox.entries.length === 2) {
    const enqueueDurable = durability.attestations.get(outbox.entries[0].envelope_digest);
    if (!enqueueDurable || ns(outbox.entries[1].payload.recorded_monotonic_ns)
      < ns(enqueueDurable.payload.directory_fsync_completed_monotonic_ns)) {
      reject("durability_order_invalid", "outbox acknowledgement preceded enqueue fsync");
    }
  }
}

function syntheticAmbiguousResult(observation, evidenceDigest) {
  return normalizeExactResult({
    result_status: "ambiguous",
    effect_state: "unknown_effect",
    result_code: observation === "missing" ? "missing_post_go_receipt" : "malformed_post_go_receipt",
    response_digest: null,
    response_byte_length: 0,
    device_state_digest: null,
    external_observation_digest: evidenceDigest,
    cleanup_state: "failed_ambiguous",
    cleanup_evidence_digest: evidenceDigest || hashCanonicalJson({ observation }),
  });
}

function reconcileAuthenticatedExchange(input) {
  const label = "reconcile_authenticated_exchange";
  assertExactObject(input, RECONCILE_FIELDS, label);
  assertExact(ownDataValue(input, "version", label), AUTHENTICATED_EXCHANGE_VERSION,
    `${label}.version`);
  const verifier = ownDataValue(input, "verifier", label);
  if (!VERIFIER_KEYS.has(verifier)) reject("keyring_invalid", `${label}.verifier is invalid`);
  const grant = verifyRecord("capability_grant", ownDataValue(input, "grant", label), verifier);
  if (grant.payload.binding.revocation_generation !== verifier.revocation_generation
      || grant.payload.binding.revocation_state_digest !== verifier.revocation_state_digest) {
    reject("authentication_invalid", "exchange revocation state is detached from the verifier");
  }
  const goInput = ownDataValue(input, "go", label);
  const go = goInput === null ? null : verifyRecord("commit_go", goInput, verifier);
  const receiptInput = ownDataValue(input, "receipt", label);
  const receipt = receiptInput === null
    ? null : verifyRecord("terminal_receipt", receiptInput, verifier);
  if ((go && go.authentication.principal_id !== grant.payload.binding.supervisor_principal_id)
      || (receipt
        && receipt.authentication.principal_id !== grant.payload.binding.worker_principal_id)) {
    reject("process_lineage_invalid",
      "GO/receipt signer principal is detached from supervisor/worker lineage");
  }
  const observation = assertEnum(ownDataValue(input, "receipt_observation", label),
    RECEIPT_OBSERVATIONS, `${label}.receipt_observation`);
  const malformedDigest = assertNullableDigest(
    ownDataValue(input, "malformed_receipt_digest", label), `${label}.malformed_receipt_digest`,
  );
  if ((observation === "present") !== (receipt !== null)
      || (observation === "malformed") !== (malformedDigest !== null)) {
    reject("receipt_invalid", `${label} receipt observation and evidence disagree`);
  }
  if ((go === null && observation !== "not_applicable")
      || (go !== null && observation === "not_applicable")) {
    reject("receipt_invalid", `${label} receipt applicability disagrees with GO issuance`);
  }
  const autoRetry = assertBoolean(ownDataValue(input, "auto_retry_requested", label),
    `${label}.auto_retry_requested`);
  if (autoRetry) {
    reject("automatic_retry_forbidden", "an authenticated grant/GO is never automatically retried");
  }
  const records = {
    capability_grant: grant.envelope_digest,
    commit_go: go ? go.envelope_digest : null,
    terminal_receipt: receipt ? receipt.envelope_digest : null,
  };
  const durableReadback = resolveDurableExchangeRecords(input, grant.payload.binding);
  const durableStores = durableReadback.snapshot.stores;
  const journal = verifyJournalChain(
    durableStores.journal.records, verifier, grant.payload.binding, records,
  );
  const eventEntries = assertEventBindings(journal, grant, go, receipt, observation);
  assertCrossRecordBindings(grant, go, receipt, journal, eventEntries);
  const terminalJournal = arrayContains(TERMINAL_STATES, journal.state)
      && journal.entries.length > 0
    ? journal.entries[journal.entries.length - 1].envelope_digest : null;
  const outbox = verifyOutboxChain(
    durableStores.outbox.records, verifier, grant.payload.binding, records, terminalJournal,
  );
  const durability = verifyDurabilityChain(
    durableStores.durability.records, verifier, grant.payload.binding,
    journal.entries, outbox.entries, durableStores,
  );
  if (journal.head !== durableStores.journal.descriptor.head_envelope_digest
      || outbox.head !== durableStores.outbox.descriptor.head_envelope_digest
      || durability.head !== durableStores.durability.descriptor.head_envelope_digest) {
    reject("durable_readback_mismatch",
      "verified sequence/head/previous chain differs from the exact durable snapshot");
  }
  assertFsyncBeforeEffects(journal, outbox, durability, grant, go, receipt);
  const current = normalizeCurrentState(ownDataValue(input, "current_state", label));

  let state = journal.state;
  let authenticatedTerminal = arrayContains(TERMINAL_STATES, state)
    && outbox.entries.length > 0;
  let recoveryAction = "none";
  let result = receipt ? receipt.payload.exact_result : null;
  if (!go) {
    if (state === "none") recoveryAction = "discard_uncommitted_grant";
    else if (!arrayContains(TERMINAL_STATES, state)) {
      recoveryAction = "terminate_exact_child_then_record_rejected_no_effect";
    } else if (!authenticatedTerminal) recoveryAction = "enqueue_authenticated_terminal";
  } else if (observation !== "present") {
    result = syntheticAmbiguousResult(observation, malformedDigest);
    state = "ambiguous_quarantined";
    const terminalTail = journal.state === "ambiguous_quarantined"
      ? journal.entries[journal.entries.length - 1] : null;
    if (terminalTail && (terminalTail.payload.subject_kind !== "receipt_loss_evidence"
      || terminalTail.payload.subject_digest !== hashCanonicalJson(result))) {
      reject("binding_invalid",
        "ambiguous terminal journal is detached from the exact receipt-loss result");
    }
    authenticatedTerminal = journal.state === "ambiguous_quarantined"
      && outbox.entries.length > 0
      && outbox.entries[0].payload.receipt_observation === observation
      && outbox.entries[0].payload.receipt_evidence_digest === malformedDigest
      && outbox.entries[0].payload.exact_result_digest === hashCanonicalJson(result);
    if (!authenticatedTerminal) recoveryAction = "persist_authenticated_ambiguous_quarantine";
  } else if (!arrayContains(TERMINAL_STATES, state)) {
    recoveryAction = state === "receipt_recorded"
      ? "persist_authenticated_terminal" : "reconcile_effect_then_quarantine_if_unproven";
  } else if (!authenticatedTerminal) {
    recoveryAction = "enqueue_authenticated_terminal";
  }
  if (authenticatedTerminal && outbox.entries.length === 1) {
    recoveryAction = "redeliver_outbox_only";
  }
  if (authenticatedTerminal && outbox.entries.length === 2) recoveryAction = "none";

  if (outbox.entries.length > 0) {
    const terminal = outbox.entries[0].payload;
    if (result == null) result = terminal.exact_result;
    if (terminal.terminal_state !== state
        || terminal.receipt_observation !== observation
        || terminal.receipt_envelope_digest !== records.terminal_receipt
        || (result && terminal.exact_result_digest !== hashCanonicalJson(result))) {
      reject("outbox_invalid", "outbox terminal projection is detached from reconciliation");
    }
    if (state === "rejected_no_effect"
        && terminal.exact_result.external_observation_digest
          !== journal.entries[journal.entries.length - 1].payload.subject_digest) {
      reject("binding_invalid", "rejected terminal is detached from its no-GO proof");
    }
  }

  let liveStateDisposition = "current";
  try {
    assertLiveExchangeState({
      binding: grant.payload.binding,
      current_state: current,
      phase: go ? "cleanup" : "go",
    });
  } catch (error) {
    if (!error || error.code !== "live_state_drift") throw error;
    liveStateDisposition = go ? "post_go_drift_quarantine_required" : "pre_go_drift_reject_no_effect";
    if (go && !authenticatedTerminal) {
      state = "ambiguous_quarantined";
      recoveryAction = "persist_authenticated_ambiguous_quarantine";
    }
  }

  return objectFreeze({
    version: AUTHENTICATED_EXCHANGE_VERSION,
    protocol: AUTHENTICATED_EXCHANGE_PROTOCOL,
    exchange_id: grant.payload.binding.exchange_id,
    binding_digest: grant.payload.binding_digest,
    state,
    journal_state: journal.state,
    authenticated_terminal: authenticatedTerminal,
    outbox_delivery_state: outbox.entries.length === 2
      ? "acknowledged" : outbox.entries.length === 1 ? "pending" : "absent",
    recovery_action: recoveryAction,
    live_state_disposition: liveStateDisposition,
    grant_consumed: eventEntries.has("grant_fsynced"),
    go_consumed: eventEntries.has("go_fsynced"),
    automatic_effect_retry_permitted: false,
    outbox_redelivery_permitted: authenticatedTerminal && outbox.entries.length === 1,
    exact_result_digest: result ? hashCanonicalJson(result) : null,
    terminal_outbox_identity_digest: outbox.terminal_identity_digest,
    journal_head_digest: journal.head,
    outbox_head_digest: outbox.head,
    durability_head_digest: durability.head,
    durable_snapshot_id: durableReadback.snapshot.snapshot_id,
    durable_snapshot_sequence: durableReadback.snapshot.snapshot_sequence,
    durable_readback_recovered_acknowledgement:
      durableReadback.recovered_acknowledgement,
    assurance: FIXTURE_ASSURANCE,
    production_ready: false,
    hardware_access_authorized: false,
  });
}

function verifySingleUseExchangeRecords(input) {
  const label = "verify_single_use_exchange_records";
  assertExactObject(input, ["version", "grants", "gos", "verifier"], label);
  assertExact(ownDataValue(input, "version", label), AUTHENTICATED_EXCHANGE_VERSION,
    `${label}.version`);
  const verifier = ownDataValue(input, "verifier", label);
  const grantsInput = ownDataValue(input, "grants", label);
  const gosInput = ownDataValue(input, "gos", label);
  assertDenseArray(grantsInput, `${label}.grants`);
  assertDenseArray(gosInput, `${label}.gos`);
  const grantUses = new Set();
  const goUses = new Set();
  const exchangeIds = new Set();
  const grantDigests = new Set();
  const grantsByDigest = new Map();
  for (let index = 0; index < grantsInput.length; index += 1) {
    const item = ownDataValue(grantsInput, String(index), `${label}.grants`);
    const grant = verifyRecord("capability_grant", item, verifier);
    const binding = grant.payload.binding;
    const keys = [
      `nonce:${grant.payload.grant_nonce}`,
      `launch:${binding.launch_nonce}:${binding.launch_generation}`,
      `capability:${binding.component_id}:${binding.capability_generation}`,
      `grant:${binding.authority_id}:${binding.grant_sequence}`,
    ];
    let replayed = false;
    for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
      if (grantUses.has(keys[keyIndex])) {
        replayed = true;
        break;
      }
    }
    if (exchangeIds.has(binding.exchange_id) || replayed) {
      reject("single_use_violation", "grant nonce/generation/sequence replay detected");
    }
    exchangeIds.add(binding.exchange_id);
    grantDigests.add(grant.envelope_digest);
    grantsByDigest.set(grant.envelope_digest, grant);
    for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
      grantUses.add(keys[keyIndex]);
    }
  }
  for (let index = 0; index < gosInput.length; index += 1) {
    const item = ownDataValue(gosInput, String(index), `${label}.gos`);
    const go = verifyRecord("commit_go", item, verifier);
    const binding = go.payload.binding;
    const keys = [
      `go:${binding.authority_id}:${binding.go_sequence}`,
      `capability:${binding.component_id}:${binding.capability_generation}`,
      `launch:${binding.launch_nonce}:${binding.launch_generation}`,
    ];
    if (!grantDigests.has(go.payload.grant_envelope_digest)) {
      reject("binding_invalid", "GO does not consume one of the supplied signed grants");
    }
    assertSameBinding(grantsByDigest.get(go.payload.grant_envelope_digest).payload,
      go.payload, "single_use_go");
    let replayed = false;
    for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
      if (goUses.has(keys[keyIndex])) {
        replayed = true;
        break;
      }
    }
    if (replayed) {
      reject("single_use_violation", "GO sequence/generation replay detected");
    }
    for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
      goUses.add(keys[keyIndex]);
    }
  }
  return objectFreeze({
    version: AUTHENTICATED_EXCHANGE_VERSION,
    grant_count: grantsInput.length,
    go_count: gosInput.length,
    replay_free: true,
    production_ready: false,
    assurance: FIXTURE_ASSURANCE,
  });
}

const signCapabilityGrant = (input) => signRecord("capability_grant", input);
const signCommitGo = (input) => signRecord("commit_go", input);
const signTerminalReceipt = (input) => signRecord("terminal_receipt", input);
const signJournalEntry = (input) => signRecord("journal_entry", input);
const signOutboxRecord = (input) => signRecord("outbox_record", input);
const signDurabilityAttestation = (input) => signRecord("durability_attestation", input);

const verifyCapabilityGrant = (input, verifier) => verifyRecord("capability_grant", input, verifier);
const verifyCommitGo = (input, verifier) => verifyRecord("commit_go", input, verifier);
const verifyTerminalReceipt = (input, verifier) => verifyRecord("terminal_receipt", input, verifier);
const verifyJournalEntry = (input, verifier) => verifyRecord("journal_entry", input, verifier);
const verifyOutboxRecord = (input, verifier) => verifyRecord("outbox_record", input, verifier);
const verifyDurabilityAttestation = (input, verifier) => (
  verifyRecord("durability_attestation", input, verifier)
);

module.exports = objectFreeze({
  AUTHENTICATED_EXCHANGE_PROTOCOL,
  AUTHENTICATED_EXCHANGE_VERSION,
  CLEANUP_STATES,
  DURABILITY_EVIDENCE_ORIGIN,
  DURABLE_READBACK_CONSISTENCY_MODEL,
  DURABILITY_SCHEME,
  FIXTURE_ASSURANCE,
  ROLE_DEFINITIONS,
  TERMINAL_STATES,
  assertLiveExchangeState,
  canonicalRecordByteLength,
  canonicalRecordSha256,
  createFixtureDurableReadbackPort,
  createFixtureExchangeSigner,
  createFixtureExchangeVerifier,
  normalizeBinding,
  normalizeCommitGoPayload,
  normalizeDurabilityAttestationPayload,
  normalizeExactResult,
  normalizeJournalEntryPayload,
  normalizeOutboxRecordPayload,
  normalizeTerminalReceiptPayload,
  normalizeCapabilityGrantPayload,
  publicKeyDigest,
  reconcileAuthenticatedExchange,
  signCapabilityGrant,
  signCommitGo,
  signDurabilityAttestation,
  signJournalEntry,
  signOutboxRecord,
  signTerminalReceipt,
  verifyCapabilityGrant,
  verifyCommitGo,
  verifyDurabilityAttestation,
  verifyJournalEntry,
  verifyOutboxRecord,
  verifySingleUseExchangeRecords,
  verifyTerminalReceipt,
});
