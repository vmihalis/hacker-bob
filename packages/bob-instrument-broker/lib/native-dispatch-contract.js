"use strict";

// Provider-neutral wire contract for a future independently scheduled native
// effect custodian. This module is deliberately inert and does not expose a
// hardware port. It produces a fixed, canonical TLV payload so the eventual
// native verifier does not need to trust JavaScript object shape or JSON
// parsing at the final effect seam.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const SafeError = Error;
const SafeBigInt = BigInt;
const SafeNumber = Number;
const HostBuffer = Buffer;
const arrayIncludes = Array.prototype.includes;
const arrayIsArray = Array.isArray;
const bigIntToString = BigInt.prototype.toString;
const bufferAlloc = Buffer.alloc;
const bufferByteLength = Buffer.byteLength;
const bufferConcat = Buffer.concat;
const bufferFrom = Buffer.from;
const bufferIsBuffer = Buffer.isBuffer;
const bufferPrototype = Buffer.prototype;
const bufferCopy = bufferPrototype.copy;
const bufferEquals = bufferPrototype.equals;
const bufferFill = bufferPrototype.fill;
const bufferReadUInt16BE = bufferPrototype.readUInt16BE;
const bufferReadUInt32BE = bufferPrototype.readUInt32BE;
const bufferReadBigUInt64BE = bufferPrototype.readBigUInt64BE;
const bufferSubarray = bufferPrototype.subarray;
const bufferToString = bufferPrototype.toString;
const bufferWriteUInt16BE = bufferPrototype.writeUInt16BE;
const bufferWriteUInt32BE = bufferPrototype.writeUInt32BE;
const bufferWriteBigInt64BE = bufferPrototype.writeBigInt64BE;
const bufferWriteBigUInt64BE = bufferPrototype.writeBigUInt64BE;
const cryptoCreateHash = crypto.createHash;
const cryptoCreatePrivateKey = crypto.createPrivateKey;
const cryptoCreatePublicKey = crypto.createPublicKey;
const cryptoSign = crypto.sign;
const cryptoVerify = crypto.verify;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const objectKeys = Object.keys;
const objectPrototype = Object.prototype;
const numberIsSafeInteger = Number.isSafeInteger;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const regexpTest = RegExp.prototype.test;
const stringEndsWith = String.prototype.endsWith;
const stringIncludes = String.prototype.includes;
const utilIsProxy = utilTypes.isProxy;
const utilIsUint8Array = utilTypes.isUint8Array;

// Capture the mutable crypto object methods/getters once. The fixed probe is a
// syntactically valid Ed25519 SPKI public key and performs no I/O or discovery.
const publicKeyProbeDer = reflectApply(bufferFrom, HostBuffer, [
  "302a300506032b65700321000000000000000000000000000000000000000000000000000000000000000000",
  "hex",
]);
const publicKeyProbe = reflectApply(cryptoCreatePublicKey, crypto, [{
  key: publicKeyProbeDer,
  format: "der",
  type: "spki",
}]);
const publicKeyPrototype = objectGetPrototypeOf(publicKeyProbe);
const asymmetricKeyPrototype = objectGetPrototypeOf(publicKeyPrototype);
const keyObjectPrototype = objectGetPrototypeOf(asymmetricKeyPrototype);
const keyExport = publicKeyPrototype.export;
const keyAsymmetricTypeGetter = objectGetOwnPropertyDescriptor(
  asymmetricKeyPrototype,
  "asymmetricKeyType",
).get;
const keyTypeGetter = objectGetOwnPropertyDescriptor(keyObjectPrototype, "type").get;
reflectApply(bufferFill, publicKeyProbeDer, [0]);

const hashProbe = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
const hashPrototype = objectGetPrototypeOf(hashProbe);
const hashUpdate = hashPrototype.update;
const hashDigest = hashPrototype.digest;
reflectApply(hashDigest, hashProbe, []);

const NATIVE_DISPATCH_CONTRACT_VERSION = 1;
const NATIVE_DISPATCH_PROTOCOL = "hacker-bob/physical-native-dispatch/v1";
const NATIVE_DISPATCH_TICKET_KIND = "physical_native_dispatch_ticket";
const NATIVE_DISPATCH_SIGNATURE_ALGORITHM = "ed25519";
const NATIVE_DISPATCH_SIGNATURE_ALGORITHM_ID = 1;
const NATIVE_DISPATCH_MAGIC = reflectApply(bufferFrom, HostBuffer, ["HBPHDSP1", "ascii"]);
const NATIVE_DISPATCH_ENVELOPE_MAGIC = reflectApply(
  bufferFrom,
  HostBuffer,
  ["HBPHDSE1", "ascii"],
);
const NATIVE_DELEGATED_DESCRIPTOR_MAGIC = reflectApply(
  bufferFrom,
  HostBuffer,
  ["HBPHDID1", "ascii"],
);
const NATIVE_DISPATCH_SIGNATURE_DOMAIN = reflectApply(
  bufferFrom,
  HostBuffer,
  ["hacker-bob/physical-native-dispatch-ticket-signature/v1\0", "utf8"],
);
const MAX_PAYLOAD_BYTES = 32 * 1024;
const MAX_ENVELOPE_BYTES = 40 * 1024;
const MAX_COMMAND_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_EFFECT_WINDOW_NS = 10n * 60n * 1_000_000_000n;
const MAX_UINT64 = (1n << 64n) - 1n;
const MIN_INT64 = -(1n << 63n);
const MAX_INT64 = (1n << 63n) - 1n;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/u;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/u;
const SIGNED_DECIMAL_PATTERN = /^-?(?:0|[1-9][0-9]{0,18})$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
const NATIVE_DELEGATED_DESCRIPTOR_FD = 4;
const NATIVE_DELEGATED_DESCRIPTOR_ROLE = "launcher_delegated_device_transport";
const NATIVE_DELEGATED_DESCRIPTOR_PURPOSE = "physical_native_dispatch_transport";
const NATIVE_DELEGATED_DESCRIPTOR_ACCESS_MODE = 2;
const NATIVE_DELEGATED_DESCRIPTOR_STATUS_FLAGS = 6;
const NATIVE_DELEGATED_DESCRIPTOR_FD_FLAGS = 0;
const NATIVE_RESPONSE_SINK_DESCRIPTOR_FD = 7;
const NATIVE_RESPONSE_SINK_DESCRIPTOR_ROLE = "vault_reserved_provider_response_sink";
const NATIVE_RESPONSE_SINK_DESCRIPTOR_PURPOSE = "physical_native_response_vault_ingest";
const NATIVE_RESPONSE_SINK_DESCRIPTOR_ACCESS_MODE = 1;
// Darwin O_WRONLY | O_APPEND. The native custodian is Darwin arm64-only and
// refuses any ambient descriptor whose kernel flags differ from this value.
const NATIVE_RESPONSE_SINK_DESCRIPTOR_STATUS_FLAGS = 9;
const NATIVE_RESPONSE_SINK_DESCRIPTOR_FD_FLAGS = 0;

const GRANT_KINDS = objectFreeze([
  "bootstrap",
  "preparation",
  "active",
  "maintenance",
  "cleanup",
]);
const COMMAND_KINDS = objectFreeze([
  "observe",
  "command",
  "cleanup",
  "fence",
  "quarantine",
]);
const EFFECT_CLASSES = objectFreeze([
  "none",
  "target",
  "environment",
  "device_admin",
]);
const RF_CONSTRAINTS = objectFreeze([
  "rf_off",
  "bounded",
  "not_applicable",
]);

const FIELD_DEFINITIONS = objectFreeze([
  [1, "version", "u32"],
  [2, "protocol", "protocol"],
  [3, "grant_kind", "grant_kind"],
  [4, "command_kind", "command_kind"],
  [5, "effect_class", "effect_class"],
  [6, "rf_constraint", "rf_constraint"],
  [7, "ticket_id", "token"],
  [8, "ticket_nonce", "nonce"],
  [9, "ticket_sequence", "u64_positive"],
  [10, "provider_id", "identifier"],
  [11, "provider_descriptor_digest", "digest"],
  [12, "provider_implementation_digest", "digest"],
  [13, "semantic_manifest_digest", "digest"],
  [14, "device_identity_digest", "digest"],
  [15, "device_enrollment_digest", "digest"],
  [16, "connection_generation", "u64_positive"],
  [17, "execution_principal_id", "token"],
  [18, "worker_process_start_digest", "digest"],
  [19, "worker_bundle_digest", "digest"],
  [20, "native_loaded_image_identity_digest", "digest"],
  [21, "launcher_ticket_digest", "digest"],
  [22, "launcher_delegation_receipt_digest", "digest"],
  [23, "device_descriptor_inventory_digest", "digest"],
  [24, "session_nucleus_hash", "digest"],
  [25, "node_id", "token"],
  [26, "contract_hash", "digest"],
  [27, "attempt_ref", "token"],
  [28, "signed_grant_digest", "digest"],
  [29, "execution_request_digest", "digest"],
  [30, "authority_resolution_digest", "digest"],
  [31, "authority_epoch", "u64_positive"],
  [32, "revocation_generation", "u64"],
  [33, "operation_id", "token"],
  [34, "operation_digest", "digest"],
  [35, "parameter_digest", "digest"],
  [36, "requested_effects_digest", "digest"],
  [37, "required_pre_state_digest", "digest"],
  [38, "authorized_transition_digest", "digest"],
  [39, "resource_bundle_digest", "digest"],
  [40, "allocation_digest", "digest"],
  [41, "reservation_receipt_digest", "digest"],
  [42, "fencing_token_digest", "digest"],
  [43, "journal_entry_digest", "digest"],
  [44, "outbox_entry_digest", "digest"],
  [45, "provider_redemption_digest", "digest"],
  [46, "safety_contract_digest", "digest"],
  [47, "safety_custody_receipt_digest", "digest"],
  [48, "cleanup_precommit_digest", "digest"],
  [49, "observer_plan_digest", "digest"],
  [50, "command_sequence", "u64_positive"],
  [51, "command_bytes_digest", "digest"],
  [52, "command_byte_length", "u32_positive"],
  [53, "maximum_response_bytes", "u32_positive"],
  [54, "clock_epoch_digest", "digest"],
  [55, "not_before_monotonic_ns", "u64"],
  [56, "deadline_monotonic_ns", "u64_positive"],
  [57, "one_use", "true"],
  [58, "delegated_descriptor_identity_digest", "digest"],
  [59, "execution_lineage_digest", "digest"],
  [60, "vault_reservation_digest", "digest"],
  [61, "vault_ingest_capability_digest", "digest"],
  [62, "vault_sink_descriptor_identity_digest", "digest"],
  [63, "vault_byte_ceiling", "u32_positive"],
  [64, "artifact_handle_digest", "digest"],
].map((entry) => objectFreeze(entry)));
const PAYLOAD_FIELDS = objectFreeze(FIELD_DEFINITIONS.map((entry) => entry[1]));
const SIGN_INPUT_FIELDS = objectFreeze(["payload", "key_id", "private_key"]);
const TICKET_FIELDS = objectFreeze([
  "version",
  "kind",
  "envelope_b64",
  "envelope_digest",
]);

const DELEGATED_DESCRIPTOR_IDENTITY_FIELDS = objectFreeze([
  "version",
  "role",
  "fd_number",
  "purpose",
  "dev",
  "ino",
  "rdev",
  "mode",
  "nlink",
  "uid",
  "gid",
  "character_device",
  "access_mode",
  "status_flags",
  "fd_flags",
]);
const DELEGATED_DESCRIPTOR_FIELD_DEFINITIONS = objectFreeze([
  [1, "version", "u32"],
  [2, "role", "text"],
  [3, "fd_number", "u32"],
  [4, "purpose", "text"],
  [5, "dev", "i64"],
  [6, "ino", "u64_positive"],
  [7, "rdev", "i64"],
  [8, "mode", "u32"],
  [9, "nlink", "u64_positive"],
  [10, "uid", "u32"],
  [11, "gid", "u32"],
  [12, "character_device", "true"],
  [13, "access_mode", "u32"],
  [14, "status_flags", "u32"],
  [15, "fd_flags", "u32"],
].map((entry) => objectFreeze(entry)));

const RESPONSE_SINK_DESCRIPTOR_IDENTITY_FIELDS = objectFreeze([
  "version",
  "role",
  "fd_number",
  "purpose",
  "dev",
  "ino",
  "rdev",
  "mode",
  "nlink",
  "uid",
  "gid",
  "regular_file",
  "access_mode",
  "status_flags",
  "fd_flags",
  "initial_size",
]);
const RESPONSE_SINK_DESCRIPTOR_FIELD_DEFINITIONS = objectFreeze([
  [1, "version", "u32"],
  [2, "role", "text"],
  [3, "fd_number", "u32"],
  [4, "purpose", "text"],
  [5, "dev", "i64"],
  [6, "ino", "u64_positive"],
  [7, "rdev", "i64"],
  [8, "mode", "u32"],
  [9, "nlink", "u64_positive"],
  [10, "uid", "u32"],
  [11, "gid", "u32"],
  [12, "regular_file", "true"],
  [13, "access_mode", "u32"],
  [14, "status_flags", "u32"],
  [15, "fd_flags", "u32"],
  [16, "initial_size", "u64"],
].map((entry) => objectFreeze(entry)));

const NATIVE_DISPATCH_CONTRACT_ASSURANCE = objectFreeze({
  version: NATIVE_DISPATCH_CONTRACT_VERSION,
  protocol: NATIVE_DISPATCH_PROTOCOL,
  canonical_binary_payload: true,
  canonical_signed_binary_envelope: true,
  signature_binds_key_id_and_public_key_digest: true,
  delegated_descriptor_identity_encoding: true,
  response_sink_descriptor_identity_encoding: true,
  raw_command_bytes_embedded_in_ticket: false,
  native_signature_verifier_implemented: false,
  native_monotonic_deadline_recheck_implemented: false,
  launcher_delegated_descriptor_consumption_implemented: false,
  independently_preemptible_effect_boundary_implemented: false,
  hardware_authority_constructible: false,
  production_ready: false,
});

function contractError() {
  const error = new SafeError("Physical native dispatch contract was rejected");
  objectDefineProperty(error, "code", {
    value: "physical_native_dispatch_contract_rejected",
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return error;
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object"
      || reflectApply(arrayIsArray, Array, [value])
      || reflectApply(utilIsProxy, utilTypes, [value])) return false;
  const prototype = objectGetPrototypeOf(value);
  if (prototype !== objectPrototype && prototype !== null) return false;
  const ownKeys = reflectOwnKeys(value);
  for (let index = 0; index < ownKeys.length; index += 1) {
    const key = ownKeys[index];
    if (typeof key !== "string") return false;
    const descriptor = objectGetOwnPropertyDescriptor(value, key);
    if (descriptor == null || !objectHasOwn(descriptor, "value")
        || descriptor.enumerable !== true) return false;
  }
  return true;
}

function assertExactDataObject(value, fields) {
  if (!isPlainDataObject(value)) throw contractError();
  const keys = objectKeys(value);
  if (keys.length !== fields.length) throw contractError();
  for (let index = 0; index < fields.length; index += 1) {
    if (!objectHasOwn(value, fields[index])) throw contractError();
  }
  return value;
}

function assertPattern(value, pattern, maximumBytes = 512) {
  if (typeof value !== "string" || value.length === 0
      || reflectApply(bufferByteLength, HostBuffer, [value, "utf8"]) > maximumBytes
      || reflectApply(stringIncludes, value, ["\0"])
      || !reflectApply(regexpTest, pattern, [value])) throw contractError();
  return value;
}

function assertDigest(value) {
  return assertPattern(value, DIGEST_PATTERN, 64);
}

function assertToken(value) {
  return assertPattern(value, TOKEN_PATTERN, 191);
}

function assertIdentifier(value) {
  return assertPattern(value, IDENTIFIER_PATTERN, 128);
}

function assertEnum(value, allowed) {
  if (typeof value !== "string"
      || !reflectApply(arrayIncludes, allowed, [value])) throw contractError();
  return value;
}

function assertUint32(value, positive) {
  if (!reflectApply(numberIsSafeInteger, SafeNumber, [value])
      || value < (positive ? 1 : 0)
      || value > 0xffff_ffff) throw contractError();
  return value;
}

function assertUint64Decimal(value, positive) {
  if (typeof value !== "string" || !reflectApply(regexpTest, DECIMAL_PATTERN, [value])) {
    throw contractError();
  }
  let parsed;
  try {
    parsed = reflectApply(SafeBigInt, undefined, [value]);
  } catch {
    throw contractError();
  }
  if (parsed > MAX_UINT64 || (positive && parsed === 0n)) throw contractError();
  return value;
}

function assertInt64Decimal(value) {
  if (typeof value !== "string"
      || !reflectApply(regexpTest, SIGNED_DECIMAL_PATTERN, [value])
      || value === "-0") throw contractError();
  const parsed = reflectApply(SafeBigInt, undefined, [value]);
  if (parsed < MIN_INT64 || parsed > MAX_INT64) throw contractError();
  return value;
}

function base64urlBytes(value, minimum, maximum) {
  assertPattern(value, BASE64URL_PATTERN, Math.ceil(maximum * 4 / 3) + 4);
  let bytes;
  try {
    bytes = reflectApply(bufferFrom, HostBuffer, [value, "base64url"]);
  } catch {
    throw contractError();
  }
  if (bytes.length < minimum || bytes.length > maximum
      || reflectApply(bufferToString, bytes, ["base64url"]) !== value) {
    reflectApply(bufferFill, bytes, [0]);
    throw contractError();
  }
  return bytes;
}

function normalizePayload(input) {
  assertExactDataObject(input, PAYLOAD_FIELDS);
  const output = {};
  for (let fieldIndex = 0; fieldIndex < FIELD_DEFINITIONS.length; fieldIndex += 1) {
    const definition = FIELD_DEFINITIONS[fieldIndex];
    const name = definition[1];
    const type = definition[2];
    const value = input[name];
    switch (type) {
      case "u32": output[name] = assertUint32(value, false); break;
      case "u32_positive": output[name] = assertUint32(value, true); break;
      case "u64": output[name] = assertUint64Decimal(value, false); break;
      case "u64_positive": output[name] = assertUint64Decimal(value, true); break;
      case "protocol":
        if (value !== NATIVE_DISPATCH_PROTOCOL) throw contractError();
        output[name] = value;
        break;
      case "grant_kind": output[name] = assertEnum(value, GRANT_KINDS); break;
      case "command_kind": output[name] = assertEnum(value, COMMAND_KINDS); break;
      case "effect_class": output[name] = assertEnum(value, EFFECT_CLASSES); break;
      case "rf_constraint": output[name] = assertEnum(value, RF_CONSTRAINTS); break;
      case "token": output[name] = assertToken(value); break;
      case "identifier": output[name] = assertIdentifier(value); break;
      case "digest": output[name] = assertDigest(value); break;
      case "nonce": {
        const bytes = base64urlBytes(value, 16, 64);
        reflectApply(bufferFill, bytes, [0]);
        output[name] = value;
        break;
      }
      case "true":
        if (value !== true) throw contractError();
        output[name] = true;
        break;
      default: throw contractError();
    }
  }
  if (output.version !== NATIVE_DISPATCH_CONTRACT_VERSION) throw contractError();
  const notBefore = reflectApply(SafeBigInt, undefined, [output.not_before_monotonic_ns]);
  const deadline = reflectApply(SafeBigInt, undefined, [output.deadline_monotonic_ns]);
  if (deadline <= notBefore || deadline - notBefore > MAX_EFFECT_WINDOW_NS) {
    throw contractError();
  }
  if (output.command_byte_length > MAX_COMMAND_BYTES
      || output.maximum_response_bytes > MAX_RESPONSE_BYTES
      || output.vault_byte_ceiling > MAX_RESPONSE_BYTES
      || output.maximum_response_bytes > output.vault_byte_ceiling) throw contractError();
  if (output.grant_kind === "bootstrap"
      && (output.command_kind !== "observe" || output.effect_class !== "none"
        || output.rf_constraint !== "rf_off")) throw contractError();
  if (output.grant_kind === "cleanup" && output.command_kind !== "cleanup") {
    throw contractError();
  }
  return objectFreeze(output);
}

function encodeString(value) {
  return reflectApply(bufferFrom, HostBuffer, [value, "utf8"]);
}

function encodeField(type, value) {
  if (type === "digest") return reflectApply(bufferFrom, HostBuffer, [value, "hex"]);
  if (type === "nonce") return base64urlBytes(value, 16, 64);
  if (type === "u32" || type === "u32_positive") {
    const bytes = reflectApply(bufferAlloc, HostBuffer, [4]);
    reflectApply(bufferWriteUInt32BE, bytes, [value, 0]);
    return bytes;
  }
  if (type === "u64" || type === "u64_positive") {
    const bytes = reflectApply(bufferAlloc, HostBuffer, [8]);
    reflectApply(bufferWriteBigUInt64BE, bytes, [reflectApply(SafeBigInt, undefined, [value]), 0]);
    return bytes;
  }
  if (type === "i64") {
    const bytes = reflectApply(bufferAlloc, HostBuffer, [8]);
    reflectApply(bufferWriteBigInt64BE, bytes, [
      reflectApply(SafeBigInt, undefined, [value]),
      0,
    ]);
    return bytes;
  }
  if (type === "true") return reflectApply(bufferFrom, HostBuffer, [[1]]);
  return encodeString(value);
}

function encodeNativeDispatchPayload(input) {
  const payload = normalizePayload(input);
  const header = reflectApply(bufferAlloc, HostBuffer, [12]);
  reflectApply(bufferCopy, NATIVE_DISPATCH_MAGIC, [header, 0]);
  reflectApply(bufferWriteUInt16BE, header, [NATIVE_DISPATCH_CONTRACT_VERSION, 8]);
  reflectApply(bufferWriteUInt16BE, header, [FIELD_DEFINITIONS.length, 10]);
  const chunks = [header];
  let total = header.length;
  try {
    for (let fieldIndex = 0; fieldIndex < FIELD_DEFINITIONS.length; fieldIndex += 1) {
      const definition = FIELD_DEFINITIONS[fieldIndex];
      const tag = definition[0];
      const name = definition[1];
      const type = definition[2];
      const value = encodeField(type, payload[name]);
      const framing = reflectApply(bufferAlloc, HostBuffer, [6]);
      reflectApply(bufferWriteUInt16BE, framing, [tag, 0]);
      reflectApply(bufferWriteUInt32BE, framing, [value.length, 2]);
      chunks.push(framing, value);
      total += framing.length + value.length;
      if (total > MAX_PAYLOAD_BYTES) throw contractError();
    }
    return reflectApply(bufferConcat, HostBuffer, [chunks, total]);
  } catch (error) {
    for (let index = 1; index < chunks.length; index += 1) {
      reflectApply(bufferFill, chunks[index], [0]);
    }
    throw error;
  }
}

function normalizeDelegatedDescriptorIdentity(input) {
  assertExactDataObject(input, DELEGATED_DESCRIPTOR_IDENTITY_FIELDS);
  const output = {};
  for (let index = 0; index < DELEGATED_DESCRIPTOR_FIELD_DEFINITIONS.length; index += 1) {
    const definition = DELEGATED_DESCRIPTOR_FIELD_DEFINITIONS[index];
    const name = definition[1];
    const type = definition[2];
    if (type === "u32") output[name] = assertUint32(input[name], false);
    else if (type === "i64") output[name] = assertInt64Decimal(input[name]);
    else if (type === "u64") output[name] = assertUint64Decimal(input[name], false);
    else if (type === "u64_positive") {
      output[name] = assertUint64Decimal(input[name], true);
    } else if (type === "true") {
      if (input[name] !== true) throw contractError();
      output[name] = true;
    } else if (type === "text") output[name] = assertToken(input[name]);
    else throw contractError();
  }
  if (output.version !== NATIVE_DISPATCH_CONTRACT_VERSION
      || output.role !== NATIVE_DELEGATED_DESCRIPTOR_ROLE
      || output.fd_number !== NATIVE_DELEGATED_DESCRIPTOR_FD
      || output.purpose !== NATIVE_DELEGATED_DESCRIPTOR_PURPOSE
      || (output.mode & 0xf000) !== 0x2000
      || output.access_mode !== NATIVE_DELEGATED_DESCRIPTOR_ACCESS_MODE
      || output.status_flags !== NATIVE_DELEGATED_DESCRIPTOR_STATUS_FLAGS
      || output.fd_flags !== NATIVE_DELEGATED_DESCRIPTOR_FD_FLAGS) throw contractError();
  return objectFreeze(output);
}

function encodeNativeDelegatedDescriptorIdentity(input) {
  const identity = normalizeDelegatedDescriptorIdentity(input);
  const header = reflectApply(bufferAlloc, HostBuffer, [12]);
  reflectApply(bufferCopy, NATIVE_DELEGATED_DESCRIPTOR_MAGIC, [header, 0]);
  reflectApply(bufferWriteUInt16BE, header, [NATIVE_DISPATCH_CONTRACT_VERSION, 8]);
  reflectApply(bufferWriteUInt16BE, header, [
    DELEGATED_DESCRIPTOR_FIELD_DEFINITIONS.length,
    10,
  ]);
  const chunks = [header];
  let total = header.length;
  try {
    for (let index = 0; index < DELEGATED_DESCRIPTOR_FIELD_DEFINITIONS.length; index += 1) {
      const definition = DELEGATED_DESCRIPTOR_FIELD_DEFINITIONS[index];
      const tag = definition[0];
      const name = definition[1];
      const type = definition[2];
      const value = encodeField(type, identity[name]);
      const framing = reflectApply(bufferAlloc, HostBuffer, [6]);
      reflectApply(bufferWriteUInt16BE, framing, [tag, 0]);
      reflectApply(bufferWriteUInt32BE, framing, [value.length, 2]);
      chunks.push(framing, value);
      total += framing.length + value.length;
      if (total > 1024) throw contractError();
    }
    return reflectApply(bufferConcat, HostBuffer, [chunks, total]);
  } catch (error) {
    for (let index = 0; index < chunks.length; index += 1) {
      reflectApply(bufferFill, chunks[index], [0]);
    }
    throw error;
  }
}

function deriveNativeDelegatedDescriptorIdentityDigest(input) {
  const encoded = encodeNativeDelegatedDescriptorIdentity(input);
  try {
    return sha256Bytes(encoded);
  } finally {
    reflectApply(bufferFill, encoded, [0]);
  }
}

function normalizeNativeResponseSinkDescriptorIdentity(input) {
  assertExactDataObject(input, RESPONSE_SINK_DESCRIPTOR_IDENTITY_FIELDS);
  const output = {};
  for (let index = 0; index < RESPONSE_SINK_DESCRIPTOR_FIELD_DEFINITIONS.length; index += 1) {
    const definition = RESPONSE_SINK_DESCRIPTOR_FIELD_DEFINITIONS[index];
    const name = definition[1];
    const type = definition[2];
    if (type === "u32") output[name] = assertUint32(input[name], false);
    else if (type === "i64") output[name] = assertInt64Decimal(input[name]);
    else if (type === "u64") output[name] = assertUint64Decimal(input[name], false);
    else if (type === "u64_positive") {
      output[name] = assertUint64Decimal(input[name], true);
    } else if (type === "true") {
      if (input[name] !== true) throw contractError();
      output[name] = true;
    } else if (type === "text") output[name] = assertToken(input[name]);
    else throw contractError();
  }
  if (output.version !== NATIVE_DISPATCH_CONTRACT_VERSION
      || output.role !== NATIVE_RESPONSE_SINK_DESCRIPTOR_ROLE
      || output.fd_number !== NATIVE_RESPONSE_SINK_DESCRIPTOR_FD
      || output.purpose !== NATIVE_RESPONSE_SINK_DESCRIPTOR_PURPOSE
      || (output.mode & 0xf000) !== 0x8000
      || (output.mode & 0o077) !== 0
      || output.nlink !== "1"
      || output.initial_size !== "0"
      || output.access_mode !== NATIVE_RESPONSE_SINK_DESCRIPTOR_ACCESS_MODE
      || output.status_flags !== NATIVE_RESPONSE_SINK_DESCRIPTOR_STATUS_FLAGS
      || output.fd_flags !== NATIVE_RESPONSE_SINK_DESCRIPTOR_FD_FLAGS) throw contractError();
  return objectFreeze(output);
}

function encodeNativeResponseSinkDescriptorIdentity(input) {
  const identity = normalizeNativeResponseSinkDescriptorIdentity(input);
  const magic = reflectApply(bufferFrom, HostBuffer, ["HBPHDVS1", "ascii"]);
  const header = reflectApply(bufferAlloc, HostBuffer, [12]);
  reflectApply(bufferCopy, magic, [header, 0]);
  reflectApply(bufferFill, magic, [0]);
  reflectApply(bufferWriteUInt16BE, header, [NATIVE_DISPATCH_CONTRACT_VERSION, 8]);
  reflectApply(bufferWriteUInt16BE, header, [
    RESPONSE_SINK_DESCRIPTOR_FIELD_DEFINITIONS.length,
    10,
  ]);
  const chunks = [header];
  let total = header.length;
  try {
    for (let index = 0; index < RESPONSE_SINK_DESCRIPTOR_FIELD_DEFINITIONS.length; index += 1) {
      const definition = RESPONSE_SINK_DESCRIPTOR_FIELD_DEFINITIONS[index];
      const value = encodeField(definition[2], identity[definition[1]]);
      const framing = reflectApply(bufferAlloc, HostBuffer, [6]);
      reflectApply(bufferWriteUInt16BE, framing, [definition[0], 0]);
      reflectApply(bufferWriteUInt32BE, framing, [value.length, 2]);
      chunks.push(framing, value);
      total += framing.length + value.length;
      if (total > 1024) throw contractError();
    }
    return reflectApply(bufferConcat, HostBuffer, [chunks, total]);
  } catch (error) {
    for (let index = 0; index < chunks.length; index += 1) {
      reflectApply(bufferFill, chunks[index], [0]);
    }
    throw error;
  }
}

function deriveNativeResponseSinkDescriptorIdentityDigest(input) {
  const encoded = encodeNativeResponseSinkDescriptorIdentity(input);
  try {
    return sha256Bytes(encoded);
  } finally {
    reflectApply(bufferFill, encoded, [0]);
  }
}

function decodeText(bytes) {
  const value = reflectApply(bufferToString, bytes, ["utf8"]);
  const canonical = encodeString(value);
  const equal = reflectApply(bufferEquals, canonical, [bytes]);
  reflectApply(bufferFill, canonical, [0]);
  if (!equal || reflectApply(stringIncludes, value, ["\0"])) throw contractError();
  return value;
}

function decodeField(type, bytes) {
  if (type === "digest") {
    if (bytes.length !== 32) throw contractError();
    return reflectApply(bufferToString, bytes, ["hex"]);
  }
  if (type === "nonce") {
    if (bytes.length < 16 || bytes.length > 64) throw contractError();
    return reflectApply(bufferToString, bytes, ["base64url"]);
  }
  if (type === "u32" || type === "u32_positive") {
    if (bytes.length !== 4) throw contractError();
    return reflectApply(bufferReadUInt32BE, bytes, [0]);
  }
  if (type === "u64" || type === "u64_positive") {
    if (bytes.length !== 8) throw contractError();
    const value = reflectApply(bufferReadBigUInt64BE, bytes, [0]);
    return reflectApply(bigIntToString, value, [10]);
  }
  if (type === "true") {
    if (bytes.length !== 1 || bytes[0] !== 1) throw contractError();
    return true;
  }
  return decodeText(bytes);
}

function assertByteInput(input, maximumBytes = MAX_PAYLOAD_BYTES) {
  if (!reflectApply(bufferIsBuffer, HostBuffer, [input])
      && (input == null || reflectApply(utilIsProxy, utilTypes, [input])
        || !reflectApply(utilIsUint8Array, utilTypes, [input]))) throw contractError();
  const bytes = reflectApply(bufferFrom, HostBuffer, [input]);
  if (bytes.length < 12 || bytes.length > maximumBytes) {
    reflectApply(bufferFill, bytes, [0]);
    throw contractError();
  }
  return bytes;
}

function decodeNativeDispatchPayload(input) {
  const bytes = assertByteInput(input);
  try {
    if (!reflectApply(bufferEquals,
      reflectApply(bufferSubarray, bytes, [0, 8]),
      [NATIVE_DISPATCH_MAGIC])
        || reflectApply(bufferReadUInt16BE, bytes, [8]) !== NATIVE_DISPATCH_CONTRACT_VERSION
        || reflectApply(bufferReadUInt16BE, bytes, [10]) !== FIELD_DEFINITIONS.length) {
      throw contractError();
    }
    let offset = 12;
    const output = {};
    for (let fieldIndex = 0; fieldIndex < FIELD_DEFINITIONS.length; fieldIndex += 1) {
      const definition = FIELD_DEFINITIONS[fieldIndex];
      const expectedTag = definition[0];
      const name = definition[1];
      const type = definition[2];
      if (offset + 6 > bytes.length) throw contractError();
      const tag = reflectApply(bufferReadUInt16BE, bytes, [offset]);
      const length = reflectApply(bufferReadUInt32BE, bytes, [offset + 2]);
      offset += 6;
      if (tag !== expectedTag || length > MAX_PAYLOAD_BYTES - offset
          || offset + length > bytes.length) throw contractError();
      output[name] = decodeField(type, reflectApply(bufferSubarray, bytes, [
        offset,
        offset + length,
      ]));
      offset += length;
    }
    if (offset !== bytes.length) throw contractError();
    const payload = normalizePayload(output);
    const canonical = encodeNativeDispatchPayload(payload);
    try {
      if (!reflectApply(bufferEquals, canonical, [bytes])) throw contractError();
    } finally {
      reflectApply(bufferFill, canonical, [0]);
    }
    return payload;
  } finally {
    reflectApply(bufferFill, bytes, [0]);
  }
}

function sha256Bytes(bytes) {
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(hashUpdate, hash, [bytes]);
  return reflectApply(hashDigest, hash, ["hex"]);
}

function normalizePrivateKey(input) {
  let key;
  try {
    if (reflectApply(keyTypeGetter, input, []) === "private"
        && reflectApply(keyAsymmetricTypeGetter, input, []) === "ed25519") {
      return input;
    }
  } catch {
    // Continue through the captured parser for encoded key material.
  }
  try {
    key = reflectApply(cryptoCreatePrivateKey, crypto, [input]);
  } catch {
    throw contractError();
  }
  if (reflectApply(keyTypeGetter, key, []) !== "private"
      || reflectApply(keyAsymmetricTypeGetter, key, []) !== "ed25519") {
    throw contractError();
  }
  return key;
}

function normalizePublicKey(input) {
  let key;
  try {
    if (reflectApply(keyTypeGetter, input, []) === "public"
        && reflectApply(keyAsymmetricTypeGetter, input, []) === "ed25519") {
      return input;
    }
  } catch {
    // Continue through the captured parser for encoded/private key material.
  }
  try {
    key = reflectApply(cryptoCreatePublicKey, crypto, [input]);
  } catch {
    throw contractError();
  }
  if (reflectApply(keyTypeGetter, key, []) !== "public"
      || reflectApply(keyAsymmetricTypeGetter, key, []) !== "ed25519") {
    throw contractError();
  }
  return key;
}

function nativeDispatchPublicKeyDigest(input) {
  const key = normalizePublicKey(input);
  const der = reflectApply(keyExport, key, [{ type: "spki", format: "der" }]);
  try {
    return sha256Bytes(der);
  } finally {
    reflectApply(bufferFill, der, [0]);
  }
}

function signatureMessage(preSignatureEnvelopeBytes) {
  const length = reflectApply(bufferAlloc, HostBuffer, [8]);
  reflectApply(bufferWriteBigUInt64BE, length, [
    reflectApply(SafeBigInt, undefined, [preSignatureEnvelopeBytes.length]),
    0,
  ]);
  return reflectApply(bufferConcat, HostBuffer, [[
    NATIVE_DISPATCH_SIGNATURE_DOMAIN,
    length,
    preSignatureEnvelopeBytes,
  ]]);
}

function encodePreSignatureEnvelope(payloadBytes, keyId, publicKeyDigest) {
  const keyIdBytes = encodeString(assertToken(keyId));
  const publicDigestBytes = reflectApply(bufferFrom, HostBuffer, [
    assertDigest(publicKeyDigest),
    "hex",
  ]);
  const header = reflectApply(bufferAlloc, HostBuffer, [50]);
  try {
    reflectApply(bufferCopy, NATIVE_DISPATCH_ENVELOPE_MAGIC, [header, 0]);
    reflectApply(bufferWriteUInt16BE, header, [NATIVE_DISPATCH_CONTRACT_VERSION, 8]);
    reflectApply(bufferWriteUInt16BE, header, [NATIVE_DISPATCH_SIGNATURE_ALGORITHM_ID, 10]);
    reflectApply(bufferWriteUInt16BE, header, [keyIdBytes.length, 12]);
    reflectApply(bufferWriteUInt32BE, header, [payloadBytes.length, 14]);
    reflectApply(bufferCopy, publicDigestBytes, [header, 18]);
    const total = header.length + keyIdBytes.length + payloadBytes.length;
    if (total + 64 > MAX_ENVELOPE_BYTES) throw contractError();
    return reflectApply(bufferConcat, HostBuffer, [
      [header, keyIdBytes, payloadBytes],
      total,
    ]);
  } finally {
    reflectApply(bufferFill, header, [0]);
    reflectApply(bufferFill, keyIdBytes, [0]);
    reflectApply(bufferFill, publicDigestBytes, [0]);
  }
}

function decodeNativeDispatchEnvelopeBytes(input) {
  const envelope = assertByteInput(input, MAX_ENVELOPE_BYTES);
  try {
    if (envelope.length < 50 + 1 + 12 + 64 || envelope.length > MAX_ENVELOPE_BYTES
        || !reflectApply(bufferEquals,
          reflectApply(bufferSubarray, envelope, [0, 8]),
          [NATIVE_DISPATCH_ENVELOPE_MAGIC])
        || reflectApply(bufferReadUInt16BE, envelope, [8])
          !== NATIVE_DISPATCH_CONTRACT_VERSION
        || reflectApply(bufferReadUInt16BE, envelope, [10])
          !== NATIVE_DISPATCH_SIGNATURE_ALGORITHM_ID) {
      throw contractError();
    }
    const keyIdLength = reflectApply(bufferReadUInt16BE, envelope, [12]);
    const payloadLength = reflectApply(bufferReadUInt32BE, envelope, [14]);
    const payloadOffset = 50 + keyIdLength;
    const signatureOffset = payloadOffset + payloadLength;
    if (keyIdLength < 1 || keyIdLength > 191
        || payloadLength < 12 || payloadLength > MAX_PAYLOAD_BYTES
        || signatureOffset + 64 !== envelope.length) throw contractError();
    const keyIdBytes = reflectApply(bufferSubarray, envelope, [50, payloadOffset]);
    const keyId = assertToken(decodeText(keyIdBytes));
    if (reflectApply(bufferByteLength, HostBuffer, [keyId, "utf8"]) !== keyIdLength) {
      throw contractError();
    }
    const publicKeyDigest = reflectApply(bufferToString,
      reflectApply(bufferSubarray, envelope, [18, 50]),
      ["hex"]);
    assertDigest(publicKeyDigest);
    const payloadBytes = reflectApply(bufferSubarray, envelope, [
      payloadOffset,
      signatureOffset,
    ]);
    const payload = decodeNativeDispatchPayload(payloadBytes);
    return objectFreeze({
      key_id: keyId,
      public_key_digest: publicKeyDigest,
      payload,
      payload_offset: payloadOffset,
      payload_length: payloadLength,
      signature_offset: signatureOffset,
    });
  } finally {
    reflectApply(bufferFill, envelope, [0]);
  }
}

function signNativeDispatchTicket(input) {
  assertExactDataObject(input, SIGN_INPUT_FIELDS);
  const keyId = assertToken(input.key_id);
  const privateKey = normalizePrivateKey(input.private_key);
  const publicKey = reflectApply(cryptoCreatePublicKey, crypto, [privateKey]);
  const publicKeyDigest = nativeDispatchPublicKeyDigest(publicKey);
  const payloadBytes = encodeNativeDispatchPayload(input.payload);
  let preSignatureEnvelope;
  let message;
  let signature;
  let envelope;
  try {
    preSignatureEnvelope = encodePreSignatureEnvelope(
      payloadBytes,
      keyId,
      publicKeyDigest,
    );
    message = signatureMessage(preSignatureEnvelope);
    signature = reflectApply(cryptoSign, crypto, [null, message, privateKey]);
    if (signature.length !== 64) throw contractError();
    envelope = reflectApply(bufferConcat, HostBuffer, [[
      preSignatureEnvelope,
      signature,
    ]]);
    return objectFreeze({
      version: NATIVE_DISPATCH_CONTRACT_VERSION,
      kind: NATIVE_DISPATCH_TICKET_KIND,
      envelope_b64: reflectApply(bufferToString, envelope, ["base64url"]),
      envelope_digest: sha256Bytes(envelope),
    });
  } finally {
    reflectApply(bufferFill, payloadBytes, [0]);
    if (preSignatureEnvelope) reflectApply(bufferFill, preSignatureEnvelope, [0]);
    if (message) reflectApply(bufferFill, message, [0]);
    if (signature) reflectApply(bufferFill, signature, [0]);
    if (envelope) reflectApply(bufferFill, envelope, [0]);
  }
}

function normalizeSignedNativeDispatchTicket(input) {
  assertExactDataObject(input, TICKET_FIELDS);
  if (input.version !== NATIVE_DISPATCH_CONTRACT_VERSION
      || input.kind !== NATIVE_DISPATCH_TICKET_KIND) {
    throw contractError();
  }
  const envelopeBytes = base64urlBytes(input.envelope_b64, 50 + 1 + 12 + 64,
    MAX_ENVELOPE_BYTES);
  try {
    decodeNativeDispatchEnvelopeBytes(envelopeBytes);
    if (sha256Bytes(envelopeBytes) !== assertDigest(input.envelope_digest)) {
      throw contractError();
    }
  } finally {
    reflectApply(bufferFill, envelopeBytes, [0]);
  }
  return objectFreeze({
    version: input.version,
    kind: input.kind,
    envelope_b64: input.envelope_b64,
    envelope_digest: input.envelope_digest,
  });
}

function verifySignedNativeDispatchTicket(input, publicKeyInput, expectedKeyIdInput) {
  const ticket = normalizeSignedNativeDispatchTicket(input);
  const publicKey = normalizePublicKey(publicKeyInput);
  const envelopeBytes = base64urlBytes(ticket.envelope_b64, 50 + 1 + 12 + 64,
    MAX_ENVELOPE_BYTES);
  let decoded;
  let message;
  try {
    decoded = decodeNativeDispatchEnvelopeBytes(envelopeBytes);
    if (nativeDispatchPublicKeyDigest(publicKey) !== decoded.public_key_digest
        || (expectedKeyIdInput !== undefined
          && assertToken(expectedKeyIdInput) !== decoded.key_id)) throw contractError();
    const preSignatureEnvelope = reflectApply(bufferSubarray, envelopeBytes, [
      0,
      decoded.signature_offset,
    ]);
    const signature = reflectApply(bufferSubarray, envelopeBytes, [decoded.signature_offset]);
    message = signatureMessage(preSignatureEnvelope);
    if (!reflectApply(cryptoVerify, crypto, [null, message, publicKey, signature])) {
      throw contractError();
    }
    return decoded.payload;
  } finally {
    reflectApply(bufferFill, envelopeBytes, [0]);
    if (message) reflectApply(bufferFill, message, [0]);
  }
}

function assertNativeDispatchCommandBytes(payloadInput, commandInput) {
  const payload = normalizePayload(payloadInput);
  if (!reflectApply(bufferIsBuffer, HostBuffer, [commandInput])
      && (commandInput == null || reflectApply(utilIsProxy, utilTypes, [commandInput])
        || !reflectApply(utilIsUint8Array, utilTypes, [commandInput]))) {
    throw contractError();
  }
  const command = reflectApply(bufferFrom, HostBuffer, [commandInput]);
  try {
    if (command.length !== payload.command_byte_length
        || command.length < 1 || command.length > MAX_COMMAND_BYTES
        || sha256Bytes(command) !== payload.command_bytes_digest) throw contractError();
    return objectFreeze({
      command_byte_length: command.length,
      command_bytes_digest: payload.command_bytes_digest,
      maximum_response_bytes: payload.maximum_response_bytes,
    });
  } finally {
    reflectApply(bufferFill, command, [0]);
  }
}

module.exports = objectFreeze({
  COMMAND_KINDS,
  EFFECT_CLASSES,
  GRANT_KINDS,
  NATIVE_DISPATCH_CONTRACT_ASSURANCE,
  NATIVE_DISPATCH_CONTRACT_VERSION,
  NATIVE_DISPATCH_SIGNATURE_ALGORITHM,
  NATIVE_DISPATCH_PROTOCOL,
  NATIVE_DISPATCH_TICKET_KIND,
  NATIVE_DELEGATED_DESCRIPTOR_ACCESS_MODE,
  NATIVE_DELEGATED_DESCRIPTOR_FD,
  NATIVE_DELEGATED_DESCRIPTOR_FD_FLAGS,
  NATIVE_DELEGATED_DESCRIPTOR_PURPOSE,
  NATIVE_DELEGATED_DESCRIPTOR_ROLE,
  NATIVE_DELEGATED_DESCRIPTOR_STATUS_FLAGS,
  NATIVE_RESPONSE_SINK_DESCRIPTOR_ACCESS_MODE,
  NATIVE_RESPONSE_SINK_DESCRIPTOR_FD,
  NATIVE_RESPONSE_SINK_DESCRIPTOR_FD_FLAGS,
  NATIVE_RESPONSE_SINK_DESCRIPTOR_PURPOSE,
  NATIVE_RESPONSE_SINK_DESCRIPTOR_ROLE,
  NATIVE_RESPONSE_SINK_DESCRIPTOR_STATUS_FLAGS,
  RF_CONSTRAINTS,
  assertNativeDispatchCommandBytes,
  decodeNativeDispatchPayload,
  deriveNativeDelegatedDescriptorIdentityDigest,
  deriveNativeResponseSinkDescriptorIdentityDigest,
  encodeNativeDelegatedDescriptorIdentity,
  encodeNativeResponseSinkDescriptorIdentity,
  encodeNativeDispatchPayload,
  nativeDispatchPublicKeyDigest,
  normalizeSignedNativeDispatchTicket,
  signNativeDispatchTicket,
  verifySignedNativeDispatchTicket,
  _internals: objectFreeze({
    FIELD_DEFINITIONS,
    DELEGATED_DESCRIPTOR_FIELD_DEFINITIONS,
    RESPONSE_SINK_DESCRIPTOR_FIELD_DEFINITIONS,
    MAX_COMMAND_BYTES,
    MAX_ENVELOPE_BYTES,
    MAX_EFFECT_WINDOW_NS,
    MAX_PAYLOAD_BYTES,
    MAX_RESPONSE_BYTES,
    decodeNativeDispatchEnvelopeBytes,
    normalizePayload,
    normalizeDelegatedDescriptorIdentity,
    normalizeNativeResponseSinkDescriptorIdentity,
  }),
});
