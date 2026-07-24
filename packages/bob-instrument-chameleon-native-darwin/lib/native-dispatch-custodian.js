"use strict";

// Pure binary contract for the Darwin native-dispatch custodian fixture. This
// module never spawns a process, opens a path, enumerates hardware, or exposes a
// transport. The effect boundary lives in the separately loaded native addon
// and accepts no JavaScript arguments; these encoders exist for the future
// launcher and for no-hardware process fixtures.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");
const {
  CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS,
} = require("./generated-bootstrap-semantics.js");

const SafeBigInt = BigInt;
const SafeError = Error;
const SafeNumber = Number;
const HostBuffer = Buffer;
const arrayIsArray = Array.isArray;
const bigIntToString = BigInt.prototype.toString;
const bufferAlloc = HostBuffer.alloc;
const bufferByteLength = HostBuffer.byteLength;
const bufferConcat = HostBuffer.concat;
const bufferCopy = HostBuffer.prototype.copy;
const bufferEquals = HostBuffer.prototype.equals;
const bufferFill = HostBuffer.prototype.fill;
const bufferFrom = HostBuffer.from;
const bufferIsBuffer = HostBuffer.isBuffer;
const bufferReadBigUInt64BE = HostBuffer.prototype.readBigUInt64BE;
const bufferReadUInt16BE = HostBuffer.prototype.readUInt16BE;
const bufferReadUInt32BE = HostBuffer.prototype.readUInt32BE;
const bufferSubarray = HostBuffer.prototype.subarray;
const bufferToString = HostBuffer.prototype.toString;
const bufferWriteBigUInt64BE = HostBuffer.prototype.writeBigUInt64BE;
const bufferWriteUInt16BE = HostBuffer.prototype.writeUInt16BE;
const bufferWriteUInt32BE = HostBuffer.prototype.writeUInt32BE;
const cryptoCreateHash = crypto.createHash;
const cryptoCreatePrivateKey = crypto.createPrivateKey;
const cryptoCreatePublicKey = crypto.createPublicKey;
const cryptoSign = crypto.sign;
const cryptoVerify = crypto.verify;
const numberIsSafeInteger = Number.isSafeInteger;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectKeys = Object.keys;
const objectPrototype = Object.prototype;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const regexpTest = RegExp.prototype.test;
const stringIncludes = String.prototype.includes;
const utilIsProxy = utilTypes.isProxy;
const utilIsUint8Array = utilTypes.isUint8Array;

// Capture the mutable KeyObject getters and export method before any caller can
// substitute instance properties. The probe is a syntactically valid Ed25519
// public key and performs no I/O or discovery.
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

const VERSION = 1;
const CONTEXT_KIND = "darwin_native_dispatch_launcher_context";
const CONTEXT_BODY_MAGIC = reflectApply(bufferFrom, HostBuffer, ["HBPHDLB1", "ascii"]);
const CONTEXT_ENVELOPE_MAGIC = reflectApply(bufferFrom, HostBuffer, ["HBPHDLC1", "ascii"]);
const DISPATCH_INPUT_MAGIC = reflectApply(bufferFrom, HostBuffer, ["HBPHDIN1", "ascii"]);
const TERMINAL_RESULT_MAGIC = reflectApply(bufferFrom, HostBuffer, ["HBPHDRS1", "ascii"]);
const CONTEXT_SIGNATURE_DOMAIN = reflectApply(bufferFrom, HostBuffer, [
  "hacker-bob/physical-native-launcher-context-signature/v1\0",
  "utf8",
]);
const ALGORITHM_ID = 1;
const ALGORITHM = "ed25519";
const CONTEXT_MAX_BYTES = 16 * 1024;
const CONTEXT_MAX_BASE64URL_CHARS = 21850;
const INPUT_MAX_BYTES = 112 * 1024;
const MAX_COMMAND_BYTES = 64 * 1024;
const MAX_DISPATCH_ENVELOPE_BYTES = 40 * 1024;
const MAX_TERMINAL_RESPONSE_BYTES = 1024 * 1024;
const TERMINAL_RESULT_BYTES = 196;
const SPKI_PREFIX = reflectApply(bufferFrom, HostBuffer, [
  "302a300506032b6570032100",
  "hex",
]);
const SPKI_BYTES = 44;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/u;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22,86}$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/u;
const MAX_UINT64 = (1n << 64n) - 1n;
const ZERO_DIGEST = "0000000000000000000000000000000000000000000000000000000000000000";

const CONTEXT_PAYLOAD_DEFINITIONS = objectFreeze([
  [1, "version", "u32"],
  [2, "fixture_only", "true"],
  [3, "worker_uid", "u32"],
  [4, "worker_gid", "u32"],
  [5, "execution_principal_id", "token"],
  [6, "worker_process_start_digest", "digest"],
  [7, "worker_bundle_digest", "digest"],
  [8, "native_loaded_image_identity_digest", "digest"],
  [9, "provider_id", "identifier"],
  [10, "provider_descriptor_digest", "digest"],
  [11, "provider_implementation_digest", "digest"],
  [12, "semantic_manifest_digest", "digest"],
  [13, "device_identity_digest", "digest"],
  [14, "device_enrollment_digest", "digest"],
  [15, "connection_generation", "u64_positive"],
  [16, "launcher_ticket_digest", "digest"],
  [17, "device_descriptor_inventory_digest", "digest"],
  [18, "delegated_descriptor_identity_digest", "digest"],
  [19, "clock_epoch_digest", "digest"],
  [20, "dispatch_key_id", "token"],
  [21, "dispatch_public_key_digest", "digest"],
  [22, "launcher_public_key_spki_der", "spki"],
  [23, "dispatch_public_key_spki_der", "spki"],
  [24, "launch_nonce", "nonce"],
  [25, "execution_lineage_digest", "digest"],
  [26, "vault_reservation_digest", "digest"],
  [27, "vault_ingest_capability_digest", "digest"],
  [28, "vault_sink_descriptor_identity_digest", "digest"],
  [29, "vault_byte_ceiling", "u32"],
  [30, "artifact_handle_digest", "digest"],
  [31, "bootstrap_manifest_digest", "digest"],
  [32, "bootstrap_operation_registry_digest", "digest"],
  [33, "bootstrap_command_set_digest", "digest"],
  [34, "native_bootstrap_semantic_table_digest", "digest"],
  [35, "bootstrap_invariants_digest", "digest"],
].map((entry) => objectFreeze(entry)));
const CONTEXT_PAYLOAD_FIELDS = objectFreeze(
  CONTEXT_PAYLOAD_DEFINITIONS.map((entry) => entry[1]),
);
const CONTEXT_SIGN_FIELDS = objectFreeze([
  "payload",
  "launcher_key_id",
  "launcher_private_key",
]);
const CONTEXT_PROJECTION_FIELDS = objectFreeze([
  "version",
  "kind",
  "context_b64",
  "context_digest",
]);
const INPUT_FIELDS = objectFreeze(["version", "envelope_bytes", "command_bytes"]);

const STATUS_BY_ID = objectCreate(null);
objectDefineProperty(STATUS_BY_ID, "1", { value: "rejected_no_effect", enumerable: true });
objectDefineProperty(STATUS_BY_ID, "2", { value: "ambiguous_quarantined", enumerable: true });
objectDefineProperty(STATUS_BY_ID, "3", {
  value: "fixture_complete_non_authorizing",
  enumerable: true,
});
objectFreeze(STATUS_BY_ID);

const DARWIN_NATIVE_DISPATCH_CUSTODIAN_ASSURANCE = objectFreeze({
  version: VERSION,
  production_ready: false,
  hardware_access_authorized: false,
  authoritative: false,
  fixture_process_only: true,
  fixed_cli: "--fixture-native-dispatch-custodian-v1",
  fixed_descriptor_map: objectFreeze({
    launcher_context_input: 3,
    launcher_delegated_device_transport: 4,
    dispatch_input: 5,
    redacted_terminal_result_output: 6,
    pre_reserved_response_vault_sink_output: 7,
  }),
  caller_selected_fd_or_path_exposed: false,
  generic_read_or_write_surface_exposed: false,
  raw_response_bytes_projected: false,
  raw_response_native_descriptor_sink: true,
  native_sink_fsync_before_terminal_result: true,
  native_deadline_recheck_before_first_write: true,
  native_signature_verification: true,
  registry_generated_native_operation_semantic_table: true,
  native_semantic_table_digest: CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.table_digest,
  bootstrap_manifest_digest:
    CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.bootstrap_manifest_digest,
  bootstrap_operation_registry_digest:
    CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.bootstrap_operation_registry_digest,
  semantic_manifest_digest:
    CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.semantic_manifest_digest,
  fixture_source_owned_operation_allowlist: objectFreeze({
    provider_id: CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.provider_id,
    operations: objectFreeze(CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.operations.map(
      (operation) => objectFreeze({
        operation_id: operation.operation_id,
        operation_digest: operation.operation_digest,
        command_set_digest: operation.command_set_digest,
        commands: objectFreeze(operation.commands.map((command) => objectFreeze({
          command_sequence: command.command_sequence,
          command_id: command.command_id,
          request_payload_bytes: command.request_payload_byte_length,
        }))),
      }),
    )),
    grant_kind: "bootstrap",
    command_kind: "observe",
    effect_class: "none",
    rf_constraint: "rf_off",
  }),
  in_process_one_use: true,
  durable_restart_replay_authority: false,
  production_blockers: objectFreeze([
    "signed_immutable_node20_arm64_prebuild_missing",
    "qualified_production_launcher_and_external_key_enrollment_missing",
    "durable_restart_replay_and_fork_fence_missing",
    "authenticated_native_terminal_receipt_and_durable_outbox_missing",
    "independent_production_vault_sink_owner_and_signed_ingest_receipt_missing",
    "durable_native_bootstrap_multi_command_orchestration_missing",
    "native_bootstrap_source_owned_multi_response_aggregation_missing",
    "bootstrap_authority_to_native_dispatch_binding_missing",
    "real_chameleon_hil_missing",
    "continuous_external_dtr_rts_witness_missing",
  ]),
});

function custodianError() {
  const error = new SafeError("Darwin native dispatch custodian contract was rejected");
  objectDefineProperty(error, "code", {
    value: "darwin_native_dispatch_custodian_contract_rejected",
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
  const keys = reflectOwnKeys(value);
  for (let index = 0; index < keys.length; index += 1) {
    const descriptor = objectGetOwnPropertyDescriptor(value, keys[index]);
    if (typeof keys[index] !== "string" || descriptor == null
        || !objectHasOwn(descriptor, "value") || descriptor.enumerable !== true) return false;
  }
  return true;
}

function assertExactObject(value, fields) {
  if (!isPlainDataObject(value)) throw custodianError();
  const keys = objectKeys(value);
  if (keys.length !== fields.length) throw custodianError();
  for (let index = 0; index < fields.length; index += 1) {
    if (!objectHasOwn(value, fields[index])) throw custodianError();
  }
  return value;
}

function assertPattern(value, pattern, maximumBytes) {
  if (typeof value !== "string" || value.length === 0
      || reflectApply(bufferByteLength, HostBuffer, [value, "utf8"]) > maximumBytes
      || reflectApply(stringIncludes, value, ["\0"])
      || !reflectApply(regexpTest, pattern, [value])) throw custodianError();
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

function assertUint32(value) {
  if (!reflectApply(numberIsSafeInteger, SafeNumber, [value])
      || value < 0 || value > 0xffff_ffff) throw custodianError();
  return value;
}

function assertUint64Decimal(value, positive) {
  if (typeof value !== "string" || !reflectApply(regexpTest, DECIMAL_PATTERN, [value])) {
    throw custodianError();
  }
  const parsed = reflectApply(SafeBigInt, undefined, [value]);
  if (parsed > MAX_UINT64 || (positive && parsed === 0n)) throw custodianError();
  return value;
}

function copyBytes(value, minimum, maximum) {
  if (!reflectApply(bufferIsBuffer, HostBuffer, [value])
      && (value == null || reflectApply(utilIsProxy, utilTypes, [value])
        || !reflectApply(utilIsUint8Array, utilTypes, [value]))) throw custodianError();
  const bytes = reflectApply(bufferFrom, HostBuffer, [value]);
  if (bytes.length < minimum || bytes.length > maximum) {
    reflectApply(bufferFill, bytes, [0]);
    throw custodianError();
  }
  return bytes;
}

function sha256Bytes(bytes) {
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(hashUpdate, hash, [bytes]);
  return reflectApply(hashDigest, hash, ["hex"]);
}

function normalizePublicKey(input) {
  let key;
  try {
    if (reflectApply(keyTypeGetter, input, []) === "public"
        && reflectApply(keyAsymmetricTypeGetter, input, []) === "ed25519") return input;
  } catch {
    // Continue through the captured parser for encoded/private key material.
  }
  try {
    key = reflectApply(cryptoCreatePublicKey, crypto, [input]);
  } catch {
    throw custodianError();
  }
  if (reflectApply(keyTypeGetter, key, []) !== "public"
      || reflectApply(keyAsymmetricTypeGetter, key, []) !== "ed25519") throw custodianError();
  return key;
}

function normalizePrivateKey(input) {
  let key;
  try {
    if (reflectApply(keyTypeGetter, input, []) === "private"
        && reflectApply(keyAsymmetricTypeGetter, input, []) === "ed25519") return input;
  } catch {
    // Continue through the captured parser for encoded key material.
  }
  try {
    key = reflectApply(cryptoCreatePrivateKey, crypto, [input]);
  } catch {
    throw custodianError();
  }
  if (reflectApply(keyTypeGetter, key, []) !== "private"
      || reflectApply(keyAsymmetricTypeGetter, key, []) !== "ed25519") throw custodianError();
  return key;
}

function publicSpki(input) {
  const key = normalizePublicKey(input);
  const der = reflectApply(keyExport, key, [{ type: "spki", format: "der" }]);
  if (der.length !== SPKI_BYTES
      || !reflectApply(bufferEquals, reflectApply(bufferSubarray, der, [0, 12]), [SPKI_PREFIX])) {
    reflectApply(bufferFill, der, [0]);
    throw custodianError();
  }
  return der;
}

function normalizeContextPayload(input) {
  assertExactObject(input, CONTEXT_PAYLOAD_FIELDS);
  const output = objectCreate(null);
  try {
    for (let index = 0; index < CONTEXT_PAYLOAD_DEFINITIONS.length; index += 1) {
      const definition = CONTEXT_PAYLOAD_DEFINITIONS[index];
      const name = definition[1];
      const type = definition[2];
      const value = input[name];
      if (type === "u32") output[name] = assertUint32(value);
      else if (type === "u64_positive") output[name] = assertUint64Decimal(value, true);
      else if (type === "digest") output[name] = assertDigest(value);
      else if (type === "token") output[name] = assertToken(value);
      else if (type === "identifier") output[name] = assertIdentifier(value);
      else if (type === "true") {
        if (value !== true) throw custodianError();
        output[name] = true;
      } else if (type === "nonce") {
        assertPattern(value, NONCE_PATTERN, 86);
        const nonce = reflectApply(bufferFrom, HostBuffer, [value, "base64url"]);
        if (nonce.length < 16 || nonce.length > 64
            || reflectApply(bufferToString, nonce, ["base64url"]) !== value) {
          reflectApply(bufferFill, nonce, [0]);
          throw custodianError();
        }
        reflectApply(bufferFill, nonce, [0]);
        output[name] = value;
      } else if (type === "spki") {
        const bytes = copyBytes(value, SPKI_BYTES, SPKI_BYTES);
        if (!reflectApply(bufferEquals,
          reflectApply(bufferSubarray, bytes, [0, 12]),
          [SPKI_PREFIX])) {
          reflectApply(bufferFill, bytes, [0]);
          throw custodianError();
        }
        output[name] = bytes;
      } else throw custodianError();
    }
    const commandSetKnown = CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.operations.some(
      (operation) => operation.command_set_digest === output.bootstrap_command_set_digest,
    );
    if (output.version !== VERSION || output.fixture_only !== true
        || sha256Bytes(output.dispatch_public_key_spki_der)
          !== output.dispatch_public_key_digest
        || output.bootstrap_manifest_digest
          !== CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.bootstrap_manifest_digest
        || output.bootstrap_operation_registry_digest
          !== CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.bootstrap_operation_registry_digest
        || output.native_bootstrap_semantic_table_digest
          !== CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.table_digest
        || output.bootstrap_invariants_digest
          !== CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.bootstrap_invariants_digest
        || !commandSetKnown) throw custodianError();
    return output;
  } catch {
    for (let index = 0; index < CONTEXT_PAYLOAD_DEFINITIONS.length; index += 1) {
      const definition = CONTEXT_PAYLOAD_DEFINITIONS[index];
      if (definition[2] === "spki" && reflectApply(bufferIsBuffer, HostBuffer,
        [output[definition[1]]])) reflectApply(bufferFill, output[definition[1]], [0]);
    }
    throw custodianError();
  }
}

function encodeContextField(type, value) {
  if (type === "digest") return reflectApply(bufferFrom, HostBuffer, [value, "hex"]);
  if (type === "spki") return reflectApply(bufferFrom, HostBuffer, [value]);
  if (type === "nonce") return reflectApply(bufferFrom, HostBuffer, [value, "base64url"]);
  if (type === "u32") {
    const bytes = reflectApply(bufferAlloc, HostBuffer, [4]);
    reflectApply(bufferWriteUInt32BE, bytes, [value, 0]);
    return bytes;
  }
  if (type === "u64_positive") {
    const bytes = reflectApply(bufferAlloc, HostBuffer, [8]);
    reflectApply(bufferWriteBigUInt64BE, bytes, [
      reflectApply(SafeBigInt, undefined, [value]),
      0,
    ]);
    return bytes;
  }
  if (type === "true") return reflectApply(bufferFrom, HostBuffer, [[1]]);
  return reflectApply(bufferFrom, HostBuffer, [value, "utf8"]);
}

function encodeContextPayload(input) {
  const payload = normalizeContextPayload(input);
  const header = reflectApply(bufferAlloc, HostBuffer, [12]);
  reflectApply(bufferCopy, CONTEXT_BODY_MAGIC, [header, 0]);
  reflectApply(bufferWriteUInt16BE, header, [VERSION, 8]);
  reflectApply(bufferWriteUInt16BE, header, [CONTEXT_PAYLOAD_DEFINITIONS.length, 10]);
  const chunks = [header];
  let total = header.length;
  try {
    for (let index = 0; index < CONTEXT_PAYLOAD_DEFINITIONS.length; index += 1) {
      const definition = CONTEXT_PAYLOAD_DEFINITIONS[index];
      const value = encodeContextField(definition[2], payload[definition[1]]);
      const framing = reflectApply(bufferAlloc, HostBuffer, [6]);
      reflectApply(bufferWriteUInt16BE, framing, [definition[0], 0]);
      reflectApply(bufferWriteUInt32BE, framing, [value.length, 2]);
      chunks.push(framing, value);
      total += framing.length + value.length;
      if (total + 512 > CONTEXT_MAX_BYTES) throw custodianError();
    }
    return reflectApply(bufferConcat, HostBuffer, [chunks, total]);
  } finally {
    for (let index = 0; index < CONTEXT_PAYLOAD_DEFINITIONS.length; index += 1) {
      const definition = CONTEXT_PAYLOAD_DEFINITIONS[index];
      if (definition[2] === "spki") reflectApply(bufferFill, payload[definition[1]], [0]);
    }
  }
}

function signatureMessage(prefix) {
  const length = reflectApply(bufferAlloc, HostBuffer, [8]);
  reflectApply(bufferWriteBigUInt64BE, length, [
    reflectApply(SafeBigInt, undefined, [prefix.length]),
    0,
  ]);
  const message = reflectApply(bufferConcat, HostBuffer, [[
    CONTEXT_SIGNATURE_DOMAIN,
    length,
    prefix,
  ]]);
  reflectApply(bufferFill, length, [0]);
  return message;
}

function signNativeDispatchLauncherContext(input) {
  assertExactObject(input, CONTEXT_SIGN_FIELDS);
  const launcherKeyId = assertToken(input.launcher_key_id);
  const privateKey = normalizePrivateKey(input.launcher_private_key);
  const launcherPublicKey = reflectApply(cryptoCreatePublicKey, crypto, [privateKey]);
  const launcherSpki = publicSpki(launcherPublicKey);
  assertExactObject(input.payload, CONTEXT_PAYLOAD_FIELDS);
  const payloadInput = objectCreate(null);
  for (let index = 0; index < CONTEXT_PAYLOAD_FIELDS.length; index += 1) {
    const field = CONTEXT_PAYLOAD_FIELDS[index];
    payloadInput[field] = input.payload[field];
  }
  const suppliedSpki = copyBytes(payloadInput.launcher_public_key_spki_der,
    SPKI_BYTES, SPKI_BYTES);
  try {
    if (!reflectApply(bufferEquals, suppliedSpki, [launcherSpki])) throw custodianError();
  } finally {
    reflectApply(bufferFill, suppliedSpki, [0]);
  }
  const payload = encodeContextPayload(payloadInput);
  const keyIdBytes = reflectApply(bufferFrom, HostBuffer, [launcherKeyId, "utf8"]);
  const publicDigestBytes = reflectApply(bufferFrom, HostBuffer, [sha256Bytes(launcherSpki), "hex"]);
  const header = reflectApply(bufferAlloc, HostBuffer, [50]);
  let prefix;
  let message;
  let signature;
  let context;
  try {
    reflectApply(bufferCopy, CONTEXT_ENVELOPE_MAGIC, [header, 0]);
    reflectApply(bufferWriteUInt16BE, header, [VERSION, 8]);
    reflectApply(bufferWriteUInt16BE, header, [ALGORITHM_ID, 10]);
    reflectApply(bufferWriteUInt16BE, header, [keyIdBytes.length, 12]);
    reflectApply(bufferWriteUInt32BE, header, [payload.length, 14]);
    reflectApply(bufferCopy, publicDigestBytes, [header, 18]);
    prefix = reflectApply(bufferConcat, HostBuffer, [[header, keyIdBytes, payload]]);
    message = signatureMessage(prefix);
    signature = reflectApply(cryptoSign, crypto, [null, message, privateKey]);
    if (signature.length !== 64 || prefix.length + signature.length > CONTEXT_MAX_BYTES) {
      throw custodianError();
    }
    context = reflectApply(bufferConcat, HostBuffer, [[prefix, signature]]);
    return objectFreeze({
      version: VERSION,
      kind: CONTEXT_KIND,
      context_b64: reflectApply(bufferToString, context, ["base64url"]),
      context_digest: sha256Bytes(context),
    });
  } finally {
    reflectApply(bufferFill, launcherSpki, [0]);
    reflectApply(bufferFill, payload, [0]);
    reflectApply(bufferFill, keyIdBytes, [0]);
    reflectApply(bufferFill, publicDigestBytes, [0]);
    reflectApply(bufferFill, header, [0]);
    if (prefix) reflectApply(bufferFill, prefix, [0]);
    if (message) reflectApply(bufferFill, message, [0]);
    if (signature) reflectApply(bufferFill, signature, [0]);
    if (context) reflectApply(bufferFill, context, [0]);
  }
}

function nativeDispatchLauncherContextBytes(input) {
  assertExactObject(input, CONTEXT_PROJECTION_FIELDS);
  if (input.version !== VERSION || input.kind !== CONTEXT_KIND) throw custodianError();
  assertPattern(input.context_b64, BASE64URL_PATTERN, CONTEXT_MAX_BASE64URL_CHARS);
  const bytes = reflectApply(bufferFrom, HostBuffer, [input.context_b64, "base64url"]);
  if (bytes.length < 50 + 1 + 12 + 64 || bytes.length > CONTEXT_MAX_BYTES
      || reflectApply(bufferToString, bytes, ["base64url"]) !== input.context_b64
      || sha256Bytes(bytes) !== assertDigest(input.context_digest)) {
    reflectApply(bufferFill, bytes, [0]);
    throw custodianError();
  }
  return bytes;
}

function verifyNativeDispatchLauncherContext(input) {
  const bytes = nativeDispatchLauncherContextBytes(input);
  let message;
  let key;
  let launcherSpki;
  try {
    if (!reflectApply(bufferEquals,
      reflectApply(bufferSubarray, bytes, [0, 8]),
      [CONTEXT_ENVELOPE_MAGIC])
        || reflectApply(bufferReadUInt16BE, bytes, [8]) !== VERSION
        || reflectApply(bufferReadUInt16BE, bytes, [10]) !== ALGORITHM_ID) {
      throw custodianError();
    }
    const keyIdLength = reflectApply(bufferReadUInt16BE, bytes, [12]);
    const payloadLength = reflectApply(bufferReadUInt32BE, bytes, [14]);
    const payloadOffset = 50 + keyIdLength;
    const signatureOffset = payloadOffset + payloadLength;
    if (keyIdLength < 1 || keyIdLength > 191 || payloadLength < 12
        || signatureOffset + 64 !== bytes.length) throw custodianError();
    const payloadBytes = reflectApply(bufferSubarray, bytes, [payloadOffset, signatureOffset]);
    // The native implementation performs the authoritative field-by-field
    // payload parse. JS verifies only enough to locate the signed embedded SPKI.
    if (!reflectApply(bufferEquals,
      reflectApply(bufferSubarray, payloadBytes, [0, 8]),
      [CONTEXT_BODY_MAGIC])
        || reflectApply(bufferReadUInt16BE, payloadBytes, [8]) !== VERSION
        || reflectApply(bufferReadUInt16BE, payloadBytes, [10])
          !== CONTEXT_PAYLOAD_DEFINITIONS.length) throw custodianError();
    let offset = 12;
    launcherSpki = null;
    for (let index = 0; index < CONTEXT_PAYLOAD_DEFINITIONS.length; index += 1) {
      const tag = reflectApply(bufferReadUInt16BE, payloadBytes, [offset]);
      const length = reflectApply(bufferReadUInt32BE, payloadBytes, [offset + 2]);
      offset += 6;
      if (tag !== CONTEXT_PAYLOAD_DEFINITIONS[index][0]
          || offset + length > payloadBytes.length) throw custodianError();
      if (tag === 22) launcherSpki = reflectApply(bufferFrom, HostBuffer, [
        reflectApply(bufferSubarray, payloadBytes, [offset, offset + length]),
      ]);
      offset += length;
    }
    if (offset !== payloadBytes.length || launcherSpki == null
        || launcherSpki.length !== SPKI_BYTES
        || !reflectApply(bufferEquals,
          reflectApply(bufferSubarray, launcherSpki, [0, 12]), [SPKI_PREFIX])
        || sha256Bytes(launcherSpki)
          !== reflectApply(bufferToString,
            reflectApply(bufferSubarray, bytes, [18, 50]), ["hex"])) {
      if (launcherSpki) reflectApply(bufferFill, launcherSpki, [0]);
      throw custodianError();
    }
    key = reflectApply(cryptoCreatePublicKey, crypto, [{
      key: launcherSpki,
      format: "der",
      type: "spki",
    }]);
    reflectApply(bufferFill, launcherSpki, [0]);
    message = signatureMessage(reflectApply(bufferSubarray, bytes, [0, signatureOffset]));
    if (!reflectApply(cryptoVerify, crypto, [
      null,
      message,
      key,
      reflectApply(bufferSubarray, bytes, [signatureOffset]),
    ])) throw custodianError();
    const keyIdBytes = reflectApply(bufferSubarray, bytes, [50, payloadOffset]);
    const keyId = reflectApply(bufferToString, keyIdBytes, ["utf8"]);
    if (reflectApply(bufferByteLength, HostBuffer, [keyId, "utf8"]) !== keyIdBytes.length
        || !reflectApply(bufferEquals,
          reflectApply(bufferFrom, HostBuffer, [keyId, "utf8"]), [keyIdBytes])) {
      throw custodianError();
    }
    assertToken(keyId);
    return objectFreeze({
      version: VERSION,
      algorithm: ALGORITHM,
      launcher_key_id: keyId,
      context_digest: input.context_digest,
    });
  } catch (error) {
    if (error != null && error.code === "darwin_native_dispatch_custodian_contract_rejected") {
      throw error;
    }
    throw custodianError();
  } finally {
    reflectApply(bufferFill, bytes, [0]);
    if (message) reflectApply(bufferFill, message, [0]);
    if (launcherSpki) reflectApply(bufferFill, launcherSpki, [0]);
  }
}

function encodeNativeDispatchCustodianInput(input) {
  assertExactObject(input, INPUT_FIELDS);
  if (input.version !== VERSION) throw custodianError();
  const envelope = copyBytes(input.envelope_bytes, 50 + 1 + 12 + 64,
    MAX_DISPATCH_ENVELOPE_BYTES);
  const command = copyBytes(input.command_bytes, 1, MAX_COMMAND_BYTES);
  const header = reflectApply(bufferAlloc, HostBuffer, [18]);
  try {
    if (!reflectApply(bufferEquals,
      reflectApply(bufferSubarray, envelope, [0, 8]),
      [reflectApply(bufferFrom, HostBuffer, ["HBPHDSE1", "ascii"])])) {
      throw custodianError();
    }
    reflectApply(bufferCopy, DISPATCH_INPUT_MAGIC, [header, 0]);
    reflectApply(bufferWriteUInt16BE, header, [VERSION, 8]);
    reflectApply(bufferWriteUInt32BE, header, [envelope.length, 10]);
    reflectApply(bufferWriteUInt32BE, header, [command.length, 14]);
    const total = header.length + envelope.length + command.length;
    if (total > INPUT_MAX_BYTES) throw custodianError();
    return reflectApply(bufferConcat, HostBuffer, [[header, envelope, command], total]);
  } finally {
    reflectApply(bufferFill, envelope, [0]);
    reflectApply(bufferFill, command, [0]);
    reflectApply(bufferFill, header, [0]);
  }
}

function decodeNativeDispatchTerminalResult(input) {
  const bytes = copyBytes(input, TERMINAL_RESULT_BYTES, TERMINAL_RESULT_BYTES);
  try {
    if (!reflectApply(bufferEquals,
      reflectApply(bufferSubarray, bytes, [0, 8]),
      [TERMINAL_RESULT_MAGIC])
        || reflectApply(bufferReadUInt16BE, bytes, [8]) !== VERSION) throw custodianError();
    const statusId = reflectApply(bufferReadUInt16BE, bytes, [10]);
    if (!objectHasOwn(STATUS_BY_ID, statusId)) throw custodianError();
    const status = STATUS_BY_ID[statusId];
    const flags = reflectApply(bufferReadUInt32BE, bytes, [12]);
    if (status == null || (flags & ~31) !== 0) throw custodianError();
    const responseLength = reflectApply(bufferReadUInt32BE, bytes, [16]);
    const sequenceValue = reflectApply(bufferReadBigUInt64BE, bytes, [20]);
    const settledValue = reflectApply(bufferReadBigUInt64BE, bytes, [28]);
    const envelopeDigest = reflectApply(bufferToString,
      reflectApply(bufferSubarray, bytes, [36, 68]), ["hex"]);
    const descriptorDigest = reflectApply(bufferToString,
      reflectApply(bufferSubarray, bytes, [68, 100]), ["hex"]);
    const responseDigest = reflectApply(bufferToString,
      reflectApply(bufferSubarray, bytes, [100, 132]), ["hex"]);
    const sinkDescriptorDigest = reflectApply(bufferToString,
      reflectApply(bufferSubarray, bytes, [132, 164]), ["hex"]);
    const sinkRecordDigest = reflectApply(bufferToString,
      reflectApply(bufferSubarray, bytes, [164, 196]), ["hex"]);
    const wrote = (flags & 1) !== 0;
    const signature = (flags & 2) !== 0;
    const descriptor = (flags & 4) !== 0;
    const deadline = (flags & 8) !== 0;
    const sinkCommitted = (flags & 16) !== 0;
    const sequencePositive = sequenceValue > 0n;
    const settledPositive = settledValue > 0n;
    const complete = status === "fixture_complete_non_authorizing";
    const ambiguous = status === "ambiguous_quarantined";
    const rejected = status === "rejected_no_effect";
    const responseObservationCoherent = (responseLength === 0
      && responseDigest === ZERO_DIGEST) || (responseLength > 0
      && responseLength <= MAX_TERMINAL_RESPONSE_BYTES
      && responseDigest !== ZERO_DIGEST);
    const rejectedStateCoherent = (flags === 0 && !sequencePositive
      && envelopeDigest === ZERO_DIGEST && descriptorDigest === ZERO_DIGEST)
      || (flags === 4 && !sequencePositive && descriptorDigest !== ZERO_DIGEST)
      || (flags === 6 && envelopeDigest !== ZERO_DIGEST
        && descriptorDigest !== ZERO_DIGEST)
      || (flags === 14 && sequencePositive && envelopeDigest !== ZERO_DIGEST
        && descriptorDigest !== ZERO_DIGEST);
    const sinkStateCoherent = sinkCommitted
      ? sinkDescriptorDigest !== ZERO_DIGEST && sinkRecordDigest !== ZERO_DIGEST
      : sinkDescriptorDigest === ZERO_DIGEST && sinkRecordDigest === ZERO_DIGEST;
    if (!settledPositive || !sinkStateCoherent
        || (complete && (!wrote || !signature || !descriptor || !deadline
          || !sinkCommitted
          || !sequencePositive || responseLength < 10
          || responseLength > MAX_TERMINAL_RESPONSE_BYTES
          || envelopeDigest === ZERO_DIGEST || descriptorDigest === ZERO_DIGEST
          || responseDigest === ZERO_DIGEST))
        || (ambiguous && (!wrote || !signature || !descriptor || !deadline
          || !sequencePositive || !responseObservationCoherent
          || envelopeDigest === ZERO_DIGEST || descriptorDigest === ZERO_DIGEST))
        || (rejected && (!rejectedStateCoherent || wrote || responseLength !== 0
          || responseDigest !== ZERO_DIGEST || sinkCommitted))) throw custodianError();
    return objectFreeze({
      version: VERSION,
      status,
      wrote_any_command_bytes: wrote,
      dispatch_signature_verified: signature,
      descriptor_identity_verified: descriptor,
      deadline_rechecked_before_first_write: deadline,
      response_sink_committed: sinkCommitted,
      response_byte_length: responseLength,
      ticket_sequence: reflectApply(bigIntToString, sequenceValue, [10]),
      settled_continuous_ns: reflectApply(bigIntToString, settledValue, [10]),
      dispatch_envelope_digest: envelopeDigest,
      delegated_descriptor_identity_digest: descriptorDigest,
      response_digest: responseDigest,
      vault_sink_descriptor_identity_digest: sinkDescriptorDigest,
      vault_sink_record_digest: sinkRecordDigest,
      production_ready: false,
      hardware_access_authorized: false,
      authoritative: false,
    });
  } finally {
    reflectApply(bufferFill, bytes, [0]);
  }
}

module.exports = objectFreeze({
  CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS,
  DARWIN_NATIVE_DISPATCH_CUSTODIAN_ASSURANCE,
  NATIVE_DISPATCH_CUSTODIAN_VERSION: VERSION,
  NATIVE_DISPATCH_TERMINAL_RESULT_BYTES: TERMINAL_RESULT_BYTES,
  decodeNativeDispatchTerminalResult,
  encodeNativeDispatchCustodianInput,
  nativeDispatchLauncherContextBytes,
  signNativeDispatchLauncherContext,
  verifyNativeDispatchLauncherContext,
  _internals: objectFreeze({
    CONTEXT_PAYLOAD_DEFINITIONS,
    CONTEXT_SIGNATURE_DOMAIN,
  }),
});
