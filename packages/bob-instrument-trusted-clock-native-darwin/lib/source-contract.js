"use strict";

// This module closes the portable wire/conformance contract for the future
// Darwin native source. It deliberately has no native loader and no production
// factory. Caller-supplied enrollment values remain diagnostic fixtures.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const SafeError = Error;
const arrayIsArray = Array.isArray;
const bufferAlloc = Buffer.alloc;
const bufferFrom = Buffer.from;
const bufferIsBuffer = Buffer.isBuffer;
const cryptoCreateHash = crypto.createHash;
const cryptoRandomBytes = crypto.randomBytes;
const numberIsInteger = Number.isInteger;
const safeBigInt = BigInt;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const objectKeys = Object.keys;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const regExpTest = RegExp.prototype.test;
const utilTypesIsProxy = utilTypes.isProxy;
const utilTypesIsSharedArrayBuffer = utilTypes.isSharedArrayBuffer;
const weakMapGet = WeakMap.prototype.get;
const weakMapSet = WeakMap.prototype.set;
const weakSetAdd = WeakSet.prototype.add;
const weakSetHas = WeakSet.prototype.has;

const OBJECT_PROTOTYPE = Object.prototype;
const HASH_PROTOTYPE = objectGetPrototypeOf(cryptoCreateHash("sha256"));
const HASH_UPDATE = objectGetOwnPropertyDescriptor(HASH_PROTOTYPE, "update").value;
const HASH_DIGEST = objectGetOwnPropertyDescriptor(HASH_PROTOTYPE, "digest").value;
const BUFFER_WRITE_UINT16_BE = objectGetOwnPropertyDescriptor(
  Buffer.prototype,
  "writeUInt16BE",
).value;
const BUFFER_WRITE_UINT32_BE = objectGetOwnPropertyDescriptor(
  Buffer.prototype,
  "writeUInt32BE",
).value;
const BUFFER_WRITE_BIG_UINT64_BE = objectGetOwnPropertyDescriptor(
  Buffer.prototype,
  "writeBigUInt64BE",
).value;
const BUFFER_READ_UINT16_BE = objectGetOwnPropertyDescriptor(
  Buffer.prototype,
  "readUInt16BE",
).value;
const BUFFER_READ_UINT32_BE = objectGetOwnPropertyDescriptor(
  Buffer.prototype,
  "readUInt32BE",
).value;
const BUFFER_READ_BIG_UINT64_BE = objectGetOwnPropertyDescriptor(
  Buffer.prototype,
  "readBigUInt64BE",
).value;
const BUFFER_SUBARRAY = objectGetOwnPropertyDescriptor(Buffer.prototype, "subarray").value;
const BUFFER_EQUALS = objectGetOwnPropertyDescriptor(Buffer.prototype, "equals").value;
const BUFFER_COPY = objectGetOwnPropertyDescriptor(Buffer.prototype, "copy").value;
const BUFFER_FILL = objectGetOwnPropertyDescriptor(Buffer.prototype, "fill").value;
const BUFFER_TO_STRING = objectGetOwnPropertyDescriptor(Buffer.prototype, "toString").value;
const BIGINT_TO_STRING = objectGetOwnPropertyDescriptor(
  objectGetPrototypeOf(0n),
  "toString",
).value;
const TYPED_ARRAY_PROTOTYPE = objectGetPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_BUFFER_GET = objectGetOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  "buffer",
).get;

const DARWIN_TRUSTED_CLOCK_SOURCE_VERSION = 1;
const DARWIN_TRUSTED_CLOCK_PROFILE = "darwin_arm64_trusted_clock_source_v1";
const DARWIN_TRUSTED_CLOCK_PROTOCOL = "hacker_bob_trusted_clock_ipc_v1";
const DARWIN_TRUSTED_CLOCK_SERVICE_ID = "io.hacker-bob.physical.trusted-clockd";
const DARWIN_TRUSTED_CLOCK_CLIENT_ID = "io.hacker-bob.physical.trusted-clock-client";
const DARWIN_TRUSTED_CLOCK_SERVICE_PRINCIPAL = "_hackerbobclock";
const DARWIN_TRUSTED_CLOCK_LAUNCHD_LABEL =
  "io.hacker-bob.physical.trusted-clockd";
const DARWIN_TRUSTED_CLOCK_LAUNCHD_SOCKET_NAME = "TrustedClockSocket";
const DARWIN_TRUSTED_CLOCK_SOCKET_PATH =
  "/private/var/run/hacker-bob/physical-trusted-clock-v1.sock";
const DARWIN_TRUSTED_CLOCK_MONOTONIC_PRIMITIVE = "mach_continuous_time_v1";
const DARWIN_TRUSTED_CLOCK_BOOT_EPOCH_SCHEME =
  "sha256_double_read_kern_bootsessionuuid_v1";
const DARWIN_TRUSTED_CLOCK_PEER_SCHEME =
  "local_peertoken_local_peerpid_getpeereid_v1";
const DARWIN_TRUSTED_CLOCK_CODE_IDENTITY_SCHEME =
  "seccode_audit_token_designated_requirement_v1";
const DARWIN_TRUSTED_CLOCK_SOURCE_ASSURANCE =
  "source_only_closed_conformance_non_authorizing";
const DARWIN_TRUSTED_CLOCK_BLOCKER =
  "signed_immutable_trusted_clock_native_attestation_and_provisioning_missing";
const DARWIN_TRUSTED_CLOCK_PRODUCTION_BLOCKERS = objectFreeze([
  DARWIN_TRUSTED_CLOCK_BLOCKER,
  "trusted_clock_native_release_envelope_v3_or_separate_missing",
  "trusted_clock_node_api_loaded_image_attestation_and_signed_delivery_missing",
  "trusted_clock_same_process_preimport_runtime_integrity_unproven",
  "trusted_clock_native_client_same_process_capability_custody_not_isolated",
  "trusted_clock_dedicated_principal_and_socket_acl_unproven",
  "trusted_clock_signer_custody_unproven",
  "trusted_clock_restart_sleep_reboot_hil_missing",
]);

const REQUEST_MAGIC = bufferFrom([0x48, 0x42, 0x43, 0x4c, 0x4b, 0x31, 0x00, 0x00]);
const RESPONSE_MAGIC = bufferFrom([0x48, 0x42, 0x43, 0x4c, 0x4b, 0x31, 0x52, 0x00]);
const REQUEST_FRAME_BYTES = 64;
const RESPONSE_FRAME_BYTES = 232;
const REQUEST_TYPE = 1;
const RESPONSE_TYPE = 2;
const REQUEST_ID_BYTES = 16;
const CHALLENGE_BYTES = 32;
const DIGEST_BYTES = 32;
const MAX_SAMPLES_PER_CONNECTION = 1;
const UINT64_MAX = 0xffff_ffff_ffff_ffffn;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const REQUEST_ID_PATTERN = /^[a-f0-9]{32}$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/u;
const SAMPLE_DIGEST_DOMAIN = bufferFrom(
  "hacker-bob/darwin-trusted-clock-source-sample/v1\0",
  "utf8",
);
const CHALLENGE_DIGEST_DOMAIN = bufferFrom(
  "hacker-bob/darwin-trusted-clock-challenge/v1\0",
  "utf8",
);
const ENROLLMENT_DIGEST_DOMAIN = bufferFrom(
  "hacker-bob/darwin-trusted-clock-conformance-enrollment/v1\0",
  "utf8",
);

const ENROLLMENT_INPUT_FIELDS = objectFreeze([
  "service_uid",
  "service_gid",
  "client_uid",
  "client_gid",
  "service_requirement_digest",
  "client_requirement_digest",
  "service_identity_digest",
  "client_identity_digest",
  "native_release_manifest_digest",
  "native_attestation_digest",
  "principal_policy_digest",
  "trust_root_digest",
]);
const ENROLLMENTS = new WeakSet();
const VERIFIERS = new WeakSet();
const VERIFIER_STATE = new WeakMap();
const CHALLENGES = new WeakSet();
const CHALLENGE_STATE = new WeakMap();
const SAMPLES = new WeakSet();

function trustedClockError(reasonCode = "trusted_clock_source_contract_rejected") {
  const error = new SafeError("Darwin trusted-clock source contract was rejected");
  objectDefineProperty(error, "code", {
    value: "darwin_trusted_clock_source_rejected",
    enumerable: false,
    writable: false,
    configurable: false,
  });
  objectDefineProperty(error, "reason_code", {
    value: reasonCode,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return error;
}

function reject(reasonCode) {
  throw trustedClockError(reasonCode);
}

function rejectSerialization() {
  reject("trusted_clock_capability_not_serializable");
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || arrayIsArray(value)
      || utilTypesIsProxy(value)) return false;
  const prototype = objectGetPrototypeOf(value);
  if (prototype !== OBJECT_PROTOTYPE && prototype !== null) return false;
  const keys = reflectOwnKeys(value);
  for (let index = 0; index < keys.length; index += 1) {
    if (typeof keys[index] !== "string") return false;
    const descriptor = objectGetOwnPropertyDescriptor(value, keys[index]);
    if (descriptor == null || !objectHasOwn(descriptor, "value")
        || descriptor.enumerable !== true) return false;
  }
  return true;
}

function assertExactObject(value, fields, reasonCode) {
  if (!isPlainDataObject(value)) reject(reasonCode);
  const keys = reflectOwnKeys(value);
  if (keys.length !== fields.length) reject(reasonCode);
  for (let index = 0; index < fields.length; index += 1) {
    if (!objectHasOwn(value, fields[index])) reject(reasonCode);
  }
  return value;
}

function own(value, field, reasonCode) {
  const descriptor = objectGetOwnPropertyDescriptor(value, field);
  if (descriptor == null || !objectHasOwn(descriptor, "value")
      || descriptor.enumerable !== true) reject(reasonCode);
  return descriptor.value;
}

function assertDigest(value, reasonCode) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, DIGEST_PATTERN, [value])) reject(reasonCode);
  return value;
}

function assertUint32(value, reasonCode) {
  if (!numberIsInteger(value) || value < 0 || value > 0xffff_ffff) {
    reject(reasonCode);
  }
  return value;
}

function assertCanonicalUint64(value, reasonCode) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, DECIMAL_PATTERN, [value])) reject(reasonCode);
  let parsed;
  try {
    parsed = safeBigInt(value);
  } catch {
    reject(reasonCode);
  }
  if (parsed < 0n || parsed > UINT64_MAX) reject(reasonCode);
  return parsed;
}

function hashParts(parts) {
  const hash = cryptoCreateHash("sha256");
  for (let index = 0; index < parts.length; index += 1) {
    reflectApply(HASH_UPDATE, hash, [parts[index]]);
  }
  return reflectApply(HASH_DIGEST, hash, ["hex"]);
}

function uint32Bytes(value) {
  const output = bufferAlloc(4);
  reflectApply(BUFFER_WRITE_UINT32_BE, output, [value, 0]);
  return output;
}

function uint64Bytes(value) {
  const output = bufferAlloc(8);
  reflectApply(BUFFER_WRITE_BIG_UINT64_BE, output, [value, 0]);
  return output;
}

function digestBytes(value, reasonCode) {
  return bufferFrom(assertDigest(value, reasonCode), "hex");
}

function conformanceEnrollmentDigest(fields) {
  return hashParts([
    ENROLLMENT_DIGEST_DOMAIN,
    uint32Bytes(fields.service_uid),
    uint32Bytes(fields.service_gid),
    uint32Bytes(fields.client_uid),
    uint32Bytes(fields.client_gid),
    digestBytes(fields.service_requirement_digest, "enrollment_digest_invalid"),
    digestBytes(fields.client_requirement_digest, "enrollment_digest_invalid"),
    digestBytes(fields.service_identity_digest, "enrollment_digest_invalid"),
    digestBytes(fields.client_identity_digest, "enrollment_digest_invalid"),
    digestBytes(fields.native_release_manifest_digest, "enrollment_digest_invalid"),
    digestBytes(fields.native_attestation_digest, "enrollment_digest_invalid"),
    digestBytes(fields.principal_policy_digest, "enrollment_digest_invalid"),
    digestBytes(fields.trust_root_digest, "enrollment_digest_invalid"),
  ]);
}

function createDarwinTrustedClockConformanceEnrollment(input) {
  if (arguments.length !== 1) reject("enrollment_argument_shape_invalid");
  assertExactObject(input, ENROLLMENT_INPUT_FIELDS, "enrollment_shape_invalid");
  const fields = objectCreate(null);
  fields.service_uid = assertUint32(
    own(input, "service_uid", "enrollment_shape_invalid"),
    "service_uid_invalid",
  );
  fields.service_gid = assertUint32(
    own(input, "service_gid", "enrollment_shape_invalid"),
    "service_gid_invalid",
  );
  fields.client_uid = assertUint32(
    own(input, "client_uid", "enrollment_shape_invalid"),
    "client_uid_invalid",
  );
  fields.client_gid = assertUint32(
    own(input, "client_gid", "enrollment_shape_invalid"),
    "client_gid_invalid",
  );
  for (let index = 4; index < ENROLLMENT_INPUT_FIELDS.length; index += 1) {
    const field = ENROLLMENT_INPUT_FIELDS[index];
    fields[field] = assertDigest(
      own(input, field, "enrollment_shape_invalid"),
      `${field}_invalid`,
    );
  }
  if (fields.service_uid === fields.client_uid) reject("dedicated_service_uid_required");
  if (fields.service_gid === fields.client_gid) reject("dedicated_service_gid_required");
  if (fields.service_identity_digest === fields.client_identity_digest
      || fields.service_requirement_digest === fields.client_requirement_digest) {
    reject("service_client_identity_must_be_distinct");
  }
  const enrollment = objectFreeze({
    version: DARWIN_TRUSTED_CLOCK_SOURCE_VERSION,
    profile: DARWIN_TRUSTED_CLOCK_PROFILE,
    service_id: DARWIN_TRUSTED_CLOCK_SERVICE_ID,
    client_id: DARWIN_TRUSTED_CLOCK_CLIENT_ID,
    service_principal: DARWIN_TRUSTED_CLOCK_SERVICE_PRINCIPAL,
    launchd_label: DARWIN_TRUSTED_CLOCK_LAUNCHD_LABEL,
    launchd_socket_name: DARWIN_TRUSTED_CLOCK_LAUNCHD_SOCKET_NAME,
    socket_path: DARWIN_TRUSTED_CLOCK_SOCKET_PATH,
    protocol: DARWIN_TRUSTED_CLOCK_PROTOCOL,
    monotonic_primitive: DARWIN_TRUSTED_CLOCK_MONOTONIC_PRIMITIVE,
    boot_epoch_scheme: DARWIN_TRUSTED_CLOCK_BOOT_EPOCH_SCHEME,
    peer_credential_scheme: DARWIN_TRUSTED_CLOCK_PEER_SCHEME,
    code_identity_scheme: DARWIN_TRUSTED_CLOCK_CODE_IDENTITY_SCHEME,
    request_frame_bytes: REQUEST_FRAME_BYTES,
    response_frame_bytes: RESPONSE_FRAME_BYTES,
    challenge_bytes: CHALLENGE_BYTES,
    max_samples_per_connection: MAX_SAMPLES_PER_CONNECTION,
    ...fields,
    enrollment_digest: conformanceEnrollmentDigest(fields),
    source_assurance: DARWIN_TRUSTED_CLOCK_SOURCE_ASSURANCE,
    native_attested: false,
    provisioning_verified: false,
    hil_verified: false,
    production_ready: false,
    production_blockers: DARWIN_TRUSTED_CLOCK_PRODUCTION_BLOCKERS,
  });
  reflectApply(weakSetAdd, ENROLLMENTS, [enrollment]);
  return enrollment;
}

function assertDarwinTrustedClockConformanceEnrollment(input) {
  if (arguments.length !== 1 || input == null || typeof input !== "object"
      || utilTypesIsProxy(input) || !objectIsFrozen(input)
      || !reflectApply(weakSetHas, ENROLLMENTS, [input])
      || input.production_ready !== false || input.native_attested !== false
      || input.provisioning_verified !== false || input.hil_verified !== false) {
    reject("conformance_enrollment_brand_invalid");
  }
  return input;
}

function challengeDigest(requestIdBytes, challengeBytes) {
  return hashParts([CHALLENGE_DIGEST_DOMAIN, requestIdBytes, challengeBytes]);
}

function encodeRequestFrame(requestIdBytes, challengeBytes) {
  const frame = bufferAlloc(REQUEST_FRAME_BYTES);
  reflectApply(BUFFER_COPY, REQUEST_MAGIC, [frame, 0]);
  reflectApply(BUFFER_WRITE_UINT16_BE, frame, [DARWIN_TRUSTED_CLOCK_SOURCE_VERSION, 8]);
  reflectApply(BUFFER_WRITE_UINT16_BE, frame, [REQUEST_TYPE, 10]);
  reflectApply(BUFFER_WRITE_UINT32_BE, frame, [REQUEST_FRAME_BYTES, 12]);
  reflectApply(BUFFER_COPY, requestIdBytes, [frame, 16]);
  reflectApply(BUFFER_COPY, challengeBytes, [frame, 32]);
  return frame;
}

function createChallenge(verifier) {
  const verifierState = reflectApply(weakMapGet, VERIFIER_STATE, [verifier]);
  if (verifierState == null || verifierState.outstanding !== null) {
    reject("one_outstanding_challenge_required");
  }
  const requestIdBytes = cryptoRandomBytes(REQUEST_ID_BYTES);
  const challengeBytes = cryptoRandomBytes(CHALLENGE_BYTES);
  const frame = encodeRequestFrame(requestIdBytes, challengeBytes);
  const challenge = objectFreeze({
    version: DARWIN_TRUSTED_CLOCK_SOURCE_VERSION,
    kind: "darwin_trusted_clock_source_challenge",
    request_id: reflectApply(BUFFER_TO_STRING, requestIdBytes, ["hex"]),
    challenge_digest: challengeDigest(requestIdBytes, challengeBytes),
    production_ready: false,
    requestFrame() {
      if (arguments.length !== 0) reject("request_frame_argument_injection");
      const state = reflectApply(weakMapGet, CHALLENGE_STATE, [challenge]);
      if (state == null || state.consumed || state.verifier !== verifier) {
        reject("challenge_consumed_or_crosswired");
      }
      return bufferFrom(state.frame);
    },
    toJSON: rejectSerialization,
  });
  reflectApply(weakSetAdd, CHALLENGES, [challenge]);
  reflectApply(weakMapSet, CHALLENGE_STATE, [challenge, {
    verifier,
    frame,
    consumed: false,
  }]);
  verifierState.outstanding = challenge;
  return challenge;
}

function assertChallenge(challenge, verifier) {
  const state = challenge == null
    ? null
    : reflectApply(weakMapGet, CHALLENGE_STATE, [challenge]);
  if (challenge == null || typeof challenge !== "object"
      || utilTypesIsProxy(challenge) || !objectIsFrozen(challenge)
      || !reflectApply(weakSetHas, CHALLENGES, [challenge]) || state == null
      || state.verifier !== verifier || state.consumed) {
    reject("challenge_consumed_or_crosswired");
  }
  return state;
}

function consumeChallenge(verifierState, challengeState) {
  challengeState.consumed = true;
  reflectApply(BUFFER_FILL, challengeState.frame, [0]);
  verifierState.outstanding = null;
}

function assertExactResponseFrame(frame) {
  if (!bufferIsBuffer(frame) || utilTypesIsProxy(frame)
      || objectGetPrototypeOf(frame) !== Buffer.prototype
      || frame.length !== RESPONSE_FRAME_BYTES) reject("response_frame_shape_invalid");
  let backing;
  try {
    backing = reflectApply(TYPED_ARRAY_BUFFER_GET, frame, []);
  } catch {
    reject("response_frame_backing_invalid");
  }
  if (utilTypesIsSharedArrayBuffer(backing)) {
    reject("response_frame_shared_backing_invalid");
  }
  const magic = reflectApply(BUFFER_SUBARRAY, frame, [0, 8]);
  if (!reflectApply(BUFFER_EQUALS, magic, [RESPONSE_MAGIC])
      || reflectApply(BUFFER_READ_UINT16_BE, frame, [8])
        !== DARWIN_TRUSTED_CLOCK_SOURCE_VERSION
      || reflectApply(BUFFER_READ_UINT16_BE, frame, [10]) !== RESPONSE_TYPE
      || reflectApply(BUFFER_READ_UINT32_BE, frame, [12]) !== RESPONSE_FRAME_BYTES) {
    reject("response_frame_header_invalid");
  }
  return frame;
}

function sliceHex(frame, start, length = DIGEST_BYTES) {
  const slice = reflectApply(BUFFER_SUBARRAY, frame, [start, start + length]);
  return reflectApply(BUFFER_TO_STRING, slice, ["hex"]);
}

function computeDarwinTrustedClockSourceSampleDigest(input) {
  if (arguments.length !== 1) reject("sample_digest_argument_shape_invalid");
  assertExactObject(input, [
    "request_id",
    "challenge_digest",
    "monotonic_ns",
    "boot_epoch_digest",
    "service_identity_digest",
    "client_identity_digest",
    "enrollment_digest",
  ], "sample_digest_shape_invalid");
  const requestId = own(input, "request_id", "sample_digest_shape_invalid");
  if (typeof requestId !== "string"
      || !reflectApply(regExpTest, REQUEST_ID_PATTERN, [requestId])) {
    reject("sample_request_id_invalid");
  }
  const monotonic = assertCanonicalUint64(
    own(input, "monotonic_ns", "sample_digest_shape_invalid"),
    "sample_monotonic_ns_invalid",
  );
  return hashParts([
    SAMPLE_DIGEST_DOMAIN,
    bufferFrom(requestId, "hex"),
    digestBytes(
      own(input, "challenge_digest", "sample_digest_shape_invalid"),
      "sample_challenge_digest_invalid",
    ),
    uint64Bytes(monotonic),
    digestBytes(
      own(input, "boot_epoch_digest", "sample_digest_shape_invalid"),
      "sample_boot_epoch_digest_invalid",
    ),
    digestBytes(
      own(input, "service_identity_digest", "sample_digest_shape_invalid"),
      "sample_service_identity_digest_invalid",
    ),
    digestBytes(
      own(input, "client_identity_digest", "sample_digest_shape_invalid"),
      "sample_client_identity_digest_invalid",
    ),
    digestBytes(
      own(input, "enrollment_digest", "sample_digest_shape_invalid"),
      "sample_enrollment_digest_invalid",
    ),
  ]);
}

function decodeResponse(frame) {
  const stableFrame = bufferFrom(assertExactResponseFrame(frame));
  return objectFreeze({
    request_id: sliceHex(stableFrame, 16, REQUEST_ID_BYTES),
    challenge_digest: sliceHex(stableFrame, 32),
    monotonic_ns: reflectApply(BIGINT_TO_STRING, reflectApply(
      BUFFER_READ_BIG_UINT64_BE,
      stableFrame,
      [64],
    ), [10]),
    boot_epoch_digest: sliceHex(stableFrame, 72),
    service_identity_digest: sliceHex(stableFrame, 104),
    client_identity_digest: sliceHex(stableFrame, 136),
    enrollment_digest: sliceHex(stableFrame, 168),
    source_sample_digest: sliceHex(stableFrame, 200),
  });
}

function verifyResponse(verifier, challenge, frame) {
  const verifierState = reflectApply(weakMapGet, VERIFIER_STATE, [verifier]);
  if (verifierState == null || verifierState.outstanding !== challenge) {
    reject("challenge_consumed_or_crosswired");
  }
  const challengeState = assertChallenge(challenge, verifier);
  // A challenge is one-use even when the peer response is malformed. This
  // prevents retrying attacker-controlled variants against one freshness token.
  consumeChallenge(verifierState, challengeState);
  const response = decodeResponse(frame);
  const enrollment = verifierState.enrollment;
  if (response.request_id !== challenge.request_id
      || response.challenge_digest !== challenge.challenge_digest) {
    reject("response_challenge_mismatch");
  }
  if (response.service_identity_digest !== enrollment.service_identity_digest
      || response.client_identity_digest !== enrollment.client_identity_digest) {
    reject("response_live_identity_drift");
  }
  if (response.enrollment_digest !== enrollment.enrollment_digest) {
    reject("response_enrollment_drift");
  }
  const expectedSampleDigest = computeDarwinTrustedClockSourceSampleDigest({
    request_id: response.request_id,
    challenge_digest: response.challenge_digest,
    monotonic_ns: response.monotonic_ns,
    boot_epoch_digest: response.boot_epoch_digest,
    service_identity_digest: response.service_identity_digest,
    client_identity_digest: response.client_identity_digest,
    enrollment_digest: response.enrollment_digest,
  });
  if (response.source_sample_digest !== expectedSampleDigest) {
    reject("response_sample_digest_invalid");
  }
  if (verifierState.boot_epoch_digest !== null
      && verifierState.boot_epoch_digest !== response.boot_epoch_digest) {
    reject("response_boot_epoch_drift");
  }
  const monotonic = assertCanonicalUint64(
    response.monotonic_ns,
    "sample_monotonic_ns_invalid",
  );
  if (verifierState.monotonic_ns !== null && monotonic < verifierState.monotonic_ns) {
    reject("response_monotonic_rollback");
  }
  verifierState.boot_epoch_digest = response.boot_epoch_digest;
  verifierState.monotonic_ns = monotonic;
  const sample = objectFreeze({
    version: DARWIN_TRUSTED_CLOCK_SOURCE_VERSION,
    source: DARWIN_TRUSTED_CLOCK_MONOTONIC_PRIMITIVE,
    request_id: response.request_id,
    monotonic_ns: response.monotonic_ns,
    monotonic_epoch_id: response.boot_epoch_digest,
    enrollment_digest: response.enrollment_digest,
    source_sample_digest: response.source_sample_digest,
    source_assurance: DARWIN_TRUSTED_CLOCK_SOURCE_ASSURANCE,
    native_attested: false,
    provisioning_verified: false,
    hil_verified: false,
    production_ready: false,
    blocker_code: DARWIN_TRUSTED_CLOCK_BLOCKER,
    toJSON: rejectSerialization,
  });
  reflectApply(weakSetAdd, SAMPLES, [sample]);
  return sample;
}

function createDarwinTrustedClockSourceConformanceVerifier(enrollmentInput) {
  if (arguments.length !== 1) reject("verifier_argument_shape_invalid");
  const enrollment = assertDarwinTrustedClockConformanceEnrollment(enrollmentInput);
  let verifier;
  verifier = objectFreeze({
    version: DARWIN_TRUSTED_CLOCK_SOURCE_VERSION,
    profile: DARWIN_TRUSTED_CLOCK_PROFILE,
    source_assurance: DARWIN_TRUSTED_CLOCK_SOURCE_ASSURANCE,
    native_attested: false,
    provisioning_verified: false,
    hil_verified: false,
    production_ready: false,
    production_blockers: DARWIN_TRUSTED_CLOCK_PRODUCTION_BLOCKERS,
    issueChallenge() {
      if (arguments.length !== 0) reject("challenge_argument_injection");
      return createChallenge(verifier);
    },
    verifyResponse(challenge, frame) {
      if (arguments.length !== 2) reject("response_argument_injection");
      return verifyResponse(verifier, challenge, frame);
    },
    toJSON: rejectSerialization,
  });
  reflectApply(weakSetAdd, VERIFIERS, [verifier]);
  reflectApply(weakMapSet, VERIFIER_STATE, [verifier, {
    enrollment,
    outstanding: null,
    boot_epoch_digest: null,
    monotonic_ns: null,
  }]);
  return verifier;
}

function assertDarwinTrustedClockSourceConformanceVerifier(input) {
  if (arguments.length !== 1 || input == null || typeof input !== "object"
      || utilTypesIsProxy(input) || !objectIsFrozen(input)
      || !reflectApply(weakSetHas, VERIFIERS, [input])
      || input.production_ready !== false || input.native_attested !== false
      || input.provisioning_verified !== false || input.hil_verified !== false) {
    reject("conformance_verifier_brand_invalid");
  }
  return input;
}

function assertDarwinTrustedClockSourceSample(input) {
  if (arguments.length !== 1 || input == null || typeof input !== "object"
      || utilTypesIsProxy(input) || !objectIsFrozen(input)
      || !reflectApply(weakSetHas, SAMPLES, [input])
      || input.production_ready !== false || input.native_attested !== false
      || input.provisioning_verified !== false || input.hil_verified !== false
      || input.blocker_code !== DARWIN_TRUSTED_CLOCK_BLOCKER) {
    reject("source_sample_brand_invalid");
  }
  return input;
}

module.exports = objectFreeze({
  CHALLENGE_BYTES,
  DARWIN_TRUSTED_CLOCK_BLOCKER,
  DARWIN_TRUSTED_CLOCK_BOOT_EPOCH_SCHEME,
  DARWIN_TRUSTED_CLOCK_CLIENT_ID,
  DARWIN_TRUSTED_CLOCK_CODE_IDENTITY_SCHEME,
  DARWIN_TRUSTED_CLOCK_LAUNCHD_LABEL,
  DARWIN_TRUSTED_CLOCK_LAUNCHD_SOCKET_NAME,
  DARWIN_TRUSTED_CLOCK_MONOTONIC_PRIMITIVE,
  DARWIN_TRUSTED_CLOCK_PEER_SCHEME,
  DARWIN_TRUSTED_CLOCK_PRODUCTION_BLOCKERS,
  DARWIN_TRUSTED_CLOCK_PROFILE,
  DARWIN_TRUSTED_CLOCK_PROTOCOL,
  DARWIN_TRUSTED_CLOCK_SERVICE_ID,
  DARWIN_TRUSTED_CLOCK_SERVICE_PRINCIPAL,
  DARWIN_TRUSTED_CLOCK_SOCKET_PATH,
  DARWIN_TRUSTED_CLOCK_SOURCE_ASSURANCE,
  DARWIN_TRUSTED_CLOCK_SOURCE_VERSION,
  MAX_SAMPLES_PER_CONNECTION,
  REQUEST_FRAME_BYTES,
  RESPONSE_FRAME_BYTES,
  assertDarwinTrustedClockConformanceEnrollment,
  assertDarwinTrustedClockSourceConformanceVerifier,
  assertDarwinTrustedClockSourceSample,
  computeDarwinTrustedClockSourceSampleDigest,
  createDarwinTrustedClockConformanceEnrollment,
  createDarwinTrustedClockSourceConformanceVerifier,
});
