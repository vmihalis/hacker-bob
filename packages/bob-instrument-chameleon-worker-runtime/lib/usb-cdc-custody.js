"use strict";

// Worker-private USB CDC custody for the optional provider. This module is
// transport-neutral and deliberately has no dependency on serialport (or any
// native USB package). Importing it performs no discovery and opens nothing.
// A future native adapter/HIL pass must supply an operator-enrolled driver and
// prove the same exclusive-open/serial-lock contract at the OS boundary. The
// signed worker authority below binds declarations about the exact driver,
// binary, principal, UID, provider, transport, and enrolled device; it cannot
// measure those claims or turn same-process callbacks into an OS boundary.
//
// The retained raw handle is available only to the enrolled driver callbacks.
// An optional, injected `transact_handle` callback can be reached only through
// a branded worker transaction port, an exact one-use connection-generation
// handoff, and a one-shot command capability from the closed provider compiler.
// Custody never accepts caller request bytes or caller-selected I/O bounds. It
// is a deterministic seam for the later codec-aware/native worker, not evidence
// of an OS principal, device ACL, or HIL result. Reconnect restores custody only:
// it never repeats a command. Every timeout/disconnect/error after handing bytes
// to that callback is ambiguous_write/reconcile-required, fences the generation,
// and must never auto-resend.

const crypto = require("node:crypto");
const {
  assertCompiledHf14aProviderCommand,
  claimCompiledHf14aProviderCommand,
  invalidateCompiledHf14aProviderCommand,
} = require("./hf14a-probe-compiler.js");

const USB_CDC_CUSTODY_VERSION = 1;
const USB_CDC_WORKER_AUTHORITY_DOMAIN =
  "hacker-bob/chameleon-usb-cdc-worker-authority/v1";
const USB_CDC_WORKER_AUTHORITY_SIGNING_DOMAIN =
  "hacker-bob/chameleon-usb-cdc-worker-authority-signature/v1";
const USB_CDC_HARDWARE_IDENTITY_DOMAIN =
  "hacker-bob/chameleon-usb-cdc-hardware-identity/v1";
const USB_CDC_STATE_VALUES = Object.freeze([
  "disconnected",
  "connecting",
  "connected",
  "disconnecting",
  "open_uncertain",
  "close_uncertain",
  "closed",
]);
const USB_CDC_LINE_CONFIGURATION = Object.freeze({
  baud_rate: 115200,
  data_bits: 8,
  stop_bits: 1,
  parity: "none",
  dtr_asserted: true,
  exclusive_open: true,
  serial_lock: true,
  rts_cts: false,
  xon_xoff: false,
  generic_write_surface_exposed: false,
  brokered_exact_transaction_write_enabled: true,
});
const USB_CDC_CUSTODY_LIMITS = Object.freeze({
  max_candidates: 64,
  min_hardware_identity_bytes: 32,
  max_hardware_identity_bytes: 256,
  max_model_bytes: 128,
  max_path_bytes: 4096,
  max_serial_bytes: 1024,
  discovery_timeout_ms: 250,
  open_timeout_ms: 500,
  close_timeout_ms: 500,
  io_timeout_ms: 1000,
  read_buffer_bytes: 16 * 1024,
  write_buffer_bytes: 16 * 1024,
});

const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/u;
const ALIAS_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/u;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/u;
const DRIVER_PORTS = new WeakSet();
const DRIVER_STATE = new WeakMap();
const OPEN_AUTHORITIES = new WeakSet();
const OPEN_AUTHORITY_STATE = new WeakMap();
const WORKER_AUTHORITIES = new WeakSet();
const WORKER_AUTHORITY_STATE = new WeakMap();
const ENROLLMENTS = new WeakSet();
const ENROLLMENT_STATE = new WeakMap();
const CUSTODIES = new WeakSet();
const CUSTODY_STATE = new WeakMap();
const CONNECTION_GENERATION_HANDOFFS = new WeakSet();
const CONNECTION_GENERATION_HANDOFF_STATE = new WeakMap();
const TRANSACTION_PORTS = new WeakSet();
const TRANSACTION_PORT_STATE = new WeakMap();
const TRANSACTION_RESULTS = new WeakSet();
const TRANSACTION_RESULT_STATE = new WeakMap();
const COMPILED_COMMAND_RESULT_BINDING_FIELDS = Object.freeze([
  "compiled_command_id",
  "provider_id",
  "compiler_id",
  "compiler_manifest_digest",
  "compiler_registry_digest",
  "source_profile_digest",
  "operation_id",
  "capability_id",
  "variant_id",
  "parameter_selector_id",
  "canonical_command_digest",
  "compiled_operation_digest",
  "compiled_command_capability_digest",
]);

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((field) => typeof field !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...required, ...optional]);
  const unknown = ownKeys.filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  for (const field of ownKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${label}.${field} must be an enumerable data field`);
    }
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertAlias(value, label) {
  if (typeof value !== "string" || !ALIAS_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase operator alias`);
  }
  return value;
}

function assertBoundedString(value, label, maximumBytes, { nullable = false } = {}) {
  if (nullable && value == null) return null;
  if (typeof value !== "string" || value.length < 1
      || Buffer.byteLength(value, "utf8") > maximumBytes) {
    throw new Error(`${label} must be a non-empty bounded string`);
  }
  return value;
}

function assertInteger(value, label, minimum, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function assertToken(value, label, prefix = null) {
  if (typeof value !== "string" || !TOKEN_PATTERN.test(value)
      || (prefix != null
        && (!value.startsWith(`${prefix}:`) || value.length === prefix.length + 1))) {
    throw new Error(`${label} must be a bounded ${prefix || "opaque"} token`);
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.keys(value).sort().map((key) => (
    `${JSON.stringify(key)}:${canonicalJson(value[key])}`
  ));
  return `{${entries.join(",")}}`;
}

function digestCanonical(value) {
  return crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function assertEd25519PublicKey(value, label) {
  if (!(value instanceof crypto.KeyObject) || value.type !== "public"
      || value.asymmetricKeyType !== "ed25519") {
    throw new Error(`${label} must be an Ed25519 public KeyObject`);
  }
  return value;
}

function publicKeyDigest(value) {
  const key = assertEd25519PublicKey(value, "usb_cdc_worker_authority public key");
  return crypto.createHash("sha256")
    .update(key.export({ type: "spki", format: "der" }))
    .digest("hex");
}

function hardwareIdentityDigest(value) {
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(value.length, 0);
  return crypto.createHash("sha256")
    .update(USB_CDC_HARDWARE_IDENTITY_DOMAIN, "utf8")
    .update(Buffer.from([0]))
    .update(length)
    .update(value)
    .digest("hex");
}

function workerAuthoritySigningMessage(payloadDigest) {
  return Buffer.from(
    `${USB_CDC_WORKER_AUTHORITY_SIGNING_DOMAIN}\0${assertDigest(
      payloadDigest,
      "usb_cdc_worker_authority payload digest",
    )}`,
    "utf8",
  );
}

function normalizeIdentity(value, label) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    throw new Error(`${label} must be private byte material`);
  }
  const identity = Buffer.from(value);
  if (identity.length < USB_CDC_CUSTODY_LIMITS.min_hardware_identity_bytes
      || identity.length > USB_CDC_CUSTODY_LIMITS.max_hardware_identity_bytes) {
    identity.fill(0);
    throw new Error(`${label} must contain 32 through 256 bytes`);
  }
  return identity;
}

function sameIdentity(left, right) {
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function randomCapabilityId(prefix) {
  return `${prefix}:${crypto.randomBytes(18).toString("base64url")}`;
}

function custodyError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function normalizeCandidateFilters(input, label) {
  assertClosedObject(input, label, ["vendor_id", "product_id", "model"]);
  return Object.freeze({
    vendor_id: assertInteger(input.vendor_id, `${label}.vendor_id`, 0, 0xffff),
    product_id: assertInteger(input.product_id, `${label}.product_id`, 0, 0xffff),
    model: assertBoundedString(
      input.model,
      `${label}.model`,
      USB_CDC_CUSTODY_LIMITS.max_model_bytes,
    ),
  });
}

function sameFilters(left, right) {
  return left.vendor_id === right.vendor_id
    && left.product_id === right.product_id
    && left.model === right.model;
}

function normalizeWorkerAuthorityPayload(input, label) {
  assertClosedObject(input, label, [
    "version",
    "authority_id",
    "trust_root_id",
    "trust_root_epoch",
    "authority_epoch",
    "revocation_generation",
    "signer_key_id",
    "signer_public_key_digest",
    "trusted",
    "revoked",
    "custody_allowed",
    "enrollment_id",
    "hardware_identity_digest",
    "custody_id",
    "driver_id",
    "driver_implementation_digest",
    "driver_binary_digest",
    "execution_principal_id",
    "worker_uid",
    "provider_descriptor_digest",
    "transport_digest",
  ]);
  if (input.version !== USB_CDC_CUSTODY_VERSION) {
    throw new Error(`${label}.version must be ${USB_CDC_CUSTODY_VERSION}`);
  }
  if (typeof input.trusted !== "boolean" || typeof input.revoked !== "boolean"
      || typeof input.custody_allowed !== "boolean") {
    throw new Error(`${label} trust fields must be booleans`);
  }
  return Object.freeze({
    version: USB_CDC_CUSTODY_VERSION,
    authority_id: assertIdentifier(input.authority_id, `${label}.authority_id`),
    trust_root_id: assertIdentifier(input.trust_root_id, `${label}.trust_root_id`),
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, 1),
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, 1),
    revocation_generation: assertInteger(
      input.revocation_generation,
      `${label}.revocation_generation`,
      0,
    ),
    signer_key_id: assertIdentifier(input.signer_key_id, `${label}.signer_key_id`),
    signer_public_key_digest: assertDigest(
      input.signer_public_key_digest,
      `${label}.signer_public_key_digest`,
    ),
    trusted: input.trusted,
    revoked: input.revoked,
    custody_allowed: input.custody_allowed,
    enrollment_id: assertIdentifier(input.enrollment_id, `${label}.enrollment_id`),
    hardware_identity_digest: assertDigest(
      input.hardware_identity_digest,
      `${label}.hardware_identity_digest`,
    ),
    custody_id: assertIdentifier(input.custody_id, `${label}.custody_id`),
    driver_id: assertIdentifier(input.driver_id, `${label}.driver_id`),
    driver_implementation_digest: assertDigest(
      input.driver_implementation_digest,
      `${label}.driver_implementation_digest`,
    ),
    driver_binary_digest: assertDigest(
      input.driver_binary_digest,
      `${label}.driver_binary_digest`,
    ),
    execution_principal_id: assertToken(
      input.execution_principal_id,
      `${label}.execution_principal_id`,
      "principal",
    ),
    worker_uid: assertInteger(input.worker_uid, `${label}.worker_uid`, 0, 2 ** 32 - 2),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    transport_digest: assertDigest(input.transport_digest, `${label}.transport_digest`),
  });
}

function normalizeSignedWorkerAuthority(input, label = "signed_usb_cdc_worker_authority") {
  assertClosedObject(input, label, [
    "version",
    "domain",
    "payload",
    "payload_digest",
    "scheme",
    "signature",
    "signed_authority_digest",
  ]);
  if (input.version !== USB_CDC_CUSTODY_VERSION
      || input.domain !== USB_CDC_WORKER_AUTHORITY_DOMAIN
      || input.scheme !== "ed25519") {
    throw new Error(`${label} version, domain, or signature scheme is invalid`);
  }
  const payload = normalizeWorkerAuthorityPayload(input.payload, `${label}.payload`);
  const payloadDigest = assertDigest(input.payload_digest, `${label}.payload_digest`);
  if (payloadDigest !== digestCanonical(payload)) {
    throw new Error(`${label}.payload_digest does not bind its canonical payload`);
  }
  if (typeof input.signature !== "string" || !SIGNATURE_PATTERN.test(input.signature)) {
    throw new Error(`${label}.signature must be canonical Ed25519 base64url`);
  }
  const signature = Buffer.from(input.signature, "base64url");
  if (signature.length !== 64 || signature.toString("base64url") !== input.signature) {
    throw new Error(`${label}.signature must be canonical Ed25519 base64url`);
  }
  const basis = Object.freeze({
    version: USB_CDC_CUSTODY_VERSION,
    domain: USB_CDC_WORKER_AUTHORITY_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature: input.signature,
  });
  const signedAuthorityDigest = assertDigest(
    input.signed_authority_digest,
    `${label}.signed_authority_digest`,
  );
  if (signedAuthorityDigest !== digestCanonical(basis)) {
    throw new Error(`${label}.signed_authority_digest is invalid`);
  }
  return Object.freeze({
    ...basis,
    signed_authority_digest: signedAuthorityDigest,
    signature_bytes: signature,
  });
}

function createUsbCdcWorkerAuthorityPort(input) {
  assertClosedObject(input, "usb_cdc_worker_authority_port", [
    "version",
    "authority_id",
    "trust_root_id",
    "signer_key_id",
    "signer_public_key",
    "minimum_trust_root_epoch",
    "minimum_authority_epoch",
    "minimum_revocation_generation",
    "resolve_current_worker_authority",
  ]);
  if (input.version !== USB_CDC_CUSTODY_VERSION) {
    throw new Error(`usb_cdc_worker_authority_port.version must be ${USB_CDC_CUSTODY_VERSION}`);
  }
  if (typeof input.resolve_current_worker_authority !== "function") {
    throw new Error(
      "usb_cdc_worker_authority_port.resolve_current_worker_authority must be a function",
    );
  }
  const authorityId = assertIdentifier(
    input.authority_id,
    "usb_cdc_worker_authority_port.authority_id",
  );
  const trustRootId = assertIdentifier(
    input.trust_root_id,
    "usb_cdc_worker_authority_port.trust_root_id",
  );
  const signerKeyId = assertIdentifier(
    input.signer_key_id,
    "usb_cdc_worker_authority_port.signer_key_id",
  );
  const signerPublicKey = assertEd25519PublicKey(
    input.signer_public_key,
    "usb_cdc_worker_authority_port.signer_public_key",
  );
  const port = Object.freeze({
    version: USB_CDC_CUSTODY_VERSION,
    authority_id: authorityId,
    capability_id: randomCapabilityId("usb-cdc-worker-authority"),
  });
  WORKER_AUTHORITIES.add(port);
  WORKER_AUTHORITY_STATE.set(port, {
    authority_id: authorityId,
    trust_root_id: trustRootId,
    signer_key_id: signerKeyId,
    signer_public_key: signerPublicKey,
    signer_public_key_digest: publicKeyDigest(signerPublicKey),
    minimum_trust_root_epoch: assertInteger(
      input.minimum_trust_root_epoch,
      "usb_cdc_worker_authority_port.minimum_trust_root_epoch",
      1,
    ),
    minimum_authority_epoch: assertInteger(
      input.minimum_authority_epoch,
      "usb_cdc_worker_authority_port.minimum_authority_epoch",
      1,
    ),
    minimum_revocation_generation: assertInteger(
      input.minimum_revocation_generation,
      "usb_cdc_worker_authority_port.minimum_revocation_generation",
      0,
    ),
    current_trust_root_epoch: null,
    current_authority_epoch: null,
    current_revocation_generation: null,
    resolve: input.resolve_current_worker_authority,
    driver_claimed: false,
    invalidated: false,
  });
  return port;
}

function assertUsbCdcWorkerAuthorityPort(input) {
  const state = input == null ? null : WORKER_AUTHORITY_STATE.get(input);
  if (!input || !WORKER_AUTHORITIES.has(input) || !state || !Object.isFrozen(input)
      || input.version !== USB_CDC_CUSTODY_VERSION
      || input.authority_id !== state.authority_id
      || typeof input.capability_id !== "string"
      || Reflect.ownKeys(input).length !== 3) {
    throw new Error(
      "usb_cdc_worker_authority_port must be a private branded authority capability",
    );
  }
  return input;
}

function resolveWorkerAuthority(port, purpose) {
  const authority = assertUsbCdcWorkerAuthorityPort(port);
  const state = WORKER_AUTHORITY_STATE.get(authority);
  let signed;
  try {
    if (state.invalidated) throw new Error("worker authority capability was invalidated");
    const raw = state.resolve(Object.freeze({
      version: USB_CDC_CUSTODY_VERSION,
      purpose,
    }));
    if (raw && typeof raw.then === "function") {
      throw new Error("worker authority must resolve synchronously");
    }
    signed = normalizeSignedWorkerAuthority(raw);
    const payload = signed.payload;
    if (!crypto.verify(
      null,
      workerAuthoritySigningMessage(signed.payload_digest),
      state.signer_public_key,
      signed.signature_bytes,
    )) {
      throw new Error("worker authority signature is invalid");
    }
    if (payload.authority_id !== state.authority_id
        || payload.trust_root_id !== state.trust_root_id
        || payload.signer_key_id !== state.signer_key_id
        || payload.signer_public_key_digest !== state.signer_public_key_digest) {
      state.invalidated = true;
      throw new Error("worker authority identity drift");
    }
    if (payload.trust_root_epoch < state.minimum_trust_root_epoch
        || payload.authority_epoch < state.minimum_authority_epoch
        || payload.revocation_generation < state.minimum_revocation_generation
        || (state.current_trust_root_epoch != null
          && payload.trust_root_epoch < state.current_trust_root_epoch)
        || (state.current_authority_epoch != null
          && payload.authority_epoch < state.current_authority_epoch)
        || (state.current_revocation_generation != null
          && payload.revocation_generation < state.current_revocation_generation)) {
      state.invalidated = true;
      throw new Error("worker authority epoch rollback");
    }
    // A signed newer epoch that changes the enrolled binding permanently raises
    // the in-process rollback floor before the mismatch is reported.
    state.current_trust_root_epoch = payload.trust_root_epoch;
    state.current_authority_epoch = payload.authority_epoch;
    state.current_revocation_generation = payload.revocation_generation;
    if (payload.revoked) state.invalidated = true;
    return payload;
  } catch {
    throw custodyError("usb_cdc_worker_authority_rejected");
  } finally {
    signed?.signature_bytes.fill(0);
  }
}

function normalizeDriverBinding(input, label) {
  return Object.freeze({
    custody_id: assertIdentifier(input.custody_id, `${label}.custody_id`),
    driver_id: assertIdentifier(input.driver_id, `${label}.driver_id`),
    driver_implementation_digest: assertDigest(
      input.driver_implementation_digest,
      `${label}.driver_implementation_digest`,
    ),
    driver_binary_digest: assertDigest(
      input.driver_binary_digest,
      `${label}.driver_binary_digest`,
    ),
    execution_principal_id: assertToken(
      input.execution_principal_id,
      `${label}.execution_principal_id`,
      "principal",
    ),
    worker_uid: assertInteger(input.worker_uid, `${label}.worker_uid`, 0, 2 ** 32 - 2),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    transport_digest: assertDigest(input.transport_digest, `${label}.transport_digest`),
  });
}

function workerAuthorityMatchesBinding(current, binding, enrollmentState) {
  return current.trusted === true
    && current.revoked === false
    && current.custody_allowed === true
    && current.enrollment_id === enrollmentState.enrollment_id
    && current.hardware_identity_digest === enrollmentState.hardware_identity_digest
    && current.custody_id === binding.custody_id
    && current.driver_id === binding.driver_id
    && current.driver_implementation_digest === binding.driver_implementation_digest
    && current.driver_binary_digest === binding.driver_binary_digest
    && current.execution_principal_id === binding.execution_principal_id
    && current.worker_uid === binding.worker_uid
    && current.provider_descriptor_digest === binding.provider_descriptor_digest
    && current.transport_digest === binding.transport_digest;
}

function assertCurrentProcessUid(binding) {
  if (typeof process.getuid !== "function" || process.getuid() !== binding.worker_uid) {
    throw custodyError("usb_cdc_worker_principal_rejected");
  }
}

function assertCurrentDriverAuthority(driverState, purpose) {
  if (driverState.invalidated) {
    throw custodyError("usb_cdc_worker_authority_rejected");
  }
  const current = resolveWorkerAuthority(driverState.worker_authority, purpose);
  if (!workerAuthorityMatchesBinding(
    current,
    driverState.binding,
    driverState.enrollment_state,
  )) {
    driverState.invalidated = true;
    throw custodyError("usb_cdc_worker_authority_rejected");
  }
  assertCurrentProcessUid(driverState.binding);
  return current;
}

function createUsbCdcDriverPort(input, enrollment, workerAuthority) {
  assertClosedObject(input, "usb_cdc_driver_port", [
    "version",
    "custody_id",
    "driver_id",
    "driver_implementation_digest",
    "driver_binary_digest",
    "execution_principal_id",
    "worker_uid",
    "provider_descriptor_digest",
    "transport_digest",
    "enumerate_candidates",
    "open_candidate",
    "activate_handle",
    "close_handle",
  ], ["transact_handle"]);
  if (input.version !== USB_CDC_CUSTODY_VERSION) {
    throw new Error(`usb_cdc_driver_port.version must be ${USB_CDC_CUSTODY_VERSION}`);
  }
  for (const callback of [
    "enumerate_candidates",
    "open_candidate",
    "activate_handle",
    "close_handle",
  ]) {
    if (typeof input[callback] !== "function") {
      throw new Error(`usb_cdc_driver_port.${callback} must be a function`);
    }
  }
  if (Object.prototype.hasOwnProperty.call(input, "transact_handle")
      && typeof input.transact_handle !== "function") {
    throw new Error("usb_cdc_driver_port.transact_handle must be a function when provided");
  }
  const enrolled = assertOperatorUsbCdcEnrollment(enrollment);
  const enrollmentState = ENROLLMENT_STATE.get(enrolled);
  const authority = assertUsbCdcWorkerAuthorityPort(workerAuthority);
  const authorityState = WORKER_AUTHORITY_STATE.get(authority);
  if (authority !== enrollmentState.worker_authority) {
    throw new Error("usb_cdc_driver_port authority does not own the enrollment capability");
  }
  if (authorityState.driver_claimed) {
    throw new Error("usb_cdc_worker_authority is already bound to a driver capability");
  }
  const binding = normalizeDriverBinding(input, "usb_cdc_driver_port");
  const provisionalState = {
    enrollment: enrolled,
    enrollment_state: enrollmentState,
    worker_authority: authority,
    binding,
    invalidated: false,
  };
  assertCurrentDriverAuthority(provisionalState, "driver_capability_creation");
  const port = Object.freeze({
    version: USB_CDC_CUSTODY_VERSION,
    driver_id: binding.driver_id,
    authority_id: authorityState.authority_id,
    capability_id: randomCapabilityId("usb-cdc-driver"),
  });
  DRIVER_PORTS.add(port);
  DRIVER_STATE.set(port, {
    ...provisionalState,
    enumerate_candidates: input.enumerate_candidates,
    open_candidate: input.open_candidate,
    activate_handle: input.activate_handle,
    close_handle: input.close_handle,
    transact_handle: input.transact_handle || null,
    custody_claimed: false,
  });
  authorityState.driver_claimed = true;
  return port;
}

function assertUsbCdcDriverPort(input) {
  const state = input == null ? null : DRIVER_STATE.get(input);
  if (!input || !DRIVER_PORTS.has(input) || !state || !Object.isFrozen(input)
      || input.version !== USB_CDC_CUSTODY_VERSION
      || input.driver_id !== state.binding.driver_id
      || input.authority_id !== WORKER_AUTHORITY_STATE.get(state.worker_authority)?.authority_id
      || typeof input.capability_id !== "string"
      || Reflect.ownKeys(input).length !== 4) {
    throw new Error("usb_cdc_driver_port must be a private branded driver capability");
  }
  return input;
}

function createUsbCdcOpenAuthorityPort(input) {
  assertClosedObject(input, "usb_cdc_open_authority_port", [
    "version",
    "authority_id",
    "worker_authority_port",
    "resolve_current_enrollment",
  ]);
  if (input.version !== USB_CDC_CUSTODY_VERSION) {
    throw new Error(`usb_cdc_open_authority_port.version must be ${USB_CDC_CUSTODY_VERSION}`);
  }
  if (typeof input.resolve_current_enrollment !== "function") {
    throw new Error("usb_cdc_open_authority_port.resolve_current_enrollment must be a function");
  }
  const authorityId = assertIdentifier(
    input.authority_id,
    "usb_cdc_open_authority_port.authority_id",
  );
  const workerAuthority = assertUsbCdcWorkerAuthorityPort(input.worker_authority_port);
  const port = Object.freeze({
    version: USB_CDC_CUSTODY_VERSION,
    authority_id: authorityId,
    capability_id: randomCapabilityId("usb-cdc-open-authority"),
  });
  OPEN_AUTHORITIES.add(port);
  OPEN_AUTHORITY_STATE.set(port, Object.freeze({
    authority_id: authorityId,
    worker_authority: workerAuthority,
    resolve_current_enrollment: input.resolve_current_enrollment,
  }));
  return port;
}

function assertUsbCdcOpenAuthorityPort(input) {
  const state = input == null ? null : OPEN_AUTHORITY_STATE.get(input);
  if (!input || !OPEN_AUTHORITIES.has(input) || !state || !Object.isFrozen(input)
      || input.version !== USB_CDC_CUSTODY_VERSION
      || input.authority_id !== state.authority_id
      || typeof input.capability_id !== "string"
      || Reflect.ownKeys(input).length !== 3) {
    throw new Error("usb_cdc_open_authority_port must be a private branded authority capability");
  }
  return input;
}

function normalizeAuthorityResolution(input, label) {
  if (input && typeof input.then === "function") {
    throw new Error(`${label} must resolve synchronously`);
  }
  assertClosedObject(input, label, [
    "version",
    "authority_id",
    "authority_epoch",
    "enrollment_id",
    "alias",
    "trusted",
    "revoked",
    "open_allowed",
    "candidate_filters",
    "hardware_identity",
    "hardware_identity_provenance",
  ]);
  if (input.version !== USB_CDC_CUSTODY_VERSION) {
    throw new Error(`${label}.version must be ${USB_CDC_CUSTODY_VERSION}`);
  }
  if (typeof input.trusted !== "boolean" || typeof input.revoked !== "boolean"
      || typeof input.open_allowed !== "boolean") {
    throw new Error(`${label} trust fields must be booleans`);
  }
  if (input.hardware_identity_provenance !== "operator_enrolled_high_entropy") {
    throw new Error(`${label}.hardware_identity_provenance is not operator-enrolled`);
  }
  return {
    version: USB_CDC_CUSTODY_VERSION,
    authority_id: assertIdentifier(input.authority_id, `${label}.authority_id`),
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, 1),
    enrollment_id: assertIdentifier(input.enrollment_id, `${label}.enrollment_id`),
    alias: assertAlias(input.alias, `${label}.alias`),
    trusted: input.trusted,
    revoked: input.revoked,
    open_allowed: input.open_allowed,
    candidate_filters: normalizeCandidateFilters(
      input.candidate_filters,
      `${label}.candidate_filters`,
    ),
    hardware_identity: normalizeIdentity(input.hardware_identity, `${label}.hardware_identity`),
  };
}

function resolveAuthority(authority, query, failureCode) {
  const port = assertUsbCdcOpenAuthorityPort(authority);
  const state = OPEN_AUTHORITY_STATE.get(port);
  let output;
  try {
    output = state.resolve_current_enrollment(Object.freeze({ ...query }));
  } catch {
    throw custodyError(failureCode);
  }
  try {
    return normalizeAuthorityResolution(output, "usb_cdc_open_authority_resolution");
  } catch {
    throw custodyError(failureCode);
  }
}

function enrollOperatorUsbCdcDevice(input, authority) {
  assertClosedObject(input, "operator_usb_cdc_enrollment", [
    "version",
    "enrollment_id",
    "alias",
    "authority_id",
  ]);
  if (input.version !== USB_CDC_CUSTODY_VERSION) {
    throw new Error(`operator_usb_cdc_enrollment.version must be ${USB_CDC_CUSTODY_VERSION}`);
  }
  const port = assertUsbCdcOpenAuthorityPort(authority);
  const portState = OPEN_AUTHORITY_STATE.get(port);
  const enrollmentId = assertIdentifier(
    input.enrollment_id,
    "operator_usb_cdc_enrollment.enrollment_id",
  );
  const alias = assertAlias(input.alias, "operator_usb_cdc_enrollment.alias");
  if (input.authority_id !== portState.authority_id) {
    throw new Error("operator_usb_cdc_enrollment does not match its authority capability");
  }
  const current = resolveAuthority(port, {
    version: USB_CDC_CUSTODY_VERSION,
    purpose: "enrollment",
    enrollment_id: enrollmentId,
    alias,
  }, "usb_cdc_enrollment_authority_rejected");
  try {
    if (current.authority_id !== portState.authority_id
        || current.enrollment_id !== enrollmentId
        || current.alias !== alias
        || current.trusted !== true
        || current.revoked !== false) {
      throw custodyError("usb_cdc_enrollment_authority_rejected");
    }
    const enrollment = Object.freeze({
      version: USB_CDC_CUSTODY_VERSION,
      enrollment_id: enrollmentId,
      alias,
      authority_id: portState.authority_id,
      capability_id: randomCapabilityId("usb-cdc-enrollment"),
    });
    ENROLLMENTS.add(enrollment);
    ENROLLMENT_STATE.set(enrollment, {
      enrollment_id: enrollmentId,
      alias,
      authority: port,
      authority_id: portState.authority_id,
      worker_authority: portState.worker_authority,
      minimum_authority_epoch: current.authority_epoch,
      current_authority_epoch: current.authority_epoch,
      candidate_filters: current.candidate_filters,
      hardware_identity: Buffer.from(current.hardware_identity),
      hardware_identity_digest: hardwareIdentityDigest(current.hardware_identity),
      custody_claimed: false,
    });
    return enrollment;
  } finally {
    current.hardware_identity.fill(0);
  }
}

function assertOperatorUsbCdcEnrollment(input) {
  const state = input == null ? null : ENROLLMENT_STATE.get(input);
  if (!input || !ENROLLMENTS.has(input) || !state || !Object.isFrozen(input)
      || input.version !== USB_CDC_CUSTODY_VERSION
      || input.enrollment_id !== state.enrollment_id
      || input.alias !== state.alias
      || input.authority_id !== state.authority_id
      || typeof input.capability_id !== "string"
      || Reflect.ownKeys(input).length !== 5) {
    throw new Error("operator_usb_cdc_enrollment must be a private branded enrollment capability");
  }
  return input;
}

function normalizeCandidate(input, index) {
  const label = `usb_cdc_candidate[${index}]`;
  assertClosedObject(input, label, [
    "vendor_id",
    "product_id",
    "model",
    "path",
    "serial_number",
    "hardware_identity",
  ]);
  return {
    vendor_id: assertInteger(input.vendor_id, `${label}.vendor_id`, 0, 0xffff),
    product_id: assertInteger(input.product_id, `${label}.product_id`, 0, 0xffff),
    model: assertBoundedString(
      input.model,
      `${label}.model`,
      USB_CDC_CUSTODY_LIMITS.max_model_bytes,
    ),
    path: assertBoundedString(
      input.path,
      `${label}.path`,
      USB_CDC_CUSTODY_LIMITS.max_path_bytes,
    ),
    serial_number: assertBoundedString(
      input.serial_number,
      `${label}.serial_number`,
      USB_CDC_CUSTODY_LIMITS.max_serial_bytes,
      { nullable: true },
    ),
    hardware_identity: normalizeIdentity(input.hardware_identity, `${label}.hardware_identity`),
  };
}

function normalizeCandidateList(input) {
  if (!Array.isArray(input) || input.length > USB_CDC_CUSTODY_LIMITS.max_candidates) {
    throw new Error("usb_cdc_candidates must be a bounded array");
  }
  const candidates = [];
  try {
    for (let index = 0; index < input.length; index += 1) {
      if (!Object.prototype.hasOwnProperty.call(input, index)) {
        throw new Error("usb_cdc_candidates cannot be sparse");
      }
      candidates.push(normalizeCandidate(input[index], index));
    }
    return candidates;
  } catch (error) {
    for (const candidate of candidates) candidate.hardware_identity.fill(0);
    throw error;
  }
}

function candidateMatchesFilters(candidate, filters) {
  return candidate.vendor_id === filters.vendor_id
    && candidate.product_id === filters.product_id
    && candidate.model === filters.model;
}

function makeOpenOptions() {
  return Object.freeze({
    baud_rate: USB_CDC_LINE_CONFIGURATION.baud_rate,
    data_bits: USB_CDC_LINE_CONFIGURATION.data_bits,
    stop_bits: USB_CDC_LINE_CONFIGURATION.stop_bits,
    parity: USB_CDC_LINE_CONFIGURATION.parity,
    // The handle must attest its private identity before DTR can be asserted.
    dtr_asserted: false,
    exclusive_open: USB_CDC_LINE_CONFIGURATION.exclusive_open,
    serial_lock: USB_CDC_LINE_CONFIGURATION.serial_lock,
    rts_cts: USB_CDC_LINE_CONFIGURATION.rts_cts,
    xon_xoff: USB_CDC_LINE_CONFIGURATION.xon_xoff,
    generic_write_surface_exposed: false,
    brokered_exact_transaction_write_enabled: false,
    read_buffer_bytes: USB_CDC_CUSTODY_LIMITS.read_buffer_bytes,
    write_buffer_bytes: USB_CDC_CUSTODY_LIMITS.write_buffer_bytes,
    io_timeout_ms: USB_CDC_CUSTODY_LIMITS.io_timeout_ms,
    open_timeout_ms: USB_CDC_CUSTODY_LIMITS.open_timeout_ms,
  });
}

function makeActivationOptions() {
  return Object.freeze({
    ...USB_CDC_LINE_CONFIGURATION,
    read_buffer_bytes: USB_CDC_CUSTODY_LIMITS.read_buffer_bytes,
    write_buffer_bytes: USB_CDC_CUSTODY_LIMITS.write_buffer_bytes,
    io_timeout_ms: USB_CDC_CUSTODY_LIMITS.io_timeout_ms,
    activation_timeout_ms: USB_CDC_CUSTODY_LIMITS.open_timeout_ms,
  });
}

function assertTransportGuarantees(input, expectedDtr, label) {
  assertClosedObject(input, label, [
    "baud_rate",
    "data_bits",
    "stop_bits",
    "parity",
    "dtr_asserted",
    "exclusive_open",
    "serial_lock",
    "rts_cts",
    "xon_xoff",
    "generic_write_surface_exposed",
    "brokered_exact_transaction_write_enabled",
    "read_buffer_bytes",
    "write_buffer_bytes",
    "io_timeout_ms",
  ]);
  const expected = {
    ...USB_CDC_LINE_CONFIGURATION,
    dtr_asserted: expectedDtr,
    generic_write_surface_exposed: false,
    brokered_exact_transaction_write_enabled: expectedDtr,
    read_buffer_bytes: USB_CDC_CUSTODY_LIMITS.read_buffer_bytes,
    write_buffer_bytes: USB_CDC_CUSTODY_LIMITS.write_buffer_bytes,
    io_timeout_ms: USB_CDC_CUSTODY_LIMITS.io_timeout_ms,
  };
  for (const [field, value] of Object.entries(expected)) {
    if (input[field] !== value) throw new Error("usb_cdc transport guarantee mismatch");
  }
}

function normalizeOpenResult(input) {
  assertClosedObject(input, "usb_cdc_open_result", [
    "handle",
    "opened_hardware_identity",
    "transport_guarantees",
  ]);
  if ((typeof input.handle !== "object" && typeof input.handle !== "function")
      || input.handle == null) {
    throw new Error("usb_cdc_open_result.handle must be an opaque driver handle");
  }
  assertTransportGuarantees(
    input.transport_guarantees,
    false,
    "usb_cdc_pre_activation_transport_guarantees",
  );
  return {
    handle: input.handle,
    opened_hardware_identity: normalizeIdentity(
      input.opened_hardware_identity,
      "usb_cdc_open_result.opened_hardware_identity",
    ),
  };
}

function normalizeActivationResult(input) {
  assertClosedObject(input, "usb_cdc_activation_result", [
    "activated",
    "opened_hardware_identity",
    "transport_guarantees",
  ]);
  if (input.activated !== true) {
    throw new Error("usb_cdc_activation_result.activated must be true");
  }
  assertTransportGuarantees(
    input.transport_guarantees,
    true,
    "usb_cdc_active_transport_guarantees",
  );
  return {
    opened_hardware_identity: normalizeIdentity(
      input.opened_hardware_identity,
      "usb_cdc_activation_result.opened_hardware_identity",
    ),
  };
}

function beginBoundedOperation(invoke, timeoutMs, timeoutCode) {
  const controller = new AbortController();
  let timedOut = false;
  let timer;
  const underlying = Promise.resolve().then(() => invoke(controller.signal));
  const timeout = new Promise((resolve, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
      reject(custodyError(timeoutCode));
    }, timeoutMs);
  });
  const result = (timedOut ? timeout : Promise.race([underlying, timeout])).finally(() => {
    if (!timedOut) clearTimeout(timer);
  });
  return Object.freeze({
    underlying,
    result,
    did_timeout: () => timedOut,
  });
}

function safeSnapshot(state) {
  return Object.freeze({
    version: USB_CDC_CUSTODY_VERSION,
    custody_id: state.custody_id,
    enrollment_id: state.enrollment_state.enrollment_id,
    alias: state.enrollment_state.alias,
    state: state.phase,
    connection_generation: state.connection_generation,
    // `open_uncertain` can mean the native adapter acquired a handle that it
    // failed to return. Report potential activity conservatively even when the
    // worker has no retained handle object.
    active_handle: state.handle != null || state.phase === "open_uncertain",
    transition_code: state.transition_code,
  });
}

function invalidateConnectionGenerationHandoffs(state, reason) {
  for (const handoff of state.connection_generation_handoffs) {
    const handoffState = CONNECTION_GENERATION_HANDOFF_STATE.get(handoff);
    if (handoffState) {
      handoffState.valid = false;
      handoffState.invalidation_reason = reason;
    }
  }
  state.connection_generation_handoffs.clear();
}

function assertCurrentEnrollment(state, purpose, nextGeneration) {
  const enrollment = state.enrollment_state;
  const current = resolveAuthority(enrollment.authority, {
    version: USB_CDC_CUSTODY_VERSION,
    purpose,
    custody_id: state.custody_id,
    enrollment_id: enrollment.enrollment_id,
    alias: enrollment.alias,
    next_connection_generation: nextGeneration,
  }, "usb_cdc_open_authority_rejected");
  try {
    if (current.authority_id !== enrollment.authority_id
        || current.enrollment_id !== enrollment.enrollment_id
        || current.alias !== enrollment.alias
        || current.trusted !== true
        || current.revoked !== false
        || current.open_allowed !== true
        || current.authority_epoch < enrollment.minimum_authority_epoch
        || current.authority_epoch < enrollment.current_authority_epoch
        || !sameFilters(current.candidate_filters, enrollment.candidate_filters)
        || !sameIdentity(current.hardware_identity, enrollment.hardware_identity)) {
      throw custodyError("usb_cdc_open_authority_rejected");
    }
    enrollment.current_authority_epoch = current.authority_epoch;
    return {
      candidate_filters: current.candidate_filters,
      hardware_identity: Buffer.from(current.hardware_identity),
    };
  } finally {
    current.hardware_identity.fill(0);
  }
}

async function enumerateCandidates(state, current) {
  const driver = DRIVER_STATE.get(state.driver);
  const operation = beginBoundedOperation(
    (signal) => driver.enumerate_candidates(Object.freeze({
      version: USB_CDC_CUSTODY_VERSION,
      signal,
      max_candidates: USB_CDC_CUSTODY_LIMITS.max_candidates,
      discovery_timeout_ms: USB_CDC_CUSTODY_LIMITS.discovery_timeout_ms,
    })),
    USB_CDC_CUSTODY_LIMITS.discovery_timeout_ms,
    "usb_cdc_discovery_timeout",
  );
  let raw;
  try {
    raw = await operation.result;
  } catch (error) {
    if (operation.did_timeout()) throw custodyError("usb_cdc_discovery_timeout");
    throw custodyError("usb_cdc_discovery_failed");
  }
  let candidates;
  try {
    candidates = normalizeCandidateList(raw);
  } catch {
    throw custodyError("usb_cdc_discovery_failed");
  }
  const filtered = candidates.filter((candidate) => (
    candidateMatchesFilters(candidate, current.candidate_filters)
    && sameIdentity(candidate.hardware_identity, current.hardware_identity)
  ));
  if (filtered.length === 0) {
    for (const candidate of candidates) candidate.hardware_identity.fill(0);
    throw custodyError("usb_cdc_candidate_not_found");
  }
  if (filtered.length !== 1) {
    for (const candidate of candidates) candidate.hardware_identity.fill(0);
    throw custodyError("usb_cdc_candidate_ambiguous");
  }
  const selected = filtered[0];
  for (const candidate of candidates) {
    if (candidate !== selected) candidate.hardware_identity.fill(0);
  }
  return selected;
}

function extractPossibleHandle(raw) {
  try {
    if (!isPlainObject(raw)) return null;
    const handle = raw.handle;
    if ((typeof handle !== "object" && typeof handle !== "function") || handle == null) return null;
    return handle;
  } catch {
    return null;
  }
}

async function closeHandleOnce(state, terminalRequested, timeoutCode = "usb_cdc_close_timeout") {
  // Invalidate before the first asynchronous close seam. A future worker may
  // redeem a handoff only while this exact handle/generation is synchronously
  // stable; even an unconfirmed close must never leave a usable capability.
  invalidateConnectionGenerationHandoffs(state, "transport_close_started");
  if (state.handle == null) {
    state.phase = terminalRequested ? "closed" : "disconnected";
    state.transition_code = terminalRequested ? "custody_closed" : "transport_disconnected";
    return safeSnapshot(state);
  }
  if (state.close_pending) throw custodyError("usb_cdc_close_pending");
  const handle = state.handle;
  const driver = DRIVER_STATE.get(state.driver);
  state.phase = "disconnecting";
  state.transition_code = "transport_close_started";
  state.close_pending = true;
  state.terminal_requested = state.terminal_requested || terminalRequested;
  const operation = beginBoundedOperation(
    (signal) => driver.close_handle(Object.freeze({
      version: USB_CDC_CUSTODY_VERSION,
      handle,
      signal,
      close_timeout_ms: USB_CDC_CUSTODY_LIMITS.close_timeout_ms,
    })),
    USB_CDC_CUSTODY_LIMITS.close_timeout_ms,
    timeoutCode,
  );
  const finishClose = (raw) => {
    if (!isPlainObject(raw)
        || Reflect.ownKeys(raw).length !== 1
        || raw.closed !== true) {
      state.close_pending = false;
      state.phase = "close_uncertain";
      state.transition_code = "transport_close_unconfirmed";
      throw custodyError("usb_cdc_close_unconfirmed");
    }
    if (state.handle === handle) state.handle = null;
    state.close_pending = false;
    state.phase = state.terminal_requested ? "closed" : "disconnected";
    state.transition_code = state.terminal_requested ? "custody_closed" : "transport_disconnected";
    if (state.terminal_requested) state.enrollment_state.hardware_identity.fill(0);
    return safeSnapshot(state);
  };
  try {
    return finishClose(await operation.result);
  } catch (error) {
    if (operation.did_timeout()) {
      state.phase = "close_uncertain";
      state.transition_code = "transport_close_timeout";
      operation.underlying.then(
        (raw) => {
          try {
            finishClose(raw);
          } catch {
            // The safe state already records that closure remains uncertain.
          }
        },
        () => {
          state.close_pending = false;
        },
      );
      throw custodyError(timeoutCode);
    }
    const closeUnconfirmed = state.transition_code === "transport_close_unconfirmed";
    state.close_pending = false;
    state.phase = "close_uncertain";
    state.transition_code = closeUnconfirmed
      ? "transport_close_unconfirmed"
      : "transport_close_failed";
    if (closeUnconfirmed) throw custodyError("usb_cdc_close_unconfirmed");
    throw custodyError("usb_cdc_close_failed");
  }
}

async function quarantineOpenedHandle(state, handle, terminalRequested = false) {
  invalidateConnectionGenerationHandoffs(state, "transport_quarantined");
  state.handle = handle;
  state.phase = "close_uncertain";
  state.transition_code = "transport_open_quarantined";
  try {
    await closeHandleOnce(state, terminalRequested);
    return true;
  } catch {
    return false;
  }
}

async function connectOnce(state, action) {
  if (state.phase === "closed") throw custodyError("usb_cdc_custody_closed");
  if (state.phase === "connected") {
    try {
      assertCurrentDriverAuthority(state.driver_state, "connected_revalidation");
      return safeSnapshot(state);
    } catch (error) {
      await quarantineOpenedHandle(state, state.handle);
      throw error;
    }
  }
  if (["open_uncertain", "close_uncertain", "disconnecting"].includes(state.phase)) {
    throw custodyError("usb_cdc_transport_state_uncertain");
  }
  const nextGeneration = state.connection_generation + 1;
  state.phase = "connecting";
  state.transition_code = `${action}_started`;
  let preDiscovery;
  let selected;
  try {
    assertCurrentDriverAuthority(state.driver_state, "pre_discovery");
    preDiscovery = assertCurrentEnrollment(state, "pre_discovery", nextGeneration);
    selected = await enumerateCandidates(state, preDiscovery);
  } catch (error) {
    state.phase = "disconnected";
    state.transition_code = "transport_open_refused";
    throw error;
  } finally {
    preDiscovery?.hardware_identity.fill(0);
  }

  let preOpen;
  try {
    assertCurrentDriverAuthority(state.driver_state, "pre_open");
    preOpen = assertCurrentEnrollment(state, "pre_open", nextGeneration);
    if (!candidateMatchesFilters(selected, preOpen.candidate_filters)
        || !sameIdentity(selected.hardware_identity, preOpen.hardware_identity)) {
      throw custodyError("usb_cdc_open_authority_rejected");
    }
  } catch (error) {
    selected.hardware_identity.fill(0);
    preOpen?.hardware_identity.fill(0);
    state.phase = "disconnected";
    state.transition_code = "transport_open_refused";
    throw error;
  }
  preOpen.hardware_identity.fill(0);

  const driver = DRIVER_STATE.get(state.driver);
  const candidateForDriver = Object.freeze({
    vendor_id: selected.vendor_id,
    product_id: selected.product_id,
    model: selected.model,
    path: selected.path,
    serial_number: selected.serial_number,
    hardware_identity: Buffer.from(selected.hardware_identity),
  });
  const operation = beginBoundedOperation(
    (signal) => driver.open_candidate(Object.freeze({
      version: USB_CDC_CUSTODY_VERSION,
      candidate: candidateForDriver,
      options: makeOpenOptions(),
      signal,
    })),
    USB_CDC_CUSTODY_LIMITS.open_timeout_ms,
    "usb_cdc_open_timeout",
  );
  let rawOpen;
  try {
    rawOpen = await operation.result;
  } catch (error) {
    selected.hardware_identity.fill(0);
    if (operation.did_timeout()) {
      state.phase = "open_uncertain";
      state.transition_code = "transport_open_timeout";
      operation.underlying.then(
        async (lateRaw) => {
          candidateForDriver.hardware_identity.fill(0);
          const lateHandle = extractPossibleHandle(lateRaw);
          if (lateHandle == null) {
            // A malformed late result cannot prove that the native adapter
            // failed to acquire a handle. Preserve the uncertainty fence just
            // as we do for an immediate rejected open callback.
            state.phase = "open_uncertain";
            state.transition_code = "transport_open_timed_out_unresolved";
            return;
          }
          await quarantineOpenedHandle(state, lateHandle, state.terminal_requested);
        },
        () => {
          candidateForDriver.hardware_identity.fill(0);
          // A late rejection also cannot prove that no native handle was
          // acquired before failure. Never allow another open without a future
          // adapter-specific reconciliation proof.
          state.phase = "open_uncertain";
          state.transition_code = "transport_open_timed_out_unresolved";
        },
      );
      throw custodyError("usb_cdc_open_timeout");
    }
    candidateForDriver.hardware_identity.fill(0);
    // A rejected open callback cannot prove whether the native adapter acquired
    // a handle before failing. Fence all further opens until a future native
    // reconciliation contract can prove otherwise.
    state.phase = "open_uncertain";
    state.transition_code = "transport_open_failed";
    throw custodyError("usb_cdc_open_failed");
  }

  let opened;
  try {
    opened = normalizeOpenResult(rawOpen);
  } catch {
    const possibleHandle = extractPossibleHandle(rawOpen);
    if (possibleHandle != null) await quarantineOpenedHandle(state, possibleHandle);
    else {
      state.phase = "open_uncertain";
      state.transition_code = "transport_open_attestation_rejected";
    }
    selected.hardware_identity.fill(0);
    candidateForDriver.hardware_identity.fill(0);
    throw custodyError("usb_cdc_open_attestation_rejected");
  }
  candidateForDriver.hardware_identity.fill(0);
  if (!sameIdentity(opened.opened_hardware_identity, selected.hardware_identity)) {
    opened.opened_hardware_identity.fill(0);
    selected.hardware_identity.fill(0);
    await quarantineOpenedHandle(state, opened.handle);
    throw custodyError("usb_cdc_opened_identity_mismatch");
  }
  opened.opened_hardware_identity.fill(0);
  selected.hardware_identity.fill(0);

  let postOpen;
  try {
    assertCurrentDriverAuthority(state.driver_state, "post_open_identity");
    postOpen = assertCurrentEnrollment(state, "post_open_identity", nextGeneration);
  } catch (error) {
    await quarantineOpenedHandle(state, opened.handle);
    throw error;
  } finally {
    postOpen?.hardware_identity.fill(0);
  }
  state.handle = opened.handle;

  const activationOperation = beginBoundedOperation(
    (signal) => driver.activate_handle(Object.freeze({
      version: USB_CDC_CUSTODY_VERSION,
      handle: opened.handle,
      options: makeActivationOptions(),
      signal,
    })),
    USB_CDC_CUSTODY_LIMITS.open_timeout_ms,
    "usb_cdc_activation_timeout",
  );
  let rawActivation;
  try {
    rawActivation = await activationOperation.result;
  } catch (error) {
    if (activationOperation.did_timeout()) {
      state.phase = "open_uncertain";
      state.transition_code = "transport_activation_timeout";
      activationOperation.underlying.then(
        () => quarantineOpenedHandle(state, opened.handle, state.terminal_requested),
        () => quarantineOpenedHandle(state, opened.handle, state.terminal_requested),
      );
      throw custodyError("usb_cdc_activation_timeout");
    }
    await quarantineOpenedHandle(state, opened.handle);
    throw custodyError("usb_cdc_activation_failed");
  }
  let activation;
  try {
    activation = normalizeActivationResult(rawActivation);
  } catch {
    await quarantineOpenedHandle(state, opened.handle);
    throw custodyError("usb_cdc_activation_attestation_rejected");
  }
  if (!sameIdentity(
    activation.opened_hardware_identity,
    state.enrollment_state.hardware_identity,
  )) {
    activation.opened_hardware_identity.fill(0);
    await quarantineOpenedHandle(state, opened.handle);
    throw custodyError("usb_cdc_activation_identity_mismatch");
  }
  activation.opened_hardware_identity.fill(0);

  let postActivation;
  try {
    assertCurrentDriverAuthority(state.driver_state, "post_activate");
    postActivation = assertCurrentEnrollment(state, "post_activate", nextGeneration);
  } catch (error) {
    await quarantineOpenedHandle(state, opened.handle);
    throw error;
  } finally {
    postActivation?.hardware_identity.fill(0);
  }
  state.connection_generation = nextGeneration;
  state.phase = "connected";
  state.transition_code = action === "reconnect"
    ? "transport_reconnected"
    : "transport_connected";
  return safeSnapshot(state);
}

function createWorkerUsbCdcCustody(input) {
  assertClosedObject(input, "worker_usb_cdc_custody", [
    "version",
    "custody_id",
    "enrollment",
    "driver_port",
    "open_authority_port",
    "worker_authority_port",
  ]);
  if (input.version !== USB_CDC_CUSTODY_VERSION) {
    throw new Error(`worker_usb_cdc_custody.version must be ${USB_CDC_CUSTODY_VERSION}`);
  }
  const enrollment = assertOperatorUsbCdcEnrollment(input.enrollment);
  const enrollmentState = ENROLLMENT_STATE.get(enrollment);
  const driver = assertUsbCdcDriverPort(input.driver_port);
  const driverState = DRIVER_STATE.get(driver);
  const authority = assertUsbCdcOpenAuthorityPort(input.open_authority_port);
  const workerAuthority = assertUsbCdcWorkerAuthorityPort(input.worker_authority_port);
  if (authority !== enrollmentState.authority) {
    throw new Error("worker_usb_cdc_custody authority does not own the enrollment capability");
  }
  const custodyId = assertIdentifier(input.custody_id, "worker_usb_cdc_custody.custody_id");
  if (driverState.enrollment !== enrollment
      || driverState.worker_authority !== workerAuthority
      || driverState.binding.custody_id !== custodyId) {
    throw new Error("worker_usb_cdc_custody driver authority binding does not match");
  }
  if (driverState.custody_claimed) {
    throw new Error("usb_cdc_driver_port is already bound to a custody controller");
  }
  if (enrollmentState.custody_claimed) {
    throw new Error("operator_usb_cdc_enrollment is already bound to a custody controller");
  }
  assertCurrentDriverAuthority(driverState, "custody_creation");
  const state = {
    custody_id: custodyId,
    enrollment_state: {
      ...enrollmentState,
      hardware_identity: Buffer.from(enrollmentState.hardware_identity),
    },
    driver,
    driver_state: driverState,
    phase: "disconnected",
    connection_generation: 0,
    connection_generation_handoffs: new Set(),
    handle: null,
    busy: false,
    busy_kind: null,
    transaction_port: null,
    transaction_lock: null,
    close_pending: false,
    terminal_requested: false,
    transition_code: "custody_created",
  };

  async function runLifecycle(callback) {
    if (state.busy) throw custodyError("usb_cdc_lifecycle_busy");
    state.busy = true;
    state.busy_kind = "lifecycle";
    try {
      return await callback();
    } finally {
      state.busy = false;
      state.busy_kind = null;
    }
  }

  const custody = Object.freeze({
    version: USB_CDC_CUSTODY_VERSION,
    custody_id: state.custody_id,
    enrollment_id: enrollmentState.enrollment_id,
    alias: enrollmentState.alias,
    snapshot() {
      return safeSnapshot(state);
    },
    async connect() {
      return runLifecycle(() => connectOnce(state, "connect"));
    },
    async disconnect() {
      return runLifecycle(async () => {
        if (state.phase === "closed") return safeSnapshot(state);
        if (state.phase === "open_uncertain") {
          throw custodyError("usb_cdc_open_resolution_pending");
        }
        if (state.phase === "disconnected") return safeSnapshot(state);
        return closeHandleOnce(state, false);
      });
    },
    async reconnect() {
      return runLifecycle(async () => {
        if (state.phase === "closed") throw custodyError("usb_cdc_custody_closed");
        if (state.phase === "open_uncertain" || state.close_pending) {
          throw custodyError("usb_cdc_transport_state_uncertain");
        }
        if (state.handle != null) await closeHandleOnce(state, false);
        if (state.phase !== "disconnected") {
          throw custodyError("usb_cdc_transport_state_uncertain");
        }
        return connectOnce(state, "reconnect");
      });
    },
    async close() {
      return runLifecycle(async () => {
        state.terminal_requested = true;
        if (state.phase === "closed") return safeSnapshot(state);
        if (state.phase === "open_uncertain") {
          throw custodyError("usb_cdc_open_resolution_pending");
        }
        const result = await closeHandleOnce(state, true);
        if (state.phase === "closed") state.enrollment_state.hardware_identity.fill(0);
        return result;
      });
    },
    toJSON() {
      return safeSnapshot(state);
    },
  });
  CUSTODIES.add(custody);
  CUSTODY_STATE.set(custody, state);
  enrollmentState.custody_claimed = true;
  driverState.custody_claimed = true;
  return custody;
}

function assertWorkerUsbCdcCustody(input) {
  const state = input == null ? null : CUSTODY_STATE.get(input);
  if (!input || !CUSTODIES.has(input) || !state || !Object.isFrozen(input)
      || input.version !== USB_CDC_CUSTODY_VERSION
      || input.custody_id !== state.custody_id
      || input.enrollment_id !== state.enrollment_state.enrollment_id
      || input.alias !== state.enrollment_state.alias
      || Reflect.ownKeys(input).length !== 10) {
    throw new Error("worker_usb_cdc_custody must be a private branded custody capability");
  }
  return input;
}

function rejectConnectionGenerationHandoffSerialization() {
  throw custodyError("usb_cdc_connection_generation_handoff_not_serializable");
}

function assertStableConnectedCustody(state) {
  if (state.busy || state.phase !== "connected" || state.handle == null) {
    throw custodyError("usb_cdc_connection_generation_handoff_requires_stable_connected_custody");
  }
}

function revalidateConnectionGenerationHandoffAuthority(state, purpose) {
  try {
    assertCurrentDriverAuthority(state.driver_state, purpose);
    const enrollment = assertCurrentEnrollment(
      state,
      purpose,
      state.connection_generation,
    );
    enrollment.hardware_identity.fill(0);
  } catch (error) {
    invalidateConnectionGenerationHandoffs(state, "authority_revalidation_failed");
    throw error;
  }
}

function validatedConnectionGenerationHandoff(
  handoffInput,
  custodyInput,
  expectedConnectionGeneration,
) {
  const handoffState = handoffInput == null
    ? null
    : CONNECTION_GENERATION_HANDOFF_STATE.get(handoffInput);
  if (!handoffInput || !CONNECTION_GENERATION_HANDOFFS.has(handoffInput)
      || !handoffState || !Object.isFrozen(handoffInput)) {
    throw new Error(
      "USB CDC connection-generation handoff must be a private branded in-memory capability",
    );
  }
  const custody = assertWorkerUsbCdcCustody(custodyInput);
  const expected = assertInteger(
    expectedConnectionGeneration,
    "usb_cdc_connection_generation_handoff.expected_connection_generation",
    1,
  );
  if (handoffState.custody !== custody
      || handoffState.custody_state !== CUSTODY_STATE.get(custody)) {
    throw custodyError("usb_cdc_connection_generation_handoff_crosswired");
  }
  if (handoffState.consumed) {
    throw custodyError("usb_cdc_connection_generation_handoff_consumed");
  }
  if (!handoffState.valid) {
    throw custodyError("usb_cdc_connection_generation_handoff_stale");
  }
  if (expected !== handoffState.connection_generation
      || handoffInput.connection_generation !== handoffState.connection_generation) {
    throw custodyError("usb_cdc_connection_generation_handoff_generation_mismatch");
  }
  return { custody, handoff: handoffInput, handoff_state: handoffState };
}

function assertExactConnectionGenerationState(handoffState, { transactionLocked = false } = {}) {
  const state = handoffState.custody_state;
  const expectedBusy = transactionLocked
    ? state.busy === true && state.busy_kind === "transaction"
    : state.busy === false;
  if (!expectedBusy || state.phase !== "connected"
      || state.connection_generation !== handoffState.connection_generation
      || state.handle == null || state.handle !== handoffState.handle) {
    invalidateConnectionGenerationHandoffs(state, "custody_generation_drift");
    throw custodyError("usb_cdc_connection_generation_handoff_stale");
  }
}

function consumeConnectionGenerationHandoff(handoff, handoffState) {
  handoffState.consumed = true;
  handoffState.valid = false;
  handoffState.invalidation_reason = "consumed";
  handoffState.custody_state.connection_generation_handoffs.delete(handoff);
}

function createWorkerUsbCdcConnectionGenerationHandoff(custodyInput) {
  if (arguments.length !== 1) {
    throw new Error("USB CDC connection-generation handoff creation accepts one custody capability");
  }
  const custody = assertWorkerUsbCdcCustody(custodyInput);
  const state = CUSTODY_STATE.get(custody);
  assertStableConnectedCustody(state);
  revalidateConnectionGenerationHandoffAuthority(state, "generation_handoff_creation");
  const handoff = Object.freeze({
    version: USB_CDC_CUSTODY_VERSION,
    kind: "usb_cdc_connected_generation_handoff",
    custody_id: state.custody_id,
    enrollment_id: state.enrollment_state.enrollment_id,
    connection_generation: state.connection_generation,
    handoff_id: randomCapabilityId("usb-cdc-generation-handoff"),
    production_ready: false,
    execution_authority: false,
    lifecycle_authority: false,
    toJSON: rejectConnectionGenerationHandoffSerialization,
  });
  const handoffState = {
    custody,
    custody_state: state,
    connection_generation: state.connection_generation,
    handle: state.handle,
    valid: true,
    consumed: false,
    invalidation_reason: null,
  };
  CONNECTION_GENERATION_HANDOFFS.add(handoff);
  CONNECTION_GENERATION_HANDOFF_STATE.set(handoff, handoffState);
  state.connection_generation_handoffs.add(handoff);
  return handoff;
}

function assertWorkerUsbCdcConnectionGenerationHandoff(
  handoffInput,
  custodyInput,
  expectedConnectionGeneration,
) {
  if (arguments.length !== 3) {
    throw new Error(
      "USB CDC connection-generation handoff assertion requires handoff, custody, and expected generation",
    );
  }
  const validated = validatedConnectionGenerationHandoff(
    handoffInput,
    custodyInput,
    expectedConnectionGeneration,
  );
  const state = validated.handoff_state.custody_state;
  assertExactConnectionGenerationState(validated.handoff_state);
  revalidateConnectionGenerationHandoffAuthority(state, "generation_handoff_assertion");
  // Authority resolvers are synchronous but still untrusted callbacks. Repeat
  // the exact state check after they return so a reentrant lifecycle request
  // cannot create a check/use gap before consumption.
  assertExactConnectionGenerationState(validated.handoff_state);
  // Consumption happens synchronously after the final live checks. The future
  // worker-private provider hook must invoke its already-registered I/O callback
  // immediately after this assertion, without an intervening await. No handle
  // or read/write/transact capability crosses this boundary.
  consumeConnectionGenerationHandoff(handoffInput, validated.handoff_state);
  return handoffInput;
}

function rejectTransactionPortSerialization() {
  throw custodyError("usb_cdc_transaction_port_not_serializable");
}

function rejectTransactionResultSerialization() {
  throw custodyError("usb_cdc_transaction_result_not_serializable");
}

function privateByteDigest(domain, bytes) {
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(bytes.length, 0);
  try {
    return crypto.createHash("sha256")
      .update(domain, "utf8")
      .update(Buffer.from([0]))
      .update(length)
      .update(bytes)
      .digest("hex");
  } finally {
    length.fill(0);
  }
}

function safeZeroBytes(value) {
  try {
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) value.fill(0);
  } catch {
    // A hostile or detached driver result must not escape the ambiguity fence.
  }
}

function claimWorkerUsbCdcCompiledCommand(commandInput) {
  const claimed = claimCompiledHf14aProviderCommand(commandInput);
  try {
    if (!Buffer.isBuffer(claimed.request_bytes)
        || claimed.request_bytes.length < 1
        || claimed.request_bytes.length > USB_CDC_CUSTODY_LIMITS.write_buffer_bytes
        || claimed.request_byte_length !== claimed.request_bytes.length
        || !Number.isSafeInteger(claimed.maximum_response_bytes)
        || claimed.maximum_response_bytes < 1
        || claimed.maximum_response_bytes > USB_CDC_CUSTODY_LIMITS.read_buffer_bytes
        || !Number.isSafeInteger(claimed.timeout_ms)
        || claimed.timeout_ms < 1
        || claimed.timeout_ms > USB_CDC_CUSTODY_LIMITS.io_timeout_ms) {
      throw custodyError("usb_cdc_compiled_command_contract_rejected");
    }
    return claimed;
  } catch (error) {
    safeZeroBytes(claimed.request_bytes);
    throw error;
  }
}

function compiledCommandResultBinding(claimed) {
  const binding = {};
  for (const field of COMPILED_COMMAND_RESULT_BINDING_FIELDS) {
    binding[field] = claimed[field];
  }
  return Object.freeze(binding);
}

function createWorkerUsbCdcTransactionPort(custodyInput) {
  if (arguments.length !== 1) {
    throw new Error("USB CDC transaction port creation accepts one custody capability");
  }
  const custody = assertWorkerUsbCdcCustody(custodyInput);
  const state = CUSTODY_STATE.get(custody);
  const driverState = DRIVER_STATE.get(state.driver);
  if (typeof driverState.transact_handle !== "function") {
    throw custodyError("usb_cdc_transaction_driver_unavailable");
  }
  if (state.transaction_port != null) return state.transaction_port;
  assertCurrentDriverAuthority(driverState, "transaction_port_creation");
  const port = Object.freeze({
    version: USB_CDC_CUSTODY_VERSION,
    kind: "worker_usb_cdc_transaction_port",
    custody_id: state.custody_id,
    enrollment_id: state.enrollment_state.enrollment_id,
    capability_id: randomCapabilityId("usb-cdc-transaction"),
    production_ready: false,
    toJSON: rejectTransactionPortSerialization,
  });
  TRANSACTION_PORTS.add(port);
  TRANSACTION_PORT_STATE.set(port, { custody, custody_state: state, driver_state: driverState });
  state.transaction_port = port;
  return port;
}

function assertWorkerUsbCdcTransactionPort(input) {
  const state = input == null ? null : TRANSACTION_PORT_STATE.get(input);
  if (!input || !TRANSACTION_PORTS.has(input) || !state || !Object.isFrozen(input)
      || input.version !== USB_CDC_CUSTODY_VERSION
      || input.kind !== "worker_usb_cdc_transaction_port"
      || input.custody_id !== state.custody_state.custody_id
      || input.enrollment_id !== state.custody_state.enrollment_state.enrollment_id
      || typeof input.capability_id !== "string"
      || input.production_ready !== false
      || Reflect.ownKeys(input).length !== 7) {
    throw new Error("worker_usb_cdc_transaction_port must be a private branded capability");
  }
  return input;
}

function claimConnectionGenerationForTransaction(portState, handoffInput, transactionId) {
  const preliminary = handoffInput == null
    ? null
    : CONNECTION_GENERATION_HANDOFF_STATE.get(handoffInput);
  const expectedGeneration = preliminary?.connection_generation || 1;
  const validated = validatedConnectionGenerationHandoff(
    handoffInput,
    portState.custody,
    expectedGeneration,
  );
  const state = portState.custody_state;
  if (validated.handoff_state.custody_state !== state) {
    throw custodyError("usb_cdc_transaction_port_crosswired");
  }
  if (state.busy) {
    invalidateConnectionGenerationHandoffs(state, "transaction_concurrency_rejected");
    throw custodyError("usb_cdc_transaction_busy");
  }
  assertExactConnectionGenerationState(validated.handoff_state);
  const lock = {
    transaction_id: transactionId,
    handle: state.handle,
    connection_generation: state.connection_generation,
    handoff: handoffInput,
  };
  // This reservation is deliberately synchronous and precedes both untrusted
  // authority resolvers and the first native callback. Lifecycle entrypoints
  // observe `busy` immediately and cannot close or replace this handle.
  state.busy = true;
  state.busy_kind = "transaction";
  state.transaction_lock = lock;
  try {
    revalidateConnectionGenerationHandoffAuthority(state, "transaction_pre_invoke");
    assertExactConnectionGenerationState(validated.handoff_state, { transactionLocked: true });
    if (!validated.handoff_state.valid || validated.handoff_state.consumed
        || state.transaction_lock !== lock
        || state.handle !== lock.handle
        || state.connection_generation !== lock.connection_generation) {
      invalidateConnectionGenerationHandoffs(state, "transaction_claim_drift");
      throw custodyError("usb_cdc_connection_generation_handoff_stale");
    }
    consumeConnectionGenerationHandoff(handoffInput, validated.handoff_state);
    return lock;
  } catch (error) {
    if (state.transaction_lock === lock) {
      state.transaction_lock = null;
      state.busy = false;
      state.busy_kind = null;
      state.transition_code = "transport_transaction_refused";
    }
    throw error;
  }
}

function beginBoundedTransactionOperation(invoke, timeoutMs) {
  const controller = new AbortController();
  const startedAt = process.hrtime.bigint();
  let callbackResult;
  let callbackError = null;
  try {
    callbackResult = invoke(controller.signal);
  } catch (error) {
    callbackError = error;
  }
  const underlying = callbackError == null
    ? Promise.resolve(callbackResult)
    : Promise.reject(callbackError);
  const elapsedMilliseconds = Number(process.hrtime.bigint() - startedAt) / 1e6;
  let timedOut = elapsedMilliseconds >= timeoutMs;
  let timer = null;
  let timeout;
  if (timedOut) {
    controller.abort();
    timeout = Promise.reject(custodyError("usb_cdc_transaction_timeout_ambiguous"));
  } else {
    timeout = new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        timedOut = true;
        controller.abort();
        reject(custodyError("usb_cdc_transaction_timeout_ambiguous"));
      }, Math.max(1, timeoutMs - elapsedMilliseconds));
    });
  }
  const result = Promise.race([underlying, timeout]).finally(() => {
    if (!timedOut && timer != null) clearTimeout(timer);
  });
  return Object.freeze({
    controller,
    underlying,
    result,
    did_timeout: () => timedOut,
  });
}

function zeroTransferredTransactionResponse(raw) {
  try {
    if (!isPlainObject(raw)) {
      safeZeroBytes(raw);
      return;
    }
    const descriptor = Object.getOwnPropertyDescriptor(raw, "response_bytes");
    if (descriptor && "value" in descriptor) safeZeroBytes(descriptor.value);
  } catch {
    // Response parsing remains fail-closed even for proxies or detached views.
  }
}

function normalizeTransferredTransactionResponse(raw, maximumResponseBytes) {
  let transferred = null;
  let response = null;
  try {
    assertClosedObject(raw, "usb_cdc_transaction_result", ["response_bytes"]);
    transferred = raw.response_bytes;
    if (!Buffer.isBuffer(transferred) && !(transferred instanceof Uint8Array)) {
      throw new Error("usb_cdc_transaction_result.response_bytes must be private bytes");
    }
    if (transferred.byteLength < 1 || transferred.byteLength > maximumResponseBytes
        || transferred.byteLength > USB_CDC_CUSTODY_LIMITS.read_buffer_bytes) {
      throw custodyError("usb_cdc_transaction_response_oversize");
    }
    response = Buffer.from(transferred);
    return response;
  } catch (error) {
    response?.fill(0);
    throw error;
  } finally {
    safeZeroBytes(transferred);
  }
}

function createWorkerUsbCdcTransactionResult(
  port,
  lock,
  commandBinding,
  requestDigest,
  response,
) {
  const portState = TRANSACTION_PORT_STATE.get(port);
  const responseBytes = Buffer.from(response);
  const result = {
    version: USB_CDC_CUSTODY_VERSION,
    kind: "worker_usb_cdc_transaction_result",
    transaction_id: lock.transaction_id,
    custody_id: portState.custody_state.custody_id,
    enrollment_id: portState.custody_state.enrollment_state.enrollment_id,
    connection_generation: lock.connection_generation,
    ...commandBinding,
    request_digest: requestDigest,
    response_digest: privateByteDigest(
      "hacker-bob/chameleon-usb-cdc-transaction-response/v1",
      responseBytes,
    ),
    toJSON: rejectTransactionResultSerialization,
  };
  Object.defineProperty(result, "response_bytes", {
    value: responseBytes,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  Object.freeze(result);
  TRANSACTION_RESULTS.add(result);
  TRANSACTION_RESULT_STATE.set(result, {
    port,
    command_binding: commandBinding,
    request_digest: requestDigest,
    response_bytes: responseBytes,
  });
  return result;
}

function assertWorkerUsbCdcTransactionResult(input, portInput) {
  if (arguments.length !== 2) {
    throw new Error("USB CDC transaction result assertion requires result and transaction port");
  }
  const resultState = input == null ? null : TRANSACTION_RESULT_STATE.get(input);
  const port = assertWorkerUsbCdcTransactionPort(portInput);
  if (!input || !TRANSACTION_RESULTS.has(input) || !resultState || !Object.isFrozen(input)
      || resultState.port !== port
      || input.version !== USB_CDC_CUSTODY_VERSION
      || input.kind !== "worker_usb_cdc_transaction_result"
      || input.response_bytes !== resultState.response_bytes
      || !Buffer.isBuffer(input.response_bytes)
      || input.request_digest !== resultState.request_digest
      || input.response_digest !== privateByteDigest(
        "hacker-bob/chameleon-usb-cdc-transaction-response/v1",
        input.response_bytes,
      )
      || COMPILED_COMMAND_RESULT_BINDING_FIELDS.some(
        (field) => input[field] !== resultState.command_binding[field],
      )
      || Reflect.ownKeys(input).length !== 10 + COMPILED_COMMAND_RESULT_BINDING_FIELDS.length) {
    throw new Error("worker_usb_cdc_transaction_result must be a private intact result");
  }
  return input;
}

function markTransactionAmbiguous(state, transitionCode) {
  invalidateConnectionGenerationHandoffs(state, transitionCode);
  state.phase = "close_uncertain";
  state.transition_code = transitionCode;
}

function releaseTransactionLock(state, lock) {
  if (state.transaction_lock !== lock) return false;
  state.transaction_lock = null;
  state.busy = false;
  state.busy_kind = null;
  return true;
}

async function quarantineTransactionConnection(state, lock, transitionCode) {
  try {
    if (state.handle == null || state.handle !== lock.handle
        || state.connection_generation !== lock.connection_generation) {
      state.phase = "close_uncertain";
      state.transition_code = `${transitionCode}_quarantine_unconfirmed`;
      return;
    }
    try {
      await closeHandleOnce(state, false, "usb_cdc_transaction_quarantine_close_timeout");
    } catch {
      state.phase = "close_uncertain";
      state.transition_code = `${transitionCode}_quarantine_unconfirmed`;
      return;
    }
    state.transition_code = `${transitionCode}_quarantined`;
  } finally {
    releaseTransactionLock(state, lock);
  }
}

function transactionAmbiguityCode(stage, timedOut) {
  if (timedOut) return "usb_cdc_transaction_timeout_ambiguous";
  if (stage === "response") return "usb_cdc_transaction_response_ambiguous";
  if (stage === "post_authority") return "usb_cdc_transaction_authority_ambiguous";
  if (stage === "post_state") return "usb_cdc_transaction_state_ambiguous";
  return "usb_cdc_transaction_failed_ambiguous";
}

async function settleWorkerUsbCdcTransaction({
  port,
  state,
  lock,
  operation,
  commandBinding,
  requestBytes,
  requestDigest,
  maximumResponseBytes,
}) {
  let raw = null;
  let response = null;
  let stage = "native";
  try {
    raw = await operation.result;
    if (operation.did_timeout()) {
      throw custodyError("usb_cdc_transaction_timeout_ambiguous");
    }
    stage = "response";
    response = normalizeTransferredTransactionResponse(raw, maximumResponseBytes);
    raw = null;
    stage = "post_authority";
    revalidateConnectionGenerationHandoffAuthority(state, "transaction_post_invoke");
    stage = "post_state";
    if (state.transaction_lock !== lock) {
      throw custodyError("usb_cdc_transaction_state_drift");
    }
    const handoffState = CONNECTION_GENERATION_HANDOFF_STATE.get(lock.handoff);
    if (!handoffState) throw custodyError("usb_cdc_transaction_state_drift");
    assertExactConnectionGenerationState(handoffState, { transactionLocked: true });
    const result = createWorkerUsbCdcTransactionResult(
      port,
      lock,
      commandBinding,
      requestDigest,
      response,
    );
    response.fill(0);
    response = null;
    requestBytes.fill(0);
    state.transition_code = "transport_transaction_succeeded";
    releaseTransactionLock(state, lock);
    return result;
  } catch {
    response?.fill(0);
    zeroTransferredTransactionResponse(raw);
    const transitionCode = transactionAmbiguityCode(stage, operation.did_timeout());
    markTransactionAmbiguous(state, transitionCode);
    if (operation.did_timeout()) {
      // Keep the lifecycle reservation until the native promise actually
      // settles. A late success is discarded and zeroed, then the exact handle
      // is quarantined; it can never become a delayed transaction success.
      void operation.underlying.then(
        (lateRaw) => zeroTransferredTransactionResponse(lateRaw),
        () => undefined,
      ).then(async () => {
        requestBytes.fill(0);
        await quarantineTransactionConnection(state, lock, transitionCode);
      }, async () => {
        requestBytes.fill(0);
        await quarantineTransactionConnection(state, lock, transitionCode);
      });
      throw custodyError(transitionCode);
    }
    requestBytes.fill(0);
    await quarantineTransactionConnection(state, lock, transitionCode);
    throw custodyError(transitionCode);
  }
}

function executeWorkerUsbCdcTransaction(portInput, handoffInput, commandInput) {
  if (arguments.length !== 3) {
    throw new Error(
      "USB CDC transaction execution requires port, handoff, and compiled command capability",
    );
  }
  const port = assertWorkerUsbCdcTransactionPort(portInput);
  const portState = TRANSACTION_PORT_STATE.get(port);
  const command = assertCompiledHf14aProviderCommand(commandInput);
  const transactionId = randomCapabilityId("usb-cdc-transaction-attempt");
  let lock;
  try {
    lock = claimConnectionGenerationForTransaction(portState, handoffInput, transactionId);
  } catch (error) {
    // A command presented against a generation that cannot be claimed is
    // deliberately stale. Reusing it with a different generation would turn a
    // failed authority presentation into an implicit retry.
    try {
      invalidateCompiledHf14aProviderCommand(command);
    } catch {
      // Preserve the exact custody/handoff refusal as the primary failure.
    }
    throw error;
  }
  const state = portState.custody_state;
  let claimed;
  let commandBinding;
  let requestDigest;
  try {
    claimed = claimWorkerUsbCdcCompiledCommand(command);
    commandBinding = compiledCommandResultBinding(claimed);
    requestDigest = privateByteDigest(
      "hacker-bob/chameleon-usb-cdc-transaction-request/v1",
      claimed.request_bytes,
    );
  } catch (error) {
    safeZeroBytes(claimed?.request_bytes);
    releaseTransactionLock(state, lock);
    state.transition_code = "transport_transaction_refused";
    throw error;
  }
  const operation = beginBoundedTransactionOperation(
    (signal) => portState.driver_state.transact_handle(Object.freeze({
      version: USB_CDC_CUSTODY_VERSION,
      handle: lock.handle,
      transaction_id: transactionId,
      connection_generation: lock.connection_generation,
      request_bytes: claimed.request_bytes,
      maximum_response_bytes: claimed.maximum_response_bytes,
      timeout_ms: claimed.timeout_ms,
      signal,
    })),
    claimed.timeout_ms,
  );
  return settleWorkerUsbCdcTransaction({
    port,
    state,
    lock,
    operation,
    commandBinding,
    requestBytes: claimed.request_bytes,
    requestDigest,
    maximumResponseBytes: claimed.maximum_response_bytes,
  });
}

module.exports = {
  USB_CDC_CUSTODY_LIMITS,
  USB_CDC_CUSTODY_VERSION,
  USB_CDC_HARDWARE_IDENTITY_DOMAIN,
  USB_CDC_LINE_CONFIGURATION,
  USB_CDC_STATE_VALUES,
  USB_CDC_WORKER_AUTHORITY_DOMAIN,
  USB_CDC_WORKER_AUTHORITY_SIGNING_DOMAIN,
  assertOperatorUsbCdcEnrollment,
  assertUsbCdcDriverPort,
  assertUsbCdcOpenAuthorityPort,
  assertUsbCdcWorkerAuthorityPort,
  assertWorkerUsbCdcConnectionGenerationHandoff,
  assertWorkerUsbCdcCustody,
  assertWorkerUsbCdcTransactionPort,
  assertWorkerUsbCdcTransactionResult,
  createUsbCdcDriverPort,
  createUsbCdcOpenAuthorityPort,
  createUsbCdcWorkerAuthorityPort,
  createWorkerUsbCdcConnectionGenerationHandoff,
  createWorkerUsbCdcCustody,
  createWorkerUsbCdcTransactionPort,
  enrollOperatorUsbCdcDevice,
  executeWorkerUsbCdcTransaction,
};
