"use strict";

// Closed, provider-private ISO14443-A discovery compiler. The only caller
// input is a reviewed schema ID. Command IDs, option bits, timeouts, bit
// lengths, and request bytes remain fixed in this module and are never part of
// an evaluator projection. This file is intentionally omitted from the
// package subpath exports; a governed provider worker is its intended consumer.

const crypto = require("node:crypto");

const {
  assertNoPublicByteMaterial,
  hashCanonicalJson,
} = require("./closed-runtime-contracts.js");
const {
  createCompiledProviderCommandChannel,
} = require("./compiled-provider-command.js");

const HF14A_PROBE_COMPILER_VERSION = 1;
const HF14A_PROBE_COMPILER_ID = "iso14443a_closed_probe_v1";
const PROVIDER_ID = "chameleon_ultra";
const CAPABILITY_ID = "CU-HF-14A-COMPILED-PROBE";
const OPERATION_ID = "protocol.discovery_probe";
const MINIMUM_ASSURANCE_PROFILE_ID = "enrolled_conformance_tested";
const REQUIRED_CONFORMANCE_DEPENDENCY_REF =
  "conformance:chameleon_hf14a_closed_probe_v1";
const HF14A_RAW_COMMAND_ID = 2010;
const FIXED_RESPONSE_TIMEOUT_MS = 100;
const FIXED_REQUEST_BIT_LENGTH = 7;
const FIXED_PROVIDER_PAYLOAD_BYTES = 6;
const MAXIMUM_RESPONSE_BYTES = 64;
const OPTION_ACTIVATE_RF_FIELD = 1 << 7;
const OPTION_WAIT_RESPONSE = 1 << 6;
const FIXED_OPTION_BYTE = OPTION_ACTIVATE_RF_FIELD | OPTION_WAIT_RESPONSE;
const SCHEMA_ID_PATTERN = /^iso14443a\.(?:requa|wupa)_atqa_v1$/u;
const COMMAND_DIGEST_DOMAIN = "hacker-bob/chameleon-hf14a-closed-probe-command/v1";
const COMPILED_PROBES = new WeakSet();
const COMPILED_PROBE_STATE = new WeakMap();

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, required) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const keys = Reflect.ownKeys(value);
  if (keys.some((field) => typeof field !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const unknown = keys.filter((field) => !required.includes(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((field) => !keys.includes(field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  for (const field of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || !descriptor.enumerable) {
      throw new Error(`${label}.${field} must be an enumerable data field`);
    }
  }
  return value;
}

function commandDigest(payload) {
  const header = Buffer.alloc(6);
  header.writeUInt16BE(HF14A_RAW_COMMAND_ID, 0);
  header.writeUInt16BE(0, 2);
  header.writeUInt16BE(payload.length, 4);
  return crypto.createHash("sha256")
    .update(COMMAND_DIGEST_DOMAIN, "utf8")
    .update(Buffer.from([0]))
    .update(header)
    .update(payload)
    .digest("hex");
}

function buildFixedPayload(requestByte) {
  const payload = Buffer.alloc(FIXED_PROVIDER_PAYLOAD_BYTES);
  payload[0] = FIXED_OPTION_BYTE;
  payload.writeUInt16BE(FIXED_RESPONSE_TIMEOUT_MS, 1);
  payload.writeUInt16BE(FIXED_REQUEST_BIT_LENGTH, 3);
  payload[5] = requestByte;
  return payload;
}

const HF14A_PROBE_SOURCE_PROFILE = deepFreeze({
  release_tag: "v2.2.0",
  tag_commit: "f349dbeeaa315776b272ae8fb851cc4042d55f07",
  source_hashes: {
    data_cmd_h: "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
    app_cmd_c: "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
    chameleon_cmd_py: "a09c9d7ade77407bbefe2a5dfb1475c995d2580422d81c326b0dc27f8baeb44d",
    rc522_h: "b2e32f301e8db38750806cd3236be7205b716bca039f765ed1940813aa730d28",
    rc522_c: "635d4d147cd884320e6fb32b37bd0e316ee32cdcc3cd55754f47dc5261c886fa",
  },
});
const sourceProfileBasis = {
  version: HF14A_PROBE_COMPILER_VERSION,
  provider_id: PROVIDER_ID,
  ...HF14A_PROBE_SOURCE_PROFILE,
};
const SOURCE_PROFILE_DIGEST = hashCanonicalJson(sourceProfileBasis);

function makeSchema(schemaId, variantId, requestByte, semantics) {
  const payload = buildFixedPayload(requestByte);
  const publicBasis = {
    version: HF14A_PROBE_COMPILER_VERSION,
    schema_id: schemaId,
    capability_id: CAPABILITY_ID,
    variant_id: variantId,
    parameter_selector_id: variantId,
    operation_id: OPERATION_ID,
    technique_id: "protocol.probe",
    minimum_assurance_profile_id: MINIMUM_ASSURANCE_PROFILE_ID,
    required_conformance_dependency_ref: REQUIRED_CONFORMANCE_DEPENDENCY_REF,
    request_semantics: semantics.request_semantics,
    response_semantics: "atqa_or_no_response",
    target_state_transition: semantics.target_state_transition,
    may_wake_halted_target: semantics.may_wake_halted_target,
    persistent_target_write: false,
    credential_data_requested: false,
    field_end_policy: "firmware_release_after_exchange",
    effect_profile_refs: ["EP-TARGET-TRANSMIT-RF"],
    command_count: 1,
    wire_request_bit_length: FIXED_REQUEST_BIT_LENGTH,
    provider_payload_byte_length: FIXED_PROVIDER_PAYLOAD_BYTES,
    maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
    fixed_response_timeout_ms: FIXED_RESPONSE_TIMEOUT_MS,
  };
  const semanticContractDigest = hashCanonicalJson(publicBasis);
  const canonicalCommandDigest = commandDigest(payload);
  return {
    payload,
    projection: deepFreeze({
      ...publicBasis,
      semantic_contract_digest: semanticContractDigest,
      canonical_command_digest: canonicalCommandDigest,
    }),
  };
}

const schemaEntries = [
  makeSchema("iso14443a.requa_atqa_v1", "requa_atqa_v1", 0x26, {
    request_semantics: "request_atqa_from_idle_targets",
    target_state_transition: "idle_to_ready_if_present",
    may_wake_halted_target: false,
  }),
  makeSchema("iso14443a.wupa_atqa_v1", "wupa_atqa_v1", 0x52, {
    request_semantics: "request_atqa_from_idle_or_halted_targets",
    target_state_transition: "idle_or_halt_to_ready_if_present",
    may_wake_halted_target: true,
  }),
];
const SCHEMA_BY_ID = new Map(schemaEntries.map((entry) => [entry.projection.schema_id, entry]));
const registryBasis = {
  version: HF14A_PROBE_COMPILER_VERSION,
  compiler_id: HF14A_PROBE_COMPILER_ID,
  source_profile_digest: SOURCE_PROFILE_DIGEST,
  schemas: schemaEntries.map((entry) => entry.projection),
};
const COMPILER_REGISTRY_DIGEST = hashCanonicalJson(registryBasis);
const manifestBasis = {
  version: HF14A_PROBE_COMPILER_VERSION,
  provider_id: PROVIDER_ID,
  compiler_id: HF14A_PROBE_COMPILER_ID,
  exposure: "provider_private",
  source_profile_digest: SOURCE_PROFILE_DIGEST,
  compiler_registry_digest: COMPILER_REGISTRY_DIGEST,
  capability_id: CAPABILITY_ID,
  operation_id: OPERATION_ID,
  minimum_assurance_profile_id: MINIMUM_ASSURANCE_PROFILE_ID,
  required_conformance_dependency_ref: REQUIRED_CONFORMANCE_DEPENDENCY_REF,
  schema_ids: [...SCHEMA_BY_ID.keys()].sort(),
  schema_variant_bindings: schemaEntries.map((entry) => ({
    schema_id: entry.projection.schema_id,
    variant_id: entry.projection.variant_id,
    parameter_selector_id: entry.projection.parameter_selector_id,
  })),
  schema_count: SCHEMA_BY_ID.size,
  maximum_command_count: 1,
  maximum_provider_payload_bytes: FIXED_PROVIDER_PAYLOAD_BYTES,
  maximum_wire_request_bits: FIXED_REQUEST_BIT_LENGTH,
  maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
  fixed_response_timeout_ms: FIXED_RESPONSE_TIMEOUT_MS,
  arbitrary_frame_input: false,
  arbitrary_rf_options: false,
  runtime_availability: "unavailable_pending_hil_conformance",
  execution_authority: false,
};
const HF14A_PROBE_COMPILER_MANIFEST = deepFreeze({
  ...manifestBasis,
  compiler_manifest_digest: hashCanonicalJson(manifestBasis),
});
const COMPILED_PROVIDER_COMMAND_CHANNEL = createCompiledProviderCommandChannel({
  version: HF14A_PROBE_COMPILER_VERSION,
  provider_id: PROVIDER_ID,
  compiler_id: HF14A_PROBE_COMPILER_ID,
  compiler_manifest_digest: HF14A_PROBE_COMPILER_MANIFEST.compiler_manifest_digest,
  compiler_registry_digest: COMPILER_REGISTRY_DIGEST,
  source_profile_digest: SOURCE_PROFILE_DIGEST,
  operation_id: OPERATION_ID,
  capability_id: CAPABILITY_ID,
  runtime_availability: "unavailable_pending_hil_conformance",
});

for (const entry of schemaEntries) {
  if (entry.payload.length !== FIXED_PROVIDER_PAYLOAD_BYTES
      || entry.payload[0] !== 0xc0
      || entry.payload.readUInt16BE(1) !== FIXED_RESPONSE_TIMEOUT_MS
      || entry.payload.readUInt16BE(3) !== FIXED_REQUEST_BIT_LENGTH
      || entry.projection.canonical_command_digest !== commandDigest(entry.payload)) {
    throw new Error("closed HF14A probe registry has an invalid fixed command encoding");
  }
  assertNoPublicByteMaterial(entry.projection, "hf14a_probe_schema");
}
assertNoPublicByteMaterial(HF14A_PROBE_SOURCE_PROFILE, "hf14a_probe_source_profile");
assertNoPublicByteMaterial(HF14A_PROBE_COMPILER_MANIFEST, "hf14a_probe_compiler_manifest");

function getHf14aProbeSchema(schemaId) {
  if (typeof schemaId !== "string" || !SCHEMA_ID_PATTERN.test(schemaId)) return null;
  return SCHEMA_BY_ID.get(schemaId)?.projection || null;
}

function compileHf14aProbe(input) {
  if (arguments.length !== 1) {
    throw new Error("HF14A probe compilation accepts one closed schema selection");
  }
  assertClosedObject(input, "hf14a_probe_selection", ["version", "schema_id"]);
  if (input.version !== HF14A_PROBE_COMPILER_VERSION) {
    throw new Error(`hf14a_probe_selection.version must be ${HF14A_PROBE_COMPILER_VERSION}`);
  }
  if (typeof input.schema_id !== "string" || !SCHEMA_ID_PATTERN.test(input.schema_id)) {
    throw new Error("hf14a_probe_selection.schema_id is not a closed probe schema");
  }
  const schema = SCHEMA_BY_ID.get(input.schema_id);
  if (!schema) throw new Error("hf14a_probe_selection.schema_id is not registered");
  const compiledBasis = {
    version: HF14A_PROBE_COMPILER_VERSION,
    provider_id: PROVIDER_ID,
    compiler_id: HF14A_PROBE_COMPILER_ID,
    compiler_manifest_digest: HF14A_PROBE_COMPILER_MANIFEST.compiler_manifest_digest,
    compiler_registry_digest: COMPILER_REGISTRY_DIGEST,
    source_profile_digest: SOURCE_PROFILE_DIGEST,
    runtime_availability: "unavailable_pending_hil_conformance",
    execution_authority: false,
    ...schema.projection,
  };
  const compiled = deepFreeze({
    ...compiledBasis,
    compiled_operation_digest: hashCanonicalJson(compiledBasis),
  });
  assertNoPublicByteMaterial(compiled, "compiled_hf14a_probe");
  COMPILED_PROBES.add(compiled);
  COMPILED_PROBE_STATE.set(compiled, {
    schema,
    provider_command_issued: false,
  });
  return compiled;
}

function assertCompiledHf14aProbe(value) {
  const state = value == null ? null : COMPILED_PROBE_STATE.get(value);
  if (!value || !state || !COMPILED_PROBES.has(value) || !Object.isFrozen(value)
      || value.canonical_command_digest !== commandDigest(state.schema.payload)) {
    throw new Error("compiled HF14A probe must come from the closed provider compiler");
  }
  assertNoPublicByteMaterial(value, "compiled_hf14a_probe");
  return value;
}

// Worker-only codec bridge. It never accepts command data and can encode only
// a branded result from the two closed schemas above. It returns a one-shot,
// byte-free command capability; only the enrolled custody seam can claim its
// sealed frame bytes. The package exports map deliberately does not expose
// this module as a consumer subpath.
function encodeCompiledHf14aProbeForProviderWorker(compiledInput) {
  if (arguments.length !== 1) {
    throw new Error("HF14A probe encoding accepts one compiled probe");
  }
  const compiled = assertCompiledHf14aProbe(compiledInput);
  const state = COMPILED_PROBE_STATE.get(compiled);
  if (state.provider_command_issued) {
    throw new Error("compiled HF14A probe has already issued its one-shot provider command");
  }
  const {
    FIXED_FRAME_BYTES,
    SOF,
    SOF_LRC,
    calculateLrc,
  } = require("./codec.js");
  const frame = Buffer.alloc(FIXED_FRAME_BYTES + state.schema.payload.length);
  try {
    frame[0] = SOF;
    frame[1] = SOF_LRC;
    frame.writeUInt16BE(HF14A_RAW_COMMAND_ID, 2);
    frame.writeUInt16BE(0, 4);
    frame.writeUInt16BE(state.schema.payload.length, 6);
    frame[8] = calculateLrc(frame.subarray(2, 8));
    state.schema.payload.copy(frame, 9);
    frame[9 + state.schema.payload.length] = calculateLrc(state.schema.payload);
    const command = COMPILED_PROVIDER_COMMAND_CHANNEL.mint({
      schema_id: compiled.schema_id,
      variant_id: compiled.variant_id,
      parameter_selector_id: compiled.parameter_selector_id,
      canonical_command_digest: compiled.canonical_command_digest,
      compiled_operation_digest: compiled.compiled_operation_digest,
      request_bytes: frame,
      maximum_response_bytes: compiled.maximum_response_bytes,
      timeout_ms: compiled.fixed_response_timeout_ms,
    });
    assertNoPublicByteMaterial(command, "compiled_hf14a_provider_command");
    state.provider_command_issued = true;
    return command;
  } finally {
    frame.fill(0);
  }
}

function assertCompiledHf14aProviderCommand(commandInput) {
  if (arguments.length !== 1) {
    throw new Error("compiled HF14A provider command assertion accepts one command");
  }
  return COMPILED_PROVIDER_COMMAND_CHANNEL.assertCommand(commandInput);
}

function claimCompiledHf14aProviderCommand(commandInput) {
  if (arguments.length !== 1) {
    throw new Error("compiled HF14A provider command claim accepts one command");
  }
  return COMPILED_PROVIDER_COMMAND_CHANNEL.claim(commandInput);
}

function invalidateCompiledHf14aProviderCommand(commandInput) {
  if (arguments.length !== 1) {
    throw new Error("compiled HF14A provider command invalidation accepts one command");
  }
  return COMPILED_PROVIDER_COMMAND_CHANNEL.invalidate(commandInput);
}

module.exports = {
  HF14A_PROBE_COMPILER_ID,
  HF14A_PROBE_COMPILER_MANIFEST,
  HF14A_PROBE_COMPILER_VERSION,
  HF14A_PROBE_SOURCE_PROFILE: deepFreeze({
    ...sourceProfileBasis,
    source_profile_digest: SOURCE_PROFILE_DIGEST,
  }),
  assertCompiledHf14aProbe,
  assertCompiledHf14aProviderCommand,
  claimCompiledHf14aProviderCommand,
  compileHf14aProbe,
  encodeCompiledHf14aProbeForProviderWorker,
  getHf14aProbeSchema,
  invalidateCompiledHf14aProviderCommand,
};
