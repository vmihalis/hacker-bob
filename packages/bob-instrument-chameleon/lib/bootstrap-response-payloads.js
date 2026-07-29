"use strict";

// Pure response-payload decoding for the source-pinned v2.2.0 bootstrap
// subset. This module cannot enumerate, open, read, or write a device. It
// accepts only frames issued by the bounded parser and an operation issued by
// the signed bootstrap compiler, then emits semantic metadata with no bytes.

const {
  V2_2_0_PROFILE_PINS,
  assertDecodedFrame,
  calculateLrc,
  eraseDecodedFrameCustodyBytes,
} = require("./codec.js");
const {
  assertCompiledChameleonBootstrapOperation,
} = require("./bootstrap-operations.js");
const {
  hashCanonicalJson,
} = require("../../bob-instrument-contracts/lib/verification-contracts.js");
const {
  CHAMELEON_SEMANTIC_MANIFEST,
  CHAMELEON_V220_CODEC_PROFILE,
  CHAMELEON_V220_SOURCE_PROFILE,
} = require("./operations.js");
const crypto = require("node:crypto");

const BOOTSTRAP_RESPONSE_PAYLOAD_VERSION = 1;
const CHAMELEON_SUCCESS_STATUS = 0x68;
const PRODUCTION_TRUSTED_CLOCK_MODE = "signed_monotonic_wall_mapping";
const GIT_REVISION_MAX_UTF8_BYTES = 128;
const CAPABILITY_ID_MAX_ENTRIES = 2048;
const CHAMELEON_BOOTSTRAP_DECODED_PAYLOADS = new WeakSet();
const CHAMELEON_GET_APP_VERSION_DECODED_PAYLOADS = new WeakSet();

const MODEL_NAME_BY_ID = Object.freeze({
  0: "Chameleon Ultra",
  1: "Chameleon Lite",
});

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

const CHAMELEON_V220_BOOTSTRAP_RESPONSE_PAYLOAD_PROFILE = deepFreeze({
  version: BOOTSTRAP_RESPONSE_PAYLOAD_VERSION,
  profile_id: "chameleon_ultra_v2_2_0_bootstrap_response_payloads_v1",
  source_profile_id: "chameleon_ultra_v2_2_0_source_pinned_v1",
  source_pins: { ...V2_2_0_PROFILE_PINS },
  success_status: CHAMELEON_SUCCESS_STATUS,
  git_revision_max_utf8_bytes: GIT_REVISION_MAX_UTF8_BYTES,
  capability_id_max_entries: CAPABILITY_ID_MAX_ENTRIES,
  command_payload_shapes: {
    1000: { encoding: "network_u8_u8", exact_byte_length: 2 },
    1017: {
      encoding: "strict_utf8",
      minimum_byte_length: 1,
      maximum_byte_length: GIT_REVISION_MAX_UTF8_BYTES,
    },
    1025: { encoding: "network_u16_u8", exact_byte_length: 3 },
    1033: { encoding: "device_model_u8", exact_byte_length: 1 },
    1035: {
      encoding: "network_u16_list",
      minimum_byte_length: 2,
      maximum_byte_length: CAPABILITY_ID_MAX_ENTRIES * 2,
      unique: true,
    },
  },
});

function encodeFixedGetAppVersionRequest() {
  const output = Buffer.alloc(10);
  output[0] = 0x11;
  output[1] = 0xef;
  output.writeUInt16BE(1000, 2);
  output.writeUInt16BE(0, 4);
  output.writeUInt16BE(0, 6);
  output[8] = calculateLrc(output.subarray(2, 8));
  output[9] = calculateLrc(Buffer.alloc(0));
  return output;
}

const fixedGetAppVersionRequest = encodeFixedGetAppVersionRequest();
const fixedGetAppVersionRequestDigest = crypto.createHash("sha256")
  .update(fixedGetAppVersionRequest)
  .digest("hex");
fixedGetAppVersionRequest.fill(0);

const CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA_BASIS = deepFreeze({
  version: BOOTSTRAP_RESPONSE_PAYLOAD_VERSION,
  schema_kind: "chameleon_get_app_version_response_schema",
  schema_id: "schema:chameleon-get-app-version-v1",
  validator_id: "chameleon_ultra.get_app_version.v1",
  provider_id: "chameleon_ultra",
  operation_id: "get_app_version",
  compiler_id: "compiler:chameleon-get-app-version-semantic-v1",
  capability_id: "capability:get-app-version",
  variant_id: "variant:rf-off-bootstrap",
  parameter_selector_id: "selector:none",
  expected_result_code: "get_app_version_ok",
  semantic_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
  source_profile_digest: CHAMELEON_V220_SOURCE_PROFILE.source_profile_digest,
  codec_profile_digest: CHAMELEON_V220_CODEC_PROFILE.codec_profile_digest,
  command_id: 1000,
  request_status: 0x0000,
  request_payload_byte_length: 0,
  canonical_request_digest: fixedGetAppVersionRequestDigest,
  response_success_status: CHAMELEON_SUCCESS_STATUS,
  response_payload_encoding: "network_u8_u8",
  response_payload_exact_byte_length: 2,
  grant_kind: "bootstrap",
  command_kind: "observe",
  effect_class: "none",
  rf_constraint: "rf_off",
});

const CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA = deepFreeze({
  ...CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA_BASIS,
  operation_schema_digest: hashCanonicalJson(
    CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA_BASIS,
  ),
});

function assertExactByteLength(data, expectedLength, label) {
  if (data.length !== expectedLength) {
    throw new Error(`${label} must contain exactly ${expectedLength} payload bytes`);
  }
}

function decodeApplicationVersion(data, label) {
  assertExactByteLength(data, 2, label);
  return `${data[0]}.${data[1]}`;
}

function decodeGitRevision(data, label) {
  if (data.length < 1 || data.length > GIT_REVISION_MAX_UTF8_BYTES) {
    throw new Error(
      `${label} must contain 1-${GIT_REVISION_MAX_UTF8_BYTES} strict UTF-8 bytes`,
    );
  }
  let value;
  try {
    value = new TextDecoder("utf-8", { fatal: true }).decode(data);
  } catch {
    throw new Error(`${label} must contain strict UTF-8`);
  }
  // Treat firmware self-reporting as hostile display text. Git describe output
  // needed by the pinned firmware fits this token alphabet; refusing whitespace,
  // bidi controls, and arbitrary Unicode prevents terminal/UI spoofing at the
  // semantic metadata boundary.
  if (!/^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,127}$/.test(value)) {
    throw new Error(`${label} must contain bounded display-safe Git metadata`);
  }
  return value;
}

function decodeBattery(data, label) {
  assertExactByteLength(data, 3, label);
  const voltageMv = data.readUInt16BE(0);
  const percent = data[2];
  if (voltageMv > 10_000) throw new Error(`${label} battery voltage exceeds 10000 mV`);
  if (percent > 100) throw new Error(`${label} battery percentage must be 0-100`);
  return deepFreeze({
    percent,
    voltage_mv: voltageMv,
    // The pinned v2.2.0 payload contains voltage and percentage only. Do not
    // invent a charging-state observation that the firmware did not report.
    charging_state: "not_reported",
  });
}

function decodeModel(data, label) {
  assertExactByteLength(data, 1, label);
  const model = MODEL_NAME_BY_ID[data[0]];
  if (model == null) throw new Error(`${label} contains an unknown v2.2.0 device model`);
  return model;
}

function decodeCapabilities(data, label) {
  if (data.length < 2 || data.length > CAPABILITY_ID_MAX_ENTRIES * 2
      || data.length % 2 !== 0) {
    throw new Error(`${label} must contain a non-empty bounded big-endian u16 list`);
  }
  const commandIds = [];
  const seen = new Set();
  for (let offset = 0; offset < data.length; offset += 2) {
    const commandId = data.readUInt16BE(offset);
    if (seen.has(commandId)) {
      throw new Error(`${label} must not contain duplicate command IDs`);
    }
    seen.add(commandId);
    commandIds.push(commandId);
  }
  return Object.freeze(commandIds);
}

function decodeCommandPayload(commandId, data, label) {
  switch (commandId) {
    case 1000:
      return Object.freeze({ application_version: decodeApplicationVersion(data, label) });
    case 1017:
      return Object.freeze({ git_revision: decodeGitRevision(data, label) });
    case 1025:
      return Object.freeze({ battery: decodeBattery(data, label) });
    case 1033:
      return Object.freeze({ model: decodeModel(data, label) });
    case 1035:
      return Object.freeze({ reported_command_ids: decodeCapabilities(data, label) });
    default:
      throw new Error(`${label} is outside the closed Chameleon bootstrap response subset`);
  }
}

function aggregateChameleonBootstrapResponsePayloads(compiledInput, framesInput) {
  if (arguments.length !== 2) {
    throw new Error(
      "bootstrap response payload aggregation accepts one compiled operation and its decoded frames",
    );
  }
  const compiled = assertCompiledChameleonBootstrapOperation(compiledInput);
  if (compiled.trusted_clock_mode !== PRODUCTION_TRUSTED_CLOCK_MODE) {
    throw new Error(
      "Chameleon bootstrap response payloads require signed monotonic wall-clock authority",
    );
  }
  if (!Array.isArray(framesInput)) {
    throw new Error("chameleon bootstrap response frames must be an array");
  }
  const expectedCommands = compiled.commands.map((command) => command.command_id);
  if (framesInput.length !== expectedCommands.length) {
    throw new Error("chameleon bootstrap response frame cardinality does not match the compiled operation");
  }

  const responseFields = {};
  for (let index = 0; index < expectedCommands.length; index += 1) {
    const label = `chameleon bootstrap response frame[${index}]`;
    const frame = assertDecodedFrame(framesInput[index], label);
    const expectedCommand = expectedCommands[index];
    if (frame.command !== expectedCommand) {
      throw new Error(`${label}.command does not match the compiled command order`);
    }
    if (frame.status !== CHAMELEON_SUCCESS_STATUS) {
      throw new Error(`${label}.status must be Chameleon success status 0x0068`);
    }
    if (frame.stream_tainted) {
      throw new Error(`${label} came from a tainted parser stream`);
    }

    // Parser frames expose defensive byte copies. Decode one copy and erase it
    // on every path; no byte-bearing value crosses this module's output seam.
    const data = frame.data;
    try {
      Object.assign(responseFields, decodeCommandPayload(expectedCommand, data, label));
    } finally {
      data.fill(0);
      eraseDecodedFrameCustodyBytes(frame);
    }
  }

  const projectionBasis = {
    version: BOOTSTRAP_RESPONSE_PAYLOAD_VERSION,
    projection_kind: "chameleon_bootstrap_response_payloads",
    payload_profile_id: CHAMELEON_V220_BOOTSTRAP_RESPONSE_PAYLOAD_PROFILE.profile_id,
    compiled_operation_digest: compiled.compiled_operation_digest,
    bootstrap_grant_projection_digest: compiled.bootstrap_grant_projection_digest,
    execution_request_digest: compiled.execution_request_digest,
    operation_id: compiled.operation_id,
    operation_digest: compiled.operation_digest,
    trusted_clock_mode: compiled.trusted_clock_mode,
    command_ids: expectedCommands,
    response_fields: responseFields,
  };
  const projection = deepFreeze({
    ...projectionBasis,
    decoded_payload_digest: hashCanonicalJson(projectionBasis),
  });
  CHAMELEON_BOOTSTRAP_DECODED_PAYLOADS.add(projection);
  return projection;
}

function decodeChameleonGetAppVersionResponsePayload(frameInput) {
  if (arguments.length !== 1) {
    throw new Error("get_app_version response decoding accepts exactly one parser frame");
  }
  const frame = assertDecodedFrame(
    frameInput,
    "chameleon get_app_version response frame",
  );
  if (frame.command !== CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.command_id) {
    throw new Error("chameleon get_app_version response command must be 1000");
  }
  if (frame.status !== CHAMELEON_SUCCESS_STATUS) {
    throw new Error(
      "chameleon get_app_version response status must be Chameleon success status 0x0068",
    );
  }
  if (frame.stream_tainted) {
    throw new Error("chameleon get_app_version response came from a tainted parser stream");
  }
  const data = frame.data;
  let applicationVersion;
  try {
    applicationVersion = decodeApplicationVersion(
      data,
      "chameleon get_app_version response frame",
    );
  } finally {
    data.fill(0);
    eraseDecodedFrameCustodyBytes(frame);
  }
  const projectionBasis = {
    version: BOOTSTRAP_RESPONSE_PAYLOAD_VERSION,
    projection_kind: "chameleon_get_app_version_semantic_payload",
    validator_id: CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.validator_id,
    provider_id: CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.provider_id,
    operation_id: CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.operation_id,
    semantic_manifest_digest:
      CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.semantic_manifest_digest,
    source_profile_digest:
      CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.source_profile_digest,
    codec_profile_digest:
      CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.codec_profile_digest,
    operation_schema_digest:
      CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.operation_schema_digest,
    command_id: CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.command_id,
    status: CHAMELEON_SUCCESS_STATUS,
    response_fields: { application_version: applicationVersion },
  };
  const projection = deepFreeze({
    ...projectionBasis,
    decoded_payload_digest: hashCanonicalJson(projectionBasis),
  });
  CHAMELEON_GET_APP_VERSION_DECODED_PAYLOADS.add(projection);
  return projection;
}

function assertChameleonGetAppVersionDecodedPayload(value) {
  if (!value || !CHAMELEON_GET_APP_VERSION_DECODED_PAYLOADS.has(value)
      || !Object.isFrozen(value)) {
    throw new Error(
      "Chameleon get_app_version decoded payload must come from the fixed source-owned validator",
    );
  }
  return value;
}

function assertChameleonBootstrapDecodedPayload(value) {
  if (!value || !CHAMELEON_BOOTSTRAP_DECODED_PAYLOADS.has(value) || !Object.isFrozen(value)) {
    throw new Error(
      "Chameleon bootstrap decoded payload must come from source-owned parser aggregation",
    );
  }
  return value;
}

module.exports = {
  BOOTSTRAP_RESPONSE_PAYLOAD_VERSION,
  CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA,
  CHAMELEON_SUCCESS_STATUS,
  CHAMELEON_V220_BOOTSTRAP_RESPONSE_PAYLOAD_PROFILE,
  aggregateChameleonBootstrapResponsePayloads,
  assertChameleonBootstrapDecodedPayload,
  assertChameleonGetAppVersionDecodedPayload,
  decodeChameleonGetAppVersionResponsePayload,
};
