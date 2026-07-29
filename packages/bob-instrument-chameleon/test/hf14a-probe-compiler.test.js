"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const codec = require("../lib/codec.js");
const compiler = require("../lib/hf14a-probe-compiler.js");
const operations = require("../lib/operations.js");
const {
  assertNoPublicByteMaterial,
} = require("../../../mcp/lib/instrument-provider-contract.js");

const {
  HF14A_PROBE_COMPILER_ID,
  HF14A_PROBE_COMPILER_MANIFEST,
  HF14A_PROBE_SOURCE_PROFILE,
  assertCompiledHf14aProbe,
  assertCompiledHf14aProviderCommand,
  compileHf14aProbe,
  encodeCompiledHf14aProbeForProviderWorker,
  getHf14aProbeSchema,
} = compiler;

test("closed probe registry is source-pinned, byte-free, and package-private", () => {
  assert.equal(HF14A_PROBE_COMPILER_ID, "iso14443a_closed_probe_v1");
  assert.deepEqual(HF14A_PROBE_COMPILER_MANIFEST.schema_ids, [
    "iso14443a.requa_atqa_v1",
    "iso14443a.wupa_atqa_v1",
  ]);
  assert.equal(HF14A_PROBE_COMPILER_MANIFEST.arbitrary_frame_input, false);
  assert.equal(HF14A_PROBE_COMPILER_MANIFEST.arbitrary_rf_options, false);
  assert.equal(HF14A_PROBE_COMPILER_MANIFEST.runtime_availability,
    "unavailable_pending_hil_conformance");
  assert.equal(HF14A_PROBE_COMPILER_MANIFEST.capability_id,
    "CU-HF-14A-COMPILED-PROBE");
  assert.equal(HF14A_PROBE_COMPILER_MANIFEST.operation_id, "protocol.discovery_probe");
  assert.equal(HF14A_PROBE_COMPILER_MANIFEST.minimum_assurance_profile_id,
    "enrolled_conformance_tested");
  assert.equal(HF14A_PROBE_COMPILER_MANIFEST.required_conformance_dependency_ref,
    "conformance:chameleon_hf14a_closed_probe_v1");
  assert.deepEqual(HF14A_PROBE_COMPILER_MANIFEST.schema_variant_bindings, [
    {
      schema_id: "iso14443a.requa_atqa_v1",
      variant_id: "requa_atqa_v1",
      parameter_selector_id: "requa_atqa_v1",
    },
    {
      schema_id: "iso14443a.wupa_atqa_v1",
      variant_id: "wupa_atqa_v1",
      parameter_selector_id: "wupa_atqa_v1",
    },
  ]);
  assert.equal(Object.isFrozen(HF14A_PROBE_COMPILER_MANIFEST.schema_variant_bindings), true);
  assert.equal(HF14A_PROBE_COMPILER_MANIFEST.execution_authority, false);
  assert.equal(HF14A_PROBE_COMPILER_MANIFEST.maximum_provider_payload_bytes, 6);
  assert.equal(HF14A_PROBE_COMPILER_MANIFEST.maximum_wire_request_bits, 7);
  assert.equal(HF14A_PROBE_COMPILER_MANIFEST.fixed_response_timeout_ms, 100);
  assert.deepEqual(HF14A_PROBE_SOURCE_PROFILE.source_hashes, {
    data_cmd_h: "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
    app_cmd_c: "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
    chameleon_cmd_py: "a09c9d7ade77407bbefe2a5dfb1475c995d2580422d81c326b0dc27f8baeb44d",
    rc522_h: "b2e32f301e8db38750806cd3236be7205b716bca039f765ed1940813aa730d28",
    rc522_c: "635d4d147cd884320e6fb32b37bd0e316ee32cdcc3cd55754f47dc5261c886fa",
  });
  assert.equal(assertNoPublicByteMaterial(HF14A_PROBE_COMPILER_MANIFEST), true);
  assert.equal(assertNoPublicByteMaterial(HF14A_PROBE_SOURCE_PROFILE), true);
  const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json")));
  assert.equal(Object.prototype.hasOwnProperty.call(
    packageJson.exports,
    "./hf14a-probe-compiler",
  ), false);
  assert.equal(Object.prototype.hasOwnProperty.call(
    packageJson.exports,
    "./compiled-provider-command",
  ), false);
});

test("compiler emits only byte-free one-shot capabilities for exact reviewed commands", () => {
  const cases = [
    [
      "iso14443a.requa_atqa_v1",
      "requa_atqa_v1",
      "c4ca2cef11a4c4f2bea51d70243b0fafafdd690d332c67d0753b4d4bd0e638fb",
      false,
    ],
    [
      "iso14443a.wupa_atqa_v1",
      "wupa_atqa_v1",
      "b52bd94fcb1936d26a219b64c686c5a991d87cde6210ced2c46d08bd3e09f619",
      true,
    ],
  ];
  for (const [schemaId, variantId, expectedCommandDigest, mayWakeHaltedTarget] of cases) {
    const schema = getHf14aProbeSchema(schemaId);
    assert.equal(Object.isFrozen(schema), true);
    assert.equal(Object.isFrozen(schema.effect_profile_refs), true);
    assert.equal(assertNoPublicByteMaterial(schema), true);
    assert.equal(schema.may_wake_halted_target, mayWakeHaltedTarget);
    assert.equal(schema.persistent_target_write, false);
    assert.equal(schema.credential_data_requested, false);
    assert.equal(schema.capability_id, "CU-HF-14A-COMPILED-PROBE");
    assert.equal(schema.variant_id, variantId);
    assert.equal(schema.parameter_selector_id, variantId);
    assert.equal(schema.operation_id, "protocol.discovery_probe");
    assert.equal(schema.minimum_assurance_profile_id, "enrolled_conformance_tested");
    assert.equal(schema.required_conformance_dependency_ref,
      "conformance:chameleon_hf14a_closed_probe_v1");
    assert.deepEqual(schema.effect_profile_refs, ["EP-TARGET-TRANSMIT-RF"]);
    assert.equal(schema.canonical_command_digest, expectedCommandDigest);

    const availabilityVariant = operations.getChameleonAvailabilityVariant(
      "CU-HF-14A-COMPILED-PROBE",
      variantId,
    );
    assert.ok(availabilityVariant);
    assert.equal(availabilityVariant.parameter_selector_id, schema.parameter_selector_id);
    assert.deepEqual(availabilityVariant.normalized_operations, [schema.operation_id]);
    assert.deepEqual(availabilityVariant.technique_bindings, [schema.technique_id]);
    assert.deepEqual(availabilityVariant.effect_profile_refs, schema.effect_profile_refs);

    const compiled = compileHf14aProbe({ version: 1, schema_id: schemaId });
    assert.equal(assertCompiledHf14aProbe(compiled), compiled);
    assert.equal(Object.isFrozen(compiled), true);
    assert.equal(assertNoPublicByteMaterial(compiled), true);
    assert.equal(compiled.runtime_availability, "unavailable_pending_hil_conformance");
    assert.equal(compiled.variant_id, variantId);
    assert.equal(compiled.execution_authority, false);
    for (const forbiddenField of ["command", "command_id", "data", "frame", "options", "payload", "request_byte"]) {
      assert.equal(Object.prototype.hasOwnProperty.call(compiled, forbiddenField), false);
    }
    const command = encodeCompiledHf14aProbeForProviderWorker(compiled);
    assert.equal(assertCompiledHf14aProviderCommand(command), command);
    assert.equal(Object.isFrozen(command), true);
    assert.equal(assertNoPublicByteMaterial(command), true);
    assert.equal(command.kind, "compiled_provider_command_capability");
    assert.match(command.compiled_command_id, /^compiled-command:v1-[A-Za-z0-9_-]{24}$/u);
    assert.equal(command.provider_id, compiled.provider_id);
    assert.equal(command.compiler_id, compiled.compiler_id);
    assert.equal(command.compiler_manifest_digest, compiled.compiler_manifest_digest);
    assert.equal(command.compiler_registry_digest, compiled.compiler_registry_digest);
    assert.equal(command.source_profile_digest, compiled.source_profile_digest);
    assert.equal(command.schema_id, compiled.schema_id);
    assert.equal(command.operation_id, compiled.operation_id);
    assert.equal(command.capability_id, compiled.capability_id);
    assert.equal(command.variant_id, compiled.variant_id);
    assert.equal(command.parameter_selector_id, compiled.parameter_selector_id);
    assert.equal(command.canonical_command_digest, compiled.canonical_command_digest);
    assert.equal(command.compiled_operation_digest, compiled.compiled_operation_digest);
    assert.match(command.compiled_command_capability_digest, /^[a-f0-9]{64}$/u);
    assert.equal(command.runtime_availability, "unavailable_pending_hil_conformance");
    assert.equal(command.execution_authority, false);
    assert.equal(command.production_ready, false);
    for (const forbiddenField of [
      "command", "command_id", "data", "frame", "options", "payload", "request_byte",
      "request_bytes", "provider_request_digest", "timeout_ms", "maximum_response_bytes",
    ]) {
      assert.equal(Object.prototype.hasOwnProperty.call(command, forbiddenField), false);
    }
    assert.throws(() => JSON.stringify(command), /compiled_provider_command_not_serializable/u);
    assert.throws(() => structuredClone(command));
    assert.throws(
      () => encodeCompiledHf14aProbeForProviderWorker(compiled),
      /already issued its one-shot provider command/u,
    );
  }
  assert.notEqual(
    getHf14aProbeSchema("iso14443a.requa_atqa_v1").canonical_command_digest,
    getHf14aProbeSchema("iso14443a.wupa_atqa_v1").canonical_command_digest,
  );
  assert.equal(operations.getChameleonAvailabilityVariant(
    "CU-HF-14A-COMPILED-PROBE",
    "default",
  ), null);
  assert.equal(getHf14aProbeSchema("iso14443a.default"), null);
});

test("compiled command IDs remain valid when base64url entropy begins with punctuation", {
  concurrency: false,
}, () => {
  const originalRandomBytes = crypto.randomBytes;
  try {
    for (const firstByte of [0xf8, 0xfc]) {
      crypto.randomBytes = (size) => {
        assert.equal(size, 18);
        const bytes = Buffer.alloc(size);
        bytes[0] = firstByte;
        return bytes;
      };
      const compiled = compileHf14aProbe({
        version: 1,
        schema_id: "iso14443a.requa_atqa_v1",
      });
      const command = encodeCompiledHf14aProbeForProviderWorker(compiled);
      assert.match(
        command.compiled_command_id,
        /^compiled-command:v1-[A-Za-z0-9_-]{24}$/u,
      );
    }
  } finally {
    crypto.randomBytes = originalRandomBytes;
  }
});

test("raw command, RF option, timeout, and forged compiled input cannot widen the compiler", () => {
  for (const selection of [
    { version: 1, schema_id: "iso14443a.rats_v1" },
    { version: 1, schema_id: "iso14443a.requa_atqa_v1", timeout_ms: 5000 },
    { version: 1, schema_id: "iso14443a.requa_atqa_v1", keep_rf_field: true },
    { version: 1, schema_id: "iso14443a.requa_atqa_v1", data: [0x26] },
  ]) {
    assert.throws(
      () => compileHf14aProbe(selection),
      /not registered|not a closed probe schema|unknown fields/u,
    );
  }
  assert.throws(
    () => compileHf14aProbe({ version: 1, schema_id: "iso14443a.requa_atqa_v1" }, {}),
    /accepts one closed schema selection/u,
  );
  assert.throws(
    () => encodeCompiledHf14aProbeForProviderWorker({
      schema_id: "iso14443a.requa_atqa_v1",
      canonical_command_digest: "0".repeat(64),
    }),
    /must come from the closed provider compiler/u,
  );

  const compiled = compileHf14aProbe({
    version: 1,
    schema_id: "iso14443a.requa_atqa_v1",
  });
  const command = encodeCompiledHf14aProbeForProviderWorker(compiled);
  assert.throws(
    () => assertCompiledHf14aProviderCommand({ ...command }),
    /compiled_provider_command_untrusted/u,
  );
  assert.throws(
    () => assertCompiledHf14aProviderCommand({
      ...command,
      compiler_manifest_digest: "0".repeat(64),
    }),
    /compiled_provider_command_cross_manifest/u,
  );
  assert.throws(
    () => assertCompiledHf14aProviderCommand(Promise.resolve(command)),
    /compiled_provider_command_async/u,
  );
  assert.throws(
    () => assertCompiledHf14aProviderCommand(new Proxy(command, {})),
    /compiled_provider_command_proxy/u,
  );
  assert.equal(Object.hasOwn(codec.V2_2_0_COMMAND_DATA_LIMITS, 2010), false);
  assert.equal(codec.v220CodecProfileSnapshot().command_count, 37);
  assert.throws(
    () => codec.createFrameEncoder({
      outbound_profile: codec.v220CodecProfileSnapshot(),
    }),
    /unknown fields: outbound_profile/u,
  );
});

test("hostile accessor, sparse, adorned, and symbol selections fail without invocation", () => {
  let getterCalls = 0;
  const accessor = { version: 1 };
  Object.defineProperty(accessor, "schema_id", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "iso14443a.requa_atqa_v1";
    },
  });
  assert.throws(() => compileHf14aProbe(accessor), /enumerable data field/u);
  assert.equal(getterCalls, 0);

  const sparse = [];
  sparse.length = 2;
  Object.defineProperty(sparse, 1, {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "iso14443a.requa_atqa_v1";
    },
  });
  assert.throws(() => compileHf14aProbe(sparse), /must be an object/u);
  assert.equal(getterCalls, 0);

  const adorned = [];
  adorned.version = 1;
  adorned.schema_id = "iso14443a.requa_atqa_v1";
  adorned.timeout_ms = 100;
  assert.throws(() => compileHf14aProbe(adorned), /must be an object/u);

  const symbolSelection = { version: 1, schema_id: "iso14443a.requa_atqa_v1" };
  symbolSelection[Symbol("raw")] = Buffer.from([0x26]);
  assert.throws(() => compileHf14aProbe(symbolSelection), /symbol fields/u);

  const nonEnumerable = { version: 1 };
  Object.defineProperty(nonEnumerable, "schema_id", {
    enumerable: false,
    value: "iso14443a.requa_atqa_v1",
  });
  assert.throws(() => compileHf14aProbe(nonEnumerable), /enumerable data field/u);
});
