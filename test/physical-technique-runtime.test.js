"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");
const {
  PHYSICAL_TECHNIQUE_FAMILIES,
  createTestPhysicalTechniqueExecutionPort,
  executePhysicalTechnique,
  installPhysicalTechniqueExecutionPort,
  installTestPhysicalTechniqueExecutionPort,
  normalizePhysicalTechniqueExecutionRequest,
  normalizePhysicalTechniqueExecutionResult,
  physicalTechniqueRuntimeReadiness,
} = require("../mcp/domains/physical/physical-technique-runtime.js");
const {
  TOOL_REGISTRY,
} = require("../mcp/tools/tool-registry.js");

const digest = (label) => hashCanonicalJson({ label });

function request(overrides = {}) {
  return {
    target_domain: "physical-technique.example",
    family: "physical_observe",
    execution_ref: "physical-execution:observe-1",
    cell_ref: "physical-cell:observe-1",
    assignment_context_digest: digest("assignment"),
    ...overrides,
  };
}

function result(overrides = {}) {
  const basis = {
    version: 1,
    family: "physical_observe",
    execution_ref: "physical-execution:observe-1",
    cell_ref: "physical-cell:observe-1",
    assignment_context_digest: digest("assignment"),
    session_nucleus_hash: digest("nucleus"),
    attempt_ref: "physical-attempt:observe-1",
    technique_id: "credential.discovery",
    execution_disposition: "stimulus_recorded",
    residual_effect_state: "restored",
    instrument_receipt_ref: "physical-execution-receipt:observe-1",
    observation_refs: ["physical-observation:control-1", "physical-observation:positive-1"],
    artifact_refs: ["artifact:trace-opaque-1"],
    verification_input_ref: "physical-verification-input:observe-1",
    ...overrides,
  };
  return {
    ...basis,
    execution_projection_digest: hashCanonicalJson(basis),
  };
}

function expected(overrides = {}) {
  return {
    family: "physical_observe",
    execution_ref: "physical-execution:observe-1",
    cell_ref: "physical-cell:observe-1",
    assignment_context_digest: digest("assignment"),
    session_nucleus_hash: digest("nucleus"),
    ...overrides,
  };
}

test("PH-C1..PH-C7 tools are registry-driven, physical-axis bound, and expose no provider primitive", () => {
  const expectedTools = new Map([
    ["bob_physical_observe", ["target.transmit"]],
    ["bob_credential_acquire", ["target.transmit", "target.mutate", "target.destroy"]],
    ["bob_credential_recover", [
      "target.transmit", "target.present", "target.mutate", "target.destroy",
    ]],
    ["bob_credential_emulate", ["instrument.configure", "target.present"]],
    ["bob_credential_write", ["instrument.configure", "target.mutate", "target.destroy"]],
    ["bob_protocol_transceive", [
      "target.transmit", "target.present", "target.mutate", "target.destroy",
    ]],
    ["bob_rf_trace", ["target.transmit", "target.present"]],
  ]);
  const found = TOOL_REGISTRY.filter((entry) => expectedTools.has(entry.name));
  assert.equal(found.length, expectedTools.size);
  for (const tool of found) {
    assert.deepEqual(tool.role_bundles, ["evaluator-physical"]);
    assert.deepEqual(tool.required_session_axes, ["physical"]);
    assert.deepEqual(tool.effect_surface, [...expectedTools.get(tool.name)].sort());
    assert.equal(tool.mutating, true);
    assert.equal(tool.global_preapproval, false);
    assert.equal(tool.network_access, false);
    assert.equal(tool.browser_access, false);
    assert.equal(tool.sensitive_output, false);
    assert.deepEqual(tool.session_artifacts_written, ["physical-campaign/experiments/"]);
    assert.deepEqual(
      Object.keys(tool.inputSchema.properties).sort(),
      ["assignment_context_digest", "cell_ref", "execution_ref", "target_domain"],
    );
    const serialized = JSON.stringify(tool.inputSchema);
    for (const forbidden of [
      "provider_id",
      "operation_id",
      "command_id",
      "device_path",
      "transport",
      "frame",
      "apdu",
      "credential_bytes",
      "raw",
    ]) assert.equal(serialized.includes(forbidden), false, `${tool.name} leaked ${forbidden}`);
  }
});

test("physical technique requests are exact, closed, and use opaque server-issued bindings", () => {
  assert.deepEqual(normalizePhysicalTechniqueExecutionRequest(request()), {
    version: 1,
    ...request(),
  });
  for (const bad of [
    request({ family: "provider.chameleon" }),
    request({ execution_ref: "command:1000" }),
    request({ cell_ref: "physical-cell:../other" }),
    request({ assignment_context_digest: "0".repeat(63) }),
    { ...request(), provider_id: "chameleon_ultra" },
  ]) assert.throws(() => normalizePhysicalTechniqueExecutionRequest(bad));
  assert.throws(() => normalizePhysicalTechniqueExecutionRequest(new Proxy(request(), {})));
  assert.deepEqual([...PHYSICAL_TECHNIQUE_FAMILIES].sort(), [
    "credential_acquire",
    "credential_emulate",
    "credential_recover",
    "credential_write",
    "physical_observe",
    "protocol_transceive",
    "rf_trace",
  ]);
});

test("report-safe execution projection binds exact assignment, cell, nucleus, and opaque evidence", () => {
  const normalized = normalizePhysicalTechniqueExecutionResult(result(), expected());
  assert.equal(normalized.execution_disposition, "stimulus_recorded");
  assert.equal(normalized.residual_effect_state, "restored");
  assert.deepEqual(normalized.artifact_refs, ["artifact:trace-opaque-1"]);
  assert.deepEqual(normalized.observation_refs, [
    "physical-observation:control-1",
    "physical-observation:positive-1",
  ]);
  assert.equal(JSON.stringify(normalized).includes("provider"), false);
  assert.equal(JSON.stringify(normalized).includes("command"), false);

  for (const [bad, match] of [
    [result({ family: "rf_trace" }), /family/u],
    [result({ session_nucleus_hash: digest("another-nucleus") }), /session_nucleus_hash/u],
    [result({ execution_projection_digest: digest("forged") }), /digest/u],
    [result({ observation_refs: ["physical-observation:same", "physical-observation:same"] }), /duplicate/u],
    [result({ execution_disposition: "blocked" }), /non-recorded/u],
    [result({ residual_effect_state: "unknown" }), /recorded stimulus/u],
    [{ ...result(), provider_id: "chameleon_ultra" }, /exactly/u],
  ]) assert.throws(() => normalizePhysicalTechniqueExecutionResult(bad, expected()), match);
});

test("non-execution dispositions cannot launder receipts and unknown effects stay inconclusive", () => {
  const inconclusiveBasis = {
    ...result(),
    execution_disposition: "inconclusive",
    residual_effect_state: "unknown",
    instrument_receipt_ref: null,
    verification_input_ref: null,
  };
  delete inconclusiveBasis.execution_projection_digest;
  const inconclusive = {
    ...inconclusiveBasis,
    execution_projection_digest: hashCanonicalJson(inconclusiveBasis),
  };
  assert.equal(
    normalizePhysicalTechniqueExecutionResult(inconclusive, expected()).residual_effect_state,
    "unknown",
  );

  const blockedBasis = {
    ...inconclusiveBasis,
    execution_disposition: "blocked",
  };
  const blocked = {
    ...blockedBasis,
    execution_projection_digest: hashCanonicalJson(blockedBasis),
  };
  assert.throws(
    () => normalizePhysicalTechniqueExecutionResult(blocked, expected()),
    /unknown residual effect/u,
  );
});

test("test callbacks can exercise contracts but can never make the public runtime ready", async () => {
  const port = createTestPhysicalTechniqueExecutionPort({
    test_only: true,
    execute: async () => result(),
  });
  const uninstall = installTestPhysicalTechniqueExecutionPort(port);
  try {
    assert.deepEqual(physicalTechniqueRuntimeReadiness(), {
      version: 1,
      production_ready: false,
      runtime_installed: true,
      reason: "production_physical_technique_composition_root_not_installed",
    });
    await assert.rejects(
      () => executePhysicalTechnique(request()),
      (error) => error.code === "physical_technique_runtime_unconfigured",
    );
    assert.throws(
      () => installPhysicalTechniqueExecutionPort(Object.freeze({
        version: 1,
        production_ready: true,
      })),
      /branded production composition port/u,
    );
  } finally {
    uninstall();
  }
  assert.equal(physicalTechniqueRuntimeReadiness().runtime_installed, false);
});

test("family tool handlers fail before session or hardware access without a production root", async () => {
  const args = {
    target_domain: "physical-technique.example",
    execution_ref: "physical-execution:observe-1",
    cell_ref: "physical-cell:observe-1",
    assignment_context_digest: digest("assignment"),
  };
  const tools = TOOL_REGISTRY.filter((entry) => entry.role_bundles.includes("evaluator-physical")
    && entry.name.startsWith("bob_")
    && [
      "bob_physical_observe",
      "bob_credential_acquire",
      "bob_credential_recover",
      "bob_credential_emulate",
      "bob_credential_write",
      "bob_protocol_transceive",
      "bob_rf_trace",
    ].includes(entry.name));
  for (const tool of tools) {
    await assert.rejects(
      () => tool.handler(args),
      (error) => error.code === "physical_technique_runtime_unconfigured",
    );
  }
});
