"use strict";

// Provider-neutral PH-C1..PH-C7 execution boundary.
//
// Public tools supply only an opaque, pre-issued execution reference and its
// assignment/cell bindings. Provider selection, commands, transport material,
// credential bytes, and artifact bodies stay behind a privately installed
// composition root. A provider response is projected only as stimulus
// evidence; this boundary never calls it a verified security outcome.

const { types: utilTypes } = require("node:util");

const {
  readVerifiedSessionNucleus,
} = require("../../core/governance/index.js");
const {
  hashCanonicalJson,
} = require("../../core/verification/verification-contracts.js");

const PHYSICAL_TECHNIQUE_RUNTIME_VERSION = 1;
const PHYSICAL_TECHNIQUE_FAMILIES = Object.freeze([
  "credential_acquire",
  "credential_emulate",
  "credential_recover",
  "credential_write",
  "physical_observe",
  "protocol_transceive",
  "rf_trace",
]);
const EXECUTION_DISPOSITIONS = Object.freeze([
  "blocked",
  "denied",
  "inconclusive",
  "not_applicable",
  "stimulus_recorded",
]);
const RESIDUAL_EFFECT_STATES = Object.freeze([
  "none",
  "quarantined",
  "restored",
  "unknown",
]);
const REQUEST_FIELDS = Object.freeze([
  "assignment_context_digest",
  "cell_ref",
  "execution_ref",
  "family",
  "target_domain",
]);
const RESULT_FIELDS = Object.freeze([
  "artifact_refs",
  "assignment_context_digest",
  "attempt_ref",
  "cell_ref",
  "execution_disposition",
  "execution_projection_digest",
  "execution_ref",
  "family",
  "instrument_receipt_ref",
  "observation_refs",
  "residual_effect_state",
  "session_nucleus_hash",
  "technique_id",
  "verification_input_ref",
  "version",
]);
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const REF_PATTERN = /^[a-z][a-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const TECHNIQUE_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/u;

const PRODUCTION_PORTS = new WeakSet();
const PRODUCTION_PORT_STATE = new WeakMap();
const TEST_PORTS = new WeakSet();
const TEST_PORT_STATE = new WeakMap();
let installedPort = null;
const activeExecutionRefs = new Set();

function runtimeError(code, message) {
  const error = new Error(`${code}: ${message}`);
  error.code = code;
  return error;
}

function isPlainDataObject(value) {
  return value != null
    && typeof value === "object"
    && !Array.isArray(value)
    && !utilTypes.isProxy(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactDataFields(input, label, fields) {
  if (!isPlainDataObject(input)) {
    throw runtimeError("physical_technique_contract_invalid", `${label} must be a plain data object`);
  }
  const keys = Reflect.ownKeys(input);
  if (keys.some((key) => typeof key !== "string")) {
    throw runtimeError("physical_technique_contract_invalid", `${label} cannot contain symbol fields`);
  }
  const expected = [...fields].sort();
  const actual = [...keys].sort();
  if (actual.length !== expected.length
      || actual.some((field, index) => field !== expected[index])) {
    throw runtimeError(
      "physical_technique_contract_invalid",
      `${label} must carry exactly ${fields.join(", ")}`,
    );
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const values = {};
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw runtimeError(
        "physical_technique_contract_invalid",
        `${label}.${field} must be an enumerable data property`,
      );
    }
    values[field] = descriptor.value;
  }
  return values;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw runtimeError("physical_technique_contract_invalid", `${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertRef(value, label, prefix = null) {
  if (typeof value !== "string" || !REF_PATTERN.test(value) || value.includes("..")
      || (prefix != null && !value.startsWith(`${prefix}:`))) {
    throw runtimeError(
      "physical_technique_contract_invalid",
      `${label} must be an opaque ${prefix || "namespaced"} reference`,
    );
  }
  return value;
}

function assertFamily(value, label = "family") {
  if (!PHYSICAL_TECHNIQUE_FAMILIES.includes(value)) {
    throw runtimeError(
      "physical_technique_contract_invalid",
      `${label} must be a registered physical technique family`,
    );
  }
  return value;
}

function assertTargetDomain(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 253
      || value !== value.trim() || /[\\/\u0000-\u001f\u007f]/u.test(value)) {
    throw runtimeError("physical_technique_request_invalid", "target_domain is invalid");
  }
  return value;
}

function normalizePhysicalTechniqueExecutionRequest(input) {
  const value = exactDataFields(input, "physical technique execution request", REQUEST_FIELDS);
  return Object.freeze({
    version: PHYSICAL_TECHNIQUE_RUNTIME_VERSION,
    target_domain: assertTargetDomain(value.target_domain),
    family: assertFamily(value.family),
    execution_ref: assertRef(value.execution_ref, "execution_ref", "physical-execution"),
    cell_ref: assertRef(value.cell_ref, "cell_ref", "physical-cell"),
    assignment_context_digest: assertDigest(
      value.assignment_context_digest,
      "assignment_context_digest",
    ),
  });
}

function normalizeRefArray(input, label) {
  if (!Array.isArray(input) || utilTypes.isProxy(input) || input.length > 16) {
    throw runtimeError(
      "physical_technique_contract_invalid",
      `${label} must be a bounded array of opaque references`,
    );
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const values = [];
  for (let index = 0; index < input.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw runtimeError("physical_technique_contract_invalid", `${label} must be dense data`);
    }
    values.push(assertRef(descriptor.value, `${label}[${index}]`));
  }
  const extra = Reflect.ownKeys(descriptors).filter((key) => (
    key !== "length" && (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/u.test(key))
  ));
  if (extra.length > 0 || new Set(values).size !== values.length) {
    throw runtimeError(
      "physical_technique_contract_invalid",
      `${label} cannot contain extra fields or duplicate references`,
    );
  }
  return Object.freeze([...values].sort());
}

function nullableRef(value, label, prefix = null) {
  return value == null ? null : assertRef(value, label, prefix);
}

function normalizePhysicalTechniqueExecutionResult(input, expected) {
  const value = exactDataFields(input, "physical technique execution result", RESULT_FIELDS);
  if (value.version !== PHYSICAL_TECHNIQUE_RUNTIME_VERSION) {
    throw runtimeError("physical_technique_contract_invalid", "execution result.version must be 1");
  }
  const family = assertFamily(value.family, "execution result.family");
  const executionRef = assertRef(
    value.execution_ref,
    "execution result.execution_ref",
    "physical-execution",
  );
  const cellRef = assertRef(value.cell_ref, "execution result.cell_ref", "physical-cell");
  const assignmentContextDigest = assertDigest(
    value.assignment_context_digest,
    "execution result.assignment_context_digest",
  );
  const sessionNucleusHash = assertDigest(
    value.session_nucleus_hash,
    "execution result.session_nucleus_hash",
  );
  for (const [actual, wanted, field] of [
    [family, expected.family, "family"],
    [executionRef, expected.execution_ref, "execution_ref"],
    [cellRef, expected.cell_ref, "cell_ref"],
    [assignmentContextDigest, expected.assignment_context_digest, "assignment_context_digest"],
    [sessionNucleusHash, expected.session_nucleus_hash, "session_nucleus_hash"],
  ]) {
    if (actual !== wanted) {
      throw runtimeError(
        "physical_technique_binding_drift",
        `execution result ${field} does not match the authorized request`,
      );
    }
  }
  if (typeof value.technique_id !== "string" || !TECHNIQUE_PATTERN.test(value.technique_id)) {
    throw runtimeError(
      "physical_technique_contract_invalid",
      "execution result.technique_id is invalid",
    );
  }
  if (!EXECUTION_DISPOSITIONS.includes(value.execution_disposition)) {
    throw runtimeError(
      "physical_technique_contract_invalid",
      "execution result.execution_disposition is invalid",
    );
  }
  if (!RESIDUAL_EFFECT_STATES.includes(value.residual_effect_state)) {
    throw runtimeError(
      "physical_technique_contract_invalid",
      "execution result.residual_effect_state is invalid",
    );
  }
  const normalized = {
    version: PHYSICAL_TECHNIQUE_RUNTIME_VERSION,
    family,
    execution_ref: executionRef,
    cell_ref: cellRef,
    assignment_context_digest: assignmentContextDigest,
    session_nucleus_hash: sessionNucleusHash,
    attempt_ref: assertRef(value.attempt_ref, "execution result.attempt_ref", "physical-attempt"),
    technique_id: value.technique_id,
    execution_disposition: value.execution_disposition,
    residual_effect_state: value.residual_effect_state,
    instrument_receipt_ref: nullableRef(
      value.instrument_receipt_ref,
      "execution result.instrument_receipt_ref",
      "physical-execution-receipt",
    ),
    observation_refs: normalizeRefArray(value.observation_refs, "execution result.observation_refs"),
    artifact_refs: normalizeRefArray(value.artifact_refs, "execution result.artifact_refs"),
    verification_input_ref: nullableRef(
      value.verification_input_ref,
      "execution result.verification_input_ref",
      "physical-verification-input",
    ),
  };
  if (normalized.execution_disposition === "stimulus_recorded") {
    if (normalized.instrument_receipt_ref == null || normalized.verification_input_ref == null
        || !["none", "restored"].includes(normalized.residual_effect_state)) {
      throw runtimeError(
        "physical_technique_contract_invalid",
        "recorded stimulus requires an instrument receipt, verifier input, and no unresolved effect",
      );
    }
  } else if (normalized.instrument_receipt_ref != null) {
    throw runtimeError(
      "physical_technique_contract_invalid",
      "a non-recorded disposition cannot claim an instrument execution receipt",
    );
  }
  if (normalized.residual_effect_state === "unknown"
      && normalized.execution_disposition !== "inconclusive") {
    throw runtimeError(
      "physical_technique_contract_invalid",
      "an unknown residual effect must remain inconclusive",
    );
  }
  const digestBasis = { ...normalized };
  const projectionDigest = hashCanonicalJson(digestBasis);
  if (assertDigest(
    value.execution_projection_digest,
    "execution result.execution_projection_digest",
  ) !== projectionDigest) {
    throw runtimeError(
      "physical_technique_contract_invalid",
      "execution result digest does not bind its report-safe projection",
    );
  }
  return Object.freeze({ ...normalized, execution_projection_digest: projectionDigest });
}

function createTestPhysicalTechniqueExecutionPort(input) {
  const value = exactDataFields(input, "test physical technique execution port", [
    "execute",
    "test_only",
  ]);
  if (value.test_only !== true || typeof value.execute !== "function") {
    throw new Error("test physical technique execution port requires test_only and execute");
  }
  const port = Object.freeze({
    version: PHYSICAL_TECHNIQUE_RUNTIME_VERSION,
    production_ready: false,
    assurance: "test_only_in_process_executor_non_authorizing",
  });
  TEST_PORTS.add(port);
  TEST_PORT_STATE.set(port, value.execute);
  return port;
}

function createProductionPhysicalTechniqueExecutionPort(input) {
  const value = exactDataFields(input, "production physical technique execution port", [
    "composition_roots",
  ]);
  if (!Array.isArray(value.composition_roots) || utilTypes.isProxy(value.composition_roots)
      || value.composition_roots.length < 1 || value.composition_roots.length > 1024) {
    throw new Error("production physical technique execution port requires 1..1024 composition roots");
  }
  // The composition module owns the unforgeable root brand and the only
  // grant->resource->provider->vault->restore execution implementation. This
  // factory deliberately accepts no callback, readiness boolean, module path,
  // or caller-authored executor descriptor.
  const {
    assertProductionPhysicalTechniqueCompositionRoot,
    describeProductionPhysicalTechniqueCompositionRoot,
    executeProductionPhysicalTechniqueCompositionRoot,
  } = require("./physical-technique-composition-root.js");
  const descriptors = Object.getOwnPropertyDescriptors(value.composition_roots);
  const roots = [];
  const byExecutionRef = new Map();
  for (let index = 0; index < value.composition_roots.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw new Error("production physical technique composition roots must be dense data");
    }
    const root = assertProductionPhysicalTechniqueCompositionRoot(descriptor.value);
    const identity = describeProductionPhysicalTechniqueCompositionRoot(root);
    if (byExecutionRef.has(identity.execution_ref)) {
      throw new Error(`duplicate production physical execution root ${identity.execution_ref}`);
    }
    roots.push(root);
    byExecutionRef.set(identity.execution_ref, Object.freeze({ identity, root }));
  }
  for (const key of Reflect.ownKeys(descriptors)) {
    if (key === "length") continue;
    if (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/u.test(key)) {
      throw new Error("production physical technique composition roots contain an extra field");
    }
  }
  const port = Object.freeze({
    version: PHYSICAL_TECHNIQUE_RUNTIME_VERSION,
    production_ready: true,
    assurance: "bob_owned_exact_composition_root_set",
    root_count: roots.length,
  });
  const execute = async (request) => {
    const selected = byExecutionRef.get(request.execution_ref);
    if (!selected) {
      throw runtimeError(
        "physical_technique_execution_not_found",
        "the opaque execution reference is not installed in the composition root set",
      );
    }
    const exact = {
      target_domain: request.target_domain,
      family: request.family,
      execution_ref: request.execution_ref,
      cell_ref: request.cell_ref,
      assignment_context_digest: request.assignment_context_digest,
      session_nucleus_hash: request.session_nucleus_hash,
      physical_scope_axis_digest: request.physical_scope_axis_digest,
    };
    for (const [field, expected] of Object.entries(exact)) {
      if (selected.identity[field] !== expected) {
        throw runtimeError(
          "physical_technique_binding_drift",
          `installed composition root ${field} does not match the authorized request`,
        );
      }
    }
    return executeProductionPhysicalTechniqueCompositionRoot(selected.root, request);
  };
  PRODUCTION_PORTS.add(port);
  PRODUCTION_PORT_STATE.set(port, execute);
  return port;
}

function installPort(port, portSet, stateMap, label) {
  if (!port || !portSet.has(port) || !stateMap.has(port)) {
    throw new Error(`physical technique runtime requires a branded ${label}`);
  }
  if (installedPort != null) throw new Error("physical technique runtime is already installed");
  installedPort = Object.freeze({ port, execute: stateMap.get(port) });
  let active = true;
  return function uninstallPhysicalTechniqueRuntime() {
    if (active && installedPort?.port === port) {
      installedPort = null;
      active = false;
    }
  };
}

function installPhysicalTechniqueExecutionPort(port) {
  if (!port || port.production_ready !== true) {
    throw new Error("physical technique runtime requires a production-qualified composition port");
  }
  return installPort(port, PRODUCTION_PORTS, PRODUCTION_PORT_STATE, "production composition port");
}

function installTestPhysicalTechniqueExecutionPort(port) {
  return installPort(port, TEST_PORTS, TEST_PORT_STATE, "test execution port");
}

async function invokeInstalledPort(request, { allowTest = false } = {}) {
  const production = installedPort != null
    && PRODUCTION_PORTS.has(installedPort.port)
    && PRODUCTION_PORT_STATE.has(installedPort.port)
    && installedPort.port.production_ready === true;
  const test = allowTest && installedPort != null
    && TEST_PORTS.has(installedPort.port)
    && TEST_PORT_STATE.has(installedPort.port);
  if (!production && !test) {
    throw runtimeError(
      "physical_technique_runtime_unconfigured",
      "production physical technique composition root is not configured",
    );
  }
  if (activeExecutionRefs.has(request.execution_ref)) {
    throw runtimeError(
      "physical_technique_execution_in_progress",
      "the exact physical execution reference is already in progress",
    );
  }
  let nucleusBefore;
  try {
    nucleusBefore = readVerifiedSessionNucleus(request.target_domain);
  } catch {
    throw runtimeError(
      "physical_technique_session_binding_invalid",
      "current verified physical session nucleus is unavailable",
    );
  }
  if (!nucleusBefore.physical_scope) {
    throw runtimeError(
      "physical_technique_session_binding_invalid",
      "current verified session nucleus has no physical authority axis",
    );
  }
  const boundRequest = Object.freeze({
    ...request,
    session_nucleus_hash: nucleusBefore.nucleus_hash,
    physical_scope_axis_digest: nucleusBefore.physical_scope.axis_digest,
  });
  activeExecutionRefs.add(request.execution_ref);
  let raw;
  try {
    try {
      raw = await installedPort.execute(boundRequest);
    } catch (cause) {
      if (cause && typeof cause.code === "string"
          && cause.code.startsWith("physical_technique_")) throw cause;
      throw runtimeError(
        "physical_technique_runtime_unavailable",
        "physical technique composition root is unavailable",
      );
    }
    let nucleusAfter;
    try {
      nucleusAfter = readVerifiedSessionNucleus(request.target_domain);
    } catch {
      throw runtimeError(
        "physical_technique_session_binding_changed",
        "verified physical session nucleus changed during execution",
      );
    }
    if (nucleusAfter.nucleus_hash !== nucleusBefore.nucleus_hash
        || !nucleusAfter.physical_scope
        || nucleusAfter.physical_scope.axis_digest
          !== nucleusBefore.physical_scope.axis_digest) {
      throw runtimeError(
        "physical_technique_session_binding_changed",
        "verified physical authority changed during execution",
      );
    }
    return normalizePhysicalTechniqueExecutionResult(raw, {
      ...request,
      session_nucleus_hash: nucleusBefore.nucleus_hash,
    });
  } finally {
    activeExecutionRefs.delete(request.execution_ref);
  }
}

async function executePhysicalTechnique(input) {
  return invokeInstalledPort(normalizePhysicalTechniqueExecutionRequest(input));
}

async function executePhysicalTechniqueForTest(input) {
  return invokeInstalledPort(normalizePhysicalTechniqueExecutionRequest(input), { allowTest: true });
}

function physicalTechniqueRuntimeReadiness() {
  const productionReady = installedPort != null
    && installedPort.port.production_ready === true
    && PRODUCTION_PORTS.has(installedPort.port)
    && PRODUCTION_PORT_STATE.has(installedPort.port);
  return Object.freeze({
    version: PHYSICAL_TECHNIQUE_RUNTIME_VERSION,
    production_ready: productionReady,
    runtime_installed: installedPort != null,
    reason: productionReady ? null : "production_physical_technique_composition_root_not_installed",
  });
}

module.exports = Object.freeze({
  EXECUTION_DISPOSITIONS,
  PHYSICAL_TECHNIQUE_FAMILIES,
  PHYSICAL_TECHNIQUE_RUNTIME_VERSION,
  RESIDUAL_EFFECT_STATES,
  createProductionPhysicalTechniqueExecutionPort,
  createTestPhysicalTechniqueExecutionPort,
  executePhysicalTechnique,
  executePhysicalTechniqueForTest,
  installPhysicalTechniqueExecutionPort,
  installTestPhysicalTechniqueExecutionPort,
  normalizePhysicalTechniqueExecutionRequest,
  normalizePhysicalTechniqueExecutionResult,
  physicalTechniqueRuntimeReadiness,
});
