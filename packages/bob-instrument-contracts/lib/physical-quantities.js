"use strict";

const { hashCanonicalJson } = require("./verification-contracts.js");

const reflectApply = Reflect.apply;
const regexpPrototypeExec = RegExp.prototype.exec;
const stringPrototypeStartsWith = String.prototype.startsWith;

const PHYSICAL_QUANTITY_VERSION = 1;
const SPATIAL_ENVELOPE_VERSION = 1;
const STIMULUS_SEQUENCE_VERSION = 1;
const PHYSICAL_ENVELOPE_REGISTRY_VERSION = 1;
const PHYSICAL_ENVELOPE_BINDING_VERSION = 1;
const OPAQUE_REF_PATTERN = /^[a-z][a-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._:-]{0,190}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const PHYSICAL_ENVELOPE_REGISTRIES = new WeakSet();
const PHYSICAL_ENVELOPE_REGISTRY_CONTEXTS = new WeakMap();

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

// Canonical units are intentionally strict. Conversion belongs at a reviewed
// provider/pack boundary; authority and grant hashes never depend on implicit
// locale, prefix, or unit conversion.
// Runtime/provider-supplied registry composition is deliberately not accepted.
// A provider quantity becomes usable only after its definition is reviewed and
// landed in this Bob-owned registry. The null prototype also prevents inherited
// names (for example `constructor`) from masquerading as registered dimensions.
const PHYSICAL_QUANTITY_REGISTRY = deepFreeze(Object.assign(Object.create(null), {
  acoustic_level: { canonical_unit: "dB_SPL", min: -300, max: 300, integer: false },
  angle: { canonical_unit: "deg", min: -360000, max: 360000, integer: false },
  battery_state: { canonical_unit: "ratio", min: 0, max: 1, integer: false },
  bandwidth: { canonical_unit: "Hz", min: 0, max: 1e15, integer: false },
  cadence: { canonical_unit: "Hz", min: 0, max: 1e12, integer: false },
  clock_uncertainty: { canonical_unit: "ms", min: 0, max: 86400000, integer: false },
  count: { canonical_unit: "count", min: 0, max: 1e12, integer: true },
  current: { canonical_unit: "A", min: -1e6, max: 1e6, integer: false },
  data_rate: { canonical_unit: "bit/s", min: 0, max: 1e15, integer: false },
  delay: { canonical_unit: "ms", min: 0, max: 86400000, integer: false },
  distance: { canonical_unit: "mm", min: 0, max: 1e12, integer: false },
  duty_cycle: { canonical_unit: "ratio", min: 0, max: 1, integer: false },
  duration: { canonical_unit: "ms", min: 0, max: 86400000, integer: false },
  energy: { canonical_unit: "J", min: 0, max: 1e15, integer: false },
  force: { canonical_unit: "N", min: 0, max: 1e12, integer: false },
  frequency: { canonical_unit: "Hz", min: 0, max: 1e15, integer: false },
  gain: { canonical_unit: "dB", min: -300, max: 300, integer: false },
  interval: { canonical_unit: "ms", min: 0, max: 86400000, integer: false },
  jitter: { canonical_unit: "ms", min: 0, max: 86400000, integer: false },
  logic_level: { canonical_unit: "V", min: -1e6, max: 1e6, integer: false },
  optical_intensity: { canonical_unit: "W/m^2", min: 0, max: 1e15, integer: false },
  power: { canonical_unit: "W", min: 0, max: 1e15, integer: false },
  rate: { canonical_unit: "1/s", min: 0, max: 1e15, integer: false },
  rf_power: { canonical_unit: "dBm", min: -300, max: 300, integer: false },
  sample_rate: { canonical_unit: "sample/s", min: 0, max: 1e15, integer: false },
  temperature: { canonical_unit: "degC", min: -273.15, max: 1e6, integer: false },
  travel: { canonical_unit: "mm", min: 0, max: 1e12, integer: false },
  voltage: { canonical_unit: "V", min: -1e6, max: 1e6, integer: false },
}));

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, requiredFields, optionalFields = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const allowed = new Set([...requiredFields, ...optionalFields]);
  const unknown = Object.keys(value).filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = requiredFields.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  return value;
}

function assertFiniteNumber(value, label) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`${label} must be a finite number`);
  }
  return value;
}

function regexpMatches(pattern, value) {
  return reflectApply(regexpPrototypeExec, pattern, [value]) !== null;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !regexpMatches(IDENTIFIER_PATTERN, value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function normalizeOpaqueRef(value, label, { prefix = null } = {}) {
  if (typeof value !== "string" || !regexpMatches(OPAQUE_REF_PATTERN, value)) {
    throw new Error(`${label} must be a namespaced opaque reference`);
  }
  if (prefix != null
      && !reflectApply(stringPrototypeStartsWith, value, [`${prefix}:`])) {
    throw new Error(`${label} must use the ${prefix}: namespace`);
  }
  return value;
}

function isRegisteredPhysicalQuantityId(value) {
  return typeof value === "string"
    && Object.prototype.hasOwnProperty.call(PHYSICAL_QUANTITY_REGISTRY, value);
}

function normalizeQuantityBound(input, label = "quantity_bound", options = {}) {
  assertClosedObject(options, `${label}.options`, [], ["expectedQuantityId", "requireUsefulBound"]);
  const expectedQuantityId = options.expectedQuantityId == null
    ? null
    : assertIdentifier(options.expectedQuantityId, `${label}.options.expectedQuantityId`);
  const requireUsefulBound = options.requireUsefulBound == null ? false : options.requireUsefulBound;
  if (typeof requireUsefulBound !== "boolean") {
    throw new Error(`${label}.options.requireUsefulBound must be a boolean`);
  }
  assertClosedObject(
    input,
    label,
    ["quantity_id", "unit"],
    ["value", "min", "max", "uncertainty", "measurement_method_ref"],
  );
  const quantityId = assertIdentifier(input.quantity_id, `${label}.quantity_id`);
  if (!isRegisteredPhysicalQuantityId(quantityId)) {
    throw new Error(`${label}.quantity_id is not registered: ${quantityId}`);
  }
  const contract = PHYSICAL_QUANTITY_REGISTRY[quantityId];
  if (expectedQuantityId != null && quantityId !== expectedQuantityId) {
    throw new Error(`${label}.quantity_id must be ${expectedQuantityId}`);
  }
  if (input.unit !== contract.canonical_unit) {
    throw new Error(`${label}.unit must be canonical ${contract.canonical_unit}`);
  }
  const hasValue = Object.prototype.hasOwnProperty.call(input, "value");
  const hasMin = Object.prototype.hasOwnProperty.call(input, "min");
  const hasMax = Object.prototype.hasOwnProperty.call(input, "max");
  if (!hasValue && !hasMin && !hasMax) {
    throw new Error(`${label} requires value, min, or max`);
  }

  const normalized = { quantity_id: quantityId, unit: contract.canonical_unit };
  for (const field of ["value", "min", "max"]) {
    if (!Object.prototype.hasOwnProperty.call(input, field)) continue;
    const value = assertFiniteNumber(input[field], `${label}.${field}`);
    if (contract.integer && !Number.isInteger(value)) {
      throw new Error(`${label}.${field} must be an integer`);
    }
    if (value < contract.min || value > contract.max) {
      throw new Error(`${label}.${field} must be between ${contract.min} and ${contract.max}`);
    }
    normalized[field] = value;
  }
  if (hasMin && hasMax && normalized.min > normalized.max) {
    throw new Error(`${label}.min must be <= ${label}.max`);
  }
  if (hasValue && hasMin && normalized.value < normalized.min) {
    throw new Error(`${label}.value must be >= ${label}.min`);
  }
  if (hasValue && hasMax && normalized.value > normalized.max) {
    throw new Error(`${label}.value must be <= ${label}.max`);
  }
  if (Object.prototype.hasOwnProperty.call(input, "uncertainty")) {
    assertClosedObject(input.uncertainty, `${label}.uncertainty`, ["value", "unit"]);
    if (input.uncertainty.unit !== contract.canonical_unit) {
      throw new Error(`${label}.uncertainty.unit must be canonical ${contract.canonical_unit}`);
    }
    const uncertaintyValue = assertFiniteNumber(
      input.uncertainty.value,
      `${label}.uncertainty.value`,
    );
    if (uncertaintyValue < 0) {
      throw new Error(`${label}.uncertainty.value must be >= 0`);
    }
    if (contract.integer && !Number.isInteger(uncertaintyValue)) {
      throw new Error(`${label}.uncertainty.value must be an integer`);
    }
    if (uncertaintyValue > contract.max - contract.min) {
      throw new Error(`${label}.uncertainty.value exceeds the registered quantity range`);
    }
    if (hasValue && (
      normalized.value - uncertaintyValue < contract.min
      || normalized.value + uncertaintyValue > contract.max
    )) {
      throw new Error(`${label}.uncertainty is incompatible with the registered ${quantityId} range`);
    }
    if (requireUsefulBound && uncertaintyValue > 0) {
      if (hasMin && hasMax) {
        const declaredSpan = normalized.max - normalized.min;
        if (uncertaintyValue * 2 >= declaredSpan) {
          throw new Error(`${label}.uncertainty band must be narrower than the declared bound`);
        }
      } else if (hasValue && contract.min >= 0) {
        const magnitudeAboveFloor = normalized.value - contract.min;
        if (uncertaintyValue >= magnitudeAboveFloor) {
          throw new Error(`${label}.uncertainty must be less than the useful value above its registered floor`);
        }
      } else if (hasValue) {
        const registeredSpan = contract.max - contract.min;
        if (uncertaintyValue * 2 >= registeredSpan) {
          throw new Error(`${label}.uncertainty band must be narrower than the registered dimension`);
        }
      } else if (!hasValue) {
        throw new Error(`${label} requires a finite declared bound when useful uncertainty is required`);
      }
    }
    normalized.uncertainty = deepFreeze({
      value: uncertaintyValue,
      unit: contract.canonical_unit,
    });
  }
  if (Object.prototype.hasOwnProperty.call(input, "measurement_method_ref")) {
    normalized.measurement_method_ref = normalizeOpaqueRef(
      input.measurement_method_ref,
      `${label}.measurement_method_ref`,
      { prefix: "measurement" },
    );
  }
  return deepFreeze(normalized);
}

function normalizeRefArray(value, label, { prefix = null } = {}) {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  const normalized = value.map((item, index) => normalizeOpaqueRef(item, `${label}[${index}]`, { prefix }));
  const sorted = [...new Set(normalized)].sort();
  if (sorted.length !== normalized.length) throw new Error(`${label} must not contain duplicates`);
  return Object.freeze(sorted);
}

function normalizeSpatialEnvelope(input, label = "spatial_envelope") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "envelope_ref",
      "coordinate_frame_ref",
      "zone_ref",
      "source_pose_ref",
      "target_pose_ref",
      "distance",
      "barrier_refs",
      "measurement_method_ref",
    ],
    ["orientation"],
  );
  if (input.version !== SPATIAL_ENVELOPE_VERSION) {
    throw new Error(`${label}.version must be ${SPATIAL_ENVELOPE_VERSION}`);
  }
  const normalized = {
    version: SPATIAL_ENVELOPE_VERSION,
    envelope_ref: normalizeOpaqueRef(input.envelope_ref, `${label}.envelope_ref`, { prefix: "spatial-envelope" }),
    coordinate_frame_ref: normalizeOpaqueRef(input.coordinate_frame_ref, `${label}.coordinate_frame_ref`, { prefix: "frame" }),
    zone_ref: normalizeOpaqueRef(input.zone_ref, `${label}.zone_ref`, { prefix: "zone" }),
    source_pose_ref: normalizeOpaqueRef(input.source_pose_ref, `${label}.source_pose_ref`, { prefix: "pose" }),
    target_pose_ref: normalizeOpaqueRef(input.target_pose_ref, `${label}.target_pose_ref`, { prefix: "pose" }),
    distance: normalizeQuantityBound(input.distance, `${label}.distance`, {
      expectedQuantityId: "distance",
      requireUsefulBound: true,
    }),
    barrier_refs: normalizeRefArray(input.barrier_refs, `${label}.barrier_refs`, { prefix: "barrier" }),
    measurement_method_ref: normalizeOpaqueRef(
      input.measurement_method_ref,
      `${label}.measurement_method_ref`,
      { prefix: "measurement" },
    ),
  };
  if (input.orientation != null) {
    normalized.orientation = normalizeQuantityBound(
      input.orientation,
      `${label}.orientation`,
      { expectedQuantityId: "angle", requireUsefulBound: true },
    );
  }
  return deepFreeze(normalized);
}

function normalizeStimulusStep(input, label) {
  assertClosedObject(
    input,
    label,
    ["step_id", "operation_ref", "interval_after_previous"],
    ["jitter", "delay", "cadence", "precondition_ref"],
  );
  const normalized = {
    step_id: assertIdentifier(input.step_id, `${label}.step_id`),
    operation_ref: normalizeOpaqueRef(input.operation_ref, `${label}.operation_ref`, { prefix: "operation" }),
    interval_after_previous: normalizeQuantityBound(
      input.interval_after_previous,
      `${label}.interval_after_previous`,
      { expectedQuantityId: "interval" },
    ),
  };
  for (const [field, quantityId] of [
    ["jitter", "jitter"],
    ["delay", "delay"],
    ["cadence", "cadence"],
  ]) {
    if (input[field] != null) {
      normalized[field] = normalizeQuantityBound(
        input[field],
        `${label}.${field}`,
        { expectedQuantityId: quantityId },
      );
    }
  }
  if (input.precondition_ref != null) {
    normalized.precondition_ref = normalizeOpaqueRef(
      input.precondition_ref,
      `${label}.precondition_ref`,
      { prefix: "precondition" },
    );
  }
  return deepFreeze(normalized);
}

function normalizeStimulusSequence(input, label = "stimulus_sequence") {
  assertClosedObject(input, label, ["version", "sequence_ref", "retry_identity_ref", "steps"]);
  if (input.version !== STIMULUS_SEQUENCE_VERSION) {
    throw new Error(`${label}.version must be ${STIMULUS_SEQUENCE_VERSION}`);
  }
  if (!Array.isArray(input.steps) || input.steps.length === 0 || input.steps.length > 1024) {
    throw new Error(`${label}.steps must contain 1-1024 ordered steps`);
  }
  const steps = input.steps.map((step, index) => normalizeStimulusStep(step, `${label}.steps[${index}]`));
  const ids = new Set(steps.map((step) => step.step_id));
  if (ids.size !== steps.length) throw new Error(`${label}.steps must have unique step_id values`);
  return deepFreeze({
    version: STIMULUS_SEQUENCE_VERSION,
    sequence_ref: normalizeOpaqueRef(input.sequence_ref, `${label}.sequence_ref`, { prefix: "stimulus-sequence" }),
    retry_identity_ref: normalizeOpaqueRef(
      input.retry_identity_ref,
      `${label}.retry_identity_ref`,
      { prefix: "retry" },
    ),
    steps: Object.freeze(steps),
  });
}

function normalizeEnvelopeDefinitionArray(value, label, normalizeDefinition, refField) {
  if (!Array.isArray(value) || value.length > 4096) {
    throw new Error(`${label} must be an array with at most 4096 entries`);
  }
  const definitions = new Map();
  for (let index = 0; index < value.length; index += 1) {
    const definition = normalizeDefinition(value[index], `${label}[${index}]`);
    const ref = definition[refField];
    if (definitions.has(ref)) throw new Error(`${label} has duplicate reference ${ref}`);
    definitions.set(ref, definition);
  }
  return definitions;
}

function buildPhysicalEnvelopeRegistry(input) {
  assertClosedObject(
    input,
    "physical_envelope_registry",
    ["version", "spatial_envelopes", "stimulus_sequences"],
  );
  if (input.version !== PHYSICAL_ENVELOPE_REGISTRY_VERSION) {
    throw new Error(`physical_envelope_registry.version must be ${PHYSICAL_ENVELOPE_REGISTRY_VERSION}`);
  }
  const spatialDefinitions = normalizeEnvelopeDefinitionArray(
    input.spatial_envelopes,
    "physical_envelope_registry.spatial_envelopes",
    normalizeSpatialEnvelope,
    "envelope_ref",
  );
  const stimulusDefinitions = normalizeEnvelopeDefinitionArray(
    input.stimulus_sequences,
    "physical_envelope_registry.stimulus_sequences",
    normalizeStimulusSequence,
    "sequence_ref",
  );
  if (spatialDefinitions.size + stimulusDefinitions.size === 0) {
    throw new Error("physical_envelope_registry requires at least one definition");
  }

  const spatialDigests = new Map(
    [...spatialDefinitions.entries()].map(([ref, definition]) => [ref, hashCanonicalJson(definition)]),
  );
  const stimulusDigests = new Map(
    [...stimulusDefinitions.entries()].map(([ref, definition]) => [ref, hashCanonicalJson(definition)]),
  );
  const spatialRefs = Object.freeze([...spatialDigests.keys()].sort());
  const stimulusRefs = Object.freeze([...stimulusDigests.keys()].sort());
  const registryDigest = hashCanonicalJson({
    version: PHYSICAL_ENVELOPE_REGISTRY_VERSION,
    spatial_envelopes: spatialRefs.map((ref) => ({ ref, definition_digest: spatialDigests.get(ref) })),
    stimulus_sequences: stimulusRefs.map((ref) => ({ ref, definition_digest: stimulusDigests.get(ref) })),
  });
  const registry = Object.freeze({
    version: PHYSICAL_ENVELOPE_REGISTRY_VERSION,
    registry_digest: registryDigest,
    hasSpatialEnvelopeRef(ref) {
      return spatialDigests.has(ref);
    },
    hasStimulusSequenceRef(ref) {
      return stimulusDigests.has(ref);
    },
    spatialEnvelopeRefs() {
      return spatialRefs;
    },
    stimulusSequenceRefs() {
      return stimulusRefs;
    },
  });
  PHYSICAL_ENVELOPE_REGISTRIES.add(registry);
  PHYSICAL_ENVELOPE_REGISTRY_CONTEXTS.set(registry, {
    spatialDigests,
    stimulusDigests,
  });
  return registry;
}

function assertPhysicalEnvelopeRegistry(registry) {
  if (!registry || !PHYSICAL_ENVELOPE_REGISTRIES.has(registry)) {
    throw new Error("physical envelope registry must be a closed Bob registry");
  }
  return registry;
}

function bindPhysicalEnvelopeRef(value, registry, label, kind) {
  assertPhysicalEnvelopeRegistry(registry);
  const spatial = kind === "spatial_envelope";
  const prefix = spatial ? "spatial-envelope" : "stimulus-sequence";
  const ref = normalizeOpaqueRef(value, label, { prefix });
  const context = PHYSICAL_ENVELOPE_REGISTRY_CONTEXTS.get(registry);
  const definitionDigest = (spatial ? context.spatialDigests : context.stimulusDigests).get(ref);
  if (!definitionDigest) throw new Error(`${label} is not registered exactly: ${ref}`);
  return deepFreeze({
    version: PHYSICAL_ENVELOPE_BINDING_VERSION,
    reference_kind: kind,
    ref,
    definition_digest: definitionDigest,
    registry_digest: registry.registry_digest,
  });
}

function bindSpatialEnvelopeRef(value, registry, label = "spatial_envelope_ref") {
  return bindPhysicalEnvelopeRef(value, registry, label, "spatial_envelope");
}

function bindStimulusSequenceRef(value, registry, label = "stimulus_sequence_ref") {
  return bindPhysicalEnvelopeRef(value, registry, label, "stimulus_sequence");
}

function physicalEnvelopeRegistryDigest(registry) {
  return assertPhysicalEnvelopeRegistry(registry).registry_digest;
}

function physicalQuantityRegistryDigest() {
  return hashCanonicalJson({
    version: PHYSICAL_QUANTITY_VERSION,
    quantities: PHYSICAL_QUANTITY_REGISTRY,
  });
}

function spatialEnvelopeDigest(value) {
  return hashCanonicalJson(normalizeSpatialEnvelope(value));
}

function stimulusSequenceDigest(value) {
  return hashCanonicalJson(normalizeStimulusSequence(value));
}

module.exports = {
  OPAQUE_REF_PATTERN,
  PHYSICAL_ENVELOPE_BINDING_VERSION,
  PHYSICAL_ENVELOPE_REGISTRY_VERSION,
  PHYSICAL_QUANTITY_REGISTRY,
  PHYSICAL_QUANTITY_VERSION,
  SPATIAL_ENVELOPE_VERSION,
  STIMULUS_SEQUENCE_VERSION,
  bindSpatialEnvelopeRef,
  bindStimulusSequenceRef,
  buildPhysicalEnvelopeRegistry,
  isRegisteredPhysicalQuantityId,
  normalizeOpaqueRef,
  normalizeQuantityBound,
  normalizeSpatialEnvelope,
  normalizeStimulusSequence,
  physicalEnvelopeRegistryDigest,
  physicalQuantityRegistryDigest,
  spatialEnvelopeDigest,
  stimulusSequenceDigest,
};
