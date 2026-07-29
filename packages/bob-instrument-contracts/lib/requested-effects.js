"use strict";

const { hashCanonicalJson } = require("./verification-contracts.js");
const {
  bindSpatialEnvelopeRef,
  bindStimulusSequenceRef,
  isRegisteredPhysicalQuantityId,
  normalizeOpaqueRef,
  normalizeQuantityBound,
  physicalEnvelopeRegistryDigest,
} = require("./physical-quantities.js");

const REQUESTED_EFFECT_VERSION = 1;
const EFFECT_TEMPLATE_VERSION = 1;
const EFFECT_SUBJECT_KINDS = Object.freeze(["instrument", "target", "environment"]);
const EFFECT_ACTIONS = Object.freeze([
  "observe",
  "configure",
  "transmit",
  "present",
  "mutate",
  "actuate",
  "administer",
  "destroy",
]);
const EFFECT_CHANNELS = Object.freeze([
  "instrument_local",
  "rf",
  "contact",
  "usb",
  "ble",
  "network",
  "gpio",
  "optical",
  "acoustic",
  "manual",
  "other",
]);
const EFFECT_PERSISTENCE_VALUES = Object.freeze(["none", "ephemeral", "persistent", "irreversible"]);
const EFFECT_SURFACE_VALUES = Object.freeze([
  "environment.actuate",
  "environment.observe",
  "environment.transmit",
  "instrument.administer",
  "instrument.configure",
  "instrument.destroy",
  "instrument.observe",
  "instrument.transmit",
  "target.destroy",
  "target.mutate",
  "target.observe",
  "target.present",
  "target.transmit",
]);
const EFFECT_SURFACE_SET = new Set(EFFECT_SURFACE_VALUES);
const EFFECT_TEMPLATE_ID_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const BOUND_ID_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const BOUND_KINDS = Object.freeze([
  "reference",
  "integer",
  "number",
  "boolean",
  "enum",
  "quantity",
  "timestamp",
  "spatial_envelope",
  "stimulus_sequence",
]);
const EFFECT_TEMPLATE_REGISTRIES = new WeakSet();
const EFFECT_TEMPLATE_REGISTRY_CONTEXTS = new WeakMap();
const PROTECTED_ENVELOPE_REF_PREFIXES = new Set(["spatial-envelope", "stimulus-sequence"]);

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

function assertClosedObject(value, label, requiredFields, optionalFields = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const allowed = new Set([...requiredFields, ...optionalFields]);
  const unknown = Object.keys(value).filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = requiredFields.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  return value;
}

function assertEnum(value, values, label) {
  if (!values.includes(value)) throw new Error(`${label} must be one of ${values.join(", ")}`);
  return value;
}

function assertFiniteNumber(value, label, { integer = false, min = null, max = null } = {}) {
  if (typeof value !== "number" || !Number.isFinite(value) || (integer && !Number.isInteger(value))) {
    throw new Error(`${label} must be a finite ${integer ? "integer" : "number"}`);
  }
  if (min != null && value < min) throw new Error(`${label} must be >= ${min}`);
  if (max != null && value > max) throw new Error(`${label} must be <= ${max}`);
  return value;
}

function normalizeBoundContract(input, label, { physicalEnvelopeRegistry = null } = {}) {
  assertClosedObject(
    input,
    label,
    ["kind", "required"],
    ["ref_prefix", "min", "max", "values", "quantity_id", "require_useful_bound"],
  );
  const kind = assertEnum(input.kind, BOUND_KINDS, `${label}.kind`);
  if (typeof input.required !== "boolean") throw new Error(`${label}.required must be a boolean`);
  const normalized = { kind, required: input.required };
  if (kind === "reference") {
    const allowed = new Set(["kind", "required", "ref_prefix"]);
    const wrong = Object.keys(input).filter((field) => !allowed.has(field));
    if (wrong.length > 0) throw new Error(`${label} has fields invalid for reference: ${wrong.sort().join(", ")}`);
    if (input.ref_prefix != null) {
      if (typeof input.ref_prefix !== "string" || !/^[a-z][a-z0-9._-]{0,63}$/.test(input.ref_prefix)) {
        throw new Error(`${label}.ref_prefix must be a lowercase namespace`);
      }
      normalized.ref_prefix = input.ref_prefix;
      if (PROTECTED_ENVELOPE_REF_PREFIXES.has(input.ref_prefix)) {
        throw new Error(`${label} must use a registered ${input.ref_prefix} bound kind`);
      }
    }
  } else if (kind === "integer" || kind === "number") {
    const allowed = new Set(["kind", "required", "min", "max"]);
    const wrong = Object.keys(input).filter((field) => !allowed.has(field));
    if (wrong.length > 0) throw new Error(`${label} has fields invalid for ${kind}: ${wrong.sort().join(", ")}`);
    if (input.min != null) normalized.min = assertFiniteNumber(input.min, `${label}.min`, { integer: kind === "integer" });
    if (input.max != null) normalized.max = assertFiniteNumber(input.max, `${label}.max`, { integer: kind === "integer" });
    if (normalized.min != null && normalized.max != null && normalized.min > normalized.max) {
      throw new Error(`${label}.min must be <= ${label}.max`);
    }
  } else if (kind === "enum") {
    const allowed = new Set(["kind", "required", "values"]);
    const wrong = Object.keys(input).filter((field) => !allowed.has(field));
    if (wrong.length > 0) throw new Error(`${label} has fields invalid for enum: ${wrong.sort().join(", ")}`);
    if (!Array.isArray(input.values) || input.values.length === 0) {
      throw new Error(`${label}.values must be a non-empty array`);
    }
    const values = input.values.map((value, index) => {
      if (typeof value !== "string" || !value.trim()) throw new Error(`${label}.values[${index}] must be a string`);
      return value.trim();
    });
    const sorted = [...new Set(values)].sort();
    if (sorted.length !== values.length) throw new Error(`${label}.values must be unique`);
    normalized.values = Object.freeze(sorted);
  } else if (kind === "quantity") {
    const allowed = new Set(["kind", "required", "quantity_id", "require_useful_bound"]);
    const wrong = Object.keys(input).filter((field) => !allowed.has(field));
    if (wrong.length > 0) throw new Error(`${label} has fields invalid for quantity: ${wrong.sort().join(", ")}`);
    if (!isRegisteredPhysicalQuantityId(input.quantity_id)) {
      throw new Error(`${label}.quantity_id is not registered`);
    }
    normalized.quantity_id = input.quantity_id;
    if (input.require_useful_bound != null && typeof input.require_useful_bound !== "boolean") {
      throw new Error(`${label}.require_useful_bound must be a boolean`);
    }
    normalized.require_useful_bound = input.require_useful_bound === true;
  } else if (kind === "spatial_envelope" || kind === "stimulus_sequence") {
    const wrong = Object.keys(input).filter((field) => !["kind", "required"].includes(field));
    if (wrong.length > 0) {
      throw new Error(`${label} has fields invalid for ${kind}: ${wrong.sort().join(", ")}`);
    }
    if (!physicalEnvelopeRegistry) {
      throw new Error(`${label} requires a closed physical envelope registry`);
    }
    normalized.registry_digest = physicalEnvelopeRegistryDigest(physicalEnvelopeRegistry);
  } else {
    const wrong = Object.keys(input).filter((field) => !["kind", "required"].includes(field));
    if (wrong.length > 0) throw new Error(`${label} has fields invalid for ${kind}: ${wrong.sort().join(", ")}`);
  }
  return deepFreeze(normalized);
}

function defineEffectTemplate(input, label = "effect_template", options = {}) {
  assertClosedObject(options, `${label}.options`, [], ["physicalEnvelopeRegistry"]);
  const physicalEnvelopeRegistry = options.physicalEnvelopeRegistry || null;
  if (physicalEnvelopeRegistry) physicalEnvelopeRegistryDigest(physicalEnvelopeRegistry);
  assertClosedObject(
    input,
    label,
    ["version", "template_id", "subject_kind", "action", "channel", "persistence", "bounds"],
  );
  if (input.version !== EFFECT_TEMPLATE_VERSION) {
    throw new Error(`${label}.version must be ${EFFECT_TEMPLATE_VERSION}`);
  }
  if (typeof input.template_id !== "string" || !EFFECT_TEMPLATE_ID_PATTERN.test(input.template_id)) {
    throw new Error(`${label}.template_id must be a lowercase identifier`);
  }
  const subjectKind = assertEnum(input.subject_kind, EFFECT_SUBJECT_KINDS, `${label}.subject_kind`);
  const action = assertEnum(input.action, EFFECT_ACTIONS, `${label}.action`);
  const effectSurface = `${subjectKind}.${action}`;
  if (!EFFECT_SURFACE_SET.has(effectSurface)) {
    throw new Error(`${label} has unsupported subject/action surface ${effectSurface}`);
  }
  const channel = assertEnum(input.channel, EFFECT_CHANNELS, `${label}.channel`);
  const persistence = assertEnum(input.persistence, EFFECT_PERSISTENCE_VALUES, `${label}.persistence`);
  if (!isPlainObject(input.bounds)) throw new Error(`${label}.bounds must be an object`);
  const bounds = {};
  for (const boundId of Object.keys(input.bounds).sort()) {
    if (!BOUND_ID_PATTERN.test(boundId)) throw new Error(`${label}.bounds has invalid bound ID ${boundId}`);
    bounds[boundId] = normalizeBoundContract(
      input.bounds[boundId],
      `${label}.bounds.${boundId}`,
      { physicalEnvelopeRegistry },
    );
  }
  const contract = {
    version: EFFECT_TEMPLATE_VERSION,
    template_id: input.template_id,
    subject_kind: subjectKind,
    action,
    channel,
    persistence,
    bounds: deepFreeze(bounds),
  };
  return deepFreeze({ ...contract, template_digest: hashCanonicalJson(contract) });
}

function buildEffectTemplateRegistry(definitions, options = {}) {
  assertClosedObject(options, "effect_template_registry.options", [], ["physicalEnvelopeRegistry"]);
  const physicalEnvelopeRegistry = options.physicalEnvelopeRegistry || null;
  if (physicalEnvelopeRegistry) physicalEnvelopeRegistryDigest(physicalEnvelopeRegistry);
  if (!Array.isArray(definitions)) throw new Error("effect template definitions must be an array");
  const templates = new Map();
  for (let index = 0; index < definitions.length; index += 1) {
    const template = defineEffectTemplate(
      definitions[index],
      `effect_templates[${index}]`,
      { physicalEnvelopeRegistry },
    );
    if (templates.has(template.template_id)) {
      throw new Error(`duplicate effect template ID ${template.template_id}`);
    }
    templates.set(template.template_id, template);
  }
  const ordered = [...templates.values()].sort((left, right) => left.template_id.localeCompare(right.template_id));
  const ids = Object.freeze(ordered.map((template) => template.template_id));
  const registryDigest = hashCanonicalJson({
    version: EFFECT_TEMPLATE_VERSION,
    templates: ordered,
  });
  const registry = Object.freeze({
    version: EFFECT_TEMPLATE_VERSION,
    registry_digest: registryDigest,
    get(templateId) {
      return templates.get(templateId) || null;
    },
    has(templateId) {
      return templates.has(templateId);
    },
    ids() {
      return ids;
    },
  });
  EFFECT_TEMPLATE_REGISTRIES.add(registry);
  EFFECT_TEMPLATE_REGISTRY_CONTEXTS.set(registry, { physicalEnvelopeRegistry });
  return registry;
}

function assertEffectTemplateRegistry(registry) {
  if (!registry || !EFFECT_TEMPLATE_REGISTRIES.has(registry)
      || !EFFECT_TEMPLATE_REGISTRY_CONTEXTS.has(registry)
      || !Object.isFrozen(registry)) {
    throw new Error("effect template registry must be a closed Bob registry");
  }
  return registry;
}

function normalizeBoundValue(value, contract, label, { physicalEnvelopeRegistry = null } = {}) {
  if (contract.kind === "reference") {
    const ref = normalizeOpaqueRef(value, label, { prefix: contract.ref_prefix || null });
    const prefix = ref.slice(0, ref.indexOf(":"));
    if (PROTECTED_ENVELOPE_REF_PREFIXES.has(prefix)) {
      throw new Error(`${label} must use a registered ${prefix} bound kind`);
    }
    return ref;
  }
  if (contract.kind === "integer" || contract.kind === "number") {
    return assertFiniteNumber(value, label, {
      integer: contract.kind === "integer",
      min: contract.min,
      max: contract.max,
    });
  }
  if (contract.kind === "boolean") {
    if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
    return value;
  }
  if (contract.kind === "enum") return assertEnum(value, contract.values, label);
  if (contract.kind === "quantity") {
    return normalizeQuantityBound(value, label, {
      expectedQuantityId: contract.quantity_id,
      requireUsefulBound: contract.require_useful_bound,
    });
  }
  if (contract.kind === "spatial_envelope" || contract.kind === "stimulus_sequence") {
    if (!physicalEnvelopeRegistry) {
      throw new Error(`${label} requires a closed physical envelope registry`);
    }
    if (physicalEnvelopeRegistryDigest(physicalEnvelopeRegistry) !== contract.registry_digest) {
      throw new Error(`${label} physical envelope registry digest does not match the template`);
    }
    return contract.kind === "spatial_envelope"
      ? bindSpatialEnvelopeRef(value, physicalEnvelopeRegistry, label)
      : bindStimulusSequenceRef(value, physicalEnvelopeRegistry, label);
  }
  if (contract.kind === "timestamp") {
    if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
      throw new Error(`${label} must be an ISO-8601 timestamp`);
    }
    const canonical = new Date(value).toISOString();
    if (canonical !== value) throw new Error(`${label} must use canonical UTC ISO-8601 form`);
    return value;
  }
  throw new Error(`${label} uses unknown bound kind ${contract.kind}`);
}

function normalizeRequestedEffect(input, registry, label = "requested_effect") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "template_id",
      "template_digest",
      "subject_ref",
      "subject_kind",
      "action",
      "channel",
      "persistence",
      "bounds",
    ],
  );
  if (!registry || !EFFECT_TEMPLATE_REGISTRIES.has(registry)) {
    throw new Error("effect template registry must be a closed Bob registry");
  }
  const registryContext = EFFECT_TEMPLATE_REGISTRY_CONTEXTS.get(registry);
  if (input.version !== REQUESTED_EFFECT_VERSION) {
    throw new Error(`${label}.version must be ${REQUESTED_EFFECT_VERSION}`);
  }
  const template = registry.get(input.template_id);
  if (!template) throw new Error(`${label}.template_id is not registered: ${input.template_id}`);
  if (typeof input.template_digest !== "string" || !HASH_PATTERN.test(input.template_digest)) {
    throw new Error(`${label}.template_digest must be a lowercase SHA-256 digest`);
  }
  if (input.template_digest !== template.template_digest) {
    throw new Error(`${label}.template_digest does not match the registered template`);
  }
  for (const field of ["subject_kind", "action", "channel", "persistence"]) {
    if (input[field] !== template[field]) {
      throw new Error(`${label}.${field} does not match the registered template`);
    }
  }
  if (!isPlainObject(input.bounds)) throw new Error(`${label}.bounds must be an object`);
  const unknownBounds = Object.keys(input.bounds)
    .filter((boundId) => !Object.prototype.hasOwnProperty.call(template.bounds, boundId))
    .sort();
  if (unknownBounds.length > 0) throw new Error(`${label}.bounds has unknown bounds: ${unknownBounds.join(", ")}`);
  const missingBounds = Object.entries(template.bounds)
    .filter(([, contract]) => contract.required)
    .map(([boundId]) => boundId)
    .filter((boundId) => !Object.prototype.hasOwnProperty.call(input.bounds, boundId))
    .sort();
  if (missingBounds.length > 0) throw new Error(`${label}.bounds is missing: ${missingBounds.join(", ")}`);
  const bounds = {};
  for (const boundId of Object.keys(input.bounds).sort()) {
    bounds[boundId] = normalizeBoundValue(
      input.bounds[boundId],
      template.bounds[boundId],
      `${label}.bounds.${boundId}`,
      registryContext,
    );
  }
  return deepFreeze({
    version: REQUESTED_EFFECT_VERSION,
    template_id: template.template_id,
    template_digest: template.template_digest,
    subject_ref: normalizeOpaqueRef(input.subject_ref, `${label}.subject_ref`, { prefix: template.subject_kind }),
    subject_kind: template.subject_kind,
    action: template.action,
    channel: template.channel,
    persistence: template.persistence,
    bounds: deepFreeze(bounds),
  });
}

function normalizeRequestedEffects(values, registry, label = "requested_effects") {
  if (!Array.isArray(values) || values.length > 64) {
    throw new Error(`${label} must be an array with at most 64 entries`);
  }
  const normalized = values.map((value, index) => normalizeRequestedEffect(value, registry, `${label}[${index}]`));
  const digests = normalized.map((value) => hashCanonicalJson(value));
  if (new Set(digests).size !== digests.length) throw new Error(`${label} must not contain duplicate effects`);
  return Object.freeze(normalized);
}

function normalizeEffectSurfaceMetadata(value, label = "effect_surface") {
  if (value == null) return Object.freeze([]);
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  const normalized = value.map((surface, index) => {
    if (typeof surface !== "string" || !EFFECT_SURFACE_SET.has(surface)) {
      throw new Error(`${label}[${index}] is not a registered effect surface`);
    }
    return surface;
  });
  const sorted = [...new Set(normalized)].sort();
  if (sorted.length !== normalized.length) throw new Error(`${label} must not contain duplicates`);
  return Object.freeze(sorted);
}

// Compatibility projection only. These flags never authorize an effect.
function projectLegacyEffectFlags(effects) {
  if (!Array.isArray(effects)) throw new Error("effects must be an array");
  for (let index = 0; index < effects.length; index += 1) {
    const effect = effects[index];
    if (!isPlainObject(effect)) throw new Error(`effects[${index}] must be an object`);
    assertEnum(effect.subject_kind, EFFECT_SUBJECT_KINDS, `effects[${index}].subject_kind`);
    assertEnum(effect.action, EFFECT_ACTIONS, `effects[${index}].action`);
    assertEnum(effect.channel, EFFECT_CHANNELS, `effects[${index}].channel`);
    assertEnum(effect.persistence, EFFECT_PERSISTENCE_VALUES, `effects[${index}].persistence`);
  }
  const effectSurface = normalizeEffectSurfaceMetadata(
    [...new Set(effects.map((effect) => `${effect.subject_kind}.${effect.action}`))],
  );
  return deepFreeze({
    mutating: effects.some((effect) => effect.action !== "observe" || effect.persistence !== "none"),
    network_access: effects.some((effect) => effect.channel === "network"),
    effect_surface: effectSurface,
  });
}

function requestedEffectDigest(value, registry) {
  return hashCanonicalJson(normalizeRequestedEffect(value, registry));
}

module.exports = {
  BOUND_KINDS,
  EFFECT_ACTIONS,
  EFFECT_CHANNELS,
  EFFECT_PERSISTENCE_VALUES,
  EFFECT_SUBJECT_KINDS,
  EFFECT_SURFACE_VALUES,
  EFFECT_TEMPLATE_VERSION,
  REQUESTED_EFFECT_VERSION,
  assertEffectTemplateRegistry,
  buildEffectTemplateRegistry,
  defineEffectTemplate,
  normalizeEffectSurfaceMetadata,
  normalizeRequestedEffect,
  normalizeRequestedEffects,
  projectLegacyEffectFlags,
  requestedEffectDigest,
};
