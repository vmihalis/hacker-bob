"use strict";

// Plane-PH PH-X4 provider-authoring assembly contract. This module does not
// define a second provider manifest language. It validates and binds the
// existing operation/effect registries, provider descriptor, and resource
// bundles into one digest-only authoring projection. It cannot mint authority,
// reserve a resource, dispatch an effect, or qualify production/HIL evidence.

const { types: utilTypes } = require("node:util");

const {
  PROVIDER_ABI_VERSION,
  PROVIDER_BOOTSTRAP_ABI_VERSION,
  PROVIDER_BOOTSTRAP_OPERATION_IDS,
  assertProviderAbiCompatible,
  normalizeProviderDescriptor,
} = require("./instrument-provider-contract.js");
const {
  assertEffectTemplateRegistry,
} = require("../../core/requested-effects.js");
const {
  RESOURCE_KIND_VALUES,
  normalizePhysicalResourceBundle,
} = require("../../core/physical-resource-contracts.js");
const {
  hashCanonicalJson,
} = require("../../core/verification/verification-contracts.js");

const PHYSICAL_PROVIDER_AUTHORING_MANIFEST_VERSION = 1;
const PHYSICAL_PROVIDER_AUTHORING_COMPATIBILITY_VERSION = 1;

const PHYSICAL_PROVIDER_QUALIFICATION_PROFILE_VALUES = Object.freeze([
  "baseline",
  "orthogonal_multi_instrument_v1",
]);

// These are requirements declared by the authoring projection, not claims that
// the flows have run. Signed gate evidence remains the only completion proof.
const PHYSICAL_PROVIDER_CONFORMANCE_REQUIREMENT_IDS = Object.freeze([
  "act",
  "authorize",
  "claim",
  "compose",
  "doctor",
  "install",
  "observe",
  "package",
  "reachability",
  "report",
  "restore",
  "verify",
]);

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const SEMVER_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const PHYSICAL_PROVIDER_AUTHORING_MANIFESTS = new WeakSet();

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || utilTypes.isProxy(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be a non-proxy object`);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...required, ...optional]);
  const unknown = keys.filter((key) => !allowed.has(key)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((key) => !Object.prototype.hasOwnProperty.call(value, key));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${label}.${key} must be an enumerable data field`);
    }
  }
  return value;
}

function assertDenseDataArray(value, label, minimum = 0, maximum = 1024) {
  if (!Array.isArray(value) || utilTypes.isProxy(value)
      || value.length < minimum || value.length > maximum) {
    throw new Error(`${label} must be a non-proxy array with ${minimum}-${maximum} entries`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([
    "length",
    ...Array.from({ length: value.length }, (_, index) => String(index)),
  ]);
  const unknown = keys.filter((key) => !allowed.has(key)).sort();
  if (unknown.length > 0) throw new Error(`${label} has adorned fields: ${unknown.join(", ")}`);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${label}[${index}] must be an enumerable data field`);
    }
  }
  return value;
}

function assertPlainDataGraph(value, label, seen = new Set()) {
  if (value == null || typeof value !== "object") return value;
  if (utilTypes.isProxy(value)) throw new Error(`${label} cannot be a proxy`);
  if (seen.has(value)) throw new Error(`${label} cannot contain cycles or aliases`);
  seen.add(value);
  if (Array.isArray(value)) {
    assertDenseDataArray(value, label, 0, 4096);
    for (let index = 0; index < value.length; index += 1) {
      assertPlainDataGraph(value[index], `${label}[${index}]`, seen);
    }
  } else {
    if (!isPlainObject(value)) throw new Error(`${label} must contain only plain data objects`);
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) {
      throw new Error(`${label} cannot contain symbol fields`);
    }
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        throw new Error(`${label}.${key} must be an enumerable data field`);
      }
      assertPlainDataGraph(descriptor.value, `${label}.${key}`, seen);
    }
  }
  return value;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function compareProtocolStrings(left, right) {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

function assertEnum(value, values, label) {
  if (!values.includes(value)) throw new Error(`${label} must be one of ${values.join(", ")}`);
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertInteger(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function normalizeSortedUniqueStrings(value, label, normalize, { minimum = 0, maximum = 1024 } = {}) {
  assertDenseDataArray(value, label, minimum, maximum);
  const entries = value.map((entry, index) => normalize(entry, `${label}[${index}]`));
  const sorted = [...entries].sort(compareProtocolStrings);
  if (new Set(sorted).size !== sorted.length) throw new Error(`${label} must not contain duplicates`);
  if (entries.some((entry, index) => entry !== sorted[index])) {
    throw new Error(`${label} must use protocol order`);
  }
  return Object.freeze(sorted);
}

function capabilityIdFromRef(value, label) {
  if (typeof value !== "string" || !value.startsWith("capability:")) {
    throw new Error(`${label} must be a capability reference`);
  }
  return assertIdentifier(value.slice("capability:".length), label);
}

function capabilityIsReadOnlyObservation(capability) {
  return capability.worst_case_effects.length > 0
    && capability.worst_case_effects.every((effect) => (
      effect.action === "observe" && effect.persistence === "none"
    ));
}

function capabilityIsEffectful(capability) {
  return capability.worst_case_effects.some((effect) => (
    effect.action !== "observe" || effect.persistence !== "none"
  ));
}

function assertExactRegistryCoverage(descriptor, operationRegistry, effectRegistry) {
  const declaredOperationIds = new Set(descriptor.capabilities.map((entry) => entry.operation_id));
  const unusedOperationIds = operationRegistry.ids().filter((operationId) => !declaredOperationIds.has(operationId));
  if (unusedOperationIds.length > 0) {
    throw new Error(`provider authoring operation registry has undeclared operations: ${unusedOperationIds.join(", ")}`);
  }
  const declaredEffectIds = new Set(descriptor.capabilities.flatMap(
    (entry) => entry.worst_case_effects.map((effect) => effect.template_id),
  ));
  const unusedEffectIds = effectRegistry.ids().filter((templateId) => !declaredEffectIds.has(templateId));
  if (unusedEffectIds.length > 0) {
    throw new Error(`provider authoring effect registry has undeclared templates: ${unusedEffectIds.join(", ")}`);
  }
  if (descriptor.abi_version === PROVIDER_BOOTSTRAP_ABI_VERSION) {
    const missingBootstrap = PROVIDER_BOOTSTRAP_OPERATION_IDS.filter(
      (operationId) => !declaredOperationIds.has(operationId),
    );
    if (missingBootstrap.length > 0) {
      throw new Error(`provider authoring ABI-v3 descriptor lacks bootstrap operations: ${missingBootstrap.join(", ")}`);
    }
  }
}

function collectResourceCoverage(descriptor, bundles) {
  const capabilityById = new Map(descriptor.capabilities.map((entry) => [entry.capability_id, entry]));
  const activeCapabilities = descriptor.capabilities.filter(
    (entry) => !PROVIDER_BOOTSTRAP_OPERATION_IDS.includes(entry.operation_id),
  );
  if (activeCapabilities.length === 0) {
    throw new Error("provider authoring manifest requires at least one active capability");
  }
  const coverage = new Map(activeCapabilities.map((entry) => [entry.capability_id, new Set()]));
  for (const bundle of bundles) {
    for (const requirement of bundle.requirements.filter((entry) => entry.resource_kind === "instrument")) {
      for (let index = 0; index < requirement.capability_refs.length; index += 1) {
        const capabilityId = capabilityIdFromRef(
          requirement.capability_refs[index],
          `resource_bundle.${bundle.bundle_id}.${requirement.alias}.capability_refs[${index}]`,
        );
        if (!capabilityById.has(capabilityId)) {
          throw new Error(`resource bundle ${bundle.bundle_id} references unknown capability ${capabilityId}`);
        }
        if (coverage.has(capabilityId)) coverage.get(capabilityId).add(bundle.resource_bundle_digest);
      }
    }
  }
  const uncovered = [...coverage.entries()]
    .filter(([, bundleDigests]) => bundleDigests.size === 0)
    .map(([capabilityId]) => capabilityId)
    .sort(compareProtocolStrings);
  if (uncovered.length > 0) {
    throw new Error(`provider authoring resource bundles do not cover active capabilities: ${uncovered.join(", ")}`);
  }
  return Object.freeze([...coverage.entries()]
    .map(([capabilityId, bundleDigests]) => deepFreeze({
      capability_id: capabilityId,
      resource_bundle_digests: Object.freeze([...bundleDigests].sort(compareProtocolStrings)),
    }))
    .sort((left, right) => compareProtocolStrings(left.capability_id, right.capability_id)));
}

function setsOverlap(left, right) {
  return [...left].some((value) => right.has(value));
}

function assertOrthogonalMultiInstrumentProfile(descriptor, bundles) {
  if (descriptor.abi_version !== PROVIDER_ABI_VERSION) {
    throw new Error(`orthogonal provider qualification requires current ABI ${PROVIDER_ABI_VERSION}`);
  }
  const capabilityById = new Map(descriptor.capabilities.map((entry) => [entry.capability_id, entry]));
  const qualifyingBundle = bundles.find((bundle) => {
    const instruments = bundle.requirements.filter((entry) => entry.resource_kind === "instrument");
    const observers = bundle.requirements.filter((entry) => entry.resource_kind === "observer");
    const controls = bundle.requirements.filter((entry) => entry.resource_kind === "control");
    const workspaces = bundle.requirements.filter((entry) => entry.resource_kind === "workspace");
    if (instruments.length < 2 || observers.length === 0 || controls.length === 0 || workspaces.length === 0) {
      return false;
    }
    if (observers.some((entry) => entry.independence_domain_ref == null)
        || controls.some((entry) => entry.independence_domain_ref == null)) return false;
    const independenceDomains = new Set([
      ...observers.map((entry) => entry.independence_domain_ref),
      ...controls.map((entry) => entry.independence_domain_ref),
    ]);
    if (independenceDomains.size < 2) return false;

    const instrumentRoles = instruments.map((requirement) => {
      const capabilities = requirement.capability_refs
        .map((ref) => capabilityById.get(capabilityIdFromRef(ref, `${bundle.bundle_id}.${requirement.alias}`)))
        .filter(Boolean);
      return {
        candidateRefs: new Set(requirement.candidate_resource_refs),
        effectful: capabilities.some(capabilityIsEffectful),
        observing: capabilities.some(capabilityIsReadOnlyObservation),
      };
    });
    for (let leftIndex = 0; leftIndex < instrumentRoles.length; leftIndex += 1) {
      for (let rightIndex = 0; rightIndex < instrumentRoles.length; rightIndex += 1) {
        if (leftIndex === rightIndex) continue;
        const left = instrumentRoles[leftIndex];
        const right = instrumentRoles[rightIndex];
        if (left.effectful && right.observing && !setsOverlap(left.candidateRefs, right.candidateRefs)) {
          return true;
        }
      }
    }
    return false;
  });
  if (!qualifyingBundle) {
    throw new Error(
      "orthogonal provider qualification requires one atomic bundle with disjoint effect and observation instruments, independent observer/control domains, and a workspace",
    );
  }
}

function normalizeCompatibility(input, label = "provider_authoring_manifest.compatibility") {
  assertClosedObject(input, label, [
    "version",
    "active_provider_abi_version",
    "declared_provider_abi_version",
    "active_compatible",
    "bootstrap_compatible",
    "legacy_active_only",
  ]);
  if (input.version !== PHYSICAL_PROVIDER_AUTHORING_COMPATIBILITY_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_PROVIDER_AUTHORING_COMPATIBILITY_VERSION}`);
  }
  if (input.active_provider_abi_version !== PROVIDER_ABI_VERSION) {
    throw new Error(`${label}.active_provider_abi_version must be ${PROVIDER_ABI_VERSION}`);
  }
  assertInteger(input.declared_provider_abi_version, `${label}.declared_provider_abi_version`, 1, 65535);
  for (const field of ["active_compatible", "bootstrap_compatible", "legacy_active_only"]) {
    if (typeof input[field] !== "boolean") throw new Error(`${label}.${field} must be a boolean`);
  }
  if (!input.active_compatible) throw new Error(`${label}.active_compatible must be true`);
  if (input.bootstrap_compatible !== (input.declared_provider_abi_version === PROVIDER_BOOTSTRAP_ABI_VERSION)) {
    throw new Error(`${label}.bootstrap_compatible contradicts the declared ABI`);
  }
  if (input.legacy_active_only !== (input.declared_provider_abi_version !== PROVIDER_BOOTSTRAP_ABI_VERSION)) {
    throw new Error(`${label}.legacy_active_only contradicts the declared ABI`);
  }
  return deepFreeze({
    version: PHYSICAL_PROVIDER_AUTHORING_COMPATIBILITY_VERSION,
    active_provider_abi_version: PROVIDER_ABI_VERSION,
    declared_provider_abi_version: input.declared_provider_abi_version,
    active_compatible: true,
    bootstrap_compatible: input.bootstrap_compatible,
    legacy_active_only: input.legacy_active_only,
  });
}

const MANIFEST_FIELDS = Object.freeze([
  "version",
  "qualification_profile",
  "provider_id",
  "provider_version",
  "provider_abi_version",
  "implementation_digest",
  "provider_descriptor_digest",
  "operation_registry_digest",
  "effect_registry_digest",
  "capability_count",
  "active_capability_ids",
  "bootstrap_capability_ids",
  "effect_template_ids",
  "resource_bundle_digests",
  "resource_kind_coverage",
  "capability_resource_coverage",
  "compatibility",
  "conformance_requirement_ids",
]);

function normalizeCapabilityResourceCoverage(input, label) {
  assertDenseDataArray(input, label, 1, 1024);
  const entries = input.map((entry, index) => {
    const entryLabel = `${label}[${index}]`;
    assertClosedObject(entry, entryLabel, ["capability_id", "resource_bundle_digests"]);
    return deepFreeze({
      capability_id: assertIdentifier(entry.capability_id, `${entryLabel}.capability_id`),
      resource_bundle_digests: normalizeSortedUniqueStrings(
        entry.resource_bundle_digests,
        `${entryLabel}.resource_bundle_digests`,
        assertDigest,
        { minimum: 1 },
      ),
    });
  });
  const sorted = [...entries].sort((left, right) => compareProtocolStrings(left.capability_id, right.capability_id));
  if (entries.some((entry, index) => entry.capability_id !== sorted[index].capability_id)) {
    throw new Error(`${label} must use capability protocol order`);
  }
  if (new Set(entries.map((entry) => entry.capability_id)).size !== entries.length) {
    throw new Error(`${label} must not repeat a capability`);
  }
  return Object.freeze(sorted);
}

function normalizePhysicalProviderAuthoringManifest(input, label = "physical_provider_authoring_manifest") {
  assertPlainDataGraph(input, label);
  assertClosedObject(input, label, [...MANIFEST_FIELDS, "manifest_digest"]);
  if (input.version !== PHYSICAL_PROVIDER_AUTHORING_MANIFEST_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_PROVIDER_AUTHORING_MANIFEST_VERSION}`);
  }
  if (typeof input.provider_version !== "string" || !SEMVER_PATTERN.test(input.provider_version)) {
    throw new Error(`${label}.provider_version must be semantic version text`);
  }
  const activeCapabilityIds = normalizeSortedUniqueStrings(
    input.active_capability_ids,
    `${label}.active_capability_ids`,
    assertIdentifier,
    { minimum: 1 },
  );
  const bootstrapCapabilityIds = normalizeSortedUniqueStrings(
    input.bootstrap_capability_ids,
    `${label}.bootstrap_capability_ids`,
    assertIdentifier,
  );
  if (setsOverlap(new Set(activeCapabilityIds), new Set(bootstrapCapabilityIds))) {
    throw new Error(`${label} active and bootstrap capabilities must be disjoint`);
  }
  const capabilityCount = assertInteger(input.capability_count, `${label}.capability_count`, 1, 1024);
  if (capabilityCount !== activeCapabilityIds.length + bootstrapCapabilityIds.length) {
    throw new Error(`${label}.capability_count does not match its capability partitions`);
  }
  const compatibility = normalizeCompatibility(input.compatibility, `${label}.compatibility`);
  const providerAbiVersion = assertInteger(input.provider_abi_version, `${label}.provider_abi_version`, 1, 65535);
  if (compatibility.declared_provider_abi_version !== providerAbiVersion) {
    throw new Error(`${label}.provider_abi_version contradicts compatibility`);
  }
  const capabilityResourceCoverage = normalizeCapabilityResourceCoverage(
    input.capability_resource_coverage,
    `${label}.capability_resource_coverage`,
  );
  if (capabilityResourceCoverage.length !== activeCapabilityIds.length
      || capabilityResourceCoverage.some((entry, index) => entry.capability_id !== activeCapabilityIds[index])) {
    throw new Error(`${label}.capability_resource_coverage must exactly cover active capabilities`);
  }
  const conformanceRequirementIds = normalizeSortedUniqueStrings(
    input.conformance_requirement_ids,
    `${label}.conformance_requirement_ids`,
    assertIdentifier,
    { minimum: PHYSICAL_PROVIDER_CONFORMANCE_REQUIREMENT_IDS.length },
  );
  if (hashCanonicalJson(conformanceRequirementIds)
      !== hashCanonicalJson(PHYSICAL_PROVIDER_CONFORMANCE_REQUIREMENT_IDS)) {
    throw new Error(`${label}.conformance_requirement_ids must equal the Plane-PH authoring requirements`);
  }
  const basis = {
    version: PHYSICAL_PROVIDER_AUTHORING_MANIFEST_VERSION,
    qualification_profile: assertEnum(
      input.qualification_profile,
      PHYSICAL_PROVIDER_QUALIFICATION_PROFILE_VALUES,
      `${label}.qualification_profile`,
    ),
    provider_id: assertIdentifier(input.provider_id, `${label}.provider_id`),
    provider_version: input.provider_version,
    provider_abi_version: providerAbiVersion,
    implementation_digest: assertDigest(input.implementation_digest, `${label}.implementation_digest`),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    operation_registry_digest: assertDigest(
      input.operation_registry_digest,
      `${label}.operation_registry_digest`,
    ),
    effect_registry_digest: assertDigest(input.effect_registry_digest, `${label}.effect_registry_digest`),
    capability_count: capabilityCount,
    active_capability_ids: activeCapabilityIds,
    bootstrap_capability_ids: bootstrapCapabilityIds,
    effect_template_ids: normalizeSortedUniqueStrings(
      input.effect_template_ids,
      `${label}.effect_template_ids`,
      assertIdentifier,
      { minimum: 1 },
    ),
    resource_bundle_digests: normalizeSortedUniqueStrings(
      input.resource_bundle_digests,
      `${label}.resource_bundle_digests`,
      assertDigest,
      { minimum: 1 },
    ),
    resource_kind_coverage: normalizeSortedUniqueStrings(
      input.resource_kind_coverage,
      `${label}.resource_kind_coverage`,
      (value, field) => assertEnum(value, RESOURCE_KIND_VALUES, field),
      { minimum: 1, maximum: RESOURCE_KIND_VALUES.length },
    ),
    capability_resource_coverage: capabilityResourceCoverage,
    compatibility,
    conformance_requirement_ids: conformanceRequirementIds,
  };
  const manifestDigest = hashCanonicalJson(basis);
  if (assertDigest(input.manifest_digest, `${label}.manifest_digest`) !== manifestDigest) {
    throw new Error(`${label}.manifest_digest does not match normalized content`);
  }
  const manifest = deepFreeze({ ...basis, manifest_digest: manifestDigest });
  PHYSICAL_PROVIDER_AUTHORING_MANIFESTS.add(manifest);
  return manifest;
}

function createPhysicalProviderAuthoringManifest(input) {
  assertClosedObject(input, "physical_provider_authoring_input", [
    "qualification_profile",
    "provider_descriptor",
    "operation_registry",
    "effect_registry",
    "resource_bundles",
  ]);
  if (utilTypes.isProxy(input.operation_registry) || utilTypes.isProxy(input.effect_registry)) {
    throw new Error("physical provider authoring registries cannot be proxies");
  }
  assertPlainDataGraph(input.provider_descriptor, "physical_provider_authoring_input.provider_descriptor");
  assertDenseDataArray(input.resource_bundles, "physical_provider_authoring_input.resource_bundles", 1, 128);
  input.resource_bundles.forEach((bundle, index) => (
    assertPlainDataGraph(bundle, `physical_provider_authoring_input.resource_bundles[${index}]`)
  ));
  assertEffectTemplateRegistry(input.effect_registry);
  const descriptor = normalizeProviderDescriptor(
    input.provider_descriptor,
    input.operation_registry,
    input.effect_registry,
    "physical_provider_authoring_input.provider_descriptor",
  );
  assertProviderAbiCompatible(descriptor);
  assertExactRegistryCoverage(descriptor, input.operation_registry, input.effect_registry);
  const bundles = input.resource_bundles.map((bundle, index) => normalizePhysicalResourceBundle(
    bundle,
    `physical_provider_authoring_input.resource_bundles[${index}]`,
  ));
  const bundleDigests = bundles.map((entry) => entry.resource_bundle_digest);
  if (new Set(bundleDigests).size !== bundleDigests.length) {
    throw new Error("physical provider authoring resource bundles must have unique digests");
  }
  const qualificationProfile = assertEnum(
    input.qualification_profile,
    PHYSICAL_PROVIDER_QUALIFICATION_PROFILE_VALUES,
    "physical_provider_authoring_input.qualification_profile",
  );
  const capabilityResourceCoverage = collectResourceCoverage(descriptor, bundles);
  if (qualificationProfile === "orthogonal_multi_instrument_v1") {
    assertOrthogonalMultiInstrumentProfile(descriptor, bundles);
  }
  const activeCapabilities = descriptor.capabilities.filter(
    (entry) => !PROVIDER_BOOTSTRAP_OPERATION_IDS.includes(entry.operation_id),
  );
  const bootstrapCapabilities = descriptor.capabilities.filter(
    (entry) => PROVIDER_BOOTSTRAP_OPERATION_IDS.includes(entry.operation_id),
  );
  const basis = {
    version: PHYSICAL_PROVIDER_AUTHORING_MANIFEST_VERSION,
    qualification_profile: qualificationProfile,
    provider_id: descriptor.provider_id,
    provider_version: descriptor.provider_version,
    provider_abi_version: descriptor.abi_version,
    implementation_digest: descriptor.implementation_digest,
    provider_descriptor_digest: descriptor.descriptor_digest,
    operation_registry_digest: input.operation_registry.registry_digest,
    effect_registry_digest: input.effect_registry.registry_digest,
    capability_count: descriptor.capabilities.length,
    active_capability_ids: Object.freeze(activeCapabilities
      .map((entry) => entry.capability_id)
      .sort(compareProtocolStrings)),
    bootstrap_capability_ids: Object.freeze(bootstrapCapabilities
      .map((entry) => entry.capability_id)
      .sort(compareProtocolStrings)),
    effect_template_ids: Object.freeze([...input.effect_registry.ids()].sort(compareProtocolStrings)),
    resource_bundle_digests: Object.freeze([...bundleDigests].sort(compareProtocolStrings)),
    resource_kind_coverage: Object.freeze([...new Set(bundles.flatMap(
      (bundle) => bundle.requirements.map((entry) => entry.resource_kind),
    ))].sort(compareProtocolStrings)),
    capability_resource_coverage: capabilityResourceCoverage,
    compatibility: deepFreeze({
      version: PHYSICAL_PROVIDER_AUTHORING_COMPATIBILITY_VERSION,
      active_provider_abi_version: PROVIDER_ABI_VERSION,
      declared_provider_abi_version: descriptor.abi_version,
      active_compatible: true,
      bootstrap_compatible: descriptor.abi_version === PROVIDER_BOOTSTRAP_ABI_VERSION,
      legacy_active_only: descriptor.abi_version !== PROVIDER_BOOTSTRAP_ABI_VERSION,
    }),
    conformance_requirement_ids: PHYSICAL_PROVIDER_CONFORMANCE_REQUIREMENT_IDS,
  };
  return normalizePhysicalProviderAuthoringManifest({
    ...basis,
    manifest_digest: hashCanonicalJson(basis),
  });
}

function assertPhysicalProviderAuthoringManifest(value) {
  if (!value || !PHYSICAL_PROVIDER_AUTHORING_MANIFESTS.has(value)) {
    throw new Error("physical provider authoring manifest must be normalized by Bob");
  }
  return value;
}

function assertPhysicalProviderAuthoringBindings(manifestInput, authoringInput) {
  const manifest = normalizePhysicalProviderAuthoringManifest(manifestInput);
  const expected = createPhysicalProviderAuthoringManifest(authoringInput);
  if (manifest.manifest_digest !== expected.manifest_digest) {
    throw new Error("physical provider authoring manifest does not bind the supplied provider assembly");
  }
  return true;
}

module.exports = {
  PHYSICAL_PROVIDER_AUTHORING_COMPATIBILITY_VERSION,
  PHYSICAL_PROVIDER_AUTHORING_MANIFEST_VERSION,
  PHYSICAL_PROVIDER_CONFORMANCE_REQUIREMENT_IDS,
  PHYSICAL_PROVIDER_QUALIFICATION_PROFILE_VALUES,
  assertPhysicalProviderAuthoringBindings,
  assertPhysicalProviderAuthoringManifest,
  createPhysicalProviderAuthoringManifest,
  normalizePhysicalProviderAuthoringManifest,
};
