"use strict";

// PH-I1: provider-neutral, assurance-qualified instrument capability index.
//
// The model-facing side of this module never receives firmware command IDs,
// proof bodies, signatures, provider callbacks, or readiness assertions.  A
// provider adapter compiles those private facts into opaque predicates and a
// signed evidence envelope.  This module re-verifies the envelope, its closed
// proof-provider bindings, trusted time, inventory binding, exact dependency
// formula, and four-axis assurance relation before producing a bounded public
// projection.  Installation remains fail-closed while the repository has no
// production-qualified inventory source or restart-stable clock source.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const {
  assertPhysicalTrustedClockPort,
  samplePhysicalTrustedClock,
} = require("./physical-trusted-clock.js");
const {
  assertNoPublicByteMaterial,
  assertProviderActiveAbiCompatible,
} = require("./instrument-provider-contract.js");
const {
  assertExecutedEvidenceRegistry,
} = require("../../core/executed-evidence-registry.js");
const {
  assertCurrentFixturePhysicalInventoryCheckpoint,
  projectFixturePhysicalInventoryCheckpoint,
} = require("./physical-inventory-checkpoint.js");
const {
  assertProductionPhysicalTrustedClockPort,
  assertRestartDurablePhysicalTrustedClockPort,
  describeProductionPhysicalTrustedClockPort,
  sampleRestartDurablePhysicalTrustedClock,
} = require("./physical-trusted-clock-store.js");
const {
  hashCanonicalJson,
  isPlainObject,
} = require("../../core/verification/verification-contracts.js");

const INSTRUMENT_CAPABILITY_INDEX_VERSION = 1;
const INSTRUMENT_CAPABILITY_EVIDENCE_DOMAIN =
  "hacker-bob/instrument-capability-evidence/v1";
const INSTRUMENT_CAPABILITY_PROOF_DOMAIN =
  "hacker-bob/instrument-capability-dependency-proof/v1";
const INSTRUMENT_CAPABILITY_SIGNING_DOMAIN =
  "hacker-bob/instrument-capability-signature/v1";
const INSTRUMENT_CAPABILITY_CLAIM_DOMAIN =
  "hacker-bob/instrument-capability-assurance-claim/v1";

const ASSURANCE_AXES = Object.freeze([
  "identity_enrollment",
  "firmware_provenance",
  "command_surface_conformance",
  "transport_trust",
]);
const SIGNER_PURPOSES = Object.freeze(["index_evidence", "dependency_proof"]);
const SIGNER_DISPOSITIONS = Object.freeze(["enrolled", "revoked"]);
const PROOF_VERDICTS = Object.freeze(["satisfied", "unsatisfied"]);
const PREDICATE_KINDS = Object.freeze([
  "device_predicate",
  "dependency_proof",
  "capability_variant",
]);
const CAPABILITY_DISPOSITIONS = Object.freeze([
  "planned",
  "optional",
  "provider_internal",
  "operator_only",
  "unsupported",
]);
const PUBLIC_AVAILABILITY_VALUES = Object.freeze(["available", "unavailable"]);
const QUERY_AVAILABILITY_VALUES = Object.freeze(["all", ...PUBLIC_AVAILABILITY_VALUES]);

const MAX_MANIFEST_VARIANTS = 2_048;
const MAX_FORMULA_PREDICATES = 256;
const MAX_ANY_OF_GROUPS = 64;
const MAX_DEPENDENCY_PROOFS = 256;
const MAX_QUERY_LIMIT = 50;
const MAX_QUERY_SCAN = MAX_MANIFEST_VARIANTS;
const MAX_EFFECT_PROFILES = 64;
const MAX_OPERATIONS_PER_VARIANT = 32;
const MAX_TECHNIQUES_PER_VARIANT = 32;

const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const ID_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/u;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const REF_PATTERN = /^[a-z][a-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/u;

const SIGNED_ENVELOPE_FIELDS = Object.freeze([
  "version",
  "domain",
  "payload",
  "payload_digest",
  "signer_registry_digest",
  "signer_key_id",
  "signer_trust_epoch",
  "signature_scheme",
  "signature",
  "envelope_digest",
]);
const EVIDENCE_PAYLOAD_FIELDS = Object.freeze([
  "version",
  "target_domain",
  "session_nucleus_hash",
  "physical_scope_axis_digest",
  "instrument_ref",
  "enrollment_candidate_ref",
  "provider_id",
  "provider_descriptor_digest",
  "provider_binary_digest",
  "transport_digest",
  "bootstrap_manifest_digest",
  "connection_generation",
  "semantic_manifest_digest",
  "operation_registry_digest",
  "capabilities_digest",
  "inventory_checkpoint_ref",
  "inventory_checkpoint_digest",
  "inventory_projection_digest",
  "evidence_generation",
  "previous_evidence_digest",
  "authority_epoch",
  "revocation_generation",
  "authority_resolution_digest",
  "observed_at",
  "expires_at",
  "assurance_claims",
  "reported_device_predicate_digests",
  "alternative_selections",
  "dependency_proofs",
]);
const DEPENDENCY_PROOF_PAYLOAD_FIELDS = Object.freeze([
  "version",
  "target_domain",
  "session_nucleus_hash",
  "instrument_ref",
  "provider_id",
  "semantic_manifest_digest",
  "inventory_checkpoint_digest",
  "evidence_generation",
  "authority_epoch",
  "revocation_generation",
  "authority_resolution_digest",
  "dependency_ref_digest",
  "reviewed_contract_digest",
  "canonical_identity_digest",
  "executed_provider_id",
  "executed_provider_digest",
  "owner_principal",
  "signed_verdict_type",
  "implementation_digest",
  "trust_epoch",
  "artifact_digest",
  "proof_generation",
  "verdict",
  "observed_at",
  "expires_at",
]);

const SEMANTIC_MANIFESTS = new WeakSet();
const SEMANTIC_MANIFEST_STATE = new WeakMap();
const SIGNER_REGISTRIES = new WeakSet();
const SIGNER_REGISTRY_STATE = new WeakMap();
const CAPABILITY_PORTS = new WeakSet();
const CAPABILITY_PORT_STATE = new WeakMap();

let installedPort = null;
let installedPortInFlight = false;

function instrumentCapabilityError(code, message) {
  const error = new Error(`${code}: ${message}`);
  error.code = code;
  return error;
}

function deepFreeze(value) {
  if (!value || (typeof value !== "object" && typeof value !== "function")
      || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function assertExactDataObject(value, label, required, optional = []) {
  if (!value || utilTypes.isProxy(value) || !isPlainObject(value)) {
    throw new Error(`${label} must be an exact plain data object`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((field) => typeof field !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...required, ...optional]);
  const unknown = keys.filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const field of keys) {
    const descriptor = descriptors[field];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw new Error(`${label}.${field} must be an enumerable data property`);
    }
  }
  return value;
}

function assertDataArray(value, label, maximum, { minimum = 0 } = {}) {
  if (utilTypes.isProxy(value) || !Array.isArray(value)
      || value.length < minimum || value.length > maximum) {
    throw new Error(`${label} must be a dense data array with ${minimum}..${maximum} entries`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw new Error(`${label}[${index}] must be an enumerable data property`);
    }
  }
  for (const field of Reflect.ownKeys(value)) {
    if (field === "length") continue;
    if (typeof field !== "string" || !/^(0|[1-9][0-9]*)$/u.test(field)
        || Number(field) >= value.length) {
      throw new Error(`${label} cannot contain non-index properties`);
    }
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertId(value, label) {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertToken(value, label) {
  if (typeof value !== "string" || !TOKEN_PATTERN.test(value)) {
    throw new Error(`${label} must be a bounded token`);
  }
  return value;
}

function assertRef(value, label, prefix = null) {
  if (typeof value !== "string" || !REF_PATTERN.test(value)
      || (prefix != null && !value.startsWith(`${prefix}:`))) {
    throw new Error(`${label} must be a bounded ${prefix || "opaque"} reference`);
  }
  return value;
}

function assertInteger(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be a safe integer in ${minimum}..${maximum}`);
  }
  return value;
}

function assertTimestamp(value, label) {
  if (typeof value !== "string") throw new Error(`${label} must be a canonical timestamp`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new Error(`${label} must be a canonical ISO-8601 UTC timestamp`);
  }
  return value;
}

function assertEnum(value, values, label) {
  if (!values.includes(value)) throw new Error(`${label} must be one of ${values.join(", ")}`);
  return value;
}

function normalizeUniqueArray(value, label, maximum, normalize, { minimum = 0, keyOf } = {}) {
  assertDataArray(value, label, maximum, { minimum });
  const result = value.map((entry, index) => normalize(entry, `${label}[${index}]`));
  // Callers whose normalized entries carry a non-canonicalizable value (e.g. a
  // live crypto KeyObject) supply keyOf to derive a canonicalizable dedup key;
  // otherwise the whole entry is hashed.
  const keys = result.map((entry) => {
    if (keyOf) return keyOf(entry);
    return typeof entry === "string" ? entry : hashCanonicalJson(entry);
  });
  if (new Set(keys).size !== keys.length) throw new Error(`${label} must not contain duplicates`);
  return Object.freeze(result);
}

function componentImplementationDigest(component) {
  return component.artifact_digest || component.tool_digest || null;
}

function normalizeProofContract(input, executedRegistry, label) {
  assertExactDataObject(input, label, [
    "dependency_ref_digest",
    "reviewed_contract_digest",
    "canonical_identity_digest",
    "executed_provider_id",
    "provider_kind",
    "canonical_owner_principal",
    "canonical_signed_verdict_type",
  ]);
  const executedProviderId = assertId(input.executed_provider_id, `${label}.executed_provider_id`);
  const component = executedRegistry.get("dependency_proof_providers", executedProviderId);
  if (!component) throw new Error(`${label}.executed_provider_id is not in the closed evidence registry`);
  const normalized = {
    dependency_ref_digest: assertDigest(input.dependency_ref_digest, `${label}.dependency_ref_digest`),
    reviewed_contract_digest: assertDigest(
      input.reviewed_contract_digest,
      `${label}.reviewed_contract_digest`,
    ),
    canonical_identity_digest: assertDigest(
      input.canonical_identity_digest,
      `${label}.canonical_identity_digest`,
    ),
    executed_provider_id: executedProviderId,
    provider_kind: assertId(input.provider_kind, `${label}.provider_kind`),
    canonical_owner_principal: assertRef(
      input.canonical_owner_principal,
      `${label}.canonical_owner_principal`,
      "principal",
    ),
    canonical_signed_verdict_type: assertId(
      input.canonical_signed_verdict_type,
      `${label}.canonical_signed_verdict_type`,
    ),
    executed_provider_digest: assertDigest(component.provider_digest, `${label}.provider_digest`),
    implementation_digest: assertDigest(
      componentImplementationDigest(component),
      `${label}.implementation_digest`,
    ),
    trust_epoch: assertInteger(component.trust_epoch, `${label}.trust_epoch`, 1),
  };
  if (component.provider_kind !== normalized.provider_kind
      || component.owner_principal !== normalized.canonical_owner_principal
      || component.signed_verdict_type !== normalized.canonical_signed_verdict_type) {
    throw new Error(`${label} canonical identity does not match the executed-evidence provider`);
  }
  const expectedIdentityDigest = hashCanonicalJson({
    domain: "hacker-bob/instrument-capability-reviewed-proof-identity/v1",
    dependency_ref_digest: normalized.dependency_ref_digest,
    reviewed_contract_digest: normalized.reviewed_contract_digest,
    executed_provider_id: normalized.executed_provider_id,
    provider_kind: normalized.provider_kind,
    canonical_owner_principal: normalized.canonical_owner_principal,
    canonical_signed_verdict_type: normalized.canonical_signed_verdict_type,
  });
  if (expectedIdentityDigest !== normalized.canonical_identity_digest) {
    throw new Error(`${label}.canonical_identity_digest does not bind both reviewed and canonical identity`);
  }
  return deepFreeze(normalized);
}

function normalizeAssuranceSatisfaction(input, label) {
  assertExactDataObject(input, label, ASSURANCE_AXES);
  const registry = {};
  for (const axis of ASSURANCE_AXES) {
    const table = input[axis];
    if (utilTypes.isProxy(table) || !isPlainObject(table)) {
      throw new Error(`${label}.${axis} must be a plain claim table`);
    }
    const claims = Object.keys(table).sort();
    assertExactDataObject(table, `${label}.${axis}`, claims);
    if (claims.length < 2 || claims.length > 32
        || !claims.includes("not_required") || !claims.includes("not_applicable")) {
      throw new Error(`${label}.${axis} must contain not_required, not_applicable, and bounded claims`);
    }
    const normalized = {};
    for (const actual of claims) {
      assertId(actual, `${label}.${axis} claim`);
      normalized[actual] = normalizeUniqueArray(
        table[actual],
        `${label}.${axis}.${actual}`,
        claims.length,
        assertId,
        { minimum: 1 },
      ).slice().sort();
      if (normalized[actual].some((minimum) => !claims.includes(minimum))) {
        throw new Error(`${label}.${axis}.${actual} names an unknown minimum claim`);
      }
      if (!normalized[actual].includes(actual)) {
        throw new Error(`${label}.${axis}.${actual} must satisfy itself`);
      }
      if (!normalized[actual].includes("not_required")) {
        throw new Error(`${label}.${axis}.${actual} must satisfy not_required`);
      }
    }
    if (normalized.not_required.length !== 1 || normalized.not_required[0] !== "not_required") {
      throw new Error(`${label}.${axis}.not_required cannot satisfy a stronger claim`);
    }
    if (normalized.not_applicable.length !== 2
        || !normalized.not_applicable.includes("not_required")
        || !normalized.not_applicable.includes("not_applicable")) {
      throw new Error(`${label}.${axis}.not_applicable has the wrong satisfaction relation`);
    }
    registry[axis] = deepFreeze(normalized);
  }
  return deepFreeze(registry);
}

function normalizeAssuranceProfiles(input, satisfaction, label) {
  if (utilTypes.isProxy(input) || !isPlainObject(input)) {
    throw new Error(`${label} must be a plain profile registry`);
  }
  const profileIds = Object.keys(input).sort();
  assertExactDataObject(input, label, profileIds);
  if (profileIds.length < 1 || profileIds.length > 64) {
    throw new Error(`${label} must contain 1..64 profiles`);
  }
  const result = {};
  for (const profileId of profileIds) {
    assertId(profileId, `${label} profile ID`);
    assertExactDataObject(input[profileId], `${label}.${profileId}`, ASSURANCE_AXES);
    result[profileId] = deepFreeze(Object.fromEntries(ASSURANCE_AXES.map((axis) => {
      const claim = assertId(input[profileId][axis], `${label}.${profileId}.${axis}`);
      if (!Object.prototype.hasOwnProperty.call(satisfaction[axis], claim)) {
        throw new Error(`${label}.${profileId}.${axis} is not a registered assurance claim`);
      }
      return [axis, claim];
    })));
  }
  return deepFreeze(result);
}

function normalizePredicate(input, proofContracts, label) {
  assertExactDataObject(
    input,
    label,
    ["kind"],
    ["predicate_digest", "dependency_ref_digest", "variant_ref"],
  );
  const kind = assertEnum(input.kind, PREDICATE_KINDS, `${label}.kind`);
  if (kind === "device_predicate") {
    if (Object.keys(input).length !== 2) throw new Error(`${label} has fields invalid for device_predicate`);
    return deepFreeze({
      kind,
      predicate_digest: assertDigest(input.predicate_digest, `${label}.predicate_digest`),
    });
  }
  if (kind === "dependency_proof") {
    if (Object.keys(input).length !== 2) throw new Error(`${label} has fields invalid for dependency_proof`);
    const dependencyRefDigest = assertDigest(
      input.dependency_ref_digest,
      `${label}.dependency_ref_digest`,
    );
    if (!proofContracts.has(dependencyRefDigest)) {
      throw new Error(`${label}.dependency_ref_digest is not in the closed proof registry`);
    }
    return deepFreeze({ kind, dependency_ref_digest: dependencyRefDigest });
  }
  if (Object.keys(input).length !== 2) throw new Error(`${label} has fields invalid for capability_variant`);
  return deepFreeze({
    kind,
    variant_ref: assertRef(input.variant_ref, `${label}.variant_ref`, "capability-variant"),
  });
}

function predicateKey(predicate) {
  if (predicate.kind === "device_predicate") return `device:${predicate.predicate_digest}`;
  if (predicate.kind === "dependency_proof") return `proof:${predicate.dependency_ref_digest}`;
  return `variant:${predicate.variant_ref}`;
}

function normalizeFormula(input, proofContracts, label) {
  assertExactDataObject(input, label, ["all_of", "any_of"]);
  const allOf = normalizeUniqueArray(
    input.all_of,
    `${label}.all_of`,
    MAX_FORMULA_PREDICATES,
    (entry, at) => normalizePredicate(entry, proofContracts, at),
  );
  assertDataArray(input.any_of, `${label}.any_of`, MAX_ANY_OF_GROUPS);
  const anyOf = input.any_of.map((group, groupIndex) => normalizeUniqueArray(
    group,
    `${label}.any_of[${groupIndex}]`,
    MAX_FORMULA_PREDICATES,
    (entry, at) => normalizePredicate(entry, proofContracts, at),
    { minimum: 1 },
  ));
  const total = allOf.length + anyOf.reduce((sum, group) => sum + group.length, 0);
  if (total > MAX_FORMULA_PREDICATES) {
    throw new Error(`${label} exceeds the total predicate budget`);
  }
  return deepFreeze({ all_of: allOf, any_of: Object.freeze(anyOf) });
}

function defineInstrumentCapabilitySemanticManifest(input, executedEvidenceRegistry) {
  assertExactDataObject(input, "instrument_capability_semantic_manifest", [
    "version",
    "provider_descriptor",
    "semantic_manifest_digest",
    "assurance_profile_registry_digest",
    "assurance_satisfaction_registry_digest",
    "dependency_proof_registry_digest",
    "assurance_profiles",
    "assurance_satisfaction",
    "proof_contracts",
    "variants",
  ]);
  if (input.version !== INSTRUMENT_CAPABILITY_INDEX_VERSION) {
    throw new Error(`instrument_capability_semantic_manifest.version must be ${INSTRUMENT_CAPABILITY_INDEX_VERSION}`);
  }
  const providerDescriptor = input.provider_descriptor;
  assertProviderActiveAbiCompatible(providerDescriptor);
  const providerOperations = new Map(providerDescriptor.capabilities.map((capability) => [
    capability.operation_id,
    capability.operation_digest,
  ]));
  // `executed_evidence_registry` deliberately is not accepted as a field: the
  // registry is supplied as the second positional argument so it cannot become
  // signed provider data or leak into a public manifest projection.
  if (arguments.length !== 2) {
    throw new Error("instrument capability semantic manifest requires a closed executed-evidence registry as its second argument");
  }
  assertExecutedEvidenceRegistry(executedEvidenceRegistry);
  const registry = executedEvidenceRegistry;
  const satisfaction = normalizeAssuranceSatisfaction(
    input.assurance_satisfaction,
    "instrument_capability_semantic_manifest.assurance_satisfaction",
  );
  const profiles = normalizeAssuranceProfiles(
    input.assurance_profiles,
    satisfaction,
    "instrument_capability_semantic_manifest.assurance_profiles",
  );
  const proofContractsList = normalizeUniqueArray(
    input.proof_contracts,
    "instrument_capability_semantic_manifest.proof_contracts",
    MAX_DEPENDENCY_PROOFS,
    (entry, label) => normalizeProofContract(entry, registry, label),
  );
  const proofContracts = new Map();
  for (const contract of proofContractsList) {
    if (proofContracts.has(contract.dependency_ref_digest)) {
      throw new Error("instrument capability proof registry has duplicate dependency_ref_digest values");
    }
    proofContracts.set(contract.dependency_ref_digest, contract);
  }
  assertDataArray(
    input.variants,
    "instrument_capability_semantic_manifest.variants",
    MAX_MANIFEST_VARIANTS,
    { minimum: 1 },
  );
  const variants = input.variants.map((variantInput, index) => {
    const label = `instrument_capability_semantic_manifest.variants[${index}]`;
    assertExactDataObject(variantInput, label, [
      "variant_ref",
      "parameter_selector_id",
      "disposition",
      "reason_code",
      "operation_bindings",
      "technique_bindings",
      "effect_profile_refs",
      "formula",
      "provider_variant_digest",
    ]);
    const operationBindings = normalizeUniqueArray(
      variantInput.operation_bindings,
      `${label}.operation_bindings`,
      MAX_OPERATIONS_PER_VARIANT,
      (entry, at) => {
        assertExactDataObject(entry, at, [
          "operation_id",
          "operation_digest",
          "operation_authority",
          "minimum_assurance_profile_id",
        ]);
        const operationId = assertId(entry.operation_id, `${at}.operation_id`);
        const operationDigest = assertDigest(entry.operation_digest, `${at}.operation_digest`);
        const operationAuthority = assertEnum(
          entry.operation_authority,
          ["provider_abi", "semantic_manifest"],
          `${at}.operation_authority`,
        );
        const providerOperationDigest = providerOperations.get(operationId) || null;
        if (operationAuthority === "provider_abi"
            && providerOperationDigest !== operationDigest) {
          throw new Error(`${at} provider_abi operation is absent or digest-drifted from the provider descriptor`);
        }
        if (operationAuthority === "semantic_manifest" && providerOperationDigest != null) {
          throw new Error(`${at} semantic operation collides with a provider_abi operation ID`);
        }
        const minimumProfileId = assertId(
          entry.minimum_assurance_profile_id,
          `${at}.minimum_assurance_profile_id`,
        );
        if (!profiles[minimumProfileId]) {
          throw new Error(`${at}.minimum_assurance_profile_id is not registered`);
        }
        return deepFreeze({
          operation_id: operationId,
          operation_digest: operationDigest,
          operation_authority: operationAuthority,
          minimum_assurance_profile_id: minimumProfileId,
        });
      },
      { minimum: 1 },
    ).slice().sort((left, right) => left.operation_id.localeCompare(right.operation_id));
    const techniqueBindings = normalizeUniqueArray(
      variantInput.technique_bindings,
      `${label}.technique_bindings`,
      MAX_TECHNIQUES_PER_VARIANT,
      (entry, at) => {
        assertExactDataObject(entry, at, ["technique_id", "technique_digest"]);
        return deepFreeze({
          technique_id: assertId(entry.technique_id, `${at}.technique_id`),
          technique_digest: assertDigest(entry.technique_digest, `${at}.technique_digest`),
        });
      },
    ).slice().sort((left, right) => left.technique_id.localeCompare(right.technique_id));
    const effectProfileRefs = normalizeUniqueArray(
      variantInput.effect_profile_refs,
      `${label}.effect_profile_refs`,
      MAX_EFFECT_PROFILES,
      (entry, at) => assertRef(entry, at, "effect-profile"),
    ).slice().sort();
    const basis = {
      variant_ref: assertRef(variantInput.variant_ref, `${label}.variant_ref`, "capability-variant"),
      parameter_selector_id: assertId(
        variantInput.parameter_selector_id,
        `${label}.parameter_selector_id`,
      ),
      disposition: assertEnum(
        variantInput.disposition,
        CAPABILITY_DISPOSITIONS,
        `${label}.disposition`,
      ),
      reason_code: assertId(variantInput.reason_code, `${label}.reason_code`),
      operation_bindings: operationBindings,
      technique_bindings: techniqueBindings,
      effect_profile_refs: effectProfileRefs,
      formula: normalizeFormula(variantInput.formula, proofContracts, `${label}.formula`),
      provider_variant_digest: assertDigest(
        variantInput.provider_variant_digest,
        `${label}.provider_variant_digest`,
      ),
    };
    return deepFreeze({ ...basis, variant_binding_digest: hashCanonicalJson(basis) });
  }).sort((left, right) => left.variant_ref.localeCompare(right.variant_ref));
  const variantByRef = new Map();
  for (const variant of variants) {
    if (variantByRef.has(variant.variant_ref)) {
      throw new Error(`instrument capability manifest has duplicate variant ${variant.variant_ref}`);
    }
    variantByRef.set(variant.variant_ref, variant);
  }
  for (const variant of variants) {
    for (const predicate of [
      ...variant.formula.all_of,
      ...variant.formula.any_of.flat(),
    ]) {
      if (predicate.kind === "capability_variant" && !variantByRef.has(predicate.variant_ref)) {
        throw new Error(`instrument capability formula names unknown variant ${predicate.variant_ref}`);
      }
    }
  }
  const manifestBasis = {
    version: INSTRUMENT_CAPABILITY_INDEX_VERSION,
    provider_id: providerDescriptor.provider_id,
    provider_descriptor_digest: providerDescriptor.descriptor_digest,
    provider_implementation_digest: providerDescriptor.implementation_digest,
    operation_registry_digest: providerDescriptor.operation_registry_digest,
    capabilities_digest: providerDescriptor.capabilities_digest,
    semantic_manifest_digest: assertDigest(
      input.semantic_manifest_digest,
      "instrument_capability_semantic_manifest.semantic_manifest_digest",
    ),
    assurance_profile_registry_digest: assertDigest(
      input.assurance_profile_registry_digest,
      "instrument_capability_semantic_manifest.assurance_profile_registry_digest",
    ),
    assurance_satisfaction_registry_digest: assertDigest(
      input.assurance_satisfaction_registry_digest,
      "instrument_capability_semantic_manifest.assurance_satisfaction_registry_digest",
    ),
    dependency_proof_registry_digest: assertDigest(
      input.dependency_proof_registry_digest,
      "instrument_capability_semantic_manifest.dependency_proof_registry_digest",
    ),
    executed_evidence_registry_digest: registry.registry_digest,
    assurance_profiles_digest: hashCanonicalJson(profiles),
    assurance_satisfaction_digest: hashCanonicalJson(satisfaction),
    proof_contracts_digest: hashCanonicalJson(proofContractsList),
    variant_registry_digest: hashCanonicalJson(variants),
    variant_count: variants.length,
    proof_contract_count: proofContractsList.length,
  };
  const manifest = deepFreeze({
    ...manifestBasis,
    instrument_capability_manifest_digest: hashCanonicalJson(manifestBasis),
    provider_ref: `instrument-provider:${hashCanonicalJson({
      provider_id: providerDescriptor.provider_id,
      descriptor_digest: providerDescriptor.descriptor_digest,
    })}`,
  });
  SEMANTIC_MANIFESTS.add(manifest);
  SEMANTIC_MANIFEST_STATE.set(manifest, {
    manifest,
    providerDescriptor,
    executedRegistry: registry,
    satisfaction,
    profiles,
    proofContracts,
    variants,
    variantByRef,
  });
  return manifest;
}

function assertInstrumentCapabilitySemanticManifest(manifest) {
  if (!manifest || utilTypes.isProxy(manifest) || !Object.isFrozen(manifest)
      || !SEMANTIC_MANIFESTS.has(manifest) || !SEMANTIC_MANIFEST_STATE.has(manifest)) {
    throw new Error("instrument capability semantic manifest must be a privately branded manifest");
  }
  return manifest;
}

function normalizePublicKey(value, label) {
  if (typeof value !== "string" || value.length > 16_384) {
    throw new Error(`${label} must be a bounded PEM public key`);
  }
  let key;
  try {
    key = crypto.createPublicKey(value);
  } catch {
    throw new Error(`${label} is not a valid public key`);
  }
  if (key.asymmetricKeyType !== "ed25519") throw new Error(`${label} must be an Ed25519 public key`);
  return key;
}

function buildInstrumentCapabilitySignerRegistry(input, executedRegistry) {
  assertExecutedEvidenceRegistry(executedRegistry);
  assertExactDataObject(input, "instrument_capability_signer_registry", [
    "version",
    "registry_id",
    "entries",
  ]);
  if (input.version !== INSTRUMENT_CAPABILITY_INDEX_VERSION) {
    throw new Error(`instrument_capability_signer_registry.version must be ${INSTRUMENT_CAPABILITY_INDEX_VERSION}`);
  }
  const entriesInput = normalizeUniqueArray(
    input.entries,
    "instrument_capability_signer_registry.entries",
    MAX_DEPENDENCY_PROOFS + 16,
    (entry, label) => {
      assertExactDataObject(entry, label, [
        "key_id",
        "purpose",
        "owner_principal",
        "signed_verdict_type",
        "trust_epoch",
        "authority_epoch",
        "revocation_generation",
        "disposition",
        "binding_digest",
        "valid_from",
        "expires_at",
        "public_key_pem",
      ], ["executed_provider_id", "executed_provider_digest"]);
      const purpose = assertEnum(entry.purpose, SIGNER_PURPOSES, `${label}.purpose`);
      const normalized = {
        key_id: assertRef(entry.key_id, `${label}.key_id`, "signer-key"),
        purpose,
        owner_principal: assertRef(entry.owner_principal, `${label}.owner_principal`, "principal"),
        signed_verdict_type: assertId(entry.signed_verdict_type, `${label}.signed_verdict_type`),
        trust_epoch: assertInteger(entry.trust_epoch, `${label}.trust_epoch`, 1),
        authority_epoch: assertInteger(entry.authority_epoch, `${label}.authority_epoch`, 1),
        revocation_generation: assertInteger(
          entry.revocation_generation,
          `${label}.revocation_generation`,
          0,
        ),
        disposition: assertEnum(entry.disposition, SIGNER_DISPOSITIONS, `${label}.disposition`),
        binding_digest: assertDigest(entry.binding_digest, `${label}.binding_digest`),
        valid_from: assertTimestamp(entry.valid_from, `${label}.valid_from`),
        expires_at: assertTimestamp(entry.expires_at, `${label}.expires_at`),
      };
      if (Date.parse(normalized.expires_at) <= Date.parse(normalized.valid_from)) {
        throw new Error(`${label} signer validity interval is empty`);
      }
      const publicKey = normalizePublicKey(entry.public_key_pem, `${label}.public_key_pem`);
      const publicKeyDigest = crypto.createHash("sha256").update(
        publicKey.export({ type: "spki", format: "der" }),
      ).digest("hex");
      if (purpose === "dependency_proof") {
        const executedProviderId = assertId(
          entry.executed_provider_id,
          `${label}.executed_provider_id`,
        );
        const provider = executedRegistry.get("dependency_proof_providers", executedProviderId);
        if (!provider) throw new Error(`${label}.executed_provider_id is not registered`);
        if (entry.executed_provider_digest !== provider.provider_digest
            || normalized.owner_principal !== provider.owner_principal
            || normalized.signed_verdict_type !== provider.signed_verdict_type
            || normalized.trust_epoch !== provider.trust_epoch
            || normalized.binding_digest !== provider.provider_digest) {
          throw new Error(`${label} dependency signer is detached from the executed-evidence provider`);
        }
        normalized.executed_provider_id = executedProviderId;
        normalized.executed_provider_digest = provider.provider_digest;
      } else if (entry.executed_provider_id != null || entry.executed_provider_digest != null) {
        throw new Error(`${label} index evidence signer cannot name a dependency provider`);
      }
      return deepFreeze({ ...normalized, public_key_digest: publicKeyDigest, publicKey });
    },
    {
      minimum: 1,
      // The entry carries a live crypto KeyObject (publicKey) that cannot be
      // canonicalized; public_key_digest is its 1:1 canonicalizable proxy, so
      // dedup on the entry with publicKey stripped — identical dedup identity,
      // no non-plain value in the hash.
      keyOf: (entry) => {
        const { publicKey: _publicKey, ...rest } = entry;
        return hashCanonicalJson(rest);
      },
    },
  );
  const entries = new Map();
  for (const entry of entriesInput) {
    const key = `${entry.key_id}:${entry.purpose}:${entry.trust_epoch}`;
    if (entries.has(key)) throw new Error(`instrument capability signer registry duplicates ${key}`);
    entries.set(key, entry);
  }
  const descriptors = entriesInput.map((entry) => {
    const { publicKey, ...descriptor } = entry;
    return descriptor;
  }).sort((left, right) => (
    `${left.key_id}:${left.purpose}:${left.trust_epoch}`.localeCompare(
      `${right.key_id}:${right.purpose}:${right.trust_epoch}`,
    )
  ));
  const basis = {
    version: INSTRUMENT_CAPABILITY_INDEX_VERSION,
    registry_id: assertId(input.registry_id, "instrument_capability_signer_registry.registry_id"),
    executed_evidence_registry_digest: executedRegistry.registry_digest,
    entries: descriptors,
  };
  const registry = deepFreeze({
    version: INSTRUMENT_CAPABILITY_INDEX_VERSION,
    registry_id: basis.registry_id,
    executed_evidence_registry_digest: executedRegistry.registry_digest,
    registry_digest: hashCanonicalJson(basis),
    entry_count: descriptors.length,
  });
  SIGNER_REGISTRIES.add(registry);
  SIGNER_REGISTRY_STATE.set(registry, { entries, executedRegistry });
  return registry;
}

function assertInstrumentCapabilitySignerRegistry(registry) {
  if (!registry || utilTypes.isProxy(registry) || !Object.isFrozen(registry)
      || !SIGNER_REGISTRIES.has(registry) || !SIGNER_REGISTRY_STATE.has(registry)) {
    throw new Error("instrument capability signer registry must be a privately branded registry");
  }
  return registry;
}

function signerEntry(registry, keyId, purpose, trustEpoch) {
  const state = SIGNER_REGISTRY_STATE.get(assertInstrumentCapabilitySignerRegistry(registry));
  return state.entries.get(`${keyId}:${purpose}:${trustEpoch}`) || null;
}

function instrumentCapabilitySignatureInputDigest(input) {
  assertExactDataObject(input, "instrument_capability_signature_input", [
    "domain",
    "payload",
    "payload_digest",
    "signer_registry_digest",
    "signer_key_id",
    "signer_trust_epoch",
    "signature_scheme",
  ]);
  if (![INSTRUMENT_CAPABILITY_EVIDENCE_DOMAIN, INSTRUMENT_CAPABILITY_PROOF_DOMAIN]
    .includes(input.domain)) {
    throw new Error("instrument_capability_signature_input.domain is not registered");
  }
  if (input.payload_digest !== hashCanonicalJson(input.payload)) {
    throw new Error("instrument_capability_signature_input.payload_digest does not bind payload");
  }
  if (input.signature_scheme !== "ed25519") {
    throw new Error("instrument_capability_signature_input.signature_scheme must be ed25519");
  }
  return hashCanonicalJson({
    signing_domain: INSTRUMENT_CAPABILITY_SIGNING_DOMAIN,
    version: INSTRUMENT_CAPABILITY_INDEX_VERSION,
    ...input,
  });
}

function assertSignerCurrent(entry, interval, authorityEpoch, revocationGeneration, label) {
  if (!entry || entry.disposition !== "enrolled") throw new Error(`${label} is not enrolled`);
  if (entry.authority_epoch !== authorityEpoch
      || entry.revocation_generation !== revocationGeneration) {
    throw new Error(`${label} authority epoch or revocation generation drifted`);
  }
  if (Date.parse(entry.valid_from) > interval.earliest
      || Date.parse(entry.expires_at) <= interval.latest) {
    throw new Error(`${label} is not current for the trusted time interval`);
  }
}

function verifySignedEnvelope(input, registry, purpose, interval, label) {
  assertExactDataObject(input, label, SIGNED_ENVELOPE_FIELDS);
  if (input.version !== INSTRUMENT_CAPABILITY_INDEX_VERSION) {
    throw new Error(`${label}.version must be ${INSTRUMENT_CAPABILITY_INDEX_VERSION}`);
  }
  const expectedDomain = purpose === "index_evidence"
    ? INSTRUMENT_CAPABILITY_EVIDENCE_DOMAIN
    : INSTRUMENT_CAPABILITY_PROOF_DOMAIN;
  if (input.domain !== expectedDomain) throw new Error(`${label}.domain has the wrong evidence type`);
  if (input.signer_registry_digest !== registry.registry_digest) {
    throw new Error(`${label}.signer_registry_digest drifted`);
  }
  const payloadDigest = assertDigest(input.payload_digest, `${label}.payload_digest`);
  if (payloadDigest !== hashCanonicalJson(input.payload)) {
    throw new Error(`${label}.payload_digest does not bind the canonical payload`);
  }
  const keyId = assertRef(input.signer_key_id, `${label}.signer_key_id`, "signer-key");
  const trustEpoch = assertInteger(input.signer_trust_epoch, `${label}.signer_trust_epoch`, 1);
  const entry = signerEntry(registry, keyId, purpose, trustEpoch);
  if (!entry) throw new Error(`${label} signer is not in the closed registry`);
  const authorityEpoch = assertInteger(input.payload.authority_epoch, `${label}.payload.authority_epoch`, 1);
  const revocationGeneration = assertInteger(
    input.payload.revocation_generation,
    `${label}.payload.revocation_generation`,
    0,
  );
  assertSignerCurrent(entry, interval, authorityEpoch, revocationGeneration, `${label} signer`);
  if (input.signature_scheme !== "ed25519") throw new Error(`${label}.signature_scheme must be ed25519`);
  if (typeof input.signature !== "string" || !SIGNATURE_PATTERN.test(input.signature)) {
    throw new Error(`${label}.signature must be canonical Ed25519 base64url`);
  }
  const signatureBytes = Buffer.from(input.signature, "base64url");
  if (signatureBytes.length !== 64 || signatureBytes.toString("base64url") !== input.signature) {
    throw new Error(`${label}.signature must be canonical Ed25519 base64url`);
  }
  const signatureInput = instrumentCapabilitySignatureInputDigest({
    domain: input.domain,
    payload: input.payload,
    payload_digest: payloadDigest,
    signer_registry_digest: input.signer_registry_digest,
    signer_key_id: keyId,
    signer_trust_epoch: trustEpoch,
    signature_scheme: "ed25519",
  });
  if (!crypto.verify(null, Buffer.from(signatureInput, "hex"), entry.publicKey, signatureBytes)) {
    throw new Error(`${label}.signature verification failed`);
  }
  const signedBody = {
    version: INSTRUMENT_CAPABILITY_INDEX_VERSION,
    domain: input.domain,
    payload: input.payload,
    payload_digest: payloadDigest,
    signer_registry_digest: input.signer_registry_digest,
    signer_key_id: keyId,
    signer_trust_epoch: trustEpoch,
    signature_scheme: "ed25519",
    signature: input.signature,
  };
  const envelopeDigest = hashCanonicalJson(signedBody);
  if (assertDigest(input.envelope_digest, `${label}.envelope_digest`) !== envelopeDigest) {
    throw new Error(`${label}.envelope_digest does not bind the signed envelope`);
  }
  return { entry, envelopeDigest };
}

function normalizeAssuranceClaims(input, manifest, payload, label) {
  assertExactDataObject(input, label, ASSURANCE_AXES);
  const state = SEMANTIC_MANIFEST_STATE.get(manifest);
  const result = {};
  for (const axis of ASSURANCE_AXES) {
    const at = `${label}.${axis}`;
    assertExactDataObject(input[axis], at, ["claim", "claim_digest"]);
    const claim = assertId(input[axis].claim, `${at}.claim`);
    if (!state.satisfaction[axis][claim]) throw new Error(`${at}.claim is not registered on this axis`);
    const expectedDigest = hashCanonicalJson({
      domain: INSTRUMENT_CAPABILITY_CLAIM_DOMAIN,
      axis,
      claim,
      semantic_manifest_digest: manifest.semantic_manifest_digest,
      inventory_checkpoint_digest: payload.inventory_checkpoint_digest,
      evidence_generation: payload.evidence_generation,
    });
    if (assertDigest(input[axis].claim_digest, `${at}.claim_digest`) !== expectedDigest) {
      throw new Error(`${at}.claim_digest does not bind the claim-specific evidence context`);
    }
    result[axis] = deepFreeze({ claim, claim_digest: expectedDigest });
  }
  return deepFreeze(result);
}

function normalizeEvidencePayload(input, manifest, interval, label) {
  assertExactDataObject(input, label, EVIDENCE_PAYLOAD_FIELDS);
  if (input.version !== INSTRUMENT_CAPABILITY_INDEX_VERSION) {
    throw new Error(`${label}.version must be ${INSTRUMENT_CAPABILITY_INDEX_VERSION}`);
  }
  const state = SEMANTIC_MANIFEST_STATE.get(manifest);
  for (const [field, expected] of Object.entries({
    provider_id: manifest.provider_id,
    provider_descriptor_digest: manifest.provider_descriptor_digest,
    semantic_manifest_digest: manifest.semantic_manifest_digest,
    operation_registry_digest: manifest.operation_registry_digest,
    capabilities_digest: manifest.capabilities_digest,
  })) {
    if (input[field] !== expected) throw new Error(`${label}.${field} drifted from the semantic/provider manifest`);
  }
  const observedAt = assertTimestamp(input.observed_at, `${label}.observed_at`);
  const expiresAt = assertTimestamp(input.expires_at, `${label}.expires_at`);
  if (Date.parse(observedAt) > interval.earliest) throw new Error(`${label}.observed_at is in the future`);
  if (Date.parse(expiresAt) <= interval.latest) throw new Error(`${label} is stale`);
  if (Date.parse(expiresAt) <= Date.parse(observedAt)) throw new Error(`${label} validity interval is empty`);
  const payload = {
    version: INSTRUMENT_CAPABILITY_INDEX_VERSION,
    target_domain: assertToken(input.target_domain, `${label}.target_domain`),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    physical_scope_axis_digest: assertDigest(
      input.physical_scope_axis_digest,
      `${label}.physical_scope_axis_digest`,
    ),
    instrument_ref: assertRef(input.instrument_ref, `${label}.instrument_ref`, "instrument"),
    enrollment_candidate_ref: assertRef(
      input.enrollment_candidate_ref,
      `${label}.enrollment_candidate_ref`,
      "enrollment-candidate",
    ),
    provider_id: input.provider_id,
    provider_descriptor_digest: input.provider_descriptor_digest,
    provider_binary_digest: assertDigest(input.provider_binary_digest, `${label}.provider_binary_digest`),
    transport_digest: assertDigest(input.transport_digest, `${label}.transport_digest`),
    bootstrap_manifest_digest: assertDigest(
      input.bootstrap_manifest_digest,
      `${label}.bootstrap_manifest_digest`,
    ),
    connection_generation: assertInteger(
      input.connection_generation,
      `${label}.connection_generation`,
      1,
    ),
    semantic_manifest_digest: input.semantic_manifest_digest,
    operation_registry_digest: input.operation_registry_digest,
    capabilities_digest: input.capabilities_digest,
    inventory_checkpoint_ref: assertRef(
      input.inventory_checkpoint_ref,
      `${label}.inventory_checkpoint_ref`,
      "physical-inventory-checkpoint",
    ),
    inventory_checkpoint_digest: assertDigest(
      input.inventory_checkpoint_digest,
      `${label}.inventory_checkpoint_digest`,
    ),
    inventory_projection_digest: assertDigest(
      input.inventory_projection_digest,
      `${label}.inventory_projection_digest`,
    ),
    evidence_generation: assertInteger(input.evidence_generation, `${label}.evidence_generation`, 1),
    previous_evidence_digest: input.previous_evidence_digest === null
      ? null
      : assertDigest(input.previous_evidence_digest, `${label}.previous_evidence_digest`),
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, 1),
    revocation_generation: assertInteger(
      input.revocation_generation,
      `${label}.revocation_generation`,
      0,
    ),
    authority_resolution_digest: assertDigest(
      input.authority_resolution_digest,
      `${label}.authority_resolution_digest`,
    ),
    observed_at: observedAt,
    expires_at: expiresAt,
  };
  payload.assurance_claims = normalizeAssuranceClaims(
    input.assurance_claims,
    manifest,
    payload,
    `${label}.assurance_claims`,
  );
  const knownDevicePredicates = new Set();
  for (const variant of state.variants) {
    for (const predicate of [...variant.formula.all_of, ...variant.formula.any_of.flat()]) {
      if (predicate.kind === "device_predicate") knownDevicePredicates.add(predicate.predicate_digest);
    }
  }
  payload.reported_device_predicate_digests = normalizeUniqueArray(
    input.reported_device_predicate_digests,
    `${label}.reported_device_predicate_digests`,
    MAX_FORMULA_PREDICATES,
    assertDigest,
  ).slice().sort();
  const unknownPredicates = payload.reported_device_predicate_digests.filter(
    (digest) => !knownDevicePredicates.has(digest),
  );
  if (unknownPredicates.length > 0) {
    throw new Error(`${label}.reported_device_predicate_digests contains unknown device predicates`);
  }
  payload.alternative_selections = normalizeUniqueArray(
    input.alternative_selections,
    `${label}.alternative_selections`,
    MAX_ANY_OF_GROUPS * Math.min(state.variants.length, 32),
    (selection, at) => {
      assertExactDataObject(selection, at, ["variant_ref", "group_index", "predicate"]);
      const variantRef = assertRef(selection.variant_ref, `${at}.variant_ref`, "capability-variant");
      const variant = state.variantByRef.get(variantRef);
      if (!variant) throw new Error(`${at}.variant_ref is not registered`);
      const groupIndex = assertInteger(selection.group_index, `${at}.group_index`, 0, MAX_ANY_OF_GROUPS - 1);
      const group = variant.formula.any_of[groupIndex];
      if (!group) throw new Error(`${at}.group_index is not present in the exact variant formula`);
      const predicate = normalizePredicate(selection.predicate, state.proofContracts, `${at}.predicate`);
      if (!group.some((candidate) => predicateKey(candidate) === predicateKey(predicate))) {
        throw new Error(`${at}.predicate is not an alternative in the exact variant formula`);
      }
      return deepFreeze({ variant_ref: variantRef, group_index: groupIndex, predicate });
    },
  ).sort((left, right) => (
    left.variant_ref.localeCompare(right.variant_ref) || left.group_index - right.group_index
  ));
  assertDataArray(
    input.dependency_proofs,
    `${label}.dependency_proofs`,
    MAX_DEPENDENCY_PROOFS,
  );
  payload.dependency_proofs = input.dependency_proofs.map((envelope, index) => {
    const envelopeLabel = `${label}.dependency_proofs[${index}]`;
    assertExactDataObject(envelope, envelopeLabel, SIGNED_ENVELOPE_FIELDS);
    assertExactDataObject(
      envelope.payload,
      `${envelopeLabel}.payload`,
      DEPENDENCY_PROOF_PAYLOAD_FIELDS,
    );
    return deepFreeze({
      ...envelope,
      payload: { ...envelope.payload },
    });
  });
  return deepFreeze(payload);
}

function normalizeProofPayload(input, context, proofContract, interval, label) {
  assertExactDataObject(input, label, DEPENDENCY_PROOF_PAYLOAD_FIELDS);
  if (input.version !== INSTRUMENT_CAPABILITY_INDEX_VERSION) {
    throw new Error(`${label}.version must be ${INSTRUMENT_CAPABILITY_INDEX_VERSION}`);
  }
  for (const field of [
    "target_domain",
    "session_nucleus_hash",
    "instrument_ref",
    "provider_id",
    "semantic_manifest_digest",
    "inventory_checkpoint_digest",
    "evidence_generation",
    "authority_epoch",
    "revocation_generation",
    "authority_resolution_digest",
  ]) {
    if (input[field] !== context[field]) throw new Error(`${label}.${field} drifted from index evidence`);
  }
  for (const [field, expected] of Object.entries({
    dependency_ref_digest: proofContract.dependency_ref_digest,
    reviewed_contract_digest: proofContract.reviewed_contract_digest,
    canonical_identity_digest: proofContract.canonical_identity_digest,
    executed_provider_id: proofContract.executed_provider_id,
    executed_provider_digest: proofContract.executed_provider_digest,
    owner_principal: proofContract.canonical_owner_principal,
    signed_verdict_type: proofContract.canonical_signed_verdict_type,
    implementation_digest: proofContract.implementation_digest,
    trust_epoch: proofContract.trust_epoch,
    artifact_digest: proofContract.implementation_digest,
  })) {
    if (input[field] !== expected) throw new Error(`${label}.${field} drifted from the closed proof contract`);
  }
  const observedAt = assertTimestamp(input.observed_at, `${label}.observed_at`);
  const expiresAt = assertTimestamp(input.expires_at, `${label}.expires_at`);
  if (Date.parse(observedAt) > interval.earliest) throw new Error(`${label}.observed_at is in the future`);
  if (Date.parse(expiresAt) <= interval.latest) throw new Error(`${label} is stale`);
  if (Date.parse(expiresAt) <= Date.parse(observedAt)) throw new Error(`${label} validity interval is empty`);
  return deepFreeze({
    ...Object.fromEntries(Object.keys(input).map((field) => [field, input[field]])),
    dependency_ref_digest: proofContract.dependency_ref_digest,
    proof_generation: assertInteger(input.proof_generation, `${label}.proof_generation`, 1),
    verdict: assertEnum(input.verdict, PROOF_VERDICTS, `${label}.verdict`),
    observed_at: observedAt,
    expires_at: expiresAt,
  });
}

function trustedClockInterval(port) {
  let descriptor = null;
  let sample;
  let restartDurable = false;
  try {
    assertRestartDurablePhysicalTrustedClockPort(port);
    descriptor = describeProductionPhysicalTrustedClockPort(port);
    sample = sampleRestartDurablePhysicalTrustedClock(port);
    restartDurable = true;
  } catch (restartError) {
    // Signed callback clocks are accepted only as non-authorizing conformance
    // clocks.  The index API still receives a private branded port rather than
    // a callback, and production port construction below requires the
    // restart-durable private brand.
    try {
      assertPhysicalTrustedClockPort(port);
      sample = samplePhysicalTrustedClock(port);
    } catch {
      throw restartError;
    }
  }
  let productionClock = false;
  if (restartDurable) {
    try {
      assertProductionPhysicalTrustedClockPort(port);
      productionClock = true;
    } catch {
      productionClock = false;
    }
  }
  return deepFreeze({
    earliest: Date.parse(sample.trusted_utc_earliest),
    latest: Date.parse(sample.trusted_utc_latest),
    sample_digest: sample.durable_state_digest || sample.signed_mapping_digest,
    authority_epoch: sample.authority_epoch,
    revocation_generation: sample.revocation_generation,
    production_clock: productionClock,
    target_domain: descriptor?.target_domain || null,
    session_nucleus_hash: descriptor?.session_nucleus_hash || null,
  });
}

function verifyEvidence(binding, interval) {
  const manifest = assertInstrumentCapabilitySemanticManifest(binding.manifest);
  const registry = assertInstrumentCapabilitySignerRegistry(binding.signer_registry);
  const manifestState = SEMANTIC_MANIFEST_STATE.get(manifest);
  const signerState = SIGNER_REGISTRY_STATE.get(registry);
  if (signerState.executedRegistry !== manifestState.executedRegistry
      || registry.executed_evidence_registry_digest !== manifest.executed_evidence_registry_digest) {
    throw new Error("instrument capability evidence and semantic manifest use different executed-evidence registries");
  }
  assertExactDataObject(
    binding.evidence_envelope,
    "instrument_capability_evidence",
    SIGNED_ENVELOPE_FIELDS,
  );
  const rawPayload = binding.evidence_envelope.payload;
  const payload = normalizeEvidencePayload(
    rawPayload,
    manifest,
    interval,
    "instrument_capability_evidence.payload",
  );
  if (hashCanonicalJson(payload) !== hashCanonicalJson(rawPayload)) {
    throw new Error("instrument capability evidence payload is not in canonical closed form");
  }
  const envelope = verifySignedEnvelope(
    binding.evidence_envelope,
    registry,
    "index_evidence",
    interval,
    "instrument_capability_evidence",
  );
  if (envelope.entry.binding_digest !== manifest.instrument_capability_manifest_digest) {
    throw new Error("instrument capability evidence signer is not bound to this semantic manifest");
  }
  if (payload.authority_epoch !== interval.authority_epoch
      || payload.revocation_generation !== interval.revocation_generation) {
    throw new Error("instrument capability evidence clock authority epoch or revocation generation drifted");
  }
  assertDataArray(
    payload.dependency_proofs,
    "instrument_capability_evidence.payload.dependency_proofs",
    MAX_DEPENDENCY_PROOFS,
  );
  const proofs = new Map();
  for (let index = 0; index < payload.dependency_proofs.length; index += 1) {
    const proofEnvelope = payload.dependency_proofs[index];
    const dependencyDigest = assertDigest(
      proofEnvelope?.payload?.dependency_ref_digest,
      `instrument_capability_evidence.payload.dependency_proofs[${index}].payload.dependency_ref_digest`,
    );
    const proofContract = manifestState.proofContracts.get(dependencyDigest);
    if (!proofContract) throw new Error("instrument capability evidence names an unregistered dependency proof");
    const proofPayload = normalizeProofPayload(
      proofEnvelope.payload,
      payload,
      proofContract,
      interval,
      `instrument_capability_evidence.payload.dependency_proofs[${index}].payload`,
    );
    if (hashCanonicalJson(proofPayload) !== hashCanonicalJson(proofEnvelope.payload)) {
      throw new Error("instrument capability dependency proof payload is not in canonical closed form");
    }
    const verified = verifySignedEnvelope(
      proofEnvelope,
      registry,
      "dependency_proof",
      interval,
      `instrument_capability_evidence.payload.dependency_proofs[${index}]`,
    );
    if (verified.entry.executed_provider_id !== proofContract.executed_provider_id
        || verified.entry.executed_provider_digest !== proofContract.executed_provider_digest
        || verified.entry.owner_principal !== proofContract.canonical_owner_principal
        || verified.entry.signed_verdict_type !== proofContract.canonical_signed_verdict_type
        || verified.entry.binding_digest !== proofContract.executed_provider_digest) {
      throw new Error("instrument capability dependency proof signer binding drifted");
    }
    if (proofs.has(dependencyDigest)) {
      throw new Error("instrument capability dependency proof fork or duplicate detected");
    }
    proofs.set(dependencyDigest, deepFreeze({
      payload: proofPayload,
      envelope_digest: verified.envelopeDigest,
    }));
  }
  return { manifest, registry, payload, proofs, evidenceDigest: envelope.envelopeDigest };
}

function inventoryDisposition(binding, payload) {
  if (binding.inventory_checkpoint == null) {
    return deepFreeze({ current: false, production: false, reason: "current_inventory_checkpoint_missing" });
  }
  const expected = {
    session_nucleus_hash: payload.session_nucleus_hash,
    physical_scope_axis_digest: payload.physical_scope_axis_digest,
    instrument_ref: payload.instrument_ref,
    enrollment_candidate_ref: payload.enrollment_candidate_ref,
    provider_id: payload.provider_id,
    provider_descriptor_digest: payload.provider_descriptor_digest,
    provider_binary_digest: payload.provider_binary_digest,
    transport_digest: payload.transport_digest,
    bootstrap_manifest_digest: payload.bootstrap_manifest_digest,
    connection_generation: payload.connection_generation,
  };
  const checkpoint = assertCurrentFixturePhysicalInventoryCheckpoint(
    binding.inventory_checkpoint,
    expected,
  );
  const projection = projectFixturePhysicalInventoryCheckpoint(checkpoint);
  if (checkpoint.checkpoint_ref !== payload.inventory_checkpoint_ref
      || checkpoint.checkpoint_digest !== payload.inventory_checkpoint_digest
      || projection.projection_digest !== payload.inventory_projection_digest) {
    throw new Error("instrument capability evidence inventory checkpoint binding drifted");
  }
  return deepFreeze({
    current: true,
    production: checkpoint.production_ready === true,
    reason: checkpoint.production_ready === true
      ? null
      : "production_inventory_checkpoint_not_enrolled",
  });
}

function assuranceResolution(variant, evidence, state) {
  const rows = [];
  let satisfied = true;
  for (const operation of variant.operation_bindings) {
    const profile = state.profiles[operation.minimum_assurance_profile_id];
    for (const axis of ASSURANCE_AXES) {
      const actual = evidence.assurance_claims[axis];
      const minimum = profile[axis];
      const relation = state.satisfaction[axis][actual.claim].includes(minimum)
        ? "satisfied"
        : "incomparable_or_weaker";
      if (relation !== "satisfied") satisfied = false;
      rows.push(deepFreeze({
        operation_id: operation.operation_id,
        axis,
        actual_claim_digest: actual.claim_digest,
        minimum_claim_digest: hashCanonicalJson({
          domain: "hacker-bob/instrument-capability-minimum-assurance/v1",
          axis,
          minimum,
          profile_id: operation.minimum_assurance_profile_id,
          assurance_profile_registry_digest: state.manifest.assurance_profile_registry_digest,
        }),
        relation,
      }));
    }
  }
  return deepFreeze({ satisfied, rows });
}

function evaluateBinding(binding) {
  const interval = trustedClockInterval(binding.trusted_clock_port);
  const verified = verifyEvidence(binding, interval);
  const { manifest, payload, proofs } = verified;
  if ((interval.target_domain != null && payload.target_domain !== interval.target_domain)
      || (interval.session_nucleus_hash != null
        && payload.session_nucleus_hash !== interval.session_nucleus_hash)) {
    throw new Error("instrument capability evidence is detached from the trusted-clock session binding");
  }
  const state = SEMANTIC_MANIFEST_STATE.get(manifest);
  const inventory = inventoryDisposition(binding, payload);
  const devicePredicates = new Set(payload.reported_device_predicate_digests);
  const selections = new Map(payload.alternative_selections.map((selection) => [
    `${selection.variant_ref}:${selection.group_index}`,
    selection.predicate,
  ]));
  const cache = new Map();
  const resolving = new Set();

  function resolvePredicate(predicate) {
    if (predicate.kind === "device_predicate") {
      return devicePredicates.has(predicate.predicate_digest);
    }
    if (predicate.kind === "dependency_proof") {
      return proofs.get(predicate.dependency_ref_digest)?.payload.verdict === "satisfied";
    }
    return resolveVariant(predicate.variant_ref).requirements_satisfied;
  }

  function publicReason(predicate) {
    if (predicate.kind === "device_predicate") return "missing_device_predicate";
    if (predicate.kind === "dependency_proof") return "missing_dependency_proof";
    return "missing_variant_dependency";
  }

  function resolveVariant(variantRef) {
    if (cache.has(variantRef)) return cache.get(variantRef);
    const variant = state.variantByRef.get(variantRef);
    if (!variant) throw new Error("instrument capability formula names an unknown variant");
    if (resolving.has(variantRef)) throw new Error("instrument capability formula contains a cycle");
    resolving.add(variantRef);
    const reasonCodes = [];
    const allBindings = variant.formula.all_of.map((predicate) => ({
      predicate,
      satisfied: resolvePredicate(predicate),
    }));
    for (const bindingResult of allBindings) {
      if (!bindingResult.satisfied) reasonCodes.push(publicReason(bindingResult.predicate));
    }
    const selectedAlternativeDigests = [];
    for (let groupIndex = 0; groupIndex < variant.formula.any_of.length; groupIndex += 1) {
      const group = variant.formula.any_of[groupIndex];
      const selected = selections.get(`${variantRef}:${groupIndex}`) || null;
      if (!selected || !group.some((candidate) => predicateKey(candidate) === predicateKey(selected))
          || !resolvePredicate(selected)) {
        reasonCodes.push("unresolved_alternative");
        selectedAlternativeDigests.push(null);
      } else {
        selectedAlternativeDigests.push(hashCanonicalJson(selected));
      }
    }
    const assurance = assuranceResolution(variant, payload, state);
    if (!assurance.satisfied) reasonCodes.push("assurance_not_satisfied");
    if (variant.disposition === "unsupported") reasonCodes.push("provider_declared_unsupported");
    const requirementsSatisfied = reasonCodes.length === 0;
    const productionEligible = interval.production_clock && inventory.production;
    if (!interval.production_clock) reasonCodes.push("production_clock_not_qualified");
    if (!inventory.production) reasonCodes.push(inventory.reason);
    if (!productionEligible) reasonCodes.push("production_trust_not_enrolled");
    const availability = requirementsSatisfied && productionEligible
      ? "available"
      : "unavailable";
    const privateResolution = {
      variant_binding_digest: variant.variant_binding_digest,
      evidence_digest: verified.evidenceDigest,
      all_of: allBindings.map((entry) => ({
        predicate_binding_digest: hashCanonicalJson(entry.predicate),
        satisfied: entry.satisfied,
      })),
      selected_alternative_digests: selectedAlternativeDigests,
      proof_envelope_digests: [...proofs.values()].map((proof) => proof.envelope_digest).sort(),
      assurance_rows: assurance.rows,
      trusted_clock_sample_digest: interval.sample_digest,
      inventory_checkpoint_digest: payload.inventory_checkpoint_digest,
    };
    const resolutionDigest = hashCanonicalJson(privateResolution);
    const capabilityRef = `instrument-capability:${hashCanonicalJson({
      manifest_digest: manifest.instrument_capability_manifest_digest,
      variant_binding_digest: variant.variant_binding_digest,
      resolution_digest: resolutionDigest,
    })}`;
    const result = deepFreeze({
      version: INSTRUMENT_CAPABILITY_INDEX_VERSION,
      capability_ref: capabilityRef,
      operation_bindings: variant.operation_bindings.map((operation) => deepFreeze({
        operation_id: operation.operation_id,
      })),
      technique_bindings: variant.technique_bindings.map((technique) => deepFreeze({
        technique_id: technique.technique_id,
      })),
      parameter_selector_id: variant.parameter_selector_id,
      effect_profile_refs: variant.effect_profile_refs,
      disposition: variant.disposition,
      availability,
      requirements_status: requirementsSatisfied ? "satisfied" : "unsatisfied",
      assurance: assurance.rows.map((row) => deepFreeze({
        operation_id: row.operation_id,
        axis: row.axis,
        relation: row.relation,
      })),
      unavailable_reason_codes: Object.freeze([...new Set(reasonCodes)].sort()),
    });
    cache.set(variantRef, result);
    resolving.delete(variantRef);
    return result;
  }

  const records = state.variants.map((variant) => resolveVariant(variant.variant_ref));
  const projectionBasis = {
    version: INSTRUMENT_CAPABILITY_INDEX_VERSION,
    target_domain: payload.target_domain,
    session_nucleus_hash: payload.session_nucleus_hash,
    instrument_ref: payload.instrument_ref,
    provider_ref: manifest.provider_ref,
    evidence_ref: `instrument-capability-evidence:${verified.evidenceDigest}`,
    observed_at: payload.observed_at,
    expires_at: payload.expires_at,
    disposition: records.some((record) => record.availability === "available")
      ? "current_available"
      : "current_unavailable",
    records,
  };
  const projection = deepFreeze({
    ...projectionBasis,
    index_projection_digest: hashCanonicalJson(projectionBasis),
  });
  assertNoPublicByteMaterial(projection, "instrument_capability_index_projection");
  const serialized = JSON.stringify(projection);
  for (const forbidden of [
    payload.provider_id,
    manifest.semantic_manifest_digest,
    manifest.provider_descriptor_digest,
    manifest.executed_evidence_registry_digest,
  ]) {
    if (serialized.includes(forbidden)) {
      throw new Error("instrument capability public projection leaked private provider identity material");
    }
  }
  return projection;
}

function createInstrumentCapabilityIndexPort(input) {
  assertExactDataObject(input, "instrument_capability_index_port", [
    "version",
    "mode",
    "bindings",
  ]);
  if (input.version !== INSTRUMENT_CAPABILITY_INDEX_VERSION) {
    throw new Error(`instrument_capability_index_port.version must be ${INSTRUMENT_CAPABILITY_INDEX_VERSION}`);
  }
  const mode = assertEnum(input.mode, ["conformance", "production"], "instrument_capability_index_port.mode");
  assertDataArray(input.bindings, "instrument_capability_index_port.bindings", 128, { minimum: 1 });
  const bindings = input.bindings.map((binding, index) => {
    const label = `instrument_capability_index_port.bindings[${index}]`;
    assertExactDataObject(binding, label, [
      "manifest",
      "signer_registry",
      "evidence_envelope",
      "trusted_clock_port",
      "inventory_checkpoint",
    ]);
    assertInstrumentCapabilitySemanticManifest(binding.manifest);
    assertInstrumentCapabilitySignerRegistry(binding.signer_registry);
    assertExactDataObject(binding.evidence_envelope, `${label}.evidence_envelope`, SIGNED_ENVELOPE_FIELDS);
    assertExactDataObject(
      binding.evidence_envelope.payload,
      `${label}.evidence_envelope.payload`,
      EVIDENCE_PAYLOAD_FIELDS,
    );
    try {
      assertRestartDurablePhysicalTrustedClockPort(binding.trusted_clock_port);
    } catch {
      assertPhysicalTrustedClockPort(binding.trusted_clock_port);
    }
    return Object.freeze({ ...binding });
  });
  const identities = new Set();
  for (const binding of bindings) {
    const payload = binding.evidence_envelope?.payload;
    const identity = `${payload?.target_domain}:${payload?.instrument_ref}`;
    if (identities.has(identity)) throw new Error("instrument capability index port has duplicate instrument bindings");
    identities.add(identity);
  }
  if (mode === "production") {
    for (const binding of bindings) {
      // Both assertions are private-brand checks.  Neither can be promoted by
      // setting a caller-controlled `production_ready` field.
      assertProductionPhysicalTrustedClockPort(binding.trusted_clock_port);
      const projection = evaluateBinding(binding);
      if (projection.records.every((record) => (
        record.unavailable_reason_codes.includes("production_inventory_checkpoint_not_enrolled")
        || record.unavailable_reason_codes.includes("current_inventory_checkpoint_missing")
      ))) {
        throw new Error("production instrument capability index requires enrolled production inventory trust");
      }
    }
  }
  const port = deepFreeze({
    version: INSTRUMENT_CAPABILITY_INDEX_VERSION,
    mode,
    binding_count: bindings.length,
    port_digest: hashCanonicalJson({
      version: INSTRUMENT_CAPABILITY_INDEX_VERSION,
      mode,
      bindings: bindings.map((binding) => ({
        manifest_digest: binding.manifest.instrument_capability_manifest_digest,
        signer_registry_digest: binding.signer_registry.registry_digest,
        evidence_digest: binding.evidence_envelope?.envelope_digest || null,
      })),
    }),
  });
  CAPABILITY_PORTS.add(port);
  CAPABILITY_PORT_STATE.set(port, { bindings });
  return port;
}

function assertInstrumentCapabilityIndexPort(port) {
  if (!port || utilTypes.isProxy(port) || !Object.isFrozen(port)
      || !CAPABILITY_PORTS.has(port) || !CAPABILITY_PORT_STATE.has(port)) {
    throw new Error("instrument capability index requires a privately branded port");
  }
  return port;
}

function normalizeQuery(input) {
  assertExactDataObject(input, "instrument_capability_query", [
    "target_domain",
    "instrument_ref",
  ], [
    "operation_id",
    "technique_id",
    "parameter_selector_id",
    "availability",
    "cursor",
    "limit",
  ]);
  return deepFreeze({
    target_domain: assertToken(input.target_domain, "instrument_capability_query.target_domain"),
    instrument_ref: assertRef(input.instrument_ref, "instrument_capability_query.instrument_ref", "instrument"),
    operation_id: input.operation_id == null
      ? null
      : assertId(input.operation_id, "instrument_capability_query.operation_id"),
    technique_id: input.technique_id == null
      ? null
      : assertId(input.technique_id, "instrument_capability_query.technique_id"),
    parameter_selector_id: input.parameter_selector_id == null
      ? null
      : assertId(input.parameter_selector_id, "instrument_capability_query.parameter_selector_id"),
    availability: input.availability == null
      ? "all"
      : assertEnum(input.availability, QUERY_AVAILABILITY_VALUES, "instrument_capability_query.availability"),
    cursor: input.cursor == null ? null : assertToken(input.cursor, "instrument_capability_query.cursor"),
    limit: input.limit == null
      ? 20
      : assertInteger(input.limit, "instrument_capability_query.limit", 1, MAX_QUERY_LIMIT),
  });
}

function cursorFor(projectionDigest, filterDigest, offset) {
  return `capability-cursor:v1:${hashCanonicalJson({ projectionDigest, filterDigest, offset })}:${offset}`;
}

function parseCursor(cursor, projectionDigest, filterDigest, maximum) {
  if (cursor == null) return 0;
  const match = /^capability-cursor:v1:([a-f0-9]{64}):(0|[1-9][0-9]*)$/u.exec(cursor);
  if (!match) throw instrumentCapabilityError("instrument_capability_query_cursor_invalid", "cursor is malformed");
  const offset = Number(match[2]);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > maximum) {
    throw instrumentCapabilityError("instrument_capability_query_budget_exceeded", "cursor exceeds the bounded result set");
  }
  const expected = cursorFor(projectionDigest, filterDigest, offset);
  if (cursor !== expected) {
    throw instrumentCapabilityError("instrument_capability_query_cursor_invalid", "cursor is detached from this projection or filter");
  }
  return offset;
}

function queryInstrumentCapabilityIndexPort(portInput, input) {
  const port = assertInstrumentCapabilityIndexPort(portInput);
  const query = normalizeQuery(input);
  const state = CAPABILITY_PORT_STATE.get(port);
  const binding = state.bindings.find((candidate) => (
    candidate.evidence_envelope?.payload?.target_domain === query.target_domain
    && candidate.evidence_envelope?.payload?.instrument_ref === query.instrument_ref
  ));
  if (!binding) {
    throw instrumentCapabilityError(
      "instrument_capability_index_binding_not_found",
      "no capability index is bound to the requested session and instrument",
    );
  }
  const projection = evaluateBinding(binding);
  const allRecords = projection.records;
  if (allRecords.length > MAX_QUERY_SCAN) {
    throw instrumentCapabilityError("instrument_capability_query_budget_exceeded", "index exceeds the fixed scan budget");
  }
  const knownOperations = new Set(allRecords.flatMap((record) => (
    record.operation_bindings.map((entry) => entry.operation_id)
  )));
  const knownTechniques = new Set(allRecords.flatMap((record) => (
    record.technique_bindings.map((entry) => entry.technique_id)
  )));
  const knownSelectors = new Set(allRecords.map((record) => record.parameter_selector_id));
  if (query.operation_id != null && !knownOperations.has(query.operation_id)) {
    throw instrumentCapabilityError("instrument_capability_query_contract_mismatch", "operation is not in the closed index");
  }
  if (query.technique_id != null && !knownTechniques.has(query.technique_id)) {
    throw instrumentCapabilityError("instrument_capability_query_contract_mismatch", "technique is not in the closed index");
  }
  if (query.parameter_selector_id != null && !knownSelectors.has(query.parameter_selector_id)) {
    throw instrumentCapabilityError("instrument_capability_query_contract_mismatch", "parameter selector is not in the closed index");
  }
  const filtered = allRecords.filter((record) => (
    (query.operation_id == null
      || record.operation_bindings.some((entry) => entry.operation_id === query.operation_id))
    && (query.technique_id == null
      || record.technique_bindings.some((entry) => entry.technique_id === query.technique_id))
    && (query.parameter_selector_id == null
      || record.parameter_selector_id === query.parameter_selector_id)
    && (query.availability === "all" || record.availability === query.availability)
  ));
  if ((query.operation_id != null || query.technique_id != null || query.parameter_selector_id != null)
      && filtered.length === 0) {
    throw instrumentCapabilityError(
      "instrument_capability_query_contract_mismatch",
      "operation, technique, and parameter selector do not identify an exact registered variant",
    );
  }
  const filterDigest = hashCanonicalJson({
    operation_id: query.operation_id,
    technique_id: query.technique_id,
    parameter_selector_id: query.parameter_selector_id,
    availability: query.availability,
  });
  const offset = parseCursor(
    query.cursor,
    projection.index_projection_digest,
    filterDigest,
    filtered.length,
  );
  const records = filtered.slice(offset, offset + query.limit);
  const nextOffset = offset + records.length;
  const result = deepFreeze({
    version: INSTRUMENT_CAPABILITY_INDEX_VERSION,
    target_domain: projection.target_domain,
    instrument_ref: projection.instrument_ref,
    index_ref: `instrument-capability-index:${projection.index_projection_digest}`,
    disposition: projection.disposition,
    total_matched: filtered.length,
    returned_count: records.length,
    records,
    next_cursor: nextOffset < filtered.length
      ? cursorFor(projection.index_projection_digest, filterDigest, nextOffset)
      : null,
  });
  assertNoPublicByteMaterial(result, "instrument_capability_query_result");
  return result;
}

function installInstrumentCapabilityIndexPort(portInput) {
  if (arguments.length !== 1) {
    throw new Error("instrument capability runtime install accepts only a branded production port");
  }
  const port = assertInstrumentCapabilityIndexPort(portInput);
  if (port.mode !== "production") {
    throw new Error("instrument capability runtime accepts only a production-qualified index port");
  }
  if (installedPort != null) throw new Error("instrument capability index port is already installed");
  installedPort = port;
  let active = true;
  return function uninstallInstrumentCapabilityIndexPort() {
    if (active && installedPort === port) {
      installedPort = null;
      active = false;
    }
  };
}

function queryInstalledInstrumentCapabilities(input) {
  if (installedPort == null || !CAPABILITY_PORTS.has(installedPort)) {
    throw instrumentCapabilityError(
      "instrument_capability_runtime_unconfigured",
      "production instrument capability index is not installed",
    );
  }
  if (installedPortInFlight) {
    throw instrumentCapabilityError(
      "instrument_capability_runtime_reentrant",
      "instrument capability query is already in progress",
    );
  }
  installedPortInFlight = true;
  try {
    return queryInstrumentCapabilityIndexPort(installedPort, input);
  } finally {
    installedPortInFlight = false;
  }
}

module.exports = Object.freeze({
  ASSURANCE_AXES,
  INSTRUMENT_CAPABILITY_CLAIM_DOMAIN,
  INSTRUMENT_CAPABILITY_EVIDENCE_DOMAIN,
  INSTRUMENT_CAPABILITY_INDEX_VERSION,
  INSTRUMENT_CAPABILITY_PROOF_DOMAIN,
  INSTRUMENT_CAPABILITY_SIGNING_DOMAIN,
  MAX_QUERY_LIMIT,
  assertInstrumentCapabilityIndexPort,
  assertInstrumentCapabilitySemanticManifest,
  assertInstrumentCapabilitySignerRegistry,
  buildInstrumentCapabilitySignerRegistry,
  createInstrumentCapabilityIndexPort,
  defineInstrumentCapabilitySemanticManifest,
  installInstrumentCapabilityIndexPort,
  instrumentCapabilitySignatureInputDigest,
  queryInstalledInstrumentCapabilities,
  queryInstrumentCapabilityIndexPort,
});
