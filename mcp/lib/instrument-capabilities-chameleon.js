"use strict";

// Private Chameleon Ultra adapter for the provider-neutral PH-I1 index.  Raw
// firmware command IDs and reviewed provider spellings terminate here.  The
// generic index receives only opaque predicate/dpendency digests and reversible
// canonical identities that fit the executed-evidence registry grammar.

const { types: utilTypes } = require("node:util");

const {
  assertExecutedEvidenceRegistry,
  buildExecutedEvidenceRegistry,
} = require("./executed-evidence-registry.js");
const {
  defineProviderDescriptor,
} = require("./instrument-provider-contract.js");
const {
  buildEffectTemplateRegistry,
} = require("./requested-effects.js");
const {
  defineInstrumentCapabilitySemanticManifest,
} = require("./instrument-capabilities.js");
const {
  hashCanonicalJson,
  isPlainObject,
} = require("./verification-contracts.js");
const {
  CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY,
} = require("../../packages/bob-instrument-chameleon/lib/bootstrap-operations.js");
const {
  CHAMELEON_SEMANTIC_DIGESTS,
  CHAMELEON_SEMANTIC_MANIFEST,
  CHAMELEON_V220_CODEC_PROFILE,
  CHAMELEON_V220_SOURCE_PROFILE,
  dependencyProofContract,
  getChameleonAvailabilityVariant,
  getChameleonOperation,
  reviewedManifestSnapshot,
} = require("../../packages/bob-instrument-chameleon/lib/operations.js");

// 62 bytes is the largest domain accepted here: the reversible `rp_`/`rv_`
// plus lowercase-hex representation then remains within the executed registry's
// 128-character identifier ceiling (3 + 2*62 = 127).
const REVIEWED_TOKEN_PATTERN = /^[a-z][a-z0-9._:-]{0,61}$/u;
const PROVIDER_KIND_MAP = Object.freeze({
  compiler: "compiler",
  conformance: "conformance",
  manual_procedure: "manual-procedure",
  observer: "observer",
  transport: "transport",
  vault_tool: "vault-tool",
});
const STATIC_VERIFY_PROOF_REJECTOR = Object.freeze(async function rejectStaticDescriptorProof() {
  throw new Error("Chameleon index proof descriptors are identity-only; signed evidence is verified by PH-I1");
});

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function assertExactDataObject(value, label, fields) {
  if (!value || utilTypes.isProxy(value) || !isPlainObject(value)) {
    throw new Error(`${label} must be an exact plain data object`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.length || fields.some((field) => !keys.includes(field))) {
    throw new Error(`${label} fields are not exact`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw new Error(`${label}.${field} must be an enumerable data property`);
    }
  }
  return value;
}

function assertDenseCommandArray(value) {
  if (utilTypes.isProxy(value) || !Array.isArray(value) || value.length > 256) {
    throw new Error("reported Chameleon commands must be a bounded dense data array");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw new Error("reported Chameleon commands must be a bounded dense data array");
    }
  }
  for (const field of Reflect.ownKeys(value)) {
    if (field === "length") continue;
    if (typeof field !== "string" || !/^(0|[1-9][0-9]*)$/u.test(field)
        || Number(field) >= value.length) {
      throw new Error("reported Chameleon commands must be a bounded dense data array");
    }
  }
  return value;
}

function encodeReviewedToken(value, label) {
  if (typeof value !== "string" || !REVIEWED_TOKEN_PATTERN.test(value)) {
    throw new Error(`${label} is outside the fixed reviewed-token grammar`);
  }
  return Buffer.from(value, "utf8").toString("hex");
}

function canonicalReviewedIdentity(dependencyRef, contract) {
  const refHex = encodeReviewedToken(dependencyRef, "reviewed dependency ref");
  const ownerHex = encodeReviewedToken(contract.owner_principal, "reviewed owner principal");
  const verdictHex = encodeReviewedToken(contract.signed_verdict_type, "reviewed verdict type");
  const providerKind = PROVIDER_KIND_MAP[contract.provider_kind];
  if (!providerKind) throw new Error("reviewed proof provider kind has no fixed canonical mapping");
  const canonical = {
    dependency_ref_digest: hashCanonicalJson({
      domain: "hacker-bob/chameleon-reviewed-dependency-ref/v1",
      dependency_ref: dependencyRef,
    }),
    reviewed_contract_digest: contract.contract_digest,
    executed_provider_id: `rp_${refHex}`,
    provider_kind: providerKind,
    canonical_owner_principal: `principal:ro.${ownerHex}`,
    canonical_signed_verdict_type: `rv_${verdictHex}`,
  };
  return deepFreeze({
    ...canonical,
    canonical_identity_digest: hashCanonicalJson({
      domain: "hacker-bob/instrument-capability-reviewed-proof-identity/v1",
      ...canonical,
    }),
  });
}

function manualContract(action) {
  const dependencyRef = `manual_procedure:${action.procedure_id}`;
  const basis = {
    dependency_ref: dependencyRef,
    provider_kind: "manual_procedure",
    owner_principal: "enrolled_operator",
    artifact_digest_binding: "procedure_and_receipt_digest",
    signed_verdict_type: "bob-proof:manual-procedure:v1",
    trust_epoch_binding: "session_authority_epoch",
    freshness_policy: "attempt_and_operator_receipt",
    revocation_policy: "deny_on_operator_session_or_receipt_drift",
  };
  return deepFreeze({
    dependencyRef,
    contract: {
      ...basis,
      contract_digest: hashCanonicalJson(basis),
    },
  });
}

function reviewedProofContracts() {
  const reviewed = reviewedManifestSnapshot();
  const entries = Object.keys(reviewed.dependency_proof_provider_registry).map((dependencyRef) => {
    const contract = dependencyProofContract(dependencyRef);
    if (!contract) throw new Error(`reviewed Chameleon proof ${dependencyRef} is missing its runtime contract`);
    return { dependencyRef, contract };
  });
  for (const action of Object.values(reviewed.manual_action_registry)) {
    entries.push(manualContract(action));
  }
  entries.sort((left, right) => left.dependencyRef.localeCompare(right.dependencyRef));
  return entries;
}

function createChameleonCapabilityExecutedEvidenceRegistry({
  attested_at: attestedAt,
  expires_at: expiresAt,
  trust_epoch: trustEpoch = 1,
} = {}) {
  const attested = new Date(attestedAt).toISOString();
  const expires = new Date(expiresAt).toISOString();
  if (Date.parse(expires) <= Date.parse(attested)) {
    throw new Error("Chameleon capability proof registry validity interval is empty");
  }
  const freshnessWindowMs = Date.parse(expires) - Date.parse(attested);
  const definitions = reviewedProofContracts().map(({ dependencyRef, contract }) => {
    const identity = canonicalReviewedIdentity(dependencyRef, contract);
    return {
      version: 1,
      provider_id: identity.executed_provider_id,
      provider_kind: identity.provider_kind,
      owner_principal: identity.canonical_owner_principal,
      signed_verdict_type: identity.canonical_signed_verdict_type,
      trust_epoch: trustEpoch,
      trust_state: "trusted",
      attested_at: attested,
      freshness_window_ms: freshnessWindowMs,
      revoked: false,
      tool_digest: hashCanonicalJson({
        domain: "hacker-bob/chameleon-proof-tool-binding/v1",
        reviewed_contract_digest: contract.contract_digest,
        canonical_identity_digest: identity.canonical_identity_digest,
      }),
      verify_proof: STATIC_VERIFY_PROOF_REJECTOR,
    };
  });
  return buildExecutedEvidenceRegistry({
    source_adapters: [],
    context_resolvers: [],
    replay_executors: [],
    verifier_templates: [],
    dependency_proof_providers: definitions,
  });
}

function chameleonBootstrapProviderDescriptor() {
  const effectRegistry = buildEffectTemplateRegistry([{
    version: 1,
    template_id: "chameleon.bootstrap.observe",
    subject_kind: "instrument",
    action: "observe",
    channel: "usb",
    persistence: "none",
    bounds: {},
  }]);
  const template = effectRegistry.get("chameleon.bootstrap.observe");
  const worstCaseEffect = {
    template_id: template.template_id,
    template_digest: template.template_digest,
    subject_kind: template.subject_kind,
    action: template.action,
    channel: template.channel,
    persistence: template.persistence,
  };
  const capabilities = CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.ids().map((operationId) => {
    const operation = CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.get(operationId);
    return {
      capability_id: `bootstrap.${operationId.slice("instrument.".length)}`,
      operation_id: operation.operation_id,
      operation_digest: operation.operation_digest,
      worst_case_effects: [worstCaseEffect],
      idempotency: "read_only_idempotent",
      retry_policy: "new_attempt_after_confirmed_no_effect",
      stop_semantics: "not_applicable",
      restore_policy: "not_required",
    };
  });
  return defineProviderDescriptor({
    version: 1,
    abi_version: 3,
    provider_id: "chameleon_ultra",
    provider_version: "2.2.0",
    implementation_digest: hashCanonicalJson({
      domain: "hacker-bob/chameleon-reviewed-bootstrap-implementation/v1",
      source_profile_digest: CHAMELEON_V220_SOURCE_PROFILE.source_profile_digest,
      codec_profile_digest: CHAMELEON_V220_CODEC_PROFILE.codec_profile_digest,
    }),
    operation_registry_digest: CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.registry_digest,
    capabilities,
  }, CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY, effectRegistry);
}

function variantRef(capabilityId, variantId) {
  return `capability-variant:${hashCanonicalJson({
    domain: "hacker-bob/chameleon-capability-variant-ref/v1",
    semantic_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
    capability_id: capabilityId,
    variant_id: variantId,
  })}`;
}

function devicePredicateDigest(commandId) {
  return hashCanonicalJson({
    domain: "hacker-bob/chameleon-device-command-predicate/v1",
    semantic_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
    source_profile_digest: CHAMELEON_V220_SOURCE_PROFILE.source_profile_digest,
    codec_profile_digest: CHAMELEON_V220_CODEC_PROFILE.codec_profile_digest,
    command_id: commandId,
  });
}

function dependencyIdentityByRef() {
  return new Map(reviewedProofContracts().map(({ dependencyRef, contract }) => [
    dependencyRef,
    canonicalReviewedIdentity(dependencyRef, contract),
  ]));
}

function normalizeFormulaRef(ref, identities) {
  if (ref.startsWith("command:")) {
    const commandId = Number(ref.slice("command:".length));
    if (!Number.isSafeInteger(commandId) || commandId < 1 || commandId > 0xffff) {
      throw new Error("reviewed Chameleon formula contains an invalid command predicate");
    }
    return deepFreeze({ kind: "device_predicate", predicate_digest: devicePredicateDigest(commandId) });
  }
  if (ref.startsWith("capability_variant:")) {
    const raw = ref.slice("capability_variant:".length);
    const separator = raw.lastIndexOf("/");
    if (separator < 1 || separator === raw.length - 1) {
      throw new Error("reviewed Chameleon formula contains a malformed exact variant ref");
    }
    return deepFreeze({
      kind: "capability_variant",
      variant_ref: variantRef(raw.slice(0, separator), raw.slice(separator + 1)),
    });
  }
  const identity = identities.get(ref);
  if (!identity) throw new Error(`reviewed Chameleon formula names unknown dependency ${ref}`);
  return deepFreeze({
    kind: "dependency_proof",
    dependency_ref_digest: identity.dependency_ref_digest,
  });
}

function dispositionReasonCode(disposition) {
  return Object.freeze({
    planned: "reviewed_provider_variant",
    optional: "optional_provider_variant",
    provider_internal: "provider_internal_variant",
    operator_only: "operator_only_variant",
    unsupported: "provider_declared_unsupported",
  })[disposition];
}

function createChameleonInstrumentCapabilitySemanticManifest(executedRegistry) {
  const reviewed = reviewedManifestSnapshot();
  const providerDescriptor = chameleonBootstrapProviderDescriptor();
  const providerOperations = new Map(providerDescriptor.capabilities.map((capability) => [
    capability.operation_id,
    capability.operation_digest,
  ]));
  const identities = dependencyIdentityByRef();
  const proofContracts = [...identities.values()].map((identity) => ({ ...identity }));
  const variants = [];
  for (const row of reviewed.coverage) {
    const dependency = reviewed.capability_dependency_registry[row.provider_capability_id];
    if (!dependency) continue;
    for (const [variantId, variant] of Object.entries(dependency.variants)) {
      const runtimeVariant = getChameleonAvailabilityVariant(row.provider_capability_id, variantId);
      if (!runtimeVariant) throw new Error("reviewed Chameleon variant is absent from runtime semantics");
      variants.push({
        variant_ref: variantRef(row.provider_capability_id, variantId),
        parameter_selector_id: variant.parameter_selector_id,
        disposition: row.disposition,
        reason_code: dispositionReasonCode(row.disposition),
        operation_bindings: variant.normalized_operations.map((operationId) => {
          const operation = getChameleonOperation(operationId);
          if (!operation) throw new Error(`reviewed Chameleon operation ${operationId} is missing`);
          const providerOperationDigest = providerOperations.get(operationId) || null;
          return {
            operation_id: operationId,
            operation_digest: providerOperationDigest || hashCanonicalJson({
              domain: "hacker-bob/chameleon-reviewed-semantic-operation/v1",
              semantic_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
              operation,
            }),
            operation_authority: providerOperationDigest == null
              ? "semantic_manifest"
              : "provider_abi",
            minimum_assurance_profile_id: operation.minimum_assurance_profile_id,
          };
        }),
        technique_bindings: variant.technique_bindings.map((techniqueId) => ({
          technique_id: techniqueId,
          technique_digest: hashCanonicalJson({
            domain: "hacker-bob/normalized-physical-technique/v1",
            technique_id: techniqueId,
            technique_registry_digest: CHAMELEON_SEMANTIC_DIGESTS.technique_registry_sha256,
          }),
        })),
        effect_profile_refs: variant.effect_profile_refs.map((effectProfileId) => (
          `effect-profile:${hashCanonicalJson({
            domain: "hacker-bob/physical-effect-profile-ref/v1",
            effect_profile_id: effectProfileId,
            effect_profile: reviewed.effect_profiles[effectProfileId],
          })}`
        )),
        formula: {
          all_of: [...dependency.all_of, ...variant.all_of]
            .map((ref) => normalizeFormulaRef(ref, identities)),
          any_of: [...dependency.any_of, ...variant.any_of]
            .map((group) => group.map((ref) => normalizeFormulaRef(ref, identities))),
        },
        provider_variant_digest: runtimeVariant.availability_variant_digest,
      });
    }
  }
  return defineInstrumentCapabilitySemanticManifest({
    version: 1,
    provider_descriptor: providerDescriptor,
    semantic_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
    assurance_profile_registry_digest:
      CHAMELEON_SEMANTIC_DIGESTS.assurance_profile_registry_sha256,
    assurance_satisfaction_registry_digest:
      CHAMELEON_SEMANTIC_DIGESTS.assurance_satisfaction_registry_sha256,
    dependency_proof_registry_digest:
      CHAMELEON_SEMANTIC_DIGESTS.dependency_proof_provider_registry_sha256,
    assurance_profiles: reviewed.assurance_profile_registry,
    assurance_satisfaction: reviewed.assurance_satisfaction_registry,
    proof_contracts: proofContracts,
    variants,
  }, executedRegistry);
}

function projectChameleonReportedCommands(commandIds) {
  assertDenseCommandArray(commandIds);
  const known = new Set(CHAMELEON_V220_CODEC_PROFILE.command_ids);
  const accepted = [];
  let rejected = 0;
  for (const commandId of commandIds) {
    if (!Number.isSafeInteger(commandId) || commandId < 1 || commandId > 0xffff) {
      throw new Error("reported Chameleon command is outside the firmware command range");
    }
    if (known.has(commandId)) accepted.push(devicePredicateDigest(commandId));
    else rejected += 1;
  }
  const unique = [...new Set(accepted)].sort();
  return deepFreeze({
    reported_device_predicate_digests: unique,
    rejected_command_count: rejected,
    projection_digest: hashCanonicalJson({
      domain: "hacker-bob/chameleon-reported-command-projection/v1",
      reported_device_predicate_digests: unique,
      rejected_command_count: rejected,
    }),
  });
}

function projectChameleonAlternativeSelection(input) {
  assertExactDataObject(input, "Chameleon alternative selection", [
    "capability_id",
    "variant_id",
    "group_index",
    "dependency_ref",
  ]);
  if (typeof input.capability_id !== "string" || typeof input.variant_id !== "string") {
    throw new Error("Chameleon alternative selection must name a reviewed exact variant");
  }
  const runtimeVariant = getChameleonAvailabilityVariant(input.capability_id, input.variant_id);
  if (!runtimeVariant) {
    throw new Error("Chameleon alternative selection must name a reviewed exact variant");
  }
  if (!Number.isSafeInteger(input.group_index) || input.group_index < 0
      || !runtimeVariant.any_of[input.group_index]
      || !runtimeVariant.any_of[input.group_index].includes(input.dependency_ref)) {
    throw new Error("Chameleon alternative selection is not in the reviewed exact variant formula");
  }
  const identities = dependencyIdentityByRef();
  return deepFreeze({
    variant_ref: variantRef(input.capability_id, input.variant_id),
    group_index: input.group_index,
    predicate: normalizeFormulaRef(input.dependency_ref, identities),
  });
}

function chameleonCapabilityProofSignerBinding(dependencyRef, executedRegistry) {
  assertExecutedEvidenceRegistry(executedRegistry);
  const entry = reviewedProofContracts().find((candidate) => candidate.dependencyRef === dependencyRef);
  if (!entry) throw new Error("Chameleon dependency proof is not registered");
  const identity = canonicalReviewedIdentity(entry.dependencyRef, entry.contract);
  const provider = executedRegistry.get("dependency_proof_providers", identity.executed_provider_id);
  if (!provider) throw new Error("Chameleon dependency proof is absent from executed-evidence registry");
  return deepFreeze({
    ...identity,
    executed_provider_digest: provider.provider_digest,
    implementation_digest: provider.tool_digest || provider.artifact_digest,
    trust_epoch: provider.trust_epoch,
  });
}

module.exports = Object.freeze({
  chameleonBootstrapProviderDescriptor,
  chameleonCapabilityProofSignerBinding,
  createChameleonCapabilityExecutedEvidenceRegistry,
  createChameleonInstrumentCapabilitySemanticManifest,
  projectChameleonAlternativeSelection,
  projectChameleonReportedCommands,
});
