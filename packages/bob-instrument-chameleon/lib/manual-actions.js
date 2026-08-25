"use strict";

// PH-P9 operator-mediated Chameleon actions. This is a provider-private,
// transport-free protocol: it never talks to hardware and never exposes an
// arbitrary button, path, callback, byte buffer, or generic manual command.
// Only source-pinned procedures in the reviewed Chameleon manifest can be
// reserved. Production remains disabled until the in-memory one-use owner is
// replaced by a restart-durable owner and the non-waivable HIL matrix passes.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const {
  assertNoPublicByteMaterial,
} = require("../../bob-instrument-contracts/lib/instrument-provider-contract.js");
const {
  normalizeOpaqueRef,
} = require("../../bob-instrument-contracts/lib/physical-quantities.js");
const {
  hashCanonicalJson,
} = require("../../bob-instrument-contracts/lib/verification-contracts.js");
const {
  assertVerifiedActivePhysicalExecutionGrant,
} = require("../../../mcp/domains/physical/physical-authority.js");
const {
  assertPhysicalObserverEnrollmentRegistry,
  normalizePhysicalExperimentPlan,
} = require("../../../mcp/domains/physical/physical-experiment-contract.js");
const {
  assertPhysicalTrustedClockSample,
} = require("../../../mcp/domains/physical/physical-trusted-clock.js");
const {
  assertChameleonStateRestoreResult,
  assertChameleonStateSnapshot,
  assertChameleonStateTransition,
} = require("./state-stewardship.js");
const {
  CHAMELEON_SEMANTIC_MANIFEST,
  getChameleonOperation,
  reviewedManifestSnapshot,
} = require("./operations.js");

const CHAMELEON_MANUAL_ACTION_VERSION = 1;
const PROVIDER_ID = "chameleon_ultra";
const MANUAL_OPERATION_ID = "instrument.manual_action";
const SIGNATURE_DOMAIN = "hacker-bob/chameleon-manual-action-signature/v1";
const RESERVATION_DOMAIN = "hacker-bob/chameleon-manual-action-reservation/v1";
const EXECUTION_DOMAIN = "hacker-bob/chameleon-manual-action-execution/v1";
const TERMINAL_DOMAIN = "hacker-bob/chameleon-manual-action-terminal/v1";
const PARAMETER_DOMAIN = "hacker-bob/chameleon-manual-action-parameters/v1";
const PROCEDURE_DOMAIN = "hacker-bob/chameleon-manual-action-procedure/v1";
const EFFECT_BINDING_DOMAIN = "hacker-bob/chameleon-manual-action-effects/v1";
const OUTCOME_DOMAIN = "hacker-bob/chameleon-manual-action-outcome/v1";
const RESTORATION_RECEIPT_DOMAIN = "hacker-bob/chameleon-manual-action-restoration/v1";
const MAX_CHALLENGE_TTL_MS = 300_000;
const MAX_RUNTIME_RESERVATIONS = 4096;
// This pins the separately inert, plan-only PH-P9 HIL contract. The plan and
// any live evidence remain outside the published runtime; changing the plan
// must deliberately update this pin after review.
const CHAMELEON_MANUAL_ACTION_HIL_PLAN_DIGEST =
  "4c20768eb5c89c86b963493c8004941aeb4fb391f0db30023ae78c2744fdb5b8";
const HASH_RE = /^[a-f0-9]{64}$/u;
const IDENTIFIER_RE = /^[a-z][a-z0-9._-]{0,127}$/u;
const SIGNATURE_RE = /^[A-Za-z0-9_-]{86}$/u;

const SIGNER_ROLES = Object.freeze(["operator", "witness"]);
const SIGNATURE_PURPOSES = Object.freeze([
  "operator_acknowledgement",
  "witness_acknowledgement",
  "operator_completion",
  "witness_completion",
]);
const ACTION_DISPOSITIONS = Object.freeze(["performed", "not_performed", "uncertain"]);
const TERMINAL_DISPOSITIONS = Object.freeze(["completed_clean", "inconclusive"]);
const FAILURE_REASON_CODES = Object.freeze([
  "late_evidence",
  "cross_attempt_evidence",
  "receipt_substitution",
  "signature_invalid",
  "rf_evidence_invalid",
  "state_binding_invalid",
  "cleanup_unresolved",
  "malformed_evidence",
]);

const SIGNER_REGISTRIES = new WeakSet();
const SIGNER_REGISTRY_STATE = new WeakMap();
const RUNTIMES = new WeakSet();
const RUNTIME_STATE = new WeakMap();
const RESERVATIONS = new WeakSet();
const RESERVATION_STATE = new WeakMap();
const EXECUTIONS = new WeakSet();
const EXECUTION_STATE = new WeakMap();
const COMPLETION_CONTEXTS = new WeakSet();
const COMPLETION_CONTEXT_STATE = new WeakMap();
const TERMINALS = new WeakSet();
const TERMINAL_STATE = new WeakMap();

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  if (utilTypes.isProxy(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function assertDataOnlyGraph(value, label) {
  const seen = new WeakSet();
  const stack = [{ value, path: label, depth: 0 }];
  let count = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    if (current.value == null || typeof current.value !== "object") {
      if (typeof current.value === "function") throw new Error(`${current.path} cannot contain callbacks`);
      continue;
    }
    if (utilTypes.isProxy(current.value)) {
      throw new Error(`${current.path} cannot be a proxy`);
    }
    if (Buffer.isBuffer(current.value) || current.value instanceof ArrayBuffer
        || ArrayBuffer.isView(current.value)) {
      throw new Error(`${current.path} cannot contain raw byte material`);
    }
    if (seen.has(current.value)) throw new Error(`${current.path} cannot contain cycles or aliases`);
    seen.add(current.value);
    count += 1;
    if (count > 4096 || current.depth > 32) throw new Error(`${label} exceeds the bounded input graph`);
    for (const key of Reflect.ownKeys(current.value)) {
      if (typeof key !== "string") throw new Error(`${current.path} cannot contain symbol fields`);
      const descriptor = Object.getOwnPropertyDescriptor(current.value, key);
      const arrayLength = Array.isArray(current.value) && key === "length";
      if (!descriptor || !("value" in descriptor) || (!descriptor.enumerable && !arrayLength)) {
        throw new Error(`${current.path}.${key} must be an enumerable data field`);
      }
      if (!arrayLength) stack.push({
        value: descriptor.value,
        path: Array.isArray(current.value) ? `${current.path}[${key}]` : `${current.path}.${key}`,
        depth: current.depth + 1,
      });
    }
  }
  assertNoPublicByteMaterial(value, label);
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) throw new Error(`${label} cannot contain symbols`);
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

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_RE.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_RE.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertInteger(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function assertTimestamp(value, label) {
  if (typeof value !== "string") throw new Error(`${label} must be a canonical UTC timestamp`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC timestamp`);
  }
  return value;
}

function assertEnum(value, values, label) {
  if (!values.includes(value)) throw new Error(`${label} must be one of ${values.join(", ")}`);
  return value;
}

function minTimestamp(...values) {
  return new Date(Math.min(...values.map((value) => Date.parse(value)))).toISOString();
}

function clockEvidence(sampleInput) {
  const sample = assertPhysicalTrustedClockSample(sampleInput);
  return {
    sample,
    now: sample.trusted_utc,
    earliest: sample.trusted_utc_earliest,
    latest: sample.trusted_utc_latest,
    evidence_digest: hashCanonicalJson({
      domain: "hacker-bob/chameleon-manual-action-clock/v1",
      clock_id: sample.clock_id,
      monotonic_epoch_id: sample.monotonic_epoch_id,
      mapping_generation: sample.mapping_generation,
      monotonic_ms: sample.monotonic_ms,
      trusted_utc: sample.trusted_utc,
      trusted_utc_earliest: sample.trusted_utc_earliest,
      trusted_utc_latest: sample.trusted_utc_latest,
      signed_mapping_digest: sample.signed_mapping_digest,
      trust_root_epoch: sample.trust_root_epoch,
      authority_epoch: sample.authority_epoch,
      revocation_generation: sample.revocation_generation,
    }),
  };
}

function assertCurrentWindow(clock, notBefore, expiresAt, label) {
  if (Date.parse(clock.earliest) < Date.parse(notBefore)) throw new Error(`${label} is not yet active`);
  if (Date.parse(clock.latest) >= Date.parse(expiresAt)) throw new Error(`${label} is late or expired`);
}

function reviewedManualRegistry() {
  const reviewed = reviewedManifestSnapshot();
  const registry = reviewed.manual_action_registry;
  // operations.js validates this digest against its own canonical manifest
  // encoding at module load. Keep that reviewed digest as the cross-package
  // identity instead of silently defining a second canonicalization scheme.
  const registryDigest = assertDigest(
    reviewed.manual_action_registry_sha256,
    "reviewed manual-action registry digest",
  );
  const ids = Object.keys(registry).sort();
  const expected = [
    "CU-ADMIN-BUTTON-CLONE-INVOKE",
    "CU-ADMIN-FIELD-GENERATOR-INVOKE",
  ];
  if (JSON.stringify(ids) !== JSON.stringify(expected)) {
    throw new Error("reviewed Chameleon manual-action registry is not the closed PH-P9 set");
  }
  const actions = {};
  for (const capabilityId of ids) {
    const entry = structuredClone(registry[capabilityId]);
    const coverage = reviewed.coverage.find((row) => row.provider_capability_id === capabilityId);
    if (!coverage || coverage.disposition !== "operator_only"
        || !coverage.normalized_operations.includes(MANUAL_OPERATION_ID)
        || coverage.upstream_command_ids.length !== 0
        || JSON.stringify(coverage.effect_profile_refs) !== JSON.stringify(entry.effect_profile_refs)) {
      throw new Error(`reviewed manual action ${capabilityId} drifted from coverage`);
    }
    if (JSON.stringify(entry.required_receipts) !== JSON.stringify([
      "operator_receipt_ref", "witness_receipt_ref",
    ]) || entry.rf_off_deadline_required !== true) {
      throw new Error(`reviewed manual action ${capabilityId} lacks PH-P9 receipt or RF-off custody`);
    }
    const effectProfiles = entry.effect_profile_refs.map((profileRef) => {
      const profile = reviewed.effect_profiles[profileRef];
      if (!profile) throw new Error(`reviewed manual action references unknown effect ${profileRef}`);
      return deepFreeze({ effect_profile_ref: profileRef, ...structuredClone(profile) });
    });
    const procedure = {
      provider_id: PROVIDER_ID,
      capability_id: capabilityId,
      source_url: entry.source_url,
      source_sha256: entry.source_sha256,
      source_symbol: entry.source_symbol,
      source_case: entry.source_case,
      procedure_id: entry.procedure_id,
      effect_profile_refs: [...entry.effect_profile_refs],
      required_receipts: [...entry.required_receipts],
      rf_off_deadline_required: true,
    };
    actions[capabilityId] = deepFreeze({
      ...procedure,
      procedure_binding_digest: hashCanonicalJson({ domain: PROCEDURE_DOMAIN, ...procedure }),
      parameter_digest: hashCanonicalJson({
        domain: PARAMETER_DOMAIN,
        manual_action_registry_digest: registryDigest,
        ...procedure,
      }),
      effect_profiles: effectProfiles,
      expected_outcome_digest: hashCanonicalJson({
        domain: OUTCOME_DOMAIN,
        provider_id: PROVIDER_ID,
        capability_id: capabilityId,
        outcome: "performed_rf_off_clean",
      }),
    });
  }
  return deepFreeze({ actions, registry_digest: registryDigest });
}

const REVIEWED_MANUAL = reviewedManualRegistry();
const MANUAL_OPERATION = getChameleonOperation(MANUAL_OPERATION_ID);
if (!MANUAL_OPERATION || MANUAL_OPERATION.exposure !== "operator_only") {
  throw new Error("reviewed Chameleon manual operation is unavailable or not operator-only");
}

function getAction(capabilityId) {
  if (typeof capabilityId !== "string") return null;
  return REVIEWED_MANUAL.actions[capabilityId] || null;
}

function chameleonManualActionParameterDigest(capabilityId) {
  return getAction(capabilityId)?.parameter_digest || null;
}

function chameleonManualActionExpectedOutcomeDigest(capabilityId) {
  return getAction(capabilityId)?.expected_outcome_digest || null;
}

function describeChameleonManualActions() {
  return deepFreeze({
    version: CHAMELEON_MANUAL_ACTION_VERSION,
    provider_id: PROVIDER_ID,
    operation_id: MANUAL_OPERATION_ID,
    operation_contract_digest: MANUAL_OPERATION.operation_contract_digest,
    manual_action_registry_digest: REVIEWED_MANUAL.registry_digest,
    hil_plan_digest: CHAMELEON_MANUAL_ACTION_HIL_PLAN_DIGEST,
    actions: Object.values(REVIEWED_MANUAL.actions).map((entry) => deepFreeze({
      capability_id: entry.capability_id,
      procedure_id: entry.procedure_id,
      procedure_binding_digest: entry.procedure_binding_digest,
      parameter_digest: entry.parameter_digest,
      source_sha256: entry.source_sha256,
      source_symbol: entry.source_symbol,
      source_case: entry.source_case,
      effect_profile_refs: Object.freeze([...entry.effect_profile_refs]),
      expected_outcome_digest: entry.expected_outcome_digest,
    })),
  });
}

function normalizeSignerDefinition(input, label) {
  assertDataOnlyGraph(input, label);
  assertClosedObject(input, label, [
    "version",
    "signer_role",
    "signer_key_id",
    "signer_principal_ref",
    "public_key_pem",
    "trust_root_epoch",
    "trust_domain_ref",
    "independence_domain_ref",
    "observer_enrollment_ref",
    "valid_from",
    "expires_at",
    "trusted",
    "revoked",
  ], ["revoked_at"]);
  if (input.version !== CHAMELEON_MANUAL_ACTION_VERSION) throw new Error(`${label}.version must be 1`);
  const role = assertEnum(input.signer_role, SIGNER_ROLES, `${label}.signer_role`);
  let publicKey;
  try {
    publicKey = crypto.createPublicKey(input.public_key_pem);
  } catch {
    throw new Error(`${label}.public_key_pem must be a valid Ed25519 public key`);
  }
  if (publicKey.asymmetricKeyType !== "ed25519") {
    throw new Error(`${label}.public_key_pem must be Ed25519`);
  }
  const validFrom = assertTimestamp(input.valid_from, `${label}.valid_from`);
  const expiresAt = assertTimestamp(input.expires_at, `${label}.expires_at`);
  if (Date.parse(expiresAt) <= Date.parse(validFrom)) {
    throw new Error(`${label}.expires_at must be after valid_from`);
  }
  if (typeof input.trusted !== "boolean" || typeof input.revoked !== "boolean") {
    throw new Error(`${label} trust flags must be booleans`);
  }
  const revokedAt = input.revoked
    ? assertTimestamp(input.revoked_at, `${label}.revoked_at`)
    : null;
  if (!input.revoked && input.revoked_at != null) throw new Error(`${label}.revoked_at requires revoked=true`);
  const observerEnrollmentRef = input.observer_enrollment_ref == null
    ? null
    : normalizeOpaqueRef(
      input.observer_enrollment_ref,
      `${label}.observer_enrollment_ref`,
      { prefix: "observer-enrollment" },
    );
  if ((role === "witness") !== (observerEnrollmentRef != null)) {
    throw new Error(`${label} witness signers require observer enrollment; operators forbid it`);
  }
  const descriptor = {
    version: CHAMELEON_MANUAL_ACTION_VERSION,
    signer_role: role,
    signer_key_id: normalizeOpaqueRef(input.signer_key_id, `${label}.signer_key_id`, {
      prefix: "signer-key",
    }),
    signer_principal_ref: normalizeOpaqueRef(
      input.signer_principal_ref,
      `${label}.signer_principal_ref`,
      { prefix: "principal" },
    ),
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, 1),
    trust_domain_ref: normalizeOpaqueRef(input.trust_domain_ref, `${label}.trust_domain_ref`, {
      prefix: "trust-domain",
    }),
    independence_domain_ref: normalizeOpaqueRef(
      input.independence_domain_ref,
      `${label}.independence_domain_ref`,
      { prefix: "independence-domain" },
    ),
    observer_enrollment_ref: observerEnrollmentRef,
    public_key_spki_sha256: crypto.createHash("sha256").update(
      publicKey.export({ type: "spki", format: "der" }),
    ).digest("hex"),
    valid_from: validFrom,
    expires_at: expiresAt,
    trusted: input.trusted,
    revoked: input.revoked,
    revoked_at: revokedAt,
  };
  return { descriptor: deepFreeze({
    ...descriptor,
    signer_enrollment_digest: hashCanonicalJson({
      domain: "hacker-bob/chameleon-manual-action-signer-enrollment/v1",
      ...descriptor,
    }),
  }), publicKey };
}

function buildChameleonManualActionSignerRegistry(input) {
  assertDataOnlyGraph(input, "chameleon_manual_action_signer_registry");
  assertClosedObject(input, "chameleon_manual_action_signer_registry", [
    "version", "registry_id", "signers",
  ]);
  if (input.version !== CHAMELEON_MANUAL_ACTION_VERSION) {
    throw new Error("chameleon_manual_action_signer_registry.version must be 1");
  }
  const registryId = assertIdentifier(
    input.registry_id,
    "chameleon_manual_action_signer_registry.registry_id",
  );
  if (!Array.isArray(input.signers) || input.signers.length < 2 || input.signers.length > 64) {
    throw new Error("manual-action signer registry requires 2..64 signers");
  }
  const entries = new Map();
  const publicKeys = new Map();
  const normalized = input.signers.map((entry, index) => normalizeSignerDefinition(
    entry,
    `chameleon_manual_action_signer_registry.signers[${index}]`,
  ));
  for (const entry of normalized) {
    const key = `${entry.descriptor.signer_key_id}:${entry.descriptor.trust_root_epoch}`;
    if (entries.has(key)) throw new Error(`duplicate manual-action signer ${key}`);
    if (publicKeys.has(entry.descriptor.public_key_spki_sha256)) {
      throw new Error("manual-action signer public key material cannot be shared");
    }
    entries.set(key, entry);
    publicKeys.set(entry.descriptor.public_key_spki_sha256, key);
  }
  const operators = normalized.filter((entry) => entry.descriptor.signer_role === "operator");
  const witnesses = normalized.filter((entry) => entry.descriptor.signer_role === "witness");
  if (operators.length < 1 || witnesses.length < 1) {
    throw new Error("manual-action signer registry requires operator and witness roles");
  }
  for (const operator of operators) {
    for (const witness of witnesses) {
      for (const field of [
        "signer_principal_ref", "trust_domain_ref", "independence_domain_ref",
      ]) {
        if (operator.descriptor[field] === witness.descriptor[field]) {
          throw new Error(`manual-action self-witnessing shares ${field}`);
        }
      }
    }
  }
  const descriptors = normalized.map((entry) => entry.descriptor).sort((left, right) => (
    `${left.signer_key_id}:${left.trust_root_epoch}`.localeCompare(
      `${right.signer_key_id}:${right.trust_root_epoch}`,
    )
  ));
  const registryDigest = hashCanonicalJson({
    version: CHAMELEON_MANUAL_ACTION_VERSION,
    registry_id: registryId,
    signers: descriptors,
  });
  const registry = deepFreeze({
    version: CHAMELEON_MANUAL_ACTION_VERSION,
    registry_id: registryId,
    registry_digest: registryDigest,
    describe() { return Object.freeze([...descriptors]); },
  });
  SIGNER_REGISTRIES.add(registry);
  SIGNER_REGISTRY_STATE.set(registry, entries);
  return registry;
}

function assertSignerRegistry(registry) {
  if (!registry || !SIGNER_REGISTRIES.has(registry)
      || !SIGNER_REGISTRY_STATE.has(registry) || !Object.isFrozen(registry)) {
    throw new Error("manual-action signer registry must be a closed Bob registry");
  }
  return registry;
}

function signerEntry(registry, keyId, epoch = null) {
  const entries = SIGNER_REGISTRY_STATE.get(assertSignerRegistry(registry));
  if (epoch != null) return entries.get(`${keyId}:${epoch}`) || null;
  const matches = [...entries.values()].filter((entry) => entry.descriptor.signer_key_id === keyId);
  return matches.length === 1 ? matches[0] : null;
}

function assertSignerCurrent(entry, role, clock, label) {
  if (!entry || entry.descriptor.signer_role !== role) throw new Error(`${label} is not enrolled for ${role}`);
  const descriptor = entry.descriptor;
  const earliest = Date.parse(clock.earliest);
  const latest = Date.parse(clock.latest);
  if (descriptor.trusted !== true || descriptor.revoked === true
      || earliest < Date.parse(descriptor.valid_from)
      || latest >= Date.parse(descriptor.expires_at)) {
    throw new Error(`${label} is not currently trusted and active`);
  }
  return descriptor;
}

function effectSemanticKey(effect) {
  return [effect.subject_kind, effect.action, effect.channel, effect.persistence].join(":");
}

function resolveEffectBinding(plan, action, rfOffDeadline) {
  if (plan.requested_effects.length !== action.effect_profiles.length) {
    throw new Error("manual action requested effects are not the exact reviewed effect set");
  }
  const remaining = [...plan.requested_effects];
  const resolved = [];
  let operatorReceiptRef = null;
  let witnessReceiptRef = null;
  for (const profile of action.effect_profiles) {
    const index = remaining.findIndex((effect) => effectSemanticKey(effect) === effectSemanticKey(profile));
    if (index < 0) throw new Error(`manual action lacks effect profile ${profile.effect_profile_ref}`);
    const effect = remaining.splice(index, 1)[0];
    for (const bound of profile.required_bounds) {
      if (!Object.prototype.hasOwnProperty.call(effect.bounds, bound)) {
        throw new Error(`manual action effect ${profile.effect_profile_ref} lacks bound ${bound}`);
      }
    }
    if (effect.bounds.instrument_ref !== plan.instrument_ref) {
      throw new Error("manual action effect instrument_ref drifted from the plan");
    }
    if (profile.subject_kind === "target" && effect.bounds.target_ref !== plan.target_asset_ref) {
      throw new Error("manual action effect target_ref drifted from the plan");
    }
    if (Object.hasOwn(effect.bounds, "cleanup_plan_digest")
        && effect.bounds.cleanup_plan_digest !== plan.cleanup_plan_digest) {
      throw new Error("manual action effect cleanup plan drifted");
    }
    if (Object.hasOwn(effect.bounds, "attempt_limit") && effect.bounds.attempt_limit !== 1) {
      throw new Error("manual action effect attempt_limit must be exactly one");
    }
    if (Object.hasOwn(effect.bounds, "execution_deadline")) {
      const deadline = assertTimestamp(
        effect.bounds.execution_deadline,
        `manual action ${profile.effect_profile_ref} execution_deadline`,
      );
      if (deadline !== rfOffDeadline) throw new Error("manual action RF-off deadline drifted from effect bounds");
    }
    const operatorRef = normalizeOpaqueRef(
      effect.bounds.operator_receipt_ref,
      "manual action operator_receipt_ref",
      { prefix: "manual-operator-receipt" },
    );
    const witnessRef = normalizeOpaqueRef(
      effect.bounds.witness_receipt_ref,
      "manual action witness_receipt_ref",
      { prefix: "manual-witness-receipt" },
    );
    if (operatorReceiptRef != null && operatorReceiptRef !== operatorRef) {
      throw new Error("manual action effects disagree on operator receipt");
    }
    if (witnessReceiptRef != null && witnessReceiptRef !== witnessRef) {
      throw new Error("manual action effects disagree on witness receipt");
    }
    operatorReceiptRef = operatorRef;
    witnessReceiptRef = witnessRef;
    resolved.push(deepFreeze({
      effect_profile_ref: profile.effect_profile_ref,
      template_id: effect.template_id,
      template_digest: effect.template_digest,
      subject_ref: effect.subject_ref,
      bounds_digest: hashCanonicalJson(effect.bounds),
    }));
  }
  const binding = {
    effect_profile_refs: [...action.effect_profile_refs],
    resolved_effects: resolved,
    requested_effects_registry_digest: plan.requested_effects_registry_digest,
    requested_effects_digest: plan.requested_effects_digest,
    operator_receipt_ref: operatorReceiptRef,
    witness_receipt_ref: witnessReceiptRef,
    rf_off_deadline: rfOffDeadline,
  };
  return deepFreeze({
    ...binding,
    effect_binding_digest: hashCanonicalJson({ domain: EFFECT_BINDING_DOMAIN, ...binding }),
  });
}

function assertPlanAndGrant(planInput, grantInput, verifier, action, preSnapshot, rfOffDeadline) {
  const plan = normalizePhysicalExperimentPlan(planInput);
  if (!grantInput || typeof grantInput !== "object" || utilTypes.isProxy(grantInput)
      || !Object.isFrozen(grantInput)) {
    throw new Error("manual action active grant must be a sealed private projection");
  }
  for (const field of [
    "execution_request_digest", "authority_resolution_digest", "execution_principal_id",
    "provider_descriptor_digest", "execution_lineage_digest", "lease_id", "fencing_token",
    "fencing_generation", "resource_bundle_digest",
  ]) {
    const descriptor = Object.getOwnPropertyDescriptor(grantInput, field);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`manual action active grant ${field} must be a sealed data field`);
    }
  }
  if (plan.operation_id !== MANUAL_OPERATION_ID
      || plan.parameter_digest !== action.parameter_digest
      || plan.positive_cohort.expected_outcome_digest !== action.expected_outcome_digest) {
    throw new Error("manual action plan operation, parameters, or expected outcome drifted");
  }
  const expectedGrantBindings = {
    execution_request_digest: grantInput.execution_request_digest,
    authority_resolution_digest: grantInput.authority_resolution_digest,
    execution_principal_id: grantInput.execution_principal_id,
    provider_id: PROVIDER_ID,
    provider_descriptor_digest: grantInput.provider_descriptor_digest,
    instrument_ref: plan.instrument_ref,
    operation_id: MANUAL_OPERATION_ID,
    operation_digest: MANUAL_OPERATION.operation_contract_digest,
    attempt_id: plan.attempt_id,
    experiment_plan_hash: plan.plan_hash,
    execution_lineage_digest: grantInput.execution_lineage_digest,
    lease_id: grantInput.lease_id,
    fencing_token: grantInput.fencing_token,
    fencing_generation: grantInput.fencing_generation,
    resource_bundle_digest: grantInput.resource_bundle_digest,
  };
  const grant = assertVerifiedActivePhysicalExecutionGrant(
    grantInput,
    verifier,
    expectedGrantBindings,
  );
  for (const [actual, expected, field] of [
    [grant.session_nucleus_hash, plan.session_nucleus_hash, "session_nucleus_hash"],
    [grant.experiment_plan_hash, plan.plan_hash, "experiment_plan_hash"],
    [grant.attempt_id, plan.attempt_id, "attempt_id"],
    [grant.instrument_ref, plan.instrument_ref, "instrument_ref"],
    [grant.operation_id, MANUAL_OPERATION_ID, "operation_id"],
    [grant.operation_digest, MANUAL_OPERATION.operation_contract_digest, "operation_digest"],
    [grant.parameter_digest, action.parameter_digest, "parameter_digest"],
    [grant.requested_effects_digest, plan.requested_effects_digest, "requested_effects_digest"],
    [grant.cleanup_plan_digest, plan.cleanup_plan_digest, "cleanup_plan_digest"],
    [grant.provider_descriptor_digest, preSnapshot.provider_descriptor_digest, "provider_descriptor_digest"],
    [grant.workspace_snapshot_digest, preSnapshot.snapshot_digest, "workspace_snapshot_digest"],
    [grant.lease_id, preSnapshot.lease_id, "lease_id"],
    [grant.fencing_generation, preSnapshot.fencing_generation, "fencing_generation"],
  ]) {
    if (actual !== expected) throw new Error(`manual action ${field} binding drift`);
  }
  if (preSnapshot.snapshot_kind !== "observed" || preSnapshot.active_mode !== "rf_off"
      || preSnapshot.assurance_status !== "valid"
      || preSnapshot.instrument_ref !== plan.instrument_ref
      || preSnapshot.operation_id !== MANUAL_OPERATION_ID
      || preSnapshot.operation_contract_digest !== MANUAL_OPERATION.operation_contract_digest
      || preSnapshot.attempt_ref !== `attempt:${plan.attempt_id}`) {
    throw new Error("manual action requires an exact valid observed RF-off pre-state");
  }
  if (Date.parse(rfOffDeadline) >= Date.parse(grant.expires_at)
      || Date.parse(rfOffDeadline) <= Date.parse(grant.not_before)) {
    throw new Error("manual action RF-off deadline must be inside the active grant window");
  }
  return { plan, grant };
}

function createChameleonManualActionRuntime(input) {
  assertClosedObject(input, "chameleon_manual_action_runtime", [
    "version",
    "runtime_id",
    "signer_registry",
    "observer_enrollment_registry",
    "active_grant_verifier",
    "challenge_ttl_ms",
  ]);
  if (input.version !== CHAMELEON_MANUAL_ACTION_VERSION) {
    throw new Error("chameleon_manual_action_runtime.version must be 1");
  }
  const signerRegistry = assertSignerRegistry(input.signer_registry);
  const observerRegistry = assertPhysicalObserverEnrollmentRegistry(
    input.observer_enrollment_registry,
  );
  const challengeTtlMs = assertInteger(
    input.challenge_ttl_ms,
    "chameleon_manual_action_runtime.challenge_ttl_ms",
    1,
    MAX_CHALLENGE_TTL_MS,
  );
  const runtime = deepFreeze({
    version: CHAMELEON_MANUAL_ACTION_VERSION,
    runtime_id: assertIdentifier(input.runtime_id, "chameleon_manual_action_runtime.runtime_id"),
    provider_id: PROVIDER_ID,
    manual_action_registry_digest: REVIEWED_MANUAL.registry_digest,
    signer_registry_digest: signerRegistry.registry_digest,
    production_ready: false,
    hil_ready: false,
  });
  RUNTIMES.add(runtime);
  RUNTIME_STATE.set(runtime, {
    signer_registry: signerRegistry,
    observer_registry: observerRegistry,
    active_grant_verifier: input.active_grant_verifier,
    challenge_ttl_ms: challengeTtlMs,
    active_instruments: new Map(),
    used_challenges: new Set(),
    reservation_count: 0,
  });
  return runtime;
}

function assertRuntime(runtime) {
  if (!runtime || !RUNTIMES.has(runtime) || !RUNTIME_STATE.has(runtime) || !Object.isFrozen(runtime)) {
    throw new Error("Chameleon manual-action runtime must be privately branded");
  }
  return runtime;
}

function findPlannedWitness(plan, cohortKind, observerId, witness, observerRegistry, clock) {
  if (cohortKind !== "positive") throw new Error("manual actions execute only the positive cohort");
  const observer = plan.positive_cohort.observer_plan.find((entry) => entry.observer_id === observerId);
  if (!observer) throw new Error("manual action witness is not in the positive observer plan");
  const enrollment = observerRegistry.get(observer.observer_enrollment_ref);
  if (!enrollment || enrollment.enrollment_digest !== observer.observer_enrollment_digest
      || enrollment.revoked === true
      || Date.parse(clock.earliest) < Date.parse(enrollment.valid_from)
      || (enrollment.expires_at != null && Date.parse(clock.latest) >= Date.parse(enrollment.expires_at))) {
    throw new Error("manual action witness enrollment is not current");
  }
  for (const [actual, expected, field] of [
    [witness.signer_key_id, observer.signer_key_id, "signer_key_id"],
    [witness.observer_enrollment_ref, observer.observer_enrollment_ref, "observer_enrollment_ref"],
    [enrollment.observer_identity_ref, observer.observer_identity_ref, "observer_identity_ref"],
    [enrollment.source_kind, "sensor", "source_kind"],
    [enrollment.source_ref, observer.source_ref, "source_ref"],
    [enrollment.trust_domain_ref, witness.trust_domain_ref, "trust_domain_ref"],
    [enrollment.independence_domain_ref, witness.independence_domain_ref, "independence_domain_ref"],
    [enrollment.external_outcome_allowed, true, "external_outcome_allowed"],
  ]) {
    if (actual !== expected) throw new Error(`manual action witness ${field} enrollment drift`);
  }
  return { observer, enrollment };
}

function reserveChameleonManualAction(runtimeInput, input, planInput, grantInput, preSnapshotInput,
  trustedClockSample) {
  const runtime = assertRuntime(runtimeInput);
  const runtimeState = RUNTIME_STATE.get(runtime);
  assertDataOnlyGraph(input, "chameleon_manual_action_reservation_request");
  assertClosedObject(input, "chameleon_manual_action_reservation_request", [
    "version",
    "capability_id",
    "cohort_kind",
    "operator_signer_key_id",
    "witness_signer_key_id",
    "witness_observer_id",
    "rf_off_deadline",
  ]);
  if (input.version !== CHAMELEON_MANUAL_ACTION_VERSION) {
    throw new Error("chameleon_manual_action_reservation_request.version must be 1");
  }
  const action = getAction(input.capability_id);
  if (!action) throw new Error("manual action capability is outside the reviewed closed registry");
  const rfOffDeadline = assertTimestamp(
    input.rf_off_deadline,
    "chameleon_manual_action_reservation_request.rf_off_deadline",
  );
  const preSnapshot = assertChameleonStateSnapshot(preSnapshotInput);
  const { plan, grant } = assertPlanAndGrant(
    planInput,
    grantInput,
    runtimeState.active_grant_verifier,
    action,
    preSnapshot,
    rfOffDeadline,
  );
  if (plan.observer_enrollment_registry_digest
      !== runtimeState.observer_registry.registry_digest) {
    throw new Error("manual action plan uses another observer enrollment registry");
  }
  const clock = clockEvidence(trustedClockSample);
  assertCurrentWindow(clock, grant.not_before, rfOffDeadline, "manual action reservation");
  const operatorEntry = signerEntry(runtimeState.signer_registry, input.operator_signer_key_id);
  const witnessEntry = signerEntry(runtimeState.signer_registry, input.witness_signer_key_id);
  const operator = assertSignerCurrent(operatorEntry, "operator", clock, "manual action operator");
  const witness = assertSignerCurrent(witnessEntry, "witness", clock, "manual action witness");
  for (const field of ["signer_principal_ref", "trust_domain_ref", "independence_domain_ref"] ) {
    if (operator[field] === witness[field]) throw new Error(`manual action self-witnessing shares ${field}`);
  }
  const plannedWitness = findPlannedWitness(
    plan,
    input.cohort_kind,
    input.witness_observer_id,
    witness,
    runtimeState.observer_registry,
    clock,
  );
  const effectBinding = resolveEffectBinding(plan, action, rfOffDeadline);
  if (runtimeState.active_instruments.has(plan.instrument_ref)) {
    throw new Error("manual action instrument already has an active or quarantined reservation");
  }
  if (runtimeState.reservation_count >= MAX_RUNTIME_RESERVATIONS) {
    throw new Error("manual action in-memory one-use owner reached its fail-closed capacity");
  }
  let challengeNonce;
  do {
    challengeNonce = crypto.randomBytes(32).toString("base64url");
  } while (runtimeState.used_challenges.has(challengeNonce));
  const challengeExpiresAt = minTimestamp(
    new Date(Date.parse(clock.now) + runtimeState.challenge_ttl_ms).toISOString(),
    rfOffDeadline,
    grant.expires_at,
  );
  const reservationRef = `manual-reservation:${hashCanonicalJson({
    runtime_id: runtime.runtime_id,
    challenge_nonce: challengeNonce,
    grant_projection_digest: grant.projection_digest,
  }).slice(0, 48)}`;
  const basis = {
    version: CHAMELEON_MANUAL_ACTION_VERSION,
    reservation_ref: reservationRef,
    runtime_id: runtime.runtime_id,
    provider_id: PROVIDER_ID,
    capability_id: action.capability_id,
    manual_action_registry_digest: REVIEWED_MANUAL.registry_digest,
    semantic_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
    procedure_id: action.procedure_id,
    procedure_binding_digest: action.procedure_binding_digest,
    source_sha256: action.source_sha256,
    source_symbol: action.source_symbol,
    source_case: action.source_case,
    parameter_digest: action.parameter_digest,
    effect_profile_refs: [...action.effect_profile_refs],
    effect_binding_digest: effectBinding.effect_binding_digest,
    requested_effects_digest: plan.requested_effects_digest,
    plan_hash: plan.plan_hash,
    session_nucleus_hash: plan.session_nucleus_hash,
    task_id: plan.task_id,
    attempt_id: plan.attempt_id,
    cohort_kind: input.cohort_kind,
    planned_grant_ref: plan.positive_cohort.grant_ref,
    execution_identity: plan.positive_cohort.execution_identity,
    active_grant_ref: grant.grant_ref,
    signed_grant_digest: grant.signed_grant_digest,
    grant_projection_digest: grant.projection_digest,
    active_execution_request_digest: grant.execution_request_digest,
    instrument_ref: plan.instrument_ref,
    instrument_identity_ref: plan.instrument_identity_ref,
    instrument_inventory_ref: plan.instrument_inventory_ref,
    provider_manifest_digest: plan.provider_manifest_digest,
    provider_descriptor_digest: grant.provider_descriptor_digest,
    lease_id: grant.lease_id,
    fencing_generation: grant.fencing_generation,
    pre_snapshot_digest: preSnapshot.snapshot_digest,
    pre_workspace_state_digest: preSnapshot.workspace_state_digest,
    pre_state_epoch: preSnapshot.state_epoch,
    pre_mode: preSnapshot.active_mode,
    cleanup_plan_digest: plan.cleanup_plan_digest,
    operator_signer_key_id: operator.signer_key_id,
    operator_principal_ref: operator.signer_principal_ref,
    witness_signer_key_id: witness.signer_key_id,
    witness_principal_ref: witness.signer_principal_ref,
    witness_observer_id: plannedWitness.observer.observer_id,
    witness_observer_identity_ref: plannedWitness.observer.observer_identity_ref,
    witness_observer_enrollment_ref: plannedWitness.observer.observer_enrollment_ref,
    witness_observer_enrollment_digest: plannedWitness.observer.observer_enrollment_digest,
    witness_source_ref: plannedWitness.observer.source_ref,
    witness_trust_domain_ref: plannedWitness.observer.required_trust_domain_ref,
    witness_independence_domain_ref: plannedWitness.observer.required_independence_domain_ref,
    operator_receipt_ref: effectBinding.operator_receipt_ref,
    witness_receipt_ref: effectBinding.witness_receipt_ref,
    challenge_nonce: challengeNonce,
    issued_at: clock.now,
    challenge_expires_at: challengeExpiresAt,
    rf_off_deadline: rfOffDeadline,
    active_grant_expires_at: grant.expires_at,
    clock_evidence_digest: clock.evidence_digest,
  };
  const reservation = deepFreeze({
    ...basis,
    reservation_digest: hashCanonicalJson({ domain: RESERVATION_DOMAIN, ...basis }),
  });
  RESERVATIONS.add(reservation);
  RESERVATION_STATE.set(reservation, {
    runtime,
    plan,
    grant,
    action,
    pre_snapshot: preSnapshot,
    effect_binding: effectBinding,
    operator_entry: operatorEntry,
    witness_entry: witnessEntry,
    planned_witness: plannedWitness.observer,
    state: "reserved",
  });
  runtimeState.used_challenges.add(challengeNonce);
  runtimeState.active_instruments.set(plan.instrument_ref, reservation);
  runtimeState.reservation_count += 1;
  return reservation;
}

function assertReservation(input, runtimeInput = null) {
  const state = input == null ? null : RESERVATION_STATE.get(input);
  if (!input || !RESERVATIONS.has(input) || !state || !Object.isFrozen(input)) {
    throw new Error("manual-action reservation must be privately branded");
  }
  if (runtimeInput != null && state.runtime !== assertRuntime(runtimeInput)) {
    throw new Error("manual-action reservation belongs to another runtime");
  }
  return input;
}

function acknowledgementPayload(reservationInput, role, acknowledgedAt) {
  const reservation = assertReservation(reservationInput);
  const signerRole = assertEnum(role, SIGNER_ROLES, "manual acknowledgement role");
  const purpose = `${signerRole}_acknowledgement`;
  return deepFreeze({
    version: CHAMELEON_MANUAL_ACTION_VERSION,
    purpose,
    reservation_ref: reservation.reservation_ref,
    reservation_digest: reservation.reservation_digest,
    challenge_nonce: reservation.challenge_nonce,
    plan_hash: reservation.plan_hash,
    attempt_id: reservation.attempt_id,
    active_grant_ref: reservation.active_grant_ref,
    grant_projection_digest: reservation.grant_projection_digest,
    capability_id: reservation.capability_id,
    procedure_binding_digest: reservation.procedure_binding_digest,
    effect_binding_digest: reservation.effect_binding_digest,
    pre_snapshot_digest: reservation.pre_snapshot_digest,
    cleanup_plan_digest: reservation.cleanup_plan_digest,
    signer_role: signerRole,
    acknowledged_at: assertTimestamp(acknowledgedAt, "manual acknowledgement acknowledged_at"),
  });
}

const createChameleonManualActionAcknowledgementPayload = acknowledgementPayload;

function manualActionSignatureInputDigest(input) {
  assertDataOnlyGraph(input, "manual_action_signature_input");
  assertClosedObject(input, "manual_action_signature_input", [
    "version", "purpose", "signer_key_id", "trust_root_epoch", "signed_at", "payload_digest",
  ]);
  if (input.version !== CHAMELEON_MANUAL_ACTION_VERSION) {
    throw new Error("manual_action_signature_input.version must be 1");
  }
  const basis = {
    version: CHAMELEON_MANUAL_ACTION_VERSION,
    domain: SIGNATURE_DOMAIN,
    purpose: assertEnum(input.purpose, SIGNATURE_PURPOSES, "manual_action_signature_input.purpose"),
    signer_key_id: normalizeOpaqueRef(input.signer_key_id, "manual_action_signature_input.signer_key_id", {
      prefix: "signer-key",
    }),
    trust_root_epoch: assertInteger(input.trust_root_epoch, "manual_action_signature_input.trust_root_epoch", 1),
    signed_at: assertTimestamp(input.signed_at, "manual_action_signature_input.signed_at"),
    payload_digest: assertDigest(input.payload_digest, "manual_action_signature_input.payload_digest"),
  };
  return hashCanonicalJson(basis);
}

function normalizeSignedPayload(input, expectedPayload, expectedEntry, clock, notBefore, notAfter, label) {
  assertDataOnlyGraph(input, label);
  assertClosedObject(input, label, [
    "version",
    "purpose",
    "signer_key_id",
    "trust_root_epoch",
    "signed_at",
    "payload",
    "payload_digest",
    "signature_input_digest",
    "signature",
  ]);
  if (input.version !== CHAMELEON_MANUAL_ACTION_VERSION) throw new Error(`${label}.version must be 1`);
  if (!Object.isFrozen(expectedPayload)) throw new Error(`${label} expected payload is not sealed`);
  if (input.payload?.attempt_id !== expectedPayload.attempt_id
      || input.payload?.plan_hash !== expectedPayload.plan_hash
      || (expectedPayload.execution_digest != null
        && input.payload?.execution_digest !== expectedPayload.execution_digest)) {
    throw new Error(`${label} crosses an attempt or execution`);
  }
  for (const field of ["capability_id", "procedure_binding_digest", "effect_binding_digest"] ) {
    if (expectedPayload[field] != null && input.payload?.[field] !== expectedPayload[field]) {
      throw new Error(`${label} substitutes ${field}`);
    }
  }
  if (hashCanonicalJson(input.payload) !== hashCanonicalJson(expectedPayload)) {
    throw new Error(`${label} substitutes signed receipt content`);
  }
  const descriptor = expectedEntry.descriptor;
  if (input.purpose !== expectedPayload.purpose
      || input.signer_key_id !== descriptor.signer_key_id
      || input.trust_root_epoch !== descriptor.trust_root_epoch) {
    throw new Error(`${label} signer or purpose substitution`);
  }
  const signedAt = assertTimestamp(input.signed_at, `${label}.signed_at`);
  if (Date.parse(signedAt) < Date.parse(notBefore) || Date.parse(signedAt) >= Date.parse(notAfter)
      || Date.parse(signedAt) > Date.parse(clock.earliest)) {
    throw new Error(`${label} is late, backdated, or in the future`);
  }
  const assertedEventAt = expectedPayload.completed_at || expectedPayload.acknowledged_at;
  if (assertedEventAt != null && Date.parse(signedAt) < Date.parse(assertedEventAt)) {
    throw new Error(`${label}.signed_at predates its asserted event`);
  }
  assertSignerCurrent(expectedEntry, descriptor.signer_role, clock, label);
  const payloadDigest = hashCanonicalJson(expectedPayload);
  if (input.payload_digest !== payloadDigest) throw new Error(`${label}.payload_digest drift`);
  const signatureInputDigest = manualActionSignatureInputDigest({
    version: 1,
    purpose: input.purpose,
    signer_key_id: input.signer_key_id,
    trust_root_epoch: input.trust_root_epoch,
    signed_at: signedAt,
    payload_digest: payloadDigest,
  });
  if (input.signature_input_digest !== signatureInputDigest) {
    throw new Error(`${label}.signature_input_digest drift`);
  }
  if (typeof input.signature !== "string" || !SIGNATURE_RE.test(input.signature)) {
    throw new Error(`${label}.signature must be canonical Ed25519 base64url`);
  }
  const signature = Buffer.from(input.signature, "base64url");
  if (signature.length !== 64 || signature.toString("base64url") !== input.signature
      || !crypto.verify(
        null,
        Buffer.from(signatureInputDigest, "hex"),
        expectedEntry.publicKey,
        signature,
      )) {
    throw new Error(`${label}.signature verification failed`);
  }
  return deepFreeze({
    purpose: input.purpose,
    signer_key_id: input.signer_key_id,
    signer_principal_ref: descriptor.signer_principal_ref,
    signer_enrollment_digest: descriptor.signer_enrollment_digest,
    signed_at: signedAt,
    payload_digest: payloadDigest,
    signature_input_digest: signatureInputDigest,
    signed_receipt_digest: hashCanonicalJson(input),
  });
}

function beginChameleonManualAction(runtimeInput, reservationInput, input, trustedClockSample) {
  const runtime = assertRuntime(runtimeInput);
  const reservation = assertReservation(reservationInput, runtime);
  const state = RESERVATION_STATE.get(reservation);
  if (state.state !== "reserved") throw new Error("manual-action reservation was already consumed");
  assertDataOnlyGraph(input, "chameleon_manual_action_begin");
  assertClosedObject(input, "chameleon_manual_action_begin", [
    "version", "operator_acknowledgement", "witness_acknowledgement",
  ]);
  if (input.version !== CHAMELEON_MANUAL_ACTION_VERSION) {
    throw new Error("chameleon_manual_action_begin.version must be 1");
  }
  const clock = clockEvidence(trustedClockSample);
  assertCurrentWindow(clock, reservation.issued_at, reservation.challenge_expires_at, "manual action challenge");
  // Revalidate the live grant immediately before authorizing the human action.
  assertPlanAndGrant(
    state.plan,
    state.grant,
    RUNTIME_STATE.get(runtime).active_grant_verifier,
    state.action,
    state.pre_snapshot,
    reservation.rf_off_deadline,
  );
  const operatorPayload = acknowledgementPayload(reservation, "operator", input.operator_acknowledgement.payload?.acknowledged_at);
  const witnessPayload = acknowledgementPayload(reservation, "witness", input.witness_acknowledgement.payload?.acknowledged_at);
  const operatorAck = normalizeSignedPayload(
    input.operator_acknowledgement,
    operatorPayload,
    state.operator_entry,
    clock,
    reservation.issued_at,
    reservation.challenge_expires_at,
    "manual operator acknowledgement",
  );
  const witnessAck = normalizeSignedPayload(
    input.witness_acknowledgement,
    witnessPayload,
    state.witness_entry,
    clock,
    reservation.issued_at,
    reservation.challenge_expires_at,
    "manual witness acknowledgement",
  );
  const executionRef = `manual-execution:${hashCanonicalJson({
    reservation_digest: reservation.reservation_digest,
    operator_ack: operatorAck.signed_receipt_digest,
    witness_ack: witnessAck.signed_receipt_digest,
  }).slice(0, 48)}`;
  const basis = {
    version: CHAMELEON_MANUAL_ACTION_VERSION,
    execution_ref: executionRef,
    runtime_id: runtime.runtime_id,
    reservation_ref: reservation.reservation_ref,
    reservation_digest: reservation.reservation_digest,
    challenge_nonce: reservation.challenge_nonce,
    plan_hash: reservation.plan_hash,
    attempt_id: reservation.attempt_id,
    active_grant_ref: reservation.active_grant_ref,
    grant_projection_digest: reservation.grant_projection_digest,
    capability_id: reservation.capability_id,
    procedure_binding_digest: reservation.procedure_binding_digest,
    effect_binding_digest: reservation.effect_binding_digest,
    instrument_ref: reservation.instrument_ref,
    pre_snapshot_digest: reservation.pre_snapshot_digest,
    pre_workspace_state_digest: reservation.pre_workspace_state_digest,
    pre_state_epoch: reservation.pre_state_epoch,
    pre_mode: reservation.pre_mode,
    cleanup_plan_digest: reservation.cleanup_plan_digest,
    operator_receipt_ref: reservation.operator_receipt_ref,
    witness_receipt_ref: reservation.witness_receipt_ref,
    operator_acknowledgement_digest: operatorAck.signed_receipt_digest,
    witness_acknowledgement_digest: witnessAck.signed_receipt_digest,
    started_at: clock.now,
    rf_off_deadline: reservation.rf_off_deadline,
    active_grant_expires_at: reservation.active_grant_expires_at,
    clock_evidence_digest: clock.evidence_digest,
  };
  const execution = deepFreeze({
    ...basis,
    execution_digest: hashCanonicalJson({ domain: EXECUTION_DOMAIN, ...basis }),
  });
  EXECUTIONS.add(execution);
  EXECUTION_STATE.set(execution, {
    ...state,
    reservation,
    operator_ack: operatorAck,
    witness_ack: witnessAck,
    state: "begun",
  });
  state.state = "begun";
  return execution;
}

function assertExecution(input, runtimeInput = null) {
  const state = input == null ? null : EXECUTION_STATE.get(input);
  if (!input || !EXECUTIONS.has(input) || !state || !Object.isFrozen(input)) {
    throw new Error("manual-action execution must be privately branded");
  }
  if (runtimeInput != null && state.runtime !== assertRuntime(runtimeInput)) {
    throw new Error("manual-action execution belongs to another runtime");
  }
  return input;
}

function resolveStateTerminal(execution, state, transitionInput, restoreResultInput) {
  const transition = assertChameleonStateTransition(transitionInput);
  for (const [actual, expected, field] of [
    [transition.instrument_ref, execution.instrument_ref, "instrument_ref"],
    [transition.operation_id, MANUAL_OPERATION_ID, "operation_id"],
    [transition.operation_contract_digest, MANUAL_OPERATION.operation_contract_digest, "operation_contract_digest"],
    [transition.attempt_ref, `attempt:${execution.attempt_id}`, "attempt_ref"],
    [transition.request_digest, state.grant.execution_request_digest, "request_digest"],
    [transition.lease_id, state.grant.lease_id, "lease_id"],
    [transition.fencing_generation, state.grant.fencing_generation, "fencing_generation"],
    [transition.authorized_effects_digest, state.plan.requested_effects_digest, "authorized_effects_digest"],
    [transition.pre_snapshot_digest, execution.pre_snapshot_digest, "pre_snapshot_digest"],
    [transition.pre_workspace_state_digest, execution.pre_workspace_state_digest, "pre_workspace_state_digest"],
    [transition.pre_state_epoch, execution.pre_state_epoch, "pre_state_epoch"],
  ]) {
    if (actual !== expected) throw new Error(`manual action state ${field} binding drift`);
  }
  if (transition.observed_post_snapshot_digest == null
      || !["confirmed_effect", "confirmed_no_effect"].includes(transition.effect_disposition)) {
    throw new Error("manual action requires observed post-state custody");
  }
  const postMode = transition.mode_change == null ? execution.pre_mode : transition.mode_change.post_mode;
  if (postMode !== "rf_off") throw new Error("manual action post-state did not return to RF-off mode");
  if (state.action.capability_id === "CU-ADMIN-FIELD-GENERATOR-INVOKE"
      && transition.observed_post_workspace_state_digest !== execution.pre_workspace_state_digest) {
    throw new Error("field-generator action changed the Chameleon workspace");
  }
  if (state.action.capability_id === "CU-ADMIN-BUTTON-CLONE-INVOKE"
      && transition.declared_post_workspace_state_digest === execution.pre_workspace_state_digest) {
    throw new Error("clone action did not declare its workspace mutation");
  }
  let cleanupDisposition;
  let cleanupRef;
  let cleanupDigest;
  if (transition.transition_state === "complete") {
    if (restoreResultInput != null) throw new Error("manual action supplied unsolicited cleanup result");
    cleanupDisposition = "no_restore_required";
    cleanupRef = transition.receipt_ref;
    cleanupDigest = transition.transition_digest;
  } else if (["restore_required", "quarantine_required"].includes(transition.transition_state)) {
    const restore = assertChameleonStateRestoreResult(restoreResultInput);
    for (const [actual, expected, field] of [
      [restore.instrument_ref, execution.instrument_ref, "instrument_ref"],
      [restore.lease_id, state.grant.lease_id, "lease_id"],
      [restore.fencing_generation, state.grant.fencing_generation, "fencing_generation"],
      [restore.restore_plan_digest, transition.restore_plan_digest, "restore_plan_digest"],
      [restore.restore_effects_digest, transition.restore_effects_digest, "restore_effects_digest"],
      [restore.source_digest, transition.transition_digest, "source_digest"],
    ]) {
      if (actual !== expected) throw new Error(`manual action cleanup ${field} binding drift`);
    }
    if (restore.disposition !== "restored") throw new Error("manual action cleanup ended in quarantine");
    cleanupDisposition = "restored";
    cleanupRef = restore.restore_ref;
    cleanupDigest = restore.restore_result_digest;
  } else {
    throw new Error("manual action ambiguous state requires reconciliation and quarantine");
  }
  const postWorkspaceStateDigest = cleanupDisposition === "restored"
    ? execution.pre_workspace_state_digest
    : transition.observed_post_workspace_state_digest;
  const postStateEpoch = cleanupDisposition === "restored"
    ? assertChameleonStateRestoreResult(restoreResultInput).restored_workspace_state_digest == null
      ? transition.declared_post_state_epoch
      : transition.declared_post_state_epoch + 1
    : transition.declared_post_state_epoch;
  const restorationReceiptRef = `restoration-receipt:${hashCanonicalJson({
    domain: RESTORATION_RECEIPT_DOMAIN,
    execution_digest: execution.execution_digest,
    transition_digest: transition.transition_digest,
    cleanup_digest: cleanupDigest,
  }).slice(0, 48)}`;
  return deepFreeze({
    transition,
    restore_result: restoreResultInput || null,
    transition_digest: transition.transition_digest,
    observed_post_snapshot_digest: transition.observed_post_snapshot_digest,
    post_mode: postMode,
    post_workspace_state_digest: postWorkspaceStateDigest,
    post_state_epoch: postStateEpoch,
    cleanup_disposition: cleanupDisposition,
    cleanup_ref: cleanupRef,
    cleanup_digest: cleanupDigest,
    restoration_receipt_ref: restorationReceiptRef,
  });
}

function createChameleonManualActionCompletionContext(executionInput, input, transitionInput,
  restoreResultInput = null) {
  const execution = assertExecution(executionInput);
  const state = EXECUTION_STATE.get(execution);
  if (state.state !== "begun") throw new Error("manual-action execution is not awaiting completion");
  assertDataOnlyGraph(input, "chameleon_manual_action_completion_context");
  assertClosedObject(input, "chameleon_manual_action_completion_context", [
    "version",
    "completed_at",
    "manual_evidence_artifact_ref",
    "rf_on_observed_at",
    "rf_off_observed_at",
    "external_rf_state_digest",
    "rf_sensor_artifact_ref",
  ]);
  if (input.version !== CHAMELEON_MANUAL_ACTION_VERSION) {
    throw new Error("chameleon_manual_action_completion_context.version must be 1");
  }
  const completedAt = assertTimestamp(input.completed_at, "manual completion completed_at");
  const rfOn = assertTimestamp(input.rf_on_observed_at, "manual completion rf_on_observed_at");
  const rfOff = assertTimestamp(input.rf_off_observed_at, "manual completion rf_off_observed_at");
  if (Date.parse(rfOn) < Date.parse(execution.started_at)
      || Date.parse(rfOff) <= Date.parse(rfOn)
      || Date.parse(rfOff) > Date.parse(execution.rf_off_deadline)
      || Date.parse(completedAt) < Date.parse(rfOff)
      || Date.parse(completedAt) >= Date.parse(execution.active_grant_expires_at)) {
    throw new Error("manual action RF evidence is late or outside the execution window");
  }
  const stateTerminal = resolveStateTerminal(execution, state, transitionInput, restoreResultInput);
  const basis = {
    version: CHAMELEON_MANUAL_ACTION_VERSION,
    execution_ref: execution.execution_ref,
    execution_digest: execution.execution_digest,
    plan_hash: execution.plan_hash,
    attempt_id: execution.attempt_id,
    capability_id: execution.capability_id,
    challenge_nonce: execution.challenge_nonce,
    completed_at: completedAt,
    manual_evidence_artifact_ref: normalizeOpaqueRef(
      input.manual_evidence_artifact_ref,
      "manual completion manual_evidence_artifact_ref",
      { prefix: "artifact" },
    ),
    rf_on_observed_at: rfOn,
    rf_off_observed_at: rfOff,
    rf_off_deadline: execution.rf_off_deadline,
    external_rf_state_digest: assertDigest(
      input.external_rf_state_digest,
      "manual completion external_rf_state_digest",
    ),
    rf_sensor_artifact_ref: normalizeOpaqueRef(
      input.rf_sensor_artifact_ref,
      "manual completion rf_sensor_artifact_ref",
      { prefix: "artifact" },
    ),
    transition_digest: stateTerminal.transition_digest,
    observed_post_snapshot_digest: stateTerminal.observed_post_snapshot_digest,
    pre_mode: execution.pre_mode,
    post_mode: stateTerminal.post_mode,
    pre_workspace_state_digest: execution.pre_workspace_state_digest,
    post_workspace_state_digest: stateTerminal.post_workspace_state_digest,
    pre_state_epoch: execution.pre_state_epoch,
    post_state_epoch: stateTerminal.post_state_epoch,
    cleanup_disposition: stateTerminal.cleanup_disposition,
    cleanup_ref: stateTerminal.cleanup_ref,
    cleanup_digest: stateTerminal.cleanup_digest,
    restoration_receipt_ref: stateTerminal.restoration_receipt_ref,
  };
  const context = deepFreeze({
    ...basis,
    completion_context_digest: hashCanonicalJson({
      domain: "hacker-bob/chameleon-manual-action-completion-context/v1",
      ...basis,
    }),
  });
  COMPLETION_CONTEXTS.add(context);
  COMPLETION_CONTEXT_STATE.set(context, { execution, state_terminal: stateTerminal });
  return context;
}

function assertCompletionContext(contextInput, executionInput = null) {
  const state = contextInput == null ? null : COMPLETION_CONTEXT_STATE.get(contextInput);
  if (!contextInput || !COMPLETION_CONTEXTS.has(contextInput) || !state
      || !Object.isFrozen(contextInput)) {
    throw new Error("manual-action completion context must be privately branded");
  }
  if (executionInput != null && state.execution !== assertExecution(executionInput)) {
    throw new Error("manual-action completion context crosses an execution");
  }
  return contextInput;
}

function completionPayload(executionInput, contextInput, role, actionDisposition) {
  const execution = assertExecution(executionInput);
  const context = assertCompletionContext(contextInput, execution);
  const signerRole = assertEnum(role, SIGNER_ROLES, "manual completion role");
  const disposition = assertEnum(
    actionDisposition,
    ACTION_DISPOSITIONS,
    "manual completion action_disposition",
  );
  const receiptRef = signerRole === "operator"
    ? execution.operator_receipt_ref
    : execution.witness_receipt_ref;
  const common = {
    version: CHAMELEON_MANUAL_ACTION_VERSION,
    purpose: `${signerRole}_completion`,
    execution_ref: execution.execution_ref,
    execution_digest: execution.execution_digest,
    reservation_digest: execution.reservation_digest,
    challenge_nonce: execution.challenge_nonce,
    plan_hash: execution.plan_hash,
    attempt_id: execution.attempt_id,
    active_grant_ref: execution.active_grant_ref,
    grant_projection_digest: execution.grant_projection_digest,
    capability_id: execution.capability_id,
    procedure_binding_digest: execution.procedure_binding_digest,
    effect_binding_digest: execution.effect_binding_digest,
    pre_snapshot_digest: execution.pre_snapshot_digest,
    completion_context_digest: context.completion_context_digest,
    transition_digest: context.transition_digest,
    observed_post_snapshot_digest: context.observed_post_snapshot_digest,
    pre_mode: context.pre_mode,
    post_mode: context.post_mode,
    pre_workspace_state_digest: context.pre_workspace_state_digest,
    post_workspace_state_digest: context.post_workspace_state_digest,
    pre_state_epoch: context.pre_state_epoch,
    post_state_epoch: context.post_state_epoch,
    cleanup_plan_digest: execution.cleanup_plan_digest,
    cleanup_disposition: context.cleanup_disposition,
    cleanup_ref: context.cleanup_ref,
    cleanup_digest: context.cleanup_digest,
    manual_evidence_artifact_ref: context.manual_evidence_artifact_ref,
    action_disposition: disposition,
    signer_role: signerRole,
    receipt_ref: receiptRef,
    completed_at: context.completed_at,
  };
  if (signerRole === "witness") {
    return deepFreeze({
      ...common,
      witness_observer_id: EXECUTION_STATE.get(execution).planned_witness.observer_id,
      witness_observer_enrollment_ref: EXECUTION_STATE.get(execution).planned_witness.observer_enrollment_ref,
      rf_on_observed_at: context.rf_on_observed_at,
      rf_off_observed_at: context.rf_off_observed_at,
      rf_off_deadline: context.rf_off_deadline,
      external_rf_state_digest: context.external_rf_state_digest,
      rf_sensor_artifact_ref: context.rf_sensor_artifact_ref,
    });
  }
  return deepFreeze(common);
}

const createChameleonManualActionCompletionPayload = completionPayload;

function classifyCompletionError(error) {
  const message = String(error && error.message || "");
  if (/late|expired|future|backdated|window/u.test(message)) return "late_evidence";
  if (/crosses an attempt|attempt_id|crosses an execution/u.test(message)) return "cross_attempt_evidence";
  if (/substitut|capability|procedure|purpose/u.test(message)) return "receipt_substitution";
  if (/signature|signer/u.test(message)) return "signature_invalid";
  if (/RF|rf_/u.test(message)) return "rf_evidence_invalid";
  if (/state|snapshot|workspace|mode|transition/u.test(message)) return "state_binding_invalid";
  if (/cleanup|restore|quarantine|reconcil/u.test(message)) return "cleanup_unresolved";
  return "malformed_evidence";
}

function terminalBasis(execution, disposition, reasonCode, clock, values = {}) {
  const basis = {
    version: CHAMELEON_MANUAL_ACTION_VERSION,
    terminal_ref: `manual-terminal:${hashCanonicalJson({
      execution_digest: execution.execution_digest,
      disposition,
      reason_code: reasonCode,
      decided_at: clock.now,
    }).slice(0, 48)}`,
    execution_ref: execution.execution_ref,
    execution_digest: execution.execution_digest,
    plan_hash: execution.plan_hash,
    attempt_id: execution.attempt_id,
    capability_id: execution.capability_id,
    challenge_nonce: execution.challenge_nonce,
    disposition,
    reason_code: reasonCode,
    closable: disposition === "completed_clean",
    cleanup_status: disposition === "completed_clean" ? "succeeded" : "quarantine_required",
    operator_receipt_digest: values.operator_receipt_digest || null,
    witness_receipt_digest: values.witness_receipt_digest || null,
    completion_context_digest: values.context?.completion_context_digest || null,
    transition_digest: values.context?.transition_digest || null,
    observed_post_snapshot_digest: values.context?.observed_post_snapshot_digest || null,
    pre_mode: execution.pre_mode,
    post_mode: values.context?.post_mode || null,
    pre_workspace_state_digest: execution.pre_workspace_state_digest,
    post_workspace_state_digest: values.context?.post_workspace_state_digest || null,
    pre_state_epoch: execution.pre_state_epoch,
    post_state_epoch: values.context?.post_state_epoch || null,
    cleanup_disposition: values.context?.cleanup_disposition || "quarantine_required",
    cleanup_ref: values.context?.cleanup_ref || null,
    cleanup_digest: values.context?.cleanup_digest || null,
    restoration_receipt_ref: values.context?.restoration_receipt_ref || null,
    manual_evidence_artifact_ref: values.context?.manual_evidence_artifact_ref || null,
    rf_on_observed_at: values.context?.rf_on_observed_at || null,
    rf_off_observed_at: values.context?.rf_off_observed_at || null,
    rf_off_deadline: execution.rf_off_deadline,
    external_rf_state_digest: values.context?.external_rf_state_digest || null,
    rf_sensor_artifact_ref: values.context?.rf_sensor_artifact_ref || null,
    started_at: execution.started_at,
    ended_at: values.context?.completed_at || clock.now,
    decided_at: clock.now,
    clock_evidence_digest: clock.evidence_digest,
  };
  return deepFreeze({
    ...basis,
    terminal_digest: hashCanonicalJson({ domain: TERMINAL_DOMAIN, ...basis }),
  });
}

function completeChameleonManualAction(runtimeInput, executionInput, contextInput, input,
  trustedClockSample) {
  const runtime = assertRuntime(runtimeInput);
  const execution = assertExecution(executionInput, runtime);
  const state = EXECUTION_STATE.get(execution);
  if (state.state !== "begun") throw new Error("manual-action execution was already consumed");
  const clock = clockEvidence(trustedClockSample);
  state.state = "settling";
  let terminal;
  try {
    const context = assertCompletionContext(contextInput, execution);
    assertDataOnlyGraph(input, "chameleon_manual_action_completion");
    assertClosedObject(input, "chameleon_manual_action_completion", [
      "version", "operator_receipt", "witness_receipt",
    ]);
    if (input.version !== CHAMELEON_MANUAL_ACTION_VERSION) {
      throw new Error("chameleon_manual_action_completion.version must be 1");
    }
    if (Date.parse(clock.latest) >= Date.parse(execution.active_grant_expires_at)
        || Date.parse(context.completed_at) > Date.parse(clock.earliest)) {
      throw new Error("manual action completion is late or in the future");
    }
    const operatorPayload = completionPayload(
      execution,
      context,
      "operator",
      input.operator_receipt.payload?.action_disposition,
    );
    const witnessPayload = completionPayload(
      execution,
      context,
      "witness",
      input.witness_receipt.payload?.action_disposition,
    );
    if (operatorPayload.action_disposition !== "performed"
        || witnessPayload.action_disposition !== "performed") {
      throw new Error("manual action performance is uncertain or disagreed");
    }
    const operatorReceipt = normalizeSignedPayload(
      input.operator_receipt,
      operatorPayload,
      state.operator_entry,
      clock,
      execution.started_at,
      execution.active_grant_expires_at,
      "manual operator completion",
    );
    const witnessReceipt = normalizeSignedPayload(
      input.witness_receipt,
      witnessPayload,
      state.witness_entry,
      clock,
      execution.started_at,
      execution.active_grant_expires_at,
      "manual witness completion",
    );
    terminal = terminalBasis(execution, "completed_clean", "completed_clean", clock, {
      context,
      operator_receipt_digest: operatorReceipt.signed_receipt_digest,
      witness_receipt_digest: witnessReceipt.signed_receipt_digest,
    });
    TERMINAL_STATE.set(terminal, {
      runtime,
      execution,
      plan: state.plan,
      planned_witness: state.planned_witness,
      operator_receipt: operatorReceipt,
      witness_receipt: witnessReceipt,
      context,
    });
  } catch (error) {
    const reasonCode = classifyCompletionError(error);
    terminal = terminalBasis(execution, "inconclusive", reasonCode, clock);
    TERMINAL_STATE.set(terminal, {
      runtime,
      execution,
      plan: state.plan,
      planned_witness: state.planned_witness,
      cause_code: reasonCode,
    });
  }
  TERMINALS.add(terminal);
  state.state = "terminal";
  state.terminal = terminal;
  const runtimeState = RUNTIME_STATE.get(runtime);
  if (terminal.disposition === "completed_clean") {
    runtimeState.active_instruments.delete(execution.instrument_ref);
  } else {
    runtimeState.active_instruments.set(execution.instrument_ref, terminal);
  }
  return terminal;
}

function assertTerminal(input, { closable = null } = {}) {
  const state = input == null ? null : TERMINAL_STATE.get(input);
  if (!input || !TERMINALS.has(input) || !state || !Object.isFrozen(input)) {
    throw new Error("manual-action terminal must be privately branded");
  }
  if (closable === true && input.closable !== true) {
    throw new Error("inconclusive manual action cannot enter the ordinary verifier path");
  }
  return input;
}

function projectChameleonManualActionExecutionPayload(terminalInput, input) {
  const terminal = assertTerminal(terminalInput, { closable: true });
  const state = TERMINAL_STATE.get(terminal);
  const plan = state.plan;
  assertDataOnlyGraph(input, "manual_action_execution_projection");
  assertClosedObject(input, "manual_action_execution_projection", [
    "version", "instrument_trust_domain_ref", "consumption_attestation",
  ]);
  if (input.version !== CHAMELEON_MANUAL_ACTION_VERSION) {
    throw new Error("manual_action_execution_projection.version must be 1");
  }
  const cohort = plan.positive_cohort;
  return deepFreeze({
    version: 1,
    plan_hash: plan.plan_hash,
    session_nucleus_hash: plan.session_nucleus_hash,
    task_id: plan.task_id,
    attempt_id: plan.attempt_id,
    cohort_kind: "positive",
    stimulus_plan_ref: cohort.stimulus_plan_ref,
    stimulus_plan_digest: cohort.stimulus_plan_digest,
    cohort_execution_request_digest: cohort.cohort_execution_request_digest,
    grant_ref: cohort.grant_ref,
    execution_identity: cohort.execution_identity,
    execution_request_digest: plan.execution_request_digest,
    instrument_ref: plan.instrument_ref,
    instrument_identity_ref: plan.instrument_identity_ref,
    instrument_inventory_ref: plan.instrument_inventory_ref,
    provider_manifest_digest: plan.provider_manifest_digest,
    instrument_trust_domain_ref: normalizeOpaqueRef(
      input.instrument_trust_domain_ref,
      "manual_action_execution_projection.instrument_trust_domain_ref",
      { prefix: "trust-domain" },
    ),
    status: "executed",
    started_at: terminal.started_at,
    ended_at: terminal.ended_at,
    consumption_attestation: input.consumption_attestation,
    state_epoch_before: terminal.pre_state_epoch,
    state_epoch_after: terminal.post_state_epoch,
    stimulus_artifact_ref: terminal.manual_evidence_artifact_ref,
  });
}

function projectChameleonManualActionObservationPayload(terminalInput, input) {
  const terminal = assertTerminal(terminalInput, { closable: true });
  const state = TERMINAL_STATE.get(terminal);
  const plan = state.plan;
  const observer = state.planned_witness;
  assertDataOnlyGraph(input, "manual_action_observation_projection");
  assertClosedObject(input, "manual_action_observation_projection", [
    "version",
    "execution_receipt_ref",
    "consumption_attestation",
    "clock_offset_ms",
    "clock_uncertainty_ms",
  ]);
  if (input.version !== CHAMELEON_MANUAL_ACTION_VERSION) {
    throw new Error("manual_action_observation_projection.version must be 1");
  }
  return deepFreeze({
    version: 1,
    plan_hash: plan.plan_hash,
    session_nucleus_hash: plan.session_nucleus_hash,
    task_id: plan.task_id,
    attempt_id: plan.attempt_id,
    cohort_kind: "positive",
    execution_receipt_ref: normalizeOpaqueRef(
      input.execution_receipt_ref,
      "manual_action_observation_projection.execution_receipt_ref",
      { prefix: "physical-execution-receipt" },
    ),
    grant_ref: plan.positive_cohort.grant_ref,
    execution_identity: plan.positive_cohort.execution_identity,
    observer_id: observer.observer_id,
    observer_enrollment_ref: observer.observer_enrollment_ref,
    source_kind: observer.source_kind,
    source_ref: observer.source_ref,
    trust_domain_ref: observer.required_trust_domain_ref,
    independence_domain_ref: observer.required_independence_domain_ref,
    observer_identity_ref: observer.observer_identity_ref,
    source_assurance_scheme: observer.source_assurance_scheme,
    challenge_nonce: observer.challenge_nonce,
    attempt_binding_digest: observer.attempt_binding_digest,
    replay_guard: { kind: "one_time_challenge", value: observer.challenge_nonce },
    consumption_attestation: input.consumption_attestation,
    observed_outcome_digest: state.plan.positive_cohort.expected_outcome_digest,
    observed_state_digest: terminal.external_rf_state_digest,
    captured_at: terminal.rf_off_observed_at,
    received_at: terminal.ended_at,
    clock_offset_ms: assertInteger(
      input.clock_offset_ms,
      "manual_action_observation_projection.clock_offset_ms",
      -86_400_000,
      86_400_000,
    ),
    clock_uncertainty_ms: assertInteger(
      input.clock_uncertainty_ms,
      "manual_action_observation_projection.clock_uncertainty_ms",
      0,
      86_400_000,
    ),
    artifact_ref: terminal.rf_sensor_artifact_ref,
  });
}

function projectChameleonManualActionCleanupPayload(terminalInput, input) {
  const terminal = assertTerminal(terminalInput, { closable: true });
  const state = TERMINAL_STATE.get(terminal);
  const plan = state.plan;
  assertDataOnlyGraph(input, "manual_action_cleanup_projection");
  assertClosedObject(input, "manual_action_cleanup_projection", [
    "version", "execution_receipt_ref",
  ]);
  if (input.version !== CHAMELEON_MANUAL_ACTION_VERSION) {
    throw new Error("manual_action_cleanup_projection.version must be 1");
  }
  return deepFreeze({
    version: 1,
    plan_hash: plan.plan_hash,
    session_nucleus_hash: plan.session_nucleus_hash,
    task_id: plan.task_id,
    attempt_id: plan.attempt_id,
    execution_receipt_refs: [normalizeOpaqueRef(
      input.execution_receipt_ref,
      "manual_action_cleanup_projection.execution_receipt_ref",
      { prefix: "physical-execution-receipt" },
    )],
    cleanup_plan_digest: plan.cleanup_plan_digest,
    outcome: "succeeded",
    cleanup_state_digest: hashCanonicalJson({
      domain: RESTORATION_RECEIPT_DOMAIN,
      terminal_digest: terminal.terminal_digest,
      cleanup_digest: terminal.cleanup_digest,
      post_workspace_state_digest: terminal.post_workspace_state_digest,
      post_mode: terminal.post_mode,
    }),
    restoration_receipt_ref: terminal.restoration_receipt_ref,
    decided_at: terminal.decided_at,
  });
}

function cancelReservedChameleonManualAction(runtimeInput, reservationInput, trustedClockSample) {
  const runtime = assertRuntime(runtimeInput);
  const reservation = assertReservation(reservationInput, runtime);
  const state = RESERVATION_STATE.get(reservation);
  if (state.state !== "reserved") throw new Error("only an unbegun manual reservation can be cancelled");
  const clock = clockEvidence(trustedClockSample);
  state.state = "cancelled";
  RUNTIME_STATE.get(runtime).active_instruments.delete(reservation.instrument_ref);
  return deepFreeze({
    version: CHAMELEON_MANUAL_ACTION_VERSION,
    reservation_ref: reservation.reservation_ref,
    reservation_digest: reservation.reservation_digest,
    disposition: "cancelled_before_effect",
    cancelled_at: clock.now,
    clock_evidence_digest: clock.evidence_digest,
    cancellation_digest: hashCanonicalJson({
      domain: "hacker-bob/chameleon-manual-action-cancellation/v1",
      reservation_digest: reservation.reservation_digest,
      cancelled_at: clock.now,
      clock_evidence_digest: clock.evidence_digest,
    }),
  });
}

function chameleonManualActionRuntimeReadiness() {
  return deepFreeze({
    version: CHAMELEON_MANUAL_ACTION_VERSION,
    node_id: "PH-P9",
    engineering_ready: true,
    production_ready: false,
    hil_ready: false,
    hil_plan_digest: CHAMELEON_MANUAL_ACTION_HIL_PLAN_DIGEST,
    blockers: [
      "restart_durable_atomic_manual_reservation_owner_not_installed",
      "production_operator_and_witness_signer_enrollment_not_installed",
      "provider_private_production_composition_owner_not_installed",
      "owned_shielded_fixture_hil_evidence_not_completed",
      "external_rf_on_off_observer_hil_evidence_not_completed",
      "signed_hil_gate_evidence_not_ingested",
    ],
  });
}

module.exports = {
  ACTION_DISPOSITIONS,
  CHAMELEON_MANUAL_ACTION_HIL_PLAN_DIGEST,
  CHAMELEON_MANUAL_ACTION_VERSION,
  FAILURE_REASON_CODES,
  SIGNATURE_PURPOSES,
  SIGNER_ROLES,
  TERMINAL_DISPOSITIONS,
  acknowledgementPayload: createChameleonManualActionAcknowledgementPayload,
  beginChameleonManualAction,
  buildChameleonManualActionSignerRegistry,
  cancelReservedChameleonManualAction,
  chameleonManualActionExpectedOutcomeDigest,
  chameleonManualActionParameterDigest,
  chameleonManualActionRuntimeReadiness,
  completeChameleonManualAction,
  completionPayload: createChameleonManualActionCompletionPayload,
  createChameleonManualActionAcknowledgementPayload,
  createChameleonManualActionCompletionContext,
  createChameleonManualActionCompletionPayload,
  createChameleonManualActionRuntime,
  describeChameleonManualActions,
  manualActionSignatureInputDigest,
  projectChameleonManualActionCleanupPayload,
  projectChameleonManualActionExecutionPayload,
  projectChameleonManualActionObservationPayload,
  reserveChameleonManualAction,
};
