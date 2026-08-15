"use strict";

// PH-X4 orthogonal engineering fixture. This is deliberately non-RFID and
// contains no device I/O. It exercises the same provider ABI with a GPIO
// actuator, optical sensor, external observer/control, and one atomic resource
// bundle. It is mock conformance data, never production or HIL evidence.

const {
  buildNormalizedOperationRegistry,
  defineProviderDescriptor,
} = require("../../../mcp/domains/physical/instrument-provider-contract.js");
const {
  buildEffectTemplateRegistry,
  requestedEffectDigest,
} = require("../../../mcp/core/requested-effects.js");
const {
  normalizePhysicalResourceBundle,
} = require("../../../mcp/lib/physical-resource-contract.js");

const PUBLIC_SUMMARY_CODES = Object.freeze([
  "operation_failed",
  "operation_inconclusive",
  "operation_refused",
  "operation_stopped",
  "operation_succeeded",
]);

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function worstCaseEffect(template) {
  return {
    template_id: template.template_id,
    template_digest: template.template_digest,
    subject_kind: template.subject_kind,
    action: template.action,
    channel: template.channel,
    persistence: template.persistence,
  };
}

function requestedEffect(template, subjectRef, bounds) {
  return deepFreeze({
    version: 1,
    template_id: template.template_id,
    template_digest: template.template_digest,
    subject_ref: subjectRef,
    subject_kind: template.subject_kind,
    action: template.action,
    channel: template.channel,
    persistence: template.persistence,
    bounds,
  });
}

function resourceRequirement({
  alias,
  resourceKind,
  candidateResourceRefs,
  capabilityRefs = [],
  requestedEffectDigests = [],
  ...optional
}) {
  return {
    alias,
    resource_kind: resourceKind,
    candidate_resource_refs: candidateResourceRefs,
    ownership: "exclusive",
    capacity_units: 1,
    capability_refs: capabilityRefs,
    requested_effect_digests: requestedEffectDigests,
    constraints: [],
    ...optional,
  };
}

function createOrthogonalMultiInstrumentProviderFixture() {
  const effectRegistry = buildEffectTemplateRegistry([
    {
      version: 1,
      template_id: "environment.actuate.gpio.v1",
      subject_kind: "environment",
      action: "actuate",
      channel: "gpio",
      persistence: "ephemeral",
      bounds: {
        attempt_limit: { kind: "integer", required: true, min: 1, max: 1 },
        duration: { kind: "quantity", required: true, quantity_id: "duration" },
        logic_level: { kind: "quantity", required: true, quantity_id: "logic_level" },
      },
    },
    {
      version: 1,
      template_id: "environment.observe.optical.v1",
      subject_kind: "environment",
      action: "observe",
      channel: "optical",
      persistence: "none",
      bounds: {
        attempt_limit: { kind: "integer", required: true, min: 1, max: 4 },
        duration: { kind: "quantity", required: true, quantity_id: "duration" },
        optical_intensity: {
          kind: "quantity",
          required: true,
          quantity_id: "optical_intensity",
        },
      },
    },
    {
      version: 1,
      template_id: "instrument.observe.instrument_local.v1",
      subject_kind: "instrument",
      action: "observe",
      channel: "instrument_local",
      persistence: "none",
      bounds: {
        attempt_limit: { kind: "integer", required: true, min: 1, max: 4 },
      },
    },
  ]);

  const operationRegistry = buildNormalizedOperationRegistry([
    ...["instrument.inventory", "instrument.capabilities", "instrument.health"].map((operationId) => ({
      version: 1,
      operation_id: operationId,
      semantic_version: 1,
      parameters: {},
      public_summary_codes: PUBLIC_SUMMARY_CODES,
    })),
    {
      version: 1,
      operation_id: "environment.actuate",
      semantic_version: 1,
      parameters: {
        duration_ms: { kind: "integer", required: true, min: 1, max: 1_000 },
        logic_level_v: { kind: "number", required: true, min: 0, max: 5 },
      },
      public_summary_codes: PUBLIC_SUMMARY_CODES,
    },
    {
      version: 1,
      operation_id: "environment.observe",
      semantic_version: 1,
      parameters: {
        maximum_duration_ms: { kind: "integer", required: true, min: 1, max: 5_000 },
        sample_count: { kind: "integer", required: true, min: 1, max: 4_096 },
      },
      public_summary_codes: PUBLIC_SUMMARY_CODES,
    },
  ]);

  const bootstrapTemplate = effectRegistry.get("instrument.observe.instrument_local.v1");
  const actuatorTemplate = effectRegistry.get("environment.actuate.gpio.v1");
  const opticalTemplate = effectRegistry.get("environment.observe.optical.v1");
  const capabilityFor = (capabilityId, operationId, effect, overrides) => {
    const operation = operationRegistry.get(operationId);
    return {
      capability_id: capabilityId,
      operation_id: operationId,
      operation_digest: operation.operation_digest,
      worst_case_effects: [worstCaseEffect(effect)],
      ...overrides,
    };
  };
  const descriptor = defineProviderDescriptor({
    version: 1,
    abi_version: 3,
    provider_id: "deterministic_orthogonal_gpio_optical",
    provider_version: "1.0.0",
    implementation_digest: "4".repeat(64),
    operation_registry_digest: operationRegistry.registry_digest,
    capabilities: [
      capabilityFor("orthogonal.inventory", "instrument.inventory", bootstrapTemplate, {
        idempotency: "read_only_idempotent",
        retry_policy: "new_attempt_after_confirmed_no_effect",
        stop_semantics: "not_applicable",
        restore_policy: "not_required",
      }),
      capabilityFor("orthogonal.capabilities", "instrument.capabilities", bootstrapTemplate, {
        idempotency: "read_only_idempotent",
        retry_policy: "new_attempt_after_confirmed_no_effect",
        stop_semantics: "not_applicable",
        restore_policy: "not_required",
      }),
      capabilityFor("orthogonal.health", "instrument.health", bootstrapTemplate, {
        idempotency: "read_only_idempotent",
        retry_policy: "new_attempt_after_confirmed_no_effect",
        stop_semantics: "not_applicable",
        restore_policy: "not_required",
      }),
      capabilityFor("orthogonal.actuate", "environment.actuate", actuatorTemplate, {
        idempotency: "attempt_idempotent",
        retry_policy: "never",
        stop_semantics: "bounded",
        restore_policy: "required",
      }),
      capabilityFor("orthogonal.observe", "environment.observe", opticalTemplate, {
        idempotency: "read_only_idempotent",
        retry_policy: "new_attempt_after_confirmed_no_effect",
        stop_semantics: "bounded",
        restore_policy: "not_required",
      }),
    ],
  }, operationRegistry, effectRegistry);

  const environmentRef = "environment:orthogonal-owned-fixture-0001";
  const actuatorEffect = requestedEffect(actuatorTemplate, environmentRef, {
    attempt_limit: 1,
    duration: { quantity_id: "duration", unit: "ms", max: 250 },
    logic_level: { quantity_id: "logic_level", unit: "V", max: 3.3 },
  });
  const opticalEffect = requestedEffect(opticalTemplate, environmentRef, {
    attempt_limit: 1,
    duration: { quantity_id: "duration", unit: "ms", max: 1_000 },
    optical_intensity: { quantity_id: "optical_intensity", unit: "W/m^2", max: 10 },
  });

  const resourceBundle = normalizePhysicalResourceBundle({
    version: 1,
    bundle_id: "orthogonal.gpio_optical.v1",
    requirements: [
      resourceRequirement({
        alias: "gpio_actuator",
        resourceKind: "instrument",
        candidateResourceRefs: ["instrument:orthogonal-gpio-actuator-0001"],
        capabilityRefs: ["capability:orthogonal.actuate"],
        requestedEffectDigests: [requestedEffectDigest(actuatorEffect, effectRegistry)],
        mode_ref: "mode:gpio-output-low-baseline",
        workspace_ref: "workspace:orthogonal-owned-bench-0001",
      }),
      resourceRequirement({
        alias: "optical_sensor",
        resourceKind: "instrument",
        candidateResourceRefs: ["instrument:orthogonal-optical-sensor-0001"],
        capabilityRefs: ["capability:orthogonal.observe"],
        requestedEffectDigests: [requestedEffectDigest(opticalEffect, effectRegistry)],
        mode_ref: "mode:bounded-optical-observation",
        workspace_ref: "workspace:orthogonal-owned-bench-0001",
      }),
      resourceRequirement({
        alias: "external_observer",
        resourceKind: "observer",
        candidateResourceRefs: ["observer:orthogonal-external-meter-0001"],
        independence_domain_ref: "independence-domain:external-meter",
      }),
      resourceRequirement({
        alias: "negative_control",
        resourceKind: "control",
        candidateResourceRefs: ["control:orthogonal-negative-control-0001"],
        independence_domain_ref: "independence-domain:control-fixture",
      }),
      resourceRequirement({
        alias: "owned_workspace",
        resourceKind: "workspace",
        candidateResourceRefs: ["workspace:orthogonal-owned-bench-0001"],
        workspace_ref: "workspace:orthogonal-owned-bench-0001",
      }),
      resourceRequirement({
        alias: "operator_presence",
        resourceKind: "operator_presence",
        candidateResourceRefs: ["principal:orthogonal-operator-0001"],
        custody_principal_ref: "principal:orthogonal-operator-0001",
      }),
    ],
    attempt_budget: 2,
    duration_ms: 5_000,
    reservation_ttl_ms: 6_000,
    cooldown_ms: 1_000,
    preemption_policy: "before_effect_only",
    fairness_class: "orthogonal_provider_conformance",
    batch_key: "orthogonal:gpio-optical:v1",
    setup_cost_units: 2,
  });

  const prepareRequests = deepFreeze({
    actuate: {
      version: 1,
      attempt_ref: "attempt:orthogonal-actuate-0001",
      instrument_ref: "instrument:orthogonal-gpio-actuator-0001",
      capability_id: "orthogonal.actuate",
      operation_id: "environment.actuate",
      operation_digest: operationRegistry.get("environment.actuate").operation_digest,
      parameters: { duration_ms: 250, logic_level_v: 3.3 },
      requested_effects: [actuatorEffect],
      execution_deadline: "2026-07-18T01:00:00.000Z",
      journal_entry_ref: "journal-entry:orthogonal-actuate-0001",
    },
    observe: {
      version: 1,
      attempt_ref: "attempt:orthogonal-observe-0001",
      instrument_ref: "instrument:orthogonal-optical-sensor-0001",
      capability_id: "orthogonal.observe",
      operation_id: "environment.observe",
      operation_digest: operationRegistry.get("environment.observe").operation_digest,
      parameters: { maximum_duration_ms: 1_000, sample_count: 64 },
      requested_effects: [opticalEffect],
      execution_deadline: "2026-07-18T01:00:00.000Z",
      journal_entry_ref: "journal-entry:orthogonal-observe-0001",
    },
  });

  return Object.freeze({
    descriptor,
    effectRegistry,
    operationRegistry,
    prepareRequests,
    requestedEffects: deepFreeze({ actuate: actuatorEffect, observe: opticalEffect }),
    resourceBundle,
  });
}

module.exports = {
  createOrthogonalMultiInstrumentProviderFixture,
};
