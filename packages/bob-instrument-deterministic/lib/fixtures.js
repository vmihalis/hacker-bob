"use strict";

const {
  buildNormalizedOperationRegistry,
  defineProviderDescriptor,
} = require("../../../mcp/domains/physical/instrument-provider-contract.js");
const {
  buildEffectTemplateRegistry,
} = require("../../../mcp/core/requested-effects.js");

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
  return {
    version: 1,
    template_id: template.template_id,
    template_digest: template.template_digest,
    subject_ref: subjectRef,
    subject_kind: template.subject_kind,
    action: template.action,
    channel: template.channel,
    persistence: template.persistence,
    bounds,
  };
}

function buildDeterministicProviderFixture(abiVersion) {
  const effectRegistry = buildEffectTemplateRegistry([
    {
      version: 1,
      template_id: "instrument.observe.usb.v1",
      subject_kind: "instrument",
      action: "observe",
      channel: "usb",
      persistence: "none",
      bounds: {
        attempt_limit: { kind: "integer", required: true, min: 1, max: 4 },
      },
    },
    {
      version: 1,
      template_id: "target.mutate.contact.v1",
      subject_kind: "target",
      action: "mutate",
      channel: "contact",
      persistence: "persistent",
      bounds: {
        attempt_limit: { kind: "integer", required: true, min: 1, max: 2 },
        source_artifact_ref: { kind: "reference", required: true, ref_prefix: "artifact" },
      },
    },
  ]);
  const operationDeclarations = [
    {
      version: 1,
      operation_id: "instrument.inventory",
      semantic_version: 1,
      parameters: {},
      public_summary_codes: [
        "operation_failed",
        "operation_inconclusive",
        "operation_refused",
        "operation_stopped",
        "operation_succeeded",
      ],
    },
    ...(abiVersion === 3 ? [
      {
        version: 1,
        operation_id: "instrument.capabilities",
        semantic_version: 1,
        parameters: {},
        public_summary_codes: [
          "operation_failed",
          "operation_inconclusive",
          "operation_refused",
          "operation_stopped",
          "operation_succeeded",
        ],
      },
      {
        version: 1,
        operation_id: "instrument.health",
        semantic_version: 1,
        parameters: {},
        public_summary_codes: [
          "operation_failed",
          "operation_inconclusive",
          "operation_refused",
          "operation_stopped",
          "operation_succeeded",
        ],
      },
    ] : []),
    {
      version: 1,
      operation_id: "representation.write",
      semantic_version: 1,
      parameters: {
        block_count: { kind: "integer", required: true, min: 1, max: 64 },
        source_artifact_ref: { kind: "reference", required: true, ref_prefix: "artifact" },
      },
      public_summary_codes: [
        "operation_failed",
        "operation_inconclusive",
        "operation_refused",
        "operation_stopped",
        "operation_succeeded",
      ],
    },
  ];
  const operationRegistry = buildNormalizedOperationRegistry(operationDeclarations);
  const observeTemplate = effectRegistry.get("instrument.observe.usb.v1");
  const mutateTemplate = effectRegistry.get("target.mutate.contact.v1");
  const inventoryOperation = operationRegistry.get("instrument.inventory");
  const capabilitiesOperation = operationRegistry.get("instrument.capabilities");
  const healthOperation = operationRegistry.get("instrument.health");
  const writeOperation = operationRegistry.get("representation.write");
  const bootstrapCapabilities = abiVersion === 3 ? [
    {
      capability_id: "mock.capabilities",
      operation_id: capabilitiesOperation.operation_id,
      operation_digest: capabilitiesOperation.operation_digest,
      worst_case_effects: [worstCaseEffect(observeTemplate)],
      idempotency: "read_only_idempotent",
      retry_policy: "new_attempt_after_confirmed_no_effect",
      stop_semantics: "not_applicable",
      restore_policy: "not_required",
    },
    {
      capability_id: "mock.health",
      operation_id: healthOperation.operation_id,
      operation_digest: healthOperation.operation_digest,
      worst_case_effects: [worstCaseEffect(observeTemplate)],
      idempotency: "read_only_idempotent",
      retry_policy: "new_attempt_after_confirmed_no_effect",
      stop_semantics: "not_applicable",
      restore_policy: "not_required",
    },
  ] : [];
  const descriptor = defineProviderDescriptor({
    version: 1,
    abi_version: abiVersion,
    provider_id: "deterministic_mock",
    provider_version: "1.0.0",
    implementation_digest: "1".repeat(64),
    operation_registry_digest: operationRegistry.registry_digest,
    capabilities: [
      {
        capability_id: "mock.inventory",
        operation_id: inventoryOperation.operation_id,
        operation_digest: inventoryOperation.operation_digest,
        worst_case_effects: [worstCaseEffect(observeTemplate)],
        idempotency: "read_only_idempotent",
        retry_policy: "new_attempt_after_confirmed_no_effect",
        stop_semantics: "not_applicable",
        restore_policy: "not_required",
      },
      ...bootstrapCapabilities,
      {
        capability_id: "mock.write",
        operation_id: writeOperation.operation_id,
        operation_digest: writeOperation.operation_digest,
        worst_case_effects: [worstCaseEffect(mutateTemplate)],
        idempotency: "attempt_idempotent",
        retry_policy: "never",
        stop_semantics: "bounded",
        restore_policy: "required",
      },
    ],
  }, operationRegistry, effectRegistry);
  const prepareRequest = deepFreeze({
    version: 1,
    attempt_ref: "attempt:write-attempt-0001",
    instrument_ref: "instrument:mock-owned-fixture-0001",
    capability_id: "mock.write",
    operation_id: writeOperation.operation_id,
    operation_digest: writeOperation.operation_digest,
    parameters: {
      block_count: 4,
      source_artifact_ref: "artifact:v1:mock-source-0001",
    },
    requested_effects: [requestedEffect(
      mutateTemplate,
      "target:owned-fixture-0001",
      {
        attempt_limit: 1,
        source_artifact_ref: "artifact:v1:mock-source-0001",
      },
    )],
    execution_deadline: "2026-07-18T01:00:00.000Z",
    journal_entry_ref: "journal-entry:mock-prepare-0001",
  });
  const inventoryPrepareRequest = deepFreeze({
    version: 1,
    attempt_ref: "attempt:inventory-attempt-0001",
    instrument_ref: "instrument:mock-owned-fixture-0001",
    capability_id: "mock.inventory",
    operation_id: inventoryOperation.operation_id,
    operation_digest: inventoryOperation.operation_digest,
    parameters: {},
    requested_effects: [requestedEffect(
      observeTemplate,
      "instrument:mock-owned-fixture-0001",
      { attempt_limit: 1 },
    )],
    execution_deadline: "2026-07-18T01:00:00.000Z",
    journal_entry_ref: "journal-entry:mock-inventory-prepare-0001",
  });
  return Object.freeze({
    descriptor,
    effectRegistry,
    inventoryPrepareRequest,
    operationRegistry,
    prepareRequest,
  });
}

function createDeterministicProviderFixture() {
  return buildDeterministicProviderFixture(3);
}

function createDeterministicActiveOnlyProviderFixture() {
  return buildDeterministicProviderFixture(2);
}

module.exports = {
  createDeterministicActiveOnlyProviderFixture,
  createDeterministicProviderFixture,
};
