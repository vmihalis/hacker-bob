"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  PROVIDER_ABI_VERSION,
  PROVIDER_BOOTSTRAP_ACTIVE_PLANE_FORBIDDEN_FIELDS,
  PROVIDER_BOOTSTRAP_OPERATION_IDS,
  PROVIDER_BOOTSTRAP_OUTCOME_VALUES,
  SUPPORTED_PROVIDER_ABI_VERSIONS,
  assertAutomaticRetryAllowed,
  assertAttemptTransition,
  assertNoPublicByteMaterial,
  assertProviderActiveAbiCompatible,
  assertProviderAbiCompatible,
  assertProviderBootstrapAbiCompatible,
  assertProviderInterface,
  buildNormalizedOperationRegistry,
  defineProviderDescriptor,
  isTerminalAttemptState,
  normalizeAttemptReport,
  normalizeCapabilitiesResponse,
  normalizeExecuteRequest,
  normalizeHealthResponse,
  normalizeInventoryResponse,
  normalizePrepareRequest,
  normalizeProviderBootstrapIntent,
  normalizeProviderBootstrapReport,
  normalizeProviderBootstrapRequest,
  normalizeProviderDescriptor,
  normalizePublicResult,
  normalizeReconcileRequest,
  normalizeRestoreRequest,
  normalizeSnapshotRequest,
  normalizeSnapshotResponse,
  normalizeStatusRequest,
  normalizeStopRequest,
} = require("../mcp/domains/physical/instrument-provider-contract.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");
const {
  buildEffectTemplateRegistry,
} = require("../mcp/core/requested-effects.js");
const {
  DeterministicInstrumentProvider,
  runProviderConformance,
} = require("./helpers/deterministic-instrument-provider.js");
const {
  createDurableProviderDispatchHarness,
} = require("./helpers/durable-provider-dispatch.js");

const PROVIDER_HARNESSES = new WeakMap();
const OPEN_HARNESSES = new Set();
test.after(() => {
  for (const harness of OPEN_HARNESSES) harness.close();
  OPEN_HARNESSES.clear();
});

function clone(value) {
  return structuredClone(value);
}

function digest(label) {
  return hashCanonicalJson({ fixture_digest: label });
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

function fixture() {
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
  const operationRegistry = buildNormalizedOperationRegistry([
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
  ]);
  const observeTemplate = effectRegistry.get("instrument.observe.usb.v1");
  const mutateTemplate = effectRegistry.get("target.mutate.contact.v1");
  const inventoryOperation = operationRegistry.get("instrument.inventory");
  const writeOperation = operationRegistry.get("representation.write");
  const descriptor = defineProviderDescriptor({
    version: 1,
    abi_version: 2,
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
  const prepareRequest = {
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
    requested_effects: [{
      version: 1,
      template_id: mutateTemplate.template_id,
      template_digest: mutateTemplate.template_digest,
      subject_ref: "target:owned-fixture-0001",
      subject_kind: mutateTemplate.subject_kind,
      action: mutateTemplate.action,
      channel: mutateTemplate.channel,
      persistence: mutateTemplate.persistence,
      bounds: {
        attempt_limit: 1,
        source_artifact_ref: "artifact:v1:mock-source-0001",
      },
    }],
    execution_deadline: "2026-07-18T01:00:00.000Z",
    journal_entry_ref: "journal-entry:mock-prepare-0001",
  };
  const inventoryPrepareRequest = {
    version: 1,
    attempt_ref: "attempt:inventory-attempt-0001",
    instrument_ref: "instrument:mock-owned-fixture-0001",
    capability_id: "mock.inventory",
    operation_id: inventoryOperation.operation_id,
    operation_digest: inventoryOperation.operation_digest,
    parameters: {},
    requested_effects: [{
      version: 1,
      template_id: observeTemplate.template_id,
      template_digest: observeTemplate.template_digest,
      subject_ref: "instrument:mock-owned-fixture-0001",
      subject_kind: observeTemplate.subject_kind,
      action: observeTemplate.action,
      channel: observeTemplate.channel,
      persistence: observeTemplate.persistence,
      bounds: { attempt_limit: 1 },
    }],
    execution_deadline: "2026-07-18T01:00:00.000Z",
    journal_entry_ref: "journal-entry:mock-inventory-prepare-0001",
  };
  return {
    descriptor,
    effectRegistry,
    inventoryPrepareRequest,
    operationRegistry,
    prepareRequest,
  };
}

function descriptorAtAbi(f, abiVersion) {
  const declaration = clone(f.descriptor);
  delete declaration.capabilities_digest;
  delete declaration.descriptor_digest;
  declaration.abi_version = abiVersion;
  return defineProviderDescriptor(
    declaration,
    f.operationRegistry,
    f.effectRegistry,
  );
}

function bootstrapIntentFixture(descriptor, overrides = {}) {
  const capability = descriptor.capabilities.find(
    (entry) => entry.operation_id === "instrument.inventory",
  );
  if (!capability) throw new Error("bootstrap fixture descriptor lacks inventory");
  return {
    version: 1,
    call_kind: "bootstrap",
    attempt_ref: "bootstrap-attempt:inventory-fixture-0001",
    session_nucleus_hash: digest("bootstrap-session-nucleus"),
    physical_scope_axis_digest: digest("bootstrap-physical-scope-axis"),
    execution_principal_id: "principal:bootstrap-operator-fixture",
    instrument_ref: "instrument:mock-owned-fixture-0001",
    enrollment_candidate_ref: "enrollment-candidate:mock-owned-fixture-0001",
    provider_id: descriptor.provider_id,
    provider_descriptor_digest: descriptor.descriptor_digest,
    provider_binary_digest: digest("bootstrap-provider-binary"),
    transport_digest: digest("bootstrap-transport"),
    bootstrap_manifest_digest: digest("bootstrap-manifest"),
    bootstrap_invariants_digest: digest("bootstrap-invariants"),
    operation_id: capability.operation_id,
    operation_digest: capability.operation_digest,
    execution_request_digest: digest("bootstrap-execution-request"),
    authority_resolution_digest: digest("bootstrap-authority-resolution"),
    signed_grant_digest: digest("bootstrap-signed-grant"),
    replay_claim_digest: digest("bootstrap-replay-claim"),
    replay_reservation_receipt_digest: digest("bootstrap-replay-reservation-receipt"),
    connection_ref: "instrument-connection:mock-owned-fixture-0001",
    connection_generation: 3,
    grant_not_before: "2026-07-18T00:00:00.000Z",
    grant_expires_at: "2026-07-18T00:30:00.000Z",
    ...overrides,
  };
}

function bootstrapRequestFixture(descriptor, options = {}) {
  const credential = options.credential || Object.freeze({ fixture_credential: "opaque" });
  const intent = normalizeProviderBootstrapIntent(
    bootstrapIntentFixture(descriptor, options.intentOverrides),
    descriptor,
  );
  return {
    credential,
    intent,
    input: {
      ...intent,
      dispatch_record_digest: digest("bootstrap-dispatch-record"),
      dispatch_credential: credential,
      ...(options.requestOverrides || {}),
    },
  };
}

function bootstrapSuccessReportFixture(request, overrides = {}) {
  return {
    version: 1,
    attempt_ref: request.attempt_ref,
    operation_id: request.operation_id,
    bootstrap_intent_digest: request.bootstrap_intent_digest,
    bootstrap_request_digest: request.bootstrap_request_digest,
    signed_grant_digest: request.signed_grant_digest,
    replay_reservation_receipt_digest: request.replay_reservation_receipt_digest,
    dispatch_record_digest: request.dispatch_record_digest,
    dispatch_redemption_digest: digest("bootstrap-dispatch-redemption"),
    connection_generation: request.connection_generation,
    outcome: "succeeded",
    observation_ref: "bootstrap-observation:inventory-fixture-0001",
    observation_digest: digest("bootstrap-observation"),
    receipt_ref: "bootstrap-receipt:inventory-fixture-0001",
    receipt_digest: digest("bootstrap-receipt"),
    response_digest: digest("bootstrap-response"),
    observed_at: "2026-07-18T00:10:00.000Z",
    assurance_claims_digest: digest("bootstrap-assurance-claims"),
    invariant_witness_digest: digest("bootstrap-invariant-witness"),
    ...overrides,
  };
}

function providerFor(f, script = []) {
  const harness = createDurableProviderDispatchHarness({
    descriptor: f.descriptor,
    instrumentRefs: [...new Set([
      f.prepareRequest.instrument_ref,
      f.inventoryPrepareRequest.instrument_ref,
    ])],
  });
  OPEN_HARNESSES.add(harness);
  const provider = new DeterministicInstrumentProvider({
    descriptor: f.descriptor,
    operationRegistry: f.operationRegistry,
    effectRegistry: f.effectRegistry,
    providerDispatchPort: harness.port,
    script,
  });
  PROVIDER_HARNESSES.set(provider, harness);
  return provider;
}

function authorizeFor(provider) {
  const harness = PROVIDER_HARNESSES.get(provider);
  if (!harness) throw new Error("provider contract test dispatch harness is unavailable");
  return harness.authorize;
}

function context(f) {
  return {
    descriptor: f.descriptor,
    operation_registry: f.operationRegistry,
    effect_registry: f.effectRegistry,
  };
}

function createdReport(prepared) {
  return {
    version: 1,
    attempt_ref: prepared.attempt_ref,
    operation_id: prepared.operation_id,
    request_digest: prepared.request_digest,
    state: "created",
    sequence: 0,
    effect_disposition: "not_dispatched",
    receipt_ref: null,
    public_result: null,
  };
}

async function prepareOnly(provider, f, request = f.prepareRequest) {
  const normalizedPrepare = normalizePrepareRequest(request, context(f));
  const prepared = normalizeAttemptReport(
    await provider.prepare(request),
    f.operationRegistry,
  );
  assertAttemptTransition(createdReport(normalizedPrepare), prepared, f.operationRegistry);
  return { normalizedPrepare, prepared };
}

async function prepareAndDispatch(provider, f, request = f.prepareRequest) {
  const { normalizedPrepare, prepared } = await prepareOnly(provider, f, request);
  const snapshotRequest = normalizeSnapshotRequest({
    version: 1,
    attempt_ref: prepared.attempt_ref,
    instrument_ref: normalizedPrepare.instrument_ref,
    operation_id: prepared.operation_id,
    request_digest: prepared.request_digest,
    expected_state: "prepared",
    expected_sequence: prepared.sequence,
    snapshot_plan_digest: "c".repeat(64),
  });
  const snapshot = normalizeSnapshotResponse(
    await provider.snapshot(snapshotRequest),
    snapshotRequest,
  );
  const dispatch = authorizeFor(provider)({
    descriptor: f.descriptor,
    normalized_prepare: normalizedPrepare,
    prepared,
  });
  const executeRequest = normalizeExecuteRequest({
    version: 1,
    attempt_ref: prepared.attempt_ref,
    operation_id: prepared.operation_id,
    request_digest: prepared.request_digest,
    expected_state: "prepared",
    expected_sequence: prepared.sequence,
    dispatch_journal_ref: dispatch.dispatch_journal_ref,
    dispatch_credential: dispatch.dispatch_credential,
  });
  return { normalizedPrepare, prepared, snapshot, snapshotRequest, executeRequest };
}

test("normalized operations and descriptors are closed, digest-bound, and ABI-compatible", () => {
  const f = fixture();
  const v3Descriptor = descriptorAtAbi(f, 3);
  assert.match(f.operationRegistry.registry_digest, /^[a-f0-9]{64}$/);
  assert.deepEqual(f.operationRegistry.ids(), ["instrument.inventory", "representation.write"]);
  assert.equal(Object.getOwnPropertySymbols(f.operationRegistry).length, 0);
  assert.equal(Object.getOwnPropertySymbols(f.descriptor).length, 0);
  assert.equal(Object.getOwnPropertySymbols(f.descriptor.capabilities[0]).length, 0);
  assert.equal(Object.isFrozen(f.descriptor), true);
  assert.equal(Object.isFrozen(f.descriptor.capabilities), true);
  assert.match(f.descriptor.descriptor_digest, /^[a-f0-9]{64}$/);
  assert.equal(f.descriptor.abi_version, 2);
  assert.equal(v3Descriptor.abi_version, 3);
  assert.equal(PROVIDER_ABI_VERSION, 3);
  assert.deepEqual(SUPPORTED_PROVIDER_ABI_VERSIONS, [2, 3]);
  assert.equal(assertProviderAbiCompatible(f.descriptor), true);
  assert.equal(assertProviderAbiCompatible(v3Descriptor), true);
  assert.equal(assertProviderAbiCompatible(f.descriptor, 2), true);
  assert.throws(() => assertProviderAbiCompatible(f.descriptor, 1), /incompatible/);
  assert.equal(assertProviderActiveAbiCompatible(f.descriptor), true);
  assert.equal(assertProviderActiveAbiCompatible(v3Descriptor), true);
  assert.throws(() => assertProviderBootstrapAbiCompatible(f.descriptor), /require provider ABI 3/);
  assert.equal(assertProviderBootstrapAbiCompatible(v3Descriptor), true);
  assert.throws(() => assertProviderAbiCompatible(clone(f.descriptor)), /must be normalized/);

  for (const unsupportedAbi of [1, 4]) {
    const declaration = clone(f.descriptor);
    delete declaration.capabilities_digest;
    delete declaration.descriptor_digest;
    declaration.abi_version = unsupportedAbi;
    assert.throws(
      () => defineProviderDescriptor(declaration, f.operationRegistry, f.effectRegistry),
      /abi_version must be one of 2, 3/,
    );
  }

  const forgedOperationRegistry = Object.freeze({
    ...f.operationRegistry,
    get: f.operationRegistry.get.bind(f.operationRegistry),
    has: f.operationRegistry.has.bind(f.operationRegistry),
    ids: f.operationRegistry.ids.bind(f.operationRegistry),
  });
  assert.throws(
    () => normalizeProviderDescriptor(clone(f.descriptor), forgedOperationRegistry, f.effectRegistry),
    /closed Bob normalized-operation registry/,
  );

  const emitted = clone(f.descriptor);
  emitted.transport = "serial";
  assert.throws(
    () => normalizeProviderDescriptor(emitted, f.operationRegistry, f.effectRegistry),
    /unknown fields: transport/,
  );
  const drifted = clone(f.descriptor);
  drifted.capabilities[0].operation_digest = "0".repeat(64);
  assert.throws(
    () => normalizeProviderDescriptor(drifted, f.operationRegistry, f.effectRegistry),
    /operation_digest does not match/,
  );
});

test("ABI-v3 bootstrap intent, request, and report envelopes are closed and exactly digest-bound", () => {
  const f = fixture();
  const descriptor = descriptorAtAbi(f, 3);
  const credential = Object.freeze({ fixture_credential: "must-not-serialize" });
  const flow = bootstrapRequestFixture(descriptor, { credential });
  const intentBasis = { ...flow.intent };
  delete intentBasis.bootstrap_intent_digest;
  assert.equal(flow.intent.bootstrap_intent_digest, hashCanonicalJson(intentBasis));
  assert.deepEqual(PROVIDER_BOOTSTRAP_OPERATION_IDS, [
    "instrument.inventory",
    "instrument.capabilities",
    "instrument.health",
  ]);
  assert.deepEqual(PROVIDER_BOOTSTRAP_OUTCOME_VALUES, [
    "succeeded",
    "refused_no_effect",
    "ambiguous",
  ]);

  const request = normalizeProviderBootstrapRequest(flow.input, descriptor);
  assert.equal(request.dispatch_credential, credential);
  assert.equal(Object.isFrozen(request), true);
  assert.equal(
    Object.getOwnPropertyDescriptor(request, "dispatch_credential").enumerable,
    false,
  );
  assert.equal(Object.hasOwn({ ...request }, "dispatch_credential"), false);
  assert.doesNotMatch(JSON.stringify(request), /dispatch_credential|must-not-serialize/);
  const requestBasis = { ...request };
  delete requestBasis.bootstrap_request_digest;
  assert.equal(request.bootstrap_request_digest, hashCanonicalJson(requestBasis));
  assert.equal(normalizeProviderBootstrapRequest(request, descriptor), request);

  const alternateCredential = Object.freeze({ entirely_different_opaque_projection: true });
  const alternateRequest = normalizeProviderBootstrapRequest({
    ...flow.input,
    dispatch_credential: alternateCredential,
  }, descriptor);
  assert.equal(
    alternateRequest.bootstrap_request_digest,
    request.bootstrap_request_digest,
    "opaque credential structure must not influence the canonical request digest",
  );

  const reportInput = bootstrapSuccessReportFixture(request);
  const report = normalizeProviderBootstrapReport(reportInput, request);
  assert.deepEqual(report, reportInput);
  assert.equal(Object.isFrozen(report), true);
  assert.equal(report.bootstrap_request_digest, request.bootstrap_request_digest);

  const ambiguous = normalizeProviderBootstrapReport(
    bootstrapSuccessReportFixture(request, {
      outcome: "ambiguous",
      observation_ref: null,
      observation_digest: null,
      response_digest: null,
      assurance_claims_digest: null,
      invariant_witness_digest: null,
      observed_at: "2026-07-18T00:31:00.000Z",
    }),
    request,
  );
  assert.equal(ambiguous.outcome, "ambiguous");
  assert.equal(ambiguous.response_digest, null);
});

test("ABI-v3 bootstrap normalization rejects v2, legacy unbound calls, and active-plane state", () => {
  const f = fixture();
  const descriptor = descriptorAtAbi(f, 3);
  let accessorReads = 0;
  const untrustedCall = {};
  Object.defineProperty(untrustedCall, "version", {
    enumerable: true,
    get() {
      accessorReads += 1;
      throw new Error("request must not be inspected");
    },
  });
  assert.throws(
    () => normalizeProviderBootstrapRequest(untrustedCall, f.descriptor),
    /require provider ABI 3/,
  );
  assert.equal(accessorReads, 0, "ABI-v2 rejection must precede request parsing");

  assert.throws(
    () => normalizeProviderBootstrapRequest({
      version: 1,
      provider_id: descriptor.provider_id,
      descriptor_digest: descriptor.descriptor_digest,
    }, descriptor),
    /unknown fields: descriptor_digest/,
  );

  const intentInput = bootstrapIntentFixture(descriptor);
  for (const field of PROVIDER_BOOTSTRAP_ACTIVE_PLANE_FORBIDDEN_FIELDS) {
    assert.throws(
      () => normalizeProviderBootstrapIntent({ ...intentInput, [field]: `fabricated:${field}` }, descriptor),
      new RegExp(`active-plane fields: ${field}`),
      `${field} must be explicitly forbidden from bootstrap`,
    );
  }
  assert.throws(
    () => normalizeProviderBootstrapIntent({ ...intentInput, raw_command: 1000 }, descriptor),
    /unknown fields: raw_command/,
  );
  assert.throws(
    () => normalizeProviderBootstrapIntent({
      ...intentInput,
      operation_id: "representation.write",
      operation_digest: f.operationRegistry.get("representation.write").operation_digest,
    }, descriptor),
    /operation_id must be one of instrument.inventory, instrument.capabilities, instrument.health/,
  );
  assert.throws(
    () => normalizeProviderBootstrapIntent({ ...intentInput, connection_generation: 0 }, descriptor),
    /connection_generation must be a safe integer between 1/,
  );
  assert.throws(
    () => normalizeProviderBootstrapIntent({
      ...intentInput,
      grant_expires_at: intentInput.grant_not_before,
    }, descriptor),
    /grant_expires_at must be after/,
  );
  assert.throws(
    () => normalizeProviderBootstrapIntent({
      ...intentInput,
      provider_descriptor_digest: digest("detached-provider-descriptor"),
    }, descriptor),
    /provider_descriptor_digest drifted/,
  );
});

test("ABI-v3 bootstrap credentials cannot survive cloning and lineage drift fails closed", () => {
  const f = fixture();
  const descriptor = descriptorAtAbi(f, 3);
  const flow = bootstrapRequestFixture(descriptor);
  const request = normalizeProviderBootstrapRequest(flow.input, descriptor);

  for (const clonedCredential of [
    structuredClone(flow.credential),
    JSON.parse(JSON.stringify(flow.credential)),
  ]) {
    assert.equal(Object.isFrozen(clonedCredential), false);
    assert.throws(
      () => normalizeProviderBootstrapRequest({
        ...flow.input,
        dispatch_credential: clonedCredential,
      }, descriptor),
      /dispatch_credential must be a frozen opaque credential object/,
    );
  }
  for (const clonedRequest of [
    structuredClone(request),
    JSON.parse(JSON.stringify(request)),
    { ...request },
  ]) {
    delete clonedRequest.bootstrap_request_digest;
    assert.equal(Object.hasOwn(clonedRequest, "dispatch_credential"), false);
    assert.throws(
      () => normalizeProviderBootstrapRequest(clonedRequest, descriptor),
      /missing fields: dispatch_credential/,
    );
  }

  for (const [field, replacement] of [
    ["session_nucleus_hash", digest("detached-session")],
    ["physical_scope_axis_digest", digest("detached-axis")],
    ["execution_principal_id", "principal:detached-operator"],
    ["instrument_ref", "instrument:detached-fixture"],
    ["enrollment_candidate_ref", "enrollment-candidate:detached-fixture"],
    ["provider_binary_digest", digest("detached-provider-binary")],
    ["transport_digest", digest("detached-transport")],
    ["bootstrap_manifest_digest", digest("detached-manifest")],
    ["bootstrap_invariants_digest", digest("detached-invariants")],
    ["execution_request_digest", digest("detached-execution-request")],
    ["authority_resolution_digest", digest("detached-authority")],
    ["signed_grant_digest", digest("detached-signed-grant")],
    ["replay_claim_digest", digest("detached-replay-claim")],
    ["replay_reservation_receipt_digest", digest("detached-replay-receipt")],
    ["connection_ref", "instrument-connection:detached-fixture"],
    ["connection_generation", 4],
  ]) {
    assert.throws(
      () => normalizeProviderBootstrapRequest({ ...flow.input, [field]: replacement }, descriptor),
      /bootstrap_intent_digest does not match/,
      `${field} drift must break the signed intent binding`,
    );
  }

  const otherDispatchRequest = normalizeProviderBootstrapRequest({
    ...flow.input,
    dispatch_record_digest: digest("other-bootstrap-dispatch-record"),
  }, descriptor);
  assert.notEqual(otherDispatchRequest.bootstrap_request_digest, request.bootstrap_request_digest);

  const reportInput = bootstrapSuccessReportFixture(request);
  for (const [field, replacement] of [
    ["attempt_ref", "bootstrap-attempt:detached-0001"],
    ["operation_id", "instrument.health"],
    ["bootstrap_intent_digest", digest("detached-intent")],
    ["bootstrap_request_digest", digest("detached-request")],
    ["signed_grant_digest", digest("detached-report-grant")],
    ["replay_reservation_receipt_digest", digest("detached-report-replay")],
    ["dispatch_record_digest", digest("detached-report-dispatch")],
    ["connection_generation", 4],
  ]) {
    assert.throws(
      () => normalizeProviderBootstrapReport({ ...reportInput, [field]: replacement }, request),
      new RegExp(`${field} drifted from the bootstrap request`),
    );
  }
  assert.throws(
    () => normalizeProviderBootstrapReport({ ...reportInput, lease_id: "lease:fabricated" }, request),
    /active-plane fields: lease_id/,
  );
  assert.throws(
    () => normalizeProviderBootstrapReport({ ...reportInput, response_digest: null }, request),
    /succeeded without evidence fields: response_digest/,
  );
  assert.throws(
    () => normalizeProviderBootstrapReport({
      ...reportInput,
      outcome: "refused_no_effect",
    }, request),
    /must not fabricate evidence fields/,
  );
  assert.throws(
    () => normalizeProviderBootstrapReport({
      ...reportInput,
      observed_at: request.grant_expires_at,
    }, request),
    /outside the bootstrap grant window/,
  );
  assert.throws(
    () => normalizeProviderBootstrapReport(reportInput, { ...request }),
    /request must be a normalized provider bootstrap request/,
  );
});

test("capability declarations fail closed on effect and retry laundering", () => {
  const f = fixture();
  const emitted = clone(f.descriptor);
  delete emitted.capabilities_digest;
  delete emitted.descriptor_digest;
  const effectful = emitted.capabilities.find((entry) => entry.capability_id === "mock.write");
  effectful.retry_policy = "new_attempt_after_confirmed_no_effect";
  effectful.idempotency = "read_only_idempotent";
  assert.throws(
    () => defineProviderDescriptor(emitted, f.operationRegistry, f.effectRegistry),
    /cannot declare effectful work read_only_idempotent/,
  );

  effectful.retry_policy = "never";
  effectful.idempotency = "attempt_idempotent";
  effectful.restore_policy = "best_effort";
  assert.throws(
    () => defineProviderDescriptor(emitted, f.operationRegistry, f.effectRegistry),
    /persistent effects require restore_policy required/,
  );

  effectful.restore_policy = "required";
  effectful.worst_case_effects[0].action = "observe";
  assert.throws(
    () => defineProviderDescriptor(emitted, f.operationRegistry, f.effectRegistry),
    /does not match the registered effect template/,
  );
});

test("prepare binds declared parameters, exact effects, a deadline, and a pre-dispatch journal entry", () => {
  const f = fixture();
  const prepared = normalizePrepareRequest(f.prepareRequest, context(f));
  assert.match(prepared.request_digest, /^[a-f0-9]{64}$/);
  assert.equal(prepared.requested_effects[0].subject_ref, "target:owned-fixture-0001");
  assert.equal(prepared.journal_entry_ref, "journal-entry:mock-prepare-0001");

  const unknownParameter = clone(f.prepareRequest);
  unknownParameter.parameters.raw_command = 1234;
  assert.throws(
    () => normalizePrepareRequest(unknownParameter, context(f)),
    /undeclared fields: raw_command/,
  );
  const omittedEffects = clone(f.prepareRequest);
  omittedEffects.requested_effects = [];
  assert.throws(
    () => normalizePrepareRequest(omittedEffects, context(f)),
    /cannot omit every declared effect/,
  );
  const driftedEffect = clone(f.prepareRequest);
  driftedEffect.requested_effects[0].template_id = "instrument.observe.usb.v1";
  driftedEffect.requested_effects[0].template_digest = f.effectRegistry.get("instrument.observe.usb.v1").template_digest;
  assert.throws(
    () => normalizePrepareRequest(driftedEffect, context(f)),
    /does not match the registered template|exceeds the capability/,
  );
  const rawEscape = clone(f.prepareRequest);
  rawEscape.raw_command = 2000;
  assert.throws(() => normalizePrepareRequest(rawEscape, context(f)), /unknown fields: raw_command/);
  const noJournal = clone(f.prepareRequest);
  delete noJournal.journal_entry_ref;
  assert.throws(() => normalizePrepareRequest(noJournal, context(f)), /missing fields: journal_entry_ref/);
});

test("all attempt-control calls are closed and attempt-bound", () => {
  const opaqueDispatchCredential = Object.freeze({ test_only_opaque_credential: true });
  const base = {
    version: 1,
    attempt_ref: "attempt:write-attempt-0001",
    operation_id: "representation.write",
    request_digest: "2".repeat(64),
  };
  assert.deepEqual(normalizeStatusRequest(base), base);
  const normalizedExecute = normalizeExecuteRequest({
    ...base,
    expected_state: "prepared",
    expected_sequence: 1,
    dispatch_journal_ref: "journal-entry:dispatch-0001",
    dispatch_credential: opaqueDispatchCredential,
  });
  assert.equal(normalizedExecute.expected_sequence, 1);
  assert.equal(normalizedExecute.dispatch_credential, opaqueDispatchCredential);
  assert.deepEqual(Object.keys(normalizedExecute), [
    "version",
    "attempt_ref",
    "operation_id",
    "request_digest",
    "expected_state",
    "expected_sequence",
    "dispatch_journal_ref",
    "dispatch_credential",
  ]);
  assert.equal(Object.hasOwn(normalizedExecute, "bootstrap_request_digest"), false);
  assert.throws(
    () => normalizeExecuteRequest({
      ...base,
      expected_state: "prepared",
      dispatch_journal_ref: "journal-entry:dispatch-0001",
      dispatch_credential: opaqueDispatchCredential,
    }),
    /missing fields: expected_sequence/,
  );
  assert.equal(normalizeStopRequest({
    ...base,
    expected_sequence: 2,
    stop_request_ref: "stop-request:stop-0001",
  }).expected_sequence, 2);
  assert.equal(normalizeReconcileRequest({
    ...base,
    expected_sequence: 3,
    observation_ref: "observation:reconcile-0001",
  }).observation_ref, "observation:reconcile-0001");
  assert.equal(normalizeRestoreRequest({
    ...base,
    expected_sequence: 4,
    snapshot_artifact_ref: "artifact:v1:before-0001",
    expected_workspace_state_digest: "5".repeat(64),
    restore_plan_digest: "3".repeat(64),
  }).snapshot_artifact_ref, "artifact:v1:before-0001");
  assert.throws(
    () => normalizeExecuteRequest({
      ...base,
      expected_state: "prepared",
      expected_sequence: 1,
      dispatch_journal_ref: "journal-entry:x",
      dispatch_credential: opaqueDispatchCredential,
      retry: true,
    }),
    /unknown fields: retry/,
  );
  assert.throws(
    () => normalizeExecuteRequest({
      ...base,
      expected_state: "ambiguous_effect",
      expected_sequence: 1,
      dispatch_journal_ref: "journal-entry:x",
      dispatch_credential: opaqueDispatchCredential,
    }),
    /expected_state must be prepared/,
  );
  assert.throws(
    () => normalizeExecuteRequest({
      ...base,
      expected_state: "prepared",
      expected_sequence: 1,
      dispatch_journal_ref: "journal-entry:x",
    }),
    /missing fields: dispatch_credential/,
  );
  assert.throws(
    () => normalizeExecuteRequest({
      ...base,
      expected_state: "prepared",
      expected_sequence: 1,
      dispatch_journal_ref: "journal-entry:x",
      dispatch_credential: {},
    }),
    /frozen opaque credential object/,
  );
});

test("snapshot is closed, prepared-state-bound, and exposes only an opaque artifact", () => {
  const request = normalizeSnapshotRequest({
    version: 1,
    attempt_ref: "attempt:write-attempt-0001",
    instrument_ref: "instrument:mock-owned-fixture-0001",
    operation_id: "representation.write",
    request_digest: "2".repeat(64),
    expected_state: "prepared",
    expected_sequence: 1,
    snapshot_plan_digest: "c".repeat(64),
  });
  const response = {
    version: 1,
    attempt_ref: request.attempt_ref,
    instrument_ref: request.instrument_ref,
    operation_id: request.operation_id,
    request_digest: request.request_digest,
    prepared_sequence: request.expected_sequence,
    snapshot_plan_digest: request.snapshot_plan_digest,
    snapshot_artifact_ref: "artifact:v1:workspace-before-0001",
    workspace_state_digest: "5".repeat(64),
    receipt_ref: "receipt:snapshot-0001",
  };
  const normalized = normalizeSnapshotResponse(response, request);
  assert.equal(normalized.snapshot_artifact_ref, "artifact:v1:workspace-before-0001");
  assert.equal(normalized.workspace_state_digest, "5".repeat(64));
  assert.equal(Object.isFrozen(normalized), true);

  assert.throws(
    () => normalizeSnapshotRequest({ ...request, expected_state: "dispatched" }),
    /expected_state must be prepared/,
  );
  assert.throws(
    () => normalizeSnapshotResponse({ ...response, prepared_sequence: 0 }, request),
    /prepared_sequence drifted/,
  );
  assert.throws(
    () => normalizeSnapshotResponse({ ...response, raw_snapshot: Buffer.from([1, 2]) }, request),
    /raw byte material/,
  );
  assert.throws(
    () => normalizeSnapshotResponse({ ...response, snapshot_artifact_ref: "snapshot:workspace-before-0001" }, request),
    /must use the artifact: namespace/,
  );
});

test("the deterministic provider requires a valid snapshot before restorable effects", async () => {
  const makeSnapshotRequest = (prepared, normalizedPrepare) => normalizeSnapshotRequest({
    version: 1,
    attempt_ref: prepared.attempt_ref,
    instrument_ref: normalizedPrepare.instrument_ref,
    operation_id: prepared.operation_id,
    request_digest: prepared.request_digest,
    expected_state: "prepared",
    expected_sequence: prepared.sequence,
    snapshot_plan_digest: "c".repeat(64),
  });
  const makeExecuteRequest = (prepared, dispatch) => normalizeExecuteRequest({
    version: 1,
    attempt_ref: prepared.attempt_ref,
    operation_id: prepared.operation_id,
    request_digest: prepared.request_digest,
    expected_state: "prepared",
    expected_sequence: prepared.sequence,
    dispatch_journal_ref: dispatch.dispatch_journal_ref,
    dispatch_credential: dispatch.dispatch_credential,
  });

  const f = fixture();
  const provider = providerFor(f);
  const gate = await prepareOnly(provider, f);
  const untrustedDispatch = Object.freeze({
    dispatch_journal_ref: "journal-entry:snapshot-gate-dispatch-0001",
    dispatch_credential: Object.freeze({ test_only_untrusted_credential: true }),
  });
  await assert.rejects(
    () => provider.execute(makeExecuteRequest(gate.prepared, untrustedDispatch)),
    (error) => error.code === "provider_snapshot_missing" && error.effect_state === "not_dispatched",
  );
  const snapshotRequest = makeSnapshotRequest(gate.prepared, gate.normalizedPrepare);
  const snapshot = normalizeSnapshotResponse(await provider.snapshot(snapshotRequest), snapshotRequest);
  assert.equal(snapshot.snapshot_artifact_ref, "artifact:v1:mock-snapshot-0001");
  const dispatch = authorizeFor(provider)({
    descriptor: f.descriptor,
    normalized_prepare: gate.normalizedPrepare,
    prepared: gate.prepared,
  });
  assert.equal(
    normalizeAttemptReport(
      await provider.execute(makeExecuteRequest(gate.prepared, dispatch)),
      f.operationRegistry,
    ).state,
    "dispatched",
  );

  for (const outcome of ["corruption", "stale_state"]) {
    const local = fixture();
    const scripted = providerFor(local, [{ method: "snapshot", outcome }]);
    const preparedFlow = await prepareOnly(scripted, local);
    const request = makeSnapshotRequest(preparedFlow.prepared, preparedFlow.normalizedPrepare);
    const response = await scripted.snapshot(request);
    assert.throws(
      () => normalizeSnapshotResponse(response, request),
      outcome === "corruption" ? /unknown fields: diagnostic_ref/ : /prepared_sequence drifted/,
    );
  }
  for (const outcome of ["timeout", "disconnect"]) {
    const local = fixture();
    const scripted = providerFor(local, [{ method: "snapshot", outcome }]);
    const preparedFlow = await prepareOnly(scripted, local);
    const request = makeSnapshotRequest(preparedFlow.prepared, preparedFlow.normalizedPrepare);
    await assert.rejects(
      () => scripted.snapshot(request),
      (error) => error.code === `provider_${outcome}` && error.effect_state === "not_dispatched",
    );
  }
});

test("public results permit only bounded summaries, counts, and opaque artifact references", () => {
  const f = fixture();
  const operation = f.operationRegistry.get("representation.write");
  const safe = normalizePublicResult({
    version: 1,
    outcome: "succeeded",
    summary_code: "operation_succeeded",
    artifact_refs: ["artifact:v1:mock-result-0001"],
    metric_counts: { observation_count: 1 },
  }, operation);
  assert.deepEqual(safe.artifact_refs, ["artifact:v1:mock-result-0001"]);
  assert.equal(Object.isFrozen(safe), true);

  for (const bytes of [Buffer.from([1, 2]), new Uint8Array([1, 2]), new DataView(new ArrayBuffer(2))]) {
    assert.throws(
      () => normalizePublicResult({
        version: 1,
        outcome: "succeeded",
        summary_code: "operation_succeeded",
        artifact_refs: [],
        metric_counts: {},
        payload: bytes,
      }, operation),
      /raw byte material/,
    );
  }
  assert.throws(() => assertNoPublicByteMaterial({ nested: [Buffer.from([1])] }), /raw byte material/);
  let getterCalls = 0;
  const accessor = {};
  Object.defineProperty(accessor, "nested", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return Buffer.from([1]);
    },
  });
  assert.throws(
    () => assertNoPublicByteMaterial(accessor),
    /nested must be an enumerable data field/u,
  );
  assert.equal(getterCalls, 0);
  assert.throws(
    () => assertNoPublicByteMaterial({ nested: new Array(1) }),
    /dense array without extra fields/u,
  );
  assert.throws(
    () => assertNoPublicByteMaterial({ nested: Array.from({ length: 4_097 }, () => ({})) }),
    /bounded public result graph/u,
  );
  assert.throws(() => normalizePublicResult({
    version: 1,
    outcome: "succeeded",
    summary_code: "operation_succeeded",
    artifact_refs: [],
    metric_counts: { secret_byte_count: 16 },
  }, operation), /not safe public metadata/);
  assert.throws(() => normalizePublicResult({
    version: 1,
    outcome: "succeeded",
    summary_code: "provider_invented_code",
    artifact_refs: [],
    metric_counts: {},
  }, operation), /not declared by operation/);
});

test("the attempt state machine rejects skipped, stale, and cross-attempt transitions", () => {
  const f = fixture();
  const preparedRequest = normalizePrepareRequest(f.prepareRequest, context(f));
  const created = createdReport(preparedRequest);
  const prepared = {
    ...created,
    state: "prepared",
    sequence: 1,
    receipt_ref: "receipt:prepared-0001",
  };
  assert.equal(assertAttemptTransition(created, prepared, f.operationRegistry).state, "prepared");
  const acknowledged = {
    ...prepared,
    state: "acknowledged",
    sequence: 2,
    effect_disposition: "confirmed_effect",
    receipt_ref: "receipt:acknowledged-0002",
    public_result: {
      version: 1,
      outcome: "succeeded",
      summary_code: "operation_succeeded",
      artifact_refs: [],
      metric_counts: {},
    },
  };
  assert.throws(
    () => assertAttemptTransition(prepared, acknowledged, f.operationRegistry),
    /prepared -> acknowledged is not allowed/,
  );
  const dispatched = {
    ...prepared,
    state: "dispatched",
    sequence: 2,
    effect_disposition: "ambiguous",
    receipt_ref: "receipt:dispatched-0002",
  };
  assert.equal(assertAttemptTransition(prepared, dispatched, f.operationRegistry).state, "dispatched");
  const stale = { ...dispatched, state: "ambiguous_effect" };
  assert.throws(() => assertAttemptTransition(dispatched, stale, f.operationRegistry), /increment by exactly one/);
  const crossAttempt = { ...dispatched, state: "ambiguous_effect", sequence: 3, attempt_ref: "attempt:other-0001" };
  assert.throws(() => assertAttemptTransition(dispatched, crossAttempt, f.operationRegistry), /changed attempt_ref/);
  assert.equal(isTerminalAttemptState("unknown_effect"), true);
  assert.equal(isTerminalAttemptState("ambiguous_effect"), false);
});

test("automatic retry requires a new attempt and confirmed no-effect read-only semantics", () => {
  const f = fixture();
  const normalized = normalizePrepareRequest(f.inventoryPrepareRequest, context(f));
  const operation = f.operationRegistry.get("instrument.inventory");
  const refused = normalizeAttemptReport({
    version: 1,
    attempt_ref: normalized.attempt_ref,
    operation_id: normalized.operation_id,
    request_digest: normalized.request_digest,
    state: "refused",
    sequence: 1,
    effect_disposition: "confirmed_no_effect",
    receipt_ref: "receipt:refused-0001",
    public_result: {
      version: 1,
      outcome: "refused",
      summary_code: "operation_refused",
      artifact_refs: [],
      metric_counts: {},
    },
  }, f.operationRegistry);
  const readOnly = f.descriptor.capabilities.find((entry) => entry.capability_id === "mock.inventory");
  assert.deepEqual(assertAutomaticRetryAllowed({
    prior_report: refused,
    capability: readOnly,
    new_attempt_ref: "attempt:inventory-attempt-0002",
  }, f.operationRegistry), {
    prior_attempt_ref: "attempt:inventory-attempt-0001",
    new_attempt_ref: "attempt:inventory-attempt-0002",
    retry_basis: "confirmed_no_effect",
  });
  assert.throws(() => assertAutomaticRetryAllowed({
    prior_report: refused,
    capability: readOnly,
    new_attempt_ref: refused.attempt_ref,
  }, f.operationRegistry), /must differ/);
  assert.throws(() => assertAutomaticRetryAllowed({
    prior_report: refused,
    capability: clone(readOnly),
    new_attempt_ref: "attempt:inventory-attempt-spoofed",
  }, f.operationRegistry), /capability must be normalized/);

  const ambiguous = {
    ...refused,
    state: "ambiguous_effect",
    effect_disposition: "ambiguous",
    receipt_ref: "receipt:ambiguous-0001",
    public_result: null,
  };
  assert.throws(() => assertAutomaticRetryAllowed({
    prior_report: ambiguous,
    capability: readOnly,
    new_attempt_ref: "attempt:inventory-attempt-0003",
  }, f.operationRegistry), /forbidden from an ambiguous or unknown effect state/);
  const effectful = f.descriptor.capabilities.find((entry) => entry.capability_id === "mock.write");
  const normalizedWrite = normalizePrepareRequest(f.prepareRequest, context(f));
  const effectfulRefusal = {
    ...refused,
    attempt_ref: normalizedWrite.attempt_ref,
    operation_id: normalizedWrite.operation_id,
    request_digest: normalizedWrite.request_digest,
  };
  assert.equal(operation.operation_id, "instrument.inventory");
  assert.throws(() => assertAutomaticRetryAllowed({
    prior_report: refused,
    capability: effectful,
    new_attempt_ref: "attempt:inventory-attempt-mismatched",
  }, f.operationRegistry), /capability does not match the prior operation/);
  assert.throws(() => assertAutomaticRetryAllowed({
    prior_report: effectfulRefusal,
    capability: effectful,
    new_attempt_ref: "attempt:inventory-attempt-0004",
  }, f.operationRegistry), /forbidden by capability retry_policy/);
});

test("the deterministic provider passes the complete success conformance path", async () => {
  const f = fixture();
  const provider = providerFor(f);
  assert.equal(assertProviderInterface(provider), provider);
  const result = await runProviderConformance({
    authorizeDispatch: authorizeFor(provider),
    provider,
    operationRegistry: f.operationRegistry,
    effectRegistry: f.effectRegistry,
    prepareRequest: f.prepareRequest,
  });
  assert.equal(result.terminal.state, "restored");
  assert.equal(result.inventory.instrument_ref, "instrument:mock-owned-fixture-0001");
  assert.equal(result.health.status, "healthy");
  assert.equal(result.capabilities.capabilities_digest, f.descriptor.capabilities_digest);
  assert.equal(result.snapshot.snapshot_artifact_ref, "artifact:v1:mock-snapshot-0001");
  assert.equal(result.snapshot.workspace_state_digest, "5".repeat(64));
});

test("the provider deterministically models refusal without dispatch", async () => {
  const f = fixture();
  const provider = providerFor(f, [{ method: "prepare", outcome: "refusal" }]);
  const result = await runProviderConformance({
    authorizeDispatch: authorizeFor(provider),
    provider,
    operationRegistry: f.operationRegistry,
    effectRegistry: f.effectRegistry,
    prepareRequest: f.prepareRequest,
  });
  assert.equal(result.terminal.state, "refused");
  assert.equal(result.terminal.effect_disposition, "confirmed_no_effect");
});

test("timeout and disconnect after dispatch become ambiguous and cannot be replayed", async () => {
  for (const outcome of ["timeout", "disconnect"]) {
    const f = fixture();
    const provider = providerFor(f, [{ method: "execute", outcome }]);
    const { prepared, executeRequest } = await prepareAndDispatch(provider, f);
    await assert.rejects(
      () => provider.execute(executeRequest),
      (error) => error.code === `provider_${outcome}` && error.effect_state === "ambiguous_effect",
    );
    const status = normalizeAttemptReport(await provider.status({
      version: 1,
      attempt_ref: prepared.attempt_ref,
      operation_id: prepared.operation_id,
      request_digest: prepared.request_digest,
    }), f.operationRegistry);
    assert.equal(status.state, "ambiguous_effect");
    await assert.rejects(() => provider.execute(executeRequest), /provider_execute_replay/);
    const effectful = f.descriptor.capabilities.find((entry) => entry.capability_id === "mock.write");
    assert.throws(() => assertAutomaticRetryAllowed({
      prior_report: status,
      capability: effectful,
      new_attempt_ref: `attempt:${outcome}-retry-0001`,
    }, f.operationRegistry), /ambiguous or unknown effect state/);
  }
});

test("ambiguous attempts reconcile explicitly to confirmed no effect", async () => {
  const f = fixture();
  const provider = providerFor(f, [{ method: "execute", outcome: "timeout" }]);
  const { prepared, executeRequest } = await prepareAndDispatch(provider, f);
  await assert.rejects(() => provider.execute(executeRequest), /provider_timeout/);
  const ambiguous = normalizeAttemptReport(await provider.status({
    version: 1,
    attempt_ref: prepared.attempt_ref,
    operation_id: prepared.operation_id,
    request_digest: prepared.request_digest,
  }), f.operationRegistry);
  const reconcileRequest = normalizeReconcileRequest({
    version: 1,
    attempt_ref: ambiguous.attempt_ref,
    operation_id: ambiguous.operation_id,
    request_digest: ambiguous.request_digest,
    expected_sequence: ambiguous.sequence,
    observation_ref: "observation:mock-reconciliation-0001",
  });
  const reconciled = normalizeAttemptReport(
    await provider.reconcile(reconcileRequest),
    f.operationRegistry,
  );
  assertAttemptTransition(ambiguous, reconciled, f.operationRegistry);
  assert.equal(reconciled.state, "reconciled_no_effect");
  assert.equal(reconciled.effect_disposition, "confirmed_no_effect");
});

test("schema-corrupt provider output and stale status are rejected by the conformance boundary", async () => {
  const f = fixture();
  const corruptProvider = providerFor(f, [{ method: "execute", outcome: "corruption" }]);
  const corruptFlow = await prepareAndDispatch(corruptProvider, f);
  const corruptResponse = await corruptProvider.execute(corruptFlow.executeRequest);
  assert.throws(
    () => normalizeAttemptReport(corruptResponse, f.operationRegistry),
    /unknown fields: diagnostic_ref/,
  );

  const staleProvider = providerFor(f, [{ method: "status", outcome: "stale_state" }]);
  const staleFlow = await prepareAndDispatch(staleProvider, f);
  const dispatched = normalizeAttemptReport(
    await staleProvider.execute(staleFlow.executeRequest),
    f.operationRegistry,
  );
  const stale = normalizeAttemptReport(await staleProvider.status({
    version: 1,
    attempt_ref: dispatched.attempt_ref,
    operation_id: dispatched.operation_id,
    request_digest: dispatched.request_digest,
  }), f.operationRegistry);
  assert.throws(
    () => assertAttemptTransition(dispatched, stale, f.operationRegistry),
    /increment by exactly one|is not allowed/,
  );
});

test("stop is operation-bound and restoration remains available afterward", async () => {
  const f = fixture();
  const provider = providerFor(f);
  const flow = await prepareAndDispatch(provider, f);
  const dispatched = normalizeAttemptReport(await provider.execute(flow.executeRequest), f.operationRegistry);
  const stopRequest = normalizeStopRequest({
    version: 1,
    attempt_ref: dispatched.attempt_ref,
    operation_id: dispatched.operation_id,
    request_digest: dispatched.request_digest,
    expected_sequence: dispatched.sequence,
    stop_request_ref: "stop-request:mock-stop-0001",
  });
  const stopping = normalizeAttemptReport(await provider.stop(stopRequest), f.operationRegistry);
  assertAttemptTransition(dispatched, stopping, f.operationRegistry);
  const stopped = normalizeAttemptReport(await provider.status({
    version: 1,
    attempt_ref: stopping.attempt_ref,
    operation_id: stopping.operation_id,
    request_digest: stopping.request_digest,
  }), f.operationRegistry);
  assertAttemptTransition(stopping, stopped, f.operationRegistry);
  assert.equal(stopped.state, "stopped");
  const restored = normalizeAttemptReport(await provider.restore({
    version: 1,
    attempt_ref: stopped.attempt_ref,
    operation_id: stopped.operation_id,
    request_digest: stopped.request_digest,
    expected_sequence: stopped.sequence,
    snapshot_artifact_ref: flow.snapshot.snapshot_artifact_ref,
    expected_workspace_state_digest: flow.snapshot.workspace_state_digest,
    restore_plan_digest: "4".repeat(64),
  }), f.operationRegistry);
  assertAttemptTransition(stopped, restored, f.operationRegistry);
  assert.equal(restored.state, "restored");
});

test("restore failure terminates in explicit quarantine", async () => {
  const f = fixture();
  const provider = providerFor(f, [{ method: "restore", outcome: "restore_failure" }]);
  const result = await runProviderConformance({
    authorizeDispatch: authorizeFor(provider),
    provider,
    operationRegistry: f.operationRegistry,
    effectRegistry: f.effectRegistry,
    prepareRequest: f.prepareRequest,
  });
  assert.equal(result.terminal.state, "quarantined");
  assert.equal(result.terminal.public_result.outcome, "failed");
  assert.equal(isTerminalAttemptState(result.terminal.state), true);
});

test("descriptor, inventory, capability, and health output drift fails closed", async () => {
  const f = fixture();
  const provider = providerFor(f);
  const descriptor = normalizeProviderDescriptor(
    await provider.describe(),
    f.operationRegistry,
    f.effectRegistry,
  );
  const request = {
    version: 1,
    provider_id: descriptor.provider_id,
    descriptor_digest: descriptor.descriptor_digest,
  };
  const caps = await provider.capabilities(request);
  assert.equal(normalizeCapabilitiesResponse(caps, descriptor).capabilities.length, 2);
  const inventory = await provider.inventory(request);
  assert.equal(normalizeInventoryResponse(inventory, descriptor).inventory_ref, "inventory:mock-inventory-0001");
  const health = await provider.health(request);
  assert.equal(normalizeHealthResponse(health, descriptor).status, "healthy");

  const driftedCaps = clone(caps);
  driftedCaps.capabilities_digest = "0".repeat(64);
  assert.throws(() => normalizeCapabilitiesResponse(driftedCaps, descriptor), /capabilities_digest drifted/);
  const rawInventory = { ...inventory, device_bytes: Buffer.from([1]) };
  assert.throws(() => normalizeInventoryResponse(rawInventory, descriptor), /unknown fields: device_bytes/);
  const rawHealth = { ...health, message: "firmware response" };
  assert.throws(() => normalizeHealthResponse(rawHealth, descriptor), /unknown fields: message/);
});

test("provider interface conformance requires every lifecycle method", () => {
  const f = fixture();
  assertProviderInterface(providerFor(f));
  assert.throws(
    () => assertProviderInterface({ describe() {}, prepare() {} }),
    /missing ABI methods: inventory, capabilities, snapshot, execute, status, stop, reconcile, restore, health/,
  );
});
