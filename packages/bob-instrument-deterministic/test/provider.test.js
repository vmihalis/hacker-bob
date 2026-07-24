"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  PROVIDER_BOOTSTRAP_REPORT_FIELDS,
  assertAttemptTransition,
  assertNoPublicByteMaterial,
  defineProviderDescriptor,
  normalizeAttemptReport,
  normalizeExecuteRequest,
  normalizeHealthResponse,
  normalizePrepareRequest,
  normalizeProviderBootstrapIntent,
  normalizeProviderBootstrapReport,
  normalizeProviderBootstrapRequest,
  normalizeReconcileRequest,
  normalizeSnapshotRequest,
  normalizeSnapshotResponse,
} = require("../../../mcp/lib/instrument-provider-contract.js");
const {
  DeterministicInstrumentProvider,
  SCRIPT_METHODS,
  SCRIPT_OUTCOMES,
  createDeterministicProviderStateStore,
  defineDeterministicFaultScript,
  runProviderConformance,
} = require("../lib/provider.js");
const {
  createDeterministicActiveOnlyProviderFixture,
  createDeterministicProviderFixture,
} = require("../lib/fixtures.js");
const {
  createOrthogonalMultiInstrumentProviderFixture,
} = require("../lib/orthogonal-fixture.js");
const {
  createDurableProviderDispatchHarness,
} = require("../../../test/helpers/durable-provider-dispatch.js");
const {
  createDurableInstrumentBootstrapStore,
  createInstrumentBootstrapBrokerCustodyBinding,
  createInstrumentBootstrapBrokerPort,
  createInstrumentBootstrapProviderRedemptionPort,
  readInstrumentBootstrapCustodyProjection,
} = require("../../../mcp/lib/instrument-bootstrap-store.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/lib/verification-contracts.js");

const PROVIDER_HARNESSES = new WeakMap();
const PROVIDER_BOOTSTRAP_HARNESSES = new WeakMap();
const OPEN_HARNESSES = new Set();
test.after(() => {
  for (const harness of OPEN_HARNESSES) harness.close();
  OPEN_HARNESSES.clear();
});

function digest(label, sequence = 0) {
  return hashCanonicalJson({
    domain: "hacker-bob/deterministic-bootstrap-test-fixture/v1",
    label,
    sequence,
  });
}

function createBootstrapHarness(fixture) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-deterministic-bootstrap-"));
  fs.chmodSync(root, 0o700);
  let anchor = null;
  const stateAnchor = {
    readState() {
      return anchor == null ? null : structuredClone(anchor);
    },
    compareAndSet(input) {
      const expected = anchor == null ? null : {
        generation: anchor.generation,
        head_event_digest: anchor.head_event_digest,
      };
      const supplied = input.expected_generation == null ? null : {
        generation: input.expected_generation,
        head_event_digest: input.expected_head_event_digest,
      };
      if (JSON.stringify(supplied) !== JSON.stringify(expected)) return false;
      anchor = structuredClone(input.next_state);
      return true;
    },
  };
  const sessionNucleusHash = digest("session-nucleus");
  const store = createDurableInstrumentBootstrapStore({
    root,
    runtimeId: "physical-runtime:v1:deterministic-bootstrap-0001",
    sessionNucleusHash,
    masterKey: Buffer.alloc(32, 0x5a),
    stateAnchor,
    now: () => new Date("2026-07-18T00:10:00.000Z"),
  });
  const broker = createInstrumentBootstrapBrokerPort(store);
  const enrollment = {
    provider_id: fixture.descriptor.provider_id,
    provider_descriptor_digest: fixture.descriptor.descriptor_digest,
    provider_binary_digest: digest("provider-binary"),
    transport_digest: digest("transport"),
    bootstrap_manifest_digest: digest("manifest"),
    bootstrap_invariants_digest: digest("invariants"),
    execution_principal_id: "principal:deterministic-bootstrap-worker",
    instrument_ref: fixture.prepareRequest.instrument_ref,
    enrollment_candidate_ref: "enrollment-candidate:deterministic-mock-0001",
    connection_ref: "instrument-connection:deterministic-mock-0001",
  };
  const connection = {
    connected: true,
    generation: 7,
    read_count: 0,
    disconnect_on_read: null,
    drift_on_read: null,
  };
  let authorityEnabled = true;
  const custodyBinding = createInstrumentBootstrapBrokerCustodyBinding(broker, {
    custody_authority: Object.freeze(Object.create(null)),
    read_connection_generation() {
      connection.read_count += 1;
      return {
        connection_ref: enrollment.connection_ref,
        connection_generation: connection.drift_on_read === connection.read_count
          ? connection.generation + 1
          : connection.generation,
        connected: connection.disconnect_on_read === connection.read_count
          ? false
          : connection.connected,
      };
    },
  });
  const providerEnrollment = {
    provider_id: enrollment.provider_id,
    provider_descriptor_digest: enrollment.provider_descriptor_digest,
    provider_binary_digest: enrollment.provider_binary_digest,
    transport_digest: enrollment.transport_digest,
    bootstrap_manifest_digest: enrollment.bootstrap_manifest_digest,
    bootstrap_invariants_digest: enrollment.bootstrap_invariants_digest,
    execution_principal_id: enrollment.execution_principal_id,
    instrument_ref: enrollment.instrument_ref,
    enrollment_candidate_ref: enrollment.enrollment_candidate_ref,
  };
  const port = createInstrumentBootstrapProviderRedemptionPort(store, {
    ...providerEnrollment,
    custody_binding: custodyBinding,
    revalidateBootstrapAuthority() {
      return authorityEnabled;
    },
  });
  let sequence = 0;
  function authorize({ descriptor, operation_id: operationId, operation_digest: operationDigest }) {
    sequence += 1;
    const intentInput = {
      version: 1,
      call_kind: "bootstrap",
      attempt_ref: `bootstrap-attempt:deterministic-${String(sequence).padStart(4, "0")}`,
      session_nucleus_hash: sessionNucleusHash,
      physical_scope_axis_digest: digest("physical-scope-axis"),
      execution_principal_id: enrollment.execution_principal_id,
      instrument_ref: enrollment.instrument_ref,
      enrollment_candidate_ref: enrollment.enrollment_candidate_ref,
      provider_id: descriptor.provider_id,
      provider_descriptor_digest: descriptor.descriptor_digest,
      provider_binary_digest: enrollment.provider_binary_digest,
      transport_digest: enrollment.transport_digest,
      bootstrap_manifest_digest: enrollment.bootstrap_manifest_digest,
      bootstrap_invariants_digest: enrollment.bootstrap_invariants_digest,
      operation_id: operationId,
      operation_digest: operationDigest,
      execution_request_digest: digest("execution-request", sequence),
      authority_resolution_digest: digest("authority-resolution", sequence),
      signed_grant_digest: digest("signed-grant", sequence),
      replay_claim_digest: digest("replay-claim", sequence),
      replay_reservation_receipt_digest: digest("replay-receipt", sequence),
      connection_ref: enrollment.connection_ref,
      connection_generation: connection.generation,
      grant_not_before: "2026-07-18T00:00:00.000Z",
      grant_expires_at: "2026-07-18T01:00:00.000Z",
    };
    const intent = normalizeProviderBootstrapIntent(intentInput, descriptor);
    const custodyProjection = readInstrumentBootstrapCustodyProjection(custodyBinding);
    const precommit = broker.precommitAttempt({
      provider_abi_version: 3,
      ...intentInput,
      bootstrap_intent_digest: intent.bootstrap_intent_digest,
      bootstrap_grant_projection_digest: digest("grant-projection", sequence),
      custody_binding_digest: custodyProjection.custody_binding_digest,
    }, custodyProjection);
    const dispatch = broker.commitDispatch({
      version: 1,
      attempt_ref: precommit.attempt_ref,
      expected_durable_attempt_binding_digest: precommit.durable_attempt_binding_digest,
    }, custodyProjection);
    const request = normalizeProviderBootstrapRequest({
      ...intent,
      dispatch_record_digest: dispatch.dispatch.dispatch_record_digest,
      dispatch_credential: dispatch.dispatch_credential,
    }, descriptor);
    connection.read_count = 0;
    return request;
  }
  return {
    authorize,
    broker,
    close() {
      store.close();
      fs.rmSync(root, { recursive: true, force: true });
    },
    connection,
    enrollment,
    port,
    setAuthorityEnabled(value) {
      authorityEnabled = value;
    },
    store,
  };
}

function providerFor(fixture, options = {}) {
  const harness = createDurableProviderDispatchHarness({
    descriptor: fixture.descriptor,
    instrumentRefs: [fixture.prepareRequest.instrument_ref],
  });
  OPEN_HARNESSES.add(harness);
  const bootstrapHarness = fixture.descriptor.abi_version === 3
    ? createBootstrapHarness(fixture)
    : null;
  if (bootstrapHarness) OPEN_HARNESSES.add(bootstrapHarness);
  const provider = new DeterministicInstrumentProvider({
    descriptor: fixture.descriptor,
    operationRegistry: fixture.operationRegistry,
    effectRegistry: fixture.effectRegistry,
    providerDispatchPort: harness.port,
    bootstrapProviderPort: bootstrapHarness == null ? null : bootstrapHarness.port,
    ...options,
  });
  PROVIDER_HARNESSES.set(provider, harness);
  if (bootstrapHarness) PROVIDER_BOOTSTRAP_HARNESSES.set(provider, bootstrapHarness);
  return provider;
}

function authorizeFor(provider) {
  const harness = PROVIDER_HARNESSES.get(provider);
  if (!harness) throw new Error("deterministic provider test harness is unavailable");
  return harness.authorize;
}

function authorizeBootstrapFor(provider) {
  const harness = PROVIDER_BOOTSTRAP_HARNESSES.get(provider);
  if (!harness) throw new Error("deterministic provider bootstrap harness is unavailable");
  return harness.authorize;
}

function bootstrapRequestFor(provider, fixture, method) {
  const operationId = `instrument.${method}`;
  const capability = fixture.descriptor.capabilities.find(
    (entry) => entry.operation_id === operationId,
  );
  if (!capability) throw new Error(`fixture lacks bootstrap operation ${operationId}`);
  return authorizeBootstrapFor(provider)({
    descriptor: fixture.descriptor,
    method,
    operation_id: operationId,
    operation_digest: capability.operation_digest,
  });
}

function context(fixture) {
  return {
    descriptor: fixture.descriptor,
    operation_registry: fixture.operationRegistry,
    effect_registry: fixture.effectRegistry,
  };
}

async function prepareSnapshot(provider, fixture) {
  const request = fixture.prepareRequest;
  const normalizedPrepare = normalizePrepareRequest(request, context(fixture));
  const prepared = normalizeAttemptReport(
    await provider.prepare(request),
    fixture.operationRegistry,
  );
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
    descriptor: fixture.descriptor,
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
  return { executeRequest, normalizedPrepare, prepared, snapshot };
}

function statusRequest(report) {
  return {
    version: 1,
    attempt_ref: report.attempt_ref,
    operation_id: report.operation_id,
    request_digest: report.request_digest,
  };
}

test("package is broker-independent, hardware-free, bounded, and registry-driven", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "lib", "provider.js"), "utf8");
  assert.doesNotMatch(source, /bob-instrument-broker|instrument-broker/);
  assert.doesNotMatch(
    source,
    /require\(["'](?:node:)?(?:fs|child_process|net|dgram|serialport|usb|bluetooth|worker_threads)["']\)/,
  );
  assert.doesNotMatch(source, /Buffer\.|Uint8Array|ArrayBuffer|raw[_-]?(?:bytes|payload|frame)/i);
  assert.ok(SCRIPT_METHODS.includes("reconcile"));
  for (const outcome of [
    "confirmed",
    "refused",
    "ambiguous",
    "unavailable",
    "crash_after_dispatch",
  ]) {
    assert.ok(SCRIPT_OUTCOMES.includes(outcome));
  }

  const fixture = createDeterministicProviderFixture();
  assert.deepEqual(fixture.operationRegistry.ids(), [
    "instrument.capabilities",
    "instrument.health",
    "instrument.inventory",
    "representation.write",
  ]);
  assert.equal(fixture.descriptor.abi_version, 3);
  assert.equal(fixture.descriptor.operation_registry_digest, fixture.operationRegistry.registry_digest);
  assert.equal(Object.isFrozen(fixture.descriptor), true);
  assert.equal(Object.isFrozen(fixture.prepareRequest), true);
});

test("orthogonal authoring export remains inert, non-RFID, and two-instrument", () => {
  const fixture = createOrthogonalMultiInstrumentProviderFixture();
  assert.equal(fixture.descriptor.provider_id, "deterministic_orthogonal_gpio_optical");
  assert.deepEqual(fixture.operationRegistry.ids(), [
    "environment.actuate",
    "environment.observe",
    "instrument.capabilities",
    "instrument.health",
    "instrument.inventory",
  ]);
  assert.deepEqual(
    fixture.resourceBundle.requirements
      .filter((entry) => entry.resource_kind === "instrument")
      .map((entry) => entry.candidate_resource_refs[0])
      .sort(),
    [
      "instrument:orthogonal-gpio-actuator-0001",
      "instrument:orthogonal-optical-sensor-0001",
    ],
  );
  const source = fs.readFileSync(path.join(__dirname, "..", "lib", "orthogonal-fixture.js"), "utf8");
  assert.doesNotMatch(
    source,
    /require\(["'](?:node:)?(?:fs|child_process|net|dgram|serialport|usb|bluetooth|worker_threads)["']\)/u,
  );
  assert.doesNotMatch(source, /chameleon|mifare|credential\.present/i);
});

test("default deterministic provider passes the complete ABI conformance path", async () => {
  const fixture = createDeterministicProviderFixture();
  const provider = providerFor(fixture);
  const result = await runProviderConformance({
    authorizeDispatch: authorizeFor(provider),
    authorizeBootstrap: authorizeBootstrapFor(provider),
    provider,
    operationRegistry: fixture.operationRegistry,
    effectRegistry: fixture.effectRegistry,
    prepareRequest: fixture.prepareRequest,
  });
  assert.equal(result.terminal.state, "restored");
  assert.deepEqual(result.terminal.public_result.artifact_refs, []);
  assert.equal(result.snapshot.snapshot_artifact_ref, "artifact:v1:mock-snapshot-0001");
  assert.equal(result.inventory.outcome, "succeeded");
  assert.equal(result.capabilities.outcome, "succeeded");
  assert.equal(result.health.outcome, "succeeded");
  assertNoPublicByteMaterial(
    JSON.parse(JSON.stringify(result)),
    "conformance_result_projection",
  );
});

test("explicit ABI-v2 active-only fixture preserves legacy conformance", async () => {
  const fixture = createDeterministicActiveOnlyProviderFixture();
  const provider = providerFor(fixture);
  assert.equal(fixture.descriptor.abi_version, 2);
  assert.deepEqual(fixture.operationRegistry.ids(), [
    "instrument.inventory",
    "representation.write",
  ]);
  const result = await runProviderConformance({
    authorizeDispatch: authorizeFor(provider),
    provider,
    operationRegistry: fixture.operationRegistry,
    effectRegistry: fixture.effectRegistry,
    prepareRequest: fixture.prepareRequest,
  });
  assert.equal(result.inventory.inventory_ref, "inventory:mock-inventory-0001");
  assert.equal(result.health.status, "healthy");
  assert.equal(result.terminal.state, "restored");
});

test("ABI-v3 bootstrap redeems durable one-use authority and returns only normalized lineage", async () => {
  const fixture = createDeterministicProviderFixture();
  const provider = providerFor(fixture);
  const harness = PROVIDER_BOOTSTRAP_HARNESSES.get(provider);
  const request = bootstrapRequestFor(provider, fixture, "inventory");

  assert.equal(Object.prototype.propertyIsEnumerable.call(request, "dispatch_credential"), false);
  assert.equal(Object.keys(request).includes("durable_attempt_binding_digest"), false);
  assert.equal(Object.keys(request).includes("bootstrap_grant_projection_digest"), false);
  const report = normalizeProviderBootstrapReport(
    await provider.inventory(request),
    request,
  );
  assert.deepEqual(Object.keys(report).sort(), [...PROVIDER_BOOTSTRAP_REPORT_FIELDS].sort());
  assert.equal(report.outcome, "succeeded");
  assert.equal(report.connection_generation, request.connection_generation);
  assert.equal(harness.store.readAttempt(request.attempt_ref).state, "succeeded");
  assertNoPublicByteMaterial(report, "deterministic_v3_inventory_report");

  await assert.rejects(
    () => provider.inventory(request),
    /dispatch credential was not issued by this live durable store/,
  );
  await assert.rejects(
    () => provider.inventory({
      version: 1,
      provider_id: fixture.descriptor.provider_id,
      descriptor_digest: fixture.descriptor.descriptor_digest,
    }),
    /bootstrap|missing fields/,
  );
});

test("ABI-v3 connected generation is exact at redemption and immediately before observation", async () => {
  {
    const fixture = createDeterministicProviderFixture();
    const provider = providerFor(fixture);
    const harness = PROVIDER_BOOTSTRAP_HARNESSES.get(provider);
    const request = bootstrapRequestFor(provider, fixture, "health");
    harness.connection.generation += 1;
    await assert.rejects(
      () => provider.health(request),
      /connection_generation custody drift/,
    );
    assert.equal(harness.store.readAttempt(request.attempt_ref).state, "dispatch_committed");
  }

  {
    const fixture = createDeterministicProviderFixture();
    const provider = providerFor(fixture);
    const harness = PROVIDER_BOOTSTRAP_HARNESSES.get(provider);
    const request = bootstrapRequestFor(provider, fixture, "health");
    harness.connection.drift_on_read = 2;
    const report = normalizeProviderBootstrapReport(
      await provider.health(request),
      request,
    );
    assert.equal(report.outcome, "refused_no_effect");
    assert.equal(report.connection_generation, request.connection_generation);
    assert.equal(report.observation_ref, null);
    assert.equal(report.response_digest, null);
    assert.equal(harness.store.readAttempt(request.attempt_ref).state, "refused_no_effect");
  }

  {
    const fixture = createDeterministicProviderFixture();
    const provider = providerFor(fixture);
    const harness = PROVIDER_BOOTSTRAP_HARNESSES.get(provider);
    const request = bootstrapRequestFor(provider, fixture, "inventory");
    harness.connection.disconnect_on_read = 2;
    const report = normalizeProviderBootstrapReport(
      await provider.inventory(request),
      request,
    );
    assert.equal(report.outcome, "refused_no_effect");
    assert.equal(report.observation_digest, null);
    assert.equal(harness.store.readAttempt(request.attempt_ref).state, "refused_no_effect");
  }
});

test("ABI-v3 bootstrap faults terminate as refused-no-effect or ambiguous without hardware", async () => {
  for (const [method, fault, expectedOutcome] of [
    ["health", "refusal", "refused_no_effect"],
    ["capabilities", "ambiguous", "ambiguous"],
    ["inventory", "corruption", "ambiguous"],
  ]) {
    const fixture = createDeterministicProviderFixture();
    const provider = providerFor(fixture, {
      script: [{ method, outcome: fault }],
    });
    const harness = PROVIDER_BOOTSTRAP_HARNESSES.get(provider);
    const request = bootstrapRequestFor(provider, fixture, method);
    const report = normalizeProviderBootstrapReport(
      await provider[method](request),
      request,
    );
    assert.equal(report.outcome, expectedOutcome);
    assert.equal(report.observation_ref, null);
    assert.equal(report.observation_digest, null);
    assert.equal(report.response_digest, null);
    assert.equal(report.assurance_claims_digest, null);
    assert.equal(report.invariant_witness_digest, null);
    assert.match(report.receipt_digest, /^[a-f0-9]{64}$/);
    assert.equal(harness.store.readAttempt(request.attempt_ref).state, expectedOutcome);
    assertNoPublicByteMaterial(report, `deterministic_v3_${method}_${fault}`);
  }
});

test("provider execution rejects cloned dispatch authority before any effect", async () => {
  const fixture = createDeterministicProviderFixture();
  const provider = providerFor(fixture);
  const flow = await prepareSnapshot(provider, fixture);
  const clonedCredential = Object.freeze(structuredClone(
    flow.executeRequest.dispatch_credential,
  ));
  const forgedRequest = normalizeExecuteRequest({
    ...flow.executeRequest,
    dispatch_credential: clonedCredential,
  });

  await assert.rejects(
    () => provider.execute(forgedRequest),
    /must be issued by a live Bob durable store/,
  );
  assert.equal(
    normalizeAttemptReport(await provider.status(statusRequest(flow.prepared)), fixture.operationRegistry).state,
    "prepared",
  );
  assert.equal(
    normalizeAttemptReport(await provider.execute(flow.executeRequest), fixture.operationRegistry).state,
    "dispatched",
  );
});

test("provider execution rejects authority enrolled for another provider descriptor", async () => {
  const fixture = createDeterministicProviderFixture();
  const alternateDescriptor = defineProviderDescriptor({
    version: 1,
    abi_version: 2,
    provider_id: "deterministic_mock_redirected",
    provider_version: "1.0.0",
    implementation_digest: "b".repeat(64),
    operation_registry_digest: fixture.operationRegistry.registry_digest,
    capabilities: structuredClone(fixture.descriptor.capabilities),
  }, fixture.operationRegistry, fixture.effectRegistry);
  const alternateHarness = createDurableProviderDispatchHarness({
    descriptor: alternateDescriptor,
    instrumentRefs: [fixture.prepareRequest.instrument_ref],
  });
  OPEN_HARNESSES.add(alternateHarness);
  const bootstrapHarness = createBootstrapHarness(fixture);
  OPEN_HARNESSES.add(bootstrapHarness);
  const crossWiredProvider = new DeterministicInstrumentProvider({
    descriptor: fixture.descriptor,
    operationRegistry: fixture.operationRegistry,
    effectRegistry: fixture.effectRegistry,
    providerDispatchPort: alternateHarness.port,
    bootstrapProviderPort: bootstrapHarness.port,
  });
  const normalizedPrepare = normalizePrepareRequest(fixture.prepareRequest, context(fixture));
  const prepared = normalizeAttemptReport(
    await crossWiredProvider.prepare(fixture.prepareRequest),
    fixture.operationRegistry,
  );
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
  normalizeSnapshotResponse(
    await crossWiredProvider.snapshot(snapshotRequest),
    snapshotRequest,
  );
  const redirectedDispatch = alternateHarness.authorize({
    descriptor: alternateDescriptor,
    normalized_prepare: normalizedPrepare,
    prepared,
  });
  const redirectedRequest = normalizeExecuteRequest({
    version: 1,
    attempt_ref: prepared.attempt_ref,
    operation_id: prepared.operation_id,
    request_digest: prepared.request_digest,
    expected_state: "prepared",
    expected_sequence: prepared.sequence,
    dispatch_journal_ref: redirectedDispatch.dispatch_journal_ref,
    dispatch_credential: redirectedDispatch.dispatch_credential,
  });

  await assert.rejects(
    () => crossWiredProvider.execute(redirectedRequest),
    /expected_provider_id binding drift/,
  );
  assert.equal(alternateHarness.store.snapshot().dispatch_redemptions.length, 0);
  assert.equal(
    normalizeAttemptReport(
      await crossWiredProvider.status(statusRequest(prepared)),
      fixture.operationRegistry,
    ).state,
    "prepared",
  );

  const correctlyWiredProvider = providerFor(fixture);
  const correctlyWiredFlow = await prepareSnapshot(correctlyWiredProvider, fixture);
  assert.equal(
    normalizeAttemptReport(
      await correctlyWiredProvider.execute(correctlyWiredFlow.executeRequest),
      fixture.operationRegistry,
    ).state,
    "dispatched",
  );
});

test("fault script exposes explicit refused, unavailable, and ambiguous dispositions", async () => {
  {
    const fixture = createDeterministicProviderFixture();
    const provider = providerFor(fixture, {
      script: [{ method: "prepare", outcome: "refused" }],
    });
    const refused = normalizeAttemptReport(
      await provider.prepare(fixture.prepareRequest),
      fixture.operationRegistry,
    );
    assert.equal(refused.state, "refused");
    assert.equal(refused.effect_disposition, "confirmed_no_effect");
  }

  {
    const fixture = createDeterministicActiveOnlyProviderFixture();
    const provider = providerFor(fixture, {
      script: [{ method: "health", outcome: "unavailable" }],
    });
    const health = normalizeHealthResponse(await provider.health({
      version: 1,
      provider_id: fixture.descriptor.provider_id,
      descriptor_digest: fixture.descriptor.descriptor_digest,
    }), fixture.descriptor);
    assert.equal(health.status, "unavailable");
  }

  {
    const fixture = createDeterministicProviderFixture();
    const provider = providerFor(fixture, {
      script: [{ method: "execute", outcome: "ambiguous" }],
    });
    const flow = await prepareSnapshot(provider, fixture);
    await assert.rejects(
      () => provider.execute(flow.executeRequest),
      (error) => error.code === "provider_ambiguous" && error.effect_state === "ambiguous_effect",
    );
    const ambiguous = normalizeAttemptReport(
      await provider.status(statusRequest(flow.prepared)),
      fixture.operationRegistry,
    );
    assert.equal(ambiguous.state, "ambiguous_effect");
    assert.equal(ambiguous.effect_disposition, "ambiguous");
  }
});

test("timeout, disconnect, stale-state, and restore-failure fixtures are deterministic", async () => {
  for (const outcome of ["timeout", "disconnect"]) {
    const fixture = createDeterministicProviderFixture();
    const provider = providerFor(fixture, {
      script: [{ method: "execute", outcome }],
    });
    const flow = await prepareSnapshot(provider, fixture);
    await assert.rejects(
      () => provider.execute(flow.executeRequest),
      (error) => error.code === `provider_${outcome}` && error.effect_state === "ambiguous_effect",
    );
    const ambiguous = normalizeAttemptReport(
      await provider.status(statusRequest(flow.prepared)),
      fixture.operationRegistry,
    );
    assert.equal(ambiguous.state, "ambiguous_effect");
  }

  {
    const fixture = createDeterministicProviderFixture();
    const provider = providerFor(fixture, {
      script: [{ method: "status", outcome: "stale_state" }],
    });
    const flow = await prepareSnapshot(provider, fixture);
    const dispatched = normalizeAttemptReport(
      await provider.execute(flow.executeRequest),
      fixture.operationRegistry,
    );
    const stale = normalizeAttemptReport(
      await provider.status(statusRequest(dispatched)),
      fixture.operationRegistry,
    );
    assert.throws(
      () => assertAttemptTransition(dispatched, stale, fixture.operationRegistry),
      /increment by exactly one|is not allowed/,
    );
  }

  {
    const fixture = createDeterministicProviderFixture();
    const provider = providerFor(fixture, {
      script: [{ method: "restore", outcome: "restore_failure" }],
    });
    const result = await runProviderConformance({
      authorizeDispatch: authorizeFor(provider),
      authorizeBootstrap: authorizeBootstrapFor(provider),
      provider,
      operationRegistry: fixture.operationRegistry,
      effectRegistry: fixture.effectRegistry,
      prepareRequest: fixture.prepareRequest,
    });
    assert.equal(result.terminal.state, "quarantined");
    assert.equal(result.terminal.public_result.outcome, "failed");
  }
});

test("crash checkpoint survives provider restart and permits only explicit reconciliation", async () => {
  const fixture = createDeterministicProviderFixture();
  const stateStore = createDeterministicProviderStateStore();
  const beforeCrash = providerFor(fixture, {
    stateStore,
    script: [{ method: "execute", outcome: "crash_after_dispatch" }],
  });
  const flow = await prepareSnapshot(beforeCrash, fixture);
  await assert.rejects(
    () => beforeCrash.execute(flow.executeRequest),
    (error) => error.code === "provider_crash" && error.effect_state === "ambiguous_effect",
  );

  const afterRestart = providerFor(fixture, { stateStore });
  const ambiguous = normalizeAttemptReport(
    await afterRestart.status(statusRequest(flow.prepared)),
    fixture.operationRegistry,
  );
  assert.equal(ambiguous.state, "ambiguous_effect");
  await assert.rejects(() => afterRestart.execute(flow.executeRequest), /provider_execute_replay/);
  await assert.rejects(
    () => afterRestart.status({ ...statusRequest(ambiguous), request_digest: "0".repeat(64) }),
    (error) => error.code === "provider_attempt_binding_mismatch",
  );

  const reconciled = normalizeAttemptReport(await afterRestart.reconcile(
    normalizeReconcileRequest({
      ...statusRequest(ambiguous),
      expected_sequence: ambiguous.sequence,
      observation_ref: "observation:restart-reconciliation-0001",
    }),
  ), fixture.operationRegistry);
  assert.equal(reconciled.state, "reconciled_no_effect");
  assert.equal(reconciled.effect_disposition, "confirmed_no_effect");
});

test("reconciliation can confirm an effect, after which exact snapshot restore remains required", async () => {
  const fixture = createDeterministicProviderFixture();
  const stateStore = createDeterministicProviderStateStore();
  const beforeCrash = providerFor(fixture, {
    stateStore,
    script: [{ method: "execute", outcome: "crash_after_dispatch" }],
  });
  const flow = await prepareSnapshot(beforeCrash, fixture);
  await assert.rejects(() => beforeCrash.execute(flow.executeRequest), /provider_crash/);

  const afterRestart = providerFor(fixture, {
    stateStore,
    script: [{ method: "reconcile", outcome: "confirmed_effect" }],
  });
  const ambiguous = normalizeAttemptReport(
    await afterRestart.status(statusRequest(flow.prepared)),
    fixture.operationRegistry,
  );
  const acknowledged = normalizeAttemptReport(await afterRestart.reconcile({
    ...statusRequest(ambiguous),
    expected_sequence: ambiguous.sequence,
    observation_ref: "observation:confirmed-effect-0001",
  }), fixture.operationRegistry);
  assert.equal(acknowledged.state, "acknowledged");
  assert.deepEqual(acknowledged.public_result.artifact_refs, [
    "artifact:v1:mock-reconciled-artifact-0001",
  ]);

  await assert.rejects(
    () => afterRestart.restore({
      ...statusRequest(acknowledged),
      expected_sequence: acknowledged.sequence,
      snapshot_artifact_ref: "artifact:v1:wrong-snapshot-0001",
      expected_workspace_state_digest: flow.snapshot.workspace_state_digest,
      restore_plan_digest: "b".repeat(64),
    }),
    (error) => error.code === "provider_snapshot_binding_mismatch",
  );
  const restored = normalizeAttemptReport(await afterRestart.restore({
    ...statusRequest(acknowledged),
    expected_sequence: acknowledged.sequence,
    snapshot_artifact_ref: flow.snapshot.snapshot_artifact_ref,
    expected_workspace_state_digest: flow.snapshot.workspace_state_digest,
    restore_plan_digest: "b".repeat(64),
  }), fixture.operationRegistry);
  assert.equal(restored.state, "restored");
});

test("corruption fixtures are schema-invalid but never contain byte material", async () => {
  const fixture = createDeterministicProviderFixture();
  const provider = providerFor(fixture, {
    script: [{ method: "execute", outcome: "corruption" }],
  });
  const flow = await prepareSnapshot(provider, fixture);
  const response = await provider.execute(flow.executeRequest);
  assert.equal(assertNoPublicByteMaterial(response, "corrupt_fixture"), true);
  assert.throws(
    () => normalizeAttemptReport(response, fixture.operationRegistry),
    /unknown fields: diagnostic_ref/,
  );
});

test("fault scripts and restart stores are closed and bounded", () => {
  const faultScript = defineDeterministicFaultScript([
    { method: "execute", outcome: "crash_after_dispatch" },
  ]);
  assert.equal(Object.isFrozen(faultScript), true);
  assert.equal(Object.isFrozen(faultScript[0]), true);
  assert.throws(
    () => defineDeterministicFaultScript([{ method: "execute", outcome: "invented" }]),
    /outcome is not supported/,
  );
  assert.throws(
    () => defineDeterministicFaultScript([{ method: "status", outcome: "crash_after_dispatch" }]),
    /valid only for execute/,
  );
  assert.throws(
    () => defineDeterministicFaultScript(Array.from(
      { length: 1025 },
      () => ({ method: "health", outcome: "confirmed" }),
    )),
    /at most 1024 events/,
  );

  const fixture = createDeterministicProviderFixture();
  assert.throws(
    () => providerFor(fixture, { stateStore: Object.freeze({ version: 1 }) }),
    /closed deterministic provider state store/,
  );
});
