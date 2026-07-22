"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

const {
  buildNormalizedOperationRegistry,
  defineProviderDescriptor,
} = require("../mcp/lib/instrument-provider-contract.js");
const {
  buildPhysicalFinding,
} = require("../mcp/lib/physical-capability-consumers.js");
const {
  assertPhysicalProviderAuthoringBindings,
  assertPhysicalProviderAuthoringManifest,
  createPhysicalProviderAuthoringManifest,
  normalizePhysicalProviderAuthoringManifest,
} = require("../mcp/lib/physical-provider-authoring.js");
const {
  normalizePhysicalResourceBundle,
} = require("../mcp/lib/physical-resource-contract.js");
const {
  MAX_RESOURCE_INVENTORY_VALIDITY_MS,
  planPhysicalResourceBundle,
} = require("../mcp/lib/physical-resource-scheduler.js");
const {
  MAX_UNCERTAINTY_MS,
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  createPhysicalTrustedClockPort,
  physicalClockMappingSigningMessage,
  publicKeyDigest,
} = require("../mcp/lib/physical-trusted-clock.js");
const {
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");
const {
  createOrthogonalMultiInstrumentProviderFixture,
} = require("../packages/bob-instrument-deterministic/lib/orthogonal-fixture.js");
const {
  DeterministicInstrumentProvider,
  runProviderConformance,
} = require("../packages/bob-instrument-deterministic/lib/provider.js");
const {
  createDurableProviderBootstrapHarness,
} = require("./helpers/durable-provider-bootstrap.js");
const {
  createDurableProviderDispatchHarness,
} = require("./helpers/durable-provider-dispatch.js");
const {
  createProductionPhysicalVerdictFixture,
} = require("./helpers/production-physical-verdict.js");

const digest = (label) => hashCanonicalJson({ label });

function authoringInput(fixture, overrides = {}) {
  return {
    qualification_profile: "orthogonal_multi_instrument_v1",
    provider_descriptor: fixture.descriptor,
    operation_registry: fixture.operationRegistry,
    effect_registry: fixture.effectRegistry,
    resource_bundles: [fixture.resourceBundle],
    ...overrides,
  };
}

function mutableBundle(bundle) {
  const value = structuredClone(bundle);
  delete value.resource_bundle_digest;
  return value;
}

function operationDeclarations(registry) {
  return registry.ids().map((operationId) => {
    const operation = registry.get(operationId);
    return {
      version: operation.version,
      operation_id: operation.operation_id,
      semantic_version: operation.semantic_version,
      parameters: structuredClone(operation.parameters),
      public_summary_codes: [...operation.public_summary_codes],
    };
  });
}

function createTrustedClockPort() {
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const payload = {
    version: 1,
    clock_id: "physical-clock:orthogonal-authoring-test",
    monotonic_epoch_id: digest("orthogonal-monotonic-epoch"),
    mapping_generation: 1,
    reference_monotonic_ms: 1_000,
    reference_utc: "2026-07-18T00:00:01.000Z",
    max_uncertainty_ms: 10,
    not_before: "2026-07-17T23:59:00.000Z",
    expires_at: "2026-07-18T00:10:00.000Z",
    trust_root_epoch: 1,
    authority_epoch: 1,
    revocation_generation: 0,
    signer_key_id: "clock-key:orthogonal-authoring-test",
    signer_public_key_digest: publicKeyDigest(keyPair.publicKey),
  };
  const payloadDigest = hashCanonicalJson(payload);
  const basis = {
    version: 1,
    domain: TRUSTED_CLOCK_MAPPING_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature: crypto.sign(
      null,
      physicalClockMappingSigningMessage(payloadDigest),
      keyPair.privateKey,
    ).toString("base64url"),
  };
  const mapping = { ...basis, signed_mapping_digest: hashCanonicalJson(basis) };
  return createPhysicalTrustedClockPort({
    port_id: "orthogonal_authoring_test_clock",
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    uncertainty_ceiling_ms: MAX_UNCERTAINTY_MS,
    read_monotonic_ms: () => 1_000,
    read_signed_mapping: () => mapping,
    resolve_current_trust: () => ({
      version: 1,
      trusted: true,
      revoked: false,
      clock_id: payload.clock_id,
      monotonic_epoch_id: payload.monotonic_epoch_id,
      current_mapping_generation: payload.mapping_generation,
      current_signed_mapping_digest: mapping.signed_mapping_digest,
      trust_root_epoch: payload.trust_root_epoch,
      authority_epoch: payload.authority_epoch,
      revocation_generation: payload.revocation_generation,
      signer_key_id: payload.signer_key_id,
      signer_public_key_digest: payload.signer_public_key_digest,
      public_key: keyPair.publicKey,
    }),
  });
}

function reservationRequest(bundle) {
  return {
    version: 1,
    reservation_request_id: "reservation-request:orthogonal-authoring-test",
    node_id: "TG-orthogonal-provider-conformance",
    contract_hash: digest("orthogonal-contract"),
    source_graph_hash: digest("orthogonal-graph"),
    session_nucleus_hash: digest("orthogonal-nucleus"),
    experiment_ref: "experiment:orthogonal-authoring-test",
    attempt_ref: "attempt:orthogonal-authoring-test",
    owner_principal_ref: "principal:orthogonal-broker",
    execution_principal_ref: "principal:orthogonal-worker",
    resource_bundle_digest: bundle.resource_bundle_digest,
    requested_at: "2026-07-18T00:00:00.000Z",
    effect_not_before: "2026-07-18T00:00:01.100Z",
    effect_deadline: "2026-07-18T00:00:05.000Z",
  };
}

function inventoryResource(requirement) {
  const resourceRef = requirement.candidate_resource_refs[0];
  const resource = {
    resource_kind: requirement.resource_kind,
    resource_ref: resourceRef,
    state_epoch_digest: digest(`state:${resourceRef}`),
    availability: "available",
    total_capacity_units: 1,
    available_capacity_units: 1,
    exclusive_available: true,
    fencing_generation: 1,
    setup_cost_units: 0,
    eligible_requirement_digests: [hashCanonicalJson(requirement)],
    switchable_mode_refs: requirement.mode_ref == null ? [] : [requirement.mode_ref],
    switchable_workspace_refs: requirement.workspace_ref == null ? [] : [requirement.workspace_ref],
  };
  if (requirement.mode_ref != null) resource.current_mode_ref = requirement.mode_ref;
  if (requirement.workspace_ref != null) resource.current_workspace_ref = requirement.workspace_ref;
  return resource;
}

function inventory(bundle, requirements = bundle.requirements) {
  return {
    version: 1,
    broker_ref: "broker:orthogonal-authoring-test",
    broker_epoch: 1,
    inventory_generation: 1,
    captured_at: "2026-07-18T00:00:00.900Z",
    valid_from: "2026-07-18T00:00:00.000Z",
    expires_at: new Date(
      Date.parse("2026-07-18T00:00:00.900Z") + MAX_RESOURCE_INVENTORY_VALIDITY_MS,
    ).toISOString(),
    session_nucleus_hash: digest("orthogonal-nucleus"),
    source_graph_hash: digest("orthogonal-graph"),
    resources: requirements.map(inventoryResource),
  };
}

test("PH-X4 authoring projection binds existing registries and omits concrete resource locators", () => {
  const fixture = createOrthogonalMultiInstrumentProviderFixture();
  const manifest = createPhysicalProviderAuthoringManifest(authoringInput(fixture));

  assert.equal(manifest.provider_id, "deterministic_orthogonal_gpio_optical");
  assert.equal(manifest.qualification_profile, "orthogonal_multi_instrument_v1");
  assert.deepEqual(manifest.active_capability_ids, ["orthogonal.actuate", "orthogonal.observe"]);
  assert.deepEqual(manifest.resource_kind_coverage, [
    "control",
    "instrument",
    "observer",
    "operator_presence",
    "workspace",
  ]);
  assert.equal(manifest.compatibility.bootstrap_compatible, true);
  assert.equal(Object.isFrozen(manifest), true);
  assert.equal(assertPhysicalProviderAuthoringManifest(manifest), manifest);
  assert.equal(assertPhysicalProviderAuthoringBindings(manifest, authoringInput(fixture)), true);

  const serialized = JSON.stringify(manifest);
  for (const privateLocator of [
    "orthogonal-gpio-actuator-0001",
    "orthogonal-optical-sensor-0001",
    "orthogonal-external-meter-0001",
    "orthogonal-owned-bench-0001",
  ]) assert.equal(serialized.includes(privateLocator), false);
});

test("serialized manifests revalidate but cannot inherit the private normalized brand", () => {
  const fixture = createOrthogonalMultiInstrumentProviderFixture();
  const original = createPhysicalProviderAuthoringManifest(authoringInput(fixture));
  const clone = structuredClone(original);
  assert.throws(
    () => assertPhysicalProviderAuthoringManifest(clone),
    /must be normalized by Bob/,
  );
  const normalized = normalizePhysicalProviderAuthoringManifest(clone);
  assert.equal(normalized.manifest_digest, original.manifest_digest);
  assert.equal(assertPhysicalProviderAuthoringManifest(normalized), normalized);
  assert.throws(
    () => normalizePhysicalProviderAuthoringManifest({ ...clone, capability_count: 6 }),
    /capability_count does not match/,
  );
});

test("authoring assembly rejects proxies, unused registry operations, and unknown capability refs", () => {
  const fixture = createOrthogonalMultiInstrumentProviderFixture();
  assert.throws(
    () => createPhysicalProviderAuthoringManifest(authoringInput(fixture, {
      provider_descriptor: new Proxy(fixture.descriptor, {}),
    })),
    /cannot be a proxy/,
  );
  const proxiedBundle = new Proxy(mutableBundle(fixture.resourceBundle), {});
  assert.throws(
    () => createPhysicalProviderAuthoringManifest(authoringInput(fixture, {
      resource_bundles: [proxiedBundle],
    })),
    /cannot be a proxy/,
  );

  const expandedRegistry = buildNormalizedOperationRegistry([
    ...operationDeclarations(fixture.operationRegistry),
    {
      version: 1,
      operation_id: "environment.unused",
      semantic_version: 1,
      parameters: {},
      public_summary_codes: ["operation_refused"],
    },
  ]);
  const expandedDescriptor = defineProviderDescriptor({
    version: fixture.descriptor.version,
    abi_version: fixture.descriptor.abi_version,
    provider_id: fixture.descriptor.provider_id,
    provider_version: fixture.descriptor.provider_version,
    implementation_digest: fixture.descriptor.implementation_digest,
    operation_registry_digest: expandedRegistry.registry_digest,
    capabilities: structuredClone(fixture.descriptor.capabilities),
  }, expandedRegistry, fixture.effectRegistry);
  assert.throws(
    () => createPhysicalProviderAuthoringManifest(authoringInput(fixture, {
      provider_descriptor: expandedDescriptor,
      operation_registry: expandedRegistry,
    })),
    /undeclared operations: environment\.unused/,
  );

  const unknownCapabilityBundle = mutableBundle(fixture.resourceBundle);
  unknownCapabilityBundle.requirements.find(
    (entry) => entry.alias === "gpio_actuator",
  ).capability_refs = ["capability:orthogonal.unknown"];
  assert.throws(
    () => createPhysicalProviderAuthoringManifest(authoringInput(fixture, {
      resource_bundles: [unknownCapabilityBundle],
    })),
    /references unknown capability orthogonal\.unknown/,
  );
});

test("orthogonal profile requires disjoint instruments and independent observer/control resources", () => {
  const fixture = createOrthogonalMultiInstrumentProviderFixture();
  const missingObserver = mutableBundle(fixture.resourceBundle);
  missingObserver.requirements = missingObserver.requirements.filter(
    (entry) => entry.resource_kind !== "observer",
  );
  assert.throws(
    () => createPhysicalProviderAuthoringManifest(authoringInput(fixture, {
      resource_bundles: [missingObserver],
    })),
    /orthogonal provider qualification requires one atomic bundle/,
  );

  const aliasedInstruments = mutableBundle(fixture.resourceBundle);
  const actuatorRef = aliasedInstruments.requirements.find(
    (entry) => entry.alias === "gpio_actuator",
  ).candidate_resource_refs[0];
  aliasedInstruments.requirements.find(
    (entry) => entry.alias === "optical_sensor",
  ).candidate_resource_refs = [actuatorRef];
  assert.throws(
    () => createPhysicalProviderAuthoringManifest(authoringInput(fixture, {
      resource_bundles: [aliasedInstruments],
    })),
    /orthogonal provider qualification requires one atomic bundle/,
  );
});

test("orthogonal fixture is unit-aware, non-RFID, and plans all resources atomically", () => {
  const fixture = createOrthogonalMultiInstrumentProviderFixture();
  assert.deepEqual(fixture.effectRegistry.ids(), [
    "environment.actuate.gpio.v1",
    "environment.observe.optical.v1",
    "instrument.observe.instrument_local.v1",
  ]);
  const fixtureText = JSON.stringify({
    descriptor: fixture.descriptor,
    effects: fixture.requestedEffects,
    bundle: fixture.resourceBundle,
  });
  for (const forbidden of ["rfid", "credential", "chameleon", "mifare"]) {
    assert.equal(fixtureText.toLowerCase().includes(forbidden), false);
  }
  assert.deepEqual(fixture.requestedEffects.actuate.bounds.duration, {
    quantity_id: "duration",
    unit: "ms",
    max: 250,
  });
  assert.deepEqual(fixture.requestedEffects.observe.bounds.optical_intensity, {
    quantity_id: "optical_intensity",
    unit: "W/m^2",
    max: 10,
  });

  const clock = createTrustedClockPort();
  const planned = planPhysicalResourceBundle(
    fixture.resourceBundle,
    reservationRequest(fixture.resourceBundle),
    inventory(fixture.resourceBundle),
    { trusted_clock_port: clock },
  );
  assert.equal(planned.disposition, "planned", JSON.stringify(planned));
  assert.equal(planned.allocations.length, fixture.resourceBundle.requirements.length);
  assert.deepEqual(
    planned.allocations.map((entry) => entry.alias),
    fixture.resourceBundle.requirements.map((entry) => entry.alias).sort(),
  );

  const withoutOpticalSensor = fixture.resourceBundle.requirements.filter(
    (entry) => entry.alias !== "optical_sensor",
  );
  const denied = planPhysicalResourceBundle(
    fixture.resourceBundle,
    reservationRequest(fixture.resourceBundle),
    inventory(fixture.resourceBundle, withoutOpticalSensor),
    { trusted_clock_port: clock },
  );
  assert.equal(denied.disposition, "unschedulable");
  assert.equal(denied.reason, "no_eligible_candidate");
  assert.deepEqual(denied.allocations, []);
  assert.deepEqual(denied.lock_order, []);
});

test("orthogonal provider executes observe and act/restore through durable ABI authority", async () => {
  const fixture = createOrthogonalMultiInstrumentProviderFixture();
  const dispatchHarness = createDurableProviderDispatchHarness({
    descriptor: fixture.descriptor,
    instrumentRefs: [
      fixture.prepareRequests.actuate.instrument_ref,
      fixture.prepareRequests.observe.instrument_ref,
    ],
  });
  const bootstrapHarness = createDurableProviderBootstrapHarness({
    descriptor: fixture.descriptor,
    instrumentRef: fixture.prepareRequests.actuate.instrument_ref,
  });
  try {
    const provider = new DeterministicInstrumentProvider({
      descriptor: fixture.descriptor,
      operationRegistry: fixture.operationRegistry,
      effectRegistry: fixture.effectRegistry,
      providerDispatchPort: dispatchHarness.port,
      bootstrapProviderPort: bootstrapHarness.port,
    });
    const actuate = await runProviderConformance({
      authorizeDispatch: dispatchHarness.authorize,
      authorizeBootstrap: bootstrapHarness.authorize,
      provider,
      operationRegistry: fixture.operationRegistry,
      effectRegistry: fixture.effectRegistry,
      prepareRequest: fixture.prepareRequests.actuate,
      snapshotPlanDigest: digest("orthogonal-snapshot-plan"),
      restorePlanDigest: digest("orthogonal-restore-plan"),
    });
    assert.equal(actuate.capability.capability_id, "orthogonal.actuate");
    assert.equal(actuate.terminal.state, "restored");
    assert.equal(actuate.terminal.effect_disposition, "confirmed_effect");
    assert.ok(actuate.snapshot.snapshot_artifact_ref.startsWith("artifact:v1:"));

    const observe = await runProviderConformance({
      authorizeDispatch: dispatchHarness.authorize,
      authorizeBootstrap: bootstrapHarness.authorize,
      provider,
      operationRegistry: fixture.operationRegistry,
      effectRegistry: fixture.effectRegistry,
      prepareRequest: fixture.prepareRequests.observe,
    });
    assert.equal(observe.capability.capability_id, "orthogonal.observe");
    assert.equal(observe.snapshot, null);
    assert.equal(observe.terminal.state, "acknowledged");
    assert.equal(observe.terminal.effect_disposition, "confirmed_effect");
  } finally {
    bootstrapHarness.close();
    dispatchHarness.close();
  }
});

test("orthogonal provider assembly enters the production verifier contracts without RFID bindings",
  { concurrency: false }, async () => {
    const fixture = createOrthogonalMultiInstrumentProviderFixture();
    const manifest = createPhysicalProviderAuthoringManifest(authoringInput(fixture));
    const targetDomain = `orthogonal-x4-${crypto.randomBytes(6).toString("hex")}.local`;
    const verified = await createProductionPhysicalVerdictFixture({
      structural_mechanism_a: true,
      target_domain: targetDomain,
      experiment_profile: {
        effect_registry: fixture.effectRegistry,
        effect_template_id: "environment.actuate.gpio.v1",
        requested_effect: fixture.requestedEffects.actuate,
        surface_ref: "surface:orthogonal-optical-transition-0001",
        experiment_id: "orthogonal-gpio-optical-differential",
        node_id: "PH-X4",
        instrument_ref: fixture.prepareRequests.actuate.instrument_ref,
        instrument_identity_ref: "instrument-identity:orthogonal-gpio-actuator-0001",
        instrument_inventory_ref: "inventory:orthogonal-gpio-actuator-0001",
        assurance_profile_id: "orthogonal-gpio-optical-v1",
        provider_manifest_digest: manifest.manifest_digest,
        source_asset_ref: "source:orthogonal-gpio-stimulus-0001",
        target_asset_ref: "target:orthogonal-owned-fixture-0001",
        operation_id: "environment.actuate",
        parameter_digest: hashCanonicalJson(fixture.prepareRequests.actuate.parameters),
      },
    });
    try {
      assert.equal(verified.ledger.plan.node_id, "PH-X4");
      assert.equal(verified.ledger.plan.provider_manifest_digest, manifest.manifest_digest);
      assert.equal(verified.ledger.plan.operation_id, "environment.actuate");
      assert.equal(
        verified.ledger.plan.instrument_identity_ref,
        "instrument-identity:orthogonal-gpio-actuator-0001",
      );
      assert.deepEqual(verified.ledger.plan.requested_effects, [fixture.requestedEffects.actuate]);
      assert.equal(verified.projection.plan_hash, verified.ledger.plan.plan_hash);
      assert.equal(verified.projection.outcome, "verified");
      const finding = buildPhysicalFinding({
        title: "Orthogonal actuator transition",
        severity: "medium",
        description: "Independent optical positive and control observations verified the bounded transition.",
        impact: "The owned-fixture actuator produced the reviewed external state transition.",
        verdict: verified.verdict,
      });
      assert.equal(finding.asset_locator, "target:orthogonal-owned-fixture-0001");
      assert.equal(finding.verification_projection_digest, verified.projection.projection_digest);
      const serialized = JSON.stringify({ plan: verified.ledger.plan, projection: verified.projection });
      for (const forbidden of ["chameleon", "mifare", "credential-present", "hotel-door"]) {
        assert.equal(serialized.toLowerCase().includes(forbidden), false);
      }
    } finally {
      verified.cleanup();
    }
  });
