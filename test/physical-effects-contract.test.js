"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  PHYSICAL_QUANTITY_REGISTRY,
  bindSpatialEnvelopeRef,
  bindStimulusSequenceRef,
  buildPhysicalEnvelopeRegistry,
  normalizeQuantityBound,
  normalizeSpatialEnvelope,
  normalizeStimulusSequence,
  physicalQuantityRegistryDigest,
  spatialEnvelopeDigest,
  stimulusSequenceDigest,
} = require("../mcp/lib/physical-quantities.js");
const {
  buildEffectTemplateRegistry,
  normalizeEffectSurfaceMetadata,
  normalizeRequestedEffect,
  normalizeRequestedEffects,
  projectLegacyEffectFlags,
  requestedEffectDigest,
} = require("../mcp/lib/requested-effects.js");
const {
  TOOL_MANIFEST,
  buildToolRegistry,
} = require("../mcp/lib/tool-registry.js");
const { buildToolTelemetryEvent } = require("../mcp/lib/tool-telemetry.js");

function rfTemplateDefinition() {
  return {
    version: 1,
    template_id: "target.transmit.rf.v1",
    subject_kind: "target",
    action: "transmit",
    channel: "rf",
    persistence: "ephemeral",
    bounds: {
      attempt_limit: { kind: "integer", required: true, min: 1, max: 10 },
      carrier_frequency: {
        kind: "quantity",
        required: true,
        quantity_id: "frequency",
        require_useful_bound: true,
      },
      duration: { kind: "quantity", required: true, quantity_id: "duration" },
      execution_deadline: { kind: "timestamp", required: true },
      spatial_envelope_ref: { kind: "spatial_envelope", required: true },
      stimulus_sequence_ref: { kind: "stimulus_sequence", required: true },
      zone_ref: { kind: "reference", required: true, ref_prefix: "zone" },
    },
  };
}

function spatialEnvelopeFixture() {
  return {
    version: 1,
    envelope_ref: "spatial-envelope:shielded-fixture-1",
    coordinate_frame_ref: "frame:lab-bench-1",
    zone_ref: "zone:shielded-lab-1",
    source_pose_ref: "pose:instrument-fixed-1",
    target_pose_ref: "pose:target-grid-1",
    distance: {
      quantity_id: "distance",
      unit: "mm",
      min: 0,
      max: 100,
      uncertainty: { value: 1, unit: "mm" },
      measurement_method_ref: "measurement:caliper-1",
    },
    orientation: {
      quantity_id: "angle",
      unit: "deg",
      min: -15,
      max: 15,
      uncertainty: { value: 0.5, unit: "deg" },
    },
    barrier_refs: ["barrier:polycarbonate-1", "barrier:air-gap-1"],
    measurement_method_ref: "measurement:fixture-survey-1",
  };
}

function stimulusSequenceFixture() {
  return {
    version: 1,
    sequence_ref: "stimulus-sequence:inventory-probe-1",
    retry_identity_ref: "retry:attempt-family-1",
    steps: [
      {
        step_id: "negative_control",
        operation_ref: "operation:credential-control-v1",
        interval_after_previous: { quantity_id: "interval", unit: "ms", value: 0 },
        jitter: { quantity_id: "jitter", unit: "ms", max: 2 },
      },
      {
        step_id: "candidate",
        operation_ref: "operation:credential-candidate-v1",
        interval_after_previous: { quantity_id: "interval", unit: "ms", min: 100, max: 150 },
        delay: { quantity_id: "delay", unit: "ms", value: 5 },
        cadence: { quantity_id: "cadence", unit: "Hz", max: 2 },
        precondition_ref: "precondition:control-denied-1",
      },
    ],
  };
}

function physicalEnvelopeRegistryFixture({ spatialEnvelope = null, stimulusSequence = null } = {}) {
  return buildPhysicalEnvelopeRegistry({
    version: 1,
    spatial_envelopes: [spatialEnvelope || spatialEnvelopeFixture()],
    stimulus_sequences: [stimulusSequence || stimulusSequenceFixture()],
  });
}

function rfFixture() {
  const physicalEnvelopeRegistry = physicalEnvelopeRegistryFixture();
  const registry = buildEffectTemplateRegistry(
    [rfTemplateDefinition()],
    { physicalEnvelopeRegistry },
  );
  const template = registry.get("target.transmit.rf.v1");
  return {
    registry,
    input: {
      version: 1,
      template_id: template.template_id,
      template_digest: template.template_digest,
      subject_ref: "target:owned-fixture-1",
      subject_kind: "target",
      action: "transmit",
      channel: "rf",
      persistence: "ephemeral",
      bounds: {
        attempt_limit: 3,
        carrier_frequency: {
          quantity_id: "frequency",
          unit: "Hz",
          value: 13560000,
          uncertainty: { value: 100, unit: "Hz" },
          measurement_method_ref: "measurement:frequency-counter-1",
        },
        duration: { quantity_id: "duration", unit: "ms", max: 5000 },
        execution_deadline: "2026-07-18T02:00:00.000Z",
        spatial_envelope_ref: "spatial-envelope:shielded-fixture-1",
        stimulus_sequence_ref: "stimulus-sequence:inventory-probe-1",
        zone_ref: "zone:shielded-lab-1",
      },
    },
    physicalEnvelopeRegistry,
  };
}

function clone(value) {
  return structuredClone(value);
}

test("requested effects bind a closed template, exact subject, canonical bounds, and stable digest", () => {
  const { registry, input, physicalEnvelopeRegistry } = rfFixture();
  const normalized = normalizeRequestedEffect(input, registry);

  assert.equal(Object.isFrozen(registry), true);
  assert.equal(Object.getOwnPropertySymbols(registry).length, 0);
  assert.equal(typeof registry.set, "undefined");
  assert.deepEqual(registry.ids(), ["target.transmit.rf.v1"]);
  assert.match(registry.registry_digest, /^[a-f0-9]{64}$/);
  assert.equal(normalized.template_id, "target.transmit.rf.v1");
  assert.equal(normalized.bounds.carrier_frequency.unit, "Hz");
  assert.equal(normalized.bounds.duration.max, 5000);
  assert.deepEqual(
    normalized.bounds.spatial_envelope_ref,
    bindSpatialEnvelopeRef(input.bounds.spatial_envelope_ref, physicalEnvelopeRegistry),
  );
  assert.deepEqual(
    normalized.bounds.stimulus_sequence_ref,
    bindStimulusSequenceRef(input.bounds.stimulus_sequence_ref, physicalEnvelopeRegistry),
  );
  assert.deepEqual(Object.keys(normalized.bounds.spatial_envelope_ref), [
    "version",
    "reference_kind",
    "ref",
    "definition_digest",
    "registry_digest",
  ]);
  assert.equal(JSON.stringify(normalized).includes("frame:lab-bench-1"), false);
  assert.equal(JSON.stringify(normalized).includes("operation:credential-candidate-v1"), false);
  assert.equal(Object.isFrozen(normalized), true);
  assert.equal(Object.isFrozen(normalized.bounds), true);
  assert.match(requestedEffectDigest(input, registry), /^[a-f0-9]{64}$/);
  assert.equal(requestedEffectDigest(input, registry), requestedEffectDigest(clone(input), registry));
  assert.throws(() => normalizeRequestedEffect(input, new Map()), /closed Bob registry/);
  const forgedRegistry = Object.freeze({
    version: registry.version,
    registry_digest: registry.registry_digest,
    get: registry.get.bind(registry),
  });
  assert.throws(() => normalizeRequestedEffect(input, forgedRegistry), /closed Bob registry/);
  assert.deepEqual(projectLegacyEffectFlags([normalized]), {
    mutating: true,
    network_access: false,
    effect_surface: ["target.transmit"],
  });
});

test("requested effect drift and unknown schema values fail closed", () => {
  const { registry, input } = rfFixture();
  const cases = [
    ["unknown template", (value) => { value.template_id = "target.transmit.rf.future"; }, /not registered/],
    ["template digest", (value) => { value.template_digest = "0".repeat(64); }, /does not match/],
    ["subject kind", (value) => { value.subject_kind = "instrument"; }, /does not match/],
    ["subject namespace", (value) => { value.subject_ref = "instrument:owned-fixture-1"; }, /target: namespace/],
    ["unknown descriptor field", (value) => { value.command = 2000; }, /unknown fields: command/],
    ["unknown bound", (value) => { value.bounds.power = 1; }, /unknown bounds: power/],
    ["missing bound", (value) => { delete value.bounds.zone_ref; }, /is missing: zone_ref/],
    ["wrong unit", (value) => { value.bounds.duration.unit = "s"; }, /canonical ms/],
    ["wrong quantity", (value) => { value.bounds.duration.quantity_id = "distance"; value.bounds.duration.unit = "mm"; }, /must be duration/],
    ["full uncertainty", (value) => {
      value.bounds.carrier_frequency.uncertainty.value = value.bounds.carrier_frequency.value;
    }, /less than the useful value/],
    ["bound ceiling", (value) => { value.bounds.attempt_limit = 11; }, /must be <= 10/],
    ["noncanonical deadline", (value) => { value.bounds.execution_deadline = "2026-07-18T02:00:00Z"; }, /canonical UTC/],
  ];
  for (const [name, mutate, expected] of cases) {
    const value = clone(input);
    mutate(value);
    assert.throws(() => normalizeRequestedEffect(value, registry), expected, name);
  }
});

test("quantity bounds use registered canonical units and reject incoherent intervals", () => {
  assert.match(physicalQuantityRegistryDigest(), /^[a-f0-9]{64}$/);
  assert.equal(Object.isFrozen(PHYSICAL_QUANTITY_REGISTRY), true);
  assert.equal(Object.getPrototypeOf(PHYSICAL_QUANTITY_REGISTRY), null);
  assert.throws(() => {
    PHYSICAL_QUANTITY_REGISTRY.provider_flux = {
      canonical_unit: "widget/s",
      min: 0,
      max: 1,
      integer: false,
    };
  }, TypeError);
  assert.deepEqual(
    Object.fromEntries([
      "acoustic_level",
      "bandwidth",
      "force",
      "gain",
      "logic_level",
      "optical_intensity",
      "power",
      "rate",
      "rf_power",
      "sample_rate",
      "travel",
    ].map((quantityId) => [quantityId, PHYSICAL_QUANTITY_REGISTRY[quantityId].canonical_unit])),
    {
      acoustic_level: "dB_SPL",
      bandwidth: "Hz",
      force: "N",
      gain: "dB",
      logic_level: "V",
      optical_intensity: "W/m^2",
      power: "W",
      rate: "1/s",
      rf_power: "dBm",
      sample_rate: "sample/s",
      travel: "mm",
    },
  );
  assert.deepEqual(
    normalizeQuantityBound({
      quantity_id: "distance",
      unit: "mm",
      min: 10,
      max: 20,
      uncertainty: { value: 1, unit: "mm" },
    }),
    {
      quantity_id: "distance",
      unit: "mm",
      min: 10,
      max: 20,
      uncertainty: { value: 1, unit: "mm" },
    },
  );
  assert.throws(
    () => normalizeQuantityBound({ quantity_id: "distance", unit: "cm", value: 1 }),
    /canonical mm/,
  );
  assert.throws(
    () => normalizeQuantityBound({ quantity_id: "distance", unit: "mm", min: 20, max: 10 }),
    /min must be <=/,
  );
  assert.throws(
    () => normalizeQuantityBound({ quantity_id: "count", unit: "count", value: 1.5 }),
    /must be an integer/,
  );
  assert.throws(
    () => normalizeQuantityBound({ quantity_id: "unregistered", unit: "x", value: 1 }),
    /not registered/,
  );
  assert.throws(
    () => normalizeQuantityBound({ quantity_id: "constructor", unit: undefined, value: 1 }),
    /not registered/,
  );
  assert.throws(
    () => normalizeQuantityBound(
      { quantity_id: "provider_flux", unit: "widget/s", value: 1 },
      "quantity_bound",
      { quantityRegistry: { provider_flux: { canonical_unit: "widget/s" } } },
    ),
    /unknown fields: quantityRegistry/,
  );
  assert.throws(
    () => normalizeQuantityBound({
      quantity_id: "distance",
      unit: "mm",
      value: 10,
      uncertainty: 1,
    }),
    /uncertainty must be an object/,
  );
  assert.throws(
    () => normalizeQuantityBound({
      quantity_id: "distance",
      unit: "mm",
      value: 10,
      uncertainty: { value: 1, unit: "ms" },
    }),
    /uncertainty.unit must be canonical mm/,
  );
  for (const uncertainty of [Number.NaN, Number.POSITIVE_INFINITY, -1]) {
    assert.throws(
      () => normalizeQuantityBound({
        quantity_id: "distance",
        unit: "mm",
        value: 10,
        uncertainty: { value: uncertainty, unit: "mm" },
      }),
      /finite number|must be >= 0/,
    );
  }
  assert.throws(
    () => normalizeQuantityBound(
      {
        quantity_id: "distance",
        unit: "mm",
        min: 0,
        max: 10,
        uncertainty: { value: 5, unit: "mm" },
      },
      "quantity_bound",
      { requireUsefulBound: true },
    ),
    /uncertainty band must be narrower/,
  );
  assert.throws(
    () => normalizeQuantityBound(
      {
        quantity_id: "angle",
        unit: "deg",
        value: 0,
        uncertainty: { value: 360000, unit: "deg" },
      },
      "angle_bound",
      { requireUsefulBound: true },
    ),
    /narrower than the registered dimension/,
  );
  assert.deepEqual(
    normalizeQuantityBound(
      { quantity_id: "rate", unit: "1/s", max: 12 },
      "rate_bound",
      { expectedQuantityId: "rate" },
    ),
    { quantity_id: "rate", unit: "1/s", max: 12 },
  );
  assert.throws(
    () => normalizeQuantityBound(
      { quantity_id: "cadence", unit: "Hz", max: 12 },
      "rate_bound",
      { expectedQuantityId: "rate" },
    ),
    /must be rate/,
  );
  assert.throws(
    () => normalizeQuantityBound(
      { quantity_id: "rate", unit: "Hz", max: 12 },
      "rate_bound",
      { expectedQuantityId: "rate" },
    ),
    /canonical 1\/s/,
  );
});

test("spatial envelopes bind pose, barriers, uncertainty, and measurement provenance", () => {
  const input = spatialEnvelopeFixture();
  const normalized = normalizeSpatialEnvelope(input);
  assert.deepEqual(normalized.barrier_refs, ["barrier:air-gap-1", "barrier:polycarbonate-1"]);
  assert.equal(normalized.orientation.quantity_id, "angle");
  assert.equal(spatialEnvelopeDigest(input), spatialEnvelopeDigest(clone(input)));
  const unknown = clone(input);
  unknown.room = "anything";
  assert.throws(() => normalizeSpatialEnvelope(unknown), /unknown fields: room/);
  const wrongDistance = clone(input);
  wrongDistance.distance.quantity_id = "duration";
  wrongDistance.distance.unit = "ms";
  assert.throws(() => normalizeSpatialEnvelope(wrongDistance), /must be distance/);
});

test("stimulus sequences preserve exact order and bind timing plus retry identity", () => {
  const input = stimulusSequenceFixture();
  const normalized = normalizeStimulusSequence(input);
  assert.deepEqual(normalized.steps.map((step) => step.step_id), ["negative_control", "candidate"]);
  assert.equal(stimulusSequenceDigest(input), stimulusSequenceDigest(clone(input)));
  const duplicate = clone(input);
  duplicate.steps[1].step_id = "negative_control";
  assert.throws(() => normalizeStimulusSequence(duplicate), /unique step_id/);
  const wrongTiming = clone(input);
  wrongTiming.steps[1].cadence.quantity_id = "frequency";
  assert.throws(() => normalizeStimulusSequence(wrongTiming), /must be cadence/);
});

test("requested effects resolve exact closed-registry envelope refs and bind content drift", () => {
  const first = rfFixture();
  const firstNormalized = normalizeRequestedEffect(first.input, first.registry);
  assert.equal(Object.isFrozen(first.physicalEnvelopeRegistry), true);
  assert.equal(typeof first.physicalEnvelopeRegistry.get, "undefined");
  assert.deepEqual(first.physicalEnvelopeRegistry.spatialEnvelopeRefs(), [
    "spatial-envelope:shielded-fixture-1",
  ]);
  assert.deepEqual(first.physicalEnvelopeRegistry.stimulusSequenceRefs(), [
    "stimulus-sequence:inventory-probe-1",
  ]);
  assert.throws(
    () => bindSpatialEnvelopeRef(
      "spatial-envelope:unregistered-fixture",
      first.physicalEnvelopeRegistry,
    ),
    /not registered exactly/,
  );
  assert.throws(
    () => bindStimulusSequenceRef(
      "stimulus-sequence:unregistered-probe",
      first.physicalEnvelopeRegistry,
    ),
    /not registered exactly/,
  );
  assert.throws(
    () => bindSpatialEnvelopeRef(
      "spatial-envelope:shielded-fixture-1",
      Object.freeze({ registry_digest: first.physicalEnvelopeRegistry.registry_digest }),
    ),
    /closed Bob registry/,
  );

  const prefixOnlyTemplate = rfTemplateDefinition();
  prefixOnlyTemplate.bounds.spatial_envelope_ref = {
    kind: "reference",
    required: true,
    ref_prefix: "spatial-envelope",
  };
  assert.throws(
    () => buildEffectTemplateRegistry(
      [prefixOnlyTemplate],
      { physicalEnvelopeRegistry: first.physicalEnvelopeRegistry },
    ),
    /must use a registered spatial-envelope bound kind/,
  );
  assert.throws(
    () => buildEffectTemplateRegistry([rfTemplateDefinition()]),
    /requires a closed physical envelope registry/,
  );

  const driftedSpatial = spatialEnvelopeFixture();
  driftedSpatial.distance.max = 90;
  const driftedPhysicalRegistry = physicalEnvelopeRegistryFixture({
    spatialEnvelope: driftedSpatial,
  });
  const driftedRegistry = buildEffectTemplateRegistry(
    [rfTemplateDefinition()],
    { physicalEnvelopeRegistry: driftedPhysicalRegistry },
  );
  const driftedInput = clone(first.input);
  driftedInput.template_digest = driftedRegistry.get("target.transmit.rf.v1").template_digest;
  const driftedNormalized = normalizeRequestedEffect(driftedInput, driftedRegistry);

  assert.notEqual(first.physicalEnvelopeRegistry.registry_digest, driftedPhysicalRegistry.registry_digest);
  assert.notEqual(first.input.template_digest, driftedInput.template_digest);
  assert.notEqual(
    firstNormalized.bounds.spatial_envelope_ref.definition_digest,
    driftedNormalized.bounds.spatial_envelope_ref.definition_digest,
  );
  assert.notEqual(
    requestedEffectDigest(first.input, first.registry),
    requestedEffectDigest(driftedInput, driftedRegistry),
  );

  const unknownSpatial = clone(first.input);
  unknownSpatial.bounds.spatial_envelope_ref = "spatial-envelope:plausible-but-unknown";
  assert.throws(
    () => normalizeRequestedEffect(unknownSpatial, first.registry),
    /not registered exactly/,
  );
  const unknownStimulus = clone(first.input);
  unknownStimulus.bounds.stimulus_sequence_ref = "stimulus-sequence:plausible-but-unknown";
  assert.throws(
    () => normalizeRequestedEffect(unknownStimulus, first.registry),
    /not registered exactly/,
  );
});

test("tool effect_surface is frozen nonauthorizing metadata with safe legacy consistency", () => {
  const base = {
    name: "bob_test_physical_effect",
    description: "Test physical effect metadata.",
    inputSchema: { type: "object", properties: {} },
    handler: () => ({}),
    role_bundles: ["evaluator-shared"],
    mutating: true,
    global_preapproval: false,
    network_access: false,
    browser_access: false,
    scope_required: false,
    sensitive_output: false,
    session_artifacts_written: [],
    effect_surface: ["target.transmit"],
  };
  const tool = buildToolRegistry({ toolModules: [base] })[0];
  assert.deepEqual(tool.effect_surface, ["target.transmit"]);
  assert.equal(Object.isFrozen(tool.effect_surface), true);
  const telemetry = buildToolTelemetryEvent({
    toolName: tool.name,
    tool,
    args: {},
    envelope: { ok: true, data: {} },
    elapsedMs: 1,
    bob_version: "test",
    now: new Date("2026-07-17T00:00:00.000Z"),
  });
  assert.deepEqual(telemetry.registry.effect_surface, ["target.transmit"]);
  assert.throws(
    () => buildToolRegistry({ toolModules: [{ ...base, mutating: false }] }),
    /effectful surface without mutating/,
  );
  assert.throws(
    () => buildToolRegistry({ toolModules: [{ ...base, effect_surface: ["target.teleport"] }] }),
    /not a registered effect surface/,
  );
  const observer = buildToolRegistry({
    toolModules: [{ ...base, mutating: false, effect_surface: ["instrument.observe"] }],
  })[0];
  assert.deepEqual(observer.effect_surface, ["instrument.observe"]);
  assert.deepEqual(normalizeEffectSurfaceMetadata(null), []);

  for (const [name, metadata] of Object.entries(TOOL_MANIFEST)) {
    assert.ok(Array.isArray(metadata.effect_surface), `${name} missing effect_surface`);
    assert.equal(Object.isFrozen(metadata.effect_surface), true, `${name} effect_surface is not frozen`);
  }
});

test("requested effect lists reject duplicate grants and preserve repeated surface projection", () => {
  const { registry, input } = rfFixture();
  assert.throws(() => normalizeRequestedEffects([input, clone(input)], registry), /duplicate effects/);
  const first = normalizeRequestedEffect(input, registry);
  const secondInput = clone(input);
  secondInput.subject_ref = "target:owned-fixture-2";
  const second = normalizeRequestedEffect(secondInput, registry);
  assert.deepEqual(projectLegacyEffectFlags([first, second]).effect_surface, ["target.transmit"]);
});
