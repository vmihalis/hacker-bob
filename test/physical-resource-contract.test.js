"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const {
  PHYSICAL_RESOURCE_BUNDLE_VERSION,
  assertReservationBindings,
  bindPhysicalResourceBundle,
  normalizePhysicalReservationReceipt,
  normalizePhysicalReservationRequest,
  normalizePhysicalResourceBundle,
  normalizePhysicalResourceBundleBinding,
  normalizeResourceRequirement,
  projectPhysicalReservationState,
} = require("../mcp/lib/physical-resource-contract.js");
const {
  PHYSICAL_QUANTITY_REGISTRY,
  physicalQuantityRegistryDigest,
} = require("../mcp/domains/physical/physical-quantities.js");
const { hashCanonicalJson } = require("../mcp/core/verification/verification-contracts.js");

const digest = (label) => hashCanonicalJson({ label });

function requirement(overrides = {}) {
  return {
    alias: "reader",
    resource_kind: "instrument",
    candidate_resource_refs: ["instrument:ultra-b", "instrument:ultra-a"],
    ownership: "exclusive",
    capacity_units: 1,
    capability_refs: ["capability:hf.inventory"],
    requested_effect_digests: [digest("instrument-observe")],
    constraints: [
      {
        constraint_id: "attempt_budget",
        bound: { quantity_id: "count", unit: "count", max: 8 },
      },
      {
        constraint_id: "thermal_ceiling",
        bound: { quantity_id: "temperature", unit: "degC", max: 60 },
      },
    ],
    required_state_epoch_digest: digest("reader-state"),
    mode_ref: "mode:reader",
    workspace_ref: "workspace:slot-1",
    compatibility_ref: "compatibility:hf-reader-v1",
    ...overrides,
  };
}

function bundle(overrides = {}) {
  return {
    version: PHYSICAL_RESOURCE_BUNDLE_VERSION,
    bundle_id: "hotel-key-inventory",
    requirements: [
      requirement(),
      {
        alias: "keycard",
        resource_kind: "target_media",
        candidate_resource_refs: ["media:authorized-test-card"],
        ownership: "exclusive",
        capacity_units: 1,
        capability_refs: [],
        requested_effect_digests: [],
        constraints: [{
          constraint_id: "attempt_budget",
          bound: { quantity_id: "count", unit: "count", max: 8 },
        }],
        required_state_epoch_digest: digest("card-custody-state"),
        custody_principal_ref: "principal:operator-a",
      },
      {
        alias: "witness",
        resource_kind: "observer",
        candidate_resource_refs: ["observer:camera-a"],
        ownership: "shared",
        capacity_units: 1,
        capability_refs: [],
        requested_effect_digests: [],
        constraints: [],
        independence_domain_ref: "independence-domain:observer-team",
        compatibility_ref: "compatibility:observer-readonly-v1",
      },
      {
        alias: "containment",
        resource_kind: "rf_zone",
        candidate_resource_refs: ["rf-zone:bench-a"],
        ownership: "exclusive",
        capacity_units: 1,
        capability_refs: [],
        requested_effect_digests: [],
        constraints: [{
          constraint_id: "rf_frequency",
          bound: { quantity_id: "frequency", unit: "Hz", min: 13_550_000, max: 13_570_000 },
        }],
        containment_ref: "containment:shield-box-a",
      },
      {
        alias: "operator",
        resource_kind: "operator_presence",
        candidate_resource_refs: ["principal:operator-a"],
        ownership: "exclusive",
        capacity_units: 1,
        capability_refs: [],
        requested_effect_digests: [],
        constraints: [],
        custody_principal_ref: "principal:operator-a",
      },
    ],
    attempt_budget: 8,
    duration_ms: 30_000,
    reservation_ttl_ms: 45_000,
    cooldown_ms: 5_000,
    preemption_policy: "before_effect_only",
    fairness_class: "authorized-keycard",
    batch_key: "hf-reader:slot-1",
    setup_cost_units: 3,
    spatial_envelope_ref: "spatial-envelope:bench-a",
    spatial_envelope_digest: digest("bench-envelope"),
    stimulus_sequence_ref: "stimulus-sequence:inventory-only",
    stimulus_sequence_digest: digest("inventory-sequence"),
    ...overrides,
  };
}

function reservationRequest(resourceBundle, overrides = {}) {
  return {
    version: 1,
    reservation_request_id: "reservation-request:one",
    node_id: "TG-cell-physical-one",
    contract_hash: digest("contract"),
    source_graph_hash: digest("graph"),
    session_nucleus_hash: digest("nucleus"),
    experiment_ref: "experiment:hotel-key-inventory",
    attempt_ref: "attempt:one",
    owner_principal_ref: "principal:broker",
    execution_principal_ref: "principal:worker",
    resource_bundle_digest: resourceBundle.resource_bundle_digest,
    requested_at: "2026-07-18T00:00:00.000Z",
    effect_not_before: "2026-07-18T00:00:01.000Z",
    effect_deadline: "2026-07-18T00:00:31.000Z",
    ...overrides,
  };
}

function receipt(request, resourceBundle, overrides = {}) {
  const allocations = resourceBundle.requirements.map((entry, index) => ({
    alias: entry.alias,
    resource_kind: entry.resource_kind,
    resource_ref: entry.candidate_resource_refs[0],
    ownership: entry.ownership,
    capacity_units: entry.capacity_units,
    state_epoch_digest: entry.required_state_epoch_digest || digest(`state-${entry.alias}`),
    fencing_generation: index + 1,
    fencing_token_hash: digest(`fence-${entry.alias}`),
  }));
  return {
    version: 1,
    reservation_ref: "reservation:one",
    broker_ref: "broker:physical-a",
    broker_epoch: 4,
    reservation_request_digest: request.reservation_request_digest,
    node_id: request.node_id,
    contract_hash: request.contract_hash,
    source_graph_hash: request.source_graph_hash,
    session_nucleus_hash: request.session_nucleus_hash,
    experiment_ref: request.experiment_ref,
    attempt_ref: request.attempt_ref,
    owner_principal_ref: request.owner_principal_ref,
    execution_principal_ref: request.execution_principal_ref,
    resource_bundle_digest: resourceBundle.resource_bundle_digest,
    inventory_digest: digest("inventory"),
    state: "held",
    sequence: 0,
    issued_at: "2026-07-18T00:00:00.500Z",
    updated_at: "2026-07-18T00:00:00.500Z",
    expires_at: "2026-07-18T00:00:36.000Z",
    allocations,
    ...overrides,
  };
}

test("physical quantity registry has a canonical battery-state dimension", () => {
  assert.deepEqual(PHYSICAL_QUANTITY_REGISTRY.battery_state, {
    canonical_unit: "ratio",
    min: 0,
    max: 1,
    integer: false,
  });
  assert.match(physicalQuantityRegistryDigest(), /^[a-f0-9]{64}$/);
});

test("resource bundles normalize deterministically and bind every scheduling dimension", () => {
  const first = normalizePhysicalResourceBundle(bundle());
  const second = normalizePhysicalResourceBundle(bundle({
    requirements: [...bundle().requirements].reverse(),
  }));
  assert.equal(first.resource_bundle_digest, second.resource_bundle_digest);
  assert.ok(Object.isFrozen(first));
  assert.ok(Object.isFrozen(first.requirements[0]));
  assert.equal(first.requirements.length, 5);
  assert.deepEqual(
    first.requirements.find((entry) => entry.alias === "reader").candidate_resource_refs,
    ["instrument:ultra-a", "instrument:ultra-b"],
  );
  assert.throws(
    () => normalizePhysicalResourceBundle({ ...bundle(), resource_bundle_digest: digest("wrong") }),
    /does not match normalized content/,
  );
});

test("compact resource-bundle bindings preserve the full bundle digest", () => {
  const resourceBundle = normalizePhysicalResourceBundle(bundle());
  const binding = bindPhysicalResourceBundle(resourceBundle, "resource-bundle:hotel-key-inventory");
  assert.deepEqual(binding, {
    version: 1,
    resource_bundle_ref: "resource-bundle:hotel-key-inventory",
    resource_bundle_digest: resourceBundle.resource_bundle_digest,
  });
  assert.ok(JSON.stringify(binding).length < 256);
  assert.throws(
    () => normalizePhysicalResourceBundleBinding({ ...binding, resource_bundle_ref: "artifact:escape" }),
    /resource-bundle: namespace/,
  );
});

test("resource requirements are closed and enforce kind-specific semantics", () => {
  assert.deepEqual(
    normalizeResourceRequirement(requirement({
      candidate_resource_refs: ["instrument:a_", "instrument:a0"],
    })).candidate_resource_refs,
    ["instrument:a0", "instrument:a_"],
  );
  assert.throws(
    () => normalizeResourceRequirement({ ...requirement(), arbitrary: true }),
    /unknown fields: arbitrary/,
  );
  assert.throws(
    () => normalizeResourceRequirement({ ...requirement(), capability_refs: [] }),
    /requires at least one capability_ref/,
  );
  assert.throws(
    () => normalizeResourceRequirement({
      ...requirement(),
      resource_kind: "observer",
      candidate_resource_refs: ["observer:one"],
      constraints: [],
    }),
    /only instrument requirements may carry capabilities/,
  );
  assert.throws(
    () => normalizeResourceRequirement({
      ...requirement(),
      constraints: [{
        constraint_id: "battery_floor",
        bound: { quantity_id: "battery_state", unit: "ratio", min: 0.5 },
      }],
    }),
    /not valid for instrument/,
  );
  assert.throws(
    () => normalizeResourceRequirement({
      ...requirement(),
      constraints: [{
        constraint_id: "power_budget",
        bound: { quantity_id: "energy", unit: "J", max: 10 },
      }],
    }),
    /quantity_id must be power/,
  );
  const accessor = requirement();
  Object.defineProperty(accessor, "mode_ref", { enumerable: true, get() { throw new Error("leak"); } });
  assert.throws(() => normalizeResourceRequirement(accessor), /enumerable data field/);
  const symbol = requirement();
  symbol[Symbol("hidden")] = "secret";
  assert.throws(() => normalizeResourceRequirement(symbol), /symbol fields/);

  let arrayGetterInvoked = false;
  const accessorArray = requirement();
  Object.defineProperty(accessorArray.candidate_resource_refs, "0", {
    enumerable: true,
    get() {
      arrayGetterInvoked = true;
      return "instrument:forbidden";
    },
  });
  assert.throws(() => normalizeResourceRequirement(accessorArray), /enumerable data field/);
  assert.equal(arrayGetterInvoked, false);
  const adornedArray = requirement();
  adornedArray.candidate_resource_refs.hidden = "instrument:forbidden";
  assert.throws(() => normalizeResourceRequirement(adornedArray), /adorned fields: hidden/);
  const sparseArray = requirement();
  delete sparseArray.candidate_resource_refs[0];
  assert.throws(() => normalizeResourceRequirement(sparseArray), /enumerable data field/);

  let nestedGetterInvoked = false;
  const nestedAccessor = requirement({
    constraints: [{
      constraint_id: "attempt_budget",
      bound: { quantity_id: "count", unit: "count" },
    }],
  });
  Object.defineProperty(nestedAccessor.constraints[0].bound, "max", {
    enumerable: true,
    get() {
      nestedGetterInvoked = true;
      return 8;
    },
  });
  assert.throws(() => normalizeResourceRequirement(nestedAccessor), /enumerable data field/);
  assert.equal(nestedGetterInvoked, false);
});

test("bundles reject duplicate aliases and TTLs that do not cover cooldown", () => {
  assert.throws(
    () => normalizePhysicalResourceBundle(bundle({
      requirements: [
        requirement(),
        requirement({ candidate_resource_refs: ["instrument:ultra-c"] }),
      ],
    })),
    /aliases must be unique/,
  );
  assert.throws(
    () => normalizePhysicalResourceBundle(bundle({ reservation_ttl_ms: 34_999 })),
    /must cover duration_ms plus cooldown_ms/,
  );
});

test("reservation requests bind graph, experiment, principals, bundle, and exact effect window", () => {
  const resourceBundle = normalizePhysicalResourceBundle(bundle());
  const request = normalizePhysicalReservationRequest(reservationRequest(resourceBundle));
  assert.match(request.reservation_request_digest, /^[a-f0-9]{64}$/);
  assert.ok(Object.isFrozen(request));
  assert.throws(
    () => normalizePhysicalReservationRequest(reservationRequest(resourceBundle, {
      effect_not_before: "2026-07-17T23:59:59.000Z",
    })),
    /cannot predate requested_at/,
  );
});

test("reservation receipts expose only fencing hashes and bind all-or-nothing allocations", () => {
  const resourceBundle = normalizePhysicalResourceBundle(bundle());
  const request = normalizePhysicalReservationRequest(reservationRequest(resourceBundle));
  const normalizedReceipt = normalizePhysicalReservationReceipt(receipt(request, resourceBundle));
  assert.equal(
    assertReservationBindings(normalizedReceipt, request, resourceBundle).receipt_digest,
    normalizedReceipt.receipt_digest,
  );
  const projection = projectPhysicalReservationState(normalizedReceipt);
  assert.equal(projection.allocation_count, resourceBundle.requirements.length);
  assert.equal(Object.prototype.hasOwnProperty.call(projection, "allocations"), false);
  assert.equal(JSON.stringify(normalizedReceipt).includes("fencing_token\""), false);
  assert.match(normalizedReceipt.receipt_digest, /^[a-f0-9]{64}$/);

  const missing = receipt(request, resourceBundle);
  missing.allocations = missing.allocations.slice(1);
  assert.throws(
    () => assertReservationBindings(missing, request, resourceBundle),
    /allocate every requirement exactly once/,
  );
  const substituted = receipt(request, resourceBundle);
  const readerIndex = substituted.allocations.findIndex((entry) => entry.alias === "reader");
  substituted.allocations[readerIndex] = {
    ...substituted.allocations[readerIndex],
    resource_ref: "instrument:not-enrolled",
  };
  assert.throws(
    () => assertReservationBindings(substituted, request, resourceBundle),
    /does not satisfy its exact requirement/,
  );
});

test("reservation binding rejects stale graph, overlong windows, short leases, and TTL widening", () => {
  const resourceBundle = normalizePhysicalResourceBundle(bundle());
  const request = normalizePhysicalReservationRequest(reservationRequest(resourceBundle));
  assert.throws(
    () => assertReservationBindings(
      receipt(request, resourceBundle, { source_graph_hash: digest("stale-graph") }),
      request,
      resourceBundle,
    ),
    /source_graph_hash binding drift/,
  );
  const longRequest = normalizePhysicalReservationRequest(reservationRequest(resourceBundle, {
    effect_deadline: "2026-07-18T00:00:32.000Z",
  }));
  assert.throws(
    () => assertReservationBindings(receipt(longRequest, resourceBundle), longRequest, resourceBundle),
    /effect window exceeds/,
  );
  assert.throws(
    () => assertReservationBindings(
      receipt(request, resourceBundle, { expires_at: "2026-07-18T00:00:35.999Z" }),
      request,
      resourceBundle,
    ),
    /does not cover the effect window and cooldown/,
  );
  assert.throws(
    () => assertReservationBindings(
      receipt(request, resourceBundle, { expires_at: "2026-07-18T00:00:45.501Z" }),
      request,
      resourceBundle,
    ),
    /exceeds the resource bundle TTL/,
  );
});

test("fencing hashes cannot be reused across different resources", () => {
  const resourceBundle = normalizePhysicalResourceBundle(bundle());
  const request = normalizePhysicalReservationRequest(reservationRequest(resourceBundle));
  const reusedFence = receipt(request, resourceBundle);
  reusedFence.allocations[1] = {
    ...reusedFence.allocations[1],
    fencing_token_hash: reusedFence.allocations[0].fencing_token_hash,
  };
  assert.throws(
    () => assertReservationBindings(reusedFence, request, resourceBundle),
    /reused across resources/,
  );
});

test("shared reservation receipts reject incompatible mode and compatibility requirements", () => {
  const sharedRequirement = (alias, compatibilityRef, modeRef) => requirement({
    alias,
    candidate_resource_refs: ["instrument:shared-reader"],
    ownership: "shared",
    compatibility_ref: compatibilityRef,
    mode_ref: modeRef,
    workspace_ref: "workspace:slot-1",
  });
  const incompatibleBundle = normalizePhysicalResourceBundle(bundle({
    requirements: [
      sharedRequirement("left", "compatibility:left", "mode:reader"),
      sharedRequirement("right", "compatibility:right", "mode:reader"),
    ],
  }));
  const incompatibleRequest = normalizePhysicalReservationRequest(reservationRequest(incompatibleBundle));
  const incompatibleReceipt = receipt(incompatibleRequest, incompatibleBundle);
  const left = incompatibleReceipt.allocations.find((entry) => entry.alias === "left");
  incompatibleReceipt.allocations = incompatibleReceipt.allocations.map((entry) => (
    entry.alias === "right"
      ? {
        ...entry,
        fencing_generation: left.fencing_generation,
        fencing_token_hash: left.fencing_token_hash,
        state_epoch_digest: left.state_epoch_digest,
      }
      : entry
  ));
  assert.throws(
    () => assertReservationBindings(incompatibleReceipt, incompatibleRequest, incompatibleBundle),
    /incompatible requirements/,
  );

  const modeConflictBundle = normalizePhysicalResourceBundle(bundle({
    requirements: [
      sharedRequirement("left", "compatibility:reader", "mode:left"),
      sharedRequirement("right", "compatibility:reader", "mode:right"),
    ],
  }));
  const modeConflictRequest = normalizePhysicalReservationRequest(reservationRequest(modeConflictBundle));
  const modeConflictReceipt = receipt(modeConflictRequest, modeConflictBundle);
  const first = modeConflictReceipt.allocations.find((entry) => entry.alias === "left");
  modeConflictReceipt.allocations = modeConflictReceipt.allocations.map((entry) => (
    entry.alias === "right"
      ? {
        ...entry,
        fencing_generation: first.fencing_generation,
        fencing_token_hash: first.fencing_token_hash,
        state_epoch_digest: first.state_epoch_digest,
      }
      : entry
  ));
  assert.throws(
    () => assertReservationBindings(modeConflictReceipt, modeConflictRequest, modeConflictBundle),
    /conflicting mode_ref requirements/,
  );
});

test("terminal receipts require closure and cleanup-pending receipts require a handoff", () => {
  const resourceBundle = normalizePhysicalResourceBundle(bundle());
  const request = normalizePhysicalReservationRequest(reservationRequest(resourceBundle));
  assert.throws(
    () => normalizePhysicalReservationReceipt(receipt(request, resourceBundle, { state: "released", sequence: 1 })),
    /canonical UTC timestamp/,
  );
  assert.throws(
    () => normalizePhysicalReservationReceipt(receipt(request, resourceBundle, {
      state: "cleanup_pending",
      sequence: 1,
    })),
    /namespaced opaque reference/,
  );
  const cleanupPending = normalizePhysicalReservationReceipt(receipt(request, resourceBundle, {
    state: "cleanup_pending",
    sequence: 1,
    cleanup_handoff_ref: "cleanup-handoff:one",
  }));
  assert.equal(cleanupPending.state, "cleanup_pending");
  const released = normalizePhysicalReservationReceipt(receipt(request, resourceBundle, {
    state: "released",
    sequence: 2,
    updated_at: "2026-07-18T00:00:36.000Z",
    closed_at: "2026-07-18T00:00:36.000Z",
    terminal_disposition: "cleanup_confirmed",
  }));
  assert.equal(released.terminal_disposition, "cleanup_confirmed");
});
