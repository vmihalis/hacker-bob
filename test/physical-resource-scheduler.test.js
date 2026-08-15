"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

const {
  normalizePhysicalResourceBundle,
} = require("../mcp/lib/physical-resource-contract.js");
const {
  MAX_RESOURCE_INVENTORY_VALIDITY_MS,
  normalizePhysicalResourceInventory,
  planPhysicalResourceBundle,
} = require("../mcp/domains/physical/physical-resource-scheduler.js");
const {
  MAX_UNCERTAINTY_MS,
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  createPhysicalTrustedClockPort,
  physicalClockMappingSigningMessage,
  publicKeyDigest,
  samplePhysicalTrustedClock,
} = require("../mcp/domains/physical/physical-trusted-clock.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");

const digest = (label) => hashCanonicalJson({ label });

function createTrustedClockFixture() {
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const payload = {
    version: 1,
    clock_id: "physical-clock:resource-scheduler-test",
    monotonic_epoch_id: digest("resource-scheduler-monotonic-epoch"),
    mapping_generation: 1,
    reference_monotonic_ms: 1_000,
    reference_utc: "2026-07-18T00:00:01.000Z",
    max_uncertainty_ms: 10,
    not_before: "2026-07-17T23:55:00.000Z",
    expires_at: "2026-07-18T00:10:00.000Z",
    trust_root_epoch: 2,
    authority_epoch: 3,
    revocation_generation: 0,
    signer_key_id: "clock-key:resource-scheduler-test",
    signer_public_key_digest: publicKeyDigest(keyPair.publicKey),
  };
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    physicalClockMappingSigningMessage(payloadDigest),
    keyPair.privateKey,
  ).toString("base64url");
  const basis = {
    version: 1,
    domain: TRUSTED_CLOCK_MAPPING_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
  };
  const mapping = {
    ...basis,
    signed_mapping_digest: hashCanonicalJson(basis),
  };
  const trust = {
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
  };
  const port = createPhysicalTrustedClockPort({
    port_id: "resource_scheduler_test_clock",
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    uncertainty_ceiling_ms: MAX_UNCERTAINTY_MS,
    read_monotonic_ms: () => 1_000,
    read_signed_mapping: () => mapping,
    resolve_current_trust: () => trust,
  });
  return { port, sample: samplePhysicalTrustedClock(port) };
}

const TRUSTED_CLOCK = createTrustedClockFixture();

function requirement(alias, candidateResourceRefs, overrides = {}) {
  return {
    alias,
    resource_kind: "instrument",
    candidate_resource_refs: candidateResourceRefs,
    ownership: "exclusive",
    capacity_units: 1,
    capability_refs: ["capability:physical.test"],
    requested_effect_digests: [digest(`effect-${alias}`)],
    constraints: [],
    ...overrides,
  };
}

function bundle(requirements, overrides = {}) {
  return normalizePhysicalResourceBundle({
    version: 1,
    bundle_id: "scheduler-test",
    requirements,
    attempt_budget: 4,
    duration_ms: 30_000,
    reservation_ttl_ms: 35_000,
    cooldown_ms: 5_000,
    preemption_policy: "before_effect_only",
    fairness_class: "scheduler-test",
    batch_key: "scheduler:test",
    setup_cost_units: 0,
    ...overrides,
  });
}

function request(resourceBundle, overrides = {}) {
  return {
    version: 1,
    reservation_request_id: "reservation-request:scheduler-test",
    node_id: "TG-cell-resource-scheduler-test",
    contract_hash: digest("scheduler-contract"),
    source_graph_hash: digest("scheduler-graph"),
    session_nucleus_hash: digest("scheduler-nucleus"),
    experiment_ref: "experiment:scheduler-test",
    attempt_ref: "attempt:scheduler-test",
    owner_principal_ref: "principal:scheduler-broker",
    execution_principal_ref: "principal:scheduler-worker",
    resource_bundle_digest: resourceBundle.resource_bundle_digest,
    requested_at: "2026-07-18T00:00:00.000Z",
    effect_not_before: "2026-07-18T00:00:02.000Z",
    effect_deadline: "2026-07-18T00:00:32.000Z",
    ...overrides,
  };
}

function inventoryResource(resourceBundle, resourceRef, aliases, overrides = {}) {
  const aliasSet = new Set(aliases);
  const eligible = resourceBundle.requirements
    .filter((entry) => aliasSet.has(entry.alias))
    .map((entry) => hashCanonicalJson(entry));
  const first = resourceBundle.requirements.find((entry) => aliasSet.has(entry.alias));
  if (!first) throw new Error(`test fixture has no requirement for ${resourceRef}`);
  return {
    resource_kind: first.resource_kind,
    resource_ref: resourceRef,
    state_epoch_digest: digest(`state-${resourceRef}`),
    availability: "available",
    total_capacity_units: 1,
    available_capacity_units: 1,
    exclusive_available: true,
    fencing_generation: 7,
    setup_cost_units: 0,
    eligible_requirement_digests: eligible,
    switchable_mode_refs: [],
    switchable_workspace_refs: [],
    ...overrides,
  };
}

function inventory(resourceBundle, resources, overrides = {}) {
  return {
    version: 1,
    broker_ref: "broker:physical-test",
    broker_epoch: 3,
    inventory_generation: 11,
    captured_at: "2026-07-18T00:00:00.500Z",
    valid_from: "2026-07-18T00:00:00.000Z",
    expires_at: "2026-07-18T00:00:10.000Z",
    session_nucleus_hash: digest("scheduler-nucleus"),
    source_graph_hash: digest("scheduler-graph"),
    resources,
    ...overrides,
  };
}

function options(overrides = {}) {
  return { trusted_clock_port: TRUSTED_CLOCK.port, ...overrides };
}

function plan(resourceBundle, reservationRequest, resourceInventory, overrides = {}) {
  return planPhysicalResourceBundle(
    resourceBundle,
    reservationRequest,
    resourceInventory,
    options(overrides),
  );
}

function backtrackingFixture() {
  const resourceBundle = bundle([
    requirement("a", ["instrument:r1", "instrument:r2"]),
    requirement("b", ["instrument:r1", "instrument:r3"]),
    requirement("c", ["instrument:r1", "instrument:r3"]),
  ]);
  const resources = [
    inventoryResource(resourceBundle, "instrument:r1", ["a", "b", "c"]),
    inventoryResource(resourceBundle, "instrument:r2", ["a"]),
    inventoryResource(resourceBundle, "instrument:r3", ["b", "c"]),
  ];
  return {
    resourceBundle,
    reservationRequest: request(resourceBundle),
    resourceInventory: inventory(resourceBundle, resources),
  };
}

test("planner tie-breaking uses locale-independent protocol code-unit order", () => {
  const resourceBundle = bundle([
    requirement("reader", ["instrument:a_", "instrument:a0"]),
  ]);
  const result = plan(
    resourceBundle,
    request(resourceBundle),
    inventory(resourceBundle, [
      inventoryResource(resourceBundle, "instrument:a_", ["reader"]),
      inventoryResource(resourceBundle, "instrument:a0", ["reader"]),
    ]),
  );
  assert.equal(result.disposition, "planned");
  assert.equal(result.allocations[0].resource_ref, "instrument:a0");
});

test("allocation is deterministic across bundle and inventory input order and uses total lock order", () => {
  const firstBundle = bundle([
    requirement("zeta", ["instrument:z"]),
    requirement("alpha", ["instrument:a"]),
  ]);
  const secondBundle = bundle([...firstBundle.requirements].reverse());
  const resources = [
    inventoryResource(firstBundle, "instrument:z", ["zeta"]),
    inventoryResource(firstBundle, "instrument:a", ["alpha"]),
  ];
  const first = plan(firstBundle, request(firstBundle), inventory(firstBundle, resources));
  const second = plan(
    secondBundle,
    request(secondBundle),
    inventory(secondBundle, [...resources].reverse()),
  );

  assert.deepEqual(first, second);
  assert.equal(first.disposition, "planned");
  assert.deepEqual(first.allocations.map((entry) => entry.alias), ["alpha", "zeta"]);
  assert.deepEqual(first.lock_order, ["instrument:a", "instrument:z"]);
  assert.equal(first.inventory_digest, normalizePhysicalResourceInventory(
    inventory(firstBundle, resources),
  ).inventory_digest);
  assert.equal(first.trusted_clock_sample_digest, hashCanonicalJson(TRUSTED_CLOCK.sample));
  assert.ok(Object.isFrozen(first));
  assert.ok(Object.isFrozen(first.allocations));
});

test("planner backtracks instead of treating a greedy exclusive choice as unschedulable", () => {
  const fixture = backtrackingFixture();
  const result = plan(
    fixture.resourceBundle,
    fixture.reservationRequest,
    fixture.resourceInventory,
  );
  assert.equal(result.disposition, "planned");
  assert.deepEqual(
    Object.fromEntries(result.allocations.map((entry) => [entry.alias, entry.resource_ref])),
    { a: "instrument:r2", b: "instrument:r1", c: "instrument:r3" },
  );
  assert.ok(result.planner_steps > result.allocations.length);
});

test("atomic conflicts return no partial allocation, lock, setup, reservation, or coverage credit", () => {
  const resourceBundle = bundle([
    requirement("a", ["instrument:r1", "instrument:r2"]),
    requirement("b", ["instrument:r1", "instrument:r2"]),
    requirement("c", ["instrument:r1", "instrument:r2"]),
  ]);
  const result = plan(resourceBundle, request(resourceBundle), inventory(resourceBundle, [
    inventoryResource(resourceBundle, "instrument:r1", ["a", "b", "c"]),
    inventoryResource(resourceBundle, "instrument:r2", ["a", "b", "c"]),
  ]));
  assert.equal(result.disposition, "unschedulable");
  assert.equal(result.reason, "atomic_conflict");
  assert.deepEqual(result.blocked_aliases, ["a", "b", "c"]);
  assert.deepEqual(result.allocations, []);
  assert.deepEqual(result.lock_order, []);
  assert.equal(result.setup_cost_units, 0);
  for (const forbidden of ["reservation_ref", "fencing_token", "coverage_credit", "covered"]) {
    assert.equal(Object.prototype.hasOwnProperty.call(result, forbidden), false);
  }
});

test("exclusive and shared claims cannot overlap one physical resource", () => {
  const resourceBundle = bundle([
    requirement("exclusive", ["instrument:shared"]),
    requirement("shared", ["instrument:shared"], {
      ownership: "shared",
      compatibility_ref: "compatibility:reader-v1",
    }),
  ]);
  const result = plan(resourceBundle, request(resourceBundle), inventory(resourceBundle, [
    inventoryResource(resourceBundle, "instrument:shared", ["exclusive", "shared"], {
      total_capacity_units: 2,
      available_capacity_units: 2,
    }),
  ]));
  assert.equal(result.reason, "atomic_conflict");
  assert.deepEqual(result.allocations, []);
});

test("compatible shared claims consume capacity and share one fence generation", () => {
  const resourceBundle = bundle([
    requirement("left", ["instrument:shared"], {
      ownership: "shared",
      capacity_units: 2,
      compatibility_ref: "compatibility:reader-v1",
    }),
    requirement("right", ["instrument:shared"], {
      ownership: "shared",
      capacity_units: 2,
      compatibility_ref: "compatibility:reader-v1",
    }),
  ]);
  const resource = inventoryResource(resourceBundle, "instrument:shared", ["left", "right"], {
    total_capacity_units: 4,
    available_capacity_units: 4,
  });
  const result = plan(resourceBundle, request(resourceBundle), inventory(resourceBundle, [resource]));
  assert.equal(result.disposition, "planned");
  assert.deepEqual(result.lock_order, ["instrument:shared"]);
  assert.deepEqual(
    [...new Set(result.allocations.map((entry) => entry.expected_fencing_generation))],
    [8],
  );

  const overCapacityBundle = bundle(resourceBundle.requirements.map((entry) => ({
    ...entry,
    capacity_units: 3,
  })));
  const overCapacity = plan(
    overCapacityBundle,
    request(overCapacityBundle),
    inventory(overCapacityBundle, [inventoryResource(
      overCapacityBundle,
      "instrument:shared",
      ["left", "right"],
      { total_capacity_units: 4, available_capacity_units: 4 },
    )]),
  );
  assert.equal(overCapacity.reason, "atomic_conflict");
  assert.deepEqual(overCapacity.allocations, []);
});

test("shared compatibility is exact for both existing and same-plan holders", () => {
  const incompatibleBundle = bundle([
    requirement("left", ["instrument:shared"], {
      ownership: "shared",
      compatibility_ref: "compatibility:left",
    }),
    requirement("right", ["instrument:shared"], {
      ownership: "shared",
      compatibility_ref: "compatibility:right",
    }),
  ]);
  const incompatible = plan(
    incompatibleBundle,
    request(incompatibleBundle),
    inventory(incompatibleBundle, [inventoryResource(
      incompatibleBundle,
      "instrument:shared",
      ["left", "right"],
      { total_capacity_units: 2, available_capacity_units: 2 },
    )]),
  );
  assert.equal(incompatible.reason, "atomic_conflict");

  const compatibleBundle = bundle([
    requirement("next", ["instrument:shared"], {
      ownership: "shared",
      compatibility_ref: "compatibility:reader-v1",
    }),
  ]);
  const partial = inventoryResource(compatibleBundle, "instrument:shared", ["next"], {
    total_capacity_units: 4,
    available_capacity_units: 2,
    exclusive_available: false,
    active_shared_compatibility_ref: "compatibility:reader-v1",
  });
  assert.equal(
    plan(compatibleBundle, request(compatibleBundle), inventory(compatibleBundle, [partial])).disposition,
    "planned",
  );
  const drifted = { ...partial, active_shared_compatibility_ref: "compatibility:other" };
  assert.equal(
    plan(compatibleBundle, request(compatibleBundle), inventory(compatibleBundle, [drifted])).reason,
    "no_eligible_candidate",
  );
  const missing = { ...partial };
  delete missing.active_shared_compatibility_ref;
  assert.throws(
    () => normalizePhysicalResourceInventory(inventory(compatibleBundle, [missing])),
    /partial available capacity requires active_shared_compatibility_ref/,
  );
});

test("shared aliases batch one identical mode/workspace transition and reject conflicting setup states", () => {
  const shared = (alias, modeRef, workspaceRef = "workspace:new") => requirement(alias, ["instrument:shared"], {
    ownership: "shared",
    compatibility_ref: "compatibility:reader-v1",
    mode_ref: modeRef,
    workspace_ref: workspaceRef,
  });
  const resourceBundle = bundle([shared("left", "mode:new"), shared("right", "mode:new")]);
  const resource = inventoryResource(resourceBundle, "instrument:shared", ["left", "right"], {
    total_capacity_units: 2,
    available_capacity_units: 2,
    setup_cost_units: 7,
    current_mode_ref: "mode:old",
    current_workspace_ref: "workspace:old",
    switchable_mode_refs: ["mode:new"],
    switchable_workspace_refs: ["workspace:new"],
  });
  const result = plan(resourceBundle, request(resourceBundle), inventory(resourceBundle, [resource]));
  assert.equal(result.disposition, "planned");
  assert.equal(result.setup_cost_units, 14);
  assert.equal(result.allocations.filter((entry) => entry.mode_change).length, 1);
  assert.equal(result.allocations.filter((entry) => entry.workspace_change).length, 1);
  assert.equal(result.allocations.reduce((sum, entry) => sum + entry.setup_cost_units, 0), 14);

  const alreadyConfigured = plan(
    resourceBundle,
    request(resourceBundle),
    inventory(resourceBundle, [{
      ...resource,
      current_mode_ref: "mode:new",
      current_workspace_ref: "workspace:new",
    }]),
  );
  assert.equal(alreadyConfigured.setup_cost_units, 0);
  assert.equal(alreadyConfigured.allocations.some((entry) => entry.mode_change), false);
  assert.equal(alreadyConfigured.allocations.some((entry) => entry.workspace_change), false);

  const conflictBundle = bundle([shared("left", "mode:left"), shared("right", "mode:right")]);
  const conflictResource = inventoryResource(
    conflictBundle,
    "instrument:shared",
    ["left", "right"],
    {
      total_capacity_units: 2,
      available_capacity_units: 2,
      setup_cost_units: 7,
      current_mode_ref: "mode:old",
      current_workspace_ref: "workspace:old",
      switchable_mode_refs: ["mode:left", "mode:right"],
      switchable_workspace_refs: ["workspace:new"],
    },
  );
  const conflict = plan(
    conflictBundle,
    request(conflictBundle),
    inventory(conflictBundle, [conflictResource]),
  );
  assert.equal(conflict.reason, "atomic_conflict");
  assert.deepEqual(conflict.allocations, []);

  const workspaceConflictBundle = bundle([
    shared("left", "mode:new", "workspace:left"),
    shared("right", "mode:new", "workspace:right"),
  ]);
  const workspaceConflictResource = inventoryResource(
    workspaceConflictBundle,
    "instrument:shared",
    ["left", "right"],
    {
      total_capacity_units: 2,
      available_capacity_units: 2,
      current_mode_ref: "mode:new",
      current_workspace_ref: "workspace:old",
      switchable_workspace_refs: ["workspace:left", "workspace:right"],
    },
  );
  assert.equal(plan(
    workspaceConflictBundle,
    request(workspaceConflictBundle),
    inventory(workspaceConflictBundle, [workspaceConflictResource]),
  ).reason, "atomic_conflict");
});

test("dynamic setup ordering batches a flexible alias onto the already-configured compatible resource", () => {
  const shared = (alias, candidates) => requirement(alias, candidates, {
    ownership: "shared",
    compatibility_ref: "compatibility:reader-v1",
    mode_ref: "mode:new",
  });
  const resourceBundle = bundle([
    shared("fixed", ["instrument:r2"]),
    shared("flexible", ["instrument:r1", "instrument:r2"]),
  ]);
  const resources = [
    inventoryResource(resourceBundle, "instrument:r1", ["flexible"], {
      total_capacity_units: 2,
      available_capacity_units: 2,
      current_mode_ref: "mode:old",
      switchable_mode_refs: ["mode:new"],
      setup_cost_units: 9,
    }),
    inventoryResource(resourceBundle, "instrument:r2", ["fixed", "flexible"], {
      total_capacity_units: 2,
      available_capacity_units: 2,
      current_mode_ref: "mode:old",
      switchable_mode_refs: ["mode:new"],
      setup_cost_units: 9,
    }),
  ];
  const result = plan(resourceBundle, request(resourceBundle), inventory(resourceBundle, resources));
  assert.equal(result.disposition, "planned");
  assert.deepEqual(result.allocations.map((entry) => entry.resource_ref), [
    "instrument:r2",
    "instrument:r2",
  ]);
  assert.equal(result.setup_cost_units, 9);
  assert.deepEqual(result.lock_order, ["instrument:r2"]);
});

test("setup transitions fail closed for active shared holders and exact state epochs", () => {
  const activeBundle = bundle([
    requirement("next", ["instrument:shared"], {
      ownership: "shared",
      compatibility_ref: "compatibility:reader-v1",
      mode_ref: "mode:new",
    }),
  ]);
  const active = inventoryResource(activeBundle, "instrument:shared", ["next"], {
    total_capacity_units: 2,
    available_capacity_units: 1,
    exclusive_available: false,
    active_shared_compatibility_ref: "compatibility:reader-v1",
    current_mode_ref: "mode:old",
    switchable_mode_refs: ["mode:new"],
  });
  assert.equal(
    plan(activeBundle, request(activeBundle), inventory(activeBundle, [active])).reason,
    "no_eligible_candidate",
  );

  const stateDigest = digest("required-state");
  const stateBundle = bundle([
    requirement("exact", ["instrument:exact"], {
      required_state_epoch_digest: stateDigest,
      mode_ref: "mode:new",
    }),
  ]);
  const stale = inventoryResource(stateBundle, "instrument:exact", ["exact"], {
    state_epoch_digest: digest("stale-state"),
    current_mode_ref: "mode:old",
    switchable_mode_refs: ["mode:new"],
  });
  assert.equal(
    plan(stateBundle, request(stateBundle), inventory(stateBundle, [stale])).reason,
    "no_eligible_candidate",
  );
  const exactButTransitioning = { ...stale, state_epoch_digest: stateDigest };
  assert.equal(
    plan(
      stateBundle,
      request(stateBundle),
      inventory(stateBundle, [exactButTransitioning]),
    ).reason,
    "no_eligible_candidate",
  );
});

test("graph, nucleus, bundle, request-time, deadline, and effect-window drift fail before search", () => {
  const resourceBundle = bundle([requirement("only", ["instrument:one"])]);
  const resource = inventoryResource(resourceBundle, "instrument:one", ["only"]);
  const baseInventory = inventory(resourceBundle, [resource]);
  const cases = [
    [request(resourceBundle, { resource_bundle_digest: digest("wrong-bundle") }), baseInventory],
    [request(resourceBundle), { ...baseInventory, source_graph_hash: digest("wrong-graph") }],
    [request(resourceBundle), { ...baseInventory, session_nucleus_hash: digest("wrong-nucleus") }],
    [request(resourceBundle, { effect_deadline: "2026-07-18T00:00:32.001Z" }), baseInventory],
    [request(resourceBundle, {
      requested_at: "2026-07-18T00:00:01.000Z",
      effect_not_before: "2026-07-18T00:00:02.000Z",
    }), baseInventory],
    [request(resourceBundle, {
      effect_not_before: "2026-07-18T00:00:00.500Z",
      effect_deadline: "2026-07-18T00:00:01.000Z",
    }), baseInventory],
  ];
  for (const [reservationRequest, resourceInventory] of cases) {
    const result = plan(resourceBundle, reservationRequest, resourceInventory);
    assert.equal(result.reason, "binding_drift");
    assert.equal(result.planner_steps, 0);
    assert.deepEqual(result.allocations, []);
  }
});

test("inventory freshness is conservative over the full trusted-time uncertainty interval", () => {
  const resourceBundle = bundle([requirement("only", ["instrument:one"])]);
  const resource = inventoryResource(resourceBundle, "instrument:one", ["only"]);
  const stale = inventory(resourceBundle, [resource], {
    expires_at: "2026-07-18T00:00:01.010Z",
  });
  const stalePlan = plan(resourceBundle, request(resourceBundle), stale);
  assert.equal(stalePlan.reason, "inventory_not_current");
  assert.equal(stalePlan.planner_steps, 0);

  const future = inventory(resourceBundle, [resource], {
    captured_at: "2026-07-18T00:00:01.000Z",
    valid_from: "2026-07-18T00:00:01.000Z",
  });
  assert.equal(plan(resourceBundle, request(resourceBundle), future).reason, "inventory_not_current");

  assert.throws(
    () => normalizePhysicalResourceInventory(inventory(resourceBundle, [resource], {
      expires_at: new Date(
        Date.parse("2026-07-18T00:00:00.500Z") + MAX_RESOURCE_INVENTORY_VALIDITY_MS + 1,
      ).toISOString(),
    })),
    /expires_at must be within/,
  );
  assert.throws(
    () => planPhysicalResourceBundle(
      resourceBundle,
      request(resourceBundle),
      inventory(resourceBundle, [resource]),
      { trusted_clock_port: { ...TRUSTED_CLOCK.port } },
    ),
    /privately branded live port/,
  );
  assert.throws(
    () => planPhysicalResourceBundle(resourceBundle, request(resourceBundle), inventory(resourceBundle, [resource])),
    /missing fields: trusted_clock_port/,
  );
});

test("inventory digest and generation are exact plan bindings", () => {
  const resourceBundle = bundle([requirement("only", ["instrument:one"])]);
  const resource = inventoryResource(resourceBundle, "instrument:one", ["only"]);
  const firstInventory = inventory(resourceBundle, [resource]);
  assert.throws(
    () => normalizePhysicalResourceInventory({ ...firstInventory, inventory_digest: digest("wrong") }),
    /inventory_digest does not match/,
  );
  const first = plan(resourceBundle, request(resourceBundle), firstInventory);
  const next = plan(
    resourceBundle,
    request(resourceBundle),
    { ...firstInventory, inventory_generation: 12 },
  );
  assert.notEqual(first.inventory_digest, next.inventory_digest);
  assert.notEqual(first.allocation_plan_digest, next.allocation_plan_digest);
  assert.equal(next.inventory_generation, 12);
});

test("planner budget is a hard cap and exhaustion never returns a partial feasible prefix", () => {
  const fixture = backtrackingFixture();
  const exhausted = plan(
    fixture.resourceBundle,
    fixture.reservationRequest,
    fixture.resourceInventory,
    { max_steps: 1 },
  );
  assert.equal(exhausted.reason, "planner_budget_exhausted");
  assert.equal(exhausted.planner_steps, 1);
  assert.deepEqual(exhausted.allocations, []);
  assert.deepEqual(exhausted.lock_order, []);
  assert.throws(
    () => planPhysicalResourceBundle(
      fixture.resourceBundle,
      fixture.reservationRequest,
      fixture.resourceInventory,
      options({ max_steps: 0 }),
    ),
    /max_steps must be a safe integer/,
  );
});

test("planner and inventory schemas reject unknown, accessor, symbol, and option fields", () => {
  const resourceBundle = bundle([requirement("only", ["instrument:one"])]);
  const resource = inventoryResource(resourceBundle, "instrument:one", ["only"]);
  assert.throws(
    () => normalizePhysicalResourceInventory({ ...inventory(resourceBundle, [resource]), extra: true }),
    /unknown fields: extra/,
  );
  assert.throws(
    () => normalizePhysicalResourceInventory(inventory(resourceBundle, [{ ...resource, extra: true }])),
    /unknown fields: extra/,
  );
  let getterInvoked = false;
  const accessorResource = { ...resource };
  Object.defineProperty(accessorResource, "current_mode_ref", {
    enumerable: true,
    get() {
      getterInvoked = true;
      return "mode:unsafe";
    },
  });
  assert.throws(
    () => normalizePhysicalResourceInventory(inventory(resourceBundle, [accessorResource])),
    /enumerable data field/,
  );
  assert.equal(getterInvoked, false);
  const symbolInventory = inventory(resourceBundle, [resource]);
  symbolInventory[Symbol("hidden")] = true;
  assert.throws(() => normalizePhysicalResourceInventory(symbolInventory), /symbol fields/);
  assert.throws(
    () => planPhysicalResourceBundle(
      resourceBundle,
      request(resourceBundle),
      inventory(resourceBundle, [resource]),
      options({ arbitrary: true }),
    ),
    /unknown fields: arbitrary/,
  );
});
