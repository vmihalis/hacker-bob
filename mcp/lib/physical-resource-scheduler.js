"use strict";

// Plane-PH PH-S11 deterministic allocation planner. It consumes an exact,
// broker-attested inventory snapshot and an immutable resource bundle, then
// produces either one complete allocation plan or an explicit unschedulable
// disposition. It never reserves a resource or mints a fencing credential;
// those mutations belong to the broker's atomic reservation port.

const {
  RESOURCE_KIND_VALUES,
  RESOURCE_REF_PREFIX,
  normalizePhysicalReservationRequest,
  normalizePhysicalResourceBundle,
} = require("./physical-resource-contract.js");
const {
  normalizeOpaqueRef,
} = require("./physical-quantities.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  samplePhysicalTrustedClock,
} = require("./physical-trusted-clock.js");

const PHYSICAL_RESOURCE_INVENTORY_VERSION = 1;
const PHYSICAL_ALLOCATION_PLAN_VERSION = 1;
const RESOURCE_AVAILABILITY_VALUES = Object.freeze([
  "available",
  "degraded",
  "quarantined",
  "unavailable",
]);
const ALLOCATION_PLAN_DISPOSITION_VALUES = Object.freeze([
  "planned",
  "unschedulable",
]);
const UNSCHEDULABLE_REASON_VALUES = Object.freeze([
  "atomic_conflict",
  "binding_drift",
  "inventory_not_current",
  "no_eligible_candidate",
  "planner_budget_exhausted",
]);
const MAX_PLANNER_STEPS = 250_000;
const MAX_RESOURCE_INVENTORY_VALIDITY_MS = 60_000;

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) throw new Error(`${label} cannot contain symbol fields`);
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

function assertDenseDataArray(value, label, minimum, maximum) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    throw new Error(`${label} must be an array with ${minimum}-${maximum} entries`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([
    "length",
    ...Array.from({ length: value.length }, (_, index) => String(index)),
  ]);
  const unknown = keys.filter((key) => !allowed.has(key)).sort();
  if (unknown.length > 0) throw new Error(`${label} has adorned fields: ${unknown.join(", ")}`);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${label}[${index}] must be an enumerable data field`);
    }
  }
  return value;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function assertEnum(value, values, label) {
  if (!values.includes(value)) throw new Error(`${label} must be one of ${values.join(", ")}`);
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertInteger(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function assertBoolean(value, label) {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
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

function comparePhysicalResourceProtocolStrings(left, right) {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

function normalizeSortedUnique(value, label, normalize, { minimum = 0, maximum = 256 } = {}) {
  assertDenseDataArray(value, label, minimum, maximum);
  const normalized = value.map((entry, index) => normalize(entry, `${label}[${index}]`));
  const identities = normalized.map((entry) => typeof entry === "string" ? entry : hashCanonicalJson(entry));
  if (new Set(identities).size !== identities.length) throw new Error(`${label} must not contain duplicates`);
  return Object.freeze(normalized
    .map((entry, index) => ({ entry, identity: identities[index] }))
    .sort((left, right) => comparePhysicalResourceProtocolStrings(left.identity, right.identity))
    .map(({ entry }) => entry));
}

function normalizeInventoryResource(input, label = "physical_inventory_resource") {
  assertClosedObject(input, label, [
    "resource_kind",
    "resource_ref",
    "state_epoch_digest",
    "availability",
    "total_capacity_units",
    "available_capacity_units",
    "exclusive_available",
    "fencing_generation",
    "setup_cost_units",
    "eligible_requirement_digests",
    "switchable_mode_refs",
    "switchable_workspace_refs",
  ], [
    "active_shared_compatibility_ref",
    "current_mode_ref",
    "current_workspace_ref",
  ]);
  const resourceKind = assertEnum(input.resource_kind, RESOURCE_KIND_VALUES, `${label}.resource_kind`);
  const availability = assertEnum(
    input.availability,
    RESOURCE_AVAILABILITY_VALUES,
    `${label}.availability`,
  );
  const totalCapacity = assertInteger(
    input.total_capacity_units,
    `${label}.total_capacity_units`,
    1,
    1_000_000,
  );
  const availableCapacity = assertInteger(
    input.available_capacity_units,
    `${label}.available_capacity_units`,
    0,
    totalCapacity,
  );
  const exclusiveAvailable = assertBoolean(input.exclusive_available, `${label}.exclusive_available`);
  if (availability !== "available" && (availableCapacity !== 0 || exclusiveAvailable)) {
    throw new Error(`${label}.${availability} must expose zero available capacity and no exclusive ownership`);
  }
  if (exclusiveAvailable && availableCapacity !== totalCapacity) {
    throw new Error(`${label}.exclusive_available requires all capacity to be free`);
  }
  const hasPartialCapacity = availableCapacity > 0 && availableCapacity < totalCapacity;
  if (hasPartialCapacity && input.active_shared_compatibility_ref == null) {
    throw new Error(`${label}.partial available capacity requires active_shared_compatibility_ref`);
  }
  const normalized = {
    resource_kind: resourceKind,
    resource_ref: normalizeOpaqueRef(
      input.resource_ref,
      `${label}.resource_ref`,
      { prefix: RESOURCE_REF_PREFIX[resourceKind] },
    ),
    state_epoch_digest: assertDigest(input.state_epoch_digest, `${label}.state_epoch_digest`),
    availability,
    total_capacity_units: totalCapacity,
    available_capacity_units: availableCapacity,
    exclusive_available: exclusiveAvailable,
    fencing_generation: assertInteger(
      input.fencing_generation,
      `${label}.fencing_generation`,
      0,
      Number.MAX_SAFE_INTEGER - 1,
    ),
    setup_cost_units: assertInteger(input.setup_cost_units, `${label}.setup_cost_units`, 0, 1_000_000),
    eligible_requirement_digests: normalizeSortedUnique(
      input.eligible_requirement_digests,
      `${label}.eligible_requirement_digests`,
      assertDigest,
      { maximum: 4_096 },
    ),
    switchable_mode_refs: normalizeSortedUnique(
      input.switchable_mode_refs,
      `${label}.switchable_mode_refs`,
      (value, field) => normalizeOpaqueRef(value, field, { prefix: "mode" }),
      { maximum: 256 },
    ),
    switchable_workspace_refs: normalizeSortedUnique(
      input.switchable_workspace_refs,
      `${label}.switchable_workspace_refs`,
      (value, field) => normalizeOpaqueRef(value, field, { prefix: "workspace" }),
      { maximum: 256 },
    ),
  };
  if (input.active_shared_compatibility_ref != null) {
    if (exclusiveAvailable || availableCapacity === totalCapacity) {
      throw new Error(`${label}.active_shared_compatibility_ref requires an active shared allocation`);
    }
    normalized.active_shared_compatibility_ref = normalizeOpaqueRef(
      input.active_shared_compatibility_ref,
      `${label}.active_shared_compatibility_ref`,
      { prefix: "compatibility" },
    );
  }
  if (input.current_mode_ref != null) {
    normalized.current_mode_ref = normalizeOpaqueRef(
      input.current_mode_ref,
      `${label}.current_mode_ref`,
      { prefix: "mode" },
    );
  }
  if (input.current_workspace_ref != null) {
    normalized.current_workspace_ref = normalizeOpaqueRef(
      input.current_workspace_ref,
      `${label}.current_workspace_ref`,
      { prefix: "workspace" },
    );
  }
  return deepFreeze(normalized);
}

function normalizePhysicalResourceInventory(input, label = "physical_resource_inventory") {
  assertClosedObject(input, label, [
    "version",
    "broker_ref",
    "broker_epoch",
    "inventory_generation",
    "captured_at",
    "valid_from",
    "expires_at",
    "session_nucleus_hash",
    "source_graph_hash",
    "resources",
  ], ["inventory_digest"]);
  if (input.version !== PHYSICAL_RESOURCE_INVENTORY_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_RESOURCE_INVENTORY_VERSION}`);
  }
  const resources = normalizeSortedUnique(
    input.resources,
    `${label}.resources`,
    normalizeInventoryResource,
    { maximum: 4_096 },
  );
  const resourceRefs = resources.map((resource) => resource.resource_ref);
  if (new Set(resourceRefs).size !== resourceRefs.length) {
    throw new Error(`${label}.resources must not repeat a resource_ref`);
  }
  const capturedAt = assertTimestamp(input.captured_at, `${label}.captured_at`);
  const validFrom = assertTimestamp(input.valid_from, `${label}.valid_from`);
  const expiresAt = assertTimestamp(input.expires_at, `${label}.expires_at`);
  if (Date.parse(validFrom) > Date.parse(capturedAt)) {
    throw new Error(`${label}.valid_from cannot be after captured_at`);
  }
  const validityAfterCapture = Date.parse(expiresAt) - Date.parse(capturedAt);
  if (validityAfterCapture <= 0 || validityAfterCapture > MAX_RESOURCE_INVENTORY_VALIDITY_MS) {
    throw new Error(`${label}.expires_at must be within ${MAX_RESOURCE_INVENTORY_VALIDITY_MS}ms after captured_at`);
  }
  const normalized = {
    version: PHYSICAL_RESOURCE_INVENTORY_VERSION,
    broker_ref: normalizeOpaqueRef(input.broker_ref, `${label}.broker_ref`, { prefix: "broker" }),
    broker_epoch: assertInteger(input.broker_epoch, `${label}.broker_epoch`, 1, Number.MAX_SAFE_INTEGER),
    inventory_generation: assertInteger(
      input.inventory_generation,
      `${label}.inventory_generation`,
      1,
      Number.MAX_SAFE_INTEGER,
    ),
    captured_at: capturedAt,
    valid_from: validFrom,
    expires_at: expiresAt,
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    source_graph_hash: assertDigest(input.source_graph_hash, `${label}.source_graph_hash`),
    resources,
  };
  const digest = hashCanonicalJson(normalized);
  if (input.inventory_digest != null
      && assertDigest(input.inventory_digest, `${label}.inventory_digest`) !== digest) {
    throw new Error(`${label}.inventory_digest does not match normalized content`);
  }
  return deepFreeze({ ...normalized, inventory_digest: digest });
}

function evaluateStaticCandidate(requirement, requirementDigest, resource) {
  if (resource.resource_kind !== requirement.resource_kind
      || !requirement.candidate_resource_refs.includes(resource.resource_ref)
      || resource.availability !== "available"
      || resource.available_capacity_units < requirement.capacity_units
      || !resource.eligible_requirement_digests.includes(requirementDigest)) {
    return null;
  }
  if (requirement.required_state_epoch_digest != null
      && resource.state_epoch_digest !== requirement.required_state_epoch_digest) {
    return null;
  }
  if (requirement.ownership === "exclusive" && !resource.exclusive_available) return null;
  if (requirement.ownership === "shared"
      && resource.active_shared_compatibility_ref != null
      && resource.active_shared_compatibility_ref !== requirement.compatibility_ref) {
    return null;
  }

  let setupCost = 0;
  let modeChange = false;
  let workspaceChange = false;
  const hasActiveSharedAllocation = resource.available_capacity_units > 0
    && resource.available_capacity_units < resource.total_capacity_units;
  if (requirement.mode_ref != null && resource.current_mode_ref !== requirement.mode_ref) {
    if (requirement.required_state_epoch_digest != null
        || hasActiveSharedAllocation
        || !resource.switchable_mode_refs.includes(requirement.mode_ref)) return null;
    modeChange = true;
    setupCost += resource.setup_cost_units;
  }
  if (requirement.workspace_ref != null && resource.current_workspace_ref !== requirement.workspace_ref) {
    if (requirement.required_state_epoch_digest != null
        || hasActiveSharedAllocation
        || !resource.switchable_workspace_refs.includes(requirement.workspace_ref)) return null;
    workspaceChange = true;
    setupCost += resource.setup_cost_units;
  }
  return deepFreeze({ resource, setup_cost_units: setupCost, mode_change: modeChange, workspace_change: workspaceChange });
}

function makePlanBase(bundle, request, inventory, trustedClockSample) {
  return {
    version: PHYSICAL_ALLOCATION_PLAN_VERSION,
    reservation_request_digest: request.reservation_request_digest,
    node_id: request.node_id,
    contract_hash: request.contract_hash,
    source_graph_hash: request.source_graph_hash,
    session_nucleus_hash: request.session_nucleus_hash,
    resource_bundle_digest: bundle.resource_bundle_digest,
    inventory_digest: inventory.inventory_digest,
    broker_ref: inventory.broker_ref,
    broker_epoch: inventory.broker_epoch,
    inventory_generation: inventory.inventory_generation,
    trusted_clock_sample_digest: hashCanonicalJson(trustedClockSample),
  };
}

function finalizePlan(value) {
  return deepFreeze({ ...value, allocation_plan_digest: hashCanonicalJson(value) });
}

function unschedulablePlan(base, reason, aliases, plannerSteps) {
  assertEnum(reason, UNSCHEDULABLE_REASON_VALUES, "physical allocation unschedulable reason");
  const value = {
    ...base,
    disposition: "unschedulable",
    reason,
    blocked_aliases: Object.freeze([...aliases].sort()),
    planner_steps: plannerSteps,
    allocations: Object.freeze([]),
    lock_order: Object.freeze([]),
    setup_cost_units: 0,
  };
  return finalizePlan(value);
}

function planPhysicalResourceBundle(bundleInput, requestInput, inventoryInput, options = {}) {
  assertClosedObject(options, "physical_resource_planner_options", ["trusted_clock_port"], ["max_steps"]);
  const bundle = normalizePhysicalResourceBundle(bundleInput);
  const request = normalizePhysicalReservationRequest(requestInput);
  const inventory = normalizePhysicalResourceInventory(inventoryInput);
  // Sample inside the call from a private live port. Accepting a branded but
  // cached sample here would let a once-current inventory be planned forever.
  const trustedClockSample = samplePhysicalTrustedClock(options.trusted_clock_port);
  const maxSteps = options.max_steps == null
    ? MAX_PLANNER_STEPS
    : assertInteger(options.max_steps, "physical_resource_planner_options.max_steps", 1, MAX_PLANNER_STEPS);
  const base = makePlanBase(bundle, request, inventory, trustedClockSample);
  const trustedEarliestMs = Date.parse(trustedClockSample.trusted_utc_earliest);
  const trustedLatestMs = Date.parse(trustedClockSample.trusted_utc_latest);
  const inventoryIsCurrent = Date.parse(inventory.captured_at) <= trustedEarliestMs
    && Date.parse(inventory.valid_from) <= trustedEarliestMs
    && trustedLatestMs < Date.parse(inventory.expires_at);
  if (!inventoryIsCurrent) {
    return unschedulablePlan(
      base,
      "inventory_not_current",
      bundle.requirements.map((entry) => entry.alias),
      0,
    );
  }
  const effectWindowMs = Date.parse(request.effect_deadline) - Date.parse(request.effect_not_before);
  if (request.resource_bundle_digest !== bundle.resource_bundle_digest
      || request.session_nucleus_hash !== inventory.session_nucleus_hash
      || request.source_graph_hash !== inventory.source_graph_hash
      || effectWindowMs > bundle.duration_ms
      || Date.parse(request.requested_at) > trustedEarliestMs
      || trustedLatestMs >= Date.parse(request.effect_deadline)) {
    return unschedulablePlan(base, "binding_drift", bundle.requirements.map((entry) => entry.alias), 0);
  }

  const resources = new Map(inventory.resources.map((resource) => [resource.resource_ref, resource]));
  const work = bundle.requirements.map((requirement) => {
    const requirementDigest = hashCanonicalJson(requirement);
    const candidates = requirement.candidate_resource_refs
      .map((resourceRef) => resources.get(resourceRef))
      .filter(Boolean)
      .map((resource) => evaluateStaticCandidate(requirement, requirementDigest, resource))
      .filter(Boolean)
      .sort((left, right) => (
        left.setup_cost_units - right.setup_cost_units
        || comparePhysicalResourceProtocolStrings(
          left.resource.resource_ref,
          right.resource.resource_ref,
        )
      ));
    return { requirement, requirement_digest: requirementDigest, candidates };
  });
  const noCandidate = work.filter((entry) => entry.candidates.length === 0).map((entry) => entry.requirement.alias);
  if (noCandidate.length > 0) return unschedulablePlan(base, "no_eligible_candidate", noCandidate, 0);
  work.sort((left, right) => (
    left.candidates.length - right.candidates.length
    || (left.requirement.ownership === right.requirement.ownership
      ? 0
      : left.requirement.ownership === "exclusive" ? -1 : 1)
    || comparePhysicalResourceProtocolStrings(left.requirement.alias, right.requirement.alias)
  ));

  const dynamic = new Map();
  const chosen = [];
  let plannerSteps = 0;
  let budgetExhausted = false;

  function stateFor(resource) {
    if (!dynamic.has(resource.resource_ref)) {
      dynamic.set(resource.resource_ref, {
        used_capacity_units: 0,
        exclusive: false,
        shared_compatibility_ref: resource.active_shared_compatibility_ref || null,
        required_mode_ref: null,
        required_workspace_ref: null,
        current_mode_ref: resource.current_mode_ref || null,
        current_workspace_ref: resource.current_workspace_ref || null,
        chosen_count: 0,
      });
    }
    return dynamic.get(resource.resource_ref);
  }

  function canChoose(requirement, candidate) {
    const resource = candidate.resource;
    const state = stateFor(resource);
    if (state.used_capacity_units + requirement.capacity_units > resource.available_capacity_units) return false;
    if (requirement.ownership === "exclusive") return state.chosen_count === 0 && !state.exclusive;
    if (state.exclusive) return false;
    if (state.shared_compatibility_ref != null
        && state.shared_compatibility_ref !== requirement.compatibility_ref) return false;
    if (requirement.mode_ref != null
        && state.required_mode_ref != null
        && state.required_mode_ref !== requirement.mode_ref) return false;
    if (requirement.workspace_ref != null
        && state.required_workspace_ref != null
        && state.required_workspace_ref !== requirement.workspace_ref) return false;
    return true;
  }

  function choose(requirement, requirementDigest, candidate) {
    const resource = candidate.resource;
    const state = stateFor(resource);
    const previous = { ...state };
    state.used_capacity_units += requirement.capacity_units;
    state.chosen_count += 1;
    if (requirement.ownership === "exclusive") state.exclusive = true;
    else if (state.shared_compatibility_ref == null) {
      state.shared_compatibility_ref = requirement.compatibility_ref;
    }
    let setupCost = 0;
    let modeChange = false;
    let workspaceChange = false;
    if (requirement.mode_ref != null) {
      if (state.required_mode_ref == null) state.required_mode_ref = requirement.mode_ref;
      if (state.current_mode_ref !== requirement.mode_ref) {
        modeChange = true;
        setupCost += resource.setup_cost_units;
        state.current_mode_ref = requirement.mode_ref;
      }
    }
    if (requirement.workspace_ref != null) {
      if (state.required_workspace_ref == null) state.required_workspace_ref = requirement.workspace_ref;
      if (state.current_workspace_ref !== requirement.workspace_ref) {
        workspaceChange = true;
        setupCost += resource.setup_cost_units;
        state.current_workspace_ref = requirement.workspace_ref;
      }
    }
    const effectiveCandidate = {
      ...candidate,
      setup_cost_units: setupCost,
      mode_change: modeChange,
      workspace_change: workspaceChange,
    };
    chosen.push({ requirement, requirement_digest: requirementDigest, candidate: effectiveCandidate });
    return () => {
      chosen.pop();
      Object.assign(state, previous);
    };
  }

  function rankCandidate(requirement, candidate) {
    const state = stateFor(candidate.resource);
    let incrementalSetupCost = 0;
    if (requirement.mode_ref != null && state.current_mode_ref !== requirement.mode_ref) {
      incrementalSetupCost += candidate.resource.setup_cost_units;
    }
    if (requirement.workspace_ref != null
        && state.current_workspace_ref !== requirement.workspace_ref) {
      incrementalSetupCost += candidate.resource.setup_cost_units;
    }
    return {
      candidate,
      eligible: canChoose(requirement, candidate),
      incremental_setup_cost_units: incrementalSetupCost,
      reuse_rank: state.chosen_count > 0 ? 0 : 1,
    };
  }

  function search(index) {
    if (index === work.length) return true;
    const item = work[index];
    const orderedCandidates = item.candidates
      .map((candidate) => rankCandidate(item.requirement, candidate))
      .sort((left, right) => (
        Number(right.eligible) - Number(left.eligible)
        || left.incremental_setup_cost_units - right.incremental_setup_cost_units
        || left.reuse_rank - right.reuse_rank
        || comparePhysicalResourceProtocolStrings(
          left.candidate.resource.resource_ref,
          right.candidate.resource.resource_ref,
        )
      ));
    for (const ranked of orderedCandidates) {
      if (plannerSteps >= maxSteps) {
        budgetExhausted = true;
        return false;
      }
      plannerSteps += 1;
      const { candidate } = ranked;
      if (!ranked.eligible) continue;
      const rollback = choose(item.requirement, item.requirement_digest, candidate);
      if (search(index + 1)) return true;
      rollback();
      if (budgetExhausted) return false;
    }
    return false;
  }

  if (!search(0)) {
    return unschedulablePlan(
      base,
      budgetExhausted ? "planner_budget_exhausted" : "atomic_conflict",
      work.map((entry) => entry.requirement.alias),
      plannerSteps,
    );
  }

  const allocations = chosen.map(({ requirement, requirement_digest: requirementDigest, candidate }) => ({
    alias: requirement.alias,
    requirement_digest: requirementDigest,
    resource_kind: requirement.resource_kind,
    resource_ref: candidate.resource.resource_ref,
    ownership: requirement.ownership,
    capacity_units: requirement.capacity_units,
    expected_state_epoch_digest: candidate.resource.state_epoch_digest,
    expected_fencing_generation: candidate.resource.fencing_generation + 1,
    compatibility_ref: requirement.compatibility_ref || null,
    mode_ref: requirement.mode_ref || null,
    workspace_ref: requirement.workspace_ref || null,
    mode_change: candidate.mode_change,
    workspace_change: candidate.workspace_change,
    setup_cost_units: candidate.setup_cost_units,
  })).sort((left, right) => comparePhysicalResourceProtocolStrings(left.alias, right.alias));
  const lockOrder = [...new Set(allocations.map((allocation) => allocation.resource_ref))].sort();
  const value = {
    ...base,
    disposition: "planned",
    planner_steps: plannerSteps,
    allocations: deepFreeze(allocations),
    lock_order: Object.freeze(lockOrder),
    setup_cost_units: allocations.reduce((sum, allocation) => sum + allocation.setup_cost_units, 0),
  };
  return finalizePlan(value);
}

module.exports = {
  ALLOCATION_PLAN_DISPOSITION_VALUES,
  MAX_PLANNER_STEPS,
  MAX_RESOURCE_INVENTORY_VALIDITY_MS,
  PHYSICAL_ALLOCATION_PLAN_VERSION,
  PHYSICAL_RESOURCE_INVENTORY_VERSION,
  RESOURCE_AVAILABILITY_VALUES,
  UNSCHEDULABLE_REASON_VALUES,
  normalizeInventoryResource,
  normalizePhysicalResourceInventory,
  planPhysicalResourceBundle,
};
