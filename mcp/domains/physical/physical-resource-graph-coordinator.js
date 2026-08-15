"use strict";

// PH-S11 internal bridge between the TaskGraph and the broker-owned atomic
// resource authority. This is deliberately not an MCP tool: the model-facing
// scheduler cannot supply a reservation receipt, credential, inventory, plan,
// or eligibility callback. A privileged coordinator owns the exact broker
// authority, retains its raw-fence-bearing credential only in a WeakMap, and
// releases the reservation if graph preparation cannot commit.
//
// The WeakMap/WeakSet brands and re-entrant session lock are an honest
// same-isolate seam, not OS isolation. A production deployment must place the
// broker authority behind an authenticated process boundary; arbitrary code in
// this isolate can import internals, and code that ignores Bob's lock file is
// outside the cooperative filesystem-serialization guarantee.

const crypto = require("node:crypto");

const {
  normalizePhysicalReservationRequest,
} = require("../../lib/physical-resource-contract.js");
const {
  GRAPH_SCHEDULED_KINDS,
} = require("../../core/waves/graph-scheduler.js");
const {
  readVerifiedSessionNucleus,
} = require("../../core/governance/governance-store.js");
const {
  materializeTaskGraph,
} = require("../../core/waves/task-graph-materializer.js");
const {
  appendNodeTransition,
  readNodeTransitions,
} = require("../../core/waves/task-graph-events.js");
const {
  assertSafeDomain,
} = require("../../core/io/paths.js");
const {
  withSessionLock,
} = require("../../core/io/storage.js");
const {
  projectCurrentPhysicalDispatchExecutionAuthority,
} = require("./physical-dispatch-authority.js");
const {
  hashCanonicalJson,
} = require("../../core/verification/verification-contracts.js");
const {
  assertPhysicalResourceReservationAuthority,
  assertCurrentPhysicalResourceReservationCredential,
  cancelPhysicalResourceReservation,
  createPhysicalResourceReservationEligibilityPort,
  expirePhysicalResourceReservation,
  reservePhysicalResources,
  resolveHeldPhysicalResourceForNode,
} = require("../../../packages/bob-instrument-broker/lib/resource-reservations.js");
const {
  armPhysicalProviderDispatchBeforeEffectCancellation,
  closePhysicalProviderDispatchBeforeEffectCancellation,
  createPhysicalProviderDispatchBridgeWithCancellationCapability,
  createPhysicalProviderDispatchHeadFence,
  projectPhysicalProviderDispatchCancellation,
} = require("../../../packages/bob-instrument-broker/lib/physical-provider-dispatch.js");

const PHYSICAL_RESOURCE_GRAPH_COORDINATOR_VERSION = 1;
const MAX_ACTIVE_PREPARED_RESERVATIONS = 4_096;
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const COORDINATORS = new WeakSet();
const COORDINATOR_PRIVATE = new WeakMap();
const HANDLES = new WeakSet();
const HANDLE_PRIVATE = new WeakMap();

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
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

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function coordinatorError(code, message) {
  const error = new Error(message);
  Object.defineProperty(error, "code", { value: code, enumerable: true });
  return error;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function nodeBinding(request) {
  return {
    node_id: request.node_id,
    contract_hash: request.contract_hash,
    source_graph_hash: request.source_graph_hash,
    session_nucleus_hash: request.session_nucleus_hash,
    resource_bundle_digest: request.resource_bundle_digest,
  };
}

function physicalDispatchBinding(eligibility) {
  const binding = {
    source_graph_hash: eligibility.source_graph_hash,
    session_nucleus_hash: eligibility.session_nucleus_hash,
    resource_bundle_digest: eligibility.resource_bundle_digest,
    reservation_ref: eligibility.reservation_ref,
    receipt_digest: eligibility.receipt_digest,
    allocation_plan_digest: eligibility.allocation_plan_digest,
    eligibility_digest: eligibility.eligibility_digest,
  };
  for (const field of [
    "source_graph_hash",
    "session_nucleus_hash",
    "resource_bundle_digest",
    "receipt_digest",
    "allocation_plan_digest",
    "eligibility_digest",
  ]) assertDigest(binding[field], `physical_resource_dispatch.${field}`);
  if (typeof binding.reservation_ref !== "string"
      || !binding.reservation_ref.startsWith("reservation:")) {
    throw coordinatorError(
      "physical_resource_reservation_drift",
      "the broker eligibility proof has an invalid reservation reference",
    );
  }
  return deepFreeze(binding);
}

function findNode(document, nodeId) {
  if (!document || !Array.isArray(document.nodes)) return null;
  return document.nodes.find((entry) => entry && entry.node_id === nodeId) || null;
}

function assertLiveGraphBinding(domain, request) {
  const nucleus = readVerifiedSessionNucleus(domain);
  if (!nucleus || nucleus.nucleus_hash !== request.session_nucleus_hash) {
    throw coordinatorError(
      "physical_resource_session_nucleus_drift",
      "the verified session nucleus no longer matches the physical reservation request",
    );
  }
  const materialized = materializeTaskGraph(domain, { write: false });
  const document = materialized.document;
  const graphHash = document && document.hashes && document.hashes.graph_hash;
  if (graphHash !== request.source_graph_hash) {
    throw coordinatorError(
      "physical_resource_graph_hash_drift",
      "the TaskGraph no longer matches the physical reservation request",
    );
  }
  const node = findNode(document, request.node_id);
  if (!node || !GRAPH_SCHEDULED_KINDS.includes(node.kind)) {
    throw coordinatorError(
      "physical_resource_node_unavailable",
      "the resource-bound TaskGraph node is unavailable or owned by another scheduler",
    );
  }
  if (!["contracted", "ready"].includes(node.state)) {
    throw coordinatorError(
      "physical_resource_node_not_prepareable",
      "the resource-bound TaskGraph node is not in a prepareable state",
    );
  }
  if (node.contract_hash !== request.contract_hash
      || !node.physical_resource_bundle
      || node.physical_resource_bundle.resource_bundle_digest !== request.resource_bundle_digest) {
    throw coordinatorError(
      "physical_resource_node_binding_drift",
      "the TaskGraph node contract or resource bundle no longer matches the reservation request",
    );
  }
  return { document, node };
}

function createPhysicalResourceGraphCoordinator(input = {}) {
  assertClosedObject(input, "physical_resource_graph_coordinator", [
    "reservation_authority",
  ]);
  const authority = assertPhysicalResourceReservationAuthority(input.reservation_authority);
  const coordinator = deepFreeze({
    version: PHYSICAL_RESOURCE_GRAPH_COORDINATOR_VERSION,
    broker_ref: authority.broker_ref,
    broker_epoch: authority.broker_epoch,
    source_graph_hash: authority.source_graph_hash,
    session_nucleus_hash: authority.session_nucleus_hash,
    coordinator_id: `physical-resource-graph-coordinator:${crypto.randomBytes(18).toString("base64url")}`,
  });
  COORDINATORS.add(coordinator);
  COORDINATOR_PRIVATE.set(coordinator, {
    authority,
    eligibility_port: createPhysicalResourceReservationEligibilityPort(authority),
    active_count: 0,
  });
  return coordinator;
}

function assertPhysicalResourceGraphCoordinator(coordinator) {
  if (!coordinator || !Object.isFrozen(coordinator) || !COORDINATORS.has(coordinator)
      || !COORDINATOR_PRIVATE.has(coordinator)) {
    throw new Error("physical resource graph coordinator must be created by Bob's private factory");
  }
  return coordinator;
}

function safeHandleSnapshot(handle, state) {
  return deepFreeze({
    version: PHYSICAL_RESOURCE_GRAPH_COORDINATOR_VERSION,
    handle_id: handle.handle_id,
    target_domain: state.target_domain,
    node_id: state.request.node_id,
    contract_hash: state.request.contract_hash,
    source_graph_hash: state.request.source_graph_hash,
    session_nucleus_hash: state.request.session_nucleus_hash,
    resource_bundle_digest: state.request.resource_bundle_digest,
    reservation_ref: state.receipt.reservation_ref,
    receipt_digest: state.receipt.receipt_digest,
    allocation_plan_digest: state.allocation_plan_digest,
    eligibility_digest: state.eligibility_digest,
    lifecycle_state: state.lifecycle_state,
  });
}

function createHandle(coordinator, state) {
  const handle = deepFreeze({
    version: PHYSICAL_RESOURCE_GRAPH_COORDINATOR_VERSION,
    handle_id: `physical-resource-graph-handle:${crypto.randomBytes(18).toString("base64url")}`,
    node_id: state.request.node_id,
    reservation_ref: state.receipt.reservation_ref,
    receipt_digest: state.receipt.receipt_digest,
  });
  HANDLES.add(handle);
  HANDLE_PRIVATE.set(handle, {
    coordinator,
    handle_receipt_digest: state.receipt.receipt_digest,
    ...state,
  });
  return handle;
}

function assertHandleForCoordinator(coordinator, handle) {
  assertPhysicalResourceGraphCoordinator(coordinator);
  const state = handle == null ? null : HANDLE_PRIVATE.get(handle);
  if (!handle || !Object.isFrozen(handle) || !HANDLES.has(handle) || !state
      || state.coordinator !== coordinator
      || handle.version !== PHYSICAL_RESOURCE_GRAPH_COORDINATOR_VERSION
      || handle.node_id !== state.request.node_id
      || handle.reservation_ref !== state.receipt.reservation_ref
      || handle.receipt_digest !== state.handle_receipt_digest
      || Reflect.ownKeys(handle).length !== 5) {
    throw new Error("physical resource graph handle is not an exact private coordinator capability");
  }
  return state;
}

function assertPhysicalResourceGraphHandle(handle) {
  const state = handle == null ? null : HANDLE_PRIVATE.get(handle);
  if (!state) throw new Error("physical resource graph handle is not privately branded");
  assertHandleForCoordinator(state.coordinator, handle);
  return handle;
}

function closeReservationBeforeEffect(authority, credential) {
  try {
    return {
      closure: "cancelled",
      result: cancelPhysicalResourceReservation(authority, credential),
    };
  } catch (cause) {
    if (!cause || cause.code !== "resource_reservation_expired") throw cause;
    return {
      closure: "expired",
      result: expirePhysicalResourceReservation(authority, credential),
    };
  }
}

function cancelAfterFailure(privateState, credential) {
  try {
    closeReservationBeforeEffect(privateState.authority, credential);
    return true;
  } catch {
    return false;
  }
}

function normalizePreparationResult(raw, request, expectedDispatch) {
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    throw coordinatorError(
      "physical_resource_prepare_invalid_result",
      "bob_prepare_node returned an invalid result",
    );
  }
  if (!isPlainObject(value)
      || value.version !== 1
      || value.node_id !== request.node_id
      || value.contract_hash !== request.contract_hash
      || typeof value.prep_token !== "string"
      || typeof value.brief_hash !== "string"
      || typeof value.graph_context_hash !== "string"
      || typeof value.event_id !== "string"
      || !isPlainObject(value.physical_resource_dispatch)) {
    throw coordinatorError(
      "physical_resource_prepare_binding_drift",
      "bob_prepare_node result does not bind the exact resource-reserved node",
    );
  }
  for (const [field, label] of [
    [value.prep_token, "prep_token"],
    [value.brief_hash, "brief_hash"],
    [value.graph_context_hash, "graph_context_hash"],
  ]) assertDigest(field, `physical_resource_prepare_result.${label}`);
  assertClosedObject(
    value.physical_resource_dispatch,
    "physical_resource_prepare_result.physical_resource_dispatch",
    [
      "source_graph_hash",
      "session_nucleus_hash",
      "resource_bundle_digest",
      "reservation_ref",
      "receipt_digest",
      "allocation_plan_digest",
      "eligibility_digest",
    ],
  );
  for (const [field, expected] of Object.entries(expectedDispatch)) {
    if (value.physical_resource_dispatch[field] !== expected) {
      throw coordinatorError(
        "physical_resource_prepare_binding_drift",
        "bob_prepare_node did not durably bind the exact broker eligibility proof",
      );
    }
  }
  if (!isPlainObject(value.brief)
      || !isPlainObject(value.brief.physical_resource_dispatch)) {
    throw coordinatorError(
      "physical_resource_prepare_binding_drift",
      "the physical node brief omitted its broker eligibility binding",
    );
  }
  for (const [field, expected] of Object.entries(expectedDispatch)) {
    if (value.brief.physical_resource_dispatch[field] !== expected) {
      throw coordinatorError(
        "physical_resource_prepare_binding_drift",
        "the physical node brief carries a different broker eligibility proof",
      );
    }
  }
  return value;
}

function physicalDispatchBindingsEqual(actual, expected) {
  if (!isPlainObject(actual)) return false;
  const expectedKeys = Object.keys(expected);
  const actualKeys = Object.keys(actual);
  return actualKeys.length === expectedKeys.length
    && expectedKeys.every((field) => actual[field] === expected[field]);
}

function exactPhysicalDispatchFailureReason(reason, state, prepTokenHash) {
  return {
    reason,
    reservation_ref: state.physical_dispatch.reservation_ref,
    receipt_digest: state.physical_dispatch.receipt_digest,
    allocation_plan_digest: state.physical_dispatch.allocation_plan_digest,
    eligibility_digest: state.physical_dispatch.eligibility_digest,
    resource_bundle_digest: state.physical_dispatch.resource_bundle_digest,
    source_graph_hash: state.physical_dispatch.source_graph_hash,
    session_nucleus_hash: state.physical_dispatch.session_nucleus_hash,
    prep_token_hash: prepTokenHash,
  };
}

function exactPhysicalDispatchEvents(domain, state, { prepTokenHash = null } = {}) {
  const transitions = readNodeTransitions(domain)
    .filter((event) => event && event.payload && event.payload.node_id === state.request.node_id);
  let dispatchIndex = -1;
  for (let index = transitions.length - 1; index >= 0; index -= 1) {
    const payload = transitions[index].payload;
    if (payload.from_state === "ready"
        && payload.to_state === "dispatched"
        && payload.contract_hash === state.request.contract_hash
        && (prepTokenHash == null || payload.prep_token_hash === prepTokenHash)
        && physicalDispatchBindingsEqual(
          payload.physical_resource_dispatch,
          state.physical_dispatch,
        )) {
      dispatchIndex = index;
      break;
    }
  }
  return {
    transitions,
    dispatchIndex,
    dispatch: dispatchIndex < 0 ? null : transitions[dispatchIndex],
    successor: dispatchIndex < 0 ? null : transitions[dispatchIndex + 1] || null,
  };
}

function isExactPhysicalDispatchTombstone(event, state, prepTokenHash, allowedReasons) {
  if (!event || !event.payload
      || event.payload.from_state !== "dispatched"
      || event.payload.to_state !== "failed"
      || event.payload.contract_hash !== state.request.contract_hash) return false;
  const prior = event.payload.failure_reason;
  const exact = exactPhysicalDispatchFailureReason(prior && prior.reason, state, prepTokenHash);
  return prior != null
    && allowedReasons.includes(prior.reason)
    && Object.entries(exact).every(([field, value]) => prior[field] === value);
}

function assertExactDurablePhysicalDispatch(domain, state) {
  const document = materializeTaskGraph(domain, { write: false }).document;
  const node = findNode(document, state.request.node_id);
  const prepTokenHash = state.preparation.prep_token;
  const events = exactPhysicalDispatchEvents(domain, state, { prepTokenHash });
  if (!node
      || node.state !== "dispatched"
      || node.contract_hash !== state.request.contract_hash
      || !node.physical_resource_bundle
      || node.physical_resource_bundle.resource_bundle_digest
        !== state.request.resource_bundle_digest
      || !physicalDispatchBindingsEqual(node.physical_resource_dispatch, state.physical_dispatch)
      || !events.dispatch
      || events.successor != null) {
    throw coordinatorError(
      "physical_resource_prepare_binding_drift",
      "physical preparation did not leave the exact broker-bound dispatch durable",
    );
  }
  return events.dispatch;
}

function tombstonePhysicalDispatchAfterPrepareFailure(domain, state) {
  const events = exactPhysicalDispatchEvents(domain, state);
  if (!events.dispatch) return false;
  const prepTokenHash = events.dispatch.payload.prep_token_hash;
  assertDigest(prepTokenHash, "physical_resource_failed_prepare.prep_token_hash");
  if (events.successor != null) {
    if (isExactPhysicalDispatchTombstone(
      events.successor,
      state,
      prepTokenHash,
      ["physical_prepare_reconciliation_failed"],
    )) return true;
    throw coordinatorError(
      "physical_resource_release_uncertain",
      "physical preparation failed after its dispatch left the cancellable state",
    );
  }
  const node = findNode(materializeTaskGraph(domain, { write: false }).document, state.request.node_id);
  if (!node || node.state !== "dispatched"
      || node.contract_hash !== state.request.contract_hash
      || !physicalDispatchBindingsEqual(node.physical_resource_dispatch, state.physical_dispatch)) {
    throw coordinatorError(
      "physical_resource_release_uncertain",
      "physical preparation failed and its durable dispatch could not be invalidated",
    );
  }
  appendNodeTransition({
    target_domain: domain,
    node_id: state.request.node_id,
    from_state: "dispatched",
    to_state: "failed",
    contract_hash: state.request.contract_hash,
    failure_reason: exactPhysicalDispatchFailureReason(
      "physical_prepare_reconciliation_failed",
      state,
      prepTokenHash,
    ),
    source: {
      tool: "physical-resource-graph-coordinator",
      reason: "invalidate_failed_physical_prepare",
    },
  });
  return true;
}

function assertDurablePhysicalDispatchAndTombstone(domain, state) {
  const document = materializeTaskGraph(domain, { write: false }).document;
  const node = findNode(document, state.request.node_id);
  const prepTokenHash = state.preparation.prep_token;
  const events = exactPhysicalDispatchEvents(domain, state, { prepTokenHash });
  if (!events.dispatch) {
    throw coordinatorError(
      "physical_resource_graph_handle_stale",
      "the TaskGraph no longer carries the exact durable physical dispatch binding",
    );
  }
  if (events.dispatch.event_id !== state.preparation.event_id) {
    throw coordinatorError(
      "physical_resource_graph_handle_stale",
      "the durable physical dispatch event is not the exact prepared event",
    );
  }

  if (events.successor != null) {
    if (isExactPhysicalDispatchTombstone(
      events.successor,
      state,
      prepTokenHash,
      ["physical_reservation_cancelled", "dispatch_timeout"],
    )) return;
    throw coordinatorError(
      "physical_resource_graph_handle_stale",
      "the physical dispatch was not followed by its exact cancellation tombstone",
    );
  }

  if (node
      && node.state === "dispatched"
      && node.contract_hash === state.request.contract_hash
      && node.physical_resource_bundle
      && node.physical_resource_bundle.resource_bundle_digest
        === state.request.resource_bundle_digest
      && physicalDispatchBindingsEqual(node.physical_resource_dispatch, state.physical_dispatch)) {
    const failureReason = exactPhysicalDispatchFailureReason(
      "physical_reservation_cancelled",
      state,
      prepTokenHash,
    );
    appendNodeTransition({
      target_domain: domain,
      node_id: state.request.node_id,
      from_state: "dispatched",
      to_state: "failed",
      contract_hash: state.request.contract_hash,
      failure_reason: failureReason,
      source: {
        tool: "physical-resource-graph-coordinator",
        reason: "cancel_before_physical_effect",
      },
    });
    return;
  }
  throw coordinatorError(
    "physical_resource_graph_handle_stale",
    "the physical node left its dispatched state without this reservation cancellation",
  );
}

function assertCancellableDurablePhysicalDispatch(domain, state) {
  const prepTokenHash = state.preparation.prep_token;
  const events = exactPhysicalDispatchEvents(domain, state, { prepTokenHash });
  if (!events.dispatch || events.dispatch.event_id !== state.preparation.event_id) {
    throw coordinatorError(
      "physical_resource_graph_handle_stale",
      "the TaskGraph no longer carries the exact prepared physical dispatch event",
    );
  }
  if (events.successor == null) {
    assertExactDurablePhysicalDispatch(domain, state);
    return "dispatched";
  }
  if (isExactPhysicalDispatchTombstone(
    events.successor,
    state,
    prepTokenHash,
    ["physical_reservation_cancelled", "dispatch_timeout"],
  )) return "tombstoned";
  throw coordinatorError(
    "physical_resource_graph_handle_stale",
    "the exact prepared physical dispatch has a different durable successor",
  );
}

function reserveAndPreparePhysicalGraphNode(coordinatorInput, input = {}) {
  const coordinator = assertPhysicalResourceGraphCoordinator(coordinatorInput);
  assertClosedObject(input, "physical_resource_graph_dispatch", [
    "target_domain",
    "reservation_request",
  ], ["actor"]);
  const privateState = COORDINATOR_PRIVATE.get(coordinator);
  if (privateState.active_count >= MAX_ACTIVE_PREPARED_RESERVATIONS) {
    throw coordinatorError(
      "physical_resource_graph_capacity_exhausted",
      "the physical graph coordinator active reservation capacity is exhausted",
    );
  }
  const domain = assertSafeDomain(input.target_domain);
  const request = normalizePhysicalReservationRequest(input.reservation_request);
  if (request.source_graph_hash !== coordinator.source_graph_hash
      || request.session_nucleus_hash !== coordinator.session_nucleus_hash) {
    throw coordinatorError(
      "physical_resource_coordinator_binding_drift",
      "the reservation request does not match this physical graph coordinator",
    );
  }

  // Pre-reservation check prevents a stale or non-physical node from consuming
  // broker capacity. The same checks run again after the atomic CAS.
  assertLiveGraphBinding(domain, request);
  const reservation = reservePhysicalResources(privateState.authority, request);
  if (!reservation.credential || reservation.receipt.state !== "held") {
    throw coordinatorError(
      "physical_resource_reservation_not_held",
      "the exact reservation request is terminal and cannot prepare a node",
    );
  }

  let eligibility;
  try {
    assertLiveGraphBinding(domain, request);
    eligibility = resolveHeldPhysicalResourceForNode(
      privateState.eligibility_port,
      nodeBinding(request),
    );
    const allocationDigest = hashCanonicalJson(reservation.receipt.allocations);
    if (!eligibility || eligibility.receipt_digest !== reservation.receipt.receipt_digest
        || eligibility.allocation_plan_digest !== reservation.allocation_plan_digest
        || eligibility.allocation_digest !== allocationDigest) {
      throw coordinatorError(
        "physical_resource_reservation_not_eligible",
        "the atomic reservation is not currently eligible for this TaskGraph node",
      );
    }

    // Hold the session lock across the final graph/reservation checks and the
    // synchronous prepare mutation. The broker state callback runs between
    // two graph checks because same-isolate callbacks may re-enter Bob's
    // session writer; the post-callback check catches that drift before the
    // prepare-node handler can append anything.
    const prepared = withSessionLock(domain, () => {
      assertLiveGraphBinding(domain, request);
      const finalEligibility = resolveHeldPhysicalResourceForNode(
        privateState.eligibility_port,
        nodeBinding(request),
      );
      if (!finalEligibility
          || finalEligibility.receipt_digest !== eligibility.receipt_digest
          || finalEligibility.eligibility_digest !== eligibility.eligibility_digest
          || finalEligibility.allocation_digest !== allocationDigest) {
        throw coordinatorError(
          "physical_resource_reservation_drift",
          "the physical reservation changed immediately before node preparation",
        );
      }
      assertLiveGraphBinding(domain, request);

      const prepareNode = require("../../tools/prepare-node.js").preparePhysicalResourceNode;
      if (typeof prepareNode !== "function") {
        throw coordinatorError(
          "physical_resource_prepare_unavailable",
          "bob_prepare_node is unavailable to the physical graph coordinator",
        );
      }
      const expectedDispatch = physicalDispatchBinding(finalEligibility);
      const coordinationState = {
        request,
        physical_dispatch: expectedDispatch,
      };
      try {
        const preparation = normalizePreparationResult(prepareNode({
          target_domain: domain,
          node_id: request.node_id,
          actor: input.actor,
        }, privateState.eligibility_port, expectedDispatch), request, expectedDispatch);
        coordinationState.preparation = preparation;
        assertExactDurablePhysicalDispatch(domain, coordinationState);
        return {
          eligibility: finalEligibility,
          preparation,
        };
      } catch (cause) {
        try {
          tombstonePhysicalDispatchAfterPrepareFailure(domain, coordinationState);
        } catch (tombstoneCause) {
          if (tombstoneCause && tombstoneCause.code === "physical_resource_release_uncertain") {
            throw tombstoneCause;
          }
          throw coordinatorError(
            "physical_resource_release_uncertain",
            "physical preparation failed and its dispatch tombstone could not be committed",
          );
        }
        throw cause;
      }
    });
    eligibility = prepared.eligibility;
    const preparation = prepared.preparation;
    const handle = createHandle(coordinator, {
      target_domain: domain,
      request,
      receipt: reservation.receipt,
      credential: reservation.credential,
      allocation_plan_digest: reservation.allocation_plan_digest,
      allocation_digest: allocationDigest,
      eligibility_digest: eligibility.eligibility_digest,
      physical_dispatch: preparation.physical_resource_dispatch,
      preparation,
      lifecycle_state: "prepared",
    });
    privateState.active_count += 1;
    return deepFreeze({
      version: PHYSICAL_RESOURCE_GRAPH_COORDINATOR_VERSION,
      reservation_handle: handle,
      reservation: safeHandleSnapshot(handle, HANDLE_PRIVATE.get(handle)),
      preparation,
    });
  } catch (cause) {
    if (cause && cause.code === "physical_resource_release_uncertain") throw cause;
    const released = cancelAfterFailure(privateState, reservation.credential);
    if (!released) {
      throw coordinatorError(
        "physical_resource_release_uncertain",
        "node preparation failed and atomic reservation release could not be confirmed",
      );
    }
    if (cause && typeof cause.code === "string") throw cause;
    throw coordinatorError(
      "physical_resource_prepare_failed",
      "resource-reserved node preparation failed before any physical effect",
    );
  }
}

function transferPreparedPhysicalGraphReservationToProviderBridge(
  coordinatorInput,
  handleInput,
  input = {},
) {
  const coordinator = assertPhysicalResourceGraphCoordinator(coordinatorInput);
  const state = assertHandleForCoordinator(coordinator, handleInput);
  assertClosedObject(input, "physical_resource_provider_transfer", [
    "dispatch_authority_port",
    "command_registry",
  ], ["provider_call_timeout_ms"]);
  if (state.lifecycle_state !== "prepared" || state.credential == null) {
    throw coordinatorError(
      "physical_resource_graph_handle_stale",
      "the physical graph reservation handle is no longer transferable",
    );
  }
  const privateState = COORDINATOR_PRIVATE.get(coordinator);
  return withSessionLock(state.target_domain, () => {
    if (state.lifecycle_state !== "prepared" || state.credential == null) {
      throw coordinatorError(
        "physical_resource_graph_handle_stale",
        "the physical graph reservation handle is no longer transferable",
      );
    }
    const credentialProjection = assertCurrentPhysicalResourceReservationCredential(
      privateState.authority,
      state.credential,
    );
    if (credentialProjection.state !== "held"
        || credentialProjection.effect_state !== "not_started"
        || credentialProjection.reservation_ref !== state.receipt.reservation_ref
        || credentialProjection.receipt_digest !== state.receipt.receipt_digest
        || credentialProjection.allocation_plan_digest !== state.allocation_plan_digest) {
      throw coordinatorError(
        "physical_resource_reservation_drift",
        "the prepared handle no longer owns its exact held reservation credential",
      );
    }
    const dispatchEvent = assertExactDurablePhysicalDispatch(state.target_domain, state);
    if (state.preparation.event_id !== dispatchEvent.event_id
        || state.preparation.prep_token !== dispatchEvent.payload.prep_token_hash) {
      throw coordinatorError(
        "physical_resource_prepare_binding_drift",
        "the current durable dispatch event does not match the exact preparation result",
      );
    }
    const allocationDigest = hashCanonicalJson(state.receipt.allocations);
    if (allocationDigest !== state.allocation_digest) {
      throw coordinatorError(
        "physical_resource_reservation_drift",
        "the prepared handle allocation digest no longer matches its exact receipt",
      );
    }
    const authorityProjection = projectCurrentPhysicalDispatchExecutionAuthority(
      input.dispatch_authority_port,
    );
    const exactAuthorityFields = {
      session_nucleus_hash: state.request.session_nucleus_hash,
      execution_principal_id: state.request.execution_principal_ref,
      attempt_ref: state.request.attempt_ref,
      node_id: state.request.node_id,
      contract_hash: state.request.contract_hash,
      prep_token_hash: state.preparation.prep_token,
      dispatch_event_id: state.preparation.event_id,
      graph_context_hash: state.preparation.graph_context_hash,
      resource_bundle_digest: state.request.resource_bundle_digest,
      effect_not_before: state.request.effect_not_before,
      effect_deadline: state.request.effect_deadline,
    };
    for (const [field, expected] of Object.entries(exactAuthorityFields)) {
      if (authorityProjection[field] !== expected) {
        throw coordinatorError(
          "physical_resource_dispatch_authority_drift",
          `${field} dispatch authority does not match the prepared graph reservation`,
        );
      }
    }
    const allocated = state.receipt.allocations.filter(
      (allocation) => allocation.resource_ref === authorityProjection.instrument_ref,
    );
    if (allocated.length !== 1) {
      throw coordinatorError(
        "physical_resource_dispatch_authority_drift",
        "dispatch authority instrument is not one exact allocated graph resource",
      );
    }
    const reservationBinding = {
      reservation_ref: state.receipt.reservation_ref,
      receipt_digest: state.receipt.receipt_digest,
      reservation_request_digest: state.request.reservation_request_digest,
      node_id: state.request.node_id,
      contract_hash: state.request.contract_hash,
      source_graph_hash: state.request.source_graph_hash,
      session_nucleus_hash: state.request.session_nucleus_hash,
      resource_bundle_digest: state.request.resource_bundle_digest,
      allocation_plan_digest: state.allocation_plan_digest,
      allocation_digest: state.allocation_digest,
      attempt_ref: state.request.attempt_ref,
      execution_principal_ref: state.request.execution_principal_ref,
      effect_not_before: state.request.effect_not_before,
      effect_deadline: state.request.effect_deadline,
      session_id: authorityProjection.session_id,
      prep_token_hash: state.preparation.prep_token,
      dispatch_event_id: state.preparation.event_id,
      graph_context_hash: state.preparation.graph_context_hash,
    };
    const dispatchHeadFence = createPhysicalProviderDispatchHeadFence({
      reservation_binding: reservationBinding,
      run_while_current(invoke) {
        let result;
        withSessionLock(state.target_domain, () => {
          if (state.lifecycle_state !== "transferred") {
            throw coordinatorError(
              "physical_resource_dispatch_head_stale",
              "the transferred reservation no longer owns live dispatch custody",
            );
          }
          const currentDispatch = assertExactDurablePhysicalDispatch(
            state.target_domain,
            state,
          );
          if (currentDispatch.event_id !== state.preparation.event_id
              || currentDispatch.payload.prep_token_hash !== state.preparation.prep_token) {
            throw coordinatorError(
              "physical_resource_dispatch_head_stale",
              "the exact preparation event is no longer the live TaskGraph dispatch head",
            );
          }
          // Do not return this value from withSessionLock: provider entry may
          // return a Promise, while the lock deliberately permits only a
          // synchronous callback. Entry occurs under the lock; asynchronous
          // provider work proceeds after the cooperative lock is released.
          result = invoke();
        });
        return result;
      },
    });
    const transferred = createPhysicalProviderDispatchBridgeWithCancellationCapability({
      reservation_authority: privateState.authority,
      reservation_credential: state.credential,
      reservation_binding: reservationBinding,
      dispatch_head_fence: dispatchHeadFence,
      command_registry: input.command_registry,
      dispatch_authority_port: input.dispatch_authority_port,
      ...(input.provider_call_timeout_ms == null
        ? {}
        : { provider_call_timeout_ms: input.provider_call_timeout_ms }),
    });
    const bridge = transferred.dispatch_bridge;
    state.dispatch_bridge = bridge;
    state.dispatch_cancellation_capability = transferred.cancellation_capability;
    state.credential = null;
    state.lifecycle_state = "transferred";
    privateState.active_count -= 1;
    return deepFreeze({
      version: PHYSICAL_RESOURCE_GRAPH_COORDINATOR_VERSION,
      dispatch_bridge: bridge,
      reservation: safeHandleSnapshot(handleInput, state),
    });
  });
}

function cancelTransferredPhysicalGraphReservation(
  coordinator,
  handle,
  state,
  privateState,
) {
  return withSessionLock(state.target_domain, () => {
    const capability = state.dispatch_cancellation_capability;
    if (capability == null || ![
      "transferred",
      "transferred_cancelling",
      "transferred_release_uncertain",
    ].includes(state.lifecycle_state)) {
      throw coordinatorError(
        "physical_resource_graph_handle_stale",
        "the transferred physical graph reservation has no private cancellation custody",
      );
    }

    if (state.lifecycle_state === "transferred") {
      // Establish the exact graph/preparation head before arming the bridge.
      // Arming is a private no-effect transition: it blocks every command
      // capability but does not release broker capacity. The TaskGraph is then
      // invalidated before the one broker close is allowed to run.
      assertCancellableDurablePhysicalDispatch(state.target_domain, state);
      try {
        armPhysicalProviderDispatchBeforeEffectCancellation(capability);
      } catch (cause) {
        if (cause && cause.code === "physical_dispatch_cancellation_after_effect") throw cause;
        state.lifecycle_state = "transferred_release_uncertain";
        throw coordinatorError(
          "physical_resource_release_uncertain",
          "the transferred bridge could not prove an exact not-started cancellation state",
        );
      }
      state.lifecycle_state = "transferred_cancelling";
    } else {
      const cancellation = projectPhysicalProviderDispatchCancellation(capability);
      if (cancellation.cancellation_state === "ambiguous") {
        throw coordinatorError(
          "physical_resource_release_uncertain",
          "the transferred bridge cancellation remains ambiguous and cannot be replayed",
        );
      }
      if (!["armed", "closed"].includes(cancellation.cancellation_state)) {
        throw coordinatorError(
          "physical_resource_release_uncertain",
          "the transferred bridge lost its exact one-shot cancellation state",
        );
      }
    }

    // This is idempotent for an already exact cancellation/timeout tombstone.
    // No broker capacity is released until this durable proof succeeds.
    assertDurablePhysicalDispatchAndTombstone(state.target_domain, state);

    let closed;
    try {
      closed = closePhysicalProviderDispatchBeforeEffectCancellation(capability);
    } catch {
      state.lifecycle_state = "transferred_release_uncertain";
      throw coordinatorError(
        "physical_resource_release_uncertain",
        "the TaskGraph dispatch was invalidated but transferred broker release is ambiguous",
      );
    }
    if (!closed || !["cancelled", "expired"].includes(closed.kind)
        || closed.reservation_ref !== state.receipt.reservation_ref
        || !closed.receipt || closed.receipt.reservation_ref !== state.receipt.reservation_ref) {
      state.lifecycle_state = "transferred_release_uncertain";
      throw coordinatorError(
        "physical_resource_release_uncertain",
        "the transferred bridge returned a mismatched cancellation result",
      );
    }
    state.lifecycle_state = closed.kind;
    state.receipt = closed.receipt;
    state.dispatch_cancellation_capability = null;
    return safeHandleSnapshot(handle, state);
  });
}

function cancelPreparedPhysicalGraphReservation(coordinatorInput, handleInput) {
  const coordinator = assertPhysicalResourceGraphCoordinator(coordinatorInput);
  const state = assertHandleForCoordinator(coordinator, handleInput);
  const privateState = COORDINATOR_PRIVATE.get(coordinator);
  if ([
    "transferred",
    "transferred_cancelling",
    "transferred_release_uncertain",
  ].includes(state.lifecycle_state)) {
    return cancelTransferredPhysicalGraphReservation(
      coordinator,
      handleInput,
      state,
      privateState,
    );
  }
  if (state.lifecycle_state !== "prepared") {
    throw coordinatorError(
      "physical_resource_graph_handle_stale",
      "the physical graph reservation handle is no longer cancellable",
    );
  }
  return withSessionLock(state.target_domain, () => {
    if (state.lifecycle_state !== "prepared" || state.credential == null) {
      throw coordinatorError(
        "physical_resource_graph_handle_stale",
        "the physical graph reservation handle is no longer cancellable",
      );
    }
    let alreadyExpired = false;
    try {
      assertCurrentPhysicalResourceReservationCredential(
        privateState.authority,
        state.credential,
      );
    } catch (cause) {
      if (cause && cause.code === "resource_reservation_expired") alreadyExpired = true;
      else if (cause && [
        "resource_inventory_expired",
        "resource_inventory_binding_drift",
      ].includes(cause.code)) {
        // The credential was proven current before the inventory freshness or
        // health check failed. Stale/unhealthy observations must stop effects,
        // but they must never prevent a before-effect close from returning
        // capacity. The close mutation revalidates the private credential and
        // durable reservation state again after the TaskGraph tombstone.
      }
      else {
        throw coordinatorError(
          "physical_resource_release_uncertain",
          "the prepared reservation credential could not be reconciled before cancellation",
        );
      }
    }

    // Invalidate the prep token in the durable TaskGraph before capacity can
    // be released. If the broker close loses its response, a retry recognizes
    // this exact tombstone and retries only the close; it never appends a
    // second transition or resurrects dispatch authority.
    assertDurablePhysicalDispatchAndTombstone(state.target_domain, state);

    let closed;
    try {
      closed = alreadyExpired
        ? {
          closure: "expired",
          result: expirePhysicalResourceReservation(
            privateState.authority,
            state.credential,
          ),
        }
        : closeReservationBeforeEffect(privateState.authority, state.credential);
    } catch {
      throw coordinatorError(
        "physical_resource_release_uncertain",
        "the TaskGraph dispatch was invalidated but broker release could not be confirmed",
      );
    }
    state.lifecycle_state = closed.closure;
    state.receipt = closed.result.receipt;
    state.credential = null;
    privateState.active_count -= 1;
    return safeHandleSnapshot(handleInput, state);
  });
}

function projectPhysicalResourceGraphHandle(handleInput) {
  const handle = assertPhysicalResourceGraphHandle(handleInput);
  return safeHandleSnapshot(handle, HANDLE_PRIVATE.get(handle));
}

module.exports = {
  MAX_ACTIVE_PREPARED_RESERVATIONS,
  PHYSICAL_RESOURCE_GRAPH_COORDINATOR_VERSION,
  assertPhysicalResourceGraphCoordinator,
  assertPhysicalResourceGraphHandle,
  cancelPreparedPhysicalGraphReservation,
  createPhysicalResourceGraphCoordinator,
  projectPhysicalResourceGraphHandle,
  reserveAndPreparePhysicalGraphNode,
  transferPreparedPhysicalGraphReservationToProviderBridge,
};
