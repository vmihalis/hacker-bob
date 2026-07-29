"use strict";

const { types: utilTypes } = require("node:util");

// Plane-PH provider command gate. Reservation credentials and provider method
// references remain private to this module. A provider implementation is only
// reached with a single-use, broker-branded capability minted after the exact
// resource reservation and provider/custody bindings have been revalidated.

const {
  assertCurrentPhysicalResourceReservationCredential,
  assertPhysicalResourceEffectAuthorizedNow,
  assertPhysicalResourceReservationAuthority,
  beginPhysicalResourceCleanup,
  cancelPhysicalResourceReservation,
  completePhysicalResourceCleanup,
  expirePhysicalResourceReservation,
  fencePhysicalResourceReservation,
  markPhysicalResourceEffectStarted,
  quarantinePhysicalResourceReservation,
  readPhysicalResourceReservationProjection,
} = require("./resource-reservations.js");
const {
  normalizeOpaqueRef,
} = require("../../../mcp/lib/physical-quantities.js");
const {
  normalizePhysicalResourceBundle,
  normalizeResourceAllocation,
} = require("../../../mcp/lib/physical-resource-contract.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/lib/verification-contracts.js");
const {
  assertProviderCompletionEvidenceAdapter,
} = require("../../bob-instrument-contracts/lib/instrument-provider-contract.js");
const {
  assertCurrentPhysicalDispatchExecutionAuthorityClaim,
  claimPhysicalDispatchExecutionAuthority,
  projectCurrentPhysicalDispatchExecutionAuthority,
  takePhysicalDispatchExecutionAuthorityClaimOwnership,
} = require("../../../mcp/lib/physical-dispatch-authority.js");

const PHYSICAL_PROVIDER_DISPATCH_VERSION = 1;
const MAX_COMMANDS = 4096;
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/u;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const COMMAND_KINDS = Object.freeze(["command", "cleanup", "fence", "quarantine"]);
const COMPLETION_VALUES = Object.freeze(["confirmed", "confirmed_no_effect", "ambiguous"]);
const DEFINITIVE_COMPLETION_VALUES = Object.freeze(["confirmed", "confirmed_no_effect"]);
const COMPLETION_EFFECT_DISPOSITIONS = Object.freeze({
  confirmed: "requested_effect_committed",
  confirmed_no_effect: "requested_effect_not_applied",
});
const COMPLETION_BINDING_DOMAIN = "hacker-bob/physical-provider-completion-binding/v1";
const COMPLETION_RECEIPT_DOMAIN = "hacker-bob/physical-provider-completion-receipt/v1";
const COMPLETION_EVIDENCE_DOMAIN = "hacker-bob/physical-provider-completion-evidence/v1";
const EXECUTION_LINEAGE_PROJECTION_MAP = Object.freeze([
  ["experiment_plan_hash", "experiment_plan_hash"],
  ["execution_lineage_digest", "execution_lineage_digest"],
  ["compiler_id", "compiler_id"],
  ["compiler_manifest_digest", "compiler_manifest_digest"],
  ["compiler_registry_digest", "compiler_registry_digest"],
  ["compiled_command_id", "compiled_command_id"],
  ["compiled_command_capability_digest", "compiled_command_capability_digest"],
  ["compiled_operation_digest", "compiled_operation_digest"],
  ["provider_command_ref", "provider_command_ref"],
  // Compensation has its own command input. Preserve the signed ordinary
  // command input under unambiguous names instead of silently overwriting it.
  ["command_input_ref", "active_command_input_ref"],
  ["command_input_digest", "active_command_input_digest"],
  ["maximum_response_bytes", "maximum_response_bytes"],
  ["vault_reservation_handle", "vault_reservation_handle"],
  ["vault_reservation_digest", "vault_reservation_digest"],
  ["vault_ingest_capability_digest", "vault_ingest_capability_digest"],
  ["vault_byte_limit", "vault_byte_limit"],
  ["worker_bundle_digest", "worker_bundle_digest"],
  ["worker_launch_profile_digest", "worker_launch_profile_digest"],
  ["worker_fence_plan_digest", "worker_fence_plan_digest"],
  ["transport_profile_digest", "transport_profile_digest"],
  ["durable_exchange_plan_digest", "durable_exchange_plan_digest"],
  ["terminal_receipt_recipient_digest", "terminal_receipt_recipient_digest"],
  ["safety_supervisor_plan_digest", "safety_supervisor_plan_digest"],
]);
const EXECUTION_LINEAGE_PROJECTION_FIELDS = Object.freeze(
  EXECUTION_LINEAGE_PROJECTION_MAP.map(([, projectionField]) => projectionField),
);
const ACTIVE_ADMISSION_PROJECTION_FIELDS = Object.freeze([
  "physical_scope_axis_digest",
  "physical_scope_policy_id",
  "physical_scope_policy_digest",
  "physical_scope_projection_digest",
  "authority_epoch",
  "revocation_generation",
  "authority_resolution_digest",
  "caller_role_id",
  "requester_principal_id",
  "ipc_peer_principal_id",
  "capability_pack_id",
  "capability_pack_version",
  "capability_pack_digest",
  "technique_cell_id",
  "inventory_observation_ref",
  "inventory_observation_digest",
  "assurance_profile_id",
  "assurance_claims_digest",
  "provider_manifest_digest",
  "availability_variant_id",
  "availability_variant_digest",
  "authorized_transition_set_digest",
  "workspace_snapshot_ref",
  "workspace_snapshot_digest",
  "observer_plan_digest",
  "control_plan_digest",
  "cleanup_plan_digest",
]);

const REGISTRIES = new WeakSet();
const REGISTRY_PRIVATE = new WeakMap();
const COMMAND_AUTHORIZATION_PORTS = new WeakSet();
const COMMAND_AUTHORIZATION_PRIVATE = new WeakMap();
const COMMAND_AUTHORIZATIONS = new WeakSet();
const COMMAND_AUTHORIZATION_OWNER = new WeakMap();
const COMMAND_PROJECTIONS = new WeakSet();
const COMMAND_PRIVATE = new WeakMap();
const DISPATCH_HEAD_FENCES = new WeakSet();
const DISPATCH_HEAD_FENCE_PRIVATE = new WeakMap();
const BRIDGES = new WeakSet();
const BRIDGE_PRIVATE = new WeakMap();
const BEFORE_EFFECT_CANCELLATION_CAPABILITIES = new WeakSet();
const BEFORE_EFFECT_CANCELLATION_PRIVATE = new WeakMap();
const ADMISSION_CAPABILITIES = new WeakSet();
const ADMISSION_PRIVATE = new WeakMap();
const PROVIDER_CAPABILITIES = new WeakSet();
const PROVIDER_CAPABILITY_PRIVATE = new WeakMap();
const COMPLETION_VERIFICATION_PORTS = new WeakSet();
const COMPLETION_VERIFICATION_PRIVATE = new WeakMap();
const ACTIVE_COMPLETION_VERIFICATION_PORTS = new WeakSet();

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function compareCodeUnits(left, right) {
  const leftValue = String(left);
  const rightValue = String(right);
  return leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0;
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedDataObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw dispatchError("physical_dispatch_invalid", `${label} must be an object`);
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw dispatchError("physical_dispatch_invalid", `${label} cannot contain symbol fields`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const allowed = new Set([...required, ...optional]);
  const unknown = Object.keys(descriptors).filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) {
    throw dispatchError("physical_dispatch_invalid", `${label} has unknown fields: ${unknown.join(", ")}`);
  }
  const missing = required.filter((field) => !Object.prototype.hasOwnProperty.call(descriptors, field));
  if (missing.length > 0) {
    throw dispatchError("physical_dispatch_invalid", `${label} is missing fields: ${missing.join(", ")}`);
  }
  for (const [field, descriptor] of Object.entries(descriptors)) {
    if (!Object.prototype.hasOwnProperty.call(descriptor, "value") || !descriptor.enumerable) {
      throw dispatchError("physical_dispatch_invalid", `${label}.${field} must be an enumerable data field`);
    }
  }
  return value;
}

function assertDenseArray(value, label, minimum, maximum) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    throw dispatchError("physical_dispatch_invalid", `${label} must contain ${minimum}-${maximum} entries`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || !descriptor.enumerable) {
      throw dispatchError("physical_dispatch_invalid", `${label} must be a dense data array`);
    }
  }
  const extra = Object.keys(descriptors).filter((field) => field !== "length" && !/^\d+$/u.test(field));
  if (extra.length > 0 || Object.getOwnPropertySymbols(value).length > 0) {
    throw dispatchError("physical_dispatch_invalid", `${label} cannot contain extra fields`);
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw dispatchError("physical_dispatch_invalid", `${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw dispatchError("physical_dispatch_invalid", `${label} must be a lowercase identifier`);
  }
  return value;
}

function assertToken(value, label) {
  if (typeof value !== "string" || !TOKEN_PATTERN.test(value)) {
    throw dispatchError("physical_dispatch_invalid", `${label} must be a bounded opaque token`);
  }
  return value;
}

function assertInteger(value, label, minimum, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw dispatchError("physical_dispatch_invalid", `${label} must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function assertTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))
      || new Date(value).toISOString() !== value) {
    throw dispatchError("physical_dispatch_invalid", `${label} must be a canonical UTC timestamp`);
  }
  return value;
}

function projectExecutionLineage(authority) {
  return Object.freeze(Object.fromEntries(
    EXECUTION_LINEAGE_PROJECTION_MAP.map(
      ([authorityField, projectionField]) => [
        projectionField,
        Object.prototype.hasOwnProperty.call(authority, projectionField)
          ? authority[projectionField]
          : authority[authorityField],
      ],
    ),
  ));
}

function projectActiveAdmission(authority) {
  return Object.freeze(Object.fromEntries(
    ACTIVE_ADMISSION_PROJECTION_FIELDS.map((field) => [field, authority[field]]),
  ));
}

function activeAdmissionBindingDigest(authority) {
  return hashCanonicalJson({
    domain: "hacker-bob/physical-provider-active-admission-binding/v1",
    ...projectActiveAdmission(authority),
  });
}

function dispatchError(code, message, cause = null) {
  const error = new Error(message);
  error.code = code;
  if (cause != null) Object.defineProperty(error, "cause", { value: cause });
  return error;
}

function assertSynchronousCompletionResult(value, label) {
  if (utilTypes.isPromise(value)) {
    throw dispatchError(
      "physical_provider_completion_port_async",
      `${label} must be synchronous`,
    );
  }
  if (value && (typeof value === "object" || typeof value === "function")
      && utilTypes.isProxy(value)) {
    throw dispatchError(
      "physical_provider_completion_evidence_invalid",
      `${label} must return an own-data object, not a Proxy`,
    );
  }
  if (value && (typeof value === "object" || typeof value === "function")) {
    let then;
    try {
      then = value.then;
    } catch (cause) {
      throw dispatchError(
        "physical_provider_completion_port_async",
        `${label} returned a hostile thenable`,
        cause,
      );
    }
    if (typeof then === "function") {
      throw dispatchError(
        "physical_provider_completion_port_async",
        `${label} must be synchronous`,
      );
    }
  }
  return value;
}

// This is a provider-neutral conformance seam, not a production attestation.
// The backend must independently verify provider-native evidence, commit the
// normalized receipt durably before returning, and expose a linearizable
// readback of that same receipt. Bob checks the exact binding and immediate
// read-after-commit, but cannot prove durability or verifier independence for
// arbitrary same-process callbacks; the public projection therefore remains
// explicitly non-production.
function createPhysicalProviderCompletionVerificationPort(input = {}) {
  assertClosedDataObject(input, "physical_provider_completion_verification_port", [
    "port_id",
    "evidence_domain_digest",
    "read_committed",
    "verify_and_commit",
  ]);
  if (typeof input.read_committed !== "function"
      || typeof input.verify_and_commit !== "function"
      || utilTypes.isAsyncFunction(input.read_committed)
      || utilTypes.isAsyncFunction(input.verify_and_commit)) {
    throw dispatchError(
      "physical_provider_completion_port_invalid",
      "physical provider completion verification requires synchronous read_committed and verify_and_commit functions",
    );
  }
  const port = deepFreeze({
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    port_id: assertIdentifier(
      input.port_id,
      "physical_provider_completion_verification_port.port_id",
    ),
    evidence_domain_digest: assertDigest(
      input.evidence_domain_digest,
      "physical_provider_completion_verification_port.evidence_domain_digest",
    ),
    consistency_contract: "synchronous-linearizable-strong-read-after-commit-v1",
    durability_assurance: "caller_asserted_callback_backend_unattested",
    production_ready: false,
  });
  COMPLETION_VERIFICATION_PORTS.add(port);
  COMPLETION_VERIFICATION_PRIVATE.set(port, Object.freeze({
    read_committed: input.read_committed,
    verify_and_commit: input.verify_and_commit,
  }));
  return port;
}

// Enroll only Bob's fixed privately branded vault/native-ticket adapter.  This
// constructor accepts no callback, path, byte surface, or readiness boolean;
// the two synchronous operations are selected here and remain private to the
// dispatch module.  The enrolled adapter is intentionally non-production until
// its independently owned trust/principal/anchor/native/HIL blockers are
// actually satisfied by a future private production constructor.
function createPhysicalProviderCompletionVerificationPortFromFixedAdapter(adapter) {
  // The adapter is provider-opaque here: the broker validates only the neutral
  // completion-evidence-adapter shape (ids, digest, durability label, and two
  // synchronous read/commit methods) and never names or requires a provider.
  // The composition root injects the concrete (provider-package) adapter.
  try {
    assertProviderCompletionEvidenceAdapter(adapter);
  } catch (cause) {
    throw dispatchError(
      "physical_provider_completion_adapter_untrusted",
      "fixed completion evidence adapter does not satisfy the neutral adapter contract",
      cause,
    );
  }
  const readCommitted = adapter.read_committed;
  const verifyAndCommit = adapter.verify_and_commit;
  const port = deepFreeze({
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    port_id: assertIdentifier(
      adapter.port_id,
      "physical_provider_fixed_completion_adapter.port_id",
    ),
    evidence_domain_digest: assertDigest(
      adapter.evidence_domain_digest,
      "physical_provider_fixed_completion_adapter.evidence_domain_digest",
    ),
    consistency_contract: "synchronous-linearizable-strong-read-after-commit-v1",
    durability_assurance: adapter.durability_assurance,
    production_ready: false,
  });
  COMPLETION_VERIFICATION_PORTS.add(port);
  COMPLETION_VERIFICATION_PRIVATE.set(port, Object.freeze({
    read_committed(query) {
      return readCommitted(query);
    },
    verify_and_commit(query) {
      return verifyAndCommit(query);
    },
  }));
  return port;
}

function assertPhysicalProviderCompletionVerificationPort(port) {
  if (!port || !Object.isFrozen(port) || !COMPLETION_VERIFICATION_PORTS.has(port)
      || !COMPLETION_VERIFICATION_PRIVATE.has(port)
      || port.consistency_contract
        !== "synchronous-linearizable-strong-read-after-commit-v1") {
    throw dispatchError(
      "physical_provider_completion_port_untrusted",
      "physical provider completion verification requires Bob's private strong synchronous port",
    );
  }
  return port;
}

function callCompletionVerificationPort(port, callbackName, query, label) {
  assertPhysicalProviderCompletionVerificationPort(port);
  if (ACTIVE_COMPLETION_VERIFICATION_PORTS.has(port)) {
    throw dispatchError(
      "physical_provider_completion_port_reentrant",
      `${label} cannot re-enter its completion verification port`,
    );
  }
  ACTIVE_COMPLETION_VERIFICATION_PORTS.add(port);
  try {
    const callback = COMPLETION_VERIFICATION_PRIVATE.get(port)[callbackName];
    return assertSynchronousCompletionResult(callback(deepFreeze(query)), label);
  } catch (cause) {
    if (cause && typeof cause.code === "string"
        && cause.code.startsWith("physical_provider_completion_")) throw cause;
    throw dispatchError(
      callbackName === "read_committed"
        ? "physical_provider_completion_read_failed"
        : "physical_provider_completion_verification_failed",
      `${label} failed`,
      cause,
    );
  } finally {
    ACTIVE_COMPLETION_VERIFICATION_PORTS.delete(port);
  }
}

function normalizeProviderBinding(input, label = "physical_provider_binding") {
  assertClosedDataObject(input, label, [
    "version",
    "provider_id",
    "provider_descriptor_digest",
    "semantic_manifest_digest",
    "device_ref",
    "device_identity_digest",
    "custody_ref",
    "custody_identity_digest",
    "custody_epoch",
  ]);
  if (input.version !== PHYSICAL_PROVIDER_DISPATCH_VERSION) {
    throw dispatchError("physical_dispatch_invalid", `${label}.version is unsupported`);
  }
  const basis = {
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    provider_id: assertIdentifier(input.provider_id, `${label}.provider_id`),
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    semantic_manifest_digest: assertDigest(
      input.semantic_manifest_digest,
      `${label}.semantic_manifest_digest`,
    ),
    device_ref: normalizeOpaqueRef(input.device_ref, `${label}.device_ref`, { prefix: "device" }),
    device_identity_digest: assertDigest(input.device_identity_digest, `${label}.device_identity_digest`),
    custody_ref: normalizeOpaqueRef(input.custody_ref, `${label}.custody_ref`, { prefix: "custody" }),
    custody_identity_digest: assertDigest(input.custody_identity_digest, `${label}.custody_identity_digest`),
    custody_epoch: assertInteger(input.custody_epoch, `${label}.custody_epoch`, 1),
  };
  return deepFreeze({ ...basis, provider_binding_digest: hashCanonicalJson(basis) });
}

function normalizeReservationBinding(input, label = "physical_dispatch_reservation_binding") {
  assertClosedDataObject(input, label, [
    "reservation_ref",
    "receipt_digest",
    "reservation_request_digest",
    "node_id",
    "contract_hash",
    "source_graph_hash",
    "session_nucleus_hash",
    "resource_bundle_digest",
    "allocation_plan_digest",
    "allocation_digest",
    "attempt_ref",
    "execution_principal_ref",
    "effect_not_before",
    "effect_deadline",
    "session_id",
    "prep_token_hash",
    "dispatch_event_id",
    "graph_context_hash",
  ]);
  const effectNotBefore = assertTimestamp(input.effect_not_before, `${label}.effect_not_before`);
  const effectDeadline = assertTimestamp(input.effect_deadline, `${label}.effect_deadline`);
  if (Date.parse(effectNotBefore) >= Date.parse(effectDeadline)) {
    throw dispatchError("physical_dispatch_invalid", `${label} effect window is empty`);
  }
  return deepFreeze({
    reservation_ref: normalizeOpaqueRef(input.reservation_ref, `${label}.reservation_ref`, {
      prefix: "reservation",
    }),
    receipt_digest: assertDigest(input.receipt_digest, `${label}.receipt_digest`),
    reservation_request_digest: assertDigest(
      input.reservation_request_digest,
      `${label}.reservation_request_digest`,
    ),
    node_id: assertToken(input.node_id, `${label}.node_id`),
    contract_hash: assertDigest(input.contract_hash, `${label}.contract_hash`),
    source_graph_hash: assertDigest(input.source_graph_hash, `${label}.source_graph_hash`),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    resource_bundle_digest: assertDigest(
      input.resource_bundle_digest,
      `${label}.resource_bundle_digest`,
    ),
    allocation_plan_digest: assertDigest(
      input.allocation_plan_digest,
      `${label}.allocation_plan_digest`,
    ),
    allocation_digest: assertDigest(input.allocation_digest, `${label}.allocation_digest`),
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, {
      prefix: "attempt",
    }),
    execution_principal_ref: normalizeOpaqueRef(
      input.execution_principal_ref,
      `${label}.execution_principal_ref`,
      { prefix: "principal" },
    ),
    effect_not_before: effectNotBefore,
    effect_deadline: effectDeadline,
    session_id: assertToken(input.session_id, `${label}.session_id`),
    prep_token_hash: assertDigest(input.prep_token_hash, `${label}.prep_token_hash`),
    dispatch_event_id: assertToken(input.dispatch_event_id, `${label}.dispatch_event_id`),
    graph_context_hash: assertDigest(input.graph_context_hash, `${label}.graph_context_hash`),
  });
}

// This fence is deliberately a cooperative same-process seam, not a durable
// authority or a process boundary. The graph coordinator supplies the runner
// and holds its session lock while it proves that the exact preparation event
// is still the live dispatch head and synchronously enters the broker callback.
// The callback itself may return a Promise, but it must be entered exactly once
// before the runner returns; deferred or substituted callbacks fail closed.
function createPhysicalProviderDispatchHeadFence(input = {}) {
  assertClosedDataObject(input, "physical_provider_dispatch_head_fence", [
    "reservation_binding",
    "run_while_current",
  ]);
  const reservationBinding = normalizeReservationBinding(
    input.reservation_binding,
    "physical_provider_dispatch_head_fence.reservation_binding",
  );
  if (typeof input.run_while_current !== "function") {
    throw dispatchError(
      "physical_dispatch_invalid",
      "physical_provider_dispatch_head_fence.run_while_current must be a function",
    );
  }
  const reservationBindingDigest = hashCanonicalJson(reservationBinding);
  const fence = deepFreeze({
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    reservation_binding_digest: reservationBindingDigest,
    node_id: reservationBinding.node_id,
    prep_token_hash: reservationBinding.prep_token_hash,
    dispatch_event_id: reservationBinding.dispatch_event_id,
    assurance: "cooperative_same_process_live_task_graph_head_v1",
  });
  DISPATCH_HEAD_FENCES.add(fence);
  DISPATCH_HEAD_FENCE_PRIVATE.set(fence, {
    reservation_binding: reservationBinding,
    reservation_binding_digest: reservationBindingDigest,
    run_while_current: input.run_while_current,
  });
  return fence;
}

function assertPhysicalProviderDispatchHeadFence(input, reservationBinding) {
  if (!input || !Object.isFrozen(input) || !DISPATCH_HEAD_FENCES.has(input)
      || !DISPATCH_HEAD_FENCE_PRIVATE.has(input)) {
    throw dispatchError(
      "physical_dispatch_head_fence_untrusted",
      "physical dispatch requires a broker-branded TaskGraph head fence",
    );
  }
  const state = DISPATCH_HEAD_FENCE_PRIVATE.get(input);
  if (state.reservation_binding_digest !== hashCanonicalJson(reservationBinding)) {
    throw dispatchError(
      "physical_dispatch_head_fence_binding_drift",
      "physical TaskGraph head fence does not bind the exact reservation dispatch",
    );
  }
  return state;
}

function runWhilePhysicalDispatchHeadCurrent(privateState, label, callback) {
  const fenceState = privateState.dispatch_head_fence_state;
  let callbackActive = true;
  let callbackCount = 0;
  let callbackResult;
  let callbackFailure = null;
  const invoke = () => {
    if (!callbackActive) {
      throw dispatchError(
        "physical_dispatch_head_fence_deferred",
        `${label} TaskGraph head fence deferred broker entry`,
      );
    }
    if (callbackCount !== 0) {
      throw dispatchError(
        "physical_dispatch_head_fence_replayed",
        `${label} TaskGraph head fence replayed broker entry`,
      );
    }
    callbackCount += 1;
    try {
      callbackResult = callback();
      return callbackResult;
    } catch (cause) {
      callbackFailure = cause;
      throw cause;
    }
  };

  let runnerResult;
  try {
    runnerResult = fenceState.run_while_current(invoke);
  } catch (cause) {
    callbackActive = false;
    if (callbackFailure === cause) throw cause;
    const stale = cause && [
      "physical_resource_prepare_binding_drift",
      "physical_resource_dispatch_head_stale",
      "physical_task_graph_dispatch_head_stale",
    ].includes(cause.code);
    throw dispatchError(
      stale
        ? "physical_task_graph_dispatch_head_stale"
        : "physical_task_graph_dispatch_head_unavailable",
      stale
        ? `${label} refused because the exact TaskGraph dispatch head is stale`
        : `${label} could not prove the exact live TaskGraph dispatch head`,
      cause,
    );
  }
  callbackActive = false;
  if (callbackCount !== 1 || runnerResult !== callbackResult) {
    throw dispatchError(
      "physical_dispatch_head_fence_invalid",
      `${label} TaskGraph head fence did not synchronously preserve exact broker entry`,
    );
  }
  return callbackResult;
}

function normalizeReservationCommandAuthorityBinding(
  input,
  label = "physical_command_authority_reservation_binding",
) {
  assertClosedDataObject(input, label, [
    "reservation_request_digest",
    "node_id",
    "contract_hash",
    "source_graph_hash",
    "session_nucleus_hash",
    "resource_bundle_digest",
    "allocation_digest",
  ]);
  const basis = {
    reservation_request_digest: assertDigest(
      input.reservation_request_digest,
      `${label}.reservation_request_digest`,
    ),
    node_id: assertToken(input.node_id, `${label}.node_id`),
    contract_hash: assertDigest(input.contract_hash, `${label}.contract_hash`),
    source_graph_hash: assertDigest(input.source_graph_hash, `${label}.source_graph_hash`),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    resource_bundle_digest: assertDigest(
      input.resource_bundle_digest,
      `${label}.resource_bundle_digest`,
    ),
    allocation_digest: assertDigest(input.allocation_digest, `${label}.allocation_digest`),
  };
  return deepFreeze({ ...basis, reservation_command_authority_digest: hashCanonicalJson(basis) });
}

function createPhysicalProviderCommandAuthorizationPort(input = {}) {
  assertClosedDataObject(input, "physical_provider_command_authorization_port", [
    "port_id",
    "semantic_authority_digest",
    "authorization_epoch",
    "provider_binding_digest",
    "reservation_binding",
    "resource_bundle",
    "receipt_allocations",
    "authorizations",
  ]);
  const portId = assertIdentifier(input.port_id, "physical_provider_command_authorization_port.port_id");
  const semanticAuthorityDigest = assertDigest(
    input.semantic_authority_digest,
    "physical_provider_command_authorization_port.semantic_authority_digest",
  );
  const authorizationEpoch = assertInteger(
    input.authorization_epoch,
    "physical_provider_command_authorization_port.authorization_epoch",
    1,
  );
  const providerBindingDigest = assertDigest(
    input.provider_binding_digest,
    "physical_provider_command_authorization_port.provider_binding_digest",
  );
  const reservationBinding = normalizeReservationCommandAuthorityBinding(input.reservation_binding);
  const resourceBundle = normalizePhysicalResourceBundle(input.resource_bundle);
  if (resourceBundle.resource_bundle_digest !== reservationBinding.resource_bundle_digest) {
    throw dispatchError(
      "physical_command_authorization_bundle_drift",
      "physical command authorization bundle does not match the exact reservation binding",
    );
  }
  assertDenseArray(
    input.receipt_allocations,
    "physical_provider_command_authorization_port.receipt_allocations",
    1,
    4096,
  );
  const receiptAllocations = deepFreeze(input.receipt_allocations.map((allocation, index) => (
    normalizeResourceAllocation(
      allocation,
      `physical_provider_command_authorization_port.receipt_allocations[${index}]`,
    )
  )));
  const allocationDigest = hashCanonicalJson(receiptAllocations);
  if (allocationDigest !== reservationBinding.allocation_digest) {
    throw dispatchError(
      "physical_command_authorization_allocation_drift",
      "physical command authorization allocations do not match the exact reservation receipt",
    );
  }
  const allocationByAlias = new Map();
  for (const allocation of receiptAllocations) {
    if (allocationByAlias.has(allocation.alias)) {
      throw dispatchError(
        "physical_command_authorization_allocation_drift",
        "physical command authorization allocations repeat a resource alias",
      );
    }
    allocationByAlias.set(allocation.alias, allocation);
  }
  const requirementByAlias = new Map(
    resourceBundle.requirements.map((requirement) => [requirement.alias, requirement]),
  );
  assertDenseArray(
    input.authorizations,
    "physical_provider_command_authorization_port.authorizations",
    4,
    MAX_COMMANDS + 3,
  );
  const authorizations = input.authorizations.map((authorization, index) => {
    const label = `physical_provider_command_authorization_port.authorizations[${index}]`;
    assertClosedDataObject(authorization, label, [
      "command_kind",
      "command_ref",
      "operation_id",
      "operation_digest",
      "semantic_owner_ref",
      "semantic_owner_digest",
      "requested_effect_digest",
      "requested_effects_digest",
      "resource_alias",
      "resource_ref",
      "resource_requirement_digest",
    ]);
    if (!COMMAND_KINDS.includes(authorization.command_kind)) {
      throw dispatchError("physical_dispatch_invalid", `${label}.command_kind is unsupported`);
    }
    const basis = {
      version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
      port_id: portId,
      semantic_authority_digest: semanticAuthorityDigest,
      authorization_epoch: authorizationEpoch,
      provider_binding_digest: providerBindingDigest,
      reservation_command_authority_digest:
        reservationBinding.reservation_command_authority_digest,
      allocation_digest: allocationDigest,
      command_kind: authorization.command_kind,
      command_ref: normalizeOpaqueRef(authorization.command_ref, `${label}.command_ref`, {
        prefix: "command",
      }),
      operation_id: assertToken(authorization.operation_id, `${label}.operation_id`),
      operation_digest: assertDigest(
        authorization.operation_digest,
        `${label}.operation_digest`,
      ),
      semantic_owner_ref: normalizeOpaqueRef(
        authorization.semantic_owner_ref,
        `${label}.semantic_owner_ref`,
        { prefix: "semantic-owner" },
      ),
      semantic_owner_digest: assertDigest(
        authorization.semantic_owner_digest,
        `${label}.semantic_owner_digest`,
      ),
      requested_effect_digest: assertDigest(
        authorization.requested_effect_digest,
        `${label}.requested_effect_digest`,
      ),
      requested_effects_digest: assertDigest(
        authorization.requested_effects_digest,
        `${label}.requested_effects_digest`,
      ),
      resource_alias: assertIdentifier(authorization.resource_alias, `${label}.resource_alias`),
      resource_ref: assertToken(authorization.resource_ref, `${label}.resource_ref`),
      resource_requirement_digest: assertDigest(
        authorization.resource_requirement_digest,
        `${label}.resource_requirement_digest`,
      ),
    };
    const allocation = allocationByAlias.get(basis.resource_alias);
    const requirement = requirementByAlias.get(basis.resource_alias);
    if (!allocation || !requirement || allocation.resource_ref !== basis.resource_ref
        || hashCanonicalJson(requirement) !== basis.resource_requirement_digest) {
      throw dispatchError(
        "physical_command_resource_binding_drift",
        `${label} does not bind one exact allocated resource requirement`,
      );
    }
    const projection = deepFreeze({
      ...basis,
      command_authorization_digest: hashCanonicalJson(basis),
    });
    if (!requirement.requested_effect_digests.includes(projection.requested_effect_digest)) {
      throw dispatchError(
        "physical_command_effect_not_in_bundle",
        `${label}.requested_effect_digest is not admitted by the exact resource bundle`,
      );
    }
    COMMAND_AUTHORIZATIONS.add(projection);
    return projection;
  });
  const commandRefs = authorizations.map((entry) => entry.command_ref);
  if (new Set(commandRefs).size !== commandRefs.length) {
    throw dispatchError("physical_dispatch_invalid", "physical command authorizations must be unique");
  }
  for (const kind of ["cleanup", "fence", "quarantine"]) {
    if (authorizations.filter((entry) => entry.command_kind === kind).length !== 1) {
      throw dispatchError(
        "physical_dispatch_invalid",
        `physical command authorization requires exactly one ${kind} binding`,
      );
    }
  }
  if (!authorizations.some((entry) => entry.command_kind === "command")) {
    throw dispatchError("physical_dispatch_invalid", "physical command authorization requires a command");
  }
  const authorizationSetDigest = hashCanonicalJson(
    [...authorizations]
      .sort((left, right) => compareCodeUnits(left.command_ref, right.command_ref))
      .map((entry) => entry.command_authorization_digest),
  );
  const port = deepFreeze({
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    port_id: portId,
    semantic_authority_digest: semanticAuthorityDigest,
    authorization_epoch: authorizationEpoch,
    provider_binding_digest: providerBindingDigest,
    reservation_binding: reservationBinding,
    resource_bundle_digest: resourceBundle.resource_bundle_digest,
    allocation_digest: allocationDigest,
    authorization_count: authorizations.length,
    authorization_set_digest: authorizationSetDigest,
  });
  const state = {
    allocation_digest: allocationDigest,
    receipt_allocations: receiptAllocations,
    authorizations_by_ref: new Map(authorizations.map((entry) => [entry.command_ref, entry])),
  };
  COMMAND_AUTHORIZATION_PORTS.add(port);
  COMMAND_AUTHORIZATION_PRIVATE.set(port, state);
  for (const authorization of authorizations) COMMAND_AUTHORIZATION_OWNER.set(authorization, state);
  return port;
}

function assertPhysicalProviderCommandAuthorizationPort(port) {
  if (!port || !Object.isFrozen(port) || !COMMAND_AUTHORIZATION_PORTS.has(port)
      || !COMMAND_AUTHORIZATION_PRIVATE.has(port)) {
    throw dispatchError(
      "physical_command_authorization_port_untrusted",
      "physical command authorization port must be created by Bob's private factory",
    );
  }
  return port;
}

function resolvePhysicalProviderCommandAuthorization(port, commandRefInput) {
  assertPhysicalProviderCommandAuthorizationPort(port);
  const commandRef = normalizeOpaqueRef(commandRefInput, "physical_command_authorization.command_ref", {
    prefix: "command",
  });
  return COMMAND_AUTHORIZATION_PRIVATE.get(port).authorizations_by_ref.get(commandRef) || null;
}

function normalizeCommandDefinition(input, kind, index, authorizationState) {
  const label = `physical_provider_commands.${kind}[${index}]`;
  assertClosedDataObject(input, label, [
    "command_authorization",
    "execute",
  ]);
  if (typeof input.execute !== "function") {
    throw dispatchError("physical_dispatch_invalid", `${label}.execute must be a function`);
  }
  const authorization = input.command_authorization;
  if (!authorization || !Object.isFrozen(authorization)
      || !COMMAND_AUTHORIZATIONS.has(authorization)
      || COMMAND_AUTHORIZATION_OWNER.get(authorization) !== authorizationState
      || authorization.command_kind !== kind) {
    throw dispatchError(
      "physical_command_authorization_untrusted",
      `${label} requires the exact private semantic/effect authorization`,
    );
  }
  const basis = {
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    command_kind: kind,
    command_ref: authorization.command_ref,
    operation_id: authorization.operation_id,
    operation_digest: authorization.operation_digest,
    semantic_owner_ref: authorization.semantic_owner_ref,
    semantic_owner_digest: authorization.semantic_owner_digest,
    requested_effect_digest: authorization.requested_effect_digest,
    requested_effects_digest: authorization.requested_effects_digest,
    command_authorization_digest: authorization.command_authorization_digest,
    semantic_authority_digest: authorization.semantic_authority_digest,
    authorization_epoch: authorization.authorization_epoch,
    reservation_command_authority_digest: authorization.reservation_command_authority_digest,
    allocation_digest: authorization.allocation_digest,
    resource_alias: authorization.resource_alias,
    resource_ref: authorization.resource_ref,
    resource_requirement_digest: authorization.resource_requirement_digest,
  };
  const projection = deepFreeze({ ...basis, command_projection_digest: hashCanonicalJson(basis) });
  COMMAND_PROJECTIONS.add(projection);
  return { execute: input.execute, projection };
}

function createPhysicalProviderCommandRegistry(input = {}) {
  assertClosedDataObject(input, "physical_provider_command_registry", [
    "provider_binding",
    "command_authorization_port",
    "completion_verification_port",
    "observe_binding",
    "commands",
    "compensation",
  ]);
  if (typeof input.observe_binding !== "function") {
    throw dispatchError(
      "physical_dispatch_invalid",
      "physical_provider_command_registry.observe_binding must be a function",
    );
  }
  const providerBinding = normalizeProviderBinding(input.provider_binding);
  const authorizationPort = assertPhysicalProviderCommandAuthorizationPort(
    input.command_authorization_port,
  );
  const completionVerificationPort = assertPhysicalProviderCompletionVerificationPort(
    input.completion_verification_port,
  );
  if (authorizationPort.provider_binding_digest !== providerBinding.provider_binding_digest) {
    throw dispatchError(
      "physical_command_authorization_provider_drift",
      "physical command authorization provider binding drift",
    );
  }
  const authorizationState = COMMAND_AUTHORIZATION_PRIVATE.get(authorizationPort);
  assertDenseArray(input.commands, "physical_provider_command_registry.commands", 1, MAX_COMMANDS);
  assertClosedDataObject(input.compensation, "physical_provider_command_registry.compensation", [
    "cleanup",
    "fence",
    "quarantine",
  ]);
  const definitions = input.commands.map((definition, index) => (
    normalizeCommandDefinition(definition, "command", index, authorizationState)
  ));
  for (const [index, kind] of ["cleanup", "fence", "quarantine"].entries()) {
    definitions.push(normalizeCommandDefinition(
      input.compensation[kind],
      kind,
      index,
      authorizationState,
    ));
  }
  const commandRefs = definitions.map((entry) => entry.projection.command_ref);
  if (new Set(commandRefs).size !== commandRefs.length) {
    throw dispatchError("physical_dispatch_invalid", "physical provider command refs must be unique");
  }
  const sortedProjections = [...definitions]
    .map((entry) => entry.projection)
    .sort((left, right) => compareCodeUnits(left.command_ref, right.command_ref));
  const registryBasis = {
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    provider_binding_digest: providerBinding.provider_binding_digest,
    command_authorization_port_id: authorizationPort.port_id,
    semantic_authority_digest: authorizationPort.semantic_authority_digest,
    authorization_epoch: authorizationPort.authorization_epoch,
    reservation_command_authority_digest:
      authorizationPort.reservation_binding.reservation_command_authority_digest,
    authorization_set_digest: authorizationPort.authorization_set_digest,
    completion_verification_port_id: completionVerificationPort.port_id,
    completion_evidence_domain_digest: completionVerificationPort.evidence_domain_digest,
    completion_consistency_contract: completionVerificationPort.consistency_contract,
    command_projection_digests: sortedProjections.map((entry) => entry.command_projection_digest),
  };
  const commands = definitions
    .filter((entry) => entry.projection.command_kind === "command")
    .map((entry) => entry.projection);
  const compensation = {};
  for (const kind of ["cleanup", "fence", "quarantine"]) {
    compensation[kind] = definitions.find((entry) => entry.projection.command_kind === kind).projection;
  }
  const registry = deepFreeze({
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    provider_binding: providerBinding,
    command_authorization: deepFreeze({
      port_id: authorizationPort.port_id,
      semantic_authority_digest: authorizationPort.semantic_authority_digest,
      authorization_epoch: authorizationPort.authorization_epoch,
      reservation_binding: authorizationPort.reservation_binding,
      authorization_set_digest: authorizationPort.authorization_set_digest,
    }),
    completion_verification: deepFreeze({
      port_id: completionVerificationPort.port_id,
      evidence_domain_digest: completionVerificationPort.evidence_domain_digest,
      consistency_contract: completionVerificationPort.consistency_contract,
      durability_assurance: completionVerificationPort.durability_assurance,
      production_ready: completionVerificationPort.production_ready,
    }),
    commands,
    compensation,
    command_registry_digest: hashCanonicalJson(registryBasis),
  });
  const privateState = {
    provider_binding: providerBinding,
    command_authorization_port: authorizationPort,
    completion_verification_port: completionVerificationPort,
    observe_binding: input.observe_binding,
    methods: new Map(),
    projections_by_ref: new Map(),
  };
  for (const definition of definitions) {
    privateState.methods.set(definition.projection, definition.execute);
    privateState.projections_by_ref.set(definition.projection.command_ref, definition.projection);
    COMMAND_PRIVATE.set(definition.projection, privateState);
  }
  REGISTRIES.add(registry);
  REGISTRY_PRIVATE.set(registry, privateState);
  return registry;
}

function assertPhysicalProviderCommandRegistry(registry) {
  if (!registry || !Object.isFrozen(registry) || !REGISTRIES.has(registry)
      || !REGISTRY_PRIVATE.has(registry)) {
    throw dispatchError(
      "physical_provider_registry_untrusted",
      "physical provider command registry must be created by Bob's private factory",
    );
  }
  return registry;
}

function resolvePhysicalProviderCommand(registry, commandRefInput) {
  assertPhysicalProviderCommandRegistry(registry);
  const commandRef = normalizeOpaqueRef(commandRefInput, "physical_provider_command.command_ref", {
    prefix: "command",
  });
  return REGISTRY_PRIVATE.get(registry).projections_by_ref.get(commandRef) || null;
}

function assertCommandProjectionForRegistry(registryState, projection, allowedKinds = COMMAND_KINDS) {
  if (!projection || !Object.isFrozen(projection) || !COMMAND_PROJECTIONS.has(projection)
      || COMMAND_PRIVATE.get(projection) !== registryState
      || !allowedKinds.includes(projection.command_kind)) {
    throw dispatchError(
      "physical_command_projection_untrusted",
      "physical command requires the exact registry-owned semantic projection",
    );
  }
  return projection;
}

function assertReservationAuthorization(privateState, authorization) {
  const expected = privateState.reservation_binding;
  for (const field of [
    "reservation_ref",
    "reservation_request_digest",
    "node_id",
    "contract_hash",
    "source_graph_hash",
    "session_nucleus_hash",
    "resource_bundle_digest",
    "allocation_plan_digest",
    "allocation_digest",
  ]) {
    if (authorization[field] !== expected[field]) {
      throw dispatchError("physical_reservation_binding_drift", `physical effect authority ${field} drift`);
    }
  }
  if (authorization.receipt_digest !== privateState.credential.receipt_digest
      || authorization.credential_binding_digest
        !== privateState.credential.credential_binding_digest) {
    throw dispatchError("physical_fence_binding_drift", "physical effect authority fence/receipt drift");
  }
  return authorization;
}

function assertProviderBindingExact(expected, observed) {
  if (observed.provider_binding_digest !== expected.provider_binding_digest) {
    throw dispatchError("physical_provider_binding_drift", "provider/device/custody binding drifted");
  }
  return observed;
}

function assertReservationEffectAuthorizedAtProviderSeam(privateState) {
  let authorization;
  try {
    authorization = assertPhysicalResourceEffectAuthorizedNow(
      privateState.reservation_authority,
      privateState.credential,
    );
  } catch (cause) {
    throw dispatchError(
      cause && typeof cause.code === "string" ? cause.code : "physical_effect_authorization_failed",
      "physical resource effect authority failed at the provider command seam",
      cause,
    );
  }
  return assertReservationAuthorization(privateState, authorization);
}

function timeoutError(label, promise) {
  const error = dispatchError("physical_provider_timeout", `${label} exceeded the broker deadline`);
  Object.defineProperty(error, "pending_provider_call", { value: promise });
  return error;
}

async function callWithDeadline(privateState, label, callback) {
  const callPromise = Promise.resolve().then(callback);
  let timer = null;
  const timeoutPromise = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(timeoutError(label, callPromise)), privateState.provider_call_timeout_ms);
  });
  try {
    return await Promise.race([callPromise, timeoutPromise]);
  } finally {
    clearTimeout(timer);
  }
}

function providerCapabilityBasis(privateState, command, commandInput, authorization) {
  const provider = privateState.registry_state.provider_binding;
  return {
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    ...projectExecutionLineage(privateState.dispatch_authority_claim),
    // The worker/provider needs proof that the whole active admission was
    // bound, not the requester/principal and campaign metadata themselves.
    // The exact fields stay broker-private until the durable completion
    // evidence join below.
    active_admission_binding_digest: activeAdmissionBindingDigest(
      privateState.dispatch_authority_claim,
    ),
    reservation_ref: authorization.reservation_ref,
    receipt_digest: authorization.receipt_digest,
    reservation_request_digest: authorization.reservation_request_digest,
    node_id: authorization.node_id,
    contract_hash: authorization.contract_hash,
    source_graph_hash: authorization.source_graph_hash,
    session_nucleus_hash: authorization.session_nucleus_hash,
    resource_bundle_digest: authorization.resource_bundle_digest,
    allocation_plan_digest: authorization.allocation_plan_digest,
    allocation_digest: authorization.allocation_digest,
    credential_binding_digest: authorization.credential_binding_digest,
    effect_authorization_digest: authorization.effect_authorization_digest,
    fencing_semantics: authorization.fencing_semantics,
    effect_deadline: authorization.effect_deadline,
    provider_id: provider.provider_id,
    provider_descriptor_digest: provider.provider_descriptor_digest,
    semantic_manifest_digest: provider.semantic_manifest_digest,
    provider_binding_digest: provider.provider_binding_digest,
    device_ref: provider.device_ref,
    device_identity_digest: provider.device_identity_digest,
    custody_ref: provider.custody_ref,
    custody_identity_digest: provider.custody_identity_digest,
    custody_epoch: provider.custody_epoch,
    command_kind: command.command_kind,
    command_ref: command.command_ref,
    operation_id: command.operation_id,
    operation_digest: command.operation_digest,
    semantic_owner_ref: command.semantic_owner_ref,
    semantic_owner_digest: command.semantic_owner_digest,
    requested_effect_digest: command.requested_effect_digest,
    command_projection_digest: command.command_projection_digest,
    command_authorization_digest: command.command_authorization_digest,
    semantic_authority_digest: command.semantic_authority_digest,
    authorization_epoch: command.authorization_epoch,
    reservation_command_authority_digest: command.reservation_command_authority_digest,
    resource_alias: command.resource_alias,
    resource_ref: command.resource_ref,
    resource_requirement_digest: command.resource_requirement_digest,
    requested_effects_digest: command.requested_effects_digest,
    command_input_ref: commandInput.command_input_ref,
    command_input_digest: commandInput.command_input_digest,
    command_sequence: privateState.command_sequence + 1,
  };
}

function mintProviderCapability(privateState, command, commandInput, authorization) {
  const basis = providerCapabilityBasis(privateState, command, commandInput, authorization);
  const capability = deepFreeze({
    ...basis,
    provider_dispatch_capability_digest: hashCanonicalJson(basis),
  });
  PROVIDER_CAPABILITIES.add(capability);
  PROVIDER_CAPABILITY_PRIVATE.set(capability, {
    bridge_state: privateState,
    command,
    consumed: false,
    in_provider_call: false,
  });
  return capability;
}

function assertPhysicalProviderDispatchCapability(capability, expected = {}) {
  if (!capability || !Object.isFrozen(capability) || !PROVIDER_CAPABILITIES.has(capability)
      || !PROVIDER_CAPABILITY_PRIVATE.has(capability)) {
    throw dispatchError(
      "physical_provider_dispatch_capability_untrusted",
      "physical provider dispatch requires Bob's private single-use capability",
    );
  }
  const capabilityState = PROVIDER_CAPABILITY_PRIVATE.get(capability);
  if (!capabilityState.in_provider_call) {
    throw dispatchError(
      "physical_provider_dispatch_capability_inactive",
      "physical provider dispatch capability is not active at the provider call seam",
    );
  }
  const allowed = [
    ...EXECUTION_LINEAGE_PROJECTION_FIELDS,
    "active_admission_binding_digest",
    "reservation_ref",
    "receipt_digest",
    "reservation_request_digest",
    "node_id",
    "contract_hash",
    "source_graph_hash",
    "session_nucleus_hash",
    "resource_bundle_digest",
    "allocation_plan_digest",
    "allocation_digest",
    "credential_binding_digest",
    "requested_effects_digest",
    "provider_id",
    "provider_descriptor_digest",
    "semantic_manifest_digest",
    "provider_binding_digest",
    "device_ref",
    "device_identity_digest",
    "custody_ref",
    "custody_identity_digest",
    "custody_epoch",
    "command_kind",
    "command_ref",
    "operation_id",
    "operation_digest",
    "semantic_owner_ref",
    "semantic_owner_digest",
    "requested_effect_digest",
    "command_projection_digest",
    "command_authorization_digest",
    "semantic_authority_digest",
    "authorization_epoch",
    "reservation_command_authority_digest",
    "resource_alias",
    "resource_ref",
    "resource_requirement_digest",
    "command_input_ref",
    "command_input_digest",
  ];
  assertClosedDataObject(expected, "physical_provider_dispatch_expected", [], allowed);
  for (const [field, value] of Object.entries(expected)) {
    if (capability[field] !== value) {
      throw dispatchError("physical_provider_dispatch_binding_drift", `${field} dispatch binding drift`);
    }
  }
  return capability;
}

function normalizeProviderResult(input, label) {
  assertClosedDataObject(input, label, ["version", "completion", "provider_result_digest"], [
    "provider_receipt_ref",
  ]);
  if (input.version !== PHYSICAL_PROVIDER_DISPATCH_VERSION
      || !COMPLETION_VALUES.includes(input.completion)) {
    throw dispatchError("physical_provider_invalid_result", `${label} has an unsupported result`);
  }
  const result = {
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    completion: input.completion,
    provider_result_digest: assertDigest(input.provider_result_digest, `${label}.provider_result_digest`),
    provider_receipt_ref: input.provider_receipt_ref == null
      ? null
      : normalizeOpaqueRef(input.provider_receipt_ref, `${label}.provider_receipt_ref`, {
        prefix: "provider-receipt",
      }),
  };
  return deepFreeze(result);
}

function completionBindingBasis(privateState, capability) {
  const reservation = privateState.reservation_binding;
  const provider = privateState.registry_state.provider_binding;
  const port = privateState.registry_state.completion_verification_port;
  return {
    domain: COMPLETION_BINDING_DOMAIN,
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    ...projectExecutionLineage(capability),
    ...projectActiveAdmission(privateState.dispatch_authority_claim),
    active_admission_binding_digest: capability.active_admission_binding_digest,
    completion_verification_port_id: port.port_id,
    completion_evidence_domain_digest: port.evidence_domain_digest,
    reservation_ref: capability.reservation_ref,
    admission_receipt_digest: reservation.receipt_digest,
    effect_receipt_digest: capability.receipt_digest,
    reservation_request_digest: capability.reservation_request_digest,
    reservation_binding_digest: hashCanonicalJson(reservation),
    node_id: capability.node_id,
    contract_hash: capability.contract_hash,
    source_graph_hash: capability.source_graph_hash,
    session_nucleus_hash: capability.session_nucleus_hash,
    resource_bundle_digest: capability.resource_bundle_digest,
    allocation_plan_digest: capability.allocation_plan_digest,
    allocation_digest: capability.allocation_digest,
    attempt_ref: reservation.attempt_ref,
    execution_principal_ref: reservation.execution_principal_ref,
    session_id: reservation.session_id,
    admission_credential_binding_digest: privateState.admission_credential_binding_digest,
    effect_credential_binding_digest: capability.credential_binding_digest,
    effect_authorization_digest: capability.effect_authorization_digest,
    fencing_semantics: capability.fencing_semantics,
    effect_not_before: reservation.effect_not_before,
    effect_deadline: capability.effect_deadline,
    task_graph_dispatch_head_fence_digest:
      privateState.dispatch_head_fence.reservation_binding_digest,
    prep_token_hash: reservation.prep_token_hash,
    dispatch_event_id: reservation.dispatch_event_id,
    graph_context_hash: reservation.graph_context_hash,
    provider_id: provider.provider_id,
    provider_descriptor_digest: provider.provider_descriptor_digest,
    semantic_manifest_digest: provider.semantic_manifest_digest,
    provider_binding_digest: provider.provider_binding_digest,
    device_ref: provider.device_ref,
    device_identity_digest: provider.device_identity_digest,
    custody_ref: provider.custody_ref,
    custody_identity_digest: provider.custody_identity_digest,
    custody_epoch: provider.custody_epoch,
    command_kind: capability.command_kind,
    command_ref: capability.command_ref,
    operation_id: capability.operation_id,
    operation_digest: capability.operation_digest,
    semantic_owner_ref: capability.semantic_owner_ref,
    semantic_owner_digest: capability.semantic_owner_digest,
    requested_effect_digest: capability.requested_effect_digest,
    requested_effects_digest: capability.requested_effects_digest,
    command_projection_digest: capability.command_projection_digest,
    command_authorization_digest: capability.command_authorization_digest,
    semantic_authority_digest: capability.semantic_authority_digest,
    authorization_epoch: capability.authorization_epoch,
    reservation_command_authority_digest: capability.reservation_command_authority_digest,
    resource_alias: capability.resource_alias,
    resource_ref: capability.resource_ref,
    resource_requirement_digest: capability.resource_requirement_digest,
    command_input_ref: capability.command_input_ref,
    command_input_digest: capability.command_input_digest,
    command_sequence: capability.command_sequence,
    provider_dispatch_capability_digest: capability.provider_dispatch_capability_digest,
  };
}

function makeCompletionBinding(privateState, capability) {
  const basis = completionBindingBasis(privateState, capability);
  return deepFreeze({
    ...basis,
    completion_binding_digest: hashCanonicalJson(basis),
  });
}

function completionReceiptBasis(evidence) {
  return {
    domain: COMPLETION_RECEIPT_DOMAIN,
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    completion_binding_digest: evidence.completion_binding_digest,
    completion: evidence.completion,
    effect_disposition: evidence.effect_disposition,
    provider_result_digest: evidence.provider_result_digest,
    provider_receipt_ref: evidence.provider_receipt_ref,
    committed_receipt_ref: evidence.committed_receipt_ref,
  };
}

function normalizeCompletionEvidenceRecord(input, binding, label, expectedClaim = null) {
  assertClosedDataObject(input, label, [
    "version",
    "completion_binding_digest",
    "completion",
    "effect_disposition",
    "provider_result_digest",
    "provider_receipt_ref",
    "committed_receipt_ref",
    "committed_receipt_digest",
    "completion_evidence_digest",
  ]);
  if (input.version !== PHYSICAL_PROVIDER_DISPATCH_VERSION
      || !DEFINITIVE_COMPLETION_VALUES.includes(input.completion)) {
    throw dispatchError(
      "physical_provider_completion_evidence_invalid",
      `${label} is not a definitive completion record`,
    );
  }
  const evidence = {
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    completion_binding_digest: assertDigest(
      input.completion_binding_digest,
      `${label}.completion_binding_digest`,
    ),
    completion: input.completion,
    effect_disposition: assertToken(input.effect_disposition, `${label}.effect_disposition`),
    provider_result_digest: assertDigest(
      input.provider_result_digest,
      `${label}.provider_result_digest`,
    ),
    provider_receipt_ref: input.provider_receipt_ref == null
      ? null
      : normalizeOpaqueRef(input.provider_receipt_ref, `${label}.provider_receipt_ref`, {
        prefix: "provider-receipt",
      }),
    committed_receipt_ref: normalizeOpaqueRef(
      input.committed_receipt_ref,
      `${label}.committed_receipt_ref`,
      { prefix: "completion-receipt" },
    ),
    committed_receipt_digest: assertDigest(
      input.committed_receipt_digest,
      `${label}.committed_receipt_digest`,
    ),
    completion_evidence_digest: assertDigest(
      input.completion_evidence_digest,
      `${label}.completion_evidence_digest`,
    ),
  };
  if (evidence.completion_binding_digest !== binding.completion_binding_digest) {
    throw dispatchError(
      "physical_provider_completion_evidence_binding_drift",
      `${label} does not bind the exact reservation, fence, provider, command, input, and capability`,
    );
  }
  if (evidence.effect_disposition !== COMPLETION_EFFECT_DISPOSITIONS[evidence.completion]) {
    throw dispatchError(
      "physical_provider_completion_evidence_disposition_drift",
      `${label} effect disposition contradicts its definitive completion`,
    );
  }
  if (expectedClaim != null
      && (evidence.completion !== expectedClaim.completion
        || evidence.provider_result_digest !== expectedClaim.provider_result_digest
        || evidence.provider_receipt_ref !== expectedClaim.provider_receipt_ref)) {
    throw dispatchError(
      "physical_provider_completion_evidence_claim_drift",
      `${label} does not bind the exact provider completion claim`,
    );
  }
  const receiptBasis = completionReceiptBasis(evidence);
  if (evidence.committed_receipt_digest !== hashCanonicalJson(receiptBasis)) {
    throw dispatchError(
      "physical_provider_completion_receipt_invalid",
      `${label} committed receipt digest is not canonical`,
    );
  }
  if (evidence.completion_evidence_digest !== hashCanonicalJson({
    ...receiptBasis,
    domain: COMPLETION_EVIDENCE_DOMAIN,
    committed_receipt_digest: evidence.committed_receipt_digest,
  })) {
    throw dispatchError(
      "physical_provider_completion_evidence_invalid",
      `${label} evidence digest is not canonical`,
    );
  }
  return deepFreeze(evidence);
}

function normalizeCompletionEvidence(input, binding, label, expectedClaim = null) {
  try {
    return normalizeCompletionEvidenceRecord(input, binding, label, expectedClaim);
  } catch (cause) {
    if (cause && typeof cause.code === "string"
        && cause.code.startsWith("physical_provider_completion_")) throw cause;
    throw dispatchError(
      "physical_provider_completion_evidence_invalid",
      `${label} is not exact closed completion evidence`,
      cause,
    );
  }
}

function readCommittedCompletionEvidence(privateState, binding, label) {
  const raw = callCompletionVerificationPort(
    privateState.registry_state.completion_verification_port,
    "read_committed",
    {
      version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
      completion_binding: binding,
    },
    `${label} durable readback`,
  );
  if (raw == null) return null;
  return normalizeCompletionEvidence(raw, binding, `${label}.committed_evidence`);
}

function verifyAndCommitCompletionEvidence(privateState, binding, claim, label) {
  const raw = callCompletionVerificationPort(
    privateState.registry_state.completion_verification_port,
    "verify_and_commit",
    {
      version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
      completion_binding: binding,
      provider_claim: claim,
    },
    `${label} verify-and-commit`,
  );
  if (raw == null) {
    throw dispatchError(
      "physical_provider_completion_evidence_missing",
      `${label} returned no durable verified completion evidence`,
    );
  }
  const committed = normalizeCompletionEvidence(
    raw,
    binding,
    `${label}.verified_evidence`,
    claim,
  );
  const readback = readCommittedCompletionEvidence(privateState, binding, label);
  if (readback == null
      || readback.completion_evidence_digest !== committed.completion_evidence_digest
      || readback.committed_receipt_ref !== committed.committed_receipt_ref
      || readback.committed_receipt_digest !== committed.committed_receipt_digest) {
    throw dispatchError(
      "physical_provider_completion_not_durable",
      `${label} completion evidence was not synchronously readable after commit`,
    );
  }
  return committed;
}

function resultFromCompletionEvidence(evidence) {
  return deepFreeze({
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    completion: evidence.completion,
    provider_result_digest: evidence.provider_result_digest,
    provider_receipt_ref: evidence.provider_receipt_ref,
  });
}

async function invokeRegisteredCommand(privateState, command, commandInput) {
  // Revocation, expiry, trust, or binding drift is checked before even the
  // provider observation callback can run.
  assertCurrentPhysicalDispatchExecutionAuthorityClaim(
    privateState.dispatch_authority_claim,
    privateState.dispatch_authority_owner,
  );
  const observedRaw = await callWithDeadline(
    privateState,
    "physical provider binding observation",
    () => {
      const observe = () => {
        assertCurrentPhysicalDispatchExecutionAuthorityClaim(
          privateState.dispatch_authority_claim,
          privateState.dispatch_authority_owner,
        );
        assertReservationEffectAuthorizedAtProviderSeam(privateState);
        return privateState.registry_state.observe_binding();
      };
      return command.command_kind === "command"
        ? runWhilePhysicalDispatchHeadCurrent(
          privateState,
          "physical provider binding observation",
          observe,
        )
        : observe();
    },
  );
  const observed = normalizeProviderBinding(observedRaw, "observed_physical_provider_binding");
  assertProviderBindingExact(privateState.registry_state.provider_binding, observed);
  const authorization = assertReservationEffectAuthorizedAtProviderSeam(privateState);
  assertCurrentPhysicalDispatchExecutionAuthorityClaim(
    privateState.dispatch_authority_claim,
    privateState.dispatch_authority_owner,
  );
  const capability = mintProviderCapability(privateState, command, commandInput, authorization);
  const capabilityState = PROVIDER_CAPABILITY_PRIVATE.get(capability);
  const completionBinding = makeCompletionBinding(privateState, capability);
  const implementation = privateState.registry_state.methods.get(command);
  if (typeof implementation !== "function") {
    throw dispatchError("physical_command_projection_untrusted", "physical command method disappeared");
  }
  if (capabilityState.consumed) {
    throw dispatchError("physical_provider_dispatch_replay", "physical provider dispatch capability was replayed");
  }
  const priorEvidence = readCommittedCompletionEvidence(
    privateState,
    completionBinding,
    `physical provider ${command.command_kind} command`,
  );
  if (priorEvidence != null) {
    capabilityState.consumed = true;
    privateState.command_sequence += 1;
    return {
      capability,
      completion_evidence: priorEvidence,
      completion_source: "durable_readback_before_provider_entry",
      provider_call_performed: false,
      result: resultFromCompletionEvidence(priorEvidence),
    };
  }
  capabilityState.consumed = true;
  capabilityState.in_provider_call = true;
  const providerRequest = deepFreeze({
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    dispatch_capability: capability,
    command_projection: command,
    command_input_ref: commandInput.command_input_ref,
    command_input_digest: commandInput.command_input_digest,
  });
  try {
    let raw;
    try {
      raw = await callWithDeadline(
        privateState,
        `physical provider ${command.command_kind} command`,
        () => {
          const enterProvider = () => {
            assertCurrentPhysicalDispatchExecutionAuthorityClaim(
              privateState.dispatch_authority_claim,
              privateState.dispatch_authority_owner,
            );
            // The deadline wrapper schedules provider entry onto a later turn.
            // Re-read the exact reservation inside that callback so expiry,
            // revocation, or durable binding drift in the scheduling gap cannot
            // reach the provider.
            assertReservationEffectAuthorizedAtProviderSeam(privateState);
            return implementation(providerRequest);
          };
          return command.command_kind === "command"
            ? runWhilePhysicalDispatchHeadCurrent(
              privateState,
              "physical provider command entry",
              enterProvider,
            )
            : enterProvider();
        },
      );
    } catch (cause) {
      const recovered = readCommittedCompletionEvidence(
        privateState,
        completionBinding,
        `physical provider ${command.command_kind} lost response`,
      );
      if (recovered == null) throw cause;
      if (cause && cause.pending_provider_call) {
        privateState.pending_provider_calls.add(cause.pending_provider_call);
        Promise.resolve(cause.pending_provider_call).finally(() => {
          privateState.pending_provider_calls.delete(cause.pending_provider_call);
        }).catch(() => undefined);
      }
      privateState.command_sequence += 1;
      return {
        capability,
        completion_evidence: recovered,
        completion_source: "durable_readback_after_provider_response_loss",
        provider_call_performed: true,
        result: resultFromCompletionEvidence(recovered),
      };
    }
    privateState.command_sequence += 1;
    let claim;
    try {
      claim = normalizeProviderResult(raw, "physical_provider_command_result");
    } catch (cause) {
      const recovered = readCommittedCompletionEvidence(
        privateState,
        completionBinding,
        `physical provider ${command.command_kind} invalid response`,
      );
      if (recovered == null) throw cause;
      return {
        capability,
        completion_evidence: recovered,
        completion_source: "durable_readback_after_invalid_provider_response",
        provider_call_performed: true,
        result: resultFromCompletionEvidence(recovered),
      };
    }
    const evidence = claim.completion === "ambiguous"
      ? readCommittedCompletionEvidence(
        privateState,
        completionBinding,
        `physical provider ${command.command_kind} ambiguous response`,
      )
      : verifyAndCommitCompletionEvidence(
        privateState,
        completionBinding,
        claim,
        `physical provider ${command.command_kind}`,
      );
    if (evidence == null) {
      return {
        capability,
        completion_evidence: null,
        completion_source: "unverified_provider_ambiguity",
        provider_call_performed: true,
        result: claim,
      };
    }
    return {
      capability,
      completion_evidence: evidence,
      completion_source: claim.completion === "ambiguous"
        ? "durable_readback_after_provider_ambiguity"
        : "verified_durable_commit",
      provider_call_performed: true,
      result: resultFromCompletionEvidence(evidence),
    };
  } finally {
    capabilityState.in_provider_call = false;
  }
}

function makeCommandInput(commandInputRef, commandInputDigest) {
  return deepFreeze({
    command_input_ref: normalizeOpaqueRef(commandInputRef, "physical_command_input.command_input_ref", {
      prefix: "command-input",
    }),
    command_input_digest: assertDigest(commandInputDigest, "physical_command_input.command_input_digest"),
  });
}

function makeInternalCompensationInput(privateState, kind, reasonCode) {
  const sequence = privateState.command_sequence + 1;
  const basis = {
    reservation_ref: privateState.reservation_binding.reservation_ref,
    kind,
    reason_code: assertIdentifier(reasonCode, "physical_compensation.reason_code"),
    sequence,
  };
  return makeCommandInput(
    `command-input:compensation-${kind}-${sequence}`,
    hashCanonicalJson(basis),
  );
}

function terminalOutcome(privateState, kind, reasonCode, transition, compensation, command = null) {
  return deepFreeze({
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    kind,
    reason_code: reasonCode,
    reservation_ref: privateState.reservation_binding.reservation_ref,
    receipt_digest: transition == null ? null : transition.receipt.receipt_digest,
    command_ref: command == null ? null : command.command_ref,
    semantic_owner_digest: command == null ? null : command.semantic_owner_digest,
    requested_effects_digest: command == null ? null : command.requested_effects_digest,
    provider_id: privateState.registry.provider_binding.provider_id,
    provider_binding_digest: privateState.registry.provider_binding.provider_binding_digest,
    compensation,
    reconciliation_required: kind === "ambiguous" || !compensation.provider_action_confirmed,
  });
}

async function terminalSafetyCompensation(privateState, kind, reasonCode, command) {
  let transition;
  try {
    // Rotate/clear the active raw reservation fences before reporting or
    // attempting any recovery. A timed-out same-process provider promise may
    // still settle, so it is never granted a second provider command under the
    // old fence. Provider-side cleanup now requires a distinct out-of-band
    // safety authority, which this in-process bridge intentionally does not
    // claim to implement.
    transition = kind === "quarantine"
      ? quarantinePhysicalResourceReservation(privateState.reservation_authority, privateState.credential)
      : fencePhysicalResourceReservation(privateState.reservation_authority, privateState.credential);
    privateState.credential = transition.credential;
    privateState.phase = kind === "quarantine" ? "quarantined" : "fenced";
  } catch (cause) {
    privateState.phase = "ambiguous";
    return terminalOutcome(
      privateState,
      "ambiguous",
      "reservation_terminal_transition_failed",
      null,
      deepFreeze({
        kind,
        authority_transition_confirmed: false,
        provider_action_confirmed: false,
        provider_action_disposition: "not_attempted_without_out_of_band_safety_authority",
        failure_code: cause.code || "reservation_transition_failed",
      }),
      command,
    );
  }
  const compensation = deepFreeze({
    kind,
    authority_transition_confirmed: true,
    provider_action_confirmed: false,
    provider_action_disposition: "deferred_requires_out_of_band_safety_authority",
    failure_code: "out_of_band_safety_authority_unavailable",
  });
  return terminalOutcome(
    privateState,
    privateState.phase,
    reasonCode,
    transition,
    compensation,
    command,
  );
}

function safetyKindForError(error) {
  const code = error && typeof error.code === "string" ? error.code : "physical_provider_unavailable";
  if (code === "physical_provider_timeout" || code.startsWith("resource_inventory_")
      || code.startsWith("physical_provider_completion_")) {
    return "quarantine";
  }
  return "fence";
}

function admissionCapabilityBasis(privateState, command) {
  const reservation = privateState.reservation_binding;
  const provider = privateState.registry.provider_binding;
  const authorityClaim = privateState.dispatch_authority_claim;
  return {
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    ...projectExecutionLineage(authorityClaim),
    reservation_ref: reservation.reservation_ref,
    admission_receipt_digest: privateState.credential.receipt_digest,
    reservation_request_digest: reservation.reservation_request_digest,
    node_id: reservation.node_id,
    contract_hash: reservation.contract_hash,
    source_graph_hash: reservation.source_graph_hash,
    session_nucleus_hash: reservation.session_nucleus_hash,
    resource_bundle_digest: reservation.resource_bundle_digest,
    allocation_plan_digest: reservation.allocation_plan_digest,
    allocation_digest: reservation.allocation_digest,
    admission_credential_binding_digest: privateState.credential.credential_binding_digest,
    provider_id: provider.provider_id,
    provider_descriptor_digest: provider.provider_descriptor_digest,
    semantic_manifest_digest: provider.semantic_manifest_digest,
    provider_binding_digest: provider.provider_binding_digest,
    device_ref: provider.device_ref,
    device_identity_digest: provider.device_identity_digest,
    custody_ref: provider.custody_ref,
    custody_identity_digest: provider.custody_identity_digest,
    custody_epoch: provider.custody_epoch,
    command_kind: command.command_kind,
    command_ref: command.command_ref,
    operation_id: command.operation_id,
    operation_digest: command.operation_digest,
    semantic_owner_ref: command.semantic_owner_ref,
    semantic_owner_digest: command.semantic_owner_digest,
    requested_effect_digest: command.requested_effect_digest,
    command_projection_digest: command.command_projection_digest,
    command_authorization_digest: command.command_authorization_digest,
    semantic_authority_digest: command.semantic_authority_digest,
    authorization_epoch: command.authorization_epoch,
    reservation_command_authority_digest: command.reservation_command_authority_digest,
    resource_alias: command.resource_alias,
    resource_ref: command.resource_ref,
    resource_requirement_digest: command.resource_requirement_digest,
    requested_effects_digest: command.requested_effects_digest,
    ...(command.command_kind === "command" ? {
      command_input_ref: authorityClaim.command_input_ref,
      command_input_digest: authorityClaim.command_input_digest,
    } : {}),
  };
}

function createAdmissionCapability(privateState, command) {
  const basis = admissionCapabilityBasis(privateState, command);
  const capability = deepFreeze({
    ...basis,
    dispatch_admission_capability_digest: hashCanonicalJson(basis),
  });
  ADMISSION_CAPABILITIES.add(capability);
  ADMISSION_PRIVATE.set(capability, { bridge_state: privateState, command, consumed: false });
  return capability;
}

function assertAdmissionCapability(bridgeState, capability, allowedKinds) {
  if (!capability || !Object.isFrozen(capability) || !ADMISSION_CAPABILITIES.has(capability)
      || !ADMISSION_PRIVATE.has(capability)) {
    throw dispatchError(
      "physical_dispatch_capability_untrusted",
      "physical command requires a private broker-branded admission capability",
    );
  }
  const state = ADMISSION_PRIVATE.get(capability);
  if (state.bridge_state !== bridgeState || !allowedKinds.includes(state.command.command_kind)) {
    throw dispatchError(
      "physical_dispatch_capability_wrong_bridge",
      "physical command capability belongs to another bridge or command kind",
    );
  }
  if (state.consumed) {
    throw dispatchError("physical_dispatch_capability_replayed", "physical command capability was replayed");
  }
  if (capability.admission_receipt_digest !== bridgeState.credential.receipt_digest
      || capability.admission_credential_binding_digest
        !== bridgeState.credential.credential_binding_digest) {
    throw dispatchError(
      "physical_dispatch_capability_stale",
      "physical command capability no longer binds the current exact receipt/fence authority",
    );
  }
  return state;
}

function commandRequestBasis(capability, commandInput) {
  return {
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    ...projectExecutionLineage(capability),
    dispatch_admission_capability_digest: capability.dispatch_admission_capability_digest,
    command_projection_digest: capability.command_projection_digest,
    command_authorization_digest: capability.command_authorization_digest,
    semantic_authority_digest: capability.semantic_authority_digest,
    authorization_epoch: capability.authorization_epoch,
    reservation_command_authority_digest: capability.reservation_command_authority_digest,
    resource_alias: capability.resource_alias,
    resource_ref: capability.resource_ref,
    resource_requirement_digest: capability.resource_requirement_digest,
    command_ref: capability.command_ref,
    operation_id: capability.operation_id,
    operation_digest: capability.operation_digest,
    semantic_owner_digest: capability.semantic_owner_digest,
    requested_effect_digest: capability.requested_effect_digest,
    requested_effects_digest: capability.requested_effects_digest,
    provider_binding_digest: capability.provider_binding_digest,
    device_identity_digest: capability.device_identity_digest,
    custody_identity_digest: capability.custody_identity_digest,
    reservation_ref: capability.reservation_ref,
    admission_receipt_digest: capability.admission_receipt_digest,
    reservation_request_digest: capability.reservation_request_digest,
    node_id: capability.node_id,
    contract_hash: capability.contract_hash,
    source_graph_hash: capability.source_graph_hash,
    session_nucleus_hash: capability.session_nucleus_hash,
    resource_bundle_digest: capability.resource_bundle_digest,
    allocation_plan_digest: capability.allocation_plan_digest,
    allocation_digest: capability.allocation_digest,
    admission_credential_binding_digest: capability.admission_credential_binding_digest,
    command_input_ref: commandInput.command_input_ref,
    command_input_digest: commandInput.command_input_digest,
  };
}

function createPhysicalProviderCommandRequest(capability, input = {}) {
  if (!capability || !ADMISSION_CAPABILITIES.has(capability) || !ADMISSION_PRIVATE.has(capability)) {
    throw dispatchError(
      "physical_dispatch_capability_untrusted",
      "physical command request requires a private broker-branded admission capability",
    );
  }
  assertClosedDataObject(input, "physical_provider_command_request_input", [
    "command_input_ref",
    "command_input_digest",
  ]);
  const commandInput = makeCommandInput(input.command_input_ref, input.command_input_digest);
  const capabilityState = ADMISSION_PRIVATE.get(capability);
  if (capabilityState.command.command_kind === "command"
      && (commandInput.command_input_ref !== capability.command_input_ref
        || commandInput.command_input_digest !== capability.command_input_digest)) {
    throw dispatchError(
      "physical_dispatch_compiled_command_drift",
      "ordinary provider dispatch must consume the exact compiled command input signed into the active grant",
    );
  }
  return deepFreeze(commandRequestBasis(capability, commandInput));
}

function assertExactCommandRequest(capability, request) {
  const required = [
    "version",
    ...EXECUTION_LINEAGE_PROJECTION_FIELDS,
    "dispatch_admission_capability_digest",
    "command_projection_digest",
    "command_authorization_digest",
    "semantic_authority_digest",
    "authorization_epoch",
    "reservation_command_authority_digest",
    "resource_alias",
    "resource_ref",
    "resource_requirement_digest",
    "command_ref",
    "operation_id",
    "operation_digest",
    "semantic_owner_digest",
    "requested_effect_digest",
    "requested_effects_digest",
    "provider_binding_digest",
    "device_identity_digest",
    "custody_identity_digest",
    "reservation_ref",
    "admission_receipt_digest",
    "reservation_request_digest",
    "node_id",
    "contract_hash",
    "source_graph_hash",
    "session_nucleus_hash",
    "resource_bundle_digest",
    "allocation_plan_digest",
    "allocation_digest",
    "admission_credential_binding_digest",
    "command_input_ref",
    "command_input_digest",
  ];
  assertClosedDataObject(request, "physical_provider_command_request", required);
  const commandInput = makeCommandInput(request.command_input_ref, request.command_input_digest);
  const capabilityState = ADMISSION_PRIVATE.get(capability);
  if (capabilityState.command.command_kind === "command"
      && (commandInput.command_input_ref !== capability.command_input_ref
        || commandInput.command_input_digest !== capability.command_input_digest)) {
    throw dispatchError(
      "physical_dispatch_compiled_command_drift",
      "ordinary provider dispatch request drifted from the exact signed compiled command input",
    );
  }
  const expected = commandRequestBasis(capability, commandInput);
  for (const field of required) {
    if (request[field] !== expected[field]) {
      throw dispatchError("physical_dispatch_request_drift", `${field} command request drift`);
    }
  }
  return commandInput;
}

function createPhysicalProviderDispatchBridgeInternal(input = {}) {
  assertClosedDataObject(input, "physical_provider_dispatch_bridge", [
    "reservation_authority",
    "reservation_credential",
    "reservation_binding",
    "dispatch_head_fence",
    "command_registry",
    "dispatch_authority_port",
  ], ["provider_call_timeout_ms"]);
  const reservationAuthority = assertPhysicalResourceReservationAuthority(input.reservation_authority);
  const registry = assertPhysicalProviderCommandRegistry(input.command_registry);
  const registryState = REGISTRY_PRIVATE.get(registry);
  const reservationBinding = normalizeReservationBinding(input.reservation_binding);
  const dispatchHeadFenceState = assertPhysicalProviderDispatchHeadFence(
    input.dispatch_head_fence,
    reservationBinding,
  );
  const commandAuthorityBinding = registry.command_authorization.reservation_binding;
  for (const field of [
    "reservation_request_digest",
    "node_id",
    "contract_hash",
    "source_graph_hash",
    "session_nucleus_hash",
    "resource_bundle_digest",
    "allocation_digest",
  ]) {
    if (commandAuthorityBinding[field] !== reservationBinding[field]) {
      throw dispatchError(
        "physical_command_authorization_reservation_drift",
        `physical command authorization ${field} drift`,
      );
    }
  }
  const credentialProjection = assertCurrentPhysicalResourceReservationCredential(
    reservationAuthority,
    input.reservation_credential,
  );
  if (credentialProjection.state !== "held" || credentialProjection.effect_state !== "not_started"
      || credentialProjection.reservation_ref !== reservationBinding.reservation_ref
      || credentialProjection.receipt_digest !== reservationBinding.receipt_digest
      || credentialProjection.allocation_plan_digest !== reservationBinding.allocation_plan_digest
      || input.reservation_credential.reservation_request_digest
        !== reservationBinding.reservation_request_digest) {
    throw dispatchError(
      "physical_reservation_binding_drift",
      "dispatch bridge reservation binding does not match the exact held credential",
    );
  }
  const providerCallTimeoutMs = input.provider_call_timeout_ms == null
    ? 30_000
    : assertInteger(input.provider_call_timeout_ms, "provider_call_timeout_ms", 1, 600_000);
  const authorityProjection = projectCurrentPhysicalDispatchExecutionAuthority(
    input.dispatch_authority_port,
  );
  const providerBinding = registryState.provider_binding;
  const exactReservationAuthorityFields = {
    session_id: reservationBinding.session_id,
    session_nucleus_hash: reservationBinding.session_nucleus_hash,
    execution_principal_id: reservationBinding.execution_principal_ref,
    attempt_ref: reservationBinding.attempt_ref,
    node_id: reservationBinding.node_id,
    contract_hash: reservationBinding.contract_hash,
    prep_token_hash: reservationBinding.prep_token_hash,
    dispatch_event_id: reservationBinding.dispatch_event_id,
    graph_context_hash: reservationBinding.graph_context_hash,
    resource_bundle_digest: reservationBinding.resource_bundle_digest,
    effect_not_before: reservationBinding.effect_not_before,
    effect_deadline: reservationBinding.effect_deadline,
    provider_id: providerBinding.provider_id,
    provider_descriptor_digest: providerBinding.provider_descriptor_digest,
  };
  for (const [field, expected] of Object.entries(exactReservationAuthorityFields)) {
    if (authorityProjection[field] !== expected) {
      throw dispatchError(
        "physical_dispatch_authority_binding_drift",
        `${field} active dispatch authority binding drift`,
      );
    }
  }
  const commandAuthorizationPort = registryState.command_authorization_port;
  const commandAuthorizationState = COMMAND_AUTHORIZATION_PRIVATE.get(commandAuthorizationPort);
  if (commandAuthorizationPort.semantic_authority_digest
      !== authorityProjection.execution_request_digest) {
    throw dispatchError(
      "physical_dispatch_semantic_authority_drift",
      "provider command semantic authority is not the exact signed execution request",
    );
  }
  const exactAllocations = commandAuthorizationState.receipt_allocations.filter(
    (allocation) => allocation.resource_ref === authorityProjection.instrument_ref,
  );
  if (exactAllocations.length !== 1
      || commandAuthorizationState.allocation_digest !== reservationBinding.allocation_digest) {
    throw dispatchError(
      "physical_dispatch_instrument_allocation_drift",
      "active dispatch instrument must have one exact reservation allocation",
    );
  }
  const exactAllocation = exactAllocations[0];
  for (const authorization of commandAuthorizationState.authorizations_by_ref.values()) {
    if (authorization.operation_id !== authorityProjection.operation_id
        || authorization.operation_digest !== authorityProjection.operation_digest
        || authorization.requested_effects_digest
          !== authorityProjection.requested_effects_digest
        || authorization.resource_alias !== exactAllocation.alias
        || authorization.resource_ref !== exactAllocation.resource_ref) {
      throw dispatchError(
        "physical_dispatch_command_authority_drift",
        "every provider command must bind the exact active operation, effects, and allocation",
      );
    }
  }
  const boundCommands = registry.commands.filter((command) => (
    command.command_ref === authorityProjection.provider_command_ref
  ));
  if (boundCommands.length !== 1) {
    throw dispatchError(
      "physical_dispatch_compiled_command_drift",
      "the signed execution lineage does not select one exact registry-owned provider command",
    );
  }
  const boundCommand = boundCommands[0];
  if (boundCommand.operation_id !== authorityProjection.operation_id
      || boundCommand.operation_digest !== authorityProjection.operation_digest) {
    throw dispatchError(
      "physical_dispatch_compiled_command_drift",
      "the signed compiled command lineage drifted from the active operation",
    );
  }
  // Claim and transfer ownership only after every non-authority bridge check
  // has succeeded. The exact assertion and raw lease fence never leave the
  // branded authority port.
  const dispatchAuthorityOwner = Object.freeze({});
  const dispatchAuthorityClaim = claimPhysicalDispatchExecutionAuthority(
    input.dispatch_authority_port,
  );
  takePhysicalDispatchExecutionAuthorityClaimOwnership(
    dispatchAuthorityClaim,
    dispatchAuthorityOwner,
  );
  const privateState = {
    reservation_authority: reservationAuthority,
    credential: input.reservation_credential,
    admission_credential_binding_digest: input.reservation_credential.credential_binding_digest,
    reservation_binding: reservationBinding,
    dispatch_head_fence: input.dispatch_head_fence,
    dispatch_head_fence_state: dispatchHeadFenceState,
    registry,
    registry_state: registryState,
    dispatch_authority_claim: dispatchAuthorityClaim,
    dispatch_authority_owner: dispatchAuthorityOwner,
    provider_call_timeout_ms: providerCallTimeoutMs,
    command_sequence: 0,
    effect_permit_consumed: false,
    phase: "held",
    in_flight: false,
    pending_provider_calls: new Set(),
    cleanup_completion_evidence: null,
    bound_command: boundCommand,
  };

  function createDispatchCapability(commandProjection) {
    if (!["held", "started"].includes(privateState.phase)) {
      throw dispatchError("physical_dispatch_terminal", `physical dispatch bridge is ${privateState.phase}`);
    }
    const command = assertCommandProjectionForRegistry(
      registryState,
      commandProjection,
      ["command", "cleanup"],
    );
    if (command.command_kind === "command" && command !== privateState.bound_command) {
      throw dispatchError(
        "physical_dispatch_compiled_command_drift",
        "active dispatch can mint authority only for the exact provider command signed into the grant",
      );
    }
    return createAdmissionCapability(privateState, command);
  }

  function ensureStarted() {
    if (privateState.phase === "started") return;
    if (privateState.phase !== "held") {
      throw dispatchError("physical_dispatch_terminal", `physical dispatch bridge is ${privateState.phase}`);
    }
    let started;
    try {
      started = markPhysicalResourceEffectStarted(
        privateState.reservation_authority,
        privateState.credential,
      );
    } catch (error) {
      if (error && error.code === "reservation_state_ambiguous") privateState.phase = "ambiguous";
      throw error;
    }
    privateState.credential = started.credential;
    privateState.phase = "started";
  }

  async function dispatch(capability, request) {
    if (privateState.in_flight) {
      throw dispatchError("physical_dispatch_in_progress", "physical provider command is already in flight");
    }
    if (!["held", "started"].includes(privateState.phase)) {
      throw dispatchError(
        "physical_dispatch_terminal",
        `physical dispatch bridge is ${privateState.phase}`,
      );
    }
    const capabilityState = assertAdmissionCapability(privateState, capability, ["command"]);
    const commandInput = assertExactCommandRequest(capability, request);
    if (privateState.effect_permit_consumed) {
      throw dispatchError(
        "physical_dispatch_command_already_consumed",
        "physical dispatch permits exactly one ordinary provider command",
      );
    }
    capabilityState.consumed = true;
    privateState.in_flight = true;
    try {
      runWhilePhysicalDispatchHeadCurrent(
        privateState,
        "physical resource effect start",
        () => ensureStarted(),
      );
      // A definitive failure to start has not consumed effect authority and may
      // still be closed through the coordinator's private before-effect path.
      privateState.effect_permit_consumed = true;
      let invoked;
      try {
        invoked = await invokeRegisteredCommand(privateState, capabilityState.command, commandInput);
      } catch (error) {
        if (error && error.pending_provider_call) {
          privateState.pending_provider_calls.add(error.pending_provider_call);
          Promise.resolve(error.pending_provider_call).finally(() => {
            privateState.pending_provider_calls.delete(error.pending_provider_call);
          }).catch(() => undefined);
        }
        const kind = safetyKindForError(error);
        return terminalSafetyCompensation(
          privateState,
          kind,
          error && typeof error.code === "string" ? error.code : "physical_provider_unavailable",
          capabilityState.command,
        );
      }
      if (invoked.result.completion === "ambiguous") {
        return terminalSafetyCompensation(
          privateState,
          "quarantine",
          "physical_provider_ambiguous_completion",
          capabilityState.command,
        );
      }
      if (invoked.result.completion === "confirmed_no_effect") {
        return performCleanup(
          privateState,
          "provider-confirmed-no-effect",
          capabilityState.command,
          invoked,
        );
      }
      return deepFreeze({
        version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
        kind: "confirmed",
        reason_code: "physical_provider_confirmed",
        reservation_ref: privateState.reservation_binding.reservation_ref,
        receipt_digest: privateState.credential.receipt_digest,
        command_ref: capabilityState.command.command_ref,
        semantic_owner_digest: capabilityState.command.semantic_owner_digest,
        requested_effects_digest: capabilityState.command.requested_effects_digest,
        provider_id: privateState.registry.provider_binding.provider_id,
        provider_binding_digest: privateState.registry.provider_binding.provider_binding_digest,
        provider_result_digest: invoked.result.provider_result_digest,
        provider_receipt_ref: invoked.result.provider_receipt_ref,
        provider_dispatch_capability_digest: invoked.capability.provider_dispatch_capability_digest,
        effect_disposition: invoked.completion_evidence.effect_disposition,
        committed_receipt_ref: invoked.completion_evidence.committed_receipt_ref,
        committed_receipt_digest: invoked.completion_evidence.committed_receipt_digest,
        completion_evidence_digest: invoked.completion_evidence.completion_evidence_digest,
        completion_source: invoked.completion_source,
        reconciliation_required: false,
      });
    } finally {
      privateState.in_flight = false;
    }
  }

  async function performCleanup(state, reasonCode, sourceCommand, sourceInvocation = null, inputOverride = null) {
    const cleanupCommand = state.registry.compensation.cleanup;
    let cleanupInvocation;
    try {
      cleanupInvocation = await invokeRegisteredCommand(
        state,
        cleanupCommand,
        inputOverride || makeInternalCompensationInput(state, "cleanup", reasonCode),
      );
      if (cleanupInvocation.result.completion === "ambiguous") {
        return terminalSafetyCompensation(
          state,
          "quarantine",
          "physical_cleanup_ambiguous",
          cleanupCommand,
        );
      }
      if (cleanupInvocation.result.completion === "confirmed_no_effect") {
        return terminalSafetyCompensation(
          state,
          "quarantine",
          "physical_cleanup_confirmed_no_effect",
          cleanupCommand,
        );
      }
    } catch (error) {
      if (error && error.pending_provider_call) {
        state.pending_provider_calls.add(error.pending_provider_call);
        Promise.resolve(error.pending_provider_call).finally(() => {
          state.pending_provider_calls.delete(error.pending_provider_call);
        }).catch(() => undefined);
      }
      return terminalSafetyCompensation(
        state,
        "quarantine",
        error && typeof error.code === "string" ? error.code : "physical_cleanup_failed",
        cleanupCommand,
      );
    }
    const handoffRef = `cleanup-handoff:${hashCanonicalJson({
      reservation_ref: state.reservation_binding.reservation_ref,
      cleanup_result_digest: cleanupInvocation.result.provider_result_digest,
      command_sequence: state.command_sequence,
    }).slice(0, 40)}`;
    let begun;
    try {
      begun = beginPhysicalResourceCleanup(
        state.reservation_authority,
        state.credential,
        handoffRef,
      );
    } catch (error) {
      return terminalSafetyCompensation(
        state,
        "quarantine",
        error && typeof error.code === "string"
          ? error.code
          : "physical_cleanup_begin_transition_failed",
        cleanupCommand,
      );
    }
    state.credential = begun.credential;
    state.phase = "cleanup_pending";
    state.cleanup_completion_evidence = cleanupInvocation.completion_evidence;
    let completed = null;
    try {
      completed = completePhysicalResourceCleanup(state.reservation_authority, state.credential);
      state.credential = completed.credential;
      state.phase = "released";
    } catch (error) {
      if (!error || error.code !== "reservation_cooldown_pending") {
        return terminalSafetyCompensation(
          state,
          "quarantine",
          error && typeof error.code === "string"
            ? error.code
            : "physical_cleanup_complete_transition_failed",
          cleanupCommand,
        );
      }
    }
    return deepFreeze({
      version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
      kind: state.phase,
      reason_code: reasonCode,
      reservation_ref: state.reservation_binding.reservation_ref,
      receipt_digest: (completed || begun).receipt.receipt_digest,
      command_ref: sourceCommand.command_ref,
      semantic_owner_digest: sourceCommand.semantic_owner_digest,
      requested_effects_digest: sourceCommand.requested_effects_digest,
      provider_id: state.registry.provider_binding.provider_id,
      provider_binding_digest: state.registry.provider_binding.provider_binding_digest,
      provider_result_digest: sourceInvocation == null
        ? null
        : sourceInvocation.result.provider_result_digest,
      provider_effect_disposition: sourceInvocation == null
        ? null
        : sourceInvocation.completion_evidence.effect_disposition,
      provider_completion_evidence_digest: sourceInvocation == null
        ? null
        : sourceInvocation.completion_evidence.completion_evidence_digest,
      provider_committed_receipt_ref: sourceInvocation == null
        ? null
        : sourceInvocation.completion_evidence.committed_receipt_ref,
      provider_committed_receipt_digest: sourceInvocation == null
        ? null
        : sourceInvocation.completion_evidence.committed_receipt_digest,
      cleanup_result_digest: cleanupInvocation.result.provider_result_digest,
      cleanup_effect_disposition: cleanupInvocation.completion_evidence.effect_disposition,
      cleanup_committed_receipt_ref:
        cleanupInvocation.completion_evidence.committed_receipt_ref,
      cleanup_committed_receipt_digest:
        cleanupInvocation.completion_evidence.committed_receipt_digest,
      cleanup_completion_evidence_digest:
        cleanupInvocation.completion_evidence.completion_evidence_digest,
      cleanup_completion_source: cleanupInvocation.completion_source,
      cleanup_dispatch_capability_digest:
        cleanupInvocation.capability.provider_dispatch_capability_digest,
      reconciliation_required: false,
    });
  }

  async function cleanup(capability, request) {
    if (privateState.in_flight) {
      throw dispatchError("physical_dispatch_in_progress", "physical provider command is already in flight");
    }
    const capabilityState = assertAdmissionCapability(privateState, capability, ["cleanup"]);
    const commandInput = assertExactCommandRequest(capability, request);
    if (privateState.phase !== "started") {
      throw dispatchError("physical_cleanup_invalid_state", "physical provider cleanup requires started effect state");
    }
    capabilityState.consumed = true;
    privateState.in_flight = true;
    try {
      return await performCleanup(
        privateState,
        "physical_cleanup_confirmed",
        capabilityState.command,
        null,
        commandInput,
      );
    } finally {
      privateState.in_flight = false;
    }
  }

  async function completeCleanup() {
    if (privateState.in_flight) {
      throw dispatchError("physical_dispatch_in_progress", "physical provider command is already in flight");
    }
    if (privateState.phase !== "cleanup_pending") {
      throw dispatchError("physical_cleanup_invalid_state", "physical resource cleanup is not pending");
    }
    privateState.in_flight = true;
    try {
      const completed = completePhysicalResourceCleanup(
        privateState.reservation_authority,
        privateState.credential,
      );
      privateState.credential = completed.credential;
      privateState.phase = "released";
      return deepFreeze({
        version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
        kind: "released",
        reservation_ref: privateState.reservation_binding.reservation_ref,
        receipt_digest: completed.receipt.receipt_digest,
        cleanup_committed_receipt_ref:
          privateState.cleanup_completion_evidence.committed_receipt_ref,
        cleanup_committed_receipt_digest:
          privateState.cleanup_completion_evidence.committed_receipt_digest,
        cleanup_completion_evidence_digest:
          privateState.cleanup_completion_evidence.completion_evidence_digest,
        reconciliation_required: false,
      });
    } catch (error) {
      if (error && error.code === "reservation_cooldown_pending") {
        return deepFreeze({
          version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
          kind: "cleanup_pending",
          reservation_ref: privateState.reservation_binding.reservation_ref,
          receipt_digest: privateState.credential.receipt_digest,
          cleanup_committed_receipt_ref:
            privateState.cleanup_completion_evidence.committed_receipt_ref,
          cleanup_committed_receipt_digest:
            privateState.cleanup_completion_evidence.committed_receipt_digest,
          cleanup_completion_evidence_digest:
            privateState.cleanup_completion_evidence.completion_evidence_digest,
          reconciliation_required: false,
        });
      }
      return terminalSafetyCompensation(
        privateState,
        "quarantine",
        error && typeof error.code === "string"
          ? error.code
          : "physical_cleanup_complete_transition_failed",
        privateState.registry.compensation.cleanup,
      );
    } finally {
      privateState.in_flight = false;
    }
  }

  function snapshot() {
    return deepFreeze({
      version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
      phase: privateState.phase,
      reservation_ref: privateState.reservation_binding.reservation_ref,
      receipt_digest: privateState.credential == null ? null : privateState.credential.receipt_digest,
      provider_id: privateState.registry.provider_binding.provider_id,
      provider_binding_digest: privateState.registry.provider_binding.provider_binding_digest,
      command_registry_digest: privateState.registry.command_registry_digest,
      command_sequence: privateState.command_sequence,
      task_graph_dispatch_head_fence_digest:
        privateState.dispatch_head_fence.reservation_binding_digest,
      in_flight: privateState.in_flight,
      pending_provider_call_count: privateState.pending_provider_calls.size,
    });
  }

  function readiness() {
    return deepFreeze({
      version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
      production_ready: false,
      provider_id: privateState.registry.provider_binding.provider_id,
      command_registry_digest: privateState.registry.command_registry_digest,
      reservation_ref: privateState.reservation_binding.reservation_ref,
      authority_enforcement: "per-command-reservation-and-private-active-fence-set-v1",
      semantic_effect_enforcement: "private-reservation-bound-command-authorization-port-v1",
      semantic_authority_assurance: "signed_execution_request_digest_exact",
      active_dispatch_authority_assurance: privateState.dispatch_authority_claim.authority_mode
        === "active"
        ? "cryptographically_verified_one_use_active_dispatch_authority_live_revalidated"
        : "deterministic_mock_dispatch_authority_only",
      durable_active_instrument_lease_fence_assurance:
        "durable_active_instrument_lease_fence_not_integrated",
      task_graph_dispatch_head_assurance:
        "cooperative_same_process_session_lock_revalidated_before_provider_entry_v1",
      task_graph_provider_entry_atomicity:
        "no_cross_process_or_crash_atomic_commit",
      provider_custody_enforcement: "same-process-callback-observation-unattested",
      completion_evidence_enforcement:
        "exact-reservation-fence-provider-device-custody-command-input-capability-effect-and-receipt-v1",
      completion_evidence_consistency:
        privateState.registry.completion_verification.consistency_contract,
      completion_evidence_backend_assurance:
        privateState.registry.completion_verification.durability_assurance,
      completion_evidence_production_ready:
        privateState.registry.completion_verification.production_ready,
      safety_compensation: "broker_fence_first_provider_cleanup_deferred",
      reason:
        "production_attested_durable_completion_backend_crash_atomic_task_graph_provider_handoff_durable_active_instrument_lease_fence_os_watchdog_cleanup_process_custody_and_hil_required",
    });
  }

  const bridge = Object.freeze({
    cleanup,
    completeCleanup,
    createDispatchCapability,
    dispatch,
    readiness,
    snapshot,
  });
  BRIDGES.add(bridge);
  BRIDGE_PRIVATE.set(bridge, privateState);
  return { bridge, privateState };
}

function createPhysicalProviderDispatchBridge(input = {}) {
  return createPhysicalProviderDispatchBridgeInternal(input).bridge;
}

function createBeforeEffectCancellationCapability(privateState) {
  const binding = {
    domain: "hacker-bob/physical-provider-before-effect-cancellation/v1",
    reservation_ref: privateState.reservation_binding.reservation_ref,
    receipt_digest: privateState.reservation_binding.receipt_digest,
    reservation_request_digest:
      privateState.reservation_binding.reservation_request_digest,
    allocation_plan_digest: privateState.reservation_binding.allocation_plan_digest,
    prep_token_hash: privateState.reservation_binding.prep_token_hash,
    dispatch_event_id: privateState.reservation_binding.dispatch_event_id,
  };
  const capability = deepFreeze({
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    reservation_ref: binding.reservation_ref,
    receipt_digest: binding.receipt_digest,
    cancellation_capability_digest: hashCanonicalJson(binding),
  });
  BEFORE_EFFECT_CANCELLATION_CAPABILITIES.add(capability);
  BEFORE_EFFECT_CANCELLATION_PRIVATE.set(capability, {
    bridge_state: privateState,
    state: "ready",
    outcome: null,
  });
  return capability;
}

function createPhysicalProviderDispatchBridgeWithCancellationCapability(input = {}) {
  const created = createPhysicalProviderDispatchBridgeInternal(input);
  return deepFreeze({
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    dispatch_bridge: created.bridge,
    cancellation_capability: createBeforeEffectCancellationCapability(created.privateState),
  });
}

function assertBeforeEffectCancellationCapability(capability) {
  const state = capability == null
    ? null
    : BEFORE_EFFECT_CANCELLATION_PRIVATE.get(capability);
  if (!capability || !Object.isFrozen(capability)
      || !BEFORE_EFFECT_CANCELLATION_CAPABILITIES.has(capability) || !state
      || capability.version !== PHYSICAL_PROVIDER_DISPATCH_VERSION
      || capability.reservation_ref !== state.bridge_state.reservation_binding.reservation_ref
      || capability.receipt_digest !== state.bridge_state.reservation_binding.receipt_digest
      || Reflect.ownKeys(capability).length !== 4) {
    throw dispatchError(
      "physical_dispatch_cancellation_capability_untrusted",
      "before-effect cancellation requires the exact private bridge capability",
    );
  }
  return state;
}

function projectPhysicalProviderDispatchCancellation(capability) {
  const state = assertBeforeEffectCancellationCapability(capability);
  return deepFreeze({
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    cancellation_state: state.state,
    bridge_phase: state.bridge_state.phase,
    reservation_ref: capability.reservation_ref,
    receipt_digest: state.outcome == null
      ? capability.receipt_digest
      : state.outcome.receipt.receipt_digest,
    cancellation_capability_digest: capability.cancellation_capability_digest,
  });
}

function armPhysicalProviderDispatchBeforeEffectCancellation(capability) {
  const cancellation = assertBeforeEffectCancellationCapability(capability);
  const bridgeState = cancellation.bridge_state;
  if (cancellation.state === "armed") {
    return projectPhysicalProviderDispatchCancellation(capability);
  }
  if (cancellation.state !== "ready") {
    throw dispatchError(
      "physical_dispatch_cancellation_not_available",
      `before-effect cancellation is ${cancellation.state}`,
    );
  }
  if (bridgeState.phase !== "held" || bridgeState.in_flight
      || bridgeState.effect_permit_consumed || bridgeState.command_sequence !== 0
      || bridgeState.pending_provider_calls.size !== 0) {
    throw dispatchError(
      "physical_dispatch_cancellation_after_effect",
      "the bridge cannot be cancelled after effect authority was consumed or started",
    );
  }

  cancellation.state = "checking";
  bridgeState.phase = "cancellation_checking";
  let projection;
  try {
    projection = readPhysicalResourceReservationProjection(
      bridgeState.reservation_authority,
      bridgeState.reservation_binding.reservation_ref,
    );
  } catch (cause) {
    cancellation.state = "ambiguous";
    bridgeState.phase = "ambiguous";
    throw dispatchError(
      "physical_dispatch_cancellation_ambiguous",
      "the exact held reservation could not be reconciled before cancellation",
      cause,
    );
  }
  if (!projection || projection.state !== "held" || projection.effect_state !== "not_started"
      || projection.reservation_ref !== bridgeState.reservation_binding.reservation_ref
      || projection.receipt_digest !== bridgeState.reservation_binding.receipt_digest
      || projection.reservation_request_digest
        !== bridgeState.reservation_binding.reservation_request_digest
      || projection.allocation_plan_digest
        !== bridgeState.reservation_binding.allocation_plan_digest
      || projection.allocation_digest !== bridgeState.reservation_binding.allocation_digest) {
    cancellation.state = "ambiguous";
    bridgeState.phase = "ambiguous";
    throw dispatchError(
      projection && projection.effect_state !== "not_started"
        ? "physical_dispatch_cancellation_after_effect"
        : "physical_dispatch_cancellation_ambiguous",
      "the bridge no longer owns its exact held, not-started reservation",
    );
  }
  cancellation.state = "armed";
  bridgeState.phase = "cancellation_pending";
  return projectPhysicalProviderDispatchCancellation(capability);
}

function closeBridgeReservationBeforeEffect(bridgeState) {
  try {
    return {
      kind: "cancelled",
      result: cancelPhysicalResourceReservation(
        bridgeState.reservation_authority,
        bridgeState.credential,
      ),
    };
  } catch (cause) {
    if (!cause || cause.code !== "resource_reservation_expired") throw cause;
    return {
      kind: "expired",
      result: expirePhysicalResourceReservation(
        bridgeState.reservation_authority,
        bridgeState.credential,
      ),
    };
  }
}

function closePhysicalProviderDispatchBeforeEffectCancellation(capability) {
  const cancellation = assertBeforeEffectCancellationCapability(capability);
  const bridgeState = cancellation.bridge_state;
  if (cancellation.state === "closed") {
    return deepFreeze({ ...cancellation.outcome, idempotent: true });
  }
  if (cancellation.state !== "armed" || bridgeState.phase !== "cancellation_pending"
      || bridgeState.in_flight || bridgeState.effect_permit_consumed) {
    throw dispatchError(
      "physical_dispatch_cancellation_not_armed",
      "before-effect cancellation has not retained its exact armed bridge state",
    );
  }
  cancellation.state = "closing";
  bridgeState.in_flight = true;
  try {
    const closed = closeBridgeReservationBeforeEffect(bridgeState);
    const receipt = closed.result && closed.result.receipt;
    const projection = closed.result && closed.result.reservation_projection;
    const expectedDisposition = closed.kind === "cancelled"
      ? "cancelled_before_effect"
      : "expired_before_effect";
    if (!receipt || !projection || receipt.state !== "released"
        || receipt.terminal_disposition !== expectedDisposition
        || projection.state !== "released" || projection.effect_state !== "not_started"
        || receipt.reservation_ref !== bridgeState.reservation_binding.reservation_ref
        || projection.reservation_request_digest
          !== bridgeState.reservation_binding.reservation_request_digest) {
      throw dispatchError(
        "physical_dispatch_cancellation_result_drift",
        "broker cancellation did not return the exact terminal before-effect reservation",
      );
    }
    bridgeState.credential = null;
    bridgeState.phase = closed.kind;
    cancellation.state = "closed";
    cancellation.outcome = deepFreeze({
      version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
      kind: closed.kind,
      reservation_ref: receipt.reservation_ref,
      receipt,
      reservation_projection: projection,
      cancellation_capability_digest: capability.cancellation_capability_digest,
      reconciliation_required: false,
      idempotent: false,
    });
    return cancellation.outcome;
  } catch (cause) {
    cancellation.state = "ambiguous";
    bridgeState.phase = "ambiguous";
    throw dispatchError(
      "physical_dispatch_cancellation_ambiguous",
      "before-effect cancellation outcome is ambiguous and cannot be replayed",
      cause,
    );
  } finally {
    bridgeState.in_flight = false;
  }
}

function assertPhysicalProviderDispatchBridge(bridge) {
  if (!bridge || !Object.isFrozen(bridge) || !BRIDGES.has(bridge) || !BRIDGE_PRIVATE.has(bridge)) {
    throw dispatchError(
      "physical_provider_dispatch_bridge_untrusted",
      "physical provider dispatch bridge must be created by Bob's private factory",
    );
  }
  return bridge;
}

// Report-safe composition binding for Bob-owned consumers.  The public bridge
// intentionally exposes operational methods, while the technique runtime must
// never accept those methods (or caller-authored readiness claims) as proof of
// production authority.  This projection is rebuilt from the bridge's private
// execution claim on every read, which also revalidates the signed grant,
// current scope/revocation state, trusted clock, and exact reservation owner.
// Provider identifiers, command references/inputs, device paths, byte-bearing
// material, and callbacks are deliberately omitted.
function projectPhysicalProviderDispatchCompositionBinding(bridgeInput) {
  const bridge = assertPhysicalProviderDispatchBridge(bridgeInput);
  const state = BRIDGE_PRIVATE.get(bridge);
  const authority = assertCurrentPhysicalDispatchExecutionAuthorityClaim(
    state.dispatch_authority_claim,
    state.dispatch_authority_owner,
  );
  const completion = state.registry.completion_verification;
  const productionBlockers = [];
  if (authority.authority_mode !== "active") {
    productionBlockers.push("signed_active_dispatch_admission_missing");
  }
  if (authority.trusted_clock_mode === "deterministic_test_clock") {
    productionBlockers.push("production_trusted_clock_missing");
  }
  if (completion.production_ready !== true) {
    productionBlockers.push("production_completion_evidence_owner_missing");
  }
  // The current bridge is an in-process callback registry with deferred
  // out-of-band compensation.  No constructor may promote it until a private
  // provider-worker-vault registry and independent restoration owner are
  // enrolled in this module.
  productionBlockers.push(
    "privately_branded_provider_worker_vault_registry_missing",
    "independent_cleanup_restoration_owner_missing",
    "hardware_in_loop_qualification_missing",
  );
  const basis = {
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    kind: "physical_provider_dispatch_composition_binding",
    signed_grant_digest: authority.signed_grant_digest,
    execution_request_digest: authority.execution_request_digest,
    execution_lineage_digest: authority.execution_lineage_digest,
    session_nucleus_hash: authority.session_nucleus_hash,
    physical_scope_axis_digest: authority.physical_scope_axis_digest,
    technique_cell_id: authority.technique_cell_id,
    attempt_ref: authority.attempt_ref,
    cleanup_plan_digest: authority.cleanup_plan_digest,
    observer_plan_digest: authority.observer_plan_digest,
    control_plan_digest: authority.control_plan_digest,
    command_registry_digest: state.registry.command_registry_digest,
    reservation_binding_digest: state.dispatch_head_fence.reservation_binding_digest,
    completion_evidence_domain_digest: completion.evidence_domain_digest,
    dispatch_phase: state.phase,
    production_qualification: productionBlockers.length === 0 ? "qualified" : "blocked",
    production_blockers: Object.freeze([...productionBlockers]),
  };
  return deepFreeze({
    ...basis,
    composition_binding_digest: hashCanonicalJson(basis),
  });
}

// Closed execution entry used only by the physical-technique composition
// root.  The ordinary and cleanup projections and their signed command-input
// bindings are selected from private registry state; callers cannot provide a
// command, provider identifier, byte surface, callback, or cleanup override.
async function executePhysicalProviderDispatchComposition(bridgeInput) {
  const bridge = assertPhysicalProviderDispatchBridge(bridgeInput);
  const state = BRIDGE_PRIVATE.get(bridge);
  const binding = projectPhysicalProviderDispatchCompositionBinding(bridge);
  if (binding.production_qualification !== "qualified") {
    throw dispatchError(
      "physical_provider_dispatch_composition_not_production",
      "physical provider dispatch composition is not production qualified",
    );
  }
  if (state.phase !== "held" || state.in_flight || state.effect_permit_consumed) {
    throw dispatchError(
      "physical_provider_dispatch_composition_replay",
      "physical provider dispatch composition no longer owns an unused held admission",
    );
  }
  const command = state.bound_command;
  const commandCapability = createAdmissionCapability(state, command);
  const commandRequest = createPhysicalProviderCommandRequest(commandCapability, {
    command_input_ref: state.dispatch_authority_claim.command_input_ref,
    command_input_digest: state.dispatch_authority_claim.command_input_digest,
  });
  const source = await bridge.dispatch(commandCapability, commandRequest);
  let terminal = source;
  if (source.kind === "confirmed") {
    const cleanupCommand = state.registry.compensation.cleanup;
    const cleanupCapability = createAdmissionCapability(state, cleanupCommand);
    const cleanupInput = makeInternalCompensationInput(
      state,
      "cleanup",
      "physical_technique_composition_cleanup",
    );
    const cleanupRequest = createPhysicalProviderCommandRequest(cleanupCapability, cleanupInput);
    terminal = await bridge.cleanup(cleanupCapability, cleanupRequest);
  }
  if (terminal.kind === "cleanup_pending") terminal = await bridge.completeCleanup();
  const sourceEvidenceDigest = source.completion_evidence_digest
    || source.provider_completion_evidence_digest
    || null;
  const sourceReceiptRef = source.committed_receipt_ref
    || source.provider_committed_receipt_ref
    || null;
  const sourceReceiptDigest = source.committed_receipt_digest
    || source.provider_committed_receipt_digest
    || null;
  const projection = {
    version: PHYSICAL_PROVIDER_DISPATCH_VERSION,
    kind: "physical_provider_dispatch_composition_outcome",
    terminal_state: terminal.kind,
    attempt_ref: state.dispatch_authority_claim.attempt_ref,
    provider_result_digest: source.provider_result_digest || null,
    completion_evidence_digest: sourceEvidenceDigest,
    committed_receipt_ref: sourceReceiptRef,
    committed_receipt_digest: sourceReceiptDigest,
    cleanup_completion_evidence_digest:
      terminal.cleanup_completion_evidence_digest || null,
    cleanup_committed_receipt_ref: terminal.cleanup_committed_receipt_ref || null,
    cleanup_committed_receipt_digest: terminal.cleanup_committed_receipt_digest || null,
    terminal_receipt_digest: terminal.receipt_digest || null,
    reconciliation_required: terminal.reconciliation_required === true,
  };
  return deepFreeze({
    ...projection,
    outcome_digest: hashCanonicalJson(projection),
  });
}

module.exports = {
  PHYSICAL_PROVIDER_COMMAND_KINDS: COMMAND_KINDS,
  PHYSICAL_PROVIDER_COMPLETION_VALUES: COMPLETION_VALUES,
  PHYSICAL_PROVIDER_DISPATCH_VERSION,
  assertPhysicalProviderCompletionVerificationPort,
  assertPhysicalProviderCommandAuthorizationPort,
  assertPhysicalProviderCommandRegistry,
  assertPhysicalProviderDispatchBridge,
  assertPhysicalProviderDispatchCapability,
  armPhysicalProviderDispatchBeforeEffectCancellation,
  closePhysicalProviderDispatchBeforeEffectCancellation,
  createPhysicalProviderCommandAuthorizationPort,
  createPhysicalProviderCommandRegistry,
  createPhysicalProviderCommandRequest,
  createPhysicalProviderCompletionVerificationPort,
  createPhysicalProviderCompletionVerificationPortFromFixedAdapter,
  createPhysicalProviderDispatchHeadFence,
  createPhysicalProviderDispatchBridge,
  createPhysicalProviderDispatchBridgeWithCancellationCapability,
  executePhysicalProviderDispatchComposition,
  normalizePhysicalProviderBinding: normalizeProviderBinding,
  projectPhysicalProviderDispatchCompositionBinding,
  projectPhysicalProviderDispatchCancellation,
  resolvePhysicalProviderCommandAuthorization,
  resolvePhysicalProviderCommand,
};
