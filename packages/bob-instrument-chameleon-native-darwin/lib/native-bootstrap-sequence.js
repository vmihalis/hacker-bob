"use strict";

// Effect-free, provider-private sequencing guard for PH-P7 bootstrap commands.
// It consumes only a privately branded compiled PH-P8 operation and emits
// semantic bindings; it never creates frames, opens/enumerates a device, loads
// native code, starts a process, or touches a transport.

const { types: utilTypes } = require("node:util");
const {
  assertCompiledChameleonBootstrapOperation,
} = require("../../bob-instrument-chameleon/lib/bootstrap-operations.js");
const {
  CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS,
} = require("./generated-bootstrap-semantics.js");

const SafeError = Error;
const arrayIsArray = Array.isArray;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const objectPrototype = Object.prototype;
const numberIsSafeInteger = Number.isSafeInteger;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const utilIsProxy = utilTypes.isProxy;
const weakMapGet = WeakMap.prototype.get;
const weakMapSet = WeakMap.prototype.set;
const weakSetAdd = WeakSet.prototype.add;
const weakSetHas = WeakSet.prototype.has;

const GUARDS = new WeakSet();
const GUARD_STATE = new WeakMap();
const STEP_BINDINGS = new WeakSet();
const COMPLETIONS = new WeakSet();
const STEP_REQUEST_FIELDS = objectFreeze(["command_sequence"]);

function sequenceError(reasonCode) {
  const error = new SafeError("Chameleon native bootstrap sequence was rejected");
  objectDefineProperty(error, "code", {
    value: "chameleon_native_bootstrap_sequence_rejected",
    enumerable: false,
    writable: false,
    configurable: false,
  });
  objectDefineProperty(error, "reason_code", {
    value: reasonCode,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return error;
}

function reject(reasonCode) {
  throw sequenceError(reasonCode);
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || arrayIsArray(value)
      || utilIsProxy(value)) return false;
  const prototype = objectGetPrototypeOf(value);
  if (prototype !== objectPrototype && prototype !== null) return false;
  const keys = reflectOwnKeys(value);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    const descriptor = objectGetOwnPropertyDescriptor(value, key);
    if (typeof key !== "string" || descriptor == null
        || !objectHasOwn(descriptor, "value") || descriptor.enumerable !== true) return false;
  }
  return true;
}

function assertExactObject(value, fields, reasonCode) {
  if (!isPlainDataObject(value)) reject(reasonCode);
  const keys = reflectOwnKeys(value);
  if (keys.length !== fields.length) reject(reasonCode);
  for (let index = 0; index < fields.length; index += 1) {
    if (!objectHasOwn(value, fields[index])) reject(reasonCode);
  }
  return value;
}

function rejectSerialization() {
  reject("sequence_capability_not_serializable");
}

function tableOperation(operationId) {
  const operations = CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.operations;
  for (let index = 0; index < operations.length; index += 1) {
    if (operations[index].operation_id === operationId) return operations[index];
  }
  reject("compiled_operation_not_in_native_table");
}

function assertCompiledBinding(compiled) {
  let value;
  try {
    value = assertCompiledChameleonBootstrapOperation(compiled);
  } catch {
    reject("compiled_operation_brand_invalid");
  }
  const operation = tableOperation(value.operation_id);
  if (value.version !== 1
      || value.provider_id !== CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.provider_id
      || value.operation_digest !== operation.operation_digest
      || value.command_set_digest !== operation.command_set_digest
      || !arrayIsArray(value.commands)
      || value.commands.length !== operation.commands.length) {
    reject("compiled_operation_native_table_drift");
  }
  for (let index = 0; index < operation.commands.length; index += 1) {
    const expected = operation.commands[index];
    const actual = value.commands[index];
    if (actual == null || actual.version !== 1
        || actual.command_id !== expected.command_id
        || actual.payload_kind !== "none"
        || actual.payload_byte_length !== 0) {
      reject("compiled_operation_command_sequence_drift");
    }
  }
  return { value, operation };
}

function createNativeBootstrapSequenceGuard(compiledOperation) {
  if (arguments.length !== 1) reject("sequence_guard_arity_invalid");
  const { value, operation } = assertCompiledBinding(compiledOperation);
  const guard = objectFreeze({
    version: 1,
    kind: "chameleon_native_bootstrap_sequence_guard",
    provider_id: CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.provider_id,
    toJSON: rejectSerialization,
  });
  reflectApply(weakSetAdd, GUARDS, [guard]);
  reflectApply(weakMapSet, GUARD_STATE, [guard, {
    operation,
    compiled_operation_digest: value.compiled_operation_digest,
    bootstrap_grant_projection_digest: value.bootstrap_grant_projection_digest,
    signed_grant_digest: value.signed_grant_digest,
    execution_request_digest: value.execution_request_digest,
    next_index: 0,
    completed: false,
  }]);
  return guard;
}

function requireGuard(guard) {
  const state = guard == null ? null : reflectApply(weakMapGet, GUARD_STATE, [guard]);
  if (!guard || !reflectApply(weakSetHas, GUARDS, [guard]) || !state) {
    reject("sequence_guard_brand_invalid");
  }
  return state;
}

function claimNativeBootstrapSequenceStep(guard, request) {
  if (arguments.length !== 2) reject("sequence_step_arity_invalid");
  const state = requireGuard(guard);
  if (state.completed) reject("sequence_already_completed");
  assertExactObject(request, STEP_REQUEST_FIELDS, "sequence_step_request_invalid");
  const expected = state.operation.commands[state.next_index];
  if (!expected) reject("sequence_has_no_remaining_commands");
  if (!numberIsSafeInteger(request.command_sequence)
      || request.command_sequence !== expected.command_sequence) {
    reject(request.command_sequence < expected.command_sequence
      ? "sequence_duplicate_or_replay"
      : "sequence_reorder_or_omission");
  }
  const binding = objectFreeze({
    version: 1,
    kind: "chameleon_native_bootstrap_command_binding",
    provider_id: CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.provider_id,
    semantic_manifest_digest: CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.semantic_manifest_digest,
    bootstrap_manifest_digest: CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.bootstrap_manifest_digest,
    bootstrap_operation_registry_digest:
      CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.bootstrap_operation_registry_digest,
    native_bootstrap_semantic_table_digest:
      CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.table_digest,
    bootstrap_invariants_digest:
      CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.bootstrap_invariants_digest,
    operation_id: state.operation.operation_id,
    operation_digest: state.operation.operation_digest,
    command_set_digest: state.operation.command_set_digest,
    command_count: state.operation.commands.length,
    command_sequence: expected.command_sequence,
    command_id: expected.command_id,
    request_payload_byte_length: 0,
    request_frame_byte_length: 10,
    bootstrap_grant_projection_digest: state.bootstrap_grant_projection_digest,
    signed_grant_digest: state.signed_grant_digest,
    execution_request_digest: state.execution_request_digest,
    compiled_operation_digest: state.compiled_operation_digest,
  });
  reflectApply(weakSetAdd, STEP_BINDINGS, [binding]);
  state.next_index += 1;
  return binding;
}

function assertNativeBootstrapCommandBinding(value) {
  if (!value || !reflectApply(weakSetHas, STEP_BINDINGS, [value]) || !objectIsFrozen(value)) {
    reject("sequence_step_binding_brand_invalid");
  }
  return value;
}

function completeNativeBootstrapSequence(guard) {
  if (arguments.length !== 1) reject("sequence_completion_arity_invalid");
  const state = requireGuard(guard);
  if (state.completed) reject("sequence_already_completed");
  if (state.next_index !== state.operation.commands.length) {
    reject("sequence_incomplete");
  }
  state.completed = true;
  const completion = objectFreeze({
    version: 1,
    kind: "chameleon_native_bootstrap_sequence_planned",
    provider_id: CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.provider_id,
    operation_id: state.operation.operation_id,
    operation_digest: state.operation.operation_digest,
    command_set_digest: state.operation.command_set_digest,
    command_count: state.operation.commands.length,
    compiled_operation_digest: state.compiled_operation_digest,
    bootstrap_grant_projection_digest: state.bootstrap_grant_projection_digest,
    semantic_admission_complete: true,
    device_effect_performed: false,
    production_ready: false,
    authoritative: false,
  });
  reflectApply(weakSetAdd, COMPLETIONS, [completion]);
  return completion;
}

function assertNativeBootstrapSequenceCompletion(value) {
  if (!value || !reflectApply(weakSetHas, COMPLETIONS, [value])
      || !objectIsFrozen(value)) {
    reject("sequence_completion_brand_invalid");
  }
  return value;
}

const NATIVE_BOOTSTRAP_SEQUENCE_ASSURANCE = objectFreeze({
  version: 1,
  import_is_inert: true,
  device_enumeration: false,
  device_open: false,
  native_load: false,
  process_spawn: false,
  network_access: false,
  usb_access: false,
  hardware_effect: false,
  privately_branded_compiled_grant_required: true,
  duplicate_reorder_omission_rejected: true,
  durable_sequence_custody: false,
  native_launch_binding: false,
  production_ready: false,
  authoritative: false,
  production_blockers: objectFreeze([
    "durable_native_bootstrap_multi_command_orchestration_missing",
    "bootstrap_sequence_guard_to_native_launch_binding_missing",
  ]),
});

module.exports = objectFreeze({
  NATIVE_BOOTSTRAP_SEQUENCE_ASSURANCE,
  assertNativeBootstrapCommandBinding,
  assertNativeBootstrapSequenceCompletion,
  claimNativeBootstrapSequenceStep,
  completeNativeBootstrapSequence,
  createNativeBootstrapSequenceGuard,
});
