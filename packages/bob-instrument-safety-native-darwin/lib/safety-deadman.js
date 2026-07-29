"use strict";

// Provider-neutral Darwin deadman and cleanup-only worker precursor. Import and
// plan construction are inert. The only active path is an explicitly gated,
// separate-process native fixture; it has no provider, hardware, RF, vault, or
// MCP surface.

const childProcess = require("node:child_process");
const crypto = require("node:crypto");
const events = require("node:events");
const fs = require("node:fs");
const hostProcess = require("node:process");
const path = require("node:path");
const stream = require("node:stream");
const { types: utilTypes } = require("node:util");

const SafeArray = Array;
const SafeBigInt = BigInt;
const SafeBuffer = Buffer;
const SafeError = Error;
const SafeNumber = Number;
const SafePromise = Promise;
const SafeString = String;
const arrayIterator = Array.prototype[Symbol.iterator];
const arrayIsArray = Array.isArray;
const bufferAlloc = SafeBuffer.alloc;
const bufferFrom = SafeBuffer.from;
const bufferCopy = SafeBuffer.prototype.copy;
const bufferFill = SafeBuffer.prototype.fill;
const bufferToString = SafeBuffer.prototype.toString;
const bufferWriteBigUInt64BE = SafeBuffer.prototype.writeBigUInt64BE;
const childKill = childProcess.ChildProcess.prototype.kill;
const childSpawn = childProcess.spawn;
const clearTimeoutCaptured = clearTimeout;
const cryptoCreateHash = crypto.createHash;
const cryptoCreateHmac = crypto.createHmac;
const cryptoRandomBytes = crypto.randomBytes;
const cryptoTimingSafeEqual = crypto.timingSafeEqual;
const eventOnce = events.EventEmitter.prototype.once;
const fsCloseSync = fs.closeSync;
const fsFstatSync = fs.fstatSync;
const fsLstatSync = fs.lstatSync;
const fsOpenSync = fs.openSync;
const fsReadFileSync = fs.readFileSync;
const fsReadSync = fs.readSync;
const fsRealpathNative = fs.realpathSync.native;
const fsOpenAppend = fs.constants.O_APPEND;
const fsOpenCloseOnExec = fs.constants.O_CLOEXEC || 0;
const fsOpenCreate = fs.constants.O_CREAT;
const fsOpenExclusive = fs.constants.O_EXCL;
const fsOpenNoFollow = fs.constants.O_NOFOLLOW || 0;
const fsOpenReadOnly = fs.constants.O_RDONLY;
const fsOpenReadWrite = fs.constants.O_RDWR;
const functionToString = Function.prototype.toString;
const globalObject = globalThis;
const numberIsSafeInteger = Number.isSafeInteger;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const objectPrototype = Object.prototype;
const pathBasename = path.basename;
const pathDirname = path.dirname;
const pathJoin = path.join;
const pathResolve = path.resolve;
const processGetegid = hostProcess.getegid;
const processGeteuid = hostProcess.geteuid;
const processGetgid = hostProcess.getgid;
const processGetuid = hostProcess.getuid;
const processHrtimeBigint = hostProcess.hrtime.bigint;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const regexpTest = RegExp.prototype.test;
const readableDestroy = stream.Readable.prototype.destroy;
const readableOn = stream.Readable.prototype.on;
const setTimeoutCaptured = setTimeout;
const stringIndexOf = String.prototype.indexOf;
const stringSlice = String.prototype.slice;
const stringStartsWith = String.prototype.startsWith;
const utilIsProxy = utilTypes.isProxy;
const weakMapGet = WeakMap.prototype.get;
const weakMapSet = WeakMap.prototype.set;
const weakSetAdd = WeakSet.prototype.add;
const weakSetHas = WeakSet.prototype.has;
const writableEnd = stream.Writable.prototype.end;
const writableWrite = stream.Writable.prototype.write;

function ownCapturedArrayIterator(value) {
  objectDefineProperty(value, Symbol.iterator, {
    value: arrayIterator,
    writable: false,
    enumerable: false,
    configurable: false,
  });
  return value;
}

const hashProbe = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
const hashPrototype = objectGetPrototypeOf(hashProbe);
const hashUpdate = hashPrototype.update;
const hashDigest = hashPrototype.digest;
reflectApply(hashDigest, hashProbe, []);
const hmacProbeKey = reflectApply(bufferAlloc, SafeBuffer, [32]);
const hmacProbe = reflectApply(cryptoCreateHmac, crypto, ["sha256", hmacProbeKey]);
const hmacPrototype = objectGetPrototypeOf(hmacProbe);
const hmacUpdate = hmacPrototype.update;
const hmacDigest = hmacPrototype.digest;
reflectApply(hmacDigest, hmacProbe, []);
reflectApply(bufferFill, hmacProbeKey, [0]);

const hostProcessGlobalDescriptor = objectGetOwnPropertyDescriptor(globalObject, "process");
const hostBufferGlobalDescriptor = objectGetOwnPropertyDescriptor(globalObject, "Buffer");
const hostProcessPlatformDescriptor = objectGetOwnPropertyDescriptor(hostProcess, "platform");
const hostProcessArchDescriptor = objectGetOwnPropertyDescriptor(hostProcess, "arch");
const hostProcessVersionsDescriptor = objectGetOwnPropertyDescriptor(hostProcess, "versions");
const hostNodeDescriptor = objectGetOwnPropertyDescriptor(
  hostProcessVersionsDescriptor?.value,
  "node",
);
const arrayIteratorDescriptor = objectGetOwnPropertyDescriptor(
  SafeArray.prototype,
  Symbol.iterator,
);
const spawnDescriptor = objectGetOwnPropertyDescriptor(childProcess, "spawn");
const bufferFromDescriptor = objectGetOwnPropertyDescriptor(SafeBuffer, "from");
const bufferAllocDescriptor = objectGetOwnPropertyDescriptor(SafeBuffer, "alloc");
const fixtureEnvironmentGate =
  hostProcess.env.BOB_DARWIN_SAFETY_DEADMAN_FIXTURE === "1";

const VERSION = 1;
const REAL_BLOCKER = "darwin_safety_deadman_real_launch_disabled";
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const POSITIVE_INTEGER_PATTERN = /^[1-9][0-9]{0,19}$/u;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/u;
const JOURNAL_BASENAME_PATTERN = /^[a-z][a-z0-9._-]{0,127}\.journal$/u;
const MAX_EXECUTABLE_BYTES = 16 * 1024 * 1024;
const MAX_JOURNAL_BYTES = 64 * 1024;
const MAX_PENDING_PRIVATE_WRITES = 4;
const WATCHDOG_READY_TIMEOUT_MS = 10000;
const WATCHDOG_FORCE_TERMINATION_MS = 5000;
const CUSTODY_ENVELOPE_END = 16;
const CUSTODY_ACCEPTANCE_FIELD_COUNT = 30;
const ZERO_DIGEST = "0".repeat(64);
const JOURNAL_DOMAIN = "hacker-bob/darwin-safety-deadman-journal/v1";
const SEMANTIC_DOMAIN = "hacker-bob/darwin-safety-semantic-cleanup/v1";
const CONTRACT_DOMAIN = "hacker-bob/darwin-safety-deadman-contract/v1";
const CUSTODY_EVIDENCE_KEY_DOMAIN =
  "hacker-bob/darwin-safety-custody-evidence-key/v1";
const STOP_REASONS = objectFreeze([
  "lease_revoked",
  "operator_stop",
  "worker_disconnect",
]);
const JOURNAL_EVENT_ORDER = objectFreeze([
  "watchdog_started",
  "cleanup_triggered",
  "cleanup_finished",
  "terminal_quarantine",
]);
const FIXTURE_BEHAVIORS = objectFreeze([
  "ack",
  "stuck",
  "partial_stuck",
  "wrong_receipt",
  "journal_trigger_fail",
  "watchdog_stall_after_ready",
  "watchdog_stall_after_cleanup_handoff",
  "watchdog_exit_before_cleanup_guard",
  "watchdog_exit_after_cleanup_guard",
  "watchdog_block_first_journal_fsync",
  "watchdog_block_ready_output",
  "custody_late_arm_after_expiry",
  "custody_delay_arm_ack",
  "custody_expired_arm_ack",
  "custody_forged_arm_ack",
  "custody_pipe_only_arm",
  "custody_late_extend_ack",
  "custody_forged_extend_ack",
  "custody_replayed_extend_ack",
  "custody_reordered_extend_ack",
]);

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || objectIsFrozen(value)) return value;
  const keys = reflectOwnKeys(value);
  for (let index = 0; index < keys.length; index += 1) deepFreeze(value[keys[index]]);
  return objectFreeze(value);
}

const DARWIN_SAFETY_DEADMAN_ASSURANCE = deepFreeze({
  version: VERSION,
  production_ready: false,
  real_launch_enabled: false,
  fixture_process_only: true,
  import_and_construction_inert: true,
  mcp_surface_exposed: false,
  agent_ipc_to_cleanup_worker_exposed: false,
  provider_execute_surface_exposed: false,
  hardware_enumeration_exposed: false,
  hardware_open_exposed: false,
  vault_handle_surface_exposed: false,
  cleanup_operation_selector_exposed: false,
  administration_surface_exposed: false,
  destruction_surface_exposed: false,
  worker_termination_enabled: false,
  watchdog_process_separate: true,
  cleanup_worker_exec_separate: true,
  cleanup_trigger_to_terminal_absolute_deadline: true,
  cleanup_worker_parent_death_guard: true,
  independent_cleanup_custodian: true,
  custody_ready_before_effect_admission: true,
  custody_arm_acceptance_before_ready: true,
  custody_ready_round_trip_confirmation_before_controller: true,
  custody_extension_acceptance_before_heartbeat_success: true,
  custody_acceptance_sequence_contract_deadline_bound: true,
  custody_acceptance_host_delivery_deadline_checked: true,
  controller_command_active_custody_deadline_checked: true,
  pipe_delivery_is_not_custody_acceptance: true,
  custody_control_fd_eof_observation_only: true,
  custody_evidence_fixture_hmac_verified: true,
  custody_evidence_child_exclusive_identity_bound: false,
  custody_pre_ready_terminal_never_success: true,
  parent_stream_failure_requests_native_cleanup: true,
  watcher_launcher_process_group_separated: true,
  custodian_watcher_session_separated: true,
  cleanup_custodian_session_separated: true,
  child_start_session_group_identity_evidence_bound: true,
  stale_pid_or_pgid_signal_rejected: true,
  watchdog_fixture_ready_timeout_ms: WATCHDOG_READY_TIMEOUT_MS,
  watchdog_fixture_force_termination_ms: WATCHDOG_FORCE_TERMINATION_MS,
  watchdog_spawn_atomic_file_identity_bound: false,
  cleanup_exec_atomic_file_identity_bound: false,
  heartbeat_key_private_capability_fd: true,
  heartbeat_signature_fixture_hmac_only: true,
  journal_external_path_authoritative: false,
  battery_powered_instrument: true,
  usb_or_process_kill_proves_rf_off: false,
  emission_state_without_external_observer: "unknown",
  terminal_state_without_external_observer: "quarantined",
  observed_worker_pid_start_identity_bracketed: true,
  caller_worker_identity_digest_matches_native_observation: false,
  worker_identity_digest_protocol_binding_only: true,
  worker_audit_token_identity_bound: false,
  semantic_cleanup_sequence: [
    {
      order: 1,
      semantic_operation: "rf_release",
      future_provider_required: true,
      reviewed_provider_family: "chameleon_ultra",
      reviewed_command_family_id: 2101,
      role: "field_release_attempt",
    },
    {
      order: 2,
      semantic_operation: "restore_mf1_field_off_reset_setting",
      future_provider_required: true,
      reviewed_provider_family: "chameleon_ultra",
      reviewed_command_family_id: 4038,
      role: "conditional_precommitted_workspace_restore_not_rf_stop",
    },
    {
      order: 3,
      semantic_operation: "readback_mf1_field_off_reset_setting",
      future_provider_required: true,
      reviewed_provider_family: "chameleon_ultra",
      reviewed_command_family_id: 4039,
      role: "conditional_restore_readback",
    },
  ],
  production_blockers: [
    "qualified_launcher_missing",
    "dedicated_watchdog_and_cleanup_principals_missing",
    "device_and_journal_acl_qualification_missing",
    "signed_immutable_arm64_prebuild_missing",
    "watchdog_path_spawn_atomic_identity_binding_missing",
    "cleanup_path_exec_atomic_identity_binding_missing",
    "fixture_hmac_not_production_signature_authority",
    "custody_evidence_child_exclusive_identity_missing",
    "caller_worker_identity_digest_native_observation_binding_missing",
    "worker_audit_token_binding_missing",
    "independent_worker_fence_missing",
    "durable_external_journal_store_missing",
    "real_cleanup_provider_missing",
    "cleanup_custody_guard_qualification_missing",
    "blocking_storage_deadline_qualification_missing",
    "real_device_hil_missing",
    "external_rf_observer_hil_missing",
  ],
});

const PLANS = new WeakSet();
const PLAN_STATE = new WeakMap();
const CONTROLLERS = new WeakSet();
const CONTROLLER_STATE = new WeakMap();
const RESULTS = new WeakSet();
const RESULT_STATE = new WeakMap();

function safetyError(code = "darwin_safety_deadman_rejected") {
  const error = new SafeError("Darwin safety deadman fixture was rejected");
  objectDefineProperty(error, "code", {
    value: code,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return error;
}

function rejectSerialization() {
  throw safetyError("darwin_safety_capability_not_serializable");
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || arrayIsArray(value)
      || utilIsProxy(value)) return false;
  const prototype = objectGetPrototypeOf(value);
  if (prototype !== objectPrototype && prototype !== null) return false;
  const keys = reflectOwnKeys(value);
  for (let index = 0; index < keys.length; index += 1) {
    if (typeof keys[index] !== "string") return false;
    const descriptor = objectGetOwnPropertyDescriptor(value, keys[index]);
    if (descriptor == null || !objectHasOwn(descriptor, "value")
        || descriptor.enumerable !== true) return false;
  }
  return true;
}

function assertExactObject(value, fields) {
  if (!isPlainObject(value)) throw safetyError();
  const keys = reflectOwnKeys(value);
  if (keys.length !== fields.length) throw safetyError();
  for (let fieldIndex = 0; fieldIndex < fields.length; fieldIndex += 1) {
    let found = false;
    for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
      if (keys[keyIndex] === fields[fieldIndex]) found = true;
    }
    if (!found) throw safetyError();
  }
}

function assertInteger(value, minimum, maximum) {
  if (!reflectApply(numberIsSafeInteger, SafeNumber, [value])
      || value < minimum || value > maximum) throw safetyError();
  return value;
}

function assertDigest(value) {
  if (typeof value !== "string"
      || !reflectApply(regexpTest, DIGEST_PATTERN, [value])) throw safetyError();
  return value;
}

function assertIdentifier(value) {
  if (typeof value !== "string"
      || !reflectApply(regexpTest, IDENTIFIER_PATTERN, [value])) throw safetyError();
  return value;
}

function containsExact(values, expected) {
  for (let index = 0; index < values.length; index += 1) {
    if (values[index] === expected) return true;
  }
  return false;
}

function framedDigest(domain, fields) {
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(hashUpdate, hash, [domain, "utf8"]);
  for (let index = 0; index < fields.length; index += 1) {
    const bytes = reflectApply(bufferFrom, SafeBuffer, [
      reflectApply(SafeString, undefined, [fields[index]]),
      "utf8",
    ]);
    const length = reflectApply(bufferAlloc, SafeBuffer, [8]);
    reflectApply(bufferWriteBigUInt64BE, length, [SafeBigInt(bytes.length)]);
    reflectApply(hashUpdate, hash, [length]);
    reflectApply(hashUpdate, hash, [bytes]);
    reflectApply(bufferFill, length, [0]);
    reflectApply(bufferFill, bytes, [0]);
  }
  return reflectApply(hashDigest, hash, ["hex"]);
}

function hashBytes(bytes) {
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(hashUpdate, hash, [bytes]);
  return reflectApply(hashDigest, hash, ["hex"]);
}

function semanticProfile(value) {
  if (value === null) return "rf_off_only";
  if (value === false) return "rf_off_restore_mf1_false";
  if (value === true) return "rf_off_restore_mf1_true";
  throw safetyError();
}

function semanticFields(profile) {
  const fields = [
    "rf_release",
    "future_cleanup_provider",
    "chameleon_reviewed_family_2101",
    "first",
    "emission_unknown_without_external_observer",
  ];
  if (profile === "rf_off_only") {
    fields[fields.length] = "mf1_field_off_reset_restore_not_applicable";
    return fields;
  }
  if (profile !== "rf_off_restore_mf1_false"
      && profile !== "rf_off_restore_mf1_true") throw safetyError();
  fields[fields.length] = "mf1_field_off_reset_restore";
  fields[fields.length] = "chameleon_reviewed_family_4038";
  fields[fields.length] = profile === "rf_off_restore_mf1_true" ? "true" : "false";
  fields[fields.length] = "readback";
  fields[fields.length] = "chameleon_reviewed_family_4039";
  return fields;
}

function deriveDarwinSafetySemanticCleanupDigest(input) {
  assertExactObject(input, ["mf1_field_off_reset_restore", "version"]);
  if (input.version !== VERSION) throw safetyError();
  const profile = semanticProfile(input.mf1_field_off_reset_restore);
  return framedDigest(SEMANTIC_DOMAIN, semanticFields(profile));
}

const CONTRACT_FIELDS = objectFreeze([
  "cleanup_capability_digest",
  "cleanup_provider_manifest_digest",
  "cleanup_timeout_ms",
  "contract_id",
  "fencing_generation",
  "fencing_token_digest",
  "fixture_cleanup_behavior",
  "fixture_only",
  "heartbeat_interval_ms",
  "instrument_ref_digest",
  "journal_id_digest",
  "lease_id_digest",
  "mf1_field_off_reset_restore",
  "miss_tolerance",
  "restore_digest",
  "version",
  "worker_identity_digest",
  "worker_pid",
]);

function normalizeContractBasis(input) {
  assertExactObject(input, CONTRACT_FIELDS);
  if (input.version !== VERSION || typeof input.fixture_only !== "boolean") {
    throw safetyError();
  }
  const heartbeat = assertInteger(input.heartbeat_interval_ms, 10, 1000);
  const tolerance = assertInteger(input.miss_tolerance, 1, 5);
  if (heartbeat * tolerance > 5000) throw safetyError();
  const fixtureBehavior = input.fixture_cleanup_behavior;
  if ((input.fixture_only && !containsExact(FIXTURE_BEHAVIORS, fixtureBehavior))
      || (!input.fixture_only && fixtureBehavior !== "unavailable")) throw safetyError();
  const profile = semanticProfile(input.mf1_field_off_reset_restore);
  const semanticDigest = framedDigest(SEMANTIC_DOMAIN, semanticFields(profile));
  return {
    version: VERSION,
    contract_id: assertIdentifier(input.contract_id),
    fixture_only: input.fixture_only,
    instrument_ref_digest: assertDigest(input.instrument_ref_digest),
    lease_id_digest: assertDigest(input.lease_id_digest),
    fencing_token_digest: assertDigest(input.fencing_token_digest),
    fencing_generation: assertInteger(input.fencing_generation, 1, 0xffff_ffff),
    worker_pid: assertInteger(input.worker_pid, 2, 0x7fff_ffff),
    worker_identity_digest: assertDigest(input.worker_identity_digest),
    cleanup_capability_digest: assertDigest(input.cleanup_capability_digest),
    restore_digest: assertDigest(input.restore_digest),
    cleanup_provider_manifest_digest: assertDigest(
      input.cleanup_provider_manifest_digest,
    ),
    journal_id_digest: assertDigest(input.journal_id_digest),
    heartbeat_interval_ms: heartbeat,
    miss_tolerance: tolerance,
    deadman_ms: heartbeat * tolerance,
    cleanup_timeout_ms: assertInteger(input.cleanup_timeout_ms, 10, 2000),
    mf1_field_off_reset_restore: input.mf1_field_off_reset_restore,
    semantic_profile: profile,
    semantic_cleanup_digest: semanticDigest,
    fixture_cleanup_behavior: fixtureBehavior,
  };
}

function contractDigestFromNormalized(value) {
  return framedDigest(CONTRACT_DOMAIN, [
    reflectApply(SafeString, undefined, [value.version]),
    value.contract_id,
    reflectApply(SafeString, undefined, [value.fixture_only]),
    value.instrument_ref_digest,
    value.lease_id_digest,
    value.fencing_token_digest,
    reflectApply(SafeString, undefined, [value.fencing_generation]),
    reflectApply(SafeString, undefined, [value.worker_pid]),
    value.worker_identity_digest,
    value.cleanup_capability_digest,
    value.restore_digest,
    value.cleanup_provider_manifest_digest,
    value.journal_id_digest,
    reflectApply(SafeString, undefined, [value.heartbeat_interval_ms]),
    reflectApply(SafeString, undefined, [value.miss_tolerance]),
    reflectApply(SafeString, undefined, [value.deadman_ms]),
    reflectApply(SafeString, undefined, [value.cleanup_timeout_ms]),
    value.semantic_profile,
    value.semantic_cleanup_digest,
    value.fixture_cleanup_behavior,
  ]);
}

function deriveDarwinSafetyDeadmanContractDigest(input) {
  return contractDigestFromNormalized(normalizeContractBasis(input));
}

function createPlan(input, fixtureOnly) {
  assertExactObject(input, ["contract", "contract_digest", "version"]);
  if (input.version !== VERSION || (fixtureOnly && !fixtureEnvironmentGate)) {
    throw safetyError();
  }
  const normalized = normalizeContractBasis(input.contract);
  if (normalized.fixture_only !== fixtureOnly
      || input.contract_digest !== contractDigestFromNormalized(normalized)) {
    throw safetyError();
  }
  const state = {
    contract: objectFreeze(normalized),
    consumed: false,
    destroyed: false,
    controller: null,
  };
  const plan = objectFreeze({
    version: VERSION,
    kind: "darwin_safety_deadman_plan",
    contract_id: normalized.contract_id,
    contract_digest: input.contract_digest,
    instrument_ref_digest: normalized.instrument_ref_digest,
    lease_id_digest: normalized.lease_id_digest,
    cleanup_capability_digest: normalized.cleanup_capability_digest,
    restore_digest: normalized.restore_digest,
    semantic_cleanup_digest: normalized.semantic_cleanup_digest,
    semantic_profile: normalized.semantic_profile,
    fixture_only: fixtureOnly,
    production_ready: false,
    blocker_code: REAL_BLOCKER,
    capability_id: `darwin-safety-deadman:${reflectApply(
      bufferToString,
      reflectApply(cryptoRandomBytes, crypto, [18]),
      ["base64url"],
    )}`,
    toJSON: rejectSerialization,
  });
  reflectApply(weakSetAdd, PLANS, [plan]);
  reflectApply(weakMapSet, PLAN_STATE, [plan, state]);
  return plan;
}

function createDarwinSafetyDeadmanPlan(input) {
  return createPlan(input, false);
}

function createDarwinSafetyDeadmanFixturePlan(input) {
  return createPlan(input, true);
}

function assertPlan(input) {
  const state = input == null ? null : reflectApply(weakMapGet, PLAN_STATE, [input]);
  if (!input || !reflectApply(weakSetHas, PLANS, [input]) || !state
      || !objectIsFrozen(input) || input.version !== VERSION
      || input.kind !== "darwin_safety_deadman_plan"
      || input.contract_id !== state.contract.contract_id
      || input.contract_digest !== contractDigestFromNormalized(state.contract)
      || input.instrument_ref_digest !== state.contract.instrument_ref_digest
      || input.lease_id_digest !== state.contract.lease_id_digest
      || input.cleanup_capability_digest !== state.contract.cleanup_capability_digest
      || input.restore_digest !== state.contract.restore_digest
      || input.semantic_cleanup_digest !== state.contract.semantic_cleanup_digest
      || input.semantic_profile !== state.contract.semantic_profile
      || input.fixture_only !== state.contract.fixture_only
      || input.production_ready !== false || input.blocker_code !== REAL_BLOCKER
      || reflectOwnKeys(input).length !== 15) throw safetyError();
  return input;
}

function sameDescriptor(actual, expected) {
  if (actual == null || expected == null) return false;
  const fields = ["value", "get", "set", "writable", "enumerable", "configurable"];
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    if (objectHasOwn(actual, field) !== objectHasOwn(expected, field)) return false;
    if (objectHasOwn(expected, field) && actual[field] !== expected[field]) return false;
  }
  return true;
}

function assertHostRuntimeUntampered() {
  const processDescriptor = objectGetOwnPropertyDescriptor(globalObject, "process");
  const bufferDescriptor = objectGetOwnPropertyDescriptor(globalObject, "Buffer");
  let currentProcess;
  let currentBuffer;
  try {
    currentProcess = reflectApply(hostProcessGlobalDescriptor.get, globalObject, []);
    currentBuffer = reflectApply(hostBufferGlobalDescriptor.get, globalObject, []);
  } catch {
    throw safetyError("darwin_safety_host_runtime_rejected");
  }
  if (!sameDescriptor(processDescriptor, hostProcessGlobalDescriptor)
      || !sameDescriptor(bufferDescriptor, hostBufferGlobalDescriptor)
      || currentProcess !== hostProcess || currentBuffer !== SafeBuffer
      // Node 20 child_process.normalizeSpawnArguments performs a live
      // for-of over an internal array. Reject an ambient iterator replacement
      // before opening the journal or attempting spawn.
      || !sameDescriptor(objectGetOwnPropertyDescriptor(
        SafeArray.prototype,
        Symbol.iterator,
      ), arrayIteratorDescriptor)
      || !sameDescriptor(objectGetOwnPropertyDescriptor(childProcess, "spawn"),
        spawnDescriptor)
      || !sameDescriptor(objectGetOwnPropertyDescriptor(SafeBuffer, "from"),
        bufferFromDescriptor)
      || !sameDescriptor(objectGetOwnPropertyDescriptor(SafeBuffer, "alloc"),
        bufferAllocDescriptor)
      || !sameDescriptor(objectGetOwnPropertyDescriptor(hostProcess, "platform"),
        hostProcessPlatformDescriptor)
      || !sameDescriptor(objectGetOwnPropertyDescriptor(hostProcess, "arch"),
        hostProcessArchDescriptor)
      || !sameDescriptor(objectGetOwnPropertyDescriptor(hostProcess, "versions"),
        hostProcessVersionsDescriptor)
      || !sameDescriptor(objectGetOwnPropertyDescriptor(
        hostProcessVersionsDescriptor?.value,
        "node",
      ), hostNodeDescriptor)
      || hostProcessPlatformDescriptor?.value !== "darwin"
      || hostProcessArchDescriptor?.value !== "arm64"
      || typeof hostNodeDescriptor?.value !== "string"
      || !reflectApply(stringStartsWith, hostNodeDescriptor.value, ["20."])) {
    throw safetyError("darwin_safety_host_runtime_rejected");
  }
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode
    && left.uid === right.uid && left.gid === right.gid && left.nlink === right.nlink
    && left.size === right.size && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function measureExecutable() {
  const candidates = [
    pathJoin(__dirname, "..", "prebuilds", "darwin-arm64", "safety_watchdog_fixture"),
    pathJoin(__dirname, "..", "build", "Release", "safety_watchdog_fixture"),
  ];
  let lastMissing = false;
  for (let index = 0; index < candidates.length; index += 1) {
    let fd = -1;
    try {
      const absolute = pathResolve(candidates[index]);
      const canonical = fsRealpathNative(candidates[index]);
      if (absolute !== canonical) throw safetyError();
      fd = fsOpenSync(
        canonical,
        fsOpenReadOnly | fsOpenCloseOnExec | fsOpenNoFollow,
      );
      const before = fsFstatSync(fd, { bigint: true });
      if (!before.isFile() || before.nlink !== 1n || (before.mode & 0o022n) !== 0n
          || before.uid !== SafeBigInt(reflectApply(processGeteuid, hostProcess, []))
          || before.size < 1n || before.size > SafeBigInt(MAX_EXECUTABLE_BYTES)) {
        throw safetyError();
      }
      const bytes = fsReadFileSync(fd);
      try {
        const after = fsFstatSync(fd, { bigint: true });
        if (!sameFileIdentity(before, after) || SafeBigInt(bytes.length) !== before.size) {
          throw safetyError();
        }
        return objectFreeze({ path: canonical, digest: hashBytes(bytes), stat: before });
      } finally {
        reflectApply(bufferFill, bytes, [0]);
      }
    } catch (error) {
      if (error?.code === "ENOENT") {
        lastMissing = true;
      } else {
        throw error;
      }
    } finally {
      if (fd >= 0) fsCloseSync(fd);
    }
  }
  if (lastMissing) throw safetyError("darwin_safety_fixture_executable_missing");
  throw safetyError("darwin_safety_fixture_executable_rejected");
}

function openJournalCapability(journalPath) {
  if (typeof journalPath !== "string") throw safetyError();
  const absolute = pathResolve(journalPath);
  const parent = pathDirname(absolute);
  const basename = pathBasename(absolute);
  if (!reflectApply(regexpTest, JOURNAL_BASENAME_PATTERN, [basename])) {
    throw safetyError();
  }
  const canonicalParent = fsRealpathNative(parent);
  const canonicalPath = pathJoin(canonicalParent, basename);
  const parentStatus = fsLstatSync(canonicalParent, { bigint: true });
  const uid = SafeBigInt(reflectApply(processGeteuid, hostProcess, []));
  const gid = SafeBigInt(reflectApply(processGetegid, hostProcess, []));
  if (!parentStatus.isDirectory() || parentStatus.uid !== uid
      || parentStatus.gid !== gid || (parentStatus.mode & 0o077n) !== 0n) {
    throw safetyError();
  }
  const flags = fsOpenCreate | fsOpenExclusive | fsOpenReadWrite
    | fsOpenAppend | fsOpenCloseOnExec | fsOpenNoFollow;
  const fd = fsOpenSync(canonicalPath, flags, 0o600);
  try {
    const status = fsFstatSync(fd, { bigint: true });
    if (!status.isFile() || status.nlink !== 1n || status.uid !== uid
        || status.gid !== gid || (status.mode & 0o077n) !== 0n || status.size !== 0n) {
      throw safetyError();
    }
    return fd;
  } catch (error) {
    fsCloseSync(fd);
    throw error;
  }
}

function splitTabs(value) {
  const output = [];
  let start = 0;
  for (let index = 0; index <= value.length; index += 1) {
    if (index === value.length || value[index] === "\t") {
      output[output.length] = reflectApply(stringSlice, value, [start, index]);
      start = index + 1;
    }
  }
  return output;
}

function joinTabs(fields) {
  let output = "";
  for (let index = 0; index < fields.length; index += 1) {
    if (index !== 0) output += "\t";
    output += fields[index];
  }
  return output;
}

function hmacHex(key, payload) {
  const hmac = reflectApply(cryptoCreateHmac, crypto, ["sha256", key]);
  reflectApply(hmacUpdate, hmac, [payload, "utf8"]);
  return reflectApply(hmacDigest, hmac, ["hex"]);
}

function deriveCustodyEvidenceKey(key, contractDigest) {
  const hmac = reflectApply(cryptoCreateHmac, crypto, ["sha256", key]);
  reflectApply(hmacUpdate, hmac, [
    `${CUSTODY_EVIDENCE_KEY_DOMAIN}\t${contractDigest}`,
    "utf8",
  ]);
  return reflectApply(hmacDigest, hmac, []);
}

function verifySignedFields(fields, key) {
  if (fields.length < 2
      || !reflectApply(regexpTest, DIGEST_PATTERN, [fields[fields.length - 1]])) {
    return false;
  }
  const payloadFields = [];
  for (let index = 0; index + 1 < fields.length; index += 1) {
    payloadFields[payloadFields.length] = fields[index];
  }
  const expectedHex = hmacHex(key, joinTabs(payloadFields));
  const expected = reflectApply(bufferFrom, SafeBuffer, [expectedHex, "hex"]);
  const actual = reflectApply(
    bufferFrom,
    SafeBuffer,
    [fields[fields.length - 1], "hex"],
  );
  let accepted = false;
  try {
    accepted = reflectApply(cryptoTimingSafeEqual, crypto, [expected, actual]);
  } finally {
    reflectApply(bufferFill, expected, [0]);
    reflectApply(bufferFill, actual, [0]);
  }
  return accepted;
}

function signedLine(fields, key) {
  const payload = joinTabs(fields);
  const mac = hmacHex(key, payload);
  return reflectApply(bufferFrom, SafeBuffer, [`${payload}\t${mac}\n`, "utf8"]);
}

function keyCapability(key) {
  const output = reflectApply(bufferAlloc, SafeBuffer, [36]);
  output[0] = 0x4b;
  output[1] = 0x45;
  output[2] = 0x59;
  output[3] = 0x31;
  reflectApply(bufferCopy, key, [output, 4]);
  return output;
}

function makeDeferred() {
  let resolve;
  let reject;
  const promise = new SafePromise((resolveValue, rejectValue) => {
    resolve = resolveValue;
    reject = rejectValue;
  });
  return { promise, resolve, reject, settled: false };
}

function settleDeferred(deferred, accepted, value) {
  if (deferred.settled) return;
  deferred.settled = true;
  if (accepted) deferred.resolve(value);
  else deferred.reject(value);
}

function parseJournal(fd, expectedContract, nativeSequence, nativeHead) {
  const status = fsFstatSync(fd, { bigint: true });
  if (status.size < 1n || status.size > SafeBigInt(MAX_JOURNAL_BYTES)) {
    throw safetyError("darwin_safety_journal_readback_rejected");
  }
  const bytes = reflectApply(bufferAlloc, SafeBuffer, [SafeNumber(status.size)]);
  let offset = 0;
  while (offset < bytes.length) {
    const count = fsReadSync(fd, bytes, offset, bytes.length - offset, offset);
    if (count < 1) throw safetyError("darwin_safety_journal_readback_rejected");
    offset += count;
  }
  try {
    const text = reflectApply(bufferToString, bytes, ["utf8"]);
    const records = [];
    let start = 0;
    let sequence = 1;
    let previous = ZERO_DIGEST;
    let previousMonotonic = 0n;
    while (start < text.length) {
      const newline = reflectApply(stringIndexOf, text, ["\n", start]);
      if (newline < 0 || newline === start) throw safetyError();
      const fields = splitTabs(reflectApply(stringSlice, text, [start, newline]));
      let monotonic;
      try { monotonic = SafeBigInt(fields[2]); } catch { monotonic = 0n; }
      if (fields.length !== 8 || fields[0] !== "J1"
          || fields[1] !== reflectApply(SafeString, undefined, [sequence])
          || sequence > JOURNAL_EVENT_ORDER.length
          || fields[3] !== JOURNAL_EVENT_ORDER[sequence - 1]
          || monotonic <= previousMonotonic
          || !reflectApply(regexpTest, IDENTIFIER_PATTERN, [fields[4]])
          || fields[5] !== expectedContract || fields[6] !== previous
          || !reflectApply(regexpTest, DIGEST_PATTERN, [fields[7]])) throw safetyError();
      const digest = framedDigest(JOURNAL_DOMAIN, [
        fields[1], fields[2], fields[3], fields[4], fields[5], fields[6],
      ]);
      if (digest !== fields[7]) throw safetyError();
      records[records.length] = objectFreeze({
        sequence,
        event_code: fields[3],
        reason_code: fields[4],
        record_digest: fields[7],
      });
      previous = fields[7];
      previousMonotonic = monotonic;
      sequence += 1;
      start = newline + 1;
    }
    if (records.length !== JOURNAL_EVENT_ORDER.length
        || records.length !== nativeSequence || previous !== nativeHead) throw safetyError();
    return objectFreeze(records);
  } finally {
    reflectApply(bufferFill, bytes, [0]);
  }
}

function buildProtocolBindings(contract, challenge) {
  return [
    challenge,
    contract.contract_digest,
    contract.instrument_ref_digest,
    contract.lease_id_digest,
    contract.fencing_token_digest,
    reflectApply(SafeString, undefined, [contract.fencing_generation]),
    contract.worker_identity_digest,
    contract.cleanup_capability_digest,
    contract.restore_digest,
    contract.semantic_cleanup_digest,
  ];
}

function verifyCustodyAcceptance(
  state,
  fields,
  expectedType,
  expectedSequence,
  expectedIssued,
  expectedValidUntil,
  watcherPid,
) {
  if (fields.length !== CUSTODY_ACCEPTANCE_FIELD_COUNT
      || fields[0] !== expectedType || fields[1] !== "1"
      || fields[2] !== state.contract.contract_digest
      || !reflectApply(regexpTest, DIGEST_PATTERN, [fields[3]])
      || !reflectApply(regexpTest, /^[a-f0-9]{32}$/u, [fields[4]])
      || !verifySignedFields(fields, state.custodyEvidenceKey)) return null;
  const numericIndexes = [5, 6, 7, 9, 10, 13, 14, 17, 18, 19, 20];
  for (let index = 0; index < numericIndexes.length; index += 1) {
    if (!reflectApply(regexpTest, POSITIVE_INTEGER_PATTERN, [
      fields[numericIndexes[index]],
    ])) return null;
  }
  if (!reflectApply(regexpTest, /^(?:0|[1-9][0-9]{0,19})$/u, [fields[16]])) {
    return null;
  }
  let custodianPid;
  let acceptedAt;
  let issued;
  let validUntil;
  try {
    custodianPid = assertInteger(SafeNumber(fields[6]), 2, 2147483647);
    issued = SafeBigInt(fields[17]);
    validUntil = SafeBigInt(fields[18]);
    acceptedAt = SafeBigInt(fields[19]);
  } catch {
    return null;
  }
  if (fields[5] !== reflectApply(SafeString, undefined, [watcherPid])
      || custodianPid === watcherPid
      || custodianPid === state.contract.worker_pid
      || fields[9] !== fields[5] || fields[10] !== fields[5]
      || fields[13] !== fields[6] || fields[14] !== fields[6]
      || !reflectApply(regexpTest, DIGEST_PATTERN, [fields[8]])
      || !reflectApply(regexpTest, DIGEST_PATTERN, [fields[11]])
      || !reflectApply(regexpTest, DIGEST_PATTERN, [fields[12]])
      || !reflectApply(regexpTest, DIGEST_PATTERN, [fields[15]])
      || fields[16] !== reflectApply(SafeString, undefined, [expectedSequence])
      || fields[17] !== expectedIssued || fields[18] !== expectedValidUntil
      || fields[20] !== expectedValidUntil
      || acceptedAt < issued || acceptedAt > validUntil) return null;
  const expectedBindings = [
    state.contract.instrument_ref_digest,
    state.contract.lease_id_digest,
    state.contract.fencing_token_digest,
    reflectApply(SafeString, undefined, [state.contract.fencing_generation]),
    state.contract.worker_identity_digest,
    state.contract.cleanup_capability_digest,
    state.contract.restore_digest,
    state.contract.semantic_cleanup_digest,
  ];
  for (let index = 0; index < expectedBindings.length; index += 1) {
    if (fields[CUSTODY_ENVELOPE_END + 5 + index] !== expectedBindings[index]) {
      return null;
    }
  }
  if (state.custodyEnvelope !== null) {
    for (let index = 2; index < CUSTODY_ENVELOPE_END; index += 1) {
      if (fields[index] !== state.custodyEnvelope[index - 2]) return null;
    }
  }
  const envelope = [];
  for (let index = 2; index < CUSTODY_ENVELOPE_END; index += 1) {
    envelope[envelope.length] = fields[index];
  }
  return {
    custodianPid,
    envelope: objectFreeze(envelope),
    acceptedAt,
    validUntil,
  };
}

function watchdogMonotonicNow(state) {
  if (state.nativeMonotonicAnchor === null || state.hostMonotonicAnchor === null) {
    throw safetyError();
  }
  const hostNow = reflectApply(processHrtimeBigint, hostProcess.hrtime, []);
  const elapsed = hostNow - state.hostMonotonicAnchor;
  if (elapsed < 0n) throw safetyError();
  // READY supplies the initial lower anchor; every accepted custody ACK then
  // refreshes it from signed `acceptedAt`. Extrapolation stays in the native
  // CLOCK_MONOTONIC domain; Node's hrtime epoch is not assumed to match it.
  return state.nativeMonotonicAnchor + elapsed;
}

function watchdogMonotonicUpperNow(state) {
  if (state.nativeMonotonicUpperAnchor === null
      || state.hostMonotonicUpperAnchor === null) throw safetyError();
  const hostNow = reflectApply(processHrtimeBigint, hostProcess.hrtime, []);
  const elapsed = hostNow - state.hostMonotonicUpperAnchor;
  if (elapsed < 0n) throw safetyError();
  return state.nativeMonotonicUpperAnchor + elapsed;
}

function requireLiveCustody(state) {
  let live = false;
  try {
    live = state.activeCustodyDeadline !== null
      && watchdogMonotonicUpperNow(state) < state.activeCustodyDeadline;
  } catch {}
  if (live) return;
  state.ready = false;
  requestNativeCleanup(state);
  throw safetyError("darwin_safety_custody_deadline_expired");
}

function armWatchdogForceTerminationAt(state, deadline, neverExtend) {
  if (state.finalized) return false;
  const now = reflectApply(processHrtimeBigint, hostProcess.hrtime, []);
  if (neverExtend && state.forceKillTimer !== null
      && state.forceKillDeadline !== null
      && state.forceKillDeadline <= deadline) return true;
  if (state.forceKillTimer !== null) {
    clearTimeoutCaptured(state.forceKillTimer);
    state.forceKillTimer = null;
  }
  const remaining = deadline > now ? deadline - now : 0n;
  const delayMs = SafeNumber((remaining + 999999n) / 1000000n);
  if (!reflectApply(numberIsSafeInteger, SafeNumber, [delayMs])) return false;
  state.forceKillDeadline = deadline;
  state.forceKillTimer = setTimeoutCaptured(() => {
    state.forceKillTimer = null;
    state.forceKillDeadline = null;
    if (state.finalized) return;
    state.ready = false;
    state.errorCode = state.errorCode || "darwin_safety_watchdog_shutdown_timeout";
    try { reflectApply(childKill, state.child, ["SIGKILL"]); } catch {}
  }, delayMs);
  return true;
}

function armWatchdogForceTermination(state, delayMs, neverExtend) {
  const now = reflectApply(processHrtimeBigint, hostProcess.hrtime, []);
  return armWatchdogForceTerminationAt(
    state,
    now + SafeBigInt(delayMs) * 1000000n,
    neverExtend,
  );
}

function armAutonomousWatchdogBound(state, nativeDeadline) {
  let nativeUpper;
  try {
    nativeUpper = watchdogMonotonicUpperNow(state);
  } catch {
    return false;
  }
  if (nativeDeadline <= nativeUpper) return false;
  const cleanupAndKillMargin = SafeBigInt(
    state.contract.cleanup_timeout_ms + WATCHDOG_FORCE_TERMINATION_MS,
  ) * 1000000n;
  return armWatchdogForceTerminationAt(
    state,
    state.hostMonotonicUpperAnchor
      + (nativeDeadline - state.nativeMonotonicUpperAnchor)
      + cleanupAndKillMargin,
    false,
  );
}

function armCleanupWatchdogBound(state) {
  armWatchdogForceTermination(
    state,
    state.contract.cleanup_timeout_ms + WATCHDOG_FORCE_TERMINATION_MS,
    true,
  );
}

function armUnconfirmedReadyWatchdogBound(state) {
  // READY has not established a host upper clock anchor, so it cannot start a
  // caller-visible lease or a fresh relative deadman. It can only start this
  // cleanup-plus-kill fallback; a valid round-trip confirmation replaces it
  // with the signed absolute-deadline projection.
  armWatchdogForceTermination(
    state,
    state.contract.cleanup_timeout_ms + WATCHDOG_FORCE_TERMINATION_MS,
    false,
  );
}

function requestNativeCleanup(state, code = null) {
  if (state.finalized) return;
  state.ready = false;
  if (code && !state.errorCode) state.errorCode = code;
  if (!state.cleanupRequested) {
    state.cleanupRequested = true;
    try { reflectApply(writableEnd, state.control, []); } catch {}
  }
  armCleanupWatchdogBound(state);
}

function writePrivate(state, bytes) {
  if (state.closed || !state.control) throw safetyError();
  if (state.pendingPrivateWrites >= MAX_PENDING_PRIVATE_WRITES) {
    reflectApply(bufferFill, bytes, [0]);
    requestNativeCleanup(state, "darwin_safety_control_backpressure_rejected");
    throw safetyError("darwin_safety_control_backpressure_rejected");
  }
  state.pendingPrivateWrites += 1;
  let released = false;
  const release = (error) => {
    if (released) return;
    released = true;
    state.pendingPrivateWrites -= 1;
    reflectApply(bufferFill, bytes, [0]);
    if (error && !state.finalized) {
      requestNativeCleanup(state, "darwin_safety_control_write_rejected");
    }
  };
  try {
    // The stream owns the bytes until its write-completion callback. Clearing
    // them earlier can mutate libuv's queued chunk before the native process
    // receives it.
    // A false return is only a backpressure signal; the chunk was still
    // queued. The explicit outstanding-write bound above prevents an
    // unbounded private queue while ownership remains with the callback.
    reflectApply(writableWrite, state.control, [bytes, release]);
  } catch {
    release();
    requestNativeCleanup(state, "darwin_safety_control_write_rejected");
    throw safetyError();
  }
}

function beginHeartbeat(state, readyConfirmation, fixedValidUntil = null) {
  if (!readyConfirmation) requireLiveCustody(state);
  state.sequence += 1;
  const issued = watchdogMonotonicNow(state);
  const maximumWindow = SafeBigInt(state.contract.deadman_ms) * 1000000n;
  const valid = fixedValidUntil === null
    ? issued + maximumWindow
    : fixedValidUntil;
  if (issued < 1n || valid <= issued || valid - issued > maximumWindow) {
    throw safetyError(
      readyConfirmation
        ? "darwin_safety_ready_confirmation_expired"
        : "darwin_safety_heartbeat_window_rejected",
    );
  }
  const issuedString = reflectApply(SafeString, undefined, [issued]);
  const validString = reflectApply(SafeString, undefined, [valid]);
  const fields = [
    "HB1", "1", reflectApply(SafeString, undefined, [state.sequence]),
    issuedString,
    validString,
  ];
  const bindings = buildProtocolBindings(state.contract, state.challenge);
  for (let index = 0; index < bindings.length; index += 1) {
    fields[fields.length] = bindings[index];
  }
  const bytes = signedLine(fields, state.key);
  if (!readyConfirmation) {
    try {
      // Do not enqueue a new extension after the previously accepted native
      // custody window has already elapsed during record construction.
      requireLiveCustody(state);
    } catch (error) {
      reflectApply(bufferFill, bytes, [0]);
      throw error;
    }
  }
  const deferred = readyConfirmation ? state.readyDeferred : makeDeferred();
  const sentAtHost = reflectApply(processHrtimeBigint, hostProcess.hrtime, []);
  state.pendingHeartbeat = {
    sequence: state.sequence,
    issued: issuedString,
    validUntil: validString,
    deferred,
    readyConfirmation,
    sentAtHost,
  };
  try {
    writePrivate(state, bytes);
  } catch (error) {
    rejectPendingHeartbeat(state, error?.code ? error : safetyError());
  }
  return deferred.promise;
}

function buildResult(state, fields, records) {
  const journalSequence = assertInteger(SafeNumber(fields[7]), 1, 1000);
  const triggerSequence = assertInteger(SafeNumber(fields[3]), 0, Number.MAX_SAFE_INTEGER);
  assertIdentifier(fields[2]);
  assertIdentifier(fields[4]);
  const result = objectFreeze({
    version: VERSION,
    kind: "darwin_safety_deadman_terminal_result",
    state: "quarantined",
    reason_code: fields[2],
    trigger_sequence: triggerSequence,
    cleanup_outcome: fields[4],
    emission_state: "unknown",
    external_observer_confirmed: false,
    quarantined: true,
    watchdog_process_separate: true,
    cleanup_worker_exec_separate: fields[12] === "true",
    process_group_identity_evidence_verified: true,
    journal_sequence: journalSequence,
    journal_head_digest: fields[8],
    journal_readback_verified: true,
    fixture_only: true,
    production_ready: false,
    toJSON: rejectSerialization,
  });
  reflectApply(weakSetAdd, RESULTS, [result]);
  reflectApply(weakMapSet, RESULT_STATE, [result, { records }]);
  return result;
}

function rejectPendingHeartbeat(state, failure) {
  if (state.pendingHeartbeat === null) return;
  const pending = state.pendingHeartbeat;
  state.pendingHeartbeat = null;
  settleDeferred(pending.deferred, false, failure);
}

function finalizeChild(state, exitCode) {
  if (state.finalized) return;
  state.finalized = true;
  state.closed = true;
  state.ready = false;
  if (state.forceKillTimer !== null) {
    clearTimeoutCaptured(state.forceKillTimer);
    state.forceKillTimer = null;
  }
  state.forceKillDeadline = null;
  if (state.key) reflectApply(bufferFill, state.key, [0]);
  if (state.custodyEvidenceKey) {
    reflectApply(bufferFill, state.custodyEvidenceKey, [0]);
  }
  let failure = null;
  let result = null;
  try {
    if (!state.terminalFields || !state.custodyFields || exitCode !== 0
        || state.output.length !== 0 || state.custodyOutput.length !== 0
        || state.errorCode) {
      failure = safetyError(
        state.errorCode || "darwin_safety_watchdog_process_rejected",
      );
    } else {
      const fields = state.terminalFields;
      let cleanupPid = -1;
      if (fields[11] !== "-1") {
        cleanupPid = assertInteger(SafeNumber(fields[11]), 2, 2147483647);
      }
      const watchdogPid = assertInteger(SafeNumber(fields[10]), 2, 2147483647);
      const custodianPid = assertInteger(SafeNumber(fields[13]), 2, 2147483647);
      const custody = state.custodyFields;
      if (fields.length !== 26 || fields[0] !== "TERM1"
          || fields[1] !== "quarantined" || fields[5] !== "unknown"
          || fields[6] !== "true" || fields[9] !== "true"
          || (fields[12] !== "true" && fields[12] !== "false")
          || !reflectApply(regexpTest, DIGEST_PATTERN, [fields[8]])
          || watchdogPid !== state.watchdogPid
          || watchdogPid === state.contract.worker_pid
          || custodianPid === watchdogPid
          || custodianPid === state.contract.worker_pid
          || (fields[12] === "true" && cleanupPid < 2)
          || (cleanupPid >= 2 && (cleanupPid === watchdogPid
            || cleanupPid === custodianPid
            || cleanupPid === state.contract.worker_pid))
          || custody.length !== 28 || custody[0] !== "CUSTODY1"
          || custody[1] !== "1" || custody[2] !== state.contract.contract_digest
          || !reflectApply(regexpTest, DIGEST_PATTERN, [custody[3]])
          || !reflectApply(regexpTest, /^[a-f0-9]{32}$/u, [custody[4]])
          || !reflectApply(regexpTest, /^[1-9][0-9]{0,19}$/u, [custody[7]])
          || (custody[18] === "fixture_acknowledged_rf_unknown"
            && custody[16] !== fields[2])
          || (custody[18] !== "fixture_acknowledged_rf_unknown"
            && fields[2] !== fields[4])
          || custody[17] !== fields[3]
          || custody[18] !== fields[4] || custody[19] !== "unknown"
          || custody[20] !== "quarantined"
          || custody[6] !== fields[13] || custody[5] !== fields[10]
          || custody[21] !== fields[11] || custody[22] !== fields[12]
          || custody[8] !== fields[14] || custody[9] !== fields[15]
          || custody[10] !== fields[16] || custody[11] !== fields[17]
          || custody[12] !== fields[18] || custody[13] !== fields[19]
          || custody[14] !== fields[20] || custody[15] !== fields[21]
          || custody[23] !== fields[22] || custody[24] !== fields[23]
          || custody[25] !== fields[24] || custody[26] !== fields[25]
          || fields[15] !== fields[10] || fields[16] !== fields[10]
          || fields[19] !== fields[13] || fields[20] !== fields[13]
          || (cleanupPid >= 2
            && (fields[23] !== fields[11] || fields[24] !== fields[11]))
          || !reflectApply(regexpTest, DIGEST_PATTERN, [fields[14]])
          || !reflectApply(regexpTest, DIGEST_PATTERN, [fields[17]])
          || !reflectApply(regexpTest, DIGEST_PATTERN, [fields[18]])
          || !reflectApply(regexpTest, DIGEST_PATTERN, [fields[21]])
          || !reflectApply(regexpTest, DIGEST_PATTERN, [fields[22]])
          || !reflectApply(regexpTest, DIGEST_PATTERN, [fields[25]])) {
        throw safetyError();
      }
      if (state.custodyEnvelope === null) throw safetyError();
      for (let index = 2; index < CUSTODY_ENVELOPE_END; index += 1) {
        if (custody[index] !== state.custodyEnvelope[index - 2]) {
          throw safetyError();
        }
      }
      const journalSequence = assertInteger(SafeNumber(fields[7]), 1, 1000);
      const records = parseJournal(
        state.journalFd,
        state.contract.contract_digest,
        journalSequence,
        fields[8],
      );
      result = buildResult(state, fields, records);
    }
  } catch {
    failure = safetyError("darwin_safety_journal_readback_rejected");
  } finally {
    if (state.journalFd >= 0) {
      fsCloseSync(state.journalFd);
      state.journalFd = -1;
    }
    state.planState.destroyed = true;
    state.planState.controller = null;
  }
  rejectPendingHeartbeat(
    state,
    failure || safetyError("darwin_safety_heartbeat_terminal_before_acceptance"),
  );
  if (failure) {
    settleDeferred(state.readyDeferred, false, failure);
    if (state.controllerDelivered) {
      settleDeferred(state.terminalDeferred, false, failure);
    } else {
      // No caller can have obtained the terminal promise when startup fails.
      // Resolve that private promise so a rejected launch cannot also surface
      // as an unrelated unhandled rejection.
      settleDeferred(state.terminalDeferred, true, null);
    }
  } else {
    settleDeferred(state.terminalDeferred, true, result);
  }
}

function consumeCustodyLine(state, line) {
  const fields = splitTabs(line);
  if (state.custodyFields || fields.length !== 28 || fields[0] !== "CUSTODY1"
      || fields[1] !== "1" || fields[2] !== state.contract.contract_digest
      || !verifySignedFields(fields, state.custodyEvidenceKey)) {
    state.errorCode = "darwin_safety_custody_evidence_rejected";
    requestNativeCleanup(state, state.errorCode);
    return;
  }
  state.custodyFields = fields;
  state.ready = false;
  if (!state.nativeReadyReceived) {
    // Signed fixture custody evidence can reject a launch, but can never make
    // it successful. Closing control immediately also starts the outer kill
    // bound while a watcher is blocked before READY.
    requestNativeCleanup(
      state,
      "darwin_safety_custody_pre_ready_terminal",
    );
  } else {
    // Custody terminal evidence means no further command can be admitted. A
    // watcher that stalls after native cleanup is bounded without converting
    // otherwise valid native evidence into a synthetic failure.
    requestNativeCleanup(state);
  }
}

function consumeOutputLine(state, line) {
  const receivedAtHost = reflectApply(processHrtimeBigint, hostProcess.hrtime, []);
  const fields = splitTabs(line);
  if (fields[0] === "READY1") {
    let nativeMonotonic;
    let watchdogPid;
    try {
      nativeMonotonic = SafeBigInt(fields[2]);
      watchdogPid = assertInteger(SafeNumber(fields[4]), 2, 2147483647);
    } catch {
      nativeMonotonic = 0n;
      watchdogPid = -1;
    }
    const acceptanceFields = [];
    for (let index = 5; index < fields.length; index += 1) {
      acceptanceFields[acceptanceFields.length] = fields[index];
    }
    const armAcceptance = verifyCustodyAcceptance(
      state,
      acceptanceFields,
      "CUSTODY_ARMED1",
      0,
      acceptanceFields[17],
      acceptanceFields[18],
      watchdogPid,
    );
    let armIssued = 0n;
    let armValidUntil = 0n;
    let armAcceptedAt = 0n;
    try {
      armIssued = SafeBigInt(acceptanceFields[17]);
      armValidUntil = SafeBigInt(acceptanceFields[18]);
      armAcceptedAt = SafeBigInt(acceptanceFields[19]);
    } catch {}
    if (fields.length !== 5 + CUSTODY_ACCEPTANCE_FIELD_COUNT
        || state.nativeReadyReceived || state.cleanupRequested
        || state.errorCode !== null || state.terminalFields !== null
        || state.custodyFields !== null || state.finalized || state.closed
        || nativeMonotonic < 1n
        || watchdogPid === state.contract.worker_pid
        || !reflectApply(regexpTest, /^[a-f0-9]{32}$/u, [fields[1]])
        || !reflectApply(regexpTest, DIGEST_PATTERN, [fields[3]])
        || armAcceptance === null || nativeMonotonic < armAcceptedAt
        || nativeMonotonic > armValidUntil || armValidUntil <= armIssued
        || armValidUntil - armIssued
          > SafeBigInt(state.contract.deadman_ms) * 1000000n) {
      state.errorCode = "darwin_safety_ready_attestation_rejected";
      requestNativeCleanup(state, state.errorCode);
      return;
    }
    state.nativeReadyReceived = true;
    state.challenge = fields[1];
    state.watchdogPid = watchdogPid;
    state.custodianPid = armAcceptance.custodianPid;
    state.custodyEnvelope = armAcceptance.envelope;
    state.custodyArmAcceptanceDigest = acceptanceFields[29];
    state.nativeMonotonicAnchor = nativeMonotonic;
    state.hostMonotonicAnchor = receivedAtHost;
    armUnconfirmedReadyWatchdogBound(state);
    try {
      // READY is phase one only. Sequence one is a private reaffirmation of
      // the already-signed ARM deadline; only its independently signed ACK can
      // make a controller caller-visible.
      beginHeartbeat(state, true, armValidUntil);
    } catch (error) {
      const failure = error?.code ? error : safetyError();
      settleDeferred(state.readyDeferred, false, failure);
      requestNativeCleanup(state, failure.code);
    }
    return;
  }
  if (fields[0] === "ACK1") {
    const pending = state.pendingHeartbeat;
    const acceptanceFields = [];
    for (let index = 3; index < fields.length; index += 1) {
      acceptanceFields[acceptanceFields.length] = fields[index];
    }
    const acceptance = pending === null ? null : verifyCustodyAcceptance(
      state,
      acceptanceFields,
      "CUSTODY_EXTENDED1",
      pending.sequence,
      pending.issued,
      pending.validUntil,
      state.watchdogPid,
    );
    if (fields.length !== 3 + CUSTODY_ACCEPTANCE_FIELD_COUNT
        || pending === null || acceptance === null
        || fields[1] !== reflectApply(SafeString, undefined, [pending.sequence])
        || fields[2] !== pending.validUntil
        || acceptance.custodianPid !== state.custodianPid) {
      const failure = safetyError("darwin_safety_custody_ack_rejected");
      state.ready = false;
      state.errorCode = failure.code;
      rejectPendingHeartbeat(state, failure);
      requestNativeCleanup(state, state.errorCode);
      return;
    }
    if (state.cleanupRequested || state.errorCode !== null
        || state.terminalFields !== null || state.custodyFields !== null
        || state.finalized || state.closed
        || (pending.readyConfirmation
          ? (!state.nativeReadyReceived || state.ready)
          : (!state.ready || !state.controllerDelivered))) {
      const failure = safetyError("darwin_safety_custody_ack_state_expired");
      state.ready = false;
      rejectPendingHeartbeat(state, failure);
      requestNativeCleanup(state);
      return;
    }
    let validUntil;
    const roundTrip = receivedAtHost - pending.sentAtHost;
    try {
      validUntil = SafeBigInt(pending.validUntil);
    } catch {
      validUntil = 0n;
    }
    const nativeUpper = acceptance.acceptedAt + roundTrip;
    if (roundTrip < 0n || validUntil < 1n || nativeUpper >= validUntil) {
      const failure = safetyError("darwin_safety_custody_ack_delivery_expired");
      state.ready = false;
      rejectPendingHeartbeat(state, failure);
      // A delayed JavaScript delivery cannot revive custody. Preserve any
      // independently valid native terminal evidence instead of turning the
      // delivery lapse into a synthetic native failure.
      requestNativeCleanup(state);
      return;
    }
    state.nativeMonotonicAnchor = acceptance.acceptedAt;
    state.hostMonotonicAnchor = receivedAtHost;
    state.nativeMonotonicUpperAnchor = nativeUpper;
    state.hostMonotonicUpperAnchor = receivedAtHost;
    if (!armAutonomousWatchdogBound(state, validUntil)) {
      const failure = safetyError("darwin_safety_custody_ack_delivery_expired");
      state.ready = false;
      rejectPendingHeartbeat(state, failure);
      requestNativeCleanup(state);
      return;
    }
    state.activeCustodyDeadline = validUntil;
    state.pendingHeartbeat = null;
    if (pending.readyConfirmation) {
      state.ready = true;
      settleDeferred(pending.deferred, true, true);
    } else {
      settleDeferred(pending.deferred, true, objectFreeze({
        sequence: pending.sequence,
        accepted: true,
        custody_deadline_monotonic_ns: pending.validUntil,
        custody_acceptance_digest: acceptanceFields[29],
      }));
    }
    return;
  }
  if (fields[0] === "TERM1") {
    if (state.terminalFields) {
      state.errorCode = "darwin_safety_duplicate_terminal_rejected";
      requestNativeCleanup(state, state.errorCode);
      return;
    }
    state.ready = false;
    state.terminalFields = fields;
    return;
  }
  if (fields[0] === "ERROR1" && fields.length === 2) {
    state.ready = false;
    state.errorCode = `darwin_safety_native_${fields[1]}`;
    return;
  }
  state.errorCode = "darwin_safety_native_output_rejected";
  requestNativeCleanup(state, state.errorCode);
}

function attachChild(state) {
  // Use Readable's captured `on`, not EventEmitter's base implementation:
  // Readable.on("data") also enters flowing mode so READY1 is observed before
  // the independently enforced native deadline expires.
  reflectApply(readableOn, state.child.stdout, ["data", (chunk) => {
    if (state.finalized) return;
    state.output += reflectApply(bufferToString, chunk, ["utf8"]);
    if (state.output.length > 16384) {
      state.errorCode = "darwin_safety_native_output_rejected";
      state.output = "";
      try { reflectApply(readableDestroy, state.child.stdout, []); } catch {}
      requestNativeCleanup(state, state.errorCode);
      return;
    }
    let newline;
    while ((newline = reflectApply(stringIndexOf, state.output, ["\n"])) >= 0) {
      const line = reflectApply(stringSlice, state.output, [0, newline]);
      state.output = reflectApply(stringSlice, state.output, [newline + 1]);
      consumeOutputLine(state, line);
    }
  }]);
  reflectApply(readableOn, state.custodyStream, ["data", (chunk) => {
    if (state.finalized) return;
    state.custodyOutput += reflectApply(bufferToString, chunk, ["utf8"]);
    if (state.custodyOutput.length > 4096) {
      state.errorCode = "darwin_safety_custody_evidence_rejected";
      state.custodyOutput = "";
      try { reflectApply(readableDestroy, state.custodyStream, []); } catch {}
      requestNativeCleanup(state, state.errorCode);
      return;
    }
    let newline;
    while ((newline = reflectApply(stringIndexOf, state.custodyOutput, ["\n"])) >= 0) {
      const line = reflectApply(stringSlice, state.custodyOutput, [0, newline]);
      state.custodyOutput = reflectApply(
        stringSlice,
        state.custodyOutput,
        [newline + 1],
      );
      consumeCustodyLine(state, line);
    }
  }]);
  reflectApply(eventOnce, state.child, ["error", () => {
    state.errorCode = "darwin_safety_watchdog_spawn_rejected";
  }]);
  const rejectStream = () => {
    if (state.finalized) return;
    requestNativeCleanup(state, "darwin_safety_private_stream_rejected");
  };
  reflectApply(eventOnce, state.child.stdout, ["error", rejectStream]);
  reflectApply(eventOnce, state.custodyStream, ["error", rejectStream]);
  reflectApply(eventOnce, state.control, ["error", rejectStream]);
  reflectApply(eventOnce, state.keyPipe, ["error", rejectStream]);
  // ChildProcess `exit` can precede the final stdout data event. `close` is the
  // terminal boundary after the stdio streams close, so TERM1 cannot be lost
  // merely because the process exited immediately after writing it.
  reflectApply(eventOnce, state.child, ["close", (code) => {
    finalizeChild(state, code);
  }]);
}

async function launchFixture(planInput, input) {
  const plan = assertPlan(planInput);
  const planState = reflectApply(weakMapGet, PLAN_STATE, [plan]);
  assertExactObject(input, ["journal_path", "version"]);
  if (input.version !== VERSION || !plan.fixture_only || !fixtureEnvironmentGate
      || planState.consumed || planState.destroyed) throw safetyError();
  planState.consumed = true;
  assertHostRuntimeUntampered();
  let journalFd = -1;
  let key;
  let child;
  let state;
  try {
    const executable = measureExecutable();
    journalFd = openJournalCapability(input.journal_path);
    key = reflectApply(cryptoRandomBytes, crypto, [32]);
    const spawnArguments = ownCapturedArrayIterator(["--watchdog-fixture"]);
    const childStdio = ownCapturedArrayIterator([
      "ignore", "pipe", "ignore", "pipe", journalFd, "pipe", "pipe",
    ]);
    child = reflectApply(childSpawn, childProcess, [
      executable.path,
      spawnArguments,
      {
        detached: true,
        env: objectCreate(null),
        stdio: childStdio,
        windowsHide: true,
      },
    ]);
    if (!child || !child.stdout || !child.stdio?.[3] || !child.stdio?.[5]
        || !child.stdio?.[6]) {
      throw safetyError("darwin_safety_watchdog_spawn_rejected");
    }
    const readyDeferred = makeDeferred();
    const terminalDeferred = makeDeferred();
    const contract = {
      ...planState.contract,
      contract_digest: plan.contract_digest,
    };
    const custodyEvidenceKey = deriveCustodyEvidenceKey(
      key,
      contract.contract_digest,
    );
    state = {
      plan,
      planState,
      contract,
      executable,
      journalFd,
      key,
      child,
      control: child.stdio[3],
      keyPipe: child.stdio[5],
      custodyStream: child.stdio[6],
      custodyEvidenceKey,
      readyDeferred,
      terminalDeferred,
      ready: false,
      nativeReadyReceived: false,
      challenge: null,
      watchdogPid: null,
      custodianPid: null,
      custodyEnvelope: null,
      custodyArmAcceptanceDigest: null,
      nativeMonotonicAnchor: null,
      hostMonotonicAnchor: null,
      nativeMonotonicUpperAnchor: null,
      hostMonotonicUpperAnchor: null,
      activeCustodyDeadline: null,
      sequence: 0,
      pendingHeartbeat: null,
      stopSent: false,
      output: "",
      custodyOutput: "",
      terminalFields: null,
      custodyFields: null,
      errorCode: null,
      closed: false,
      finalized: false,
      controllerDelivered: false,
      pendingPrivateWrites: 0,
      cleanupRequested: false,
      forceKillTimer: null,
      forceKillDeadline: null,
    };
    // From this point the child lifecycle owns the parent copy of the journal
    // capability. The outer failure path must not close a descriptor that an
    // asynchronous exit finalizer may already have closed.
    journalFd = -1;
    attachChild(state);
    const capability = keyCapability(key);
    let capabilityReleased = false;
    const releaseCapability = () => {
      if (capabilityReleased) return;
      capabilityReleased = true;
      reflectApply(bufferFill, capability, [0]);
    };
    try {
      // Writable.end's completion callback is the ownership boundary for the
      // one-shot private key capability. The agent-facing controller never
      // receives this buffer or the underlying FD.
      reflectApply(writableEnd, state.keyPipe, [capability, releaseCapability]);
    } catch {
      releaseCapability();
      throw safetyError();
    }
    const configFields = [
      "CFG1",
      "1",
      contract.contract_digest,
      executable.digest,
      contract.instrument_ref_digest,
      contract.lease_id_digest,
      contract.fencing_token_digest,
      reflectApply(SafeString, undefined, [contract.fencing_generation]),
      reflectApply(SafeString, undefined, [contract.worker_pid]),
      contract.worker_identity_digest,
      contract.cleanup_capability_digest,
      contract.restore_digest,
      contract.semantic_cleanup_digest,
      contract.cleanup_provider_manifest_digest,
      contract.journal_id_digest,
      contract.semantic_profile,
      reflectApply(SafeString, undefined, [contract.deadman_ms]),
      reflectApply(SafeString, undefined, [contract.deadman_ms]),
      reflectApply(SafeString, undefined, [contract.cleanup_timeout_ms]),
      contract.fixture_cleanup_behavior,
    ];
    writePrivate(state, signedLine(configFields, state.key));
    const timeout = setTimeoutCaptured(() => {
      if (!state.ready) {
        requestNativeCleanup(state, "darwin_safety_watchdog_ready_timeout");
      }
    }, WATCHDOG_READY_TIMEOUT_MS);
    try {
      await readyDeferred.promise;
    } finally {
      clearTimeoutCaptured(timeout);
    }
    if (!state.ready || state.pendingHeartbeat !== null
        || state.cleanupRequested || state.errorCode !== null
        || state.terminalFields !== null || state.custodyFields !== null
        || state.finalized || state.closed) {
      throw safetyError("darwin_safety_ready_state_expired");
    }
    requireLiveCustody(state);
    const controller = objectFreeze({
      version: VERSION,
      kind: "darwin_safety_deadman_fixture_controller",
      contract_digest: contract.contract_digest,
      fixture_only: true,
      production_ready: false,
      capability_id: `darwin-safety-controller:${reflectApply(
        bufferToString,
        reflectApply(cryptoRandomBytes, crypto, [18]),
        ["base64url"],
      )}`,
      heartbeat: () => {
        if (state.closed || state.stopSent || !state.ready
            || state.pendingHeartbeat !== null || state.cleanupRequested
            || state.errorCode !== null || state.terminalFields !== null
            || state.custodyFields !== null || state.finalized
            || !state.controllerDelivered) throw safetyError();
        return beginHeartbeat(state, false);
      },
      stop: (reason = "operator_stop") => {
        if (state.closed || state.stopSent || !state.ready
            || state.pendingHeartbeat !== null || state.cleanupRequested
            || state.errorCode !== null || state.terminalFields !== null
            || state.custodyFields !== null || state.finalized
            || !state.controllerDelivered
            || !containsExact(STOP_REASONS, reason)) {
          throw safetyError();
        }
        requireLiveCustody(state);
        state.ready = false;
        state.stopSent = true;
        state.sequence += 1;
        const issued = watchdogMonotonicNow(state);
        const valid = issued + SafeBigInt(contract.deadman_ms) * 1000000n;
        const fields = [
          "STOP1", "1", reflectApply(SafeString, undefined, [state.sequence]), reason,
          reflectApply(SafeString, undefined, [issued]),
          reflectApply(SafeString, undefined, [valid]),
        ];
        const bindings = buildProtocolBindings(contract, state.challenge);
        for (let index = 0; index < bindings.length; index += 1) {
          fields[fields.length] = bindings[index];
        }
        const bytes = signedLine(fields, state.key);
        try {
          requireLiveCustody(state);
        } catch (error) {
          reflectApply(bufferFill, bytes, [0]);
          throw error;
        }
        writePrivate(state, bytes);
        armCleanupWatchdogBound(state);
        return terminalDeferred.promise;
      },
      closeControlForFixture: () => {
        if (state.closed || state.stopSent || !state.ready
            || state.pendingHeartbeat !== null || state.cleanupRequested
            || state.errorCode !== null || state.terminalFields !== null
            || state.custodyFields !== null || state.finalized
            || !state.controllerDelivered) {
          throw safetyError();
        }
        requireLiveCustody(state);
        state.ready = false;
        state.stopSent = true;
        requestNativeCleanup(state);
        return terminalDeferred.promise;
      },
      waitForTerminal: () => terminalDeferred.promise,
      toJSON: rejectSerialization,
    });
    if (!state.ready || state.pendingHeartbeat !== null
        || state.cleanupRequested || state.errorCode !== null
        || state.terminalFields !== null || state.custodyFields !== null
        || state.finalized || state.closed) {
      throw safetyError("darwin_safety_ready_state_expired");
    }
    requireLiveCustody(state);
    reflectApply(weakSetAdd, CONTROLLERS, [controller]);
    reflectApply(weakMapSet, CONTROLLER_STATE, [controller, state]);
    planState.controller = controller;
    state.controllerDelivered = true;
    journalFd = -1;
    key = null;
    child = null;
    return controller;
  } catch (error) {
    planState.destroyed = true;
    if (state) {
      const code = error?.code || "darwin_safety_launch_rejected";
      const preserveNativeTerminal =
        code === "darwin_safety_custody_ack_delivery_expired"
        || code === "darwin_safety_custody_deadline_expired"
        || state.terminalFields !== null || state.custodyFields !== null;
      requestNativeCleanup(state, preserveNativeTerminal ? null : code);
    } else if (child) {
      try { reflectApply(childKill, child, ["SIGKILL"]); } catch {}
    }
    if (key) reflectApply(bufferFill, key, [0]);
    if (journalFd >= 0) fsCloseSync(journalFd);
    throw error?.code ? error : safetyError();
  }
}

function launchDarwinSafetyDeadman(planInput, input) {
  const plan = assertPlan(planInput);
  const state = reflectApply(weakMapGet, PLAN_STATE, [plan]);
  if (state.consumed || state.destroyed) throw safetyError();
  state.consumed = true;
  state.destroyed = true;
  void input;
  throw safetyError(REAL_BLOCKER);
}

function readDarwinSafetyDeadmanJournal(resultInput) {
  const state = resultInput == null
    ? null
    : reflectApply(weakMapGet, RESULT_STATE, [resultInput]);
  if (!resultInput || !reflectApply(weakSetHas, RESULTS, [resultInput]) || !state
      || !objectIsFrozen(resultInput)
      || resultInput.kind !== "darwin_safety_deadman_terminal_result") {
    throw safetyError();
  }
  return state.records;
}

module.exports = objectFreeze({
  DARWIN_SAFETY_DEADMAN_ASSURANCE,
  DARWIN_SAFETY_DEADMAN_REAL_BLOCKER: REAL_BLOCKER,
  DARWIN_SAFETY_DEADMAN_VERSION: VERSION,
  createDarwinSafetyDeadmanFixturePlan,
  createDarwinSafetyDeadmanPlan,
  deriveDarwinSafetyDeadmanContractDigest,
  deriveDarwinSafetySemanticCleanupDigest,
  launchDarwinSafetyDeadman,
  launchDarwinSafetyDeadmanFixture: launchFixture,
  readDarwinSafetyDeadmanJournal,
});
