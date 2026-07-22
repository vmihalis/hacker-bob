"use strict";

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const SafeError = Error;
const SafeDate = Date;
const arrayIsArray = Array.isArray;
const arrayJoin = Array.prototype.join;
const arrayPush = Array.prototype.push;
const bufferByteLength = Buffer.byteLength;
const cryptoCreateHash = crypto.createHash;
const dateParse = Date.parse;
const dateToISOString = Date.prototype.toISOString;
const numberIsFinite = Number.isFinite;
const numberIsSafeInteger = Number.isSafeInteger;
const numberToString = Number.prototype.toString;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectKeys = Object.keys;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const regExpTest = RegExp.prototype.test;
const stringCharCodeAt = String.prototype.charCodeAt;
const stringPadStart = String.prototype.padStart;
const utilTypesIsProxy = utilTypes.isProxy;
const weakSetAdd = WeakSet.prototype.add;
const weakSetHas = WeakSet.prototype.has;

const ARRAY_PROTOTYPE = Array.prototype;
const OBJECT_PROTOTYPE = Object.prototype;
const HASH_PROTOTYPE = objectGetPrototypeOf(cryptoCreateHash("sha256"));
const HASH_UPDATE = objectGetOwnPropertyDescriptor(HASH_PROTOTYPE, "update").value;
const HASH_DIGEST = objectGetOwnPropertyDescriptor(HASH_PROTOTYPE, "digest").value;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/u;
const PRINCIPAL_PATTERN = /^principal:[a-z][a-z0-9._-]{0,117}$/u;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const MAX_ARRAY_ITEMS = 128;
const MAX_TEXT_BYTES = 512;
const POLICY_DOMAIN = "hacker-bob/darwin-principal-acl-policy/v1";
const OBSERVATION_DOMAIN = "hacker-bob/darwin-principal-acl-observation/v1";
const PLAN_DOMAIN = "hacker-bob/darwin-principal-acl-provisioning-plan/v1";
const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

const ROLE_IDS = objectFreeze([
  "operator_control",
  "grant_issuer",
  "active_device_worker",
  "safety_supervisor",
  "cleanup_worker",
  "privileged_launcher",
]);
const DESCRIPTOR_DELEGATE_ROLE_IDS = objectFreeze([
  "active_device_worker",
  "cleanup_worker",
]);
const DELEGATION_PROFILE_MATRIX = objectFreeze([
  objectFreeze([
    "active_device_session", "active_device_worker", "active",
    "exclusive_delegated_descriptor", false,
  ]),
  objectFreeze([
    "cleanup_recovery_session", "cleanup_worker", "cleanup",
    "precommitted_cleanup_descriptor", true,
  ]),
]);
const EDGE_MATRIX = objectFreeze([
  objectFreeze(["operator_control", "grant_issuer", "control", "grant_request"]),
  objectFreeze(["grant_issuer", "privileged_launcher", "authority", "launch_ticket"]),
  objectFreeze(["privileged_launcher", "active_device_worker", "launch", "worker_launch"]),
  objectFreeze(["privileged_launcher", "safety_supervisor", "launch", "safety_launch"]),
  objectFreeze(["privileged_launcher", "cleanup_worker", "launch", "cleanup_launch"]),
  objectFreeze(["active_device_worker", "safety_supervisor", "safety", "heartbeat"]),
  objectFreeze(["safety_supervisor", "active_device_worker", "safety", "stop_authority"]),
  objectFreeze(["safety_supervisor", "cleanup_worker", "recovery", "cleanup_authority"]),
  objectFreeze(["cleanup_worker", "safety_supervisor", "recovery", "cleanup_receipt"]),
]);
const READINESS_BLOCKERS = objectFreeze([
  "caller_supplied_observation_is_diagnostic_only",
  "native_principal_acl_attestation_not_authorizing",
  "signed_immutable_native_apply_prebuild_missing",
  "operator_approved_native_apply_missing",
  "principal_device_acl_hil_missing",
]);

const ROLE_FIELDS = objectFreeze([
  "role_id", "principal_id", "uid", "primary_gid", "supplementary_gids",
  "non_root", "service_account", "login_policy", "interactive_login_allowed",
  "expected_launcher_role_id", "executable_digest", "bundle_digest",
  "prebuild_digest", "launch_attestation_digest", "root_authorization_digest",
]);
const EDGE_FIELDS = objectFreeze([
  "from_role_id", "to_role_id", "channel", "purpose",
  "mutual_authentication_required",
]);
const ACL_ENTRY_FIELDS = objectFreeze([
  "order", "role_id", "effect", "permissions", "inheritance",
]);
const OS_EXPECTATION_FIELDS = objectFreeze([
  "platform", "os_version_digest", "os_build_digest", "boot_epoch_digest",
  "security_epoch",
]);
const OBSERVER_EXPECTATION_FIELDS = objectFreeze([
  "implementation_digest", "prebuild_digest", "bundle_digest",
  "launch_attestation_digest", "code_signature_requirement_digest",
  "observation_signing_identity_digest",
]);
const DELEGATION_PROFILE_FIELDS = objectFreeze([
  "order", "profile_id", "delegate_role_id", "phase", "delivery_mechanism",
  "permissions", "descriptor_policy_digest", "capability_binding_digest",
  "exclusive_across_profiles", "precommitted", "closed_when_inactive",
  "revocation_required",
]);
const RESOURCE_POLICY_FIELDS = objectFreeze([
  "resource_id", "provider_id", "resource_class", "device_identity_digest",
  "ioregistry_identity_digest", "device_path_digest", "device_file_id_digest",
  "device_major_minor_digest", "openat_directory_identity_digest",
  "owner_uid", "owner_gid", "mode", "filesystem_open_role_id",
  "direct_service_account_acl_allowed", "acl_inheritance", "deny_unlisted",
  "everyone_access_allowed", "broad_group_access_allowed", "acl_entries",
  "launcher_authorization_mode", "launcher_entitlement_state",
  "launcher_io_service_authorize_state", "launcher_authorization_scope_digest",
  "delegation_policy_digest", "descriptor_inventory_policy_digest",
  "delegation_profiles",
]);
const POLICY_INPUT_FIELDS = objectFreeze([
  "version", "policy_id", "policy_epoch", "issued_at", "expires_at",
  "max_observation_age_seconds", "os_expectation", "observer_expectation",
  "roles", "edges", "resources",
]);
const ACCOUNT_FIELDS = objectFreeze([
  "role_id", "principal_id", "account_record_digest", "account_name_digest",
  "uid", "primary_gid", "supplementary_gids", "service_account",
  "login_policy", "interactive_login_allowed", "record_source",
]);
const GROUP_FIELDS = objectFreeze([
  "role_id", "principal_id", "primary_group_record_digest",
  "supplementary_group_records_digest", "primary_gid", "supplementary_gids",
  "membership_complete", "no_unlisted_memberships", "record_epoch",
]);
const CREDENTIAL_FIELDS = objectFreeze([
  "role_id", "principal_id", "real_uid", "effective_uid", "saved_uid",
  "real_gid", "effective_gid", "saved_gid", "supplementary_gids",
  "audit_token_digest", "process_start_digest", "executable_digest",
  "bundle_digest", "prebuild_digest", "launch_attestation_digest",
  "root_claimed", "root_authorization_digest", "root_authorization_qualified",
]);
const RESOURCE_OBSERVATION_FIELDS = objectFreeze([
  "resource_id", "provider_id", "resource_class", "device_identity_digest",
  "ioregistry_identity_digest", "device_path_digest", "device_file_id_digest",
  "device_major_minor_digest", "device_type", "open_method",
  "openat_directory_identity_digest", "filesystem_open_role_id", "no_symlink",
  "hardlink_count", "owner_uid", "owner_gid", "mode", "acl_entries",
  "direct_service_account_acl_present", "acl_inherited", "acl_widened",
  "delegation_policy_digest", "mutual_exclusion_enforced",
  "safety_raw_transport_present", "descriptor_inventory_complete",
  "descriptor_inventory_digest", "descriptor_inventory_before_digest",
  "descriptor_inventory_after_digest", "descriptor_custody_state",
  "launcher_descriptor_present", "active_descriptor_present",
  "cleanup_descriptor_present", "unlisted_descriptor_count",
  "inherited_descriptor_count", "launcher_redundant_descriptor_closed",
  "stat_before_digest", "stat_after_digest",
  "ioregistry_before_digest", "ioregistry_after_digest", "stable",
]);
const ANCESTRY_FIELDS = objectFreeze([
  "role_id", "principal_id", "direct_parent_role_id",
  "direct_parent_principal_id", "ancestry_digest", "stable",
]);
const AUTHORIZATION_FIELDS = objectFreeze([
  "resource_id", "role_id", "principal_id", "authorization_mode",
  "entitlement_state", "entitlement_digest", "io_service_authorize_state",
  "io_service_authorize_digest", "authorization_scope_digest",
  "root_authorization_digest", "root_claimed", "root_authorization_qualified",
]);
const DELEGATION_EVIDENCE_FIELDS = objectFreeze([
  "resource_id", "profile_id", "delegate_role_id", "delegate_principal_id",
  "delivery_mechanism", "descriptor_policy_digest", "capability_binding_digest",
  "mutual_exclusion_qualified", "precommitted", "closed_at_observation",
  "raw_path_access_present",
]);
const OS_FIELDS = objectFreeze([
  "platform", "os_version_digest", "os_build_digest", "boot_epoch_digest",
  "security_epoch",
]);
const NATIVE_EVIDENCE_FIELDS = objectFreeze([
  "observer_implementation_digest", "observer_prebuild_digest",
  "observer_bundle_digest", "observer_launch_attestation_digest",
  "observer_code_signature_requirement_digest",
  "observation_signing_identity_digest",
  "observation_signature_digest", "before_snapshot_digest",
  "after_snapshot_digest", "stable", "read_only", "native_attested",
  "observation_signature_verified", "prebuild_qualified",
  "launch_attestation_qualified", "hil_qualified",
]);
const OBSERVATION_INPUT_FIELDS = objectFreeze([
  "version", "observation_id", "policy_id", "policy_digest", "policy_epoch",
  "observed_at", "expires_at", "os", "accounts", "groups", "credentials",
  "resources", "ancestry", "authorizations", "delegations", "native_evidence",
]);
const DOCTOR_INPUT_FIELDS = objectFreeze(["policy", "observation", "now"]);
const PLAN_INPUT_FIELDS = objectFreeze(["policy", "observation"]);

const POLICIES = new WeakSet();
const OBSERVATIONS = new WeakSet();

function contractError() {
  const error = new SafeError("Darwin principal and device ACL contract was rejected");
  objectDefineProperty(error, "code", {
    value: "darwin_principal_acl_rejected",
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return error;
}

function reject() {
  throw contractError();
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || arrayIsArray(value)
      || utilTypesIsProxy(value)) return false;
  const prototype = objectGetPrototypeOf(value);
  if (prototype !== OBJECT_PROTOTYPE && prototype !== null) return false;
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
  if (!isPlainDataObject(value)) reject();
  const keys = reflectOwnKeys(value);
  if (keys.length !== fields.length) reject();
  for (let index = 0; index < fields.length; index += 1) {
    if (!objectHasOwn(value, fields[index])) reject();
  }
  return value;
}

function own(value, field) {
  const descriptor = objectGetOwnPropertyDescriptor(value, field);
  if (descriptor == null || !objectHasOwn(descriptor, "value")
      || descriptor.enumerable !== true) reject();
  return descriptor.value;
}

function assertDenseArray(value, minimum = 0, maximum = MAX_ARRAY_ITEMS) {
  if (!arrayIsArray(value) || utilTypesIsProxy(value)
      || objectGetPrototypeOf(value) !== ARRAY_PROTOTYPE
      || !numberIsSafeInteger(value.length)
      || value.length < minimum || value.length > maximum) reject();
  const keys = reflectOwnKeys(value);
  if (keys.length !== value.length + 1 || keys[keys.length - 1] !== "length") reject();
  for (let index = 0; index < value.length; index += 1) {
    if (keys[index] !== `${index}`) reject();
    const descriptor = objectGetOwnPropertyDescriptor(value, `${index}`);
    if (descriptor == null || !objectHasOwn(descriptor, "value")
        || descriptor.enumerable !== true) reject();
  }
  return value;
}

function assertString(value, pattern = null, maximumBytes = MAX_TEXT_BYTES) {
  if (typeof value !== "string" || value.length === 0
      || bufferByteLength(value, "utf8") > maximumBytes
      || (pattern != null && !reflectApply(regExpTest, pattern, [value]))) reject();
  return value;
}

function assertIdentifier(value) {
  return assertString(value, IDENTIFIER_PATTERN, 128);
}

function assertToken(value) {
  return assertString(value, TOKEN_PATTERN, 191);
}

function assertPrincipal(value) {
  return assertString(value, PRINCIPAL_PATTERN, 128);
}

function assertDigest(value) {
  return assertString(value, DIGEST_PATTERN, 64);
}

function assertBoolean(value) {
  if (value !== true && value !== false) reject();
  return value;
}

function assertInteger(value, minimum = 0, maximum = MAX_SAFE_INTEGER) {
  if (!numberIsSafeInteger(value) || value < minimum || value > maximum) reject();
  return value;
}

function assertNullableIdentifier(value) {
  return value === null ? null : assertIdentifier(value);
}

function assertNullablePrincipal(value) {
  return value === null ? null : assertPrincipal(value);
}

function assertNullableDigest(value) {
  return value === null ? null : assertDigest(value);
}

function assertTimestamp(value) {
  if (typeof value !== "string") reject();
  const milliseconds = reflectApply(dateParse, SafeDate, [value]);
  if (!numberIsFinite(milliseconds)
      || reflectApply(dateToISOString, new SafeDate(milliseconds), []) !== value) reject();
  return value;
}

function timestampMilliseconds(value) {
  assertTimestamp(value);
  return reflectApply(dateParse, SafeDate, [value]);
}

function makeRecord(fields, source) {
  const output = objectCreate(null);
  for (let index = 0; index < fields.length; index += 1) {
    objectDefineProperty(output, fields[index], {
      value: source[fields[index]],
      enumerable: true,
      writable: false,
      configurable: false,
    });
  }
  return objectFreeze(output);
}

function makeArray(values) {
  return objectFreeze(values);
}

function canonicalString(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!numberIsSafeInteger(value)) reject();
    return `${value}`;
  }
  if (typeof value === "string") {
    let escaped = '"';
    for (let index = 0; index < value.length; index += 1) {
      const code = reflectApply(stringCharCodeAt, value, [index]);
      if (code === 0x22) escaped += '\\"';
      else if (code === 0x5c) escaped += "\\\\";
      else if (code === 0x08) escaped += "\\b";
      else if (code === 0x0c) escaped += "\\f";
      else if (code === 0x0a) escaped += "\\n";
      else if (code === 0x0d) escaped += "\\r";
      else if (code === 0x09) escaped += "\\t";
      else if (code < 0x20 || code === 0x2028 || code === 0x2029
          || (code >= 0xd800 && code <= 0xdfff)) {
        const hexadecimal = reflectApply(numberToString, code, [16]);
        escaped += `\\u${reflectApply(stringPadStart, hexadecimal, [4, "0"])}`;
      } else escaped += value[index];
    }
    return `${escaped}"`;
  }
  if (arrayIsArray(value)) {
    const parts = [];
    for (let index = 0; index < value.length; index += 1) {
      reflectApply(arrayPush, parts, [canonicalString(value[index])]);
    }
    return `[${reflectApply(arrayJoin, parts, [","])}]`;
  }
  const keys = objectKeys(value);
  const parts = [];
  for (let index = 0; index < keys.length; index += 1) {
    reflectApply(arrayPush, parts, [
      `${canonicalString(keys[index])}:${canonicalString(value[keys[index]])}`,
    ]);
  }
  return `{${reflectApply(arrayJoin, parts, [","])}}`;
}

function hashValue(domain, value) {
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(HASH_UPDATE, hash, [`${domain}\n${canonicalString(value)}`]);
  return reflectApply(HASH_DIGEST, hash, ["hex"]);
}

function normalizeIntegerArray(input, minimumLength = 0) {
  assertDenseArray(input, minimumLength, 16);
  const values = [];
  let previous = -1;
  for (let index = 0; index < input.length; index += 1) {
    const value = assertInteger(input[index], 0, 0xffff_ffff);
    if (value <= previous) reject();
    previous = value;
    reflectApply(arrayPush, values, [value]);
  }
  return makeArray(values);
}

function normalizePermissions(input, policyMode) {
  assertDenseArray(input, 1, 5);
  const allowed = ["read", "write", "execute", "delete", "administer"];
  const values = [];
  for (let index = 0; index < input.length; index += 1) {
    const value = assertIdentifier(input[index]);
    if (value !== allowed[index]) {
      let recognized = false;
      for (let allowedIndex = 0; allowedIndex < allowed.length; allowedIndex += 1) {
        if (allowed[allowedIndex] === value) recognized = true;
      }
      if (!recognized) reject();
    }
    for (let prior = 0; prior < values.length; prior += 1) {
      if (values[prior] === value) reject();
    }
    reflectApply(arrayPush, values, [value]);
  }
  if (policyMode && (values.length !== 2 || values[0] !== "read"
      || values[1] !== "write")) reject();
  return makeArray(values);
}

function normalizeRole(input, expectedRoleId) {
  assertExactObject(input, ROLE_FIELDS);
  const roleId = assertIdentifier(own(input, "role_id"));
  if (roleId !== expectedRoleId) reject();
  const source = {
    role_id: roleId,
    principal_id: assertPrincipal(own(input, "principal_id")),
    uid: assertInteger(own(input, "uid"), 0, 0xffff_ffff),
    primary_gid: assertInteger(own(input, "primary_gid"), 0, 0xffff_ffff),
    supplementary_gids: normalizeIntegerArray(own(input, "supplementary_gids")),
    non_root: assertBoolean(own(input, "non_root")),
    service_account: assertBoolean(own(input, "service_account")),
    login_policy: assertIdentifier(own(input, "login_policy")),
    interactive_login_allowed: assertBoolean(own(input, "interactive_login_allowed")),
    expected_launcher_role_id: assertNullableIdentifier(
      own(input, "expected_launcher_role_id"),
    ),
    executable_digest: assertDigest(own(input, "executable_digest")),
    bundle_digest: assertDigest(own(input, "bundle_digest")),
    prebuild_digest: assertDigest(own(input, "prebuild_digest")),
    launch_attestation_digest: assertDigest(own(input, "launch_attestation_digest")),
    root_authorization_digest: assertNullableDigest(
      own(input, "root_authorization_digest"),
    ),
  };
  if (source.service_account !== true || source.login_policy !== "no_login"
      || source.interactive_login_allowed !== false) reject();
  const launchChild = roleId === "active_device_worker"
    || roleId === "safety_supervisor" || roleId === "cleanup_worker";
  if (roleId === "privileged_launcher") {
    if (source.uid !== 0 || source.primary_gid !== 0 || source.non_root !== false
        || source.supplementary_gids.length !== 0
        || source.expected_launcher_role_id !== null
        || source.root_authorization_digest == null) reject();
  } else if (source.uid === 0 || source.primary_gid === 0 || source.non_root !== true
      || source.expected_launcher_role_id
        !== (launchChild ? "privileged_launcher" : null)
      || source.root_authorization_digest !== null) reject();
  return makeRecord(ROLE_FIELDS, source);
}

function normalizeEdge(input, expected) {
  assertExactObject(input, EDGE_FIELDS);
  const source = {
    from_role_id: assertIdentifier(own(input, "from_role_id")),
    to_role_id: assertIdentifier(own(input, "to_role_id")),
    channel: assertIdentifier(own(input, "channel")),
    purpose: assertIdentifier(own(input, "purpose")),
    mutual_authentication_required: assertBoolean(
      own(input, "mutual_authentication_required"),
    ),
  };
  if (source.from_role_id !== expected[0] || source.to_role_id !== expected[1]
      || source.channel !== expected[2] || source.purpose !== expected[3]
      || source.mutual_authentication_required !== true) reject();
  return makeRecord(EDGE_FIELDS, source);
}

function normalizeAclEntry(input, expectedRoleId = null, policyMode = false) {
  assertExactObject(input, ACL_ENTRY_FIELDS);
  const source = {
    order: assertInteger(own(input, "order"), 0, 127),
    role_id: assertIdentifier(own(input, "role_id")),
    effect: assertIdentifier(own(input, "effect")),
    permissions: normalizePermissions(own(input, "permissions"), policyMode),
    inheritance: assertIdentifier(own(input, "inheritance")),
  };
  if (expectedRoleId != null && source.role_id !== expectedRoleId) reject();
  if (policyMode && (source.effect !== "allow" || source.inheritance !== "none")) reject();
  return makeRecord(ACL_ENTRY_FIELDS, source);
}

function normalizeOsExpectation(input, policyEpoch) {
  assertExactObject(input, OS_EXPECTATION_FIELDS);
  const source = {
    platform: assertIdentifier(own(input, "platform")),
    os_version_digest: assertDigest(own(input, "os_version_digest")),
    os_build_digest: assertDigest(own(input, "os_build_digest")),
    boot_epoch_digest: assertDigest(own(input, "boot_epoch_digest")),
    security_epoch: assertInteger(own(input, "security_epoch"), 1),
  };
  if (source.platform !== "darwin" || source.security_epoch !== policyEpoch) reject();
  return makeRecord(OS_EXPECTATION_FIELDS, source);
}

function normalizeObserverExpectation(input) {
  assertExactObject(input, OBSERVER_EXPECTATION_FIELDS);
  return makeRecord(OBSERVER_EXPECTATION_FIELDS, {
    implementation_digest: assertDigest(own(input, "implementation_digest")),
    prebuild_digest: assertDigest(own(input, "prebuild_digest")),
    bundle_digest: assertDigest(own(input, "bundle_digest")),
    launch_attestation_digest: assertDigest(own(input, "launch_attestation_digest")),
    code_signature_requirement_digest: assertDigest(
      own(input, "code_signature_requirement_digest"),
    ),
    observation_signing_identity_digest: assertDigest(
      own(input, "observation_signing_identity_digest"),
    ),
  });
}

function normalizeDelegationProfile(input, index) {
  assertExactObject(input, DELEGATION_PROFILE_FIELDS);
  const expected = DELEGATION_PROFILE_MATRIX[index];
  const source = {
    order: assertInteger(own(input, "order"), 0, 1),
    profile_id: assertIdentifier(own(input, "profile_id")),
    delegate_role_id: assertIdentifier(own(input, "delegate_role_id")),
    phase: assertIdentifier(own(input, "phase")),
    delivery_mechanism: assertIdentifier(own(input, "delivery_mechanism")),
    permissions: normalizePermissions(own(input, "permissions"), true),
    descriptor_policy_digest: assertDigest(own(input, "descriptor_policy_digest")),
    capability_binding_digest: assertDigest(own(input, "capability_binding_digest")),
    exclusive_across_profiles: assertBoolean(own(input, "exclusive_across_profiles")),
    precommitted: assertBoolean(own(input, "precommitted")),
    closed_when_inactive: assertBoolean(own(input, "closed_when_inactive")),
    revocation_required: assertBoolean(own(input, "revocation_required")),
  };
  if (source.order !== index || source.profile_id !== expected[0]
      || source.delegate_role_id !== expected[1] || source.phase !== expected[2]
      || source.delivery_mechanism !== expected[3]
      || source.precommitted !== expected[4]
      || source.exclusive_across_profiles !== true
      || source.closed_when_inactive !== true
      || source.revocation_required !== true) reject();
  return makeRecord(DELEGATION_PROFILE_FIELDS, source);
}

function normalizeResourcePolicy(input) {
  assertExactObject(input, RESOURCE_POLICY_FIELDS);
  const rawEntries = own(input, "acl_entries");
  assertDenseArray(rawEntries, 0, 0);
  const rawProfiles = own(input, "delegation_profiles");
  assertDenseArray(rawProfiles, DELEGATION_PROFILE_MATRIX.length,
    DELEGATION_PROFILE_MATRIX.length);
  const profiles = [];
  for (let index = 0; index < rawProfiles.length; index += 1) {
    reflectApply(arrayPush, profiles, [normalizeDelegationProfile(rawProfiles[index], index)]);
  }
  const source = {
    resource_id: assertToken(own(input, "resource_id")),
    provider_id: assertIdentifier(own(input, "provider_id")),
    resource_class: assertIdentifier(own(input, "resource_class")),
    device_identity_digest: assertDigest(own(input, "device_identity_digest")),
    ioregistry_identity_digest: assertDigest(own(input, "ioregistry_identity_digest")),
    device_path_digest: assertDigest(own(input, "device_path_digest")),
    device_file_id_digest: assertDigest(own(input, "device_file_id_digest")),
    device_major_minor_digest: assertDigest(own(input, "device_major_minor_digest")),
    openat_directory_identity_digest: assertDigest(
      own(input, "openat_directory_identity_digest"),
    ),
    owner_uid: assertInteger(own(input, "owner_uid"), 0, 0xffff_ffff),
    owner_gid: assertInteger(own(input, "owner_gid"), 0, 0xffff_ffff),
    mode: assertInteger(own(input, "mode"), 0, 0o777),
    filesystem_open_role_id: assertIdentifier(own(input, "filesystem_open_role_id")),
    direct_service_account_acl_allowed: assertBoolean(
      own(input, "direct_service_account_acl_allowed"),
    ),
    acl_inheritance: assertIdentifier(own(input, "acl_inheritance")),
    deny_unlisted: assertBoolean(own(input, "deny_unlisted")),
    everyone_access_allowed: assertBoolean(own(input, "everyone_access_allowed")),
    broad_group_access_allowed: assertBoolean(own(input, "broad_group_access_allowed")),
    acl_entries: makeArray([]),
    launcher_authorization_mode: assertIdentifier(
      own(input, "launcher_authorization_mode"),
    ),
    launcher_entitlement_state: assertIdentifier(
      own(input, "launcher_entitlement_state"),
    ),
    launcher_io_service_authorize_state: assertIdentifier(
      own(input, "launcher_io_service_authorize_state"),
    ),
    launcher_authorization_scope_digest: assertDigest(
      own(input, "launcher_authorization_scope_digest"),
    ),
    delegation_policy_digest: assertDigest(own(input, "delegation_policy_digest")),
    descriptor_inventory_policy_digest: assertDigest(
      own(input, "descriptor_inventory_policy_digest"),
    ),
    delegation_profiles: makeArray(profiles),
  };
  if (source.owner_uid !== 0 || source.owner_gid !== 0 || source.mode !== 0o600
      || source.filesystem_open_role_id !== "privileged_launcher"
      || source.direct_service_account_acl_allowed !== false
      || source.acl_inheritance !== "none" || source.deny_unlisted !== true
      || source.everyone_access_allowed !== false
      || source.broad_group_access_allowed !== false
      || source.launcher_authorization_mode !== "root_device_capture_v1"
      || source.launcher_entitlement_state !== "absent"
      || source.launcher_io_service_authorize_state !== "not_required") reject();
  return makeRecord(RESOURCE_POLICY_FIELDS, source);
}

function createDarwinPrincipalAclPolicy(input) {
  if (arguments.length !== 1) reject();
  assertExactObject(input, POLICY_INPUT_FIELDS);
  if (own(input, "version") !== 1) reject();
  const policyEpoch = assertInteger(own(input, "policy_epoch"), 1);
  const maxObservationAgeSeconds = assertInteger(
    own(input, "max_observation_age_seconds"), 1, 3_600,
  );
  const osExpectation = normalizeOsExpectation(
    own(input, "os_expectation"), policyEpoch,
  );
  const observerExpectation = normalizeObserverExpectation(
    own(input, "observer_expectation"),
  );
  const rawRoles = own(input, "roles");
  assertDenseArray(rawRoles, ROLE_IDS.length, ROLE_IDS.length);
  const roles = [];
  const usedUids = [];
  const usedGids = [];
  const principals = [];
  for (let index = 0; index < ROLE_IDS.length; index += 1) {
    const role = normalizeRole(rawRoles[index], ROLE_IDS[index]);
    for (let prior = 0; prior < principals.length; prior += 1) {
      if (principals[prior] === role.principal_id || usedUids[prior] === role.uid) reject();
    }
    reflectApply(arrayPush, principals, [role.principal_id]);
    reflectApply(arrayPush, usedUids, [role.uid]);
    const roleGids = [role.primary_gid];
    for (let groupIndex = 0; groupIndex < role.supplementary_gids.length; groupIndex += 1) {
      reflectApply(arrayPush, roleGids, [role.supplementary_gids[groupIndex]]);
    }
    for (let groupIndex = 0; groupIndex < roleGids.length; groupIndex += 1) {
      for (let prior = 0; prior < usedGids.length; prior += 1) {
        if (usedGids[prior] === roleGids[groupIndex]) reject();
      }
      reflectApply(arrayPush, usedGids, [roleGids[groupIndex]]);
    }
    reflectApply(arrayPush, roles, [role]);
  }
  const rawEdges = own(input, "edges");
  assertDenseArray(rawEdges, EDGE_MATRIX.length, EDGE_MATRIX.length);
  const edges = [];
  for (let index = 0; index < EDGE_MATRIX.length; index += 1) {
    reflectApply(arrayPush, edges, [normalizeEdge(rawEdges[index], EDGE_MATRIX[index])]);
  }
  const rawResources = own(input, "resources");
  assertDenseArray(rawResources, 1, 16);
  const resources = [];
  const usedResourceIdentityDigests = [];
  const usedResourceAuthorityDigests = [];
  for (let index = 0; index < rawResources.length; index += 1) {
    const resource = normalizeResourcePolicy(rawResources[index]);
    for (let prior = 0; prior < resources.length; prior += 1) {
      if (resources[prior].resource_id === resource.resource_id) reject();
    }
    const identityDigests = [
      resource.device_identity_digest, resource.ioregistry_identity_digest,
      resource.device_path_digest, resource.device_file_id_digest,
      resource.device_major_minor_digest,
    ];
    for (let digestIndex = 0; digestIndex < identityDigests.length; digestIndex += 1) {
      for (let prior = 0; prior < usedResourceIdentityDigests.length; prior += 1) {
        if (usedResourceIdentityDigests[prior] === identityDigests[digestIndex]) reject();
      }
      reflectApply(arrayPush, usedResourceIdentityDigests, [identityDigests[digestIndex]]);
    }
    const authorityDigests = [
      resource.launcher_authorization_scope_digest,
      resource.delegation_policy_digest,
      resource.descriptor_inventory_policy_digest,
    ];
    for (let profileIndex = 0; profileIndex < resource.delegation_profiles.length;
      profileIndex += 1) {
      reflectApply(arrayPush, authorityDigests, [
        resource.delegation_profiles[profileIndex].descriptor_policy_digest,
        resource.delegation_profiles[profileIndex].capability_binding_digest,
      ]);
    }
    for (let digestIndex = 0; digestIndex < authorityDigests.length; digestIndex += 1) {
      for (let prior = 0; prior < usedResourceAuthorityDigests.length; prior += 1) {
        if (usedResourceAuthorityDigests[prior] === authorityDigests[digestIndex]) reject();
      }
      reflectApply(arrayPush, usedResourceAuthorityDigests, [authorityDigests[digestIndex]]);
    }
    reflectApply(arrayPush, resources, [resource]);
  }
  const issuedAt = assertTimestamp(own(input, "issued_at"));
  const expiresAt = assertTimestamp(own(input, "expires_at"));
  if (timestampMilliseconds(expiresAt) <= timestampMilliseconds(issuedAt)) reject();
  const basisFields = POLICY_INPUT_FIELDS;
  const basis = makeRecord(basisFields, {
    version: 1,
    policy_id: assertToken(own(input, "policy_id")),
    policy_epoch: policyEpoch,
    issued_at: issuedAt,
    expires_at: expiresAt,
    max_observation_age_seconds: maxObservationAgeSeconds,
    os_expectation: osExpectation,
    observer_expectation: observerExpectation,
    roles: makeArray(roles),
    edges: makeArray(edges),
    resources: makeArray(resources),
  });
  const outputFields = [
    ...basisFields, "policy_digest", "production_ready",
    "hardware_access_authorized", "readiness_blockers",
  ];
  const policy = makeRecord(outputFields, {
    ...basis,
    policy_digest: hashValue(POLICY_DOMAIN, basis),
    production_ready: false,
    hardware_access_authorized: false,
    readiness_blockers: READINESS_BLOCKERS,
  });
  reflectApply(weakSetAdd, POLICIES, [policy]);
  return policy;
}

function assertPolicy(value) {
  if (value == null || typeof value !== "object" || utilTypesIsProxy(value)
      || !reflectApply(weakSetHas, POLICIES, [value])) reject();
  return value;
}

function normalizeAccount(input, expectedRoleId) {
  assertExactObject(input, ACCOUNT_FIELDS);
  const source = {
    role_id: assertIdentifier(own(input, "role_id")),
    principal_id: assertPrincipal(own(input, "principal_id")),
    account_record_digest: assertDigest(own(input, "account_record_digest")),
    account_name_digest: assertDigest(own(input, "account_name_digest")),
    uid: assertInteger(own(input, "uid"), 0, 0xffff_ffff),
    primary_gid: assertInteger(own(input, "primary_gid"), 0, 0xffff_ffff),
    supplementary_gids: normalizeIntegerArray(own(input, "supplementary_gids")),
    service_account: assertBoolean(own(input, "service_account")),
    login_policy: assertIdentifier(own(input, "login_policy")),
    interactive_login_allowed: assertBoolean(own(input, "interactive_login_allowed")),
    record_source: assertIdentifier(own(input, "record_source")),
  };
  if (source.role_id !== expectedRoleId) reject();
  return makeRecord(ACCOUNT_FIELDS, source);
}

function normalizeGroup(input, expectedRoleId) {
  assertExactObject(input, GROUP_FIELDS);
  const source = {
    role_id: assertIdentifier(own(input, "role_id")),
    principal_id: assertPrincipal(own(input, "principal_id")),
    primary_group_record_digest: assertDigest(own(input, "primary_group_record_digest")),
    supplementary_group_records_digest: assertDigest(
      own(input, "supplementary_group_records_digest"),
    ),
    primary_gid: assertInteger(own(input, "primary_gid"), 0, 0xffff_ffff),
    supplementary_gids: normalizeIntegerArray(own(input, "supplementary_gids")),
    membership_complete: assertBoolean(own(input, "membership_complete")),
    no_unlisted_memberships: assertBoolean(own(input, "no_unlisted_memberships")),
    record_epoch: assertInteger(own(input, "record_epoch"), 1),
  };
  if (source.role_id !== expectedRoleId) reject();
  return makeRecord(GROUP_FIELDS, source);
}

function normalizeCredential(input, expectedRoleId) {
  assertExactObject(input, CREDENTIAL_FIELDS);
  const source = {
    role_id: assertIdentifier(own(input, "role_id")),
    principal_id: assertPrincipal(own(input, "principal_id")),
    real_uid: assertInteger(own(input, "real_uid"), 0, 0xffff_ffff),
    effective_uid: assertInteger(own(input, "effective_uid"), 0, 0xffff_ffff),
    saved_uid: assertInteger(own(input, "saved_uid"), 0, 0xffff_ffff),
    real_gid: assertInteger(own(input, "real_gid"), 0, 0xffff_ffff),
    effective_gid: assertInteger(own(input, "effective_gid"), 0, 0xffff_ffff),
    saved_gid: assertInteger(own(input, "saved_gid"), 0, 0xffff_ffff),
    supplementary_gids: normalizeIntegerArray(own(input, "supplementary_gids")),
    audit_token_digest: assertDigest(own(input, "audit_token_digest")),
    process_start_digest: assertDigest(own(input, "process_start_digest")),
    executable_digest: assertDigest(own(input, "executable_digest")),
    bundle_digest: assertDigest(own(input, "bundle_digest")),
    prebuild_digest: assertDigest(own(input, "prebuild_digest")),
    launch_attestation_digest: assertDigest(own(input, "launch_attestation_digest")),
    root_claimed: assertBoolean(own(input, "root_claimed")),
    root_authorization_digest: assertNullableDigest(own(input, "root_authorization_digest")),
    root_authorization_qualified: assertBoolean(
      own(input, "root_authorization_qualified"),
    ),
  };
  if (source.role_id !== expectedRoleId) reject();
  return makeRecord(CREDENTIAL_FIELDS, source);
}

function normalizeResourceObservation(input) {
  assertExactObject(input, RESOURCE_OBSERVATION_FIELDS);
  const rawEntries = own(input, "acl_entries");
  assertDenseArray(rawEntries, 0, 16);
  const entries = [];
  for (let index = 0; index < rawEntries.length; index += 1) {
    const entry = normalizeAclEntry(rawEntries[index]);
    if (entry.order !== index) reject();
    reflectApply(arrayPush, entries, [entry]);
  }
  return makeRecord(RESOURCE_OBSERVATION_FIELDS, {
    resource_id: assertToken(own(input, "resource_id")),
    provider_id: assertIdentifier(own(input, "provider_id")),
    resource_class: assertIdentifier(own(input, "resource_class")),
    device_identity_digest: assertDigest(own(input, "device_identity_digest")),
    ioregistry_identity_digest: assertDigest(own(input, "ioregistry_identity_digest")),
    device_path_digest: assertDigest(own(input, "device_path_digest")),
    device_file_id_digest: assertDigest(own(input, "device_file_id_digest")),
    device_major_minor_digest: assertDigest(own(input, "device_major_minor_digest")),
    device_type: assertIdentifier(own(input, "device_type")),
    open_method: assertIdentifier(own(input, "open_method")),
    openat_directory_identity_digest: assertDigest(
      own(input, "openat_directory_identity_digest"),
    ),
    filesystem_open_role_id: assertIdentifier(
      own(input, "filesystem_open_role_id"),
    ),
    no_symlink: assertBoolean(own(input, "no_symlink")),
    hardlink_count: assertInteger(own(input, "hardlink_count"), 0, 0xffff_ffff),
    owner_uid: assertInteger(own(input, "owner_uid"), 0, 0xffff_ffff),
    owner_gid: assertInteger(own(input, "owner_gid"), 0, 0xffff_ffff),
    mode: assertInteger(own(input, "mode"), 0, 0o777),
    acl_entries: makeArray(entries),
    direct_service_account_acl_present: assertBoolean(
      own(input, "direct_service_account_acl_present"),
    ),
    acl_inherited: assertBoolean(own(input, "acl_inherited")),
    acl_widened: assertBoolean(own(input, "acl_widened")),
    delegation_policy_digest: assertDigest(own(input, "delegation_policy_digest")),
    mutual_exclusion_enforced: assertBoolean(
      own(input, "mutual_exclusion_enforced"),
    ),
    safety_raw_transport_present: assertBoolean(
      own(input, "safety_raw_transport_present"),
    ),
    descriptor_inventory_complete: assertBoolean(
      own(input, "descriptor_inventory_complete"),
    ),
    descriptor_inventory_digest: assertDigest(
      own(input, "descriptor_inventory_digest"),
    ),
    descriptor_inventory_before_digest: assertDigest(
      own(input, "descriptor_inventory_before_digest"),
    ),
    descriptor_inventory_after_digest: assertDigest(
      own(input, "descriptor_inventory_after_digest"),
    ),
    descriptor_custody_state: assertIdentifier(
      own(input, "descriptor_custody_state"),
    ),
    launcher_descriptor_present: assertBoolean(
      own(input, "launcher_descriptor_present"),
    ),
    active_descriptor_present: assertBoolean(own(input, "active_descriptor_present")),
    cleanup_descriptor_present: assertBoolean(
      own(input, "cleanup_descriptor_present"),
    ),
    unlisted_descriptor_count: assertInteger(
      own(input, "unlisted_descriptor_count"), 0, 0xffff,
    ),
    inherited_descriptor_count: assertInteger(
      own(input, "inherited_descriptor_count"), 0, 0xffff,
    ),
    launcher_redundant_descriptor_closed: assertBoolean(
      own(input, "launcher_redundant_descriptor_closed"),
    ),
    stat_before_digest: assertDigest(own(input, "stat_before_digest")),
    stat_after_digest: assertDigest(own(input, "stat_after_digest")),
    ioregistry_before_digest: assertDigest(own(input, "ioregistry_before_digest")),
    ioregistry_after_digest: assertDigest(own(input, "ioregistry_after_digest")),
    stable: assertBoolean(own(input, "stable")),
  });
}

function normalizeAncestry(input, expectedRoleId) {
  assertExactObject(input, ANCESTRY_FIELDS);
  const source = {
    role_id: assertIdentifier(own(input, "role_id")),
    principal_id: assertPrincipal(own(input, "principal_id")),
    direct_parent_role_id: assertNullableIdentifier(own(input, "direct_parent_role_id")),
    direct_parent_principal_id: assertNullablePrincipal(
      own(input, "direct_parent_principal_id"),
    ),
    ancestry_digest: assertDigest(own(input, "ancestry_digest")),
    stable: assertBoolean(own(input, "stable")),
  };
  if (source.role_id !== expectedRoleId) reject();
  return makeRecord(ANCESTRY_FIELDS, source);
}

function normalizeAuthorization(input) {
  assertExactObject(input, AUTHORIZATION_FIELDS);
  return makeRecord(AUTHORIZATION_FIELDS, {
    resource_id: assertToken(own(input, "resource_id")),
    role_id: assertIdentifier(own(input, "role_id")),
    principal_id: assertPrincipal(own(input, "principal_id")),
    authorization_mode: assertIdentifier(own(input, "authorization_mode")),
    entitlement_state: assertIdentifier(own(input, "entitlement_state")),
    entitlement_digest: assertNullableDigest(own(input, "entitlement_digest")),
    io_service_authorize_state: assertIdentifier(
      own(input, "io_service_authorize_state"),
    ),
    io_service_authorize_digest: assertNullableDigest(
      own(input, "io_service_authorize_digest"),
    ),
    authorization_scope_digest: assertDigest(own(input, "authorization_scope_digest")),
    root_authorization_digest: assertDigest(own(input, "root_authorization_digest")),
    root_claimed: assertBoolean(own(input, "root_claimed")),
    root_authorization_qualified: assertBoolean(
      own(input, "root_authorization_qualified"),
    ),
  });
}

function normalizeDelegationEvidence(input) {
  assertExactObject(input, DELEGATION_EVIDENCE_FIELDS);
  return makeRecord(DELEGATION_EVIDENCE_FIELDS, {
    resource_id: assertToken(own(input, "resource_id")),
    profile_id: assertIdentifier(own(input, "profile_id")),
    delegate_role_id: assertIdentifier(own(input, "delegate_role_id")),
    delegate_principal_id: assertPrincipal(own(input, "delegate_principal_id")),
    delivery_mechanism: assertIdentifier(own(input, "delivery_mechanism")),
    descriptor_policy_digest: assertDigest(own(input, "descriptor_policy_digest")),
    capability_binding_digest: assertDigest(own(input, "capability_binding_digest")),
    mutual_exclusion_qualified: assertBoolean(
      own(input, "mutual_exclusion_qualified"),
    ),
    precommitted: assertBoolean(own(input, "precommitted")),
    closed_at_observation: assertBoolean(own(input, "closed_at_observation")),
    raw_path_access_present: assertBoolean(own(input, "raw_path_access_present")),
  });
}

function normalizeDarwinPrincipalAclObservation(input) {
  if (arguments.length !== 1) reject();
  assertExactObject(input, OBSERVATION_INPUT_FIELDS);
  if (own(input, "version") !== 1) reject();
  const osInput = own(input, "os");
  assertExactObject(osInput, OS_FIELDS);
  const os = makeRecord(OS_FIELDS, {
    platform: assertIdentifier(own(osInput, "platform")),
    os_version_digest: assertDigest(own(osInput, "os_version_digest")),
    os_build_digest: assertDigest(own(osInput, "os_build_digest")),
    boot_epoch_digest: assertDigest(own(osInput, "boot_epoch_digest")),
    security_epoch: assertInteger(own(osInput, "security_epoch"), 1),
  });
  if (os.platform !== "darwin") reject();
  const accountsInput = own(input, "accounts");
  const groupsInput = own(input, "groups");
  const credentialsInput = own(input, "credentials");
  const ancestryInput = own(input, "ancestry");
  const roleRecordSets = [accountsInput, groupsInput, credentialsInput, ancestryInput];
  for (let index = 0; index < roleRecordSets.length; index += 1) {
    assertDenseArray(roleRecordSets[index], ROLE_IDS.length, ROLE_IDS.length);
  }
  const accounts = [];
  const groups = [];
  const credentials = [];
  const ancestry = [];
  for (let index = 0; index < ROLE_IDS.length; index += 1) {
    reflectApply(arrayPush, accounts, [normalizeAccount(accountsInput[index], ROLE_IDS[index])]);
    reflectApply(arrayPush, groups, [normalizeGroup(groupsInput[index], ROLE_IDS[index])]);
    reflectApply(arrayPush, credentials, [
      normalizeCredential(credentialsInput[index], ROLE_IDS[index]),
    ]);
    reflectApply(arrayPush, ancestry, [
      normalizeAncestry(ancestryInput[index], ROLE_IDS[index]),
    ]);
  }
  const resourcesInput = own(input, "resources");
  assertDenseArray(resourcesInput, 1, 16);
  const resources = [];
  for (let index = 0; index < resourcesInput.length; index += 1) {
    reflectApply(arrayPush, resources, [normalizeResourceObservation(resourcesInput[index])]);
  }
  const authorizationsInput = own(input, "authorizations");
  assertDenseArray(authorizationsInput, 1, 48);
  const authorizations = [];
  for (let index = 0; index < authorizationsInput.length; index += 1) {
    reflectApply(arrayPush, authorizations, [
      normalizeAuthorization(authorizationsInput[index]),
    ]);
  }
  const delegationsInput = own(input, "delegations");
  assertDenseArray(delegationsInput, 1, 32);
  const delegations = [];
  for (let index = 0; index < delegationsInput.length; index += 1) {
    reflectApply(arrayPush, delegations, [
      normalizeDelegationEvidence(delegationsInput[index]),
    ]);
  }
  const nativeInput = own(input, "native_evidence");
  assertExactObject(nativeInput, NATIVE_EVIDENCE_FIELDS);
  const nativeEvidence = makeRecord(NATIVE_EVIDENCE_FIELDS, {
    observer_implementation_digest: assertDigest(
      own(nativeInput, "observer_implementation_digest"),
    ),
    observer_prebuild_digest: assertDigest(own(nativeInput, "observer_prebuild_digest")),
    observer_bundle_digest: assertDigest(own(nativeInput, "observer_bundle_digest")),
    observer_launch_attestation_digest: assertDigest(
      own(nativeInput, "observer_launch_attestation_digest"),
    ),
    observer_code_signature_requirement_digest: assertDigest(
      own(nativeInput, "observer_code_signature_requirement_digest"),
    ),
    observation_signing_identity_digest: assertDigest(
      own(nativeInput, "observation_signing_identity_digest"),
    ),
    observation_signature_digest: assertDigest(
      own(nativeInput, "observation_signature_digest"),
    ),
    before_snapshot_digest: assertDigest(own(nativeInput, "before_snapshot_digest")),
    after_snapshot_digest: assertDigest(own(nativeInput, "after_snapshot_digest")),
    stable: assertBoolean(own(nativeInput, "stable")),
    read_only: assertBoolean(own(nativeInput, "read_only")),
    native_attested: assertBoolean(own(nativeInput, "native_attested")),
    observation_signature_verified: assertBoolean(
      own(nativeInput, "observation_signature_verified"),
    ),
    prebuild_qualified: assertBoolean(own(nativeInput, "prebuild_qualified")),
    launch_attestation_qualified: assertBoolean(
      own(nativeInput, "launch_attestation_qualified"),
    ),
    hil_qualified: assertBoolean(own(nativeInput, "hil_qualified")),
  });
  const observedAt = assertTimestamp(own(input, "observed_at"));
  const expiresAt = assertTimestamp(own(input, "expires_at"));
  if (timestampMilliseconds(expiresAt) <= timestampMilliseconds(observedAt)) reject();
  const basisFields = OBSERVATION_INPUT_FIELDS;
  const basis = makeRecord(basisFields, {
    version: 1,
    observation_id: assertToken(own(input, "observation_id")),
    policy_id: assertToken(own(input, "policy_id")),
    policy_digest: assertDigest(own(input, "policy_digest")),
    policy_epoch: assertInteger(own(input, "policy_epoch"), 1),
    observed_at: observedAt,
    expires_at: expiresAt,
    os,
    accounts: makeArray(accounts),
    groups: makeArray(groups),
    credentials: makeArray(credentials),
    resources: makeArray(resources),
    ancestry: makeArray(ancestry),
    authorizations: makeArray(authorizations),
    delegations: makeArray(delegations),
    native_evidence: nativeEvidence,
  });
  const outputFields = [
    ...basisFields, "observation_digest", "production_ready",
    "hardware_access_authorized",
  ];
  const observation = makeRecord(outputFields, {
    ...basis,
    observation_digest: hashValue(OBSERVATION_DOMAIN, basis),
    production_ready: false,
    hardware_access_authorized: false,
  });
  reflectApply(weakSetAdd, OBSERVATIONS, [observation]);
  return observation;
}

function assertObservation(value) {
  if (value == null || typeof value !== "object" || utilTypesIsProxy(value)
      || !reflectApply(weakSetHas, OBSERVATIONS, [value])) reject();
  return value;
}

function arraysEqual(left, right) {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function aclEntriesEqual(left, right) {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index].order !== right[index].order
        || left[index].role_id !== right[index].role_id
        || left[index].effect !== right[index].effect
        || left[index].inheritance !== right[index].inheritance
        || !arraysEqual(left[index].permissions, right[index].permissions)) return false;
  }
  return true;
}

function addBlocker(blockers, code) {
  for (let index = 0; index < blockers.length; index += 1) {
    if (blockers[index] === code) return;
  }
  reflectApply(arrayPush, blockers, [code]);
}

function roleBindingsMatch(role, account, group, credential, ancestry, roles) {
  const expectedParentRole = role.expected_launcher_role_id;
  let expectedParentPrincipal = null;
  if (expectedParentRole != null) {
    for (let index = 0; index < roles.length; index += 1) {
      if (roles[index].role_id === expectedParentRole) {
        expectedParentPrincipal = roles[index].principal_id;
      }
    }
  }
  return account.principal_id === role.principal_id
    && account.uid === role.uid && account.primary_gid === role.primary_gid
    && arraysEqual(account.supplementary_gids, role.supplementary_gids)
    && account.service_account === true && account.login_policy === "no_login"
    && account.interactive_login_allowed === false
    && account.record_source === "opendirectory_native"
    && group.principal_id === role.principal_id && group.primary_gid === role.primary_gid
    && arraysEqual(group.supplementary_gids, role.supplementary_gids)
    && group.membership_complete === true && group.no_unlisted_memberships === true
    && credential.principal_id === role.principal_id
    && credential.real_uid === role.uid && credential.effective_uid === role.uid
    && credential.saved_uid === role.uid && credential.real_gid === role.primary_gid
    && credential.effective_gid === role.primary_gid
    && credential.saved_gid === role.primary_gid
    && arraysEqual(credential.supplementary_gids, role.supplementary_gids)
    && credential.executable_digest === role.executable_digest
    && credential.bundle_digest === role.bundle_digest
    && credential.prebuild_digest === role.prebuild_digest
    && credential.launch_attestation_digest === role.launch_attestation_digest
    && (role.role_id === "privileged_launcher"
      ? credential.root_claimed === true
        && credential.root_authorization_digest === role.root_authorization_digest
        && credential.root_authorization_qualified === true
      : credential.root_claimed === false
        && credential.root_authorization_digest === null
        && credential.root_authorization_qualified === false)
    && ancestry.principal_id === role.principal_id
    && ancestry.direct_parent_role_id === expectedParentRole
    && ancestry.direct_parent_principal_id === expectedParentPrincipal
    && ancestry.stable === true;
}

function collectQualificationBlockers(policy, observation, now) {
  const blockers = [];
  const nowMilliseconds = timestampMilliseconds(now);
  if (observation.policy_id !== policy.policy_id
      || observation.policy_digest !== policy.policy_digest) {
    addBlocker(blockers, "policy_binding_mismatch");
  }
  if (observation.policy_epoch !== policy.policy_epoch
      || observation.os.security_epoch !== policy.policy_epoch) {
    addBlocker(blockers, "authority_epoch_mismatch");
  }
  const expectedOs = policy.os_expectation;
  if (observation.os.platform !== expectedOs.platform
      || observation.os.os_version_digest !== expectedOs.os_version_digest
      || observation.os.os_build_digest !== expectedOs.os_build_digest
      || observation.os.boot_epoch_digest !== expectedOs.boot_epoch_digest
      || observation.os.security_epoch !== expectedOs.security_epoch) {
    addBlocker(blockers, "darwin_os_binding_mismatch");
  }
  if (nowMilliseconds < timestampMilliseconds(policy.issued_at)
      || nowMilliseconds >= timestampMilliseconds(policy.expires_at)) {
    addBlocker(blockers, "policy_time_invalid");
  }
  if (nowMilliseconds < timestampMilliseconds(observation.observed_at)) {
    addBlocker(blockers, "observation_from_future");
  }
  if (nowMilliseconds >= timestampMilliseconds(observation.expires_at)) {
    addBlocker(blockers, "observation_stale");
  }
  const observedAtMilliseconds = timestampMilliseconds(observation.observed_at);
  const observationExpiresMilliseconds = timestampMilliseconds(observation.expires_at);
  const maximumAgeMilliseconds = policy.max_observation_age_seconds * 1_000;
  if (observedAtMilliseconds < timestampMilliseconds(policy.issued_at)
      || observationExpiresMilliseconds > timestampMilliseconds(policy.expires_at)) {
    addBlocker(blockers, "observation_window_outside_policy");
  }
  if (nowMilliseconds - observedAtMilliseconds > maximumAgeMilliseconds
      || observationExpiresMilliseconds - observedAtMilliseconds
        > maximumAgeMilliseconds) {
    addBlocker(blockers, "observation_age_exceeds_policy");
  }
  const usedUids = [];
  const usedGids = [];
  const usedAuditTokenDigests = [];
  const usedProcessStartDigests = [];
  for (let index = 0; index < policy.roles.length; index += 1) {
    const role = policy.roles[index];
    const account = observation.accounts[index];
    const group = observation.groups[index];
    const credential = observation.credentials[index];
    const ancestry = observation.ancestry[index];
    if (!roleBindingsMatch(
      role, account, group, credential, ancestry, policy.roles,
    )) addBlocker(blockers, `role_binding_mismatch:${role.role_id}`);
    if (group.record_epoch !== policy.policy_epoch) {
      addBlocker(blockers, `group_epoch_mismatch:${role.role_id}`);
    }
    for (let prior = 0; prior < usedAuditTokenDigests.length; prior += 1) {
      if (usedAuditTokenDigests[prior] === credential.audit_token_digest) {
        addBlocker(blockers, "credential_audit_token_alias_detected");
      }
      if (usedProcessStartDigests[prior] === credential.process_start_digest) {
        addBlocker(blockers, "credential_process_start_alias_detected");
      }
    }
    reflectApply(arrayPush, usedAuditTokenDigests, [credential.audit_token_digest]);
    reflectApply(arrayPush, usedProcessStartDigests, [credential.process_start_digest]);
    for (let prior = 0; prior < usedUids.length; prior += 1) {
      if (usedUids[prior] === account.uid) addBlocker(blockers, "uid_alias_detected");
    }
    reflectApply(arrayPush, usedUids, [account.uid]);
    const gids = [account.primary_gid];
    for (let groupIndex = 0; groupIndex < account.supplementary_gids.length;
      groupIndex += 1) {
      reflectApply(arrayPush, gids, [account.supplementary_gids[groupIndex]]);
    }
    for (let groupIndex = 0; groupIndex < gids.length; groupIndex += 1) {
      for (let prior = 0; prior < usedGids.length; prior += 1) {
        if (usedGids[prior] === gids[groupIndex]) {
          addBlocker(blockers, "gid_alias_detected");
        }
      }
      reflectApply(arrayPush, usedGids, [gids[groupIndex]]);
    }
    if (role.role_id === "privileged_launcher") {
      if (credential.root_claimed !== true
          || credential.root_authorization_digest !== role.root_authorization_digest
          || credential.root_authorization_qualified !== true) {
        addBlocker(blockers, "privileged_launcher_root_unqualified");
      }
    } else if (credential.root_claimed !== false
        || credential.root_authorization_digest !== null
        || credential.root_authorization_qualified !== false) {
      addBlocker(blockers, `unqualified_root_claim:${role.role_id}`);
    }
  }
  if (observation.resources.length !== policy.resources.length) {
    addBlocker(blockers, "resource_set_mismatch");
  }
  const observedResourceIdentityDigests = [];
  for (let index = 0; index < observation.resources.length; index += 1) {
    const resource = observation.resources[index];
    const identityDigests = [
      resource.device_identity_digest, resource.ioregistry_identity_digest,
      resource.device_path_digest, resource.device_file_id_digest,
      resource.device_major_minor_digest,
    ];
    for (let digestIndex = 0; digestIndex < identityDigests.length; digestIndex += 1) {
      for (let prior = 0; prior < observedResourceIdentityDigests.length; prior += 1) {
        if (observedResourceIdentityDigests[prior] === identityDigests[digestIndex]) {
          addBlocker(blockers, "device_identity_alias_detected");
        }
      }
      reflectApply(arrayPush, observedResourceIdentityDigests, [identityDigests[digestIndex]]);
    }
  }
  const resourceCount = observation.resources.length < policy.resources.length
    ? observation.resources.length : policy.resources.length;
  for (let index = 0; index < resourceCount; index += 1) {
    const expected = policy.resources[index];
    const actual = observation.resources[index];
    if (actual.resource_id !== expected.resource_id
        || actual.provider_id !== expected.provider_id
        || actual.resource_class !== expected.resource_class
        || actual.device_identity_digest !== expected.device_identity_digest
        || actual.ioregistry_identity_digest !== expected.ioregistry_identity_digest
        || actual.device_path_digest !== expected.device_path_digest
        || actual.device_file_id_digest !== expected.device_file_id_digest
        || actual.device_major_minor_digest !== expected.device_major_minor_digest
        || actual.openat_directory_identity_digest
          !== expected.openat_directory_identity_digest) {
      addBlocker(blockers, `device_identity_mismatch:${expected.resource_id}`);
    }
    if (actual.device_type !== "character" || actual.open_method !== "openat_no_follow"
        || actual.filesystem_open_role_id !== expected.filesystem_open_role_id
        || actual.no_symlink !== true || actual.hardlink_count !== 1
        || actual.owner_uid !== expected.owner_uid || actual.owner_gid !== expected.owner_gid
        || actual.mode !== expected.mode) {
      addBlocker(blockers, `device_path_or_stat_mismatch:${expected.resource_id}`);
    }
    if (actual.stat_before_digest !== actual.stat_after_digest
        || actual.ioregistry_before_digest !== actual.ioregistry_after_digest
        || actual.stable !== true) {
      addBlocker(blockers, `device_replacement_or_instability:${expected.resource_id}`);
    }
    if (actual.direct_service_account_acl_present !== false
        || actual.acl_inherited !== false || actual.acl_widened !== false
        || !aclEntriesEqual(actual.acl_entries, expected.acl_entries)) {
      addBlocker(blockers, `root_only_device_node_mismatch:${expected.resource_id}`);
    }
    if (actual.delegation_policy_digest !== expected.delegation_policy_digest
        || actual.mutual_exclusion_enforced !== true
        || actual.safety_raw_transport_present !== false) {
      addBlocker(blockers, `descriptor_delegation_policy_mismatch:${expected.resource_id}`);
    }
    if (actual.descriptor_inventory_complete !== true
        || actual.descriptor_inventory_digest
          !== expected.descriptor_inventory_policy_digest
        || actual.descriptor_inventory_before_digest
          !== actual.descriptor_inventory_digest
        || actual.descriptor_inventory_after_digest
          !== actual.descriptor_inventory_digest
        || actual.descriptor_custody_state !== "closed"
        || actual.launcher_descriptor_present !== false
        || actual.active_descriptor_present !== false
        || actual.cleanup_descriptor_present !== false
        || actual.unlisted_descriptor_count !== 0
        || actual.inherited_descriptor_count !== 0
        || actual.launcher_redundant_descriptor_closed !== true) {
      addBlocker(blockers, `descriptor_inventory_unqualified:${expected.resource_id}`);
    }
    for (let entryIndex = 0; entryIndex < actual.acl_entries.length; entryIndex += 1) {
      const roleId = actual.acl_entries[entryIndex].role_id;
      if (roleId === "everyone" || roleId === "admin" || roleId === "wheel"
          || roleId === "operator" || roleId === "operator_control") {
        addBlocker(blockers, `broad_acl_principal:${expected.resource_id}`);
      }
    }
  }
  const expectedAuthorizationCount = policy.resources.length;
  if (observation.authorizations.length !== expectedAuthorizationCount) {
    addBlocker(blockers, "authorization_set_mismatch");
  }
  for (let resourceIndex = 0; resourceIndex < policy.resources.length;
    resourceIndex += 1) {
    if (resourceIndex >= observation.authorizations.length) break;
    const expectedResource = policy.resources[resourceIndex];
    const authorization = observation.authorizations[resourceIndex];
    const launcher = policy.roles[ROLE_IDS.length - 1];
    if (authorization.resource_id !== expectedResource.resource_id
        || authorization.role_id !== launcher.role_id
        || authorization.principal_id !== launcher.principal_id
        || authorization.authorization_mode
          !== expectedResource.launcher_authorization_mode
        || authorization.entitlement_state
          !== expectedResource.launcher_entitlement_state
        || authorization.entitlement_digest !== null
        || authorization.io_service_authorize_state
          !== expectedResource.launcher_io_service_authorize_state
        || authorization.io_service_authorize_digest !== null
        || authorization.authorization_scope_digest
          !== expectedResource.launcher_authorization_scope_digest
        || authorization.root_authorization_digest
          !== launcher.root_authorization_digest
        || authorization.root_claimed !== true
        || authorization.root_authorization_qualified !== true) {
      addBlocker(blockers, `launcher_device_authorization_unqualified:${
        expectedResource.resource_id}`);
    }
  }
  const expectedDelegationCount = policy.resources.length
    * DELEGATION_PROFILE_MATRIX.length;
  if (observation.delegations.length !== expectedDelegationCount) {
    addBlocker(blockers, "delegation_set_mismatch");
  }
  let delegationIndex = 0;
  for (let resourceIndex = 0; resourceIndex < policy.resources.length;
    resourceIndex += 1) {
    const expectedResource = policy.resources[resourceIndex];
    for (let profileIndex = 0; profileIndex < expectedResource.delegation_profiles.length;
      profileIndex += 1) {
      if (delegationIndex >= observation.delegations.length) break;
      const profile = expectedResource.delegation_profiles[profileIndex];
      const actual = observation.delegations[delegationIndex];
      let delegateRole = null;
      for (let roleIndex = 0; roleIndex < policy.roles.length; roleIndex += 1) {
        if (policy.roles[roleIndex].role_id === profile.delegate_role_id) {
          delegateRole = policy.roles[roleIndex];
        }
      }
      if (delegateRole == null || actual.resource_id !== expectedResource.resource_id
          || actual.profile_id !== profile.profile_id
          || actual.delegate_role_id !== profile.delegate_role_id
          || actual.delegate_principal_id !== delegateRole.principal_id
          || actual.delivery_mechanism !== profile.delivery_mechanism
          || actual.descriptor_policy_digest !== profile.descriptor_policy_digest
          || actual.capability_binding_digest !== profile.capability_binding_digest
          || actual.mutual_exclusion_qualified !== true
          || actual.precommitted !== profile.precommitted
          || actual.closed_at_observation !== true
          || actual.raw_path_access_present !== false) {
        addBlocker(blockers, `descriptor_delegation_unqualified:${
          expectedResource.resource_id}:${profile.profile_id}`);
      }
      delegationIndex += 1;
    }
  }
  const nativeEvidence = observation.native_evidence;
  const expectedObserver = policy.observer_expectation;
  if (nativeEvidence.observer_implementation_digest
      !== expectedObserver.implementation_digest
      || nativeEvidence.observer_prebuild_digest !== expectedObserver.prebuild_digest
      || nativeEvidence.observer_bundle_digest !== expectedObserver.bundle_digest
      || nativeEvidence.observer_launch_attestation_digest
        !== expectedObserver.launch_attestation_digest
      || nativeEvidence.observer_code_signature_requirement_digest
        !== expectedObserver.code_signature_requirement_digest
      || nativeEvidence.observation_signing_identity_digest
        !== expectedObserver.observation_signing_identity_digest) {
    addBlocker(blockers, "native_observer_source_mismatch");
  }
  if (nativeEvidence.before_snapshot_digest !== nativeEvidence.after_snapshot_digest
      || nativeEvidence.stable !== true) addBlocker(blockers, "native_snapshot_forked");
  if (nativeEvidence.read_only !== true || nativeEvidence.native_attested !== true
      || nativeEvidence.observation_signature_verified !== true) {
    addBlocker(blockers, "native_observation_unqualified");
  }
  if (nativeEvidence.prebuild_qualified !== true) {
    addBlocker(blockers, "native_observer_prebuild_unqualified");
  }
  if (nativeEvidence.launch_attestation_qualified !== true) {
    addBlocker(blockers, "native_observer_launch_unqualified");
  }
  if (nativeEvidence.hil_qualified !== false) {
    addBlocker(blockers, "hil_claim_not_accepted_by_source_contract");
  }
  return makeArray(blockers);
}

function makeDoctorResult(status, policy, observation, now, blockers) {
  const fields = [
    "version", "status", "policy_id", "policy_digest", "observation_id",
    "observation_digest", "checked_at", "qualification_blockers",
    "readiness_blockers", "production_ready", "hardware_access_authorized",
  ];
  return makeRecord(fields, {
    version: 1,
    status,
    policy_id: policy.policy_id,
    policy_digest: policy.policy_digest,
    observation_id: observation == null ? null : observation.observation_id,
    observation_digest: observation == null ? null : observation.observation_digest,
    checked_at: now,
    qualification_blockers: blockers,
    readiness_blockers: READINESS_BLOCKERS,
    production_ready: false,
    hardware_access_authorized: false,
  });
}

function runDarwinPrincipalAclDoctor(input) {
  if (arguments.length !== 1) reject();
  assertExactObject(input, DOCTOR_INPUT_FIELDS);
  const policy = assertPolicy(own(input, "policy"));
  const now = assertTimestamp(own(input, "now"));
  const observationValue = own(input, "observation");
  if (observationValue === null) {
    return makeDoctorResult(
      "unavailable",
      policy,
      null,
      now,
      makeArray(["native_observation_unavailable"]),
    );
  }
  const observation = assertObservation(observationValue);
  const blockers = collectQualificationBlockers(policy, observation, now);
  return makeDoctorResult(
    blockers.length === 0 ? "diagnostic_match_pending_native_prebuild_hil" : "blocked",
    policy,
    observation,
    now,
    blockers,
  );
}

function accountComponentMatches(role, observation, index) {
  const account = observation.accounts[index];
  return account.principal_id === role.principal_id && account.uid === role.uid
    && account.primary_gid === role.primary_gid
    && arraysEqual(account.supplementary_gids, role.supplementary_gids)
    && account.service_account === true && account.login_policy === "no_login"
    && account.interactive_login_allowed === false
    && account.record_source === "opendirectory_native";
}

function groupComponentMatches(role, observation, index, epoch) {
  const group = observation.groups[index];
  return group.principal_id === role.principal_id && group.primary_gid === role.primary_gid
    && arraysEqual(group.supplementary_gids, role.supplementary_gids)
    && group.membership_complete === true && group.no_unlisted_memberships === true
    && group.record_epoch === epoch;
}

function launchComponentMatches(policy, observation, index) {
  return roleBindingsMatch(
    policy.roles[index], observation.accounts[index], observation.groups[index],
    observation.credentials[index], observation.ancestry[index], policy.roles,
  );
}

function resourceIdentityMatches(expected, actual) {
  return actual.resource_id === expected.resource_id
    && actual.provider_id === expected.provider_id
    && actual.resource_class === expected.resource_class
    && actual.device_identity_digest === expected.device_identity_digest
    && actual.ioregistry_identity_digest === expected.ioregistry_identity_digest
    && actual.device_path_digest === expected.device_path_digest
    && actual.device_file_id_digest === expected.device_file_id_digest
    && actual.device_major_minor_digest === expected.device_major_minor_digest
    && actual.openat_directory_identity_digest
      === expected.openat_directory_identity_digest
    && actual.device_type === "character" && actual.open_method === "openat_no_follow"
    && actual.filesystem_open_role_id === expected.filesystem_open_role_id
    && actual.no_symlink === true && actual.hardlink_count === 1
    && actual.owner_uid === expected.owner_uid && actual.owner_gid === expected.owner_gid
    && actual.mode === expected.mode && actual.stat_before_digest === actual.stat_after_digest
    && actual.ioregistry_before_digest === actual.ioregistry_after_digest
    && actual.stable === true;
}

function observerBindingMatches(policy, observation) {
  if (observation.policy_id !== policy.policy_id
      || observation.policy_digest !== policy.policy_digest
      || observation.policy_epoch !== policy.policy_epoch) return false;
  const actualOs = observation.os;
  const expectedOs = policy.os_expectation;
  if (actualOs.platform !== expectedOs.platform
      || actualOs.os_version_digest !== expectedOs.os_version_digest
      || actualOs.os_build_digest !== expectedOs.os_build_digest
      || actualOs.boot_epoch_digest !== expectedOs.boot_epoch_digest
      || actualOs.security_epoch !== expectedOs.security_epoch) return false;
  if (timestampMilliseconds(observation.expires_at)
      - timestampMilliseconds(observation.observed_at)
      > policy.max_observation_age_seconds * 1_000) return false;
  if (timestampMilliseconds(observation.observed_at)
      < timestampMilliseconds(policy.issued_at)
      || timestampMilliseconds(observation.expires_at)
        > timestampMilliseconds(policy.expires_at)) return false;
  const actual = observation.native_evidence;
  const expected = policy.observer_expectation;
  return actual.observer_implementation_digest === expected.implementation_digest
    && actual.observer_prebuild_digest === expected.prebuild_digest
    && actual.observer_bundle_digest === expected.bundle_digest
    && actual.observer_launch_attestation_digest === expected.launch_attestation_digest
    && actual.observer_code_signature_requirement_digest
      === expected.code_signature_requirement_digest
    && actual.observation_signing_identity_digest
      === expected.observation_signing_identity_digest
    && actual.before_snapshot_digest === actual.after_snapshot_digest
    && actual.stable === true && actual.read_only === true
    && actual.native_attested === true && actual.observation_signature_verified === true
    && actual.prebuild_qualified === true
    && actual.launch_attestation_qualified === true
    && actual.hil_qualified === false;
}

function launcherAuthorizationMatches(policy, resource, authorization) {
  if (authorization == null) return false;
  const launcher = policy.roles[ROLE_IDS.length - 1];
  return authorization.resource_id === resource.resource_id
    && authorization.role_id === launcher.role_id
    && authorization.principal_id === launcher.principal_id
    && authorization.authorization_mode === resource.launcher_authorization_mode
    && authorization.entitlement_state === resource.launcher_entitlement_state
    && authorization.entitlement_digest === null
    && authorization.io_service_authorize_state
      === resource.launcher_io_service_authorize_state
    && authorization.io_service_authorize_digest === null
    && authorization.authorization_scope_digest
      === resource.launcher_authorization_scope_digest
    && authorization.root_authorization_digest === launcher.root_authorization_digest
    && authorization.root_claimed === true
    && authorization.root_authorization_qualified === true;
}

function delegationEvidenceMatches(policy, resource, observation, resourceIndex) {
  if (observation.delegations.length
      !== policy.resources.length * DELEGATION_PROFILE_MATRIX.length) return false;
  for (let profileIndex = 0; profileIndex < resource.delegation_profiles.length;
    profileIndex += 1) {
    const profile = resource.delegation_profiles[profileIndex];
    const actual = observation.delegations[
      (resourceIndex * DELEGATION_PROFILE_MATRIX.length) + profileIndex
    ];
    let delegateRole = null;
    for (let roleIndex = 0; roleIndex < policy.roles.length; roleIndex += 1) {
      if (policy.roles[roleIndex].role_id === profile.delegate_role_id) {
        delegateRole = policy.roles[roleIndex];
      }
    }
    if (actual == null || delegateRole == null
        || actual.resource_id !== resource.resource_id
        || actual.profile_id !== profile.profile_id
        || actual.delegate_role_id !== profile.delegate_role_id
        || actual.delegate_principal_id !== delegateRole.principal_id
        || actual.delivery_mechanism !== profile.delivery_mechanism
        || actual.descriptor_policy_digest !== profile.descriptor_policy_digest
        || actual.capability_binding_digest !== profile.capability_binding_digest
        || actual.mutual_exclusion_qualified !== true
        || actual.precommitted !== profile.precommitted
        || actual.closed_at_observation !== true
        || actual.raw_path_access_present !== false) return false;
  }
  return true;
}

function makeAction(changeKind, subjectKind, subjectId, currentDigest, desiredValue) {
  const fields = [
    "action_id", "change_kind", "subject_kind", "subject_id",
    "current_state_digest", "desired_state_digest", "requires_operator_approval",
    "requires_native_apply",
  ];
  return makeRecord(fields, {
    action_id: `plan-action:${changeKind}:${subjectId}`,
    change_kind: changeKind,
    subject_kind: subjectKind,
    subject_id: subjectId,
    current_state_digest: currentDigest,
    desired_state_digest: hashValue(`${PLAN_DOMAIN}/${changeKind}`, desiredValue),
    requires_operator_approval: true,
    requires_native_apply: true,
  });
}

function createDarwinPrincipalAclProvisioningPlan(input) {
  if (arguments.length !== 1) reject();
  assertExactObject(input, PLAN_INPUT_FIELDS);
  const policy = assertPolicy(own(input, "policy"));
  const observationValue = own(input, "observation");
  const observation = observationValue === null ? null : assertObservation(observationValue);
  const actions = [];
  if (observation == null || !observerBindingMatches(policy, observation)) {
    reflectApply(arrayPush, actions, [makeAction(
      "ensure_native_observer_binding", "policy", policy.policy_id,
      observation == null ? null : hashValue(
        `${PLAN_DOMAIN}/observed-native-source`, observation,
      ),
      makeArray([
        policy.os_expectation, policy.observer_expectation,
        policy.max_observation_age_seconds,
      ]),
    )]);
  }
  for (let index = 0; index < policy.roles.length; index += 1) {
    const role = policy.roles[index];
    if (observation == null || !accountComponentMatches(role, observation, index)) {
      reflectApply(arrayPush, actions, [makeAction(
        "ensure_account_policy", "principal", role.principal_id,
        observation == null ? null : observation.accounts[index].account_record_digest,
        role,
      )]);
    }
    if (observation == null
        || !groupComponentMatches(role, observation, index, policy.policy_epoch)) {
      reflectApply(arrayPush, actions, [makeAction(
        "ensure_group_policy", "principal", role.principal_id,
        observation == null ? null : observation.groups[index].primary_group_record_digest,
        makeArray([role.primary_gid, role.supplementary_gids]),
      )]);
    }
    if (observation == null || !launchComponentMatches(policy, observation, index)) {
      reflectApply(arrayPush, actions, [makeAction(
        "ensure_launch_identity_binding", "role", role.role_id,
        observation == null ? null : hashValue(
          `${PLAN_DOMAIN}/observed-launch`, observation.credentials[index],
        ),
        makeArray([
          role.executable_digest, role.bundle_digest, role.prebuild_digest,
          role.launch_attestation_digest, role.expected_launcher_role_id,
          role.root_authorization_digest,
        ]),
      )]);
    }
  }
  if (observation != null && observation.resources.length !== policy.resources.length) {
    reflectApply(arrayPush, actions, [makeAction(
      "reconcile_device_resource_set", "policy", policy.policy_id,
      hashValue(`${PLAN_DOMAIN}/observed-resource-set`, observation.resources),
      policy.resources,
    )]);
  }
  for (let index = 0; index < policy.resources.length; index += 1) {
    const expected = policy.resources[index];
    const actual = observation == null ? null : observation.resources[index];
    if (actual == null || !resourceIdentityMatches(expected, actual)) {
      reflectApply(arrayPush, actions, [makeAction(
        "ensure_device_identity_binding", "resource", expected.resource_id,
        actual == null ? null : hashValue(`${PLAN_DOMAIN}/observed-device`, actual),
        makeArray([
          expected.provider_id, expected.resource_class, expected.device_identity_digest,
          expected.ioregistry_identity_digest, expected.device_path_digest,
          expected.device_file_id_digest, expected.device_major_minor_digest,
          expected.openat_directory_identity_digest, expected.owner_uid,
          expected.owner_gid, expected.mode, expected.filesystem_open_role_id,
        ]),
      )]);
    }
    if (actual == null || actual.direct_service_account_acl_present !== false
        || actual.acl_inherited !== false || actual.acl_widened !== false
        || !aclEntriesEqual(actual.acl_entries, expected.acl_entries)) {
      reflectApply(arrayPush, actions, [makeAction(
        "enforce_root_only_device_node", "resource", expected.resource_id,
        actual == null ? null : hashValue(
          `${PLAN_DOMAIN}/observed-root-only-node`, actual,
        ),
        makeArray([
          expected.owner_uid, expected.owner_gid, expected.mode,
          expected.direct_service_account_acl_allowed, expected.acl_entries,
          expected.acl_inheritance, expected.deny_unlisted,
        ]),
      )]);
    }
    const authorization = observation == null ? null : observation.authorizations[index];
    if (observation == null || observation.authorizations.length !== policy.resources.length
        || !launcherAuthorizationMatches(policy, expected, authorization)) {
      reflectApply(arrayPush, actions, [makeAction(
        "ensure_launcher_open_authorization", "resource", expected.resource_id,
        observation == null ? null : hashValue(
          `${PLAN_DOMAIN}/observed-authorizations`, observation.authorizations,
        ),
        makeArray([
          expected.resource_id, expected.filesystem_open_role_id,
          expected.launcher_authorization_mode,
          expected.launcher_entitlement_state,
          expected.launcher_io_service_authorize_state,
          expected.launcher_authorization_scope_digest,
          policy.roles[ROLE_IDS.length - 1].root_authorization_digest,
        ]),
      )]);
    }
    if (actual == null || actual.delegation_policy_digest
        !== expected.delegation_policy_digest
        || actual.mutual_exclusion_enforced !== true
        || actual.safety_raw_transport_present !== false
        || observation == null
        || !delegationEvidenceMatches(policy, expected, observation, index)) {
      reflectApply(arrayPush, actions, [makeAction(
        "ensure_exclusive_descriptor_delegation", "resource", expected.resource_id,
        observation == null ? null : hashValue(
          `${PLAN_DOMAIN}/observed-delegation`, makeArray([
            actual, observation.delegations,
          ]),
        ),
        makeArray([
          expected.delegation_policy_digest, expected.delegation_profiles,
          "safety_control_only", "no_raw_paths", "exclusive_active_or_cleanup",
        ]),
      )]);
    }
    if (actual == null || actual.descriptor_inventory_complete !== true
        || actual.descriptor_inventory_digest
          !== expected.descriptor_inventory_policy_digest
        || actual.descriptor_inventory_before_digest
          !== actual.descriptor_inventory_digest
        || actual.descriptor_inventory_after_digest
          !== actual.descriptor_inventory_digest
        || actual.descriptor_custody_state !== "closed"
        || actual.launcher_descriptor_present !== false
        || actual.active_descriptor_present !== false
        || actual.cleanup_descriptor_present !== false
        || actual.unlisted_descriptor_count !== 0
        || actual.inherited_descriptor_count !== 0
        || actual.launcher_redundant_descriptor_closed !== true) {
      reflectApply(arrayPush, actions, [makeAction(
        "ensure_closed_descriptor_inventory", "resource", expected.resource_id,
        actual == null ? null : hashValue(
          `${PLAN_DOMAIN}/observed-descriptor-inventory`, actual,
        ),
        makeArray([
          expected.descriptor_inventory_policy_digest,
          "complete_closed_inventory", "launcher_copy_closed",
          "active_copy_closed", "cleanup_copy_closed",
          "no_unlisted_or_inherited_descriptors",
        ]),
      )]);
    }
  }
  const planBasisFields = [
    "version", "policy_id", "policy_digest", "observation_id",
    "observation_digest", "actions", "approval_required", "native_apply_required",
    "idempotent", "contains_executable_commands", "contains_secret_material",
    "contains_raw_device_paths", "production_ready", "hardware_access_authorized",
  ];
  const basis = makeRecord(planBasisFields, {
    version: 1,
    policy_id: policy.policy_id,
    policy_digest: policy.policy_digest,
    observation_id: observation == null ? null : observation.observation_id,
    observation_digest: observation == null ? null : observation.observation_digest,
    actions: makeArray(actions),
    approval_required: actions.length > 0,
    native_apply_required: actions.length > 0,
    idempotent: actions.length === 0,
    contains_executable_commands: false,
    contains_secret_material: false,
    contains_raw_device_paths: false,
    production_ready: false,
    hardware_access_authorized: false,
  });
  return makeRecord([...planBasisFields, "plan_digest", "readiness_blockers"], {
    ...basis,
    plan_digest: hashValue(PLAN_DOMAIN, basis),
    readiness_blockers: READINESS_BLOCKERS,
  });
}

module.exports = objectFreeze({
  DARWIN_PRINCIPAL_ACL_ROLE_IDS: ROLE_IDS,
  DARWIN_PRINCIPAL_ACL_DESCRIPTOR_DELEGATE_ROLE_IDS: DESCRIPTOR_DELEGATE_ROLE_IDS,
  createDarwinPrincipalAclPolicy,
  normalizeDarwinPrincipalAclObservation,
  runDarwinPrincipalAclDoctor,
  createDarwinPrincipalAclProvisioningPlan,
});
