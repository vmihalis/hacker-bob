"use strict";

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const DARWIN_NATIVE_FIXTURE_CONTRACT_RECORD_VERSION = 2;
const DARWIN_NATIVE_FIXTURE_CONTRACT_RECORD_DOMAIN =
  "hacker-bob/instrument-darwin-native-launcher-fixture-contract-record/v2";
const DARWIN_NATIVE_FIXTURE_ENTRY_COUNT = 8;
const DARWIN_NATIVE_FIXTURE_CONTRACT_PRODUCTION_BLOCKERS = Object.freeze([
  "adhoc_native_signature_not_production_qualified",
  "root_owned_immutable_install_not_qualified",
  "real_credential_drop_readback_hil_missing",
  "negative_principal_matrix_hil_missing",
  "capability_fd_projection_not_linked_into_fixture",
  "privileged_launch_wire_authority_verifier_not_integrated",
  "privileged_launch_provenance_persistence_not_integrated",
  "standalone_native_dispatch_custodian_prebuild_missing",
  "node_fixture_adapter_argv_not_executor_contract",
  "production_executor_not_linked",
  "fixture_mode_execve_disabled",
  "root_owned_immutable_ancestry_hil_missing",
  "darwin_fd_bound_exec_unavailable",
  "native_launcher_mapped_process_image_identity_unbound",
  "native_fixture_record_provenance_unattested",
  "writable_fixture_bracketing_not_production_immutability",
]);

const RECORD_FIELDS = Object.freeze([
  "version",
  "kind",
  "record_domain",
  "fixture_manifest_digest",
  "native_launcher_on_disk_path_object_sha256",
  "declared_launch_plan_digest",
  "declared_worker_bundle_projection_digest",
  "declared_native_evidence_digest",
  "declared_path_plan_digest",
  "declared_argv_digest",
  "declared_environment_digest",
  "declared_fd_set_digest",
  "declared_credential_plan_digest",
  "fixture_root_identity_digest",
  "openat_fstatat_walk_digest",
  "fd_enumeration_digest",
  "credential_observation_digest",
  "bundle_entry_count",
  "all_path_components_openat_verified",
  "all_bundle_objects_exact",
  "all_unlisted_fds_closed",
  "stdio_reopened_dev_null",
  "empty_environment",
  "retained_bundle_fds_verified",
  "double_hash_identity_pass_complete",
  "terminal_ancestry_rewalk_complete",
  "final_retained_fd_identity_sweep_complete",
  "credential_drop_executed",
  "execve_executed",
  "native_launcher_mapped_process_image_identity_bound",
  "native_fixture_record_provenance_attested",
  "child_process_custody_attested",
  "report_channel_authenticated",
  "production_attested",
  "production_ready",
  "production_blockers",
  "contract_record_checksum",
]);
const RECORD_CHECKSUM_INPUT_FIELDS = Object.freeze(RECORD_FIELDS.slice(0, -1));
const DIGEST_FIELDS = Object.freeze([
  "fixture_manifest_digest",
  "native_launcher_on_disk_path_object_sha256",
  "declared_launch_plan_digest",
  "declared_worker_bundle_projection_digest",
  "declared_native_evidence_digest",
  "declared_path_plan_digest",
  "declared_argv_digest",
  "declared_environment_digest",
  "declared_fd_set_digest",
  "declared_credential_plan_digest",
  "fixture_root_identity_digest",
  "openat_fstatat_walk_digest",
  "fd_enumeration_digest",
  "credential_observation_digest",
]);
const TRUE_FIELDS = Object.freeze([
  "all_path_components_openat_verified",
  "all_bundle_objects_exact",
  "all_unlisted_fds_closed",
  "stdio_reopened_dev_null",
  "empty_environment",
  "retained_bundle_fds_verified",
  "double_hash_identity_pass_complete",
  "terminal_ancestry_rewalk_complete",
  "final_retained_fd_identity_sweep_complete",
]);
const FALSE_FIELDS = Object.freeze([
  "credential_drop_executed",
  "execve_executed",
  "native_launcher_mapped_process_image_identity_bound",
  "native_fixture_record_provenance_attested",
  "child_process_custody_attested",
  "report_channel_authenticated",
  "production_attested",
  "production_ready",
]);

const objectFreeze = Object.freeze;
const objectCreate = Object.create;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwnProperty = Object.prototype.hasOwnProperty;
const objectPrototype = Object.prototype;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const arrayIsArray = Array.isArray;
const arrayJoin = Array.prototype.join;
const regexpTest = RegExp.prototype.test;
const utilIsProxy = utilTypes.isProxy;
const cryptoCreateHash = crypto.createHash;
const hashPrototype = objectGetPrototypeOf(reflectApply(cryptoCreateHash, crypto, ["sha256"]));
const hashUpdate = objectGetOwnPropertyDescriptor(hashPrototype, "update").value;
const hashDigest = objectGetOwnPropertyDescriptor(hashPrototype, "digest").value;
const HASH_PATTERN = /^[a-f0-9]{64}$/u;

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object"
      || reflectApply(utilIsProxy, utilTypes, [value]) || arrayIsArray(value)) return false;
  const prototype = objectGetPrototypeOf(value);
  if (prototype !== objectPrototype && prototype !== null) return false;
  const keys = reflectOwnKeys(value);
  for (let index = 0; index < keys.length; index += 1) {
    if (typeof keys[index] !== "string") return false;
    const descriptor = objectGetOwnPropertyDescriptor(value, keys[index]);
    if (descriptor == null || !("value" in descriptor) || descriptor.enumerable !== true) {
      return false;
    }
  }
  return true;
}

function ownDataValue(value, field, label) {
  const descriptor = objectGetOwnPropertyDescriptor(value, field);
  if (descriptor == null || !("value" in descriptor) || descriptor.enumerable !== true) {
    throw new Error(`${label}.${field} must be an enumerable own data field`);
  }
  return descriptor.value;
}

function assertExactObject(value, fields, label) {
  if (!isPlainDataObject(value)) throw new Error(`${label} must be a plain own-data object`);
  const keys = reflectOwnKeys(value);
  if (keys.length !== fields.length) throw new Error(`${label} fields are not exact`);
  for (let index = 0; index < fields.length; index += 1) {
    if (!reflectApply(objectHasOwnProperty, value, [fields[index]])) {
      throw new Error(`${label} fields are not exact`);
    }
  }
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !reflectApply(regexpTest, HASH_PATTERN, [value])) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function denseStringArray(value, expected, label) {
  if (value == null || typeof value !== "object"
      || reflectApply(utilIsProxy, utilTypes, [value]) || !arrayIsArray(value)) {
    throw new Error(`${label} must be a dense non-Proxy array`);
  }
  const lengthDescriptor = objectGetOwnPropertyDescriptor(value, "length");
  if (lengthDescriptor == null || lengthDescriptor.value !== expected.length
      || reflectOwnKeys(value).length !== expected.length + 1) {
    throw new Error(`${label} length is not exact`);
  }
  const result = [];
  for (let index = 0; index < expected.length; index += 1) {
    const descriptor = objectGetOwnPropertyDescriptor(value, `${index}`);
    if (descriptor == null || !("value" in descriptor) || descriptor.enumerable !== true
        || descriptor.value !== expected[index]) {
      throw new Error(`${label} values are not exact`);
    }
    result[index] = descriptor.value;
  }
  return objectFreeze(result);
}

function recordTranscript(input) {
  let transcript = `${DARWIN_NATIVE_FIXTURE_CONTRACT_RECORD_DOMAIN}\n`;
  transcript += `version=${input.version}\n`;
  transcript += `kind=${input.kind}\n`;
  transcript += `record_domain=${input.record_domain}\n`;
  for (let index = 0; index < DIGEST_FIELDS.length; index += 1) {
    const field = DIGEST_FIELDS[index];
    transcript += `${field}=${input[field]}\n`;
  }
  transcript += `bundle_entry_count=${input.bundle_entry_count}\n`;
  for (let index = 0; index < TRUE_FIELDS.length; index += 1) {
    transcript += `${TRUE_FIELDS[index]}=true\n`;
  }
  for (let index = 0; index < FALSE_FIELDS.length; index += 1) {
    transcript += `${FALSE_FIELDS[index]}=false\n`;
  }
  transcript += `production_blockers=${reflectApply(
    arrayJoin,
    DARWIN_NATIVE_FIXTURE_CONTRACT_PRODUCTION_BLOCKERS,
    [","],
  )}\n`;
  return transcript;
}

function normalizeRecordChecksumInput(input, label) {
  assertExactObject(input, RECORD_CHECKSUM_INPUT_FIELDS, label);
  if (ownDataValue(input, "version", label) !== DARWIN_NATIVE_FIXTURE_CONTRACT_RECORD_VERSION
      || ownDataValue(input, "kind", label)
        !== "darwin_native_launcher_fixture_contract_record"
      || ownDataValue(input, "record_domain", label)
        !== DARWIN_NATIVE_FIXTURE_CONTRACT_RECORD_DOMAIN
      || ownDataValue(input, "bundle_entry_count", label) !== DARWIN_NATIVE_FIXTURE_ENTRY_COUNT) {
    throw new Error(`${label} version, kind, domain, or entry count is invalid`);
  }
  const normalized = objectCreate(null);
  normalized.version = DARWIN_NATIVE_FIXTURE_CONTRACT_RECORD_VERSION;
  normalized.kind = "darwin_native_launcher_fixture_contract_record";
  normalized.record_domain = DARWIN_NATIVE_FIXTURE_CONTRACT_RECORD_DOMAIN;
  for (let index = 0; index < DIGEST_FIELDS.length; index += 1) {
    const field = DIGEST_FIELDS[index];
    normalized[field] = assertDigest(ownDataValue(input, field, label), `${label}.${field}`);
  }
  normalized.bundle_entry_count = DARWIN_NATIVE_FIXTURE_ENTRY_COUNT;
  for (let index = 0; index < TRUE_FIELDS.length; index += 1) {
    const field = TRUE_FIELDS[index];
    if (ownDataValue(input, field, label) !== true) throw new Error(`${label}.${field} must be true`);
    normalized[field] = true;
  }
  for (let index = 0; index < FALSE_FIELDS.length; index += 1) {
    const field = FALSE_FIELDS[index];
    if (ownDataValue(input, field, label) !== false) throw new Error(`${label}.${field} must be false`);
    normalized[field] = false;
  }
  normalized.production_blockers = denseStringArray(
    ownDataValue(input, "production_blockers", label),
    DARWIN_NATIVE_FIXTURE_CONTRACT_PRODUCTION_BLOCKERS,
    `${label}.production_blockers`,
  );
  return objectFreeze(normalized);
}

function darwinNativeFixtureContractRecordChecksum(input) {
  const normalized = normalizeRecordChecksumInput(
    input,
    "darwin_native_launcher_fixture_contract_record_checksum_input",
  );
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(hashUpdate, hash, [recordTranscript(normalized), "utf8"]);
  return reflectApply(hashDigest, hash, ["hex"]);
}

function normalizeDarwinNativeFixtureContractRecord(input) {
  const label = "darwin_native_launcher_fixture_contract_record";
  assertExactObject(input, RECORD_FIELDS, label);
  const checksumInput = objectCreate(null);
  for (let index = 0; index < RECORD_CHECKSUM_INPUT_FIELDS.length; index += 1) {
    const field = RECORD_CHECKSUM_INPUT_FIELDS[index];
    checksumInput[field] = ownDataValue(input, field, label);
  }
  const normalized = normalizeRecordChecksumInput(checksumInput, label);
  const recordChecksum = assertDigest(
    ownDataValue(input, "contract_record_checksum", label),
    `${label}.contract_record_checksum`,
  );
  if (darwinNativeFixtureContractRecordChecksum(normalized) !== recordChecksum) {
    throw new Error(`${label}.contract_record_checksum is invalid`);
  }
  return objectFreeze({ ...normalized, contract_record_checksum: recordChecksum });
}

module.exports = objectFreeze({
  DARWIN_NATIVE_FIXTURE_ENTRY_COUNT,
  DARWIN_NATIVE_FIXTURE_CONTRACT_PRODUCTION_BLOCKERS,
  DARWIN_NATIVE_FIXTURE_CONTRACT_RECORD_DOMAIN,
  DARWIN_NATIVE_FIXTURE_CONTRACT_RECORD_VERSION,
  darwinNativeFixtureContractRecordChecksum,
  normalizeDarwinNativeFixtureContractRecord,
});
