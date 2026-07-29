"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const MODULE_PATH = path.join(__dirname, "..", "lib", "self-identity.js");
const BINDING_PATH = path.join(__dirname, "..", "build", "Release", "peer_credentials.node");
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const CODE_DIRECTORY_HASH_PATTERN = /^(?:[a-f0-9]{2}){16,64}$/u;
const EXPECTED_BLOCKERS = Object.freeze([
  "self_code_identity_policy_allowlist_missing",
  "self_code_identity_hil_missing",
  "native_addon_non_executable_runtime_state_unverified",
  "native_addon_signed_immutable_delivery_unverified",
  "root_owned_immutable_bundle_unverified",
  "launch_ticket_binding_missing",
  "broker_activation_not_implemented",
  "dedicated_worker_uid_unverified",
  "device_acl_hil_missing",
  "raw_native_primitive_not_policy_one_shot",
]);
const RAW_NATIVE_SELF_FIELDS = Object.freeze([
  "primitive",
  "self_audit_token_digest",
  "self_code_certificate_chain_digest",
  "self_code_certificate_chain_state",
  "self_code_certificate_count",
  "self_code_designated_requirement_digest",
  "self_code_directory_hash",
  "self_code_directory_hash_algorithm",
  "self_code_directory_hashes_digest",
  "self_code_dynamic_status_digest",
  "self_code_dynamic_validity",
  "self_code_dynamic_validity_scheme",
  "self_code_identity_audit_token_bound",
  "self_code_identity_completeness",
  "self_code_identity_scheme",
  "self_code_identity_seccode_self_cross_checked",
  "self_code_identity_stable",
  "self_code_signature_class",
  "self_code_signer_identity_complete",
  "self_code_signing_identifier_digest",
  "self_code_signing_identity_digest",
  "self_code_static_flags_digest",
  "self_code_team_identifier_digest",
  "self_code_team_identifier_state",
  "self_egid",
  "self_euid",
  "self_executable_path_digest",
  "self_kernel_snapshot_stable",
  "self_mapped_code_identity_digest",
  "self_pid",
  "self_pidversion",
  "self_process_start_token_digest",
  "self_process_start_tvsec",
  "self_process_start_tvusec",
  "self_rgid",
  "self_ruid",
  "version",
]);
const SELF_PROJECTION_FIELDS = Object.freeze([
  "adapter_id",
  "architecture",
  "credential_source",
  "native_binding_implementation_digest",
  "native_binding_measurement_scheme",
  "native_loaded_image_callback_in_executable_segment",
  "native_loaded_image_canonical_path_digest",
  "native_loaded_image_dladdr_base_matches_dyld",
  "native_loaded_image_dyld_canonical_path_matches_dladdr",
  "native_loaded_image_dyld_header_unique",
  "native_loaded_image_dyld_snapshot_stable",
  "native_loaded_image_executable_file_bytes",
  "native_loaded_image_executable_identity_complete",
  "native_loaded_image_executable_pages_read_execute_only",
  "native_loaded_image_executable_segment_count",
  "native_loaded_image_executable_segment_file_size_equals_vm_size",
  "native_loaded_image_executable_segments_digest",
  "native_loaded_image_executable_segments_match_file",
  "native_loaded_image_file_identity_digest",
  "native_loaded_image_file_sha256",
  "native_loaded_image_full_runtime_state_identity_complete",
  "native_loaded_image_header_and_load_commands_digest",
  "native_loaded_image_header_and_load_commands_match_file",
  "native_loaded_image_identity_digest",
  "native_loaded_image_lc_uuid_digest",
  "native_loaded_image_measurement_scheme",
  "native_loaded_image_non_executable_runtime_state_measured",
  "native_loaded_image_signed_immutable_delivery_verified",
  "platform",
  "primitive",
  "production_blockers",
  "production_ready",
  "self_audit_token_digest",
  "self_code_certificate_chain_digest",
  "self_code_certificate_chain_state",
  "self_code_certificate_count",
  "self_code_designated_requirement_digest",
  "self_code_directory_hash",
  "self_code_directory_hash_algorithm",
  "self_code_directory_hashes_digest",
  "self_code_dynamic_status_digest",
  "self_code_dynamic_validity",
  "self_code_dynamic_validity_scheme",
  "self_code_identity_audit_token_bound",
  "self_code_identity_completeness",
  "self_code_identity_scheme",
  "self_code_identity_seccode_self_cross_checked",
  "self_code_identity_stable",
  "self_code_signature_class",
  "self_code_signer_identity_complete",
  "self_code_signing_identifier_digest",
  "self_code_signing_identity_digest",
  "self_code_static_flags_digest",
  "self_code_team_identifier_digest",
  "self_code_team_identifier_state",
  "self_executable_bytes_measurement_complete",
  "self_executable_bytes_measurement_scheme",
  "self_executable_path_digest",
  "self_executable_path_measurement_complete",
  "self_executable_path_measurement_scheme",
  "self_gid",
  "self_mapped_code_identity_digest",
  "self_pid",
  "self_pidversion",
  "self_process_start_token_digest",
  "self_process_start_tvsec",
  "self_process_start_tvusec",
  "self_real_gid",
  "self_real_uid",
  "self_uid",
  "snapshot_digest",
  "version",
]);

function assertSafeSelfRejection(error) {
  assert.equal(error?.code, "darwin_native_self_rejected");
  assert.equal(error?.message, "Darwin native self identity was rejected");
  assert.equal(Object.hasOwn(error, "cause"), false);
  return true;
}

function independentSnapshotDigest(domain, snapshot) {
  const basis = Object.create(null);
  for (const key of Object.keys(snapshot)) {
    if (key !== "snapshot_digest") basis[key] = snapshot[key];
  }
  const serialized = `{"domain":${JSON.stringify(domain)},"snapshot":${
    JSON.stringify(basis)}}`;
  return crypto.createHash("sha256").update(serialized).digest("hex");
}

function inspectInFreshProcess() {
  const source = [
    `const m = require(${JSON.stringify(MODULE_PATH)});`,
    "const port = m.createDarwinNativeSelfIdentityInspector({adapter_id:'self_child'});",
    "const snapshot = m.inspectCurrentDarwinSelf(port);",
    "process.stdout.write(JSON.stringify(snapshot));",
  ].join("");
  const result = spawnSync(process.execPath, ["-e", source], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  return JSON.parse(result.stdout);
}

test("self module import is inert and does not load native code", () => {
  const originalDlopen = process.dlopen;
  let loads = 0;
  process.dlopen = () => {
    loads += 1;
    throw new Error("native load during inert import");
  };
  try {
    delete require.cache[require.resolve(MODULE_PATH)];
    const imported = require(MODULE_PATH);
    assert.deepEqual(Object.keys(imported).sort(), [
      "DARWIN_NATIVE_SELF_IDENTITY_DOMAIN",
      "DARWIN_NATIVE_SELF_IDENTITY_PRIMITIVE",
      "DARWIN_NATIVE_SELF_IDENTITY_PRODUCTION_BLOCKERS",
      "DARWIN_NATIVE_SELF_IDENTITY_VERSION",
      "assertDarwinNativeSelfIdentityInspector",
      "createDarwinNativeSelfIdentityInspector",
      "inspectCurrentDarwinSelf",
    ]);
    assert.equal(loads, 0);
  } finally {
    process.dlopen = originalDlopen;
  }
});

test("self native load failures are redacted", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-native-self-missing-"));
  const isolatedLib = path.join(root, "lib");
  const isolatedModule = path.join(isolatedLib, "self-identity.js");
  fs.mkdirSync(isolatedLib);
  fs.copyFileSync(MODULE_PATH, isolatedModule);
  fs.copyFileSync(
    path.join(__dirname, "..", "lib", "canonical-snapshot.js"),
    path.join(isolatedLib, "canonical-snapshot.js"),
  );
  fs.copyFileSync(
    path.join(__dirname, "..", "lib", "native-binding-loader.js"),
    path.join(isolatedLib, "native-binding-loader.js"),
  );
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const isolated = require(isolatedModule);
  assert.throws(
    () => isolated.createDarwinNativeSelfIdentityInspector({ adapter_id: "missing_self" }),
    (error) => {
      assertSafeSelfRejection(error);
      assert.equal(error.message.includes(root), false);
      assert.equal(error.message.includes("peer_credentials.node"), false);
      assert.equal(error.message.includes("prebuilds"), false);
      return true;
    },
  );
});

test("self inspector constructors reject Proxy, accessor, clone, and malformed input", () => {
  const {
    assertDarwinNativeSelfIdentityInspector,
    createDarwinNativeSelfIdentityInspector,
    inspectCurrentDarwinSelf,
  } = require(MODULE_PATH);
  let reads = 0;
  const proxy = new Proxy({ adapter_id: "self_proxy" }, {
    get(target, property, receiver) {
      reads += 1;
      return Reflect.get(target, property, receiver);
    },
  });
  assert.throws(
    () => createDarwinNativeSelfIdentityInspector(proxy),
    assertSafeSelfRejection,
  );
  assert.equal(reads, 0);

  let accessorCalls = 0;
  const accessor = {};
  Object.defineProperty(accessor, "adapter_id", {
    enumerable: true,
    get() {
      accessorCalls += 1;
      return "self_accessor";
    },
  });
  assert.throws(
    () => createDarwinNativeSelfIdentityInspector(accessor),
    assertSafeSelfRejection,
  );
  assert.equal(accessorCalls, 0);

  for (const input of [
    undefined,
    null,
    {},
    { adapter_id: "INVALID" },
    { adapter_id: "self_extra", extra: true },
  ]) {
    assert.throws(
      () => createDarwinNativeSelfIdentityInspector(input),
      assertSafeSelfRejection,
    );
  }
  assert.throws(
    () => createDarwinNativeSelfIdentityInspector(),
    assertSafeSelfRejection,
  );
  assert.throws(
    () => createDarwinNativeSelfIdentityInspector({ adapter_id: "self_args" }, null),
    assertSafeSelfRejection,
  );

  const port = createDarwinNativeSelfIdentityInspector({ adapter_id: "self_valid" });
  assert.equal(assertDarwinNativeSelfIdentityInspector(port), port);
  assert.throws(
    () => assertDarwinNativeSelfIdentityInspector(structuredClone(port)),
    assertSafeSelfRejection,
  );
  let portReads = 0;
  const portProxy = new Proxy(port, {
    get(target, property, receiver) {
      portReads += 1;
      return Reflect.get(target, property, receiver);
    },
  });
  assert.throws(
    () => inspectCurrentDarwinSelf(portProxy),
    assertSafeSelfRejection,
  );
  assert.equal(portReads, 0);
});

test("current process yields one exact redacted audit-token-bound self snapshot", () => {
  const {
    DARWIN_NATIVE_SELF_IDENTITY_PRODUCTION_BLOCKERS,
    createDarwinNativeSelfIdentityInspector,
    inspectCurrentDarwinSelf,
  } = require(MODULE_PATH);
  assert.deepEqual(DARWIN_NATIVE_SELF_IDENTITY_PRODUCTION_BLOCKERS, EXPECTED_BLOCKERS);
  assert.equal(Object.isFrozen(DARWIN_NATIVE_SELF_IDENTITY_PRODUCTION_BLOCKERS), true);
  const port = createDarwinNativeSelfIdentityInspector({ adapter_id: "self_exact" });
  assert.equal(port.production_ready, false);
  assert.deepEqual(port.production_blockers, EXPECTED_BLOCKERS);
  const originalToJSON = Object.getOwnPropertyDescriptor(Object.prototype, "toJSON");
  let inheritedToJSONCalls = 0;
  let snapshot;
  try {
    Object.defineProperty(Object.prototype, "toJSON", {
      configurable: true,
      enumerable: false,
      get() {
        inheritedToJSONCalls += 1;
        return () => ({ forged: true });
      },
    });
    snapshot = inspectCurrentDarwinSelf(port);
  } finally {
    if (originalToJSON == null) delete Object.prototype.toJSON;
    else Object.defineProperty(Object.prototype, "toJSON", originalToJSON);
  }
  assert.equal(inheritedToJSONCalls, 0);
  assert.equal(
    snapshot.snapshot_digest,
    independentSnapshotDigest(
      "hacker-bob/darwin-native-self-identity-snapshot/v1",
      snapshot,
    ),
  );
  assert.deepEqual(Object.keys(snapshot).sort(), SELF_PROJECTION_FIELDS);
  assert.equal(snapshot.self_pid, process.pid);
  assert.equal(snapshot.self_uid, process.geteuid());
  assert.equal(snapshot.self_gid, process.getegid());
  assert.equal(snapshot.self_real_uid, process.getuid());
  assert.equal(snapshot.self_real_gid, process.getgid());
  assert.equal(snapshot.production_ready, false);
  assert.deepEqual(snapshot.production_blockers, EXPECTED_BLOCKERS);
  assert.equal(snapshot.native_loaded_image_file_sha256,
    snapshot.native_binding_implementation_digest);
  assert.equal(snapshot.native_loaded_image_dyld_header_unique, true);
  assert.equal(snapshot.native_loaded_image_dladdr_base_matches_dyld, true);
  assert.equal(snapshot.native_loaded_image_dyld_snapshot_stable, true);
  assert.equal(snapshot.native_loaded_image_dyld_canonical_path_matches_dladdr, true);
  assert.equal(snapshot.native_loaded_image_callback_in_executable_segment, true);
  assert.equal(snapshot.native_loaded_image_header_and_load_commands_match_file, true);
  assert.equal(snapshot.native_loaded_image_executable_segments_match_file, true);
  assert.equal(snapshot.native_loaded_image_executable_pages_read_execute_only, true);
  assert.equal(
    snapshot.native_loaded_image_executable_segment_file_size_equals_vm_size,
    true,
  );
  assert.equal(snapshot.native_loaded_image_executable_identity_complete, true);
  assert.equal(snapshot.native_loaded_image_non_executable_runtime_state_measured, false);
  assert.equal(snapshot.native_loaded_image_full_runtime_state_identity_complete, false);
  assert.equal(snapshot.native_loaded_image_signed_immutable_delivery_verified, false);
  assert.equal(snapshot.self_code_identity_audit_token_bound, true);
  assert.equal(snapshot.self_code_identity_seccode_self_cross_checked, true);
  assert.equal(snapshot.self_code_identity_stable, true);
  assert.equal(snapshot.self_code_dynamic_validity, "valid");
  assert.match(snapshot.self_code_directory_hash, CODE_DIRECTORY_HASH_PATTERN);
  for (const field of [
    "native_binding_implementation_digest",
    "native_loaded_image_identity_digest",
    "native_loaded_image_canonical_path_digest",
    "native_loaded_image_file_identity_digest",
    "native_loaded_image_lc_uuid_digest",
    "native_loaded_image_header_and_load_commands_digest",
    "native_loaded_image_executable_segments_digest",
    "self_audit_token_digest",
    "self_process_start_token_digest",
    "self_executable_path_digest",
    "self_code_directory_hashes_digest",
    "self_code_signing_identifier_digest",
    "self_code_team_identifier_digest",
    "self_code_certificate_chain_digest",
    "self_code_designated_requirement_digest",
    "self_code_static_flags_digest",
    "self_code_dynamic_status_digest",
    "self_code_signing_identity_digest",
    "self_mapped_code_identity_digest",
    "snapshot_digest",
  ]) assert.match(snapshot[field], DIGEST_PATTERN, field);
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(Object.isFrozen(snapshot.production_blockers), true);
  const serialized = JSON.stringify(snapshot);
  assert.equal(serialized.includes(process.execPath), false);
  assert.equal(serialized.includes(os.homedir()), false);
  assert.equal(serialized.includes("audit_token_t"), false);
  assert.equal(serialized.includes("signing_identifier\":"), false);
  assert.equal(serialized.includes("team_identifier\":"), false);

  assert.throws(
    () => inspectCurrentDarwinSelf(port),
    assertSafeSelfRejection,
  );
  delete require.cache[require.resolve(MODULE_PATH)];
  const reloaded = require(MODULE_PATH);
  const reloadedPort = reloaded.createDarwinNativeSelfIdentityInspector({
    adapter_id: "self_after_reload",
  });
  assert.throws(
    () => reloaded.inspectCurrentDarwinSelf(reloadedPort),
    assertSafeSelfRejection,
  );
});

test("signing identity is stable while process-instance bindings change", () => {
  const first = inspectInFreshProcess();
  const second = inspectInFreshProcess();
  for (const field of [
    "native_loaded_image_identity_digest",
    "native_loaded_image_file_sha256",
    "native_loaded_image_lc_uuid_digest",
    "native_loaded_image_executable_segments_digest",
    "self_code_directory_hash",
    "self_code_directory_hash_algorithm",
    "self_code_directory_hashes_digest",
    "self_code_signing_identifier_digest",
    "self_code_team_identifier_state",
    "self_code_team_identifier_digest",
    "self_code_certificate_chain_state",
    "self_code_certificate_count",
    "self_code_certificate_chain_digest",
    "self_code_designated_requirement_digest",
    "self_code_static_flags_digest",
    "self_code_signing_identity_digest",
  ]) assert.equal(first[field], second[field], field);
  assert.notEqual(first.self_pid, second.self_pid);
  assert.notEqual(first.self_audit_token_digest, second.self_audit_token_digest);
  assert.notEqual(
    first.self_process_start_token_digest,
    second.self_process_start_token_digest,
  );
  assert.notEqual(
    first.self_mapped_code_identity_digest,
    second.self_mapped_code_identity_digest,
  );
  assert.notEqual(first.snapshot_digest, second.snapshot_digest);
});

test("native self snapshots have an exact closed schema and raw repeatability stays explicit", () => {
  const binding = require(BINDING_PATH);
  const first = binding.inspectCurrentSelf();
  const second = binding.inspectCurrentSelf();
  assert.deepEqual(Object.keys(first).sort(), RAW_NATIVE_SELF_FIELDS);
  assert.deepEqual(first, second);
  for (const field of RAW_NATIVE_SELF_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(first, field);
    assert.equal(descriptor.writable, false, field);
    assert.equal(descriptor.configurable, false, field);
    assert.equal(descriptor.enumerable, true, field);
    assert.equal(Object.hasOwn(descriptor, "get"), false, field);
  }
  assert.equal(first.self_pid, process.pid);
  assert.equal(first.self_euid, process.geteuid());
  assert.equal(first.self_egid, process.getegid());
  assert.throws(
    () => binding.inspectCurrentSelf(1),
    (error) => error?.code === "darwin_native_self_inspection_failed"
      && error?.message === "Darwin native self inspection failed",
  );
});
