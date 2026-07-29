"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");
const CHAMELEON_ROOT = path.resolve(ROOT, "..", "bob-instrument-chameleon");
const {
  BOOTSTRAP_INVARIANTS_DIGEST,
  CHAMELEON_BOOTSTRAP_MANIFEST,
  CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY,
} = require(path.join(CHAMELEON_ROOT, "lib", "bootstrap-operations.js"));
const {
  CHAMELEON_SEMANTIC_MANIFEST,
  CHAMELEON_V220_SOURCE_PROFILE,
} = require(path.join(CHAMELEON_ROOT, "lib", "operations.js"));
const {
  CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS,
} = require("../lib/generated-bootstrap-semantics.js");
const CUSTODIAN = require("../lib/native-dispatch-custodian.js");

function sha256File(filename) {
  return crypto.createHash("sha256").update(fs.readFileSync(filename)).digest("hex");
}

function pair() {
  return crypto.generateKeyPairSync("ed25519");
}

function launcherPayload(overrides = {}) {
  const launcher = pair();
  const dispatch = pair();
  const launcherSpki = launcher.publicKey.export({ type: "spki", format: "der" });
  const dispatchSpki = dispatch.publicKey.export({ type: "spki", format: "der" });
  const inventory = CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.operations.find(
    (operation) => operation.operation_id === "instrument.inventory",
  );
  const digest = (label) => crypto.createHash("sha256").update(label).digest("hex");
  return {
    launcher,
    payload: {
      version: 1,
      fixture_only: true,
      worker_uid: process.getuid(),
      worker_gid: process.getgid(),
      execution_principal_id: "principal:fixture-native-bootstrap",
      worker_process_start_digest: digest("worker-process-start"),
      worker_bundle_digest: digest("worker-bundle"),
      native_loaded_image_identity_digest: digest("native-image"),
      provider_id: "chameleon_ultra",
      provider_descriptor_digest: digest("provider-descriptor"),
      provider_implementation_digest: digest("provider-implementation"),
      semantic_manifest_digest: CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.semantic_manifest_digest,
      device_identity_digest: digest("device-identity"),
      device_enrollment_digest: digest("device-enrollment"),
      connection_generation: "1",
      launcher_ticket_digest: digest("launcher-ticket"),
      device_descriptor_inventory_digest: digest("device-descriptor-inventory"),
      delegated_descriptor_identity_digest: digest("delegated-descriptor"),
      clock_epoch_digest: digest("clock-epoch"),
      dispatch_key_id: "dispatch-key:fixture-native-bootstrap",
      dispatch_public_key_digest: crypto.createHash("sha256").update(dispatchSpki).digest("hex"),
      launcher_public_key_spki_der: launcherSpki,
      dispatch_public_key_spki_der: dispatchSpki,
      launch_nonce: Buffer.alloc(24, 3).toString("base64url"),
      execution_lineage_digest: digest("execution-lineage"),
      vault_reservation_digest: digest("vault-reservation"),
      vault_ingest_capability_digest: digest("vault-ingest"),
      vault_sink_descriptor_identity_digest: digest("vault-sink"),
      vault_byte_ceiling: 4096,
      artifact_handle_digest: digest("artifact-handle"),
      bootstrap_manifest_digest: CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.bootstrap_manifest_digest,
      bootstrap_operation_registry_digest:
        CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.bootstrap_operation_registry_digest,
      bootstrap_command_set_digest: inventory.command_set_digest,
      native_bootstrap_semantic_table_digest:
        CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.table_digest,
      bootstrap_invariants_digest:
        CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.bootstrap_invariants_digest,
      ...overrides,
    },
  };
}

test("generated native bootstrap table is an exact source-pinned projection", () => {
  const table = CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS;
  assert.equal(table.provider_id, "chameleon_ultra");
  assert.equal(table.semantic_manifest_digest, CHAMELEON_SEMANTIC_MANIFEST.manifest_digest);
  assert.equal(table.bootstrap_manifest_digest, CHAMELEON_BOOTSTRAP_MANIFEST.manifest_digest);
  assert.equal(table.bootstrap_operation_registry_digest,
    CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.registry_digest);
  assert.equal(table.bootstrap_invariants_digest, BOOTSTRAP_INVARIANTS_DIGEST);
  assert.equal(table.source_profile_digest, CHAMELEON_V220_SOURCE_PROFILE.source_profile_digest);
  assert.equal(table.upstream_declaration_source_sha256,
    CHAMELEON_V220_SOURCE_PROFILE.declaration_source_sha256);
  assert.equal(table.upstream_registry_source_sha256,
    CHAMELEON_V220_SOURCE_PROFILE.registry_source_sha256);
  assert.equal(table.local_bootstrap_source_sha256, sha256File(path.join(
    CHAMELEON_ROOT, "lib", "bootstrap-operations.js",
  )));
  assert.equal(table.local_operations_source_sha256, sha256File(path.join(
    CHAMELEON_ROOT, "lib", "operations.js",
  )));
  assert.deepEqual(Object.fromEntries(table.operations.map((operation) => [
    operation.operation_id,
    operation.commands.map((command) => command.command_id),
  ])), {
    "instrument.capabilities": [1035],
    "instrument.health": [1025],
    "instrument.inventory": [1000, 1017, 1033],
  });
  for (const operation of table.operations) {
    const source = CHAMELEON_BOOTSTRAP_MANIFEST.operations.find(
      (entry) => entry.operation_id === operation.operation_id,
    );
    assert.equal(operation.operation_digest, source.operation_digest);
    assert.equal(operation.command_set_digest, source.command_set_digest);
    assert.deepEqual(operation.commands.map((command) => command.command_sequence),
      Array.from({ length: operation.commands.length }, (_, index) => index + 1));
    assert.ok(operation.commands.every((command) => (
      command.request_payload_byte_length === 0 && command.request_frame_byte_length === 10
    )));
  }
});

test("generated C++ table contains the exact closed operation surface", () => {
  const source = fs.readFileSync(path.join(ROOT, "native",
    "generated_bootstrap_semantics.h"), "utf8");
  for (const operation of CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS.operations) {
    assert.match(source, new RegExp(operation.operation_id.replace(".", "\\."), "u"));
    for (const command of operation.commands) {
      assert.match(source, new RegExp(`\\b${command.command_id}U\\b`, "u"));
    }
  }
  for (const forbidden of [1001, 1002, 4000, 6004, 65535]) {
    assert.doesNotMatch(source, new RegExp(`\\b${forbidden}U\\b`, "u"));
  }
  assert.match(source, /kSemanticManifestDigest/u);
  assert.match(source, /kBootstrapManifestDigest/u);
  assert.match(source, /kBootstrapOperationRegistryDigest/u);
  assert.match(source, /kNativeSemanticTableDigest/u);
});

test("launcher context refuses generated manifest, registry, set, and table drift", () => {
  const valid = launcherPayload();
  assert.doesNotThrow(() => CUSTODIAN.signNativeDispatchLauncherContext({
    payload: valid.payload,
    launcher_key_id: "launcher-key:fixture-native-bootstrap",
    launcher_private_key: valid.launcher.privateKey,
  }));
  for (const field of [
    "bootstrap_manifest_digest",
    "bootstrap_operation_registry_digest",
    "bootstrap_command_set_digest",
    "native_bootstrap_semantic_table_digest",
    "bootstrap_invariants_digest",
  ]) {
    const fixture = launcherPayload({ [field]: "0".repeat(64) });
    assert.throws(() => CUSTODIAN.signNativeDispatchLauncherContext({
      payload: fixture.payload,
      launcher_key_id: "launcher-key:fixture-native-bootstrap",
      launcher_private_key: fixture.launcher.privateKey,
    }), (error) => error.code === "darwin_native_dispatch_custodian_contract_rejected", field);
  }
});

test("sequence module import is inert and exposes no transport or effect surface", () => {
  const sequence = require("../lib/native-bootstrap-sequence.js");
  assert.equal(sequence.NATIVE_BOOTSTRAP_SEQUENCE_ASSURANCE.import_is_inert, true);
  assert.equal(sequence.NATIVE_BOOTSTRAP_SEQUENCE_ASSURANCE.device_enumeration, false);
  assert.equal(sequence.NATIVE_BOOTSTRAP_SEQUENCE_ASSURANCE.device_open, false);
  assert.equal(sequence.NATIVE_BOOTSTRAP_SEQUENCE_ASSURANCE.network_access, false);
  assert.equal(sequence.NATIVE_BOOTSTRAP_SEQUENCE_ASSURANCE.usb_access, false);
  assert.equal(sequence.NATIVE_BOOTSTRAP_SEQUENCE_ASSURANCE.hardware_effect, false);
  for (const effectName of ["enumerate", "open", "read", "write", "dispatch", "spawn"] ) {
    assert.equal(typeof sequence[effectName], "undefined");
  }
  assert.throws(() => sequence.createNativeBootstrapSequenceGuard(Object.freeze({})),
    (error) => error.code === "chameleon_native_bootstrap_sequence_rejected"
      && error.reason_code === "compiled_operation_brand_invalid");
});
