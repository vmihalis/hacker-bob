"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const ble = require("../lib/ble.js");
const operations = require("../lib/operations.js");

const {
  BLE_NUS_CAPABILITY_ID,
  BLE_NUS_DEPENDENCY_REF,
  BLE_NUS_ENDPOINT_KIND,
  BLE_NUS_FORBIDDEN_ENDPOINT_KINDS,
  BLE_NUS_MAXIMUM_ATT_MTU,
  BLE_NUS_MINIMUM_ATT_MTU,
  BLE_NUS_READINESS_BLOCKERS,
  BLE_NUS_RX_CHARACTERISTIC_UUID,
  BLE_NUS_SERVICE_UUID,
  BLE_NUS_TRANSPORT_ID,
  BLE_NUS_TRANSPORT_VERSION,
  BLE_NUS_TX_CHARACTERISTIC_UUID,
  assertBleNusConformanceResult,
  bleNusTransportContract,
  createBleNusTransportSwitchPlan,
  createInertBleNusConformanceSession,
  createTestBleNusAuthorityResolverPort,
  getBleNusConformanceVector,
  inspectInertBleNusConformanceSession,
  normalizeBleNusEnrollment,
  normalizeBleNusPairingPosture,
  runInertBleNusConformanceVector,
} = ble;

function digest(label) {
  return crypto.createHash("sha256").update(label, "utf8").digest("hex");
}

function enrollment(overrides = {}) {
  return normalizeBleNusEnrollment({
    version: 1,
    enrollment_id: "ble-enrollment:fixture-1",
    device_identity_digest: digest("device-identity"),
    peripheral_identifier_digest: digest("corebluetooth-peripheral-id"),
    endpoint_kind: BLE_NUS_ENDPOINT_KIND,
    identity_provenance: "operator_enrolled_corebluetooth_peripheral_service_set",
    ...overrides,
  });
}

function pairing(deviceIdentityDigest, overrides = {}) {
  return normalizeBleNusPairingPosture({
    version: 1,
    observation_ref: "pairing-observation:fixture-1",
    device_identity_digest: deviceIdentityDigest,
    observed_at_monotonic_ns: "100",
    pairing_required: true,
    link_encrypted: true,
    bond_present: true,
    enrolled_bond_match: true,
    secure_connections: true,
    ...overrides,
  });
}

function authorityBinding(enrolled, overrides = {}) {
  return {
    version: 1,
    broker_ref: "broker:physical-fixture",
    session_nucleus_hash: digest("session-nucleus"),
    execution_lineage_digest: digest("execution-lineage"),
    grant_envelope_digest: digest("grant-envelope"),
    grant_journal_entry_digest: digest("grant-journal"),
    execution_claim_receipt_digest: digest("execution-claim-receipt"),
    deadline_fence_receipt_digest: digest("deadline-fence-receipt"),
    task_id: "task:ble-conformance",
    attempt_id: "attempt:ble-conformance-1",
    lease_id: "lease:physical-device-1",
    resource_epoch: "7",
    resource_fence_digest: digest("resource-fence"),
    effect_deadline_monotonic_ns: "10000",
    worker_fence_digest: digest("worker-fence"),
    transport_binding_digest: digest("transport-binding"),
    authorized_transport_set_digest: digest("authorized-usb-ble-set"),
    transport_switch_fence_digest: digest("transport-switch-fence"),
    device_enrollment_digest: enrolled.enrollment_digest,
    device_identity_digest: enrolled.device_identity_digest,
    authority_epoch: 4,
    revocation_generation: 2,
    ...overrides,
  };
}

function currentAuthority(binding, overrides = {}) {
  return {
    ...binding,
    current_monotonic_ns: "500",
    trusted: true,
    revoked: false,
    lease_live: true,
    resource_fence_live: true,
    deadline_live: true,
    transport_switch_allowed: true,
    ...overrides,
  };
}

function planInput(binding, overrides = {}) {
  return {
    version: 1,
    authority_binding: binding,
    from_transport_id: "usb_cdc_acm_115200_dtr_v1",
    to_transport_id: BLE_NUS_TRANSPORT_ID,
    previous_connection_generation: 8,
    next_connection_generation: 9,
    previous_transport_terminal_state: "closed_confirmed",
    previous_transport_terminal_receipt_digest: digest("usb-terminal-receipt"),
    previous_transport_fence_digest: digest("usb-generation-fence"),
    outstanding_transaction_count: 0,
    ...overrides,
  };
}

function fixture({
  mtu = 23,
  pairingOverrides = {},
  bindingOverrides = {},
  resolver,
  planOverrides = {},
} = {}) {
  const enrolled = enrollment();
  const binding = authorityBinding(enrolled, bindingOverrides);
  const calls = [];
  const port = createTestBleNusAuthorityResolverPort({
    version: 1,
    port_id: "ble-authority-port:fixture-1",
    test_only: true,
    resolve_current_authority(query) {
      calls.push(query);
      return resolver ? resolver(query, calls.length, binding) : currentAuthority(binding);
    },
  });
  const switchPlan = createBleNusTransportSwitchPlan(planInput(binding, planOverrides), port);
  const pairingPosture = pairing(enrolled.device_identity_digest, pairingOverrides);
  const session = pairingPosture.secure_pairing_posture
    ? createInertBleNusConformanceSession({
      version: 1,
      switch_plan: switchPlan,
      enrollment: enrolled,
      pairing_posture: pairingPosture,
      negotiated_att_mtu: mtu,
    }, port)
    : null;
  return { binding, calls, enrolled, pairingPosture, port, session, switchPlan };
}

test("BLE NUS contract is derived from the closed provider registry and remains inert", () => {
  assert.deepEqual(Object.keys(ble).sort(), [
    "BLE_NUS_CAPABILITY_ID",
    "BLE_NUS_DEPENDENCY_REF",
    "BLE_NUS_ENDPOINT_KIND",
    "BLE_NUS_FORBIDDEN_ENDPOINT_KINDS",
    "BLE_NUS_MAXIMUM_ATT_MTU",
    "BLE_NUS_MINIMUM_ATT_MTU",
    "BLE_NUS_READINESS_BLOCKERS",
    "BLE_NUS_RX_CHARACTERISTIC_UUID",
    "BLE_NUS_SERVICE_UUID",
    "BLE_NUS_TRANSPORT_ID",
    "BLE_NUS_TRANSPORT_VERSION",
    "BLE_NUS_TX_CHARACTERISTIC_UUID",
    "assertBleNusConformanceResult",
    "bleNusTransportContract",
    "createBleNusTransportSwitchPlan",
    "createInertBleNusConformanceSession",
    "createTestBleNusAuthorityResolverPort",
    "getBleNusConformanceVector",
    "inspectInertBleNusConformanceSession",
    "normalizeBleNusEnrollment",
    "normalizeBleNusPairingPosture",
    "runInertBleNusConformanceVector",
  ].sort());
  for (const forbidden of [
    "connect", "disconnect", "discover", "enumerate", "open", "read", "write",
    "sendFrame", "sendRaw", "setPairingKey", "deleteBonds",
  ]) {
    assert.equal(Object.hasOwn(ble, forbidden), false, forbidden);
  }
  const contract = bleNusTransportContract();
  const capability = operations.getChameleonCapability(BLE_NUS_CAPABILITY_ID);
  const variant = operations.getChameleonAvailabilityVariant(BLE_NUS_CAPABILITY_ID, "default");
  const dependency = operations.dependencyProofContract(BLE_NUS_DEPENDENCY_REF);
  assert.equal(contract.capability_coverage_row_digest, capability.coverage_row_digest);
  assert.equal(contract.availability_variant_digest, variant.availability_variant_digest);
  assert.equal(contract.dependency_contract_digest, dependency.contract_digest);
  assert.equal(contract.semantic_manifest_digest,
    operations.CHAMELEON_SEMANTIC_MANIFEST.manifest_digest);
  assert.deepEqual(contract.normalized_operations.map((entry) => entry.operation_id).sort(), [
    "transport.connect", "transport.disconnect", "transport.exchange",
  ]);
  assert.ok(contract.normalized_operations.every((entry) => entry.exposure === "provider_private"));
  assert.equal(contract.evaluator_callable, false);
  assert.equal(contract.raw_ble_surface_exposed, false);
  assert.equal(contract.raw_frame_surface_exposed, false);
  assert.equal(contract.pairing_key_surface_exposed, false);
  assert.equal(contract.bond_admin_surface_exposed, false);
  assert.equal(contract.live_connect_exported, false);
  assert.equal(contract.bluetooth_pseudo_serial_allowed, false);
  assert.equal(contract.production_ready, false);
  assert.equal(contract.execution_authority, false);
  assert.deepEqual(contract.readiness_blockers, BLE_NUS_READINESS_BLOCKERS);
  for (const blocker of [
    "native_corebluetooth_custody_not_implemented",
    "dedicated_privileged_ble_principal_not_enrolled",
    "durable_ble_identity_and_bond_store_not_implemented",
    "rf_off_ble_nus_hil_not_recorded",
    "usb_ble_safe_state_parity_hil_not_recorded",
    "usb_ble_target_effect_parity_deferred_to_ph_x5",
  ]) assert.ok(BLE_NUS_READINESS_BLOCKERS.includes(blocker), blocker);
});

test("enrollment accepts only fixed NUS UUIDs behind CoreBluetooth and rejects pseudo-serial", () => {
  const value = enrollment();
  assert.equal(value.service_uuid, BLE_NUS_SERVICE_UUID);
  assert.equal(value.central_write_characteristic_uuid, BLE_NUS_RX_CHARACTERISTIC_UUID);
  assert.equal(value.peripheral_notify_characteristic_uuid, BLE_NUS_TX_CHARACTERISTIC_UUID);
  assert.equal(value.arbitrary_uuid_allowed, false);
  assert.equal(value.serial_path_allowed, false);
  assert.equal(value.bluetooth_pseudo_serial_allowed, false);
  assert.equal(value.production_ready, false);
  assert.deepEqual(BLE_NUS_FORBIDDEN_ENDPOINT_KINDS, [
    "serial_path", "bluetooth_pseudo_serial", "iokit_tty", "usb_cdc_path",
  ]);
  for (const endpoint_kind of BLE_NUS_FORBIDDEN_ENDPOINT_KINDS) {
    assert.throws(() => enrollment({ endpoint_kind }), /pseudo-serial|CoreBluetooth/u);
  }
  assert.throws(() => normalizeBleNusEnrollment({
    version: 1,
    enrollment_id: "ble-enrollment:fixture-1",
    device_identity_digest: digest("device-identity"),
    peripheral_identifier_digest: digest("corebluetooth-peripheral-id"),
    endpoint_kind: BLE_NUS_ENDPOINT_KIND,
    identity_provenance: "operator_enrolled_corebluetooth_peripheral_service_set",
    serial_path: "/dev/cu.DPill",
  }), /unknown fields: serial_path/u);
  assert.throws(() => normalizeBleNusEnrollment({
    version: 1,
    enrollment_id: "ble-enrollment:fixture-1",
    device_identity_digest: digest("device-identity"),
    peripheral_identifier_digest: digest("corebluetooth-peripheral-id"),
    endpoint_kind: BLE_NUS_ENDPOINT_KIND,
    identity_provenance: "operator_enrolled_corebluetooth_peripheral_service_set",
    service_uuid: "attacker-selected",
  }), /unknown fields: service_uuid/u);
});

test("pairing posture reports insecurity without accepting or exposing a key", () => {
  const enrolled = enrollment();
  const secure = pairing(enrolled.device_identity_digest);
  assert.equal(secure.classification, "secure_enrolled_bond");
  assert.equal(secure.secure_pairing_posture, true);
  assert.equal(secure.pairing_secret_disposition, "not_collected_redacted_at_native_boundary");
  assert.equal(secure.pairing_key_exposed, false);
  assert.equal(secure.bond_admin_exposed, false);
  assert.doesNotMatch(JSON.stringify(secure), /pairing_key\s*[:=]\s*["']?[0-9]/u);
  const insecure = pairing(enrolled.device_identity_digest, { pairing_required: false });
  assert.equal(insecure.classification, "insecure_pairing_not_required");
  assert.equal(insecure.secure_pairing_posture, false);
  assert.equal(insecure.operator_action_required, true);
  assert.throws(() => normalizeBleNusPairingPosture({
    version: 1,
    observation_ref: "pairing-observation:fixture-1",
    device_identity_digest: enrolled.device_identity_digest,
    observed_at_monotonic_ns: "100",
    pairing_required: true,
    link_encrypted: true,
    bond_present: true,
    enrolled_bond_match: true,
    secure_connections: true,
    pairing_key: "123456",
  }), /unknown fields: pairing_key/u);
  assert.throws(() => normalizeBleNusPairingPosture(new Proxy({}, {})), /plain synchronous/u);
});

test("switch plan preserves the exact broker lease/fences and fences the prior generation", () => {
  const value = fixture();
  assert.equal(value.switchPlan.execution_lineage_digest, value.binding.execution_lineage_digest);
  assert.equal(value.switchPlan.lease_id, value.binding.lease_id);
  assert.equal(value.switchPlan.resource_epoch, value.binding.resource_epoch);
  assert.equal(value.switchPlan.resource_fence_digest, value.binding.resource_fence_digest);
  assert.equal(value.switchPlan.worker_fence_digest, value.binding.worker_fence_digest);
  assert.equal(value.switchPlan.from_transport_id, "usb_cdc_acm_115200_dtr_v1");
  assert.equal(value.switchPlan.to_transport_id, BLE_NUS_TRANSPORT_ID);
  assert.equal(value.switchPlan.previous_connection_generation, 8);
  assert.equal(value.switchPlan.next_connection_generation, 9);
  assert.equal(value.switchPlan.lease_preserved, true);
  assert.equal(value.switchPlan.previous_generation_fenced, true);
  assert.equal(value.switchPlan.activation_authority, false);
  assert.equal(value.switchPlan.production_ready, false);
  assert.equal(value.calls[0].execution_lineage_digest, value.binding.execution_lineage_digest);
  assert.equal(value.calls[0].lease_id, value.binding.lease_id);
  assert.equal(value.calls[0].resource_fence_digest, value.binding.resource_fence_digest);
  assert.equal(value.calls[0].transport_contract_digest,
    bleNusTransportContract().transport_contract_digest);
});

test("switch planning rejects generation skips, active transactions, unclosed USB and replay", () => {
  const enrolled = enrollment();
  const binding = authorityBinding(enrolled);
  const port = createTestBleNusAuthorityResolverPort({
    version: 1,
    port_id: "ble-authority-port:fixture-2",
    test_only: true,
    resolve_current_authority: () => currentAuthority(binding),
  });
  assert.throws(() => createBleNusTransportSwitchPlan(planInput(binding, {
    next_connection_generation: 10,
  }), port), /increment the connection generation exactly once/u);
  assert.throws(() => createBleNusTransportSwitchPlan(planInput(binding, {
    outstanding_transaction_count: 1,
  }), port), /outstanding transaction/u);
  assert.throws(() => createBleNusTransportSwitchPlan(planInput(binding, {
    previous_transport_terminal_state: "disconnecting",
  }), port), /confirmed terminal state/u);
  const plan = createBleNusTransportSwitchPlan(planInput(binding), port);
  assert.ok(plan.switch_plan_digest);
  assert.throws(
    () => createBleNusTransportSwitchPlan(planInput(binding), port),
    /generation_replayed/u,
  );
});

test("insecure posture and device/enrollment drift cannot create a conformance session", () => {
  const enrolled = enrollment();
  const binding = authorityBinding(enrolled);
  const port = createTestBleNusAuthorityResolverPort({
    version: 1,
    port_id: "ble-authority-port:fixture-3",
    test_only: true,
    resolve_current_authority: () => currentAuthority(binding),
  });
  const switchPlan = createBleNusTransportSwitchPlan(planInput(binding), port);
  assert.throws(() => createInertBleNusConformanceSession({
    version: 1,
    switch_plan: switchPlan,
    enrollment: enrolled,
    pairing_posture: pairing(enrolled.device_identity_digest, { link_encrypted: false }),
    negotiated_att_mtu: 23,
  }, port), /pairing_posture_refused:insecure_link_unencrypted/u);

  const enrolled2 = enrollment({
    enrollment_id: "ble-enrollment:fixture-2",
    device_identity_digest: digest("different-device"),
    peripheral_identifier_digest: digest("different-peripheral"),
  });
  const port2 = createTestBleNusAuthorityResolverPort({
    version: 1,
    port_id: "ble-authority-port:fixture-4",
    test_only: true,
    resolve_current_authority: () => currentAuthority(binding),
  });
  const plan2 = createBleNusTransportSwitchPlan(planInput(binding, {
    previous_connection_generation: 9,
    next_connection_generation: 10,
  }), port2);
  assert.throws(() => createInertBleNusConformanceSession({
    version: 1,
    switch_plan: plan2,
    enrollment: enrolled2,
    pairing_posture: pairing(enrolled2.device_identity_digest),
    negotiated_att_mtu: 23,
  }, port2), /device_identity_or_enrollment_drift/u);
});

test("closed vectors prove exact MTU boundary fragmentation and maximum reassembly", () => {
  const cases = [
    ["two_fragments_exact_v1", 23, 40, 2],
    ["two_fragments_plus_one_v1", 23, 41, 3],
    ["maximum_codec_frame_v1", 23, 4106, 206],
    ["two_fragments_plus_one_v1", 517, 1029, 3],
  ];
  for (const [vectorId, mtu, frameBytes, fragmentCount] of cases) {
    const value = fixture({ mtu });
    const result = runInertBleNusConformanceVector(value.session, {
      version: 1,
      vector_id: vectorId,
      fault: "none",
    });
    assert.equal(assertBleNusConformanceResult(result), result);
    assert.equal(result.disposition, "passed");
    assert.equal(result.terminal_code, "inert_fragmentation_reassembly_conformant");
    assert.equal(result.frame_byte_length, frameBytes);
    assert.equal(result.expected_fragment_count, fragmentCount);
    assert.equal(result.observed_fragment_count, fragmentCount);
    assert.equal(result.decoded_frame_count, 1);
    assert.equal(result.parser_error_count, 0);
    assert.equal(result.original_frame_digest, result.reassembled_frame_digest);
    assert.equal(result.raw_bytes_exposed, false);
    assert.equal(result.live_connection, false);
    assert.equal(result.hardware_access_authorized, false);
    assert.equal(result.execution_authority, false);
    assert.equal(result.production_ready, false);
    assert.equal(inspectInertBleNusConformanceSession(value.session).state, "consumed");
    assert.throws(
      () => runInertBleNusConformanceVector(value.session, {
        version: 1, vector_id: vectorId, fault: "none",
      }),
      /connection_generation_consumed/u,
    );
  }
  assert.equal(getBleNusConformanceVector("unknown"), null);
  assert.deepEqual(getBleNusConformanceVector("two_fragments_exact_v1"), {
    version: 1,
    vector_id: "two_fragments_exact_v1",
    direction: "central_to_peripheral",
    sizing: "two_attribute_values_exact",
    caller_byte_input: false,
    live_transport: false,
  });
});

test("every corruption/disconnect case fences the one-shot generation with no auto-retry", () => {
  for (const [fault, terminalCode] of [
    ["drop_fragment", "fragment_count_mismatch"],
    ["duplicate_fragment", "fragment_count_mismatch"],
    ["reorder_fragments", "fragment_sequence_or_offset_mismatch"],
    ["corrupt_fragment", "fragment_digest_mismatch"],
    ["disconnect_after_fragment", "disconnect_before_reassembly"],
  ]) {
    const value = fixture();
    const result = runInertBleNusConformanceVector(value.session, {
      version: 1,
      vector_id: "two_fragments_plus_one_v1",
      fault,
    });
    assert.equal(result.disposition, "fenced", fault);
    assert.equal(result.terminal_code, terminalCode, fault);
    assert.equal(result.connection_generation_fenced, true, fault);
    assert.equal(result.automatic_retry_allowed, false, fault);
    assert.equal(result.reassembled_frame_digest, null, fault);
    assert.equal(inspectInertBleNusConformanceSession(value.session).state, "fenced", fault);
    assert.throws(
      () => runInertBleNusConformanceVector(value.session, {
        version: 1, vector_id: "two_fragments_plus_one_v1", fault: "none",
      }),
      /connection_generation_fenced/u,
    );
  }
});

test("authority revocation, rollback, async resolution, drift and deadline expiry fail closed", () => {
  for (const override of [
    { trusted: false },
    { revoked: true },
    { lease_live: false },
    { resource_fence_live: false },
    { deadline_live: false },
    { transport_switch_allowed: false },
    { current_monotonic_ns: "10000" },
  ]) {
    const enrolled = enrollment();
    const binding = authorityBinding(enrolled);
    const port = createTestBleNusAuthorityResolverPort({
      version: 1,
      port_id: `ble-authority-port:${Object.keys(override)[0]}`,
      test_only: true,
      resolve_current_authority: () => currentAuthority(binding, override),
    });
    assert.throws(
      () => createBleNusTransportSwitchPlan(planInput(binding), port),
      /authority_(?:not_live|resolution_rejected)/u,
    );
  }

  const enrolled = enrollment();
  const binding = authorityBinding(enrolled);
  const asyncPort = createTestBleNusAuthorityResolverPort({
    version: 1,
    port_id: "ble-authority-port:async",
    test_only: true,
    resolve_current_authority: async () => currentAuthority(binding),
  });
  assert.throws(
    () => createBleNusTransportSwitchPlan(planInput(binding), asyncPort),
    /must_be_synchronous/u,
  );
  const driftPort = createTestBleNusAuthorityResolverPort({
    version: 1,
    port_id: "ble-authority-port:drift",
    test_only: true,
    resolve_current_authority: () => currentAuthority(binding, {
      lease_id: "lease:substituted",
    }),
  });
  assert.throws(
    () => createBleNusTransportSwitchPlan(planInput(binding), driftPort),
    /authority_binding_drift/u,
  );
  const secretPort = createTestBleNusAuthorityResolverPort({
    version: 1,
    port_id: "ble-authority-port:secret-error",
    test_only: true,
    resolve_current_authority: () => { throw new Error("PAIRING-KEY-123456"); },
  });
  assert.throws(
    () => createBleNusTransportSwitchPlan(planInput(binding), secretPort),
    (error) => error.message === "ble_nus_authority_resolution_failed"
      && !error.message.includes("123456"),
  );
});

test("post-reassembly authority drift fences the session and cannot become a pass", () => {
  const value = fixture({
    resolver(_query, call, binding) {
      if (call < 4) return currentAuthority(binding);
      return currentAuthority(binding, { resource_fence_digest: digest("replaced-fence") });
    },
  });
  assert.throws(() => runInertBleNusConformanceVector(value.session, {
    version: 1,
    vector_id: "two_fragments_exact_v1",
    fault: "none",
  }), /authority_binding_drift/u);
  assert.equal(inspectInertBleNusConformanceSession(value.session).state, "fenced");
});

test("MTU and input surfaces are closed, synchronous, byte-free and one-shot", () => {
  assert.throws(() => fixture({ mtu: BLE_NUS_MINIMUM_ATT_MTU - 1 }), /negotiated_att_mtu/u);
  assert.throws(() => fixture({ mtu: BLE_NUS_MAXIMUM_ATT_MTU + 1 }), /negotiated_att_mtu/u);
  const value = fixture();
  assert.throws(() => runInertBleNusConformanceVector(value.session, {
    version: 1,
    vector_id: "two_fragments_exact_v1",
    fault: "none",
    bytes: Buffer.from([0x11, 0xef]),
  }), /unknown fields: bytes/u);
  assert.throws(() => runInertBleNusConformanceVector(value.session, {
    version: 1,
    vector_id: "two_fragments_exact_v1",
    fault: "none",
    frame: { command: 2010 },
  }), /unknown fields: frame/u);
  assert.throws(() => createTestBleNusAuthorityResolverPort({
    version: 1,
    port_id: "ble-authority-port:not-test",
    test_only: false,
    resolve_current_authority: () => ({}),
  }), /test_only must be literal true/u);
  assert.throws(() => createTestBleNusAuthorityResolverPort({
    version: 1,
    port_id: "ble-authority-port:transport-callback",
    test_only: true,
    resolve_current_authority: () => ({}),
    connect: () => undefined,
  }), /unknown fields: connect/u);
});

test("module import has no BLE/native dependency and no serial-path transport fallback", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "lib", "ble.js"), "utf8");
  for (const forbiddenDependency of [
    /require\(["'](?:@abandonware\/noble|noble|node-ble|serialport)["']\)/u,
    /process\.getBuiltinModule/u,
    /child_process/u,
  ]) assert.doesNotMatch(source, forbiddenDependency);
  assert.match(source, /Bluetooth pseudo-serial and arbitrary serial paths are forbidden/u);
  assert.doesNotMatch(source, /\/dev\/cu\.DPill/u);
  const contract = bleNusTransportContract();
  assert.equal(contract.endpoint_kind, "corebluetooth_service_characteristic");
  assert.equal(contract.auto_connect, false);
  assert.equal(contract.auto_reconnect, false);
  assert.equal(contract.retry_after_ambiguous_write, false);
});
