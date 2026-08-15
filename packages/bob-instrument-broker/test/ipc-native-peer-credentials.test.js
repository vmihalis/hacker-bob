"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");
const {
  NATIVE_IPC_PEER_CREDENTIAL_SNAPSHOT_DOMAIN,
  PLATFORM_PROFILES,
  assertConformanceNativeIpcPeerCredentialAdapter,
  createConformanceNativeIpcPeerCredentialAdapter,
  inspectAcceptedSocketWithConformanceAdapter,
  normalizeNativeIpcPeerCredentialSnapshot,
} = require("../lib/ipc-native-peer-credentials.js");

function digest(label) {
  return hashCanonicalJson({ label });
}

function nonce() {
  return crypto.randomBytes(18).toString("base64url");
}

function snapshot(overrides = {}) {
  const profile = PLATFORM_PROFILES[process.platform] || PLATFORM_PROFILES.linux;
  const bindingNonce = overrides.socket_binding_nonce || nonce();
  const basis = {
    version: 1,
    credential_source: "native_os_socket",
    platform: process.platform in PLATFORM_PROFILES ? process.platform : "linux",
    primitive: profile.primitive,
    socket_binding_nonce: bindingNonce,
    peer_uid: 501,
    peer_gid: 20,
    peer_pid: 4123,
    peer_process_start_token_digest: digest("process-start-token"),
    peer_executable_measurement_scheme: profile.executable_measurement_scheme,
    peer_executable_measurement_digest: digest("executable-measurement"),
    ...overrides,
  };
  return {
    basis,
    value: {
      ...basis,
      snapshot_digest: hashCanonicalJson({
        domain: NATIVE_IPC_PEER_CREDENTIAL_SNAPSHOT_DOMAIN,
        snapshot: basis,
      }),
    },
  };
}

test("native peer snapshot is closed, socket-bound, profile-bound, and digest-bound", () => {
  const fixture = snapshot();
  const expected = {
    platform: fixture.basis.platform,
    primitive: fixture.basis.primitive,
    socket_binding_nonce: fixture.basis.socket_binding_nonce,
    peer_executable_measurement_scheme:
      fixture.basis.peer_executable_measurement_scheme,
  };
  const normalized = normalizeNativeIpcPeerCredentialSnapshot(fixture.value, expected);
  assert.equal(Object.isFrozen(normalized), true);
  assert.equal(normalized.peer_pid, 4123);
  assert.match(normalized.snapshot_digest, /^[a-f0-9]{64}$/);

  for (const [label, mutate] of [
    ["socket nonce", (value) => { value.socket_binding_nonce = nonce(); }],
    ["platform primitive", (value) => { value.primitive = "advisory_process_lookup"; }],
    ["credential source", (value) => { value.credential_source = "caller_claim"; }],
    ["snapshot digest", (value) => { value.snapshot_digest = digest("wrong"); }],
    ["process-start token", (value) => { value.peer_process_start_token_digest = digest("drift"); }],
    ["executable measurement", (value) => { value.peer_executable_measurement_digest = digest("drift"); }],
  ]) {
    const drift = structuredClone(fixture.value);
    mutate(drift);
    assert.throws(
      () => normalizeNativeIpcPeerCredentialSnapshot(drift, expected),
      undefined,
      label,
    );
  }

  for (const advisoryField of ["socket_path", "remote_address", "process_claim", "argv"]) {
    const drift = structuredClone(fixture.value);
    drift[advisoryField] = "untrusted";
    assert.throws(
      () => normalizeNativeIpcPeerCredentialSnapshot(drift, expected),
      /unknown fields/,
    );
  }
});

test("adapter is private, inert at construction, platform-exact, and explicitly non-production", () => {
  if (!PLATFORM_PROFILES[process.platform]) return;
  const profile = PLATFORM_PROFILES[process.platform];
  let inspections = 0;
  const adapter = createConformanceNativeIpcPeerCredentialAdapter({
    adapter_id: "private_native_peer_adapter",
    platform: process.platform,
    primitive: profile.primitive,
    executable_measurement_scheme: profile.executable_measurement_scheme,
    native_binding_implementation_digest: digest("native-binding-implementation"),
    inspect_accepted_socket: () => {
      inspections += 1;
      throw new Error("not reached");
    },
  });
  assert.equal(inspections, 0);
  assert.equal(Object.isFrozen(adapter), true);
  assert.equal(adapter.production_attested, false);
  assert.equal(adapter.credential_source, "native_kernel_adapter_conformance");
  assert.doesNotMatch(JSON.stringify(adapter), /inspect_accepted_socket|function/);
  assert.equal(assertConformanceNativeIpcPeerCredentialAdapter(adapter), adapter);
  assert.throws(
    () => assertConformanceNativeIpcPeerCredentialAdapter({ ...adapter }),
    /privately branded/,
  );
  assert.throws(
    () => inspectAcceptedSocketWithConformanceAdapter(adapter, {}, nonce()),
    /live accepted net.Socket/,
  );
  assert.equal(inspections, 0);

  assert.throws(() => createConformanceNativeIpcPeerCredentialAdapter({
    adapter_id: "wrong_native_peer_adapter",
    platform: process.platform,
    primitive: process.platform === "linux"
      ? PLATFORM_PROFILES.darwin.primitive
      : PLATFORM_PROFILES.linux.primitive,
    executable_measurement_scheme: profile.executable_measurement_scheme,
    native_binding_implementation_digest: digest("wrong-native-binding"),
    inspect_accepted_socket: () => null,
  }), /running platform profile/);
});

