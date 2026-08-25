"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const {
  WORKER_BUNDLE_ATTESTATION_VERSION,
  WORKER_BUNDLE_AUTHORITY_STATE_DOMAIN,
  WORKER_BUNDLE_ENROLLMENT_DOMAIN,
  WORKER_BUNDLE_ENTRY_IDENTITY_DOMAIN,
  WORKER_BUNDLE_IMMUTABILITY_DOMAIN,
  WORKER_BUNDLE_IMMUTABILITY_SCHEME,
  WORKER_BUNDLE_LIVE_SNAPSHOT_DOMAIN,
  WORKER_BUNDLE_MANIFEST_DOMAIN,
  WORKER_BUNDLE_MAX_ENTRIES,
  WORKER_BUNDLE_MAX_PATH_DEPTH,
  WORKER_BUNDLE_NATIVE_ADDON_SET_DOMAIN,
  WORKER_BUNDLE_ROLES,
  WORKER_BUNDLE_STATIC_CODE_NOT_APPLICABLE_DIGEST,
  assertConformanceWorkerBundleAuthorityResolver,
  assertConformanceWorkerBundleEnrollmentSigner,
  assertConformanceWorkerBundleNativeSnapshotResolver,
  assertConformanceWorkerBundleReservationPort,
  assertVerifiedWorkerBundleEnrollment,
  createConformanceWorkerBundleAuthorityResolver,
  createConformanceWorkerBundleEnrollmentSigner,
  createConformanceWorkerBundleNativeSnapshotResolver,
  createConformanceWorkerBundleReservationPort,
  normalizeSignedWorkerBundleEnrollment,
  normalizeWorkerBundleEnrollmentPayload,
  normalizeWorkerBundleManifest,
  signWorkerBundleEnrollment,
  verifyAndReserveWorkerBundleEnrollment,
  workerBundleAuthorityStateDigest,
  workerBundleEntryIdentityDigest,
  workerBundleImmutabilityEvidenceDigest,
  workerBundleLaunchFields,
  workerBundleLiveSnapshotDigest,
  workerBundleManifestDigest,
  workerBundleReservationReceiptDigest,
} = require("../lib/worker-bundle-attestation.js");
const { hashCanonicalJson } = require("../../../mcp/core/verification/verification-contracts.js");

const FIXED_NOW = "2026-07-19T04:00:00.000Z";

function digest(label) {
  return crypto.createHash("sha256").update(`test:${label}`, "utf8").digest("hex");
}

function publicKeyDigest(key) {
  return crypto.createHash("sha256")
    .update(key.export({ type: "spki", format: "der" }))
    .digest("hex");
}

function clone(value) {
  return structuredClone(value);
}

function entry(path, purpose, index, overrides = {}) {
  const applicable = purpose === "runtime" || purpose === "native_addon";
  return {
    path,
    purpose,
    file_type: "regular_file",
    byte_size: applicable ? 4096 + index : 200 + index,
    content_digest: digest(`content-${path}`),
    owner_uid: 501,
    owner_gid: 80,
    mode: purpose === "runtime" ? 0o500 : 0o400,
    nlink: 1,
    object_identity_digest: digest(`object-${path}`),
    static_code_identity_applicable: applicable,
    static_code_identity_scheme: applicable ? "darwin_static_code_v1" : "not_applicable",
    static_code_identity_digest: applicable
      ? digest(`static-code-${path}`)
      : WORKER_BUNDLE_STATIC_CODE_NOT_APPLICABLE_DIGEST,
    static_code_identity_complete: true,
    ...overrides,
  };
}

function manifestFor(role = "active_device_worker") {
  return {
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    bundle_id: `worker-bundle:${role}-v1`,
    role,
    entries: [
      entry("bin/node", "runtime", 1),
      entry("config/worker.json", "config_manifest", 2),
      entry("lib/entry.js", "entrypoint", 3),
      entry("native/driver.node", "native_addon", 4),
    ],
  };
}

function rootEvidence(overrides = {}) {
  return {
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    root_path_digest: digest("absolute-root-path"),
    directory_type: "directory",
    directory_identity_digest: digest("root-directory-object"),
    owner_uid: 501,
    owner_gid: 80,
    mode: 0o500,
    nlink: 4,
    mount_identity_scheme: "darwin_fsid_mount_generation_v1",
    mount_identity_digest: digest("mount-identity"),
    filesystem_identity_scheme: "darwin_apfs_volume_identity_v1",
    filesystem_identity_digest: digest("filesystem-identity"),
    immutability_scheme: "darwin_file_flags_and_mount_policy_v1",
    immutable_flags_digest: digest("immutable-flags"),
    immutable_flags_complete: true,
    read_only_mount: false,
    root_immutable: true,
    native_resolution_complete: true,
    ...overrides,
  };
}

function derivedIdentities(manifest) {
  const nativeEntries = manifest.entries.filter((candidate) => candidate.purpose === "native_addon");
  const runtime = manifest.entries.find((candidate) => candidate.purpose === "runtime");
  const entrypoint = manifest.entries.find((candidate) => candidate.purpose === "entrypoint");
  const config = manifest.entries.find((candidate) => candidate.purpose === "config_manifest");
  return {
    entrypoint_digest: entrypoint.content_digest,
    config_manifest_digest: config.content_digest,
    native_addon_set_digest: hashCanonicalJson({
      domain: WORKER_BUNDLE_NATIVE_ADDON_SET_DOMAIN,
      version: WORKER_BUNDLE_ATTESTATION_VERSION,
      native_addon_entry_identity_digests: nativeEntries.map(workerBundleEntryIdentityDigest),
    }),
    runtime_identity_digest: workerBundleEntryIdentityDigest(runtime),
  };
}

function authorityFixture() {
  const keys = crypto.generateKeyPairSync("ed25519");
  const authority = {
    authority_id: "bundle-authority:test-root",
    authority_key_id: "bundle-key:test-root-v1",
    authority_public_key_digest: publicKeyDigest(keys.publicKey),
    authority_trust_root_epoch: 3,
    authority_epoch: 8,
    authority_generation: 13,
    revocation_generation: 2,
    revocation_state_digest: digest("revocation-state"),
    anchor_digest: digest("anchor"),
    trusted_clock_digest: digest("clock"),
    runtime_epoch_digest: digest("runtime-epoch"),
    hil_qualification_digest: digest("conformance-hil-placeholder"),
  };
  return { keys, authority };
}

function payloadFor(role, authority, overrides = {}) {
  const manifest = manifestFor(role);
  const root = rootEvidence();
  return {
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    enrollment_id: `bundle-enrollment:${role}-v1`,
    bundle_id: manifest.bundle_id,
    role,
    attestation_assurance: "caller_injected_conformance_only",
    production_ready: false,
    separate_identity_authorized: false,
    hardware_authorized: false,
    manifest,
    manifest_digest: workerBundleManifestDigest(manifest),
    root_evidence: root,
    bundle_immutability_scheme: WORKER_BUNDLE_IMMUTABILITY_SCHEME,
    bundle_immutability_evidence_digest: workerBundleImmutabilityEvidenceDigest(manifest, root),
    bundle_immutability_complete: true,
    ...derivedIdentities(manifest),
    ...authority,
    authority_state_digest: workerBundleAuthorityStateDigest(authority),
    issued_at: "2026-07-19T03:59:50.000Z",
    expires_at: "2026-07-19T04:00:40.000Z",
    nonce: crypto.randomBytes(18).toString("base64url"),
    ...overrides,
  };
}

function currentAuthority(fixture, signed, trustedNow = FIXED_NOW) {
  return {
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    trusted: true,
    revoked: false,
    ...fixture.authority,
    authority_state_digest: workerBundleAuthorityStateDigest(fixture.authority),
    authority_public_key: fixture.keys.publicKey,
    current_enrollment_digest: signed.enrollment_digest,
    current_manifest_digest: signed.payload.manifest_digest,
    current_bundle_immutability_evidence_digest:
      signed.payload.bundle_immutability_evidence_digest,
    trusted_now: trustedNow,
  };
}

function snapshotBasis(signed) {
  return {
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    enrollment_digest: signed.enrollment_digest,
    bundle_id: signed.payload.bundle_id,
    role: signed.payload.role,
    manifest: signed.payload.manifest,
    manifest_digest: signed.payload.manifest_digest,
    root_evidence: signed.payload.root_evidence,
    bundle_immutability_scheme: signed.payload.bundle_immutability_scheme,
    bundle_immutability_evidence_digest: signed.payload.bundle_immutability_evidence_digest,
    bundle_immutability_complete: true,
    entrypoint_digest: signed.payload.entrypoint_digest,
    config_manifest_digest: signed.payload.config_manifest_digest,
    native_addon_set_digest: signed.payload.native_addon_set_digest,
    runtime_identity_digest: signed.payload.runtime_identity_digest,
  };
}

function safeRejection(error) {
  assert.equal(error?.code, "worker_bundle_attestation_rejected");
  assert.equal(error?.message, "Worker bundle attestation was rejected");
  assert.equal(Object.hasOwn(error, "cause"), false);
  return true;
}

function makeFixture(role = "active_device_worker") {
  const fixture = authorityFixture();
  const payload = payloadFor(role, fixture.authority);
  const signer = createConformanceWorkerBundleEnrollmentSigner({
    port_id: `bundle_signer_${role}`,
    ...fixture.authority,
    authority_private_key: fixture.keys.privateKey,
  });
  const signed = signWorkerBundleEnrollment(signer, payload);
  const calls = { authority: 0, live: 0, reservation: 0 };
  const behavior = {
    authority(value) { return value; },
    live(value) { return value; },
    reservation: null,
  };
  const captured = { authority_queries: [], live_queries: [], claim: null };
  const seen = new Set();
  const authorityPort = createConformanceWorkerBundleAuthorityResolver({
    port_id: `bundle_authority_${role}`,
    resolve_current_authority(query) {
      calls.authority += 1;
      captured.authority_queries.push(query);
      return behavior.authority(currentAuthority(fixture, signed), calls.authority);
    },
  });
  const livePortId = `bundle_live_${role}`;
  const livePort = createConformanceWorkerBundleNativeSnapshotResolver({
    port_id: livePortId,
    resolve_live_bundle(query) {
      calls.live += 1;
      captured.live_queries.push(query);
      const basis = behavior.live(clone(snapshotBasis(signed)), calls.live);
      return {
        ...basis,
        snapshot_digest: workerBundleLiveSnapshotDigest(livePortId, basis),
      };
    },
  });
  const reservationPortId = `bundle_reservation_${role}`;
  const reservationPort = createConformanceWorkerBundleReservationPort({
    port_id: reservationPortId,
    reserve_once(claim) {
      calls.reservation += 1;
      captured.claim = claim;
      if (behavior.reservation) return behavior.reservation(claim, reservationPortId);
      const disposition = seen.has(claim.enrollment_digest) ? "replay" : "reserved";
      if (disposition === "reserved") seen.add(claim.enrollment_digest);
      const basis = {
        version: WORKER_BUNDLE_ATTESTATION_VERSION,
        disposition,
        claim_digest: claim.claim_digest,
        reservation_generation: calls.reservation,
      };
      return {
        ...basis,
        receipt_digest: workerBundleReservationReceiptDigest(reservationPortId, basis),
      };
    },
  });
  return {
    fixture,
    payload,
    signed,
    signer,
    authorityPort,
    livePort,
    reservationPort,
    calls,
    behavior,
    captured,
    verify(enrollment = signed) {
      return verifyAndReserveWorkerBundleEnrollment({
        enrollment,
        authority_resolver_port: authorityPort,
        native_snapshot_resolver_port: livePort,
        reservation_port: reservationPort,
      });
    },
  };
}

test("manifest and enrollment domains are distinct and launch projection is digest-compatible", () => {
  assert.equal(new Set([
    WORKER_BUNDLE_MANIFEST_DOMAIN,
    WORKER_BUNDLE_ENTRY_IDENTITY_DOMAIN,
    WORKER_BUNDLE_IMMUTABILITY_DOMAIN,
    WORKER_BUNDLE_ENROLLMENT_DOMAIN,
    WORKER_BUNDLE_LIVE_SNAPSHOT_DOMAIN,
    WORKER_BUNDLE_AUTHORITY_STATE_DOMAIN,
  ]).size, 6);
  const manifest = manifestFor();
  const root = rootEvidence();
  const normalized = normalizeWorkerBundleManifest(manifest);
  const launchFields = workerBundleLaunchFields(normalized, root);
  assert.equal(Object.isFrozen(normalized), true);
  assert.deepEqual(Object.keys(launchFields).sort(), [
    "bundle_immutability_complete",
    "bundle_immutability_evidence_digest",
    "bundle_immutability_scheme",
    "bundle_manifest_digest",
    "config_manifest_digest",
    "entrypoint_digest",
  ]);
  assert.equal(launchFields.bundle_manifest_digest, workerBundleManifestDigest(manifest));
  assert.equal(launchFields.bundle_immutability_complete, true);
  assert.equal(JSON.stringify(launchFields).includes("lib/entry.js"), false);
});

test("all launch roles sign and verify with two live reads and post-reservation authority readback", () => {
  for (const role of WORKER_BUNDLE_ROLES) {
    const scenario = makeFixture(role);
    assert.equal(assertConformanceWorkerBundleEnrollmentSigner(scenario.signer), scenario.signer);
    assert.equal(
      assertConformanceWorkerBundleAuthorityResolver(scenario.authorityPort),
      scenario.authorityPort,
    );
    assert.equal(
      assertConformanceWorkerBundleNativeSnapshotResolver(scenario.livePort),
      scenario.livePort,
    );
    assert.equal(
      assertConformanceWorkerBundleReservationPort(scenario.reservationPort),
      scenario.reservationPort,
    );
    assert.equal(normalizeSignedWorkerBundleEnrollment(scenario.signed).payload.role, role);
    const verified = scenario.verify();
    assert.equal(assertVerifiedWorkerBundleEnrollment(verified), verified);
    assert.equal(verified.role, role);
    assert.deepEqual(scenario.calls, { authority: 2, live: 2, reservation: 1 });
    assert.equal(
      scenario.captured.authority_queries[1].purpose,
      "revalidate_exact_current_worker_bundle_authority_after_reservation",
    );
    assert.equal(scenario.captured.live_queries[0], scenario.captured.live_queries[1]);
    assert.equal(verified.production_ready, false);
    assert.equal(verified.separate_identity_authorized, false);
    assert.equal(verified.hardware_authorized, false);
    assert.deepEqual(verified.production_blockers, [
      "native_openat_fstatat_walk_not_qualified",
      "native_file_flags_immutability_not_qualified",
      "native_static_code_identity_not_qualified",
      "native_live_snapshot_hil_missing",
      "root_owned_immutable_launcher_not_qualified",
    ]);
    const serialized = JSON.stringify(verified);
    assert.equal(serialized.includes("signature"), false);
    assert.equal(serialized.includes("private"), false);
    assert.equal(serialized.includes("lib/entry.js"), false);
    const callbackMaterial = JSON.stringify(scenario.captured);
    assert.equal(callbackMaterial.includes("signature"), false);
    assert.equal(callbackMaterial.includes("private"), false);
    assert.equal(callbackMaterial.includes("lib/entry.js"), false);
    assert.equal(JSON.stringify(scenario.signer).includes("private"), false);
    assert.equal(JSON.stringify(scenario.authorityPort).includes("resolve_current_authority"), false);
    assert.equal(JSON.stringify(scenario.livePort).includes("resolve_live_bundle"), false);
    assert.deepEqual(
      verified.launch_attestation_bundle_fields,
      workerBundleLaunchFields(scenario.signed.payload.manifest, scenario.signed.payload.root_evidence),
    );
  }
});

test("manifest rejects traversal, aliases, unsorted paths, hard links, and prefix collisions", () => {
  const cases = [];
  const traversal = manifestFor();
  traversal.entries[2].path = "lib/../entry.js";
  cases.push(traversal);
  const absolute = manifestFor();
  absolute.entries[2].path = "/lib/entry.js";
  cases.push(absolute);
  const backslash = manifestFor();
  backslash.entries[2].path = "lib\\entry.js";
  cases.push(backslash);
  const unsorted = manifestFor();
  [unsorted.entries[0], unsorted.entries[1]] = [unsorted.entries[1], unsorted.entries[0]];
  cases.push(unsorted);
  const caseAlias = manifestFor();
  caseAlias.entries.splice(3, 0, entry("LIB/ENTRY.JS", "support_file", 7));
  caseAlias.entries.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  cases.push(caseAlias);
  const hardLink = manifestFor();
  hardLink.entries[3].object_identity_digest = hardLink.entries[2].object_identity_digest;
  cases.push(hardLink);
  const prefix = manifestFor();
  prefix.entries.splice(3, 0, entry("lib/entry.js/child", "support_file", 8));
  cases.push(prefix);
  for (const candidate of cases) {
    assert.throws(() => normalizeWorkerBundleManifest(candidate));
  }
});

test("manifest enforces count, byte, depth, mode, purpose, static-code, and ownership bounds", () => {
  const tooMany = manifestFor();
  for (let index = 0; index <= WORKER_BUNDLE_MAX_ENTRIES; index += 1) {
    tooMany.entries.push(entry(`support/z${String(index).padStart(4, "0")}`, "support_file", index + 10));
  }
  tooMany.entries.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  assert.throws(() => normalizeWorkerBundleManifest(tooMany));

  const tooDeep = manifestFor();
  tooDeep.entries[2].path = `${Array(WORKER_BUNDLE_MAX_PATH_DEPTH + 1).fill("x").join("/")}.js`;
  tooDeep.entries.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  assert.throws(() => normalizeWorkerBundleManifest(tooDeep));

  const tooLarge = manifestFor();
  for (const candidate of tooLarge.entries) candidate.byte_size = 200 * 1024 * 1024;
  assert.throws(() => normalizeWorkerBundleManifest(tooLarge));

  const writable = manifestFor();
  writable.entries[2].mode = 0o422;
  assert.throws(() => normalizeWorkerBundleManifest(writable));

  const missingStaticCode = manifestFor();
  Object.assign(missingStaticCode.entries[3], {
    static_code_identity_applicable: false,
    static_code_identity_scheme: "not_applicable",
    static_code_identity_digest: WORKER_BUNDLE_STATIC_CODE_NOT_APPLICABLE_DIGEST,
  });
  assert.throws(() => normalizeWorkerBundleManifest(missingStaticCode));

  const scenario = authorityFixture();
  const payload = payloadFor("active_device_worker", scenario.authority);
  payload.root_evidence.owner_uid = 0;
  assert.throws(() => normalizeWorkerBundleEnrollmentPayload(payload));
});

test("tampered signatures and revoked, stale, or drifted current authority fail safely", () => {
  const signatureScenario = makeFixture();
  const tampered = clone(signatureScenario.signed);
  const replacement = tampered.authentication.signature[0] === "A" ? "B" : "A";
  tampered.authentication.signature = `${replacement}${tampered.authentication.signature.slice(1)}`;
  assert.throws(() => signatureScenario.verify(tampered), safeRejection);

  const revokedScenario = makeFixture();
  revokedScenario.behavior.authority = (value) => ({ ...value, revoked: true });
  assert.throws(() => revokedScenario.verify(), safeRejection);

  const staleScenario = makeFixture();
  staleScenario.behavior.authority = (value) => ({
    ...value,
    trusted_now: "2026-07-19T04:01:00.000Z",
  });
  assert.throws(() => staleScenario.verify(), safeRejection);

  const driftScenario = makeFixture();
  driftScenario.behavior.authority = (value) => ({
    ...value,
    current_manifest_digest: digest("forked-current-manifest"),
  });
  assert.throws(() => driftScenario.verify(), safeRejection);
});

test("a self-consistent authority/live fork cannot replace the Ed25519 enrollment signature", () => {
  const scenario = makeFixture();
  const fork = clone(scenario.signed);
  const replacement = fork.authentication.signature[0] === "A" ? "B" : "A";
  fork.authentication.signature = `${replacement}${fork.authentication.signature.slice(1)}`;
  fork.enrollment_digest = hashCanonicalJson({
    version: fork.version,
    kind: fork.kind,
    domain: fork.domain,
    payload: fork.payload,
    payload_digest: fork.payload_digest,
    authentication: fork.authentication,
  });
  scenario.behavior.authority = (value) => ({
    ...value,
    current_enrollment_digest: fork.enrollment_digest,
  });
  scenario.behavior.live = (value) => ({
    ...value,
    enrollment_digest: fork.enrollment_digest,
  });
  assert.throws(() => scenario.verify(fork), safeRejection);
  assert.deepEqual(scenario.calls, { authority: 1, live: 1, reservation: 0 });
});

test("live snapshot drift across the verification bracket is rejected after one-use reservation", () => {
  const scenario = makeFixture();
  scenario.behavior.live = (value, call) => {
    if (call === 2) value.root_evidence.directory_identity_digest = digest("replacement-root");
    if (call === 2) {
      value.bundle_immutability_evidence_digest = workerBundleImmutabilityEvidenceDigest(
        value.manifest,
        value.root_evidence,
      );
    }
    return value;
  };
  assert.throws(() => scenario.verify(), safeRejection);
  assert.deepEqual(scenario.calls, { authority: 2, live: 2, reservation: 1 });
});

test("post-reservation revocation, epoch drift, and backwards clock are always read and rejected", () => {
  for (const mutate of [
    (value) => ({ ...value, revoked: true }),
    (value) => ({ ...value, authority_epoch: value.authority_epoch + 1 }),
    (value) => ({ ...value, trusted_now: "2026-07-19T03:59:59.999Z" }),
  ]) {
    const scenario = makeFixture();
    scenario.behavior.authority = (value, call) => (call === 2 ? mutate(value) : value);
    assert.throws(() => scenario.verify(), safeRejection);
    assert.equal(scenario.calls.reservation, 1);
    assert.equal(scenario.calls.authority, 2);
  }
});

test("one-use reservation rejects replay and forked receipts without returning evidence", () => {
  const scenario = makeFixture();
  scenario.verify();
  assert.throws(() => scenario.verify(), safeRejection);

  const forked = makeFixture();
  forked.behavior.reservation = (claim, portId) => {
    const basis = {
      version: WORKER_BUNDLE_ATTESTATION_VERSION,
      disposition: "reserved",
      claim_digest: digest("wrong-claim"),
      reservation_generation: 1,
    };
    return { ...basis, receipt_digest: workerBundleReservationReceiptDigest(portId, basis) };
  };
  assert.throws(() => forked.verify(), safeRejection);
  assert.equal(forked.calls.authority, 2);

  const lostReply = makeFixture();
  lostReply.behavior.reservation = () => {
    throw new Error("reservation reply lost after commit");
  };
  assert.throws(() => lostReply.verify(), safeRejection);
  assert.equal(lostReply.calls.reservation, 1);
  assert.equal(lostReply.calls.authority, 2);
});

test("authority and native snapshot ports reject asynchronous callback results", () => {
  const asyncAuthority = makeFixture();
  asyncAuthority.behavior.authority = async (value) => value;
  assert.throws(() => asyncAuthority.verify(), safeRejection);
  assert.deepEqual(asyncAuthority.calls, { authority: 1, live: 1, reservation: 0 });

  const scenario = makeFixture();
  const asyncLivePort = createConformanceWorkerBundleNativeSnapshotResolver({
    port_id: "async_bundle_live",
    async resolve_live_bundle() {
      return snapshotBasis(scenario.signed);
    },
  });
  assert.throws(() => verifyAndReserveWorkerBundleEnrollment({
    enrollment: scenario.signed,
    authority_resolver_port: scenario.authorityPort,
    native_snapshot_resolver_port: asyncLivePort,
    reservation_port: scenario.reservationPort,
  }), safeRejection);
  assert.deepEqual(scenario.calls, { authority: 0, live: 0, reservation: 0 });
});

test("accessors and Proxies are rejected without invoking hostile code", () => {
  const scenario = makeFixture();
  let getterCalls = 0;
  const accessorEnrollment = clone(scenario.signed);
  Object.defineProperty(accessorEnrollment, "payload", {
    enumerable: true,
    configurable: true,
    get() {
      getterCalls += 1;
      throw new Error("secret raw path /private/worker and signature bytes");
    },
  });
  assert.throws(() => scenario.verify(accessorEnrollment), safeRejection);
  assert.equal(getterCalls, 0);

  assert.throws(() => scenario.verify(new Proxy(scenario.signed, {
    ownKeys() { throw new Error("must not run"); },
  })), safeRejection);

  const proxyManifest = manifestFor();
  proxyManifest.entries[2] = new Proxy(proxyManifest.entries[2], {
    get() { throw new Error("must not run"); },
  });
  assert.throws(() => normalizeWorkerBundleManifest(proxyManifest));
});

test("inherited toJSON cannot influence manifest, enrollment, snapshot, or receipt digests", () => {
  const scenario = makeFixture();
  let calls = 0;
  Object.defineProperty(Object.prototype, "toJSON", {
    configurable: true,
    enumerable: false,
    value() {
      calls += 1;
      return { forged: true };
    },
  });
  try {
    const signedAgain = signWorkerBundleEnrollment(scenario.signer, scenario.payload);
    assert.equal(signedAgain.enrollment_digest, scenario.signed.enrollment_digest);
    const verified = scenario.verify(signedAgain);
    assert.equal(assertVerifiedWorkerBundleEnrollment(verified), verified);
    assert.equal(calls, 0);
    assert.notEqual(
      scenario.signed.payload.manifest_digest,
      digest("constant-attacker-selected-manifest"),
    );
  } finally {
    delete Object.prototype.toJSON;
  }
});

test("cache-like frozen port lookalikes and cloned verified results do not cross private brands", () => {
  const scenario = makeFixture();
  const fakePort = Object.freeze({
    ...scenario.livePort,
    cache_key: "require.cache/native-binding.node",
  });
  assert.throws(() => verifyAndReserveWorkerBundleEnrollment({
    enrollment: scenario.signed,
    authority_resolver_port: scenario.authorityPort,
    native_snapshot_resolver_port: fakePort,
    reservation_port: scenario.reservationPort,
  }), safeRejection);
  assert.equal(scenario.calls.live, 0);

  const verified = scenario.verify();
  const cloned = Object.freeze(clone(verified));
  assert.throws(() => assertVerifiedWorkerBundleEnrollment(cloned));
});

test("a live resolver cannot redirect later private ports or hash operations through prototypes", () => {
  const scenario = makeFixture();
  const weakMapGet = Object.getOwnPropertyDescriptor(WeakMap.prototype, "get");
  const hashPrototype = Object.getPrototypeOf(crypto.createHash("sha256"));
  const hashUpdate = Object.getOwnPropertyDescriptor(hashPrototype, "update");
  const hashDigest = Object.getOwnPropertyDescriptor(hashPrototype, "digest");
  let poisoned = false;
  scenario.behavior.live = (value, call) => {
    if (call === 1) {
      poisoned = true;
      Object.defineProperty(WeakMap.prototype, "get", {
        ...weakMapGet,
        value() {
          throw new Error("attacker redirected a private callback port");
        },
      });
      Object.defineProperty(hashPrototype, "update", {
        ...hashUpdate,
        value() {
          throw new Error("attacker replaced hash update");
        },
      });
      Object.defineProperty(hashPrototype, "digest", {
        ...hashDigest,
        value() {
          throw new Error("attacker replaced hash digest");
        },
      });
    }
    return value;
  };
  try {
    const verified = scenario.verify();
    assert.equal(poisoned, true);
    assert.equal(assertVerifiedWorkerBundleEnrollment(verified), verified);
    assert.deepEqual(scenario.calls, { authority: 2, live: 2, reservation: 1 });
  } finally {
    Object.defineProperty(WeakMap.prototype, "get", weakMapGet);
    Object.defineProperty(hashPrototype, "update", hashUpdate);
    Object.defineProperty(hashPrototype, "digest", hashDigest);
  }
});

test("unknown fields and resolver failures collapse to a stable redacted rejection", () => {
  const scenario = makeFixture();
  const unknown = clone(scenario.signed);
  unknown.payload.cache = { path: "/private/worker", signature: "secret" };
  assert.throws(() => scenario.verify(unknown), (error) => {
    safeRejection(error);
    assert.equal(error.message.includes("/private/worker"), false);
    assert.equal(error.message.includes("secret"), false);
    return true;
  });

  const throwing = makeFixture();
  throwing.behavior.live = () => {
    throw new Error("/private/worker raw bytes and signing key");
  };
  assert.throws(() => throwing.verify(), safeRejection);
});
