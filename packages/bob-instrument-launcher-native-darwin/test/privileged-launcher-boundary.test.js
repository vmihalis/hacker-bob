"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const {
  DARWIN_LAUNCHER_VERSION,
  DARWIN_LAUNCH_ENV_ALLOWLIST,
  DARWIN_LAUNCH_ROLES,
  assertConformanceDarwinLaunchAuthorityResolver,
  assertConformanceDarwinLaunchReplayPort,
  assertConformanceDarwinLaunchTicketSigner,
  assertConformanceDarwinNativeLaunchResolver,
  assertVerifiedDarwinNativeFixtureContractConsistency,
  assertVerifiedDarwinLaunchPlan,
  bindDarwinNativeFixtureContractConsistency,
  createConformanceDarwinLaunchAuthorityResolver,
  createConformanceDarwinLaunchReplayPort,
  createConformanceDarwinLaunchTicketSigner,
  createConformanceDarwinNativeLaunchResolver,
  darwinCredentialDropReadbackDigest,
  darwinLaunchArgvDigest,
  darwinLaunchAuthorityStateDigest,
  darwinLaunchEnvironmentDigest,
  darwinLaunchFdSetDigest,
  darwinLaunchPlanDigest,
  darwinLaunchCredentialPlanDigest,
  darwinLaunchReplayReceiptDigest,
  darwinLauncherPathDigest,
  darwinNativeLaunchEvidenceDigest,
  darwinNativeLaunchSnapshotDigest,
  darwinWorkerBundleProjectionDigest,
  normalizeDarwinLaunchPlan,
  normalizeDarwinNativeLaunchEvidence,
  normalizeSignedDarwinLaunchTicket,
  signDarwinLaunchTicket,
  verifyAndReserveDarwinLaunchTicket,
} = require("../lib/privileged-launcher-boundary.js");

const nativeRecordModulePath = require.resolve("../lib/native-fixture-record.js");
const {
  DARWIN_NATIVE_FIXTURE_ENTRY_COUNT,
  DARWIN_NATIVE_FIXTURE_CONTRACT_PRODUCTION_BLOCKERS,
  DARWIN_NATIVE_FIXTURE_CONTRACT_RECORD_DOMAIN,
  DARWIN_NATIVE_FIXTURE_CONTRACT_RECORD_VERSION,
  darwinNativeFixtureContractRecordChecksum,
} = require(nativeRecordModulePath);

const {
  WORKER_BUNDLE_ATTESTATION_VERSION,
  WORKER_BUNDLE_IMMUTABILITY_SCHEME,
  WORKER_BUNDLE_NATIVE_ADDON_SET_DOMAIN,
  WORKER_BUNDLE_STATIC_CODE_NOT_APPLICABLE_DIGEST,
  assertVerifiedWorkerBundleEnrollment,
  createConformanceWorkerBundleAuthorityResolver,
  createConformanceWorkerBundleEnrollmentSigner,
  createConformanceWorkerBundleNativeSnapshotResolver,
  createConformanceWorkerBundleReservationPort,
  signWorkerBundleEnrollment,
  verifyAndReserveWorkerBundleEnrollment,
  workerBundleAuthorityStateDigest,
  workerBundleEntryIdentityDigest,
  workerBundleImmutabilityEvidenceDigest,
  workerBundleLiveSnapshotDigest,
  workerBundleManifestDigest,
  workerBundleReservationReceiptDigest,
} = require("../../bob-instrument-broker/lib/worker-bundle-attestation.js");
const { hashCanonicalJson } = require("../../../mcp/lib/verification-contracts.js");

const FIXED_NOW = "2026-07-19T04:00:00.000Z";

function digest(label) {
  return crypto.createHash("sha256").update(`launcher-test:${label}`, "utf8").digest("hex");
}

function keyDigest(key) {
  return crypto.createHash("sha256")
    .update(key.export({ type: "spki", format: "der" }))
    .digest("hex");
}

function clone(value) {
  return structuredClone(value);
}

function bundleEntry(pathValue, purpose, index) {
  const staticCode = purpose === "runtime" || purpose === "native_addon";
  return {
    path: pathValue,
    purpose,
    file_type: "regular_file",
    byte_size: staticCode ? 8192 + index : 512 + index,
    content_digest: digest(`bundle-content-${pathValue}`),
    owner_uid: 0,
    owner_gid: 0,
    mode: purpose === "runtime" ? 0o500 : 0o400,
    nlink: 1,
    object_identity_digest: digest(`bundle-object-${pathValue}`),
    static_code_identity_applicable: staticCode,
    static_code_identity_scheme: staticCode ? "darwin_static_code_v1" : "not_applicable",
    static_code_identity_digest: staticCode
      ? digest(`bundle-static-code-${pathValue}`)
      : WORKER_BUNDLE_STATIC_CODE_NOT_APPLICABLE_DIGEST,
    static_code_identity_complete: true,
  };
}

function createVerifiedWorkerBundle(role) {
  const keys = crypto.generateKeyPairSync("ed25519");
  const authority = {
    authority_id: "bundle-authority:launcher-test-root",
    authority_key_id: "bundle-key:launcher-test-root-v1",
    authority_public_key_digest: keyDigest(keys.publicKey),
    authority_trust_root_epoch: 2,
    authority_epoch: 4,
    authority_generation: 7,
    revocation_generation: 1,
    revocation_state_digest: digest(`bundle-revocation-${role}`),
    anchor_digest: digest(`bundle-anchor-${role}`),
    trusted_clock_digest: digest(`bundle-clock-${role}`),
    runtime_epoch_digest: digest(`bundle-runtime-epoch-${role}`),
    hil_qualification_digest: digest(`bundle-hil-placeholder-${role}`),
  };
  const manifest = {
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    bundle_id: `worker-bundle:${role}-launcher-v1`,
    role,
    entries: [
      bundleEntry("bin/node", "runtime", 1),
      bundleEntry("config/worker.json", "config_manifest", 2),
      bundleEntry("lib/worker.js", "entrypoint", 3),
      bundleEntry("native/driver.node", "native_addon", 4),
    ],
  };
  const root = {
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    root_path_digest: digest(`bundle-root-path-${role}`),
    directory_type: "directory",
    directory_identity_digest: digest(`bundle-root-object-${role}`),
    owner_uid: 0,
    owner_gid: 0,
    mode: 0o500,
    nlink: 4,
    mount_identity_scheme: "darwin_fsid_mount_generation_v1",
    mount_identity_digest: digest(`bundle-mount-${role}`),
    filesystem_identity_scheme: "darwin_apfs_volume_identity_v1",
    filesystem_identity_digest: digest(`bundle-filesystem-${role}`),
    immutability_scheme: "darwin_file_flags_and_mount_policy_v1",
    immutable_flags_digest: digest(`bundle-flags-${role}`),
    immutable_flags_complete: true,
    read_only_mount: false,
    root_immutable: true,
    native_resolution_complete: true,
  };
  const entrypoint = manifest.entries.find((entry) => entry.purpose === "entrypoint");
  const config = manifest.entries.find((entry) => entry.purpose === "config_manifest");
  const runtime = manifest.entries.find((entry) => entry.purpose === "runtime");
  const nativeAddons = manifest.entries.filter((entry) => entry.purpose === "native_addon");
  const nativeAddonSetDigest = hashCanonicalJson({
    domain: WORKER_BUNDLE_NATIVE_ADDON_SET_DOMAIN,
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    native_addon_entry_identity_digests: nativeAddons.map(workerBundleEntryIdentityDigest),
  });
  const payload = {
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    enrollment_id: `bundle-enrollment:${role}-launcher-v1`,
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
    entrypoint_digest: entrypoint.content_digest,
    config_manifest_digest: config.content_digest,
    native_addon_set_digest: nativeAddonSetDigest,
    runtime_identity_digest: workerBundleEntryIdentityDigest(runtime),
    ...authority,
    authority_state_digest: workerBundleAuthorityStateDigest(authority),
    issued_at: "2026-07-19T03:59:40.000Z",
    expires_at: "2026-07-19T04:00:30.000Z",
    nonce: crypto.randomBytes(18).toString("base64url"),
  };
  const signer = createConformanceWorkerBundleEnrollmentSigner({
    port_id: `bundle_signer_${role}_launcher`,
    ...authority,
    authority_private_key: keys.privateKey,
  });
  const signed = signWorkerBundleEnrollment(signer, payload);
  const current = () => ({
    version: WORKER_BUNDLE_ATTESTATION_VERSION,
    trusted: true,
    revoked: false,
    ...authority,
    authority_state_digest: workerBundleAuthorityStateDigest(authority),
    authority_public_key: keys.publicKey,
    current_enrollment_digest: signed.enrollment_digest,
    current_manifest_digest: signed.payload.manifest_digest,
    current_bundle_immutability_evidence_digest:
      signed.payload.bundle_immutability_evidence_digest,
    trusted_now: FIXED_NOW,
  });
  const authorityPort = createConformanceWorkerBundleAuthorityResolver({
    port_id: `bundle_authority_${role}_launcher`,
    resolve_current_authority: current,
  });
  const livePortId = `bundle_live_${role}_launcher`;
  const livePort = createConformanceWorkerBundleNativeSnapshotResolver({
    port_id: livePortId,
    resolve_live_bundle() {
      const basis = {
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
      return { ...basis, snapshot_digest: workerBundleLiveSnapshotDigest(livePortId, basis) };
    },
  });
  const replayPortId = `bundle_replay_${role}_launcher`;
  let generation = 0;
  const replayPort = createConformanceWorkerBundleReservationPort({
    port_id: replayPortId,
    reserve_once(claim) {
      generation += 1;
      const basis = {
        version: WORKER_BUNDLE_ATTESTATION_VERSION,
        disposition: generation === 1 ? "reserved" : "replay",
        claim_digest: claim.claim_digest,
        reservation_generation: generation,
      };
      return { ...basis, receipt_digest: workerBundleReservationReceiptDigest(replayPortId, basis) };
    },
  });
  return verifyAndReserveWorkerBundleEnrollment({
    enrollment: signed,
    authority_resolver_port: authorityPort,
    native_snapshot_resolver_port: livePort,
    reservation_port: replayPort,
  });
}

const PRINCIPAL_ROWS = Object.freeze([
  Object.freeze({
    role: "issuer_peer",
    principal_id: "principal:grant-issuer",
    uid: 501,
    gid: 601,
    supplementary_groups: Object.freeze([
      Object.freeze({ purpose: "ipc_transport", gid: 701 }),
    ]),
  }),
  Object.freeze({
    role: "active_device_worker",
    principal_id: "principal:active-device-worker",
    uid: 502,
    gid: 602,
    supplementary_groups: Object.freeze([
      Object.freeze({ purpose: "active_device_access", gid: 702 }),
      Object.freeze({ purpose: "ipc_transport", gid: 701 }),
    ]),
  }),
  Object.freeze({
    role: "cleanup_only_worker",
    principal_id: "principal:cleanup-worker",
    uid: 503,
    gid: 603,
    supplementary_groups: Object.freeze([
      Object.freeze({ purpose: "cleanup_device_access", gid: 703 }),
    ]),
  }),
  Object.freeze({
    role: "safety_supervisor",
    principal_id: "principal:safety-supervisor",
    uid: 504,
    gid: 604,
    supplementary_groups: Object.freeze([]),
  }),
]);
const FD_PURPOSES = Object.freeze({
  issuer_peer: Object.freeze(["grant_signer", "ipc_channel"]),
  active_device_worker: Object.freeze([
    "device_handle", "ipc_channel", "lease_journal", "receipt_signer",
  ]),
  cleanup_only_worker: Object.freeze([
    "cleanup_device_handle", "cleanup_journal", "recovery_signer", "snapshot_materialization",
  ]),
  safety_supervisor: Object.freeze(["cleanup_journal", "cleanup_root", "safety_control"]),
});

function projectionFromVerifiedBundle(value) {
  const verified = assertVerifiedWorkerBundleEnrollment(value);
  return {
    version: verified.version,
    enrollment_digest: verified.enrollment_digest,
    bundle_id: verified.bundle_id,
    role: verified.role,
    manifest_digest: verified.manifest_digest,
    native_addon_set_digest: verified.native_addon_set_digest,
    runtime_identity_digest: verified.runtime_identity_digest,
    reservation_receipt_digest: verified.reservation_receipt_digest,
    live_snapshot_digest: verified.live_snapshot_digest,
    launch_attestation_bundle_fields: verified.launch_attestation_bundle_fields,
    assurance: verified.assurance,
    production_ready: verified.production_ready,
  };
}

function planFor(role, bundleId, overrides = {}) {
  const selected = PRINCIPAL_ROWS[DARWIN_LAUNCH_ROLES.indexOf(role)];
  const profile = {
    issuer_peer: {
      target: "principal:grant-issuer",
      authorizer: "principal:operator-control-plane",
    },
    active_device_worker: {
      target: "principal:active-device-worker",
      authorizer: "principal:operator-control-plane",
    },
    cleanup_only_worker: {
      target: "principal:cleanup-worker",
      authorizer: "principal:safety-supervisor",
    },
    safety_supervisor: {
      target: "principal:safety-supervisor",
      authorizer: "principal:operator-control-plane",
    },
  }[role];
  const root = `/Library/HackerBob/Bundles/${role}`;
  const executable = `${root}/bin/node`;
  const entrypoint = `${root}/lib/worker.js`;
  const config = `${root}/config/worker.json`;
  const fds = FD_PURPOSES[role].map((purpose, index) => ({
    fd: 10 + index,
    purpose,
    capability_digest: digest(`${role}-fd-${purpose}`),
    owner_principal_id: profile.target,
    one_shot: true,
    inherited_across_exec: true,
  }));
  return {
    version: DARWIN_LAUNCHER_VERSION,
    plan_id: `launch-plan:${role}-v1`,
    role,
    bundle_id: bundleId,
    launcher_principal_id: "principal:privileged-launcher",
    authorizer_principal_id: profile.authorizer,
    target_principal_id: profile.target,
    execution_method: "darwin_execve_absolute_no_shell_v1",
    shell_allowed: false,
    path_lookup_allowed: false,
    working_directory: root,
    executable_path: executable,
    entrypoint_path: entrypoint,
    config_manifest_path: config,
    argv: [executable, entrypoint, "--role", role, "--config", config],
    environment_policy: "empty_environment_v1",
    environment: [],
    stdio_policy: "dev_null_reopen_v1",
    fd_enumeration_scheme: "darwin_proc_pidfdinfo_complete_v1",
    fd_close_policy: "close_all_then_dup_enrolled_one_shot_v1",
    all_unlisted_file_descriptors_closed: true,
    allowed_file_descriptors: fds,
    principal_matrix: clone(PRINCIPAL_ROWS),
    real_uid: selected.uid,
    effective_uid: selected.uid,
    saved_uid: selected.uid,
    real_gid: selected.gid,
    effective_gid: selected.gid,
    saved_gid: selected.gid,
    ...overrides,
  };
}

function nativeEvidenceFor(plan, projection, overrides = {}) {
  const selected = plan.principal_matrix[DARWIN_LAUNCH_ROLES.indexOf(plan.role)];
  return {
    version: DARWIN_LAUNCHER_VERSION,
    platform: "darwin",
    architecture: "arm64",
    plan_digest: darwinLaunchPlanDigest(plan),
    worker_bundle_projection_digest: darwinWorkerBundleProjectionDigest(projection),
    native_resolver_implementation_digest: digest("native-resolver-implementation"),
    native_launcher_binary_digest: digest("native-launcher-binary"),
    native_launcher_code_signing_scheme: "darwin_static_signing_identity_v1",
    native_launcher_code_signing_identity_digest: digest("native-launcher-code-signing"),
    native_launcher_code_signing_complete: true,
    working_root_path_digest: darwinLauncherPathDigest("working_root", plan.working_directory),
    executable_path_digest: darwinLauncherPathDigest("executable", plan.executable_path),
    entrypoint_path_digest: darwinLauncherPathDigest("entrypoint", plan.entrypoint_path),
    config_manifest_path_digest: darwinLauncherPathDigest("config_manifest", plan.config_manifest_path),
    working_directory_identity_digest: digest("working-directory-identity"),
    root_owner_uid: 0,
    root_owner_gid: 0,
    root_mode: 0o500,
    root_nlink: 4,
    root_directory_identity_digest: digest("native-root-directory"),
    mount_identity_digest: digest("native-mount"),
    filesystem_identity_digest: digest("native-filesystem"),
    immutable_flags_digest: digest("native-immutable-flags"),
    openat_fstatat_walk_digest: digest("native-openat-fstatat-walk"),
    all_path_components_openat_verified: true,
    all_bundle_objects_root_owned: true,
    all_bundle_objects_immutable: true,
    entrypoint_content_digest: projection.launch_attestation_bundle_fields.entrypoint_digest,
    config_manifest_content_digest: projection.launch_attestation_bundle_fields.config_manifest_digest,
    native_addon_set_digest: projection.native_addon_set_digest,
    runtime_identity_digest: projection.runtime_identity_digest,
    static_code_identity_digest: digest("native-static-code-set"),
    static_code_identity_complete: true,
    argv_digest: darwinLaunchArgvDigest(plan),
    environment_digest: darwinLaunchEnvironmentDigest(plan),
    allowed_fd_set_digest: darwinLaunchFdSetDigest(plan),
    fd_enumeration_digest: digest("native-fd-enumeration"),
    all_unlisted_fds_closed: true,
    stdio_reopened_dev_null: true,
    real_uid: plan.real_uid,
    effective_uid: plan.effective_uid,
    saved_uid: plan.saved_uid,
    real_gid: plan.real_gid,
    effective_gid: plan.effective_gid,
    saved_gid: plan.saved_gid,
    supplementary_groups: clone(selected.supplementary_groups),
    credential_drop_readback_digest: darwinCredentialDropReadbackDigest(plan),
    credential_drop_complete: true,
    snapshot_complete: true,
    ...overrides,
  };
}

function launcherAuthorityFixture() {
  const keys = crypto.generateKeyPairSync("ed25519");
  const authority = {
    authority_id: "launcher-authority:test-root",
    authority_key_id: "launcher-key:test-root-v1",
    authority_public_key_digest: keyDigest(keys.publicKey),
    authority_trust_root_epoch: 3,
    authority_epoch: 6,
    authority_generation: 9,
    revocation_generation: 2,
    revocation_state_digest: digest("launcher-revocation"),
    anchor_digest: digest("launcher-anchor"),
    trusted_clock_digest: digest("launcher-clock"),
    runtime_epoch_digest: digest("launcher-runtime-epoch"),
    hil_qualification_digest: digest("launcher-hil-placeholder"),
  };
  return { keys, authority };
}

function safeRejection(error) {
  assert.equal(error?.code, "darwin_privileged_launch_rejected");
  assert.equal(error?.message, "Darwin privileged launch plan was rejected");
  assert.equal(Object.hasOwn(error, "cause"), false);
  return true;
}

function makeLauncherFixture(role = "active_device_worker") {
  const verifiedBundle = createVerifiedWorkerBundle(role);
  const projection = projectionFromVerifiedBundle(verifiedBundle);
  const plan = planFor(role, verifiedBundle.bundle_id);
  const nativeEvidence = nativeEvidenceFor(plan, projection);
  const authorityFixture = launcherAuthorityFixture();
  const payload = {
    version: DARWIN_LAUNCHER_VERSION,
    ticket_id: `launch-ticket:${role}-v1`,
    role,
    bundle_id: verifiedBundle.bundle_id,
    attestation_assurance: "caller_injected_conformance_only",
    production_attested: false,
    production_ready: false,
    separate_identity_authorized: false,
    hardware_authorized: false,
    worker_bundle_enrollment_digest: verifiedBundle.enrollment_digest,
    worker_bundle_projection_digest: darwinWorkerBundleProjectionDigest(projection),
    worker_bundle_manifest_digest: verifiedBundle.manifest_digest,
    worker_bundle_reservation_receipt_digest: verifiedBundle.reservation_receipt_digest,
    worker_bundle_live_snapshot_digest: verifiedBundle.live_snapshot_digest,
    launch_plan: plan,
    launch_plan_digest: darwinLaunchPlanDigest(plan),
    expected_native_evidence_digest: darwinNativeLaunchEvidenceDigest(
      nativeEvidence,
      plan,
      projection,
    ),
    ...authorityFixture.authority,
    authority_state_digest: darwinLaunchAuthorityStateDigest(authorityFixture.authority),
    issued_at: "2026-07-19T03:59:55.000Z",
    expires_at: "2026-07-19T04:00:20.000Z",
    nonce: crypto.randomBytes(18).toString("base64url"),
  };
  const signer = createConformanceDarwinLaunchTicketSigner({
    port_id: `launcher_signer_${role}`,
    ...authorityFixture.authority,
    authority_private_key: authorityFixture.keys.privateKey,
  });
  const ticket = signDarwinLaunchTicket(signer, payload);
  const calls = { authority: 0, native: 0, replay: 0 };
  const behavior = {
    authority(value) { return value; },
    native(value) { return value; },
    replay: null,
  };
  const currentAuthority = () => ({
    version: DARWIN_LAUNCHER_VERSION,
    trusted: true,
    revoked: false,
    ...authorityFixture.authority,
    authority_state_digest: darwinLaunchAuthorityStateDigest(authorityFixture.authority),
    authority_public_key: authorityFixture.keys.publicKey,
    current_ticket_digest: ticket.ticket_digest,
    current_launch_plan_digest: ticket.payload.launch_plan_digest,
    current_worker_bundle_projection_digest: ticket.payload.worker_bundle_projection_digest,
    current_native_evidence_digest: ticket.payload.expected_native_evidence_digest,
    trusted_now: FIXED_NOW,
  });
  const authorityPort = createConformanceDarwinLaunchAuthorityResolver({
    port_id: `launcher_authority_${role}`,
    resolve_current_authority(query) {
      calls.authority += 1;
      return behavior.authority(currentAuthority(), calls.authority, query);
    },
  });
  const nativePortId = `launcher_native_${role}`;
  const nativePort = createConformanceDarwinNativeLaunchResolver({
    port_id: nativePortId,
    resolve_live_launch_boundary(query) {
      calls.native += 1;
      const evidence = behavior.native(clone(nativeEvidence), calls.native, query);
      const evidenceDigest = darwinNativeLaunchEvidenceDigest(evidence, plan, projection);
      return {
        version: DARWIN_LAUNCHER_VERSION,
        ticket_digest: ticket.ticket_digest,
        native_evidence: evidence,
        native_evidence_digest: evidenceDigest,
        snapshot_digest: darwinNativeLaunchSnapshotDigest(
          nativePortId,
          ticket.ticket_digest,
          evidence,
          plan,
          projection,
        ),
      };
    },
  });
  const replayPortId = `launcher_replay_${role}`;
  const seen = new Set();
  const replayPort = createConformanceDarwinLaunchReplayPort({
    port_id: replayPortId,
    reserve_once(claim) {
      calls.replay += 1;
      if (behavior.replay) return behavior.replay(claim, replayPortId);
      const disposition = seen.has(claim.ticket_digest) ? "replay" : "reserved";
      if (disposition === "reserved") seen.add(claim.ticket_digest);
      const basis = {
        version: DARWIN_LAUNCHER_VERSION,
        disposition,
        claim_digest: claim.claim_digest,
        reservation_generation: calls.replay,
      };
      return { ...basis, receipt_digest: darwinLaunchReplayReceiptDigest(replayPortId, basis) };
    },
  });
  return {
    verifiedBundle,
    projection,
    plan,
    nativeEvidence,
    authorityFixture,
    payload,
    ticket,
    signer,
    authorityPort,
    nativePort,
    replayPort,
    calls,
    behavior,
    verify(ticketInput = ticket, bundleInput = verifiedBundle, ports = {}) {
      return verifyAndReserveDarwinLaunchTicket({
        ticket: ticketInput,
        verified_worker_bundle: bundleInput,
        authority_resolver_port: ports.authority || authorityPort,
        native_resolver_port: ports.native || nativePort,
        replay_port: ports.replay || replayPort,
      });
    },
  };
}

function nativeFixtureContractRecordForVerified(verified, overrides = {}) {
  const basis = {
    version: DARWIN_NATIVE_FIXTURE_CONTRACT_RECORD_VERSION,
    kind: "darwin_native_launcher_fixture_contract_record",
    record_domain: DARWIN_NATIVE_FIXTURE_CONTRACT_RECORD_DOMAIN,
    fixture_manifest_digest: digest("native-fixture-manifest"),
    native_launcher_on_disk_path_object_sha256: digest("native-on-disk-path-object"),
    declared_launch_plan_digest: verified.launch_plan_digest,
    declared_worker_bundle_projection_digest: verified.worker_bundle_projection_digest,
    declared_native_evidence_digest: verified.native_evidence_digest,
    declared_path_plan_digest: verified.path_plan_digest,
    declared_argv_digest: verified.argv_digest,
    declared_environment_digest: verified.environment_digest,
    declared_fd_set_digest: verified.fd_set_digest,
    declared_credential_plan_digest: verified.credential_plan_digest,
    fixture_root_identity_digest: digest("native-fixture-root"),
    openat_fstatat_walk_digest: digest("native-openat-fstatat-walk"),
    fd_enumeration_digest: digest("native-fd-enumeration"),
    credential_observation_digest: digest("native-fixture-credentials"),
    bundle_entry_count: DARWIN_NATIVE_FIXTURE_ENTRY_COUNT,
    all_path_components_openat_verified: true,
    all_bundle_objects_exact: true,
    all_unlisted_fds_closed: true,
    stdio_reopened_dev_null: true,
    empty_environment: true,
    retained_bundle_fds_verified: true,
    double_hash_identity_pass_complete: true,
    terminal_ancestry_rewalk_complete: true,
    final_retained_fd_identity_sweep_complete: true,
    credential_drop_executed: false,
    execve_executed: false,
    native_launcher_mapped_process_image_identity_bound: false,
    native_fixture_record_provenance_attested: false,
    child_process_custody_attested: false,
    report_channel_authenticated: false,
    production_attested: false,
    production_ready: false,
    production_blockers: [...DARWIN_NATIVE_FIXTURE_CONTRACT_PRODUCTION_BLOCKERS],
    ...overrides,
  };
  return {
    ...basis,
    contract_record_checksum: darwinNativeFixtureContractRecordChecksum(basis),
  };
}

test("package imports are inert and only the explicit fixture CLI can create a child boundary", () => {
  const packageRoot = path.resolve(__dirname, "..");
  const packageManifest = JSON.parse(fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"));
  const source = fs.readFileSync(
    path.join(packageRoot, "lib", "privileged-launcher-boundary.js"),
    "utf8",
  );

  assert.equal(packageManifest.private, true);
  assert.equal(packageManifest.gypfile, false);
  assert.equal(packageManifest.scripts.preinstall, undefined);
  assert.equal(packageManifest.scripts.install, undefined);
  assert.equal(packageManifest.scripts.postinstall, undefined);
  assert.deepEqual(packageManifest.bin, {
    "bob-darwin-launcher-fixture": "dist/bob-darwin-launcher-fixture",
  });
  assert.deepEqual(packageManifest.files.sort(), [
    "README.md",
    "dist/bob-darwin-launcher-fixture",
    "lib/native-binary-symbol-contract.js",
    "lib/native-fixture-record.js",
    "lib/privileged-launcher-boundary.js",
    "native/darwin-launcher-fixture.c",
    "native/darwin-post-exec-capability-release.source.c",
    "native/darwin-privileged-launch-executor.source.c",
    "scripts/build-native-fixture.js",
    "scripts/check-native-fixture.js",
  ]);
  assert.equal(
    fs.readFileSync(path.join(packageRoot, ".gitignore"), "utf8"),
    "dist/\n.native-fixture-test-*/\n",
  );
  assert.doesNotMatch(source, /node:(?:child_process|fs|worker_threads)/u);
  assert.doesNotMatch(source, /\b(?:spawn|spawnSync|execFile|execFileSync|fork)\s*\(/u);
  assert.doesNotMatch(source, /\b(?:setuid|seteuid|setgid|setegid|initgroups)\s*\(/u);
  assert.equal(DARWIN_LAUNCH_ENV_ALLOWLIST.length, 0);
  assert.equal(typeof require("../lib/privileged-launcher-boundary.js").exec, "undefined");
  assert.equal(typeof require("../lib/privileged-launcher-boundary.js").launch, "undefined");
  assert.equal(
    typeof require("../lib/privileged-launcher-boundary.js").bindDarwinNativeFixtureRecord,
    "undefined",
  );
  assert.equal(typeof bindDarwinNativeFixtureContractConsistency, "function");
});

test("native fixture record yields only private contract consistency without provenance", () => {
  const fixture = makeLauncherFixture();
  const verified = fixture.verify();
  const record = nativeFixtureContractRecordForVerified(verified);
  const consistency = bindDarwinNativeFixtureContractConsistency(record, verified);
  assert.equal(
    assertVerifiedDarwinNativeFixtureContractConsistency(consistency),
    consistency,
  );
  assert.equal(consistency.fixture_contract_consistent, true);
  assert.equal(consistency.native_evidence_digest_contract_consistent, true);
  assert.equal(consistency.openat_fstatat_walk_digest_contract_consistent, true);
  assert.equal(consistency.fd_enumeration_digest_contract_consistent, true);
  assert.equal(consistency.native_launcher_mapped_process_image_identity_bound, false);
  assert.equal(consistency.native_fixture_record_provenance_attested, false);
  assert.equal(consistency.child_process_custody_attested, false);
  assert.equal(consistency.report_channel_authenticated, false);
  assert.equal(
    consistency.fixture_contract_record_checksum,
    record.contract_record_checksum,
  );
  assert.equal(consistency.production_attested, false);
  assert.equal(consistency.production_ready, false);
  assert.deepEqual(consistency.native_fixture_production_blockers, record.production_blockers);
  assert.deepEqual(consistency.launch_contract_production_blockers, verified.production_blockers);
  assert.equal(
    consistency.production_blockers.includes("verified_bundle_brand_bridge_packaging_missing"),
    true,
  );
  assert.equal(
    consistency.production_blockers.includes("capability_fd_projection_not_linked_into_fixture"),
    true,
  );
  assert.equal(
    consistency.production_blockers.includes("native_fixture_record_provenance_unattested"),
    true,
  );
  assert.equal(
    consistency.production_blockers.includes(
      "native_launcher_mapped_process_image_identity_unbound"
    ),
    true,
  );
  assert.throws(() => assertVerifiedDarwinNativeFixtureContractConsistency(clone(consistency)));
  assert.throws(
    () => bindDarwinNativeFixtureContractConsistency(record, clone(verified)),
    safeRejection,
  );

  for (const field of [
    "declared_launch_plan_digest",
    "openat_fstatat_walk_digest",
    "fd_enumeration_digest",
  ]) {
    const drifted = nativeFixtureContractRecordForVerified(verified, {
      [field]: digest(`forked-native-fixture-${field}`),
    });
    assert.throws(
      () => bindDarwinNativeFixtureContractConsistency(drifted, verified),
      safeRejection,
    );
  }
  const callerSelectedPathHash = nativeFixtureContractRecordForVerified(verified, {
    native_launcher_on_disk_path_object_sha256: digest("caller-selected-path-hash"),
  });
  const callerSelectedConsistency = bindDarwinNativeFixtureContractConsistency(
    callerSelectedPathHash,
    verified,
  );
  assert.equal(callerSelectedConsistency.fixture_contract_consistent, true);
  assert.equal(callerSelectedConsistency.native_fixture_record_provenance_attested, false);
  let getterCalls = 0;
  const accessorRecord = { ...record };
  Object.defineProperty(accessorRecord, "declared_native_evidence_digest", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return record.declared_native_evidence_digest;
    },
  });
  assert.throws(
    () => bindDarwinNativeFixtureContractConsistency(accessorRecord, verified),
    safeRejection,
  );
  assert.equal(getterCalls, 0);
  assert.throws(
    () => bindDarwinNativeFixtureContractConsistency(new Proxy(record, {}), verified),
    safeRejection,
  );

  const cachedRecordModule = require.cache[nativeRecordModulePath];
  const originalExports = cachedRecordModule.exports;
  let substitutedCalls = 0;
  try {
    cachedRecordModule.exports = Object.freeze({
      normalizeDarwinNativeFixtureContractRecord() {
        substitutedCalls += 1;
        throw new Error("late native record module substitution reached");
      },
    });
    const secondConsistency = bindDarwinNativeFixtureContractConsistency(record, verified);
    assert.equal(
      assertVerifiedDarwinNativeFixtureContractConsistency(secondConsistency),
      secondConsistency,
    );
  } finally {
    cachedRecordModule.exports = originalExports;
  }
  assert.equal(substitutedCalls, 0);
});

test("all closed launcher roles bind bundle, principal, argv, environment, fd, and credentials", async (t) => {
  for (const role of DARWIN_LAUNCH_ROLES) {
    await t.test(role, () => {
      const fixture = makeLauncherFixture(role);
      assert.equal(assertConformanceDarwinLaunchTicketSigner(fixture.signer), fixture.signer);
      assert.equal(
        assertConformanceDarwinLaunchAuthorityResolver(fixture.authorityPort),
        fixture.authorityPort,
      );
      assert.equal(
        assertConformanceDarwinNativeLaunchResolver(fixture.nativePort),
        fixture.nativePort,
      );
      assert.equal(assertConformanceDarwinLaunchReplayPort(fixture.replayPort), fixture.replayPort);

      const verified = fixture.verify();
      assert.equal(assertVerifiedDarwinLaunchPlan(verified), verified);
      assert.equal(verified.role, role);
      assert.equal(verified.target_principal_id, fixture.plan.target_principal_id);
      assert.equal(verified.authorizer_principal_id, fixture.plan.authorizer_principal_id);
      assert.equal(verified.argv_digest, darwinLaunchArgvDigest(fixture.plan));
      assert.equal(verified.environment_digest, darwinLaunchEnvironmentDigest(fixture.plan));
      assert.equal(verified.fd_set_digest, darwinLaunchFdSetDigest(fixture.plan));
      assert.equal(
        verified.credential_plan_digest,
        darwinLaunchCredentialPlanDigest(fixture.plan),
      );
      assert.deepEqual(fixture.calls, { authority: 2, native: 2, replay: 1 });
      assert.equal(verified.import_inert, true);
      assert.equal(verified.activating, false);
      assert.equal(verified.production_attested, false);
      assert.equal(verified.production_ready, false);
      assert.equal(verified.separate_identity_authorized, false);
      assert.equal(verified.hardware_authorized, false);
      assert.equal(
        verified.production_blockers.includes("verified_bundle_brand_bridge_packaging_missing"),
        true,
      );
      const serialized = JSON.stringify(verified);
      assert.doesNotMatch(serialized, /\/Library\/HackerBob/u);
      assert.doesNotMatch(serialized, /authority_private_key|"signature"\s*:|device_handle/u);
    });
  }
});

function mutablePlan() {
  return planFor(
    "active_device_worker",
    "worker-bundle:active_device_worker-launcher-v1",
  );
}

function assertPlanMutationRejected(mutator) {
  const candidate = mutablePlan();
  mutator(candidate);
  assert.throws(() => normalizeDarwinLaunchPlan(candidate));
}

test("launch plan rejects every environment entry including PATH, DYLD, and NODE injection", () => {
  for (const entry of [
    "PATH=/tmp/bin",
    "DYLD_INSERT_LIBRARIES=/tmp/inject.dylib",
    "DYLD_LIBRARY_PATH=/tmp/lib",
    "NODE_OPTIONS=--require=/tmp/inject.js",
    "NODE_PATH=/tmp/modules",
    "LANG=en_US.UTF-8",
  ]) {
    assertPlanMutationRejected((plan) => { plan.environment = [entry]; });
  }
  assertPlanMutationRejected((plan) => { plan.environment_policy = "allowlist_v1"; });
});

test("launch plan rejects shell, PATH lookup, argv expansion, and non-canonical paths", () => {
  const mutations = [
    (plan) => { plan.shell_allowed = true; },
    (plan) => { plan.path_lookup_allowed = true; },
    (plan) => { plan.execution_method = "posix_spawnp_v1"; },
    (plan) => { plan.argv = ["/bin/sh", "-c", "id", "--role", plan.role, "--config"]; },
    (plan) => { plan.argv[1] = `${plan.entrypoint_path}--eval`; },
    (plan) => { plan.executable_path = "bin/node"; },
    (plan) => { plan.entrypoint_path = `${plan.working_directory}/lib/../worker.js`; },
    (plan) => { plan.config_manifest_path = "/tmp/worker.json"; },
    (plan) => { plan.working_directory = "/Library/HackerBob/Bundles/active_device_worker/"; },
  ];
  for (const mutate of mutations) assertPlanMutationRejected(mutate);
});

test("launch plan rejects inherited descriptor ambiguity and role-purpose drift", () => {
  const mutations = [
    (plan) => { plan.allowed_file_descriptors[0].fd = 2; },
    (plan) => { plan.allowed_file_descriptors[1].fd = plan.allowed_file_descriptors[0].fd; },
    (plan) => { plan.allowed_file_descriptors.reverse(); },
    (plan) => { plan.allowed_file_descriptors[1].purpose = plan.allowed_file_descriptors[0].purpose; },
    (plan) => {
      plan.allowed_file_descriptors[1].capability_digest =
        plan.allowed_file_descriptors[0].capability_digest;
    },
    (plan) => { plan.allowed_file_descriptors[0].purpose = "cleanup_device_handle"; },
    (plan) => { plan.allowed_file_descriptors[0].owner_principal_id = "principal:cleanup-worker"; },
    (plan) => { plan.allowed_file_descriptors[0].one_shot = false; },
    (plan) => { plan.allowed_file_descriptors[0].inherited_across_exec = false; },
    (plan) => { plan.allowed_file_descriptors.pop(); },
    (plan) => { plan.all_unlisted_file_descriptors_closed = false; },
    (plan) => { plan.fd_close_policy = "inherit_all_v1"; },
  ];
  for (const mutate of mutations) assertPlanMutationRejected(mutate);
});

test("launch plan rejects principal aliasing, root identities, and credential readback drift", () => {
  const mutations = [
    (plan) => { plan.principal_matrix[1].uid = plan.principal_matrix[0].uid; },
    (plan) => { plan.principal_matrix[1].gid = plan.principal_matrix[0].gid; },
    (plan) => { plan.principal_matrix[1].uid = 0; },
    (plan) => { plan.principal_matrix[1].supplementary_groups[0].gid = 701; },
    (plan) => { plan.principal_matrix[2].supplementary_groups[0].gid = 702; },
    (plan) => { plan.principal_matrix[0].supplementary_groups[0].gid = 601; },
    (plan) => { plan.target_principal_id = "principal:cleanup-worker"; },
    (plan) => { plan.authorizer_principal_id = "principal:safety-supervisor"; },
    (plan) => { plan.saved_uid += 1; },
    (plan) => { plan.effective_gid += 1; },
  ];
  for (const mutate of mutations) assertPlanMutationRejected(mutate);
});

test("normalizers require exact own-data schemas and ignore inherited toJSON", () => {
  const plan = mutablePlan();
  let getterCalls = 0;
  const accessorPlan = { ...plan };
  Object.defineProperty(accessorPlan, "role", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return plan.role;
    },
  });
  assert.throws(() => normalizeDarwinLaunchPlan(accessorPlan));
  assert.equal(getterCalls, 0);
  assert.throws(() => normalizeDarwinLaunchPlan(new Proxy(plan, {})));

  let toJSONCalls = 0;
  const inherited = Object.create({
    toJSON() {
      toJSONCalls += 1;
      return {};
    },
  });
  Object.assign(inherited, plan);
  assert.throws(() => normalizeDarwinLaunchPlan(inherited));
  assert.equal(toJSONCalls, 0);
});

test("worker bundle must carry the broker's actual private verified brand", () => {
  const fixture = makeLauncherFixture();
  const forgedBundle = clone(fixture.verifiedBundle);
  assert.throws(() => fixture.verify(fixture.ticket, forgedBundle), safeRejection);
  assert.deepEqual(fixture.calls, { authority: 0, native: 0, replay: 0 });

  const fakeAuthority = Object.freeze({ ...fixture.authorityPort });
  assert.throws(
    () => fixture.verify(fixture.ticket, fixture.verifiedBundle, { authority: fakeAuthority }),
    safeRejection,
  );
  assert.deepEqual(fixture.calls, { authority: 0, native: 0, replay: 0 });
});

test("self-consistent ticket digest fork still fails Ed25519 authentication", () => {
  const fixture = makeLauncherFixture();
  const forged = clone(fixture.ticket);
  const signature = forged.authentication.signature;
  forged.authentication.signature = `${signature.startsWith("A") ? "B" : "A"}${signature.slice(1)}`;
  const basis = {
    version: forged.version,
    kind: forged.kind,
    domain: forged.domain,
    payload: forged.payload,
    payload_digest: forged.payload_digest,
    authentication: forged.authentication,
  };
  forged.ticket_digest = hashCanonicalJson(basis);
  fixture.behavior.authority = (current) => ({
    ...current,
    current_ticket_digest: forged.ticket_digest,
  });

  assert.equal(normalizeSignedDarwinLaunchTicket(forged).ticket_digest, forged.ticket_digest);
  assert.throws(() => fixture.verify(forged), safeRejection);
  assert.deepEqual(fixture.calls, { authority: 1, native: 0, replay: 0 });
});

test("ticket freshness, revocation, and post-reservation authority drift fail closed", async (t) => {
  await t.test("expired", () => {
    const fixture = makeLauncherFixture();
    fixture.behavior.authority = (current) => ({
      ...current,
      trusted_now: "2026-07-19T04:00:21.000Z",
    });
    assert.throws(() => fixture.verify(), safeRejection);
    assert.deepEqual(fixture.calls, { authority: 1, native: 0, replay: 0 });
  });

  await t.test("revoked", () => {
    const fixture = makeLauncherFixture();
    fixture.behavior.authority = (current) => ({ ...current, trusted: false, revoked: true });
    assert.throws(() => fixture.verify(), safeRejection);
    assert.deepEqual(fixture.calls, { authority: 1, native: 0, replay: 0 });
  });

  await t.test("epoch drift after reservation", () => {
    const fixture = makeLauncherFixture();
    fixture.behavior.authority = (current, call) => call === 1 ? current : {
      ...current,
      authority_epoch: current.authority_epoch + 1,
    };
    assert.throws(() => fixture.verify(), safeRejection);
    assert.deepEqual(fixture.calls, { authority: 2, native: 1, replay: 1 });
  });
});

test("ticket signer refuses long-lived, weak-nonce, or production-authorizing tickets", () => {
  const fixture = makeLauncherFixture();
  const tooLong = clone(fixture.payload);
  tooLong.expires_at = "2026-07-19T04:01:00.000Z";
  assert.throws(() => signDarwinLaunchTicket(fixture.signer, tooLong));

  const weakNonce = clone(fixture.payload);
  weakNonce.nonce = "short";
  assert.throws(() => signDarwinLaunchTicket(fixture.signer, weakNonce));

  for (const field of [
    "production_attested",
    "production_ready",
    "separate_identity_authorized",
    "hardware_authorized",
  ]) {
    const broadened = clone(fixture.payload);
    broadened[field] = true;
    assert.throws(() => signDarwinLaunchTicket(fixture.signer, broadened));
  }
});

test("native evidence requires root-owned immutable openat closure and exact readback", () => {
  const fixture = makeLauncherFixture();
  const mutations = [
    (evidence) => { evidence.root_owner_uid = 1; },
    (evidence) => { evidence.root_owner_gid = 1; },
    (evidence) => { evidence.root_mode = 0o700; },
    (evidence) => { evidence.all_path_components_openat_verified = false; },
    (evidence) => { evidence.all_bundle_objects_root_owned = false; },
    (evidence) => { evidence.all_bundle_objects_immutable = false; },
    (evidence) => { evidence.entrypoint_content_digest = digest("forked-entrypoint"); },
    (evidence) => { evidence.runtime_identity_digest = digest("forked-runtime"); },
    (evidence) => { evidence.allowed_fd_set_digest = digest("forked-fd-set"); },
    (evidence) => { evidence.all_unlisted_fds_closed = false; },
    (evidence) => { evidence.stdio_reopened_dev_null = false; },
    (evidence) => { evidence.saved_uid += 1; },
    (evidence) => { evidence.effective_gid += 1; },
    (evidence) => { evidence.supplementary_groups[0].gid += 1; },
    (evidence) => { evidence.credential_drop_complete = false; },
    (evidence) => { evidence.native_launcher_code_signing_scheme = "none"; },
    (evidence) => { evidence.native_launcher_code_signing_complete = false; },
    (evidence) => {
      evidence.fd_enumeration_digest = evidence.openat_fstatat_walk_digest;
    },
  ];
  for (const mutate of mutations) {
    const candidate = clone(fixture.nativeEvidence);
    mutate(candidate);
    assert.throws(() => normalizeDarwinNativeLaunchEvidence(
      candidate,
      fixture.plan,
      fixture.projection,
    ));
  }
});

test("second native snapshot drift after reservation fails closed", () => {
  const fixture = makeLauncherFixture();
  fixture.behavior.native = (evidence, call) => {
    if (call === 2) evidence.working_directory_identity_digest = digest("native-root-raced");
    return evidence;
  };
  assert.throws(() => fixture.verify(), safeRejection);
  assert.deepEqual(fixture.calls, { authority: 2, native: 2, replay: 1 });
});

test("replay is one-use and every failed reservation still forces authority readback", async (t) => {
  await t.test("one-use replay", () => {
    const fixture = makeLauncherFixture();
    assertVerifiedDarwinLaunchPlan(fixture.verify());
    assert.throws(() => fixture.verify(), safeRejection);
    assert.deepEqual(fixture.calls, { authority: 4, native: 3, replay: 2 });
  });

  await t.test("lost replay reply", () => {
    const fixture = makeLauncherFixture();
    fixture.behavior.replay = () => {
      throw new Error("sensitive replay transport path and nonce");
    };
    assert.throws(() => fixture.verify(), safeRejection);
    assert.deepEqual(fixture.calls, { authority: 2, native: 1, replay: 1 });
  });

  await t.test("malformed replay reply", () => {
    const fixture = makeLauncherFixture();
    fixture.behavior.replay = () => ({ disposition: "reserved" });
    assert.throws(() => fixture.verify(), safeRejection);
    assert.deepEqual(fixture.calls, { authority: 2, native: 1, replay: 1 });
  });
});

test("callback ports are synchronous, privately branded, and non-reentrant", () => {
  const fixture = makeLauncherFixture();
  let asyncCalls = 0;
  const asyncAuthority = createConformanceDarwinLaunchAuthorityResolver({
    port_id: "launcher_async_authority",
    resolve_current_authority() {
      asyncCalls += 1;
      return Promise.resolve({});
    },
  });
  assert.throws(
    () => fixture.verify(fixture.ticket, fixture.verifiedBundle, { authority: asyncAuthority }),
    safeRejection,
  );
  assert.equal(asyncCalls, 1);
  assert.deepEqual(fixture.calls, { authority: 0, native: 0, replay: 0 });

  let getterCalls = 0;
  const boundaryInput = {
    verified_worker_bundle: fixture.verifiedBundle,
    authority_resolver_port: fixture.authorityPort,
    native_resolver_port: fixture.nativePort,
    replay_port: fixture.replayPort,
  };
  Object.defineProperty(boundaryInput, "ticket", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return fixture.ticket;
    },
  });
  assert.throws(() => verifyAndReserveDarwinLaunchTicket(boundaryInput), safeRejection);
  assert.equal(getterCalls, 0);
});

test("first live callback cannot redirect later ports or launcher hashing through prototypes", () => {
  const fixture = makeLauncherFixture();
  const hashPrototype = Object.getPrototypeOf(crypto.createHash("sha256"));
  const publicKeyPrototype = Object.getPrototypeOf(fixture.authorityFixture.keys.publicKey);
  const isKeyObjectDescriptor = Object.getOwnPropertyDescriptor(utilTypes, "isKeyObject");
  if (process.versions.node.startsWith("20.")) {
    assert.equal(isKeyObjectDescriptor.writable, false);
    assert.equal(isKeyObjectDescriptor.configurable, false);
  }
  const targets = [
    [WeakMap.prototype, "get"],
    [WeakMap.prototype, "has"],
    [WeakMap.prototype, "set"],
    [WeakSet.prototype, "has"],
    [WeakSet.prototype, "add"],
    [WeakSet.prototype, "delete"],
    [hashPrototype, "update"],
    [hashPrototype, "digest"],
    [publicKeyPrototype, "export"],
    [utilTypes, "isPromise"],
    [utilTypes, "isProxy"],
    [Number, "isFinite"],
    [Number, "isSafeInteger"],
    [Array.prototype, Symbol.iterator],
  ];
  const originals = [];
  for (let index = 0; index < targets.length; index += 1) {
    originals[index] = [
      targets[index][0],
      targets[index][1],
      Object.getOwnPropertyDescriptor(targets[index][0], targets[index][1]),
    ];
  }
  let redirectedCalls = 0;
  const redirectedProperties = [];
  let tampered = false;
  fixture.behavior.native = (evidence, call) => {
    if (call === 1 && !tampered) {
      tampered = true;
      for (let index = 0; index < originals.length; index += 1) {
        const prototype = originals[index][0];
        const property = originals[index][1];
        const descriptor = originals[index][2];
        Object.defineProperty(prototype, property, {
          ...descriptor,
          value() {
            redirectedProperties[redirectedCalls] = String(property);
            redirectedCalls += 1;
            throw new Error("redirected mutable prototype reached");
          },
        });
      }
    }
    return evidence;
  };

  let verified;
  let verificationError;
  try {
    verified = fixture.verify();
  } catch (error) {
    verificationError = error;
  } finally {
    for (let index = 0; index < originals.length; index += 1) {
      Object.defineProperty(originals[index][0], originals[index][1], originals[index][2]);
    }
  }
  assert.equal(
    verificationError,
    undefined,
    `redirected properties: ${redirectedProperties.join(",")}; calls=${JSON.stringify(fixture.calls)}`,
  );
  assert.equal(redirectedCalls, 0);
  assert.equal(assertVerifiedDarwinLaunchPlan(verified), verified);
  assert.deepEqual(fixture.calls, { authority: 2, native: 2, replay: 1 });
});

test("callback failures are stable and redact paths, identities, descriptors, and signatures", () => {
  const fixture = makeLauncherFixture();
  fixture.behavior.authority = () => {
    throw new Error(
      "secret /Library/HackerBob/Bundles/active_device_worker uid=502 fd=10 signature=abc",
    );
  };
  let observed;
  try {
    fixture.verify();
  } catch (error) {
    observed = error;
  }
  assert.equal(safeRejection(observed), true);
  assert.doesNotMatch(observed.stack, /uid=502|fd=10|signature=abc/u);
  assert.deepEqual(fixture.calls, { authority: 1, native: 0, replay: 0 });
});
