"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const test = require("node:test");

const api = require("../lib/index.js");

const ROLE_IDS = [
  "operator_control",
  "grant_issuer",
  "active_device_worker",
  "safety_supervisor",
  "cleanup_worker",
  "privileged_launcher",
];
const EDGE_MATRIX = [
  ["operator_control", "grant_issuer", "control", "grant_request"],
  ["grant_issuer", "privileged_launcher", "authority", "launch_ticket"],
  ["privileged_launcher", "active_device_worker", "launch", "worker_launch"],
  ["privileged_launcher", "safety_supervisor", "launch", "safety_launch"],
  ["privileged_launcher", "cleanup_worker", "launch", "cleanup_launch"],
  ["active_device_worker", "safety_supervisor", "safety", "heartbeat"],
  ["safety_supervisor", "active_device_worker", "safety", "stop_authority"],
  ["safety_supervisor", "cleanup_worker", "recovery", "cleanup_authority"],
  ["cleanup_worker", "safety_supervisor", "recovery", "cleanup_receipt"],
];
const ISSUED_AT = "2026-07-19T04:00:00.000Z";
const OBSERVED_AT = "2026-07-19T04:05:00.000Z";
const OBSERVATION_EXPIRES_AT = "2026-07-19T04:10:00.000Z";
const POLICY_EXPIRES_AT = "2026-07-19T06:00:00.000Z";
const NOW = "2026-07-19T04:06:00.000Z";

function digest(label) {
  return crypto.createHash("sha256").update(label).digest("hex");
}

function makeRole(roleId, index) {
  const launcher = roleId === "privileged_launcher";
  const launchChild = roleId === "active_device_worker"
    || roleId === "safety_supervisor" || roleId === "cleanup_worker";
  return {
    role_id: roleId,
    principal_id: `principal:bob_${roleId}`,
    uid: launcher ? 0 : 5_011 + index,
    primary_gid: launcher ? 0 : 6_011 + index,
    supplementary_gids: launcher ? [] : [7_011 + index],
    non_root: !launcher,
    service_account: true,
    login_policy: "no_login",
    interactive_login_allowed: false,
    expected_launcher_role_id: launchChild ? "privileged_launcher" : null,
    executable_digest: digest(`role:${roleId}:executable`),
    bundle_digest: digest(`role:${roleId}:bundle`),
    prebuild_digest: digest(`role:${roleId}:prebuild`),
    launch_attestation_digest: digest(`role:${roleId}:launch`),
    root_authorization_digest: launcher ? digest("launcher:root-authorization") : null,
  };
}

function makeDelegationProfile(profileId, roleId, phase, mechanism, precommitted,
  index) {
  return {
    order: index,
    profile_id: profileId,
    delegate_role_id: roleId,
    phase,
    delivery_mechanism: mechanism,
    permissions: ["read", "write"],
    descriptor_policy_digest: digest(`descriptor-policy:${profileId}`),
    capability_binding_digest: digest(`capability-binding:${profileId}`),
    exclusive_across_profiles: true,
    precommitted,
    closed_when_inactive: true,
    revocation_required: true,
  };
}

function makePolicyInput() {
  return {
    version: 1,
    policy_id: "darwin-principal-acl:fixture",
    policy_epoch: 7,
    issued_at: ISSUED_AT,
    expires_at: POLICY_EXPIRES_AT,
    max_observation_age_seconds: 600,
    os_expectation: {
      platform: "darwin",
      os_version_digest: digest("os:version"),
      os_build_digest: digest("os:build"),
      boot_epoch_digest: digest("os:boot-epoch"),
      security_epoch: 7,
    },
    observer_expectation: {
      implementation_digest: digest("observer:implementation"),
      prebuild_digest: digest("observer:prebuild"),
      bundle_digest: digest("observer:bundle"),
      launch_attestation_digest: digest("observer:launch"),
      code_signature_requirement_digest: digest("observer:code-signature"),
      observation_signing_identity_digest: digest("observer:signing-identity"),
    },
    roles: ROLE_IDS.map(makeRole),
    edges: EDGE_MATRIX.map((edge) => ({
      from_role_id: edge[0],
      to_role_id: edge[1],
      channel: edge[2],
      purpose: edge[3],
      mutual_authentication_required: true,
    })),
    resources: [{
      resource_id: "instrument:fixture",
      provider_id: "provider_neutral",
      resource_class: "contactless_research_instrument",
      device_identity_digest: digest("device:identity"),
      ioregistry_identity_digest: digest("device:ioregistry"),
      device_path_digest: digest("device:path"),
      device_file_id_digest: digest("device:file-id"),
      device_major_minor_digest: digest("device:major-minor"),
      openat_directory_identity_digest: digest("device:openat-directory"),
      owner_uid: 0,
      owner_gid: 0,
      mode: 0o600,
      filesystem_open_role_id: "privileged_launcher",
      direct_service_account_acl_allowed: false,
      acl_inheritance: "none",
      deny_unlisted: true,
      everyone_access_allowed: false,
      broad_group_access_allowed: false,
      acl_entries: [],
      launcher_authorization_mode: "root_device_capture_v1",
      launcher_entitlement_state: "absent",
      launcher_io_service_authorize_state: "not_required",
      launcher_authorization_scope_digest: digest("device:authorization-scope"),
      delegation_policy_digest: digest("device:delegation-policy"),
      descriptor_inventory_policy_digest: digest("device:descriptor-inventory-policy"),
      delegation_profiles: [
        makeDelegationProfile(
          "active_device_session",
          "active_device_worker",
          "active",
          "exclusive_delegated_descriptor",
          false,
          0,
        ),
        makeDelegationProfile(
          "cleanup_recovery_session",
          "cleanup_worker",
          "cleanup",
          "precommitted_cleanup_descriptor",
          true,
          1,
        ),
      ],
    }],
  };
}

function appendSecondPolicyResource(input) {
  const second = structuredClone(input.resources[0]);
  second.resource_id = "instrument:fixture-second";
  second.device_identity_digest = digest("device:second:identity");
  second.ioregistry_identity_digest = digest("device:second:ioregistry");
  second.device_path_digest = digest("device:second:path");
  second.device_file_id_digest = digest("device:second:file-id");
  second.device_major_minor_digest = digest("device:second:major-minor");
  second.launcher_authorization_scope_digest = digest("device:second:scope");
  second.delegation_policy_digest = digest("device:second:delegation-policy");
  second.descriptor_inventory_policy_digest = digest(
    "device:second:descriptor-inventory-policy",
  );
  for (const profile of second.delegation_profiles) {
    profile.descriptor_policy_digest = digest(
      `device:second:descriptor:${profile.profile_id}`,
    );
    profile.capability_binding_digest = digest(
      `device:second:capability:${profile.profile_id}`,
    );
  }
  input.resources.push(second);
  return second;
}

function roleFor(policy, roleId) {
  return policy.roles.find((role) => role.role_id === roleId);
}

function makeObservationInput(policy) {
  const launcher = roleFor(policy, "privileged_launcher");
  const resource = policy.resources[0];
  return {
    version: 1,
    observation_id: "darwin-observation:fixture",
    policy_id: policy.policy_id,
    policy_digest: policy.policy_digest,
    policy_epoch: policy.policy_epoch,
    observed_at: OBSERVED_AT,
    expires_at: OBSERVATION_EXPIRES_AT,
    os: {
      platform: policy.os_expectation.platform,
      os_version_digest: policy.os_expectation.os_version_digest,
      os_build_digest: policy.os_expectation.os_build_digest,
      boot_epoch_digest: policy.os_expectation.boot_epoch_digest,
      security_epoch: policy.os_expectation.security_epoch,
    },
    accounts: policy.roles.map((role) => ({
      role_id: role.role_id,
      principal_id: role.principal_id,
      account_record_digest: digest(`account:${role.role_id}:record`),
      account_name_digest: digest(`account:${role.role_id}:name`),
      uid: role.uid,
      primary_gid: role.primary_gid,
      supplementary_gids: [...role.supplementary_gids],
      service_account: true,
      login_policy: "no_login",
      interactive_login_allowed: false,
      record_source: "opendirectory_native",
    })),
    groups: policy.roles.map((role) => ({
      role_id: role.role_id,
      principal_id: role.principal_id,
      primary_group_record_digest: digest(`group:${role.role_id}:primary`),
      supplementary_group_records_digest: digest(`group:${role.role_id}:supplementary`),
      primary_gid: role.primary_gid,
      supplementary_gids: [...role.supplementary_gids],
      membership_complete: true,
      no_unlisted_memberships: true,
      record_epoch: policy.policy_epoch,
    })),
    credentials: policy.roles.map((role) => ({
      role_id: role.role_id,
      principal_id: role.principal_id,
      real_uid: role.uid,
      effective_uid: role.uid,
      saved_uid: role.uid,
      real_gid: role.primary_gid,
      effective_gid: role.primary_gid,
      saved_gid: role.primary_gid,
      supplementary_gids: [...role.supplementary_gids],
      audit_token_digest: digest(`credential:${role.role_id}:audit-token`),
      process_start_digest: digest(`credential:${role.role_id}:process-start`),
      executable_digest: role.executable_digest,
      bundle_digest: role.bundle_digest,
      prebuild_digest: role.prebuild_digest,
      launch_attestation_digest: role.launch_attestation_digest,
      root_claimed: role.role_id === "privileged_launcher",
      root_authorization_digest: role.root_authorization_digest,
      root_authorization_qualified: role.role_id === "privileged_launcher",
    })),
    resources: [{
      resource_id: resource.resource_id,
      provider_id: resource.provider_id,
      resource_class: resource.resource_class,
      device_identity_digest: resource.device_identity_digest,
      ioregistry_identity_digest: resource.ioregistry_identity_digest,
      device_path_digest: resource.device_path_digest,
      device_file_id_digest: resource.device_file_id_digest,
      device_major_minor_digest: resource.device_major_minor_digest,
      device_type: "character",
      open_method: "openat_no_follow",
      openat_directory_identity_digest: resource.openat_directory_identity_digest,
      filesystem_open_role_id: resource.filesystem_open_role_id,
      no_symlink: true,
      hardlink_count: 1,
      owner_uid: resource.owner_uid,
      owner_gid: resource.owner_gid,
      mode: resource.mode,
      acl_entries: [],
      direct_service_account_acl_present: false,
      acl_inherited: false,
      acl_widened: false,
      delegation_policy_digest: resource.delegation_policy_digest,
      mutual_exclusion_enforced: true,
      safety_raw_transport_present: false,
      descriptor_inventory_complete: true,
      descriptor_inventory_digest: resource.descriptor_inventory_policy_digest,
      descriptor_inventory_before_digest: resource.descriptor_inventory_policy_digest,
      descriptor_inventory_after_digest: resource.descriptor_inventory_policy_digest,
      descriptor_custody_state: "closed",
      launcher_descriptor_present: false,
      active_descriptor_present: false,
      cleanup_descriptor_present: false,
      unlisted_descriptor_count: 0,
      inherited_descriptor_count: 0,
      launcher_redundant_descriptor_closed: true,
      stat_before_digest: digest("device:stat-snapshot"),
      stat_after_digest: digest("device:stat-snapshot"),
      ioregistry_before_digest: digest("device:ioregistry-snapshot"),
      ioregistry_after_digest: digest("device:ioregistry-snapshot"),
      stable: true,
    }],
    ancestry: policy.roles.map((role) => ({
      role_id: role.role_id,
      principal_id: role.principal_id,
      direct_parent_role_id: role.expected_launcher_role_id,
      direct_parent_principal_id: role.expected_launcher_role_id == null
        ? null : launcher.principal_id,
      ancestry_digest: digest(`ancestry:${role.role_id}`),
      stable: true,
    })),
    authorizations: [{
      resource_id: resource.resource_id,
      role_id: launcher.role_id,
      principal_id: launcher.principal_id,
      authorization_mode: resource.launcher_authorization_mode,
      entitlement_state: resource.launcher_entitlement_state,
      entitlement_digest: null,
      io_service_authorize_state: resource.launcher_io_service_authorize_state,
      io_service_authorize_digest: null,
      authorization_scope_digest: resource.launcher_authorization_scope_digest,
      root_authorization_digest: launcher.root_authorization_digest,
      root_claimed: true,
      root_authorization_qualified: true,
    }],
    delegations: resource.delegation_profiles.map((profile) => ({
      resource_id: resource.resource_id,
      profile_id: profile.profile_id,
      delegate_role_id: profile.delegate_role_id,
      delegate_principal_id: roleFor(policy, profile.delegate_role_id).principal_id,
      delivery_mechanism: profile.delivery_mechanism,
      descriptor_policy_digest: profile.descriptor_policy_digest,
      capability_binding_digest: profile.capability_binding_digest,
      mutual_exclusion_qualified: true,
      precommitted: profile.precommitted,
      closed_at_observation: true,
      raw_path_access_present: false,
    })),
    native_evidence: {
      observer_implementation_digest: policy.observer_expectation.implementation_digest,
      observer_prebuild_digest: policy.observer_expectation.prebuild_digest,
      observer_bundle_digest: policy.observer_expectation.bundle_digest,
      observer_launch_attestation_digest:
        policy.observer_expectation.launch_attestation_digest,
      observer_code_signature_requirement_digest:
        policy.observer_expectation.code_signature_requirement_digest,
      observation_signing_identity_digest:
        policy.observer_expectation.observation_signing_identity_digest,
      observation_signature_digest: digest("observation:signature"),
      before_snapshot_digest: digest("observation:snapshot"),
      after_snapshot_digest: digest("observation:snapshot"),
      stable: true,
      read_only: true,
      native_attested: true,
      observation_signature_verified: true,
      prebuild_qualified: true,
      launch_attestation_qualified: true,
      hil_qualified: false,
    },
  };
}

function createFixture() {
  const policy = api.createDarwinPrincipalAclPolicy(makePolicyInput());
  const observationInput = makeObservationInput(policy);
  const observation = api.normalizeDarwinPrincipalAclObservation(observationInput);
  return { policy, observationInput, observation };
}

function expectContractRejection(callback) {
  assert.throws(callback, (error) => error != null
    && error.code === "darwin_principal_acl_rejected"
    && error.message === "Darwin principal and device ACL contract was rejected");
}

function doctor(policy, observation, now = NOW) {
  return api.runDarwinPrincipalAclDoctor({ policy, observation, now });
}

test("import and policy construction are inert and load no operational modules", () => {
  const entry = path.resolve(__dirname, "../lib/index.js");
  const source = fs.readFileSync(path.resolve(__dirname, "../lib/principal-acl.js"), "utf8");
  assert.doesNotMatch(source, /require\(["']node:(?:fs|child_process|net|http|https|tls|dgram|worker_threads)["']\)/u);
  assert.doesNotMatch(source, /\bprocess\s*\./u);
  const serializedInput = JSON.stringify(makePolicyInput());
  const childSource = `
    const Module = require("node:module");
    const originalLoad = Module._load;
    const forbidden = new Set([
      "node:fs", "node:child_process", "node:net", "node:http", "node:https",
      "node:tls", "node:dgram", "node:worker_threads"
    ]);
    Module._load = function(request) {
      if (forbidden.has(request)) throw new Error("operational module loaded: " + request);
      return Reflect.apply(originalLoad, this, arguments);
    };
    const loaded = require(${JSON.stringify(entry)});
    const policy = loaded.createDarwinPrincipalAclPolicy(
      JSON.parse(${JSON.stringify(serializedInput)})
    );
    String.prototype.charCodeAt = () => { throw new Error("ambient charCodeAt used"); };
    String.prototype.padStart = () => { throw new Error("ambient padStart used"); };
    Number.prototype.toString = () => { throw new Error("ambient number toString used"); };
    Number.isSafeInteger = () => { throw new Error("ambient Number.isSafeInteger used"); };
    const hardenedPolicy = loaded.createDarwinPrincipalAclPolicy(
      JSON.parse(${JSON.stringify(serializedInput)})
    );
    if (hardenedPolicy.policy_digest !== policy.policy_digest) process.exitCode = 3;
    if (policy.production_ready || policy.hardware_access_authorized) process.exitCode = 2;
  `;
  execFileSync(process.execPath, ["-e", childSource], { stdio: "pipe" });
});

test("policy fixes six principals and a launcher-opened root-only descriptor model", () => {
  const policy = api.createDarwinPrincipalAclPolicy(makePolicyInput());
  assert.deepEqual([...api.DARWIN_PRINCIPAL_ACL_ROLE_IDS], ROLE_IDS);
  assert.deepEqual(
    [...api.DARWIN_PRINCIPAL_ACL_DESCRIPTOR_DELEGATE_ROLE_IDS],
    ["active_device_worker", "cleanup_worker"],
  );
  assert.equal(policy.roles.length, 6);
  assert.equal(policy.edges.length, 9);
  assert.equal(policy.resources[0].owner_uid, 0);
  assert.equal(policy.resources[0].owner_gid, 0);
  assert.equal(policy.resources[0].mode, 0o600);
  assert.equal(policy.resources[0].filesystem_open_role_id, "privileged_launcher");
  assert.match(policy.resources[0].descriptor_inventory_policy_digest, /^[a-f0-9]{64}$/u);
  assert.equal(policy.resources[0].acl_entries.length, 0);
  assert.equal(policy.resources[0].direct_service_account_acl_allowed, false);
  assert.deepEqual(
    policy.resources[0].delegation_profiles.map((profile) => profile.delegate_role_id),
    ["active_device_worker", "cleanup_worker"],
  );
  assert.equal(policy.resources[0].delegation_profiles[1].precommitted, true);
  assert.equal(policy.production_ready, false);
  assert.equal(policy.hardware_access_authorized, false);
  assert.ok(Object.isFrozen(policy));
  assert.ok(Object.isFrozen(policy.resources[0].delegation_profiles));
});

test("policy admits multiple resources only when identity and authority digests are distinct", () => {
  const input = makePolicyInput();
  appendSecondPolicyResource(input);
  const policy = api.createDarwinPrincipalAclPolicy(input);
  assert.equal(policy.resources.length, 2);
  assert.notEqual(
    policy.resources[0].device_file_id_digest,
    policy.resources[1].device_file_id_digest,
  );
  assert.equal(
    policy.resources[0].openat_directory_identity_digest,
    policy.resources[1].openat_directory_identity_digest,
  );
});

test("policy rejects hostile records, aliasing, login drift, and widened access", async (t) => {
  const cases = [
    ["proxy", (input) => new Proxy(input, {})],
    ["accessor", (input) => {
      Object.defineProperty(input, "policy_id", {
        enumerable: true,
        configurable: true,
        get() { return "darwin-principal-acl:fixture"; },
      });
      return input;
    }],
    ["symbol key", (input) => {
      input[Symbol("hidden")] = true;
      return input;
    }],
    ["custom prototype", (input) => Object.assign(Object.create({ inherited: true }), input)],
    ["sparse roles", (input) => {
      delete input.roles[2];
      return input;
    }],
    ["uid alias", (input) => {
      input.roles[1].uid = input.roles[0].uid;
      return input;
    }],
    ["gid alias", (input) => {
      input.roles[1].supplementary_gids = [input.roles[0].primary_gid];
      return input;
    }],
    ["interactive login", (input) => {
      input.roles[2].interactive_login_allowed = true;
      return input;
    }],
    ["non-launcher root authorization", (input) => {
      input.roles[2].root_authorization_digest = digest("bad:root");
      return input;
    }],
    ["launcher root authorization absent", (input) => {
      input.roles[5].root_authorization_digest = null;
      return input;
    }],
    ["service account device ACL", (input) => {
      input.resources[0].acl_entries.push({
        order: 0,
        role_id: "active_device_worker",
        effect: "allow",
        permissions: ["read", "write"],
        inheritance: "none",
      });
      return input;
    }],
    ["group writable node", (input) => {
      input.resources[0].mode = 0o660;
      return input;
    }],
    ["safety descriptor delegation", (input) => {
      input.resources[0].delegation_profiles[0].delegate_role_id = "safety_supervisor";
      return input;
    }],
    ["cleanup capability not precommitted", (input) => {
      input.resources[0].delegation_profiles[1].precommitted = false;
      return input;
    }],
    ["broad group access", (input) => {
      input.resources[0].broad_group_access_allowed = true;
      return input;
    }],
    ["ambiguous root plus entitlement mode", (input) => {
      input.resources[0].launcher_authorization_mode = "entitlement_device_capture_v1";
      return input;
    }],
    ["root mode requiring IOServiceAuthorize", (input) => {
      input.resources[0].launcher_io_service_authorize_state = "required";
      return input;
    }],
    ["resource file identity alias", (input) => {
      const second = appendSecondPolicyResource(input);
      second.device_file_id_digest = input.resources[0].device_file_id_digest;
      return input;
    }],
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, () => {
      const input = mutate(makePolicyInput());
      expectContractRejection(() => api.createDarwinPrincipalAclPolicy(input));
    });
  }
});

test("matching native observation is diagnostic-only and still never authorizes hardware", () => {
  const { policy, observation } = createFixture();
  const result = doctor(policy, observation);
  assert.equal(result.status, "diagnostic_match_pending_native_prebuild_hil");
  assert.deepEqual(result.qualification_blockers, []);
  assert.equal(result.production_ready, false);
  assert.equal(result.hardware_access_authorized, false);
  assert.ok(result.readiness_blockers.includes(
    "caller_supplied_observation_is_diagnostic_only",
  ));
  assert.equal(observation.production_ready, false);
  assert.equal(observation.hardware_access_authorized, false);
});

test("doctor reports unavailable without treating absence as authority", () => {
  const policy = api.createDarwinPrincipalAclPolicy(makePolicyInput());
  const result = doctor(policy, null);
  assert.equal(result.status, "unavailable");
  assert.deepEqual(result.qualification_blockers, ["native_observation_unavailable"]);
  assert.equal(result.production_ready, false);
  assert.equal(result.hardware_access_authorized, false);
});

test("doctor blocks identity, ACL, descriptor, authorization, freshness, and fork drift",
  async (t) => {
    const cases = [
      ["OS binding", (input) => { input.os.os_build_digest = digest("drift:os"); },
        "darwin_os_binding_mismatch"],
      ["observation window before policy", (input) => {
        input.observed_at = "2026-07-19T03:59:00.000Z";
        input.expires_at = "2026-07-19T04:04:00.000Z";
      }, "observation_window_outside_policy"],
      ["UID alias", (input) => { input.accounts[1].uid = input.accounts[0].uid; },
        "uid_alias_detected"],
      ["audit token alias", (input) => {
        input.credentials[1].audit_token_digest = input.credentials[0].audit_token_digest;
      }, "credential_audit_token_alias_detected"],
      ["process start alias", (input) => {
        input.credentials[1].process_start_digest = input.credentials[0].process_start_digest;
      }, "credential_process_start_alias_detected"],
      ["observed resource identity alias", (input) => {
        const duplicate = structuredClone(input.resources[0]);
        duplicate.resource_id = "instrument:alias";
        input.resources.push(duplicate);
      }, "device_identity_alias_detected"],
      ["device path replacement", (input) => {
        input.resources[0].device_path_digest = digest("replacement:path");
      }, "device_identity_mismatch:instrument:fixture"],
      ["symlink", (input) => { input.resources[0].no_symlink = false; },
        "device_path_or_stat_mismatch:instrument:fixture"],
      ["hardlink", (input) => { input.resources[0].hardlink_count = 2; },
        "device_path_or_stat_mismatch:instrument:fixture"],
      ["stat fork", (input) => {
        input.resources[0].stat_after_digest = digest("replacement:stat");
      }, "device_replacement_or_instability:instrument:fixture"],
      ["direct service ACL", (input) => {
        input.resources[0].direct_service_account_acl_present = true;
      }, "root_only_device_node_mismatch:instrument:fixture"],
      ["widened ACL", (input) => {
        input.resources[0].acl_entries.push({
          order: 0,
          role_id: "everyone",
          effect: "allow",
          permissions: ["read", "write"],
          inheritance: "none",
        });
        input.resources[0].acl_widened = true;
      }, "root_only_device_node_mismatch:instrument:fixture"],
      ["safety raw transport", (input) => {
        input.resources[0].safety_raw_transport_present = true;
      }, "descriptor_delegation_policy_mismatch:instrument:fixture"],
      ["simultaneous descriptor state", (input) => {
        input.resources[0].active_descriptor_present = true;
        input.resources[0].cleanup_descriptor_present = true;
      }, "descriptor_inventory_unqualified:instrument:fixture"],
      ["incomplete descriptor inventory", (input) => {
        input.resources[0].descriptor_inventory_complete = false;
      }, "descriptor_inventory_unqualified:instrument:fixture"],
      ["descriptor inventory digest drift", (input) => {
        input.resources[0].descriptor_inventory_digest = digest("drift:inventory");
      }, "descriptor_inventory_unqualified:instrument:fixture"],
      ["descriptor inventory fork", (input) => {
        input.resources[0].descriptor_inventory_after_digest = digest("fork:inventory");
      }, "descriptor_inventory_unqualified:instrument:fixture"],
      ["launcher descriptor retained", (input) => {
        input.resources[0].launcher_descriptor_present = true;
      }, "descriptor_inventory_unqualified:instrument:fixture"],
      ["launcher duplicate not closed", (input) => {
        input.resources[0].launcher_redundant_descriptor_closed = false;
      }, "descriptor_inventory_unqualified:instrument:fixture"],
      ["unlisted descriptor", (input) => {
        input.resources[0].unlisted_descriptor_count = 1;
      }, "descriptor_inventory_unqualified:instrument:fixture"],
      ["inherited descriptor", (input) => {
        input.resources[0].inherited_descriptor_count = 1;
      }, "descriptor_inventory_unqualified:instrument:fixture"],
      ["active custody at closed snapshot", (input) => {
        input.resources[0].descriptor_custody_state = "active";
        input.resources[0].active_descriptor_present = true;
      }, "descriptor_inventory_unqualified:instrument:fixture"],
      ["cleanup custody at closed snapshot", (input) => {
        input.resources[0].descriptor_custody_state = "cleanup";
        input.resources[0].cleanup_descriptor_present = true;
      }, "descriptor_inventory_unqualified:instrument:fixture"],
      ["unqualified root", (input) => {
        input.credentials[5].root_authorization_digest = digest("drift:root");
      }, "privileged_launcher_root_unqualified"],
      ["entitlement drift", (input) => {
        input.authorizations[0].entitlement_state = "present";
        input.authorizations[0].entitlement_digest = digest("drift:entitlement");
      }, "launcher_device_authorization_unqualified:instrument:fixture"],
      ["IOServiceAuthorize unexpectedly used", (input) => {
        input.authorizations[0].io_service_authorize_state = "required";
        input.authorizations[0].io_service_authorize_digest = digest("drift:io-authorize");
      }, "launcher_device_authorization_unqualified:instrument:fixture"],
      ["cleanup not precommitted", (input) => {
        input.delegations[1].precommitted = false;
      }, "descriptor_delegation_unqualified:instrument:fixture:cleanup_recovery_session"],
      ["safety-like raw path", (input) => {
        input.delegations[0].raw_path_access_present = true;
      }, "descriptor_delegation_unqualified:instrument:fixture:active_device_session"],
      ["observer source", (input) => {
        input.native_evidence.observer_prebuild_digest = digest("drift:observer");
      }, "native_observer_source_mismatch"],
      ["native fork", (input) => {
        input.native_evidence.after_snapshot_digest = digest("fork:after");
      }, "native_snapshot_forked"],
      ["signature unverified", (input) => {
        input.native_evidence.observation_signature_verified = false;
      }, "native_observation_unqualified"],
    ];
    for (const [name, mutate, expectedBlocker] of cases) {
      await t.test(name, () => {
        const policy = api.createDarwinPrincipalAclPolicy(makePolicyInput());
        const input = makeObservationInput(policy);
        mutate(input);
        const observation = api.normalizeDarwinPrincipalAclObservation(input);
        const result = doctor(policy, observation);
        assert.equal(result.status, "blocked");
        assert.ok(result.qualification_blockers.includes(expectedBlocker),
          `${expectedBlocker} absent from ${result.qualification_blockers.join(", ")}`);
        assert.equal(result.production_ready, false);
        assert.equal(result.hardware_access_authorized, false);
      });
    }
  });

test("doctor enforces policy-bounded observation age", () => {
  const { policy, observation } = createFixture();
  const result = doctor(policy, observation, "2026-07-19T04:16:00.000Z");
  assert.equal(result.status, "blocked");
  assert.ok(result.qualification_blockers.includes("observation_stale"));
  assert.ok(result.qualification_blockers.includes("observation_age_exceeds_policy"));
});

test("observation normalization rejects hostile and ambiguous data objects", async (t) => {
  const policy = api.createDarwinPrincipalAclPolicy(makePolicyInput());
  const cases = [
    ["proxy", (input) => new Proxy(input, {})],
    ["nested accessor", (input) => {
      Object.defineProperty(input.resources[0], "mode", {
        enumerable: true,
        configurable: true,
        get() { return 0o600; },
      });
      return input;
    }],
    ["symbol", (input) => {
      input.native_evidence[Symbol("hidden")] = true;
      return input;
    }],
    ["sparse credentials", (input) => {
      delete input.credentials[2];
      return input;
    }],
    ["custom nested prototype", (input) => {
      input.os = Object.assign(Object.create({ inherited: true }), input.os);
      return input;
    }],
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, () => {
      expectContractRejection(() => api.normalizeDarwinPrincipalAclObservation(
        mutate(makeObservationInput(policy)),
      ));
    });
  }
});

test("policy and observation brands reject cloned or forged authority inputs", () => {
  const { policy, observation } = createFixture();
  expectContractRejection(() => doctor(structuredClone(policy), observation));
  expectContractRejection(() => doctor(policy, structuredClone(observation)));
  expectContractRejection(() => api.createDarwinPrincipalAclProvisioningPlan({
    policy: structuredClone(policy),
    observation,
  }));
});

test("provisioning plan is idempotent for a diagnostic match", () => {
  const { policy, observation } = createFixture();
  const plan = api.createDarwinPrincipalAclProvisioningPlan({ policy, observation });
  assert.equal(plan.actions.length, 0);
  assert.equal(plan.idempotent, true);
  assert.equal(plan.approval_required, false);
  assert.equal(plan.native_apply_required, false);
  assert.equal(plan.contains_executable_commands, false);
  assert.equal(plan.contains_secret_material, false);
  assert.equal(plan.contains_raw_device_paths, false);
  assert.equal(plan.production_ready, false);
  assert.equal(plan.hardware_access_authorized, false);
});

test("provisioning diff uses root-only and descriptor actions without raw paths", () => {
  const policy = api.createDarwinPrincipalAclPolicy(makePolicyInput());
  const input = makeObservationInput(policy);
  input.resources[0].direct_service_account_acl_present = true;
  const observation = api.normalizeDarwinPrincipalAclObservation(input);
  const plan = api.createDarwinPrincipalAclProvisioningPlan({ policy, observation });
  assert.deepEqual(plan.actions.map((action) => action.change_kind), [
    "enforce_root_only_device_node",
  ]);
  assert.equal(plan.actions[0].current_state_digest.length, 64);
  assert.equal(JSON.stringify(plan).includes("/dev/"), false);
  assert.equal(JSON.stringify(plan).includes("chmod"), false);
  assert.equal(JSON.stringify(plan).includes("chown"), false);
});

test("provisioning diff isolates a retained launcher descriptor inventory action", () => {
  const policy = api.createDarwinPrincipalAclPolicy(makePolicyInput());
  const input = makeObservationInput(policy);
  input.resources[0].launcher_descriptor_present = true;
  input.resources[0].launcher_redundant_descriptor_closed = false;
  const observation = api.normalizeDarwinPrincipalAclObservation(input);
  const plan = api.createDarwinPrincipalAclProvisioningPlan({ policy, observation });
  assert.deepEqual(plan.actions.map((action) => action.change_kind), [
    "ensure_closed_descriptor_inventory",
  ]);
  assert.equal(plan.production_ready, false);
  assert.equal(plan.hardware_access_authorized, false);
});

test("missing-observation plan is deterministic, declarative, and nonauthorizing", () => {
  const policy = api.createDarwinPrincipalAclPolicy(makePolicyInput());
  const first = api.createDarwinPrincipalAclProvisioningPlan({
    policy,
    observation: null,
  });
  const second = api.createDarwinPrincipalAclProvisioningPlan({
    policy,
    observation: null,
  });
  assert.deepEqual(first, second);
  assert.ok(first.actions.length > 0);
  assert.ok(first.actions.some((action) => action.change_kind
    === "ensure_exclusive_descriptor_delegation"));
  assert.ok(first.actions.some((action) => action.change_kind
    === "ensure_closed_descriptor_inventory"));
  assert.equal(first.idempotent, false);
  assert.equal(first.production_ready, false);
  assert.equal(first.hardware_access_authorized, false);
  for (const action of first.actions) {
    assert.deepEqual(Object.keys(action), [
      "action_id", "change_kind", "subject_kind", "subject_id",
      "current_state_digest", "desired_state_digest", "requires_operator_approval",
      "requires_native_apply",
    ]);
    assert.equal(action.requires_operator_approval, true);
    assert.equal(action.requires_native_apply, true);
  }
  const serialized = JSON.stringify(first);
  assert.doesNotMatch(serialized, /(?:\/dev\/|password|bearer|private[_-]?key|\bargv\b|\bshell\b)/iu);
});

test("package tarball contains only the private data-contract surface", () => {
  const packageDirectory = path.resolve(__dirname, "..");
  const output = execFileSync("npm", ["pack", "--dry-run", "--json"], {
    cwd: packageDirectory,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  const report = JSON.parse(output);
  const files = report[0].files.map((entry) => entry.path).sort();
  assert.deepEqual(files, ["lib/index.js", "lib/principal-acl.js", "package.json"]);
  assert.equal(files.some((file) => /(?:^|\/)(?:test|fixtures|reports)(?:\/|$)/u.test(file)), false);
  assert.equal(files.some((file) => /\.(?:node|pem|key|p12|mobileprovision)$/u.test(file)), false);
});
