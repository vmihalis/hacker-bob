"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const stewardship = require("../lib/state-stewardship.js");
const {
  CHAMELEON_OPERATION_STATE_POLICIES,
  CHAMELEON_SLOT_COUNT,
  assertChameleonLogPageReceipt,
  assertChameleonStateReconciliation,
  assertChameleonStateRestoreResult,
  assertChameleonStateSnapshot,
  assertChameleonStateTransition,
  createChameleonLogPageReceipt,
  createChameleonStateReconciliation,
  createChameleonStateRestoreResult,
  createChameleonStateSnapshot,
  createChameleonStateTransition,
  getChameleonStateOperationPolicy,
} = stewardship;
const {
  CHAMELEON_SEMANTIC_MANIFEST,
  getChameleonOperation,
} = require("../lib/operations.js");
const {
  MAX_UNCERTAINTY_MS,
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  createPhysicalTrustedClockPort,
  physicalClockMappingSigningMessage,
  publicKeyDigest,
  samplePhysicalTrustedClock,
} = require("../../../mcp/lib/physical-trusted-clock.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/lib/verification-contracts.js");

function digest(label) {
  return hashCanonicalJson({ label });
}

function artifact(label) {
  return `artifact:v1:${crypto.createHash("sha256").update(label).digest("base64url")}`;
}

function signMapping(keyPair, payload) {
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    physicalClockMappingSigningMessage(payloadDigest),
    keyPair.privateKey,
  ).toString("base64url");
  const basis = {
    version: 1,
    domain: TRUSTED_CLOCK_MAPPING_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
  };
  return { ...basis, signed_mapping_digest: hashCanonicalJson(basis) };
}

function clockFixture() {
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const payload = {
    version: 1,
    clock_id: "physical-clock:chameleon-state-test",
    monotonic_epoch_id: digest("chameleon-state-monotonic-epoch"),
    mapping_generation: 1,
    reference_monotonic_ms: 1_000,
    reference_utc: "2026-07-18T12:00:00.000Z",
    max_uncertainty_ms: 5,
    not_before: "2026-07-18T11:55:00.000Z",
    expires_at: "2026-07-18T12:10:00.000Z",
    trust_root_epoch: 4,
    authority_epoch: 7,
    revocation_generation: 2,
    signer_key_id: "clock-key:chameleon-state-test",
    signer_public_key_digest: publicKeyDigest(keyPair.publicKey),
  };
  const mapping = signMapping(keyPair, payload);
  const trust = {
    version: 1,
    trusted: true,
    revoked: false,
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    current_mapping_generation: payload.mapping_generation,
    current_signed_mapping_digest: mapping.signed_mapping_digest,
    trust_root_epoch: payload.trust_root_epoch,
    authority_epoch: payload.authority_epoch,
    revocation_generation: payload.revocation_generation,
    signer_key_id: payload.signer_key_id,
    signer_public_key_digest: payload.signer_public_key_digest,
    public_key: keyPair.publicKey,
  };
  const control = { monotonic_ms: 1_000 };
  const port = createPhysicalTrustedClockPort({
    port_id: "chameleon_state_test_clock",
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    uncertainty_ceiling_ms: MAX_UNCERTAINTY_MS,
    read_monotonic_ms() { return control.monotonic_ms; },
    read_signed_mapping() { return mapping; },
    resolve_current_trust() { return trust; },
  });
  return {
    next() {
      control.monotonic_ms += 10;
      return samplePhysicalTrustedClock(port);
    },
  };
}

function settings(overrides = {}) {
  return {
    animation_config_digest: digest("setting-animation"),
    ble_pairing_config_digest: digest("setting-ble-pairing"),
    button_a_config_digest: digest("setting-button-a"),
    button_b_config_digest: digest("setting-button-b"),
    detection_config_digest: digest("setting-detection"),
    hf_emulator_config_digest: digest("setting-hf-emulator"),
    lf_emulator_config_digest: digest("setting-lf-emulator"),
    reader_profile_config_digest: digest("setting-reader-profile"),
    ...overrides,
  };
}

function emptySlot(slotIndex, revision = 0) {
  return {
    slot_index: slotIndex,
    slot_revision: revision,
    slot_status: "empty",
    hf_enabled: false,
    lf_enabled: false,
    hf_type_id: null,
    lf_type_id: null,
    metadata_artifact_handle: null,
    content_artifact_handle: null,
  };
}

function occupiedSlot(slotIndex, revision = 1, overrides = {}) {
  return {
    slot_index: slotIndex,
    slot_revision: revision,
    slot_status: "occupied",
    hf_enabled: true,
    lf_enabled: false,
    hf_type_id: "mifare_classic",
    lf_type_id: null,
    metadata_artifact_handle: artifact(`slot-${slotIndex}-metadata-v${revision}`),
    content_artifact_handle: artifact(`slot-${slotIndex}-content-v${revision}`),
    ...overrides,
  };
}

function slots(first = emptySlot(1)) {
  return [first, ...Array.from({ length: CHAMELEON_SLOT_COUNT - 1 }, (_, index) => (
    emptySlot(index + 2)
  ))];
}

function logState(overrides = {}) {
  return {
    log_generation: 1,
    origin_cursor_ref: "log-cursor:origin-1",
    tail_cursor_ref: "log-cursor:origin-1",
    retained_event_count: 0,
    overflow_count: 0,
    overflow_status: "none",
    ...overrides,
  };
}

function snapshotInput({
  kind = "observed",
  operationId = "emulator.configure",
  attemptRef = "attempt:chameleon-state-1",
  stateEpoch = 1,
  assuranceEpoch = 1,
  assuranceStatus = "valid",
  assuranceReason = null,
  activeMode = "rf_off",
  enabledSlot = null,
  slotState = slots(),
  settingState = settings(),
  logs = logState(),
  handleLabel = "state-snapshot",
  instrumentIdentityDigest = digest("enrolled-chameleon-identity"),
  providerDescriptorDigest = digest("chameleon-provider-descriptor"),
  leaseId = "lease-chameleon-state-1",
  fencingGeneration = 3,
} = {}) {
  const operation = getChameleonOperation(operationId);
  assert.ok(operation);
  return {
    version: 1,
    snapshot_kind: kind,
    instrument_ref: "instrument:chameleon-ultra-owned-1",
    instrument_identity_digest: instrumentIdentityDigest,
    provider_id: "chameleon_ultra",
    provider_descriptor_digest: providerDescriptorDigest,
    semantic_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
    assurance_profile_id: "enrolled_source_pinned",
    assurance_claims_digest: digest("chameleon-assurance-claims"),
    assurance_epoch: assuranceEpoch,
    assurance_status: assuranceStatus,
    assurance_invalidation_reason: assuranceReason,
    state_epoch: stateEpoch,
    active_mode: activeMode,
    enabled_slot: enabledSlot,
    slots: slotState,
    settings: settingState,
    log_state: logs,
    lease_id: leaseId,
    fencing_generation: fencingGeneration,
    operation_id: operationId,
    operation_contract_digest: operation.operation_contract_digest,
    attempt_ref: attemptRef,
    snapshot_artifact_handle: kind === "observed" ? artifact(handleLabel) : null,
    snapshot_plan_digest: digest("snapshot-plan"),
  };
}

function transitionInput({
  operationId = "emulator.configure",
  attemptRef = "attempt:chameleon-state-1",
  effectDisposition = "confirmed_effect",
  recoveryPolicy = "required",
  logAction = "preserve",
  slotMutations = [],
  modeChange = null,
  settingsChangeIds = [],
  settingsChangePlanDigest = null,
} = {}) {
  const operation = getChameleonOperation(operationId);
  return {
    version: 1,
    transition_ref: "state-transition:chameleon-state-1",
    operation_id: operationId,
    operation_contract_digest: operation.operation_contract_digest,
    attempt_ref: attemptRef,
    request_digest: digest("execution-request"),
    lease_id: "lease-chameleon-state-1",
    fencing_generation: 3,
    authorized_effects_digest: digest("authorized-effects"),
    recovery_policy: recoveryPolicy,
    restore_plan_digest: recoveryPolicy === "required" ? digest("restore-plan") : null,
    restore_effects_digest: recoveryPolicy === "required" ? digest("restore-effects") : null,
    slot_mutations: slotMutations,
    mode_change: modeChange,
    settings_change_ids: settingsChangeIds,
    settings_change_plan_digest: settingsChangePlanDigest,
    log_action: logAction,
    effect_disposition: effectDisposition,
    receipt_ref: "receipt:chameleon-transition-1",
  };
}

function configureScenario({ effectDisposition = "confirmed_effect" } = {}) {
  const clock = clockFixture();
  const pre = createChameleonStateSnapshot(snapshotInput(), clock.next());
  const postSlot = occupiedSlot(1);
  const declared = createChameleonStateSnapshot(snapshotInput({
    kind: "declared",
    stateEpoch: 2,
    activeMode: "hf_emulator",
    enabledSlot: 1,
    slotState: slots(postSlot),
  }), clock.next());
  const observed = ["confirmed_effect", "confirmed_no_effect"].includes(effectDisposition)
    ? createChameleonStateSnapshot(snapshotInput(effectDisposition === "confirmed_effect" ? {
      stateEpoch: 2,
      activeMode: "hf_emulator",
      enabledSlot: 1,
      slotState: slots(postSlot),
      handleLabel: "observed-configured-state",
    } : {
      handleLabel: "observed-no-effect-state",
    }), clock.next())
    : null;
  const transition = createChameleonStateTransition(transitionInput({
    effectDisposition,
    slotMutations: [{
      slot_index: 1,
      action: "stage",
      pre_slot_digest: pre.slots[0].slot_digest,
      post_slot_digest: declared.slots[0].slot_digest,
      authorization_plan_digest: digest("slot-stage-plan"),
      source_artifact_handle: declared.slots[0].content_artifact_handle,
      preimage_artifact_handle: null,
    }],
    modeChange: {
      pre_mode: "rf_off",
      post_mode: "hf_emulator",
      pre_enabled_slot: null,
      post_enabled_slot: 1,
      change_plan_digest: digest("mode-change-plan"),
    },
  }), pre, declared, observed, clock.next());
  return { clock, declared, observed, pre, transition };
}

function restoreSnapshot(scenario, overrides = {}) {
  return createChameleonStateSnapshot(snapshotInput({
    operationId: "workspace.restore",
    attemptRef: "attempt:chameleon-restore-1",
    stateEpoch: 3,
    activeMode: scenario.pre.active_mode,
    enabledSlot: scenario.pre.enabled_slot,
    slotState: scenario.pre.slots.map((slot) => {
      const { slot_digest, ...value } = slot;
      return { ...value };
    }),
    settingState: { ...scenario.pre.settings },
    logs: { ...scenario.pre.log_state },
    handleLabel: "restored-state",
    ...overrides,
  }), scenario.clock.next());
}

function restoreInput(scenario, overrides = {}) {
  const operation = getChameleonOperation("workspace.restore");
  return {
    version: 1,
    restore_ref: "restore:chameleon-state-1",
    restore_attempt_ref: "attempt:chameleon-restore-1",
    operation_id: "workspace.restore",
    operation_contract_digest: operation.operation_contract_digest,
    lease_id: scenario.transition.lease_id,
    fencing_generation: scenario.transition.fencing_generation,
    snapshot_artifact_handle: scenario.pre.snapshot_artifact_handle,
    restore_plan_digest: scenario.transition.restore_plan_digest,
    restore_effects_digest: scenario.transition.restore_effects_digest,
    log_action: "preserve",
    disposition: "restored",
    receipt_ref: "receipt:chameleon-restore-1",
    ...overrides,
  };
}

test("state stewardship is pure, closed, provider-owned, and registry driven", () => {
  const source = fs.readFileSync(path.join(__dirname, "../lib/state-stewardship.js"), "utf8");
  const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, "../package.json"), "utf8"));
  assert.doesNotMatch(source, /require\(["'](?:node:)?(?:fs|net|dgram|http|https|tls|child_process|serialport|worker_threads)["']\)/u);
  assert.doesNotMatch(source, /navigator\.serial|usb\.openDevice|bluetooth\.requestDevice/iu);
  assert.doesNotMatch(source, /readFile|writeFile|openSync|execFile|spawn\(/u);
  assert.equal(Object.keys(CHAMELEON_OPERATION_STATE_POLICIES).length, 50);
  assert.equal(getChameleonStateOperationPolicy("protocol.discovery_probe").workspace_mutation,
    false);
  assert.deepEqual(getChameleonStateOperationPolicy("protocol.discovery_probe")
    .allowed_log_actions, ["preserve"]);
  assert.equal(getChameleonStateOperationPolicy("emulator.configure").workspace_mutation, true);
  assert.equal(getChameleonStateOperationPolicy("emulator.configure").mode_mutation, true);
  assert.deepEqual(getChameleonStateOperationPolicy("rf_session.acquire").allowed_slot_actions, []);
  assert.deepEqual(getChameleonStateOperationPolicy("reader_profile.configure")
    .allowed_settings_change_ids, ["reader_profile_config_digest"]);
  assert.deepEqual(getChameleonStateOperationPolicy("emulator.present").allowed_log_actions, [
    "append", "preserve",
  ]);
  assert.equal(getChameleonStateOperationPolicy("instrument.erase").assurance_action,
    "invalidate_data_erase");
  assert.equal(getChameleonStateOperationPolicy("workspace.restore").restore_only, true);
  assert.equal(getChameleonStateOperationPolicy("invented.operation"), null);
  assert.equal(Object.isFrozen(CHAMELEON_OPERATION_STATE_POLICIES), true);
  assert.equal(packageJson.exports["./state-stewardship"], "./lib/state-stewardship.js");
});

test("operation policy cannot launder unrelated workspace deltas", () => {
  const clock = clockFixture();
  const operationId = "rf_session.acquire";
  const attemptRef = "attempt:rf-session-delta-laundering";
  const pre = createChameleonStateSnapshot(snapshotInput({
    operationId,
    attemptRef,
    handleLabel: "rf-session-pre",
  }), clock.next());
  const staged = occupiedSlot(1);
  const declared = createChameleonStateSnapshot(snapshotInput({
    kind: "declared",
    operationId,
    attemptRef,
    stateEpoch: 2,
    activeMode: "hf_reader",
    slotState: slots(staged),
  }), clock.next());
  const observed = createChameleonStateSnapshot(snapshotInput({
    operationId,
    attemptRef,
    stateEpoch: 2,
    activeMode: "hf_reader",
    slotState: slots(staged),
    handleLabel: "rf-session-observed",
  }), clock.next());
  assert.throws(() => createChameleonStateTransition(transitionInput({
    operationId,
    attemptRef,
    slotMutations: [{
      slot_index: 1,
      action: "stage",
      pre_slot_digest: pre.slots[0].slot_digest,
      post_slot_digest: declared.slots[0].slot_digest,
      authorization_plan_digest: digest("rf-session-illegal-slot-stage"),
      source_artifact_handle: declared.slots[0].content_artifact_handle,
      preimage_artifact_handle: null,
    }],
    modeChange: {
      pre_mode: "rf_off",
      post_mode: "hf_reader",
      pre_enabled_slot: null,
      post_enabled_slot: null,
      change_plan_digest: digest("rf-session-mode-change"),
    },
  }), pre, declared, observed, clock.next()), /cannot authorize stage slot mutation/u);
});

test("snapshot binds exact identity, manifest, assurance, state, slots, lease, fence, and trusted time", () => {
  const clock = clockFixture();
  const snapshot = createChameleonStateSnapshot(snapshotInput(), clock.next());
  assert.equal(assertChameleonStateSnapshot(snapshot), snapshot);
  assert.equal(snapshot.provider_id, "chameleon_ultra");
  assert.equal(snapshot.semantic_manifest_digest, CHAMELEON_SEMANTIC_MANIFEST.manifest_digest);
  assert.equal(snapshot.slots.length, 8);
  assert.equal(snapshot.lease_id, "lease-chameleon-state-1");
  assert.equal(snapshot.fencing_generation, 3);
  assert.equal(snapshot.assurance_status, "valid");
  assert.match(snapshot.snapshot_artifact_handle, /^artifact:v1:/u);
  assert.equal(snapshot.trusted_clock_id, "physical-clock:chameleon-state-test");
  assert.equal(snapshot.trusted_clock_max_uncertainty_ms, 5);
  assert.equal(snapshot.trusted_clock_trust_root_epoch, 4);
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(Object.isFrozen(snapshot.slots), true);
  assert.equal(Object.isFrozen(snapshot.settings), true);
  assert.equal(Object.isFrozen(snapshot.log_state), true);
  assert.throws(() => assertChameleonStateSnapshot({ ...snapshot }), /private branded snapshot/u);
  assert.throws(() => createChameleonStateSnapshot({
    ...snapshotInput(),
    semantic_manifest_digest: digest("substituted-manifest"),
  }, clock.next()), /manifest binding drifted/u);
  assert.throws(() => createChameleonStateSnapshot({
    ...snapshotInput(),
    snapshot_artifact_handle: "/tmp/raw-device-state.bin",
  }, clock.next()), /opaque artifact:v1 vault handle/u);
  const slotsWithHiddenState = slots();
  slotsWithHiddenState.extra = "undeclared-slot-state";
  assert.throws(() => createChameleonStateSnapshot({
    ...snapshotInput(),
    slots: slotsWithHiddenState,
  }, clock.next()), /dense array without extra fields/u);
});

test("confirmed mutation declares every state delta and restores the exact precommitted workspace", () => {
  const scenario = configureScenario();
  assert.equal(assertChameleonStateTransition(scenario.transition), scenario.transition);
  assert.equal(scenario.transition.transition_state, "restore_required");
  assert.equal(scenario.transition.declared_post_state_epoch, 2);
  assert.equal(scenario.transition.slot_mutations[0].action, "stage");
  assert.equal(scenario.transition.mode_change.post_mode, "hf_emulator");
  const restored = restoreSnapshot(scenario);
  const result = createChameleonStateRestoreResult(
    restoreInput(scenario),
    scenario.transition,
    restored,
    scenario.clock.next(),
  );
  assert.equal(assertChameleonStateRestoreResult(result), result);
  assert.equal(result.disposition, "restored");
  assert.equal(restored.restorable_workspace_digest, scenario.pre.restorable_workspace_digest);
  assert.equal(restored.state_epoch, 3);
  assert.equal(result.restore_effects_digest, scenario.transition.restore_effects_digest);
  assert.throws(() => createChameleonStateRestoreResult(
    restoreInput(scenario, { restore_ref: "restore:replay" }),
    scenario.transition,
    restored,
    scenario.clock.next(),
  ), /unclaimed recovery source/u);
});

test("slot reuse, overwrite, erase, and undeclared deltas fail closed", () => {
  const make = (mutateInput) => {
    const clock = clockFixture();
    const pre = createChameleonStateSnapshot(snapshotInput(), clock.next());
    const postSlot = occupiedSlot(1);
    const declared = createChameleonStateSnapshot(snapshotInput({
      kind: "declared",
      stateEpoch: 2,
      activeMode: "hf_emulator",
      enabledSlot: 1,
      slotState: slots(postSlot),
    }), clock.next());
    const observed = createChameleonStateSnapshot(snapshotInput({
      stateEpoch: 2,
      activeMode: "hf_emulator",
      enabledSlot: 1,
      slotState: slots(postSlot),
      handleLabel: "slot-negative-observed",
    }), clock.next());
    const valid = transitionInput({
      slotMutations: [{
        slot_index: 1,
        action: "stage",
        pre_slot_digest: pre.slots[0].slot_digest,
        post_slot_digest: declared.slots[0].slot_digest,
        authorization_plan_digest: digest("slot-plan"),
        source_artifact_handle: declared.slots[0].content_artifact_handle,
        preimage_artifact_handle: null,
      }],
      modeChange: {
        pre_mode: "rf_off",
        post_mode: "hf_emulator",
        pre_enabled_slot: null,
        post_enabled_slot: 1,
        change_plan_digest: digest("mode-plan"),
      },
    });
    return { clock, declared, observed, pre, input: mutateInput(valid, pre, declared) };
  };
  for (const [name, mutate, pattern] of [
    ["missing delta", (value) => ({ ...value, slot_mutations: [] }), /every changed slot/u],
    ["implicit overwrite", (value) => ({
      ...value,
      slot_mutations: [{ ...value.slot_mutations[0], action: "overwrite" }],
    }), /overwrite must bind/u],
    ["wrong preimage", (value) => ({
      ...value,
      slot_mutations: [{
        ...value.slot_mutations[0],
        preimage_artifact_handle: artifact("invented-preimage"),
      }],
    }), /stage must populate/u],
  ]) {
    const f = make(mutate);
    assert.throws(() => createChameleonStateTransition(
      f.input,
      f.pre,
      f.declared,
      f.observed,
      f.clock.next(),
    ), pattern, name);
  }
});

test("clone, identity, fence, manifest, state-epoch, and pre-state replay drift are rejected", () => {
  const scenario = configureScenario({ effectDisposition: "ambiguous" });
  assert.throws(() => assertChameleonStateTransition({ ...scenario.transition }), /private branded transition/u);
  assert.throws(() => createChameleonStateTransition(
    transitionInput({
      effectDisposition: "ambiguous",
      slotMutations: scenario.transition.slot_mutations,
      modeChange: scenario.transition.mode_change,
    }),
    scenario.pre,
    scenario.declared,
    null,
    scenario.clock.next(),
  ), /already consumed/u);

  const clock = clockFixture();
  const pre = createChameleonStateSnapshot(snapshotInput(), clock.next());
  const declared = createChameleonStateSnapshot(snapshotInput({
    kind: "declared",
    stateEpoch: 1,
    instrumentIdentityDigest: digest("replacement-device"),
  }), clock.next());
  assert.throws(() => createChameleonStateTransition(
    transitionInput({ effectDisposition: "ambiguous" }),
    pre,
    declared,
    null,
    clock.next(),
  ), /instrument_identity_digest binding drift/u);

  const pre2 = createChameleonStateSnapshot(snapshotInput({
    handleLabel: "pre-fence-drift",
  }), clock.next());
  const declared2 = createChameleonStateSnapshot(snapshotInput({
    kind: "declared",
    fencingGeneration: 4,
  }), clock.next());
  assert.throws(() => createChameleonStateTransition(
    transitionInput({ effectDisposition: "ambiguous" }),
    pre2,
    declared2,
    null,
    clock.next(),
  ), /snapshot operation, attempt, lease, or fence binding drift/u);
});

test("ambiguous and disconnect-like effects require one reconciliation before restore or quarantine", () => {
  const scenario = configureScenario({ effectDisposition: "ambiguous" });
  assert.equal(scenario.transition.transition_state, "reconcile_required");
  const observed = createChameleonStateSnapshot(snapshotInput({
    stateEpoch: 2,
    activeMode: "hf_emulator",
    enabledSlot: 1,
    slotState: scenario.declared.slots.map((slot) => {
      const { slot_digest, ...value } = slot;
      return { ...value };
    }),
    handleLabel: "reconciled-declared-state",
  }), scenario.clock.next());
  const reconciliation = createChameleonStateReconciliation({
    version: 1,
    reconciliation_ref: "reconciliation:chameleon-state-1",
    disposition: "confirmed_declared_post",
    observation_ref: "observation:chameleon-state-1",
    receipt_ref: "receipt:chameleon-reconciliation-1",
  }, scenario.transition, observed, scenario.clock.next());
  assert.equal(assertChameleonStateReconciliation(reconciliation), reconciliation);
  assert.equal(reconciliation.reconciliation_state, "restore_required");
  assert.throws(() => createChameleonStateReconciliation({
    version: 1,
    reconciliation_ref: "reconciliation:replay",
    disposition: "confirmed_declared_post",
    observation_ref: "observation:replay",
    receipt_ref: "receipt:replay",
  }, scenario.transition, observed, scenario.clock.next()), /unclaimed reconcile-required/u);

  const restored = restoreSnapshot(scenario);
  const result = createChameleonStateRestoreResult(
    restoreInput(scenario),
    reconciliation,
    restored,
    scenario.clock.next(),
  );
  assert.equal(result.disposition, "restored");

  const unobservable = configureScenario({ effectDisposition: "ambiguous" });
  const quarantineRequired = createChameleonStateReconciliation({
    version: 1,
    reconciliation_ref: "reconciliation:unobservable",
    disposition: "unobservable",
    observation_ref: "observation:unobservable",
    receipt_ref: "receipt:unobservable",
  }, unobservable.transition, null, unobservable.clock.next());
  assert.equal(quarantineRequired.reconciliation_state, "quarantine_required");
  const quarantined = createChameleonStateRestoreResult(
    restoreInput(unobservable, {
      restore_ref: "restore:quarantine-unobservable",
      disposition: "quarantined",
      receipt_ref: "receipt:quarantine-unobservable",
    }),
    quarantineRequired,
    null,
    unobservable.clock.next(),
  );
  assert.equal(quarantined.disposition, "quarantined");
});

function eraseScenario() {
  const clock = clockFixture();
  const operationId = "instrument.erase";
  const attemptRef = "attempt:chameleon-erase-1";
  const beforeSlot = occupiedSlot(1);
  const beforeLogs = logState({
    origin_cursor_ref: "log-cursor:erase-origin",
    tail_cursor_ref: "log-cursor:erase-tail",
    retained_event_count: 4,
  });
  const pre = createChameleonStateSnapshot(snapshotInput({
    operationId,
    attemptRef,
    slotState: slots(beforeSlot),
    logs: beforeLogs,
    handleLabel: "erase-pre-state",
  }), clock.next());
  const afterLogs = logState({
    log_generation: 2,
    origin_cursor_ref: "log-cursor:erase-cleared",
    tail_cursor_ref: "log-cursor:erase-cleared",
  });
  const postOptions = {
    operationId,
    attemptRef,
    stateEpoch: 2,
    assuranceEpoch: 2,
    assuranceStatus: "invalidated",
    assuranceReason: "data_erase",
    slotState: slots(emptySlot(1, 2)),
    logs: afterLogs,
  };
  const declared = createChameleonStateSnapshot(snapshotInput({
    ...postOptions,
    kind: "declared",
  }), clock.next());
  const observed = createChameleonStateSnapshot(snapshotInput({
    ...postOptions,
    handleLabel: "erase-observed-state",
  }), clock.next());
  const transition = createChameleonStateTransition(transitionInput({
    operationId,
    attemptRef,
    recoveryPolicy: "quarantine_only",
    logAction: "clear",
    slotMutations: [{
      slot_index: 1,
      action: "erase",
      pre_slot_digest: pre.slots[0].slot_digest,
      post_slot_digest: declared.slots[0].slot_digest,
      authorization_plan_digest: digest("erase-plan"),
      source_artifact_handle: null,
      preimage_artifact_handle: pre.slots[0].content_artifact_handle,
    }],
  }), pre, declared, observed, clock.next());
  return { clock, declared, observed, pre, transition };
}

test("admin, firmware, erase, and log-clear semantics invalidate assurance and cannot fake restoration", () => {
  const scenario = eraseScenario();
  assert.equal(scenario.transition.transition_state, "quarantine_required");
  assert.equal(scenario.declared.assurance_status, "invalidated");
  assert.equal(scenario.declared.assurance_invalidation_reason, "data_erase");
  assert.equal(scenario.declared.assurance_epoch, 2);
  assert.equal(scenario.transition.log_action, "clear");
  assert.throws(() => createChameleonStateRestoreResult(
    restoreInput(scenario),
    scenario.transition,
    restoreSnapshot(scenario),
    scenario.clock.next(),
  ), /restored requires exact state/u);
  const operation = getChameleonOperation("instrument.restore");
  const result = createChameleonStateRestoreResult({
    version: 1,
    restore_ref: "restore:erase-quarantine",
    restore_attempt_ref: "attempt:erase-quarantine",
    operation_id: "instrument.restore",
    operation_contract_digest: operation.operation_contract_digest,
    lease_id: scenario.transition.lease_id,
    fencing_generation: scenario.transition.fencing_generation,
    snapshot_artifact_handle: scenario.pre.snapshot_artifact_handle,
    restore_plan_digest: null,
    restore_effects_digest: null,
    log_action: "preserve",
    disposition: "quarantined",
    receipt_ref: "receipt:erase-quarantine",
  }, scenario.transition, null, scenario.clock.next());
  assert.equal(result.disposition, "quarantined");
});

function traceSnapshot(clock, { overflow = 0, handleLabel = "trace-state" } = {}) {
  return createChameleonStateSnapshot(snapshotInput({
    operationId: "interaction.trace",
    attemptRef: "attempt:trace-pagination-1",
    handleLabel,
    logs: logState({
      origin_cursor_ref: "log-cursor:trace-origin",
      tail_cursor_ref: "log-cursor:trace-tail",
      retained_event_count: 10,
      overflow_count: overflow,
      overflow_status: overflow > 0 ? "observed" : "none",
    }),
  }), clock.next());
}

function pageInput(overrides = {}) {
  const operation = getChameleonOperation("interaction.trace");
  return {
    version: 1,
    page_ref: "log-page:trace-1",
    operation_id: "interaction.trace",
    operation_contract_digest: operation.operation_contract_digest,
    attempt_ref: "attempt:trace-pagination-1",
    start_cursor_ref: "log-cursor:trace-origin",
    end_cursor_ref: "log-cursor:trace-middle",
    record_count: 5,
    has_more: true,
    overflow_observed: false,
    page_artifact_handle: artifact("trace-page-1"),
    receipt_ref: "receipt:trace-page-1",
    ...overrides,
  };
}

test("log pagination is continuous, one-shot, and complete only at a no-overflow snapshot tail", () => {
  const clock = clockFixture();
  const snapshot = traceSnapshot(clock);
  assert.throws(() => createChameleonLogPageReceipt(pageInput({
    attempt_ref: "attempt:wrong-trace-attempt",
  }), snapshot, null, clock.next()), /snapshot operation or attempt binding drift/u);
  const first = createChameleonLogPageReceipt(pageInput(), snapshot, null, clock.next());
  assert.equal(assertChameleonLogPageReceipt(first), first);
  assert.equal(first.evidence_completeness, "incomplete_paginated");
  assert.throws(() => createChameleonLogPageReceipt(pageInput({
    page_ref: "log-page:trace-cycle",
    start_cursor_ref: first.end_cursor_ref,
    end_cursor_ref: snapshot.log_state.origin_cursor_ref,
    record_count: 2,
    page_artifact_handle: artifact("trace-page-cycle"),
    receipt_ref: "receipt:trace-page-cycle",
  }), snapshot, first, clock.next()), /cannot revisit an earlier chain position/u);
  const second = createChameleonLogPageReceipt(pageInput({
    page_ref: "log-page:trace-2",
    start_cursor_ref: first.end_cursor_ref,
    end_cursor_ref: snapshot.log_state.tail_cursor_ref,
    has_more: false,
    page_artifact_handle: artifact("trace-page-2"),
    receipt_ref: "receipt:trace-page-2",
  }), snapshot, first, clock.next());
  assert.equal(second.evidence_completeness, "complete_for_snapshot");
  assert.equal(second.cumulative_record_count, snapshot.log_state.retained_event_count);
  assert.throws(() => assertChameleonLogPageReceipt({ ...second }), /private branded receipt/u);
  assert.throws(() => createChameleonLogPageReceipt(pageInput({
    page_ref: "log-page:trace-branch",
    start_cursor_ref: first.end_cursor_ref,
  }), snapshot, first, clock.next()), /consumed, terminal, cross-snapshot, or discontinuous/u);
  assert.throws(() => createChameleonLogPageReceipt(pageInput({
    page_ref: "log-page:trace-restart",
  }), snapshot, null, clock.next()), /already has a log pagination chain/u);
});

test("log overflow can never be projected as complete evidence", () => {
  const clock = clockFixture();
  const snapshot = traceSnapshot(clock, { overflow: 2, handleLabel: "overflow-trace-state" });
  const receipt = createChameleonLogPageReceipt(pageInput({
    page_ref: "log-page:overflow",
    end_cursor_ref: snapshot.log_state.tail_cursor_ref,
    has_more: false,
    overflow_observed: true,
    record_count: 10,
    page_artifact_handle: artifact("overflow-page"),
    receipt_ref: "receipt:overflow-page",
  }), snapshot, null, clock.next());
  assert.equal(receipt.evidence_completeness, "incomplete_overflow");
  assert.equal(receipt.overflow_observed, true);
});

test("terminal log accounting and restore-time evidence preservation fail closed", () => {
  const pageClock = clockFixture();
  const snapshot = traceSnapshot(pageClock, { handleLabel: "trace-count-state" });
  assert.throws(() => createChameleonLogPageReceipt(pageInput({
    page_ref: "log-page:short-terminal",
    end_cursor_ref: snapshot.log_state.tail_cursor_ref,
    record_count: 9,
    has_more: false,
    page_artifact_handle: artifact("trace-short-page"),
    receipt_ref: "receipt:trace-short-page",
  }), snapshot, null, pageClock.next()), /account for every retained snapshot event/u);

  const scenario = configureScenario();
  const cleared = restoreSnapshot(scenario, {
    logs: logState({
      log_generation: 2,
      origin_cursor_ref: "log-cursor:restore-cleared",
      tail_cursor_ref: "log-cursor:restore-cleared",
    }),
    handleLabel: "restore-cleared-state",
  });
  assert.throws(() => createChameleonStateRestoreResult(
    restoreInput(scenario, { log_action: "clear" }),
    scenario.transition,
    cleared,
    scenario.clock.next(),
  ), /cannot clear or rewind evidentiary logs/u);
});

test("raw bytes, paths, secrets, drifted effects, and materialized restore payloads never enter public records", () => {
  const clock = clockFixture();
  let getterInvoked = false;
  const accessorInput = snapshotInput();
  Object.defineProperty(accessorInput, "raw_device_path", {
    enumerable: true,
    get() {
      getterInvoked = true;
      return "/dev/cu.accessor-must-not-run";
    },
  });
  assert.throws(() => createChameleonStateSnapshot(
    accessorInput,
    clock.next(),
  ), /must be an enumerable data field/u);
  assert.equal(getterInvoked, false);
  assert.throws(() => createChameleonStateSnapshot({
    ...snapshotInput(),
    slots: slots({ ...emptySlot(1), content_artifact_handle: Buffer.from("secret") }),
  }, clock.next()), /raw byte material/u);
  assert.throws(() => createChameleonStateSnapshot({
    ...snapshotInput(),
    raw_device_path: "/dev/cu.usbmodem-private",
  }, clock.next()), /unknown fields: raw_device_path/u);
  assert.throws(() => createChameleonStateSnapshot({
    ...snapshotInput(),
    slots: slots({ ...emptySlot(1), content_digest: digest("linkable-card-fingerprint") }),
  }, clock.next()), /unknown fields: content_digest/u);

  const scenario = configureScenario();
  const restored = restoreSnapshot(scenario);
  assert.throws(() => createChameleonStateRestoreResult(
    restoreInput(scenario, { restore_effects_digest: digest("widened-restore-effects") }),
    scenario.transition,
    restored,
    scenario.clock.next(),
  ), /plan, or effect binding drift/u);
  assert.throws(() => createChameleonStateRestoreResult({
    ...restoreInput(scenario),
    materialized_bytes: Buffer.from("credential"),
  }, scenario.transition, restored, scenario.clock.next()), /raw byte material/u);

  for (const projection of [scenario.pre, scenario.declared, scenario.transition]) {
    const json = JSON.stringify(projection);
    assert.doesNotMatch(json, /\/dev\/|PRIVATE|secret|materialized|payload|raw_bytes/iu);
    assert.doesNotMatch(json, /content_digest|metadata_digest|comparison_token/u);
    assert.doesNotMatch(json, /"type":"Buffer"|"data":\[/u);
  }
});
