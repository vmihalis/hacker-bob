"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  PHYSICAL_SCOPE_IMPORT_DOMAIN,
  PHYSICAL_SCOPE_IMPORT_KEY_USAGE,
  PHYSICAL_SCOPE_IMPORT_KIND,
  PHYSICAL_SCOPE_COMPATIBILITY_RULE,
  assertVerifiedPhysicalScopeImport,
  buildPhysicalOnlySessionBootstrapPayload,
  createPhysicalScopeImportVerifier,
  migratePhysicalScopePolicy,
  normalizePhysicalScopeImportEnvelope,
  normalizePhysicalScopePolicy,
  physicalScopeImportSignatureInputDigest,
  projectPhysicalScopeNucleusAxis,
  projectVerifiedPhysicalScopeImport,
  resolvePhysicalScopeCompatibility,
} = require("../mcp/lib/physical-scope.js");
const {
  buildSessionNucleus,
  normalizePhysicalScopeNucleusAxis,
  normalizeScopePolicy,
  sessionNucleusHash,
} = require("../mcp/lib/governance-contracts.js");
const {
  buildEffectTemplateRegistry,
} = require("../mcp/lib/requested-effects.js");
const {
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");
const {
  executeTool,
} = require("../mcp/lib/dispatch.js");
const {
  installPhysicalSessionBootstrapResolver,
  resolvePhysicalSessionBootstrapImport,
} = require("../mcp/lib/physical-session-runtime.js");
const {
  createTestPhysicalVerdictResolverPort,
  installPhysicalVerdictResolver,
  installTestPhysicalVerdictResolver,
  resolvePhysicalVerdict,
} = require("../mcp/lib/physical-verdict-runtime.js");
const {
  physicalSessionBootstrapPath,
  sessionNucleusPath,
  statePath,
} = require("../mcp/lib/paths.js");
const {
  readJsonFile,
} = require("../mcp/lib/storage.js");
const {
  readVerifiedPhysicalSessionBootstrapJournal,
} = require("../mcp/lib/physical-session-journal.js");
const {
  authorizeToolCall,
} = require("../mcp/lib/session-authority.js");
const {
  getRegisteredTool,
} = require("../mcp/lib/tool-registry.js");
const {
  setOperatorNote,
} = require("../mcp/lib/session-state.js");

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-physical-session-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function digest(label) {
  return hashCanonicalJson({ label });
}

function registry() {
  return buildEffectTemplateRegistry([
    {
      version: 1,
      template_id: "instrument.observe.usb.v1",
      subject_kind: "instrument",
      action: "observe",
      channel: "usb",
      persistence: "none",
      bounds: {},
    },
    {
      version: 1,
      template_id: "target.present.rf.v1",
      subject_kind: "target",
      action: "present",
      channel: "rf",
      persistence: "ephemeral",
      bounds: {},
    },
  ]);
}

function effect(templates, templateId, subjectRef, overrides = {}) {
  const template = templates.get(templateId);
  return {
    version: 1,
    template_id: template.template_id,
    template_digest: template.template_digest,
    subject_ref: subjectRef,
    subject_kind: template.subject_kind,
    action: template.action,
    channel: template.channel,
    persistence: template.persistence,
    bounds: {},
    ...overrides,
  };
}

function assets() {
  return [
    {
      version: 1,
      asset_role: "verifier",
      asset_ref: "verifier:reader-1",
      effect_subject_refs: [],
      graph_nodes: [
        { node_type: "zone", node_ref: "zone:restricted-1" },
        { node_type: "verifier", node_ref: "verifier:reader-1" },
      ],
    },
    {
      version: 1,
      asset_role: "source",
      asset_ref: "source:credential-1",
      effect_subject_refs: ["target:credential-1"],
      graph_nodes: [
        { node_type: "representation", node_ref: "representation:credential-1" },
      ],
    },
    {
      version: 1,
      asset_role: "instrument",
      asset_ref: "instrument:reader-1",
      effect_subject_refs: ["instrument:reader-1"],
      graph_nodes: [
        { node_type: "instrument", node_ref: "instrument:reader-1" },
      ],
    },
  ];
}

function rules(templates) {
  return [
    {
      version: 1,
      rule_id: "allow_present",
      decision: "allow",
      tuple: {
        version: 1,
        grant_kind: "active",
        instrument_ref: "instrument:reader-1",
        subject_asset_ref: "source:credential-1",
        verifier_ref: "verifier:reader-1",
        operation_id: "credential.present.v1",
        parameter_digest: digest("present-parameters"),
        requested_effect: effect(templates, "target.present.rf.v1", "target:credential-1"),
      },
    },
    {
      version: 1,
      rule_id: "allow_inventory",
      decision: "allow",
      tuple: {
        version: 1,
        grant_kind: "bootstrap",
        instrument_ref: "instrument:reader-1",
        subject_asset_ref: "instrument:reader-1",
        operation_id: "instrument.inventory.v1",
        parameter_digest: digest("inventory-parameters"),
        requested_effect: effect(templates, "instrument.observe.usb.v1", "instrument:reader-1"),
      },
    },
  ];
}

function basePolicy(templates) {
  return {
    version: 1,
    policy_id: "physical_campaign_1",
    authority_epoch: 4,
    revocation_generation: 2,
    transition_receipt_registry_digest: digest("surface-transition-registry"),
    asset_aliases: assets(),
    effect_rules: rules(templates),
    expected_transitions: [],
    constraints: [],
    exclusions: [],
  };
}

function policyWithTransition(templates) {
  const initial = normalizePhysicalScopePolicy(basePolicy(templates), templates);
  const presentTuple = initial.effect_rules.find((rule) => rule.rule_id === "allow_present").tuple;
  return {
    ...basePolicy(templates),
    expected_transitions: [
      {
        version: 1,
        transition_id: "credential_to_restricted_zone",
        source_asset_ref: "source:credential-1",
        verifier_asset_ref: "verifier:reader-1",
        source_node: { node_type: "representation", node_ref: "representation:credential-1" },
        target_node: { node_type: "zone", node_ref: "zone:restricted-1" },
        edge_type: "demonstrated_transition",
        expected_outcome_ref: "outcome:access-granted",
        predicate_digest: digest("access-granted-predicate"),
        verifier_template_id: "independent_access_observer_v1",
        verifier_template_version: 1,
        verifier_template_digest: digest("observer-template"),
        effect_tuple_digests: [presentTuple.tuple_digest],
      },
    ],
    constraints: [
      {
        version: 1,
        constraint_id: "bounded_zone",
        constraint_kind: "spatial_envelope",
        constraint_ref: "constraint:bounded-zone-1",
        constraint_digest: digest("bounded-zone"),
        applies_to: [
          { subject_kind: "expected_transition", subject_ref: "credential_to_restricted_zone" },
          { subject_kind: "effect_rule", subject_ref: "allow_present" },
        ],
      },
    ],
    exclusions: [
      {
        version: 1,
        exclusion_id: "exclude_inventory_outside_fixture",
        exclusion_kind: "operation",
        excluded_ref: "instrument.inventory.v1",
        reason_code: "fixture_only",
      },
    ],
  };
}

function sha256Bytes(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function replayReservationResult(claim, options = {}) {
  const generation = options.generation || 1;
  const receipt = {
    version: 1,
    reservation_ref: options.reservation_ref
      || `scope-replay-reservation:${hashCanonicalJson(claim).slice(0, 40)}`,
    replay_claim: options.replay_claim || claim,
    replay_claim_digest: hashCanonicalJson(options.replay_claim || claim),
    generation,
    previous_receipt_digest: generation === 1
      ? null
      : options.previous_receipt_digest || digest(`scope-replay-${generation - 1}`),
    reserved_at: options.reserved_at || "2026-07-18T00:00:10.000Z",
    fsynced_at: options.fsynced_at || "2026-07-18T00:00:10.000Z",
    ...(options.receipt || {}),
  };
  return {
    version: 1,
    disposition: options.disposition || "created",
    reservation_receipt: {
      ...receipt,
      receipt_digest: hashCanonicalJson(receipt),
      ...(options.receipt_envelope || {}),
    },
  };
}

function scopeImportFixture(templates, policy = policyWithTransition(templates), options = {}) {
  const normalizedPolicy = normalizePhysicalScopePolicy(policy, templates);
  const payload = {
    version: 1,
    import_id: options.import_id || "operator_import_1",
    operator_principal_id: "principal:operator-1",
    authored_at: "2026-07-18T00:00:00.000Z",
    authoring_system_ref: "authoring-system:control-plane-1",
    authorization_record_ref: "authorization-record:engagement-1",
    authorization_record_digest: digest("signed-authorization-record"),
    nonce: options.nonce || "physical-scope-import-nonce-1",
    sequence: options.sequence || 1,
    not_before: options.not_before || "2026-07-18T00:00:00.000Z",
    expires_at: options.expires_at || "2026-07-18T00:01:00.000Z",
    policy: normalizedPolicy,
  };
  const importPayloadDigest = hashCanonicalJson(payload);
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const signerPublicKeyDigest = sha256Bytes(
    keyPair.publicKey.export({ type: "spki", format: "der" }),
  );
  const authenticationBasis = {
    version: 1,
    method: "detached_signature",
    trust_root_id: "trust-root:physical-scope-test",
    trust_root_epoch: 7,
    trust_registry_digest: digest("physical-scope-trust-registry"),
    signer_principal_id: "principal:operator-1",
    signer_key_id: "signer-key:operator-scope-1",
    signer_epoch: 3,
    signer_public_key_digest: signerPublicKeyDigest,
    key_usage: PHYSICAL_SCOPE_IMPORT_KEY_USAGE,
    signed_at: options.signed_at || "2026-07-18T00:00:05.000Z",
    signed_payload_digest: importPayloadDigest,
    ...(options.authentication || {}),
  };
  const signatureInputDigest = physicalScopeImportSignatureInputDigest(
    payload,
    authenticationBasis,
    templates,
  );
  const signature = crypto.sign(
    null,
    Buffer.from(signatureInputDigest, "hex"),
    keyPair.privateKey,
  );
  const proofRef = "auth-proof:operator-import-1";
  const proofDigest = options.proof_digest || sha256Bytes(signature);
  const envelope = {
    kind: PHYSICAL_SCOPE_IMPORT_KIND,
    domain: PHYSICAL_SCOPE_IMPORT_DOMAIN,
    ...payload,
    import_payload_digest: importPayloadDigest,
    signature_input_digest: signatureInputDigest,
    authentication: {
      ...authenticationBasis,
      proof_ref: proofRef,
      proof_digest: proofDigest,
    },
  };
  const authority = {
    version: 1,
    import_id: payload.import_id,
    import_payload_digest: importPayloadDigest,
    operator_principal_id: payload.operator_principal_id,
    authorization_record_ref: payload.authorization_record_ref,
    authorization_record_digest: payload.authorization_record_digest,
    policy_id: normalizedPolicy.policy_id,
    policy_digest: normalizedPolicy.policy_digest,
    authority_epoch: normalizedPolicy.authority_epoch,
    revocation_generation: normalizedPolicy.revocation_generation,
    authorization_decision: "allow",
    authorization_reason: "exact_allow",
    authorization_resolution_digest: digest("physical-scope-authorization-resolution"),
    trust_root_id: authenticationBasis.trust_root_id,
    trust_root_epoch: authenticationBasis.trust_root_epoch,
    trust_registry_digest: authenticationBasis.trust_registry_digest,
    trust_root_trusted: true,
    trust_root_revoked: false,
    signer_principal_id: authenticationBasis.signer_principal_id,
    signer_key_id: authenticationBasis.signer_key_id,
    signer_epoch: authenticationBasis.signer_epoch,
    signer_public_key_digest: authenticationBasis.signer_public_key_digest,
    key_usage: PHYSICAL_SCOPE_IMPORT_KEY_USAGE,
    signer_trusted: true,
    signer_revoked: false,
    ...(options.authority || {}),
  };
  let now = options.now || "2026-07-18T00:00:10.000Z";
  const replayReservations = options.replay_reservations || new Map();
  let signatureVerificationCount = 0;
  let replayReservationCount = 0;
  const reserveReplay = options.reserve_replay || ((claim) => {
    const existing = [...replayReservations.values()].find((entry) => {
      const prior = entry.reservation_receipt.replay_claim;
      return prior.import_id === claim.import_id
        || prior.import_payload_digest === claim.import_payload_digest
        || (prior.operator_principal_id === claim.operator_principal_id && prior.nonce === claim.nonce)
        || (prior.operator_principal_id === claim.operator_principal_id && prior.sequence === claim.sequence);
    });
    if (existing) return { ...existing, disposition: "existing_same" };
    const previous = [...replayReservations.values()].at(-1);
    const reservation = replayReservationResult(claim, {
      generation: replayReservations.size + 1,
      previous_receipt_digest: previous == null
        ? null
        : previous.reservation_receipt.receipt_digest,
      reserved_at: now,
      fsynced_at: now,
    });
    replayReservations.set(claim.import_id, reservation);
    return reservation;
  });
  const verifier = createPhysicalScopeImportVerifier({
    verifier_id: options.verifier_id || "physical-scope-import-verifier-v1",
    trusted_now: () => now,
    resolve_current_authority: () => authority,
    verify_detached_signature: (verification) => {
      signatureVerificationCount += 1;
      if (verification.proof_ref !== proofRef || verification.proof_digest !== sha256Bytes(signature)) {
        return false;
      }
      return crypto.verify(
        null,
        Buffer.from(verification.signature_input_digest, "hex"),
        keyPair.publicKey,
        signature,
      );
    },
    reserve_replay: (claim) => {
      replayReservationCount += 1;
      return reserveReplay(claim);
    },
  });
  return {
    envelope,
    payload,
    authority,
    verifier,
    keyPair,
    signature,
    replayReservations,
    setNow(value) {
      now = value;
    },
    getSignatureVerificationCount() {
      return signatureVerificationCount;
    },
    getReplayReservationCount() {
      return replayReservationCount;
    },
  };
}

test("physical scope normalizes opaque aliases, exact effects, transitions, constraints, and exclusions", () => {
  const templates = registry();
  const normalized = normalizePhysicalScopePolicy(policyWithTransition(templates), templates);

  assert.equal(normalized.version, 1);
  assert.equal(normalized.asset_aliases.length, 3);
  assert.equal(normalized.effect_rules.length, 2);
  assert.equal(normalized.expected_transitions.length, 1);
  assert.equal(normalized.constraints.length, 1);
  assert.equal(normalized.exclusions.length, 1);
  assert.match(normalized.policy_digest, /^[a-f0-9]{64}$/);
  assert.ok(Object.isFrozen(normalized));
  assert.ok(Object.isFrozen(normalized.asset_aliases));
  assert.equal(
    normalized.expected_transitions[0].effect_tuple_digests[0],
    normalized.effect_rules.find((rule) => rule.rule_id === "allow_present").tuple.tuple_digest,
  );
});

test("policy normalization is order-independent and exact allow/deny rules retain deny precedence data", () => {
  const templates = registry();
  const first = policyWithTransition(templates);
  const allowPresent = first.effect_rules.find((rule) => rule.rule_id === "allow_present");
  const allowInventory = first.effect_rules.find((rule) => rule.rule_id === "allow_inventory");
  const withDeny = {
    ...first,
    asset_aliases: [...first.asset_aliases].reverse(),
    effect_rules: [
      {
        ...allowInventory,
        rule_id: "deny_inventory",
        decision: "deny",
      },
      ...[...first.effect_rules].reverse(),
    ],
  };
  const normalized = normalizePhysicalScopePolicy(withDeny, templates);
  const allow = normalized.effect_rules.find((rule) => rule.rule_id === "allow_inventory");
  const deny = normalized.effect_rules.find((rule) => rule.rule_id === "deny_inventory");

  assert.equal(allow.tuple.tuple_digest, deny.tuple.tuple_digest);
  assert.notEqual(allow.rule_digest, deny.rule_digest);

  assert.throws(
    () => normalizePhysicalScopePolicy({
      ...first,
      effect_rules: [
        ...first.effect_rules,
        { ...allowPresent, rule_id: "deny_present", decision: "deny" },
      ],
    }, templates),
    /without an exact allow rule/,
  );

  const reordered = {
    ...withDeny,
    asset_aliases: [...withDeny.asset_aliases].reverse(),
    effect_rules: [...withDeny.effect_rules].reverse(),
  };
  assert.equal(
    normalizePhysicalScopePolicy(reordered, templates).policy_digest,
    normalized.policy_digest,
  );

  assert.throws(
    () => normalizePhysicalScopePolicy({
      ...withDeny,
      effect_rules: [...withDeny.effect_rules, { ...allowPresent, rule_id: "allow_present_again" }],
    }, templates),
    /repeats a decision for an exact tuple/,
  );
});

test("unknown versions, fields, actions, aliases, graph types, and floating transitions fail closed", () => {
  const templates = registry();
  const policy = policyWithTransition(templates);
  assert.throws(
    () => normalizePhysicalScopePolicy({ ...policy, version: 2 }, templates),
    /unknown versions fail closed/,
  );
  assert.throws(
    () => normalizePhysicalScopePolicy({ ...policy, raw_asset_metadata: { serial: "secret" } }, templates),
    /unknown fields: raw_asset_metadata/,
  );
  const badAction = structuredClone(policy);
  badAction.effect_rules[0].tuple.requested_effect.action = "unlock";
  assert.throws(() => normalizePhysicalScopePolicy(badAction, templates), /action does not match/);

  const undeclaredSubject = structuredClone(policy);
  undeclaredSubject.effect_rules[0].tuple.requested_effect.subject_ref = "target:other";
  assert.throws(() => normalizePhysicalScopePolicy(undeclaredSubject, templates), /not bound to subject_asset_ref/);

  const badNode = structuredClone(policy);
  badNode.asset_aliases[0].graph_nodes[0].node_type = "hotel_room";
  assert.throws(() => normalizePhysicalScopePolicy(badNode, templates), /not a physical surface-graph node type/);

  const floatingTransition = structuredClone(policy);
  floatingTransition.expected_transitions[0].effect_tuple_digests = [digest("not-allowed")];
  assert.throws(
    () => normalizePhysicalScopePolicy(floatingTransition, templates),
    /without an exact allow rule/,
  );
});

test("authenticated import binds the normalized payload and strips authority/proof handles from projection", () => {
  const templates = registry();
  const fixture = scopeImportFixture(templates);
  const imported = normalizePhysicalScopeImportEnvelope(fixture.envelope, templates);
  const projection = projectVerifiedPhysicalScopeImport(
    fixture.envelope,
    templates,
    fixture.verifier,
  );
  const serialized = JSON.stringify(projection);

  assert.equal(imported.import_payload_digest, fixture.envelope.import_payload_digest);
  assert.equal(projection.policy_digest, imported.policy.policy_digest);
  assert.match(projection.provenance_digest, /^[a-f0-9]{64}$/);
  assert.match(projection.projection_digest, /^[a-f0-9]{64}$/);
  assert.match(projection.provenance.signature_verification_digest, /^[a-f0-9]{64}$/);
  assert.match(projection.provenance.replay_reservation_receipt_digest, /^[a-f0-9]{64}$/);
  assert.doesNotMatch(serialized, /authorization-record:engagement-1/);
  assert.doesNotMatch(serialized, /auth-proof:operator-import-1/);
  assert.doesNotMatch(serialized, /authorization_record_digest|proof_digest/);
  assert.equal(projection.provenance.operator_principal_id, "principal:operator-1");
  assert.equal(projection.provenance.key_usage, PHYSICAL_SCOPE_IMPORT_KEY_USAGE);
  assert.equal(fixture.getSignatureVerificationCount(), 1);
  assert.equal(fixture.getReplayReservationCount(), 1);
  assert.equal(fixture.replayReservations.size, 1);
  assert.equal(
    assertVerifiedPhysicalScopeImport(projection, fixture.verifier),
    projection,
  );

  const rawDocument = { ...fixture.envelope, authorization_document: "raw signed content" };
  assert.throws(() => normalizePhysicalScopeImportEnvelope(rawDocument, templates), /unknown fields/);
});

test("canonical physical scope is digest-bound into the session nucleus without raw authority material", () => {
  const templates = registry();
  const first = scopeImportFixture(templates);
  const second = scopeImportFixture(templates, {
    ...policyWithTransition(templates),
    revocation_generation: 3,
  }, {
    import_id: "operator_import_2",
    nonce: "physical-scope-import-nonce-2",
    sequence: 2,
  });
  const firstProjection = projectVerifiedPhysicalScopeImport(
    first.envelope,
    templates,
    first.verifier,
  );
  const secondProjection = projectVerifiedPhysicalScopeImport(
    second.envelope,
    templates,
    second.verifier,
  );
  const firstAxis = projectPhysicalScopeNucleusAxis(firstProjection, first.verifier);
  const secondAxis = projectPhysicalScopeNucleusAxis(secondProjection, second.verifier);
  const common = {
    target_domain: "physical-scope.example.com",
    target_url: "https://physical-scope.example.com",
    scope_policy: {
      target_domain: "physical-scope.example.com",
      target_url: "https://physical-scope.example.com",
      checkpoint_mode: "normal",
      block_internal_hosts: false,
      block_internal_hosts_source: "mode_default",
    },
    egress_identity: { egress_profile: "default", proxy_configured: false },
    auth_context: { auth_status: "pending" },
    operator_constraint: { handoff_provenance_required: true },
    lifecycle_state: "SETUP",
  };
  const firstNucleus = buildSessionNucleus({ ...common, physical_scope: firstAxis });
  const secondNucleus = buildSessionNucleus({ ...common, physical_scope: secondAxis });

  assert.equal(firstNucleus.physical_scope.policy_digest, firstProjection.policy_digest);
  assert.equal(firstNucleus.physical_scope.projection_digest, firstProjection.projection_digest);
  assert.equal(firstNucleus.physical_scope.provenance_digest, firstProjection.provenance_digest);
  assert.equal(firstNucleus.physical_scope.authority_epoch, firstProjection.policy.authority_epoch);
  assert.equal(firstNucleus.physical_scope.revocation_generation, 2);
  assert.equal(secondNucleus.physical_scope.revocation_generation, 3);
  assert.notEqual(firstAxis.axis_digest, secondAxis.axis_digest);
  assert.notEqual(
    firstNucleus.nucleus_hash,
    secondNucleus.nucleus_hash,
    "otherwise identical sessions with distinct physical scope must have distinct nuclei",
  );
  assert.equal(sessionNucleusHash(firstNucleus), firstNucleus.nucleus_hash);
  assert.equal(
    buildSessionNucleus({ ...common, physical_scope: structuredClone(firstAxis) }).nucleus_hash,
    firstNucleus.nucleus_hash,
    "persisted compact axes re-normalize without hash drift",
  );

  const serialized = JSON.stringify(firstNucleus);
  assert.doesNotMatch(serialized, /authorization-record|authorization_record|auth-proof|proof_digest/);
  assert.doesNotMatch(serialized, /signed-authorization-record|detached-signature/);
  assert.equal(Object.prototype.hasOwnProperty.call(firstNucleus.physical_scope, "policy"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(firstNucleus.physical_scope, "provenance"), false);
  assert.throws(
    () => buildSessionNucleus({ ...common, physical_scope: firstProjection }),
    /physical_scope has unknown fields/,
    "the full authenticated import projection is not a nucleus document",
  );
  assert.throws(
    () => buildSessionNucleus({
      ...common,
      physical_scope: { ...firstAxis, authorization_document: "raw operator secret" },
    }),
    /physical_scope has unknown fields: authorization_document/,
  );
  const ignoredTopLevelSecret = buildSessionNucleus({
    ...common,
    physical_scope: firstAxis,
    authorization_document: "raw operator secret",
  });
  assert.doesNotMatch(JSON.stringify(ignoredTopLevelSecret), /raw operator secret/);
  const secretNamedAxis = { ...firstAxis, policy_id: "sk_live_abcdefghijklmnopqrst" };
  delete secretNamedAxis.axis_digest;
  assert.throws(
    () => buildSessionNucleus({ ...common, physical_scope: secretNamedAxis }),
    /appears to contain secrets/,
  );
});

test("physical-only scope shell is private to a verified axis and the leaf rejects adorned objects", () => {
  const targetDomain = `physical-${"a".repeat(24)}`;
  const emptyPolicy = {
    target_domain: targetDomain,
    checkpoint_mode: "normal",
    block_internal_hosts: false,
    block_internal_hosts_source: "mode_default",
  };
  assert.throws(
    () => normalizeScopePolicy(emptyPolicy, { allowPhysicalOnly: true }),
    /requires exactly one/,
  );

  const templates = registry();
  const fixture = scopeImportFixture(templates);
  const projection = projectVerifiedPhysicalScopeImport(
    fixture.envelope,
    templates,
    fixture.verifier,
  );
  const axis = projectPhysicalScopeNucleusAxis(projection, fixture.verifier);
  const nucleus = buildSessionNucleus({
    target_domain: targetDomain,
    scope_policy: emptyPolicy,
    physical_scope: axis,
    egress_identity: { egress_profile: "default", proxy_configured: false },
    auth_context: { auth_status: "pending" },
    operator_constraint: { handoff_provenance_required: true },
  });
  assert.equal(nucleus.scope_policy.target_url, undefined);
  assert.equal(nucleus.physical_scope.axis_digest, axis.axis_digest);

  let getterCalls = 0;
  const accessorAxis = { ...axis };
  Object.defineProperty(accessorAxis, "policy_digest", {
    enumerable: true,
    get() {
      getterCalls += 1;
      throw new Error("hostile getter invoked");
    },
  });
  assert.throws(
    () => normalizePhysicalScopeNucleusAxis(accessorAxis),
    /must be an enumerable data property/,
  );
  assert.equal(getterCalls, 0);

  const symbolAxis = { ...axis, [Symbol("hidden")]: "forged" };
  assert.throws(() => normalizePhysicalScopeNucleusAxis(symbolAxis), /must not carry symbol fields/);
  const nonEnumerableAxis = { ...axis };
  Object.defineProperty(nonEnumerableAxis, "hidden", { value: "forged", enumerable: false });
  assert.throws(() => normalizePhysicalScopeNucleusAxis(nonEnumerableAxis), /unknown fields: hidden/);
});

test("legacy web nucleus hash remains byte-stable after physical-axis extraction", () => {
  const nucleus = buildSessionNucleus({
    target_domain: "example.com",
    target_url: "https://example.com",
    scope_policy: {
      target_domain: "example.com",
      target_url: "https://example.com",
      checkpoint_mode: "normal",
      block_internal_hosts: false,
      block_internal_hosts_source: "mode_default",
    },
    egress_identity: { egress_profile: "default" },
    auth_context: { auth_status: "pending" },
    operator_constraint: { handoff_provenance_required: true },
  });
  assert.equal(
    nucleus.nucleus_hash,
    "608a0554e70eb9fd58de133e0a55d53d222305f59ff8c71a3ff1545b5f39e6cf",
  );
  assert.equal(Object.prototype.hasOwnProperty.call(nucleus, "physical_scope"), false);
});

test("scope import rejects forgeable verdicts, signature/domain tamper, clones, and verifier substitution", () => {
  const templates = registry();
  {
    const fixture = scopeImportFixture(templates);
    assert.throws(
      () => projectVerifiedPhysicalScopeImport(fixture.envelope, templates, {
        authenticated: true,
        caller_role_id: "operator",
      }),
      /configured Bob verifier/,
      "the retired caller-constructible trusted context cannot mint a projection",
    );
  }
  {
    const fixture = scopeImportFixture(templates);
    assert.throws(
      () => projectVerifiedPhysicalScopeImport({
        ...fixture.envelope,
        domain: "hacker-bob/physical-active-execution-grant/v1",
      }, templates, fixture.verifier),
      /signature domain/,
    );
  }
  {
    const fixture = scopeImportFixture(templates);
    const tampered = structuredClone(fixture.envelope);
    tampered.authentication.proof_digest = digest("substituted-signature");
    delete tampered.signature_input_digest;
    assert.throws(
      () => projectVerifiedPhysicalScopeImport(tampered, templates, fixture.verifier),
      /signature verification failed/,
    );
    assert.equal(fixture.replayReservations.size, 0, "signature failure precedes replay reservation");
  }
  {
    const fixture = scopeImportFixture(templates);
    const tampered = structuredClone(fixture.envelope);
    tampered.policy.authority_epoch += 1;
    assert.throws(
      () => normalizePhysicalScopeImportEnvelope(tampered, templates),
      /policy_digest does not match normalized content|signed_payload_digest does not bind/,
    );
  }
  {
    const fixture = scopeImportFixture(templates);
    const projection = projectVerifiedPhysicalScopeImport(
      fixture.envelope,
      templates,
      fixture.verifier,
    );
    assert.throws(
      () => assertVerifiedPhysicalScopeImport({ ...projection }, fixture.verifier),
      /was not issued by the configured verifier/,
    );
    const other = scopeImportFixture(templates, policyWithTransition(templates), {
      verifier_id: "other-physical-scope-import-verifier-v1",
    });
    assert.throws(
      () => assertVerifiedPhysicalScopeImport(projection, other.verifier),
      /was not issued by the configured verifier/,
    );
  }
});

test("scope import verification binds current operator, record, policy epoch, trust, signer usage, and time", () => {
  const templates = registry();
  for (const [name, mutate, pattern] of [
    ["operator drift", (fixture) => {
      fixture.authority.operator_principal_id = "principal:other-operator";
    }, /operator_principal_id does not match/],
    ["authorization record drift", (fixture) => {
      fixture.authority.authorization_record_digest = digest("withdrawn-authorization-record");
    }, /authorization_record_digest does not match/],
    ["policy epoch drift", (fixture) => {
      fixture.authority.authority_epoch += 1;
    }, /authority_epoch does not match/],
    ["revocation generation drift", (fixture) => {
      fixture.authority.revocation_generation += 1;
    }, /revocation_generation does not match/],
    ["trust root revoked", (fixture) => {
      fixture.authority.trust_root_revoked = true;
    }, /trust root is not currently usable/],
    ["signer revoked", (fixture) => {
      fixture.authority.signer_revoked = true;
    }, /signer is not currently usable/],
    ["trust registry drift", (fixture) => {
      fixture.authority.trust_registry_digest = digest("rotated-trust-registry");
    }, /trust_registry_digest does not match/],
    ["signer key drift", (fixture) => {
      fixture.authority.signer_public_key_digest = digest("rotated-signer-key");
    }, /signer_public_key_digest does not match/],
    ["key usage removed", (fixture) => {
      fixture.authority.key_usage = "physical_active_grant_signing";
    }, /key_usage must be one of physical_scope_import_signing/],
  ]) {
    const fixture = scopeImportFixture(templates);
    mutate(fixture);
    assert.throws(
      () => projectVerifiedPhysicalScopeImport(fixture.envelope, templates, fixture.verifier),
      pattern,
      name,
    );
    assert.equal(fixture.replayReservations.size, 0, `${name} must fail before replay reservation`);
  }
  {
    const fixture = scopeImportFixture(templates, policyWithTransition(templates), {
      not_before: "2026-07-18T00:00:20.000Z",
      now: "2026-07-18T00:00:10.000Z",
    });
    assert.throws(
      () => projectVerifiedPhysicalScopeImport(fixture.envelope, templates, fixture.verifier),
      /not yet valid/,
    );
  }
  {
    const fixture = scopeImportFixture(templates, policyWithTransition(templates), {
      now: "2026-07-18T00:01:00.000Z",
    });
    assert.throws(
      () => projectVerifiedPhysicalScopeImport(fixture.envelope, templates, fixture.verifier),
      /has expired/,
    );
  }
  {
    const fixture = scopeImportFixture(templates, policyWithTransition(templates), {
      signed_at: "2026-07-18T00:00:20.000Z",
      now: "2026-07-18T00:00:10.000Z",
    });
    assert.throws(
      () => projectVerifiedPhysicalScopeImport(fixture.envelope, templates, fixture.verifier),
      /signed in the future/,
    );
  }
});

test("scope replay reservations are one-shot, claim-bound, fsynced, and fail closed on rehydration", () => {
  const templates = registry();
  {
    const fixture = scopeImportFixture(templates);
    projectVerifiedPhysicalScopeImport(fixture.envelope, templates, fixture.verifier);
    assert.throws(
      () => projectVerifiedPhysicalScopeImport(fixture.envelope, templates, fixture.verifier),
      /replay was rejected/,
    );
    assert.equal(fixture.getReplayReservationCount(), 1);
  }
  {
    const fixture = scopeImportFixture(templates, policyWithTransition(templates), {
      reserve_replay: (claim) => replayReservationResult(claim, { disposition: "existing_same" }),
    });
    assert.throws(
      () => projectVerifiedPhysicalScopeImport(fixture.envelope, templates, fixture.verifier),
      /existing replay reservation requires unavailable durable session rehydration/,
    );
  }
  {
    const fixture = scopeImportFixture(templates, policyWithTransition(templates), {
      reserve_replay: (claim) => replayReservationResult(claim, {
        replay_claim: { ...claim, sequence: claim.sequence + 1 },
      }),
    });
    assert.throws(
      () => projectVerifiedPhysicalScopeImport(fixture.envelope, templates, fixture.verifier),
      /replay reservation failed closed/,
    );
  }
  {
    const fixture = scopeImportFixture(templates, policyWithTransition(templates), {
      reserve_replay: (claim) => replayReservationResult(claim, {
        reserved_at: "2026-07-18T00:00:10.001Z",
        fsynced_at: "2026-07-18T00:00:10.000Z",
      }),
    });
    assert.throws(
      () => projectVerifiedPhysicalScopeImport(fixture.envelope, templates, fixture.verifier),
      /replay reservation failed closed/,
    );
  }
  {
    const fixture = scopeImportFixture(templates, policyWithTransition(templates), {
      reserve_replay: (claim) => replayReservationResult(claim, {
        reserved_at: "2026-07-18T00:00:04.000Z",
        fsynced_at: "2026-07-18T00:00:04.000Z",
      }),
    });
    assert.throws(
      () => projectVerifiedPhysicalScopeImport(fixture.envelope, templates, fixture.verifier),
      /outside its trusted validity window/,
    );
  }
});

test("compatibility is physical-off for an absent legacy axis and migration is explicit identity-only", () => {
  const templates = registry();
  const policy = policyWithTransition(templates);
  const absent = resolvePhysicalScopeCompatibility(null, templates);
  const native = resolvePhysicalScopeCompatibility(policy, templates);
  const migrated = migratePhysicalScopePolicy(policy, templates);

  assert.equal(absent.mode, "legacy_absent");
  assert.equal(absent.physical_enabled, false);
  assert.equal(native.mode, "native_v1");
  assert.equal(native.physical_enabled, true);
  assert.equal(migrated.migration_kind, "identity");
  assert.equal(migrated.source_policy_digest, migrated.migrated_policy_digest);
  assert.equal(PHYSICAL_SCOPE_COMPATIBILITY_RULE.rollback_behavior, "new_session_nucleus_required");
  assert.throws(
    () => migratePhysicalScopePolicy({ ...policy, version: 0 }, templates),
    /only an explicit version 1 source policy/,
  );
  assert.throws(
    () => migratePhysicalScopePolicy(policy, templates, { targetVersion: 2 }),
    /no registered target/,
  );
});

test("physical-only bootstrap accepts only verifier-branded projections and binds one physical axis", () => {
  const templates = registry();
  const fixture = scopeImportFixture(templates);
  const projection = projectVerifiedPhysicalScopeImport(
    fixture.envelope,
    templates,
    fixture.verifier,
  );
  const bootstrap = buildPhysicalOnlySessionBootstrapPayload(projection, fixture.verifier, {
    version: 1,
    session_id: "physical-session-1",
    session_namespace: "session-namespace:physical-campaign-1",
  });

  assert.equal(bootstrap.bootstrap_kind, "physical_only");
  assert.deepEqual(bootstrap.scope_axes, ["physical"]);
  assert.equal(bootstrap.physical_scope_projection_digest, projection.projection_digest);
  assert.equal(bootstrap.authority_epoch, 4);
  assert.equal(bootstrap.revocation_generation, 2);
  assert.match(bootstrap.bootstrap_payload_digest, /^[a-f0-9]{64}$/);
  assert.ok(Object.isFrozen(bootstrap));
  assert.equal(Object.prototype.hasOwnProperty.call(bootstrap, "target_url"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(bootstrap, "target_repo"), false);

  assert.throws(
    () => buildPhysicalOnlySessionBootstrapPayload(
      JSON.parse(JSON.stringify(projection)),
      fixture.verifier,
      {
      version: 1,
      session_id: "forged-session",
      session_namespace: "session-namespace:forged",
      },
    ),
    /was not issued by the configured verifier/,
  );
  assert.deepEqual(Object.getOwnPropertySymbols(projection), []);
  assert.throws(
    () => buildPhysicalOnlySessionBootstrapPayload({ ...projection }, fixture.verifier, {
      version: 1,
      session_id: "forged-session",
      session_namespace: "session-namespace:forged",
    }),
    /was not issued by the configured verifier/,
  );
  assert.throws(
    () => buildPhysicalOnlySessionBootstrapPayload(projection, fixture.verifier, {
      version: 1,
      session_id: "physical-session-1",
      session_namespace: "session-namespace:physical-campaign-1",
      target_url: "https:\/\/not-allowed.example",
    }),
    /unknown fields: target_url/,
  );
});

test("nucleus and physical-only bootstrap minting live-revalidate authority, trust, and time", () => {
  const templates = registry();
  for (const [name, mutate, pattern] of [
    ["authorization withdrawn", (fixture) => {
      fixture.authority.authorization_decision = "deny";
    }, /authorization_decision must be one of allow/],
    ["record revoked", (fixture) => {
      fixture.authority.authorization_record_digest = digest("revoked-record");
    }, /authorization_record_digest does not match/],
    ["authorization resolution replaced", (fixture) => {
      fixture.authority.authorization_resolution_digest = digest("replacement-resolution");
    }, /authorization_resolution_digest does not match/],
    ["scope generation advanced", (fixture) => {
      fixture.authority.revocation_generation += 1;
    }, /revocation_generation does not match/],
    ["signer revoked", (fixture) => {
      fixture.authority.signer_revoked = true;
    }, /signer is not currently usable/],
    ["expired", (fixture) => {
      fixture.setNow("2026-07-18T00:01:00.000Z");
    }, /has expired/],
  ]) {
    const fixture = scopeImportFixture(templates);
    const projection = projectVerifiedPhysicalScopeImport(
      fixture.envelope,
      templates,
      fixture.verifier,
    );
    mutate(fixture);
    assert.throws(
      () => projectPhysicalScopeNucleusAxis(projection, fixture.verifier),
      pattern,
      `${name} must block nucleus minting`,
    );
    assert.throws(
      () => buildPhysicalOnlySessionBootstrapPayload(projection, fixture.verifier, {
        version: 1,
        session_id: "physical-session-live-check",
        session_namespace: "session-namespace:physical-live-check",
      }),
      pattern,
      `${name} must block physical-only bootstrap minting`,
    );
    assert.equal(fixture.getSignatureVerificationCount(), 1, `${name} does not repeat signature verification`);
    assert.equal(fixture.getReplayReservationCount(), 1, `${name} does not repeat replay reservation`);
  }
});

test("physical bootstrap resolver boundary is sanitized, synchronous, accessor-safe, and non-reentrant", async () => {
  const importRef = "physical-scope-import:runtime-boundary-test";

  {
    const secret = "/dev/cu.usbmodem-secret policy-token=raw-secret";
    const uninstall = installPhysicalSessionBootstrapResolver(() => {
      const error = new Error(secret);
      // A resolver must not be able to spoof one of Bob's public runtime
      // error codes and thereby make its private message trusted.
      error.code = "physical_bootstrap_runtime_contract_invalid";
      throw error;
    });
    try {
      await withTempHome(async () => {
        const response = await executeTool("bob_init_physical_session", {
          physical_scope_import_ref: importRef,
        });
        assert.equal(response.ok, false);
        assert.equal(response.error.code, "STATE_CONFLICT");
        assert.equal(
          response.error.details.physical_bootstrap_error_code,
          "physical_bootstrap_runtime_unavailable",
        );
        assert.equal(response.error.message, "physical session bootstrap resolver is unavailable");
        assert.doesNotMatch(JSON.stringify(response), /usbmodem-secret|raw-secret/);
      });
      assert.throws(
        () => resolvePhysicalSessionBootstrapImport(importRef),
        (error) => error.code === "physical_bootstrap_runtime_unavailable"
          && error.message === "physical session bootstrap resolver is unavailable"
          && !error.message.includes(secret),
      );
    } finally {
      uninstall();
    }
  }

  {
    let thenGetterCalls = 0;
    const accessorResult = {};
    Object.defineProperty(accessorResult, "then", {
      enumerable: true,
      get() {
        thenGetterCalls += 1;
        throw new Error("then-getter-private-secret");
      },
    });
    Object.freeze(accessorResult);
    const uninstall = installPhysicalSessionBootstrapResolver(() => accessorResult);
    try {
      assert.throws(
        () => resolvePhysicalSessionBootstrapImport(importRef),
        (error) => error.code === "physical_bootstrap_runtime_contract_invalid"
          && !error.message.includes("then-getter-private-secret"),
      );
      assert.equal(thenGetterCalls, 0, "thenable detection must not execute an accessor");
    } finally {
      uninstall();
    }
  }

  {
    let reflectionTrapCalls = 0;
    const proxyResult = new Proxy(Object.freeze({}), {
      getPrototypeOf() {
        reflectionTrapCalls += 1;
        throw new Error("proxy-reflection-private-secret");
      },
      ownKeys() {
        reflectionTrapCalls += 1;
        throw new Error("proxy-own-keys-private-secret");
      },
    });
    const uninstall = installPhysicalSessionBootstrapResolver(() => proxyResult);
    try {
      assert.throws(
        () => resolvePhysicalSessionBootstrapImport(importRef),
        (error) => error.code === "physical_bootstrap_runtime_contract_invalid"
          && !error.message.includes("private-secret"),
      );
      assert.equal(reflectionTrapCalls, 0, "resolver result validation must not reflect over a Proxy");
    } finally {
      uninstall();
    }
  }

  {
    let resolverCalls = 0;
    let nestedError = null;
    const result = Object.freeze({
      effect_template_registry: null,
      envelope: null,
      session_namespace: null,
      verifier: null,
    });
    const uninstall = installPhysicalSessionBootstrapResolver(() => {
      resolverCalls += 1;
      try {
        resolvePhysicalSessionBootstrapImport(importRef);
      } catch (error) {
        nestedError = error;
      }
      return result;
    });
    try {
      assert.deepEqual(resolvePhysicalSessionBootstrapImport(importRef), result);
      assert.equal(resolverCalls, 1, "nested resolution must not invoke the resolver twice");
      assert.equal(nestedError && nestedError.code, "physical_bootstrap_runtime_reentrant");
      assert.equal(
        nestedError && nestedError.message,
        "physical session bootstrap resolver invocation is already in progress",
      );
      assert.deepEqual(resolvePhysicalSessionBootstrapImport(importRef), result);
      assert.equal(resolverCalls, 2, "the in-flight guard must release after a completed call");
    } finally {
      uninstall();
    }
  }

  {
    const uninstall = installPhysicalSessionBootstrapResolver(async () => {
      throw new Error("async-resolver-private-secret");
    });
    try {
      assert.throws(
        () => resolvePhysicalSessionBootstrapImport(importRef),
        (error) => error.code === "physical_bootstrap_runtime_contract_invalid"
          && error.message === "physical session bootstrap resolver must be synchronous",
      );
      await new Promise((resolve) => setImmediate(resolve));
    } finally {
      uninstall();
    }
  }

  {
    const templates = registry();
    const fixture = scopeImportFixture(templates, policyWithTransition(templates), {
      import_id: "operator_import_private_callback",
      nonce: "physical-scope-import-private-callback",
      sequence: 27,
    });
    const verifier = createPhysicalScopeImportVerifier({
      verifier_id: "physical-scope-private-callback-test",
      trusted_now: () => "2026-07-18T00:00:10.000Z",
      resolve_current_authority: () => {
        throw new Error("/dev/cu.private callback-policy-token=secret");
      },
      verify_detached_signature: () => true,
      reserve_replay: () => {
        throw new Error("must not reach replay reservation");
      },
    });
    const uninstall = installPhysicalSessionBootstrapResolver(() => Object.freeze({
      effect_template_registry: templates,
      envelope: fixture.envelope,
      session_namespace: "session-namespace:private-callback-test",
      verifier,
    }));
    try {
      await withTempHome(async () => {
        const response = await executeTool("bob_init_physical_session", {
          physical_scope_import_ref: "physical-scope-import:private-callback-test",
        });
        assert.equal(response.ok, false);
        assert.equal(response.error.code, "STATE_CONFLICT");
        assert.equal(
          response.error.details.physical_bootstrap_error_code,
          "physical_bootstrap_import_verification_failed",
        );
        assert.equal(
          response.error.message,
          "physical session bootstrap import verification failed",
        );
        assert.doesNotMatch(JSON.stringify(response), /cu\.private|callback-policy-token|secret/);
      });
    } finally {
      uninstall();
    }
  }
});

test("physical-only session front door is effect-free, durable, idempotent, and authority-bound", async () => {
  await withTempHome(async () => {
    const templates = registry();
    const fixture = scopeImportFixture(templates);
    const importRef = "physical-scope-import:operator-import-1";
    let resolverCalls = 0;
    const uninstall = installPhysicalSessionBootstrapResolver((ref) => {
      resolverCalls += 1;
      assert.equal(ref, importRef);
      return Object.freeze({
        effect_template_registry: templates,
        envelope: fixture.envelope,
        session_namespace: "session-namespace:physical-campaign-1",
        verifier: fixture.verifier,
      });
    });
    const originalFsync = fs.fsyncSync;
    let fsyncCalls = 0;
    fs.fsyncSync = (...args) => {
      fsyncCalls += 1;
      return originalFsync(...args);
    };
    try {
      const first = await executeTool("bob_init_physical_session", {
        physical_scope_import_ref: importRef,
      });
      assert.equal(first.ok, true, JSON.stringify(first));
      assert.deepEqual(Object.keys(first.data).sort(), [
        "created",
        "nucleus_hash",
        "physical_scope",
        "scope_axes",
        "session_id",
        "target_domain",
        "version",
      ]);
      assert.equal(first.data.created, true);
      assert.deepEqual(first.data.scope_axes, ["physical"]);
      assert.match(first.data.target_domain, /^physical-[a-f0-9]{24}$/);
      assert.equal(first.data.session_id, first.data.target_domain);
      assert.deepEqual(Object.keys(first.data.physical_scope).sort(), [
        "authority_epoch",
        "axis_digest",
        "policy_digest",
        "projection_digest",
        "provenance_digest",
        "revocation_generation",
      ]);
      assert.equal(fsyncCalls >= 4, true, "pending and complete each fsync file + directory");
      assert.equal(resolverCalls, 1);
      assert.equal(fixture.getReplayReservationCount(), 1);

      const domain = first.data.target_domain;
      const state = readJsonFile(statePath(domain), { label: "state.json" });
      const nucleus = readJsonFile(sessionNucleusPath(domain), { label: "session-nucleus.json" });
      const journal = readVerifiedPhysicalSessionBootstrapJournal(domain, { requireComplete: true });
      assert.equal(state.target, domain);
      assert.equal(state.target_url, null);
      assert.equal(state.target_repo, undefined);
      assert.deepEqual(state.target_contracts, undefined);
      assert.equal(state.physical_scope.axis_digest, first.data.physical_scope.axis_digest);
      assert.equal(nucleus.physical_scope.axis_digest, state.physical_scope.axis_digest);
      assert.equal(journal.status, "complete");
      assert.equal(journal.nucleus_hash, nucleus.nucleus_hash);
      assert.match(journal.bootstrap_binding_digest, /^[a-f0-9]{64}$/);
      assert.match(journal.signed_import_digest, /^[a-f0-9]{64}$/);
      assert.match(journal.replay_reservation_receipt_digest, /^[a-f0-9]{64}$/);
      const serializedArtifacts = JSON.stringify({ state, nucleus, journal });
      assert.doesNotMatch(serializedArtifacts, /authorization-record:engagement-1/);
      assert.doesNotMatch(serializedArtifacts, /auth-proof:operator-import-1/);
      assert.doesNotMatch(serializedArtifacts, /effect_rules|asset_aliases|signature_input_digest/);

      const second = await executeTool("bob_init_physical_session", {
        physical_scope_import_ref: importRef,
      });
      assert.equal(second.ok, true, JSON.stringify(second));
      assert.equal(second.data.created, false);
      assert.equal(second.data.nucleus_hash, first.data.nucleus_hash);
      assert.equal(resolverCalls, 1, "complete exact retry must not resolve or consume replay again");
      assert.equal(fixture.getReplayReservationCount(), 1);

      const read = await executeTool("bob_read_session_state", { target_domain: domain });
      assert.equal(read.ok, true, JSON.stringify(read));
      assert.equal(read.data.state.physical_scope.axis_digest, state.physical_scope.axis_digest);

      const physicalVerdictTool = getRegisteredTool("bob_verify_physical_verdict");
      const physicalVerdictAuthority = authorizeToolCall(physicalVerdictTool, {
        target_domain: domain,
        asset_locator: "physical-asset:door-reader",
        verified_verdict_ref: "physical-claim-verdict:authority-test",
      });
      assert.equal(physicalVerdictAuthority.authority_class, "initialized_session_read");
      assert.equal(physicalVerdictAuthority.authority_result, "allowed");
      assert.equal(physicalVerdictAuthority.authority_source, "session_state");

      const webDomain = "physical-verdict-axis.example.com";
      const webSession = await executeTool("bob_init_session", {
        target_domain: webDomain,
        target_url: `https://${webDomain}`,
      });
      assert.equal(webSession.ok, true, JSON.stringify(webSession));
      assert.throws(
        () => authorizeToolCall(physicalVerdictTool, {
          target_domain: webDomain,
          asset_locator: "physical-asset:door-reader",
          verified_verdict_ref: "physical-claim-verdict:authority-test",
        }),
        (error) => error && error.code === "SCOPE_BLOCKED"
          && error.authority.authority_error_code === "session_axis_mismatch",
        "a nonphysical session cannot use global_preapproval metadata to invoke the physical verifier",
      );

      assert.throws(
        () => installPhysicalVerdictResolver(() => ({})),
        /production-qualified resolver port/,
      );
      let testVerdictResolverCalls = 0;
      let uninstallVerdictResolver = installTestPhysicalVerdictResolver(
        createTestPhysicalVerdictResolverPort({ test_only: true, resolve: () => {
          testVerdictResolverCalls += 1;
          setOperatorNote({
            target_domain: domain,
            operator_note: "a test resolver must never enter the production verdict path",
          });
          return {};
        } }),
      );
      try {
        assert.throws(
          () => resolvePhysicalVerdict({
            target_domain: domain,
            asset_locator: "physical-asset:door-reader",
            verified_verdict_ref: "physical-claim-verdict:authority-test",
          }),
          (error) => error && error.code === "physical_verdict_runtime_unconfigured",
          "the public verdict path must refuse an installed test resolver before invoking it",
        );
        assert.equal(testVerdictResolverCalls, 0);
      } finally {
        uninstallVerdictResolver();
      }

      uninstallVerdictResolver = installTestPhysicalVerdictResolver(
        createTestPhysicalVerdictResolverPort({ test_only: true, resolve: async () => ({}) }),
      );
      try {
        assert.throws(
          () => resolvePhysicalVerdict({
            target_domain: domain,
            asset_locator: "physical-asset:door-reader",
            verified_verdict_ref: "physical-claim-verdict:authority-test",
          }),
          (error) => error && error.code === "physical_verdict_runtime_unconfigured",
          "an asynchronous test callback cannot be promoted into the production verdict path",
        );
      } finally {
        uninstallVerdictResolver();
      }

      const note = await executeTool("bob_set_operator_note", {
        target_domain: domain,
        operator_note: "keep the physical inventory checkpoint fail-closed",
      });
      assert.equal(note.ok, true, JSON.stringify(note));
      const afterMutationRetry = await executeTool("bob_init_physical_session", {
        physical_scope_import_ref: importRef,
      });
      assert.equal(afterMutationRetry.ok, true, JSON.stringify(afterMutationRetry));
      assert.equal(afterMutationRetry.data.created, false);
      assert.notEqual(afterMutationRetry.data.nucleus_hash, first.data.nucleus_hash);
      assert.equal(resolverCalls, 1, "ordinary coherent mutations must not re-consume bootstrap replay");

      for (const [toolName, args] of [
        ["bob_http_scan", { target_domain: domain, method: "GET", url: "https://example.com" }],
        ["bob_browser_session_start", { target_domain: domain, target_url: "https://example.com" }],
        ["bob_evm_fetch_source", {
          target_domain: domain,
          chain_id: 1,
          address: "0x0000000000000000000000000000000000000001",
        }],
        ["bob_evm_call", {
          target_domain: domain,
          chain_id: 1,
          to: "0x0000000000000000000000000000000000000001",
          data: "0x",
        }],
        ["bob_evm_storage_read", {
          target_domain: domain,
          chain_id: 1,
          address: "0x0000000000000000000000000000000000000001",
          slot: "0x0",
        }],
        ["bob_evm_role_table", {
          target_domain: domain,
          chain_id: 1,
          contract: "0x0000000000000000000000000000000000000001",
          accounts: ["0x0000000000000000000000000000000000000002"],
        }],
        ["bob_temp_email", { target_domain: domain, operation: "create" }],
      ]) {
        assert.throws(
          () => authorizeToolCall(getRegisteredTool(toolName), args),
          (error) => error && error.code === "SCOPE_BLOCKED"
            && error.authority.authority_error_code === "physical_axis_effect_denied",
          `${toolName} must not inherit authority from a physical slug`,
        );
      }
      for (const toolName of [
        "bob_repo_inventory",
        "bob_repo_prepare_env",
        "bob_repo_docker_run",
        "bob_repo_check",
        "bob_verify_repro_reproduction",
        "bob_verify_oracle_differential",
      ]) {
        assert.throws(
          () => authorizeToolCall(getRegisteredTool(toolName), { target_domain: domain }),
          (error) => error && error.code === "SCOPE_BLOCKED"
            && error.authority.authority_error_code === "session_axis_mismatch",
          `${toolName} must require an explicit repo axis before any local/container execution`,
        );
      }
      const conjunctiveAxisTool = {
        ...getRegisteredTool("bob_repo_inventory"),
        required_session_axes: Object.freeze(["physical", "repo"]),
      };
      assert.throws(
        () => authorizeToolCall(conjunctiveAxisTool, { target_domain: domain }),
        (error) => error && error.code === "SCOPE_BLOCKED"
          && error.authority.authority_error_code === "session_axis_mismatch",
        "multi-axis requirements must require every declared axis",
      );

      const advance = await executeTool("bob_advance_session", {
        target_domain: domain,
        to_state: "OPEN_FRONTIER",
        override: "operator_force",
        override_reason: "test that the physical inventory sentinel is non-bypassable",
      });
      assert.equal(advance.ok, false);
      assert.equal(advance.error.code, "STATE_CONFLICT");
      assert.equal(advance.error.details.blocked_by, "physical_inventory_required");

      const journalPath = physicalSessionBootstrapPath(domain);
      const hardlinkPath = `${journalPath}.hardlink-test`;
      fs.linkSync(journalPath, hardlinkPath);
      try {
        assert.throws(
          () => readVerifiedPhysicalSessionBootstrapJournal(domain, { requireComplete: true }),
          /single-link regular file/,
        );
      } finally {
        fs.unlinkSync(hardlinkPath);
      }

      const journalBackupPath = `${journalPath}.symlink-test`;
      fs.renameSync(journalPath, journalBackupPath);
      fs.symlinkSync(path.basename(journalBackupPath), journalPath);
      try {
        assert.throws(
          () => readVerifiedPhysicalSessionBootstrapJournal(domain, { requireComplete: true }),
          /single-link regular file/,
        );
      } finally {
        fs.unlinkSync(journalPath);
        fs.renameSync(journalBackupPath, journalPath);
      }
      assert.equal(
        readVerifiedPhysicalSessionBootstrapJournal(domain, { requireComplete: true }).status,
        "complete",
      );
    } finally {
      fs.fsyncSync = originalFsync;
      uninstall();
    }
  });
});

test("post-replay bootstrap failure leaves a durable pending journal and exact retry fails closed", async () => {
  await withTempHome(async () => {
    const templates = registry();
    const fixture = scopeImportFixture(templates, policyWithTransition(templates), {
      import_id: "operator_import_pending",
      nonce: "physical-scope-import-pending",
      sequence: 8,
    });
    const importRef = "physical-scope-import:operator-import-pending";
    let resolverCalls = 0;
    const uninstall = installPhysicalSessionBootstrapResolver(() => {
      resolverCalls += 1;
      return Object.freeze({
        effect_template_registry: templates,
        envelope: fixture.envelope,
        session_namespace: "session-namespace:physical-pending",
        verifier: fixture.verifier,
      });
    });
    const originalFsync = fs.fsyncSync;
    let fsyncCalls = 0;
    fs.fsyncSync = (...args) => {
      fsyncCalls += 1;
      if (fsyncCalls === 3) {
        const error = new Error("simulated complete-journal fsync failure");
        error.code = "EIO";
        throw error;
      }
      return originalFsync(...args);
    };
    try {
      const first = await executeTool("bob_init_physical_session", {
        physical_scope_import_ref: importRef,
      });
      assert.equal(first.ok, false);
      assert.equal(resolverCalls, 1);
      assert.equal(fixture.getReplayReservationCount(), 1);
    } finally {
      fs.fsyncSync = originalFsync;
    }
    try {
      const { target_domain: domain } = require("../mcp/lib/physical-session-identity.js")
        .derivePhysicalSessionIdentity(importRef);
      assert.equal(fs.existsSync(physicalSessionBootstrapPath(domain)), true);
      const pending = readVerifiedPhysicalSessionBootstrapJournal(domain);
      assert.equal(pending.status, "pending");
      const retry = await executeTool("bob_init_physical_session", {
        physical_scope_import_ref: importRef,
      });
      assert.equal(retry.ok, false);
      assert.equal(retry.error.code, "STATE_CONFLICT");
      assert.equal(
        retry.error.details.physical_bootstrap_error_code,
        "physical_bootstrap_recovery_required",
      );
      assert.equal(resolverCalls, 1, "pending retry must not re-resolve or weaken replay rejection");
      assert.equal(fixture.getReplayReservationCount(), 1);
    } finally {
      uninstall();
    }
  });
});
