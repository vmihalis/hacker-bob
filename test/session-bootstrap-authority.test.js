"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const REPO_ROOT = path.resolve(__dirname, "..");
const CHILD_ENV_FLAG = "A1_BOOTSTRAP_AUTHORITY_CHILD";
const CHILD_CASE_ENV = "A1_BOOTSTRAP_AUTHORITY_CASE";

function trackedRootEnv() {
  return {
    HOME: process.env.HOME,
    BOB_SESSIONS_ROOT: process.env.BOB_SESSIONS_ROOT,
    BOUNTY_TELEMETRY_DIR: process.env.BOUNTY_TELEMETRY_DIR,
    BOB_PROJECT_DIR: process.env.BOB_PROJECT_DIR,
  };
}

function mkdirPrivate(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
}

function runChildCase(caseName) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `a1-bootstrap-${caseName}-`));
  const home = path.join(root, "home");
  const sessionsRoot = path.join(root, "sessions");
  const telemetryRoot = path.join(root, "telemetry");
  const projectDir = path.join(root, "project");
  for (const directory of [home, sessionsRoot, telemetryRoot, projectDir]) {
    mkdirPrivate(directory);
  }

  const before = trackedRootEnv();
  try {
    const result = spawnSync(
      process.execPath,
      [
        "--require",
        "./mcp/tools/tool-registry.js",
        "--test",
        __filename,
      ],
      {
        cwd: REPO_ROOT,
        env: {
          ...process.env,
          [CHILD_ENV_FLAG]: "1",
          [CHILD_CASE_ENV]: caseName,
          HOME: home,
          BOB_SESSIONS_ROOT: sessionsRoot,
          BOUNTY_TELEMETRY_DIR: telemetryRoot,
          BOB_PROJECT_DIR: projectDir,
        },
        encoding: "utf8",
      },
    );
    assert.deepEqual(trackedRootEnv(), before, "parent ambient roots must not be mutated");
    assert.equal(
      result.status,
      0,
      [
        `child case ${caseName} exited ${result.status}`,
        "stdout:",
        result.stdout,
        "stderr:",
        result.stderr,
      ].join("\n"),
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function parentSuite() {
  test("pure bootstrap authority matrix pins SETUP and verified nucleus parity", async (t) => {
    for (const caseName of [
      "success-url",
      "success-repo",
      "success-contract",
      "success-physical",
    ]) {
      await t.test(caseName, () => runChildCase(caseName));
    }
  });

  test("web bootstrap create collisions preserve native EEXIST winners without effects", async (t) => {
    for (const caseName of [
      "web-create-collision-state",
      "web-create-collision-nucleus",
      "web-create-collision-events",
    ]) {
      await t.test(caseName, () => runChildCase(caseName));
    }
  });

  test("web bootstrap postcommit failure preserves canonical authority only", () => {
    runChildCase("web-postcommit-lab-failure");
  });

  test("contract bootstrap is contracts-only with one canonical initialization event", () => {
    runChildCase("contract-state-shape");
  });

  test("contract bootstrap create collisions preserve winners and expose no effects", async (t) => {
    for (const caseName of [
      "contract-create-collision-state",
      "contract-create-collision-nucleus",
      "contract-create-collision-events",
    ]) {
      await t.test(caseName, () => runChildCase(caseName));
    }
  });

  test("contract bootstrap rejects unsafe preimages without touching outsiders", async (t) => {
    for (const caseName of [
      "contract-preimage-symlink",
      "contract-preimage-nonempty",
    ]) {
      await t.test(caseName, () => runChildCase(caseName));
    }
  });

  test("contract bootstrap postcommit failures retain canonical authority", () => {
    runChildCase("contract-postcommit-key-failure");
  });

  test("physical bootstrap rejects before replay without documents or journal", async (t) => {
    for (const caseName of [
      "physical-resolver-rejection",
      "physical-verifier-rejection",
    ]) {
      await t.test(caseName, () => runChildCase(caseName));
    }
  });

  test("physical post-replay failure leaves only pending recovery authority", () => {
    runChildCase("physical-post-replay-failure");
  });

  test("physical A2 authority write faults preserve pending recovery authority", async (t) => {
    for (const caseName of [
      "physical-a2-state-failure",
      "physical-a2-event-failure",
    ]) {
      await t.test(caseName, () => runChildCase(caseName));
    }
  });
}

function childSuite() {
  const {
    executeTool,
  } = require("../mcp/core/dispatch/dispatch.js");
  const {
    LIFECYCLE_STATE_VALUES,
    readVerifiedSessionNucleus,
    sessionNucleusFromState,
  } = require("../mcp/core/governance/index.js");
  const {
    frontierEventsJsonlPath,
    physicalSessionBootstrapPath,
    handoffSigningKeyPath,
    handoffSigningPrivateKeyPath,
    handoffSigningPublicKeyPath,
    labAuthorizationPath,
    pipelineEventsJsonlPath,
    queuePolicyPath,
    sandboxIsolationPath,
    sessionEventsJsonlPath,
    sessionDir,
    sessionNucleusPath,
    sessionsRoot,
    statePath,
    surfaceIndexPath,
    taskGraphPath,
    taskQueuePath,
    telemetryDir,
  } = require("../mcp/core/io/paths.js");
  const {
    readSessionStateStrict,
  } = require("../mcp/core/session/session-state-store.js");
  const {
    publicSessionState,
  } = require("../mcp/core/session/session-state-contracts.js");
  const {
    derivePhysicalSessionIdentity,
  } = require("../mcp/core/session/synthetic-session-identity-contracts.js");
  const {
    deriveContractSession,
  } = require("../mcp/core/chain-authority-contracts.js");
  const {
    hashCanonicalJson,
  } = require("../mcp/core/verification/verification-contracts.js");
  const {
    buildEffectTemplateRegistry,
  } = require("../mcp/core/requested-effects.js");
  const {
    deriveRepoTargetDomain,
  } = require("../mcp/domains/repo/repo-target.js");
  const {
    PHYSICAL_SCOPE_IMPORT_DOMAIN,
    PHYSICAL_SCOPE_IMPORT_KEY_USAGE,
    PHYSICAL_SCOPE_IMPORT_KIND,
    createPhysicalScopeImportVerifier,
    normalizePhysicalScopePolicy,
    physicalScopeImportSignatureInputDigest,
  } = require("../mcp/domains/physical/physical-scope.js");
  const {
    installPhysicalSessionBootstrapResolver,
  } = require("../mcp/domains/physical/physical-session-runtime.js");
  const {
    readVerifiedPhysicalSessionBootstrapJournal,
  } = require("../mcp/domains/physical/physical-session-journal.js");
  const {
    readSessionEvents,
  } = require("../mcp/core/session/session-events.js");
  const {
    readFrontierEvents,
  } = require("../mcp/core/frontier/frontier-events.js");
  const {
    loadQueuePolicy,
  } = require("../mcp/core/io/queue-policy.js");
  const {
    LAB_TARGET_ACK_ENV,
    LAB_TARGET_ACK_TOKEN,
    LAB_TARGET_HOST_ENV,
  } = require("../mcp/core/lab-target-attest.js");

  const EVM_CONTRACT = Object.freeze({
    chain_family: "evm",
    chain_id: "1",
    address: "0x00000000000000000000000000000000000000a1",
  });

  function assertChildRootsAreBootBound() {
    assert.equal(sessionsRoot(), process.env.BOB_SESSIONS_ROOT);
    assert.equal(telemetryDir(), process.env.BOUNTY_TELEMETRY_DIR);
    assert.equal(os.homedir(), process.env.HOME);
  }

  function makeTempRepo(name = "repo-fixture") {
    const repo = fs.mkdtempSync(path.join(process.env.HOME, `${name}-`));
    return fs.realpathSync.native ? fs.realpathSync.native(repo) : fs.realpathSync(repo);
  }

  function documentPairStatus(domain) {
    return {
      state: fs.existsSync(statePath(domain)),
      nucleus: fs.existsSync(sessionNucleusPath(domain)),
    };
  }

  function assertDocumentPairAbsent(domain) {
    assert.deepEqual(documentPairStatus(domain), { state: false, nucleus: false });
  }

  function assertNoPhysicalBootstrapArtifacts(domain) {
    for (const filePath of [
      physicalSessionBootstrapPath(domain),
      statePath(domain),
      sessionNucleusPath(domain),
      sessionEventsJsonlPath(domain),
      pipelineEventsJsonlPath(domain),
      handoffSigningKeyPath(domain),
      handoffSigningPrivateKeyPath(domain),
      handoffSigningPublicKeyPath(domain),
    ]) {
      assert.equal(fs.existsSync(filePath), false, `${path.basename(filePath)} must be absent`);
    }
  }

  function activeAxes(state) {
    const axes = [];
    if (state.target_url != null) axes.push("url");
    if (state.target_repo != null) axes.push("repo");
    if (Array.isArray(state.target_contracts) && state.target_contracts.length > 0) {
      axes.push("contracts");
    }
    if (state.physical_scope != null) axes.push("physical");
    return axes;
  }

  function assertSetupLifecycle(document, label) {
    assert.ok(LIFECYCLE_STATE_VALUES.includes("SETUP"), "SETUP must remain canonical");
    assert.equal(document.lifecycle_state, "SETUP", `${label} must carry SETUP`);
  }

  function assertPureBootstrapState(domain, expectedAxis) {
    const { state } = readSessionStateStrict(domain);
    assertSetupLifecycle(state, "state.json");
    assert.deepEqual(activeAxes(state), [expectedAxis], "pure bootstrap must activate exactly one axis");
    return state;
  }

  function assertVerifiedNucleusParity(domain, expectedAxis) {
    assert.deepEqual(documentPairStatus(domain), { state: true, nucleus: true });
    const state = assertPureBootstrapState(domain, expectedAxis);
    const rehydrated = sessionNucleusFromState(state);
    const verified = readVerifiedSessionNucleus(domain);
    assertSetupLifecycle(rehydrated, "state-derived nucleus");
    assertSetupLifecycle(verified, "session-nucleus.json");
    assert.equal(rehydrated.nucleus_hash, verified.nucleus_hash);
    return { state, rehydrated, verified };
  }

  function authorityPaths(domain) {
    return {
      state: statePath(domain),
      nucleus: sessionNucleusPath(domain),
      events: sessionEventsJsonlPath(domain),
    };
  }

  function downstreamArtifactPaths(domain) {
    return [
      labAuthorizationPath(domain),
      handoffSigningKeyPath(domain),
      handoffSigningPrivateKeyPath(domain),
      handoffSigningPublicKeyPath(domain),
      queuePolicyPath(domain),
      sandboxIsolationPath(domain),
      pipelineEventsJsonlPath(domain),
      frontierEventsJsonlPath(domain),
      surfaceIndexPath(domain),
      taskQueuePath(domain),
      taskGraphPath(domain),
    ];
  }

  function assertDownstreamArtifactsAbsent(domain) {
    for (const filePath of downstreamArtifactPaths(domain)) {
      assert.equal(fs.existsSync(filePath), false, `${path.basename(filePath)} must be absent`);
    }
  }

  function assertAuthorityTempsAbsent(domain) {
    const basenames = Object.values(authorityPaths(domain)).map((filePath) => path.basename(filePath));
    const names = fs.existsSync(sessionDir(domain)) ? fs.readdirSync(sessionDir(domain)) : [];
    const authorityTemps = names.filter((name) => basenames.some(
      (basename) => name.startsWith(`.${basename}.`) && name.endsWith(".tmp"),
    ));
    assert.deepEqual(authorityTemps, [], "authority staging files must be removed");
  }

  function assertSingleBoundInitEvent(domain, verified) {
    const events = readSessionEvents(domain);
    assert.equal(events.length, 1, "bootstrap must publish exactly one governance event");
    const [event] = events;
    assert.equal(event.kind, "governance.session.initialized");
    assert.equal(event.target_domain, domain);
    assert.equal(event.nucleus_hash, verified.nucleus_hash);
    assert.equal(event.payload.nucleus_hash, verified.nucleus_hash);
    assert.equal(event.payload.scope_policy_hash, hashCanonicalJson(verified.scope_policy));
    assert.equal(event.payload.egress_identity_hash, hashCanonicalJson(verified.egress_identity));
    assert.equal(event.payload.auth_context_hash, hashCanonicalJson(verified.auth_context));
    assert.equal(
      event.payload.operator_constraint_hash,
      hashCanonicalJson(verified.operator_constraint),
    );
    return event;
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

  function physicalAssets() {
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

  function physicalRules(templates) {
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

  function basePhysicalPolicy(templates) {
    return {
      version: 1,
      policy_id: "physical_campaign_1",
      authority_epoch: 4,
      revocation_generation: 2,
      transition_receipt_registry_digest: digest("surface-transition-registry"),
      asset_aliases: physicalAssets(),
      effect_rules: physicalRules(templates),
      expected_transitions: [],
      constraints: [],
      exclusions: [],
    };
  }

  function physicalPolicyWithTransition(templates) {
    const initial = normalizePhysicalScopePolicy(basePhysicalPolicy(templates), templates);
    const presentTuple = initial.effect_rules.find((rule) => rule.rule_id === "allow_present").tuple;
    return {
      ...basePhysicalPolicy(templates),
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

  function scopeImportFixture(templates, policy = physicalPolicyWithTransition(templates), options = {}) {
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
      verifier,
      getReplayReservationCount() {
        return replayReservationCount;
      },
    };
  }

  async function bootstrapPhysicalSession(importRef, fixtureOptions = {}) {
    const templates = registry();
    const fixture = scopeImportFixture(
      templates,
      physicalPolicyWithTransition(templates),
      fixtureOptions,
    );
    const uninstall = installPhysicalSessionBootstrapResolver((ref) => {
      assert.equal(ref, importRef);
      return Object.freeze({
        effect_template_registry: templates,
        envelope: fixture.envelope,
        session_namespace: `session-namespace:${importRef.split(":")[1]}`,
        verifier: fixture.verifier,
      });
    });
    try {
      const env = await executeTool("bob_init_physical_session", {
        physical_scope_import_ref: importRef,
      });
      return { env, fixture };
    } finally {
      uninstall();
    }
  }

  function assertWinnerUnchanged(filePath, expectedStats, expectedBytes) {
    const currentStats = fs.lstatSync(filePath);
    assert.equal(currentStats.isFile(), true);
    assert.equal(currentStats.isSymbolicLink(), false);
    assert.equal(currentStats.nlink, 1);
    assert.equal(currentStats.dev, expectedStats.dev);
    assert.equal(currentStats.ino, expectedStats.ino);
    assert.equal(Buffer.compare(fs.readFileSync(filePath), expectedBytes), 0);
  }

  function contractFixture(label) {
    return Object.freeze({
      chain_family: "evm",
      chain_id: "1",
      address: `0x${crypto.createHash("sha256").update(label).digest("hex").slice(0, 40)}`,
    });
  }

  function assertContractEffects(domain, env, contract, authorityHash, linkedDepth = 3) {
    for (const filePath of [
      handoffSigningKeyPath(domain),
      handoffSigningPrivateKeyPath(domain),
      handoffSigningPublicKeyPath(domain),
      queuePolicyPath(domain),
      frontierEventsJsonlPath(domain),
      surfaceIndexPath(domain),
      taskQueuePath(domain),
      taskGraphPath(domain),
    ]) {
      assert.equal(fs.existsSync(filePath), true, `${path.basename(filePath)} must be materialized`);
    }
    assert.equal(loadQueuePolicy(domain).linked_contract_depth, linkedDepth);
    const expectedSurface = `sc-evm-1-${contract.address.toLowerCase()}`;
    assert.deepEqual(env.data.seeded_surfaces, [expectedSurface]);
    const frontier = readFrontierEvents(domain);
    assert.equal(frontier.length, 2, "one seed and one contract surface must be recorded");
    assert.equal(frontier[0].kind, "session.seeded");
    assert.equal(frontier[0].payload.chain_authority_hash, authorityHash);
    assert.equal(frontier[1].kind, "surface.observed");
    assert.equal(frontier[1].surface_id, expectedSurface);
    assert.equal(frontier[1].payload.chain_family, "evm");
    assert.equal(frontier[1].payload.contract_address, contract.address.toLowerCase());
  }

  function assertContractResult(env, contract, derived, linkedDepth = 3) {
    assert.equal(env.ok, true, JSON.stringify(env));
    assert.equal(env.data.version, 1);
    assert.equal(env.data.created, true);
    assert.equal(env.data.target_domain, derived.domain);
    assert.equal(env.data.session_dir, sessionDir(derived.domain));
    assert.equal(env.data.chain_authority_hash, derived.authorityHash);
    assert.equal(env.data.linked_contract_depth, linkedDepth);
    assert.deepEqual(env.data.target_contracts, [
      `evm:1:${contract.address.toLowerCase()}`,
    ]);
    const { state, verified } = assertVerifiedNucleusParity(derived.domain, "contracts");
    assert.equal(state.chain_authority_hash, derived.authorityHash);
    assert.deepEqual(state.target_contracts, env.data.target_contracts);
    assert.deepEqual(verified.scope_policy.target_contracts, [{
      chain_family: "evm",
      chain_id: "1",
      address: contract.address.toLowerCase(),
    }]);
    assert.equal(verified.scope_policy.chain_authority_hash, derived.authorityHash);
    const event = assertSingleBoundInitEvent(derived.domain, verified);
    assert.equal(event.payload.chain_authority_hash, derived.authorityHash);
    assert.deepEqual(event.source, {
      artifact: "state.json",
      tool: "bob_init_contract_session",
    });
    assertContractEffects(derived.domain, env, contract, derived.authorityHash, linkedDepth);
    assertAuthorityTempsAbsent(derived.domain);
    return { state, verified };
  }

  async function assertContractSuccess(contract, options = {}) {
    const derived = deriveContractSession([contract]);
    const linkedDepth = options.linked_contract_depth == null ? 3 : options.linked_contract_depth;
    const env = await executeTool("bob_init_contract_session", {
      contracts: [contract],
      ...options,
    });
    assertContractResult(env, contract, derived, linkedDepth);
    return { env, derived };
  }

  function removeExactWinner(filePath, expectedStats, expectedBytes) {
    assertWinnerUnchanged(filePath, expectedStats, expectedBytes);
    fs.unlinkSync(filePath);
    assert.equal(fs.existsSync(filePath), false);
  }

  async function assertContractCreateCollision(member) {
    const contract = contractFixture(`a5r-contract-${member}-collision`);
    const derived = deriveContractSession([contract]);
    const files = authorityPaths(derived.domain);
    const order = ["state", "nucleus", "events"];
    const targetIndex = order.indexOf(member);
    const target = files[member];
    const winnerBytes = Buffer.from(`a5r ${member} outsider\n`, "utf8");
    const realLinkSync = fs.linkSync;
    const realOpenSync = fs.openSync;
    const realWriteSync = fs.writeSync;
    const realCloseSync = fs.closeSync;
    let hookCalls = 0;
    let nativeCollision = null;
    let winnerStats = null;

    fs.linkSync = function injectedContractCollision(source, destination) {
      if (path.resolve(destination) !== path.resolve(target)) {
        return realLinkSync(source, destination);
      }
      hookCalls += 1;
      assert.equal(hookCalls, 1);
      for (const [index, name] of order.entries()) {
        assert.equal(
          fs.existsSync(files[name]),
          index < targetIndex,
          `${name} must reflect state -> nucleus -> events publication order`,
        );
      }
      const sourceStats = fs.lstatSync(source);
      assert.equal(sourceStats.isFile(), true);
      assert.equal(sourceStats.isSymbolicLink(), false);
      assert.equal(path.dirname(source), path.dirname(target));
      assert.equal(path.basename(source).startsWith(`.${path.basename(target)}.`), true);
      assert.equal(path.basename(source).endsWith(".tmp"), true);
      const fd = realOpenSync(
        target,
        fs.constants.O_CREAT
          | fs.constants.O_EXCL
          | fs.constants.O_WRONLY
          | (fs.constants.O_NOFOLLOW || 0),
        0o600,
      );
      try {
        assert.equal(realWriteSync(fd, winnerBytes, 0, winnerBytes.length, 0), winnerBytes.length);
      } finally {
        realCloseSync(fd);
      }
      winnerStats = fs.lstatSync(target);
      try {
        return realLinkSync(source, destination);
      } catch (error) {
        nativeCollision = error;
        throw error;
      }
    };

    let env;
    try {
      env = await executeTool("bob_init_contract_session", { contracts: [contract] });
    } finally {
      fs.linkSync = realLinkSync;
    }

    assert.equal(hookCalls, 1);
    assert.equal(nativeCollision && nativeCollision.code, "EEXIST");
    assert.equal(env.ok, false, JSON.stringify(env));
    assert.equal(env.error.code, "STATE_CONFLICT");
    assert.equal(env.error.message, `${path.basename(target)} already exists`);
    for (const [name, filePath] of Object.entries(files)) {
      assert.equal(fs.existsSync(filePath), name === member, `${name} authority residue`);
    }
    assert.ok(winnerStats);
    assertWinnerUnchanged(target, winnerStats, winnerBytes);
    assertAuthorityTempsAbsent(derived.domain);
    assertDownstreamArtifactsAbsent(derived.domain);

    removeExactWinner(target, winnerStats, winnerBytes);
    assert.deepEqual(
      Object.fromEntries(Object.entries(files).map(([name, filePath]) => [name, fs.existsSync(filePath)])),
      { state: false, nucleus: false, events: false },
    );
    await assertContractSuccess(contract);
  }

  async function assertContractPreimage(kind) {
    const contract = contractFixture(`a5r-contract-${kind}-preimage`);
    const { domain } = deriveContractSession([contract]);
    const files = authorityPaths(domain);
    fs.mkdirSync(sessionDir(domain), { recursive: true, mode: 0o700 });
    const outsiderBytes = Buffer.from(`a5r ${kind} outsider\n`, "utf8");
    let preimage;
    let outsider = null;
    let outsiderStats = null;

    if (kind === "symlink") {
      outsider = path.join(process.env.HOME, "a5r-contract-symlink-outsider.json");
      fs.writeFileSync(outsider, outsiderBytes, { flag: "wx", mode: 0o600 });
      outsiderStats = fs.lstatSync(outsider);
      preimage = files.nucleus;
      fs.symlinkSync(outsider, preimage);
    } else {
      preimage = files.events;
      fs.writeFileSync(preimage, outsiderBytes, { flag: "wx", mode: 0o600 });
      outsiderStats = fs.lstatSync(preimage);
    }

    const env = await executeTool("bob_init_contract_session", { contracts: [contract] });
    assert.equal(env.ok, false, JSON.stringify(env));
    assert.equal(env.error.code, "STATE_CONFLICT");
    if (kind === "symlink") {
      assert.equal(fs.lstatSync(preimage).isSymbolicLink(), true);
      assert.equal(fs.readlinkSync(preimage), outsider);
      assertWinnerUnchanged(outsider, outsiderStats, outsiderBytes);
    } else {
      assertWinnerUnchanged(preimage, outsiderStats, outsiderBytes);
    }
    for (const [name, filePath] of Object.entries(files)) {
      assert.equal(fs.existsSync(filePath), filePath === preimage, `${name} preimage residue`);
    }
    assertAuthorityTempsAbsent(domain);
    assertDownstreamArtifactsAbsent(domain);
  }

  async function assertContractPostcommitFailure() {
    const contract = contractFixture("a5r-contract-postcommit-key-failure");
    const derived = deriveContractSession([contract]);
    const realOpenSync = fs.openSync;
    const injected = Object.assign(new Error("simulated contract postcommit key failure"), {
      code: "EIO",
    });
    let faultCount = 0;
    let env;

    fs.openSync = function injectedKeyOpen(requested, ...rest) {
      const isKeyTemp = typeof requested === "string"
        && path.dirname(requested) === sessionDir(derived.domain)
        && path.basename(requested).startsWith("..handoff-signing-key.json.")
        && path.basename(requested).endsWith(".tmp");
      if (!isKeyTemp) return realOpenSync(requested, ...rest);
      faultCount += 1;
      assert.equal(faultCount, 1);
      const { verified } = assertVerifiedNucleusParity(derived.domain, "contracts");
      const event = assertSingleBoundInitEvent(derived.domain, verified);
      assert.equal(event.payload.chain_authority_hash, derived.authorityHash);
      assertDownstreamArtifactsAbsent(derived.domain);
      throw injected;
    };

    try {
      env = await executeTool("bob_init_contract_session", { contracts: [contract] });
    } finally {
      fs.openSync = realOpenSync;
    }
    assert.equal(faultCount, 1);
    assert.equal(env.ok, false, JSON.stringify(env));
    assert.equal(env.error.code, "INTERNAL_ERROR");
    assert.equal(env.error.message, injected.message);
    const { verified } = assertVerifiedNucleusParity(derived.domain, "contracts");
    assertSingleBoundInitEvent(derived.domain, verified);
    assertAuthorityTempsAbsent(derived.domain);
    assertDownstreamArtifactsAbsent(derived.domain);

    const snapshots = Object.fromEntries(Object.entries(authorityPaths(derived.domain)).map(
      ([name, filePath]) => [name, { stats: fs.lstatSync(filePath), bytes: fs.readFileSync(filePath) }],
    ));
    const retry = await executeTool("bob_init_contract_session", { contracts: [contract] });
    assert.equal(retry.ok, false, JSON.stringify(retry));
    assert.equal(retry.error.code, "STATE_CONFLICT");
    for (const [name, filePath] of Object.entries(authorityPaths(derived.domain))) {
      assertWinnerUnchanged(filePath, snapshots[name].stats, snapshots[name].bytes);
    }
    assertSingleBoundInitEvent(derived.domain, verified);
    assertDownstreamArtifactsAbsent(derived.domain);
  }

  async function assertWebCreateCollision(member) {
    const domain = `a3r-web-${member}-collision.example.com`;
    const files = authorityPaths(domain);
    const publicationOrder = ["state", "nucleus", "events"];
    const targetIndex = publicationOrder.indexOf(member);
    const target = files[member];
    const winnerBytes = Buffer.from(`a3r ${member} collision winner\n`, "utf8");
    const realLinkSync = fs.linkSync;
    let hookCalls = 0;
    let nativeCollision = null;
    let winnerStats = null;

    fs.linkSync = function injectedLink(source, destination) {
      if (path.resolve(destination) !== path.resolve(target)) {
        return realLinkSync(source, destination);
      }
      hookCalls += 1;
      assert.equal(hookCalls, 1, "target publication must reach link exactly once");
      for (const [index, name] of publicationOrder.entries()) {
        assert.equal(
          fs.existsSync(files[name]),
          index < targetIndex,
          `${name} must reflect state -> nucleus -> events publication order`,
        );
      }
      assert.equal(path.dirname(source), path.dirname(target));
      assert.equal(path.basename(source).startsWith(`.${path.basename(target)}.`), true);
      assert.equal(path.basename(source).endsWith(".tmp"), true);
      assert.equal(fs.lstatSync(source).isFile(), true);
      fs.writeFileSync(target, winnerBytes, { flag: "wx", mode: 0o600 });
      winnerStats = fs.lstatSync(target);
      try {
        return realLinkSync(source, destination);
      } catch (error) {
        nativeCollision = error;
        throw error;
      }
    };

    let env;
    try {
      env = await executeTool("bob_init_session", {
        target_domain: domain,
        target_url: `https://${domain}/`,
      });
    } finally {
      fs.linkSync = realLinkSync;
    }

    assert.equal(hookCalls, 1);
    assert.ok(nativeCollision);
    assert.equal(nativeCollision.code, "EEXIST");
    assert.equal(env.ok, false, JSON.stringify(env));
    assert.equal(env.error.code, "STATE_CONFLICT");
    assert.equal(env.error.message, `${path.basename(target)} already exists`);
    assert.ok(winnerStats);
    for (const [name, filePath] of Object.entries(files)) {
      assert.equal(fs.existsSync(filePath), name === member, `${name} authority residue`);
    }
    assertWinnerUnchanged(target, winnerStats, winnerBytes);
    assertAuthorityTempsAbsent(domain);
    assertDownstreamArtifactsAbsent(domain);

    const retry = await executeTool("bob_init_session", {
      target_domain: domain,
      target_url: `https://${domain}/`,
    });
    assert.equal(retry.ok, false, JSON.stringify(retry));
    assert.equal(retry.error.code, "STATE_CONFLICT");
    for (const [name, filePath] of Object.entries(files)) {
      assert.equal(fs.existsSync(filePath), name === member, `${name} retry authority residue`);
    }
    assertWinnerUnchanged(target, winnerStats, winnerBytes);
    assertAuthorityTempsAbsent(domain);
    assertDownstreamArtifactsAbsent(domain);
  }

  async function assertWebPostcommitLabFailure() {
    const domain = "127.0.0.1";
    const args = {
      target_domain: domain,
      target_url: `https://${domain}/`,
      lab_authorization: { private_targets: true },
    };
    const previousAck = process.env[LAB_TARGET_ACK_ENV];
    const previousHost = process.env[LAB_TARGET_HOST_ENV];
    const realWriteFileSync = fs.writeFileSync;
    const injected = Object.assign(new Error("simulated postcommit lab-sidecar failure"), {
      code: "EIO",
    });
    let faultCount = 0;
    let env;

    process.env[LAB_TARGET_ACK_ENV] = LAB_TARGET_ACK_TOKEN;
    process.env[LAB_TARGET_HOST_ENV] = domain;
    fs.writeFileSync = function injectedLabWrite(requested, ...rest) {
      const isLabTemp = typeof requested === "string"
        && path.dirname(requested) === sessionDir(domain)
        && path.basename(requested).startsWith(".lab-authorization.json.")
        && path.basename(requested).endsWith(".tmp");
      if (!isLabTemp) return realWriteFileSync(requested, ...rest);
      faultCount += 1;
      assert.equal(faultCount, 1);
      assert.deepEqual(
        Object.fromEntries(Object.entries(authorityPaths(domain)).map(([name, filePath]) => [
          name,
          fs.existsSync(filePath),
        ])),
        { state: true, nucleus: true, events: true },
        "authority must commit before the lab sidecar",
      );
      assertDownstreamArtifactsAbsent(domain);
      throw injected;
    };

    try {
      try {
        env = await executeTool("bob_init_session", args);
      } finally {
        fs.writeFileSync = realWriteFileSync;
      }
      assert.equal(faultCount, 1);
      assert.equal(env.ok, false, JSON.stringify(env));
      assert.equal(env.error.code, "INTERNAL_ERROR");
      assert.equal(env.error.message, injected.message);
      const { verified } = assertVerifiedNucleusParity(domain, "url");
      assertSingleBoundInitEvent(domain, verified);
      assertAuthorityTempsAbsent(domain);
      assertDownstreamArtifactsAbsent(domain);
      const authoritySnapshots = Object.fromEntries(Object.entries(authorityPaths(domain)).map(
        ([name, filePath]) => [name, {
          stats: fs.lstatSync(filePath),
          bytes: fs.readFileSync(filePath),
        }],
      ));
      const labTemps = fs.readdirSync(sessionDir(domain)).filter(
        (name) => name.startsWith(".lab-authorization.json.") && name.endsWith(".tmp"),
      );
      assert.deepEqual(labTemps, []);

      const retry = await executeTool("bob_init_session", args);
      assert.equal(retry.ok, false, JSON.stringify(retry));
      assert.equal(retry.error.code, "STATE_CONFLICT");
      const { verified: retryVerified } = assertVerifiedNucleusParity(domain, "url");
      assertSingleBoundInitEvent(domain, retryVerified);
      for (const [name, filePath] of Object.entries(authorityPaths(domain))) {
        const snapshot = authoritySnapshots[name];
        assertWinnerUnchanged(filePath, snapshot.stats, snapshot.bytes);
      }
      assertAuthorityTempsAbsent(domain);
      assertDownstreamArtifactsAbsent(domain);
    } finally {
      fs.writeFileSync = realWriteFileSync;
      if (previousAck === undefined) delete process.env[LAB_TARGET_ACK_ENV];
      else process.env[LAB_TARGET_ACK_ENV] = previousAck;
      if (previousHost === undefined) delete process.env[LAB_TARGET_HOST_ENV];
      else process.env[LAB_TARGET_HOST_ENV] = previousHost;
    }
  }

  const cases = {
    async "success-url"() {
      const domain = "a1-bootstrap-url.example.com";
      const env = await executeTool("bob_init_session", {
        target_domain: domain,
        target_url: `https://${domain}/`,
      });
      assert.equal(env.ok, true, JSON.stringify(env));
      assert.equal(env.data.version, 1);
      assert.equal(env.data.created, true);
      assert.equal(env.data.session_dir, sessionDir(domain));
      assert.equal(env.data.state.target, domain);
      const { verified } = assertVerifiedNucleusParity(domain, "url");
      assertSingleBoundInitEvent(domain, verified);
    },

    async "web-create-collision-state"() {
      await assertWebCreateCollision("state");
    },

    async "web-create-collision-nucleus"() {
      await assertWebCreateCollision("nucleus");
    },

    async "web-create-collision-events"() {
      await assertWebCreateCollision("events");
    },

    async "web-postcommit-lab-failure"() {
      await assertWebPostcommitLabFailure();
    },

    async "success-repo"() {
      const repoPath = makeTempRepo("repo-axis");
      const domain = deriveRepoTargetDomain(repoPath);
      const env = await executeTool("bob_init_repo_session", {
        repo_path: repoPath,
      });
      assert.equal(env.ok, true, JSON.stringify(env));
      assert.equal(env.data.target_domain, domain);
      const { state, verified } = assertVerifiedNucleusParity(domain, "repo");
      assert.equal(state.target_repo.root_path, repoPath);
      assert.equal(verified.scope_policy.target_repo.root_path, repoPath);
    },

    async "success-contract"() {
      await assertContractSuccess(EVM_CONTRACT);
    },

    async "contract-state-shape"() {
      const derived = deriveContractSession([EVM_CONTRACT]);
      const env = await executeTool("bob_init_contract_session", {
        contracts: [EVM_CONTRACT],
      });
      const { state } = assertContractResult(env, EVM_CONTRACT, derived);
      assert.equal(state.target_url, null);
      assert.equal(state.target_repo == null, true);
      assert.equal(state.physical_scope == null, true);
      assert.equal(Array.isArray(state.target_contracts), true);
      assert.equal(state.target_contracts.length > 0, true);
      assert.deepEqual(state.target_contracts, [
        "evm:1:0x00000000000000000000000000000000000000a1",
      ]);
      assert.equal(state.chain_authority_hash, derived.authorityHash);
    },

    async "contract-create-collision-state"() {
      await assertContractCreateCollision("state");
    },

    async "contract-create-collision-nucleus"() {
      await assertContractCreateCollision("nucleus");
    },

    async "contract-create-collision-events"() {
      await assertContractCreateCollision("events");
    },

    async "contract-preimage-symlink"() {
      await assertContractPreimage("symlink");
    },

    async "contract-preimage-nonempty"() {
      await assertContractPreimage("nonempty");
    },

    async "contract-postcommit-key-failure"() {
      await assertContractPostcommitFailure();
    },

    async "success-physical"() {
      const importRef = "physical-scope-import:a1-axis-matrix";
      const identity = derivePhysicalSessionIdentity(importRef);
      const { env, fixture } = await bootstrapPhysicalSession(importRef, {
        import_id: "operator_import_a1_axis_matrix",
        nonce: "physical-scope-import-a1-axis-matrix",
        sequence: 41,
      });
      assert.equal(env.ok, true, JSON.stringify(env));
      assert.equal(env.data.target_domain, identity.target_domain);
      assert.equal(env.data.session_id, identity.session_id);
      assert.equal(fixture.getReplayReservationCount(), 1);
      const { state, verified } = assertVerifiedNucleusParity(identity.target_domain, "physical");
      assert.equal(state.physical_scope.axis_digest, env.data.physical_scope.axis_digest);
      assert.equal(verified.physical_scope.axis_digest, env.data.physical_scope.axis_digest);
      const journal = readVerifiedPhysicalSessionBootstrapJournal(identity.target_domain, { requireComplete: true });
      assert.equal(journal.status, "complete");
      assert.equal(journal.nucleus_hash, verified.nucleus_hash);
      assert.equal(journal.state_hash, hashCanonicalJson(publicSessionState(state)));
      const initializedEvents = readSessionEvents(identity.target_domain)
        .filter((event) => event.kind === "governance.session.initialized");
      assert.equal(initializedEvents.length, 1);
      assert.equal(initializedEvents[0].nucleus_hash, verified.nucleus_hash);
      assert.equal(initializedEvents[0].payload.nucleus_hash, verified.nucleus_hash);
    },

    async "physical-resolver-rejection"() {
      const importRef = "physical-scope-import:a1-resolver-rejection";
      const identity = derivePhysicalSessionIdentity(importRef);
      let resolverCalls = 0;
      const uninstall = installPhysicalSessionBootstrapResolver((ref) => {
        resolverCalls += 1;
        assert.equal(ref, importRef);
        const error = new Error("private resolver rejection before replay");
        error.code = "physical_bootstrap_runtime_unavailable";
        throw error;
      });
      try {
        const env = await executeTool("bob_init_physical_session", {
          physical_scope_import_ref: importRef,
        });
        assert.equal(env.ok, false);
        assert.equal(env.error.code, "STATE_CONFLICT");
        assert.equal(
          env.error.details.physical_bootstrap_error_code,
          "physical_bootstrap_runtime_unavailable",
        );
        assert.equal(resolverCalls, 1);
        assertNoPhysicalBootstrapArtifacts(identity.target_domain);
      } finally {
        uninstall();
      }
    },

    async "physical-verifier-rejection"() {
      const templates = registry();
      const fixture = scopeImportFixture(templates, physicalPolicyWithTransition(templates), {
        import_id: "operator_import_a1_verifier_rejection",
        nonce: "physical-scope-import-a1-verifier-rejection",
        sequence: 42,
      });
      let replayCalls = 0;
      const verifier = createPhysicalScopeImportVerifier({
        verifier_id: "physical-scope-a1-pre-replay-verifier",
        trusted_now: () => "2026-07-18T00:00:10.000Z",
        resolve_current_authority: () => {
          throw new Error("private verifier rejection before replay");
        },
        verify_detached_signature: () => true,
        reserve_replay: () => {
          replayCalls += 1;
          throw new Error("replay must not be consumed");
        },
      });
      const importRef = "physical-scope-import:a1-verifier-rejection";
      const identity = derivePhysicalSessionIdentity(importRef);
      const uninstall = installPhysicalSessionBootstrapResolver((ref) => {
        assert.equal(ref, importRef);
        return Object.freeze({
          effect_template_registry: templates,
          envelope: fixture.envelope,
          session_namespace: "session-namespace:a1-verifier-rejection",
          verifier,
        });
      });
      try {
        const env = await executeTool("bob_init_physical_session", {
          physical_scope_import_ref: importRef,
        });
        assert.equal(env.ok, false);
        assert.equal(env.error.code, "STATE_CONFLICT");
        assert.equal(
          env.error.details.physical_bootstrap_error_code,
          "physical_bootstrap_import_verification_failed",
        );
        assert.equal(replayCalls, 0);
        assertNoPhysicalBootstrapArtifacts(identity.target_domain);
      } finally {
        uninstall();
      }
    },

    async "physical-post-replay-failure"() {
      const templates = registry();
      const fixture = scopeImportFixture(templates, physicalPolicyWithTransition(templates), {
        import_id: "operator_import_a1_pending",
        nonce: "physical-scope-import-a1-pending",
        sequence: 43,
      });
      const importRef = "physical-scope-import:a1-pending";
      const identity = derivePhysicalSessionIdentity(importRef);
      let resolverCalls = 0;
      const uninstall = installPhysicalSessionBootstrapResolver((ref) => {
        resolverCalls += 1;
        assert.equal(ref, importRef);
        return Object.freeze({
          effect_template_registry: templates,
          envelope: fixture.envelope,
          session_namespace: "session-namespace:a1-pending",
          verifier: fixture.verifier,
        });
      });
      const originalWriteFileSync = fs.writeFileSync;
      let completeJournalWriteAttempts = 0;
      fs.writeFileSync = (...args) => {
        const serialized = typeof args[1] === "string" ? args[1] : null;
        let document = null;
        if (serialized != null) {
          try {
            document = JSON.parse(serialized);
          } catch {}
        }
        if (
          document != null
          && document.bootstrap_kind === "physical_only"
          && document.target_domain === identity.target_domain
          && document.status === "complete"
        ) {
          completeJournalWriteAttempts += 1;
          const error = new Error("simulated complete-journal write failure");
          error.code = "EIO";
          throw error;
        }
        return originalWriteFileSync(...args);
      };
      try {
        const first = await executeTool("bob_init_physical_session", {
          physical_scope_import_ref: importRef,
        });
        assert.equal(first.ok, false);
        assert.equal(resolverCalls, 1);
        assert.equal(fixture.getReplayReservationCount(), 1);
        assert.equal(completeJournalWriteAttempts, 1);
      } finally {
        fs.writeFileSync = originalWriteFileSync;
      }
      try {
        assert.equal(fs.existsSync(physicalSessionBootstrapPath(identity.target_domain)), true);
        const pending = readVerifiedPhysicalSessionBootstrapJournal(identity.target_domain);
        assert.equal(pending.status, "pending");
        const { state, verified } = assertVerifiedNucleusParity(identity.target_domain, "physical");
        assert.equal(pending.nucleus_hash, verified.nucleus_hash);
        assert.equal(pending.state_hash, hashCanonicalJson(publicSessionState(state)));
        const initializedEvents = readSessionEvents(identity.target_domain)
          .filter((event) => event.kind === "governance.session.initialized");
        assert.equal(initializedEvents.length, 1);
        assert.equal(initializedEvents[0].nucleus_hash, verified.nucleus_hash);
        const retry = await executeTool("bob_init_physical_session", {
          physical_scope_import_ref: importRef,
        });
        assert.equal(retry.ok, false);
        assert.equal(retry.error.code, "STATE_CONFLICT");
        assert.equal(
          retry.error.details.physical_bootstrap_error_code,
          "physical_bootstrap_recovery_required",
        );
        assert.equal(resolverCalls, 1, "pending retry must not resolve or consume replay again");
        assert.equal(fixture.getReplayReservationCount(), 1);
      } finally {
        uninstall();
      }
    },

    async "physical-a2-state-failure"() {
      await assertPhysicalA2FaultRecovery({
        importRef: "physical-scope-import:a2-state-failure",
        fixtureOptions: {
          import_id: "operator_import_a2_state_failure",
          nonce: "physical-scope-import-a2-state-failure",
          sequence: 44,
        },
        sessionNamespace: "session-namespace:a2-state-failure",
        patchFs(identity, counters) {
          const originalWriteFileSync = fs.writeFileSync;
          fs.writeFileSync = (...args) => {
            const requested = typeof args[0] === "string" ? args[0] : null;
            if (requested != null && path.basename(requested).startsWith(".state.json.")) {
              counters.authorityFaults += 1;
              assert.equal(fs.existsSync(physicalSessionBootstrapPath(identity.target_domain)), true);
              const error = new Error("simulated A2 state write failure");
              error.code = "EIO";
              throw error;
            }
            return originalWriteFileSync(...args);
          };
          return () => {
            fs.writeFileSync = originalWriteFileSync;
          };
        },
      });
    },

    async "physical-a2-event-failure"() {
      await assertPhysicalA2FaultRecovery({
        importRef: "physical-scope-import:a2-event-failure",
        fixtureOptions: {
          import_id: "operator_import_a2_event_failure",
          nonce: "physical-scope-import-a2-event-failure",
          sequence: 45,
        },
        sessionNamespace: "session-namespace:a2-event-failure",
        patchFs(identity, counters) {
          const originalAppendFileSync = fs.appendFileSync;
          fs.appendFileSync = (...args) => {
            if (args[0] === sessionEventsJsonlPath(identity.target_domain)) {
              counters.authorityFaults += 1;
              assert.equal(fs.existsSync(physicalSessionBootstrapPath(identity.target_domain)), true);
              assert.equal(fs.existsSync(statePath(identity.target_domain)), true);
              assert.equal(fs.existsSync(sessionNucleusPath(identity.target_domain)), true);
              const error = new Error("simulated A2 event append failure");
              error.code = "EIO";
              throw error;
            }
            return originalAppendFileSync(...args);
          };
          return () => {
            fs.appendFileSync = originalAppendFileSync;
          };
        },
      });
    },

  };

  async function assertPhysicalA2FaultRecovery({
    importRef,
    fixtureOptions,
    sessionNamespace,
    patchFs,
  }) {
    const templates = registry();
    const fixture = scopeImportFixture(templates, physicalPolicyWithTransition(templates), fixtureOptions);
    const identity = derivePhysicalSessionIdentity(importRef);
    let resolverCalls = 0;
    const counters = { authorityFaults: 0 };
    const uninstall = installPhysicalSessionBootstrapResolver((ref) => {
      resolverCalls += 1;
      assert.equal(ref, importRef);
      return Object.freeze({
        effect_template_registry: templates,
        envelope: fixture.envelope,
        session_namespace: sessionNamespace,
        verifier: fixture.verifier,
      });
    });
    const restoreFs = patchFs(identity, counters);
    try {
      const first = await executeTool("bob_init_physical_session", {
        physical_scope_import_ref: importRef,
      });
      assert.equal(first.ok, false);
      assert.equal(resolverCalls, 1);
      assert.equal(fixture.getReplayReservationCount(), 1);
      assert.equal(counters.authorityFaults, 1);
    } finally {
      restoreFs();
    }
    try {
      assert.equal(fs.existsSync(physicalSessionBootstrapPath(identity.target_domain)), true);
      const pending = readVerifiedPhysicalSessionBootstrapJournal(identity.target_domain);
      assert.equal(pending.status, "pending");
      assertDocumentPairAbsent(identity.target_domain);
      assert.equal(fs.existsSync(sessionEventsJsonlPath(identity.target_domain)), false);
      assert.equal(fs.existsSync(pipelineEventsJsonlPath(identity.target_domain)), false);
      assert.equal(fs.existsSync(handoffSigningKeyPath(identity.target_domain)), false);
      assert.equal(fs.existsSync(handoffSigningPrivateKeyPath(identity.target_domain)), false);
      assert.equal(fs.existsSync(handoffSigningPublicKeyPath(identity.target_domain)), false);
      const retry = await executeTool("bob_init_physical_session", {
        physical_scope_import_ref: importRef,
      });
      assert.equal(retry.ok, false);
      assert.equal(retry.error.code, "STATE_CONFLICT");
      assert.equal(
        retry.error.details.physical_bootstrap_error_code,
        "physical_bootstrap_recovery_required",
      );
      assert.equal(resolverCalls, 1, "pending retry must not resolve after an A2 authority fault");
      assert.equal(fixture.getReplayReservationCount(), 1);
    } finally {
      uninstall();
    }
  }

  const caseName = process.env[CHILD_CASE_ENV];
  test(`child ${caseName}`, async () => {
    assertChildRootsAreBootBound();
    assert.equal(typeof cases[caseName], "function", `unknown child case ${caseName}`);
    await cases[caseName]();
  });
}

if (process.env[CHILD_ENV_FLAG] === "1") {
  childSuite();
} else {
  parentSuite();
}
