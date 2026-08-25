"use strict";

// S1: adversarial forgeability proof for the cross-axis session-authority
// gate (mcp/core/session/session-authority.js). session-authority-nucleus-
// binding.test.js already proves url/repo/contracts-axis nucleus tamper hard-
// fails and the exact legacy carveout. physical-scope-contract.test.js proves
// the physical happy path plus one axis-mismatch case. This file drives a
// forgery table through readRawAuthorityState's isPhysicalAuthority branch
// (physical_scope_binding_missing / physical_bootstrap_incomplete /
// physical_bootstrap_drift), the governance-store / physical-session-journal
// verified-read tamper-evidence (hash mismatch, symlink, single-link), and
// the authorizeChainScope tuple-forgery path -- every blocked row is
// exact-byte-restored and reproven to succeed, so a block is attributable to
// the attack, not a fixture defect.
//
// Offline only. No network/Docker.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

require("../mcp/tools/tool-registry.js"); // composition root: installs the tool registry as a side effect

const { executeTool } = require("../mcp/core/dispatch/dispatch.js");
const {
  authorizeToolCall,
  classForTool,
  validateSessionAuthorityState,
} = require("../mcp/core/session/session-authority.js");
const {
  LEGACY_MIGRATION_ONLY_TOOL,
  LEGACY_PROJECTION_READ_TOOLS,
} = require("../mcp/core/session/session-authority-context.js");
const {
  buildSessionNucleus,
  normalizePhysicalScopeNucleusAxis,
  readVerifiedSessionNucleus,
} = require("../mcp/core/governance/index.js");
const {
  sessionNucleusPath,
  physicalSessionBootstrapPath,
  statePath,
} = require("../mcp/core/io/paths.js");
const { readJsonFile } = require("../mcp/core/io/storage.js");
const { readSessionEvents } = require("../mcp/core/session/session-events.js");
const {
  normalizePhysicalSessionBootstrapJournal,
  readVerifiedPhysicalSessionBootstrapJournal,
} = require("../mcp/domains/physical/physical-session-journal.js");
const {
  getRegisteredTool,
  TOOL_REGISTRY,
} = require("../mcp/tools/tool-registry.js");
const {
  installPhysicalSessionBootstrapResolver,
} = require("../mcp/domains/physical/physical-session-runtime.js");
const {
  PHYSICAL_SCOPE_IMPORT_DOMAIN,
  PHYSICAL_SCOPE_IMPORT_KEY_USAGE,
  PHYSICAL_SCOPE_IMPORT_KIND,
  createPhysicalScopeImportVerifier,
  normalizePhysicalScopePolicy,
  physicalScopeImportSignatureInputDigest,
} = require("../mcp/domains/physical/physical-scope.js");
const {
  buildEffectTemplateRegistry,
} = require("../mcp/core/requested-effects.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-s1-forgeability-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function makeTempRepoDir(prefix = "bob-s1-repo-fixture-") {
  const raw = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return fs.realpathSync.native ? fs.realpathSync.native(raw) : fs.realpathSync(raw);
}

function snapshot(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function restore(filePath, bytes) {
  fs.writeFileSync(filePath, bytes, "utf8");
}

function readAuthorityErrorCode(fn) {
  try {
    fn();
  } catch (error) {
    return error && error.authority ? error.authority.authority_error_code : null;
  }
  throw new Error("expected authorizeToolCall to throw");
}

// Generic row runner: attack() mutates on-disk fixture state, the blocked
// call must throw with expectedErrorCode and must NOT touch state.json,
// restore() puts the attacked file back byte-for-byte, and the identical
// call must then succeed -- proving the block was caused by the attack, not
// a fixture defect.
function runForgeryRow({
  domain, tool, args, attack, restoreAttack, expectedErrorCode, label,
}) {
  attack();
  const stateAfterAttack = snapshot(statePath(domain));
  let caught = null;
  try {
    authorizeToolCall(tool, args);
  } catch (error) {
    caught = error;
  }
  assert.ok(caught, `${label}: expected a block`);
  assert.equal(caught.authority.authority_result, "blocked", label);
  assert.equal(caught.authority.authority_error_code, expectedErrorCode, label);
  // The GATE itself (not the attacker) must cause no further state.json
  // mutation: compare against the state immediately after the attack, not
  // the pristine pre-attack baseline (the attack itself may legitimately
  // touch state.json, e.g. the raw-field-drift rows).
  const stateAfterBlockedCall = snapshot(statePath(domain));
  assert.equal(
    stateAfterBlockedCall,
    stateAfterAttack,
    `${label}: blocked pre-handler call must not mutate state.json beyond the attack itself`,
  );
  restoreAttack();
  const decision = authorizeToolCall(tool, args);
  assert.equal(decision.authority_result, "allowed", `${label}: restore must reprove the identical call succeeds`);
}

// ---------------------------------------------------------------------------
// Physical fixture plumbing -- reused from physical-scope-contract.test.js's
// scopeImportFixture/registry/policyWithTransition pattern (verbatim
// technique, redefined locally because those helpers are function-scoped in
// that file, not exported as a module).
// ---------------------------------------------------------------------------

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
    policy_id: "physical_campaign_s1",
    authority_epoch: 4,
    revocation_generation: 2,
    transition_receipt_registry_digest: digest("surface-transition-registry-s1"),
    asset_aliases: assets(),
    effect_rules: rules(templates),
    expected_transitions: [],
    constraints: [],
    exclusions: [],
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

function scopeImportFixture(templates, policy = basePolicy(templates), options = {}) {
  const normalizedPolicy = normalizePhysicalScopePolicy(policy, templates);
  const payload = {
    version: 1,
    import_id: options.import_id || "s1_operator_import_1",
    operator_principal_id: "principal:s1-operator-1",
    authored_at: "2026-07-18T00:00:00.000Z",
    authoring_system_ref: "authoring-system:s1-control-plane-1",
    authorization_record_ref: "authorization-record:s1-engagement-1",
    authorization_record_digest: digest("s1-signed-authorization-record"),
    nonce: options.nonce || "s1-physical-scope-import-nonce-1",
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
    trust_root_id: "trust-root:s1-physical-scope-test",
    trust_root_epoch: 7,
    trust_registry_digest: digest("s1-physical-scope-trust-registry"),
    signer_principal_id: "principal:s1-operator-1",
    signer_key_id: "signer-key:s1-operator-scope-1",
    signer_epoch: 3,
    signer_public_key_digest: signerPublicKeyDigest,
    key_usage: PHYSICAL_SCOPE_IMPORT_KEY_USAGE,
    signed_at: options.signed_at || "2026-07-18T00:00:05.000Z",
    signed_payload_digest: importPayloadDigest,
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
  const proofRef = "auth-proof:s1-operator-import-1";
  const proofDigest = sha256Bytes(signature);
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
    authorization_resolution_digest: digest("s1-physical-scope-authorization-resolution"),
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
  };
  const now = options.now || "2026-07-18T00:00:10.000Z";
  const replayReservations = new Map();
  const verifier = createPhysicalScopeImportVerifier({
    verifier_id: options.verifier_id || "s1-physical-scope-import-verifier-v1",
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
      const existing = [...replayReservations.values()].find((entry) => (
        entry.reservation_receipt.replay_claim.import_id === claim.import_id
      ));
      if (existing) return { ...existing, disposition: "existing_same" };
      const reservation = replayReservationResult(claim, { reserved_at: now, fsynced_at: now });
      replayReservations.set(claim.import_id, reservation);
      return reservation;
    },
  });
  return { envelope, verifier };
}

async function seedPhysicalSession(importId = "s1_operator_import_1") {
  const templates = registry();
  const fixture = scopeImportFixture(templates, basePolicy(templates), { import_id: importId });
  const importRef = `physical-scope-import:${importId}`;
  const uninstall = installPhysicalSessionBootstrapResolver(() => Object.freeze({
    effect_template_registry: templates,
    envelope: fixture.envelope,
    session_namespace: `session-namespace:s1-${importId}`,
    verifier: fixture.verifier,
  }));
  try {
    const response = await executeTool("bob_init_physical_session", {
      physical_scope_import_ref: importRef,
    });
    assert.equal(response.ok, true, JSON.stringify(response));
    return response.data.target_domain;
  } finally {
    uninstall();
  }
}

async function seedUrlSession(domain) {
  const response = await executeTool("bob_init_session", {
    target_domain: domain,
    target_url: `https://${domain}/`,
  });
  assert.equal(response.ok, true, JSON.stringify(response));
  return domain;
}

async function seedRepoSession() {
  const repoPath = makeTempRepoDir();
  const response = await executeTool("bob_init_repo_session", { repo_path: repoPath });
  assert.equal(response.ok, true, JSON.stringify(response));
  return response.data.target_domain;
}

const EVM_BOUND_ADDRESS = "0x0000000000000000000000000000000000000002";
const EVM_UNBOUND_ADDRESS = "0x0000000000000000000000000000000000000099";

async function seedContractsSession() {
  const response = await executeTool("bob_init_contract_session", {
    contracts: [{ chain_family: "evm", chain_id: "1", address: EVM_BOUND_ADDRESS }],
  });
  assert.equal(response.ok, true, JSON.stringify(response));
  return response.data.target_domain;
}

// A self-consistently-rehashed nucleus mutation: feeds a verified nucleus
// object back through buildSessionNucleus (the exact production
// normalization/hashing pipeline) after mutating a field, producing a
// nucleus that VERIFIES (single-link, hash matches) but carries different
// content -- the honest way to test "the nucleus content forges a different
// grant", as distinct from "the nucleus file is corrupt/tampered".
function rebuildNucleusWith(domain, mutate) {
  const nucleus = JSON.parse(JSON.stringify(readVerifiedSessionNucleus(domain)));
  mutate(nucleus);
  return buildSessionNucleus(nucleus);
}

const httpScanTool = getRegisteredTool("bob_http_scan");
const repoCheckTool = getRegisteredTool("bob_repo_check");
const evmCallTool = getRegisteredTool("bob_evm_call");
const foundryRunTool = getRegisteredTool("bob_foundry_run");
const physicalVerdictTool = getRegisteredTool("bob_verify_physical_verdict");
const setOperatorNoteTool = getRegisteredTool("bob_set_operator_note");
const readSessionSummaryTool = getRegisteredTool("bob_read_session_summary");
const readSessionStateTool = getRegisteredTool("bob_read_session_state");
const readSessionNucleusTool = getRegisteredTool("bob_read_session_nucleus");
const advanceSessionTool = getRegisteredTool("bob_advance_session");

// ---------------------------------------------------------------------------
// 4. Four controls pass: one clean call per axis, untouched fixtures,
// through the real dispatch/authority-gate path.
// ---------------------------------------------------------------------------

test("four controls pass: url, repo, contracts, physical each grant their representative session-bound tool with untouched fixtures", async () => {
  await withTempHome(async () => {
    const urlDomain = await seedUrlSession("s1-control-url.example.com");
    const urlDecision = authorizeToolCall(httpScanTool, {
      target_domain: urlDomain, method: "GET", url: `https://${urlDomain}/`,
    });
    assert.equal(urlDecision.authority_result, "allowed");

    const repoDomain = await seedRepoSession();
    const repoDecision = authorizeToolCall(repoCheckTool, {
      target_domain: repoDomain, check_type: "file_exists", file_path: "does-not-exist.txt",
    });
    assert.equal(repoDecision.authority_result, "allowed");

    const contractsDomain = await seedContractsSession();
    const contractsDecision = authorizeToolCall(evmCallTool, {
      target_domain: contractsDomain, chain_id: 1, to: EVM_BOUND_ADDRESS, data: "0x",
    });
    assert.equal(contractsDecision.authority_result, "allowed");

    const physicalDomain = await seedPhysicalSession("s1_control_physical");
    const physicalDecision = authorizeToolCall(physicalVerdictTool, {
      target_domain: physicalDomain,
      asset_locator: "physical-asset:s1-control",
      verified_verdict_ref: "physical-claim-verdict:s1-control",
    });
    assert.equal(physicalDecision.authority_result, "allowed");
  });
});

// ---------------------------------------------------------------------------
// url axis forgery table
// ---------------------------------------------------------------------------

test("url axis forgery table: nucleus delete/tamper/symlink and raw target_url drift", async () => {
  await withTempHome(async () => {
    const domain = "s1-forge-url.example.com";
    await seedUrlSession(domain);
    const args = { target_domain: domain, method: "GET", url: `https://${domain}/` };
    const nucleusPath = sessionNucleusPath(domain);

    // (a) delete session-nucleus.json -> legacy carveout, not an axis grant.
    {
      const nucleusBytes = snapshot(nucleusPath);
      runForgeryRow({
        domain,
        tool: httpScanTool,
        args,
        attack: () => fs.unlinkSync(nucleusPath),
        restoreAttack: () => restore(nucleusPath, nucleusBytes),
        expectedErrorCode: "legacy_session_axis_carveout",
        label: "url (a) delete nucleus",
      });
    }

    // (b) tamper nucleus content without recomputing nucleus_hash -> hard
    // fail via readVerifiedSessionNucleus, never a raw-state fallback.
    {
      const nucleusBytes = snapshot(nucleusPath);
      runForgeryRow({
        domain,
        tool: httpScanTool,
        args,
        attack: () => {
          const nucleus = JSON.parse(nucleusBytes);
          nucleus.lifecycle_state = "GRADE";
          fs.writeFileSync(nucleusPath, `${JSON.stringify(nucleus, null, 2)}\n`, "utf8");
        },
        restoreAttack: () => restore(nucleusPath, nucleusBytes),
        expectedErrorCode: "nucleus_unverifiable",
        label: "url (b) tamper nucleus hash",
      });
    }

    // (c) drift state.json's target_url to a different domain against an
    // untouched nucleus -> target_url_drift (SCOPE_BLOCKED).
    {
      const statePathForDomain = statePath(domain);
      const stateBytes = snapshot(statePathForDomain);
      runForgeryRow({
        domain,
        tool: httpScanTool,
        args,
        attack: () => {
          const state = JSON.parse(stateBytes);
          state.target_url = "https://s1-forged-elsewhere.example.net/";
          fs.writeFileSync(statePathForDomain, `${JSON.stringify(state, null, 2)}\n`, "utf8");
        },
        restoreAttack: () => restore(statePathForDomain, stateBytes),
        expectedErrorCode: "target_url_drift",
        label: "url (c) raw target_url drift",
      });
    }

    // (g) symlink-substitute session-nucleus.json -> single-link/no-symlink
    // verified-read rejection.
    {
      const nucleusBytes = snapshot(nucleusPath);
      const backupPath = `${nucleusPath}.s1-orig`;
      runForgeryRow({
        domain,
        tool: httpScanTool,
        args,
        attack: () => {
          fs.renameSync(nucleusPath, backupPath);
          fs.symlinkSync(path.basename(backupPath), nucleusPath);
        },
        restoreAttack: () => {
          fs.unlinkSync(nucleusPath);
          fs.renameSync(backupPath, nucleusPath);
        },
        expectedErrorCode: "nucleus_unverifiable",
        label: "url (g) symlink nucleus",
      });
      assert.equal(snapshot(nucleusPath), nucleusBytes);
    }
  });
});

// ---------------------------------------------------------------------------
// repo axis forgery table
// ---------------------------------------------------------------------------

test("repo axis forgery table: nucleus delete/tamper/symlink and malformed raw repo_hash", async () => {
  await withTempHome(async () => {
    const domain = await seedRepoSession();
    const args = { target_domain: domain, check_type: "file_exists", file_path: "does-not-exist.txt" };
    const nucleusPath = sessionNucleusPath(domain);

    {
      const nucleusBytes = snapshot(nucleusPath);
      runForgeryRow({
        domain,
        tool: repoCheckTool,
        args,
        attack: () => fs.unlinkSync(nucleusPath),
        restoreAttack: () => restore(nucleusPath, nucleusBytes),
        expectedErrorCode: "legacy_session_axis_carveout",
        label: "repo (a) delete nucleus",
      });
    }

    {
      const nucleusBytes = snapshot(nucleusPath);
      runForgeryRow({
        domain,
        tool: repoCheckTool,
        args,
        attack: () => {
          const nucleus = JSON.parse(nucleusBytes);
          nucleus.lifecycle_state = "GRADE";
          fs.writeFileSync(nucleusPath, `${JSON.stringify(nucleus, null, 2)}\n`, "utf8");
        },
        restoreAttack: () => restore(nucleusPath, nucleusBytes),
        expectedErrorCode: "nucleus_unverifiable",
        label: "repo (b) tamper nucleus hash",
      });
    }

    // (c) malformed raw repo_hash fails the presence/format legacy-field
    // check. Note (verified, not assumed): there is no independent raw-vs-
    // nucleus repo_hash EQUALITY check in this dispatch path -- axis grant is
    // sourced exclusively from the verified nucleus (readRepoSession reads
    // the nucleus, not state.repo_hash), so a well-formed-but-wrong raw
    // repo_hash would NOT be caught here. Only the format assertion is
    // real, tested exactly as it exists.
    {
      const statePathForDomain = statePath(domain);
      const stateBytes = snapshot(statePathForDomain);
      runForgeryRow({
        domain,
        tool: repoCheckTool,
        args,
        attack: () => {
          const state = JSON.parse(stateBytes);
          state.repo_hash = "not-a-hex-digest";
          fs.writeFileSync(statePathForDomain, `${JSON.stringify(state, null, 2)}\n`, "utf8");
        },
        restoreAttack: () => restore(statePathForDomain, stateBytes),
        expectedErrorCode: "legacy_security_field_missing",
        label: "repo (c) malformed raw repo_hash",
      });
    }

    {
      const nucleusBytes = snapshot(nucleusPath);
      const backupPath = `${nucleusPath}.s1-orig`;
      runForgeryRow({
        domain,
        tool: repoCheckTool,
        args,
        attack: () => {
          fs.renameSync(nucleusPath, backupPath);
          fs.symlinkSync(path.basename(backupPath), nucleusPath);
        },
        restoreAttack: () => {
          fs.unlinkSync(nucleusPath);
          fs.renameSync(backupPath, nucleusPath);
        },
        expectedErrorCode: "nucleus_unverifiable",
        label: "repo (g) symlink nucleus",
      });
      assert.equal(snapshot(nucleusPath), nucleusBytes);
    }
  });
});

// ---------------------------------------------------------------------------
// contracts axis forgery table + chain-scope tuple forgery
// ---------------------------------------------------------------------------

test("contracts axis forgery table: nucleus delete/tamper/symlink, malformed raw chain_authority_hash, and exact-tuple nucleus forgery", async () => {
  await withTempHome(async () => {
    const domain = await seedContractsSession();
    const evmArgs = { target_domain: domain, chain_id: 1, to: EVM_BOUND_ADDRESS, data: "0x" };
    const nucleusPath = sessionNucleusPath(domain);

    {
      const nucleusBytes = snapshot(nucleusPath);
      runForgeryRow({
        domain,
        tool: evmCallTool,
        args: evmArgs,
        attack: () => fs.unlinkSync(nucleusPath),
        restoreAttack: () => restore(nucleusPath, nucleusBytes),
        expectedErrorCode: "legacy_session_axis_carveout",
        label: "contracts (a) delete nucleus",
      });
    }

    {
      const nucleusBytes = snapshot(nucleusPath);
      runForgeryRow({
        domain,
        tool: evmCallTool,
        args: evmArgs,
        attack: () => {
          const nucleus = JSON.parse(nucleusBytes);
          nucleus.lifecycle_state = "GRADE";
          fs.writeFileSync(nucleusPath, `${JSON.stringify(nucleus, null, 2)}\n`, "utf8");
        },
        restoreAttack: () => restore(nucleusPath, nucleusBytes),
        expectedErrorCode: "nucleus_unverifiable",
        label: "contracts (b) tamper nucleus hash",
      });
    }

    // (c) malformed raw chain_authority_hash. bob_foundry_run (not in
    // CHAIN_SCOPE_TUPLE_BY_TOOL) is the representative here rather than
    // bob_evm_call: verified, not assumed -- authorizeChainScope short-
    // circuits BEFORE authorizeSessionBound's raw-state legacy-field checks
    // whenever the nucleus already binds a matching tuple, so bob_evm_call
    // never actually reaches this raw-state validation while the session's
    // nucleus is intact. bob_foundry_run is smart_contract_contextual but
    // absent from CHAIN_SCOPE_TUPLE_BY_TOOL, so it takes the base class
    // dispatch and does reach readRawAuthorityState's raw-field check.
    {
      const statePathForDomain = statePath(domain);
      const stateBytes = snapshot(statePathForDomain);
      runForgeryRow({
        domain,
        tool: foundryRunTool,
        args: { target_domain: domain },
        attack: () => {
          const state = JSON.parse(stateBytes);
          state.chain_authority_hash = "not-a-hex-digest";
          fs.writeFileSync(statePathForDomain, `${JSON.stringify(state, null, 2)}\n`, "utf8");
        },
        restoreAttack: () => restore(statePathForDomain, stateBytes),
        expectedErrorCode: "legacy_security_field_missing",
        label: "contracts (c) malformed raw chain_authority_hash (bob_foundry_run)",
      });
    }

    {
      const nucleusBytes = snapshot(nucleusPath);
      const backupPath = `${nucleusPath}.s1-orig`;
      runForgeryRow({
        domain,
        tool: evmCallTool,
        args: evmArgs,
        attack: () => {
          fs.renameSync(nucleusPath, backupPath);
          fs.symlinkSync(path.basename(backupPath), nucleusPath);
        },
        restoreAttack: () => {
          fs.unlinkSync(nucleusPath);
          fs.renameSync(backupPath, nucleusPath);
        },
        expectedErrorCode: "nucleus_unverifiable",
        label: "contracts (g) symlink nucleus",
      });
      assert.equal(snapshot(nucleusPath), nucleusBytes);
    }

    // (7) authorizeChainScope-specific forgery: swap the bound tuple's
    // address inside a SELF-CONSISTENTLY rehashed nucleus (chain_authority_hash's
    // hex-shape stays valid but now stale) -- the previously-bound address must
    // no longer be authorized, proving membership tracks live nucleus content,
    // not a cached/widened set. Restore-and-reprove closes the loop.
    {
      const nucleusBytes = snapshot(nucleusPath);
      let caught = null;
      const forged = rebuildNucleusWith(domain, (nucleus) => {
        nucleus.scope_policy.target_contracts[0].address = EVM_UNBOUND_ADDRESS;
      });
      fs.writeFileSync(nucleusPath, `${JSON.stringify(forged, null, 2)}\n`, "utf8");
      try {
        authorizeToolCall(evmCallTool, evmArgs);
      } catch (error) {
        caught = error;
      }
      assert.ok(caught, "contracts (7): previously-bound address must block after tuple swap");
      assert.equal(caught.authority.authority_error_code, "chain_scope_blocked");
      // The forged tuple (now bound) is admitted -- exact-tuple membership
      // tracks the live nucleus, not a superset of every address ever bound.
      const forgedGrant = authorizeToolCall(evmCallTool, {
        target_domain: domain, chain_id: 1, to: EVM_UNBOUND_ADDRESS, data: "0x",
      });
      assert.equal(forgedGrant.authority_result, "allowed");
      restore(nucleusPath, nucleusBytes);
      const restoredGrant = authorizeToolCall(evmCallTool, evmArgs);
      assert.equal(restoredGrant.authority_result, "allowed");
      assert.throws(
        () => authorizeToolCall(evmCallTool, {
          target_domain: domain, chain_id: 1, to: EVM_UNBOUND_ADDRESS, data: "0x",
        }),
        (error) => error.authority && error.authority.authority_error_code === "chain_scope_blocked",
        "contracts (7): after restore the forged address must be blocked again",
      );
    }
  });
});

// ---------------------------------------------------------------------------
// physical axis forgery table: journal + nucleus + state three-way
// consistency, all distinct tamper surfaces.
// ---------------------------------------------------------------------------

test("physical axis forgery table: nucleus/journal delete/tamper/symlink and state<->journal<->nucleus drift", async () => {
  await withTempHome(async () => {
    const domain = await seedPhysicalSession("s1_physical_forge");
    const args = {
      target_domain: domain,
      asset_locator: "physical-asset:s1-forge",
      verified_verdict_ref: "physical-claim-verdict:s1-forge",
    };
    const nucleusPath = sessionNucleusPath(domain);
    const journalPath = physicalSessionBootstrapPath(domain);

    // (a) delete nucleus -- physical never enters the state-only legacy
    // branch (readRawAuthorityState's isPhysicalAuthority arm always reads
    // journal+nucleus together), so this collapses to the SAME code as (e)/
    // (b): physical_bootstrap_incomplete, not legacy_session_axis_carveout.
    // Verified, not assumed: documented here as the real behavior.
    {
      const nucleusBytes = snapshot(nucleusPath);
      runForgeryRow({
        domain,
        tool: physicalVerdictTool,
        args,
        attack: () => fs.unlinkSync(nucleusPath),
        restoreAttack: () => restore(nucleusPath, nucleusBytes),
        expectedErrorCode: "physical_bootstrap_incomplete",
        label: "physical (a) delete nucleus",
      });
    }

    // (b) tamper nucleus content without recomputing nucleus_hash -> caught
    // by the same journal+nucleus try/catch -> physical_bootstrap_incomplete.
    {
      const nucleusBytes = snapshot(nucleusPath);
      runForgeryRow({
        domain,
        tool: physicalVerdictTool,
        args,
        attack: () => {
          const nucleus = JSON.parse(nucleusBytes);
          nucleus.physical_scope.revocation_generation += 1; // stale hash
          fs.writeFileSync(nucleusPath, `${JSON.stringify(nucleus, null, 2)}\n`, "utf8");
        },
        restoreAttack: () => restore(nucleusPath, nucleusBytes),
        expectedErrorCode: "physical_bootstrap_incomplete",
        label: "physical (b) tamper nucleus hash",
      });
    }

    // (d) journal <-> nucleus axis_digest drift: rebuild the JOURNAL's
    // physical_scope through the real normalizer so the journal stays
    // internally self-consistent (verifies fine on its own) but now
    // disagrees with the untouched nucleus -> physical_bootstrap_drift.
    {
      const journalBytes = snapshot(journalPath);
      runForgeryRow({
        domain,
        tool: physicalVerdictTool,
        args,
        attack: () => {
          const journal = JSON.parse(journalBytes);
          const { axis_digest: _drop, ...axisFields } = journal.physical_scope;
          const tamperedAxis = normalizePhysicalScopeNucleusAxis({
            ...axisFields,
            revocation_generation: axisFields.revocation_generation + 1,
          });
          const { journal_hash: _dropHash, ...journalFields } = journal;
          const rebuilt = normalizePhysicalSessionBootstrapJournal({
            ...journalFields,
            physical_scope: tamperedAxis,
          }, { expectedDomain: domain });
          fs.writeFileSync(journalPath, `${JSON.stringify(rebuilt, null, 2)}\n`, "utf8");
        },
        restoreAttack: () => restore(journalPath, journalBytes),
        expectedErrorCode: "physical_bootstrap_drift",
        label: "physical (d) journal axis_digest drift",
      });
    }

    // (c)/state-vs-journal-and-nucleus drift: rebuild state.json's
    // physical_scope through the real axis normalizer (self-consistent on
    // its own) but different content -> the explicit state<->journal/
    // nucleus cross-check fires -> physical_bootstrap_drift, a DIFFERENT
    // tamper surface (state.json, not the journal file) landing on the same
    // code.
    {
      const statePathForDomain = statePath(domain);
      const stateBytes = snapshot(statePathForDomain);
      runForgeryRow({
        domain,
        tool: physicalVerdictTool,
        args,
        attack: () => {
          const state = JSON.parse(stateBytes);
          const { axis_digest: _drop, ...axisFields } = state.physical_scope;
          state.physical_scope = normalizePhysicalScopeNucleusAxis({
            ...axisFields,
            revocation_generation: axisFields.revocation_generation + 1,
          });
          fs.writeFileSync(statePathForDomain, `${JSON.stringify(state, null, 2)}\n`, "utf8");
        },
        restoreAttack: () => restore(statePathForDomain, stateBytes),
        expectedErrorCode: "physical_bootstrap_drift",
        label: "physical (c) state.json physical_scope drift",
      });
    }

    // (e) delete/corrupt physical-session-bootstrap.json -> incomplete.
    {
      const journalBytes = snapshot(journalPath);
      runForgeryRow({
        domain,
        tool: physicalVerdictTool,
        args,
        attack: () => fs.unlinkSync(journalPath),
        restoreAttack: () => restore(journalPath, journalBytes),
        expectedErrorCode: "physical_bootstrap_incomplete",
        label: "physical (e) delete journal",
      });
    }

    // (g) symlink-substitute the journal file -> single-link rejection,
    // surfaced through the physical branch as physical_bootstrap_incomplete.
    {
      const journalBytes = snapshot(journalPath);
      const backupPath = `${journalPath}.s1-orig`;
      runForgeryRow({
        domain,
        tool: physicalVerdictTool,
        args,
        attack: () => {
          fs.renameSync(journalPath, backupPath);
          fs.symlinkSync(path.basename(backupPath), journalPath);
        },
        restoreAttack: () => {
          fs.unlinkSync(journalPath);
          fs.renameSync(backupPath, journalPath);
        },
        expectedErrorCode: "physical_bootstrap_incomplete",
        label: "physical (g) symlink journal",
      });
      assert.equal(snapshot(journalPath), journalBytes);
      // Restored: the journal verifies cleanly again (no residual symlink).
      assert.equal(
        readVerifiedPhysicalSessionBootstrapJournal(domain, { requireComplete: true }).status,
        "complete",
      );
    }
  });
});

// ---------------------------------------------------------------------------
// (f) lifecycle_state: captured in context, NOT gated by the authority
// dispatch path. Verified by grep of the tree (currentSessionAuthorityContext
// has zero non-definition call sites outside session-authority-context.js)
// and proven here empirically: a self-consistently rehashed nucleus with a
// different lifecycle_state still grants normally. Documented as an honest
// negative result per the task's instruction, not silently dropped.
// ---------------------------------------------------------------------------

test("lifecycle_state drift is captured in context but the authority dispatch path does not gate on it", async () => {
  await withTempHome(async () => {
    const domain = "s1-lifecycle-drift.example.com";
    await seedUrlSession(domain);
    const nucleusPath = sessionNucleusPath(domain);
    const nucleusBytes = snapshot(nucleusPath);

    const priorNucleus = JSON.parse(nucleusBytes);
    assert.notEqual(priorNucleus.lifecycle_state, "GRADE");

    const rehashed = rebuildNucleusWith(domain, (nucleus) => {
      nucleus.lifecycle_state = "GRADE";
    });
    fs.writeFileSync(nucleusPath, `${JSON.stringify(rehashed, null, 2)}\n`, "utf8");

    // A self-consistently rehashed nucleus with a drifted lifecycle_state
    // still grants -- the authority gate never consults lifecycle_state.
    const decision = authorizeToolCall(httpScanTool, {
      target_domain: domain, method: "GET", url: `https://${domain}/`,
    });
    assert.equal(decision.authority_result, "allowed");

    restore(nucleusPath, nucleusBytes);
  });
});

// ---------------------------------------------------------------------------
// 5. Nucleus-free exception coverage: the carveout is EXACT across every
// registry-enumerated session-bound tool, not per-tool special-casing.
// This directly settles whether bob_read_session_summary is in the
// carveout: EXPLICIT_AUTHORITY_CLASS_BY_TOOL classifies it
// initialized_session_read (a SESSION_AUTHORITY_CLASSES member), and
// LEGACY_PROJECTION_READ_TOOLS as currently defined does NOT include it --
// so it funnels through the same legacy branch as every other non-carveout
// tool and must be BLOCKED, not admitted.
// ---------------------------------------------------------------------------

const SESSION_BOUND_CLASSES = new Set([
  "initialized_session_read",
  "initialized_session_mutation",
  "scoped_http_network",
  "smart_contract_contextual",
]);

test("the state-only legacy carveout is exactly LEGACY_PROJECTION_READ_TOOLS + LEGACY_MIGRATION_ONLY_TOOL across the full registered tool set", async () => {
  await withTempHome(async () => {
    const domain = "s1-full-carveout.example.com";
    await seedUrlSession(domain);
    fs.unlinkSync(sessionNucleusPath(domain));

    const sessionBoundToolNames = TOOL_REGISTRY
      .map((tool) => tool.name)
      .filter((name) => SESSION_BOUND_CLASSES.has(classForTool(name)));
    assert.ok(sessionBoundToolNames.length > 50, "expected a broad session-bound tool universe");
    assert.ok(sessionBoundToolNames.includes("bob_read_session_summary"));

    const carveoutSet = new Set([...LEGACY_PROJECTION_READ_TOOLS, LEGACY_MIGRATION_ONLY_TOOL]);
    let blockedCount = 0;
    for (const name of sessionBoundToolNames) {
      const tool = getRegisteredTool(name);
      const args = { target_domain: domain };
      if (carveoutSet.has(name)) continue;
      const errorCode = readAuthorityErrorCode(() => authorizeToolCall(tool, args));
      assert.equal(errorCode, "legacy_session_axis_carveout", name);
      blockedCount += 1;
    }
    assert.ok(blockedCount > 40, "expected a broad blocked set beyond the fixed carveout");

    // The correction this test settles: bob_read_session_summary is BLOCKED,
    // not admitted -- it is not part of the exact carveout.
    const summaryErrorCode = readAuthorityErrorCode(
      () => authorizeToolCall(readSessionSummaryTool, { target_domain: domain }),
    );
    assert.equal(summaryErrorCode, "legacy_session_axis_carveout");

    // The two exact carveout reads are still admitted with no axes attached.
    for (const tool of [readSessionStateTool, readSessionNucleusTool]) {
      const decision = authorizeToolCall(tool, { target_domain: domain });
      assert.equal(decision.authority_result, "allowed", tool.name);
      assert.equal(decision.authority_source, "legacy_state_projection", tool.name);
    }
    const advanceDecision = authorizeToolCall(advanceSessionTool, { target_domain: domain, to_state: "OPEN_FRONTIER" });
    assert.equal(advanceDecision.authority_result, "allowed");
    assert.equal(advanceDecision.authority_source, "legacy_migration_only");
  });
});

// ---------------------------------------------------------------------------
// 6. Bootstrap/global/cross-session dispatch check: validateSessionAuthorityState
// routes through the exact same readRawAuthorityState hard-fail as
// authorizeToolCall -- not a separate, weaker code path.
// ---------------------------------------------------------------------------

test("validateSessionAuthorityState hard-fails on a tampered nucleus through readRawAuthorityState, same as authorizeToolCall", async () => {
  await withTempHome(async () => {
    const domain = "s1-validate-state.example.com";
    await seedUrlSession(domain);
    const nucleusPath = sessionNucleusPath(domain);
    const nucleusBytes = snapshot(nucleusPath);

    const decision = validateSessionAuthorityState(domain);
    assert.equal(decision.authority_result, "allowed");

    const nucleus = JSON.parse(nucleusBytes);
    nucleus.lifecycle_state = "GRADE";
    fs.writeFileSync(nucleusPath, `${JSON.stringify(nucleus, null, 2)}\n`, "utf8");

    assert.throws(
      () => validateSessionAuthorityState(domain),
      (error) => error.authority && error.authority.authority_error_code === "nucleus_unverifiable",
    );

    restore(nucleusPath, nucleusBytes);
    const restored = validateSessionAuthorityState(domain);
    assert.equal(restored.authority_result, "allowed");
  });
});

// ---------------------------------------------------------------------------
// 8. Governance-event/audit expectation: a blocked forged call appends no
// session event; the legitimate restored call does.
// ---------------------------------------------------------------------------

test("a blocked forged call appends no session event; the legitimate restored call does", async () => {
  await withTempHome(async () => {
    const domain = "s1-event-ledger.example.com";
    await seedUrlSession(domain);
    const nucleusPath = sessionNucleusPath(domain);
    const nucleusBytes = snapshot(nucleusPath);

    const eventsBefore = readSessionEvents(domain);

    const nucleus = JSON.parse(nucleusBytes);
    nucleus.lifecycle_state = "GRADE";
    fs.writeFileSync(nucleusPath, `${JSON.stringify(nucleus, null, 2)}\n`, "utf8");

    const blocked = await executeTool("bob_set_operator_note", {
      target_domain: domain,
      operator_note: "should never land: forged nucleus",
    });
    assert.equal(blocked.ok, false);
    assert.equal(blocked.error.details.authority.authority_error_code, "nucleus_unverifiable");

    const eventsAfterBlocked = readSessionEvents(domain);
    assert.deepEqual(eventsAfterBlocked, eventsBefore, "a blocked pre-handler call must append no session event");

    restore(nucleusPath, nucleusBytes);

    const legit = await executeTool("bob_set_operator_note", {
      target_domain: domain,
      operator_note: "restored call must append an event",
    });
    assert.equal(legit.ok, true, JSON.stringify(legit));

    const eventsAfterLegit = readSessionEvents(domain);
    assert.equal(eventsAfterLegit.length, eventsBefore.length + 1);
    assert.equal(
      eventsAfterLegit[eventsAfterLegit.length - 1].kind,
      "governance.operator_constraint.updated",
    );
  });
});

// Direct authorizeToolCall variant of the same governance-event proof,
// isolating the gate itself (rather than the full dispatch/handler path) as
// the thing that never appends when the forgery is caught pre-handler.
test("authorizeToolCall throwing pre-handler on a symlinked nucleus never reaches the handler that would append a session event", async () => {
  await withTempHome(async () => {
    const domain = "s1-event-ledger-symlink.example.com";
    await seedUrlSession(domain);
    const nucleusPath = sessionNucleusPath(domain);
    const nucleusBytes = snapshot(nucleusPath);
    const backupPath = `${nucleusPath}.s1-orig`;

    const eventsBefore = readSessionEvents(domain);
    fs.renameSync(nucleusPath, backupPath);
    fs.symlinkSync(path.basename(backupPath), nucleusPath);

    assert.throws(
      () => authorizeToolCall(setOperatorNoteTool, { target_domain: domain, operator_note: "x" }),
      (error) => error.authority && error.authority.authority_error_code === "nucleus_unverifiable",
    );
    assert.deepEqual(readSessionEvents(domain), eventsBefore);

    fs.unlinkSync(nucleusPath);
    fs.renameSync(backupPath, nucleusPath);
    assert.equal(snapshot(nucleusPath), nucleusBytes);

    const readJson = readJsonFile(statePath(domain), { label: "state.json" });
    assert.equal(readJson.target, domain);
  });
});
