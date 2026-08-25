const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  buildSessionNucleus,
  normalizeLifecycleState,
  normalizePhysicalScopeNucleusAxis,
  sessionNucleusHash,
} = require("../mcp/core/governance/index.js");
const {
  advanceSession,
  initSession,
  resolveAndAssertSessionEgressIdentity,
  setOperatorNote,
} = require("../mcp/core/session/session-state.js");
const {
  readSessionNucleus,
} = require("../mcp/core/governance/index.js");
const {
  writeJsonDocument,
} = require("../mcp/core/io/storage.js");
const {
  sessionNucleusPath,
  statePath,
} = require("../mcp/core/io/paths.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");

function digest(label) {
  return hashCanonicalJson({ label });
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-governance-contracts-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

test("session nucleus normalizes governance planes and hashes stable content", () => {
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
    egress_identity: {
      egress_profile: "default",
      proxy_configured: false,
    },
    auth_context: {
      auth_status: "pending",
    },
    operator_constraint: {
      handoff_provenance_required: true,
    },
  });

  assert.equal(nucleus.lifecycle_state, "SETUP");
  assert.equal(nucleus.scope_policy.target_domain, "example.com");
  assert.equal(nucleus.egress_identity.egress_profile, "default");
  assert.equal(nucleus.auth_context.auth_status, "pending");
  assert.equal(nucleus.operator_constraint.handoff_provenance_required, true);
  assert.equal(sessionNucleusHash(nucleus), nucleus.nucleus_hash);
});

test("session initialization passes through the governance nucleus", () => {
  withTempHome(() => {
    const domain = "governance.example.com";
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));

    const nucleus = readSessionNucleus(domain);
    assert.equal(nucleus.target_domain, domain);
    assert.equal(nucleus.scope_policy.target_url, `https://${domain}`);
    assert.equal(nucleus.lifecycle_state, "SETUP");
    assert.equal(nucleus.operator_constraint.handoff_provenance_required, true);
    assert.match(nucleus.nucleus_hash, /^[0-9a-f]{64}$/);
  });
});

test("operator and lifecycle nucleus rewrites preserve a bound physical scope axis", () => {
  withTempHome(() => {
    const domain = "physical-nucleus-preservation.example.com";
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
    const initial = readSessionNucleus(domain);
    const physicalScope = normalizePhysicalScopeNucleusAxis({
      version: 1,
      physical_enabled: true,
      policy_version: 1,
      policy_id: "physical_campaign_preservation",
      policy_digest: digest("physical-policy"),
      projection_version: 1,
      projection_digest: digest("physical-projection"),
      provenance_digest: digest("physical-provenance"),
      compatibility_digest: digest("physical-compatibility"),
      transition_receipt_registry_digest: digest("surface-transition-registry"),
      authority_epoch: 4,
      revocation_generation: 2,
    });
    const repoHash = "a1b2c3d4e5f60718";
    const bound = buildSessionNucleus({
      target_domain: initial.target_domain,
      target_url: initial.scope_policy.target_url,
      scope_policy: initial.scope_policy,
      egress_identity: initial.egress_identity,
      auth_context: initial.auth_context,
      operator_constraint: initial.operator_constraint,
      lifecycle_state: initial.lifecycle_state,
      physical_scope: physicalScope,
      repo_hash: repoHash,
    });
    writeJsonDocument(sessionNucleusPath(domain), bound);

    JSON.parse(setOperatorNote({ target_domain: domain, operator_note: "preserve physical scope" }));
    const afterNote = readSessionNucleus(domain);
    assert.deepEqual(afterNote.physical_scope, physicalScope);
    assert.equal(afterNote.repo_hash, repoHash);
    assert.notEqual(afterNote.nucleus_hash, bound.nucleus_hash);

    JSON.parse(advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER" }));
    const afterAdvance = readSessionNucleus(domain);
    assert.deepEqual(afterAdvance.physical_scope, physicalScope);
    assert.equal(afterAdvance.repo_hash, repoHash);
    assert.equal(afterAdvance.lifecycle_state, "OPEN_FRONTIER");
    assert.notEqual(afterAdvance.nucleus_hash, afterNote.nucleus_hash);
  });
});

test("a state-backed egress legacy-migration rewrite preserves a bound physical scope axis and repo_hash", () => {
  withTempHome(() => {
    const domain = "legacy-egress-nucleus-preservation.example.com";
    const state = {
      target: domain,
      target_url: `https://${domain}`,
      deep_mode: false,
      checkpoint_mode: "normal",
      block_internal_hosts: false,
      block_internal_hosts_source: "legacy_default",
      phase: "EVALUATE",
      evaluation_wave: 0,
      pending_wave: null,
      total_findings: 0,
      prereq_registry_snapshots: [],
      blocked_prereq_history: [],
      terminal_block_clear_history: [],
      dead_ends: [],
      waf_blocked_endpoints: [],
      scope_exclusions: [],
      hold_count: 0,
      auth_status: "pending",
      egress_profile: "default",
      egress_region: null,
      proxy_configured: false,
      egress_profile_identity_hash: null,
      egress_profile_identity_version: null,
      egress_profile_identity_source: {
        proxy_url_source: "none",
        proxy_env_var: null,
        proxy_url_redacted: null,
        resolved_proxy: null,
      },
      egress_profile_identity_bound_at: null,
      egress_profile_identity_bind_source: null,
      egress_profile_legacy_migration: null,
      operator_note: null,
      verification_schema_version: null,
      verification_attempt_id: null,
      verification_snapshot_hash: null,
      verification_entered_at: null,
    };
    writeJsonDocument(statePath(domain), state);

    const physicalScope = normalizePhysicalScopeNucleusAxis({
      version: 1,
      physical_enabled: true,
      policy_version: 1,
      policy_id: "physical_campaign_egress_preservation",
      policy_digest: digest("physical-policy-egress"),
      projection_version: 1,
      projection_digest: digest("physical-projection-egress"),
      provenance_digest: digest("physical-provenance-egress"),
      compatibility_digest: digest("physical-compatibility-egress"),
      transition_receipt_registry_digest: digest("surface-transition-registry-egress"),
      authority_epoch: 1,
      revocation_generation: 0,
    });
    const repoHash = "0011223344556677";
    const priorNucleus = buildSessionNucleus({
      target_domain: domain,
      target_url: state.target_url,
      scope_policy: {
        target_url: state.target_url,
        checkpoint_mode: state.checkpoint_mode,
        block_internal_hosts: state.block_internal_hosts,
      },
      egress_identity: {
        egress_profile: state.egress_profile,
        egress_region: state.egress_region,
        proxy_configured: state.proxy_configured,
        egress_profile_identity_hash: state.egress_profile_identity_hash,
        egress_profile_identity_version: state.egress_profile_identity_version,
      },
      auth_context: { auth_status: state.auth_status },
      operator_constraint: {},
      lifecycle_state: "OPEN_FRONTIER",
      physical_scope: physicalScope,
      repo_hash: repoHash,
    });
    writeJsonDocument(sessionNucleusPath(domain), priorNucleus);

    resolveAndAssertSessionEgressIdentity(domain, "default", { source: "governance_contracts_test" });
    const afterMigration = readSessionNucleus(domain);
    assert.deepEqual(afterMigration.physical_scope, physicalScope);
    assert.equal(afterMigration.repo_hash, repoHash);
    assert.notEqual(afterMigration.nucleus_hash, priorNucleus.nucleus_hash);
  });
});

test("lifecycle state rejects unknown target states", () => {
  assert.throws(
    () => normalizeLifecycleState("UNKNOWN"),
    /lifecycle_state must be one of/,
  );
});
