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
} = require("../mcp/lib/governance-contracts.js");
const {
  advanceSession,
  initSession,
  setOperatorNote,
} = require("../mcp/lib/session-state.js");
const {
  readSessionNucleus,
} = require("../mcp/lib/governance-store.js");
const {
  writeJsonDocument,
} = require("../mcp/lib/fabric-common.js");
const {
  sessionNucleusPath,
} = require("../mcp/lib/paths.js");
const {
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");

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
    const bound = buildSessionNucleus({
      target_domain: initial.target_domain,
      target_url: initial.scope_policy.target_url,
      scope_policy: initial.scope_policy,
      egress_identity: initial.egress_identity,
      auth_context: initial.auth_context,
      operator_constraint: initial.operator_constraint,
      lifecycle_state: initial.lifecycle_state,
      physical_scope: physicalScope,
    });
    writeJsonDocument(sessionNucleusPath(domain), bound);

    JSON.parse(setOperatorNote({ target_domain: domain, operator_note: "preserve physical scope" }));
    const afterNote = readSessionNucleus(domain);
    assert.deepEqual(afterNote.physical_scope, physicalScope);
    assert.notEqual(afterNote.nucleus_hash, bound.nucleus_hash);

    JSON.parse(advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER" }));
    const afterAdvance = readSessionNucleus(domain);
    assert.deepEqual(afterAdvance.physical_scope, physicalScope);
    assert.equal(afterAdvance.lifecycle_state, "OPEN_FRONTIER");
    assert.notEqual(afterAdvance.nucleus_hash, afterNote.nucleus_hash);
  });
});

test("lifecycle state rejects unknown target states", () => {
  assert.throws(
    () => normalizeLifecycleState("UNKNOWN"),
    /lifecycle_state must be one of/,
  );
});
