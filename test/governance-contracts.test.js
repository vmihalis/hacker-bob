const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  buildSessionNucleus,
  normalizeLifecycleState,
  sessionNucleusHash,
} = require("../mcp/lib/governance-contracts.js");
const {
  initSession,
} = require("../mcp/lib/session-state.js");
const {
  readSessionNucleus,
} = require("../mcp/lib/governance-store.js");

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

test("lifecycle state rejects unknown target states", () => {
  assert.throws(
    () => normalizeLifecycleState("UNKNOWN"),
    /lifecycle_state must be one of/,
  );
});
