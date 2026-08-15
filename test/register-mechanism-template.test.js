"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  registerMechanismCandidates,
  readMechanismCandidates,
} = require("../mcp/core/mechanism/mechanism-candidate-store.js");
const {
  mechanismCandidatesJsonlPath,
  isAuditGradedPath,
  WRITE_GUARD_TABLES,
} = require("../mcp/core/io/paths.js");
const { TOOL_MODULES } = require("../mcp/tools/index.js");

function uniqueDomain(prefix = "bob-mech-candidate-test") {
  const suffix = crypto.randomBytes(4).toString("hex");
  return `${prefix}-${suffix}.local`;
}

function domainDir(domain) {
  return path.join(os.homedir(), "hacker-bob-sessions", domain);
}

function cleanupDomain(domain) {
  const dir = domainDir(domain);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}

function registerTool() {
  const tool = TOOL_MODULES.find((entry) => entry.name === "bob_register_mechanism_template");
  assert.ok(tool, "bob_register_mechanism_template is registered in TOOL_MODULES");
  return tool;
}

// A loader-shaped candidate the store accepts. The store stamps the advisory tier
// markers regardless of what the caller declares.
function sampleCandidate(overrides) {
  return {
    id: "cand-cwe-639",
    mechanism_id: "CWE-639",
    name: "Object authorization candidate",
    description: "An advisory candidate normalized from a known class.",
    required_entities: ["principal", "object", "policy_gate", "effect"],
    interventions: ["object_swap"],
    positive_controls: ["owned_object_allowed"],
    negative_controls: ["public_object_check", "non_discriminating_control_refused"],
    confounders: ["public_object"],
    evidence_predicate: { kind: "differential_effect", required_cwe: "CWE-639" },
    source_tier: "cwe_catalog",
    ...overrides,
  };
}

test("the tool dispatches, persists candidates, and writes mechanism-candidates.jsonl", () => {
  const domain = uniqueDomain();
  try {
    const tool = registerTool();
    const result = tool.handler({
      target_domain: domain,
      candidates: [sampleCandidate()],
    });
    assert.equal(result.registered_count, 1);
    assert.equal(result.new_count, 1);
    assert.equal(result.total_in_registry, 1);
    assert.ok(fs.existsSync(mechanismCandidatesJsonlPath(domain)), "ledger file written");
  } finally {
    cleanupDomain(domain);
  }
});

test("a registered candidate persists tier:3 / candidate:true / claim_authority:false", () => {
  const domain = uniqueDomain();
  try {
    registerMechanismCandidates({ target_domain: domain, candidates: [sampleCandidate()] });
    const stored = readMechanismCandidates(domain);
    assert.equal(stored.length, 1);
    assert.equal(stored[0].tier, 3, "registered candidate is tier-3 advisory");
    assert.equal(stored[0].candidate, true);
    assert.equal(stored[0].claim_authority, false, "a candidate never carries claim authority");
    assert.equal(stored[0].advisory_evidence.executed_proof, false, "merely-believed marker preserved");
  } finally {
    cleanupDomain(domain);
  }
});

test("registration is idempotent by dedup key (re-register replaces, never duplicates)", () => {
  const domain = uniqueDomain();
  try {
    const first = registerMechanismCandidates({ target_domain: domain, candidates: [sampleCandidate()] });
    assert.equal(first.new_count, 1);
    const second = registerMechanismCandidates({
      target_domain: domain,
      candidates: [sampleCandidate({ description: "re-ingested with a tweaked description" })],
    });
    assert.equal(second.new_count, 0, "same dedup key is not a new candidate");
    assert.equal(second.replaced_count, 1, "same dedup key replaces in place");
    const stored = readMechanismCandidates(domain);
    assert.equal(stored.length, 1, "no duplicate row for the same mechanism");
  } finally {
    cleanupDomain(domain);
  }
});

test("a caller cannot register a candidate as confirmed (declared claim_authority is overridden)", () => {
  const domain = uniqueDomain();
  try {
    // A caller declaring tier:2 / claim_authority:true must NOT be able to mint a
    // confirmed template through the advisory registry: minting != confirming.
    registerMechanismCandidates({
      target_domain: domain,
      candidates: [sampleCandidate({ tier: 2, candidate: false, claim_authority: true })],
    });
    const stored = readMechanismCandidates(domain);
    assert.equal(stored[0].tier, 3, "the registry forces tier-3 on registration");
    assert.equal(stored[0].claim_authority, false, "registration never grants claim authority");
  } finally {
    cleanupDomain(domain);
  }
});

test("a malformed candidate (bad shape) is refused with a warning, never persisted", () => {
  const domain = uniqueDomain();
  try {
    const result = registerMechanismCandidates({
      target_domain: domain,
      candidates: [sampleCandidate({ interventions: [] })],
    });
    assert.equal(result.registered_count, 0);
    assert.ok(result.warnings.length >= 1, "shape violation produces a warning");
    assert.equal(readMechanismCandidates(domain).length, 0, "malformed candidate is not persisted");
  } finally {
    cleanupDomain(domain);
  }
});

test("mechanism-candidates.jsonl is MCP-write-only (blocked for agent Write) but NOT audit-graded", () => {
  const domain = uniqueDomain();
  const ledger = mechanismCandidatesJsonlPath(domain);
  const basename = "mechanism-candidates.jsonl";
  // It is advisory, not a hash-bound verdict ledger.
  assert.equal(isAuditGradedPath(ledger, domain), false, "candidate registry is not audit-graded");
  assert.equal(
    WRITE_GUARD_TABLES.audit_graded_basenames.includes(basename),
    false,
    "candidate registry basename is not in the audit-graded BLOCK set",
  );
  // An agent Write to it is blocked by the MCP-owned write-guard class: only the
  // MCP tool may write the registry.
  assert.equal(
    WRITE_GUARD_TABLES.mcp_owned_basenames.includes(basename),
    true,
    "candidate registry basename is MCP-owned (agent Write blocked)",
  );
  assert.equal(
    WRITE_GUARD_TABLES.agent_writable_basenames.includes(basename),
    false,
    "candidate registry basename is not agent-writable",
  );
});

test("the include_authz_family lift registers the family as tier-3 candidates", () => {
  const domain = uniqueDomain();
  try {
    const tool = registerTool();
    const result = tool.handler({ target_domain: domain, include_authz_family: true });
    assert.ok(result.registered_count >= 5, "the five authz family members register");
    const stored = readMechanismCandidates(domain);
    const objectAuth = stored.find((record) => record.id === "object_authorization");
    assert.ok(objectAuth, "the object-auth lift is registered");
    assert.equal(objectAuth.tier, 3, "the lifted object-auth is tier-3 advisory, not confirmed");
    assert.equal(objectAuth.claim_authority, false);
  } finally {
    cleanupDomain(domain);
  }
});
