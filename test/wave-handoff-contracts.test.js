"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  HANDOFF_PROVENANCE_MODEL,
  signHandoffProvenance,
  validateHandoffProvenance,
  normalizeDiscoveredPivots,
  normalizeSpawnedChildren,
} = require("../mcp/lib/wave-handoff-contracts.js");
const { FANOUT_ROLE_REGISTRY } = require("../mcp/lib/nested-spawn.js");

test("B5: normalizeDiscoveredPivots accepts bounded pivot entries and rejects malformed ones", () => {
  assert.deepEqual(normalizeDiscoveredPivots(undefined), [], "absent => empty");
  assert.deepEqual(normalizeDiscoveredPivots([]), []);
  const ok = normalizeDiscoveredPivots([
    { from_surface: "surface:api", to_surface: "surface:ledger", kind: "value_movement", trust_assumption: "api value trusted on ledger", evidence_refs: ["F-1"] },
  ]);
  assert.equal(ok.length, 1);
  assert.equal(ok[0].to_surface, "surface:ledger");
  assert.deepEqual(ok[0].evidence_refs, ["F-1"]);
  assert.throws(() => normalizeDiscoveredPivots([{ from_surface: "a", to_surface: "b", kind: "k" }]), /trust_assumption is required/);
  const many = Array.from({ length: 21 }, () => ({ from_surface: "a", to_surface: "b", kind: "k", trust_assumption: "t" }));
  assert.throws(() => normalizeDiscoveredPivots(many), /at most 20/);
  assert.throws(() => normalizeDiscoveredPivots("nope"), /must be an array/);
});

test("B6: normalizeSpawnedChildren bounds the self-report; validateSpawnFanout is the detective cross-check", () => {
  const { validateSpawnFanout } = require("../mcp/lib/nested-spawn.js");
  const writeHandoffTool = require("../mcp/lib/tools/write-wave-handoff.js");
  assert.deepEqual(
    writeHandoffTool.inputSchema.properties.spawned_children.items.required,
    ["subagent_type", "cell_key"],
    "new MCP handoffs must bind every reported child to an issued cell",
  );
  assert.deepEqual(normalizeSpawnedChildren(undefined), []);
  const reported = normalizeSpawnedChildren([
    { subagent_type: FANOUT_ROLE_REGISTRY.child.subagent_type, cell_key: "k1" },
    { subagent_type: FANOUT_ROLE_REGISTRY.child.subagent_type },
  ]);
  assert.equal(reported.length, 2);
  assert.equal(reported[0].cell_key, "k1");
  assert.throws(() => normalizeSpawnedChildren([{}]), /subagent_type is required/);
  assert.throws(
    () => normalizeSpawnedChildren(Array.from({ length: 65 }, () => ({ subagent_type: FANOUT_ROLE_REGISTRY.child.subagent_type }))),
    /at most 64/,
  );
  // The orchestrator's finalize cross-check: validateSpawnFanout flags an off-allowlist
  // child type and an over-budget count on the reported children.
  const offType = validateSpawnFanout(
    [{ subagent_type: "evaluator-rogue" }],
    { remaining_depth: 1, max_children: 8, child_type_allowlist: [FANOUT_ROLE_REGISTRY.child.subagent_type] },
  );
  assert.equal(offType.ok, false);
  const overBudget = validateSpawnFanout(reported, { remaining_depth: 1, max_children: 1 });
  assert.equal(overBudget.ok, false, "2 reported children exceeds max_children 1");
});

function baseHandoff() {
  return {
    target_domain: "example.com",
    wave: "w1",
    agent: "a1",
    surface_id: "surface-a",
    surface_type: null,
    surface_status: "complete",
    provenance: "verified",
    summary: "Tested the assigned surface.",
    chain_notes: [],
    blocked_harness_runs: [],
    blocked_prereqs: [],
    bypass_attempts: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
  };
}

test("signed handoff provenance verifies without storing the raw handoff token", () => {
  const signingKey = Buffer.from("0123456789abcdef0123456789abcdef");
  const assignment = {
    agent: "a1",
    surface_id: "surface-a",
    handoff_token_required: true,
    handoff_token_sha256: "0".repeat(64),
  };

  const signed = signHandoffProvenance(baseHandoff(), signingKey, { assignment });

  assert.equal(signed.provenance, "verified");
  assert.equal(signed.provenance_model, HANDOFF_PROVENANCE_MODEL);
  assert.match(signed.provenance_assignment_hash, /^[0-9a-f]{64}$/);
  assert.equal(signed.provenance_signature.algorithm, "hmac-sha256");
  assert.doesNotMatch(JSON.stringify(signed), /plain-handoff-token/);
  assert.equal(validateHandoffProvenance(signed, assignment, { signingKey }), "verified");
});

test("signed handoff provenance is invalid after payload tampering", () => {
  const signingKey = Buffer.from("0123456789abcdef0123456789abcdef");
  const assignment = {
    agent: "a1",
    surface_id: "surface-a",
    handoff_token_required: true,
    handoff_token_sha256: "0".repeat(64),
  };
  const signed = signHandoffProvenance(baseHandoff(), signingKey, { assignment });

  assert.throws(
    () => validateHandoffProvenance({ ...signed, summary: "Different summary." }, assignment, { signingKey }),
    /signature does not match/,
  );
});

test("signed handoff provenance is bound to the current assignment hash", () => {
  const signingKey = Buffer.from("0123456789abcdef0123456789abcdef");
  const assignment = {
    agent: "a1",
    surface_id: "surface-a",
    handoff_token_required: true,
    handoff_token_sha256: "0".repeat(64),
  };
  const signed = signHandoffProvenance(baseHandoff(), signingKey, { assignment });

  assert.throws(
    () => validateHandoffProvenance(signed, { ...assignment, handoff_token_sha256: "1".repeat(64) }, { signingKey }),
    /assignment hash does not match/,
  );
});

test("tokenized assignments reject unsigned verified provenance claims", () => {
  const signingKey = Buffer.from("0123456789abcdef0123456789abcdef");
  const assignment = {
    agent: "a1",
    surface_id: "surface-a",
    handoff_token_required: true,
    handoff_token_sha256: "0".repeat(64),
  };

  assert.throws(
    () => validateHandoffProvenance(baseHandoff(), assignment, { signingKey }),
    /provenance model is missing or unsupported/,
  );
});

test("legacy assignments without token metadata are unconditionally rejected", () => {
  // v1.3.6 removed the legacy_unverified downgrade path. Assignments missing
  // handoff token metadata are refused regardless of session state, closing
  // the assignment-file-downgrade attack documented in R1-HIGH-#1.
  assert.throws(
    () => validateHandoffProvenance(baseHandoff(), {}),
    /assignment lacks token metadata.*pre-v1\.3\.5/,
  );
});
