"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  ELICITATION_PROVENANCE,
  ELICITATION_ROLE,
  normalizeElicitation,
  evidenceSensitivity,
} = require("../mcp/lib/belief/elicitation.js");
const elicitBeliefTool = require("../mcp/lib/tools/elicit-belief.js");
const { queryBeliefSignals } = require("../mcp/lib/belief/authority.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-belief-elicit-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function elicitation(distribution, latentId = "effective_permission:attacker->victim_obj") {
  return normalizeElicitation({
    latent_id: latentId,
    latent_type: "effective_permission",
    states: ["allowed", "blocked", "unknown"],
    distribution,
    evidence_refs: ["http-audit:req-7", "schema-contracts:GET /orders/{id}"],
    rationale: "auth-differential shows unauth blocked but attacker-auth reaches the victim order id",
  });
}

test("normalizeElicitation validates a distribution over declared states and forces advisory provenance", () => {
  const e = elicitation({ allowed: 0.7, blocked: 0.2, unknown: 0.1 });
  assert.equal(e.provenance, ELICITATION_PROVENANCE); // llm_inferred
  assert.equal(e.role, ELICITATION_ROLE); // prior
  assert.equal(e.advisory, true);
  assert.ok(e.elicitation_hash);
});

test("rejects malformed distributions", () => {
  assert.throws(() => elicitation({ allowed: 0.7, blocked: 0.2 }), /exactly the declared states/); // missing 'unknown'
  assert.throws(() => elicitation({ allowed: 0.6, blocked: 0.2, unknown: 0.1 }), /sum to 1/);
  assert.throws(() => elicitation({ allowed: 1.2, blocked: -0.3, unknown: 0.1 }), /probability in \[0,1\]/);
  assert.throws(
    () => normalizeElicitation({
      latent_id: "x", latent_type: "effective_permission",
      states: ["allowed", "blocked", "unknown"],
      distribution: { allowed: 0.7, blocked: 0.2, unknown: 0.1 },
      evidence_refs: [], // must cite evidence
      rationale: "r",
    }),
    /evidence_refs is required/,
  );
});

test("deterministic: same elicitation reproduces the same hash", () => {
  assert.equal(
    elicitation({ allowed: 0.7, blocked: 0.2, unknown: 0.1 }).elicitation_hash,
    elicitation({ allowed: 0.7, blocked: 0.2, unknown: 0.1 }).elicitation_hash,
  );
});

// THE GATE. The belief MUST move on relevant evidence and stay flat on irrelevant.
test("evidence-sensitivity gate: relevant evidence change that shifts the belief PASSES", () => {
  const before = elicitation({ allowed: 0.7, blocked: 0.2, unknown: 0.1 });
  const after = elicitation({ allowed: 0.2, blocked: 0.7, unknown: 0.1 }); // auth now blocks
  const v = evidenceSensitivity({ before, after, relevant: true, expected_shift_state: "blocked" });
  assert.equal(v.pass, true);
  assert.equal(v.moved, true);
  assert.equal(v.toward_expected, true);
});

test("evidence-sensitivity gate: relevant evidence that leaves the belief FLAT fails (the regex-with-a-model_id failure)", () => {
  const before = elicitation({ allowed: 0.7, blocked: 0.2, unknown: 0.1 });
  const after = elicitation({ allowed: 0.71, blocked: 0.19, unknown: 0.1 }); // barely moved
  const v = evidenceSensitivity({ before, after, relevant: true, expected_shift_state: "blocked" });
  assert.equal(v.pass, false);
  assert.equal(v.moved, false);
});

test("evidence-sensitivity gate: irrelevant change that stays flat PASSES", () => {
  const before = elicitation({ allowed: 0.7, blocked: 0.2, unknown: 0.1 });
  const after = elicitation({ allowed: 0.7, blocked: 0.2, unknown: 0.1 });
  const v = evidenceSensitivity({ before, after, relevant: false });
  assert.equal(v.pass, true);
});

test("evidence-sensitivity gate: irrelevant change that MOVES the belief fails (agent pattern-matched the shell)", () => {
  const before = elicitation({ allowed: 0.7, blocked: 0.2, unknown: 0.1 });
  const after = elicitation({ allowed: 0.2, blocked: 0.7, unknown: 0.1 });
  const v = evidenceSensitivity({ before, after, relevant: false });
  assert.equal(v.pass, false);
  assert.equal(v.moved, true);
});

test("bob_elicit_belief records an elicited belief as advisory llm_inferred/prior scratch", () => {
  withTempHome(() => {
    const domain = "belief.example";
    const out = elicitBeliefTool.handler({
      target_domain: domain,
      latent_id: "effective_permission:attacker->victim_obj",
      latent_type: "effective_permission",
      states: ["allowed", "blocked", "unknown"],
      distribution: { allowed: 0.7, blocked: 0.2, unknown: 0.1 },
      evidence_refs: ["http-audit:req-7"],
      rationale: "attacker-auth reaches the victim order id; unauth blocked",
    });
    assert.equal(out.provenance, "llm_inferred");
    assert.equal(out.role, "prior");
    assert.ok(out.elicitation_hash && out.signal_hash);

    const queried = queryBeliefSignals({ target_domain: domain, provenance: "llm_inferred", role: "prior" });
    assert.equal(queried.signals.length, 1);
    assert.equal(queried.signals[0].payload.latent_id, "effective_permission:attacker->victim_obj");

    // tool inherits the lib's validation: a malformed distribution is refused
    assert.throws(() => elicitBeliefTool.handler({
      target_domain: domain,
      latent_id: "x", latent_type: "effective_permission",
      states: ["allowed", "blocked", "unknown"],
      distribution: { allowed: 0.9, blocked: 0.2, unknown: 0.1 },
      evidence_refs: ["http-audit:req-9"],
      rationale: "bad",
    }), /sum to 1/);
  });
});

// Tool is a mutating scratch-only, non-networked registry entry.
test("bob_elicit_belief is mutating scratch-only with no network", () => {
  assert.equal(elicitBeliefTool.name, "bob_elicit_belief");
  assert.equal(elicitBeliefTool.mutating, true);
  assert.equal(elicitBeliefTool.network_access, false);
  assert.deepEqual(elicitBeliefTool.session_artifacts_written, ["belief-scratch/belief-signals.jsonl"]);
});
