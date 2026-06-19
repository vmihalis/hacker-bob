"use strict";

// Cycle Y.6 — bob_propose_friction_promotion integration test.
//
// Asserts:
//   * Y-P6 — pack widening request lands BEFORE bob_attach_contract by
//     threading friction_history + add_tools into suggested_contract on
//     the hypothesis_proposed observation.
//   * Y-P11 — tool_inadequate frictions are quarantined; the caller MUST
//     opt in via include_inadequacy: true.
//   * tool_absent + tool_inadequate groups do NOT merge (separate
//     promotions).
//   * Promotion below the operator-configurable threshold returns
//     promoted: false with reason: below_threshold and DOES NOT append a
//     hypothesis_proposed event.
//   * A second promotion call for the SAME group_key and the same set of
//     friction event_ids short-circuits with idempotent: true.
//   * A new friction added to the group AFTER a prior promotion is
//     allowed to re-promote (the prior set no longer covers all current
//     frictions).
//   * The tool is orchestrator-only (Y-P8 single-spawner topology
//     preserved).
//   * The tool name is registered in the tool registry under
//     bob_propose_friction_promotion.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const proposeFrictionPromotionTool = require("../mcp/lib/tools/propose-friction-promotion.js");
const logCapabilityFrictionTool = require("../mcp/lib/tools/log-capability-friction.js");
const {
  appendFrontierEvent,
  readFrontierEvents,
  FRONTIER_EVENT_KINDS,
} = require("../mcp/lib/frontier-events.js");
const {
  writeQueuePolicy,
} = require("../mcp/lib/queue-policy.js");
const {
  sessionDir,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-y6-promotion-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function ensureSessionDir(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
}

function logAbsentFriction(domain, overrides = {}) {
  return JSON.parse(logCapabilityFrictionTool.handler({
    target_domain: domain,
    run_id: "run-A",
    node_id: "N-1",
    wanted_tool: "bob_http_scan",
    purpose: "http_probe",
    fallback_used: "bash_curl",
    friction_kind: "tool_absent",
    detected_by: "agent_self_report",
    rationale: "Pack omitted bob_http_scan; reached for curl as fallback.",
    surface_id: "surface:billing-admin",
    ...overrides,
  }));
}

function seedInadequateWitness(domain, runId, tool) {
  // Y-P10 requires a real frontier_event:<id> witness for tool_inadequate.
  // We seed an observation.recorded event whose payload.tool matches the
  // wanted_tool so the log-capability-friction tool's witness validator
  // accepts it.
  const witness = appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    payload: {
      observation_kind: "mcp_invocation_recorded",
      run_id: runId,
      tool,
      outcome: "error",
      summary: "seeded inadequate-witness invocation",
    },
    source: {
      artifact: "frontier-events.jsonl",
      tool: "test-seed",
    },
  });
  return witness;
}

function logInadequateFriction(domain, overrides = {}) {
  const witnessRef = overrides.witness_event_id
    ? `frontier_event:${overrides.witness_event_id}`
    : null;
  return JSON.parse(logCapabilityFrictionTool.handler({
    target_domain: domain,
    run_id: "run-A",
    node_id: "N-1",
    wanted_tool: "bob_http_scan",
    purpose: "http_probe",
    fallback_used: "bash_curl",
    friction_kind: "tool_inadequate",
    inadequacy_mode: "body_truncated",
    inadequate_invocation_ref: witnessRef,
    detected_by: "agent_self_report",
    rationale: "bob_http_scan truncated a 300KB body; needed full bytes for parsing.",
    surface_id: "surface:billing-admin",
    ...overrides,
  }));
}

function readHypothesisProposals(domain) {
  return readFrontierEvents(domain).filter(
    (e) => e
      && e.kind === "observation.recorded"
      && e.payload
      && e.payload.kind === "hypothesis_proposed",
  );
}

// ── tool registration ───────────────────────────────────────────────────────

test("bob_propose_friction_promotion is orchestrator-only (Y-P8 single-spawner)", () => {
  assert.equal(proposeFrictionPromotionTool.name, "bob_propose_friction_promotion");
  assert.deepEqual(
    proposeFrictionPromotionTool.role_bundles,
    ["orchestrator"],
    "promotion must be orchestrator-only",
  );
  assert.deepEqual(
    proposeFrictionPromotionTool.session_artifacts_written,
    ["frontier-events.jsonl"],
  );
});

test("the tool rides observation.recorded — no new top-level FRONTIER_EVENT_KIND", () => {
  // The proposal appends hypothesis_proposed which is itself a payload
  // shape on observation.recorded; this guard re-asserts X-P8 / Y-P1.
  assert.ok(FRONTIER_EVENT_KINDS.includes("observation.recorded"));
  assert.equal(FRONTIER_EVENT_KINDS.includes("friction_promotion"), false);
});

// ── threshold gate ──────────────────────────────────────────────────────────

test("below-threshold promotion returns promoted: false WITHOUT appending a Hypothesis", () => {
  withTempHome(() => {
    const domain = "below-threshold.example.com";
    ensureSessionDir(domain);

    // One friction recorded — below default threshold of 2.
    logAbsentFriction(domain);

    const response = JSON.parse(proposeFrictionPromotionTool.handler({
      target_domain: domain,
      wanted_tool: "bob_http_scan",
      friction_kind: "tool_absent",
      surface_id: "surface:billing-admin",
    }));
    assert.equal(response.promoted, false);
    assert.equal(response.reason, "below_threshold");
    assert.equal(response.friction_count, 1);
    assert.equal(response.min_frictions, 2);

    assert.equal(readHypothesisProposals(domain).length, 0);
  });
});

test("at-threshold promotion APPENDS a Hypothesis with friction_history + pack_widening_request (Y-P6)", () => {
  withTempHome(() => {
    const domain = "promote-success.example.com";
    ensureSessionDir(domain);

    // Two frictions for the same group (different run_id keeps Y-P3
    // idempotency from collapsing them).
    logAbsentFriction(domain, { run_id: "run-A" });
    logAbsentFriction(domain, { run_id: "run-B" });

    const response = JSON.parse(proposeFrictionPromotionTool.handler({
      target_domain: domain,
      wanted_tool: "bob_http_scan",
      friction_kind: "tool_absent",
      surface_id: "surface:billing-admin",
    }));
    assert.equal(response.promoted, true);
    assert.equal(response.idempotent, false);
    assert.equal(response.friction_count, 2);
    assert.deepEqual(response.surface_refs, ["surface:billing-admin"]);
    assert.equal(typeof response.event_id, "string");

    const proposals = readHypothesisProposals(domain);
    assert.equal(proposals.length, 1);
    const proposal = proposals[0];
    assert.equal(proposal.payload.kind, "hypothesis_proposed");
    assert.deepEqual(proposal.payload.surface_refs, ["surface:billing-admin"]);
    assert.ok(proposal.payload.suggested_contract);
    assert.ok(proposal.payload.suggested_contract.promotion_marker);
    assert.equal(
      proposal.payload.suggested_contract.promotion_marker.kind,
      "friction_promotion",
    );
    assert.equal(
      proposal.payload.suggested_contract.promotion_marker.wanted_tool,
      "bob_http_scan",
    );
    assert.equal(
      proposal.payload.suggested_contract.promotion_marker.friction_kind,
      "tool_absent",
    );
    // Y-P6: pack_widening_request lands in suggested_contract BEFORE
    // bob_attach_contract runs. The downstream attach-contract reads
    // suggested_contract and can union add_tools[] into
    // allowed_tools_for_node[] before the satisfiability gate fires.
    assert.deepEqual(
      proposal.payload.suggested_contract.pack_widening_request.add_tools,
      ["bob_http_scan"],
    );
    assert.equal(proposal.payload.suggested_contract.friction_history.length, 2);
    for (const entry of proposal.payload.suggested_contract.friction_history) {
      assert.equal(entry.wanted_tool, "bob_http_scan");
      assert.equal(entry.friction_kind, "tool_absent");
      assert.equal(entry.surface_id, "surface:billing-admin");
    }
  });
});

// ── Y-P11 inadequacy quarantine ────────────────────────────────────────────

test("tool_inadequate is QUARANTINED by default (Y-P11) — must pass include_inadequacy: true", () => {
  withTempHome(() => {
    const domain = "inadequate-quarantine.example.com";
    ensureSessionDir(domain);
    // Seed witnesses + log two tool_inadequate frictions.
    const w1 = seedInadequateWitness(domain, "run-A", "bob_http_scan");
    const w2 = seedInadequateWitness(domain, "run-B", "bob_http_scan");
    logInadequateFriction(domain, { run_id: "run-A", witness_event_id: w1.event_id });
    logInadequateFriction(domain, { run_id: "run-B", witness_event_id: w2.event_id });

    // Default invocation REFUSES because include_inadequacy is not set.
    assert.throws(
      () => proposeFrictionPromotionTool.handler({
        target_domain: domain,
        wanted_tool: "bob_http_scan",
        friction_kind: "tool_inadequate",
        surface_id: "surface:billing-admin",
      }),
      /quarantined from auto-promotion/,
    );
    assert.equal(readHypothesisProposals(domain).length, 0);

    // Opt-in succeeds.
    const response = JSON.parse(proposeFrictionPromotionTool.handler({
      target_domain: domain,
      wanted_tool: "bob_http_scan",
      friction_kind: "tool_inadequate",
      surface_id: "surface:billing-admin",
      include_inadequacy: true,
    }));
    assert.equal(response.promoted, true);
    assert.equal(response.friction_count, 2);

    const proposals = readHypothesisProposals(domain);
    assert.equal(proposals.length, 1);
    assert.equal(
      proposals[0].payload.suggested_contract.promotion_marker.friction_kind,
      "tool_inadequate",
    );
  });
});

// ── grouping discipline ─────────────────────────────────────────────────────

test("tool_absent and tool_inadequate groups do NOT merge (separate promotions per kind)", () => {
  withTempHome(() => {
    const domain = "no-merge.example.com";
    ensureSessionDir(domain);

    // Two tool_absent + two tool_inadequate frictions for the same wanted_tool
    // + surface_id. Each kind must promote independently.
    logAbsentFriction(domain, { run_id: "run-A" });
    logAbsentFriction(domain, { run_id: "run-B" });
    const w1 = seedInadequateWitness(domain, "run-C", "bob_http_scan");
    const w2 = seedInadequateWitness(domain, "run-D", "bob_http_scan");
    logInadequateFriction(domain, { run_id: "run-C", witness_event_id: w1.event_id });
    logInadequateFriction(domain, { run_id: "run-D", witness_event_id: w2.event_id });

    const absentResponse = JSON.parse(proposeFrictionPromotionTool.handler({
      target_domain: domain,
      wanted_tool: "bob_http_scan",
      friction_kind: "tool_absent",
      surface_id: "surface:billing-admin",
    }));
    assert.equal(absentResponse.promoted, true);
    assert.equal(absentResponse.friction_count, 2);

    const inadequateResponse = JSON.parse(proposeFrictionPromotionTool.handler({
      target_domain: domain,
      wanted_tool: "bob_http_scan",
      friction_kind: "tool_inadequate",
      surface_id: "surface:billing-admin",
      include_inadequacy: true,
    }));
    assert.equal(inadequateResponse.promoted, true);
    assert.equal(inadequateResponse.friction_count, 2);

    const proposals = readHypothesisProposals(domain);
    assert.equal(proposals.length, 2, "two independent Hypothesis proposals");
    const kinds = proposals.map(
      (e) => e.payload.suggested_contract.promotion_marker.friction_kind,
    );
    assert.deepEqual(kinds.sort(), ["tool_absent", "tool_inadequate"]);
  });
});

// ── idempotency ─────────────────────────────────────────────────────────────

test("second promotion call with the SAME covered friction event_ids returns idempotent: true", () => {
  withTempHome(() => {
    const domain = "promote-idempotent.example.com";
    ensureSessionDir(domain);

    logAbsentFriction(domain, { run_id: "run-A" });
    logAbsentFriction(domain, { run_id: "run-B" });

    const first = JSON.parse(proposeFrictionPromotionTool.handler({
      target_domain: domain,
      wanted_tool: "bob_http_scan",
      friction_kind: "tool_absent",
      surface_id: "surface:billing-admin",
    }));
    assert.equal(first.promoted, true);

    const second = JSON.parse(proposeFrictionPromotionTool.handler({
      target_domain: domain,
      wanted_tool: "bob_http_scan",
      friction_kind: "tool_absent",
      surface_id: "surface:billing-admin",
    }));
    assert.equal(second.promoted, false);
    assert.equal(second.idempotent, true);
    assert.equal(second.reason, "already_promoted");
    assert.equal(second.prior_event_id, first.event_id);

    // Only ONE Hypothesis lands.
    assert.equal(readHypothesisProposals(domain).length, 1);
  });
});

test("findPriorPromotion returns the LATEST prior — 3+ sequential identical calls stay idempotent", () => {
  // Regression for the Y.6 brutalist defect: a first-match iteration of
  // `findPriorPromotion` returned the oldest promotion whose covered
  // friction_event_ids set was a strict subset of the later (extended)
  // promotion, so a 3rd or 4th identical call would re-promote because the
  // oldest cover-set check returned `allCovered: false`. Reverse-iteration
  // (latest-wins) keeps the Y-P6 idempotency contract under repeated calls.
  withTempHome(() => {
    const domain = "promote-3plus-idempotent.example.com";
    ensureSessionDir(domain);

    logAbsentFriction(domain, { run_id: "run-A" });
    logAbsentFriction(domain, { run_id: "run-B" });

    const first = JSON.parse(proposeFrictionPromotionTool.handler({
      target_domain: domain,
      wanted_tool: "bob_http_scan",
      friction_kind: "tool_absent",
      surface_id: "surface:billing-admin",
    }));
    assert.equal(first.promoted, true);

    // Add a third friction; this WIDENS the group beyond the first
    // promotion's cover set, so the 2nd call legitimately re-promotes.
    logAbsentFriction(domain, { run_id: "run-C" });
    const second = JSON.parse(proposeFrictionPromotionTool.handler({
      target_domain: domain,
      wanted_tool: "bob_http_scan",
      friction_kind: "tool_absent",
      surface_id: "surface:billing-admin",
    }));
    assert.equal(second.promoted, true);

    // 3rd call with NO new frictions MUST be idempotent against the LATEST
    // (2nd) promotion — which covers all 3 frictions. A first-match scan
    // would compare against the FIRST promotion (covers 2/3) and incorrectly
    // re-promote.
    const third = JSON.parse(proposeFrictionPromotionTool.handler({
      target_domain: domain,
      wanted_tool: "bob_http_scan",
      friction_kind: "tool_absent",
      surface_id: "surface:billing-admin",
    }));
    assert.equal(third.promoted, false);
    assert.equal(third.idempotent, true);
    assert.equal(third.prior_event_id, second.event_id);

    // 4th call (still no new frictions) stays idempotent.
    const fourth = JSON.parse(proposeFrictionPromotionTool.handler({
      target_domain: domain,
      wanted_tool: "bob_http_scan",
      friction_kind: "tool_absent",
      surface_id: "surface:billing-admin",
    }));
    assert.equal(fourth.promoted, false);
    assert.equal(fourth.idempotent, true);
    assert.equal(fourth.prior_event_id, second.event_id);

    // Only the two genuine promotions landed.
    assert.equal(readHypothesisProposals(domain).length, 2);
  });
});

test("a new friction extending the group AFTER a prior promotion allows a fresh promotion", () => {
  withTempHome(() => {
    const domain = "promote-extend.example.com";
    ensureSessionDir(domain);

    logAbsentFriction(domain, { run_id: "run-A" });
    logAbsentFriction(domain, { run_id: "run-B" });

    const first = JSON.parse(proposeFrictionPromotionTool.handler({
      target_domain: domain,
      wanted_tool: "bob_http_scan",
      friction_kind: "tool_absent",
      surface_id: "surface:billing-admin",
    }));
    assert.equal(first.promoted, true);

    // A third friction extends the group BEYOND the prior promotion's
    // covered set; the next call promotes again.
    logAbsentFriction(domain, { run_id: "run-C" });

    const second = JSON.parse(proposeFrictionPromotionTool.handler({
      target_domain: domain,
      wanted_tool: "bob_http_scan",
      friction_kind: "tool_absent",
      surface_id: "surface:billing-admin",
    }));
    assert.equal(second.promoted, true);
    assert.equal(second.friction_count, 3);
    assert.notEqual(second.event_id, first.event_id);

    assert.equal(readHypothesisProposals(domain).length, 2);
  });
});

// ── operator-tunable threshold ─────────────────────────────────────────────

test("queue-policy.friction_promotion_threshold drives the default min_frictions", () => {
  withTempHome(() => {
    const domain = "policy-threshold.example.com";
    ensureSessionDir(domain);
    // Raise the threshold to 3.
    writeQueuePolicy(domain, { friction_promotion_threshold: 3 });

    logAbsentFriction(domain, { run_id: "run-A" });
    logAbsentFriction(domain, { run_id: "run-B" });

    const below = JSON.parse(proposeFrictionPromotionTool.handler({
      target_domain: domain,
      wanted_tool: "bob_http_scan",
      friction_kind: "tool_absent",
      surface_id: "surface:billing-admin",
    }));
    assert.equal(below.promoted, false);
    assert.equal(below.min_frictions, 3);
    assert.equal(readHypothesisProposals(domain).length, 0);

    logAbsentFriction(domain, { run_id: "run-C" });
    const at = JSON.parse(proposeFrictionPromotionTool.handler({
      target_domain: domain,
      wanted_tool: "bob_http_scan",
      friction_kind: "tool_absent",
      surface_id: "surface:billing-admin",
    }));
    assert.equal(at.promoted, true);
    assert.equal(at.friction_count, 3);
  });
});

test("min_frictions on the call overrides the queue-policy default", () => {
  withTempHome(() => {
    const domain = "min-override.example.com";
    ensureSessionDir(domain);
    // Default policy = 2.
    logAbsentFriction(domain, { run_id: "run-A" });

    // Per-call min_frictions: 1 → 1 friction is enough.
    const response = JSON.parse(proposeFrictionPromotionTool.handler({
      target_domain: domain,
      wanted_tool: "bob_http_scan",
      friction_kind: "tool_absent",
      surface_id: "surface:billing-admin",
      min_frictions: 1,
    }));
    assert.equal(response.promoted, true);
    assert.equal(response.friction_count, 1);
  });
});

// ── queue-policy schema ─────────────────────────────────────────────────────

test("queue-policy normalizes friction_promotion_threshold + target_class_default + lead_rationale_required_when_below_threshold", () => {
  withTempHome(() => {
    const domain = "policy-shape.example.com";
    ensureSessionDir(domain);
    writeQueuePolicy(domain, {
      friction_promotion_threshold: 5,
      target_class_default: "smart_contract",
      lead_rationale_required_when_below_threshold: true,
      subdomain_enum_circuit_breaker_threshold: 100,
    });
    // Read back via loadQueuePolicy.
    // eslint-disable-next-line global-require
    const { loadQueuePolicy } = require("../mcp/lib/queue-policy.js");
    const policy = loadQueuePolicy(domain);
    assert.equal(policy.friction_promotion_threshold, 5);
    assert.equal(policy.target_class_default, "smart_contract");
    assert.equal(policy.lead_rationale_required_when_below_threshold, true);
    assert.equal(policy.subdomain_enum_circuit_breaker_threshold, 100);
  });
});

test("queue-policy rejects unknown target_class_default values", () => {
  withTempHome(() => {
    const domain = "policy-bad-target-class.example.com";
    ensureSessionDir(domain);
    assert.throws(
      () => writeQueuePolicy(domain, {
        target_class_default: "not_a_real_class",
      }),
      /target_class_default/,
    );
  });
});
