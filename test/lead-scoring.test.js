"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  normalizePromotionOptions,
  scoreStaticLeadWithReachability,
  shouldPromoteLead,
} = require("../mcp/lib/lead-scoring.js");

function baseStaticLead(overrides = {}) {
  return {
    title: "cpp.unbounded-copy",
    source: "bob_static_scan",
    hosts: [],
    endpoints: ["src/server.c:42"],
    interesting_params: [],
    nuclei_hits: [],
    bug_class_hints: ["validate_vs_consume"],
    evidence: ["src/server.c:42 - length reaches copy before bounds check"],
    surface_type: "oss_static_sink",
    status: "new",
    promote: false,
    ...overrides,
  };
}

test("scoreStaticLeadWithReachability boosts AV:N static leads over the min_score gate", () => {
  const scored = scoreStaticLeadWithReachability(baseStaticLead(), {
    attack_vector: "network",
    network_reachable: true,
    severity_ceiling: "critical",
  });
  const { minScore } = normalizePromotionOptions({});

  assert.ok(scored.score >= minScore);
  assert.ok(scored.score >= 70);
  assert.equal(scored.confidence, "high");
  assert.equal(shouldPromoteLead(scored, { minScore, includeMedium: false }), true);
});

test("scoreStaticLeadWithReachability caps AV:L leads at medium with rationale", () => {
  const scored = scoreStaticLeadWithReachability(baseStaticLead({ rationale: "" }), {
    attack_vector: "local",
    network_reachable: false,
    severity_ceiling: "medium",
  });
  const { minScore } = normalizePromotionOptions({});

  assert.ok(scored.score > 0);
  assert.ok(scored.score < minScore);
  assert.equal(scored.confidence, "medium");
  assert.match(scored.rationale, /capped but retained/);
  assert.equal(shouldPromoteLead(scored, { minScore, includeMedium: false }), false);
});

test("scoreStaticLeadWithReachability never drops unreachable static hypotheses", () => {
  const scored = scoreStaticLeadWithReachability(baseStaticLead(), {
    attack_vector: "network",
    network_reachable: false,
    severity_ceiling: "critical",
  });

  assert.ok(scored);
  assert.deepEqual(scored.endpoints, ["src/server.c:42"]);
  assert.ok(scored.score > 0);
  assert.equal(scored.confidence, "medium");
  assert.ok(scored.rationale.length > 0);
});
