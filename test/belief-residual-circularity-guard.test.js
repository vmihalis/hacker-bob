"use strict";

// Circularity guard on the residual -> scheduler edge.
//
// A residual is built by SAMPLING the belief window's own marginals
// (buildFactorGraphSample/inferMarginals), so on its own it is self-generated
// belief. The ONLY outcomes allowed to move dispatch ORDER are EXECUTED ones, so the
// scheduler admits a residual hint solely when its provenance chain traces to an
// executed outcome — a verified_intervention signal, a realized dead-end, or a
// realized-vs-predicted coverage delta — cited via {kind, artifact_ref} in the
// residual_anomaly payload. A residual built purely from self-sampling (no executed
// citation) is recorded as a diagnostic but is NOT admitted: it cannot boost any
// candidate's scheduler score. NON-GATING throughout: this changes ORDER only.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendEdges } = require("../mcp/lib/surface-graph.js");
const { sessionDir } = require("../mcp/lib/paths.js");
const { runBeliefResidual } = require("../mcp/lib/belief/residual.js");
const { queryBeliefSignals } = require("../mcp/lib/belief/authority.js");
const { buildBeliefSchedulerHints } = require("../mcp/lib/belief/scheduler-priority.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-residual-circularity-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function seedGraph(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  appendEdges({
    target_domain: domain,
    edges: [
      {
        source: { type: "principal", id: "principal:attacker" },
        target: { type: "policy_gate", id: "policy_gate:owner" },
        edge_type: "tests_gate",
      },
      {
        source: { type: "policy_gate", id: "policy_gate:owner" },
        target: { type: "effect", id: "effect:unauth_succeeds_where_auth_blocked:victim" },
        edge_type: "permits_effect",
      },
    ],
  });
}

// A surface whose tokens overlap the object_authorization candidate's scope so
// buildBeliefSchedulerHints emits a hint for it.
function matchingSurface(domain) {
  return {
    id: "surface:idor-victim",
    title: "victim object access",
    hosts: [domain],
    bug_class_hints: ["unauth_succeeds_where_auth_blocked"],
    high_value_flows: ["attacker reads owner victim object"],
  };
}

test("a self-sampled-only residual is recorded but NOT scheduler-admissible (no executed citation)", () => {
  withTempHome(() => {
    const domain = "f1b-self-sampled.example.com";
    seedGraph(domain);

    const diag = runBeliefResidual({ target_domain: domain, seed: "self", sample_count: 512 });
    // The residual still exists as a diagnostic / human-router record...
    const signals = queryBeliefSignals({
      target_domain: domain,
      provenance: "residual_anomaly",
      role: "diagnostic",
    }).signals;
    assert.equal(signals.length, 1);
    const payload = signals[0].payload;
    // ...but it cites NO executed outcome and is marked inadmissible.
    assert.deepEqual([...payload.executed_provenance], []);
    assert.equal(payload.scheduler_admissible, false);
    assert.equal(payload.priority_hint.scheduler_admissible, false);
    assert.ok(diag.residual_score >= 0);
  });
});

test("an executed-outcome citation makes the SAME residual scheduler-admissible", () => {
  withTempHome(() => {
    const domain = "f1b-executed.example.com";
    seedGraph(domain);

    runBeliefResidual({
      target_domain: domain,
      seed: "executed",
      sample_count: 512,
      executed_provenance: [
        { kind: "verified_intervention", artifact_ref: "composition_verified:abc123" },
        { kind: "dead_end", artifact_ref: "frontier_event:de-1" },
      ],
    });
    const payload = queryBeliefSignals({
      target_domain: domain,
      provenance: "residual_anomaly",
      role: "diagnostic",
    }).signals[0].payload;
    assert.equal(payload.scheduler_admissible, true);
    assert.equal(payload.priority_hint.scheduler_admissible, true);
    assert.deepEqual(
      payload.executed_provenance.map((e) => e.kind).sort(),
      ["dead_end", "verified_intervention"],
    );
  });
});

test("a residual moves scheduler ORDER only when it cites an executed outcome", () => {
  // Two byte-identical setups; the only difference is whether the residual cites an
  // executed outcome. The executed-cited residual boosts the candidate's scheduler
  // score; the self-sampled-only one does not. NON-GATING: this is a score (ORDER),
  // never a verdict/closure/claim.
  let selfSampledScore;
  let executedScore;

  withTempHome(() => {
    const domain = "f1b-no-boost.example.com";
    seedGraph(domain);
    runBeliefResidual({ target_domain: domain, seed: "order", sample_count: 512 });
    const hints = buildBeliefSchedulerHints({
      target_domain: domain,
      surfaces: [matchingSurface(domain)],
      seed: "belief-scheduler-priority",
    });
    assert.equal(hints.applied, true, "candidate matched the surface");
    selfSampledScore = hints.hints[0].score;
    // The admitted residual hint is null -> the replay record shows no residual fed.
    assert.equal(hints.residual_hash, null);
  });

  withTempHome(() => {
    const domain = "f1b-boost.example.com";
    seedGraph(domain);
    runBeliefResidual({
      target_domain: domain,
      seed: "order",
      sample_count: 512,
      executed_provenance: [
        { kind: "coverage_delta", artifact_ref: "coverage:realized-vs-predicted:w2" },
      ],
    });
    const hints = buildBeliefSchedulerHints({
      target_domain: domain,
      surfaces: [matchingSurface(domain)],
      seed: "belief-scheduler-priority",
    });
    assert.equal(hints.applied, true, "candidate matched the surface");
    executedScore = hints.hints[0].score;
    assert.ok(hints.residual_hash, "executed-cited residual is admitted and recorded");
  });

  assert.ok(
    executedScore > selfSampledScore,
    `executed-cited residual must boost order (got executed=${executedScore} self=${selfSampledScore})`,
  );
});

test("a malformed executed_provenance entry is dropped (honest validation, no admission)", () => {
  withTempHome(() => {
    const domain = "f1b-malformed.example.com";
    seedGraph(domain);
    runBeliefResidual({
      target_domain: domain,
      seed: "malformed",
      sample_count: 256,
      executed_provenance: [
        { kind: "not_a_real_kind", artifact_ref: "x" },
        { kind: "verified_intervention", artifact_ref: "" },
        { kind: "verified_intervention" },
      ],
    });
    const payload = queryBeliefSignals({
      target_domain: domain,
      provenance: "residual_anomaly",
      role: "diagnostic",
    }).signals[0].payload;
    assert.deepEqual([...payload.executed_provenance], []);
    assert.equal(payload.scheduler_admissible, false);
  });
});
