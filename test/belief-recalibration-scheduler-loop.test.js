"use strict";

// The model loop is advisory + deterministic.
//
// The executed-label-trained isotonic recalibration map (model.js trainBeliefModel,
// recalibration.js applyRecalibration) is wired into the scheduler's per-candidate
// score so the trained model adjusts dispatch ORDER only. Invariants under test:
//   - ADVISORY / NO GATING: the model never gates a verdict/closure/claim. With no
//     model, or an identity (data-starved) map, the scheduler score is byte-identical
//     to the no-model path (modelBoost is 0).
//   - ORDER-ONLY nudge: a non-identity map monotonically re-maps the EIG proxy and
//     folds the delta back as a bounded score nudge — it can reorder, never gate.
//   - DETERMINISM / REPLAYABILITY: the wave-start hints pin model_hash + the fed-signal
//     set (belief_replay), and two runs with the same model_hash + signals produce an
//     identical order. A different model_hash is RECORDED, not silently consumed.
//   - trainBeliefModel trains on EXECUTED labels (grade verdicts / verification-round
//     outcomes), never belief.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendEdges } = require("../mcp/lib/surface-graph.js");
const { appendCandidateClaim } = require("../mcp/lib/claims.js");
const {
  beliefModelInfoPath,
  gradeArtifactPaths,
  sessionDir,
  verificationRoundPaths,
} = require("../mcp/lib/paths.js");
const { trainBeliefModel } = require("../mcp/lib/belief/model.js");
const { buildBeliefSchedulerHints } = require("../mcp/lib/belief/scheduler-priority.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-recalib-scheduler-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
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

function matchingSurface(domain) {
  return {
    id: "surface:idor-victim",
    title: "victim object access",
    hosts: [domain],
    bug_class_hints: ["unauth_succeeds_where_auth_blocked"],
    high_value_flows: ["attacker reads owner victim object"],
  };
}

// A labeled domain whose label is derived ONLY from executed outcomes (verification
// round disposition + grade verdict/score), so the trainer's labels are executed.
function seedLabeledDomain({ domain, findingId, label }) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  appendCandidateClaim({
    target_domain: domain,
    claim_id: `claim-${findingId}`,
    title: `Claim ${findingId}`,
    summary: `Sanitized summary ${findingId}`,
    severity: label === 1 ? "high" : "low",
    evidence_refs: [{ kind: "finding", finding_id: findingId }],
    payload: {
      causal_support: {
        mechanism_id: "object_authorization",
        controls_run: label === 1 ? ["c1", "c2"] : [],
        confounders_ruled_out: label === 1 ? ["cache"] : [],
      },
    },
  });
  writeJson(verificationRoundPaths(domain, "final").json, {
    results: [{
      finding_id: findingId,
      disposition: label === 1 ? "confirmed" : "denied",
      reportable: label === 1,
      confidence: label === 1 ? "high" : "low",
      confidence_reasons: label === 1 ? ["fresh_replay_passed"] : ["missing_control"],
    }],
  });
  writeJson(gradeArtifactPaths(domain).json, {
    verdict: label === 1 ? "SUBMIT" : "SKIP",
    total_score: label === 1 ? 75 : 0,
    findings: [{ finding_id: findingId, total_score: label === 1 ? 75 : 0 }],
  });
}

test("with NO model the scheduler score is the no-model baseline (advisory, never required)", () => {
  withTempHome(() => {
    const domain = "f1d-no-model.example.com";
    seedGraph(domain);
    const hints = buildBeliefSchedulerHints({
      target_domain: domain,
      surfaces: [matchingSurface(domain)],
      seed: "belief-scheduler-priority",
    });
    assert.equal(hints.applied, true);
    // No model on disk -> belief_replay records a null model_hash (recorded, not faked).
    assert.equal(hints.belief_replay.model_hash, null);
    // EIG proxy ~1.585 -> base = round(45 + 1.585*30) = 93, residual not admitted -> 93.
    assert.equal(hints.hints[0].score, 93);
  });
});

test("an identity (data-starved) trained model does NOT move the score (advisory)", () => {
  withTempHome(() => {
    const pos = "f1d-pos.example.com";
    const neg = "f1d-neg.example.com";
    const domain = "f1d-identity.example.com";
    seedGraph(domain);
    seedLabeledDomain({ domain: pos, findingId: "F-POS", label: 1 });
    seedLabeledDomain({ domain: neg, findingId: "F-NEG", label: 0 });

    const model = trainBeliefModel({ target_domain: domain, training_domains: [pos, neg] });
    // Executed-label provenance: the trainer's label source is verification + grade.
    assert.equal(model.label_source, "verification_round_and_grade_outcomes");
    // 2 pooled labels -> identity map (no overfit).
    assert.equal(model.recalibration_map.kind, "identity");

    const hints = buildBeliefSchedulerHints({
      target_domain: domain,
      surfaces: [matchingSurface(domain)],
      seed: "belief-scheduler-priority",
    });
    assert.equal(hints.applied, true);
    // The model is pinned (replayable) but identity -> score == the no-model baseline.
    assert.equal(hints.belief_replay.model_hash, model.model_hash);
    assert.equal(hints.belief_replay.model_needs_more_data, true);
    assert.equal(hints.belief_replay.model_label_source, "verification_round_and_grade_outcomes");
    assert.equal(hints.hints[0].score, 93);
  });
});

test("a non-identity model adjusts ORDER only, monotonically, never gating", () => {
  withTempHome(() => {
    const domain = "f1d-nonidentity.example.com";
    seedGraph(domain);
    // Train a real (identity) model first so the document shape is exact, then
    // overwrite the recalibration_map with a non-identity isotonic map that LOWERS a
    // high raw proxy (the executed outcomes recalibrated the over-eager raw EIG down).
    const pos = "f1d-ni-pos.example.com";
    const neg = "f1d-ni-neg.example.com";
    seedLabeledDomain({ domain: pos, findingId: "F-POS", label: 1 });
    seedLabeledDomain({ domain: neg, findingId: "F-NEG", label: 0 });
    const model = trainBeliefModel({ target_domain: domain, training_domains: [pos, neg] });

    const doc = JSON.parse(fs.readFileSync(beliefModelInfoPath(domain), "utf8"));
    doc.recalibration_map = {
      kind: "isotonic",
      points: [{ x: 0.5, p: 0.1 }, { x: 1, p: 0.4 }],
      sample_count: 40,
      min_samples: 20,
      needs_more_data: false,
    };
    fs.writeFileSync(beliefModelInfoPath(domain), `${JSON.stringify(doc, null, 2)}\n`);

    const hints = buildBeliefSchedulerHints({
      target_domain: domain,
      surfaces: [matchingSurface(domain)],
      seed: "belief-scheduler-priority",
    });
    assert.equal(hints.applied, true);
    // proxy = min(1, EIG ~1.585) = 1 -> applyRecalibration -> 0.4; modelBoost =
    // round((0.4 - 1) * 10) = -6; score = clamp(93 - 6) = 87. ORDER moved, no gate.
    assert.equal(hints.hints[0].score, 87);
    // model is recorded (the run is auditable / replayable).
    assert.equal(hints.belief_replay.model_needs_more_data, false);
    assert.ok(hints.hints[0].score >= 0 && hints.hints[0].score <= 100, "still a bounded score, never a gate");
  });
});

test("REPLAYABLE — same model_hash + same signals => byte-identical order", () => {
  withTempHome(() => {
    const domain = "f1d-replay.example.com";
    seedGraph(domain);
    const pos = "f1d-rp-pos.example.com";
    const neg = "f1d-rp-neg.example.com";
    seedLabeledDomain({ domain: pos, findingId: "F-POS", label: 1 });
    seedLabeledDomain({ domain: neg, findingId: "F-NEG", label: 0 });
    const model = trainBeliefModel({ target_domain: domain, training_domains: [pos, neg] });

    const run = () => buildBeliefSchedulerHints({
      target_domain: domain,
      surfaces: [matchingSurface(domain), { id: "surface:other", title: "owner gate", hosts: [domain] }],
      seed: "belief-scheduler-priority",
    });
    const first = run();
    const second = run();
    // Identical pin + identical order across replays.
    assert.equal(first.belief_replay.model_hash, model.model_hash);
    assert.deepEqual(first.belief_replay, second.belief_replay);
    assert.deepEqual(
      first.hints.map((h) => [h.surface_id, h.score]),
      second.hints.map((h) => [h.surface_id, h.score]),
      "same model_hash + same fed-signals => identical order",
    );
    // The fed-signal set is pinned alongside the model (calculus/window/residual).
    assert.equal(first.belief_replay.fed_signals.calculus_hash, first.calculus_hash);
    assert.equal(first.belief_replay.fed_signals.window_hash, first.window_hash);
    assert.equal(first.belief_replay.fed_signals.residual_admitted, false);
  });
});
