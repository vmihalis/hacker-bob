"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  MIN_RECALIBRATION_SAMPLES,
  fitIsotonicRecalibration,
  applyRecalibration,
  recalibrationReport,
} = require("../mcp/core/belief/recalibration.js");

// A systematically OVERCONFIDENT estimator: it says ~0.9 but is right ~50% of the time.
function overconfidentSamples(n) {
  const out = [];
  for (let i = 0; i < n; i += 1) {
    out.push({ score: 0.9, label: i % 2 }); // predicted 0.9, empirical 0.5
    out.push({ score: 0.1, label: i % 5 === 0 ? 1 : 0 }); // predicted 0.1, empirical 0.2
  }
  return out;
}

test("too few samples returns the identity map and needs_more_data (no overfit)", () => {
  const map = fitIsotonicRecalibration([{ score: 0.9, label: 1 }, { score: 0.1, label: 0 }]);
  assert.equal(map.kind, "identity");
  assert.equal(map.needs_more_data, true);
  assert.ok(map.sample_count < MIN_RECALIBRATION_SAMPLES);
  // identity passes scores through unchanged
  assert.equal(applyRecalibration(map, 0.9), 0.9);
});

test("isotonic recalibration pulls an overconfident estimator toward its empirical rate", () => {
  const samples = overconfidentSamples(40); // 80 samples
  const map = fitIsotonicRecalibration(samples);
  assert.equal(map.kind, "isotonic");
  assert.equal(map.needs_more_data, false);
  // 0.9 predictions were right ~50% of the time -> recalibrated well below 0.9
  const recal = applyRecalibration(map, 0.9);
  assert.ok(recal < 0.7, `0.9 should recalibrate toward ~0.5, got ${recal}`);

  // and recalibration improves (lowers) Brier vs the raw overconfident scores
  const report = recalibrationReport(samples, map);
  assert.ok(report.brier_recalibrated <= report.brier_raw);
  assert.ok(report.brier_improvement >= 0);
});

test("the fitted map is monotonic non-decreasing", () => {
  const map = fitIsotonicRecalibration(overconfidentSamples(40));
  let prev = -1;
  for (const point of map.points) {
    assert.ok(point.p >= prev - 1e-9, "recalibrated probabilities must be non-decreasing in score");
    prev = point.p;
  }
  // higher raw scores never recalibrate below lower raw scores
  assert.ok(applyRecalibration(map, 0.95) >= applyRecalibration(map, 0.05) - 1e-9);
});
