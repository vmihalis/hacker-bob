"use strict";

// CB-B5 -- monotonic recalibration of a raw score against pooled outcomes (isotonic
// regression, pool-adjacent-violators). Recalibrating ONE estimator needs far less
// data than fitting a model from scratch; with too few samples it returns the
// identity map (no recalibration) rather than overfitting. Advisory + shipped gated:
// the map corrects confidence, but default enablement waits for held-out lift.

const MIN_RECALIBRATION_SAMPLES = 20;

function clamp01(x) {
  return Math.max(0, Math.min(1, Number(x) || 0));
}

// samples: [{ score: number in [0,1], label: 0|1 }]
function fitIsotonicRecalibration(samples, { minSamples = MIN_RECALIBRATION_SAMPLES } = {}) {
  const clean = (samples || [])
    .filter((s) => s && Number.isFinite(s.score) && (s.label === 0 || s.label === 1))
    .map((s) => ({ x: clamp01(s.score), y: s.label }))
    .sort((a, b) => a.x - b.x || a.y - b.y);
  if (clean.length < minSamples) {
    return Object.freeze({
      kind: "identity",
      points: Object.freeze([]),
      sample_count: clean.length,
      min_samples: minSamples,
      needs_more_data: true,
    });
  }
  // pool-adjacent-violators: enforce a non-decreasing fitted rate over sorted x
  const blocks = clean.map((p) => ({ x: p.x, sum: p.y, n: 1 }));
  let i = 0;
  while (i < blocks.length - 1) {
    if (blocks[i].sum / blocks[i].n > blocks[i + 1].sum / blocks[i + 1].n) {
      blocks[i].sum += blocks[i + 1].sum;
      blocks[i].n += blocks[i + 1].n;
      blocks[i].x = blocks[i + 1].x; // block threshold spans up to this x
      blocks.splice(i + 1, 1);
      if (i > 0) i -= 1;
    } else {
      i += 1;
    }
  }
  const points = blocks.map((b) => Object.freeze({ x: Number(b.x.toFixed(6)), p: Number((b.sum / b.n).toFixed(6)) }));
  return Object.freeze({
    kind: "isotonic",
    points: Object.freeze(points),
    sample_count: clean.length,
    min_samples: minSamples,
    needs_more_data: false,
  });
}

function applyRecalibration(map, score) {
  const v = clamp01(score);
  if (!map || map.kind === "identity" || !Array.isArray(map.points) || map.points.length === 0) return v;
  for (const point of map.points) {
    if (v <= point.x) return point.p;
  }
  return map.points[map.points.length - 1].p;
}

function brier(samples, predictor) {
  if (!samples || samples.length === 0) return null;
  const total = samples.reduce((sum, s) => sum + ((predictor(s.score) - s.label) ** 2), 0);
  return Number((total / samples.length).toFixed(6));
}

function recalibrationReport(samples, map) {
  const raw = brier(samples, (x) => clamp01(x));
  const recalibrated = brier(samples, (x) => applyRecalibration(map, x));
  return Object.freeze({
    sample_count: (samples || []).length,
    brier_raw: raw,
    brier_recalibrated: recalibrated,
    brier_improvement: raw == null || recalibrated == null ? null : Number((raw - recalibrated).toFixed(6)),
    needs_more_data: Boolean(map && map.needs_more_data),
  });
}

module.exports = {
  MIN_RECALIBRATION_SAMPLES,
  fitIsotonicRecalibration,
  applyRecalibration,
  recalibrationReport,
};
