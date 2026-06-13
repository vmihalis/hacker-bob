# CB-B5 -- Calibrated Factor Model

## Node

- `id`: `CB-B5`
- `action`: `build_new+layer_on_labels`
- `anchor`: `mcp/lib/belief/model.js`
- `status`: `done`

## Contract

The learned factor model is an offline calibration artifact over explicit local
session exports. It consumes sanitized candidate-claim, final-verification, and
grade-outcome features, then writes inspectable metadata under belief scratch.
It never reads raw report bodies or evidence bodies, never records claims, never
grades, and never schedules work.

## Implementation

- `mcp/lib/belief/model.js` builds labeled examples from `claims.jsonl`,
  final verification outcomes, and grade verdict summaries.
- Feature extraction is limited to numeric/enum facts: causal-support presence,
  control/confounder counts, final disposition/reportability/confidence, replay
  reason flags, and negative confounder reasons.
- `bob_train_belief_model` trains deterministic calibrated logistic factor
  weights and writes `belief-scratch/belief-model-info.json`.
- The model info includes a versioned factor table, model hash, training
  summary, reliability curve, Brier score, precision@5, and lift over hand
  weights.
- `bob_read_belief_model_info` reads only the metadata document.
- The artifact is advisory with `claim_authority=false`,
  `verification_authority=false`, `grade_authority=false`, and
  `dispatch_authority=false`.
- Stigmergy pair: producer `belief_calibrated_factor_model` consumed by
  `belief_model_info_reader`.

## Path A-prime revision

- REMOVED the fake trainer: `trainWeights = (mean_pos - mean_neg) * 2` (no loss, no
  gradient, no calibration), the logistic `scoreExample`, `featureStats`,
  `evaluateModel`, and the `calibrated_logistic_factors` misnomer.
- REPLACED with a real monotonic **recalibration** (`mcp/lib/belief/recalibration.js`,
  isotonic / pool-adjacent-violators): the raw predictor is the transparent
  deterministic `handScore`; the map recalibrates it against pooled cross-session
  outcomes. Output is `recalibration_map` + a report with `brier_raw`,
  `brier_recalibrated`, `brier_improvement`. Recalibrating ONE estimator is the
  honest, data-efficient operation -- not a from-scratch fit.
- Data-starvation is honest: below `MIN_RECALIBRATION_SAMPLES` (20) the map is
  IDENTITY with `needs_more_data=true` (no overfit). Per-engagement labels are
  single-digit, so the map is pooled CROSS-SESSION and shipped gated
  (`default_enablement_ready=false`). Unit-tested: an overconfident estimator (says
  0.9, right ~50%) recalibrates below 0.7 and lowers Brier; the map is monotonic.

## Findings

- Default enablement is deferred. The recalibration stays
  `default_enablement_ready=false` until held-out equal-budget lift review; with
  too few pooled labels it is an identity map (`needs_more_data`).
- Belief suite 51/51; full `test:mcp` 2447 pass / 0 fail; stigmergy/agent-tools/skill
  coherent.

## Review Evidence

Engineering review passed:

- `node --test test/belief-model.test.js test/mcp-test-discovery.test.js test/stigmergic-producers-shape.test.js test/stigmergic-consumers-shape.test.js test/mcp-server.test.js`
- `npm run check:syntax`
- `npm run check:stigmergy-coherence`
- `npm run test:mcp`
- `npm run test:prompts`
- `verify-CB-B5-calibrated-factor-model: PASS`
