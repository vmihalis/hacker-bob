# CB-B6 -- Residual Anomaly Surfacing

## Node

- `id`: `CB-B6`
- `action`: `build_new`
- `anchor`: `mcp/lib/belief/residual.js`
- `status`: `done`

## Contract

Residual anomaly is a deterministic diagnostic over CB-B4 sampler marginals. It
is high-recall and low-precision by design: a routing hint for humans and future
CB-C1 priority input, never a finding, claim support, dispatch authority, or
template-promotion authority.

## Implementation

- `mcp/lib/belief/residual.js` emits `belief-residual.v1` from
  `factor-graph-sampler.v1` marginals using negative log-likelihood plus entropy
  decomposition per variable.
- The output is deterministic for the same registry, seed, window hash, evidence,
  and sample count.
- `bob_run_belief_residual` persists a bounded `residual_anomaly` diagnostic to
  `belief-scratch/belief-signals.jsonl` with `role: diagnostic`.
- The diagnostic includes non-gating `priority_hint` and `human_router_record`
  fields, all with `claim_authority`, `dispatch_authority`, and
  `template_promotion_authority` set false.
- Stigmergy pair: producer `belief_residual_anomaly_diagnostic` consumed by
  `belief_residual_diagnostic_reader`.

## Findings

None.

## Review Evidence

Engineering review passed:

- `node --test test/belief-residual.test.js test/belief-factor-graph.test.js test/mcp-test-discovery.test.js`
- `npm run check:syntax`
- `npm run check:stigmergy-coherence`
- `npm run test:mcp`
- `npm run test:prompts`
- `verify-CB-B6-residual-anomaly: PASS`
