# CB-B4 -- Factor Graph Sampler

## Node

- `id`: `CB-B4`
- `action`: `build_new`
- `anchor`: `mcp/lib/belief/factor-graph.js`
- `status`: `done`

## Contract

The sampler is a deterministic, advisory inference engine over the bounded
belief window. It ranks frontier leaves, intervention candidates, and bounded
registry-template compositions, but it never records claims, schedules work, or
becomes authoritative ordering.

## Implementation

- `mcp/lib/belief/factor-graph.js` converts `belief-window.v1` into
  `factor-graph-sampler.v1` aggregate marginals using a seeded pure-JS sampler.
- Identical `seed + window_hash + sample_count` produces identical marginals and
  `sample_hash`.
- Rankings cover frontier leaves, object-authorization interventions, and
  registry-template pair/chain composition search inside the prior.
- `bob_run_belief_sampler` persists aggregate samples to
  `belief-scratch/belief-samples.jsonl` through the existing belief scratch path
  guard. It is offline and cannot write claims, verification, grade, report, or
  governance artifacts.
- Stigmergy pair: producer `belief_factor_graph_samples` consumed by
  `belief_sample_scratch_reader`.

## Path A-prime revision

- DEMOTED from deliverable to **A/B hypothesis**: true n-ary message-passing /
  sum-product over independently-sourced potentials is NOT built. The roast showed
  that sum-product over a single estimator's self-supplied joint manufactures the
  appearance of inference. The sampler stays an advisory marginal-over-priors.
- After CB-B1, `inferMarginals` samples `variable.posterior`, which is now the
  host-agent's elicited prior (or honest uniform) -- NOT the regex constant. So the
  sampler now echoes the real belief. Behavioral test (CB-B4 case in
  `test/belief-factor-graph.test.js`): a confident elicitation drives the marginal's
  `allowed` mass above 0.7; absent one it stays below 0.5 (uniform). This is the
  CB-B1 -> CB-B4 link and the proof the sampler is no longer a constant.

## Findings

- Field A/B is deferred (rationale). The sampler remains advisory scratch until an
  equal-budget field run shows sampler-ranked selection beats the
  information-gain heuristic-only path. True factor coupling is gated behind that
  same A/B as an explicit hypothesis, not a committed deliverable.

## Review Evidence

Engineering review passed:

- `node --test test/belief-factor-graph.test.js test/belief-window.test.js test/mcp-test-discovery.test.js`
- `npm run check:syntax`
- `npm run check:stigmergy-coherence`
- `npm run test:mcp`
- `npm run test:prompts`
- `verify-CB-B4-factor-graph-sampler: PASS`
