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

## Findings

- Field A/B is deferred. The sampler remains advisory scratch until an
  equal-budget field run shows sampler-ranked selection beats the
  information-gain heuristic-only path.

## Review Evidence

Engineering review passed:

- `node --test test/belief-factor-graph.test.js test/belief-window.test.js test/mcp-test-discovery.test.js`
- `npm run check:syntax`
- `npm run check:stigmergy-coherence`
- `npm run test:mcp`
- `npm run test:prompts`
- `verify-CB-B4-factor-graph-sampler: PASS`
