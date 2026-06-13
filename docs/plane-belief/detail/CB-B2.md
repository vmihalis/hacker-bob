# CB-B2 -- Intervention Calculus

## Node

- `id`: `CB-B2`
- `action`: `build_new`
- `anchor`: `mcp/lib/belief/intervention-calculus.js`
- `status`: `done`

## Contract

The intervention calculus is a deterministic, advisory do-operator over the
belief window. It ranks candidate experiments by expected information gain,
predicts effects, and lists explicit confounders/controls, but it never writes
artifacts, records claims, or schedules work.

## Implementation

- `mcp/lib/belief/intervention-calculus.js` emits `intervention-calculus.v1`
  rankings from `belief-window.v1` and CB-B4 sampler marginals.
- Object-authorization interventions include selector swaps, public-object
  checks, no-auth controls, victim-auth controls, nonexistent-object checks,
  stale-session checks, and cache/nonce checks.
- The output carries per-candidate `do_operation`, `predicted_effect`,
  `posterior_delta`, `expected_information_gain_bits`,
  `confounders_discriminated`, and explicit control/confounder vocabulary.
- `bob_query_intervention_calculus` is read-only/offline and writes no session
  artifacts.
- Stigmergy pair: producer `belief_intervention_calculus_ranking` consumed by
  `belief_intervention_query_tool`.

## Findings

None.

## Review Evidence

Engineering review passed:

- `node --test test/belief-intervention-calculus.test.js test/belief-window.test.js test/belief-factor-graph.test.js test/mcp-test-discovery.test.js`
- `npm run check:syntax`
- `npm run check:stigmergy-coherence`
- `npm run test:mcp`
- `npm run test:prompts`
- `verify-CB-B2-intervention-calculus: PASS`
