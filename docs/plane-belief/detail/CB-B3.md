# CB-B3 -- Active Experiment Loop

## Node

- `id`: `CB-B3`
- `action`: `build_new+layer_on_dispatch`
- `anchor`: `mcp/core/belief/experiment-loop.js`
- `status`: `done`

## Contract

The experiment loop is a bounded advisory planner. It chooses candidate
interventions from CB-B2, then appends proposals through the existing
`bob_propose_hypothesis` frontier-event path. It never spawns workers directly
and never records claims.

## Implementation

- `mcp/core/belief/experiment-loop.js` ranks interventions and emits
  `belief-experiment-loop.v1` plans.
- `dry_run: true` returns the same bounded proposal shape without writing.
- Non-dry runs append `hypothesis_proposed` observations with advisory
  `suggested_contract` objects containing `production_paths`,
  `relational_value_match` witnesses, provenance hashes, predicted effect, and
  controls.
- `max_iterations` is capped at 5.
- `bob_plan_belief_experiment` is offline, mutating only through
  `frontier-events.jsonl`, and has no claim or scheduler-spawn authority.
- Stigmergy pair: producer `belief_experiment_hypothesis_proposals` consumed by
  `belief_experiment_loop_reader`.

## Findings

- Field A/B is deferred. Default use requires equal-budget comparison against
  the evaluator baseline for valid-claim rate, false-positive rate,
  controls-run completeness, and time-to-first verified object-auth claim.

## Review Evidence

Engineering review passed:

- `node --test test/belief-experiment-loop.test.js test/belief-intervention-calculus.test.js test/mcp-test-discovery.test.js`
- `npm run check:syntax`
- `npm run check:stigmergy-coherence`
- `npm run test:mcp`
- `npm run test:prompts`
- `verify-CB-B3-active-experiment-loop: PASS`
