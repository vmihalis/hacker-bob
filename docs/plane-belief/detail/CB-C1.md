# CB-C1 -- Belief Into the One Scheduler

## Node

- `id`: `CB-C1`
- `action`: `layer_on`
- `anchor`: `lead-scoring.js`, `ranking.js`, `wave-planner.js`, `queue-policy`
- `status`: `done`

## Contract

Belief-assisted scheduling is an opt-in ranking input to the existing wave
planner. It does not add a second scheduler, dispatcher, queue, or assignment
writer. The queue policy remains the switch and the existing priority bridge
remains the banding mechanism.

## Implementation

- `mcp/lib/belief/scheduler-priority.js` converts CB-B2 intervention rankings
  and optional residual diagnostics into advisory per-surface priority hints.
- `queue-policy.json` gains `belief_assisted_priority_enabled` plus deterministic
  seed/rank-limit knobs. The default is disabled.
- `planNextWave` calls the bridge only when the policy enables it, then sorts
  through the existing `ranking.score`, `ranking.priority`, and
  `compareSurfaces` path.
- Decorated surfaces record `ranking.belief` with model version, calculus/window
  hashes, candidate id, intervention, information gain, non-gating status, and
  no dispatch authority.
- Stigmergy pair: producer `belief_scheduler_priority_hints` consumed by
  `wave_planner_belief_priority_bridge`.

## Findings

- Default enablement is deferred. Belief-assisted priority requires an
  equal-budget A/B against the current scheduler before it can become the
  default queue policy.

## Review Evidence

Engineering review passed:

- `node --test test/wave-planner.test.js test/belief-intervention-calculus.test.js test/scheduler-decisions.test.js test/scheduler-decisions-wiring.test.js test/mcp-test-discovery.test.js`
- `npm run check:syntax`
- `npm run check:stigmergy-coherence`
- `npm run test:mcp`
- `npm run test:prompts`
- `verify-CB-C1-belief-scheduler-gate: PASS`
