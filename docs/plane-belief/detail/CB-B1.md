# CB-B1 -- Belief Window

## Node

- `id`: `CB-B1`
- `action`: `build_new`
- `anchor`: `mcp/lib/belief/belief-window.js`
- `status`: `done`

## Contract

The belief window is a bounded, deterministic, advisory projection over CB-1
mechanism edges, CB-2 mechanism templates, and CB-3 frontier typed facts. It
does not write claims, verification rounds, grade artifacts, reports, or a
persisted belief-window store.

## Implementation

- `mcp/lib/belief/belief-window.js` builds `belief-window.v1` with latent
  variable types `effective_permission`, `object_ownership`,
  `request_equivalence`, and `gate_effectiveness`.
- The window binds `object_authorization` to `CWE-639`, mechanism graph paths,
  and frontier typed facts, then emits deterministic `variable_id`,
  `factor_id`, and `window_hash` values.
- Hard caps cover variables, factors, typed facts, and serialized size; cap
  violations throw `belief_window_too_large`.
- `bob_query_belief_window` exposes the projection as read-only, offline, and
  non-mutating with no `session_artifacts_written`.
- Stigmergy pair: producer `belief_window_projection` consumed by
  `belief_window_query_tool`.

## Findings

None.

## Review Evidence

Engineering review passed:

- `node --test test/belief-window.test.js test/belief-frontier-facts.test.js test/surface-graph.test.js test/mcp-test-discovery.test.js`
- `npm run check:syntax`
- `npm run check:stigmergy-coherence`
- `npm run test:mcp`
- `npm run test:prompts`
- `verify-CB-B1-belief-window: PASS`

No field review is required for this node.
