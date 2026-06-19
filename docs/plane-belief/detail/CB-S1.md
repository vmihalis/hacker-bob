# CB-S1 -- Authority Preservation

## Node

- `id`: `CB-S1`
- `action`: `extend_existing`
- `anchor`: `mcp/lib/role-model.js` read-only pattern; `mcp/lib/paths.js` `AUDIT_GRADED_PATHS`
- `status`: `done`

## Contract

Belief outputs are advisory, derived, recomputable scratch. They do not create a
second claim, verification, grade, report, governance, graph, or dispatch
authority.

## Implementation

- `mcp/lib/paths.js` defines `beliefScratchDir()` and
  `beliefSignalsJsonlPath()` under each session root.
- `mcp/lib/belief/authority.js` is the shared substrate for later belief
  producers. It classifies `mechanism_projection` and `belief_signal` outputs as
  `advisory`, `derived`, and `scratch`, writes only
  `belief-scratch/belief-signals.jsonl`, and refuses paths rejected by
  `isAuditGradedPath()`.
- `bob_read_belief_signals` and `bob_query_belief_signals` are registry-backed
  read/query tools with `mutating:false`, `network_access:false`,
  `browser_access:false`, and no `session_artifacts_written`.
- Stigmergy pair: producer `belief_scratch_signals` consumed by
  `belief_signal_read_query_tools`.

## Review Evidence

Engineering review passed:

- `node --test test/belief-authority.test.js`
- `npm run check:syntax`
- `npm run check:stigmergy-coherence`
- `npm run test:mcp`
- `npm run test:prompts`
- `verify-CB-S1-authority: PASS` adversarial anchor check grounding
  `mcp/lib/paths.js`, `mcp/lib/tool-registry.js`, and
  `mcp/lib/role-model.js`

No field review is required for this node.
