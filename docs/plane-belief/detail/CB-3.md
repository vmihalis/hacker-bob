# CB-3 -- Frontier Typed-Fact Intake

## Node

- `id`: `CB-3`
- `action`: `layer_on`
- `anchor`: `mcp/lib/frontier-events.js`; `mcp/lib/frontier-materializer.js`;
  `mcp/lib/frontier-projections.js`; `mcp/lib/capability-observations.js`
- `status`: `done`

## Contract

Belief intake reads typed facts from the existing `frontier-events.jsonl`
`observation.recorded` ledger. CB-3 does not add a second typed-fact ledger,
extractor tier, or write path.

## Implementation

- `mcp/lib/belief/frontier-facts.js` adds a pure projection over
  `readFrontierEvents`, reusing `normalizeObservationEvent` and timestamp
  ordering from `frontier-projections.js`.
- `queryFrontierTypedFacts` returns bounded, read-only `frontier_observation`
  facts with stable `fact_id`, `source_event_id`, `artifact_ref`, provenance,
  source metadata, and redacted payload.
- Observation provenance maps existing observation kinds into the CB-S2 closed
  provenance vocabulary: HTTP observations as `observed_http`, schema
  observations as `declared_schema`, OSS/static observations as `static_code`,
  and unclassified telemetry as `operator_asserted`.
- String leaves changed by redaction collapse to `REDACTED` before
  `validateNoSensitiveMaterial`, so belief facts cannot carry token-shaped
  payload fragments.
- Stigmergy pair: producer `frontier_observation_typed_fact_projection`
  consumed by `belief_frontier_fact_projection_reader`.

## Findings

None.

## Review Evidence

Engineering review passed:

- `node --test test/belief-frontier-facts.test.js test/frontier-observation-ledger.test.js test/frontier-projections.test.js test/mcp-test-discovery.test.js`
- `npm run check:syntax`
- `npm run check:stigmergy-coherence`
- `npm run test:mcp`
- `npm run test:prompts`
- `verify-CB-3-frontier-typed-facts: PASS`

No field review is required for this node.
