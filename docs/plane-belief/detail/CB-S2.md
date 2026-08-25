# CB-S2 -- Provenance and Secret-Safety

## Node

- `id`: `CB-S2`
- `action`: `extend_existing`
- `anchor`: `mcp/core/redaction/sensitive-material.js` `validateNoSensitiveMaterial`;
  `mcp/redaction.js` `redactTextSensitiveValues`; `mcp/core/claims/claims.js`
  `EVIDENCE_REFERENCE_KIND_VALUES`
- `status`: `done`

## Contract

Every belief signal carries closed-enum provenance and an artifact reference.
Belief scratch records distinguish observed, inferred, learned, verified, and
diagnostic material. `residual_anomaly` is diagnostic-only and cannot enter the
belief window as evidence or prior.

## Implementation

- `mcp/core/belief/authority.js` defines frozen
  `BELIEF_PROVENANCE_VALUES`, matching the Plane-B spec.
- `writeBeliefSignalScratch()` requires `provenance` and `artifact_ref`, redacts
  all string leaves with `redactTextSensitiveValues`, then runs
  `validateNoSensitiveMaterial` before appending to
  `belief-scratch/belief-signals.jsonl`.
- `role` is a closed enum: `evidence`, `prior`, or `diagnostic`.
  `residual_anomaly` is accepted only with `role: "diagnostic"`.
- `bob_query_belief_signals` can filter by `provenance` and `role`; the tool
  remains read-only and offline.

## Review Evidence

Engineering review passed:

- `node --test test/belief-authority.test.js`
- `npm run check:syntax`
- `npm run check:stigmergy-coherence`
- `npm run test:mcp`
- `npm run test:prompts`
- `verify-CB-S2-provenance-secret-safety: PASS` adversarial anchor check
  grounding `mcp/core/redaction/sensitive-material.js`, `mcp/redaction.js`, and
  `mcp/core/belief/authority.js`

No field review is required for this node.
