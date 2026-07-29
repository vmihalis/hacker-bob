# CB-C2 -- Causal Support on Claims and the Verifier

## Node

- `id`: `CB-C2`
- `action`: `extend_existing`
- `anchor`: `record-candidate-claim`, `claims.js`, verification v2 adjudication
- `status`: `done`

## Contract

CB-C2 extends existing claim and verification authority. It does not add a
claim writer, a fourth `evidence_refs[]` location, or a verifier artifact. Causal
support is persisted on the CandidateClaim payload and verifier uncertainty is
recorded as closed `confidence_reasons[]` values that are folded into the
existing adjudication plan hash.

## Implementation

- `bob_record_candidate_claim` accepts optional `mechanism_id`,
  `hypothesis_statement`, `intervention`, `expected_effect`, `controls_run[]`,
  and `confounders_ruled_out[]`.
- The writer normalizes those fields into `payload.causal_support`, so
  `claim_hash` changes when causal support changes.
- `unruled_confounder` and `missing_control` are added to the closed
  verification confidence-reason enum.
- `buildVerificationAdjudication` maps those verifier signals into replay
  reasons while still writing only `verification-adjudication.json`.
- Stigmergy pair: producer `claim_causal_support_payload` consumed by
  `verification_adjudication_causal_reason_reader`.

## Findings

- The verifier coupling stayed inside the existing v2 adjudication hash. No
  new evidence reference home or verification ledger was introduced.

## Review Evidence

Engineering review passed:

- `node --test test/verification-contracts.test.js test/stigmergic-producers-shape.test.js test/stigmergic-consumers-shape.test.js`
- `npm run check:syntax`
- `npm run check:stigmergy-coherence`
- `npm run test:mcp`
- `npm run test:prompts`
- `verify-CB-C2-causal-support-verification: PASS`
