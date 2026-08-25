# CB-B2 -- Intervention Calculus

## Node

- `id`: `CB-B2`
- `action`: `build_new`
- `anchor`: `mcp/core/belief/intervention-calculus.js`
- `status`: `done`

## Contract

The intervention calculus is a deterministic, advisory do-operator over the
belief window. It ranks candidate experiments by expected information gain,
predicts effects, and lists explicit confounders/controls, but it never writes
artifacts, records claims, or schedules work.

## Implementation

- `mcp/core/belief/intervention-calculus.js` emits `intervention-calculus.v1`
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

## Path A-prime revision

- REMOVED the hardcoded `posteriorForCandidate` lookup, the `candidateScore` hand
  bonuses (`+0.75`/`+1.0`/`-0.25`), and the `isIdorLike`/`isPublicObject` regexes.
  Also removed the discarded `inferMarginals` call (the sampler-computed-then-thrown
  finding) and its import.
- `expected_information_gain_bits` is now the entropy of the latent's
  elicited-or-uniform belief (the most a discriminating test can resolve). A pure
  function of the elicited belief: a confident elicitation lowers VoI; no bonus
  distinguishes interventions for a latent. VoI prioritizes the most-uncertain
  latent (where there is most to learn).
- Ranking is RUNNABLE-only: `victim_auth_same_object` (needs the victim credential)
  is excluded by default; the caller passes `runnable_controls` from available auth
  profiles. On actuatable surfaces, prefer running the control (CB-D1) over scoring.
- `predicted_effect.expected_state` and `confounders_discriminated` are now
  deterministic maps (the experimental design + the control's confounder role), not
  fabricated probabilities.

## Findings

- Behavioral gates rewritten: the two prior tests ("swap ranks above control",
  "public_object_check ranks first") were tautologies satisfied by the removed hand
  bonuses. Replaced by: VoI == elicited-belief entropy and drops on a confident
  elicitation (no bonus); runnable-only ranking. Belief suite 41/41.

## Review Evidence

Engineering review passed:

- `node --test test/belief-intervention-calculus.test.js test/belief-window.test.js test/belief-factor-graph.test.js test/mcp-test-discovery.test.js`
- `npm run check:syntax`
- `npm run check:stigmergy-coherence`
- `npm run test:mcp`
- `npm run test:prompts`
- `verify-CB-B2-intervention-calculus: PASS`
