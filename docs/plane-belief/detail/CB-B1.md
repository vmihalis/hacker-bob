# CB-B1 -- Belief window over elicited-or-uniform latent priors

## Node

- `id`: `CB-B1`
- `action`: `build_new` (reopened + reworked under path A-prime)
- `anchor`: `mcp/lib/belief/belief-window.js`
- `status`: `done`

## Contract

The belief window holds latent variables (effective_permission, object_ownership,
request_equivalence, gate_effectiveness) whose prior is the host agent's elicited
belief (CB-B7) when it cited one for that exact latent, else an honest uniform over
the declared states. The brittle regex is removed: no prior is fabricated from a
string match on the effect id.

## What changed (path A-prime)

`mcp/lib/belief/belief-window.js`:

- DELETED `idorLikeEffect` / `publicObjectEffect` (the regexes) and
  `posteriorForEffectivePermission` (the hardcoded `{allowed:0.88,...}` triples),
  plus the regex-keyed factor weight (`idorLikeEffect ? 0.88 : 0.45` -> constant 0.5).
- Also removed the hardcoded object_ownership `{owned:0.70}`, request_equivalence
  `{equivalent:0.55}`, and gate_effectiveness `{effective:0.78/0.60}` constants.
- ADDED `CANONICAL_STATES`, `uniformPrior`, `elicitedPriorIndex(target_domain)`
  (indexes `llm_inferred`/`role:prior` belief signals by `latent_id`), and
  `priorForLatent(type, scope, elicitedIndex)`: returns the elicited distribution if
  one exists for `stableId("BV", {type, scope})` (== the variable_id) and its keys
  match the declared states, else uniform. Each variable records
  `prior_source: "elicited" | "uniform"`.

The latent_id the agent elicits against == the window `variable_id`, so the window
and the elicitation share one deterministic id.

## Failure mode it prevents

The shipped window fabricated `allowed: 0.88` for any effect id matching `/idor/`. A
test pinned `posterior.allowed >= 0.85` -- a tautology over the regex constant. Now
the prior is uniform absent evidence (maximally uncertain, honest) and reflects the
elicited belief when present.

## Review

**Engineering (PASS).** Full belief suite 40/40. Behavioral gates: absent an
elicitation the effective_permission prior is uniform (~0.333, `prior_source:
uniform`) and explicitly NOT >= 0.85; when the agent elicits for that latent the
posterior becomes the elicited distribution (`prior_source: elicited`) and the
window_hash MOVES (a regex window would not move). Two downstream tests that were
tautologically tied to the regex were rewritten to the honest behavior (window
IDOR-confidence; residual-vs-elicited-confidence). `check:syntax` clean;
`idorLikeEffect`/`publicObjectEffect`/`posteriorForEffectivePermission` grep-clean
repo-wide; none was exported, so no external consumer.

## Authority

Unchanged: advisory/derived, `writes_artifacts:false`. The window only READS elicited
belief scratch; the elicited prior is `role:prior` and never enters as evidence (the
CB-B7 guard).

## Unlocks

`CB-B4` (the sampler now echoes the real elicited prior, not the regex) and `CB-B2`.
