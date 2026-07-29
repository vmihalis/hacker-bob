# CB-D1 -- Deterministic object-authorization differential tester

## Contract

Where the discriminating controls can be run, the object-authorization verdict is a
**deterministic AND-over-controls** over observed effects -- a hard
confirmed/denied/inconclusive label, no probability, no LLM, replayable from the
recorded control outcomes. This is the PRIMARY path: a runnable control returns a
free hard label; the elicitation primitive (CB-B7) is only the fallback prior.

## What it does

`evaluateObjectAuthDifferential({ primary_effect, controls })` (`mcp/lib/belief/differential-tester.js:41`):

- `primary_effect.reached` is the attack -- the attacker principal reaching the
  victim object. Not reached -> `denied`.
- Positive controls (`attacker_owned_control`, `victim_auth_same_object`) must reach
  to validate the test; a failed positive -> `inconclusive` (setup invalid).
- Discriminating controls each rule out one confounder when their observed reach
  matches `safe_reached`; an unsafe one means the confounder is PRESENT -> `denied`:
  `no_auth_same_object`/`public_object_check` -> `public_object`,
  `nonexistent_object` -> `response_reflection`, `stale_session_check` ->
  `expired_auth`, `cache_nonce_check` -> `cache_bleed`.
- A missing discriminating control -> `inconclusive` with `unruled_confounders[]`.
- Only when the attack reaches AND every confounder is ruled out -> `confirmed`.

`buildCausalSupport(verdict)` shapes a confirmed verdict into the CB-C2 causal-support
payload (`mechanism_id`, `intervention`, `expected_effect`, `controls_run[]`,
`confounders_ruled_out[]`) accepted by `bob_record_candidate_claim`
(`record-candidate-claim.js:380-410`). Non-confirmed -> `null` (no claim).

## Failure mode it prevents

The shipped engine's "confirmation" was an evidence-invariant constant. CB-D1's
verdict is a pure function of the observed control outcomes: flip a decisive control
and the verdict flips; that is the behavioral gate.

## Predecessors / unlocks

- Predecessors: none (builds on shipped substrate).
- Unlocks: `CB-B5` (confirmed/denied verdicts are the calibration labels).
- Imports (resolved): `intervention-calculus.js` `OBJECT_AUTH_CONTROLS`,
  `verification-contracts.js` `hashCanonicalJson`. The reach/blocked semantics
  mirror `auth-differential.js` `classifyResponse` conceptually (not imported).
  Records through CB-C2 `controls_run[]`/`confounders_ruled_out[]`.

## Build slices (real anchors)

- `mcp/lib/belief/differential-tester.js` -- verdict logic + CB-C2 payload builder;
  imports `hashCanonicalJson` (`verification-contracts.js:*`) and `OBJECT_AUTH_CONTROLS`
  (`intervention-calculus.js:25`); no re-implemented hashing (DRY vs the audit finding).
- `test/belief-differential-tester.test.js` -- behavioral suite; registered in
  `test/mcp-test-manifest.json`.

## Review

**Engineering (PASS).** 9/9 behavioral tests: confirmed on a full safe set; **verdict
flips to denied on a decisive control flip** (`no_auth_same_object`,
`nonexistent_object`); **verdict + hash invariant to an irrelevant field**;
deterministic hash; `denied` with no primary; `inconclusive` on missing controls and
failed positives; CB-C2 payload only for confirmed. A constant fails the suite by
construction. `check:syntax` clean.

**Field (DEFERRED, rationale).** The equal-budget A/B (`object_auth_valid_claim_rate`
/ `missing_control_rate` vs baseline) requires authorized-target runs and is deferred
until an engagement supplies them. No engine-code gate blocks this; the verdict logic
is fully exercised offline.

## Authority

Advisory, derived, no claim/dispatch authority; records a claim only through the
existing claim plane (`bob_record_candidate_claim`) -- never writes one itself. No
networked surface added.
