# Path A-prime: the LLM-as-estimator belief engine

## Status

DESIGN, roast-validated 2026-06-13 (3-critic brutalist + independent verification).
Verdict: **keep one primitive, strip the dressing.** Pre-implementation. No engine
code until the falsifiable gate below passes.

## Problem (verified)

The shipped belief engine's estimators are degenerate:
- regex priors (`belief-window.js:77-89`), lookup-table + hand bonuses
  (`intervention-calculus.js:67-103`), `(mean_pos-mean_neg)*2` trainer
  (`model.js:176-185`), and `inferMarginals` samples each variable independently and
  ignores its factors (`factor-graph.js:85-111`). The "posterior" is invariant to its
  evidence -- the cardinal sin this work exists to fix.

Standalone Bayesian path (a) was rejected: starved estimator (unexecutable
victim-auth controls, n=1, K=1, single-digit labels).

## Reframe

The belief engine augments LLM agents. **The agent is the estimator.** The regex was
a fake stand-in for the agent's judgment. Remove it; put the agent in; the engine
becomes the typed, calibrated, replayable, provenance-disciplined scaffold around the
agent's judgment.

## Roast verdict: the split

A-prime is partly engineering, partly vibe-laundering. The line is clean.

**The engineering (keep):** replace a posterior that is *provably invariant to its
evidence* with an agent-elicited distribution that *moves when its cited evidence
changes* -- recorded as advisory scratch, tagged `llm_inferred`, cited, non-gating.
For an audit pipeline this is **more honest than the regex on the one axis that
matters**: its dishonesty (it is a judgment) is *legible* (tagged + cited), where the
regex hid a frozen constant inside a posterior's clothes. It loses only on
re-derivability -- which is fine, because it lives in scratch and never claims to be
a measurement.

**The vibe-laundering (strip):** recording into the frontier-events ledger;
sum-product over the agent's own self-supplied potentials; a content-hash called an
"audit certificate"; per-engagement calibration.

### The verified crux (corrects the earlier draft)

The earlier draft said "record the elicitation as a typed fact in the frontier-events
ledger." That is wrong and would launder provenance:
- `FRONTIER_EVENT_KINDS` is a closed, `assertEnumValue`-guarded enum
  (`frontier-events.js:33,61`) -- a `belief.elicited` event is refused at append.
- The only projected kind is `observation.recorded`, whose provenance map has **no**
  `llm_inferred` entry and **defaults unknown kinds to `operator_asserted`**
  (`frontier-facts.js:21-41,7`). The ledger path would stamp an LLM judgment with the
  provenance of a deliberate human assertion -- the exact laundering
  `causal-belief-hypergraph.md:155-158` forbids.

The honest home already exists: `writeBeliefSignalScratch` writes `llm_inferred`
(`authority.js:31`) into `belief-signals.jsonl`, force-stamped `scratch: true`
(`:156`), under `assertBeliefScratchWritePath` which refuses audit-graded paths
(`:115`). **The load-bearing gap:** `normalizeSignal` defaults `role: "evidence"` and
gates only `residual_anomaly` (`:126,130`) -- so nothing stops an `llm_inferred`
signal from being written `role: "evidence"`. That missing guard is the honesty rail.

## The minimum viable version (what to build)

1. **One evidence-conditioned elicitation primitive.** For a single latent
   (`effective_permission`), the agent returns a distribution over its declared
   states + a bounded rationale + cited `evidence_refs`. Recorded via the existing
   `writeBeliefSignalScratch` as `provenance: llm_inferred, role: prior` into scratch
   -- never the frontier-events ledger.
2. **The missing honesty guard.** Extend `normalizeSignal` so `llm_inferred` is
   forbidden from `role: "evidence"` and from sourcing any severity/grade -- the same
   shape as the existing `residual_anomaly` gate. This is the 10% that makes the rest
   honest.
3. **Lazy elicitation.** Only the latent the scheduler is about to act on, only when a
   cited `evidence_ref` changed, cached by `window_hash` + evidence-ref set. Never 64
   latents every turn.
4. **Recalibration only as a pooled cross-session offline map**, shipped gated
   (`default_enablement_ready=false`, as CB-B5 already is). Per-engagement labels are
   single-digit and unfittable.

## What is deferred or dropped

- **Factor-graph sum-product: demoted from deliverable to A/B hypothesis.** If one
  model supplies the marginals *and* the conditionals, sum-product cannot discover
  coupling the model did not already encode -- it manufactures the appearance of
  inference. Revisit only after the elicitation primitive proves evidence-sensitivity,
  and only if conditionals are elicited from *independent* evidence subsets.
- **Ledger recording of elicited belief: dropped** (laundering; see crux).
- **Every-turn / 64-latent fan-out: dropped** (cost; lazy elicitation instead).
- **VoI ranking on *actuatable* surfaces: dropped** -- where the control is runnable,
  run it; it is free and returns a hard label, not a sampled triple.

## Determinism: scratch tamper-check, not an audit certificate

The elicited distribution is recorded in scratch (`prompt_hash + model_id + response +
evidence_refs`); replay reads the record. The content-hash proves the blob was not
*modified*; it does **not** prove the belief is *re-derivable* (the model is
non-deterministic). So it is documented as a scratch tamper-check, never an audit
re-derivability certificate. This is honest because the belief is advisory scratch.

## The falsifiable gate (build this FIRST, before any inference layer)

The evidence-sensitivity differential: elicit on a fixture, record P0; flip exactly
one cited `evidence_ref` (auth-differential `unauth_succeeds` -> `auth_blocked`)
without touching the prompt scaffold; re-elicit P1. The primitive earns its keep iff
`||P1 - P0||` exceeds a preregistered threshold **and** moves toward `blocked`, while
flipping an *irrelevant* field stays below threshold. If the posterior moves the same
regardless of which field flips, the agent is pattern-matching the prompt shell, not
the evidence -- and you have rebuilt the regex with a `model_id` attached. (The regex
fails arm one by construction, so this is exactly the line between the two.)

## The economic reframe (primary vs secondary)

- **Primary value: the deterministic differential tester.** Where a control is
  runnable (the object-auth selector swap is a pure HTTP auth-differential pair),
  *run it* -- zero tokens, a hard confirmed/denied label, recorded through CB-C2's
  shipped `controls_run[]`/`confounders_ruled_out[]`. This is most of the realizable
  lift and it is nearly free.
- **Secondary: the elicitation primitive** is an advisory *routing prior* -- for
  prioritizing which surface to test next, and for the unactuatable surfaces where no
  control can run (legible-but-unverified, never gating).

## Circularity guard

Belief-assisted scheduler priority stays **gated off** (`queue-policy.js:77
belief_assisted_priority_enabled=false`) until an *external-label* loop-breaker
exists (an executed control with a verification outcome). Otherwise belief ranks what
the scheduler runs, which decides what the agent sees, which feeds belief -- and
"most informative" collapses toward "most confirming."

## What A-prime explicitly does NOT claim

Not standalone Bayesian inference; not a from-scratch trained model; not class
invention; not authority (advisory, scratch, provenance-tagged, single-gate,
single-dispatch); not an audit-grade re-derivable fact.

## Node deltas (see nodes.json)

- `CB-D1` (new, primary): deterministic differential tester -- run runnable controls,
  hard labels, via auth-differential + CB-C2. Buildable now on existing parts.
- `CB-B7` (new): the evidence-conditioned elicitation primitive + the honesty guard +
  the evidence-sensitivity gate.
- `CB-B1`/`CB-B2`: reopened -- rework on top of `CB-B7` (elicited belief, runnable-only
  VoI); drop regex + hand bonuses.
- `CB-B4`: reopened, demoted to A/B hypothesis (gated behind `CB-B7`).
- `CB-B5`: rewrite as pooled cross-session recalibration, shipped gated.
