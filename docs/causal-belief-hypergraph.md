# Bob Causal Belief Hypergraph

## Audience and scope

This is an internal engineering roadmap for adding a genuinely new capability to
Hacker Bob: **active causal experimentation**. Bob today runs coverage-driven,
heuristic-ranked exploration -- run techniques, score leads with a linear weight
table, expand the frontier. That is a checklist with excellent bookkeeping. This
roadmap adds the thing the checklist structurally cannot do: form a mechanism
hypothesis, choose the single most *informative* intervention given current
belief, run it, update belief from the observed effect under controls, rule out
confounders, and chain -- recombining partial evidence across surfaces to
predict a vulnerability before testing it.

```text
typed facts -> belief over latent mechanism variables -> max-information intervention
            -> observed effect under controls -> belief update -> next intervention / claim
```

The first mechanism is **object authorization** because it is high-yield,
cross-stack, and already richly observable in Bob's evidence.

## The central principle: reuse the substrate, build the engine

A supersession audit found that ~80 percent of a naive "belief plane" already
exists in Bob, and that duplicating it as parallel stores/scorers/dispatchers
would create authority drift. That finding is correct -- about the **substrate**.
It is not a verdict on the **inference engine**, which does not exist anywhere in
Bob and is the actual product.

So this plan is explicitly two-tier, with different rules for each:

```text
Tier 1  Substrate            LAYER-ON. Reuse. Typed facts are projections over
                             surface-graph, contracts, auth-differential,
                             frontier-events. Do not rebuild them.

Tier 2  Inference engine     NET-NEW, FIRST-CLASS. A calibrated latent-variable
                             belief model + counterfactual intervention calculus
                             + information-gain sampler + the active experiment
                             loop. This is the capability. Do not dilute it into
                             "more features in lead-scoring."

Tier 3  Coupling             ADVISORY, SINGLE-AUTHORITY. The engine reads Tier 1
                             and emits through Bob's existing single authorities
                             (one scheduler, one promotion gate, one verification
                             hash). Net-new reasoning, reused plumbing.
```

The drift the audit warned about was duplicate **stores and authorities**, never
a new **reasoning layer**. Tier 2 duplicates neither: it reads the substrate and
writes advisory signals through Tier 3. The intelligence behind the scheduler's
"what next" decision becomes a causal belief engine instead of a keyword weight
table; there is still exactly one scheduler and one gate.

## What exists, and what does not

Already shipped (Tier 1 substrate -- reuse, with anchors):

- Typed, content-addressed graph: `mcp/lib/surface-graph.js:14` `NODE_TYPES`,
  `:28` `EDGE_TYPES` (`edge_hash` via `normalizeEdge`).
- Principal x Credential x Endpoint -> Effect, already computed:
  `mcp/lib/auth-differential.js:130` (`unauth_succeeds_where_auth_blocked`).
- PolicyGate facts: `schema-contracts.js` `claimed_auth`; on-chain role matrix
  `mcp/lib/tools/evm-role-table.js`.
- Contract DSL with witnesses: `mcp/lib/contracts.js:70` `WITNESS_KIND_VALUES`,
  `:77` `relational_value_match`.
- Typed-fact ledger + projection: `mcp/lib/frontier-events.js:33`
  `FRONTIER_EVENT_KINDS`, folded by `mcp/lib/frontier-materializer.js`.
- One dispatch authority: the TaskGraph materializer + `bob_propose_hypothesis`
  (`mcp/lib/tools/propose-hypothesis.js:72` `suggested_contract`).
- One promotion gate: `mcp/lib/lead-scoring.js:35` `evidenceScore` -> `:97`
  `confidenceFromScore`.
- Verification hash + replay battery: `mcp/lib/verification.js` +
  `computeAdjudicationPlanHash`; `state_sensitive` and replay triggers already
  ship (`mcp/lib/verification-round-store.js:134`, `verification.js:684`).

Does not exist anywhere in Bob (Tier 2 inference engine -- net-new, grep-confirmed
zero hits for factor-graph / sampler / belief-state / information-gain / posterior
code):

- A belief state over **latent** mechanism variables (effective permission,
  object ownership, request-equivalence class) with calibrated uncertainty.
- A counterfactual intervention calculus (do-operations on the belief, expected
  effect, value of information).
- Information-gain-driven test selection.
- The active experiment loop that updates belief from observed effects.

The substrate makes the engine cheap to build. It does not make it already-built.

## Node namespace

`CB-S*` substrate, `CB-B*` belief/inference engine, `CB-C*` coupling. The `CB-`
prefix avoids collision with the shipped capability-hypergraph nodes (`S1..S10`,
`IP1..IP6`).

## Authority and guardrails

The belief plane is advisory and derived; `mcp/lib/lifecycle-gates.js`, the tool
registry, role bundles, egress binding, claim freeze, verification, grade, and
report remain authoritative. The engine is allowed to be ambitious *because* it
never holds authority. Guardrails:

- One graph store. Mechanism facts are a projection over `surface-graph.jsonl`
  bound by the same `edge_hash`; no parallel `mechanism-graph.json`.
- One promotion gate. The belief engine's output is the *input* the single gate
  consumes -- it replaces the keyword weight table as the intelligence behind the
  number, it is not a second competing band.
- One dispatch authority. The experiment loop selects interventions but dispatches
  them through the TaskGraph materializer / `propose_hypothesis`; it never spawns
  its own.
- One disposition axis + one verification hash. Confounder reasoning folds into
  `confidence_reasons[]` and `computeAdjudicationPlanHash`, the way X10 added
  `reasoning_divergence`.
- Determinism preserved. Sampling is seeded and recorded; same seed + same belief
  window reproduce the same marginals within tolerance. The sampler ranks; it is
  never the source of truth.
- Secret-safe by construction. The belief window reads names/keys/hashes only;
  `redactTextSensitiveValues` runs before `validateNoSensitiveMaterial`.
- No cross-target similarity duplication. Consume the planned I13 transfer index;
  do not revive the I6/I13 orphan-index regression.
- No machine-invented mechanism classes. The engine instantiates and composes
  registry templates and surfaces what it cannot explain; it never promotes an
  LLM-proposed template to trusted registry authority (see Novelty boundary).

## Novelty: what the engine can and cannot discover

Class-level novelty -- a vulnerability mechanism nobody has templated -- splits
into three problems with three different owners. Conflating them is how you build
a fiction generator.

- Surface what the model cannot explain -> machine, deterministically. `CB-B6`
  exposes the inference residual: a high-residual surface is one the registry
  predicts poorly. This is a routing signal, not a finding.
- Compose known mechanisms into novel chains -> machine. The `CB-B4` joint sampler
  searches O(K^2) pairs and bounded O(K^d) chains over the K registry templates,
  entirely inside the prior's support. Most "novel" bugs in mature programs are
  chains of known mechanisms, not new CWEs; this is the abundant, reachable slice.
- Invent and certify a genuinely new mechanism class -> human. A maintainer
  authors a reviewed template into the registry. The machine makes the anomaly
  legible and maximizes the human's leverage; it does not name the class.

Rejected: machine template-induction (an LLM proposes a new template the engine
self-validates and promotes to trusted registry knowledge). It is dominated, for
reasons that are structural, not tunable:

- Instance validation is not class validation. Confirming one intervention is
  existential; a template is a universal claim that needs out-of-sample instances
  plus negative controls plus confounder discrimination to falsify an overfit.
- The falsifying controls are the unexecutable ones. On a single target the
  negative controls that separate a real mechanism from its confounders are the
  victim-auth interventions Bob often cannot run, with n=1 per surface and an
  empty in-session held-out set by construction. A "safe" inductor never promotes;
  a "useful" one promotes from a coincidence.
- Promotion launders provenance. It turns an `llm_inferred` guess into
  `verified_intervention`-grade authority -- the exact thing `CB-S2` provenance
  exists to prevent -- and mints a class-creation authority the lifecycle has no
  state for.
- It poisons learning. A laundered template corrupts the verification-outcome
  labels `CB-B5` trains on, and calibration is computed on the same corrupted
  ground truth, so it cannot self-detect; contamination compounds across retrains.
- The inference is structurally blind to it. Information gain (`CB-B2`) is scored
  only over latents already in the window; a novel latent is not in the factor
  set, so "confirmation" is computed against the old structure. Inventing a class
  is abduction over the model space, which a closed-world factor graph cannot
  represent.

## How to read this graph

Each node: **TIER** / **ACTION** (`extend_existing`, `merge`, `layer_on`, or
`build_new`) / **DO** / **REVIEW (engineering)** / **REVIEW (field)**. A hyperedge
(H) links predecessors to unlocked nodes.

## Tier 1 -- Substrate (layer-on)

### CB-S1 -- Authority preservation

**ACTION.** `extend_existing` (`mcp/lib/role-model.js` read-only pattern;
`mcp/lib/paths.js` `AUDIT_GRADED_PATHS`).

Belief outputs are derived, recomputable, **scratch**. Belief read/query tools are
`network_access:false`, `mutating:false`. The one belief write that touches a
claim is the optional, validated causal-support extension on
`record-candidate-claim` (CB-C2).

**REVIEW (engineering).** Role-bundle tests prove belief tools cannot write
claim/verification/grade/report/governance artifacts; a runtime-denial test
asserts refusal (the current suite proves grants, not denials).

### CB-S2 -- Provenance and secret-safety

**ACTION.** `extend_existing` (`mcp/lib/sensitive-material.js`
`validateNoSensitiveMaterial`; `mcp/redaction.js` `redactTextSensitiveValues`;
enum convention `mcp/lib/claims.js:84` `EVIDENCE_REFERENCE_KIND_VALUES`).

Every belief edge/fact carries a provenance value from a closed enum
(`observed_http`, `observed_traffic`, `declared_schema`, `static_code`,
`surface_graph`, `claim_ledger`, `verification_result`, `operator_asserted`,
`llm_inferred`, `learned_prior`, `verified_intervention`, `residual_anomaly`) and
an artifact ref; inferred edges are distinguishable from observed and verified
ones. This matters more than elegance: provenance is how the belief avoids
becoming fiction, and how the sampler knows which edges it is allowed to treat as
evidence versus prior. `residual_anomaly` is a diagnostic class -- a property of
an inference run, not a fact -- usable only to route to the scheduler or a human
(`CB-B6`); it is structurally forbidden from entering the belief window as
evidence or prior.

### CB-1 -- Mechanism projection over the surface graph

**ACTION.** `extend_existing` (`mcp/lib/surface-graph.js` taxonomy;
`mcp/lib/surface-graph-builder.js` builders; fed by `auth-differential.js`,
`evm-role-table.js`, `symbol-surface-index.js`, `chain-state-tree.js`).

**DO.** Add the missing node/edge types -- `principal`, `credential`,
`policy_gate`, `effect`, `intervention` -- to the existing content-addressed
taxonomy, and one builder source projecting auth-differential rows, evm-role
matrices, schema `claimed_auth`, and chain-node outcomes into them. Expose the
mechanism view as a bounded `bob_query` mode over `surface-graph.jsonl`, not a
new store. This is the typed fact layer the engine reasons over.

### CB-2 -- Object-authorization mechanism template

**ACTION.** `merge` into `mcp/lib/invariant-template-corpus.js` +
`mcp/lib/oss-rootcause-family-corpus.js` + `mcp/lib/contracts.js` witness DSL;
mechanism id from `mcp/lib/cwe-catalog.js` (`CWE-284/862/863`).

**DO.** Add `object_authorization` as a template record in the existing corpus
shape (`required_entities`, `interventions`, `positive_controls`,
`negative_controls`, `confounders`, `evidence_predicate`), surfaced through the
existing bounded, secret-safe `technique-packs.js` loader pattern. The template
is the structural prior the belief engine instantiates per surface.

### CB-3 -- Typed-fact intake (reuse frontier-events)

**ACTION.** `layer_on` (`mcp/lib/frontier-events.js` `observation.recorded`;
`mcp/lib/frontier-materializer.js`; `http-records.js`, `schema-contracts-store.js`;
the `capability-observations.js` "add a derived fact" precedent).

**DO.** Do not build a second extractor tier. The belief window reads the typed
facts the frontier-events ledger already emits from traffic/HTTP-audit, schema/
surface, and claims/verification; any genuinely new derived fact is added via the
`capability-observations.js` pattern.

## Tier 2 -- Inference engine (net-new, first-class)

This is the capability. Each node here is new code under `mcp/lib/belief/*`. None
of it duplicates a store or an authority; it reads Tier 1 and emits through
Tier 3.

### CB-B1 -- Belief state over latent mechanism variables

**ACTION.** `build_new`.

A bounded, local belief window materializes a small set of **latent** variables
the substrate cannot observe directly, each with a calibrated distribution, not a
point score:

```text
effective_permission(principal, object)     hidden; inferred
object_ownership(principal, object)          hidden; inferred
request_equivalence_class(endpoint_a, endpoint_b)
shared_object_namespace(endpoint_a, endpoint_b)
gate_effectiveness(policy_gate, effect)      does the gate actually stop E
```

These bind to observed facts (CB-1 edges, auth-differential signatures, schema
claims) through factors, with provenance. The belief is the posterior over these
latents given evidence so far. This is the structural break from `lead-scoring`:
that engine produces a heuristic point score from keyword weights; CB-B1 maintains
a distribution over unobservable mechanism state that evidence updates.

**DO.** Define `mcp/lib/belief/belief-window.js` (schema, latent variables,
factor bindings, provenance, content-addressed window hash). Hard caps on
variables, factors, and serialized size; oversized windows refuse with
`belief_window_too_large`.

**REVIEW (engineering).** Same evidence -> same posterior. A fixture IDOR surface
yields high `effective_permission` mass on the attacker-victim object pair; a
public-object surface does not. No claim is recorded from belief alone.

### CB-B2 -- Counterfactual intervention calculus

**ACTION.** `build_new`.

Encode interventions as do-operations on the belief window. For object auth, the
core operation holds `principal/auth_profile` fixed and sets the selector from an
attacker-owned to a victim-owned object, asking what the model predicts for the
effect under each control, and what the *posterior would become* under each
possible observed outcome.

```text
intervention      do(selector := victim_object), principal fixed
predicted_effect  P(effect | do(...), belief)
controls          attacker_owned, victim_auth_same_object, no_auth_same_object,
                  nonexistent_object, public_object_check, stale_session_check,
                  cache/nonce_check
confounders       public_object, role_inheritance, expired_auth, cache_bleed,
                  response_reflection, eventual_consistency, egress_drift,
                  policy_allows_delegation
```

The calculus computes, per candidate intervention, the **expected information
gain** -- how much running it would reduce uncertainty about the mechanism
hypothesis (e.g. expected reduction in entropy of `gate_effectiveness`). This is
the function that makes Bob pick experiments a heuristic ranker would never
prioritize.

**DO.** `mcp/lib/belief/intervention-calculus.js`: do-operator over the belief
window, predicted-effect, per-control posterior deltas, and an information-gain
ranking of candidate interventions. Confounders are explicit latent alternatives
the calculus must be able to discriminate, not prose.

**REVIEW (engineering).** Deterministic given window + seed. On the IDOR fixture,
the victim-object selector swap ranks above re-running an already-observed
attacker-owned control; on a public-object fixture, the `public_object_check`
ranks first (the model knows it cannot yet distinguish IDOR from public access).

### CB-B3 -- Active experiment loop

**ACTION.** `build_new` reasoning; dispatch is `layer_on` the existing authority.

The loop is the product in motion:

```text
1. instantiate belief window for a mechanism hypothesis (CB-B1)
2. rank candidate interventions by information gain (CB-B2)
3. dispatch the top intervention THROUGH bob_propose_hypothesis /
   the TaskGraph materializer as a Contract: production_paths = the intervention,
   a relational_value_match witness across the two runs = the control
4. observe the effect via the existing evaluator + evidence path
5. Bayesian belief update from the observed effect under the run controls
6. if a confounder remains unruled, GOTO 2 to select the discriminating control;
   if the evidence predicate is met, emit causal support (CB-C2); else stop with
   a calibrated negative
```

The loop never spawns its own dispatcher or records its own claims. It chooses,
the materializer dispatches, the evaluator observes, the claim/verification plane
adjudicates.

**DO.** `mcp/lib/belief/experiment-loop.js` as an advisory planner that emits
`propose_hypothesis` Contracts and consumes their observed outcomes; a bound on
loop iterations per hypothesis; full provenance on every belief update.

**REVIEW (field).** On authorized targets, compare object-auth hypotheses run
through the loop against the current evaluator baseline: valid-claim rate,
false-positive rate, controls-run completeness, and time-to-first verified
object-auth claim.

### CB-B4 -- Factor-graph sampler (the inference algorithm)

**ACTION.** `build_new`, first-class (not deferred).

CB-B1/CB-B2 need an inference engine to compute posteriors and information gain
over the local belief window. CB-B4 is that engine: convert the bounded window
into a small discrete factor graph and run marginal inference + information-gain
estimation. This is the THRML/Extropic-style core, and it is the reason the
capability is more than a heuristic -- it does probabilistic inference over hidden
variables, not a weighted sum of features.

Composition is a first-class output here, not an afterthought. The joint factor
graph over multiple instantiated templates searches O(K^2) pairs and bounded
O(K^d) chains of the K registry mechanisms, surfacing cross-mechanism chains no
single template predicts (IDOR x cache x reflection, SSRF x metadata x trust
boundary). This stays inside the prior's support -- no new authority, no
laundering -- and is the engine's largest reachable source of novel findings. The
same marginals feed the residual diagnostic (`CB-B6`).

**DO.** `mcp/lib/belief/factor-graph.js` with a **pure-JS deterministic sampler
first** (seeded; same seed + window hash -> same marginals within tolerance). An
optional Python/JAX/THRML backend may follow only if release policy permits and
must never become an npm install requirement. Persist `belief-samples` as scratch
with model version, window hash, seed, sample count, and aggregate marginals.

**REVIEW (engineering).** Determinism: identical seed + window reproduce
marginals. The sampler is advisory -- it cannot record claims or schedule
networked actions; it ranks frontier leaves and interventions, it is never the
authoritative order. A/B: sampler-ranked intervention selection beats the
information-gain heuristic-only path under equal budget before any default
enablement.

### CB-B5 -- Learned, calibrated factor weights

**ACTION.** `build_new` model; labels are `layer_on` the verification plane.

Train factor weights over the typed belief features, not the causal skeleton.
Labels come from the verification/claim outcomes (`confirmed`, `denied`,
`downgraded`, `reportable`, `duplicate`, `blocked_not_false`, `dead_end`,
`tooling_failure`, `environmental_failure`) -- the same line the planned I13/C13
transfer index defines.

**DO.** Offline trainer over sanitized session exports; logistic / calibrated
gradient-boosted factors exported as versioned inspectable tables; calibration
report (reliability curve, Brier, precision@K, lift over hand weights);
`bob_read_belief_model_info`.

**REVIEW (engineering).** Learned weights beat hand weights on held-out sessions
under equal budget; uncalibrated models cannot ship as default; training excludes
raw secrets and report evidence bodies.

### CB-B6 -- Residual anomaly surfacing

**ACTION.** `build_new` signal; both sinks are `layer_on` existing channels.

The reachable form of class-level novelty (see Novelty boundary). `CB-B4` already
computes, per surface, the marginal likelihood of the observed evidence under the
whole registry; expose its negative log as a deterministic diagnostic:

```text
residual(surface) = -log p(evidence | all_templates, seed, window)
```

A high residual means the modeled mechanisms explain this surface poorly -- a
candidate for an unmodeled mechanism or an unexpected composition. It is a
property of the inference run, carried under the `residual_anomaly` provenance
class, and structurally forbidden from entering `CB-B1` as a prior, `CB-B2` as a
scored latent, or `CB-C2` as claim support. It is a routing signal, never a
finding.

Two non-gating sinks, and an inverted LLM role:

- Scheduler priority hint (`CB-C1`): high-residual surfaces are scheduled earlier
  and get more of the existing iteration budget. This re-ranks within the existing
  dispatcher and caps; it dispatches nothing new and changes no authority.
- Human router: emit the residual plus a per-factor decomposition of where the
  templates mispredict, so an operator can look for an unmodeled mechanism.
- The LLM is invoked downstream, in the evaluator turn, to hypothesize in natural
  language about a flagged surface. That hypothesis is an ordinary lead that earns
  trust only through the one existing gate (`record-candidate-claim` with real
  intervention evidence); it is never a self-validated template.

**DO.** `mcp/lib/belief/residual.js` deriving the residual from the `CB-B4`
marginals (deterministic, replay-checkable); the `residual_anomaly` provenance
value; a bounded human-routed record; a priority-hint input to `CB-C1` that cannot
change dispatch authority.

**REVIEW (engineering).** Residual is a pure function of seed/window/evidence/
registry and reproduces under replay. It is high-recall, low-precision by design
(it also fires on noise and mis-specified templates), so it routes to a human and
never adjudicates. No promotion path exists; nothing is minted as a class. A
wasted investigation turn is the acceptable failure; a poisoned training
generation is not.

## Tier 3 -- Coupling (advisory, single-authority)

### CB-C1 -- Belief into the one scheduler

**ACTION.** `layer_on` (`mcp/lib/lead-scoring.js` score+rationale ->
`mcp/lib/ranking.js` `priorityFromScore` -> `mcp/lib/wave-planner.js:50`
`compareSurfaces` / graph scheduler; `queue-policy` recorded into the hash-bound
`SchedulerDecision`).

**DO.** The belief engine's expected-value-of-information becomes the intelligence
the single promotion/scheduling pipeline consumes -- belief-derived score and
`score_reasons` flow through the existing score-to-priority bridge. One gate, one
band, one `queue_policy_hash` replay; the number is now computed by the engine,
not by keyword weights. Belief-assisted mode is disableable per session.

### CB-C2 -- Causal support on claims and the verifier

**ACTION.** `extend_existing` (`record-candidate-claim` + `claims.js`
`evidence_refs[]`; `evidence.js` C10 differential; `proof-bundle.js`;
verification v2 schema + `confidence_reasons[]` + `computeAdjudicationPlanHash`).

**DO.** Add `confounders_ruled_out[]` (the one field with no analogue) to the
claim payload; bind `mechanism_id` to an OSS-FAM / CWE id, `hypothesis` to
`hypothesis_statement`, and `intervention`/`expected_effect`/`controls_run[]` to
the C10 differential + proof bundle through the existing `evidence_refs[]` kinds.
Add `unruled_confounder` / `missing_control` as deterministic
`confidence_reasons[]` enum values folded into the adjudication hash. Drop
`state_sensitive` and `intervention_replayed` from the proposal -- they already
ship.

## Net-new vs reused, explicit

```text
NET-NEW (Tier 2, the capability):
  CB-B1 latent-variable belief state + window
  CB-B2 counterfactual intervention calculus + information gain
  CB-B3 active experiment loop (belief update from observed effect)
  CB-B4 factor-graph sampler + composition search over registry templates
  CB-B5 learned calibrated factors
  CB-B6 residual anomaly surfacing (deterministic, human-routed)
  + confounders_ruled_out[] (CB-C2)
  + the principal-fixed selector-swap convention

EXPLICITLY OUT OF SCOPE:
  machine template-induction (LLM-proposed class promoted to trusted registry) --
  dominated; class invention stays a human-reviewed registry change

REUSED (Tier 1 substrate + Tier 3 plumbing):
  typed facts                 surface-graph projection (CB-1)
  mechanism template          existing corpora (CB-2)
  fact intake                 frontier-events (CB-3)
  dispatch                    propose_hypothesis / materializer (CB-B3)
  promotion / scheduling      lead-scoring gate / ranking / wave-planner (CB-C1)
  claim + verification        record-candidate-claim / verification hash (CB-C2)
```

## Hyperedges

| Hyperedge | From | To | Meaning |
| --- | --- | --- | --- |
| H1 | `CB-S1 + CB-S2` | `CB-1` | Projection needs authority separation and provenance. |
| H2 | `CB-1 + CB-2 + CB-3` | `CB-B1` | The belief window needs typed facts, a template, and intake. |
| H3 | `CB-B1 + CB-B4` | `CB-B2` | The intervention calculus needs a belief state and an inference engine. |
| H4 | `CB-B2` | `CB-B3` | The experiment loop runs on information-gain-ranked interventions. |
| H5 | `CB-B3` | `CB-C2` | Causal support and confounder verdicts come from run interventions. |
| H6 | `CB-B3 + CB-C1` | Field A/B | Scheduler lift needs the loop feeding the one gate. |
| H7 | `CB-C2` | `CB-B5` | Training labels come from verification/claim outcomes. |
| H8 | `CB-B4` | Composition | The joint sampler yields cross-mechanism chains within the prior. |
| H9 | `CB-B4` | `CB-B6` | The residual is the negative log marginal from the sampler. |
| H10 | `CB-B6` | Human / `CB-C1` | Residual routes to a human and re-ranks existing scheduling. |

## Implementation order

Each step is one PR following the repo node-shipping workflow (topology entry +
`detail/<id>.md` with anchors, a `verify-*` adversarial pass, feature PR + tests,
stigmergic producer/consumer registration, `mcp-test-manifest.json` registration,
progress-log promotion).

1. **CB-S1 + CB-S2 + CB-1.** Substrate projection + provenance/secret-safety.
   Proves the typed mechanism view with zero new stores.
2. **CB-2 + CB-3.** Object-auth template in the corpora; confirm fact intake.
3. **CB-B1.** Latent-variable belief window (hand-initialized priors). First
   net-new node -- the belief state itself.
4. **CB-B4.** The deterministic factor-graph sampler, including composition search
   (joint inference over multiple templates). Pulled forward, first-class: the
   inference engine the belief state runs on, and the largest novelty source.
5. **CB-B6.** Residual anomaly surfacing derived from the `CB-B4` marginals -- the
   reachable, deterministic form of class-level novelty, human-routed.
6. **CB-B2 + CB-B3.** Counterfactual intervention calculus and the active
   experiment loop dispatched through `propose_hypothesis`. This is where Bob
   starts doing experiments the heuristic ranker would never choose.
7. **CB-C2.** Causal support + confounder verifier signals on the claim/
   verification plane.
8. **CB-C1.** Belief as the intelligence behind the one scheduler/gate.
9. **CB-B5.** Learned calibrated factors over verification outcomes (needs labels,
   so last).

## Progress Log

| Date | Node | Status | Review evidence |
| --- | --- | --- | --- |
| 2026-06-13 | `CB-S1` | `done` | `node --test test/belief-authority.test.js`; `npm run check:syntax`; `npm run check:stigmergy-coherence`; `npm run test:mcp`; `npm run test:prompts`; `verify-CB-S1-authority: PASS` |
| 2026-06-13 | `CB-S2` | `done` | `node --test test/belief-authority.test.js`; `npm run check:syntax`; `npm run check:stigmergy-coherence`; `npm run test:mcp`; `npm run test:prompts`; `verify-CB-S2-provenance-secret-safety: PASS` |
| 2026-06-13 | `CB-1` | `done` | `node --test test/surface-graph.test.js test/surface-graph-builder.test.js`; `npm run check:syntax`; `npm run check:stigmergy-coherence`; `npm run test:mcp`; `npm run test:prompts`; `verify-CB-1-mechanism-projection: PASS`; `verify-CB-1-no-mechanism-graph-store-in-runtime: PASS` |
| 2026-06-13 | `CB-2` | `done` | `node --test test/invariant-template-corpus.test.js test/oss-rootcause-family-index.test.js test/cwe-catalog.test.js`; `npm run check:syntax`; `npm run check:stigmergy-coherence`; `npm run test:mcp`; `npm run test:prompts`; `verify-CB-2-object-authorization-template: PASS` |
| 2026-06-13 | `CB-3` | `done` | `node --test test/belief-frontier-facts.test.js test/frontier-observation-ledger.test.js test/frontier-projections.test.js test/mcp-test-discovery.test.js`; `npm run check:syntax`; `npm run check:stigmergy-coherence`; `npm run test:mcp`; `npm run test:prompts`; `verify-CB-3-frontier-typed-facts: PASS` |

## Completion gates and metrics

The work is complete when it improves Bob under equal budget, and specifically
when Bob runs interventions a heuristic ranker would not. Track outcome metrics
(`valid_claims_per_evaluator_turn`, `verified_to_recorded_claim_ratio`,
`duplicate_claim_rate`, `time_to_first_verified_claim`, `verifier_overturn_rate`)
plus object-auth specifics (`object_auth_valid_claim_rate`,
`object_auth_missing_control_rate`, `object_auth_cache_confounder_rate`,
`object_auth_replay_stability`) and the engine's own signals
(`expected_vs_realized_information_gain`, `interventions_to_first_confirmation`,
`confounders_ruled_out_rate`, `composition_chain_yield`,
`residual_routed_anomaly_hit_rate`).

The potency test -- which side of the line we are on:

- Fallback (rejected): the "model" is a weight table whose output nudges
  lead-scoring. If CB-B1..B4 reduce to features, we built a slightly better
  heuristic.
- Realized (target): the engine maintains a calibrated belief over latent
  mechanism variables and selects interventions by expected information gain,
  running experiments the heuristic would never prioritize, and demonstrating
  equal-budget lift on object-auth valid-claim rate and time-to-first-confirmation.
- Novelty, honestly scoped: the machine surfaces residual anomalies and composes
  known mechanisms into novel chains; it never certifies a new mechanism class.
  Class invention reaches the registry only through human review.

Invariants that must hold at every gate: one graph store; one promotion gate fed
by the engine; one dispatch authority; one disposition axis and verification
hash; deterministic replay end to end including under sampling; belief outputs
provenance-tagged, secret-safe, scratch, and recomputable; no machine-invented
mechanism class is ever promoted to trusted registry authority.
