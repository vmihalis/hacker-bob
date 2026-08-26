# CB-B7 -- Evidence-conditioned belief elicitation primitive

## Contract

Bob runs inside a host coding-agent session tasked with a target, so the host agent
IS the estimator. Elicitation is the agent emitting, during the turn it is already
taking, a distribution over one latent's declared states with cited `evidence_refs`.
No separate model, no separate inference budget. The engine is the deterministic,
provenance-disciplined shell around that judgment; it never makes an LLM call.

## What it does

- `bob_elicit_belief` (`mcp/tools/elicit-belief.js`): the host agent records a
  belief. The tool hardcodes `provenance: "llm_inferred"`, `role: "prior"` and writes
  through `writeBeliefSignalScratch` -- advisory scratch only.
- `normalizeElicitation` (`elicitation.js:39`): validates a proper distribution over
  exactly the declared states (sums to 1, each in [0,1], >=2 states), requires cited
  `evidence_refs`, bounds the rationale. A rubber stamp would not reject these.
- The honesty rail (`authority.js:136`): an `llm_inferred` signal can never be
  `role: "evidence"` -- default-role included. The tool cannot override it.
- `evidenceSensitivity` (`elicitation.js:115`): the acceptance gate -- a belief that
  stays flat on a relevant evidence change FAILS; one that moves on an irrelevant
  change FAILS; one that moves away from the expected state FAILS.

## The gate is an eval harness, not a per-call guard

`evidenceSensitivity` is deliberately not wired into the per-call tool path: an
individual elicitation is non-binding advisory scratch, so there is nothing to reject
at write time. The gate polices the *agent's* sensitivity across a before/after
fixture (or a CI battery / a real session): flip one cited `evidence_ref` and the
agent's elicited distribution must move toward the right state; flip an irrelevant
field and it must stay flat. A belief invariant to its evidence is the regex with a
`model_id`. This is the line CB-B7 exists to enforce.

## Review

**Engineering (PASS).** elicitation lib 7/7 + tool integration 2/2 + role-guard case
in belief-authority (6/6); `mcp-server` 458/458 (tool registration, EXPECTED_TOOL_NAMES
deepEqual, capability map); `check:syntax` / `check:agent-tools` / `check:skill` /
`check:stigmergy-coherence` clean. Independent adversarial verify PASS: honesty rail
closed (no path records `llm_inferred` as evidence, incl. default-role and
tool-override attempts); gate fails a constant on relevant evidence; advisory-only on
all axes; the elicited belief reaches no claim/verification/grade artifact (the
scheduler reads only `residual_anomaly`/`diagnostic`).

**Field (DEFERRED, rationale).** Whether a *real* host agent produces evidence-sensitive
distributions is a runtime validation: it needs live sessions / a fixture battery. The
gate that will enforce it is built and unit-tested; the deferral is the live run, not
the logic.

## Authority

Advisory, derived, scratch. `mutating:true` (writes only `belief-scratch/belief-signals.jsonl`),
`network_access:false`. Records solely through `writeBeliefSignalScratch`, which refuses
audit-graded paths. Cannot record claims, schedule, or promote templates.

## Unlocks

`CB-B1` (the belief window consumes the elicited prior instead of the regex) and,
through it, `CB-B2`/`CB-B4`.
