# Bob Plane-B hypergraph (causal belief)

The causal-belief roadmap (`../causal-belief-hypergraph.md`) expressed as a machine-readable
task hypergraph the `/goal` driver walks to completion, one node at a time, through
DO -> REVIEW cycles.

## Read in this order

1. **`../causal-belief-hypergraph.md`** — the spec: the two-tier principle (reuse the
   substrate, build the inference engine), every CB node's DO / REVIEW, the guardrails,
   the novelty boundary, and the invariants. Start here.
2. **`nodes.json`** — the node register (topology + live status + DO/REVIEW + findings).
3. **`hyperedges.json`** — the fan-in/fan-out edges (`H1`-`H10`).
4. **`detail/<id>.md`** — one code-grounded spec per node, written when the node is built.

## What makes this a status board, not just a topology

Plane-Δ (`../plane-delta/`) keeps `nodes.json` as a *proposal topology* and tracks "done"
out-of-band in the progress log. This register intentionally goes further: each node
carries a live `status` and a `findings[]` array, so the hypergraph itself is the single
source of truth `/goal` reads and writes. Completion and emergent work live in the graph.

- `status`: `blocked` -> `ready` -> `in_progress` -> `in_review` -> `done`.
- `ready` rule: a node is `ready` iff every predecessor is `done`. `/goal` recomputes this
  every cycle; never trust a stale value.
- `findings[]`: issues surfaced during DO or REVIEW. A *structural* finding (a missing
  substrate, a new test class, a discovered regression, an ABI conflict) is minted as a
  **new node** with wired predecessors/unlocks — the graph grows to absorb what the work
  reveals.

## The DO -> REVIEW contract

Each node is realized by one cycle:

```text
SELECT (next ready node)
  -> DO        implement node.do against node.anchor; spec + tests + manifest +
               stigmergic registration; repo node-shipping workflow
  -> REVIEW    engineering gates (node.review.engineering + focused suites + a verify-*
               adversarial pass) MUST pass; field gates (equal-budget A/B) passed or
               explicitly deferred
  -> RECORD    status=done only on pass; append findings; mint new nodes for structural
               findings; propagate ready to successors
  -> COMMIT    one PR per node, progress-log promotion
  -> LOOP
```

A node never reaches `done` on assertion; only on cited REVIEW evidence.

## Run it

The DO -> REVIEW driver is a paste-able prompt (kept short on purpose), not a slash
command. Paste it and name a target node, or let it pick the next `ready` one. Its
contract: SELECT next ready node -> DO (implement against `anchor` + spec/tests/manifest/
stigmergic registration) -> REVIEW (engineering gates + `verify-*` pass; field A/B) ->
RECORD (status + mint nodes for structural findings) -> propagate -> commit -> loop.

## Current frontier

Ready now (no predecessors): `CB-S1`, `CB-S2`, `CB-2`, `CB-3` (substrate, all layer-on).
The first engine node `CB-B1` unblocks once `CB-1` + `CB-2` + `CB-3` are `done`.

## Out of scope (doctrine)

Machine template-induction (an LLM-proposed mechanism class self-validated and promoted to
the registry) is excluded — see `excluded_by_doctrine` in `nodes.json` and the Novelty
boundary in the spec. Class invention reaches the registry only through human review.

## Durability

The tracked home is branch `docs/causal-belief-layer-on` (isolated worktree), not the main
worktree, which a concurrent merge keeps churning. If the working copy disappears, restore
from that branch or the backup before running `/goal`.
