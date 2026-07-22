# Bob Physical-Security Task Hypergraph (Plane-PH)

Plane-PH is the engineering roadmap for making physical pentesting a first-class
Hacker Bob capability. It is deliberately environment-agnostic: no hotel,
campus, lock vendor, controller, or hardware brand appears in core authority,
technique, evidence, outcome, or finding abstractions. Brand-specific detail is
confined to provider nodes and provider coverage.

The attached Chameleon Ultra is the first hardware-in-loop provider and the
first complete acceptance envelope. It is not the capability boundary.

## Read in this order

1. [`task-hypergraph.md`](task-hypergraph.md) — architecture, capability
   coverage, critical paths, tier gates, implementation order, and risks.
2. [`nodes.json`](nodes.json) — machine-readable task register and live
   readiness state.
3. [`hyperedges.json`](hyperedges.json) — N-to-M dependency edges, cut sets,
   and parallel workstreams.
4. [`coverage.json`](coverage.json) — provider-to-operation-to-technique
   traceability, including explicit unsupported and operator-owned surfaces.
5. [`adversarial-review.md`](adversarial-review.md) — defects exposed by the
   architecture challenge, accepted corrections, preserved strengths, and the
   claims the roadmap still cannot make.

## Vocabulary

- **S — substrate/authority:** contracts every physical capability must obey.
- **I — index/projection:** bounded, deterministic views over instruments,
  assets, techniques, attempts, and reachability.
- **IP — ingestion path:** scope, observations, and instrument artifacts entering
  Bob-owned state.
- **P — provider:** a hardware/transport implementation of normalized instrument
  operations. This is intentionally distinct from a security capability.
- **C — capability:** an evaluating mode that exercises a security hypothesis and
  can produce a verified finding.
- **X — cross-cutting:** generated surfaces, redaction, packaging, conformance,
  and hardware-in-loop resilience.
- **H — hyperedge:** N predecessors jointly unlocking one or more tasks.

## Non-negotiable distinction

```text
device command
    -> provider operation
        -> pentest technique
            -> controlled experiment
                -> differential verification
                    -> finding
```

No evaluator-originated operation that can affect a target may skip another. In
particular:

- device command IDs never become model-facing Bob tools;
- provider support never implies a technique is applicable;
- a successful instrument response never proves a physical effect;
- a human or controller observation never becomes a finding without a control;
- possession of hardware never expands engagement authority.

Inventory/provenance, health, snapshot/restore, and operator maintenance follow separate
broker-lifecycle paths. They are still authority-bound and ledgered, but they do
not masquerade as pentest techniques and cannot mint findings.

## Status

`v0.3-proposed` records the task topology plus a package-safe implementation
ledger. No Chameleon command or RF action was executed while producing or
reconciling this graph. The five root nodes are `in_review`; all other readiness
is derived from predecessor completion. A node
cannot be marked `done` until its engineering gate has evidence and every
declared HIL gate has evidence or an explicit signed waiver. A waiver is only a
degraded/experimental tracking disposition: every node listed in
`production_nonwaivable_hil_node_ids` requires passed HIL evidence before it can
close, and `PH-X8` refuses a production release while any such gate is waived or
missing. Run
`npm run check:plane-physical` to validate references, readiness, acyclicity,
typed gate-reference schemes, exact upstream command and semantic ownership,
closed operation/technique/assurance/proof-provider registries, exact
per-operation/per-technique command variants, reviewed node/hyperedge digests,
RF and maintenance effect bounds, provider coverage, and C-node brand/context
leak checks. Runtime advancement must additionally resolve and verify the
signed evidence object from Bob-owned session state; package-safe ref syntax is
not evidence existence. The current package graph deliberately contains no live
evidence refs; candidate implementation progress, failed gates, and current
blocker ownership are summarized in `task-hypergraph.md`.
