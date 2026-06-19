# Bob Plane-Δ hypergraph (post-v2.1 capability roadmap)

The **post-v2.1 Bob capability hypergraph**, composed in Bob's own S/I/IP/C/X/H formalism (`../capability-hypergraph.md`), adversarially verified against live code, and detailed to one `do→review` spec per node.

**Codename Plane-Δ = Differential, Defensible, Distinguished.** Provenance: `../COMPETITOR_ANALYSIS.md` (+ APPENDIX) + a frontier pass. Memory: `project_competitive_analysis_raptor_csai_poclab`.

## Read in this order
1. **`capability-hypergraph-delta.md`** — the topology: node register, hyperedge map, tier sequencing, gates, doctrine boundary, two confirmed regressions. **Start here.**
2. **`detail/IMPLEMENTATION-ORDER.md`** — 26-PR dependency-ordered build plan, the Δ1 critical path, the gate-resourcing decision, and a 7-item risk register.
3. **`detail/<id>.md`** — 30 code-grounded specs (Spec contract · what it does · failure mode · predecessors/unlocks · build slices with real file:line · engineering review · parishioner gate · context budget · risks/doctrine). Index: `detail/INDEX.md`.
4. **`detail/COHERENCE.md`** — cross-spec reconciliations to apply **before building each sibling pair** (ABI contracts, shared stores, shared emitters).
5. **`verification/`** — the adversarial verification reasoning (per-kind verifiers + critic + weave) that hardened the topology.
6. **`nodes.json` / `hyperedges.json`** — machine-readable node + edge lists.

## Vocabulary (`../capability-hypergraph.md`)
S = slab/substrate · I = index · IP = ingestion path · C = capability · X = cross-cutting · H = hyperedge. New numbering continues the shipped series (S11+/I9+/IP7+/C9+/X6+).

## Two confirmed regressions (code-verified)
- **I9** reachability/severity-ceiling producer — dropped at the Plane-O merge; consumers wired + inert. Recover blob `d1647c0`.
- **I6** findings-index — **deleted in `c02179c`** but still documented as shipped. Cross-target prior survives only as orphaned `claim-clusters.js mergePriorClaimMatches`.

## Phase state
1. Topology — **DONE** (v2-verified).
2. Verification — **DONE** (`verification/`).
3. Progressive detail — **DONE** (30 specs in `detail/`, all 4 tiers).
4. Promotion to repo — **DONE** (this dir; untracked, not committed).
5. **Δ1 — SHIPPED** (PR #73 S15+DOC · #74 I9+S12 · #75 C9 · #76 PR4 ride-alongs C14-lite/IP8/I12-plumbing · #79 integrated onto `main`). Each shipped node is promoted in `../capability-hypergraph.md`'s progress log (the authoritative done-tracker; this `nodes.json`/`hyperedges.json` graph stays a *proposal* topology, not a per-node status board).
6. **In flight:** PR #80 — reachability-provenance (issue #78), the I9-prov Δ2 lead extending the shipped I9/C9 (spec: `detail/reachability-provenance.md`). Must land before C14 (the asserted `attack_vector` feeds C14's disclosure-bundle CVSS).
7. **Next (Δ2):** differential-proof thread S14 → C10 → C14; hardening thread S13 → X6; cheap parallel X7 / X10.
