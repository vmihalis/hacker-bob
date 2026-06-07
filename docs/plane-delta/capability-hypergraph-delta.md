# Bob Capability Hypergraph — Post-v2.1 (codename **Plane-Δ**)

*Topology layer, **v2-verified 2026-06-07**. Composed from `docs/COMPETITOR_ANALYSIS.md` + a frontier pass, expressed in Bob's own hypergraph vocabulary (`docs/capability-hypergraph.md`), then hardened by an adversarial code-grounded verification pass (`verification/WEAVE.md`). This is the **topology**; per-node `do→review` specs are the **progressive-detail** phase that follows.*

---

## Two silent regressions (the structural headline — both code-verified)

The v2 graph is documented as *realized*, but verification against HEAD found **two shipped nodes silently gone**, their consumers left wired and inert:

1. **I9 (reachability producer)** — dropped at the Plane-O (v2.1) merge. Consumers in `assignment-brief.js:134-141`, `wave-brief-derivation.js`, `dashboard.js:186-189` still reference `severity_ceiling`/`network_reachable`; nothing writes them. `repo-target.js:752` has no producer. Recover ancestor blob `d1647c0`(+`1a456f1`).
2. **I6 (findings-index)** — **deleted in commit `c02179c`** ("Delete finding-store, findings-index, findings: claims is solo"), yet `capability-hypergraph.md:194-206,570-572` still says it shipped "Engineering-complete." No embeddings, no `bob_index/query` tools, no `priors_slice`, `calibration_label` gone. The cross-target prior survives **only** as the orphaned, unconsumed `claim-clusters.js mergePriorClaimMatches`.

These are not just gaps — they're **doc-vs-code drift** that the test/CI substrate failed to catch. That failure-class is itself a Δ1 node (**S12**) and two doc-fixes (**DOC-1/DOC-2**).

---

## Thesis

**Δ = Differential, Defensible, Distinguished.** (1) Close the OSS severity ceiling the dropped producer left open; (2) make every HIGH *provable* and make Bob *measured + self-defending*; (3) spend the **existing** index substrate (I1/I3/I5/I7, content-addressed evidence, wave system, **6-VM smart-contract** stack) on capabilities no agentic pentester ships today. Inherited principle: *graph-shaped state with tool-mediated dereferencing, not context width.*

---

## Node register (verified)

Legend: ✅ keep · ✏️ revised · ✂️ split · ➕ new (verification-surfaced) · ⛔ demoted. Anchors are code-verified unless marked *(assumed)*.

### Slab — substrate (S11–S15)
| ID | Title | Δ | Verdict | Anchor / fix |
|----|-------|---|---------|--------------|
| **S15** | OSS-container substrate (register) | Δ1 | ➕ | **Missing S-node.** Register shipped Plane-O substrate (`bob_repo_prepare_env`/`repo_docker_run`/`init_repo_session`, `--network none`, init-never-clones, `/work` staging). Fixes the systemic S6 mislabel. |
| **S12** | Test-manifest + consumer-registration integrity | Δ1 | ✏️ | Extend `test/mcp-test-discovery.test.js` (drop `mcp-` filter) + register reachability fields in `stigmergic-consumers.js`. **Absorbs demoted X9.** Same-PR fast-follow to I9, not a strict blocker. |
| **S13** | Untrusted-content envelope | Δ2 | ✅ | new `mcp/lib/untrusted-envelope.js` (nonce like `session-cap.js`). pred S7→**S10**. |
| **S14** | In-container differential checkout | Δ2 | ✏️ | NOT an init clone-flag (violates O-P1). New `git checkout`/`apply` on `/work` mount + shallow-clone guard. pred→**S15**. |
| **S11** | Cross-session label/metric store | Δ4 | ✏️ | Extend **existing** cross-session substrate (`pipeline-analytics.js` `cross_session`, `cross_session_read` authority, `sensitive-material.js`). re-typed net-new→adopt; no new dir. |

### Pillars — indexes (I9–I13)
| ID | Title | Δ | Verdict | Anchor / fix |
|----|-------|---|---------|--------------|
| **I9** | Source reachability index | Δ1 | ✅ | RESTORE from blob `d1647c0`. **FIRST** fix broken `repo-target.test.js` require (`hunter-completion.js`→`agent-run-completion.js`). pred→**S15**. |
| **I12-plumbing** | Finish orphaned `ossTechniquePacks` consumer | Δ1 | ✂️ | `assignment-brief.js:403` references it with no producer. Cheap ride-along; unlocks I12 content. |
| **C14-lite** *(listed under C)* | Disclosure metadata | Δ1 | ✂️ | (see Capabilities) |
| **I10** | Static-analysis finding index (SARIF) | Δ3 | ✅ | new `static-analysis-index.js`; **runner already ships** (`cli-tool-packs.js` semgrep/trivy) — only SARIF ingest is new. pred→IP7,**S15**. |
| **I12** | OSS root-cause family index | Δ3 | ✂️ | Extend shipped **I5** `invariant-template-corpus.js` shape; +2 families (crypto-ordering, validate-vs-consume). `technique-packs.js:92`. |
| **I11** | Calibration ledger / trust cells | Δ4 | ✅ | Labels from grade verdicts+adjudication (the I6 `calibration_label` slot is **gone**). Gate = engineering/fixture; long-horizon. |
| **I13** | Cross-target transfer index | Δ4 | ✏️ | I6 deleted → repoint to **claims subsystem** (`claims.js`+`claim-clusters.js`); cross-target retrieval-into-brief must be **rebuilt**, not assumed. pred I1,I3,claims. |

### Pillars — ingestion (IP7–IP9)
| ID | Title | Δ | Verdict | Anchor / fix |
|----|-------|---|---------|--------------|
| **IP8** | Fuzz-seed corpus ingest | Δ1-lite/Δ3 | ✅ | `fuzz` role declared `repo-env.js:141`, **never emitted** by `recommendedCommandsFor` (~`:207`). pred→S15. |
| **IP7** | SARIF ingest path | Δ3 | ✏️ | Narrowed to ingest-only (runner ships). May merge into I10. pred→S15. |
| **IP9** | Continuous CVE/commit feed | Δ4 (policy) | ✏️ | NOT thin: IP3 watcher unbuilt + **no scheduler substrate**; resurrects vacated C8; strains the two-turn human-gated design. |

### Roof — capabilities (C9–C17)
| ID | Title | Δ | Verdict | Anchor / fix |
|----|-------|---|---------|--------------|
| **C9** | OSS severity-ceiling closure (grade-time lift) | Δ1 | ✏️ | NEW grade-time lift/**cap** gate in `grade-verdict-store.js`/`lifecycle-gates.js`. Drop already-shipped chain elevation (`chain.md:8-10,49`). **Cap, never kill.** |
| **C14-lite** | Disclosure metadata (CWE/CVSS/refs) | Δ1 | ✂️ | Prompt-only; adopt-extend the existing SC CWE table (`reporter.md:49-57`) into OSS branch (`:28-31`). No predecessor; doesn't move the Δ1 gate. |
| **C10** | Patched-vs-unpatched differential proof | Δ2 | ✅ | differential evidence row in `write-evidence-packs.js`+`evidence.js`. pred S14. |
| **C14** | Proof-carrying disclosure (bundle) | Δ2 | ✂️ | machine-checkable bundle. **Dropped I12 predecessor** (tier inversion). pred C10 only. |
| **C11** | Static-driven source audit | Δ3 | ✅ | **Heaviest fan-in** (I9+I10+IP7+I12). `lead-promotion.js`+OSS lens. |
| **C12** | Coverage-guided fuzzing maturity | Δ3 | ✏️ | re-typed adopt→net-new; emitter is `recommendedCommandsFor:207` (not `:141` enum). **Unblocks C9's harness dep.** |
| **C13** | Cross-target finding transfer | Δ4 | ✏️ | needs `bob_init_session(targetB)`+`bob_start_wave`+**hard scope-auth gate in dispatch** (not prompt). rests on claims. |
| **C15** | Adversarial self-patch loop | Δ4 | ✅ | invariant: a fixed-PoC patch must **never** auto-suppress the pre-patch finding. |
| **C16** | Cross-VM invariant/finding transfer | Δ4 | ➕ | **Uniquely Bob (6 VMs).** Confirm an invariant on one VM → transfer to the protocol's Move/SVM/CosmWasm deployment. pred I5,I7,I13. |
| **C17** | Proof-carrying regression sentinel | Δ4 | ➕ | Re-run a fixed finding's C14 bundle on each new commit/CVE; alert on re-introduction. Serves the disclosure campaign. pred C14,IP9,S1. |

### Cross-cutting (X6–X10)
| ID | Title | Δ | Verdict | Anchor / fix |
|----|-------|---|---------|--------------|
| **X7** | Evaluator-run-avoided telemetry | Δ2 | ✂️ | Descriptive count; needs neither S11 nor I11. `evaluator_run_avoided` via `pipeline-events.js`. |
| **X10** | Reasoning-divergence adjudication | Δ2 | ➕ | Deterministic `artifact_hashes` mismatch flag (no LLM diff) into `verification.js findingDiffs:471-473`. |
| **X6** | Agent self-security | Δ2 | ✅ | wire S13 into `assignment-brief.js` slices + `body-resolvers/index.js` + system preamble. |
| **X8** | Live in-run observability (SSE) | Δ4 polish | ✅ | SSE **upgrade** over existing `/api/snapshot` poll; `dashboard.js`. |
| **X7b** | Cost-per-finding telemetry | Δ4 | ✂️ | needs a token-telemetry substrate Bob **lacks**. |
| **X9** | ~~Orphaned-consumer CI~~ | — | ⛔ | **Already shipped** as `check-stigmergy-coherence.js`. Folded into **S12** (register reachability fields). |

---

## Hyperedge map (corrected)

```
S15 (register OSS substrate) ──► S14, I9, I10, IP7, IP8, C10, C12   ← fixes the systemic S6 mislabel
S12 (+folded X9) ··fast-follow··► I9        DOC-1/DOC-2 correct the two stale "shipped" claims

S12 → I9 (reachability) → C9 (grade-time lift/cap) ─────► defensible HIGH/CRIT
                              └─ augments ─► C11
S14 → C10 (differential) ─┬─► C14 (proof-carrying bundle) ─┐
                          ├─► C15 (self-patch loop)        ├─► C17 (regression sentinel)
                          └────────────────────────────────┘         ▲
                                                              IP9 ─────┘ (+ S1)
IP7 → I10 ─┐
I9   ──────┼─► C11 (static-driven audit)      I12 ─augment─┘   (heaviest fan-in)
I12  ──────┘
I5 ─┐
I7 ─┼─► C16 (cross-VM transfer)   ← fan-in over SHIPPED I5+I7, uniquely Bob
I13 ┘
I1 ─┐
I3 ─┼─► I13 → C13 (cross-target transfer)     (I6 deleted → rebuilt on claims subsystem)
claims ┘
S13 → X6 (self-security)   IP8 → C12 (fuzzing, unblocks C9 harness)
S11 → I11 → X7b ;  lead-scoring → X7 (descriptive savings)
verification-spine → X10 (deterministic reasoning-divergence)
```
Machine-readable: `hyperedges.json`. Nodes: `nodes.json`.

---

## Tiered sequencing (gated on real-target findings)

### Tier Δ1 — Close the OSS severity ceiling *(highest value-to-effort)*
**Nodes:** S15 (register) · I9 (restore, repair broken test first) · S12 (+X9 fold) · C9 (grade-time lift/cap) · DOC-1/DOC-2. **Ride-alongs (prompt-only):** C14-lite (CWE/CVSS/refs), IP8-lite (fuzz-seed lens), I12-plumbing (wire `ossTechniquePacks`).
**Δ1 readiness — NOT cleanly ready; clear these first (verification):**
1. Fix broken `repo-target.test.js` require before "re-arming" anything.
2. Re-anchor S12 to `mcp-test-discovery.test.js`; demote to same-PR fast-follow (not strict blocker).
3. Trim C9 to the grade-time gate only (drop shipped chain elevation); enforce **cap-not-kill**.
4. Resolve the S15 (OSS-container) predecessor that I9 inherits.
5. **Gate-resourcing risk:** the "maintainer-accepted defensible HIGH" gate couples to Δ3 work (record-time proof-gate downgrades on harness block; compiler-rt fix is in **C12/Δ3**). Either widen C9 to the record-time path, or **soften the Δ1 gate to "stamp present + consumed + lifted in grade"** and move the maintainer-accepted-HIGH milestone to the Δ1/Δ2 boundary. Otherwise a blocked harness stalls the whole ladder at Δ1.

### Tier Δ2 — Make HIGHs provable + harden the agent
S14→C10→C14 · S13→X6 · X7 (savings) · X10 (reasoning-divergence) · X8 (polish, may slip Δ4).
**Gate:** differential proves a residual on a real target (rebuts "already fixed"); a proof-carrying bundle accepted by a maintainer/triager.

### Tier Δ3 — Static-analysis depth + fuzzing maturity
IP7→I10, I12, with I9 → C11 · IP8→C12.
**Gate:** ≥1 finding from a static lead blind hunting missed; fuzz throughput measurably up; **C12 unblocks C9's harness dependency**.

### Tier Δ4 — Compounding + frontier *(measured, cross-domain, never-before-seen)*
S11+I11+X7b · I13→C13 · **C16 (cross-VM)** · C15 (self-patch) · C17 (regression sentinel) · IP9 (policy-gated) · X8.
**Gate (engineering/fixture, long-horizon):** calibration persists labels + Wilson read returns a bound; cross-target transfer confirms a family on a 2nd authorized target; C16 transfers an invariant across two VM deployments.

---

## Excluded by doctrine (the honest boundary — see `nodes.json` excluded_by_doctrine)
SMT-unsat / not-in-CVE-DB auto-skips · FP prefilter before brutalist verifier · exemplars into the hunt brief · CSAI brute-force RAG + in-memory bus · wholesale binary-oracle import · smt-feasibility (corroboration-only park) · osv-scanner SEED_PACK (park) · 148-tool schema to all hosts (park / X6 sub-item) · browser DOM access-control differential (out of Δ scope; document).

---

## Confidence (from `verification/WEAVE.md`)
- **Code-verified this session:** both regressions (I9 producer drop, I6 deletion `c02179c`); inert consumers; broken `repo-target.test.js`; S12 partial in `mcp-test-discovery.test.js`; X9 shipped in `check-stigmergy-coherence.js`; semgrep/trivy runner in `cli-tool-packs.js`; unemitted fuzz role; S14 no-clone/`--network none`; `bob_static_scan` token-only; existing cross-session substrate; `envelope.js` name collision.
- **Still assumed:** most exact line numbers; IP3-watcher/scheduler absence; C9's missing grade gate; the I11/X7b "dormant at operator volume" claim; all external-tool competitive provenance. **No dependency cycle found.**

## Build protocol
1. Topology — **DONE, verified.** 2. Verification — **DONE** (`verification/`). 3. Progressive detail — `detail/<id>.md` per node, Δ1 first. 4. Promotion — detailed node → PR + `capability-hypergraph.md` progress log.
