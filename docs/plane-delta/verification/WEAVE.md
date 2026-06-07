Verification confirmed the single contested fact and surfaced a second silent regression. Here is the consolidated corrections digest.

## Verdict roll-up

| Node | VERDICT | Most important reason |
|------|---------|------------------------|
| **S11** | revise | Cross-session read substrate already exists (`pipeline-analytics.js` `mode:"cross_session"`, `cross_session_read` authority class, `sensitive-material.js` sanitizers); re-type `adopt`, drop the new `~/.cross` dir, the "parked I6 prereq" rationale is stale. |
| **S12** | revise | ~80% shipped in `test/mcp-test-discovery.test.js` (entry-exists :28, dup :26, sync :31) but only for `mcp-`-prefixed tests; re-anchor to extend that file, not a new `check-manifest-integrity.js`. |
| **S13** | keep | Genuinely new — no datamarking exists anywhere; `envelope.js` is the unrelated `ToolError` wrapper. Only fix: predecessor S7→S10. |
| **S14** | revise | Clone-flag anchor violates Plane-O O-P1 ("never used to clone", `--network none`); reframe as net-new in-container `git checkout` on `read_write`/`/work` staging; bump effort off "adopt". |
| **I9** | keep | Strongest, best-evidenced node; producer truly dropped, consumers inert — but "re-arm tests" must first fix `repo-target.test.js`'s broken `require('../mcp/lib/hunter-completion.js')`. |
| **I10** | keep | Net-new — `bob_static_scan` is token-contract only; zero SARIF footprint. Clean index→C11. |
| **I11** | keep | Clean non-binding ledger — but source labels from grade verdicts + adjudication, NOT the I6 `calibration_label` slot (now deleted, verified). |
| **I12** | split | Finishing the orphaned `ossTechniquePacks` consumer is a cheap Δ1 ride-along; only the named families + witnesses are real Δ3. |
| **I13** | revise | Predecessor I6/`findings-index.js` was deleted (commit `c02179c`); repoint to the claims subsystem; bigger than "cheap because indexes exist." |
| **IP7** | revise | Runner half already ships (`cli-tool-packs.js` semgrep/trivy via `bob_repo_docker_run`); net-new is only SARIF ingest; wrong S6 predecessor; consider merging into I10. |
| **IP8** | keep | Unused `fuzz` role verified (declared `repo-env.js:141`, never emitted by `recommendedCommandsFor`); fix S6 predecessor + the `:141`→emitter-body line nit. |
| **IP9** | revise | Not "thin": IP3 watcher is unbuilt, Bob has no scheduler substrate, it resurrects the deliberately-vacated C8 and strains the two-turn human-gated design. |
| **C9** | revise | Drop already-shipped chain severity elevation (`chain.md:8-10,49`); keep only the grade-time reachability lift; ceiling must CAP, never kill. |
| **C10** | keep | Net-new differential evidence-pack extension; doctrine-aligned residual proof. |
| **C11** | keep | Net-new SARIF→lead path; flag heaviest dependency depth (I9+I10+IP7+I12 all gate it). |
| **C12** | revise | Mis-anchored (`:141` is the enum, emitter is `recommendedCommandsFor:207`); fuzz lens already in `evaluator.md`; this is net-new Δ3-heavy, not "adopt". |
| **C13** | revise | Anchor incomplete — cross-target transfer also needs `bob_init_session(targetB)` + a hard scope gate enforced in the dispatch routine; rests on claims, not `findings-index`. |
| **C14** | split | Lite (CWE/CVSS/refs) is adopt-extend of the existing SC CWE table (`reporter.md:49-57`), Δ1; only the bundle is net-new Δ2 — and drop the Δ3 I12 predecessor (tier inversion). |
| **C15** | keep | Largest-effort Δ4; encode "a patch that fixes the PoC must never auto-suppress the pre-patch finding"; scope strictly as the iterate-until-robust controller. |
| **X6** | keep | Real gap (no self-defense datamarking); add `mcp/lib/body-resolvers/index.js` to the anchor for the output-fencing path. |
| **X7** | split | Per-session `evaluator_run_avoided` count needs neither S11 nor I11 (Δ2 ride); `$`-cost-per-finding is a separate token-telemetry substrate Bob lacks (Δ4). Keep the "descriptive-only" guard. |
| **X8** | keep | SSE *upgrade* over the existing `/api/snapshot` poll; file-backed tail respects `X-rej-4`. (Critic disputes tier → Δ4.) |
| **X9** | demote-already-covered | Mechanism is shipped + CI-wired as `check-stigmergy-coherence.js` (`checkAssertionC/A/B`); the new `check-orphaned-consumers.js` would duplicate it. Real work = manifest coverage; fold into the stigmergy gate (and arguably merge with S12). |

## Must-fix before progressive detail

1. **I6 is a phantom at HEAD — second silent regression (the structural headline).** *(Code-verified by me this session.)* The shipped doc claims `findings-index.js` shipped "Engineering-complete" (`capability-hypergraph.md:194-206,570-572`), but commit `c02179c "Delete finding-store, findings-index, findings: claims is solo"` removed it. At HEAD: no `findings-index.js`, no embeddings/cosine, no `bob_index_candidate_claim`/`query` tools, no `priors_slice` in `assignment-brief.js`, `calibration_label` gone. The cross-target prior primitive survives as `claim-clusters.js mergePriorClaimMatches` but is **unconsumed** (orphaned producer); only `readClaimClusters` is live (`claim-freeze.js`, within-session). **Fix:** (a) correct the I6 status in the shipped doc; (b) repoint I13/C13 predecessor from "findings-index" to the claims subsystem (`claims.js` + `claim-clusters.js`), noting the cross-target *retrieval-into-brief* must be re-wired, not assumed live; (c) keep I11 sourcing labels from grade verdicts/adjudication (the calibration slot is gone). This reconciles the three reports' disagreement: the capability shipped (critic/C right) but the anchor file is deleted and the consumer is inert (I-verifier right).

2. **Systemic S6 predecessor mislabel across the OSS cluster (S14, I9, I10, IP7, IP8).** S6 = `bob_import_static_artifact` (`capability-hypergraph.md:51`), not the Plane-O container substrate (`bob_repo_prepare_env`/`bob_repo_docker_run`/`bob_init_repo_session`), which has **no S-node in either graph**. *Fix:* add that missing OSS-container S-node and re-point all five predecessors to it.

3. **S14 anchor contradicts policy, not just naming.** "`bob_init_repo_session` full-clone flag" is forbidden by Plane-O O-P1 (`init-repo-session.js:35,38`, `repo-target.js:11`) and `--network none` (`repo-env.js:838`) blocks in-container fetch; no `git checkout` codepath exists. *Fix:* reframe as operator-history shallow-clone *guard* + a net-new in-container `git checkout` on a `read_write`/`/work` mount; raise effort above "adopt/Δ2".

4. **C14 tier inversion (Δ2 node blocks on Δ3 predecessor I12).** CVSS/CWE assemble from final-verifier severity + `attack_vector`, not root-cause families. *Fix:* demote the H-C14→I12 edge to `augment` (non-blocking) or drop it; C14's only hard predecessor becomes C10 (Δ2), restoring tier monotonicity.

5. **S12 should not strict-block I9, and is mis-anchored.** Re-anchor S12 to extend `test/mcp-test-discovery.test.js` (drop the `mcp-` prefix filter, add module→guard-test coverage). Ship it as a fast-follow inside the I9 restore PR rather than a blocking predecessor (the backlog treats re-arming the manifest as part of the restore).

6. **I9 broken guard test must be repaired first.** `test/repo-target.test.js` won't even load (`require('../mcp/lib/hunter-completion.js')` → renamed to `agent-run-completion.js`); the reachability tests at `:231-271` are dead. This broken-test-that-should-have-caught-the-drop is itself the proof-of-need for S12.

7. **C9 double-counts an already-shipped capability.** Chain severity elevation already exists (`chain.md:8-10,49`). Trim C9 to the grade-time reachability lift/ceiling only (no such gate in `grade-verdict-store.js`/`lifecycle-gates.js`); the AV:L ceiling must **cap** severity, never drop the finding from the reportable set.

8. **X9 demote.** Core already shipped + CI-wired (`check-stigmergy-coherence.js` `checkAssertionC/A/B`, manifests `stigmergic-{producers,consumers}.js`, `npm test`). The reachability drop escaped only because the field-pair was never *registered* in `stigmergic-consumers.js`. *Fix:* register the brief/prompt-consumed reachability fields (+ optional auto-extractor); delete the stale `check-orphaned-consumers.js` anchor; consider merging with S12.

9. **C13 dispatch anchor incomplete + scope-risky.** `bob_start_wave` is single-domain; transfer additionally needs `bob_init_session(targetB)` and a hard scope-authorization gate enforced in the dispatch routine (not the prompt). State both.

10. **IP9 oversized + double-blocked.** Drop "thin dispatch wrapper"; add the unbuilt IP3 watcher and an absent scheduler substrate as explicit sub-work; keep Δ4/policy-gated and flag the tension with Bob's two-turn human-gated design.

11. **I11/X7 gates can't pass at operator volume** (calibration "mostly dormant at Bob's claim volume"). Re-state both gates as engineering/fixture criteria ("ledger persists labels; Wilson read returns a bound on a seeded corpus"), and mark them long-horizon.

12. **No actual dependency cycle exists** (augment edges are correctly non-blocking). Confirmed.

13. **Dropped backlog items need traceability.** Add `excluded_by_doctrine` stubs for `smt-feasibility-tool` (corroboration-only) and the `osv-scanner` SEED_PACK one-liner; decide gap #11 (148-tool schema to all hosts, `transport.js:43`) as either an X6 tool-surface-minimization sub-item or an explicit park.

## New nodes to add

```text
X10 — Reasoning-divergence adjudication
  kind: X   tier: Δ2   type: harden
  intent: Catch the "two rounds agree on disposition/severity/reportable but
          describe different bugs" gap. Deterministic form ONLY: flag
          artifact_hashes mismatch for findings both rounds independently
          replayed; add a `reasoning_divergence` enum into the adjudication
          plan hash. No semantic/LLM diff.
  predecessors: (verification spine — bob_build_verification_adjudication, shipped)
  unlocks: tighter adjudication on the spine "ahead of every peer"
  anchor: mcp/lib/verification.js findingDiffs (:471-473, currently diffs only
          disposition/severity/reportable) + computeAdjudicationPlanHash
  source: COMPETITOR_ANALYSIS.md:84,113 (gap #10, defer-table safe form)

C16 — Cross-VM invariant/finding transfer
  kind: C   tier: Δ4   type: net-new
  intent: Confirm an oracle-manipulation/reentrancy invariant on one VM
          deployment, then auto-transfer the hypothesis to the same protocol's
          Move/SVM/CosmWasm deployment. Unique to Bob (no peer ships 6 VMs).
  predecessors: I5 (invariant-template-corpus, shipped), I7 (chain tree,
          shipped), I13 (transfer machinery)
  unlocks: findings:cross-VM
  anchor: invariant-template-corpus.js + I7 chain-tree fan-in; new transfer
          routine over the 6-chain SC fetch tools (evm/sui/aptos/svm/cosmwasm/
          substrate)
  source: critic §2 — 6-chain SC substrate has zero new frontier consumers

C17 — Proof-carrying regression sentinel
  kind: C   tier: Δ4   type: net-new
  intent: Re-execute a confirmed-and-fixed finding's C14 machine-checkable
          bundle against HEAD on each new commit/CVE; alert on re-introduction.
          Directly serves the live disclosure campaign ("is the netatalk/openexr
          fix still holding?"). Distinct from C13 (new targets) and IP9 (new CVEs).
  predecessors: C14 (bundle), IP9 (commit/CVE feed), S1 (content-addressed evidence)
  unlocks: regression-alerts on disclosed findings
  anchor: replay C14 bundle via bob_repo_docker_run on IP9-fed commits; S1
          content-addressing keys the re-fire check
  source: critic §2 — cheap composition nobody captured
```

(Optional, lower priority: an X-node or X6 sub-item for **tool-surface minimization** (gap #11, `transport.js:43` returns all 148 tools to every host); and a deferred **authenticated DOM-level access-control differential** over `bob_browser_*` + I1 — currently the browser substrate has zero Δ-consumers. At minimum, document browser as deliberately out of Δ's OSS scope.)

## Δ1 readiness

**Not cleanly ready — node-level verified, but three structural blockers and one gate-resourcing risk must clear first.** The Δ1 nodes themselves (S12, I9, C9, C14-lite, IP8-lite) are the most code-verified in the graph: I9's dropped producer / inert consumers, S12's partial implementation, C9's missing grade-gate, C14-lite's adopt-extend basis, and IP8-lite's unemitted fuzz role are all confirmed.

Blockers before detailing Δ1:
1. **Fix the broken `repo-target.test.js` require** before "re-arming" anything (Must-fix #6).
2. **Re-anchor S12** to extend `mcp-test-discovery.test.js` and demote it from a strict I9 blocker to a same-PR fast-follow (#5).
3. **Trim C9** to the grade-time gate only (drop already-shipped chain elevation) and enforce cap-not-kill (#7).
4. **Resolve the S6→OSS-container-substrate predecessor** that I9 inherits (#2).
5. **Gate-resourcing risk (decide before locking the tier):** the Δ1 GATE ("a maintainer-accepted defensible HIGH") is coupled to Δ3 work — the "record-time proof-gate downgrades on harness block" overrides C9's grade-time lift, and the compiler-rt fix that unblocks the aarch64 harness lives in C12 (Δ3). Either widen C9 to touch the record-time proof-gate path, or soften the Δ1 gate to "stamp present + consumed + lifted in grade" and move the maintainer-accepted-HIGH milestone to the Δ1/Δ2 boundary. Without this, a blocked harness can stall the whole tier ladder at Δ1.

C14-lite and IP8-lite are clean ride-alongs; neither moves the Δ1 gate, so don't let them pad the tier's apparent value.

## Confidence note

**Code-verified this session (high confidence):**
- I6/`findings-index.js` deleted in `c02179c`; `mergePriorClaimMatches` orphaned; no `priors_slice` in `assignment-brief.js`; `calibration_label` gone; cross-target priors survive only as an unconsumed primitive in `claim-clusters.js` (this directly resolved the I-vs-C/critic disagreement).
- The doc's I6 "all shipped" claim (`capability-hypergraph.md:194-206,570-572`) is stale.

**Code-verified by the per-kind verifiers (trusted, not independently re-run by me):** I9 producer drop + inert consumers (`repo-target.js:752`, `dashboard.js:186-189`, `assignment-brief.js:134-141`, `wave-brief-derivation.js`); broken `repo-target.test.js` require; S12 partial in `mcp-test-discovery.test.js`; chain elevation in `chain.md`; X9 shipped in `check-stigmergy-coherence.js`; semgrep/trivy runner in `cli-tool-packs.js`; unemitted fuzz role in `repo-env.js`; S14 no-clone policy + `--network none`; `bob_static_scan` token-contract-only; `pipeline-analytics` `cross_session` + `cross_session_read` authority + `sensitive-material` sanitizers; `S13`/`envelope.js` name collision.

**Still assumed (not re-verified):** most exact line numbers in anchors; IP3 watcher absence + no-scheduler-substrate; C9's missing grade-verdict reachability gate; the I11/X7 "calibration dormant at operator volume" statistical claim; and all raptor/poc-lab/CSAI competitive provenance. No dependency cycle was found by any reviewer.