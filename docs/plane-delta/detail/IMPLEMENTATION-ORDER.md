## Implementation order

Continuous PR numbering; tier gates are stated at each Δ boundary. "Parallel" = no blocking predecessor among un-merged PRs, so it can run on a separate branch concurrently.

### Tier Δ1 — close the OSS severity ceiling

**PR1 — S15 (register OSS-container substrate) + DOC-1 + DOC-2.**
Node(s): S15 (register), DOC-1 (correct stale I6 "shipped" claim), DOC-2 (record the reachability-producer drop). Why first: S15 is the systemic unblocker — it is the missing S-node that every OSS-cluster predecessor was mislabeled against (it unlocks S14, I9, I10, IP7, IP8, C10, C12). It is pure registration (adds `--network none` / init-never-clones / `read_write` `/work` staging to the slab table) with zero runtime change, so it ships risk-free alongside the two doc corrections that make HEAD tell the truth. Bundling DOC here lands ground truth *before* any code is built on a phantom — critically DOC-1 de-risks the entire I13/C13/C16 chain four tiers ahead. Parallel: nothing precedes it; it gates almost everything, so it goes alone first.

**PR2 — I9 (restore reachability producer) + S12 (test-manifest + consumer-registration integrity).**
Node(s): I9 (restore), S12 (harden, same-PR fast-follow). Why here: pred S15 (PR1). The strict ordering *inside* the PR matters — (a) FIRST repair the broken `repo-target.test.js` require (`hunter-completion.js` → `agent-run-completion.js`) so the dead guard test loads, (b) re-port the producer from blob `d1647c0`(+`1a456f1`) into `mcp/lib/reachability.js`, (c) re-arm the reachability tests `:231-271`. S12 rides in the *same* PR (not a strict blocker): extend `mcp-test-discovery.test.js` (drop the `mcp-` filter, add module→guard-test coverage) and register the `network_reachable`/`severity_ceiling` field-pair in `stigmergic-consumers.js`. Bundling means the restore lands *with* the CI guard that would have caught its loss. Parallel: depends only on PR1.

**PR3 — C9 (OSS severity-ceiling closure, grade-time lift/cap).**
Node(s): C9 (net-new). Why here: pred I9 (PR2) — it consumes the restored `severity_ceiling`/`attack_vector`. This is the Δ1 capstone: a NEW grade-time lift/cap gate in `grade-verdict-store.js`/`lifecycle-gates.js`. Trim to grade-time ONLY (chain elevation already ships, `chain.md:8-10,49`). Hard invariant: **cap, never kill** — AV:L caps severity, it never drops a finding from the reportable set. Parallel: must follow PR2.

**PR4 — Δ1 ride-alongs: C14-lite + I12-plumbing + IP8(-lite).**
Node(s): C14-lite (adopt, no predecessor — prompt-only CWE/CVSS-4.0/refs into the OSS reporter branch `reporter.md:28-31`); I12-plumbing (harden, pred S5 shipped — wire the orphaned `context.ossTechniquePacks` consumer at `assignment-brief.js:403`); IP8-lite (adopt, pred S15 — fuzz-seed lens + seed store, emit the declared-but-unemitted `fuzz` role groundwork). Why here: all three are cheap, independent, and unblocked (IP8 needs only PR1). Parallel: fully parallelizable with PR2/PR3 and with each other; can be three separate micro-PRs. Explicitly do **not** count them toward the Δ1 gate — they don't move it.

**→ Δ1→Δ2 gate (see gate-resourcing decision below).** Engineering-checkable: reachability stamp *present + consumed + lifted in grade* on a fixture (C9 caps/lifts deterministically). The "maintainer-accepted defensible HIGH" milestone is moved to the Δ1/Δ2 boundary and is retroactively closed by C12 (Δ3) for harness-blocked findings.

### Tier Δ2 — make HIGHs provable + harden the agent

**PR5 — S14 (in-container differential checkout).** Pred S15 (PR1). Net-new `git checkout`/`git apply` on the `read_write` `/work` mount via `bob_repo_docker_run`, plus a non-shallow-history guard in `repo-target.js`. Does NOT touch init (respects O-P1: init never clones, `--network none`). Substrate for the whole differential chain.

**PR6 — C10 (patched-vs-unpatched differential proof).** Pred S14 (PR5). Differential evidence row `{vuln_run_id, control_run_id, control_kind, verdict}` in `write-evidence-packs.js`+`evidence.js`. Proves residual / self_patch / pre_introduction.

**PR7 — C14 (proof-carrying disclosure bundle).** Pred C10 (PR6) only (I12 predecessor DROPPED — tier inversion fixed; CVSS/CWE come from final-verifier severity + `attack_vector`). Machine-checkable bundle via `compose-report.js` SECTION_KINDS extension.

**PR8 — S13 (untrusted-content envelope).** Pred S10 (shipped) — **parallel to PR5–7**. New `mcp/lib/untrusted-envelope.js` (nonce per `session-cap.js`; note the `envelope.js` name collision is the unrelated ToolError wrapper).

**PR9 — X6 (agent self-security).** Pred S13 (PR8). Wire the envelope into untrust-bearing brief slices (`assignment-brief.js` traffic/audit/intel/schema/surface_graph) + `body-resolvers/index.js` output-fencing + a standing system preamble.

**PR10 — X7 (evaluator-run-avoided telemetry).** Pred `lead-scoring.js` (shipped) — needs neither S11 nor I11; **fully parallel, could even pull into the Δ1 window**. Descriptive count only, never an auto-kill gate (`evaluator_run_avoided` via `pipeline-events.js`).

**PR11 — X10 (reasoning-divergence adjudication).** Pred `bob_build_verification_adjudication` (shipped) — **parallel**. Deterministic only: flag `artifact_hashes` mismatch for findings both rounds independently replayed; add a `reasoning_divergence` enum to the plan hash (`verification.js findingDiffs:471-473`). No LLM diff.

**→ Δ2→Δ3 gate (parishioner/real-target):** differential proves a residual on a real target (rebuts "already fixed") AND a proof-carrying bundle is accepted by a maintainer/triager.

### Tier Δ3 — static-analysis depth + fuzzing maturity

**PR12 — C12 (coverage-guided fuzzing maturity). PRIORITIZE FIRST in Δ3.** Pred IP8 (PR4). Emit the fuzz role at `recommendedCommandsFor` (~`repo-env.js:207`), plateau detection, structure-aware harness hints, sanitizer matrix, and the **aarch64 compiler-rt fix**. Critical-path note: C12 `unblocks:C9-harness` — it is the node that *retroactively closes the deferred Δ1 maintainer-accepted-HIGH milestone* for harness-blocked findings, so it leads Δ3 rather than trailing it. Parallel to the I10/C11 chain below.

**PR13 — IP7 (SARIF ingest path).** Pred S15 (PR1). SARIF parser only (the semgrep/trivy/CodeQL runner already ships in `cli-tool-packs.js`). May be merged into PR14.

**PR14 — I10 (static-analysis finding index).** Pred IP7 (PR13) + S15. New `static-analysis-index.js`; SARIF → `lead-intake.js` → frontier LEADS (never auto-findings). Also augments I9 when a build exists (non-blocking back-edge, no cycle).

**PR15 — I12 (OSS root-cause family index).** Pred I5 (shipped) + I12-plumbing (PR4). Extend the `invariant-template-corpus.js` shape (`technique-packs.js:92`); add the two absent families (crypto-ordering, validate-vs-consume). **Parallel** to PR13/PR14 (independent predecessor).

**PR16 — C11 (static-driven source audit). HEAVIEST FAN-IN — sequence LAST in Δ3.** Pred I10 (PR14) + I9 (PR2) + I12 (PR15) (+ IP7). Cannot start until four predecessors across Δ1+Δ3 land. Drives evaluators toward reachable source/sink paths (`lead-promotion.js` + OSS lens).

**→ Δ3→Δ4 gate (parishioner):** ≥1 finding from a static lead that blind hunting missed; fuzz throughput measurably up; C12 confirmed to have unblocked C9's harness dependency.

### Tier Δ4 — compounding + frontier

**PR17 — S11 (cross-session label/metric store).** Pred S1, S2 (shipped). Adopt-extend `pipeline-analytics.js` (`mode:'cross_session'`) + `cross_session_read` authority + `sensitive-material.js` sanitizers. No new `~/.cross` dir; no raw PII/secrets.

**PR18 — I11 (calibration ledger / trust cells).** Pred S11 (PR17). Per-(model, attack_class, decision_class) outcome ledger + Wilson lower-bound, NON-BINDING. Source labels from grade verdicts + adjudication (the deleted I6 `calibration_label` slot is gone). Augments grader (non-blocking).

**PR19 — I13 (cross-target transfer index — the I6-REBUILD).** Pred I1, I3, `claims.js`, `claim-clusters.js` (shipped). **Parallel** to PR17/PR18. This is NOT cheap: I6/findings-index was deleted (`c02179c`), so the cross-target retrieval-into-brief must be genuinely rebuilt on the claims subsystem over the currently-orphaned `mergePriorClaimMatches`. Size effort accordingly. Shared by both C13 and C16, so build it once.

**PR20 — C13 (cross-target finding transfer).** Pred I13 (PR19). New orchestrator routine: `bob_init_session(targetB)` + `bob_start_wave` + a **hard scope-authorization gate enforced in dispatch (not the prompt)**.

**PR21 — C16 (cross-VM invariant/finding transfer).** Pred I5, I7 (shipped) + I13 (PR19). **Parallel to PR20** (both consume I13). Transfer routine over the 6-chain SC fetch tools (evm/sui/aptos/svm/cosmwasm/substrate) — uniquely Bob.

**PR22 — C15 (adversarial self-patch loop).** Pred C10 + S14 (both Δ2) — **independent of the Δ4 chains, fully parallelizable; could ship at the Δ2/Δ3 boundary**, kept in Δ4 only by effort size. HARD INVARIANT encoded in the controller: a patch that fixes the PoC must NEVER auto-suppress the pre-patch finding. Iterate-until-robust controller only.

**PR23 — IP9 (continuous CVE/commit feed). LARGEST/RISKIEST — sequence late, split into sub-PRs.** Pred IP5, I8 (shipped) + IP3 (unbuilt) + scheduler substrate (absent). Sub-PRs: (23a) build the IP3 watcher, (23b) build the scheduler substrate, (23c) policy-gated dispatch. Keep policy-gated; flag the tension with Bob's two-turn human-gated design; resurrects vacated C8.

**PR24 — C17 (proof-carrying regression sentinel).** Pred C14 (PR7) + IP9 (PR23) + S1 (shipped). Replay the C14 bundle on IP9-fed commits via `bob_repo_docker_run`; S1 content-addressing keys the re-fire check. Build with a **manual commit/CVE-input fallback** so a stalled IP9 doesn't block the sentinel (it serves the live netatalk/openexr/etc. disclosure campaign).

**PR25 — X7b (cost-per-finding telemetry).** Pred S11 (PR17). **Parallel** to the calibration chain after PR17. Requires a new token-telemetry substrate Bob lacks (reconstructable from CC transcripts per the benchmark plan).

**PR26 — X8 (live in-run observability, SSE).** Pred `dashboard.js`, `frontier-events` (shipped). Polish, fully independent, **lowest priority — anytime**. SSE upgrade over the existing `/api/snapshot` poll; loopback-only; file-backed tail over `frontier-events.jsonl`.

**→ Δ4 gate (engineering/fixture, long-horizon):** calibration persists labels + Wilson read returns a bound on a seeded corpus; cross-target transfer confirms a family on a 2nd authorized target; C16 transfers an invariant across two VM deployments.

---

## Δ1 critical path

The exact sequence that closes the OSS severity ceiling:

1. **PR1 S15** — register the OSS-container substrate so I9's predecessor is real (resolves readiness blocker #4, the S6→OSS-container mislabel). Ship DOC-1/DOC-2 here.
2. **PR2 step (a): fix the broken `repo-target.test.js` require** (`hunter-completion.js`→`agent-run-completion.js`) — readiness blocker #1 and #6. Until this loads, nothing can be "re-armed."
3. **PR2 step (b): re-port the I9 producer** from blob `d1647c0`(+`1a456f1`) into `mcp/lib/reachability.js`; the consumers in `assignment-brief.js:134-141`, `wave-brief-derivation.js`, `dashboard.js:186-189` are already wired and inert — restoring the producer makes them live.
4. **PR2 step (c): S12 fast-follow** — extend `mcp-test-discovery.test.js` (drop `mcp-` filter) and register the reachability field-pair in `stigmergic-consumers.js` (readiness blockers #2 and #5: S12 re-anchored and demoted to same-PR fast-follow, not a strict blocker).
5. **PR3 C9** — add the grade-time reachability lift/cap gate, trimmed to grade-time only (chain elevation already ships) and enforced as **cap-not-kill** (readiness blocker #3).

The five readiness blockers, mapped: (#1/#6) broken guard test → fixed first inside PR2; (#2) S12 re-anchored to `mcp-test-discovery.test.js` → PR2; (#3) C9 trimmed to grade-time + cap-not-kill → PR3; (#4) S15 substrate predecessor → PR1; (#5) the gate-resourcing risk → decided below.

**Gate-resourcing decision — soften the Δ1 gate; do NOT widen C9 in Δ1.**
The Δ1 end-to-end "maintainer-accepted defensible HIGH" milestone couples to Δ3: the record-time proof-gate downgrades on harness block, and the aarch64 compiler-rt fix that unblocks the harness lives in **C12 (Δ3)**. Widening C9 to own the record-time path would drag C12's compiler-rt/aarch64 work into Δ1, destroying the "highest value-to-effort" character of the tier and risking a hard stall of the whole ladder on a blocked harness. Decision:

- **Soften the Δ1 gate** to the engineering-checkable criterion: *reachability stamp present + consumed + lifted in grade on a fixture* (C9 caps/lifts deterministically). 
- **Move the maintainer-accepted-defensible-HIGH milestone to the Δ1/Δ2 boundary**, where it is *retroactively closed by C12 (Δ3)* for harness-blocked findings — which is why C12 is sequenced FIRST in Δ3.
- **One cheap hedge inside C9 (not a full widen):** make the grade-time lift authoritative for the *reachability dimension only*, so a record-time harness-block records a ceiling note rather than a hard downgrade that silently clobbers a reachability-justified lift. This is consistent with cap-not-kill and avoids importing C12's harness work into Δ1.

---

## Risk register

**R1 — C9 harness / Δ3 coupling (critical-path stall).** C9's defensible-HIGH depends end-to-end on C12's aarch64 compiler-rt harness fix, and the record-time downgrade-on-harness-block can override C9's grade-time lift. *Mitigation in the order:* the gate-resourcing decision above (soften the Δ1 gate, move the HIGH milestone to the Δ1/Δ2 boundary, cap-not-kill); C12 is pulled to **first in Δ3** because it `unblocks:C9-harness`; and C9 carries the one-line reachability-authoritative hedge so a blocked harness sets a ceiling note, never a hard kill. A blocked harness can no longer stall the tier ladder at Δ1.

**R2 — I6-rebuild for I13/C13 (building on a phantom).** I6/findings-index was DELETED (`c02179c`); the cross-target retrieval-into-brief that I13/C13/C16 assume is not live and survives only as the orphaned `claim-clusters.js mergePriorClaimMatches`. *Mitigation:* **DOC-1 lands in PR1 (Δ1)**, four tiers before anyone builds on it, correcting the stale "shipped" claim; **I13 (PR19) is scoped as a genuine net-new rebuild** on the claims subsystem with effort sized accordingly (not "cheap because indexes exist"); both C13 (PR20) and C16 (PR21) gate on I13, so the rebuild lands once and is shared.

**R3 — IP9 policy gating (oversized + double-blocked + resurrects vacated C8).** IP9 needs the unbuilt IP3 watcher and an absent scheduler substrate, and it re-introduces a deliberately policy-vacated capability while straining the two-turn human-gated design. *Mitigation:* IP9 is sequenced **last among its dependents' needs** and split into 23a (IP3 watcher) / 23b (scheduler substrate) / 23c (policy-gated dispatch); kept explicitly policy-gated; and **C17 (PR24) is built with a manual commit/CVE-input fallback** so a stalled or policy-blocked IP9 does not block the regression sentinel that serves the live disclosure campaign.

**R4 — no-auto-suppress invariant for C15.** The self-patch loop could silently hide a real finding once it generates a passing fix. *Mitigation:* C15 (PR22) is sequenced **after C10 (PR6) and C14 (PR7)** so the differential-evidence substrate exists first; the fixed-PoC is recorded as a `control_kind=self_patch` differential row (`{vuln_run_id, control_run_id}`) that is structurally distinct from the pre-patch finding, and the invariant is encoded as a hard controller gate: the pre-patch finding's reportable status is immutable; the patch result is only ever a suggested-fix/evidence row.

**R5 (cross-cutting) — silent-drop regression class recurring.** I9's loss escaped because the field-pair was never registered and a guard test was broken. *Mitigation:* **S12 ships in PR2 with I9** — manifest coverage + consumer-field registration makes inert consumers fail CI, so the next dropped producer fails the build instead of shipping silently.

**R6 (cross-cutting) — C11 heaviest fan-in scheduling.** C11 needs I9 (Δ1) + I10 + IP7 + I12 (Δ3) before it can start. *Mitigation:* C11 is sequenced **last in Δ3 (PR16)**, with I12 (PR15) built in parallel to the IP7→I10 chain so all four predecessors converge without serializing the whole tier.

**R7 (cross-cutting) — slab-invariant regressions.** Every new node must not embed credentials in a brief, advance state without manifest refresh, hold artifacts without content-addressing, or bypass replay-lease typing. *Mitigation:* this is a standing PR-review reject criterion applied to all 26 PRs; S11 (PR17) in particular is constrained to the existing cross-session substrate with `sensitive-material.js` sanitizers and no raw PII/secrets.