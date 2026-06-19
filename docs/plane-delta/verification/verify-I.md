I have all the evidence. Writing the verdict report.

### I9 — Source reachability index
**VERDICT: keep** (anchor accurate; one addition needed)

- **Already shipped?** No — correctly a *restore*. The producer is gone from `mcp/lib/repo-target.js` (`buildRepoInventory` at `repo-target.js:752` emits no `reachability`; grep for `reachab|severity_ceiling|max_credible` in that file = empty). `mcp/lib/reachability.js` does not exist. The consumers are still wired and **inert**: `mcp/lib/dashboard.js:186-189` defensively reads `inventory.reachability.{max_credible_severity_ceiling,network_reachable_surface_ids}`; `mcp/lib/assignment-brief.js:134-141` and `mcp/lib/wave-brief-derivation.js:133-134,174-178` cap `severity_ceiling`/`network_reachable` slices with a comment literally describing a "future derivation reader." Textbook wired-but-inert.
- **Anchor real?** Yes. `buildRepoInventory` exists. The git refs are real commits, not blobs: `d1647c0 Add OSS reachability/severity-ceiling triage…`, `1a456f1 Add per-path reachability attribution to the OSS native surface (#7)`, plus `4c4607f Harden OSS reachability/severity-ceiling triage…` — the full producer history is recoverable. Both named test files exist.
- **STALE detail to fix:** "re-arm `test/repo-target.test.js`" *understates* it. That file currently fails to even load — it `require`s `../mcp/lib/hunter-completion.js`, which was renamed to `mcp/lib/agent-run-completion.js` and never updated (`node --test` → `Cannot find module '../mcp/lib/hunter-completion.js'`, 0 pass / 1 fail). So the reachability tests at `repo-target.test.js:231-271` are dead code, and that broken require must be fixed first. `test/dashboard.test.js` passes 5/5 (it hand-feeds a mock `reachability` object — proving the consumer is live + tested but unfed). This broken-test-that-should-have-caught-the-drop is itself the proof-of-need for S12.
- **Predecessors sound?** S6 (shipped slab) ✓, S12 (new manifest gate) ✓ — and S12 is *validated* by this exact incident. No cycle.
- **Anti-pattern:** Clean. `severity_ceiling` could be misread as auto-suppression, but I9 only *stamps*; the suppress/lift decision lives in C9 at grade-time (post-verification), so it does not invert freeze-then-verify or no-premature-termination.
- **Effort/value:** Δ1 correct — highest value-to-effort, mostly re-porting already-written code.

### I10 — Static-analysis finding index
**VERDICT: keep**

- **Already shipped?** No. `bob_static_scan` (`mcp/lib/tools/static-scan.js` → `static-artifacts.js`) is a *token-contract* scan only (`scan_type` enum = `token_contract`); zero `sarif|codeql|semgrep|coccinelle` anywhere in `mcp/lib`. `mcp/lib/static-analysis-index.js` does not exist. Genuinely net-new, no overlap.
- **Anchor real?** Yes — `static-analysis-index.js` correctly marked new; `mcp/lib/lead-intake.js` exists as the real intake consumer (`normalizeSurfaceLead`/`readSurfaceLeadsDocument`).
- **Predecessors sound?** IP7 (new SARIF runner, absent ✓), S6 (shipped) ✓. No cycle.
- **Anti-pattern:** Clean — explicitly "candidate LEADS (never auto-findings)," respecting freeze-then-verify; index has its tier-mate consumer C11.
- **Effort/value:** Δ3 plausible (containerized CodeQL/semgrep + SARIF normalize/dedup is real work).

### I11 — Calibration ledger / trust cells
**VERDICT: keep** (one dependency caveat)

- **Already shipped?** No. Zero `wilson|trust.?cell|calibration|fp.?rate` in `mcp/lib`. `capability-metrics.js` only buckets per-capability *tool usage*, not per-(model,attack_class,decision_class) *outcomes*. `grade-verdict-store.js` persists `verdict` but no per-class disposition ledger. Net-new (tagged "adopt" from raptor, fine).
- **Anchor real?** Yes — `bob_write_grade_verdict` exists (`tools/write-grade-verdict.js`); the adjudication source exists (`tools/build-verification-adjudication.js`). S11 store is new.
- **Predecessors sound?** S11 (new) ✓, single predecessor, no cycle. **Caveat:** do NOT lean on I6's "reserved calibration_label slot" that capability-hypergraph.md advertises — that slot was never built (see summary). I11 must source labels directly from grade verdicts + adjudication, which its intent text already says.
- **Anti-pattern:** This is the *correct* boundary case — "Passive, default-off, NON-BINDING prior… never short-circuiting a claim pre-verification." It adopts the signal, not the kill, so it does NOT drift into `X-rej-1`/`X-rej-2`. Clean. (Keep the non-binding gate language verbatim in the detail spec.)
- **Effort/value:** Δ4 plausible (needs S11 first; Wilson + cross-session persistence is moderate).

### I12 — OSS root-cause family index
**VERDICT: revise / split**

- **Already shipped?** Partially. OSS technique packs already exist in the registry: `mcp/lib/technique-packs.js` has `oss_native_code` (`:89`), `oss_api_schema`, and a dependency/lockfile pack. So a "family corpus" partly exists. What's missing: (a) the brief plumbing is **broken**, and (b) the 2 named families + worked witnesses.
- **Anchor real?** Yes, exact: `assignment-brief.js:403` is literally `briefSliceEntry("technique_packs", 8192, (context) => context.ossTechniquePacks)`, and `context.ossTechniquePacks` has **no producer** anywhere (grep returns only that one consumer line) — confirming "currently unwired"; this is itself an orphaned-consumer (X9 class). `oss_native_code` is at `technique-packs.js:89`, not `:92` (minor line drift, symbol real). `invariant-template-corpus.js` (I5 shape) exists.
- **Predecessors sound?** I5-shape (`invariant-template-corpus.js`, shipped) ✓. No cycle.
- **Anti-pattern:** Clean (index → evaluator brief → C11).
- **Effort/value — SPLIT:** the "finish the unwired `ossTechniquePacks` plumbing" half is a *cheap S12/X9-class dangling-consumer fix* and should NOT be gated behind Δ3; only the named-family (crypto-ordering, validate-vs-consume) + worked-witness corpus is genuine Δ3. Recommend splitting the plumbing fix out as a Δ1 ride-along.

### I13 — Cross-target transfer index
**VERDICT: revise** (phantom predecessor; bigger than implied)

- **Already shipped?** No — `mcp/lib/cross-target-transfer.js` does not exist.
- **Anchor real? PARTIALLY STALE.** Anchor is "over symbol-surface-index + **findings-index** + surface-graph." `symbol-surface-index.js` ✓ (I3) and `surface-graph.js` ✓ (I1) exist, but **"findings-index" (I6) does not exist**: no embeddings, no vector store (`grep embedding|sqlite-vss|vector|cosine` = empty), no `bob_index_candidate_claim` / `bob_query_candidate_claims_index` tool files, no `findings-index` file, no `priors_slice`. `claim-correlator.js` is **within-session** clustering only (surface_id / auth_profile_ref / subject_id signals on a single freeze batch), not a cross-target retrieval layer. So one of I13's three named substrates is a phantom.
- **Predecessors sound?** I1 ✓, I3 ✓, **I6 ✗** — `docs/capability-hypergraph.md` declares I6 "engineering-complete… library, MCP tool wrappers… all shipped," but the actual cross-target findings index was never built; the shipped doc overstates it. No literal cycle, but I13 depends on a non-existent index.
- **Anti-pattern:** Clean on doctrine — it auto-proposes *sibling hypotheses* fanned into `bob_start_wave` (full freeze-then-verify), not auto-findings; the gate requires confirmation on the 2nd target.
- **Effort/value:** Δ4 is **optimistic**. The pitch ("cheap precisely because the indexes already exist") is false for one-third of its substrate. I13 must either (a) absorb building/restoring the I6 findings index into its scope, or (b) be repointed to the real claim store (`claims.js` / `read-candidate-claims` + `claim-correlator` signals like attack_class + surface_family) it can actually query. Bigger than implied either way.

### I-cluster summary
Most important corrections, ranked:

1. **I13/C13 rest on a phantom predecessor (I6).** The shipped `docs/capability-hypergraph.md` claims the "findings vector index" I6 is shipped, but there are **no embeddings, no vector store, no `bob_index_candidate_claim`/`bob_query_candidate_claims_index` tools, no `priors_slice`, no findings-index file** — only within-session `claim-correlator.js`. Fix the I6 status claim and either fold I6's build into I13 or repoint I13 at `claims.js`/`claim-correlator` signals before promoting. This also moots I11's documented reliance on I6's "reserved calibration_label."

2. **I9 is the strongest, best-evidenced node — keep as the Δ1 headline, but the anchor undersells the test damage.** Producer truly dropped (`repo-target.js` grep empty), git history real (`d1647c0`/`1a456f1`/`4c4607f`), consumers live+inert (`dashboard.js:186-189` PASS, `assignment-brief.js:134-141`, `wave-brief-derivation.js:133-178`). But `test/repo-target.test.js` is 100% un-loadable (`require '../mcp/lib/hunter-completion.js'` → renamed to `agent-run-completion.js`); "re-arm tests" must include fixing that stale require. This broken guard test is concrete proof-of-need for predecessor S12.

3. **I12 should split.** Anchor verified exact (`assignment-brief.js:403` consumer with zero producer = unwired/orphaned). But finishing that plumbing is a cheap S12/X9-class fix that shouldn't be Δ3-gated; only the crypto-ordering / validate-vs-consume families + witnesses are real Δ3. Note the `:92`→`:89` line drift for `oss_native_code`.

4. **I10 and I11 are clean keeps.** No overlap with existing `bob_static_scan` (token-contract only) or `capability-metrics` (tool buckets, not outcome calibration). I11's "non-binding, default-off, never pre-verification short-circuit" framing correctly stays out of the `excluded_by_doctrine` zone (`X-rej-1`/`X-rej-2`).

5. **No node in my cluster drifts into the doctrine-excluded set.** All five are stamp/index/ledger producers; none auto-kill, prefilter pre-verifier, or inject exemplars into the HUNT brief. I10 and I13 explicitly emit *leads/hypotheses*, not auto-findings.