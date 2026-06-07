### IP7 — Static-analysis runner ingestion
**VERDICT: revise** (partially shipped + wrong predecessor; net-new content is narrower than stated)

1. **Already shipped? PARTIAL.** The *runner half* exists. `mcp/lib/cli-tool-packs.js:219-232` already ships `semgrep` (`semgrep --config auto /src`) and `trivy` as OSS CLI-tool-pack seeds gated on `surface.kind === "repo"`, and they execute inside the container via `bob_repo_docker_run` (`mcp/lib/repo-env.js:1073` `repoDockerRun`). The evaluator prompt already instructs their use (`prompts/roles/evaluator.md:60`). So "run semgrep/coccinelle/codeql in the OSS container" is **not** net-new for semgrep. What *is* genuinely new: CodeQL/Coccinelle are explicitly "Deferred" (`cli-tool-packs.js:213`), and SARIF **parse/normalize/ingest has zero footprint** — `grep -rni sarif mcp/ scripts/ test/` returns nothing. `bob_static_scan` is token-contract-only (`docs/COMPETITOR_ANALYSIS_APPENDIX.md:630`). So IP7's real deliverable is the SARIF→`lead-intake.js` ingestion, not "running a runner." Reframe the intent accordingly.

2. **Anchor real? MOSTLY.** `bob_repo_docker_run` exists (`mcp/lib/repo-env.js:1073`). The downstream sink it must feed, `mcp/lib/lead-intake.js`, exists (confirmed). The SARIF parser does not exist yet and is correctly implied-new. No stale symbol.

3. **Predecessors sound? NO — STALE/MISLABELED.** Listed predecessor is `S6`, but `S6` = "Static artifact import (foundry, anchor, OpenAPI partial)" (`docs/capability-hypergraph.md:51`) — that's `bob_import_static_artifact`, the wrong substrate. IP7's actual dependency is the **Plane-O containerized OSS substrate** (`bob_repo_prepare_env` / `bob_repo_docker_run` / `bob_init_repo_session`), which has **no S-node in either graph**. Fix the predecessor to name the repo-docker substrate (the same one S14 leans on via "reuse `bob_repo_docker_run` writable path").

4. **Anti-pattern check: CLEAN.** Feeds I10 (index) → C11 (consumer) in the same Δ3 tier, so no index-without-consumer. Stays on the right side of `X-rej-5` (binary-oracle import) — it's source-SARIF, not a compiled-artifact oracle. I10's "candidate LEADS (never auto-findings)" framing respects `X-rej-1`. No drift.

5. **Effort/value sanity: SMALLER than implied.** Δ3 placement is fine, but because the semgrep runner + `lead-intake.js` sink already exist, IP7 collapses to "SARIF normalization + dedup + lead emission." Consider whether IP7 should **merge into I10** rather than stand as a separate ingestion node — the IP/I vocabulary split is defensible, but the genuinely-new surface of IP7 is just the ingestion half of I10.

---

### IP8 — Fuzz-seed corpus ingestion
**VERDICT: keep** (anchor accurate, honest split; one predecessor fix + a line-number nit)

1. **Already shipped? NO.** No seed store, no `testdata/`/OSS-Fuzz seed-corpus ingestion exists (`grep -rniE "seed_corpus|oss-fuzz|fuzz.?seed|testdata"` over `mcp/`+`prompts/` returns nothing). The "unused fuzz role" claim is **correct and verified**: `fuzz` is declared in `RECOMMENDED_COMMAND_ROLES` (`mcp/lib/repo-env.js:141`) and validated (`repo-env.js:570-572`), but `recommendedCommandsFor` (`repo-env.js:207-331`) emits **no fuzz-role command for any language** — every branch returns only `build`/`test`/`compose`. The role is a dangling enum value. Good catch; genuinely net-new.

2. **Anchor real? YES, with a line nit.** `recommendedCommandsFor` exists and is the correct emission site. The cited line `:141` points at the *enum entry* (`"fuzz",`), not the emission site (the function body, `:207-331`). Minor — name the function, drop/adjust the `:141`.

3. **Predecessors sound? NO — same S6 issue as IP7.** `S6` (static-artifact import) is the wrong substrate; reading `testdata/` from the checkout depends on the Plane-O repo session (`bob_init_repo_session` / repo-target), not `bob_import_static_artifact`. Re-anchor to the OSS repo substrate.

4. **Anti-pattern check: CLEAN.** IP8 → C12 (consumer) in Δ3, with a Δ1-lite ride-along consistent with TOPOLOGY's Δ1 ride-along policy (`TOPOLOGY.md:108`). No substrate-as-trajectory; not in `excluded_by_doctrine`.

5. **Effort/value sanity: ACCURATE.** The `Δ1-lite/Δ3-full` split is the most honest tiering in the cluster: the lite half (emit the already-declared fuzz role + an evaluator lens) is a handful of lines in `recommendedCommandsFor`; the full half (per-target seed store + OSS-Fuzz ingest + plateau detection) is real Δ3 work. Ties correctly to `reference_bob_oss_libcupsfilters_fuzz_image`.

---

### IP9 — Continuous CVE/commit feed activation
**VERDICT: revise** (much bigger than "thin dispatch wrapper"; one predecessor is unbuilt, no scheduler substrate exists, and it resurrects a deliberately-vacated item)

1. **Already shipped? NO (and partly deliberately not).** The matcher/parser substrate ships: `mcp/lib/cve-feed-parser.js` (IP5) and `mcp/lib/cve-scope-matcher.js` (I8) both exist. But the *activation loop* (C8 "live disclosure speedrun") was **deliberately vacated** from the engineering graph: `docs/capability-hypergraph.md:525-527` states the dispatch wrapper is intentionally not built because "adding the dispatch wrapper before the [policy] conversation would tempt premature use against programs whose policy hasn't been confirmed." IP9 = building exactly that wrapper. It's policy-*gated*, not doctrine-*excluded*, but it re-opens a thing the shipped graph closed on purpose.

2. **Anchor real? PARTIALLY ASPIRATIONAL.** "thin dispatch wrapper + ScheduleWakeup/cron" — there is **no scheduling substrate in Bob's MCP**: `grep -rniE "cron|ScheduleWakeup|setInterval"` over `mcp/lib` finds only an unrelated replay-safety timer (`mcp/lib/verification-replay-safety.js:194`). `ScheduleWakeup`/cron live in the Claude Code harness, not Bob — so the temporal loop has no in-tree anchor. The anchor names a primitive Bob doesn't own.

3. **Predecessors sound? NO — one is UNBUILT.** IP5 ✓ (`cve-feed-parser.js`), I8 ✓ (`cve-scope-matcher.js`), but **IP3 (repo watcher) does not exist as a producer.** Only IP3's *downstream* shipped: `mcp/lib/unified-diff-parser.js` + `bob_summarize_diff_impact` (`mcp/lib/tools/summarize-diff-impact.js`). The actual watcher/poller has zero footprint (`grep -rniE "repo.?poll|watcher|webhook"` finds only "webhook" as an *input format* string in the diff tool's description). The shipped doc itself lists IP3 as "New" (`docs/capability-hypergraph.md:277`) and C3 says the repo-poller is "operator-driven for first slice" (`:319`). So IP9 must *also build the IP3 watcher half* — a predecessor it lists as if it were done.

4. **Anti-pattern check: NO hard doctrine violation, but architectural tension.** It does not invert freeze-then-verify and does not auto-kill, so it's correctly outside `excluded_by_doctrine`. However, "cron-driven temporal re-discovery against a moving target" runs against Bob's deliberate **two-turn human-gated** design (`docs/COMPETITOR_ANALYSIS_APPENDIX.md:598`: "Bob is two-turn human-gated by design and cannot [run unattended]"). Unattended autonomous dispatch is the exact property Bob declined; flag this as a design-boundary risk, not just a policy gate.

5. **Effort/value sanity: UNDERSIZED.** "thin dispatch wrapper" is wrong: it must (a) build the absent IP3 watcher, (b) introduce a scheduler substrate Bob doesn't have, (c) clear C8's non-engineering policy gate, and (d) reconcile with the human-in-the-loop design. Δ4 placement is right; "thin" is not. This is the heaviest, most-blocked node in the cluster.

---

### IP-cluster summary
- **Systemic predecessor bug (IP7 + IP8):** both cite `S6` "Static artifact import" as predecessor, but `S6` is `bob_import_static_artifact` (`docs/capability-hypergraph.md:51`). Their real dependency is the **Plane-O containerized OSS substrate** (`bob_repo_prepare_env`/`bob_repo_docker_run`/`bob_init_repo_session`), which has **no S-node in either graph**. Either add that S-node or re-point both predecessors — citing S6 is misleading across the whole OSS cluster (also affects I9, I10, S14).
- **IP7 is narrower than stated:** the runner already ships (`cli-tool-packs.js:219-232` semgrep/trivy via `bob_repo_docker_run`); the only net-new surface is SARIF parse/dedup→`lead-intake.js`. Reframe as SARIF-ingestion, and seriously consider **merging IP7 into I10** since its genuinely-new content is I10's ingestion half. CodeQL/Coccinelle remain real gaps (`cli-tool-packs.js:213` "Deferred").
- **IP8 is the cleanest node:** "unused fuzz role" verified (`repo-env.js:141` declares it, `recommendedCommandsFor` `:207-331` never emits it); no seed store exists; the Δ1-lite/Δ3-full split is honest. Only fixes: re-point S6 and adjust the `:141` line ref to the `recommendedCommandsFor` body.
- **IP9 is over-promised and double-blocked:** its predecessor IP3 (repo watcher) is **unbuilt** (only the diff parser shipped — `unified-diff-parser.js`/`summarize-diff-impact.js`); Bob has **no cron/scheduler substrate** in MCP (`verification-replay-safety.js:194` is the only `setInterval`, unrelated); and it resurrects the **deliberately-vacated** C8 whose blocker is non-engineering program policy (`capability-hypergraph.md:525-527`). It also strains Bob's two-turn human-gated design (`COMPETITOR_ANALYSIS_APPENDIX.md:598`). Keep it Δ4/policy-gated but drop the "thin dispatch wrapper" framing and add the IP3-watcher + scheduler-substrate build as explicit sub-work.