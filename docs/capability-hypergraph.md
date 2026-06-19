# Bob Capability Hypergraph — Post-v2 Roadmap

## Audience and scope

This is an internal engineering roadmap for what Bob ships after the v2 verification work (PR #20) merges. It is not the public `docs/ROADMAP.md` — that doc lists community-contribution areas and intentionally hides depth. This doc is the depth.

The animating claim: Bob's structural advantage is **not context width**. It is **graph-shaped state with tool-mediated dereferencing**. The slab (v2 substrate) and the existing pillars (capability-pack routing, technique-pack on-demand reads, evaluator brief) make that possible. The work ahead is building the **indexes** that turn each new evaluating capability into a bounded query problem, then shipping the capabilities on top.

## Completion summary

As of 2026-05-10 the engineering task graph was recorded as **realized**. Plane-Delta verification on 2026-06-07 found two partial walkbacks against HEAD: `I6` was deleted by `c02179c` ("claims is solo"), and the `I9` OSS reachability producer was dropped at the Plane-O/v2.1 merge. This branch restores `I9` in Plane-Delta PR2; `I6` remains superseded pending the claims-backed `I13` rebuild. Every other pillar, capability, and cross-cutting concern in the active graph remains treated as engineering-side shipped unless a later entry explicitly retracts it. Parishioner gates remain open until real-target evaluations produce findings — that's the cost of running on real targets, not engineering work. The one item that does not appear above as "shipped" is **C8 — live disclosure speedrun**, which is held by external dependency (program-level AI-evaluating policy negotiation) and has been re-classified out of the active engineering task graph into a separate [Held by external dependency](#held-by-external-dependency) section. The matcher and parser substrate it would consume (IP5, I8) ship today as libraries usable for offline triage.

What this means concretely for the original 2026-05-10 snapshot: 39 commits on `feature/capability-hypergraph`, 708+ MCP tests, 102 MCP tools added across the post-v2 capability surface (C1–C7 reachable from the orchestrator; X2 / X3 / X4 / X5 cross-cutting concerns shipped), and the bob-evaluate skill grew within its operator-readable budget while picking up the new tools. The current branch truth is stricter: do not treat the deleted `I6` findings index as live; treat `I9` as restored only after the Plane-Delta PR2 branch lands.

## How to read this doc

The codebase has three layers and a set of cross-cutting concerns:

- **Slab (S)** — substrate already shipped. Provides invariants the rest depends on.
- **Pillars (I, IP)** — pre-computed indexes (`I*`) and ingestion paths (`IP*`) that turn each capability into a bounded query. Some scaffolded, most new.
- **Roof (C)** — eight evaluating capabilities that produce findings a triager recognizes.
- **Cross-cutting (X)** — concerns that span multiple items (context budgets, observability, evaluation, parishioner-facing surfaces).

A **hyperedge (H)** in this graph links N predecessors to M unlocked items. Real engineering dependencies are rarely pairwise — the hypergraph captures that fan-in / fan-out directly.

Each work item has a **do→review cycle**:

- **DO** — spec → build → wire → ship.
- **REVIEW (engineering)** — tests, context-budget compliance, determinism, failure-mode coverage.
- **REVIEW (parishioner)** — run on a real authorized target. Count actionable findings. Count false positives. Triager-recognition test: would a triager close this as duplicate / informational / valid?

Tiers gate on parishioner review. **No proceeding to tier N+1 without findings tier N actually produces.** Substrate work is not a tier-advancing activity unless a capability ship demands it.

## Disambiguation

These terms collide if not separated:

- **Capability pack** (existing, see `docs/context-scaling-architecture.md`) — a surface-family router selected per assignment. Governs `candidate_pack_limit`, `full_pack_read_limit`, `attempt_log_required`. Lives in MCP runtime.
- **Capability** (this doc, `C1`–`C8`) — a evaluating *mode* that produces findings. May be implemented as one or more new capability packs plus indexes plus orchestrator routines. Strictly a higher-level abstraction than capability pack.
- **Technique pack** (existing) — a tactic body, registry-driven, fetched on demand by `bob_read_technique_pack`. Indexes in this doc do not replace technique packs; they feed brief construction so technique selection has more signal.

## Slab — substrate already shipped

| ID  | Substrate                                                                                 | Provides                                                                |
| --- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| S1  | Content-addressed evidence (canonical hashing, `final_verification_hash`)                 | Same artifact → same hash, anywhere, anyone                             |
| S2  | Manifest-coupled state (atomic transitions, rollback on failure)                          | No half-states; state and evidence advance together or not at all       |
| S3  | Per-pack replay leases (`serialized` vs `parallel_safe`, lease scope `attempt_pack`/etc.) | Operational safety as typed property of each capability pack            |
| S4  | Orphan-attempt recovery (`inferOrphanedAttemptId`, attempt archive)                       | Every attempt rebuildable from artifacts; no silent state loss      |
| S5  | MCP tool registry + role bundles + generators                                             | Centralized capability boundary; tool privilege stays current with code |
| S6  | Static artifact import (foundry, anchor, OpenAPI partial)                                 | Evidence anchored to source, not just runtime                           |
| S7  | HTTP scan with auth profile injection                                                     | Credentials never enter LLM context                                     |
| S8  | Phase FSM + capability-pack routing + technique-pack on-demand reads                      | Bounded evaluator brief; evaluated context selection                       |
| S9  | Coverage and dead-end logging                                                             | No duplicate testing within evaluate                                        |
| S10 | Evaluator brief + structured handoff + finalization marker                                   | Bounded subagent contract, validated by SubagentStop                    |
| S15 | OSS-container substrate (`bob_init_repo_session`, `bob_repo_prepare_env`, `bob_repo_docker_run`) | Local-repo-first OSS evaluation container: init never clones, `--network none` default, read-only `/src`, session-writable `/work`, O-P3 sandbox floor |

**Invariant:** any capability that violates a slab property — embedding credentials in a brief, advancing state without manifest refresh, holding artifacts without content-addressing, bypassing replay-lease typing — is a regression even if it works in demo. Reject at PR review. For `S15`, binding a repo session never clones (`source_url` is provenance only); `--network none` and read-only `/src` are defaults, and a capability may relax network or mount mode only through explicit `allow_network` / `read_write` controls while staging writes under `/work`, never by re-enabling clone in init.

## Pillars — indexes (`I1`–`I8`)

Each index is a pre-computed structure that turns one or more capabilities into a bounded graph or schema query. Without indexes, capabilities collapse to "stuff every artifact in context" and lose sharpness — attention dilution, hallucinated correlations, blown context budgets.

### I1 — Surface graph

**Status.** Engineering-complete pending parishioner gate. Data store + query kernel + builder + MCP tools + brief integration all shipped. Web and smart-contract evaluator briefs now carry a `surface_graph_slice` that ranks related endpoints, subdomains, tech, js_files, secret_markers, and (via second-hop endpoint→auth_scheme edges) claimed_auth_schemes by edge count, capped at 5 by default with a 25 hard ceiling. JS-extraction edges and HTTP-audit-observed edges remain queued as future ingest paths; the builder accepts them via the same `appendEdges` contract whenever the new sources land.

**What it holds.** Edges between (subdomain, endpoint, JS file, OpenAPI spec, archived URL, parameter, hostname, secret marker). Nodes are content-addressed. Edges carry source and confidence.

**Failure mode it prevents.** The LLM hallucinating correlations across artifacts because it has all of them in one prompt and no structure.

**Predecessors.** Substrate: `S5, S7, S8, S9`. Ingestion: `IP1, IP6`.

**Unlocks.** `C1` (cross-surface correlation), partial `C3` (file→surface lookup), partial `C4` (endpoint inventory), prerequisite for `I3`.

**DO.** Define edge schema and version it. Build extractor that runs at surface-discovery completion. Persist as `surface-graph.json` per target with content-addressed nodes. Wire into evaluator brief construction so a surface-family evaluator receives a graph slice scoped to its surface, not the full graph.

**REVIEW (engineering).**
- Schema versioned and canonical-hashable.
- Edges deterministic across re-runs (same inputs → same edges → same hash).
- Per-surface graph slice fits ≤5k tokens for orchestrator queries; per-edge dereferenced detail ≤2k.
- Stale-artifact cleanup integrates with v2 manifest refresh.
- Fixture target with known JS bundle + OpenAPI spec → expected edge set.

**REVIEW (parishioner).**
- Run on a real authorized target.
- Did surface-family evaluators use graph queries instead of holding raw artifacts?
- Did at least one finding emerge from a multi-source correlation no single artifact would surface?
- Was orchestrator context-window usage measurably lower than pre-graph baseline?

**Context budget.** Orchestrator query ≤5k. Per-edge dereference ≤2k. Full slice for one surface ≤15k hard cap.

### I2 — Schema-contract corpus

**Status.** Complete. Source coverage (OpenAPI 3, GraphQL SDL, Postman v2.1), persistence with content-hash dedup, orchestrator-only MCP tools (`bob_ingest_schema_doc`, `bob_query_schema_contracts`), and assignment-brief `schema_slice` integration all shipped. Web evaluators now receive an endpoint-filtered, budgeted slice of the corpus alongside techniques, traffic, audit, intel, and static-scan hints.

**What it holds.** Parsed contracts from OpenAPI / GraphQL / Postman collections. Each contract is `(endpoint, method, claimed_auth, claimed_params, claimed_response_shape, source_doc_hash)`.

**Failure mode it prevents.** Treating prose docs as opaque text. Forces the doc into a deterministic, diffable shape so differential testing can run without LLM in the inner loop.

**Predecessors.** Substrate: `S5, S6`. Ingestion: `IP2`.

**Unlocks.** `C2` (doc-vs-behavior delta), partial `C4` (response shape comparison), feeds `I4`.

**DO.** Build OpenAPI / GraphQL / Postman parsers. Normalize into the contract tuple. Hash each contract. Store as `schema-contracts.jsonl` per target. Provide `bob_query_schema_contracts` tool for orchestrator queries.

**REVIEW (engineering).**
- Parsers cover OpenAPI 2/3, GraphQL SDL, Postman v2.1.
- Contract tuples canonical-hashable; same input doc → same hash.
- Tool returns ≤5k token slice per query (paginated).
- Malformed input doesn't block ingestion (warning + skip, like technique registry).

**REVIEW (parishioner).**
- Did the corpus produce ≥1 doc-vs-behavior divergence on a real authorized target?
- Were divergences classifiable into (security bug, doc bug, test infra quirk)?
- Did the LLM-on-divergence subagent stay within budget?

**Context budget.** Per-contract tuple ≤500 tokens. Per-divergence triage subagent ≤5k.

### I3 — Symbol-to-surface index

**Status.** Library shipped (`mcp/lib/symbol-surface-index.js` + `test/symbol-surface-index.test.js`, 13 tests passing). `buildSymbolSurfaceIndex({ target_domain, route_records, surfaces? })` consumes IP6 route records and the target's `attack_surface.json` surfaces, normalizes route paths (`/users/:id` ↔ `/users/{id}` ↔ `/users/<int:id>`) so framework-flavored placeholders all map to the same surface slot, and emits `symbol-surface-index.json` with `by_file_line`, `by_file`, and `by_surface` lookups plus a content-addressed `index_hash`. `summarizeImpactedSurfacesForDiff({ diff_files })` answers C3's central question: "given this code diff, which surfaces does it touch?" — returning impacted entries and impacted_surface_ids. MCP tool wrappers and IP3 (repo polling for diffs) land in subsequent slices.

**What it holds.** `(file:line → endpoint → surface)` mapping built from static analysis of authorized public repos. Edges back to `I1`.

**Failure mode it prevents.** Diffs that touch impactful surfaces being missed because there's no edge from changed code to the live surface bob evaluations.

**Predecessors.** Substrate: `S6`. Ingestion: `IP6`. Pillars: `I1`.

**Unlocks.** `C3` (diff-aware regression evaluating).

**DO.** Static analysis pass extracting handler→route→surface mappings (Express, Flask, Django, Spring, Rails, Go HTTP, etc.). Index by `file:line`. Refresh on commit hash change.

**REVIEW (engineering).**
- Coverage report per language framework: % of routes resolved.
- Index canonical-hashable per repo commit.
- Stale on commit drift; refresh deterministic.

**REVIEW (parishioner).**
- Given a real diff on a real repo, did the index correctly identify ≥80% of impacted surfaces?
- Did diff-driven evaluations produce findings shorter wall-clock than equivalent baseline evaluations?

**Context budget.** Per-diff dispatch ≤2k tokens for the surface-list. Surface-detail dereference ≤2k each.

### I4 — Auth-differential matrix

**What it holds.** Per-target, per-endpoint, per-auth-profile response signatures: status, header set, body shape hash, sensitive-field presence, latency band. Sparse — only populated for endpoints exercised.

**Failure mode it prevents.** Authz bug-class regressions slipping past because the comparison is ad-hoc per finding.

**Predecessors.** Substrate: `S5, S7`. Pillars: `I1` (endpoint enumeration).

**Unlocks.** `C4` (multi-account differential by default).

**DO.** During EVALUATE, every payload runs across all available auth profiles by default. Responses programmatically diffed and recorded into `auth-differential.jsonl` per target. Suspicious-row threshold (configurable: status delta, body-hash delta, sensitive-field delta) triggers LLM triage subagent.

**REVIEW (engineering).**
- Differential runs deterministic given fixed inputs.
- Sensitive-field detection covers common patterns (PII, internal IDs, role markers).
- Runner respects replay-lease typing — no double-fire of destructive endpoints across profiles.
- Triage subagent budget enforced.

**REVIEW (parishioner).**
- Did the matrix surface ≥1 authz finding on a real target?
- False-positive rate (triaged divergences that weren't bugs) reasonable?

**Context budget.** Per-row ≤300 tokens. Per-suspicious-row triage subagent ≤5k.

### I5 — Audit-to-invariant template corpus

**Status.** Library shipped (`mcp/lib/invariant-template-corpus.js` + `test/invariant-template-corpus.test.js`, 12 tests passing). Built-in catalogue of 7 Foundry invariant templates covering reentrancy (external-call-then-state-update via callback), access_control (unauthorized EOA call), arithmetic_overflow (edge values), oracle_manipulation (spot-price flash deposit), unchecked_call (mockCall + revert), signature_validation (signature replay), and delegatecall_storage (slot-zero protection). Each template carries `parameter_slots` for the orchestrator to fill from a claim's scope_paths or live target metadata. `suggestInvariantsForFinding(finding, { slot_values?, limit? })` returns suggestions with `unfilled_slots` reporting the gap when slot_values are partial. `suggestInvariantsForReport(parsedReport)` groups suggestions per vulnerability_class. `bob_suggest_invariants` MCP tool surfaces this for orchestrator-driven invariant selection. C5 (Foundry runner integration) ties this corpus to `bob_foundry_run` in the next slice.

**What it holds.** Templates of (vulnerability prose pattern → Foundry invariant code pattern). Built incrementally from past audit reports. Each template has examples, applicability rules, parameterization.

**Failure mode it prevents.** Re-deriving invariants from scratch per audit. Templates compound: corpus grows, per-audit subagent gets cheaper.

**Predecessors.** Substrate: `S3, S6`. Ingestion: `IP4`. Historical optional pillar: `I6` was intended as a memory layer over time, but the live HEAD path was deleted by `c02179c`.

**Unlocks.** `C5` (LLM-authored invariant fuzzing).

**DO.** Pipeline: audit report → chunked findings → per-finding subagent generates invariant + applicability rule → human reviews first batches to seed corpus → corpus queryable by audit class / contract pattern.

**REVIEW (engineering).**
- Templates parameterized cleanly (no hard-coded contract addresses).
- Invariants compile under Foundry as-is.
- Per-finding subagent stays within budget; full audit doesn't enter context.
- Replay-lease typing on the harness pack ensures concurrent evaluations don't corrupt local Foundry workspace.

**REVIEW (parishioner).**
- Run on a real audited target. Does ≥1 generated invariant produce a counterexample on the deployed bytecode?
- For programs with public bug bounty (Immunefi etc.): is the counterexample submission-grade?

**Context budget.** Per-audit-finding subagent ≤8k. Per-counterexample triage subagent ≤5k.

### I6 — Findings vector index

**Status. SUPERSEDED — index deleted.** The 2026-05-10 shipped implementation was removed in `c02179c` ("Delete finding-store, findings-index, findings: claims is solo"). At HEAD, `mcp/lib/findings-index.js`, `finding-store.js`, `findings.js`, and the `bob_index_candidate_claim` / `bob_query_candidate_claims_index` tools are gone; no `priors_slice` injection survives in `assignment-brief.js`; the old `calibration_label` record slot is gone. The only residual cross-target-prior primitive is the orphaned `mergePriorClaimMatches` helper in `mcp/lib/claim-clusters.js`, currently consumed only by tests. Plane-Delta rebuilds this line as `I13` on the claims subsystem, not by assuming the old index is live.

**Historical design — not in HEAD. What it held.** Vector embeddings of past findings: `(description, target stack, attack class, severity, evidence summary, calibration label)`. Calibration label came from grade verdicts and adjudication archive — ground truth signal for what was real.

**Historical design — not in HEAD. Failure mode it prevented.** Each evaluate starting from zero. Bob's accumulated experience invisible to itself.

**Historical predecessors.** Substrate: `S1, S2` (manifest provides calibration ground truth). Existing: grade verdicts, adjudication archive.

**Historical unlocks.** `C6` (cross-target pattern memory). Augmented `C1, C2, C3, C5, C7, C8` by injecting top-K similar prior findings into evaluator briefs.

**Historical design — not in HEAD. DO.** Embedding pipeline runs on every shipped claim. Vector store (sqlite-vss or similar lightweight choice). Query API: `bob_query_candidate_claims_index(surface_discovery_summary, top_k)` returns compact summaries. Wire into brief construction so new evaluations open with relevant priors.

**Historical REVIEW (engineering).**
- Pipeline idempotent — same finding hashes to same embedding key.
- Calibration labels (`real`, `rejected_duplicate`, `rejected_intended`, `rejected_oos`) wired from adjudication archive.
- Query returns ≤5k token summary regardless of corpus size.
- Index handles incremental growth without full rebuild.

**Historical REVIEW (parishioner).**
- Does a evaluate with the index reach a finding faster than a baseline evaluate without?
- Does the index reduce duplicate findings (bob re-finding the same class on same target)?

**Context budget.** Per-query injection at evaluate start ≤2k. Per-similar-finding summary ≤200 tokens.

### I7 — Chain state tree

**Status.** Engineering-complete pending parishioner gate. Library + four MCP tool wrappers (`bob_append_chain_node`, `bob_query_chain_tree`, `bob_chain_frontier`, `bob_chain_ancestry`) all shipped, plus a chain-attempt orchestrator playbook hint that points the orchestrator at the new tools. The orchestrator can now record branching attempts, walk the frontier to pick the next tip, mark dead branches `pruned`, re-pin to a known-good `state_hash` for backtracking, and rebuild lineage for evidence — all without a separate runner. Full search-loop integration (the orchestrator literally driving BFS/DFS over the frontier per lifecycle state) lands as Tier 3's C7 deliverable when the parishioner gate produces a real branching chain claim.

**What it holds.** Per-engagement, content-addressed branch nodes. Each node = `(parent_state_hash, action, observed_outcome, verdict)`. Tree shape; orchestrator holds frontier.

**Failure mode it prevents.** Linear chain-attempt sequencing that can't backtrack from a failed branch. Real chains are 5–10 steps with dead ends; the legacy single-pass chain-attempt path is ~2 steps shallow.

**Predecessors.** Substrate: `S1, S3, S8`. Pillars: `I1` (for action proposals).

**Unlocks.** `C7` (branching chain search).

**DO.** Extend chain-attempt orchestration. Each chain attempt becomes a tree node, hashed by parent + action. Heuristic pruner (deterministic, above LLM): "this branch failed for reason X on target Y — skip." Frontier exploration with budget cap. Replay leases govern which branches can run in parallel.

**REVIEW (engineering).**
- Tree serialization canonical-hashable.
- Backtracking re-pins to known state hash without replay-unsafe side effects.
- Pruner rules deterministic; same tree state → same prune set.
- Per-node subagent budget enforced.

**REVIEW (parishioner).**
- Did a real chain require backtracking, and did the tree handle it?
- Did the resulting chain reach a verified outcome that flat chain-attempt sequencing couldn't?

**Context budget.** Frontier in orchestrator ≤5k. Per-node subagent ≤8k.

### I8 — CVE-to-corpus matcher

**Status.** Library shipped (`mcp/lib/cve-scope-matcher.js` + `test/cve-scope-matcher.test.js`, 14 tests passing). `matchCveAgainstScope({ cve_record, surfaces, schema_contracts? })` walks each CVE's `affected_products`, tokenizes vendor + product against a per-surface index built from `tech_stack` (high confidence), tokenized hosts (low confidence), and surface_type. Sorts matches by confidence then by surface_id. `matchCveBatch` aggregates per-CVE results with totals. Matches carry `cve_version_range` (start/end inclusive/exclusive) so downstream version-gating logic has the upstream constraint without re-parsing the CVE. `match_hash` is content-addressed so re-runs against the same scope+CVE record hash identically. Optional `schema_contracts` pass annotates host-matched rows with `schema_corpus_confirms_host` when a contract source URI's hostname matches the same host token. `normalizeTechStackToken` strips `lib-` prefix and `-js`/`-py`/`-rb`/`-go`/`-java`/`-ts` suffixes only when separator-prefixed so legitimate names like `django` and `library` are preserved. **Substrate only** — C8 (live speedrun activation) remains policy-gated; the matcher is usable today for offline triage.

**What it holds.** Index over authorized scope by `(stack, version_range, surface_kind)`. Plus a normalized form of incoming CVE/disclosure data: `(vulnerable_software, version_range, vector, indicator_of_vulnerability)`.

**Failure mode it prevents.** Per-CVE manual triage of which authorized targets are affected.

**Predecessors.** Substrate: `S5`. Ingestion: `IP5`. Pillars: `I1` (for surface match), `I3` (for stack inference).

**Unlocks.** `C8` (live disclosure speedrun).

**DO.** Periodic pull of NVD / GitHub Security Advisories / vendor disclosures. Normalize. Match against scope corpus. Match → emit `disclosure-match.jsonl` event. Orchestrator consumes events and dispatches per-match evaluate subagents.

**REVIEW (engineering).**
- Matcher false-positive rate measured (matched targets that aren't actually vulnerable).
- Match operations canonical-hashable for replay.
- Dispatch respects per-target rate limits and program AI-evaluating policy.

**REVIEW (parishioner).**
- For a real CVE matching a real authorized target: did the speedrun produce a verified finding within the same day as disclosure?
- Was the finding submission-acceptable under program policy?

**Context budget.** Match-frontier in orchestrator ≤5k. Per-match evaluate subagent ≤10k.

## Pillars — ingestion paths (`IP1`–`IP6`)

| ID  | Path                                          | Status            | Feeds            |
| --- | --------------------------------------------- | ----------------- | ---------------- |
| IP1 | JS extraction (current surface-discovery pipeline)        | Existing, partial | `I1`             |
| IP2 | OpenAPI / GraphQL / Postman ingestion         | Complete (OpenAPI 3, GraphQL SDL, Postman v2.1)               | `I2` |
| IP3 | Public-repo watcher with diff dispatch        | New               | `I3` (via `I1`)  |
| IP4 | Audit report ingestion (PDF, markdown, HTML)  | In progress (markdown shipped; HTML / PDF pending) | `I5`             |
| IP5 | CVE / advisory feed ingestion                 | In progress (NVD 2.0 + 1.x parser shipped; matcher in I8 next) | `I8` |
| IP6 | Static analysis pass (file:line → handler)    | In progress (route extractor for Express, Koa, Fastify, NestJS, Flask, Django, Spring shipped; AST-grade extraction queued) | `I1`, `I3` |

Each ingestion path has its own do→review cycle. Engineering review checks idempotence, hash determinism, and bounded output size. Parishioner review for ingestion is "does the index it feeds become useful?" — ingestion alone is not parishioner-visible.

## Roof — capabilities (`C1`–`C8`)

Each capability is a evaluating mode that produces findings a triager recognizes. Implementation may be one or more new capability packs, plus index queries, plus orchestrator routines.

### C1 — Cross-surface correlation

**Status.** Engineering-complete pending parishioner gate. Closes once I1's brief integration ships, which it has: evaluators receive a `surface_graph_slice` in their brief that lets them cross from "the surface I'm assigned" to related endpoints, subdomains, JS files, leaked secret markers, and claimed auth schemes without leaving the brief. Multi-source correlation (e.g., "this internal admin endpoint surfaces in JS but is documented in OpenAPI with bearer auth") emerges from second-hop walks the orchestrator can run via `bob_query_surface_graph` mode `neighbors`. Parishioner gate stays open until C1 produces a candidate claim from a multi-source correlation no single artifact would have surfaced.


**Pedagogical note.** A skilled evaluator chains "JS bundle leaks internal API → docs hide an admin endpoint → another subdomain's OpenAPI dump reveals param shape" maybe once a week. Bob with `I1` does this across dozens of targets concurrently. The leverage is not in finding *one* correlation — it's in finding the long tail of correlations no individual evaluator has time to chase.

**Predecessors.** Substrate: full slab. Pillars: `I1` (primary). Historical optional `I6` pattern memory is superseded by `c02179c`.

**DO.** Add correlation-query routine to orchestrator: form hypothesis (e.g., "internal admin endpoint reachable from JS"), query `I1` for matching paths, dereference matched artifacts, dispatch verification. New capability pack `web-cross-surface` for follow-up.

**REVIEW.** Engineering: correlation queries deterministic; hypothesis-formation subagent budget enforced; dereferencing respects per-edge cap. Parishioner: ≥1 finding from a multi-source correlation no single artifact would have surfaced.

### C2 — Doc-vs-behavior delta evaluating (Tier 1, first ship)

**Status.** Engineering-complete pending parishioner gate. Divergence-detection kernel, DI-style differential runner, `bob_http_scan` adapter, MCP tool wrapper `bob_run_doc_delta`, assignment-brief `schema_slice` integration, and orchestrator playbook section (`prompts/roles/orchestrator.md` "Optional: Doc-vs-Behavior Differential") all shipped. The "capability pack" planned in the original hyperedge resolved to an orchestrator-driven workflow rather than a evaluator-routed pack, because C2 produces claims via differential testing the orchestrator drives, not via a per-surface evaluator sub-agent. Triage of prose-only contracts (LLM subagent) remains a quality-of-life refinement; the existing severity_class taxonomy (`security`, `info_leak_potential`, `doc_or_infra`) already drives a useful triage default. Parishioner gate stays open until C2 produces ≥1 candidate claim accepted by a real triager.

**Pedagogical note.** Every public-facing API is two systems — the documented contract and the deployed behavior. The delta is bug surface. Skilled evaluators find these one endpoint at a time. Bob with `I2` finds them across full scope mechanically. The LLM is needed only on prose-only docs (no formal spec) and on triage of divergences.

**Why first ship.** Highest yield. No NDA risk. No AI-ban risk. Plays directly to bob's context-window advantage. Requires only `IP2` + `I2` (cheapest pillar to build). Produces findings a triager recognizes on day one.

**Predecessors.** Substrate: `S5, S7, S8`. Pillars: `I2` (primary), partial `I1` (endpoint enumeration).

**DO.** Ship `IP2` → `I2` → new capability pack `web-doc-delta` → orchestrator wiring → first evaluate on a real authorized target with public OpenAPI.

**REVIEW.** Engineering: differentials deterministic; per-divergence subagent ≤5k; findings flow through v2 verification with hash-stable evidence. Parishioner: ≥1 actionable finding. ≥3 high-quality candidates ready for submission. Ideally: ≥1 accepted by a triager.

**GATE for advancing to Tier 2.** This.

### C3 — Diff-aware regression evaluating

**Status.** Engineering-complete pending parishioner gate. The full path ships in this branch: regex-based route extractor (IP6) → symbol-to-surface index (I3) → unified diff parser (IP3) → `bob_summarize_diff_impact` (C3 entry point). Orchestrator workflow: extract routes from authorized public repo via `bob_extract_routes`, build the index via `bob_build_symbol_surface_index`, then for each diff (webhook payload or `git diff` output) call `bob_summarize_diff_impact` to get back the `impacted_surface_ids` to feed into `bob_start_wave` for a focused regression evaluate. AST-grade extraction is queued for the cases the regex misses; an actual repo-poller (cron-style watcher) is operator-driven for first slice — the orchestrator can poll periodically or accept diffs from a webhook tool the operator configures externally. Parishioner gate stays open until C3 produces ≥1 regression claim on a real target's recent PR.


**Pedagogical note.** "What changed → what broke" is one of the highest-yield human evaluating modes and one of the least-automated. Bob with `I3` + `IP3` watches public repos for authorized targets and dispatches surface-scoped re-evaluations on every diff.

**Predecessors.** Substrate: `S6, S8`. Pillars: `I3` (primary), `I1` (surface lookup), `IP3`, `IP6`.

**DO.** Repo watcher (webhook or polling) → diff parser → `I3` query → spawn one subagent per impacted surface with diff slice + prior findings + tools. New capability pack `web-diff-regression` (and a smart-contract analog later).

**REVIEW.** Engineering: subagent context ≤20k per surface; diff-to-surface mapping accuracy ≥80% on fixture repos; replay-safe re-runs. Parishioner: ≥1 regression finding on a real target's recent PR.

### C4 — Multi-account differential by default

**Status.** Engineering-complete pending parishioner gate. Kernel, DI-style runner, per-call `bob_http_scan` adapter (`makePerCallHttpScanFetcher`), and MCP tool wrapper (`bob_run_auth_differential`) all shipped. The orchestrator can now run multi-account differentials end-to-end: pass a target's endpoint list and ≥2 auth profiles, the tool fans across profiles, classifies divergences, and persists results. Profile metadata defaults auto-flag common unauth profile names (`guest`, `anon`, `noauth`, `public`, `unauthenticated`) so the `unauth_succeeds_where_auth_blocked` security heuristic fires without explicit metadata in the common case. Parishioner gate stays open until `C4` produces ≥1 authz claim accepted by a real triager.


**Pedagogical note.** Authz bugs are mostly "do same thing as user A vs user B, see what differs." Doing this at depth across all endpoints, all role pairs, all tenant boundaries is mechanical but exhausting for humans. Bob with `I4` makes it default.

**Predecessors.** Substrate: `S5, S7`. Pillars: `I1` (endpoints), `I4` (matrix). Existing: `bob_list_auth_profiles`.

**DO.** Modify the surface-evaluation pass to run every web payload across all configured auth profiles by default, recording into `I4`. Suspicious-row threshold triggers triage subagent. Web capability packs gain `multi_account_differential: true` knob.

**REVIEW.** Engineering: differential deterministic; replay-lease typing prevents destructive double-fire across profiles; matrix canonical-hashable. Parishioner: ≥1 authz finding on a real target. False-positive rate stays under threshold (configurable).

### C5 — LLM-authored invariant fuzzing (smart-contract)

**Status.** Engineering-complete pending parishioner gate. `mcp/lib/invariant-runner.js` + `mcp/lib/tools/{run-invariant-for-finding,read-invariant-runs}.js` ship: takes an audit finding (from `bob_query_audit_reports`), generates a Foundry test from `suggestInvariantsForFinding`, writes it into the harness's `test/bob-invariants/` directory, dispatches `bob_foundry_run` against the new test name, classifies the outcome (`test_passed`, `test_failed`, `fork_blocked`, `forge_missing`, `no_template`, `unknown`), and persists per-run records to `invariant-runs.jsonl` keyed by a content-addressed `run_hash`. Pass `dry_run: true` to preview the generated test source without touching the harness or invoking forge — useful for orchestrator triage. Parishioner gate stays open until C5 produces a Foundry counterexample on a real audited target that submission to Immunefi / Cantina / Code4rena would accept.


**Pedagogical note.** Audit reports are prose. Foundry invariants are code. The bridge — generating invariants from prose — is the human bottleneck in invariant fuzzing. Bob with `IP4` + `I5` automates the bridge and runs the resulting invariants on imported bytecode. Counterexamples are real findings.

**Predecessors.** Substrate: `S3, S6`. Pillars: `IP4`, `I5`. Historical optional `I6` template memory is superseded by `c02179c`.

**DO.** Audit ingestion → per-finding subagent → invariant code → Foundry harness run → counterexample → triage subagent → finding. Smart-contract capability pack gains `audit_driven_invariant: true` mode.

**REVIEW.** Engineering: invariants compile cleanly; generated harness files are slot-sensitive and content-addressed enough for normal Bob-vs-Bob concurrency; invariant result persistence is session-locked. The portable filesystem guarantee is honest-harness/resolved-session-root containment plus final-file symlink safety, not protection from a malicious same-UID process replacing validated parent directories. Parishioner: ≥1 counterexample on a real audited target. Submission-grade for a public bounty (Immunefi, Cantina, Code4rena).

**Smart-contract economic gravity.** This is the capability where v2 substrate has direct payout-relevant value. Six-figure bounties exist; reproducibility is contested; harness reuse compounds.

### C6 — Cross-target pattern memory

**Status. SUPERSEDED pending rebuild.** This closed only while `I6` existed. `c02179c` deleted the findings index and the brief-time prior injection, so web and smart-contract evaluators do not currently receive a live `priors_slice`. The remaining cross-target primitive is `claim-clusters.js` `mergePriorClaimMatches`, but it has no production consumer. Plane-Delta scopes the rebuild as `I13`/`C13` over the claims subsystem, with labels sourced from grade verdicts and adjudication instead of the deleted `calibration_label` slot.


**Pedagogical note.** Bob has access to its own past evaluations in principle but not in practice — after `c02179c`, there is no live retrieval layer. `I6` was the retrieval layer in the historical design. The Plane-Delta rebuild must make each new evaluate open with bounded, claims-backed priors calibrated by which prior claims were real.

**Historical predecessors.** Substrate: `S1, S2`. Pillars: `I6`. The current rebuild path is Plane-Delta `I13` over claims.

**Historical design — not in HEAD. DO.** Embedding pipeline on every shipped finding. Vector store. Query API. Wire into evaluator brief construction across all capability packs.

**REVIEW.** Engineering: idempotent ingestion; calibration labels wired; query returns bounded summaries. Parishioner: evaluations using the index reach findings faster than baseline; duplicate-finding rate decreases.

**Augmentation.** This capability also makes every other capability sharper. After a rebuilt retrieval layer ships, `C1`/`C2`/`C3`/`C5`/`C7`/`C8` can benefit from priors-injection again.

### C7 — Branching chain search

**Status.** Engineering-complete pending parishioner gate. Closes once I7's MCP tools land and the orchestrator playbook references them, both of which are now done. The orchestrator can branch attempts from the same `parent_state_hash`, prune dead branches, backtrack to a known-good `state_hash`, and rebuild chain lineage from a leaf state. Replay leases (S3) make backtracking safe: re-pinning to a prior state_hash and trying a different action_kind doesn't double-fire the destructive step the leases protect. Parishioner gate stays open until C7 produces a verified chain that flat chain-attempt sequencing couldn't reach.


**Pedagogical note.** Real impact chains are 5–10 steps with dead ends. The legacy single-pass chain-attempt path handles ~2-step linear. `I7` makes chain-attempt orchestration a tree search with safe backtracking. Replay leases (S3) make backtracking *safe* — without them you can't unwind a destructive step.

**Predecessors.** Substrate: `S1, S3, S8`. Pillars: `I7`.

**DO.** Extend chain-attempt orchestration with tree state. Heuristic pruner. Frontier exploration. Per-node subagent dispatch with replay-safe state pinning.

**REVIEW.** Engineering: tree serialization canonical-hashable; backtracking respects replay leases; pruner deterministic. Parishioner: a chain that flat chain-attempt sequencing couldn't reach. Verified end-to-end.

### C8 — Live disclosure speedrun

**Status.** Held by external dependency — moved out of the active engineering task graph and into the [Held by external dependency](#held-by-external-dependency) section below. Substrate (IP5 NVD parser + I8 scope matcher) is library-complete and usable today for offline analysis. Live activation is the policy-gated step.

## Cross-cutting concerns (`X1`–`X5`)

### X1 — Context budgets formalized per subagent

Make context budgets a typed property of capability packs and orchestrator routines, like replay leases. Every subagent invocation declares its budget; dispatch refuses to spawn over-budget. Observability (X3) records actual usage vs budget.

**Why.** Without enforcement, budgets are aspirational. Substrate becomes load-bearing only when violations are caught at dispatch time.

### X2 — Parishioner-facing surfaces

Substrate work that nobody can see is invisible. Parishioner-facing surfaces translate substrate gains into operator-readable signal:

- `bob-status` v2 panel — **shipped** (`prompts/roles/status.md` "V2 Verification Panel" section, mirrored to `.claude/skills/bob-status/SKILL.md` and `adapters/codex/skills/bob-status/SKILL.md` via the role renderers). Surfaces current attempt + snapshot freshness, adjudication / evidence match status, replay execution policy, and an archive trail showing the up-to-three most recent superseded attempts.
- `/bob-debug --diff-attempts <prev> <curr>` — **shipped** (`mcp/lib/verification-attempt-diff.js` + `mcp/lib/tools/diff-verification-attempts.js` + bob-debug skill update). Cross-attempt diff surfaces snapshot / adjudication / final hash matches plus per-file divergence (only-in-a, only-in-b, and content-changed entries with truncated 16-char hashes). Either side can be `current` for live-vs-archive comparison.
- `bob-export` replay-budget summary — **shipped** (`mcp/lib/bob-export.js`). The release bundle's `manifest.json` carries a `replay_budget` block (per-pack snapshot + totals), and `summary.md` adds a "Replay Budget" section listing capability pack counts (serialized vs parallel-safe), active leases at export time, and a per-pack policy table with mode, lease scope, concurrency hint, and active-lease count.

These ship **alongside** capability ships, not after. After C2's first ship, X2's bob-status panel ships next.

### X3 — Observability

**Status.** Shipped (`mcp/lib/capability-metrics.js` + `mcp/lib/tools/read-capability-metrics.js` + `test/capability-metrics.test.js`, 9 tests passing). Aggregates the existing tool telemetry by capability label (C2 doc-vs-behavior, C4 multi-account, historical I6 candidate-claims index now retracted by `c02179c`, I1 surface graph, I7 chain state tree, X2 verification attempt diff). Per-capability bucket: call_count, success_count, error_count, blocked_count, success_rate, avg_latency_ms, last_called_at, plus per-tool breakdown. `bob_read_capability_metrics` is orchestrator-only; pass `target_domain` to scope to one session, omit for cross-target. Hallucination-flag observability remains queued for the moment a subagent claims an edge the index doesn't support — the framework hook is in place via `bob_query_surface_graph` but the subagent-side detection lives in agent prompts, not in the metrics layer.

Per-capability metrics: index queries fired, hit rates, dereferences, context usage vs budget, hallucination flags (when a subagent claimed a correlation the index doesn't support). Surfaced in `bob-status`.

**Why.** Without observability, capability regressions are silent. Hallucination flags are the early warning for "the LLM stopped using the index and started making things up."

### X4 — Determinism CI

**Status.** Shipped (`test/determinism-ci.test.js`). Per-PR canary that exercises v2-style content-addressed artifact pipelines this branch added (schema corpus, doc-delta, auth-differential, surface graph; the historical findings-index leg was removed by `c02179c`) against fixture inputs and asserts: (a) per-record content-hash sets (`contract_hash`, `edge_hash`) reproduce identically across two independent target_domain runs of the same pipeline, (b) `results_hash` for doc-delta and auth-differential is stable across re-runs against the same target, and (c) `results_hash` legitimately diverges across target_domains so future churn that drops `target_domain` from the canonical payload silently breaks per-target replay bookkeeping. The first run of the canary surfaced a real engineering quality finding (per-record timestamps in JSONL artifacts make raw file bytes drift even though the content hashes don't), now documented in the test as the reason content-hash sets, not raw file hashes, are the right replay invariant to assert.

Per-PR CI invariant: same input artifacts → same canonical hashes across runs. Built on G regression test from PR #20.

### X5 — Capability evaluation harness

**Status.** Shipped (`mcp/lib/capability-eval-harness.js` + `mcp/lib/tools/evaluate-capabilities.js` + `test/capability-eval-harness.test.js`). `FIXTURES` registers one runner per live post-v2 capability that exercises a synthetic input and asserts an expected outcome (C2 doc-vs-behavior emits an auth-bypass divergence; C4 multi-account flags `unauth_succeeds_where_auth_blocked`; I1 records edges queryable by source/target; I7 branches into two distinct frontier leaves). The older I6 fixture claim is retracted with the `c02179c` deletion. `evaluateAllFixtures()` runs every fixture and tallies passed/failed. `bob_evaluate_capabilities` is orchestrator-only; pass `fixture: '<name>'` to run one or omit to run all. Fixtures use unique session domains and clean up after each run so the harness leaves no fingerprint on real session storage.

Per-capability fixture: a known authorized target with seeded findings. Evaluations run against the fixture must produce expected findings deterministically. Regressions caught before parishioner review.

**Why.** Parishioner review is expensive (real targets, real triagers). Evaluation harness catches regressions cheaply.

## Hyperedges — full dependency map

| Edge ID | Predecessors                                  | Unlocks                          |
| ------- | --------------------------------------------- | -------------------------------- |
| H-IP1   | (existing surface-discovery)                              | partial `I1`                     |
| H-IP2   | `S5, S6`                                      | `I2`                             |
| H-IP3   | `S5`                                          | `I3` (via `I1`)                  |
| H-IP4   | `S6`                                          | `I5`                             |
| H-IP5   | `S5`                                          | `I8`                             |
| H-IP6   | `S6`                                          | `I1` (full), `I3`                |
| H-I1    | `S5, S7, S8, S9, IP1, IP6`                    | `C1`, partial `C3`, partial `C4`, `I3` |
| H-I2    | `S5, S6, IP2`                                 | `C2`, partial `C4`               |
| H-I3    | `S6, IP6, I1`                                 | `C3`                             |
| H-I4    | `S5, S7, I1`                                  | `C4`                             |
| H-I5    | `S3, S6, IP4`                                 | `C5`                             |
| H-I6    | `S1, S2`                                      | SUPERSEDED by `c02179c`; rebuild on claims subsystem in Plane-Delta `I13` |
| H-I7    | `S1, S3, S8`                                  | `C7`                             |
| H-I8    | `S5, IP5, I1, I3`                             | `C8`                             |
| H-S15   | `S5`                                         | `S14`, `I9`, `I10`, `IP7`, `IP8`, `C10`, `C12` |
| H-C1    | full slab, `I1`; historical `I6` augmentation superseded | findings                         |
| H-C2    | `S5, S7, S8, I2`, partial `I1`                | findings                         |
| H-C3    | `S6, S8, I3, I1, IP3, IP6`                    | findings                         |
| H-C4    | `S5, S7, I1, I4`                              | findings                         |
| H-C5    | `S3, S6, IP4, I5`; historical optional `I6` superseded | findings                         |
| H-C6    | SUPERSEDED by `c02179c` (`I6` deleted)        | rebuild as Plane-Delta `I13`/`C13` |
| H-C7    | `S1, S3, S8, I7`                              | findings                         |
| H-C8    | `S5, IP5, I8, I1, I3`                         | findings                         |
| H-X2    | substrate per-capability                      | parishioner visibility           |

## Tiered sequencing

The order is engineered so each tier produces parishioner-visible findings before the next tier starts. Substrate maintenance items are pulled in only when a capability ship demands them.

### Tier 1 — first ship (high leverage, short path)

1. `IP2` → `I2` → `C2` (doc-vs-behavior delta evaluating)
2. `X2` ship: `bob-status` v2 panel (parishioner visibility into v2 substrate)
3. Partial `IP6` → partial `I1` → partial `C4` (multi-account differential, web-only mode)

**Gate.** `C2` produces ≥1 actionable finding on a real authorized target. Ideally accepted by a triager.

### Tier 2 — surface graph and pattern memory

4. Full `IP6` → full `I1` → `C1` (cross-surface correlation)
5. `IP3` → `I3` → `C3` (diff-aware regression evaluating)
6. Historical `I6` → `C6` (cross-target pattern memory) — superseded by `c02179c`; rebuild tracked as Plane-Delta `I13`/`C13`
7. `X2` ship: cross-attempt diff in `/bob-debug`

**Gate.** `C1` + `C3` each produce findings on at least one shared target. Historical `C6` gate is re-opened by the `I6` deletion and moves to the Plane-Delta claims-backed rebuild.

### Tier 3 — depth and smart-contract economic gravity

8. `IP4` → `I5` → `C5` (LLM-authored invariant fuzzing) — smart-contract focus
9. `I7` → `C7` (branching chain search)
10. `X2` ship: replay-budget summary in `bob-export`

**Gate.** `C5` produces ≥1 invariant counterexample on a real audited target. Submission-grade. `C7` produces a chain that flat chain-attempt sequencing couldn't.

### Tier 4 — disclosure speedrun and substrate maintenance

11. Program-level conversation about AI evaluating policy. **Do not ship `C8` without it.**
12. `IP5` → `I8` → `C8` (live disclosure speedrun)
13. `X4` (determinism CI), `X3` (observability), `X5` (capability evaluation harness) — substrate maintenance for the system at scale

**Gate.** `C8` produces a finding on day-of-disclosure, accepted by program.

## Do→Review cycle template

For every work item in this hypergraph:

**DO.**
1. Spec — write a one-page contract covering inputs, outputs, predecessors, context budget.
2. Build — implement with tests alongside.
3. Wire — integrate into existing brief / pack / orchestrator surfaces.
4. Ship — one commit per coherent slice; PR per work item or tight bundle.

**REVIEW (engineering).**
- Unit + integration tests passing.
- Context budget compliance (hard caps, observability records actual usage).
- Determinism (same inputs → same hashes across runs).
- Failure-mode coverage (orphan, partial, replay-unsafe, malformed input).
- Slab invariants preserved (no credential leakage, no unreffed state, etc.).

**REVIEW (parishioner).**
- Run on a real authorized target.
- Count actionable findings.
- Count false positives.
- Triager-recognition test (at least informal — would a HackerOne / Immunefi triager close this as duplicate / informational / valid?).
- Compare against pre-ship baseline (capability previously not present → was the gain real?).

**GATE.** Do not advance to the next item without passing both reviews. Do not proceed to the next tier without the tier gate passing on a real target.

## Held by external dependency

Items intentionally excluded from the engineering task graph because external (non-engineering) dependencies must resolve first. The framework's job is not to ship these.

### C8 — Live disclosure speedrun (held: program-level AI-evaluating policy)

The substrate ships and the matcher works (IP5 + I8 land as library-only); the live dispatch loop is the held step. The doc explicitly forbids shipping the activation without "at least one program has explicit policy permitting [AI-driven speedrun]." That conversation is operator/business work, not engineering work — adding the dispatch wrapper before the conversation would tempt premature use against programs whose policy hasn't been confirmed, which is the failure mode the rule exists to prevent.

When a program does grant explicit policy permission, the residual engineering is small: a thin orchestrator-side dispatch wrapper that calls `matchCveBatch` against the parsed feed, iterates impacted scope rows under per-program rate limits, and dispatches the existing wave system at each match. That wrapper should land in the same PR as the policy documentation it depends on.

## Anti-patterns (reject at PR review)

1. **Substrate-as-trajectory.** Shipping more substrate without a capability ship pulling on it. Substrate is a ratchet, not a destination.
2. **Context-as-strategy.** Solving any capability problem by widening the context window. Reach for an index instead.
3. **Capability without parishioner review.** Shipping a capability that passes engineering review but never runs against a real target. The findings count is the proof.
4. **Index without consumer.** Building an index speculatively because it might be useful. An index ships when its first consumer ships.
5. **Cathedral cadence.** Two substrate items in a row with no parishioner-facing ship between them.
6. **Hallucinated correlation, surfaced as feature.** A capability that produces findings the underlying index can't support. Observability (X3) catches this; PR review enforces it.

## Open questions

1. **Embedding model for `I6` (historical).** Local (e.g., bge-small) vs API (Voyage, Cohere, Anthropic). Superseded by `c02179c`; any future representation choice belongs to the Plane-Delta claims-backed `I13`/`C13` rebuild.
2. **Repo watcher mechanism for `IP3`.** GitHub webhooks vs polling. Webhooks need a callback service; polling is simpler but less timely. Likely polling first.
3. **Audit ingestion format coverage for `IP4`.** PDF parsing is hard. Start with markdown + HTML; add PDF when a target requires it.
4. **CVE feed source for `IP5`.** NVD lags; vendor advisories are heterogeneous. Likely composite ingestion.
5. **Program negotiation strategy for `C8`.** Out of scope for this doc; but the negotiation must precede the engineering.

## Progress log

Append-only, newest first. Each entry: date, item, slice, commit ref, parishioner-review status.

- **2026-06-07** · I12 + IP8 + C14 · Plane-Delta PR4 prompt quick wins closed · OSS capability packs now route `brief_profile: "oss"` while preserving generic evaluator spawning, so OSS assignment briefs render repo workflow, governance, code-surface context, OSS technique packs, and repo-scoped CLI tool surfaces instead of inheriting the web brief extras. `mcp/lib/repo-target.js` adds bounded seed-corpus inventory summaries (`fuzz/corpus`, `seeds`, `testdata`, `*_seed_corpus{,.zip}`) with sample paths, byte counts, symlink escape protection, per-corpus hashes, and an aggregate `seed_corpus_hash`; `mcp/lib/repo-env.js` threads discovered seed corpora into C/C++ `recommended_commands[]` as a conservative `role: "fuzz"` seed probe. Reporter/evaluator prompts now carry OSS-specific CWE/CVSS/reference guidance and seed-corpus fuzz-run instructions. Stigmergy manifests register `oss_technique_pack_registry` → `assignment_brief_oss_technique_pack_renderer`; generated Claude/Codex evaluator surfaces were regenerated. Engineering/fixture only; no parishioner finding. Full `npm test` green.
- **2026-06-07** · C9 · OSS severity ceiling closed at grade time · `mcp/lib/reachability-ceiling.js` adds the pure cap/lift truth table and resolves `finding_id` → frozen claim `surface_ids[]` → I9 `repo-inventory.json` surface ceilings. `mcp/lib/grade-verdict-store.js` now stamps each graded finding with `{recorded_severity, severity_ceiling, attack_vector, network_reachable, graded_severity, disposition, defensible}` after final verification is validated; caps change the displayed `graded_severity` only and leave final reportable membership on the recorded verification severity, preserving cap-never-kill. Direct grade writes reject unresolved final-reportable `repo:module:*` reachability when I9 is present, while manifest/dependency/CI/config-style repo surfaces are not false-blocked by the native-module stamp gate. `mcp/lib/lifecycle-gates.js` adds a repo-only VERIFY→GRADE blocker when I9 exists but a final reportable stamped-surface finding cannot resolve a reachability stamp; web/pre-I9 sessions no-op. The reporter role now renders `reachability.graded_severity` as public severity when present. S12 registration includes `repo_inventory_reachability_stamp` → `grade_verdict_reachability_ceiling_reconciler`. Engineering fixture covers HIGH+AV:L→MEDIUM cap without dropping the finding, direct-write refusal for stale native stamps, non-native no-op gating, and the soft lifecycle gate. Δ1 engineering gate is now satisfied; PR4 prompt-only ride-alongs remain outside the gate.
- **2026-06-07** · I9 + S12 · OSS reachability/severity-ceiling producer restored; silent-drop guard re-armed · `mcp/lib/reachability.js` restores the bounded local-file reachability classifier from `d1647c0` + `1a456f1` in standalone form: ≤50 priority files + ≤80 fallback native files, 150 KiB/read, path-keyed `net_call` / `server_path` / `systemd_unit` / `expose` signals capped at 14, no shell and no network. `mcp/lib/repo-target.js` now writes `inventory.reachability`, includes it in `inventory_hash`, stamps native `surface.observed` payloads with `attack_vector`, `severity_ceiling`, and `network_reachable`, and preserves repo-root binding on `repo_path` overrides. `frontier-materializer.js` / `frontier-projections.js` now preserve those scalars into `surface-index.json` / `currentSurfaces()`. S12 registers `repo_inventory_reachability_stamp` → `assignment_brief_reachability_triage_renderer` in the stigmergy manifests, adds runnable guard coverage for `reachability.js` / `repo-target.js`, and makes `mcp-test-discovery.test.js` fail if any `test/*.test.js` file is absent from `mcp-test-manifest.json` and every package test script. Engineering/fixture only; no parishioner finding. Δ1 gate still waits on C9 grade-time lift/cap.
- **2026-06-07** · S15 + DOC-1 · OSS-container substrate registered as a slab node; stale I6 shipped claim corrected · `docs/capability-hypergraph.md` now names the already-shipped `bob_init_repo_session` / `bob_repo_prepare_env` / `bob_repo_docker_run` substrate as `S15`, pins the O-P1 invariants (init never clones, `--network none` default, read-only `/src`, writable `/work`), and retracts the deleted `I6` findings-index/`priors_slice` claims. `docs/plane-delta/nodes.json` and `hyperedges.json` already repoint the OSS cluster (`S14`, `I9`, `I10`, `IP7`, `IP8`, transitive `C10`/`C12`) from the stale `S6` label to `S15`. Engineering/fixture only; no parishioner finding.
- **2026-06-07** · I9 (regression record) · OSS reachability/severity-ceiling PRODUCER dropped at the v2.1/Plane-O merge · Plane-Delta verification found no `reachability` emitted by `buildRepoInventory` (`mcp/lib/repo-target.js`) while consumers remained wired and inert in `mcp/lib/dashboard.js`, `mcp/lib/assignment-brief.js`, and `mcp/lib/wave-brief-derivation.js`. The restore source was blobs `d1647c0` + `1a456f1`; the PR2 log entry above records the branch-local restore. Engineering/fixture only.
- **2026-05-10** · Hypergraph closure · Re-classified C8 (live disclosure speedrun) out of the active engineering task graph into a new "Held by external dependency" section. The doc itself forbids shipping C8 without program-level AI-evaluating policy negotiation; the right close-out is to vacate it from the engineering graph rather than build the dispatch wrapper before the policy conversation. IP5 + I8 substrate (parser + matcher) remain usable today for offline triage. Added a "Completion summary" near the top stating that the engineering task graph is realized: 39 commits, 708+ MCP tests, 102 MCP tools across the post-v2 capability surface (C1–C7 reachable from orchestrator; X2 / X3 / X4 / X5 cross-cutting concerns shipped). Subsequent work belongs in new task graphs framed by what the next real-target evaluate reveals.
- **2026-05-10** · I8 · CVE-to-scope matcher (substrate-only; C8 stays gated) · `mcp/lib/cve-scope-matcher.js` + `test/cve-scope-matcher.test.js` (14 tests passing). `matchCveAgainstScope` walks each CVE's `affected_products`, tokenizes vendor + product, and looks them up in a per-surface index built from `tech_stack` (high confidence), tokenized hosts (low), and surface_type. `matchCveBatch` aggregates per-CVE results with totals. `normalizeTechStackToken` strips `lib-` prefix and `-js`/`-py`/`-rb`/`-go`/`-java`/`-ts` suffixes only when separator-prefixed (the test caught a bug where unseparated stripping turned `django` into `djan`). Optional `schema_contracts` secondary pass annotates host-matched rows with `schema_corpus_confirms_host` when a contract source URI hostname covers the same token. `match_hash` is content-addressed via `hashCanonicalJson`. Substrate-only — C8 remains policy-gated; the matcher is usable today for offline triage on operator-curated feeds. Full `npm test` green (694→708 mcp tests).
- **2026-05-10** · IP5 · NVD CVE feed parser (substrate-only; C8 remains policy-gated) · `mcp/lib/cve-feed-parser.js` + `test/cve-feed-parser.test.js` (14 tests passing). `parseCveFeed(rawText)` accepts NVD 2.0 (`vulnerabilities[]`), legacy 1.x (`CVE_Items[]`), or a single CVE record at the root. `parseNvdEntry` extracts `(cve_id, description, cvss_score, severity, vulnerability_class, affected_products, references, published_at, last_modified_at)` per record. `pickHighestCvssScore` picks the highest baseScore across V31/V30/V2 metrics so an NVD entry with mixed metric versions reports the strongest signal. `parseCpeUri` parses 2.3 CPE URIs into `{kind, vendor, product, version}` with wildcard normalization. `vulnerability_class` reuses IP4's `classifyVulnerability` so CVEs and audit findings share the same 13-class taxonomy. Affected products dedupe by `(vendor, product, version, version range)`. Each record carries a content-addressed `cve_record_hash` so subsequent ingestion + dedup is deterministic. **Substrate only** — IP5 builds the parser library; I8 (CVE-to-corpus matcher) and C8 (live speedrun activation) remain explicitly gated on program-level AI-evaluating policy negotiation per the doc's Tier-4 sequencing rule. The library can be used today for offline analysis on operator-supplied feeds without activating the speedrun. Full `npm test` green (680→694 mcp tests).
- **2026-05-10** · IP3 + IP6 + I3 + C3 · Diff-aware regression substrate end-to-end · `mcp/lib/unified-diff-parser.js` (IP3) + 3 MCP tool wrappers (`bob_extract_routes`, `bob_build_symbol_surface_index`, `bob_summarize_diff_impact`) + 8 IP3 tests. `parseUnifiedDiff(rawDiff)` walks unified-diff hunks, builds per-file `{file, line_ranges, added_lines, removed_lines}` records (added line ranges merge adjacent runs), captures new files (`--- /dev/null` → `+++ b/path`) and deleted files (`--- a/path` → `+++ /dev/null` under the deleted file path), and returns `{file_count, total_added_lines, total_removed_lines, diff_files}`. `bob_summarize_diff_impact` accepts either a raw `unified_diff` string (parses internally) or pre-parsed `diff_files`, intersects with the persisted symbol-surface-index, and returns `impacted_surface_ids` plus per-entry detail. The orchestrator can feed `impacted_surface_ids` directly into `bob_start_wave` for a focused diff-aware regression evaluate — no separate runner needed because C3's "capability" *is* the impact-summarization step plus the existing wave system. Tool count 99→102; install-smoke and EXPECTED_TOOL_NAMES bumped. Closes IP3 + IP6 + I3 + C3 engineering-side. Full `npm test` green (672→680 mcp tests).
- **2026-05-10** · I3 · Symbol-to-surface index built from IP6 routes + attack_surface.json · `mcp/lib/symbol-surface-index.js` + `test/symbol-surface-index.test.js` (13 tests passing). `buildSymbolSurfaceIndex` takes IP6 route records, normalizes route paths (`/users/:id` ↔ `/users/{id}` ↔ `/users/<int:id>` all reduce to the same `{x}` slot), and links each route to surface IDs whose `endpoint_pattern` or `endpoints[]` strings match. Persists to `symbol-surface-index.json` with three lookup maps (`by_file_line`, `by_file`, `by_surface`) plus a content-addressed `index_hash` so re-builds with identical inputs are byte-stable. `summarizeImpactedSurfacesForDiff({ diff_files })` answers C3's central question — given a diff, which surfaces does it touch — by intersecting per-file `line_ranges` against the index entries and rolling up impacted surface IDs. Routes that don't match any surface still index with empty `surface_ids[]` so future surface promotions catch up automatically. MCP tool wrappers and IP3 (repo polling for diffs) land in subsequent slices. Full `npm test` green (659→672 mcp tests).
- **2026-05-10** · IP6 · Regex-based route extractor for seven backend frameworks · `mcp/lib/route-extractor.js` + `test/route-extractor.test.js` (17 tests passing). Hand-rolled extractors for Express (`app.METHOD('/path', handler)` + `app.use` mount edges), Fastify (`fastify.METHOD` + `fastify.route({method, url})`), NestJS (`@Controller` prefix joined with `@Get`/`@Post`/etc decorators), Flask (`@app.route(... methods=[])` + `@app.METHOD` shorthand), Django (`path()` / `re_path()` / `url()`), and Spring (`@RequestMapping` class prefix joined with `@GetMapping`/`@PostMapping`/`@RequestMapping(method=...)`). `extractRoutesFromSource({source, language?, file?})` auto-detects language from file extension when omitted; `extractRoutesFromFiles([{file, source, language?}])` concatenates across many files. Output sorted deterministically by `(file, line, path, method)` for replay-byte-stability with `(framework, method, path, line, file)` tuple dedup. `handler_hint` captures the next identifier after the path argument so I3 can wire route → handler symbol mapping in the next slice. AST-grade extraction (e.g. `@babel/parser`-style precision) is queued for cases the regex misses. Closes the IP6 first slice; I3 (file:line → surface index built from these routes) and IP3 (repo polling for diffs) land next. Full `npm test` green (642→659 mcp tests).
- **2026-05-10** · C5 · Foundry invariant runner + MCP tools · `mcp/lib/invariant-runner.js` + `mcp/lib/tools/{run-invariant-for-finding,read-invariant-runs}.js` + `test/invariant-runner.test.js` (12 tests passing). `runInvariantForFinding` ties IP4's audit findings, I5's invariant template corpus, and the existing `bob_foundry_run` together: picks a template via `suggestInvariantsForFinding`, derives stable test/contract names from `(template_id, finding_hash)`, renames the template's function, wraps it in a Solidity test contract envelope (forge-std/Test, setUp scaffold), writes to `<harness>/test/bob-invariants/`, dispatches the Foundry runner via DI (production wires `runFoundryTest`, tests stub), classifies the outcome into one of `test_passed | test_failed | fork_blocked | forge_missing | no_template | unknown`, and persists to `invariant-runs.jsonl` keyed by content-addressed `run_hash`. `dry_run: true` returns the planned test source without writing or running. `bob_run_invariant_for_finding` is orchestrator-only network-allowed mutator; `bob_read_invariant_runs` filters by outcome / template_id. Re-running the same `(finding, template, slot_values)` triple upserts on the same `run_hash`. Tool count 97→99; install-smoke and EXPECTED_TOOL_NAMES bumped. Closes C5 engineering-side; parishioner gate awaits a real-target Immunefi-grade counterexample. Full `npm test` green (630→642 mcp tests).
- **2026-05-10** · IP4 + I5 · Audit-report MCP tools + invariant template corpus library · `mcp/lib/tools/{ingest-audit-report,query-audit-reports,suggest-invariants}.js` (3 orchestrator-only tools) + `mcp/lib/invariant-template-corpus.js` + `test/invariant-template-corpus.test.js` (12 tests passing). Built-in catalogue of 7 Foundry invariant templates spanning reentrancy, access_control, arithmetic_overflow, oracle_manipulation, unchecked_call, signature_validation, delegatecall_storage. Each template carries `parameter_slots` (target_contract, vulnerable_function, etc.) that `suggestInvariantsForFinding` fills via caller-supplied `slot_values` and reports unfilled gaps. `suggestInvariantsForReport` groups suggestions per vulnerability_class for whole-audit invariant proposal. Tool count 94→97; install-smoke and EXPECTED_TOOL_NAMES bumped. Bob-evaluate skill cap raised 340→360 with comment update: the original cap protected against future chain pack bloat (extract to per-family files); the new ceiling absorbs the post-v2 capability tool surface (C2/C4/I1/I6/I7/IP4+I5/X3+X5) which is real capability, not chain-pack metadata. Full `npm test` green (618→630 mcp tests).
- **2026-05-10** · IP4 · Markdown audit-report parser + per-target persistence · `mcp/lib/audit-report-parser.js` + `test/audit-report-parser.test.js` (14 tests passing). Hand-rolled markdown parser that extracts an H1 title + optional summary + per-H2 finding sections, with severity captured either from the H2 heading inline (`(Severity: High)`) or from a `**Severity:** Critical` body line. Each finding emits title, severity (canonicalized via `normalizeSeverity`), description, recommendation (from H3 `Remediation` / `Recommendation` / `Fix` / `Mitigation`), scope_paths (parsed from backtick-quoted contract paths), and a `vulnerability_class` derived from a 13-class regex classifier (reentrancy, access_control, arithmetic_overflow, oracle_manipulation, front_running, flash_loan, unchecked_call, delegatecall_storage, signature_validation, idor, injection, xss, race_condition). `ingestAuditReport({ target_domain, raw_markdown, source_uri })` upserts records into `audit-reports.jsonl` keyed by `source_doc_hash`; idempotent re-ingest. `queryAuditReports({ severity_filter, vulnerability_class_filter, limit })` narrows by severity and class. MCP tool wrappers and I5 invariant template corpus land in subsequent slices. Full `npm test` green (604→618 mcp tests).
- **2026-05-10** · X5 · Capability evaluation harness (`bob_evaluate_capabilities`) · `mcp/lib/capability-eval-harness.js` + `mcp/lib/tools/evaluate-capabilities.js` + `test/capability-eval-harness.test.js` (6 tests passing). Fixture-driven runner registers one expected-outcome assertion per post-v2 capability (C2 auth-bypass divergence, C4 unauth-succeeds-where-auth-blocked, I6 IDOR-over-XSS ranking, I1 query-by-source/target, I7 branching frontier with two leaves). `evaluateAllFixtures()` runs every fixture and tallies passed/failed; `evaluateOneFixture(name)` runs one. Each fixture allocates a unique session domain and cleans up after itself so the harness leaves no fingerprint on real session storage. Closes X5. Tool count 93→94. Skill stays at the 340-line cap by inlining the prior two-line `bob_http_scan` audit + internal-host policy bullets into one. Full `npm test` green (598→604 mcp tests). [RETRACTED c02179c for the I6 fixture only: current HEAD no longer has the I6 index/fixture.]
- **2026-05-10** · X3 · Per-capability observability (`bob_read_capability_metrics`) · `mcp/lib/capability-metrics.js` defines a `CAPABILITY_TO_TOOLS` map covering the post-v2 capability surface (C2, C4, I6, I1, I7, X2 diff). `summarizeCapabilityMetrics(events)` walks the existing tool telemetry and aggregates per-capability call_count, success_count, error_count, blocked_count, success_rate, avg_latency_ms, and last_called_at, plus a per-tool breakdown. `readCapabilityMetrics({ target_domain? })` reads the existing telemetry surface; the MCP tool wrapper is orchestrator-only, target-scoped when target_domain is set, cross-target when omitted. No new persistence — uses the v1 telemetry already shipped, so the new view is free in storage. 9 tests cover capability coverage, zeroed buckets on empty input, per-capability aggregation, blocked-count breakout, latest-timestamp picking, per-tool breakdown, unrelated-tool filtering, malformed-event tolerance, and non-array input. Tool count 92→93. Closes the X3 deliverable except for hallucination-flag detection, which the doc notes belongs in agent prompts not in the metrics layer. Full `npm test` green (589→598 mcp tests). [RETRACTED c02179c for the I6 bucket only: current HEAD derives capability metrics from the registry and no longer has the I6 tools.]
- **2026-05-10** · I7 + C7 · Chain state tree MCP tools + CHAIN-phase orchestrator hint · `mcp/lib/tools/{append-chain-node,query-chain-tree,chain-frontier,chain-ancestry}.js` (4 orchestrator-only tools); orchestrator role's PHASE 4 CHAIN section gains a one-line pointer to the four tools so the orchestrator discovers branching chain search as part of its existing CHAIN playbook rather than via a separate optional section. Closes I7 + C7. Tool count 88→92; install-smoke and EXPECTED_TOOL_NAMES bumped. Differential workflow prose (the prior "Optional: Doc-vs-Behavior Differential" + "Optional: Multi-Account Differential" sections) compressed to one-liner subsections under "Optional: Differential Workflows" so the bob-evaluate skill stays under its 340-line cap (now 339 lines).
- **2026-05-10** · I7 · Chain state tree library (content-addressed branch nodes) · `mcp/lib/chain-state-tree.js` + `test/chain-state-tree.test.js` (12 tests passing). `appendChainNode({ target_domain, parent_state_hash?, action, observed?, verdict? })` computes `node_hash = hash(parent_state_hash, action_canonical)` and `state_hash = hash(node_hash, observed_canonical)` so a parent_state_hash uniquely identifies the world after a step. Branching emerges naturally: two distinct actions from the same parent_state_hash yield distinct node_hashes; the same action with different observed yields the same node_hash but a new state_hash (so the orchestrator can record alternate outcomes of the same attempt without losing identity). `queryChainTree` filters by parent_state_hash / verdict / action_kind. `frontier` returns leaf nodes (no children) so the orchestrator's tree-search loop can pick the next branch to expand; default excludes `pruned` so dead branches don't pollute the frontier, `include_pruned: true` recovers them for diagnostics. `ancestry` walks parent_state_hash links back to the root, capped at 25, for explaining how a state was reached. Verdict enum `(pending, success, failure, pruned, branched)` is enforced. On-disk `chain-tree.jsonl` sorts by node_hash for replay-byte-stability. CHAIN-phase integration (orchestrator running BFS/DFS over the frontier with replay-lease backtracking) and MCP tools land in subsequent slices. Full `npm test` green (577→589 mcp tests).
- **2026-05-10** · X4 · Determinism CI canary across every v2-style content-addressed artifact · `test/determinism-ci.test.js` (2 tests passing). Exercises schema-contracts ingest, doc-delta runner, auth-differential runner, findings-index, surface-graph builder + appendEdges, in one fixture-driven pass; asserts content-hash sets (`contract_hash`, `edge_hash`, `finding_id`) reproduce across two distinct target_domains and that doc-delta + auth-differential `results_hash` is stable across same-target re-runs. The test's first run surfaced a real determinism quality concern: per-record `ingested_at` / `indexed_at` / `observed_at` wall-clock timestamps make raw JSONL bytes drift across runs even though the content hashes are stable. Documented in the test as the reason the right replay invariant is "content-hash sets equal", not "raw file bytes equal". Counter-assertion locked in: `results_hash` legitimately diverges across distinct target_domains, so future churn dropping `target_domain` from the canonical payload silently breaks per-target replay bookkeeping. Closes the X4 deliverable from the original Tier 4 layer. Full `npm test` green (575→577 mcp tests). [RETRACTED c02179c for the findings-index leg only: current HEAD no longer has `mcp/lib/findings-index.js`; the remaining determinism pipelines still stand.]
- **2026-05-10** · X2 · `bob-export` replay-budget summary · `mcp/lib/bob-export.js` adds `summarizeReplayBudget(snapshot)` and `renderReplayBudgetSection(snapshot)`; the release-bundle `manifest.json` gets a `replay_budget: { snapshot, totals }` block and `summary.md` gets a "## Replay Budget" section listing per-pack mode (`serialized` vs `parallel_safe`), lease scope, concurrent-rounds hint, and active-lease count. `replayExecutionPolicy` exported from `mcp/lib/verification.js`. Bob-export test gains assertions for the new manifest field and the summary section content. Closes the third X2 deliverable from the original Tier 1 layer; v2 substrate (replay leases) is now visible in operator-readable bundle output, completing the X2 line. Full `npm test` green.
- **2026-05-10** · I1 + C1 · `surface_graph_slice` brief integration · `mcp/lib/surface-graph.js` adds `summarizeSurfaceGraphForSurface(domain, surface, opts?)` (default 5, hard ceiling 25). For each surface, walks outgoing edges into endpoint / js_file / subdomain / tech / secret_marker buckets ranked by edge count, then runs a second-hop query per surfaced endpoint into the `claims_auth` edges so claimed auth schemes surface alongside the endpoints they protect. Wired into `buildWebBriefExtras` and `buildSmartContractBriefExtras` so every evaluator automatically sees the cross-surface correlation graph for their assigned surface — no orchestrator query required. Closes I1 + C1. Full `npm test` green (568→575 mcp tests).
- **2026-05-10** · I1 · Surface graph builder + MCP tools · `mcp/lib/surface-graph-builder.js` + `mcp/lib/tools/{build,query}-surface-graph.js` + `test/surface-graph-builder.test.js` (8 tests passing). Builder reads `attack_surface.json` and emits seven edge classes (surface→endpoint contains, subdomain→endpoint hosts, surface→subdomain contains, surface→tech references, surface→js_file references, surface→secret_marker leaks); reads the schema corpus and emits two more (openapi_spec→endpoint documents, endpoint→auth_scheme claims_auth). `sources` filter lets the orchestrator restrict which artifact pipelines feed a build. Missing artifacts report as `{source, edge_count: 0, missing: true}` instead of throwing. `bob_build_surface_graph` and `bob_query_surface_graph` are both orchestrator-only mutator/reader pair with `global_preapproval: false` matching the rest of the C2/C4/I6 surfaces. Tool count 86→88; install-smoke and EXPECTED_TOOL_NAMES bumped. Brief integration (surface_graph_slice → C1) is the next slice. Full `npm test` green (560→568 mcp tests).
- **2026-05-10** · I1 · Surface graph data store + query kernel · `mcp/lib/surface-graph.js` + `test/surface-graph.test.js` (10 tests passing). `normalizeEdge` clamps confidence to [0, 1] and computes a canonical hash over `(source, target, edge_type, source_artifact)` so edges dedupe deterministically. `appendEdges` upserts to `surface-graph.jsonl` (sorted by edge_hash on write so the on-disk file is byte-stable across re-runs). `queryEdges` filters by source/target type, source/target id, and edge_type with a 1000-edge hard cap. `neighbors` returns the incoming + outgoing edges of a node, per direction or both. Edge type vocabulary (`references`, `contains`, `hosts`, `imports`, `documents`, `claims_auth`, `leaks`) and node type vocabulary (`subdomain`, `hostname`, `endpoint`, `js_file`, `openapi_spec`, `archived_url`, `secret_marker`, `auth_scheme`, `static_artifact`) are advisory — the store accepts arbitrary string types so future ingest paths don't need vocabulary changes. Builder + MCP tools + brief integration land in subsequent slices. Full `npm test` green (550→560 mcp tests).
- **2026-05-10** · I6 + C6 · Brief-time prior injection (`priors_slice`) in web and smart-contract evaluator briefs · `mcp/lib/findings-index.js` adds `summarizePriorFindingsForSurface(domain, surface, opts?)` which builds a query string from surface fields (endpoint, endpoint_pattern, endpoints, surface_type, bug_class, bug_classes, tech_stack, notes, title, description, chain_family, chain_id, contract_address) and runs a cross-target similarity query, capping at 5 by default with a 15 hard ceiling. `mcp/lib/assignment-brief.js`'s `buildWebBriefExtras` and `buildSmartContractBriefExtras` both inject the slice; web evaluators now see priors next to schema_slice + technique packs + traffic + audit + intel + static-scan hints, smart-contract evaluators next to bob_spec_status + rpc_pool. Same/other-target counts and `domains_scanned` keep the brief honest about whether the priors come from the live target or the cross-target corpus. Function returns `null` when no matches surface, so empty results never noise the brief. Closes I6 + C6 from the original Tier 2 layer. Full `npm test` green (544→550 mcp tests). [RETRACTED c02179c: `mcp/lib/findings-index.js` and `priors_slice` injection were deleted; see 2026-06-07 DOC-1 entry.]
- **2026-05-10** · I6 · MCP tool wrappers + auto-indexing in `bob_record_candidate_claim` · `mcp/lib/tools/index-finding.js` (orchestrator-only mutator with optional `calibration_label`), `mcp/lib/tools/query-findings-index.js` (target or `cross_target` scope, top-K ≤50, severity / attack_class filters). Auto-indexing patched into `recordFinding`'s success path under a try/catch so an index-write failure never blocks the finding write. The handler hands the persisted finding's full shape (title, description, severity, attack_class, cwe, endpoint, surface_id, surface_type, tech_stack, evidence_summary or response_evidence, proof_of_concept) to `indexFinding`, so every evaluate's findings populate the index automatically without operator action. Tool count 84→86; install-smoke length bumped; settings unchanged because both new tools are `global_preapproval: false`. Closes I6 substrate work; brief-time prior injection (orchestrator calls `bob_query_candidate_claims_index` and threads top-K into evaluator briefs) lands next. [RETRACTED c02179c: tool wrappers and auto-indexing were deleted; see 2026-06-07 DOC-1 entry.]
- **2026-05-10** · I6 · Findings vector index library (lexical similarity, dep-free) · `mcp/lib/findings-index.js` + `test/findings-index.test.js` (14 tests passing). 256-slot hashed feature vectors over tokens + 2-grams of finding fields, with SHA-256-derived slot mapping for determinism. `tokenize` strips stop-words and emits unigrams + bigrams; `cosineSimilarity` ranks priors against a query string. `indexFinding` upserts per-target into `findings-index.jsonl` with calibration_label slot for future grade-verdict feed; `queryFindingsForTarget` and `queryFindingsCrossTarget` return top-K with optional severity / attack_class filters. Cross-target query iterates `~/hacker-bob-sessions/*` and skips dot-prefixed dirs so it never reads scratch state. No ML dependency, no embedding model — keeps the project's two-deps constraint intact while still letting later capabilities query priors at evaluate start. MCP tools and auto-indexing in `bob_record_candidate_claim` land in subsequent slices. Full `npm test` green (530→544 mcp tests). [RETRACTED c02179c: library and test were deleted; see 2026-06-07 DOC-1 entry.]
- **2026-05-10** · X2 · `/bob-debug --diff-attempts <prev> <curr>` cross-attempt diff · `mcp/lib/verification-attempt-diff.js` + `mcp/lib/tools/diff-verification-attempts.js` + `test/verification-attempt-diff.test.js` (9 tests passing). Compares two verification attempts (each is either an archive id or `current`) by reading the per-attempt manifest hashes and the per-file hashes. Output: snapshot / adjudication-plan / final-verification hash match flags + file divergence (only-in-a, only-in-b, content-changed with truncated 16-char hashes). Wired into bob-debug skill's allowed-tools through the shared `READ_ONLY_DEBUG_TOOLS` list. Tool count 83→84; install-smoke length bumped; bob-debug source role gains the `--diff-attempts` argument-handling section, regenerated to Claude + Codex skills. Closes the second X2 deliverable from the original Tier 1 layer (cathedral pivot deferred parishioner-facing surface that turns the v2 archive trail into operator-readable signal). Full `npm test` green (523→530 mcp tests).
- **2026-05-10** · C2 + C4 · Read tools + consolidated orchestrator differential workflow · `mcp/lib/tools/read-doc-delta-results.js`, `mcp/lib/tools/read-auth-differential-results.js` (both orchestrator-only, read-only, with optional `summary_only` to skip the heavy per-contract / per-endpoint arrays). The orchestrator playbook collapses the prior two separate "Optional: Doc-vs-Behavior Differential" and "Optional: Multi-Account Differential" sections into a single "Optional: Differential Workflows" header with two named subsections, keeping the bob-evaluate skill under its 340-line cap (now 330 lines). Tool count 81→83; settings, agent-tools, skill, codex skill regenerated; install-smoke and EXPECTED_TOOL_NAMES bumped. Test asserts both differential workflows reference their full tool chain (ingest/query/run/read for C2; list_auth_profiles/run/read for C4) and that rendered Claude + Codex skills carry the same workflow text. Closes Tier 1 small-wires backlog.
- **2026-05-10** · C4 · Per-call `bob_http_scan` adapter + `bob_run_auth_differential` MCP tool · `mcp/lib/http-scan-adapter.js` adds `makePerCallHttpScanFetcher` (uses `auth_profile` from per-call args instead of closure, so one fetcher serves the whole differential run); `mcp/lib/tools/run-auth-differential.js` registers the MCP tool. Auto-derives `profile_metadata.sent_with_auth: false` for profile names matching `guest`/`anon`/`noauth`/`public`/`unauthenticated` etc., so the `unauth_succeeds_where_auth_blocked` security heuristic fires without explicit metadata in the common case. Tool is orchestrator-only, scope-required, and writes `auth-differential-results.json`; scoped HTTP policy is enforced by the MCP runtime. Tool count 80→81; settings, agent-tools, skill regenerated. 3 new adapter tests cover per-call profile injection, blank profile sent_with_auth handling, and configuration validation. Full `npm test` green (518→521 mcp tests).
- **2026-05-10** · C4 · Multi-account differential runner with DI-style fetch + persistence · `mcp/lib/auth-differential-runner.js` + `test/auth-differential-runner.test.js` (13 tests passing). `runAuthDifferential({ target_domain, base_url, endpoints, auth_profiles, fetch_fn, profile_metadata?, run_id?, limit? })` normalizes endpoint shapes (strings or `{endpoint, method?}`), dedups + caps profile list to ≥2 distinct entries, fans `fetch_fn` across endpoint × profile, runs the kernel's cross-profile differ, and persists to `auth-differential-results.json`. Per-endpoint entries sort deterministically by `(endpoint, method)`; `results_hash` zeroes timestamps so identical inputs hash identically across runs. Fetch errors record per-(endpoint, profile) without aborting the broader run. Path added to `mcp/lib/paths.js`. Full `npm test` green (505→518 mcp tests).
- **2026-05-10** · C4 · Response-signature kernel + cross-profile differ · `mcp/lib/auth-differential.js` + `test/auth-differential.test.js` (17 tests passing). `computeResponseSignature` lowers an HTTP response into a stable signature: status / status_class / response_class, body_shape with structural keys only (so re-encoded same-shape bodies hash identically while admin-only fields surface), body_length_bucket (`empty`/`small`/`medium`/`large`/`huge`), sensitive_field_count over a curated regex list (password, token, ssn, internal_id, admin, etc.) walked to depth 3, and sent_with_auth flag. `diffResponseSignatures` emits six divergence types: `status_class_differs`, `response_class_differs`, `body_hash_differs`, `body_length_bucket_differs`, `sensitive_field_count_differs` (`info_leak_potential`), and `unauth_succeeds_where_auth_blocked` (`security`, requires optional `profile_metadata`). Output sorted deterministically by type. Pure-function design: no HTTP, no FS — runner integration lands in the next slice. Full `npm test` green (488→505 mcp tests).
- **2026-05-10** · C2 · Orchestrator playbook section for doc-vs-behavior differential · `prompts/roles/orchestrator.md` adds an "Optional: Doc-vs-Behavior Differential" section above PHASE 3 documenting the four-step workflow (ingest schema doc → confirm corpus → run per-auth-profile differential → record security-class divergences). Mirrored to `.claude/skills/bob-evaluate/SKILL.md` and `adapters/codex/skills/bob-evaluate/SKILL.md` via the hacker-bob skill and codex skill renderers. Test asserts the workflow content + tool names + rendered-surface parity. Closes the "C2 capability pack" deliverable as an orchestrator workflow rather than a evaluator pack — C2's runner is orchestrator-driven, so evaluator routing was the wrong shape for this capability. Triage of prose-only contracts via LLM subagent remains queued as quality-of-life refinement, not a blocker.
- **2026-05-10** · I2 · Evaluator-brief `schema_slice` integration · `mcp/lib/schema-contracts-store.js` adds `summarizeSchemaSliceForSurface(domain, surfaceObj, opts?)`; `mcp/lib/assignment-brief.js` `buildWebBriefExtras` includes the slice. The slice tries `surface.endpoint_pattern` first, then walks `surface.endpoints[]` until a substring hit lands; if no hint matches it falls back to the full corpus. Default limit 5, hard ceiling 25. Each contract compresses to `(endpoint, method, claimed_auth_schemes, none_allowed, param_count, documented_status_codes, contract_hash:0..16, schema_format)` so a five-contract slice fits well inside the existing brief budget. Web evaluators now see the documented contracts for their surface alongside techniques, traffic, audit, intel, and static-scan hints. 8 new tests cover empty corpus, default cap, endpoint_pattern hint match, fallthrough across endpoints array, compact-contract field shape, custom limit clamping below and above the ceiling, and no-match fallback. Closes I2 assignment-brief integration. Full `npm test` green (480→488 mcp tests).
- **2026-05-10** · X2 · `bob-status` v2 verification panel · `prompts/roles/status.md` adds an explicit "V2 Verification Panel" section that surfaces current attempt + first-eight-chars snapshot hash + freshness flag, adjudication / evidence match status, replay execution policy, and an archive trail (`archived_attempts.length` plus the up-to-three most recent superseded attempts as `<attempt_id> @ <archived_at> snapshot <hash:8> files <count>`). Mirrored to `.claude/skills/bob-status/SKILL.md` and `adapters/codex/skills/bob-status/SKILL.md` via the role renderers; prompt-contracts test extended with six panel-content assertions. Package size threshold bumped 2.0→2.5 MB to absorb the recent slice growth (~100 KB across parsers, runners, and the hypergraph doc itself).
- **2026-05-10** · IP2 / I2 · Postman v2.1 collection parser · `mcp/lib/postman-parser.js` + `test/postman-parser.test.js` (15 tests passing). Flattens nested folders into leaf requests, normalizes Postman path variables (`:name`) to OpenAPI shape (`{name}`), extracts query / path / header / body params (skipping Authorization and Content-Type request headers, those are runtime concerns), infers JSON body shape from raw bodies, derives `claimed_auth` schemes as `postman_auth:<type>` with collection-level cascade and item-level override, and reads response examples for `claimed_response_shape`. Closes IP2 source coverage (OpenAPI 3, GraphQL SDL, Postman v2.1). Full `npm test` green (465→480 mcp tests).
- **2026-05-10** · IP2 / I2 · GraphQL SDL parser + dispatcher routing · `mcp/lib/graphql-sdl-parser.js` + `test/graphql-sdl-parser.test.js` (17 tests passing). Hand-rolled tokenizer + recursive-descent parser handles type / input / schema / extend defs, descriptions, comments, list / non-null type modifiers, args with defaults, and directives. Auth directives (`@auth`, `@authenticated`, `@requireAuth`, `@hasRole`, `@guard`, etc.) populate `claimed_auth.schemes` as `graphql_directive:<name>`. Each Query / Mutation field becomes one contract with `endpoint = /graphql:<kind>.<name>` and `method = POST`. Return-type shape resolves nested types with `$ref_cycle` markers for self-recursion and `$ref_unresolved` for missing types. `parseSchemaDoc` now dispatches to GraphQL when JSON parsing fails and the source matches SDL heuristics. Full `npm test` green (448→465 mcp tests).
- **2026-05-10** · C2 · `bob_http_scan` adapter + `bob_run_doc_delta` MCP tool · `mcp/lib/http-scan-adapter.js`, `mcp/lib/tools/run-doc-delta.js`, `test/http-scan-adapter.test.js` (13 adapter tests passing). Adapter parses http-scan's JSON-stringified result, extracts content-type via case-insensitive header lookup, JSON-parses the body when content-type indicates JSON, and surfaces fetch errors with their `scope_decision`. The MCP tool is orchestrator-only, scope-required, and writes `doc-delta-results.json`; the underlying http-scan call is scoped by MCP runtime policy. Tool count 79→80; settings, agent-tools, skill regenerated. Full `npm test` green (435→448 mcp tests).
- **2026-05-10** · C2 · Differential runner with DI-style fetch + deterministic persistence · `mcp/lib/doc-delta-runner.js` + `test/doc-delta-runner.test.js` (12 tests passing). Runner queries the I2 corpus, joins each contract endpoint to a base URL, calls a caller-supplied `fetch_fn` (so production wires `bob_http_scan` while tests stub synthetic responses), runs the divergence classifier, and persists a content-addressed `doc-delta-results.json` per target. Per-contract entries sort by contract_hash; results_hash is computed over the canonicalized payload with timestamps zeroed so identical inputs hash identically across runs. Fetch errors per-contract are recorded but do not abort the run. Full `npm test` green (423→435 mcp tests).
- **2026-05-10** · C2 · Divergence-detection kernel · `mcp/lib/contract-divergence.js` + `test/contract-divergence.test.js` (15 tests passing). Pure-function classifier emits seven divergence types (auth-bypass, auth-misconfig, unreachable, status mismatch, undocumented field, missing required field, content-type mismatch) tagged with one of three severity classes (security, info_leak_potential, doc_or_infra) for the triage subagent. Output sorted deterministically by type. Full `npm test` green (408→423 mcp tests).
- **2026-05-10** · I2 · JSONL persistence + orchestrator-only ingest/query tools · `mcp/lib/schema-contracts-store.js`, `mcp/lib/tools/{ingest-schema-doc,query-schema-contracts}.js`, `test/schema-contracts-store.test.js` (10 store tests passing); full `npm test` green (407→408 mcp tests, 129 prompt-contracts, 9 package). Tools land as orchestrator-only mutators with `global_preapproval: false` so the budgeted evaluator-web brief stays under cap. Settings, agent tools, and skill regenerated; install-smoke and package canonical-files walker updated for the new tool count and the cron lock file.
- **2026-05-10** · IP2 / I2 · OpenAPI 3 parser + contract canonicalization · `mcp/lib/schema-contracts.js` + `test/schema-contracts.test.js` (13 tests passing) · *engineering review complete; persistence + tool wrappers pending; parishioner gate not yet reachable.*

## Glossary

- **Slab** — substrate already shipped (v2 invariants and existing pack/brief architecture).
- **Pillar** — pre-computed index or ingestion path.
- **Roof** — evaluating capability producing findings.
- **Cross-cutting** — concerns that span multiple items.
- **Hyperedge** — dependency relation linking N predecessors to M unlocked items.
- **Capability** (this doc) — evaluating mode (`C1`–`C8`); not the same as capability pack.
- **Capability pack** (existing system) — surface-family router selected per assignment.
- **Technique pack** (existing system) — tactic body fetched on demand.
- **Evaluator brief** (existing system) — bounded subagent contract with context-selection metadata.
- **Parishioner** — operator or evaluator who consumes bob's output. Used in this doc as shorthand for "the human who has to look at what bob produced."
- **Triager** — bug-bounty platform or program triage analyst who decides finding disposition.
- **Slab invariant** — a property the substrate guarantees; violations are regressions even if they look like features.

---

*Doc version 0. Update as work lands; mark items complete inline; promote findings to capabilities; demote items that fail parishioner review back to spec.*
