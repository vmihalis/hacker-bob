# Changelog

## [2.0.1] - 2026-06-08

First npm publication of the v2 line. `v2.0.0` was tagged but never released to npm; the registry `latest` remained on the v1.3.x maintenance line. `2.0.1` publishes the accumulated v2.0.x work on top of the [2.0.0] topology.

### OSS / repo-mode diff review

- Repo-bound sessions accept the synthetic `repo-<name>-<sha8>` `target_domain` across the `initialized_session_read` and `initialized_session_mutation` session-authority classes, not only at bootstrap. `bob_extract_routes`, `bob_build_symbol_surface_index`, and `bob_summarize_diff_impact` now run against a locally checked-out repository instead of being rejected by the registrable-domain normalization that governs live-target sessions. This lets a headless diff-review build a real symbol-surface index and diff-impact map rather than falling back to heuristic dispatch.
- `deriveRepoTargetDomain` emits an 8-character path hash that matches the `REPO_TARGET_DOMAIN_PATTERN` authority guard, so the deriver and the validator agree on the repo-session slug.
- Structured OSS fuzz-seed paths and the repo reachability producer are exposed for evaluator dispatch.

### Report and topology authority

- Structured report composition (`bob_compose_report`, `bob_write_chain_rollup`, `bob_amend_report`) and the `AUDIT_GRADED_PATHS` registry are authoritative; the Write tool is removed from `report-writer` and `chain-builder`.
- Frontier and scheduler coherence hardening: surface-leads producer rationale with orchestrator handoff receipts, an advance-session partial-surface runtime gate, and single-spawner topology enforcement.

### CI / release

- Tag-triggered release pipeline with clean-release and dependency-freshness audits and npm provenance.

## [2.0.0] - 2026-05-28

### Topology realization

v2.0.0 realizes the frontier-topology hypergraph against the live codebase. The session model is no longer a phase-ordered FIFO mutating a single `state.json`; it is four append-only planes (governance, frontier, scheduler, claim) coordinated by a six-state lifecycle FSM.

- Absorbs PR #58 (kimi adapter + PSL warn), PR #59 (OSS hunting mode → ported), PR #60 (CVE feed matching).
- New planes:
  - Governance plane (`session-nucleus.json`, `session-events.jsonl`) — authoritative scope policy, egress identity, operator constraints, lifecycle state. Mutations append events with `prior_nucleus_hash → nucleus_hash` transitions.
  - Frontier plane (`frontier-events.jsonl` + materialized `surface-index.json` / `task-queue.json`) — append-only discovery progress: seeded surfaces, lead enqueues, observations, closures, blockers.
  - Scheduler plane (`assignments/<id>.json`, `agent-runs.jsonl`, `scheduler-decisions.jsonl`) — immutable wave assignments and AgentRun ledger drive merge gates from state instead of file presence.
  - Claim plane (`claims.jsonl`, `claim-clusters.jsonl`, `claim-freeze/<id>.json`, `report-snapshots.jsonl`) — CandidateClaim records, cluster grouping, immutable frozen batches for verification, and report snapshots.
- Lifecycle FSM: `SETUP -> OPEN_FRONTIER -> CLAIM_FREEZE -> VERIFY -> GRADE -> REPORT`. `OPEN_FRONTIER` is re-entrant from every later state. Each transition emits a `governance.lifecycle.advanced` event with explicit `from_state`, `to_state`, and `nucleus_hash` fields. The old eight-phase FSM (`SURFACE_DISCOVERY -> AUTH -> EVALUATE -> CHAIN -> VERIFY -> GRADE -> REPORT -> EXPLORE`) is retired; the lifecycle tool `bob_advance_session(to_state)` replaces `bounty_transition_phase(target_phase)`.
- Tool prefix renamed `bounty_*` -> `bob_*`. Every primary tool now declares a `bob_*` name; v1.x callers keep working through a one-release alias layer in `tool-registry.js`. Invoking an alias appends a `governance.tool_deprecated` event to `session-events.jsonl` when a `target_domain` is in scope. The alias layer is removed in v2.1.0.
- MCP server name renamed `bountyagent` -> `hacker-bob`. Installed `.mcp.json` files now register `mcpServers.hacker-bob`. Permission-string compatibility is preserved: settings carrying `mcp__bountyagent__*` entries continue to resolve through the deprecation window. The transport advertises `hacker-bob` as the product identifier on the wire.
- Vocabulary: per-finding records are now `CandidateClaim` written to `claims.jsonl` (the old `Finding`/`findings.jsonl` writer is preserved read-only). Cluster grouping (`ClaimCluster` in `claim-clusters.jsonl`) and frozen verification batches (`ClaimFreeze` in `claim-freeze/<id>.json`) are new claim-plane artifacts. Verification produces `VerificationResult[]` over a frozen payload instead of re-reading the live findings ledger; reports produce `ReportSnapshot` records in `report-snapshots.jsonl`.
- Session root migrated `~/bounty-agent-sessions/` -> `~/hacker-bob-sessions/`. On first access of any legacy domain directory, Bob **copies — never moves —** the directory into the canonical root and preserves the legacy copy on disk. The legacy root remains readable as a fallback through v2.0.x; v2.1.0 ships the `--purge-legacy-session-root` flag for explicit cleanup.

### Renamed tools (sample)

Every `bounty_<verb>` invocation now resolves through a `bob_<verb>` primary name. The complete rename map covers 100+ tools and is materialized at registry boot in `mcp/lib/tool-registry.js`. The top-20 renames most visible to operators and downstream integrations:

| v1.x name (alias)               | v2.x name (primary)            |
|---------------------------------|--------------------------------|
| `bounty_http_scan`              | `bob_http_scan`                |
| `bounty_read_http_audit`        | `bob_read_http_audit`          |
| `bounty_record_finding`         | `bob_record_candidate_claim`   |
| `bounty_read_findings`          | `bob_read_candidate_claims`    |
| `bounty_list_findings`          | `bob_list_candidate_claims`    |
| `bounty_index_finding`          | `bob_index_candidate_claim`    |
| `bounty_query_findings_index`   | `bob_query_candidate_claims_index` |
| `bounty_write_chain_attempt`    | `bob_write_chain_attempt`      |
| `bounty_write_verification_round` | `bob_write_verification_round` |
| `bounty_read_verification_round` | `bob_read_verification_round` |
| `bounty_read_verification_context` | `bob_read_verification_context` |
| `bounty_write_grade_verdict`    | `bob_write_grade_verdict`      |
| `bounty_read_grade_verdict`     | `bob_read_grade_verdict`       |
| `bounty_write_evidence_packs`   | `bob_write_evidence_packs`     |
| `bounty_read_evidence_packs`    | `bob_read_evidence_packs`      |
| `bounty_write_wave_handoff`     | `bob_write_wave_handoff`       |
| `bounty_apply_wave_merge`       | `bob_apply_wave_merge`         |
| `bounty_start_wave`             | `bob_start_wave`               |
| `bounty_start_next_wave`        | `bob_start_next_wave`          |
| `bounty_route_surfaces`         | `bob_route_surfaces`           |
| `bounty_transition_phase`       | `bob_advance_session` (semantics change: lifecycle states, not phases) |

Smart-contract family runners and read tools (EVM, SVM, Aptos, Sui, Substrate, CosmWasm), authorization tools, surface-leads tools, technique-pack readers, scheduling/queue-policy tools, audit-report ingestion, invariant runners, capability metrics, and verification-attempt diff tools all rename under the same `bounty_*` -> `bob_*` rule; their alias entries are listed in `mcp/lib/tools/*.js`.

### Migration

Downstream consumers should:

- Update any hard-coded `mcp__bountyagent__bounty_*` permission strings to `mcp__hacker-bob__bob_*`. The legacy form continues to resolve during the v2.0.0 alias window.
- Update phase-driven scripts to call `bob_advance_session(to_state)` with the new lifecycle state enum; the old `bounty_transition_phase(target_phase)` shim still routes but emits a deprecation event and is removed in v2.1.0.
- Treat `~/bounty-agent-sessions/` as legacy-read-only. New sessions are written to `~/hacker-bob-sessions/`; legacy directories are copied on first read and preserved on disk until `--purge-legacy-session-root` lands in v2.1.0.
- Read findings through `claims.jsonl` (`CandidateClaim` shape). The legacy `findings.jsonl` writer is retained for back-compat reads through v2.0.x and removed in a later release.
- Update verification-round and repo-init callers for two intentional schema tightenings: `bob_write_verification_round.results[]` now requires `finding_id`, `disposition`, `severity`, `reportable`, `reasoning`, `repro_steps`, and `evidence_refs`; `bob_init_session` rejects `target_repo` with `INVALID_ARGUMENTS` and `redirect_to_tool: "bob_init_repo_session"`.

Release notes: [docs/releases/v2.0.0.md](docs/releases/v2.0.0.md).

## [Unreleased]

- Renamed the telemetry-rooted `agent-runs.jsonl` to `tool-invocations.jsonl` to resolve the filename collision with the session-rooted AgentRun ledger. Consumers of `mcp/lib/tool-telemetry.js` must use the renamed exports: `toolInvocationTelemetryPath`, `appendToolInvocationTelemetryEvent`, `buildToolInvocationTelemetryEvent`, `readToolInvocationTelemetryEvents`, `recordToolInvocationTelemetry`, `safeRecordToolInvocationTelemetry`, `summarizeToolInvocationTelemetryEvents`, `toolInvocationSidecarPath`, `TOOL_INVOCATIONS_FILE_NAME`, `TOOL_INVOCATION_TELEMETRY_VERSION`, and `TOOL_INVOCATION_TELEMETRY_MAX_RECORDS`. The export-bundle filename moved from `agent-runs.filtered.jsonl` to `tool-invocations.filtered.jsonl`. An idempotent in-process migration shim (`mcp/lib/telemetry-migration.js`) renames any existing legacy `<telemetryDir>/agent-runs.jsonl` to `<telemetryDir>/tool-invocations.jsonl` on first write/read of the canonical path.
- v1.3.6 follow-up: complete removal of the `legacy_unverified` handoff path. v1.3.5 keeps the path behind the per-session `handoff_provenance_required` flag so sessions initialised on v1.3.5+ already fail-closed; v1.3.6 will drop the legacy branch entirely from `wave-handoff-contracts.js`, `phase-gates.js`, `pipeline-session-artifacts.js`, and `wave-handoff-store.js`.
- v1.3.6 follow-up: end-to-end live policy-replay smoke. v1.3.5 fixes SDK package + native-binary resolution from an installed workspace's `testing/policy-replay/replay.mjs`, but does not exercise `query()` invocation. v1.3.6 will add a Claude-OAuth-gated live-replay smoke test so binary lookup is verified beyond static resolution.

## [1.3.5] - 2026-06-03

### OSS repo hunting mode

- Added `/bob-oss` (Claude) and `$bob-oss` (Codex) for authorized OSS repository security research. The skill accepts a GitHub URL, clones into a sandboxed session directory, scaffolds a Docker toolchain image via `bounty_repo_prepare_env`, and runs the full Bob hunter pipeline (recon → hunt → verify → grade → report) against the local repo surface.
- Added `bounty_repo_docker_run`, `bounty_repo_check`, `bounty_repo_inventory`, `bounty_repo_prepare_env`, `bounty_import_static_artifact`, and `bounty_static_scan` MCP tools covering sandboxed Docker execution, repo health checks, source inventory, static artifact ingestion, and CodeQL/Semgrep static scanning.
- Added a `native` surface type handled by a shared `hunter-agent` with OSS-specific brief: ASAN/libFuzzer/Valgrind harness building, static-scan result ingestion, and coverage-guided fuzzing within the Docker sandbox.
- Added per-path reachability and severity-ceiling triage: the OSS hunter brief includes a `reachability` object per finding with `caller_path`, `trigger_conditions`, and `severity_ceiling` so the grader can downgrade unbounded heap findings gated behind CLI-local or daemon-only call paths.
- Added local OSS session dashboard (`/bob-status` renders `oss-dashboard.html`) showing active repo sessions, per-session phase/finding counts, and open blockers without requiring a live MCP connection.
- Hardened the OSS Docker proof gate: `bounty_repo_docker_run` rejects runs that lack a prior successful `bounty_repo_prepare_env` image, and hunter briefs cap array fields so a large source tree cannot overflow the context window.
- Added OSS planning docs at `docs/OSS_MODE_MVP.md` covering the sandboxing contract, harness patterns, and escalation path from ASAN crash to CVE submission.
- Added pcap build detection and attribution credit fields to `hunter-techniques.json` for network-protocol fuzz harnesses.

### Kimi CLI adapter

- Added a Kimi CLI adapter (`adapters/kimi/`) that mirrors the Codex adapter shape: six Bob skills (`bob-hunt`, `bob-debug`, `bob-status`, `bob-update`, `bob-export`, `bob-egress`), adapter config, and role rendering via `scripts/lib/kimi-role-renderer.js` + `scripts/generate-kimi-roles.js`.
- Published a thin `hacker-bob-kimi` wrapper package (`packages/hacker-bob-kimi/`) that pins `--adapter kimi` and delegates to the canonical `hacker-bob` CLI, matching the existing `hacker-bob-cc` and `hacker-bob-codex` wrappers.
- Wired Kimi into install + lifecycle plumbing: `scripts/install.js` and `scripts/lifecycle.js` now route to the Kimi adapter, `dev-sync.sh` covers the Kimi workspace, and `bin/hacker-bob.js` recognizes `--adapter kimi`.
- Centralized the wrapper-package and install-metadata registries in `scripts/lib/package-policy.js` so `release-check.js`, `test/package.test.js`, and adapter detection see all three wrappers through a single source.
- Added Kimi coverage to the adapter test surfaces (`test/adapter-detection.test.js`, `test/cli.test.js`, `test/install-smoke.test.js`, `test/mcp-server.test.js`, `test/package.test.js`, `test/prompt-contracts.test.js`) and documented the adapter in `docs/ADAPTERS.md`, `docs/FIRST_RUN.md`, and `docs/TROUBLESHOOTING.md`.
- Restored the explicit `severity: null` schema entry in `mcp/lib/tools/write-verification-round.js` that regressed during the runtime-contracts refactor, so verification rounds that legitimately drop severity to null pass tool validation.

### CVE feed matching and public intel

- Wired CVE feed matching into `bounty_public_intel`: the tool now cross-references NVD/GHSA feeds against the session's target domain and known surface endpoints, surfacing relevant recent CVEs as ranked leads in the hunter brief.

### Installer and dependency hardening

- Hardened installer writes against symlinks: `scripts/install.js` now resolves symlinks before writing any Bob-owned file, preventing a TOCTOU attack where a malicious symlink placed in `.claude/` could redirect an install write to an arbitrary path.
- Added `bounty_warn_stale_psl` (surfaced via `/bob-status`) that flags when the installed Public Suffix List dependency is more than 90 days old, so domain-scoping checks remain accurate against new TLDs and private-domain additions.
- Isolated MCP egress profile tests so `egress-profiles.json` reads and writes during `npm test` cannot interfere with an active operator workspace.
- Strengthened attribution on `hunter-techniques.json` so technique entries carry a `source` field referencing the originating research or CVE advisory.
- Added Codex review guidance (`docs/CODEX_REVIEW.md`) covering how to run and interpret Codex-adapter hunts alongside Claude-adapter hunts.

### Runtime contracts and release gates

- Narrowed `mcp/server.js` to the runtime MCP facade: `TOOLS`, `TOOL_MANIFEST`, `executeTool`, and `startServer`. Internal tests now import lower-level contracts from their owning modules.
- Clarified the egress policy boundary: raw shell surface-discovery is not claimed as Bob-enforced containment, MCP-scoped HTTP tools remain the runtime policy authority, no-op scope guard hooks were removed from generated settings, browser auto-signup now uses egress profiles and refuses strict internal-host mode, and `block_internal_hosts` now rejects proxy-backed HTTP egress profiles because proxy-side DNS/routing cannot be verified by Bob.
- Extracted shared contract/store modules for session state, findings, verification rounds, wave handoffs, grade verdicts, pipeline events, and session authority.
- Added clean release/package gates, dependency freshness checks, package-surface documentation, and a generated authority inventory freshness check.
- Suppressed stale Claude statusline update hints after local installs and clarified the hint text as an update target instead of a current-version label.
- Release notes: [docs/releases/v1.3.5.md](docs/releases/v1.3.5.md).

### Review-cycle hardening

- Fixed `mcp/lib/tool-validation.js` so explicit `null` is no longer conflated with "missing" for required + nullable fields. Affects `bounty_write_verification_round.notes`, `bounty_write_evidence_packs.packs[].redaction_notes`, `bounty_write_grade_verdict.feedback`, and `bounty_write_grade_verdict.findings[].feedback`; consumers already normalize null via `normalizeOptionalText`.
- Restored a compat shim in `mcp/lib/pipeline-analytics.js` that re-exports `appendPipelineEventDirect`, `safeAppendPipelineEventDirect`, `safeAppendPipelineEventWithSessionLock`, and `safeRecordEvaluatorStoppedPipelineEvent` from `pipeline-events.js` so downstream importers do not break.
- Reordered session-state normalization before fail-closed assertion in `mcp/lib/session-authority.js`, and trimmed `LEGACY_FAIL_CLOSED_FIELDS` to `target` + `target_url` only. v1.3.4-shaped sessions now backfill via the normalizer instead of failing with `STATE_CONFLICT` on read.
- Added the per-session `handoff_provenance_required` flag in `mcp/lib/session-state-contracts.js`, defaulted to `true` for sessions initialised on v1.3.5+ and `false` for legacy sessions resumed from disk. When set, `validateHandoffToken` and `validateHandoffProvenance` reject the previous `legacy_unverified` downgrade path with an actionable re-init hint; when unset, legacy behavior is preserved so in-flight pre-v1.3.5 sessions can drain.
- Unified wave readiness in `mcp/lib/wave-handoff-store.js`: `buildWaveReadiness` now validates handoff content and provenance inline when the domain is provided, exposes an `invalid_agents` field, and sets `is_complete = missing.length === 0 && invalid.length === 0`. `bounty_apply_wave_merge` propagates invalid surfaces into `missing_surface_ids` so the orchestrator cannot lose track of them.
- Hardened `summarizeStructuredHandoffChainNotes` in `mcp/lib/pipeline-session-artifacts.js`: a legitimately missing assignment file (ENOENT) falls back to direct `chain_notes` parsing capped at 10 per session, and the summary reports `unsigned_handoff_count` for operator visibility. Tamper-style validation failures still drop the affected handoff.
- Wired `npm run release:check:dependencies` as its own step in `.github/workflows/release.yml` so PSL freshness gates run on every tagged release.
- Closed the pre-existing live-replay SDK-resolution gap surfaced by the PR #44 install layout: `testing/policy-replay/replay.mjs` now tries the bare specifier first and falls back to `createRequire(<workspace>/mcp/server.js).resolve("@anthropic-ai/claude-agent-sdk")`, and `scripts/install.js` now walks `optionalDependencies` so the SDK's current-platform native package (e.g. `@anthropic-ai/claude-agent-sdk-darwin-arm64`) propagates into the installed workspace when npm installed it in source. `test/install-smoke.test.js` asserts both contracts.

## [1.3.4] - 2026-05-14

### Codex adapter parity

- Added `$bob-egress` as a Codex direct skill and plugin command wrapper so Codex users can list, add, test, enable, disable, and remove operator egress profiles without switching to Claude Code.
- Moved the egress profile command implementation into shared runtime code at `mcp/lib/egress-cli.js`, with the Claude `/bob-egress` hook delegating to the same helper.
- Kept host-specific environment fallback in the Claude adapter wrapper so shared runtime code stays host-neutral.
- Updated install, doctor, uninstall, prompt-contract, CLI, and install-smoke coverage for the new Codex egress surface.
- Release notes: [docs/releases/v1.3.4.md](docs/releases/v1.3.4.md).

## [1.3.3] - 2026-05-13

### Session contract hardening

- Tightened evaluator and orchestrator contracts so web evaluators log a completion-status `bounty_log_technique_attempt` before finalization, and finalization failures explicitly direct agents to repair either the structured handoff or the missing technique-attempt log.
- Required `steps[]` on `bounty_write_chain_attempt` examples so CHAIN -> VERIFY transitions preserve the replay or rejection path for every terminal chain decision.
- Clarified that reporters must write the canonical session `report.md` before calling `bounty_report_written`; analytics now distinguishes SUBMIT grades with a missing canonical report path from ordinary missing-report states.
- Clamped oversized `bounty_read_http_audit` limits to the release cap instead of rejecting otherwise valid audit-summary reads.
- Regenerated Claude and Codex prompt artifacts and added regression tests for the new session-contract expectations.
- Release notes: [docs/releases/v1.3.3.md](docs/releases/v1.3.3.md).

## [1.3.2] - 2026-05-12

### Surface-discovery guard compatibility

- Updated normal and deep surface-discovery prompts to keep bulky collection captures in temporary scratch outside `~/bounty-agent-sessions`, while preserving compact session artifacts for downstream routing.
- Removed guard-blocked surface-discovery scratch names such as `subdomains.tmp`, `family_raw.txt`, `js_raw.txt`, and deep surface-discovery `[SESSION]/raw/*` paths from the generated Claude and Codex surface-discovery contracts.
- Kept MCP-owned session boundaries intact: compact surface-discovery summaries are readable, `surface-leads.json` remains write-protected outside MCP-owned flows, and raw proof/body/dump-style artifacts remain blocked.
- Added hook and prompt-contract tests that exercise compact surface-discovery JSON allowlists and prevent surface-discovery prompts from reintroducing guard-blocked session scratch paths.
- Release notes: [docs/releases/v1.3.2.md](docs/releases/v1.3.2.md).

## [1.3.1] - 2026-05-11

### Runtime-owned wave starts

- Added `bounty_start_next_wave` so normal EVALUATE/EXPLORE wave assignment policy now lives in the MCP runtime instead of orchestrator prompt prose.
- Added the pure wave planner for standard bucket ordering, open requeue coverage, lead-surface follow-up, assignment caps, dedupe, and stable `aN` labels.
- Moved automatic deep lead promotion into the new next-wave starter, leaving `bounty_promote_surface_leads` for explicit operator use.
- Updated EVALUATE -> CHAIN gating, prompts, manifests, generated Claude/Codex artifacts, and tests so normal waves use the runtime-owned result instead of manual assignment calculation.
- Rewrote the README into a cleaner user-facing guide and removed install instructions aimed at users' coding assistants.
- Release notes: [docs/releases/v1.3.1.md](docs/releases/v1.3.1.md).

## [1.3.0] - 2026-05-10

### Capability hypergraph

- Shipped the post-v2 [capability hypergraph](docs/capability-hypergraph.md): 8 capabilities, with C8 shipping substrate-only until explicit program policy permits live AI-driven disclosure speedruns.
- Added 26 MCP tools across schema contracts, doc delta, auth differential, findings index, surface graph, chain tree, audit report ingest, invariant suggestions/runs, route extraction, symbol-surface indexing, diff impact, capability metrics, and capability evaluation.
- Added 9 session artifacts: `schema-contracts.jsonl`, `doc-delta-results.json`, `auth-differential-results.json`, `findings-index.jsonl`, `surface-graph.jsonl`, `chain-tree.jsonl`, `audit-reports.jsonl`, `invariant-runs.jsonl`, and `symbol-surface-index.json`.
- Added 3 bounded assignment-brief slices: `schema_slice`, `priors_slice`, and `surface_graph_slice`.
- Added regression guards for web and smart-contract evaluator brief size, v1/v2 `/bob-status` verification-panel rendering, and MCP-driven doc-delta execution against a local HTTP fixture.
- Release notes: [docs/releases/v1.3.0.md](docs/releases/v1.3.0.md).

## [1.2.5] - 2026-05-08

### Adapter wrapper READMEs

- Added `README.md` to the `hacker-bob-cc` and `hacker-bob-codex` wrapper packages so the npmjs.com listing explains the wrapper, install command, and link back to the canonical `hacker-bob` package.
- Updated the wrapper `files` allowlist to include `README.md`, and bumped the release-check and `test/package.test.js` size cap from 3 KB to 5 KB while still rejecting any other extra files in the wrapper pack.

## [1.2.4] - 2026-05-08

### Evidence agent color fix

- Replaced the unsupported `teal` color on the rendered `evidence-agent` Claude agent with the supported `cyan` value so Claude Code stops warning on agent load.
- Added a shared list of Claude Code-supported agent colors and a prompt-contract test that fails if any rendered agent uses a color outside that allowlist.

## [1.2.3] - 2026-05-08

### Post-release export bundles

- Added `/bob-export` for Claude and `$bob-export` for Codex to create deterministic, timestamped release improvement bundles after completed Bob sessions.
- Added a shared non-LLM exporter that filters telemetry and sessions to the current `bob_version`, excludes unknown/mixed-version sessions, and records exclusions in `manifest.json`.
- Bundle output now includes `AGENT_PROMPT.md`, `manifest.json`, `summary.md`, `problem-clusters.json`, `sessions.json`, filtered telemetry JSONL files, and `source-paths.txt` under `~/bounty-agent-telemetry/release-bundles/v<version>/<timestamp>/`.
- Clustered repeated bottlenecks, failed MCP tool/error-code groups, evaluator block codes, malformed artifacts, evidence/report/coverage blockers, version exclusions, and source paths for fresh-agent patching.
- Updated Claude/Codex adapter wiring, installer/dev-sync/doctor/uninstall expectations, docs, and release/package checks for the new export surface.

## [1.2.2] - 2026-05-07

### Telemetry version stamping

- Stamped `bob_version` into MCP tool telemetry, evaluator run telemetry, and pipeline analytics events so `/bob-debug` can identify which Bob build produced a run.
- Added `observed_bob_versions` to telemetry summaries so debug output can flag mixed-install drift before diagnosing target behavior.
- Updated Bob debug guidance to record the current Bob version and call out multi-version sessions explicitly.
- Fixed source-checkout version resolution so the package manifest wins over stale source-resource VERSION files, while installed project `.hacker-bob/VERSION` files still override the packaged runtime.
- Narrowed the canonical npm package include rules so local install metadata under `.claude/bob/` and `.hacker-bob/` is not packed.

## [1.2.1] - 2026-05-07

### Public naming cleanup

- Replaced public site metadata and landing-page copy that described Hacker Bob as a "bug bounty agent" with "bug bounty workflow framework" wording.
- Updated the MCP server facade comment to use Hacker Bob naming.
- Added a prompt-contract regression so public copy does not reintroduce the retired product phrasing.
- Preserved compatibility identifiers: the `bountyagent` MCP namespace and `~/bounty-agent-sessions` state path are unchanged.

### Surface-discovery tool coverage

- Added optional Katana integration to normal and deep surface-discovery so bounded in-scope crawling augments CDX/Wayback and JS extraction before `attack_surface.json` is built.
- Added JWT-shaped candidate extraction from JavaScript artifacts plus `jwt_tool` availability checks for later authorized token review without adding automated cracking or token mutation.
- Added optional deep-surface-discovery DNS/TLS enrichment with `dnsx` and `tlsx`, plus bounded `subzy` checks against CNAME takeover candidates.
- Expanded installer, doctor, README, and troubleshooting guidance to cover the existing broader surface-discovery tools (`amass`, `assetfinder`, `chaos`) plus `dnsx`, `tlsx`, `katana`, `subzy`, and `jwt_tool`.

### Capability-pack routing for evaluator dispatch

- New `mcp/lib/capability-packs.js` defines a registry of capability packs (web + smart_contract_evm/svm/aptos/sui/substrate/cosmwasm) plus a `EVALUATOR_ROLES` map keyed by role_id. Each pack pins `evaluator_agent`, `brief_profile`, `role_bundles`, and pack-keyed verifier/evidence/spawn dispatch metadata. `EVALUATOR_ROLES` is the single source of truth for evaluator role display (name, description, color, role_bundles, prompt body filename).
- `bounty_route_surfaces` and the new `surface-router-agent` classify `attack_surface.json` entries into capability packs and write `surface-routes.json`. The orchestrator transitions SURFACE_DISCOVERY → AUTH only after routing succeeds. New `bounty_read_surface_routes` tool exposes the routes to verifier/chain/evidence/reporter.
- Evaluator waves carry the route triple end-to-end: `bounty_start_wave` writes `capability_pack` + `evaluator_agent` + `brief_profile` into each persisted assignment; `bounty_record_finding` persists them on every finding; `bounty_read_assignment_brief` dispatches by `brief_profile` to either the web builder (HTTP context, traffic/audit summaries, auth-profile hints) or the smart-contract builder (`bob_spec_status` filtered to the assigned surface plus `rpc_pool` for the surface's chain). Cross-cutting fields stay in both profiles.
- Verifier, evidence, and reporter prompts dispatch on `finding.capability_pack` and embed `{{CAPABILITY_PACK_VERIFIER_TABLE}}` rendered from the registry. The orchestrator skill embeds one canonical SC spawn template plus a `{{EVALUATOR_PACK_CATALOGUE}}` keyed by `capability_pack`. Per-chain dispatch lives in the pack manifest's `verifier`/`evidence`/`spawn` blocks; prompt sources do not branch on `chain_family`.
- Read-side backfill in `normalizeFindingRecord` rebuilds the pack triple from `surface_type` + `sc_evidence.chain_family` for legacy rows that lack the metadata, so downstream consumers never see null. The all-null assignment shortcut now throws on smart-contract surfaces; the surface classifier throws on missing/unsupported `chain_family`; `recordFinding` rejects `sc_evidence` when wave/agent are absent.
- MCP tool bundles are per-chain: legacy `evaluator` bundle removed; new bundles `evaluator-shared`, `evaluator-web`, `evaluator-evm`, `evaluator-svm`, `evaluator-move`, `evaluator-substrate`, `evaluator-cosmwasm`. SC evaluator agents went from 38 tools to 10–13. `tool-registry.js` derives the chain-specific bundles from `EVALUATOR_ROLES` at module load. `SubagentStop` matchers now cover every registered evaluator family.
- `mcp/lib/role-model.js`, `scripts/lib/claude-role-renderer.js`, `adapters/codex/role-specs.js`, and `scripts/lib/codex-role-renderer.js` derive their per-chain evaluator entries from `EVALUATOR_ROLES`; adding a chain pack auto-extends every consumer. The Codex renderer's cross-cutting role list (`CODEX_CROSS_CUTTING_ROLE_IDS`) is explicit; per-chain ids are appended from the registry.
- Schema and runtime parity: `bounty_write_wave_handoff` `blocked_harness_runs[].kind` enum, the renderer's `BLOCKED_HARNESS_RUN_KINDS` constant, and `mcp/lib/waves.js BLOCKED_HARNESS_KIND_VALUES` mirror each other; tests assert the three-way mirror so a future schema or normalizer edit cannot diverge silently.
- `mcp/lib/capability-packs-rendering.js` exposes `renderCapabilityPackVerifierTable`, `substituteClaudeEvaluatorPackCatalogue`, and `substituteCodexEvaluatorPackCatalogue` so both renderers go through the same substitution helpers. Both Claude agents and Codex worker contracts ship complete tables; no rendered prompt artifact leaks an unsubstituted `{{...}}` placeholder.
- New tests: pack ↔ role-bundle consistency, evaluator MCP-tool budget ≤16, every SC pack ships a complete spawn block, rendered orchestrator catalogue lists every SC pack exactly once, no chain-specific identifier appears outside the registry, `EVALUATOR_ROLES` drives every consumer, no renderer leaks a raw placeholder, verifier/evidence registry resolution per pack, chain_family branching budget per verifier source.

### Adapter wrapper packages — `hacker-bob-cc` (Claude Code) and `hacker-bob-codex`

- `hacker-bob-cc` is now an explicit Claude Code adapter wrapper: its bin is `hacker-bob-cc`, and it injects `--adapter claude` as the default before delegating to the canonical `hacker-bob` CLI. Explicit `--adapter <id>` is preserved so the wrapper does not block multi-adapter installs.
- New parallel package `hacker-bob-codex`: `npx hacker-bob-codex install <project-dir>` installs the Codex adapter without needing `--adapter codex`.
- The canonical `hacker-bob` package and its `hacker-bob` binary are unchanged. Both wrappers depend on the canonical `hacker-bob@<version>`; framework updates ship from the canonical package and the wrapper deps bump in lock-step.
- Bin rename: the previous `hacker-bob-cc` package exposed a `hacker-bob` binary (collided with canonical when globally installed). It now exposes `hacker-bob-cc`. Use `npx hacker-bob-cc install <dir>` or `npx hacker-bob-codex install <dir>`.
- `scripts/release-check.js` now drives both wrappers from a `WRAPPER_PACKAGES` registry — adding a third wrapper means appending one entry. Each wrapper's bin source is grepped for the adapter literal so a future maintainer who renames the wrapper without updating its adapter pin gets a release-check failure.
- Tests added: per-wrapper version sync, package shape (bin name matches package name, files list contains only the bin, `dependencies.hacker-bob` pinned), bin script content (pushes `--adapter <id>`, respects explicit `--adapter`, delegates via `require`), and npm-pack output stays under 3 KB.

### Capability-pack routing (merged from main)

- Added `mcp/lib/capability-packs.js` with a `web` pack and five smart-contract packs (`smart_contract_evm`, `smart_contract_svm`, `smart_contract_move`, `smart_contract_substrate`, `smart_contract_cosmwasm`). Each pack pins a `evaluator_agent`, `brief_profile`, and role bundle; SC packs route by `surface.chain_family` (Aptos and Sui both go to `evaluator-move-agent`).
- Added `bounty_route_surfaces` MCP tool plus `mcp/lib/surface-router.js` and a new `surface-router-agent` (rendered for both Claude and Codex). The orchestrator now spawns the router after surface-discovery and only transitions SURFACE_DISCOVERY → AUTH after `surface-routes.json` is written.
- `bounty_start_wave` now writes `capability_pack`, `evaluator_agent`, and `brief_profile` into each persisted assignment and returns them in `result.data.assignments[]`. Evaluators are spawned with `subagent_type: assignment.evaluator_agent`; the orchestrator no longer branches by `chain_family` itself.
- Web tools moved to a new `evaluator-web` role bundle so the `evaluator-agent` agent receives a web-only allowlist; SC tools stay in `evaluator` and SC evaluator agents (`evaluator-evm-agent`, etc.) keep their full chain tooling.
- `SubagentStop` hooks are now derived from `evaluatorAgentNamesForCapabilityPacks()` so each registered evaluator family gets its own stop hook automatically; adding a pack adds a hook.
- `bounty_read_assignment_brief` now omits `bob_spec_status` and `rpc_pool` for web profiles and includes `run_context.capability_pack` / `evaluator_agent` / `brief_profile` so evaluators can confirm their routing.

## [1.2.0] - 2026-05-02

### Deep surface-discovery mode (merged from main)

- Added a `--deep` flag to `/bob-evaluate` and `$bob-evaluate` that swaps the normal surface-discovery agent for a new `deep-surface-discovery-agent` running broader passive discovery (subfinder, amass, assetfinder, chaos, crt.sh, archived URL collection, JS endpoint extraction, takeover candidates).
- Added compact `surface-leads.json` with three new MCP tools — `bounty_record_surface_leads`, `bounty_read_surface_leads`, `bounty_promote_surface_leads` — so evaluators can log durable leads in deep mode and the orchestrator can promote ranked leads back into `attack_surface.json` for new waves.
- `state.deep_mode` persists on resume, so `/bob-evaluate resume` keeps deep behavior even when `--deep` is omitted.

### Session summary, read guard, operator notes (merged from main)

- Added `bounty_read_session_summary` MCP tool returning a compact, structured summary (phase, blockers, evidence status, next action) so orchestrator/status/debug avoid bulky raw `state.json` reads.
- Added `.claude/hooks/session-read-guard.sh` PreToolUse hook that blocks Bash/Read against denylisted session artifacts (`state.json`, `findings.jsonl`, `report.md`, etc.) under `~/bounty-agent-sessions/`. Only `attack_surface.json` is allowed for direct reads.
- Added `mcp/lib/sensitive-material.js` validation that rejects auth headers, cookies, JWTs, and other secrets at the input boundary of any mutating MCP tool.
- Added `bounty_set_operator_note` and `bounty_clear_operator_note` for bounded non-secret operator instructions stored in session state.
- Verifier/grader/reporter/evidence prompts now require compact summary-only final responses with `BOB_VERIFY_DONE` / `BOB_CHAIN_DONE` / `BOB_GRADE_DONE` / `BOB_REPORT_DONE` / `BOB_EVIDENCE_DONE` markers and explicit forbids on raw requests, responses, cookies, tokens, or authorization headers in the final message.

### Offline guide and architecture site (merged from main)

- Added `docs/hacker-bob-offline-guide.md` (operator manual) and `docs/hacker-bob-offline-guide.pdf` (printable form).
- Added `docs/bob-architecture-event.html` (single-page architecture overview) and `docs/hacker-bob-github-qr.png`.
- Added `site/` (React + Vite marketing site source).

### Smart-contract testing pipeline

- Added six chain-family runners with allowlisted, sandboxed test execution: `bounty_foundry_run` and `bounty_halmos_run` (EVM), `bounty_anchor_run` (SVM), `bounty_aptos_run` and `bounty_sui_run` (Move), `bounty_substrate_run` (ink! / `cargo test`), and `bounty_cosmwasm_run` (cw-multi-test / `cargo test`). Each runner accepts a manifest path and a single test selector, parses framework output into structured pass/fail records, and caps captured stdout to bounded excerpts.
- Added 14 read-only chain-data fetch tools across the same six families for live state lookups during EVALUATE/CHAIN/VERIFY.
- Added new `evaluator-substrate` and `evaluator-cosmwasm` agent roles with bug-class catalogs (e.g., `set_code_hash_unauthorized`, `caller_spoof`, `lazy_storage_layout_drift`, `chain_extension_unauthenticated`, `migrate_msg_open`, `submessage_reply_misuse`, `indexed_map_key_collision`).
- Extended findings normalization to validate SS58 (substrate) and bech32 (cosmwasm) addresses with their actual checksum/length rules; rejected EVM-shape addresses on Move families.
- Added a dedicated `evidence-agent` role that dispatches by `surface_type`: HTTP findings go through `bounty_http_scan`; SC findings go through the appropriate family runner with a `sample_type` mapping (`evm_foundry_run`, `svm_anchor_run`, `aptos_move_test`, `sui_move_test`, `substrate_ink_test`, `cosmwasm_cw_multi_test`).
- Phase gates now treat SC surfaces consistently: EVALUATE→CHAIN respects `partial` + `bypass_attempts`; CHAIN→VERIFY clears via `bounty_write_chain_attempt` per pivot; VERIFY→GRADE clears via SC-aware evidence packs.

### Adapter auto-detection on install / update / doctor / uninstall

- `hacker-bob install <project-dir>` no longer requires `--adapter`. When the flag is omitted, Bob picks an adapter using a layered detector: (1) prior install metadata in `.hacker-bob/install.json`, (2) host environment markers (`$CLAUDE_PROJECT_DIR`, `$CODEX_HOME`), (3) project files (`.claude/`, `.codex/plugins/`, `.agents/plugins/`, `.mcp.json`), or (4) host CLI on `PATH`. Claude remains the final fallback. The chosen adapter and reason are logged to stderr.
- **Behavior change (no-flag `install` and `update`):** previously, missing `--adapter` always defaulted to `claude`. Reinstalling a Codex-only project would silently install Claude *alongside* it; updating that project would refresh only Claude. With auto-detection, reinstalls and updates preserve the existing adapter mix from `.hacker-bob/install.json`.
- **Behavior change (no-flag `doctor`):** previously, missing `--adapter` ran only Claude checks. Now `doctor` runs the checks for every adapter recorded in install metadata.
- **Behavior change (no-flag `uninstall`):** previously, missing `--adapter` removed only Claude. Now `uninstall` removes every adapter recorded in install metadata. The default `--dry-run` behavior is unchanged: explicit `--yes` is still required to remove files.
- Added `detectAdapterId(projectDir, options)` to `adapters/index.js` as a pure, host-injectable function with a fixed precedence order; added `resolveInstallAdapters` and `resolveLifecycleAdapters` helpers in `scripts/install.js` and `scripts/lifecycle.js` so install/update/doctor/uninstall share the same adapter resolution path.

### Brutalist verifier wired to `@brutalist/mcp`

- Added the external `@brutalist/mcp` server (npm) to the install configuration of every adapter as an optional MCP server alongside `bountyagent`. Claude registers it via `.mcp.json` merge; Codex ships it in the bundled plugin `.mcp.json`; generic-mcp merges it into the operator's root `.mcp.json`.
- Updated `prompts/roles/brutalist-verifier.md` so the brutalist verifier calls `mcp__brutalist__roast` per finding for an additional adversarial pass after the PoC re-run, with explicit graceful fallback when the MCP is unavailable. The roast verdict folds into `reasoning`; the PoC re-run still drives `disposition` and `severity`.
- The brutalist tools allowlist excludes `mcp__brutalist__roast_cli_debate` — the debate orchestrator is too time-expensive for a per-finding loop. Only `roast`, `brutalist_discover`, and `cli_agent_roster` are exposed.
- `requiredMcpServers` for brutalist-verifier remains `bountyagent`-only so the agent can spawn even when `@brutalist/mcp` is absent.
- Added an info-level doctor check (`claude_mcp_brutalist_optional`, `generic_mcp_brutalist_optional`) reporting brutalist-server presence; never errors on absence.

### AI-agent install reframing (mirrors main v1.1.8 / v1.1.9 intents, adapted for the multi-adapter architecture)

- Added a new `### For AI Coding Agents` subsection at the top of the README Quickstart that treats a pasted repository URL as an install request, defaults the install target to `$PWD`, and tells AI agents not to ask "what do you want to do?" when the current directory is a normal project.
- Documented the auto-detection precedence and the per-adapter verification commands (claude: `claude mcp list` shows `bountyagent`; codex: `~/.codex/skills/bob-evaluate/SKILL.md` exists; generic-mcp: `.mcp.json` contains `mcpServers.bountyagent`).
- Added a "do not install into the Hacker Bob source tree" guard for AI agents.
- Added a `## MCP Troubleshooting` section covering the `Cannot find module './tools/index.js'` failure mode and three adapter-specific reload failures, plus a callout that `bountyagent` is the expected MCP server namespace and not a stale skill name.
- Tagline edit: "point him at a domain" → "point him at an authorized target".
- Ignored `.claude/bob/{VERSION,install.json,egress-profiles.json}` so installing Bob into a hacker-bob source checkout does not leak machine-specific install metadata into commits.

### Tests

- Added `test/adapter-detection.test.js` with 14 unit tests covering all four detection layers and precedence.
- Added 7 new CLI integration tests covering: fresh-install default fallback, project-artifact-driven codex selection, reinstall preservation, multi-adapter no-flag uninstall, multi-adapter no-flag doctor, no-flag update preserving prior adapters, and generic-mcp `.mcp.json` presence after install.

## [1.1.9] - 2026-04-29

- Simplified README onboarding for AI coding agents: a pasted repository URL is now explicitly treated as an install request.
- Changed the AI-agent default path to install into the current working directory with `npx -y hacker-bob-cc@latest install "$PWD"`, then run the MCP load check and `claude mcp list`.
- Added guidance that agents should not ask "what do you want to do?" when the current directory is a normal project/workspace.
- Kept source-clone installation as a fallback for npm outages or explicit source-install requests.

## [1.1.8] - 2026-04-29

- Reordered the README quickstart so AI coding agents see the repository-link install flow before the human install path.
- Clarified that the cloned Hacker Bob repository is normally the install source and that Bob must be installed into the Claude Code project where `/bob-evaluate` will run.
- Documented that `bountyagent` is the expected internal MCP server namespace behind Bob's `bounty_*` tools, while `/bob-*` commands remain the user-facing surface.
- Added MCP troubleshooting for stale or incomplete installs that fail with `Cannot find module './tools/index.js'`.
- Ignored local `.claude/bob/` install metadata so source checkouts used for packaging do not accidentally include machine-specific install state.

## [1.1.7] - 2026-04-28

- Added operator-controlled egress profiles under `.claude/bob/`, including a safe example config, installer-preserved operator config, and `/bob-egress` management commands for listing, adding, testing, enabling, disabling, and removing profiles.
- Extended `bounty_http_scan` with optional `egress_profile` support, proxy-backed `http`, `https`, `socks5`, and `socks5h` scanning through `proxy-agent`, early profile validation, credential redaction, and audit fields for `egress_profile` and `egress_region`.
- Added geofence/reachability visibility for repeated first-party network failures through HTTP audit summaries, circuit-breaker summaries, pipeline analytics, `/bob-status`, `/bob-debug --deep`, and evaluator briefs.
- Updated `/bob-evaluate` so `--egress <profile>` is passed through AUTH, evaluator, chain, verifier, and evidence prompts while keeping profile switching explicit and operator-controlled.
- Updated install, doctor, uninstall, packaging, and release checks so the egress command, helper, config example, runtime dependency, and package metadata are shipped and validated.
- Changed `/bob-evaluate` so zero-reportable VERIFY results still close through SKIP grading and a no-findings report instead of stopping at VERIFY.
- Added evaluator guardrails for repeated `INTERNAL_ERROR` host failures and explicit `chain_notes` length truncation before wave handoff writes.
- Added required force-merge reasons to wave settlement and pipeline analytics so debug attribution survives without transcript context.

## [1.1.6] - 2026-04-27

- Added bounded evidence pack visibility to `/bob-status` so operators can see whether final reportable findings have valid, missing/invalid, skipped, or unknown evidence readiness.
- Documented the `VERIFY -> GRADE` evidence-pack gate without adding a new FSM phase: final reportable findings need valid evidence packs after final verification and before grading or reporting.
- Tightened prompt-contract coverage so `/bob-status` may read evidence packs for confirmation while remaining read-only and non-networked.

## [1.1.5] - 2026-04-26

- Fixed `/bob-update` and the `bob-status` skill body so the `node .../.claude/hooks/bob-update.js` invocations resolve when Claude Code does not propagate `CLAUDE_PROJECT_DIR` into the assistant's Bash tool subprocess (observed on Claude Code 2.1.119). Both surfaces now use `${CLAUDE_PROJECT_DIR:-$PWD}` so the path falls back to the Bash tool's working directory, which is the project root, while still preferring the env var when the harness exports it.
- Added prompt-contract regression assertions pinning the `${CLAUDE_PROJECT_DIR:-$PWD}` form in `bob-update.md` and `bob-status/SKILL.md` so a future edit cannot silently reintroduce the bare `$CLAUDE_PROJECT_DIR` that produced `MODULE_NOT_FOUND /.claude/hooks/bob-update.js`.

## [1.1.4] - 2026-04-27

- Fixed the installer to copy the shipped `testing/policy-replay/` harness into target projects so `/bob-debug` replay escalation can run from installed workspaces.
- Added doctor and install-smoke coverage for the policy replay harness files.

## [1.1.3] - 2026-04-27

- Added a shipped `testing/policy-replay/` harness for diagnosing Bob policy/refusal regressions with the Claude Agent SDK and local Claude OAuth.
- Updated `/bob-debug` so post-session QA can detect policy/refusal stuck signals, run bounded local replay/tune diagnostics, and suggest a reviewed prompt change without editing prompts or mutating session state.
- Added structured chain-attempt artifacts and read/write MCP tools so CHAIN, VERIFY, GRADE, REPORT, analytics, and hooks consume machine-readable chain evidence instead of markdown.
- Added CI-safe policy replay tests, package coverage for the replay harness, and release packaging of the harness scripts and sample fixture.
- Deprecated the older raw Anthropic API refusal replay helpers in favor of the maintained policy replay case format.

## [1.1.2] - 2026-04-26

- Renamed the three skill directories and frontmatter `name:` fields to hyphen form (`bob-evaluate`, `bob-status`, `bob-debug`). v1.1.1 used colon-form `name:` (`bob:evaluate`), which Claude Code v2.1.119 rejects as invalid (`name:` only accepts lowercase letters, numbers, and hyphens), so it silently fell back to the directory name and registered the slashes as `/bountyagent`, `/bountyagentstatus`, `/bountyagentdebug` — meaning typing `/bob:evaluate` got rewritten to `/bountyagent` on enter.
- Renamed `/bob:update` to `/bob-update` and moved the command from `.claude/commands/bob/update.md` to `.claude/commands/bob-update.md` so all four slash commands share the same hyphen scheme.
- Installer and `dev-sync.sh` now proactively delete the legacy `bountyagent`, `bountyagentstatus`, `bountyagentdebug` skill directories and the entire `commands/bob/` subdirectory on upgrade, so users coming from `<=1.1.1` do not keep orphan slash entries.
- Uninstall manifest sweeps the new layout, the v1.1.1 layout, and the v1.1.0 layout so old installs still clean up entirely.
- Updated README, CLAUDE.md, FIRST_RUN, ROADMAP, TROUBLESHOOTING, and media docs to use the new `/bob-evaluate`, `/bob-status`, `/bob-debug`, `/bob-update` slashes.

## [1.1.1] - 2026-04-25

- Fixed duplicate slash entries (`/bob-evaluate` + `/bob:evaluate`, etc.) in the Claude Code menu by giving the three skills colon-form `name:` frontmatter (`bob:evaluate`, `bob:status`, `bob:debug`) so each skill IS its own slash command.
- Removed redundant command shims `commands/bob/{evaluate,status,debug}.md`; only `commands/bob/update.md` remains because no skill backs `/bob:update`.
- Installer and `dev-sync.sh` now proactively delete the legacy evaluate/status/debug shims on upgrade so users coming from <=1.1.0 do not retain orphan files that would re-introduce the duplicates.
- Uninstall manifest sweeps both the current shim layout and the legacy three-shim layout so old installs still clean up entirely.

## [1.1.0] - 2026-04-26

- Added `hacker-bob doctor <project-dir> [--json]` for read-only install diagnostics.
- Added `hacker-bob uninstall <project-dir> [--dry-run] [--yes] [--json]` for conservative removal of Bob-managed files and config entries.
- Added the `hacker-bob` npm alias package while keeping `hacker-bob-cc` canonical.
- Updated release publishing to publish both npm packages with provenance.
- Added Quickstart, troubleshooting docs, release notes, and bug report diagnostics guidance.
- Optimized the README image to reduce npm package size.

## [1.0.1] - 2026-04-26

- Clarified install docs and CLI help: Bob installs into one project directory per command, while global npm install only installs the `hacker-bob` CLI.

## [1.0.0] - 2026-04-26

- Initial public `hacker-bob-cc` npm package with `hacker-bob` CLI install and update commands.
- Added `/bob:update`, passive update cache checks, installed version metadata, and status update hints.
- Preserved the source `install.sh` path as a compatibility wrapper.
