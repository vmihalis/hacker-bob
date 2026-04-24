# Hacker Bob

Autonomous bug bounty hunting framework for Claude Code. Spawns specialized agents for recon, hunting, verification, grading, reporting, and optional post-report exploration through a skill-based FSM.

## Install

```bash
git clone https://github.com/vmihalis/hacker-bob.git
cd hacker-bob
chmod +x install.sh
./install.sh /path/to/your/project
```

The installer copies agents, the `/bountyagent` skill, rules, hooks, and knowledge into your project's `.claude/` directory, sets up the MCP server in `.mcp.json`, and merges hooks + status line into `.claude/settings.json`. Existing MCP servers, permissions, hooks, and unrelated user settings are preserved; running the installer repeatedly is idempotent.

## For Coding Agents

If a user pastes this repo URL into Claude Code and says "install this framework", the correct flow is:

```bash
git clone https://github.com/vmihalis/hacker-bob.git
cd hacker-bob
./install.sh /absolute/path/to/their/project
```

Install into the project where Claude Code will actually run. Do not assume the cloned `hacker-bob` repo itself is the user's working project unless they explicitly ask for that.

## Usage

```bash
cd /path/to/your/project
claude
```

Then:
```
/bountyagent target.com         # full autonomous run
/bountyagent resume target.com  # pick up where you left off
/bountyagent resume target.com force-merge  # recover a stuck/interrupted partial wave
```

Pending hunt waves reconcile on explicit `/bountyagent resume [domain]`. The launch turn that spawns background hunters stops after reporting wave launch status; merge/requeue decisions happen later on resume. Use `force-merge` only when a wave is interrupted or stuck and you need to reconcile with missing/invalid handoffs requeued by the existing merge behavior.

## Development

If you are developing the framework itself and want to sync the current repo into
your local Claude Code test workspace with one command:

```bash
cd hacker-bob
./dev-sync.sh /absolute/path/to/test-workspace
```

This backs up the target workspace's `.mcp.json` and `.claude/settings.json`,
runs the installer, recopies the repo-backed MCP runtime including per-tool
modules, re-merges the repo-backed dev config, and runs `claude mcp list` as
a smoke check unless `--no-health-check` is supplied.

## What it does

```
RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT
                                                  ↓
                                                EXPLORE
```

1. **RECON** — subdomain enum, live hosts, archived URLs, nuclei scan, JS secret extraction
2. **AUTH** — detects signup, stores attacker/victim auth profiles when possible, or continues unauthenticated/`--no-auth`
3. **HUNT** — parallel hunter agents per attack surface (2-6 waves)
4. **CHAIN** — finds A→B exploit chains across findings
5. **VERIFY** — 3 rounds: brutalist (skeptical), balanced (catch false negatives), final (fresh PoCs)
6. **GRADE** — 5-axis scoring, SUBMIT/HOLD/SKIP verdict
7. **REPORT** — submission-ready report with PoCs and evidence
8. **EXPLORE** — optional user-requested post-report hunt loop that returns to CHAIN → VERIFY → GRADE → REPORT

## Agents

| Agent | Role | Tools |
|---|---|---|
| recon-agent | Subdomain enum, URL crawling, nuclei, JS extraction | Bash, Read, Write, Glob, Grep |
| hunter-agent | Tests one attack surface per spawn | Bash, Read, Grep, Glob, MCP |
| brutalist-verifier | Round 1: maximum skepticism | Bash, Read, MCP |
| balanced-verifier | Round 2: catch false negatives | Bash, Read, MCP |
| final-verifier | Round 3: fresh PoC confirmation | Bash, MCP |
| chain-builder | A→B exploit chain analysis | Read, Write, MCP |
| grader | 5-axis scoring + verdict | MCP |
| report-writer | Submission-ready report | Write, MCP |

## MCP Server

The installer configures a local stdio MCP server (`mcp/server.js`). Its tool surface covers HTTP scanning and audit reads, optional Burp/HAR traffic import, optional public intel, safe static-artifact import and token-contract scans, auth profile storage/listing, session FSM operations, wave assignment/merge operations, hunter handoff and coverage logging, finding/verification/grade storage, and bounded hunter briefs.

The source of truth for the exported MCP surface is the registry in `mcp/lib/tool-registry.js`. A pilot set of tools already uses per-tool modules under `mcp/lib/tools/`, where the schema, role metadata, side-effect metadata, sensitivity/scope flags, and handler binding live together. Legacy tools continue to flow through `tool-definitions.js`, `tool-manifest.js`, and `tool-handlers.js` during the transition. `TOOLS`, dispatcher lookup, role-bundle permissions, generated skill frontmatter, generated agent tool frontmatter, and Claude settings all derive from the registry.

Every MCP tool response is wrapped in a standard envelope: success responses use `{ "ok": true, "data": ..., "meta": { "tool": "...", "version": 1 } }`; failures use `{ "ok": false, "error": { "code": "...", "message": "..." }, "meta": ... }`. Prompts and integrations should read successful payloads from `.data`.

Structured artifacts are the only control-plane source of truth for the FSM and downstream agents. Markdown mirrors remain for humans/debugging only and are never parsed as state. `SESSION_HANDOFF.md`, `findings.md`, handoff markdown, verification markdown, and grade markdown are human/debug only. Chain-building uses structured `summary` and `chain_notes` from `bounty_read_wave_handoffs`, not markdown handoffs. The legacy prose exceptions are `chains.md`, which verifiers may read as narrative chain context, and `report.md`, which is the final human-facing report.

Coverage, traffic, request audit, public intel, and static scans are session-scoped and MCP-owned. Hunters append concise coverage entries through `bounty_log_coverage`; `bounty_http_scan` appends Bob-generated request results to `http-audit.jsonl`; `bounty_import_http_traffic` imports optional Burp/HAR request history to `traffic.jsonl`; `bounty_public_intel` stores optional public program/report hints in `public-intel.json`; and `bounty_import_static_artifact` plus `bounty_static_scan` store redacted token-contract scan artifacts/results without ever reading arbitrary filesystem paths. `bounty_read_hunter_brief` returns only the assigned surface's capped latest-per-endpoint/class/auth coverage, relevant observed traffic, audit/circuit-breaker feedback, ranking reasons, intel hints, and bounded static scan hints. Wave merge uses unfinished coverage statuses to requeue surfaces without introducing cross-target memory.

`bounty_http_scan` blocks out-of-scope hosts by default and writes blocked attempts to `http-audit.jsonl` with `scope_decision: "blocked"`. Allowed destinations are the session target domain, hosts listed in `attack_surface.json`, and explicit public-intel hosts only when the URL references the current target. Deny-listed hosts remain hard-blocked.

The `.claude/knowledge/` layer is curated read-only reference input distilled from `claude-bug-bounty` methodology, web2 bug-class notes, payload hints, and selected wordlist patterns. It is not an imported execution system: no external scanners, extra slash commands, broad web3 automation, shell fuzzing, or memory stores are used by this phase. Burp/HAR traffic, public intel, and safe static artifact scans are optional MCP-owned inputs only; Bob still works without them. `bounty_read_hunter_brief` selects a few bounded snippets by surface tech, endpoint patterns, params, nuclei hits, JS hints, optional recon metadata, observed traffic, public intel, and static scan hints.

Recon may enrich `attack_surface.json` surfaces with optional `surface_type`, `bug_class_hints`, `high_value_flows`, `evidence`, and `ranking` fields. The original required fields remain compatible: `id`, `hosts`, `tech_stack`, `endpoints`, `interesting_params`, `nuclei_hits`, and `priority`. MCP ranking can raise priority and add reasons using API-ness, auth/admin/billing/data flows, GraphQL/WebSocket, object IDs, nuclei hits, JS secrets, imported traffic, and disclosed-report hints. This improves hunter prioritization only; it does not add scanners, web3 automation, or cross-target memory.

`bounty_wave_handoff_status` is a readiness tool, not a merge tool. It reports whether all assigned `handoff-wN-aN.json` files exist yet, but it does not validate handoff payloads. Malformed handoffs are left for `bounty_merge_wave_handoffs` to classify during actual reconciliation.

`bounty_apply_wave_merge` and `bounty_merge_wave_handoffs` never synthesize missing structured handoffs from markdown or `SESSION_HANDOFF.md`. New waves include per-agent handoff tokens; only token hashes are stored in `wave-N-assignments.json`, and merge/read responses report whether handoffs are `verified` or `legacy_unverified`. Lifecycle hooks validate hunter completion only; the orchestrator skill is the normal owner of wave merge state mutation.

If the MCP server isn't available, hunters can still use `curl` plus local file tools for ad hoc work, but durable findings, structured verification/grade artifacts, and structured wave handoffs are unavailable. Normal orchestration expects the MCP server to be installed.

## Hooks

- **scope-guard.sh** — PreToolUse hook on Bash. Logs out-of-scope HTTP requests. Hard-blocks domains in `deny-list.txt`.
- **scope-guard-mcp.sh** — PreToolUse hook on MCP scans. Preflights/logs scope drift while `bounty_http_scan` itself enforces out-of-scope blocking and auditing.
- **hunter-subagent-stop.js** — SubagentStop hook for hunter agents. Requires the final marker plus a valid structured handoff, then exits successfully without mutating wave/session state.
- **bounty-statusline.js** — Shows phase, wave, finding count, target, and context usage in the terminal footer.

## Rules (always active)

- **hunting.md** — 20 rules: scope checking, 5-minute rule, sibling endpoint testing, A→B signal method, CI/CD testing, SAML/SSO testing
- **reporting.md** — 12 rules: no theoretical language, mandatory PoC, CVSS accuracy, title formula, 600-word limit

## Session data

All hunt state lives in `~/bounty-agent-sessions/[domain]/`:
- `state.json` — FSM phase, wave count, pending wave, findings, explored surface IDs, exclusions, and lead routing hints; pending waves reconcile on explicit `resume`
- `attack_surface.json` — recon output grouped by priority, optionally enriched with surface type, likely bug classes, high-value flows, short evidence strings, and additive ranking reasons
- `wave-N-assignments.json` — persisted per-wave `agent -> surface_id` assignments with hashed handoff-token provenance for new waves
- `handoff-wN-aN.md` — freeform hunter handoff markdown for humans/debugging only
- `handoff-wN-aN.json` — structured hunter handoff fields, including `summary` and `chain_notes`, used for deterministic merge/requeue and chain context
- `SESSION_HANDOFF.md` — human/debug resume notes written by `bounty_write_handoff`; never parsed as control-plane input
- `findings.jsonl` — append-only authoritative finding storage across waves
- `findings.md` — human/debug mirror of recorded findings
- `coverage.jsonl` — MCP-owned hunter coverage ledger
- `http-audit.jsonl` — MCP-owned Bob-generated request audit ledger
- `traffic.jsonl` — MCP-owned imported Burp/HAR-style traffic ledger
- `public-intel.json` — MCP-owned optional public program/report intel cache
- `static-imports/` — MCP-owned redacted imported static artifacts
- `static-artifacts.jsonl` — MCP-owned static artifact manifest
- `static-scan-results.jsonl` — MCP-owned redacted static scan results
- `chains.md` — legacy prose exploit chain analysis read by verifiers as narrative context only
- `brutalist.json` / `brutalist.md` — round 1 control-plane JSON plus human/debug markdown
- `balanced.json` / `balanced.md` — round 2 control-plane JSON plus human/debug markdown
- `verified-final.json` / `verified-final.md` — round 3 control-plane JSON plus human/debug markdown
- `grade.json` / `grade.md` — grading control-plane JSON plus human/debug markdown
- `report.md` — submission-ready report

## What works out of the box

The full core pipeline: agents, orchestrator, MCP server, hooks, and status line. Hunters get `bounty_http_scan` with auto-analysis and request auditing out of the box.

## Optional extras (degrade gracefully)

| Feature | What it needs | Without it |
|---|---|---|
| **Authenticated testing** | User-provided cookies/localStorage auth data | Falls back to unauthenticated testing |
| **Burp/HAR traffic import** | User-supplied request history passed to `bounty_import_http_traffic` | Hunters use recon-only endpoints and Bob-generated audit |
| **Public intel** | Network access to public program/report pages, or a provided program handle | Brief returns empty intel hints and ranking uses local signals only |
| **Static token scan** | User-supplied token contract source passed as content to `bounty_import_static_artifact`, then scanned by `bounty_static_scan` | Brief returns empty static scan hints |
| **Recon tools** | `subfinder`, `httpx`, `nuclei` | Steps that need missing tools are skipped, recon continues with what's available |

The orchestrator handles all fallbacks automatically.

## Tool Development Contract

Adding a Bob MCP tool should be boring: prefer a per-tool module in `mcp/lib/tools/` that owns the schema, handler binding, role bundles, side-effect metadata, scope-hook requirement, and sensitivity flags. Legacy registry entries still exist for unmigrated tools, but new tool work should avoid manually editing separate definition, manifest, and handler-map files when a per-tool module is sufficient. Add focused tests for validation, envelope behavior, metadata, and role permissions. `TOOLS`, dispatcher lookup, role-bundle permissions, generated skill/agent tool frontmatter, and Claude settings are generated from the registry/config helpers, so do not hand-maintain duplicate permission lists in installer scripts.

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) with Claude Opus
- `curl` and `python3` (almost certainly already installed)
- Optional recon tools for deeper subdomain/vuln scanning:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```
