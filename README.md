# Bounty Agent

Autonomous bug bounty hunting framework for Claude Code. Spawns specialized agents for recon, hunting, verification, grading, and reporting — fully orchestrated through a 7-phase FSM.

## Install

```bash
git clone https://github.com/vmihalis/bounty-agent.git
cd bounty-agent
chmod +x install.sh
./install.sh /path/to/your/project
```

The installer copies everything into your project's `.claude/` directory, sets up the MCP server in `.mcp.json`, and configures hooks + status line. If you already have a `.claude/settings.json` or `.mcp.json`, it prints exactly what to merge.

## For Coding Agents

If a user pastes this repo URL into Claude Code and says "install this framework", the correct flow is:

```bash
git clone https://github.com/vmihalis/bounty-agent.git
cd bounty-agent
./install.sh /absolute/path/to/their/project
```

Install into the project where Claude Code will actually run. Do not assume the cloned `bounty-agent` repo itself is the user's working project unless they explicitly ask for that.

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
cd bounty-agent
./dev-sync.sh /absolute/path/to/test-workspace
```

This backs up the target workspace's `.mcp.json` and `.claude/settings.json`,
re-runs the installer, writes the repo-backed dev config, and runs
`claude mcp list` as a smoke check.

## What it does

```
RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT
```

1. **RECON** — subdomain enum, live hosts, archived URLs, nuclei scan, JS secret extraction
2. **AUTH** — accepts user-provided auth material when available, otherwise continues unauthenticated
3. **HUNT** — parallel hunter agents per attack surface (2-6 waves)
4. **CHAIN** — finds A→B exploit chains across findings
5. **VERIFY** — 3 rounds: brutalist (skeptical), balanced (catch false negatives), final (fresh PoCs)
6. **GRADE** — 5-axis scoring, SUBMIT/HOLD/SKIP verdict
7. **REPORT** — submission-ready report with PoCs and evidence

## Agents

| Agent | Role | Tools |
|---|---|---|
| recon-agent | Subdomain enum, URL crawling, nuclei, JS extraction | Bash, Read, Write, Glob, Grep |
| hunter-agent | Tests one attack surface per spawn | Bash, Read, Grep, Glob, MCP |
| brutalist-verifier | Round 1: maximum skepticism | Bash, Read, MCP |
| balanced-verifier | Round 2: catch false negatives | Bash, Read, MCP |
| final-verifier | Round 3: fresh PoC confirmation | Bash, MCP |
| chain-builder | A→B exploit chain analysis | Read, Write, Bash, MCP |
| grader | 5-axis scoring + verdict | MCP |
| report-writer | Submission-ready report | Write, MCP |

## MCP Server

The installer configures a local MCP server (`mcp/server.js`) that gives hunter agents structured tools:

| Tool | What it does |
|---|---|
| `bounty_http_scan` | HTTP request + auto-analysis (tech fingerprinting, secret detection, endpoint extraction) |
| `bounty_import_http_traffic` | Import Burp/HAR-style first-party request history into session-owned `traffic.jsonl` |
| `bounty_read_http_audit` | Read a capped summary of Bob-generated request audit entries from `http-audit.jsonl` |
| `bounty_public_intel` | Fetch optional public bounty intel: policy summary, program stats, scopes, and disclosed report hints |
| `bounty_record_finding` | Append an authoritative finding record to `findings.jsonl` and best-effort mirror it to `findings.md` |
| `bounty_read_findings` | Read the authoritative structured findings document for a target |
| `bounty_list_findings` | List recorded findings for a target for hunter dedupe |
| `bounty_write_verification_round` | Write one verification round JSON plus a best-effort markdown mirror |
| `bounty_read_verification_round` | Read one verification round JSON document |
| `bounty_write_grade_verdict` | Write the grade verdict JSON plus a best-effort markdown mirror |
| `bounty_read_grade_verdict` | Read the grade verdict JSON document |
| `bounty_write_handoff` | Write `SESSION_HANDOFF.md` for cross-session resume only |
| `bounty_write_wave_handoff` | Hunter-final writer for one wave handoff as `handoff-wN-aN.md` plus authoritative `handoff-wN-aN.json` |
| `bounty_wave_handoff_status` | Readiness/count check for one wave based on assignment and handoff file presence |
| `bounty_merge_wave_handoffs` | Merge one wave's structured handoffs against `wave-N-assignments.json` |
| `bounty_read_handoff` | Read previous handoff to resume |
| `bounty_auth_manual` | Store auth tokens as reusable profiles |
| `bounty_log_coverage` | Append per-session endpoint/bug-class/auth-profile coverage records to `coverage.jsonl` |
| `bounty_auto_signup` | Optional browser-assisted signup that stores attacker/victim auth profiles when Patchright is installed |
| `bounty_wave_status` | Read-only summary of findings for wave-to-wave decisions |
| `bounty_read_state_summary` | Compact phase/wave/finding/coverage state for orchestration decisions |
| `bounty_read_hunter_brief` | Per-hunter startup brief with assigned surface, exclusions, coverage, traffic, audit/circuit-breaker, ranking, intel, bypass table, and bounded curated technique guidance |

Runs as a stdio MCP server — zero dependencies, just Node.js. Configured automatically by `install.sh`.

Structured artifacts are the only control-plane source of truth for the FSM and downstream agents. Markdown outputs remain for humans/debugging only and are never intended to be parsed by code or prompts.

Coverage, traffic, request audit, and public intel are session-scoped and MCP-owned. Hunters append concise coverage entries through `bounty_log_coverage`; `bounty_http_scan` appends Bob-generated request results to `http-audit.jsonl`; `bounty_import_http_traffic` imports optional Burp/HAR request history to `traffic.jsonl`; and `bounty_public_intel` stores optional public program/report hints in `public-intel.json`. `bounty_read_hunter_brief` returns only the assigned surface's capped latest-per-endpoint/class/auth coverage, relevant observed traffic, audit/circuit-breaker feedback, ranking reasons, and intel hints. Wave merge uses unfinished coverage statuses to requeue surfaces without introducing cross-target memory.

The `.claude/knowledge/` layer is curated read-only reference input distilled from `claude-bug-bounty` methodology, web2 bug-class notes, payload hints, and selected wordlist patterns. It is not an imported execution system: no external scanners, extra slash commands, web3 automation, or memory stores are used by this phase. Burp/HAR traffic and public intel are optional MCP-owned inputs only; Bob still works without them. `bounty_read_hunter_brief` selects a few bounded snippets by surface tech, endpoint patterns, params, nuclei hits, JS hints, optional recon metadata, observed traffic, and public intel.

Recon may enrich `attack_surface.json` surfaces with optional `surface_type`, `bug_class_hints`, `high_value_flows`, `evidence`, and `ranking` fields. The original required fields remain compatible: `id`, `hosts`, `tech_stack`, `endpoints`, `interesting_params`, `nuclei_hits`, and `priority`. MCP ranking can raise priority and add reasons using API-ness, auth/admin/billing/data flows, GraphQL/WebSocket, object IDs, nuclei hits, JS secrets, imported traffic, and disclosed-report hints. This improves hunter prioritization only; it does not add scanners, web3 automation, or cross-target memory.

`bounty_wave_handoff_status` is a readiness tool, not a merge tool. It reports whether all assigned `handoff-wN-aN.json` files exist yet, but it does not validate handoff payloads. Malformed handoffs are left for `bounty_merge_wave_handoffs` to classify during actual reconciliation.

`bounty_apply_wave_merge` and `bounty_merge_wave_handoffs` never synthesize missing structured handoffs from markdown or `SESSION_HANDOFF.md`. Prompt/tool hardening reduces accidental drift, but true write-path enforcement would require MCP-side provenance checks and is out of scope for this patch.

If the MCP server isn't available, hunters can still use `curl` plus local file tools for ad hoc work, but durable findings, structured verification/grade artifacts, and structured wave handoffs are unavailable. Normal orchestration expects the MCP server to be installed.

## Hooks

- **scope-guard.sh** — PreToolUse hook on Bash. Logs out-of-scope HTTP requests. Hard-blocks domains in `deny-list.txt`.
- **bounty-statusline.js** — Shows phase, wave, finding count, target, and context usage in the terminal footer.

## Rules (always active)

- **hunting.md** — 20 rules: scope checking, 5-minute rule, sibling endpoint testing, A→B signal method, CI/CD testing, SAML/SSO testing
- **reporting.md** — 12 rules: no theoretical language, mandatory PoC, CVSS accuracy, title formula, 600-word limit

## Session data

All hunt state lives in `~/bounty-agent-sessions/[domain]/`:
- `state.json` — FSM phase, wave count, pending wave, findings, explored surface IDs, exclusions, and lead routing hints; pending waves reconcile on explicit `resume`
- `attack_surface.json` — recon output grouped by priority, optionally enriched with surface type, likely bug classes, high-value flows, short evidence strings, and additive ranking reasons
- `wave-N-assignments.json` — persisted per-wave `agent -> surface_id` assignments
- `handoff-wN-aN.md` — freeform hunter handoff markdown for humans and chain-building
- `handoff-wN-aN.json` — structured hunter handoff fields used for deterministic merge/requeue
- `SESSION_HANDOFF.md` — session-only resume handoff written by `bounty_write_handoff`
- `findings.jsonl` — append-only authoritative finding storage across waves
- `findings.md` — human/debug mirror of recorded findings
- `coverage.jsonl` — MCP-owned hunter coverage ledger
- `http-audit.jsonl` — MCP-owned Bob-generated request audit ledger
- `traffic.jsonl` — MCP-owned imported Burp/HAR-style traffic ledger
- `public-intel.json` — MCP-owned optional public program/report intel cache
- `chains.md` — exploit chain analysis
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
| **Recon tools** | `subfinder`, `httpx`, `nuclei` | Steps that need missing tools are skipped, recon continues with what's available |

The orchestrator handles all fallbacks automatically.

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) with Claude Opus
- `curl` and `python3` (almost certainly already installed)
- Optional recon tools for deeper subdomain/vuln scanning:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```
