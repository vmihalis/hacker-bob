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
| hunter-agent | Tests one attack surface per spawn | Bash, Read, Write, Grep, Glob, MCP |
| brutalist-verifier | Round 1: maximum skepticism | Bash, Read, Write |
| balanced-verifier | Round 2: catch false negatives | Bash, Read, Write |
| final-verifier | Round 3: fresh PoC confirmation | Bash, Read, Write |
| chain-builder | A→B exploit chain analysis | Read, Write, Bash |
| grader | 5-axis scoring + verdict | Read, Write |
| report-writer | Submission-ready report | Read, Write |

## MCP Server

The installer configures a local MCP server (`mcp/server.js`) that gives hunter agents structured tools:

| Tool | What it does |
|---|---|
| `bounty_http_scan` | HTTP request + auto-analysis (tech fingerprinting, secret detection, endpoint extraction) |
| `bounty_record_finding` | Write findings to disk (survives context rotation) |
| `bounty_list_findings` | List recorded findings for a target |
| `bounty_write_handoff` | Write `SESSION_HANDOFF.md` for cross-session resume only |
| `bounty_write_wave_handoff` | Write one hunter wave handoff as `handoff-wN-aN.md` plus `handoff-wN-aN.json` |
| `bounty_wave_handoff_status` | Readiness/count check for one wave based on assignment and handoff file presence |
| `bounty_merge_wave_handoffs` | Merge one wave's structured handoffs against `wave-N-assignments.json` |
| `bounty_read_handoff` | Read previous handoff to resume |
| `bounty_auth_manual` | Store auth tokens as reusable profiles |
| `bounty_wave_status` | Read-only summary of findings for wave-to-wave decisions |

Runs as a stdio MCP server — zero dependencies, just Node.js. Configured automatically by `install.sh`.

`bounty_wave_handoff_status` is a readiness tool, not a merge tool. It reports whether all assigned `handoff-wN-aN.json` files exist yet, but it does not validate handoff payloads. Malformed handoffs are left for `bounty_merge_wave_handoffs` to classify during actual reconciliation.

If the MCP server isn't available, hunters can still use `curl` plus local file tools for ad hoc work, but durable finding helpers and structured wave handoffs are unavailable. Normal orchestration expects the MCP server to be installed.

## Hooks

- **scope-guard.sh** — PreToolUse hook on Bash. Logs out-of-scope HTTP requests. Hard-blocks domains in `deny-list.txt`.
- **bounty-statusline.js** — Shows phase, wave, finding count, target, and context usage in the terminal footer.

## Rules (always active)

- **hunting.md** — 20 rules: scope checking, 5-minute rule, sibling endpoint testing, A→B signal method, CI/CD testing, SAML/SSO testing
- **reporting.md** — 12 rules: no theoretical language, mandatory PoC, CVSS accuracy, title formula, 600-word limit

## Session data

All hunt state lives in `~/bounty-agent-sessions/[domain]/`:
- `state.json` — FSM phase, wave count, pending wave, findings, explored surface IDs, exclusions, and lead routing hints; pending waves reconcile on explicit `resume`
- `attack_surface.json` — recon output grouped by priority
- `wave-N-assignments.json` — persisted per-wave `agent -> surface_id` assignments
- `handoff-wN-aN.md` — freeform hunter handoff markdown for humans and chain-building
- `handoff-wN-aN.json` — structured hunter handoff fields used for deterministic merge/requeue
- `SESSION_HANDOFF.md` — session-only resume handoff written by `bounty_write_handoff`
- `findings.md` — merged findings across waves
- `chains.md` — exploit chain analysis
- `verified-final.md` — final verified findings
- `grade.md` — scoring and verdict
- `report.md` — submission-ready report

## What works out of the box

The full core pipeline: agents, orchestrator, MCP server, hooks, and status line. Hunters get `bounty_http_scan` with auto-analysis out of the box.

## Optional extras (degrade gracefully)

| Feature | What it needs | Without it |
|---|---|---|
| **Authenticated testing** | User-provided cookies/localStorage auth data | Falls back to unauthenticated testing |
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
