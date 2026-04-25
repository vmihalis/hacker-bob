<p align="center">
  <img src="docs/hacker-bob.png" alt="Hacker Bob" width="320" />
</p>

<h1 align="center">Meet Hacker Bob</h1>

<p align="center"><i>Autonomous bug bounty hunting framework for Claude Code.</i></p>

Bob spawns specialized agents for recon, hunting, verification, grading, and reporting — all driven by a single `/bountyagent` command.

## Install

```bash
git clone https://github.com/vmihalis/hacker-bob.git
cd hacker-bob
./install.sh /path/to/your/project
```

The installer drops agents, the `/bountyagent` skill, rules, hooks, and the MCP server into your project's `.claude/` directory. Re-running it is idempotent and preserves your existing config.

## Usage

```bash
cd /path/to/your/project
claude
```

Then in Claude Code:

```
/bountyagent target.com         # full autonomous run
/bountyagent resume target.com  # pick up where you left off
```

## Pipeline

```
RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT
```

1. **RECON** — subdomains, live hosts, archived URLs, nuclei, JS secrets
2. **AUTH** — detects signup, stores attacker/victim profiles, or runs unauthenticated
3. **HUNT** — parallel hunter agents per attack surface
4. **CHAIN** — A→B exploit chain analysis
5. **VERIFY** — 3 rounds: skeptical, balanced, fresh PoC
6. **GRADE** — 5-axis scoring with SUBMIT/HOLD/SKIP verdict
7. **REPORT** — submission-ready report with PoCs and evidence

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) with Claude Opus
- `curl` and `python3`
- Optional: `subfinder`, `httpx`, `nuclei` for deeper recon

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

## Development

To sync the current repo into a local test workspace:

```bash
./dev-sync.sh /absolute/path/to/test-workspace
```

This backs up the target's `.mcp.json` and `.claude/settings.json`, runs the installer, recopies the MCP runtime, and smoke-checks with `claude mcp list`.

See [`CLAUDE.md`](CLAUDE.md) for the maintainer workflow.
