<p align="center">
  <img src="docs/hacker-bob.png" alt="Hacker Bob" width="320" />
</p>

<h1 align="center">Meet Hacker Bob</h1>

<p align="center"><i>Autonomous bug bounty agent for Claude Code.</i></p>

<p align="center">
  <a href="https://github.com/vmihalis/hacker-bob/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/vmihalis/hacker-bob/actions/workflows/ci.yml/badge.svg" /></a>
  <a href="https://www.npmjs.com/package/hacker-bob-cc"><img alt="hacker-bob-cc on npm" src="https://img.shields.io/npm/v/hacker-bob-cc?label=hacker-bob-cc" /></a>
  <a href="https://www.npmjs.com/package/hacker-bob"><img alt="hacker-bob on npm" src="https://img.shields.io/npm/v/hacker-bob?label=hacker-bob" /></a>
  <a href="LICENSE"><img alt="Apache-2.0 license" src="https://img.shields.io/github/license/vmihalis/hacker-bob" /></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/vmihalis/hacker-bob"><img alt="OpenSSF Scorecard" src="https://api.securityscorecards.dev/projects/github.com/vmihalis/hacker-bob/badge" /></a>
</p>

Bob is an autonomous bug bounty hunting framework for Claude Code. You point him at a domain. He spawns a small army of agents — recon goblins, hunter gremlins, verifiers with trust issues — and they argue with each other until a report falls out.

You go to bed. Bob does not.

## Quickstart

Create or choose one Claude Code project directory, then install Bob into that directory:

```bash
npx -y hacker-bob-cc@latest install /path/to/your/project
cd /path/to/your/project
claude --dangerously-skip-permissions --effort max
```

Then run:

```
/bob:hunt target.com
```

## Install

Bob installs into **one Claude Code project directory per command**. The install target is the project you will later run `claude` from; the installer writes that project's `.claude/`, `mcp/`, `.mcp.json`, and related config.

Recommended one-off install:

```bash
npx -y hacker-bob-cc@latest install /path/to/your/project
```

`hacker-bob-cc` is the canonical npm package. The `hacker-bob` package is a small convenience alias that delegates to `hacker-bob-cc`; keep using `hacker-bob-cc` for pinned installs and release provenance.

The installer drops Bob's brain (agents, `/bob:*` commands, skills, rules, hooks, MCP server) into your project's `.claude/` directory. Run it as many times as you like — it's idempotent and keeps your existing config intact. Bob is polite about other people's settings.

If you prefer a global command, install the CLI once:

```bash
npm install -g hacker-bob-cc
hacker-bob install /path/to/your/project
```

Global npm install only puts the `hacker-bob` command on your `PATH`; it does **not** install Bob into every directory. To use Bob in another Claude Code project, run `hacker-bob install /path/to/that/project` for that project too.

The alias package also provides the same command:

```bash
npm install -g hacker-bob
hacker-bob install /path/to/your/project
```

Source installs still work for contributors:

```bash
git clone https://github.com/vmihalis/hacker-bob.git
cd hacker-bob
./install.sh /path/to/your/project
```

## Usage

```bash
cd /path/to/your/project
claude --dangerously-skip-permissions --effort max
```

Then in Claude Code, summon Bob:

```
/bob:hunt target.com         # full autonomous run
/bob:hunt resume target.com  # pick up where you left off
/bob:status                 # quick latest-session status
/bob:debug                   # review the latest local session
/bob:update                  # preview and install the latest Bob release
```

That's it. Now go make coffee.

For install diagnostics, run:

```bash
hacker-bob doctor /path/to/your/project
```

For common setup issues, see [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md).
For a copy-paste first-run flow, see [`docs/FIRST_RUN.md`](docs/FIRST_RUN.md).

## Updates

Run `/bob:update` inside Claude Code from the project where Bob is installed. The command checks the installed version, previews relevant `CHANGELOG.md` entries, asks before changing files, installs with:

```bash
npx -y hacker-bob-cc@latest install "$CLAUDE_PROJECT_DIR"
```

After an update, fully restart Claude Code in that project. Bob also checks for available updates once per day on `SessionStart` and stores the result in `~/.cache/hacker-bob/update-checks/`; the statusline and `/bob:status` only read that local cache.

## How Bob hunts

```
RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT
```

1. **RECON** — Bob sniffs around. Subdomains, live hosts, archived URLs, nuclei, JS secrets people forgot about.
2. **AUTH** — Bob tries to sign up. If he can, he keeps a victim and an attacker account in his pocket. If he can't, he shrugs and hunts unauthenticated.
3. **HUNT** — Parallel hunter agents fan out, one per attack surface. They are not gentle.
4. **CHAIN** — Bob squints at the findings and asks "wait, can I combine these into something worse?"
5. **VERIFY** — Three rounds of arguing with himself: skeptical Bob, balanced Bob, and final-PoC Bob. Most "bugs" do not survive.
6. **GRADE** — 5-axis scoring. Bob decides: SUBMIT, HOLD, or "this is not a bug, please stop."
7. **REPORT** — A clean, submission-ready writeup with PoCs and evidence. No "could potentially". No "an attacker may". Just receipts.

MCP ranking computes runtime priority for status views and hunter briefs. Imports and public-intel fetches do not rewrite `attack_surface.json`.

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) with Claude Opus (Bob has expensive taste)
- Node.js 20 or newer
- `curl` and `python3` (already on your machine, probably)
- Optional sidekicks for deeper recon:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

If those aren't installed, Bob just works with what he's got and doesn't complain.

## Security Model

Bob installs into a local Claude Code project directory. The installer writes Bob-managed files under `.claude/`, copies the MCP runtime into `mcp/`, merges a local `.mcp.json`, and merges Claude settings/hooks into `.claude/settings.json`. These files are project-local and should be reviewed like any other automation that can run commands from Claude Code.

Bob stores local run state and evidence under `~/bounty-agent-sessions`. Treat that directory as sensitive: it can contain target names, request metadata, notes, and report evidence from authorized testing.

During a hunt, Bob may make outbound HTTP requests, run local recon tools you have installed, import local HTTP/static artifacts, and ask Claude Code agents to reason over the results. Optional third-party services, such as browser automation dependencies, CAPTCHA solving, public-intel sources, or external recon tools, are only used when you configure the relevant dependencies or credentials.

The npm packages are published through the GitHub release workflow with npm provenance. `hacker-bob-cc` is the canonical package; `hacker-bob` is a small alias package that depends on the matching canonical version.

Bob will scan the targets you provide. You are responsible for running it only against domains, applications, accounts, and infrastructure that you own or are explicitly authorized to test, and for following each program's scope and rules of engagement.

## Development

If you're hacking on Bob himself and want to push the current repo into a test workspace:

```bash
./dev-sync.sh /absolute/path/to/test-workspace
```

It backs up the target's `.mcp.json` and `.claude/settings.json`, runs the installer, recopies the MCP runtime, and smoke-checks with `claude mcp list`. You can find the maintainer workflow in [`CLAUDE.md`](CLAUDE.md).

## A note on scope

Bob will scan whatever you tell him to scan. **You are responsible for making sure the target is in scope and that you have permission.** Bob is enthusiastic, not licensed.

Hunt responsibly. Read the program's policy. Read [`DISCLAIMER.md`](DISCLAIMER.md) before you point him at anything.

## Contributing

Community pull requests are welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening an issue or PR, and report vulnerabilities in Hacker Bob itself through [`SECURITY.md`](SECURITY.md).

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
