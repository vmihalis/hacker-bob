# First Run

This guide walks through a clean install into one project directory and a short smoke test.

## Install

Choose the project directory where you will run your host CLI, then install Bob into that directory. Claude is the default adapter:

```bash
npx -y hacker-bob@latest install /path/to/your/project
cd /path/to/your/project
```

Other adapters use the same target directory with an explicit adapter flag:

```bash
npx -y hacker-bob@latest install /path/to/your/project --adapter codex
npx -y hacker-bob@latest install /path/to/your/project --adapter generic-mcp
npx -y hacker-bob@latest install /path/to/your/project --adapter kimi
npx -y hacker-bob@latest install /path/to/your/project --adapter all
```

The installer writes shared runtime files into `mcp/` and `.hacker-bob/`, then writes the selected adapter surface. Claude uses `.claude/`, Codex uses direct `$bob-*` skills in `~/.codex/skills` plus `.codex/plugins/hacker-bob`, `.agents/plugins/marketplace.json`, and Codex cache/config activation for MCP wiring, Kimi uses `.kimi/skills` with `.kimi/mcp.json`, and generic MCP uses root `.mcp.json` plus `.hacker-bob/generic-mcp/` prompt docs. Codex exposes Bob as `$bob-evaluate`, `$bob-status`, `$bob-debug`, `$bob-update`, `$bob-export`, and `$bob-egress` skills. Kimi exposes Bob as `/skill:bob-evaluate`, `/skill:bob-status`, `/skill:bob-debug`, `/skill:bob-update`, `/skill:bob-export`, and `/skill:bob-egress`. A global npm install adds the `hacker-bob` command to your `PATH`, but it does not install Bob into every project automatically.

## Doctor Check

Run the read-only doctor command:

```bash
hacker-bob doctor /path/to/your/project
hacker-bob doctor /path/to/your/project --adapter codex
hacker-bob doctor /path/to/your/project --adapter kimi
```

A healthy install has this shape:

```text
Hacker Bob doctor: /path/to/your/project

OK: node_version - Node.js ... satisfies >=20
OK: target_directory - /path/to/your/project is a directory
OK: required_tool_curl - curl is available
OK: required_tool_python3 - python3 is available
OK: install_version - Installed Bob version is ...
OK: install_metadata_json - .hacker-bob/install.json is valid JSON
OK: install_metadata - Neutral install metadata matches this project
OK: claude_installed_version - Installed Bob version is ...
OK: claude_install_metadata_json - .claude/bob/install.json is valid JSON
OK: claude_install_metadata - Install metadata matches this project
OK: claude_commands - Bob slash commands are installed
OK: claude_hook_files - Bob hook files are installed
OK: claude_hook_modes - Executable Bob hooks have executable mode
OK: claude_mcp_json - .mcp.json is valid JSON
OK: claude_mcp_server_config - .mcp.json points hacker-bob at this project's mcp/server.js
OK: claude_settings_json - .claude/settings.json is valid JSON
OK: claude_settings_hooks - .claude/settings.json contains Bob hooks
OK: claude_settings_permissions - .claude/settings.json contains Bob MCP permissions
OK: claude_settings_statusline - .claude/settings.json contains Bob statusline
OK: mcp_server_file - mcp/server.js is installed
OK: mcp_server_loadable - mcp/server.js loads successfully
WARN: optional_tool_subfinder - subfinder is missing; related surface-discovery steps will be skipped
WARN: optional_tool_nuclei - nuclei is missing; related surface-discovery steps will be skipped
WARN: optional_tool_httpx - httpx is missing; related surface-discovery steps will be skipped
WARN: optional_tool_dnsx - dnsx is missing; related surface-discovery steps will be skipped
WARN: optional_tool_tlsx - tlsx is missing; related surface-discovery steps will be skipped
WARN: optional_tool_katana - katana is missing; related surface-discovery steps will be skipped
WARN: optional_tool_subzy - subzy is missing; related surface-discovery steps will be skipped
WARN: optional_tool_jwt_tool - jwt_tool is missing; JWT candidate review helpers will be skipped
WARN: optional_patchright - patchright is missing; Tier 2 auto-signup is disabled
WARN: optional_capsolver - CAPSOLVER_API_KEY is not set; CAPTCHA solving is disabled

No required problems found.
```

The exact list can grow as diagnostics improve. Treat any `ERROR` line as something to fix before starting a evaluate. Optional tools can be missing without blocking first use.

If doctor reports `WARN: install_version` or `WARN: install_metadata_json` and mentions legacy `.claude/bob/` metadata, the runtime can still read the legacy fallback. Rerun the installer to write neutral `.hacker-bob/` metadata.

## Restart Claude Code

After a Claude install or update, fully restart Claude Code from the project directory:

```bash
cd /path/to/your/project
claude --dangerously-skip-permissions --effort max
```

Warning: `--dangerously-skip-permissions` disables Claude Code permission prompts. Use it only in a dedicated workspace for authorized security testing.

The restart is required because Claude Code reads slash commands, MCP config, settings, hooks, and statusline setup at startup.

For Codex, restart Codex in the target directory and confirm `$bob-evaluate`, `$bob-status`, `$bob-debug`, `$bob-update`, `$bob-export`, and `$bob-egress` are available. The installer activates `hacker-bob@hacker-bob-local` in Codex's cache/config for MCP wiring; if skills are still missing, run `hacker-bob doctor /path/to/your/project --adapter codex --json`. For Kimi, launch Kimi CLI with `kimi --mcp-config-file .kimi/mcp.json` and confirm `/skill:bob-evaluate`, `/skill:bob-status`, `/skill:bob-debug`, `/skill:bob-update`, `/skill:bob-export`, and `/skill:bob-egress` are available. For generic MCP hosts, reload the host's MCP server configuration and use `.hacker-bob/generic-mcp/hacker-bob.md` as the operator prompt guide.

## Smoke Check

For Claude, run:

```text
/bob-status
```

For a fresh install, it is normal for Bob to report that there is no completed session yet. The command should load without a missing-command error and should be able to read the local MCP/status files. Bob writes session state under `~/hacker-bob-sessions/<target_domain>/`; if a pre-existing `~/bounty-agent-sessions/<target_domain>/` directory remains from before the v2.0 rename, Bob copies (never moves) it into the canonical location on first access and preserves the legacy directory until the v2.1.0 `--purge-legacy-session-root` flag is invoked.

For Codex, invoke `$bob-status`. For Kimi, invoke `/skill:bob-status`. For generic MCP hosts, list the `hacker-bob` tools or call a read-only status tool through the host's MCP UI.

## Pre-Run Checklist

Before running `/bob-evaluate`, confirm that you have written authorization for the target and accounts, and that the authorization explicitly covers the testing methods Bob may use. Check that automated scanning, authenticated testing, signup or account creation, third-party pivots, internal or private-network targets, rate limits, and data handling rules are all allowed for this engagement.

For a first smoke test, use a private lab target or an intentionally vulnerable training app you control:

```text
/bob-evaluate lab.example.test
```

Do not use a real company, public service, customer environment, or bug bounty target until you have confirmed that the target is in scope and you understand the allowed testing methods.

## Lifecycle States

A `/bob-evaluate` run advances through six lifecycle states driven by `bob_advance_session(to_state)`:

```text
SETUP -> OPEN_FRONTIER -> CLAIM_FREEZE -> VERIFY -> GRADE -> REPORT
```

- `SETUP`: session nucleus initialized (scope policy, egress identity, auth context, operator constraints) and seeded into `session-nucleus.json`.
- `OPEN_FRONTIER`: frontier-events ledger grows as surfaces are seeded, leads enqueued, observations recorded, closures and blockers asserted. Re-entrant from every later state, so the operator can return to discovery mid-run.
- `CLAIM_FREEZE`: a `ClaimFreeze` artifact captures the current `CandidateClaim` batch as an immutable frozen payload for downstream verification.
- `VERIFY`: `VerificationResult[]` records evaluate the frozen claim payload against live target behavior; no re-reads of the mutable claim ledger.
- `GRADE`: grade verdicts assign final severities and submission readiness.
- `REPORT`: `ReportSnapshot` records record the final triage-facing report; `REPORT -> OPEN_FRONTIER` is authorized for follow-up discovery.

The MCP tool surface uses the `bob_*` prefix (e.g., `bob_http_scan`, `bob_record_candidate_claim`, `bob_advance_session`). v1.x integrations that hard-coded `bounty_*` names continue to resolve through a one-release alias layer; invoking an alias appends a `governance.tool_deprecated` event to `session-events.jsonl` for visibility, and the alias layer is removed in v2.1.0.
