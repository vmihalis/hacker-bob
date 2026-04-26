# First Run

This guide walks through a clean install into one Claude Code project directory and a short smoke test.

## Install

Choose the project directory where you will run Claude Code, then install Bob into that directory:

```bash
npx -y hacker-bob-cc@latest install /path/to/your/project
cd /path/to/your/project
```

The installer writes `.claude/`, `mcp/`, `.mcp.json`, and Claude settings/hooks into that project only. A global npm install adds the `hacker-bob` command to your `PATH`, but it does not install Bob into every project automatically.

## Doctor Check

Run the read-only doctor command:

```bash
hacker-bob doctor /path/to/your/project
```

A healthy install has this shape:

```text
Hacker Bob doctor: /path/to/your/project

OK: node_version - Node.js ... satisfies >=20
OK: target_directory - /path/to/your/project is a directory
OK: required_tool_curl - curl is available
OK: required_tool_python3 - python3 is available
OK: installed_version - Installed Bob version is ...
OK: install_metadata_json - .claude/bob/install.json is valid JSON
OK: install_metadata - Install metadata matches this project
OK: commands - Bob slash commands are installed
OK: hook_files - Bob hook files are installed
OK: hook_modes - Executable Bob hooks have executable mode
OK: mcp_json - .mcp.json is valid JSON
OK: mcp_server_config - .mcp.json points bountyagent at this project's mcp/server.js
OK: settings_json - .claude/settings.json is valid JSON
OK: settings_hooks - .claude/settings.json contains Bob hooks
OK: settings_permissions - .claude/settings.json contains Bob MCP permissions
OK: settings_statusline - .claude/settings.json contains Bob statusline
OK: mcp_server_file - mcp/server.js is installed
OK: mcp_server_loadable - mcp/server.js loads successfully
WARN: optional_tool_subfinder - subfinder is missing; related recon steps will be skipped
WARN: optional_tool_nuclei - nuclei is missing; related recon steps will be skipped
WARN: optional_tool_httpx - httpx is missing; related recon steps will be skipped
WARN: optional_patchright - patchright is missing; Tier 2 auto-signup is disabled
WARN: optional_capsolver - CAPSOLVER_API_KEY is not set; CAPTCHA solving is disabled

No required problems found.
```

The exact list can grow as diagnostics improve. Treat any `ERROR` line as something to fix before starting a hunt. Optional tools can be missing without blocking first use.

## Restart Claude Code

After install or update, fully restart Claude Code from the project directory:

```bash
cd /path/to/your/project
claude --dangerously-skip-permissions --effort max
```

Warning: `--dangerously-skip-permissions` disables Claude Code permission prompts. Use it only in a dedicated workspace for authorized security testing.

The restart is required because Claude Code reads slash commands, MCP config, settings, hooks, and statusline setup at startup.

## Smoke Check

In Claude Code, run:

```text
/bob:status
```

For a fresh install, it is normal for Bob to report that there is no completed session yet. The command should load without a missing-command error and should be able to read the local MCP/status files.

## Pre-Run Checklist

Before running `/bob:hunt`, confirm that you have written authorization for the target and accounts, and that the authorization explicitly covers the testing methods Bob may use. Check that automated scanning, authenticated testing, signup or account creation, third-party pivots, internal or private-network targets, rate limits, and data handling rules are all allowed for this engagement.

For a first smoke test, use a private lab target or an intentionally vulnerable training app you control:

```text
/bob:hunt lab.example.test
```

Do not use a real company, public service, customer environment, or bug bounty target until you have confirmed that the target is in scope and you understand the allowed testing methods.
