# Bounty Agent Repo Instructions

This repository is an install source for the Bounty Agent framework.

If a user asks you to install this framework into a project:

1. Clone this repo locally.
2. Run `./install.sh /absolute/path/to/target/project` from the cloned repo.
3. If the target project already has `.claude/settings.json` or `.mcp.json`, merge the printed `bountyagent` settings instead of overwriting unrelated config.
4. After install, run Claude Code from the target project and use `/bountyagent <target>`.

Do not assume this cloned repo is the user's active workspace unless they explicitly want that.

If the user is developing this framework itself and wants to test changes in a
local Claude Code workspace:

1. Use `./dev-sync.sh /absolute/path/to/test-workspace` from this repo.
2. This script backs up the target `.mcp.json` and `.claude/settings.json`,
   runs the installer, writes the repo-backed dev config, and runs
   `claude mcp list`.
3. It is intended for a dedicated local test workspace because it overwrites
   the target `.mcp.json` and `.claude/settings.json` after backing them up.
4. After `dev-sync.sh`, fully restart Claude Code in the test workspace, run
   `/mcp`, and smoke test `bounty_http_scan` against `https://example.com`.
