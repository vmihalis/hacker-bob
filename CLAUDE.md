# Hacker Bob Repo Instructions

This repository is the install source for the Hacker Bob `/bob-hunt` Claude Code framework.

If a user asks you to install this framework into a project:

1. Clone this repo locally.
2. Run `./install.sh /absolute/path/to/target/project` from the cloned repo.
3. The installer copies the skill, command shim, agents, rules, hooks, knowledge, bypass tables, MCP runtime, and generated settings. It merges `.mcp.json` and `.claude/settings.json` instead of overwriting unrelated config.
4. After install, run Claude Code from the target project and use `/bob-hunt <target>`.

Do not assume this cloned repo is the user's active workspace unless they explicitly want that.

If the user is developing this framework itself and wants to test changes in a
local Claude Code workspace:

1. Use `./dev-sync.sh /absolute/path/to/test-workspace` from this repo.
2. This script backs up the target `.mcp.json` and `.claude/settings.json`,
   runs the installer, recopies repo-backed MCP files including
   `mcp/lib/tools/*.js`, re-merges the dev config, and runs `claude mcp list`
   unless `--no-health-check` is supplied.
3. It is intended for a dedicated local test workspace because it overwrites
   Bob-owned runtime files after backing up the target MCP/settings files.
4. After `dev-sync.sh`, fully restart Claude Code in the test workspace, run
   `/mcp`, and smoke test `bounty_http_scan` with
   `target_domain: "example.com"` against `https://example.com`.

Maintainer workflow:

- Run `npm test` before handing off changes. Useful focused commands are
  `npm run test:mcp`, `npm run test:prompts`, `npm run test:install`, and
  `npm run check:syntax`.
- Generated prompt/config surfaces must stay current. Run
  `node scripts/generate-agent-tools.js` after role-bundle metadata changes and
  `node scripts/generate-bountyagent-skill.js` after orchestrator/auth bundle
  changes.
- `TOOLS`, MCP dispatch, role-bundle permissions, agent tool frontmatter, skill
  allowed-tools, Claude settings, and scope-hook registration must remain
  registry-driven.
- Lifecycle hooks enforce contracts only. Hunter `SubagentStop` validates the
  final marker and structured handoff but must not advance `pending_wave`,
  `hunt_wave`, `explored`, findings summaries, or phase state.
- Markdown mirrors are human/debug artifacts. Chain evidence is MCP-owned in
  `chain-attempts.jsonl`; `report.md` remains the final human-facing
  agent-written report.
- Hunter briefs must stay bounded: array counts are capped, scalar strings are
  capped or omitted, and agents should use auth through `bounty_list_auth_profiles`
  rather than reading secret files directly.
