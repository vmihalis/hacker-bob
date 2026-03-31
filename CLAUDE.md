# Bounty Agent Repo Instructions

This repository is an install source for the Bounty Agent framework.

If a user asks you to install this framework into a project:

1. Clone this repo locally.
2. Run `./install.sh /absolute/path/to/target/project` from the cloned repo.
3. If the target project already has `.claude/settings.json` or `.mcp.json`, merge the printed `bountyagent` settings instead of overwriting unrelated config.
4. After install, run Claude Code from the target project and use `/bountyagent <target>`.

Do not assume this cloned repo is the user's active workspace unless they explicitly want that.
