---
allowed-tools:
  - Bash
  - AskUserQuestion
---
Run the installed Hacker Bob update workflow for this project.

1. Run:
   `node "${CLAUDE_PROJECT_DIR:-$PWD}/.claude/hooks/bob-update.js" plan "${CLAUDE_PROJECT_DIR:-$PWD}"`
2. If the helper says Hacker Bob is already up to date or cannot reach npm, report that result and stop.
3. If an update is available or the install is legacy, ask the operator exactly: `Update now?`
4. Only when the operator confirms, run:
   `npx -y hacker-bob-cc@latest install "${CLAUDE_PROJECT_DIR:-$PWD}"`
5. Then run:
   `node "${CLAUDE_PROJECT_DIR:-$PWD}/.claude/hooks/bob-update.js" clear-cache "${CLAUDE_PROJECT_DIR:-$PWD}"`
6. Tell the operator to fully restart Claude Code in this project before continuing.
