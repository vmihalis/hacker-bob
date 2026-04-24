#!/bin/bash
set -euo pipefail

# Bounty Agent — Claude Code installer
# Copies agent definitions, command shim, skills, rules, hooks, MCP server, and settings into your project

TARGET="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLAUDE_DIR="$TARGET/.claude"
TARGET_ABS="$(cd "$TARGET" && pwd)"

echo "Installing Bounty Agent into $TARGET/.claude/"
echo ""

# Create directories
mkdir -p "$CLAUDE_DIR/agents" "$CLAUDE_DIR/commands" "$CLAUDE_DIR/rules" "$CLAUDE_DIR/hooks" "$CLAUDE_DIR/knowledge" "$CLAUDE_DIR/skills"

# Copy agents
cp "$SCRIPT_DIR/.claude/agents/"*.md "$CLAUDE_DIR/agents/"
AGENT_COUNT=$(ls "$SCRIPT_DIR/.claude/agents/"*.md 2>/dev/null | wc -l | tr -d ' ')
echo "  $AGENT_COUNT agent definitions"

# Copy orchestrator command
cp "$SCRIPT_DIR/.claude/commands/bountyagent.md" "$CLAUDE_DIR/commands/"
echo "  legacy command shim (/bountyagent)"

# Copy skills
mkdir -p "$CLAUDE_DIR/skills/bountyagent"
cp "$SCRIPT_DIR/.claude/skills/bountyagent/SKILL.md" "$CLAUDE_DIR/skills/bountyagent/"
echo "  bountyagent skill"

# Copy rules
cp "$SCRIPT_DIR/.claude/rules/"*.md "$CLAUDE_DIR/rules/"
echo "  hunting + reporting rules"

# Copy bypass tables (required for HUNT phase)
if [ ! -d "$SCRIPT_DIR/.claude/bypass-tables" ] || [ -z "$(ls "$SCRIPT_DIR/.claude/bypass-tables/"*.txt 2>/dev/null)" ]; then
  echo "ERROR: .claude/bypass-tables/ is missing or empty. HUNT phase requires these files." >&2
  exit 1
fi
mkdir -p "$CLAUDE_DIR/bypass-tables"
cp "$SCRIPT_DIR/.claude/bypass-tables/"*.txt "$CLAUDE_DIR/bypass-tables/"
echo "  bypass tables"

# Copy curated read-only hunter knowledge
cp "$SCRIPT_DIR/.claude/knowledge/"*.json "$CLAUDE_DIR/knowledge/"
echo "  hunter knowledge"

# Copy hooks
cp "$SCRIPT_DIR/.claude/hooks/scope-guard.sh" "$CLAUDE_DIR/hooks/"
cp "$SCRIPT_DIR/.claude/hooks/scope-guard-mcp.sh" "$CLAUDE_DIR/hooks/"
cp "$SCRIPT_DIR/.claude/hooks/session-write-guard.sh" "$CLAUDE_DIR/hooks/"
cp "$SCRIPT_DIR/.claude/hooks/bounty-statusline.js" "$CLAUDE_DIR/hooks/"
cp "$SCRIPT_DIR/.claude/hooks/hunter-subagent-stop.js" "$CLAUDE_DIR/hooks/"
chmod +x "$CLAUDE_DIR/hooks/scope-guard.sh" "$CLAUDE_DIR/hooks/scope-guard-mcp.sh" "$CLAUDE_DIR/hooks/session-write-guard.sh" "$CLAUDE_DIR/hooks/hunter-subagent-stop.js"
echo "  scope/session guard hooks (Bash + MCP) + status line"

# Copy complete MCP runtime
mkdir -p "$TARGET_ABS/mcp/lib"
cp "$SCRIPT_DIR/mcp/server.js" "$TARGET_ABS/mcp/"
cp "$SCRIPT_DIR/mcp/auto-signup.js" "$TARGET_ABS/mcp/"
cp "$SCRIPT_DIR/mcp/redaction.js" "$TARGET_ABS/mcp/"
cp "$SCRIPT_DIR/mcp/lib/"*.js "$TARGET_ABS/mcp/lib/"
chmod +x "$TARGET_ABS/mcp/server.js"
echo "  MCP runtime (mcp/server.js, auto-signup.js, redaction.js, lib/*.js)"

# Configure .mcp.json and .claude/settings.json without clobbering unrelated user config
node "$SCRIPT_DIR/scripts/merge-claude-config.js" "$TARGET_ABS" >/dev/null
echo "  .mcp.json merged"
echo "  settings.json merged (permissions + hooks + statusLine)"

# Create session directory
mkdir -p ~/bounty-agent-sessions
echo "  ~/bounty-agent-sessions/"

# Check dependencies
echo ""
echo "Dependency check:"
echo ""

# Required
for tool in node curl python3; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "  OK: $tool"
  else
    echo "  MISSING: $tool (REQUIRED)"
  fi
done

# Optional recon tools
# Optional: patchright for browser-based auto-signup
echo ""
echo "Optional browser automation (auto-signup with CAPTCHA solving):"
if node -e "require.resolve('patchright')" 2>/dev/null; then
  echo "  OK: patchright"
else
  echo "  MISSING: patchright (optional — enables Tier 2 auto-signup)"
  echo "    Install: cd $TARGET_ABS && npm init -y && npm install patchright && npx patchright install chromium"
fi
if [ -n "${CAPSOLVER_API_KEY:-}" ]; then
  echo "  OK: CAPSOLVER_API_KEY is set"
else
  echo "  NOT SET: CAPSOLVER_API_KEY (optional — enables CAPTCHA solving)"
  echo "    Get a key at https://capsolver.com and export CAPSOLVER_API_KEY=..."
fi

echo ""
echo "Optional recon tools (hunting works without these, recon steps are skipped):"
for tool in subfinder nuclei; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "  OK: $tool"
  else
    echo "  MISSING: $tool"
  fi
done
if [ -x ~/go/bin/httpx ] || command -v httpx >/dev/null 2>&1; then
  echo "  OK: httpx"
else
  echo "  MISSING: httpx"
fi

echo ""
echo "Install recon tools (optional):"
echo "  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
echo "  go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
echo "  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

echo ""
echo "Done. Start Claude Code in $TARGET, then run: /bountyagent target.com"
