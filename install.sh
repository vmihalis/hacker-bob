#!/bin/bash
set -e

# Bounty Agent — Claude Code installer
# Copies agent definitions, commands, rules, hooks, MCP server, and settings into your project

TARGET="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLAUDE_DIR="$TARGET/.claude"
TARGET_ABS="$(cd "$TARGET" && pwd)"

echo "Installing Bounty Agent into $TARGET/.claude/"
echo ""

# Create directories
mkdir -p "$CLAUDE_DIR/agents" "$CLAUDE_DIR/commands" "$CLAUDE_DIR/rules" "$CLAUDE_DIR/hooks"

# Copy agents
cp "$SCRIPT_DIR/.claude/agents/"*.md "$CLAUDE_DIR/agents/"
echo "  8 agent definitions"

# Copy orchestrator command
cp "$SCRIPT_DIR/.claude/commands/bountyagent.md" "$CLAUDE_DIR/commands/"
echo "  orchestrator command (/bountyagent)"

# Copy rules
cp "$SCRIPT_DIR/.claude/rules/"*.md "$CLAUDE_DIR/rules/"
echo "  hunting + reporting rules"

# Copy hooks
cp "$SCRIPT_DIR/.claude/hooks/scope-guard.sh" "$CLAUDE_DIR/hooks/"
cp "$SCRIPT_DIR/.claude/hooks/scope-guard-mcp.sh" "$CLAUDE_DIR/hooks/"
cp "$SCRIPT_DIR/.claude/hooks/bounty-statusline.js" "$CLAUDE_DIR/hooks/"
chmod +x "$CLAUDE_DIR/hooks/scope-guard.sh" "$CLAUDE_DIR/hooks/scope-guard-mcp.sh"
echo "  scope guard hooks (Bash + MCP) + status line"

# Copy MCP server
mkdir -p "$TARGET_ABS/mcp"
cp "$SCRIPT_DIR/mcp/server.js" "$TARGET_ABS/mcp/"
chmod +x "$TARGET_ABS/mcp/server.js"
echo "  MCP server (mcp/server.js)"

# Configure .mcp.json
MCP_JSON="$TARGET_ABS/.mcp.json"
if [ -f "$MCP_JSON" ]; then
  # Check if bountyagent already configured
  if grep -q "bountyagent" "$MCP_JSON" 2>/dev/null; then
    echo "  .mcp.json already has bountyagent — skipping"
  else
    echo ""
    echo "  WARNING: $MCP_JSON already exists."
    echo "  Add this to your mcpServers:"
    echo ""
    echo '    "bountyagent": {'
    echo "      \"command\": \"node\","
    echo "      \"args\": [\"$TARGET_ABS/mcp/server.js\"]"
    echo '    }'
    echo ""
  fi
else
  cat > "$MCP_JSON" <<EOF
{
  "mcpServers": {
    "bountyagent": {
      "command": "node",
      "args": ["$TARGET_ABS/mcp/server.js"]
    }
  }
}
EOF
  echo "  .mcp.json configured"
fi

# Configure settings.json
if [ -f "$CLAUDE_DIR/settings.json" ]; then
  echo ""
  echo "  WARNING: $CLAUDE_DIR/settings.json already exists."
  echo "  Merge these settings manually:"
  echo ""
  echo '  permissions.allow: bountyagent MCP tools, Bash(mkdir/test/cat/ls), Read, Glob, Grep'
  echo '  hooks.PreToolUse: scope-guard.sh (Bash) + scope-guard-mcp.sh (bounty_http_scan)'
  echo '  statusLine: node "$PROJECT_DIR/.claude/hooks/bounty-statusline.js"'
  echo ""
else
  cat > "$CLAUDE_DIR/settings.json" <<EOF
{
  "permissions": {
    "allow": [
      "mcp__bountyagent__bounty_http_scan",
      "mcp__bountyagent__bounty_record_finding",
      "mcp__bountyagent__bounty_list_findings",
      "mcp__bountyagent__bounty_write_handoff",
      "mcp__bountyagent__bounty_read_handoff",
      "mcp__bountyagent__bounty_auth_manual",
      "Bash(mkdir *)",
      "Bash(test *)",
      "Bash(cat *)",
      "Bash(ls *)",
      "Bash(sort *)",
      "Bash(wc *)",
      "Bash(head *)",
      "Bash(tail *)",
      "Bash(jq *)",
      "Bash(printf *)",
      "Bash(echo *)",
      "Read",
      "Glob",
      "Grep"
    ]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash \"\$PROJECT_DIR/.claude/hooks/scope-guard.sh\"",
            "timeout": 5
          }
        ]
      },
      {
        "matcher": "mcp__bountyagent__bounty_http_scan",
        "hooks": [
          {
            "type": "command",
            "command": "bash \"\$PROJECT_DIR/.claude/hooks/scope-guard-mcp.sh\"",
            "timeout": 5
          }
        ]
      }
    ]
  },
  "statusLine": {
    "type": "command",
    "command": "node \"\$PROJECT_DIR/.claude/hooks/bounty-statusline.js\""
  }
}
EOF
  echo "  settings.json (permissions + hooks + statusLine)"
fi

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
